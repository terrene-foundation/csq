"""JSONL writer + reader + aggregator hardening primitives.

The harness emits one JSONL file per `(run_id, suite)` under
`coc-eval/results/<run_id>/<suite>-<timestamp>.jsonl`. Line 1 is the
header record (`_header: true`); subsequent lines are per-test records.
Every line is validated against `coc-eval/schemas/v1.0.0.json` at
write-time (defense in depth — a bad record never reaches disk).

Token redaction (`redact_tokens` from `redact.py`) is applied to
`stdout_truncated` and `stderr_truncated` BEFORE serialization. The
companion `.log` file, written at the same time, is also redacted but
retains untruncated bodies. This is the SAME `redact_tokens` Rust port
used by the auth probe (defense-in-depth: redact at every persistence
boundary, not just at JSONL).

Aggregator hardening (R1-HIGH-03 + R1-HIGH-05) lives here too:
- `escape_md` for markdown emission of untrusted strings.
- `iter_records` with per-file (10 MB) + per-line (100 KB) caps and
  bounded int parsing.

Run-id validation: every public entry point that accepts a `run_id`
calls `run_id.validate_run_id` first. A malformed id NEVER becomes a
filesystem path.

Stdlib-only.
"""

from __future__ import annotations

import json
import os
import platform as _platform
import shutil
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from .redact import redact_tokens
from .run_id import validate_run_id
from .schema_validator import (
    SchemaValidationError,
    validate_against_schema,
)
from .validators import SUITE_MANIFEST, validate_name

# JSONL schema artifact path — bundled with the harness, NOT loaded over
# the network.
SCHEMA_VERSION: str = "1.0.0"
HARNESS_VERSION: str = "1.0.0"
_SCHEMA_PATH: Path = Path(__file__).resolve().parent.parent / "schemas" / "v1.0.0.json"

# Aggregator hardening caps (R1-HIGH-05).
JSONL_FILE_SIZE_CAP_BYTES: int = 10_000_000  # per-file
JSONL_LINE_BYTES_HARD: int = 100_000  # per-record
JSONL_INT_PARSE_DIGITS_MAX: int = 19  # bounded `parse_int` ceiling


# ---- Schema loading ----------------------------------------------------------

_cached_schema: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any]:
    global _cached_schema
    cached = _cached_schema
    if cached is None:
        if not _SCHEMA_PATH.exists():
            raise RuntimeError(f"v1.0.0 schema not found at {_SCHEMA_PATH}")
        cached = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        _cached_schema = cached
    return cached


def validate_record(record: dict[str, Any]) -> None:
    """Validate a JSONL record against `schemas/v1.0.0.json`.

    Header records (`_header: true`) validate against the `header_record`
    sub-schema; test records (`_header: false`) validate against
    `test_record`. The dispatch is by `_header` truthiness.
    """
    schema = _load_schema()
    is_header = bool(record.get("_header", False))
    sub = schema["definitions"]["header_record" if is_header else "test_record"]
    try:
        validate_against_schema(record, sub, path="", root_schema=schema)
    except SchemaValidationError as e:
        raise SchemaValidationError(
            f"v{SCHEMA_VERSION} validation failed for "
            f"{'header' if is_header else 'test'} record: {e}"
        ) from e


# ---- Markdown escape (R1-HIGH-03 / AC-8a) -----------------------------------


def escape_md(s: str) -> str:
    """Escape a string for safe inclusion in a Markdown table cell.

    Strings consumed by the aggregator (test names, fixture names, error
    reasons, prompt excerpts) are untrusted: anyone with write access to
    `results/` can drop a crafted JSONL. We sanitize before emission so
    a `<script>...` or `|<a href=javascript:...>` payload renders inert.

    Mapping:
      `|`        → `\\|`     (table-cell separator escape)
      `<`        → `&lt;`    (HTML entity — Markdown renderers passthrough)
      `>`        → `&gt;`
      backtick   → `\\``     (code-fence escape)
      `\\n`/`\\r`  → space     (single-line cell)
    """
    if not isinstance(s, str):
        return ""
    out = (
        s.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "\\`")
        .replace("\r\n", " ")
        .replace("\n", " ")
        .replace("\r", " ")
    )
    return out


# ---- Path helpers -----------------------------------------------------------


def _default_results_root() -> Path:
    """Default `coc-eval/results/` path, resolved relative to this module.

    Tests pass an explicit `base_dir` to `JsonlWriter.open` to redirect
    output into a tmp dir; production callers omit it and use this root.
    """
    return Path(__file__).resolve().parent.parent / "results"


def _verify_results_path_gitignored(results_root: Path) -> None:
    """MED-04 startup assertion: `results_root` MUST be gitignored.

    Best-effort: if `git` is not available (no repo, missing binary, or
    binary outside the trusted-prefix allowlist), the check is skipped.
    Hard-failing on a missing `git` binary would block legitimate harness
    invocations in minimal environments.

    Hard-fails when `git` IS available and reports `results_root` as
    NOT ignored — that is a misconfiguration, not an environment gap.

    Hardening (H4 review H2):
      - `git` resolved via `shutil.which` to an absolute path inside a
        small allowlist of OS-managed prefixes. A user-installed shim at
        `~/bin/git` is NOT trusted.
      - subprocess env is reduced to `{PATH, HOME, LANG}` with PATH
        pointing only at trusted bin dirs. This neutralizes
        `GIT_CONFIG_COUNT` / `GIT_*` injection vectors.
    """
    if not results_root.is_absolute():
        results_root = results_root.resolve()
    repo_root = results_root.parent
    while repo_root != repo_root.parent:
        if (repo_root / ".git").exists():
            break
        repo_root = repo_root.parent
    else:
        # Walked all the way up without finding `.git/`. No repo, no check.
        return

    git_bin = shutil.which("git")
    if git_bin is None:
        return
    trusted_prefixes = ("/usr/bin/", "/bin/", "/usr/local/bin/", "/opt/homebrew/bin/")
    if not git_bin.startswith(trusted_prefixes):
        # User-installed shim at ~/bin/git or similar is NOT trusted —
        # skip the check rather than execute an attacker-controlled
        # binary inside the harness.
        sys.stderr.write(
            f"_verify_results_path_gitignored: skipping check; "
            f"git binary {git_bin!r} is outside the trusted prefix allowlist\n"
        )
        return

    safe_env = {
        "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        "HOME": os.environ.get("HOME", ""),
        "LANG": os.environ.get("LANG", "C"),
    }
    # `git check-ignore` against a directory path returns rc=1 even when
    # the .gitignore pattern is `<dir>/` — git's pattern semantics only
    # match the directory's CONTENTS, not the directory entry itself. A
    # synthetic probe file inside the dir forces git to evaluate the
    # pattern against a contained path and report rc=0 when ignored.
    probe = results_root / ".gitignore-probe"
    try:
        result = subprocess.run(
            [git_bin, "check-ignore", "-q", str(probe)],
            capture_output=True,
            cwd=str(repo_root),
            env=safe_env,
            timeout=5.0,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # `git` missing or hung; skip the check (best-effort guard).
        return
    # `git check-ignore -q` exits 0 iff the path IS ignored.
    if result.returncode != 0:
        raise RuntimeError(
            f"MED-04: results dir {results_root} is NOT in .gitignore. "
            "Refusing to write — add `coc-eval/results/` (or the equivalent) "
            "to .gitignore before re-running."
        )


def _deep_redact_record(record: dict[str, Any]) -> None:
    """In-place recursive redaction of every string in a record.

    Defense-in-depth (H4 review H1): any sink that lands in JSONL —
    `extra` overrides on the header, `auth_probes[*].reason`,
    `score.criteria[*].label`, future fields — passes through
    `redact_tokens` before serialization. Idempotent: applying the
    redactor twice (e.g. on `stdout_truncated` which `record_result`
    already redacted) yields the same bytes.
    """
    for key, value in list(record.items()):
        if isinstance(value, str):
            record[key] = redact_tokens(value)
        elif isinstance(value, dict):
            _deep_redact_record(value)
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if isinstance(item, str):
                    value[idx] = redact_tokens(item)
                elif isinstance(item, dict):
                    _deep_redact_record(item)


# ---- JSONL writer -----------------------------------------------------------


@dataclass
class JsonlWriter:
    """One open JSONL file plus its companion log directory.

    Use `JsonlWriter.open(run_id, suite, ...)` to create one. Call
    `write_header(...)` exactly once and `record_result(...)` per test.
    `close()` flushes and closes the file handle. The class is a small
    context manager too (`__enter__`/`__exit__`).
    """

    path: Path
    run_id: str
    suite: str
    log_dir: Path
    _fh: IO[str]

    @classmethod
    def open(
        cls,
        run_id: str,
        suite: str,
        base_dir: Path | None = None,
        skip_gitignore_check: bool = False,
    ) -> "JsonlWriter":
        """Create the JSONL file for a `(run_id, suite)` pair.

        Args:
            run_id: validated run id from `run_id.generate_run_id()`.
            suite: suite name (validated against `SUITE_MANIFEST`).
            base_dir: results directory root. Defaults to
                `coc-eval/results/`. Tests pass a tmp dir.
            skip_gitignore_check: tests opt out of the MED-04 startup
                assertion when running outside a git repo (or when the
                tmp `base_dir` is, by design, NOT gitignored).

        Returns:
            An open `JsonlWriter`. File on disk is empty (no header
            written yet).
        """
        validate_run_id(run_id)
        if suite not in SUITE_MANIFEST:
            raise ValueError(f"unknown suite: {suite!r}; valid: {SUITE_MANIFEST}")
        validate_name(suite)
        root = base_dir if base_dir is not None else _default_results_root()
        if not skip_gitignore_check:
            _verify_results_path_gitignored(root)
        run_dir = root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
        path = run_dir / f"{suite}-{ts}.jsonl"
        log_dir = run_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = path.open("w", encoding="utf-8")
        return cls(path=path, run_id=run_id, suite=suite, log_dir=log_dir, _fh=fh)

    # Context manager sugar.
    def __enter__(self) -> "JsonlWriter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if not self._fh.closed:
            self._fh.flush()
            self._fh.close()

    # --- Records ---

    def write_header(
        self,
        *,
        started_at: str,
        host: dict[str, Any] | None = None,
        cli_versions: dict[str, str] | None = None,
        auth_probes: dict[str, Any] | None = None,
        fixtures_commit: str | None = None,
        selected_clis: list[str] | None = None,
        selected_tests: list[str] | None = None,
        selected_rubrics: list[str] | None = None,
        permission_profile: str = "plan",
        home_mode: str = "stub",
        harness_invocation: str | None = None,
        model_id: str | None = None,
        token_budget: dict[str, int] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compose + persist the header record. Returns the record dict
        (post-validation, post-write) for tests and dry-runs.
        """
        if host is None:
            host = {
                "platform": f"{_platform.system().lower()} {_platform.release()}",
                "arch": _platform.machine(),
                "python": _platform.python_version(),
            }
        record: dict[str, Any] = {
            "_header": True,
            "schema_version": SCHEMA_VERSION,
            "harness_version": HARNESS_VERSION,
            "run_id": self.run_id,
            "suite": self.suite,
            "started_at": started_at,
            "host": host,
            "cli_versions": cli_versions or {},
            "auth_probes": auth_probes or {},
            "selected_clis": selected_clis or [],
            "selected_rubrics": selected_rubrics or ["default"],
            "permission_profile": permission_profile,
            "home_mode": home_mode,
        }
        # Optional fields: include only when set, so the schema's strict
        # `type: "string"` for plain optionals does not reject a `null`.
        if fixtures_commit is not None:
            record["fixtures_commit"] = fixtures_commit
        if selected_tests is not None:
            record["selected_tests"] = selected_tests
        if harness_invocation is not None:
            record["harness_invocation"] = harness_invocation
        if model_id is not None:
            record["model_id"] = model_id
        if token_budget is not None:
            record["token_budget"] = token_budget
        if extra:
            record.update(extra)
        # Defense-in-depth (H4 review H1): every string in the record —
        # including `extra` overrides + `auth_probes[*].reason` — is
        # redacted before persistence. The probe already redacts at
        # source (H3 review H1), but `extra` is operator-supplied and
        # has no other redaction sink.
        _deep_redact_record(record)
        validate_record(record)
        self._write_line(record)
        return record

    def record_result(self, record: dict[str, Any]) -> dict[str, Any]:
        """Persist a per-test record.

        Mutates the record in place: every string value (including but
        not limited to `stdout_truncated` and `stderr_truncated`) is
        pushed through `redact_tokens` BEFORE validation + write. Also
        forces `_header` to `False`.

        Defense-in-depth (H4 review H1): redacting at every string sink
        means a future field added to `06-jsonl-schema-v1.md` cannot
        accidentally leak token shapes — the redactor walks the whole
        record. Idempotent: stdout/stderr that were already redacted by
        a producer remain identical.

        Returns:
            The record dict actually written (post-redaction). Tests use
            it to assert that the persisted bytes do not contain a token.
        """
        record["_header"] = False
        _deep_redact_record(record)
        validate_record(record)
        self._write_line(record)
        return record

    def write_log(
        self,
        cli: str,
        test: str,
        stdout: str,
        stderr: str,
        *,
        cmd_template_id: str | None = None,
        cwd: Path | str | None = None,
        stub_home: Path | str | None = None,
        exit_code: int | None = None,
        signal: str | None = None,
        runtime_ms: int | None = None,
        timed_out: bool | None = None,
        score: dict[str, Any] | None = None,
        evidence_required: bool = False,
    ) -> Path:
        """Write the companion `.log` file (full body, redacted, mode 0o600).

        Filename: `<cli>-<suite>-<test>.log` under the run's `logs/`
        subdir. For tests with `evidence_required=True`, an additional
        `<test>.evidence.log` sibling is emitted with a banner header.

        Returns the path of the primary log file.
        """
        validate_name(cli)
        validate_name(test)
        log_path = self.log_dir / f"{cli}-{self.suite}-{test}.log"
        self._write_log_body(
            log_path,
            cli=cli,
            test=test,
            stdout=stdout,
            stderr=stderr,
            cmd_template_id=cmd_template_id,
            cwd=cwd,
            stub_home=stub_home,
            exit_code=exit_code,
            signal=signal,
            runtime_ms=runtime_ms,
            timed_out=timed_out,
            score=score,
            banner=None,
        )
        if evidence_required:
            evidence_path = self.log_dir / f"{cli}-{self.suite}-{test}.evidence.log"
            self._write_log_body(
                evidence_path,
                cli=cli,
                test=test,
                stdout=stdout,
                stderr=stderr,
                cmd_template_id=cmd_template_id,
                cwd=cwd,
                stub_home=stub_home,
                exit_code=exit_code,
                signal=signal,
                runtime_ms=runtime_ms,
                timed_out=timed_out,
                score=score,
                banner="EVIDENCE LOG — DO NOT COMMIT — DELETE AFTER REVIEW",
            )
        return log_path

    # --- Internals ---

    def _write_line(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        if len(line) + 1 > JSONL_LINE_BYTES_HARD:  # +1 for newline
            raise ValueError(
                f"record exceeds {JSONL_LINE_BYTES_HARD}-byte hard cap "
                f"(was {len(line)} bytes); truncate before writing"
            )
        self._fh.write(line + "\n")
        self._fh.flush()

    def _write_log_body(
        self,
        path: Path,
        *,
        cli: str,
        test: str,
        stdout: str,
        stderr: str,
        cmd_template_id: str | None,
        cwd: Path | str | None,
        stub_home: Path | str | None,
        exit_code: int | None,
        signal: str | None,
        runtime_ms: int | None,
        timed_out: bool | None,
        score: dict[str, Any] | None,
        banner: str | None,
    ) -> None:
        # M1: refuse to overwrite a symlink at the destination path.
        # `os.rename` follows symlinks on some Linux variants — fail
        # closed if a malicious actor planted one.
        if path.is_symlink():
            raise RuntimeError(
                f"_write_log_body: refusing to overwrite symlink at {path}"
            )

        # M2/M3: open the tmp file with O_CREAT|O_EXCL + mode 0o600 so the
        # at-rest permissions are correct from the FIRST byte written, not
        # only after a post-write `chmod`. Closes the umask-race window
        # called out in `rules/security.md` §5a.
        tmp = path.with_suffix(path.suffix + ".tmp")
        # Best-effort cleanup of a stale tmp from a crashed prior run.
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # Permission denied or similar: let the open below surface it.
            pass

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(str(tmp), flags, 0o600)
        except OSError as e:
            raise RuntimeError(
                f"_write_log_body: could not create tmp at {tmp}: {e}"
            ) from e

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                if banner:
                    fh.write(f"### {banner} ###\n")
                fh.write(f"# cli: {cli}\n")
                fh.write(f"# test: {test}\n")
                fh.write(f"# suite: {self.suite}\n")
                fh.write(f"# run_id: {self.run_id}\n")
                if cmd_template_id is not None:
                    fh.write(f"# cmd_template_id: {cmd_template_id}\n")
                if cwd is not None:
                    fh.write(f"# cwd: {cwd}\n")
                if stub_home is not None:
                    fh.write(f"# stub_home: {stub_home}\n")
                if exit_code is not None:
                    fh.write(f"# exit_code: {exit_code}\n")
                if signal is not None:
                    fh.write(f"# signal: {signal}\n")
                if runtime_ms is not None:
                    fh.write(f"# runtime_ms: {runtime_ms}\n")
                if timed_out is not None:
                    fh.write(f"# timed_out: {timed_out}\n")
                if score is not None:
                    fh.write(
                        "# score: "
                        + json.dumps(score, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
                fh.write("--- STDOUT ---\n")
                fh.write(redact_tokens(stdout or ""))
                if not (stdout or "").endswith("\n"):
                    fh.write("\n")
                fh.write("--- STDERR ---\n")
                fh.write(redact_tokens(stderr or ""))
                if not (stderr or "").endswith("\n"):
                    fh.write("\n")
            # tmp already at 0o600; rename atomically replaces `path`.
            os.rename(tmp, path)
        except Exception:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise


# ---- Reader / aggregator hardening -----------------------------------------


def _bounded_parse_int(s: str) -> int:
    """`json.loads(line, parse_int=...)` callback that caps the digit count.

    Lines containing absurdly large integers (potential JSON-bombs) yield
    `0` rather than allocating arbitrarily large `int` objects. The cap
    is `JSONL_INT_PARSE_DIGITS_MAX` digits — well above any legitimate
    runtime_ms/exit_code/token-count value but small enough that
    parsing remains O(1).
    """
    return int(s) if len(s) < JSONL_INT_PARSE_DIGITS_MAX else 0


def read_record(line: str) -> dict[str, Any]:
    """Parse a single JSONL line. Forward-compatible: unknown keys preserved.

    Raises `ValueError` on malformed JSON or oversized lines.
    """
    if len(line) > JSONL_LINE_BYTES_HARD:
        raise ValueError(
            f"line exceeds {JSONL_LINE_BYTES_HARD}-byte hard cap "
            f"(was {len(line)} bytes)"
        )
    record = json.loads(line, parse_int=_bounded_parse_int)
    if not isinstance(record, dict):
        raise ValueError(
            f"JSONL line did not decode to a dict; got {type(record).__name__}"
        )
    return record


def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Iterate JSONL records from `path` with hardening caps applied.

    Skips files larger than `JSONL_FILE_SIZE_CAP_BYTES` (yields nothing
    + writes a one-line warning to stderr — caller decides whether to
    treat skipped files as failures).

    Per-line: lines longer than `JSONL_LINE_BYTES_HARD` raise; the caller
    can wrap in try/except to skip-and-continue.
    """
    try:
        statinfo = path.stat()
    except OSError as e:
        raise OSError(f"iter_records: stat failed for {path}: {e}") from e
    if statinfo.st_size > JSONL_FILE_SIZE_CAP_BYTES:
        sys.stderr.write(
            f"iter_records: skipping oversized JSONL {path} "
            f"({statinfo.st_size} > {JSONL_FILE_SIZE_CAP_BYTES})\n"
        )
        return
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.rstrip("\n")
            if not stripped:
                continue
            yield read_record(stripped)


# ---- Convenience -----------------------------------------------------------


def now_iso8601_ms() -> str:
    """ISO-8601 timestamp with millisecond precision and a `Z` suffix.

    Matches the `iso8601_ts` shape used in the v1.0.0 schema header /
    record fields.
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


__all__ = [
    "HARNESS_VERSION",
    "JSONL_FILE_SIZE_CAP_BYTES",
    "JSONL_INT_PARSE_DIGITS_MAX",
    "JSONL_LINE_BYTES_HARD",
    "JsonlWriter",
    "SCHEMA_VERSION",
    "escape_md",
    "iter_records",
    "now_iso8601_ms",
    "read_record",
    "validate_record",
]
