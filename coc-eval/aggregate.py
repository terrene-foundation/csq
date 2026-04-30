#!/usr/bin/env python3
"""coc-eval aggregator (H9).

Reads JSONL records emitted by the harness and renders a matrix of
`(test, cli) -> {state, score}` cells in pretty/json/csv/md formats.
Optional gates: baseline floor (`--gate baseline`), partial-coverage
(`--full`), quarantine inclusion (`--include-quarantined`).

Stdlib-only per `rules/independence.md` §3.

Usage:

    coc-eval/aggregate.py [--run-id RUN_ID | --since 7d]
                          [--format pretty|json|csv|md]
                          [--top N | --regressions-only | --failed-only]
                          [--gate baseline]
                          [--full | --allow-partial]
                          [--include-quarantined]
                          [--validate]
                          [--baselines-path PATH]

Default: aggregate the latest run under `coc-eval/results/`.

Exit codes:
  0    success (or --gate baseline with all cells at-or-above floor)
  1    one or more cells below baseline (with `--gate baseline`)
       OR one or more failed cells (default behavior; see `--strict`)
  2    --full requested but the run is partial
  64   usage error (UX-13: bad run-id, unknown flag, etc.)
  78   no JSONL records found (zero-data state)
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, IO


# ── Constants (JSON-bomb defenses, R1-HIGH-05 / AC-8b) ────────────────

# Per-file JSONL cap. Anything beyond is rejected with a structured
# error, NOT silently skipped — the operator should know the file was
# anomalous. 10 MiB is generous for legitimate runs (a 5-test suite
# with 8 KiB stdout truncation produces ~50 KiB/test).
_PER_FILE_BYTES_CAP: int = 10 * 1024 * 1024  # 10 MiB

# Per-record cap. Stdout/stderr already truncate to 8 KiB / 4 KiB; a
# JSONL record that exceeds 100 KiB carries either an inflated
# criteria list or a malicious oversized field. Refuse and continue.
_PER_RECORD_BYTES_CAP: int = 100 * 1024  # 100 KiB

# Bounded integer parsing — JSON's spec allows arbitrarily large
# integers. Python parses them as native int (unbounded). A malicious
# JSONL with `"runtime_ms": <huge>` would cause downstream sort
# operations to misbehave; reject anything outside JS-safe-int range
# (2^53 - 1, the IEEE-754 boundary).
_JS_SAFE_INT_MAX: int = (1 << 53) - 1


# Schema version this aggregator was written against. R1: each header
# record carries `schema_version`; we accept exact match by default,
# `--allow-stale` to override (e.g. for forensics on older runs).
_AGGREGATOR_SCHEMA_VERSION: str = "1.0.0"


# ── Sentinels for cell shapes ─────────────────────────────────────────


@dataclass(frozen=True)
class Cell:
    """One (test, cli) cell in the rendered matrix."""

    state: str  # one of the state-enum values from v1.0.0
    total: float
    max_total: float
    runtime_ms: float
    attempts: int
    quarantined: bool = False
    isolation_breach: bool = False  # canary leak (H7)


@dataclass
class RunData:
    """Resolved run: header + records keyed by (suite, test, cli)."""

    run_id: str
    schema_version: str
    started_at: str
    cells: dict[tuple[str, str, str], Cell] = field(default_factory=dict)
    suites_seen: set[str] = field(default_factory=set)
    clis_seen: set[str] = field(default_factory=set)
    tests_seen: set[tuple[str, str]] = field(default_factory=set)  # (suite, test)
    skipped_records: int = 0
    invalid_records: int = 0
    # H9 R1-B-HIGH-5: quarantined tests whose JSONL carried a canary
    # `isolation_breach: True`. Surfaced in main() as a security audit
    # banner — quarantine MUST NOT silence credential / memory leaks.
    quarantined_breaches: list[tuple[str, str, str]] = field(default_factory=list)


# ── JSONL parsing with JSON-bomb defenses ─────────────────────────────


class AggregatorError(RuntimeError):
    """Raised on hard errors that abort aggregation."""


# H9 R1-A-LOW-1: structured exit-code mapping. Sub-classes carry their
# semantic exit code so `main()` doesn't substring-match on messages.
class InvalidRunIdError(AggregatorError):
    """Bad --run-id format or content."""


class RunNotFoundError(AggregatorError):
    """No run directory found (zero-data state)."""


def _check_int_bounds(obj: Any, depth: int = 0, max_depth: int = 64) -> bool:
    """Recursively check every int in `obj` is within JS safe-int range.

    Returns True if all ints are within bounds; False on first
    out-of-range. `max_depth` caps recursion to prevent stack bombs
    via deeply nested JSON.

    H9 R1-A-HIGH-1: depth cap raised from 32 → 64. Dict keys are
    leaf strings (JSON disallows non-string keys); we still iterate
    them but DON'T charge a recursion level for the key check —
    keys can only be `str` (already JSON-parsed) and `_check_int_bounds`
    on a `str` is constant-time.
    """
    if depth > max_depth:
        return False
    if isinstance(obj, bool):
        # bool is an int subclass in Python — exclude.
        return True
    if isinstance(obj, int):
        return -_JS_SAFE_INT_MAX <= obj <= _JS_SAFE_INT_MAX
    if isinstance(obj, dict):
        for v in obj.values():
            # Keys are guaranteed `str` post-`json.loads`; descend
            # only into values.
            if not _check_int_bounds(v, depth + 1, max_depth):
                return False
        return True
    if isinstance(obj, list):
        for v in obj:
            if not _check_int_bounds(v, depth + 1, max_depth):
                return False
        return True
    return True


def _iter_jsonl_records(path: Path) -> tuple[list[dict[str, Any]], int]:
    """Read a JSONL file with JSON-bomb defenses.

    Returns `(records, invalid_count)`. Records that exceed the
    per-record cap, fail JSON parse, or carry out-of-range ints are
    counted in `invalid_count` and excluded from the records list.

    Raises `AggregatorError` if the file itself exceeds the per-file
    cap — the file is anomalous and continuing would mislead the
    operator. Symlinks are refused (operator-supplied path is fine,
    but `results_root/run_id/*.jsonl` should never resolve through
    a symlink — defense-in-depth alongside `_resolve_run_dir`).

    H9 R1-A-CRIT-1 fix: read in fixed 64 KiB chunks rather than
    Python's default line-iterator. A 10 MiB JSONL file with NO
    newlines would otherwise cause Python to materialize a 10 MiB
    `bytes` line before ANY size check could fire. The chunked path
    bounds peak memory at one record budget plus the buffer cap.
    """
    if path.is_symlink():
        raise AggregatorError(f"refusing symlinked JSONL file: {path}")
    try:
        size = path.stat().st_size
    except OSError as e:
        raise AggregatorError(f"cannot stat {path}: {e}") from e
    if size > _PER_FILE_BYTES_CAP:
        raise AggregatorError(
            f"JSONL file exceeds {_PER_FILE_BYTES_CAP} byte cap: "
            f"{path} ({size} bytes)"
        )

    records: list[dict[str, Any]] = []
    invalid = 0
    chunk_size = 65_536
    buf = bytearray()
    overflow_in_progress = False  # True while skipping bytes of an oversized record

    def _process_line(line: bytes) -> None:
        nonlocal invalid
        line = line.rstrip(b"\r")
        if not line:
            return
        if len(line) > _PER_RECORD_BYTES_CAP:
            invalid += 1
            return
        try:
            rec = json.loads(line.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            invalid += 1
            return
        if not isinstance(rec, dict):
            invalid += 1
            return
        if not _check_int_bounds(rec):
            invalid += 1
            return
        records.append(rec)

    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                start = 0
                while True:
                    nl = chunk.find(b"\n", start)
                    if nl == -1:
                        # Append chunk tail to buffer; check buffer cap.
                        if overflow_in_progress:
                            # Already counted; just keep skipping bytes
                            # without buffering (memory bound).
                            pass
                        else:
                            buf.extend(chunk[start:])
                            if len(buf) > _PER_RECORD_BYTES_CAP:
                                invalid += 1
                                buf.clear()
                                overflow_in_progress = True
                        break
                    # We have a complete line: prefix-buffer + chunk slice.
                    if overflow_in_progress:
                        # The current oversized record ends at this newline.
                        overflow_in_progress = False
                        buf.clear()
                    else:
                        buf.extend(chunk[start:nl])
                        if len(buf) > _PER_RECORD_BYTES_CAP:
                            invalid += 1
                            buf.clear()
                        else:
                            _process_line(bytes(buf))
                            buf.clear()
                    start = nl + 1
            # Trailing line without final newline.
            if buf and not overflow_in_progress:
                if len(buf) > _PER_RECORD_BYTES_CAP:
                    invalid += 1
                else:
                    _process_line(bytes(buf))
    except OSError as e:
        raise AggregatorError(f"cannot read {path}: {e}") from e
    return records, invalid


# ── Run discovery ─────────────────────────────────────────────────────


_RUN_ID_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z-\d+-\d{4}-[A-Za-z0-9_-]{6,12}$"
)


def _default_results_root() -> Path:
    return Path(__file__).resolve().parent / "results"


def _discover_latest_run(results_root: Path) -> Path | None:
    """Find the most-recent run directory by lexicographic order.

    Run IDs are ISO-8601-prefixed, so lexicographic order = chronological
    order for runs in the same year. H9 R1-A-HIGH-2: skips symlinked
    entries — a symlink under results_root pointing at another tree
    would otherwise be silently followed.
    """
    if not results_root.is_dir():
        return None
    candidates: list[Path] = []
    try:
        entries = list(results_root.iterdir())
    except OSError:
        return None
    for entry in entries:
        if entry.is_symlink():
            continue
        if not entry.is_dir():
            continue
        if not _RUN_ID_RE.fullmatch(entry.name):
            continue
        candidates.append(entry)
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.name, reverse=True)
    return candidates[0]


def _resolve_run_dir(
    args: argparse.Namespace,
    results_root: Path,
) -> Path:
    """Resolve the run directory to aggregate.

    H9 R1-A-HIGH-2: even though `_RUN_ID_RE` rejects `..`/`/`, we
    additionally `resolve()` and assert containment under
    `results_root.resolve()` so a symlink at `results_root/<runid>`
    cannot redirect.
    """
    results_root_resolved = results_root.resolve()
    if args.run_id is not None:
        if not _RUN_ID_RE.fullmatch(args.run_id):
            raise InvalidRunIdError(f"invalid --run-id format: {args.run_id!r}")
        run_dir = results_root / args.run_id
        if not run_dir.is_dir():
            raise RunNotFoundError(f"run directory not found: {run_dir}")
        if run_dir.is_symlink():
            raise InvalidRunIdError(f"refusing symlinked run directory: {run_dir}")
        try:
            run_dir.resolve(strict=True).relative_to(results_root_resolved)
        except (ValueError, OSError) as e:
            raise InvalidRunIdError(
                f"run directory escapes results_root: {run_dir}"
            ) from e
        return run_dir
    latest = _discover_latest_run(results_root)
    if latest is None:
        raise RunNotFoundError(
            f"no run directories found under {results_root}; pass "
            f"--run-id explicitly"
        )
    return latest


# ── Load + reduce ─────────────────────────────────────────────────────


def _load_run(
    run_dir: Path,
    *,
    expected_schema_version: str = _AGGREGATOR_SCHEMA_VERSION,
    allow_stale: bool = False,
    include_quarantined: bool = False,
) -> RunData:
    """Read every JSONL file in `run_dir` and reduce to a RunData.

    Header records contribute `run_id` / `schema_version` / `started_at`
    metadata; subsequent test records populate `cells`. Quarantined
    tests are SKIPPED unless `include_quarantined=True`.

    Raises AggregatorError on:
    - schema_version mismatch (unless allow_stale)
    - per-file size cap exceeded
    - no JSONL files found
    """
    jsonl_files = sorted(run_dir.glob("*.jsonl"))
    if not jsonl_files:
        raise AggregatorError(f"no JSONL files in {run_dir}")

    run = RunData(run_id="", schema_version="", started_at="")
    seen_header = False
    quarantined_breaches: list[tuple[str, str, str]] = []  # B-HIGH-5 audit

    # B-MED-3: closed enum check on `state`. The schema enforces this
    # but the aggregator's parser accepted any string; a malicious
    # JSONL with terminal-control sequences in `state` would write
    # those to stderr later. Enum-validate at load time.
    valid_states = frozenset(
        {
            "pass",
            "pass_after_retry",
            "fail",
            "error_fixture",
            "error_invocation",
            "error_json_parse",
            "error_timeout",
            "error_token_budget",
            "skipped_sandbox",
            "skipped_artifact_shape",
            "skipped_cli_missing",
            "skipped_cli_auth",
            "skipped_quota",
            "skipped_quarantined",
            "skipped_user_request",
            "skipped_budget",
        }
    )

    for path in jsonl_files:
        records, invalid_count = _iter_jsonl_records(path)
        run.invalid_records += invalid_count
        for rec in records:
            if rec.get("_header") is True:
                # Header record. Record metadata + validate schema.
                if not seen_header:
                    run.run_id = str(rec.get("run_id", ""))
                    run.schema_version = str(rec.get("schema_version", ""))
                    run.started_at = str(rec.get("started_at", ""))
                    seen_header = True
                else:
                    # H9 R1-A-HIGH-3: subsequent headers must match the
                    # first. A run dir co-mingling two run_ids' JSONL
                    # would otherwise silently merge under the first
                    # header — forensically dangerous.
                    rec_run_id = str(rec.get("run_id", ""))
                    if rec_run_id != run.run_id:
                        raise AggregatorError(
                            f"multi-suite run_id drift in {path.name}: "
                            f"header says {rec_run_id!r}, first header "
                            f"was {run.run_id!r}. Run dir contains "
                            f"records from multiple runs."
                        )
                rec_schema = str(rec.get("schema_version", ""))
                if rec_schema != expected_schema_version and not allow_stale:
                    raise AggregatorError(
                        f"schema_version drift: header says {rec_schema!r}, "
                        f"aggregator expects {expected_schema_version!r}. "
                        f"Use --allow-stale for forensic reads."
                    )
                continue
            # Test record. H9 R1-A-HIGH-4: a test record carrying
            # `_header: false` AND header-only fields like `run_id`/
            # `schema_version` is impersonating run metadata. Reject.
            if "run_id" in rec or "schema_version" in rec:
                run.invalid_records += 1
                continue
            suite = rec.get("suite")
            test = rec.get("test")
            cli = rec.get("cli")
            state = rec.get("state")
            if not (
                isinstance(suite, str)
                and isinstance(test, str)
                and isinstance(cli, str)
                and isinstance(state, str)
            ):
                run.invalid_records += 1
                continue
            # B-MED-3: enum-validate state.
            if state not in valid_states:
                run.invalid_records += 1
                continue
            score = rec.get("score") or {}
            total_v = float(score.get("total", 0))
            max_total_v = float(score.get("max_total", 0))
            # B-HIGH-3: refuse malformed score shape (negative values,
            # total > max_total). A malicious record with `total=-5,
            # max_total=-10` would otherwise pass the `> 0` guard.
            if (
                total_v < 0
                or max_total_v < 0
                or (max_total_v > 0 and total_v > max_total_v)
            ):
                run.invalid_records += 1
                continue
            isolation_breach = bool(score.get("isolation_breach", False))
            if state == "skipped_quarantined" and not include_quarantined:
                # B-HIGH-5: even when skipping a quarantined cell from
                # the matrix, surface the canary leak for forensic
                # audit. Quarantine MUST NOT silence isolation
                # breaches.
                if isolation_breach:
                    quarantined_breaches.append((suite, test, cli))
                run.skipped_records += 1
                continue
            cell = Cell(
                state=state,
                total=total_v,
                max_total=max_total_v,
                runtime_ms=float(rec.get("runtime_ms", 0)),
                attempts=int(rec.get("attempts", 0)),
                quarantined=(state == "skipped_quarantined"),
                isolation_breach=isolation_breach,
            )
            key = (suite, test, cli)
            run.cells[key] = cell
            run.suites_seen.add(suite)
            run.clis_seen.add(cli)
            run.tests_seen.add((suite, test))
    run.quarantined_breaches = quarantined_breaches
    if not seen_header:
        raise AggregatorError(f"no header record found in {run_dir}")
    return run


# ── Render formats ────────────────────────────────────────────────────


# Markdown-special characters that need escaping when emitted in cells.
# H9 R1-B-HIGH-2 widened set: pipe/backslash/backtick are table-cell
# injection vectors; brackets are link-syntax vectors; angle brackets
# are HTML/markdown-mixing vectors.
_MD_ESCAPE_RE = re.compile(r"([\\|`\[\]])")


def _md_escape(s: str) -> str:
    """Escape markdown table-cell special characters (R1-HIGH-03 / AC-8a).

    H9 R1-B-HIGH-1 + B-HIGH-2 hardening: cells in a markdown matrix
    could otherwise:
    - pipe-inject (`|` splits columns)
    - backtick-inject (`code-fence`)
    - link-inject (`[click](javascript:...)` becomes a clickable link)
    - row-break inject (a literal `\\n` in a cell ends the row early
      and can forge subsequent rows)

    We escape pipe/backslash/backtick/bracket and entity-encode angle
    brackets. Newlines + carriage returns are replaced with a single
    space — table cells cannot legitimately contain row breaks. Other
    control characters (`\\x00-\\x1f` minus space) are stripped to
    prevent terminal-control injection on subsequent paste.
    """
    if not isinstance(s, str):
        s = str(s)
    # Strip control chars (incl. \r, \n, \t).
    s = "".join(" " if (0 <= ord(c) < 32 and c != " ") else c for c in s)
    s = _MD_ESCAPE_RE.sub(r"\\\1", s)
    # Entity-encode angle brackets so HTML-permissive renderers
    # (Notion, some markdown→HTML pipelines) cannot interpret them.
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return s


def _state_glyph(state: str) -> str:
    """Compact glyph for pretty/md output."""
    return {
        "pass": "OK",
        "pass_after_retry": "RT",
        "fail": "X",
        "error_fixture": "EF",
        "error_invocation": "EI",
        "error_json_parse": "EJ",
        "error_timeout": "TO",
        "error_token_budget": "TB",
        "skipped_sandbox": "S-",
        "skipped_artifact_shape": "S~",
        "skipped_cli_missing": "S?",
        "skipped_cli_auth": "SA",
        "skipped_quota": "SQ",
        "skipped_quarantined": "Sq",
        "skipped_user_request": "Su",
        "skipped_budget": "SB",
    }.get(state, "??")


def _filter_cells(
    run: RunData,
    *,
    failed_only: bool = False,
    regressions_only: bool = False,
    baselines: dict | None = None,
) -> list[tuple[tuple[str, str, str], Cell]]:
    """Apply --failed-only / --regressions-only filters.

    Returns the filtered list as (key, cell) tuples in deterministic
    order: suite (canonical), then test, then cli.
    """
    pairs = sorted(run.cells.items(), key=lambda p: p[0])
    if failed_only:
        pairs = [
            (k, c)
            for k, c in pairs
            if c.state.startswith("error_") or c.state == "fail"
        ]
    if regressions_only and baselines is not None:
        pairs = [(k, c) for k, c in pairs if _below_baseline(k, c, baselines)]
    return pairs


def _render_pretty(
    run: RunData, pairs: list[tuple[tuple[str, str, str], Cell]], out: IO[str]
) -> None:
    out.write(f"run_id={run.run_id}\n")
    out.write(f"schema_version={run.schema_version}\n")
    out.write(f"started_at={run.started_at}\n")
    out.write(
        f"cells={len(pairs)} suites={len(run.suites_seen)} "
        f"clis={len(run.clis_seen)}\n"
    )
    out.write("\n")
    out.write(
        f"{'SUITE':<14} {'TEST':<32} {'CLI':<8} {'STATE':<6} "
        f"{'SCORE':>10} {'RUNTIME':>9}\n"
    )
    out.write("-" * 80 + "\n")
    for (suite, test, cli), c in pairs:
        score_str = f"{c.total:.0f}/{c.max_total:.0f}" if c.max_total else "-"
        rt = f"{c.runtime_ms / 1000:.1f}s"
        breach = " ⚠" if c.isolation_breach else ""
        out.write(
            f"{suite:<14} {test:<32} {cli:<8} "
            f"{_state_glyph(c.state):<6} {score_str:>10} {rt:>9}{breach}\n"
        )
    out.write(f"\nskipped={run.skipped_records} invalid={run.invalid_records}\n")


def _render_json(
    run: RunData, pairs: list[tuple[tuple[str, str, str], Cell]], out: IO[str]
) -> None:
    payload = {
        "run_id": run.run_id,
        "schema_version": run.schema_version,
        "started_at": run.started_at,
        "suites": sorted(run.suites_seen),
        "clis": sorted(run.clis_seen),
        "skipped": run.skipped_records,
        "invalid": run.invalid_records,
        "cells": [
            {
                "suite": s,
                "test": t,
                "cli": c,
                "state": cell.state,
                "total": cell.total,
                "max_total": cell.max_total,
                "runtime_ms": cell.runtime_ms,
                "attempts": cell.attempts,
                "isolation_breach": cell.isolation_breach,
            }
            for (s, t, c), cell in pairs
        ],
    }
    json.dump(payload, out, indent=2, sort_keys=True)
    out.write("\n")


def _render_csv(
    run: RunData, pairs: list[tuple[tuple[str, str, str], Cell]], out: IO[str]
) -> None:
    w = csv.writer(out, lineterminator="\n")
    w.writerow(
        [
            "suite",
            "test",
            "cli",
            "state",
            "total",
            "max_total",
            "runtime_ms",
            "attempts",
            "isolation_breach",
        ]
    )
    for (suite, test, cli), c in pairs:
        w.writerow(
            [
                suite,
                test,
                cli,
                c.state,
                f"{c.total:g}",
                f"{c.max_total:g}",
                f"{c.runtime_ms:.0f}",
                str(c.attempts),
                "true" if c.isolation_breach else "false",
            ]
        )


def _render_md(
    run: RunData, pairs: list[tuple[tuple[str, str, str], Cell]], out: IO[str]
) -> None:
    out.write(f"# coc-eval run `{_md_escape(run.run_id)}`\n\n")
    out.write(f"- schema: `{_md_escape(run.schema_version)}`\n")
    out.write(f"- started: `{_md_escape(run.started_at)}`\n")
    out.write(
        f"- cells: {len(pairs)} | suites: {len(run.suites_seen)} | "
        f"clis: {len(run.clis_seen)}\n\n"
    )
    out.write("| Suite | Test | CLI | State | Score | Runtime |\n")
    out.write("| --- | --- | --- | --- | --- | --- |\n")
    for (suite, test, cli), c in pairs:
        score_str = f"{c.total:g}/{c.max_total:g}" if c.max_total else "—"
        rt = f"{c.runtime_ms / 1000:.1f}s"
        breach = " ⚠" if c.isolation_breach else ""
        out.write(
            f"| {_md_escape(suite)} | {_md_escape(test)} | "
            f"{_md_escape(cli)} | {_md_escape(c.state)}{breach} | "
            f"{score_str} | {rt} |\n"
        )
    out.write(
        f"\n_skipped: {run.skipped_records}, " f"invalid: {run.invalid_records}_\n"
    )


# ── Baselines + gates ─────────────────────────────────────────────────


def _default_baselines_path() -> Path:
    return Path(__file__).resolve().parent / "baselines.json"


# Baselines file size cap (1 MiB; current real file is < 1 KB).
_BASELINES_FILE_CAP: int = 1 * 1024 * 1024

# Allowed leaf-dict keys in baselines per-test entries.
_BASELINE_LEAF_KEYS: frozenset[str] = frozenset({"min_total", "min_pct"})


def _load_baselines(path: Path) -> dict[str, Any]:
    """Load baselines.json. Returns `{}` if missing.

    Schema (informal):
      {
        "v1": {
          "suite_name": {
            "cli": {
              "test_id": {"min_total": int, "min_pct": float}
            }
          }
        }
      }

    H9 R1-A-MED-1 + B-MED-1: applies the same size-cap + symlink-
    reject discipline as `_iter_jsonl_records`. H9 R1-B-MED-2:
    walks every leaf entry and asserts at least one of
    `{min_total, min_pct}` is present and that NO unknown leaf
    keys exist (catches typos like `min_totl` that would otherwise
    silently mean "no floor → false-pass").
    """
    if not path.is_file():
        return {}
    if path.is_symlink():
        raise AggregatorError(f"refusing symlinked baselines: {path}")
    try:
        size = path.stat().st_size
    except OSError as e:
        raise AggregatorError(f"cannot stat baselines: {e}") from e
    if size > _BASELINES_FILE_CAP:
        raise AggregatorError(
            f"baselines.json exceeds {_BASELINES_FILE_CAP} byte cap: "
            f"{path} ({size} bytes)"
        )
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise AggregatorError(f"baselines.json invalid: {e}") from e
    if not isinstance(body, dict):
        raise AggregatorError("baselines.json must be a JSON object")
    # B-MED-2: walk every (v1.suite.cli.test) leaf and validate shape.
    v1 = body.get("v1")
    if isinstance(v1, dict):
        for suite_name, suite_v in v1.items():
            if not isinstance(suite_v, dict):
                raise AggregatorError(
                    f"baselines.v1.{suite_name}: must be a JSON object"
                )
            for cli_name, cli_v in suite_v.items():
                if not isinstance(cli_v, dict):
                    raise AggregatorError(
                        f"baselines.v1.{suite_name}.{cli_name}: must be "
                        f"a JSON object"
                    )
                for test_id, leaf in cli_v.items():
                    if not isinstance(leaf, dict):
                        raise AggregatorError(
                            f"baselines.v1.{suite_name}.{cli_name}."
                            f"{test_id}: must be a JSON object"
                        )
                    extra = set(leaf.keys()) - _BASELINE_LEAF_KEYS
                    if extra:
                        raise AggregatorError(
                            f"baselines.v1.{suite_name}.{cli_name}."
                            f"{test_id}: unknown floor key(s) "
                            f"{sorted(extra)} — typo? expected any of "
                            f"{sorted(_BASELINE_LEAF_KEYS)}"
                        )
                    if not (set(leaf.keys()) & _BASELINE_LEAF_KEYS):
                        raise AggregatorError(
                            f"baselines.v1.{suite_name}.{cli_name}."
                            f"{test_id}: must define at least one of "
                            f"{sorted(_BASELINE_LEAF_KEYS)}"
                        )
    return body


def _below_baseline(
    key: tuple[str, str, str], cell: Cell, baselines: dict[str, Any]
) -> bool:
    """Return True if `cell` violates ANY defined floor for `key`.

    H9 R1-B-MED-4: when both `min_total` AND `min_pct` are set, BOTH
    are enforced independently — the cell must satisfy every floor.
    A cell with `total >= min_total` but `total/max_total < min_pct`
    fails. This is the conservative "all floors hold" semantic.

    Edge cases:
    - `max_total <= 0`: pct floor cannot be evaluated; if a `min_pct`
      is set we treat that as a fail (a cell with no scoring budget
      cannot meet a floor). `min_total` is still evaluated.
    """
    suite, test, cli = key
    floors = baselines.get("v1", {}).get(suite, {}).get(cli, {}).get(test)
    if not isinstance(floors, dict):
        return False
    min_total = floors.get("min_total")
    min_pct = floors.get("min_pct")
    if isinstance(min_total, (int, float)) and cell.total < min_total:
        return True
    if isinstance(min_pct, (int, float)):
        if cell.max_total <= 0:
            # Cannot evaluate pct; fail-safe.
            return True
        if (cell.total / cell.max_total) < min_pct:
            return True
    return False


def _check_baseline_gate(run: RunData, baselines: dict[str, Any], err: IO[str]) -> int:
    """Apply the --gate baseline check.

    Returns:
        0 if every cell with a defined baseline is at-or-above floor.
        1 if any cell is below floor. Each violation is logged to `err`.
        Cells without a baseline entry are ignored (not yet covered).
    """
    violations: list[tuple[tuple[str, str, str], Cell]] = [
        (k, c) for k, c in run.cells.items() if _below_baseline(k, c, baselines)
    ]
    if not violations:
        return 0
    err.write("aggregator: baseline-gate violations:\n")
    for (suite, test, cli), c in violations:
        err.write(
            f"  {suite}/{test} cli={cli} "
            f"score={c.total:g}/{c.max_total:g} state={c.state}\n"
        )
    return 1


def _check_full_coverage(
    run: RunData,
    *,
    suite_test_manifests: dict[str, tuple[str, ...]],
    selected_clis: tuple[str, ...],
    err: IO[str],
) -> int:
    """Verify every (suite, test, cli) cell from selection is present.

    Returns 0 if full, 2 if partial. Missing cells logged.
    """
    missing: list[tuple[str, str, str]] = []
    for suite in run.suites_seen:
        for test in suite_test_manifests.get(suite, ()):
            for cli in selected_clis:
                if (suite, test, cli) not in run.cells:
                    missing.append((suite, test, cli))
    if not missing:
        return 0
    err.write(f"aggregator: --full requested but {len(missing)} cells missing:\n")
    for s, t, c in missing[:25]:  # cap output
        err.write(f"  missing: {s}/{t} cli={c}\n")
    if len(missing) > 25:
        err.write(f"  … and {len(missing) - 25} more\n")
    return 2


# ── argparse ──────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="coc-eval/aggregate.py",
        description=(
            "Aggregate coc-eval JSONL records into a matrix. "
            "Default: latest run. Stdlib-only."
        ),
    )
    p.add_argument(
        "--run-id",
        default=None,
        help="explicit run id under coc-eval/results/ (default: latest)",
    )
    p.add_argument(
        "--results-root",
        default=None,
        help="results root dir (default: coc-eval/results/)",
    )
    p.add_argument(
        "--format",
        choices=("pretty", "json", "csv", "md"),
        default="pretty",
        help="output format (default: pretty)",
    )
    p.add_argument(
        "--top",
        type=int,
        default=None,
        help="limit output to top N cells by score descending",
    )
    p.add_argument(
        "--failed-only",
        action="store_true",
        help="restrict output to failed/error cells",
    )
    p.add_argument(
        "--regressions-only",
        action="store_true",
        help="restrict output to cells below baseline (requires baselines)",
    )
    p.add_argument(
        "--gate",
        choices=("baseline",),
        default=None,
        help="apply a gate; 'baseline' exits 1 on any below-floor cell",
    )
    p.add_argument(
        "--baselines-path",
        default=None,
        help="baselines.json path (default: coc-eval/baselines.json)",
    )
    p.add_argument(
        "--full",
        action="store_true",
        help="require all cells from manifest × selected CLIs to be present",
    )
    p.add_argument(
        "--allow-partial",
        action="store_true",
        help="permit partial runs even with --full (override safety)",
    )
    p.add_argument(
        "--include-quarantined",
        action="store_true",
        help="include quarantined tests in the matrix (default: skip)",
    )
    p.add_argument(
        "--allow-stale",
        action="store_true",
        help="permit aggregation of older schema_version (forensic mode)",
    )
    p.add_argument(
        "--validate",
        action="store_true",
        help="validate the run (load + parse) and exit 0 / 1",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 64

    out = sys.stdout
    err = sys.stderr

    results_root = (
        Path(args.results_root).resolve()
        if args.results_root
        else _default_results_root()
    )

    # H9 R1-A-LOW-1: typed exit mapping. `InvalidRunIdError` → 64,
    # `RunNotFoundError` → 78, generic `AggregatorError` → 1.
    try:
        run_dir = _resolve_run_dir(args, results_root)
    except InvalidRunIdError as e:
        err.write(f"aggregator: {e}\n")
        return 64
    except RunNotFoundError as e:
        err.write(f"aggregator: {e}\n")
        return 78
    except AggregatorError as e:
        err.write(f"aggregator: {e}\n")
        return 1

    try:
        run = _load_run(
            run_dir,
            allow_stale=args.allow_stale,
            include_quarantined=args.include_quarantined,
        )
    except AggregatorError as e:
        err.write(f"aggregator: {e}\n")
        return 1

    # H9 R1-B-HIGH-5: quarantine MUST NOT silence canary leaks. If any
    # quarantined cell carried `isolation_breach: True`, surface them
    # via stderr regardless of `--include-quarantined`.
    if run.quarantined_breaches:
        err.write(
            f"aggregator: WARNING — {len(run.quarantined_breaches)} "
            f"quarantined cell(s) carried canary isolation_breach=True:\n"
        )
        for s, t, c in run.quarantined_breaches:
            err.write(f"  isolation_breach: {s}/{t} cli={c}\n")

    if args.validate:
        out.write(
            f"OK: {len(run.cells)} cells across "
            f"{len(run.suites_seen)} suites × {len(run.clis_seen)} clis\n"
        )
        return 0

    # Load baselines if any gate or filter needs them.
    baselines: dict[str, Any] = {}
    if args.gate == "baseline" or args.regressions_only:
        bp = (
            Path(args.baselines_path).resolve()
            if args.baselines_path
            else _default_baselines_path()
        )
        baselines = _load_baselines(bp)

    pairs = _filter_cells(
        run,
        failed_only=args.failed_only,
        regressions_only=args.regressions_only,
        baselines=baselines if baselines else None,
    )
    if args.top is not None:
        # H9 R1-A-MED-3: filter out non-pass states before --top sort.
        # `skipped_*` cells have `max_total=0` and would all rank at
        # ratio 0, polluting the top-N output. Errors are likewise
        # suppressed so `--top N` answers "best N runs" cleanly.
        scoreable = [
            (k, c)
            for k, c in pairs
            if c.state in ("pass", "pass_after_retry") and c.max_total > 0
        ]
        pairs = sorted(
            scoreable,
            key=lambda p: p[1].total / p[1].max_total,
            reverse=True,
        )[: args.top]

    # Render.
    renderers = {
        "pretty": _render_pretty,
        "json": _render_json,
        "csv": _render_csv,
        "md": _render_md,
    }
    renderers[args.format](run, pairs, out)

    # Apply gates AFTER render so the operator sees the matrix even on
    # gate failure.
    rc = 0
    if args.full and not args.allow_partial:
        from lib.validators import SUITE_TEST_MANIFESTS  # noqa: E402

        # H9 R1-B-HIGH-4: default `selected_clis` to whatever CLIs
        # actually emitted records in this run. A single-CLI
        # invocation (cc only) would otherwise be flagged as partial
        # for codex/gemini even though the operator never asked for
        # those. Falls back to an empty tuple if the run was empty,
        # which produces zero missing cells (vacuously full).
        partial_rc = _check_full_coverage(
            run,
            suite_test_manifests=SUITE_TEST_MANIFESTS,
            selected_clis=tuple(sorted(run.clis_seen)),
            err=err,
        )
        if partial_rc:
            rc = partial_rc
    if args.gate == "baseline":
        gate_rc = _check_baseline_gate(run, baselines, err)
        if gate_rc and gate_rc > rc:
            rc = gate_rc

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
