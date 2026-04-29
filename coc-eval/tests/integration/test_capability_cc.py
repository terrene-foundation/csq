"""H5 gate — `coc-eval/run.py capability --cli cc` end-to-end.

Skips cleanly if cc is missing or auth is invalid (the H3 launcher table
maps these to `skipped_cli_*` states; integration tests should not noisily
fail on missing-auth boxes).

Verifies:
  - 4 JSONL records emitted (one per C1-C4) under `<run_id>/capability-*.jsonl`
  - First and last stdout lines contain `run_id=` (AC-45)
  - C1, C2, C4 deterministic states pass; C3 is informational (model-fragile)
  - Each record carries `cli_version`, `runtime_ms`
  - Single-test mode (--test C1-baseline-root) emits exactly 1 test record

Hardening (security review round 1):
  - H5-T-1: parsed run_id is validated before any filesystem use
  - H5-T-2: cc subprocess inherits a bounded env (no tracing-var passthrough)
  - H5-T-3: results land in `tmp_path` via `--results-root`, not `coc-eval/results/`
  - H5-T-10: shutil.rmtree uses an `onerror=` callback that surfaces failures
  - H5-T-11: try/finally on both tests so a failed assertion still cleans up
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from lib import auth
from lib.jsonl import iter_records
from lib.run_id import validate_run_id


SUITE = "capability"

# Env vars that MAY be forwarded to the cc subprocess. PATH + HOME are
# essential. CLAUDE_CONFIG_DIR is forwarded only if the developer has
# explicitly set it (e.g. running under a csq handle dir). Everything
# else (ANTHROPIC_LOG, CLAUDE_TRACE, CLAUDE_DEBUG, ANTHROPIC_API_KEY)
# is intentionally NOT inherited — H5-T-2.
_INHERITED_ENV_KEYS: tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)
_OPTIONAL_INHERITED_KEYS: tuple[str, ...] = ("CLAUDE_CONFIG_DIR",)


def _claude_or_skip() -> None:
    if shutil.which("claude") is None:
        pytest.skip("claude binary not on PATH")


def _auth_or_skip() -> None:
    auth.reset_cache()
    probe = auth.probe_auth("cc", SUITE)
    if not probe.ok:
        pytest.skip(f"cc auth probe failed (skipped_cli_auth): {probe.reason!r}")


def _build_subprocess_env() -> dict[str, str]:
    """Bounded env — no tracing vars, no API keys (H5-T-2)."""
    env: dict[str, str] = {
        "PYTHONUNBUFFERED": "1",
        "TERM": "dumb",  # force jsonl format (no isatty)
    }
    for key in _INHERITED_ENV_KEYS:
        v = os.environ.get(key)
        if v is not None:
            env[key] = v
    for key in _OPTIONAL_INHERITED_KEYS:
        v = os.environ.get(key)
        if v is not None:
            env[key] = v
    return env


def _validate_parsed_run_id(stdout: str, stderr: str) -> str:
    """Parse `run_id=...` from stdout and validate via RUN_ID_RE.

    H5-T-1: an attacker-influenced or buggy stdout line `run_id=../..` would
    feed `shutil.rmtree` a path outside `tmp_path`. Validating against
    the closed regex (RUN_ID_RE) bounds path traversal at the boundary.
    """
    lines = [line for line in stdout.splitlines() if line.strip()]
    assert lines, f"empty stdout; stderr={stderr!r}"
    first = lines[0]
    assert first.startswith(
        "run_id="
    ), f"first stdout line does not begin with run_id=: {first!r}"
    run_id = first.removeprefix("run_id=").strip()
    validate_run_id(run_id)  # raises ValueError on garbage / empty / traversal
    return run_id


def _surface_rmtree_failure(func: Any, path: Any, excinfo: BaseException) -> None:
    """`onexc` callback that surfaces failures instead of swallowing.

    H5-T-10: `ignore_errors=True` masks real cleanup problems (in-use
    files on macOS, permission errors). Surfacing via stderr means CI
    captures the warning even though the test still completes.
    """
    sys.stderr.write(
        f"warn: cleanup failed for {path!r} via {func.__name__}: {excinfo!r}\n"
    )


def _cleanup(run_dir: Path) -> None:
    if run_dir.exists():
        shutil.rmtree(run_dir, onexc=_surface_rmtree_failure)


def _list_capability_jsonl(results_root: Path, run_id: str) -> list[Path]:
    return sorted((results_root / run_id).glob(f"{SUITE}-*.jsonl"))


@pytest.mark.integration
def test_capability_cc_emits_four_pass_records(tmp_path: Path) -> None:
    _claude_or_skip()
    _auth_or_skip()

    script = Path(__file__).resolve().parents[2] / "run.py"
    results_root = tmp_path / "results"
    results_root.mkdir()
    cmd = [
        sys.executable,
        str(script),
        "capability",
        "--cli",
        "cc",
        "--results-root",
        str(results_root),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,  # generous: 4 cc calls × ~60s each, sequential
        check=False,
        cwd=str(tmp_path),  # NOT script.parent — keep cwd in tmp_path (T-2)
        env=_build_subprocess_env(),
    )
    run_id = _validate_parsed_run_id(proc.stdout, proc.stderr)
    run_dir = results_root / run_id
    try:
        # AC-45: first AND last stdout lines contain run_id=
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        assert lines[0].startswith("run_id=")
        assert lines[-1].startswith("run_id=") or "run_id=" in lines[-1]

        jsonls = _list_capability_jsonl(results_root, run_id)
        assert len(jsonls) == 1, (
            f"expected exactly 1 capability JSONL; got {len(jsonls)}; "
            f"stderr={proc.stderr[:600]!r}"
        )

        records = list(iter_records(jsonls[0]))
        test_records = [r for r in records if not r.get("_header")]
        assert (
            len(test_records) == 4
        ), f"expected 4 test records; got {len(test_records)}"

        # C1, C2, C4 are deterministic on cc — they MUST reach pass /
        # pass_after_retry. C3 (pathscoped-canary) is informational per the
        # H5 todo's "Risk" section: it depends on cc auto-injecting the
        # `paths:`-frontmatter rule, which is empirically observed but
        # version-fragile. The harness contract (record emitted, score
        # computed, schema valid) is enforced unconditionally.
        pass_states = {"pass", "pass_after_retry"}
        deterministic_tests = {
            "C1-baseline-root",
            "C2-baseline-subdir",
            "C4-native-subagent",
        }
        for rec in test_records:
            assert rec["cli"] == "cc"
            assert isinstance(rec["runtime_ms"], (int, float))
            assert rec["runtime_ms"] > 0
            assert "cli_version" in rec
            assert rec["state"] in (
                pass_states | {"fail", "error_invocation", "error_timeout"}
            ), f"test {rec['test']} reached unknown state {rec['state']!r}"

            if rec["test"] in deterministic_tests:
                assert rec["state"] in pass_states, (
                    f"deterministic test {rec['test']} reached state "
                    f"{rec['state']!r} (expected pass)\n"
                    f"score: {rec.get('score')}\n"
                    f"stderr: {rec.get('stderr_truncated', '')[:200]}"
                )
                assert rec["score"]["pass"] is True
            elif rec["test"] == "C3-pathscoped-canary":
                assert (
                    rec["score"]["max_total"] == 1.0
                ), "C3 score must always evaluate the canary criterion"
    finally:
        _cleanup(run_dir)


@pytest.mark.integration
def test_capability_cc_single_test_invocation(tmp_path: Path) -> None:
    """AC-11: --test <id> emits exactly 1 test record + 1 header."""
    _claude_or_skip()
    _auth_or_skip()

    script = Path(__file__).resolve().parents[2] / "run.py"
    results_root = tmp_path / "results"
    results_root.mkdir()
    cmd = [
        sys.executable,
        str(script),
        "capability",
        "--cli",
        "cc",
        "--test",
        "C1-baseline-root",
        "--results-root",
        str(results_root),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        cwd=str(tmp_path),
        env=_build_subprocess_env(),
    )
    run_id = _validate_parsed_run_id(proc.stdout, proc.stderr)
    run_dir = results_root / run_id
    try:
        jsonls = _list_capability_jsonl(results_root, run_id)
        assert len(jsonls) == 1
        records = list(iter_records(jsonls[0]))
        headers = [r for r in records if r.get("_header")]
        test_records = [r for r in records if not r.get("_header")]
        assert len(headers) == 1
        assert len(test_records) == 1
        assert test_records[0]["test"] == "C1-baseline-root"
    finally:
        _cleanup(run_dir)
