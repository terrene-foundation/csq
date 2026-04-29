"""H6 gate — `coc-eval/run.py compliance --cli cc` end-to-end.

Skips cleanly if cc is missing or auth is invalid. Mirrors the H5 capability
integration test pattern (bounded env, --results-root tmp_path, validate
parsed run_id, try/finally + onexc cleanup).

Verifies:
  - 9 JSONL records emitted (one per CM1-CM9) under `<run_id>/compliance-*.jsonl`
  - First and last stdout lines contain `run_id=` (AC-45)
  - All 9 records have a registered final state (pass / pass_after_retry /
    fail / error_*); no record reaches an unknown state
  - post_assertions criteria appear in `score.criteria` for tests that
    declare them (CM1, CM2, CM9)
  - The fixture-substitution audit passes alongside the run

Hardening (mirrors H5-T-1..T-11):
  - parsed run_id validated before any filesystem use
  - cc subprocess inherits a bounded env (no tracing-var passthrough)
  - results land in `tmp_path` via `--results-root`
  - shutil.rmtree uses `onexc` callback that surfaces failures
  - try/finally so a failed assertion still cleans up
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


SUITE = "compliance"

# Bounded env — same as test_capability_cc.py (H5-T-2). NO tracing/debug/
# API-key vars are forwarded; the cc subprocess gets exactly what's
# essential to authenticate and run.
_INHERITED_ENV_KEYS: tuple[str, ...] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
)
_OPTIONAL_INHERITED_KEYS: tuple[str, ...] = ("CLAUDE_CONFIG_DIR",)

_PASS_STATES = {"pass", "pass_after_retry"}
_KNOWN_TERMINAL_STATES = _PASS_STATES | {
    "fail",
    "error_invocation",
    "error_timeout",
    "error_fixture",
    "error_json_parse",
    "skipped_quarantined",
    "skipped_artifact_shape",
    "skipped_cli_auth",
    "skipped_cli_missing",
    "error_token_budget",
}

# Tests with post_assertions per `suites/compliance.py`. The integration test
# asserts these tests' score.criteria includes a fs_assert criterion when the
# CLI exits cleanly — a regression in `_merge_fs_assertions` would silently
# drop the side-effect axis.
_TESTS_WITH_POST_ASSERTIONS = {
    "CM1-refuse-stub",
    "CM2-refuse-hardcoded-secret",
    "CM9-proposal-append-not-overwrite",
}


def _claude_or_skip() -> None:
    if shutil.which("claude") is None:
        pytest.skip("claude binary not on PATH")


def _auth_or_skip() -> None:
    auth.reset_cache()
    probe = auth.probe_auth("cc", SUITE)
    if not probe.ok:
        pytest.skip(f"cc auth probe failed (skipped_cli_auth): {probe.reason!r}")


# Quota-exhaustion sentinels surfaced by the cc binary on stdout/stderr
# when the active account is over its 5h or 7d budget. Both shapes have
# been observed in 2026-04 cycle. The integration test treats this as
# environmental skip — auth is structurally OK but no model call can
# succeed, so the gate cannot meaningfully verify CM1-CM9 behavior.
_QUOTA_EXHAUSTED_SENTINELS: tuple[str, ...] = (
    "You've hit your limit",
    "rate limit",
    "rate_limit_error",
)


def _quota_exhausted_in_records(records: list[dict[str, Any]]) -> bool:
    """Detect quota exhaustion across all attempts of all tests."""
    for r in records:
        if r.get("_header"):
            continue
        body = (r.get("stdout_truncated") or "") + (r.get("stderr_truncated") or "")
        if any(sentinel in body for sentinel in _QUOTA_EXHAUSTED_SENTINELS):
            return True
    return False


def _build_subprocess_env() -> dict[str, str]:
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
    lines = [line for line in stdout.splitlines() if line.strip()]
    assert lines, f"empty stdout; stderr={stderr!r}"
    first = lines[0]
    assert first.startswith(
        "run_id="
    ), f"first stdout line does not begin with run_id=: {first!r}"
    run_id = first.removeprefix("run_id=").strip()
    validate_run_id(run_id)
    return run_id


def _surface_rmtree_failure(func: Any, path: Any, excinfo: BaseException) -> None:
    sys.stderr.write(
        f"warn: cleanup failed for {path!r} via {func.__name__}: {excinfo!r}\n"
    )


def _cleanup(run_dir: Path) -> None:
    if run_dir.exists():
        shutil.rmtree(run_dir, onexc=_surface_rmtree_failure)


def _list_compliance_jsonl(results_root: Path, run_id: str) -> list[Path]:
    return sorted((results_root / run_id).glob(f"{SUITE}-*.jsonl"))


@pytest.mark.integration
def test_compliance_cc_emits_nine_records(tmp_path: Path) -> None:
    _claude_or_skip()
    _auth_or_skip()

    script = Path(__file__).resolve().parents[2] / "run.py"
    results_root = tmp_path / "results"
    results_root.mkdir()
    cmd = [
        sys.executable,
        str(script),
        "compliance",
        "--cli",
        "cc",
        "--results-root",
        str(results_root),
    ]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        # 9 cc calls × ~60s each, sequential, plus retry budget.
        timeout=1500,
        check=False,
        cwd=str(tmp_path),
        env=_build_subprocess_env(),
    )
    run_id = _validate_parsed_run_id(proc.stdout, proc.stderr)
    run_dir = results_root / run_id
    try:
        # AC-45: first AND last stdout lines contain run_id=
        lines = [line for line in proc.stdout.splitlines() if line.strip()]
        assert lines[0].startswith("run_id=")
        assert lines[-1].startswith("run_id=") or "run_id=" in lines[-1]

        jsonls = _list_compliance_jsonl(results_root, run_id)
        assert len(jsonls) == 1, (
            f"expected exactly 1 compliance JSONL; got {len(jsonls)}; "
            f"stderr={proc.stderr[:600]!r}"
        )

        records = list(iter_records(jsonls[0]))
        test_records = [r for r in records if not r.get("_header")]
        assert (
            len(test_records) == 9
        ), f"expected 9 test records; got {len(test_records)}"

        # Quota exhaustion masquerades as `error_invocation` (cc exits with
        # rc=1 after printing "You've hit your limit"). The harness records
        # 9 valid JSONL entries — structurally green — but no model call
        # succeeded. Skip with a specific marker so CI logs make the
        # environmental cause obvious.
        if _quota_exhausted_in_records(records):
            pytest.skip(
                "cc account is quota-exhausted (5h or 7d limit); "
                "swap to an account with available budget via `csq swap N`"
            )

        for rec in test_records:
            assert rec["cli"] == "cc"
            assert isinstance(rec["runtime_ms"], (int, float))
            assert "cli_version" in rec
            assert (
                rec["state"] in _KNOWN_TERMINAL_STATES
            ), f"test {rec['test']} reached unknown state {rec['state']!r}"

            # Tests with post_assertions: when the CLI exits cleanly, the
            # fs_assert criterion(s) must appear in score.criteria. If the
            # CLI errored out (rc!=0/timeout) the runner's error path skips
            # criteria population entirely — both branches are valid; we
            # only enforce when state is a terminal pass/fail.
            if rec["test"] in _TESTS_WITH_POST_ASSERTIONS and rec["state"] in (
                _PASS_STATES | {"fail"}
            ):
                criteria = rec["score"].get("criteria") or []
                fs_assert_criteria = [
                    c for c in criteria if c.get("kind") == "fs_assert"
                ]
                assert fs_assert_criteria, (
                    f"{rec['test']}: post_assertions declared but no "
                    f"fs_assert criterion in score.criteria — "
                    f"_merge_fs_assertions did not run"
                )
    finally:
        _cleanup(run_dir)


@pytest.mark.integration
def test_compliance_cc_single_test_invocation(tmp_path: Path) -> None:
    """AC-11: --test <id> emits exactly 1 test record + 1 header."""
    _claude_or_skip()
    _auth_or_skip()

    script = Path(__file__).resolve().parents[2] / "run.py"
    results_root = tmp_path / "results"
    results_root.mkdir()
    cmd = [
        sys.executable,
        str(script),
        "compliance",
        "--cli",
        "cc",
        "--test",
        "CM1-refuse-stub",
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
        jsonls = _list_compliance_jsonl(results_root, run_id)
        assert len(jsonls) == 1
        records = list(iter_records(jsonls[0]))
        headers = [r for r in records if r.get("_header")]
        test_records = [r for r in records if not r.get("_header")]
        assert len(headers) == 1
        assert len(test_records) == 1
        assert test_records[0]["test"] == "CM1-refuse-stub"
    finally:
        _cleanup(run_dir)


def test_fixture_substitution_audit_passes() -> None:
    """The audit script must report no proprietary product references in
    `coc-eval/fixtures/`. Runs alongside cc execution to catch a same-PR
    regression that adds a Kailash/DataFlow string into a fixture.
    """
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "check-fixture-substitution.sh"
    )
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, (
        f"fixture-substitution audit failed: stdout={proc.stdout!r} "
        f"stderr={proc.stderr!r}"
    )
    assert "OK:" in proc.stdout
