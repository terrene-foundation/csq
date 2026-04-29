"""AC-32 / R3-MED-03 — zero-auth first-run banner exits 78.

Mocks `auth.probe_auth` to always return `ok=False`; calls
`runner.run(...)` and asserts:
  - exit code 78 (EX_CONFIG)
  - banner naming each CLI's auth source + login command
  - no JSONL files created
"""

from __future__ import annotations

import io
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from lib import auth, runner
from lib.launcher import AuthProbeResult


# H5-T-6: the autouse cache reset moved to `tests/integration/conftest.py`
# so it covers EVERY integration test, not just this file.


def _patch_probe_to_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail_probe(cli, suite, env=None):
        return AuthProbeResult(
            ok=False,
            reason=f"mocked auth failure for {cli}",
            version="0.0.0-mock",
            probed_at=time.monotonic(),
        )

    monkeypatch.setattr(auth, "probe_auth", _fail_probe)


def test_zero_auth_exits_78(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_probe_to_fail(monkeypatch)
    sel = runner.resolve_selection("capability", "cc")
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = runner.run(
            sel,
            base_results_dir=tmp_path,
            skip_gitignore_check=True,
        )
    assert rc == 78
    err_text = err.getvalue()
    assert "no CLI has working authentication" in err_text
    assert "cc:" in err_text
    assert "csq login" in err_text or "claude auth login" in err_text
    # No JSONL files were created (we never reached the run loop).
    assert not list(tmp_path.glob("**/*.jsonl"))


def test_zero_auth_first_and_last_stdout_have_run_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """AC-45 holds even on the zero-auth path."""
    _patch_probe_to_fail(monkeypatch)
    sel = runner.resolve_selection("capability", "cc")
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = runner.run(
            sel,
            base_results_dir=tmp_path,
            skip_gitignore_check=True,
        )
    assert rc == 78
    lines = [line for line in out.getvalue().splitlines() if line.strip()]
    assert lines, "stdout was empty; AC-45 violated"
    assert lines[0].startswith("run_id=")
    assert lines[-1].startswith("run_id=")
