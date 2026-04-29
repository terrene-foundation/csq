"""Tests for `kill_process_group` (INV-RUN-3) and `spawn_cli` orchestration.

INV-RUN-3: a hung CLI MUST be reaped via SIGTERM-then-SIGKILL on the entire
process group, so that subprocess children survive neither the timeout nor
the grace window. AC-19a: a child that ignores SIGTERM is still killed
within `grace_secs` after the grace expires.

`spawn_cli` end-to-end coverage uses a fake `claude` binary written into a
tmp dir. The fake exits 0 with a synthetic stdout banner; the real auth
probe + cc launcher tests exercise the path against the user's binary.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from lib.launcher import (
    LaunchInputs,
    LaunchSpec,
    kill_process_group,
    spawn_cli,
)


def _spawn_python_helper(src: Path) -> subprocess.Popen[str]:
    """Spawn a Python helper with a fresh session group (matches `spawn_cli`).

    Used directly here to isolate `kill_process_group` from the rest of
    `spawn_cli`'s contract (INV-PERM-1 + INV-ISO-6) — those have their own
    coverage in `test_launcher.py` / `test_cc_launcher.py`.
    """
    return subprocess.Popen(  # noqa: S603 — explicit argv list, shell=False.
        [sys.executable, str(src)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        text=True,
    )


def _wait_for_line(proc: subprocess.Popen[str], needle: str, timeout: float) -> None:
    """Block until the helper writes a sync banner or the timeout elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = proc.stdout.readline() if proc.stdout else ""
        if needle in line:
            return
        if line == "" and proc.poll() is not None:
            raise RuntimeError(f"helper exited prematurely, rc={proc.returncode}")
    raise TimeoutError(f"sync line {needle!r} not seen within {timeout}s")


class TestKillProcessGroupSigtermIgnoringChild:
    """AC-19a — a SIGTERM-ignoring child gets SIGKILLed after grace expiry."""

    def test_sigterm_ignoring_child_killed_by_sigkill(self, tmp_path: Path) -> None:
        helper = tmp_path / "trap_sigterm.py"
        helper.write_text(
            textwrap.dedent(
                """
                import os, signal, sys, time
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                sys.stdout.write("ready\\n"); sys.stdout.flush()
                time.sleep(99999)
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        proc = _spawn_python_helper(helper)
        try:
            _wait_for_line(proc, "ready", timeout=5.0)
            start = time.monotonic()
            rc = kill_process_group(proc, grace_secs=1.0)
            elapsed = time.monotonic() - start
        finally:
            # Defensive cleanup if the test asserts before we get here.
            if proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    pass
                proc.wait(timeout=2.0)

        assert rc is not None, "process not reaped within SIGKILL window"
        # Must be killed within (grace_secs + buffer). Spec says <5s.
        assert elapsed < 5.0, f"reaper took {elapsed:.2f}s, expected <5.0s"


class TestKillProcessGroupAlreadyDead:
    def test_already_exited_returns_returncode(self, tmp_path: Path) -> None:
        helper = tmp_path / "exit_immediately.py"
        helper.write_text(
            "import sys\nsys.exit(7)\n",
            encoding="utf-8",
        )
        proc = _spawn_python_helper(helper)
        # Wait for natural exit so the kill path takes the early-return branch.
        proc.wait(timeout=5.0)
        assert proc.returncode == 7
        rc = kill_process_group(proc, grace_secs=1.0)
        assert rc == 7


class TestKillProcessGroupCooperativeChild:
    """A SIGTERM-respecting child exits BEFORE grace expires; total elapsed
    time MUST be much less than grace_secs.
    """

    def test_cooperative_child_exits_quickly(self, tmp_path: Path) -> None:
        helper = tmp_path / "cooperative.py"
        helper.write_text(
            textwrap.dedent(
                """
                import sys, time
                # Default SIGTERM handler exits the process immediately.
                sys.stdout.write("ready\\n"); sys.stdout.flush()
                time.sleep(99999)
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        proc = _spawn_python_helper(helper)
        try:
            _wait_for_line(proc, "ready", timeout=5.0)
            start = time.monotonic()
            rc = kill_process_group(proc, grace_secs=5.0)
            elapsed = time.monotonic() - start
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2.0)

        assert rc is not None
        # Cooperative SIGTERM exit should be sub-second on any sane host.
        assert elapsed < 2.0, f"cooperative kill took {elapsed:.2f}s"


def _make_executable(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class TestSpawnCliEndToEnd:
    """End-to-end smoke for `spawn_cli` with a fake binary that prints to
    stdout and exits 0. Exercises INV-PERM-1 (passes for valid mode), the
    skip-of-INV-ISO-6 when stub_home is None, and the start_new_session
    process-group setup so kill_process_group can find a pgid.
    """

    def test_spawn_returns_running_proc(self, tmp_path: Path) -> None:
        fake = _make_executable(
            tmp_path / "claude",
            '#!/bin/sh\necho "hello-from-fake-claude"\nexit 0\n',
        )
        spec = LaunchSpec(
            cmd=str(fake),
            args=("--print", "ping"),
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", "")},
            sandbox_wrapper=(),
        )
        inputs = LaunchInputs(
            cli="cc",
            suite="capability",
            fixture_dir=tmp_path,
            prompt="ping",
            permission_mode="plan",
        )
        proc = spawn_cli(spec, inputs)
        try:
            stdout, _ = proc.communicate(timeout=5.0)
        finally:
            if proc.poll() is None:
                kill_process_group(proc, grace_secs=1.0)
        assert proc.returncode == 0
        assert "hello-from-fake-claude" in stdout

    def test_spawn_aborts_on_inv_perm_1_violation(self, tmp_path: Path) -> None:
        fake = _make_executable(
            tmp_path / "claude",
            "#!/bin/sh\nexit 0\n",
        )
        spec = LaunchSpec(
            cmd=str(fake),
            args=(),
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", "")},
            sandbox_wrapper=(),
        )
        # safety + write is the canonical AC-22a violation.
        inputs = LaunchInputs(
            cli="cc",
            suite="safety",
            fixture_dir=tmp_path,
            prompt="rm -rf /",
            permission_mode="write",
        )
        with pytest.raises(RuntimeError, match=r"INV-PERM-1 violation"):
            spawn_cli(spec, inputs)

    def test_spawn_aborts_on_missing_credential_symlink(self, tmp_path: Path) -> None:
        # When stub_home is set but the credential symlink is missing,
        # INV-ISO-6 must abort BEFORE the binary is invoked.
        stub = tmp_path / "_stub_home"
        stub.mkdir()
        # No `.credentials.json` symlink — the revalidator should refuse.

        fake = _make_executable(
            tmp_path / "claude",
            "#!/bin/sh\nexit 0\n",
        )
        spec = LaunchSpec(
            cmd=str(fake),
            args=(),
            cwd=tmp_path,
            env={"PATH": os.environ.get("PATH", ""), "CLAUDE_CONFIG_DIR": str(stub)},
            sandbox_wrapper=(),
        )
        inputs = LaunchInputs(
            cli="cc",
            suite="compliance",
            fixture_dir=tmp_path,
            prompt="x",
            permission_mode="plan",
            stub_home=stub,
        )
        with pytest.raises(RuntimeError, match=r"INV-ISO-6 violation"):
            spawn_cli(spec, inputs)
