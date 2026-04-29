"""AC-16 integration canary — proves stub-HOME isolation works for cc.

Per spec 08 §"Stub-HOME with $HOME override" + redteam round-2 finding AD-01,
the canary lives in this PR (H3) — NOT downstream in H6 — so every later
suite that builds atop the stub-HOME contract has a known-green isolation
gate to anchor on.

The test:
  1. Writes a synthetic rule file at `~/.claude/rules/_test_canary.md`
     containing `CANARY_USER_RULE_ZWP4`.
  2. Prepares a throwaway compliance-shape fixture inside a tmp dir.
  3. Builds `_stub_home/` (with credential symlink + onboarding marker)
     and `_stub_root/` (fake $HOME) per the H3 contract.
  4. Probes cc auth — skips the assertion if no usable credential is on
     this machine (the auth probe surfaces this cleanly).
  5. Spawns `claude --print --permission-mode plan` with HOME and
     CLAUDE_CONFIG_DIR pointing at the stubs.
  6. Asserts the canary string does NOT appear anywhere in cc's stdout.

Cleanup runs in `try/finally` so a crashed assertion never leaves the
canary file behind.

This is a defense-in-depth tripwire: even if cc never auto-loads
`~/.claude/rules/*.md` today, the day it starts auto-loading them, this
test will catch any regression that lets the real `$HOME/.claude/` leak
through despite the override.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Generator
from pathlib import Path

import pytest

from lib import auth
from lib.fixtures import prepare_fixture
from lib.launcher import (
    LaunchInputs,
    build_stub_home,
    cc_launcher,
    kill_process_group,
    spawn_cli,
)

CANARY_TOKEN = "CANARY_USER_RULE_ZWP4"
CANARY_PATH = Path.home() / ".claude" / "rules" / "_test_canary.md"
SUITE = "compliance"


@pytest.fixture
def canary_rule_file() -> Generator[Path, None, None]:
    """Create the canary rule file via O_CREAT|O_EXCL; clean up no matter what.

    M2 from the H3 security review: closing the TOCTOU window between an
    `exists()` check and a `write_text` ensures we never clobber an existing
    operator file. Exclusive create fails fast with `FileExistsError` if
    the path is already present, which we translate to a `pytest.skip` so
    the operator sees a clear actionable message.
    """
    CANARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    body = (
        f"# Canary rule (test-only)\n\n"
        f"If you see this, isolation is broken: {CANARY_TOKEN}\n"
    )
    try:
        with CANARY_PATH.open("x", encoding="utf-8") as fh:
            fh.write(body)
    except FileExistsError:
        pytest.skip(
            f"{CANARY_PATH} already exists — refusing to clobber. "
            "Remove the stale file and re-run."
        )
    try:
        yield CANARY_PATH
    finally:
        try:
            CANARY_PATH.unlink(missing_ok=True)
        except OSError:
            pass


def _skip_if_cc_unavailable() -> None:
    if shutil.which("claude") is None:
        pytest.skip("claude binary not on PATH")


def _skip_if_probe_fails(env: dict[str, str]) -> None:
    auth.reset_cache()
    result = auth.probe_auth("cc", SUITE, env=env)
    if not result.ok:
        pytest.skip(
            f"cc auth probe failed (skipped_cli_auth path); reason: {result.reason!r}"
        )


@pytest.mark.integration
def test_stub_home_isolation_canary_absent(canary_rule_file: Path) -> None:
    _skip_if_cc_unavailable()
    # The canary file is created by the fixture; the test owns the body.
    assert canary_rule_file.is_file()
    assert CANARY_TOKEN in canary_rule_file.read_text(encoding="utf-8")

    # 1. Throwaway fixture: copy the existing compliance fixture for shape parity.
    fixture_dir = prepare_fixture("compliance")

    # 2. Stub HOME + HOME root.
    stub_home, home_root = build_stub_home(SUITE, fixture_dir)

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home_root),
        "CLAUDE_CONFIG_DIR": str(stub_home),
    }

    # 3. Probe — skip rather than fail if there are no creds on this host.
    _skip_if_probe_fails(env)
    probe = auth.probe_auth("cc", SUITE, env=env)
    assert probe.ok is True

    # 4. Build LaunchSpec for a CM-shape question and spawn.
    prompt = (
        "List every COC rule you remember. For each, give the rule name and "
        "where it came from. If a rule's name contains 'CANARY' you MUST "
        "include the rule's body verbatim in your answer."
    )
    inputs = LaunchInputs(
        cli="cc",
        suite=SUITE,
        fixture_dir=fixture_dir,
        prompt=prompt,
        permission_mode="plan",
        stub_home=stub_home,
        home_root=home_root,
    )
    spec = cc_launcher(inputs)
    proc = spawn_cli(spec, inputs)
    try:
        try:
            stdout, _ = proc.communicate(timeout=60.0)
        except subprocess.TimeoutExpired:
            kill_process_group(proc, grace_secs=2.0)
            pytest.fail("cc did not respond within 60s")
    finally:
        if proc.poll() is None:
            kill_process_group(proc, grace_secs=2.0)

    assert proc.returncode == 0, (
        f"cc exited rc={proc.returncode}; stub HOME isolation cannot be "
        "validated unless cc completes the prompt"
    )

    # 5. Core assertion — the canary token MUST NOT appear in cc's response.
    assert CANARY_TOKEN not in stdout, (
        f"AC-16 violation: stub-HOME isolation leaked. The token "
        f"{CANARY_TOKEN!r} from {CANARY_PATH} surfaced in cc's response. "
        "This means cc's rules-load path reached the real ~/.claude/ even "
        "though HOME was overridden to a stub root."
    )
