"""C1-baseline-root smoke — cc launcher contract validates end-to-end.

Per H3 todo "Smoke integration": run a single capability test against the
real cc binary + stub HOME + real auth probe, and confirm the marker from
the loom-ported `baseline-cc/CLAUDE.md` surfaces in cc's output. This is a
pre-cursor to H5 (capability suite); the assertion only validates the
launcher CONTRACT, not full capability scoring.

Skips cleanly if cc is missing or auth is invalid — H3's launcher table
maps both to `skipped_cli_*` states in the runner, so a missing-auth box
produces an unambiguous skip rather than a noisy false fail.
"""

from __future__ import annotations

import os
import shutil
import subprocess

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

EXPECTED_MARKER = "MARKER_CC_BASE=cc-base-loaded-CC9A1"
SUITE = "capability"


@pytest.mark.integration
def test_c1_baseline_root_marker_emitted() -> None:
    if shutil.which("claude") is None:
        pytest.skip("claude binary not on PATH")

    fixture_dir = prepare_fixture("baseline-cc")
    stub_home, home_root = build_stub_home(SUITE, fixture_dir)

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home_root),
        "CLAUDE_CONFIG_DIR": str(stub_home),
    }
    auth.reset_cache()
    probe = auth.probe_auth("cc", SUITE, env=env)
    if not probe.ok:
        pytest.skip(
            f"cc auth probe failed (skipped_cli_auth path); reason: {probe.reason!r}"
        )

    prompt = (
        "List every line in your loaded context that starts with the string "
        "'MARKER_'. Output them verbatim, one per line. If none, say 'no markers'."
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

    assert proc.returncode == 0, f"cc exited rc={proc.returncode}; stdout={stdout!r}"
    assert EXPECTED_MARKER in stdout, (
        f"baseline-cc CLAUDE.md did not surface in cc's response. The "
        f"H3 launcher contract is broken: cc's CLAUDE.md auto-load did NOT "
        f"see the project memory at {fixture_dir / 'CLAUDE.md'}.\n"
        f"Expected substring: {EXPECTED_MARKER!r}\n"
        f"Got stdout (first 600 chars): {stdout[:600]!r}"
    )
