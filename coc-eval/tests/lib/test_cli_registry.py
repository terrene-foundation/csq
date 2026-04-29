"""AC-42 — CLI registry stub mechanism works without launcher table edits.

A new CLI registers via `register_cli(CliEntry(...))`. The registry is the
only authority — adding a CLI is a registration, not an architectural
change (R1-UX-11). Runner consults `CLI_REGISTRY` for binary discovery
and probe dispatch.
"""

from __future__ import annotations

import time

from lib.launcher import (
    CLI_REGISTRY,
    AuthProbeResult,
    CliEntry,
    LaunchInputs,
    LaunchSpec,
)


def _noop_launcher(inputs: LaunchInputs) -> LaunchSpec:
    return LaunchSpec(
        cmd="/bin/true",
        args=(),
        cwd=inputs.fixture_dir,
        env={"PATH": "/bin:/usr/bin"},
    )


def _noop_probe() -> AuthProbeResult:
    return AuthProbeResult(
        ok=False,
        reason="noop probe never authenticates",
        version="noop-1.0.0",
        probed_at=time.monotonic(),
    )


def test_register_noop_cli_appears_in_registry(monkeypatch) -> None:
    """`register_cli` is the single mechanism — no launcher-table edit required.

    H5-T-5: use `monkeypatch.setitem` for auto-restore on failure.
    """
    monkeypatch.setitem(
        CLI_REGISTRY,
        "noop_cli",
        CliEntry(
            cli_id="noop_cli",
            binary="/bin/true",
            launcher=_noop_launcher,
            auth_probe=_noop_probe,
        ),
    )
    assert "noop_cli" in CLI_REGISTRY
    assert CLI_REGISTRY["noop_cli"].binary == "/bin/true"
    result = CLI_REGISTRY["noop_cli"].auth_probe()
    assert result.ok is False
    assert result.version == "noop-1.0.0"


def test_register_overrides_existing_entry(monkeypatch) -> None:
    """Re-registering replaces the previous entry (test-mock pattern).

    H5-T-5: use `monkeypatch.setitem` so the registry is auto-restored
    on test failure or interrupt — try/finally only covers the happy
    path; an assertion-fail or KeyboardInterrupt mid-test would leave
    the global registry mocked for every subsequent test in the worker.
    """
    original = CLI_REGISTRY["cc"]

    def replacement_probe() -> AuthProbeResult:
        return AuthProbeResult(ok=True, reason=None, version="mocked", probed_at=0.0)

    monkeypatch.setitem(
        CLI_REGISTRY,
        "cc",
        CliEntry(
            cli_id="cc",
            binary=original.binary,
            launcher=original.launcher,
            auth_probe=replacement_probe,
        ),
    )
    assert CLI_REGISTRY["cc"].auth_probe().version == "mocked"


def test_phase1_registry_contains_only_cc() -> None:
    """Phase 1 ships exactly one CLI entry — codex/gemini land in H10/H11."""
    assert set(CLI_REGISTRY.keys()) == {"cc"}
