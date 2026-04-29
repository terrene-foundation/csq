"""Tests for `coc-eval/lib/launcher.py` — dataclasses + INV-PERM-1 + registry.

Verifies:
- LaunchInputs/LaunchSpec dataclasses round-trip correctly.
- INV-PERM-1 hard-panic on (suite, cli, permission_mode) mismatch.
- CLI_REGISTRY register/lookup mechanism (R1-UX-11).
- PERMISSION_MODE_MAP coverage for all (suite, cli) cells.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path

import pytest

from lib.launcher import (
    CLI_REGISTRY,
    CLI_TIMEOUT_MS,
    PERMISSION_MODE_MAP,
    SANDBOX_PROFILE_MAP,
    AuthProbeResult,
    CliEntry,
    LaunchInputs,
    LaunchSpec,
    assert_permission_mode_valid,
    register_cli,
)


class TestLaunchInputsDataclass:
    def test_construct_minimal(self):
        inputs = LaunchInputs(
            cli="cc",
            suite="capability",
            fixture_dir=Path("/tmp/fixture"),
            prompt="hello",
            permission_mode="plan",
        )
        assert inputs.cli == "cc"
        assert inputs.timeout_ms is None
        assert inputs.stub_home is None
        assert inputs.home_root is None  # R1-CRIT-02 field default.
        assert inputs.sandbox_profile is None
        assert inputs.extra_env == {}

    def test_construct_full(self):
        inputs = LaunchInputs(
            cli="cc",
            suite="implementation",
            fixture_dir=Path("/tmp/fixture"),
            prompt="diagnose this",
            permission_mode="write",
            timeout_ms=600_000,
            stub_home=Path("/tmp/fixture/_stub_home"),
            home_root=Path("/tmp/fixture/_stub_root"),  # R1-CRIT-02.
            extra_env={"ANTHROPIC_MODEL": "claude-opus-4-7"},
            sandbox_profile="write-confined",  # R1-CRIT-01.
        )
        assert inputs.home_root == Path("/tmp/fixture/_stub_root")
        assert inputs.sandbox_profile == "write-confined"

    def test_frozen(self):
        inputs = LaunchInputs(
            cli="cc",
            suite="capability",
            fixture_dir=Path("/tmp/fixture"),
            prompt="hello",
            permission_mode="plan",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            inputs.cli = "codex"  # type: ignore[misc]

    def test_serialize_via_asdict(self):
        inputs = LaunchInputs(
            cli="cc",
            suite="capability",
            fixture_dir=Path("/tmp/fixture"),
            prompt="hello",
            permission_mode="plan",
        )
        d = dataclasses.asdict(inputs)
        assert d["cli"] == "cc"
        assert d["permission_mode"] == "plan"


class TestLaunchSpecDataclass:
    def test_construct(self):
        spec = LaunchSpec(
            cmd="claude",
            args=("--print", "--permission-mode", "plan", "hello"),
            cwd=Path("/tmp"),
            env={"HOME": "/tmp/_home"},
            sandbox_wrapper=(),
        )
        assert spec.cmd == "claude"
        assert spec.expected_state_on_missing == "skipped_cli_missing"
        assert spec.sandbox_wrapper == ()

    def test_with_sandbox_wrapper(self):
        spec = LaunchSpec(
            cmd="claude",
            args=("--print", "hello"),
            cwd=Path("/tmp"),
            env={},
            sandbox_wrapper=("sandbox-exec", "-f", "profile.sb"),  # R1-CRIT-01.
        )
        assert spec.sandbox_wrapper == ("sandbox-exec", "-f", "profile.sb")

    def test_frozen(self):
        spec = LaunchSpec(cmd="claude", args=(), cwd=Path("/tmp"), env={})
        with pytest.raises(dataclasses.FrozenInstanceError):
            spec.cmd = "codex"  # type: ignore[misc]


class TestAuthProbeResult:
    def test_success(self):
        result = AuthProbeResult(
            ok=True, reason=None, version="claude 2.0.31", probed_at=time.monotonic()
        )
        assert result.ok
        assert result.reason is None

    def test_failure(self):
        result = AuthProbeResult(
            ok=False,
            reason="no credentials.json",
            version="claude 2.0.31",
            probed_at=time.monotonic(),
        )
        assert not result.ok
        assert result.reason is not None


class TestPermissionModeMap:
    """INV-PERM-1: every (suite, cli) cell must have a defined permission_mode."""

    def test_all_cells_covered(self):
        suites = ("capability", "compliance", "safety", "implementation")
        clis = ("cc", "codex", "gemini")
        for suite in suites:
            for cli in clis:
                assert (suite, cli) in PERMISSION_MODE_MAP, f"missing ({suite}, {cli})"

    def test_capability_compliance_safety_are_read_only(self):
        for suite in ("capability", "compliance", "safety"):
            assert PERMISSION_MODE_MAP[(suite, "cc")] == "plan"
            assert PERMISSION_MODE_MAP[(suite, "codex")] == "read-only"
            assert PERMISSION_MODE_MAP[(suite, "gemini")] == "plan"

    def test_implementation_is_write_across_clis(self):
        # Implementation is "write" mode in the table; codex/gemini cells are
        # filtered out at runtime via skipped_artifact_shape (ADR-B), but the
        # table entry exists for INV-PERM-1 lookup.
        for cli in ("cc", "codex", "gemini"):
            assert PERMISSION_MODE_MAP[("implementation", cli)] == "write"


class TestSandboxProfileMap:
    """R1-CRIT-01: implementation × cc requires write-confined sandbox."""

    def test_implementation_cc_sandbox_mandatory(self):
        assert SANDBOX_PROFILE_MAP[("implementation", "cc")] == "write-confined"

    def test_other_cells_no_sandbox(self):
        # capability/compliance/safety: HOME override is primary; sandbox optional.
        for suite in ("capability", "compliance", "safety"):
            for cli in ("cc", "codex", "gemini"):
                assert SANDBOX_PROFILE_MAP[(suite, cli)] is None


class TestCliTimeoutMs:
    def test_gemini_gets_180s(self):
        for suite in ("capability", "compliance", "safety"):
            assert CLI_TIMEOUT_MS[(suite, "gemini")] == 180_000

    def test_cc_codex_get_60s(self):
        for suite in ("capability", "compliance", "safety"):
            assert CLI_TIMEOUT_MS[(suite, "cc")] == 60_000
            assert CLI_TIMEOUT_MS[(suite, "codex")] == 60_000

    def test_implementation_uses_test_def_timeout(self):
        # None signals "use test_def['timeout'] override".
        assert CLI_TIMEOUT_MS[("implementation", "cc")] is None


class TestInvPerm1RuntimeCheck:
    """R2-MED-01: runtime enforcement of permission_mode at spawn time.

    AC-22a: bypass canary — a developer who wires the wrong permission_mode
    aborts at spawn time with `INV-PERM-1 violation`.
    """

    def test_valid_permission_mode_passes(self):
        inputs = LaunchInputs(
            cli="cc",
            suite="compliance",
            fixture_dir=Path("/tmp"),
            prompt="x",
            permission_mode="plan",
        )
        # Should not raise.
        assert_permission_mode_valid(inputs)

    def test_implementation_write_passes(self):
        inputs = LaunchInputs(
            cli="cc",
            suite="implementation",
            fixture_dir=Path("/tmp"),
            prompt="x",
            permission_mode="write",
        )
        assert_permission_mode_valid(inputs)

    def test_safety_with_write_panics(self):
        # Bypass canary (AC-22a): safety suite must NOT use write mode.
        inputs = LaunchInputs(
            cli="cc",
            suite="safety",
            fixture_dir=Path("/tmp"),
            prompt="rm -rf /",
            permission_mode="write",  # WRONG for safety.
        )
        with pytest.raises(RuntimeError, match=r"INV-PERM-1 violation"):
            assert_permission_mode_valid(inputs)

    def test_compliance_with_default_panics(self):
        inputs = LaunchInputs(
            cli="cc",
            suite="compliance",
            fixture_dir=Path("/tmp"),
            prompt="x",
            permission_mode="default",  # not a valid value for compliance.
        )
        with pytest.raises(RuntimeError, match=r"INV-PERM-1 violation"):
            assert_permission_mode_valid(inputs)


class TestCliRegistry:
    """R1-UX-11: CLI registration mechanism — adding a 4th CLI is data, not code."""

    def setup_method(self):
        # Save + clear so each test sees a deterministic registry. cc is
        # registered at module import (H3); restore it in teardown so other
        # test modules that depend on the live registry (e.g. integration
        # canary, smoke tests) see the production state.
        self._saved_registry = dict(CLI_REGISTRY)
        CLI_REGISTRY.clear()

    def teardown_method(self):
        CLI_REGISTRY.clear()
        CLI_REGISTRY.update(self._saved_registry)

    def test_register_and_lookup(self):
        def fake_launcher(
            inputs,
        ):  # noqa: ARG001 — signature mirrors launcher protocol.
            return LaunchSpec(cmd="fake", args=(), cwd=Path("/tmp"), env={})

        def fake_probe():
            return AuthProbeResult(
                ok=True, reason=None, version="fake 0.0", probed_at=0.0
            )

        entry = CliEntry(
            cli_id="noop_cli",
            binary="echo",
            launcher=fake_launcher,
            auth_probe=fake_probe,
        )
        register_cli(entry)

        assert "noop_cli" in CLI_REGISTRY
        assert CLI_REGISTRY["noop_cli"].binary == "echo"
        # Idempotent: re-register overwrites cleanly.
        register_cli(entry)
        assert len(CLI_REGISTRY) == 1


class TestCcRegisteredOnImport:
    """H3: cc auto-registers when `lib.launcher` is imported."""

    def test_cc_entry_present(self):
        # Re-import to defeat the test class above's setup/teardown side-
        # effects. The module-level registration line in launcher.py runs
        # exactly once per process; after the TestCliRegistry teardown
        # restores it, the entry is back.
        assert "cc" in CLI_REGISTRY
        entry = CLI_REGISTRY["cc"]
        assert entry.cli_id == "cc"
        assert entry.binary == "claude"
        assert callable(entry.launcher)
        assert callable(entry.auth_probe)
