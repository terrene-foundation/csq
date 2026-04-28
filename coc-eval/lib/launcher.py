"""Per-CLI launcher dataclasses + INV-PERM-1 runtime check + CLI registry.

Mirrors loom's `CLI_COMMANDS` shape (`harness.mjs:88-139`). Launcher behavior
is split between this module (dataclasses + registry + invariant check) and
later PRs (H3 cc, H10 codex, H11 gemini) which register concrete launchers.

R1+R2 changes:
- `home_root` field on LaunchInputs (R1-CRIT-02): `$HOME` override for
  capability/compliance/safety. Closes the model-tool-access credential-exfil
  path that stub-HOME alone (CLAUDE_CONFIG_DIR override) does not close.
- `sandbox_wrapper` field on LaunchSpec (R1-CRIT-01): bwrap/sandbox-exec
  argv prefix for implementation suite. Phase 1 ships `bwrap` (Linux) +
  `sandbox-exec` (macOS); Windows is gated out at argparse.
- `CliId = str` (R1-UX-11): NOT closed Literal. Suites are closed Literal
  because they map to COC methodology layers; CLIs are open because new
  model-CLIs ship continuously.
- INV-PERM-1 runtime check (R2-HIGH-01 vs R2-MED-01): at spawn time,
  asserts (suite, cli) → permission_mode matches the per-suite × per-CLI
  table. Mismatch is a hard panic. Bypass requires editing two files in
  the same PR.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal, Mapping

# CLI identifier: open string type (not Literal). Validated at runtime against
# CLI_REGISTRY.keys() in `validators.validate_cli_id`.
CliId = str

# Suite identifier: closed Literal. Maps to COC methodology layers
# (capability/compliance/safety/implementation). Adding a suite is a
# methodology-level change, not a continuous-integration concern.
SuiteId = Literal["capability", "compliance", "safety", "implementation"]

# Permission mode applied to the spawned CLI process.
PermissionMode = Literal["plan", "read-only", "write", "default"]

# Sandbox profile selector (per-CLI launcher chooses the wrapper argv).
SandboxProfile = Literal["none", "read-only", "write-confined"]


@dataclass(frozen=True)
class LaunchInputs:
    """Inputs to a per-CLI launcher function."""

    cli: CliId
    suite: SuiteId
    fixture_dir: (
        Path  # Already-prepared, isolated copy (or coc-env for implementation).
    )
    prompt: str  # Byte-identical across CLIs (INV-PAR-1).
    permission_mode: PermissionMode
    timeout_ms: int | None = None  # None → CLI_TIMEOUT_MS[(suite, cli)].
    stub_home: Path | None = (
        None  # cc/codex; None for gemini (no documented config-dir env).
    )
    home_root: Path | None = None  # NEW R1: fake $HOME root with empty .ssh/.codex/etc.
    extra_env: Mapping[str, str] = field(default_factory=dict)
    sandbox_profile: SandboxProfile | None = (
        None  # implementation suite uses write-confined.
    )


@dataclass(frozen=True)
class LaunchSpec:
    """Output of a per-CLI launcher function — argv + env + cwd to spawn."""

    cmd: str  # Absolute or PATH-resolved binary.
    args: tuple[str, ...]  # Argv after cmd.
    cwd: Path  # Almost always == fixture_dir.
    env: Mapping[str, str]  # Full env, NOT merged at the call site.
    sandbox_wrapper: tuple[
        str, ...
    ] = ()  # NEW R1: bwrap/sandbox-exec prefix; () for unsandboxed.
    expected_state_on_missing: Literal["skipped_cli_missing"] = "skipped_cli_missing"


@dataclass(frozen=True)
class AuthProbeResult:
    """Result of a per-CLI authentication probe."""

    ok: bool
    reason: str | None  # None on success.
    version: str  # CLI version string from `<cli> --version`.
    probed_at: float  # `time.monotonic()` ts for re-probe interval tracking.


# Per-suite × per-CLI permission-mode authority table.
# INV-PERM-1: launcher MUST assert spawn-time `(suite, cli)` matches this table.
# Mismatch is a hard panic, not a warning.
PERMISSION_MODE_MAP: dict[tuple[SuiteId, CliId], PermissionMode] = {
    # capability — read-only behavior across CLIs.
    ("capability", "cc"): "plan",
    ("capability", "codex"): "read-only",
    ("capability", "gemini"): "plan",
    # compliance — same.
    ("compliance", "cc"): "plan",
    ("compliance", "codex"): "read-only",
    ("compliance", "gemini"): "plan",
    # safety — same.
    ("safety", "cc"): "plan",
    ("safety", "codex"): "read-only",
    ("safety", "gemini"): "plan",
    # implementation — write mode (cc-only Phase 1; codex/gemini = skipped_artifact_shape).
    ("implementation", "cc"): "write",
    ("implementation", "codex"): "write",
    ("implementation", "gemini"): "write",
}


# Per-suite × per-CLI sandbox profile.
# capability/compliance/safety: HOME override is primary defense; sandbox optional.
# implementation × cc: sandbox MANDATORY (R1-CRIT-01).
# implementation × codex/gemini: Phase 1 skipped_artifact_shape.
SANDBOX_PROFILE_MAP: dict[tuple[SuiteId, CliId], SandboxProfile | None] = {
    ("capability", "cc"): None,
    ("capability", "codex"): None,
    ("capability", "gemini"): None,
    ("compliance", "cc"): None,
    ("compliance", "codex"): None,
    ("compliance", "gemini"): None,
    ("safety", "cc"): None,
    ("safety", "codex"): None,
    ("safety", "gemini"): None,
    ("implementation", "cc"): "write-confined",
    ("implementation", "codex"): None,  # skipped_artifact_shape Phase 1.
    ("implementation", "gemini"): None,  # skipped_artifact_shape Phase 1.
}


# Per-suite × per-CLI timeout table (milliseconds).
# Implementation × cc uses test_def["timeout"] override (None = use per-test value).
CLI_TIMEOUT_MS: dict[tuple[SuiteId, CliId], int | None] = {
    ("capability", "cc"): 60_000,
    ("capability", "codex"): 60_000,
    ("capability", "gemini"): 180_000,
    ("compliance", "cc"): 60_000,
    ("compliance", "codex"): 60_000,
    ("compliance", "gemini"): 180_000,
    ("safety", "cc"): 60_000,
    ("safety", "codex"): 60_000,
    ("safety", "gemini"): 180_000,
    ("implementation", "cc"): None,  # use test_def["timeout"] (default 600s).
    ("implementation", "codex"): None,
    ("implementation", "gemini"): None,
}


@dataclass(frozen=True)
class CliEntry:
    """One row in CLI_REGISTRY — registers a CLI's launcher + probe + defaults.

    Adding a 4th CLI in v1.1 (e.g., a native csq CLI for Phase 2b) is a
    registration, not an architectural change. The launcher function and
    auth probe function are populated by H3 (cc), H10 (codex), H11 (gemini).
    """

    cli_id: CliId
    binary: str  # Resolved via shutil.which().
    launcher: Callable[[LaunchInputs], LaunchSpec]
    auth_probe: Callable[[], AuthProbeResult]


# CLI registry. Populated at module import time by H3/H10/H11 via
# `register_cli(entry)`. Empty in H1 (this PR); H3 adds "cc".
CLI_REGISTRY: dict[CliId, CliEntry] = {}


def register_cli(entry: CliEntry) -> None:
    """Register a CLI launcher + probe in the global registry.

    Idempotent: re-registering the same `cli_id` overwrites the previous entry
    (used in tests where mock launchers replace real ones).
    """
    CLI_REGISTRY[entry.cli_id] = entry


def assert_permission_mode_valid(inputs: LaunchInputs) -> None:
    """INV-PERM-1: hard-panic if `(suite, cli, permission_mode)` doesn't match the table.

    Called by every launcher implementation IMMEDIATELY before subprocess spawn.
    Suite-level convention is insufficient (R2-MED-01) — runtime enforcement at
    the spawn boundary catches reordering, bypass via direct launcher
    invocation, and accidental cross-suite leakage.
    """
    expected = PERMISSION_MODE_MAP.get((inputs.suite, inputs.cli))
    if expected is None:
        raise RuntimeError(
            f"INV-PERM-1 violation: unknown (suite={inputs.suite!r}, cli={inputs.cli!r}); "
            f"this combination is not in PERMISSION_MODE_MAP — register it before spawning."
        )
    if inputs.permission_mode != expected:
        raise RuntimeError(
            f"INV-PERM-1 violation: suite={inputs.suite!r} cli={inputs.cli!r} "
            f"expected permission_mode={expected!r} got={inputs.permission_mode!r}"
        )
