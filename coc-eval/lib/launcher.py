"""Per-CLI launcher dataclasses + INV-PERM-1 runtime check + CLI registry.

Mirrors loom's `CLI_COMMANDS` shape (`harness.mjs:88-139`). Launcher behavior
is split between this module (dataclasses + registry + invariant check + cc
launcher) and later PRs (H10 codex, H11 gemini) which register more launchers.

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

H3 additions:
- `cc_launcher`: builds the LaunchSpec for the `claude` CLI per suite.
- `build_stub_home`: composes `<fixture_dir>/_stub_home/` with credential
  symlink + onboarding marker, plus `<fixture_dir>/_stub_root/` as a fake
  $HOME with empty `.ssh/`, `.codex/`, `.gemini/`, `.aws/`, `.gnupg/`
  placeholder dirs (R1-CRIT-02).
- `_filter_settings_overlay`: positive-allowlist filter on settings keys
  (R1-HIGH-02). Caller-provided overlay dicts are reduced to
  `{env, model, permissions}` with sub-key validation.
- `spawn_cli`: subprocess launch with INV-PERM-1 spawn-time check,
  INV-ISO-6 pre-spawn symlink revalidation, and `start_new_session=True`
  so the harness can SIGTERM/SIGKILL the entire process group on timeout
  (INV-RUN-3).
- `kill_process_group`: SIGTERM → grace → SIGKILL via `os.killpg`
  (INV-RUN-3).
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, Mapping

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


# -----------------------------------------------------------------------------
# H3 — cc launcher, stub-HOME builder, settings allowlist, spawn helper.
# -----------------------------------------------------------------------------

# Settings-key positive allowlist (R1-HIGH-02). Anything outside this set is
# dropped recursively. The implementation filter is applied to any caller-
# provided settings overlay BEFORE merge into a stub-HOME; suites that need
# new keys must extend this allowlist deliberately.
_SETTINGS_KEY_ALLOWLIST: frozenset[str] = frozenset({"env", "model", "permissions"})

# Allowed env-key prefixes. `ANTHROPIC_*` covers model + auth overrides; the
# explicit harness allowlist covers a small set of csq-domain vars. Anything
# else (LD_PRELOAD, DYLD_INSERT_LIBRARIES, PATH) is filtered out — even if
# it would otherwise match a prefix.
_ENV_KEY_PREFIX_ALLOWED: tuple[str, ...] = ("ANTHROPIC_",)
_ENV_KEY_HARNESS_ALLOWED: frozenset[str] = frozenset({"CLAUDE_CONFIG_DIR"})
_ENV_KEY_FORBIDDEN: frozenset[str] = frozenset(
    {"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PATH"}
)

# Allowed sub-keys of the `permissions` settings block. Other keys (e.g. an
# attempt to introduce a `loadFrom: file:///...` indirection) are dropped.
_PERMISSIONS_KEY_ALLOWLIST: frozenset[str] = frozenset({"allow", "deny", "defaultMode"})

# Sandbox profile path (macOS sandbox-exec). Resolved once at module import
# so the path is stable across calls.
_SANDBOX_PROFILE_PATH: Path = (
    Path(__file__).resolve().parent.parent / "sandbox-profiles" / "write-confined.sb"
)

# Subdirectories under the fake $HOME root that MUST exist (empty placeholders)
# so a process inspecting `~/.ssh/` etc. sees a directory, not the user's real
# secrets. Per spec 08 §"Stub-HOME with $HOME override".
_HOME_ROOT_PLACEHOLDER_DIRS: tuple[str, ...] = (
    ".ssh",
    ".codex",
    ".gemini",
    ".aws",
    ".gnupg",
)


def _is_within(child: Path, parent: Path) -> bool:
    """True if `child.resolve()` is inside `parent.resolve()`.

    Used as the symlink-target containment check (M1 hardening): credential
    candidates that resolve OUTSIDE `~/.claude/` are refused, even though
    the same-user threat model bounds the exploit. A `config-N/.credentials.json`
    that points at `/tmp/attacker-creds.json` is anomalous — surface it
    rather than silently chain it into `_stub_home`.
    """
    try:
        child_resolved = child.resolve()
        parent_resolved = parent.resolve()
    except OSError:
        return False
    try:
        child_resolved.relative_to(parent_resolved)
        return True
    except ValueError:
        return False


def _find_user_credentials() -> Path | None:
    """Locate a usable cc credentials file in the current user's home.

    Order of preference:
      1. `~/.claude/.credentials.json` (single-account / non-csq layout).
      2. `~/.claude/accounts/config-N/.credentials.json` — the most-recently
         modified `config-N` wins. csq's handle-dir model (spec 02) keeps
         credentials per account here.

    Symlink-target containment (M1 from H3 review): if a candidate is a
    symlink, its target MUST resolve inside `~/.claude/`. Anything else is
    silently skipped — the discovery walk continues to the next candidate.

    Returns the credential path, or `None` if no candidate is found.
    """
    home = Path.home()
    claude_root = home / ".claude"
    direct = claude_root / ".credentials.json"
    if direct.is_file() or direct.is_symlink():
        if _is_within(direct, claude_root):
            return direct

    accounts = claude_root / "accounts"
    if not accounts.is_dir():
        return None

    candidates: list[tuple[float, Path]] = []
    try:
        entries = list(accounts.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.is_dir() or not entry.name.startswith("config-"):
            continue
        creds = entry / ".credentials.json"
        if not (creds.is_file() or creds.is_symlink()):
            continue
        # Containment check before we trust the target.
        if not _is_within(creds, claude_root):
            continue
        try:
            mtime = creds.stat().st_mtime
        except OSError:
            continue
        candidates.append((mtime, creds))
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0], reverse=True)
    return candidates[0][1]


def build_stub_home(
    suite: SuiteId,
    fixture_dir: Path,
    credentials_src: Path | None = None,
) -> tuple[Path, Path]:
    """Compose `_stub_home/` (CC config dir) and `_stub_root/` (fake $HOME).

    Layout produced:

        <fixture_dir>/
            _stub_home/
                .credentials.json -> <credentials_src>     (symlink)
                .claude.json                                ({"hasCompletedOnboarding": true})
            _stub_root/
                .ssh/                                       (empty dir)
                .codex/                                     (empty dir)
                .gemini/                                    (empty dir)
                .aws/                                       (empty dir)
                .gnupg/                                     (empty dir)

    The credential file is a SYMLINK to the user's real credential, never a
    copy. Copying would either snapshot a soon-to-be-rotated token (memory:
    "No credential copies in benchmarks") or, worse, persist a credential
    file at a non-`0o600` location.

    Args:
        suite: Suite name. Plays no role in H3's layout — kept in the
            signature so future suites can vary the stub-HOME shape.
        fixture_dir: Already-prepared fixture root from `prepare_fixture`.
        credentials_src: Override path to use as the symlink target. Defaults
            to `_find_user_credentials()`. Tests can pass a fake credentials
            file in a tmp dir.

    Returns:
        `(stub_home, home_root)` — both absolute paths inside `fixture_dir`.

    Raises:
        FileNotFoundError: no credentials available for the symlink.
    """
    del suite  # H3 does not vary layout per suite; reserved for H4+.

    src = credentials_src if credentials_src is not None else _find_user_credentials()
    if src is None:
        raise FileNotFoundError(
            "no credentials found at ~/.claude/.credentials.json or "
            "~/.claude/accounts/config-*/.credentials.json — run `csq login N` first"
        )

    fixture_dir = fixture_dir.resolve()
    stub_home = fixture_dir / "_stub_home"
    home_root = fixture_dir / "_stub_root"

    stub_home.mkdir(parents=True, exist_ok=True)
    home_root.mkdir(parents=True, exist_ok=True)

    # `.credentials.json` symlink. Replace any prior link or file so a stale
    # `_stub_home` from a crashed previous run cannot poison the new one.
    creds_link = stub_home / ".credentials.json"
    if creds_link.is_symlink() or creds_link.exists():
        creds_link.unlink()
    creds_link.symlink_to(src.resolve())

    # `.claude.json` skips the first-run onboarding wizard. CC honors this
    # marker even when the file lives at $CLAUDE_CONFIG_DIR.
    claude_json = stub_home / ".claude.json"
    claude_json.write_text(
        json.dumps({"hasCompletedOnboarding": True}, separators=(",", ":")),
        encoding="utf-8",
    )

    # Empty placeholder dirs in $HOME root. A model that explores `~/.ssh/`
    # via a tool call sees an empty directory, not the user's real keys.
    for sub in _HOME_ROOT_PLACEHOLDER_DIRS:
        (home_root / sub).mkdir(exist_ok=True)

    return stub_home, home_root


def _filter_env_keys(env: Mapping[str, Any]) -> dict[str, str]:
    """Allowlist-filter env-vars from a settings overlay.

    Keeps `ANTHROPIC_*` plus an explicit harness-allowed set; drops anything
    in `_ENV_KEY_FORBIDDEN` (LD_PRELOAD, DYLD_INSERT_LIBRARIES, PATH) even if
    it would otherwise match a prefix.
    """
    out: dict[str, str] = {}
    for k, v in env.items():
        if not isinstance(k, str) or not isinstance(v, str):
            continue
        if k in _ENV_KEY_FORBIDDEN:
            continue
        if k in _ENV_KEY_HARNESS_ALLOWED or any(
            k.startswith(p) for p in _ENV_KEY_PREFIX_ALLOWED
        ):
            out[k] = v
    return out


def _filter_permissions_keys(perms: Mapping[str, Any]) -> dict[str, Any]:
    """Allowlist-filter the `permissions` block of a settings overlay.

    Keeps `{allow, deny, defaultMode}`. `allow`/`deny` must be lists of
    simple strings (rejects objects, $ref indirections, and `file://` URIs
    that could become file references).
    """
    out: dict[str, Any] = {}
    for k, v in perms.items():
        if k not in _PERMISSIONS_KEY_ALLOWLIST:
            continue
        if k in ("allow", "deny"):
            if not isinstance(v, list):
                continue
            simple = [
                item
                for item in v
                if isinstance(item, str) and not item.lower().startswith("file:")
            ]
            out[k] = simple
        elif k == "defaultMode":
            if isinstance(v, str):
                out[k] = v
    return out


def filter_settings_overlay(merged: Mapping[str, Any]) -> dict[str, Any]:
    """Apply the R1-HIGH-02 positive allowlist to a merged settings dict.

    Only `{env, model, permissions}` survive. `env` is filtered to harness-
    allowed keys; `permissions` is filtered to `{allow, deny, defaultMode}`
    with simple-string-pattern values; `model` passes through if it is a
    string.

    This filter applies BEFORE a settings overlay is written into the
    stub-HOME (`<stub_home>/.claude/settings.json` in future suites). Phase 1
    suites do not yet write a settings overlay — the function is provided
    here so suites added in H4+ can rely on it.

    Args:
        merged: Caller-merged settings dict (already-resolved overlay).

    Returns:
        A new dict containing only the allowlisted keys.
    """
    out: dict[str, Any] = {}
    for key in merged:
        if key not in _SETTINGS_KEY_ALLOWLIST:
            continue
        v = merged[key]
        if key == "env":
            if isinstance(v, dict):
                out[key] = _filter_env_keys(v)
        elif key == "permissions":
            if isinstance(v, dict):
                out[key] = _filter_permissions_keys(v)
        elif key == "model":
            if isinstance(v, str):
                out[key] = v
    return out


def _resolve_sandbox_wrapper(fixture_dir: Path) -> tuple[str, ...]:
    """Resolve the platform sandbox argv prefix for the implementation suite.

    macOS: `sandbox-exec -f <profile>.sb`. Profile path is the workspace-
    rooted `coc-eval/sandbox-profiles/write-confined.sb` resolved at module
    import time.

    Linux: `bwrap --ro-bind / / --tmpfs ~/.{claude,ssh,codex,gemini,aws,gnupg}
    --bind <fixture_dir> /workspace --chdir /workspace`. Operator must
    install bubblewrap (`apt install bubblewrap`).

    Windows: `RuntimeError`. The implementation suite is gated out at
    argparse in Phase 1 per ADR-F; reaching this branch is a programming
    error that the runtime catches as a defense-in-depth tripwire.
    """
    sysname = platform.system()
    if sysname == "Darwin":
        return ("sandbox-exec", "-f", str(_SANDBOX_PROFILE_PATH))
    if sysname == "Linux":
        # Resolve HOME before interpolating into bwrap argv (M3 hardening).
        # A HOME containing `..` would produce confusing tmpfs mount paths
        # under the same-user threat model; argv-list invocation makes
        # shell injection structurally impossible, but path-traversal is
        # worth eliminating defensively.
        home_resolved = Path.home().resolve()
        if not home_resolved.is_absolute():
            raise RuntimeError(
                f"_resolve_sandbox_wrapper: HOME does not resolve to an "
                f"absolute path: {home_resolved!r}"
            )
        home = str(home_resolved)
        return (
            "bwrap",
            "--ro-bind",
            "/",
            "/",
            "--tmpfs",
            f"{home}/.claude",
            "--tmpfs",
            f"{home}/.ssh",
            "--tmpfs",
            f"{home}/.codex",
            "--tmpfs",
            f"{home}/.gemini",
            "--tmpfs",
            f"{home}/.aws",
            "--tmpfs",
            f"{home}/.gnupg",
            "--bind",
            str(fixture_dir.resolve()),
            "/workspace",
            "--chdir",
            "/workspace",
        )
    raise RuntimeError(
        f"sandbox not supported on platform={sysname!r}; "
        "implementation suite is Phase-1-gated to macOS/Linux"
    )


def _build_cc_args(suite: SuiteId, prompt: str) -> tuple[str, ...]:
    """Compose `claude` CLI argv (without the binary itself).

    - implementation: `--print --output-format json --dangerously-skip-permissions <prompt>`
    - all others: `--print --permission-mode plan <prompt>`
    """
    if suite == "implementation":
        return (
            "--print",
            "--output-format",
            "json",
            "--dangerously-skip-permissions",
            prompt,
        )
    return ("--print", "--permission-mode", "plan", prompt)


def _build_cc_env(inputs: LaunchInputs) -> dict[str, str]:
    """Compose env mapping for cc subprocess.

    Sets `CLAUDE_CONFIG_DIR=<stub_home>` and `HOME=<home_root>` per
    R1-CRIT-02. Always preserves PATH (so the binary resolves) and any
    caller-supplied `extra_env`.
    """
    env: dict[str, str] = {}
    # Inherit only minimal non-secret-bearing parents. `PATH` is required for
    # the kernel to resolve the binary; `LANG`/`LC_*` keep CC's output stable.
    # Deliberate omission (L2): LOGNAME/USER are NOT forwarded — CC's current
    # auth path does not consult them, and a bare env reduces accidental
    # token-display paths via username-keyed prompts. Add them only if a
    # future CC version is observed depending on them.
    parent_path = os.environ.get("PATH", "")
    if parent_path:
        env["PATH"] = parent_path
    for key in ("LANG", "LC_ALL", "LC_CTYPE"):
        v = os.environ.get(key)
        if v is not None:
            env[key] = v

    if inputs.stub_home is not None:
        env["CLAUDE_CONFIG_DIR"] = str(inputs.stub_home)
    if inputs.home_root is not None:
        env["HOME"] = str(inputs.home_root)
    # Caller-supplied additions win (per-test ANTHROPIC_MODEL overrides etc.).
    if inputs.extra_env:
        env.update(inputs.extra_env)
    return env


def cc_launcher(inputs: LaunchInputs) -> LaunchSpec:
    """Build a LaunchSpec for the `claude` CLI per the H3 contract.

    - Permission mapping: `--permission-mode plan` for capability/compliance/
      safety; `--dangerously-skip-permissions` for implementation.
    - Output format: `--print` (text) for non-implementation; `--print
      --output-format json` for implementation.
    - Env: `CLAUDE_CONFIG_DIR=stub_home` AND `HOME=home_root` for non-
      implementation suites; sandbox wrapper handles implementation.
    - INV-PERM-1: validated up-front so a launcher caller cannot construct
      a spec with the wrong permission_mode and then bypass `spawn_cli`.

    Args:
        inputs: LaunchInputs (typed). `inputs.cli` MUST equal `"cc"`.

    Returns:
        A LaunchSpec ready to be passed to `spawn_cli(spec, inputs)`.

    Raises:
        ValueError: cli is not "cc".
        RuntimeError: INV-PERM-1 violation, OR sandbox wrapper requested on
            an unsupported platform.
    """
    if inputs.cli != "cc":
        raise ValueError(f"cc_launcher requires inputs.cli='cc', got {inputs.cli!r}")

    # Front-loaded INV-PERM-1: any caller building a misaligned spec sees the
    # error here, not after env/sandbox prep.
    assert_permission_mode_valid(inputs)

    binary = shutil.which("claude") or "claude"
    args = _build_cc_args(inputs.suite, inputs.prompt)
    env = _build_cc_env(inputs)

    sandbox_wrapper: tuple[str, ...] = ()
    if inputs.sandbox_profile == "write-confined":
        sandbox_wrapper = _resolve_sandbox_wrapper(inputs.fixture_dir)

    return LaunchSpec(
        cmd=binary,
        args=args,
        cwd=inputs.fixture_dir,
        env=env,
        sandbox_wrapper=sandbox_wrapper,
    )


def _assert_credentials_symlink_intact(stub_home: Path) -> None:
    """INV-ISO-6: pre-spawn revalidation of the credential symlink.

    Verifies:
      - `<stub_home>/.credentials.json` exists and is a symlink.
      - The link target is reachable (stat succeeds).
      - The inode reached via the link matches the inode reached by stat-ing
        the symlink path (catches a target-replaced race).

    Raises:
        RuntimeError on any mismatch. The launcher MUST treat this as a
        hard error — do NOT proceed to spawn.
    """
    creds_link = stub_home / ".credentials.json"
    if not creds_link.is_symlink():
        raise RuntimeError(
            f"INV-ISO-6 violation: {creds_link} is not a symlink "
            "(stub-HOME was not built via build_stub_home)"
        )
    try:
        link_target = os.readlink(str(creds_link))
    except OSError as e:
        raise RuntimeError(
            f"INV-ISO-6 violation: readlink failed for {creds_link}: {e}"
        ) from e
    target_path = Path(link_target)
    if not target_path.is_absolute():
        target_path = (creds_link.parent / target_path).resolve()
    try:
        target_ino = os.stat(str(target_path)).st_ino
        link_follow_ino = os.stat(str(creds_link)).st_ino
    except OSError as e:
        raise RuntimeError(
            f"INV-ISO-6 violation: stat failed during revalidation: {e}"
        ) from e
    if target_ino != link_follow_ino:
        raise RuntimeError(
            f"INV-ISO-6 violation: credential symlink {creds_link} -> "
            f"{target_path} inode mismatch ({link_follow_ino} vs {target_ino})"
        )


def spawn_cli(spec: LaunchSpec, inputs: LaunchInputs) -> subprocess.Popen[str]:
    """Spawn the CLI subprocess. Asserts INV-PERM-1 + INV-ISO-6 + uses
    `start_new_session=True` so the harness can SIGTERM/SIGKILL the entire
    process group on timeout (INV-RUN-3).

    Returns the Popen handle. Caller is responsible for `communicate(...)`
    plus invoking `kill_process_group` on timeout.
    """
    # INV-PERM-1 (defense in depth — `cc_launcher` already checks).
    assert_permission_mode_valid(inputs)

    # INV-ISO-6 — only meaningful when stub_home is set (capability/
    # compliance/safety). Implementation suite uses the sandbox wrapper as
    # the primary defense.
    if inputs.stub_home is not None:
        _assert_credentials_symlink_intact(inputs.stub_home)

    full_argv: list[str] = list(spec.sandbox_wrapper) + [spec.cmd, *spec.args]

    # PEP 446: file descriptors opened by the harness are non-inheritable by
    # default in Python 3.4+. We additionally pass DEVNULL on stdin so a hung
    # CLI never blocks on tty input.
    return subprocess.Popen(  # noqa: S603 — argv list, shell=False (default).
        full_argv,
        cwd=str(spec.cwd),
        env=dict(spec.env),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        text=True,
    )


def kill_process_group(
    proc: subprocess.Popen[Any],
    grace_secs: float = 5.0,
) -> int | None:
    """SIGTERM the process group, wait `grace_secs`, then SIGKILL (INV-RUN-3).

    Args:
        proc: A Popen returned by `spawn_cli`. MUST have been spawned with
            `start_new_session=True`.
        grace_secs: Seconds to wait between SIGTERM and SIGKILL. Five seconds
            is the operational default — long enough to let a well-behaved
            CLI flush, short enough that a stuck CLI does not delay the run.

    Returns:
        The final returncode, or `None` if the process is somehow still
        running after SIGKILL + a 2s wait (which would indicate uninterruptible-
        sleep state — surfaces as `None` so the caller can distinguish).
    """
    if proc.poll() is not None:
        return proc.returncode
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        # Process has already exited between poll() and getpgid().
        try:
            return proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return None
    try:
        os.killpg(pgid, signal.SIGTERM)
    except OSError:
        # Process group already gone.
        try:
            return proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return None
    try:
        return proc.wait(timeout=grace_secs)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass
        try:
            return proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            return None


def _probe_auth_cc_proxy() -> AuthProbeResult:
    """Module-level cc auth probe binding.

    The actual probe lives in `coc_eval.lib.auth.probe_auth("cc", ...)`. This
    proxy lets `CliEntry.auth_probe` carry a no-arg callable matching the
    H1 contract. Tests that want a probe scoped to a specific suite call
    `auth.probe_auth("cc", suite=...)` directly; the registry probe is the
    suite-agnostic default used by smoke flows.
    """
    # Local import to keep the dataclasses module side-effect-free for code
    # that only needs LaunchInputs/LaunchSpec without pulling in subprocess.
    from . import auth as _auth

    return _auth.probe_auth("cc", "default")


# Register cc as the first concrete entry in CLI_REGISTRY. H10 + H11 add
# codex + gemini in their respective PRs.
CLI_REGISTRY["cc"] = CliEntry(
    cli_id="cc",
    binary="claude",
    launcher=cc_launcher,
    auth_probe=_probe_auth_cc_proxy,
)
