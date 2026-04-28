# Per-CLI Launcher Table Contract (R1-revised)

Mirrors loom's `CLI_COMMANDS` shape (`harness.mjs:88-139`). In Python, `dict[CliId, Callable[..., LaunchSpec]]` returning a typed `LaunchSpec` dataclass.

**R1 changes:** `CliId` is a string TypeAlias (not a closed Literal — UX-11); `LaunchInputs` carries an explicit `home_root` for `$HOME` override (R1-CRIT-02); per-suite × per-CLI sandbox profile selectable (R1-CRIT-01); INV-PERM-1 enforced at spawn time (R1-MED-01).

## Inputs

```python
CliId = str  # validated at runtime against CLI_COMMANDS.keys() and validators.FIXTURE_NAME_RE
# Note (R2-LOW-02): `suite` below remains a closed Literal because the four suites map
# to the COC capability/compliance/safety/implementation taxonomy (CO methodology layers).
# A new suite represents a methodology-level change requiring deliberate analysis.
# CLI IDs are open because new model-CLIs ship continuously (codex, gemini, future native csq CLI).

@dataclass(frozen=True)
class LaunchInputs:
    cli: CliId
    suite: Literal["capability", "compliance", "safety", "implementation"]
    fixture_dir: Path             # already-prepared, isolated copy (or coc-env for implementation)
    prompt: str                    # byte-identical across CLIs (INV-PAR-1)
    permission_mode: Literal["plan", "read-only", "write", "default"]
    timeout_ms: int | None         # None → CLI_TIMEOUT_MS[(suite, cli)]
    stub_home: Path | None         # populated for cc/codex; None for gemini (no env)
    home_root: Path | None         # NEW R1: $HOME override (capability/compliance/safety only).
                                   # Fake $HOME root whose ~/.claude is the stub_home,
                                   # whose ~/.ssh/, ~/.codex/, ~/.gemini/, ~/.aws/, ~/.gnupg/
                                   # are absent or empty placeholder dirs.
    extra_env: Mapping[str, str]   # per-test additions (rare; e.g. ANTHROPIC_MODEL override)
    sandbox_profile: Literal["none", "read-only", "write-confined"] | None  # NEW R1
```

## Outputs

```python
@dataclass(frozen=True)
class LaunchSpec:
    cmd: str                        # absolute or PATH-resolved binary
    args: list[str]                 # argv after cmd
    cwd: Path                       # almost always == fixture_dir
    env: dict[str, str]             # full env, NOT merged at the call site
    sandbox_wrapper: list[str] | None  # NEW R1: e.g. ["sandbox-exec", "-f", profile_path]
                                      # or ["bwrap", "--ro-bind", "/", "/", ...]
                                      # None for capability/compliance/safety (HOME override is enough).
                                      # Required for implementation suite per CRIT-01.
    expected_state_on_missing: Literal["skipped_cli_missing"]
```

## Per-CLI specifics

| CLI    | Binary   | Permission flag                                                                                             | HOME-override env (capability/compliance/safety)            | Sandbox (implementation) | Notes                                                                                       |
| ------ | -------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------- |
| cc     | `claude` | `--permission-mode plan` (compliance/capability/safety) / `--dangerously-skip-permissions` (implementation) | `CLAUDE_CONFIG_DIR=stub_home` AND `HOME=home_root`          | `sandbox-exec`/`bwrap`   | `--print` + `--output-format json` for implementation; bare `-p` + scrape stdout for others |
| codex  | `codex`  | `--sandbox read-only` (default) / `--sandbox workspace-write` (implementation)                              | `CODEX_HOME=stub_home` AND `HOME=home_root`                 | `sandbox-exec`/`bwrap`   | Always `--skip-git-repo-check --color never`. Subcommand is `exec`.                         |
| gemini | `gemini` | `--approval-mode plan` (default) / `--approval-mode auto-edit` (implementation)                             | `HOME=home_root` only (no documented gemini config-dir env) | `sandbox-exec`/`bwrap`   | Slow first token; 180s timeout. Quota retry per INV-DET-2.                                  |

## Permission-mode mapping (suite × CLI)

| Suite          | cc                               | codex                       | gemini                      |
| -------------- | -------------------------------- | --------------------------- | --------------------------- |
| capability     | `--permission-mode plan`         | `--sandbox read-only`       | `--approval-mode plan`      |
| compliance     | `--permission-mode plan`         | `--sandbox read-only`       | `--approval-mode plan`      |
| safety         | `--permission-mode plan`         | `--sandbox read-only`       | `--approval-mode plan`      |
| implementation | `--dangerously-skip-permissions` | `--sandbox workspace-write` | `--approval-mode auto-edit` |

Phase 1: implementation × {codex, gemini} = `state: skipped_artifact_shape` (cells exist in matrix; tests don't run; ADR-B).

## Sandbox profile selection (R1-CRIT-01 mitigation)

Sandbox is mandatory for the implementation suite and OPTIONAL (defense-in-depth) for others on platforms where it's available.

```python
SANDBOX_PROFILE = {
    ("capability",     "*"): "read-only",      # HOME override is primary; sandbox optional
    ("compliance",     "*"): "read-only",
    ("safety",         "*"): "read-only",
    ("implementation", "cc"): "write-confined", # MANDATORY: cwd=coc-env; deny ~/.claude, ~/.ssh, etc.
    ("implementation", "codex"): None,         # Phase 1: skipped_artifact_shape
    ("implementation", "gemini"): None,        # Phase 1: skipped_artifact_shape
}
```

**Linux (`bwrap`):**

```
bwrap --ro-bind / / \
      --tmpfs /home/$USER/.claude \
      --tmpfs /home/$USER/.ssh \
      --tmpfs /home/$USER/.codex \
      --tmpfs /home/$USER/.gemini \
      --tmpfs /home/$USER/.aws \
      --tmpfs /home/$USER/.gnupg \
      --bind <coc-env> /workspace \
      --chdir /workspace \
      <cmd> <args>
```

**macOS (`sandbox-exec`):**

```
sandbox-exec -f coc-eval/sandbox-profiles/write-confined.sb <cmd> <args>
```

Sandbox profile file (Phase 1):

```scheme
(version 1)
(allow default)
(deny file-read* (regex "^/Users/[^/]+/\\.(?:claude|ssh|codex|gemini|aws|gnupg)(/|$)"))
(deny file-write* (regex "^/Users/[^/]+/\\.(?:claude|ssh|codex|gemini|aws|gnupg)(/|$)"))
```

**Sandbox-exec deprecation note** (per ADR-F): `sandbox-exec` is Apple-deprecated as of macOS 10.10 but functional. v1.1 follow-up: macOS `sandbox` framework via Rust shim. Phase 1 ships with `sandbox-exec` as documented deprecation risk.

**Platforms without sandbox** (Windows): implementation suite is gated out at argparse in Phase 1 (per ADR-F).

## Implementation-suite override (FR-7)

Implementation tests CAN override at the test level via `permission_mode_override: "write"` in their `TEST_DEF`. Other suites' tests MUST NOT set this — fixture-validity check rejects cross-suite write requests. A non-default override on capability/compliance/safety MUST set `requires_write_justification: str` (one-sentence reason) — catches accidental cross-suite leakage (R1-MED-01).

## INV-PERM-1 runtime enforcement (R1-MED-01)

At subprocess spawn time, the launcher MUST assert `(spec.suite, spec.cli) → spec.permission_mode` matches the per-suite × per-CLI launcher table. Mismatch is a hard panic, not a warning. Bypass requires editing two files in the same PR — a higher tripwire than reordering one list. Implementation in `coc-eval/lib/launcher.py`:

```python
def spawn_cli(spec: LaunchSpec, inputs: LaunchInputs) -> subprocess.Popen:
    expected_mode = PERMISSION_MODE_MAP[(inputs.suite, inputs.cli)]
    if inputs.permission_mode != expected_mode:
        raise RuntimeError(
            f"INV-PERM-1 violation: suite={inputs.suite} cli={inputs.cli} "
            f"expected={expected_mode} got={inputs.permission_mode}"
        )
    # ... spawn ...
```

AC-22a: "Bypass canary: a developer adds a fake `coc-eval/suites/_evil.py` that builds a LaunchSpec with `permission_mode='write'` for the safety suite. Harness invocation aborts at spawn time with `INV-PERM-1 violation`."

## Auth-probe contract

```python
@dataclass(frozen=True)
class AuthProbeResult:
    ok: bool
    reason: str | None      # None on success
    version: str            # CLI version string
    probed_at: float        # monotonic ts for re-probe interval tracking

def probe_auth(cli: CliId) -> AuthProbeResult: ...
```

**R1 change:** Auth probe runs before each suite (INV-AUTH-3), not just once per invocation (HIGH-10). Probe failure → entire CLI gets `skipped_cli_auth` records for every test in every selected suite for that suite's loop iteration.

**Probe logic — replaces mtime heuristic with real call:**

| CLI    | Probe                                                                                            |
| ------ | ------------------------------------------------------------------------------------------------ |
| cc     | `which claude` AND `claude --print "ping"` exits 0 within 10s                                    |
| codex  | `which codex` AND `codex auth status` (if exists) OR `~/.codex/auth.json` exists with valid JSON |
| gemini | `which gemini` AND `~/.gemini/oauth_creds.json` exists with valid JSON                           |

## Per-suite × per-CLI timeout matrix

```python
CLI_TIMEOUT_MS = {
    ("capability", "cc"):     60_000,
    ("capability", "codex"):  60_000,
    ("capability", "gemini"): 180_000,
    ("compliance", "cc"):     60_000,
    ("compliance", "codex"):  60_000,
    ("compliance", "gemini"): 180_000,
    ("safety",     "cc"):     60_000,
    ("safety",     "codex"):  60_000,
    ("safety",     "gemini"): 180_000,
    ("implementation", "cc"): None,  # use test_def["timeout"] (default 600s)
}
```

Hard cap per test = `2 × test_timeout` regardless of retries (F09). Implementation suite hard cap = `2 × test_def["timeout"]` = 1200s default.

## Fixture-name validator

```python
FIXTURE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-][a-zA-Z0-9._-]*$")
def validate_name(s: str, max_len: int = 64) -> None:
    if not FIXTURE_NAME_RE.fullmatch(s) or ".." in s or len(s) > max_len:
        raise ValueError(f"invalid name: {s!r}")
```

Used for: fixture names, suite names, CLI ids, profile names. One validator, all paths.

## CLI registration mechanism (R1-UX-11)

`coc-eval/lib/cli_registry.py`:

```python
@dataclass(frozen=True)
class CliEntry:
    cli_id: CliId                                              # e.g. "cc", "codex", "gemini"
    binary: str                                                 # e.g. "claude", "codex", "gemini"
    launcher: Callable[[LaunchInputs], LaunchSpec]
    auth_probe: Callable[[], AuthProbeResult]
    timeout_overrides: dict[tuple[str, CliId], int]            # per-suite timeouts
    default_permission_mode: dict[str, str]                    # per-suite default
    default_sandbox_profile: dict[str, str | None]             # per-suite default

CLI_REGISTRY: dict[CliId, CliEntry] = {
    "cc": cc_entry,
    "codex": codex_entry,
    "gemini": gemini_entry,
}
```

Adding a 4th CLI in v1.1 (e.g., a native csq CLI for Phase 2b) is a registration, not an architectural change. AC-42: stub `noop_cli` proves registration mechanism works without touching launcher table internals.

## Naming convention reference

The Python table mirrors csq's Rust runtime per-surface dispatch in `csq-cli/src/commands/run.rs:60-84`: surface-keyed dispatch table, each entry returning a typed launch spec. Same shape, different language.

## Cross-references

- `04-nfr-and-invariants.md` INV-PERM-1, INV-AUTH-3, INV-ISO-6, INV-RUN-3 (process-group kill), INV-RUN-7 (token budget)
- `06-jsonl-schema-v1.md` schema records `permission_mode`, `sandbox_profile`, `home_mode` per record
- `09-security-review.md` CRIT-01, CRIT-02, HIGH-02, HIGH-06 — the security findings these mitigations address
- `04-validate/01-redteam-round1-findings.md` R1-CRIT-01, R1-CRIT-02, R1-MED-01, R1-UX-11 — origin of these contract changes
