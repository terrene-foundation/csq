# Spec 08 — coc-eval Multi-CLI Test Harness

**Status:** Authoritative. Per `rules/specs-authority.md`, this spec is the single source of domain truth for the coc-eval harness. Workspace analysis at `workspaces/coc-harness-unification/01-analysis/` is the derivation; this spec is the contract.

**Companion docs:** `coc-eval/README.md` (operator quick-start, drifts allowed); workspace ADRs at `workspaces/coc-harness-unification/01-analysis/07-adrs.md` (decision history).

## Purpose

The coc-eval harness measures four orthogonal axes of CLI/model behavior under COC artifact load:

- **capability** — does the CLI auto-load its baseline file? (4 tests, regex scoring)
- **compliance** — does the CLI cite the right RULE_ID when refusing? (9 tests, regex scoring)
- **safety** — does the CLI refuse adversarial prompts? (5 tests, regex + post-assertion scoring)
- **implementation** — can the model fix real bugs guided by COC? (5 tests, tiered artifact scoring)

Phase 1 ships against three CLIs: `claude` (cc), `codex`, `gemini`. Implementation suite is cc-only Phase 1 (per ADR-B); codex/gemini implementation cells emit `skipped_artifact_shape`.

## Architectural pillars

### Stdlib-only Python (ADR-A)

Per `rules/independence.md` §3, the harness uses Python 3 stdlib + POSIX/macOS/Windows system tools. No PyPI deps. Loom's Node.js harness is ported byte-for-byte to Python.

### Per-suite × per-CLI launcher table (ADR-E, INV-PERM-1)

Each cell `(suite, cli)` has a fixed `permission_mode` per `coc-eval/lib/launcher.py::PERMISSION_MODE_MAP`:

| Suite | cc | codex | gemini |
| --- | --- | --- | --- |
| capability | plan | read-only | plan |
| compliance | plan | read-only | plan |
| safety | plan | read-only | plan |
| implementation | write | write (skipped) | write (skipped) |

**INV-PERM-1**: at subprocess spawn time, the launcher MUST assert `(spec.suite, spec.cli) → spec.permission_mode` matches the table. Mismatch is a hard panic. Suite-level convention is insufficient — runtime enforcement catches reordering, bypass via direct launcher invocation, and accidental cross-suite leakage.

### Stub-HOME with `$HOME` override + sandbox (ADR-F, R1-CRIT-02 + R1-CRIT-01)

For capability/compliance/safety: launcher sets BOTH `CLAUDE_CONFIG_DIR=stub_home` AND `HOME=home_root` env vars. `home_root` is a fake `$HOME` whose `~/.claude/` IS the stub-HOME (with credential symlink) and whose `~/.ssh/`, `~/.codex/`, `~/.gemini/`, `~/.aws/`, `~/.gnupg/` are absent or empty placeholders.

For implementation suite: process-level sandbox (`bwrap` on Linux, `sandbox-exec` on macOS) confines the spawned process so credential-shaped paths are physically unreachable to the model's tool calls. The credential symlink lives inside the test fixture's stub-HOME and is the ONLY credential-shaped file the process can see.

The audit hook (`sys.addaudithook`) is a defense-in-depth tripwire that catches harness-internal Python `open()` events ONLY — it does NOT see syscalls in spawned subprocess children. Sandbox is the primary defense; audit hook is secondary.

### Closed state taxonomy with split precedence (INV-OUT-3, R2-MED-01)

Two ladders avoid conflating per-record predicate resolution with run-loop boundaries:

**Within-test predicate precedence** (single record):
`error_fixture > error_invocation > error_json_parse > error_timeout > skipped_sandbox > skipped_artifact_shape > pass_after_retry > pass > fail`

**Across-test invariants** (run-loop boundaries):
`skipped_cli_missing`, `skipped_cli_auth`, `skipped_quota`, `skipped_quarantined`, `skipped_user_request`, `skipped_budget`, `error_token_budget`. If `error_token_budget` fires during an in-flight test, that test keeps its in-flight predicate; subsequent un-run tests stamp `error_token_budget`.

### JSONL schema v1.0.0 with parallel-arrays score shape (R1-AD-05)

`score.criteria` (regex backend) and `score.tiers` (tiered_artifact backend) are independent optional arrays at the same level. A record may have one, the other, or both. Universal scalars: `score.pass`, `score.total`, `score.max_total`. Aggregator reads these uniformly.

Run-id format: `<iso8601-second>-<pid>-<counter>-<rand>` where `<rand>` is `secrets.token_urlsafe(6)`. Deterministic-distinct under scripted invocation per AC-11a.

### Token redaction with word-boundary parity (R1-HIGH-01)

`coc-eval/lib/redact.py` is a Python port of `csq-core/src/error.rs:161 redact_tokens`. Patterns: `sk-ant-oat01-`, `sk-ant-ort01-`, `sk-* + 20`, `sess-* + 20`, `rt_* + 20`, `AIza* + 30`, 32+ hex run, 3-segment JWT, PEM blocks. Word-boundary semantics use a custom char-class predicate (`is_key_char`); naive Python `\b` regex is INCORRECT (would match `module_sk-...` while Rust skips it).

ALL `stdout_truncated` and `stderr_truncated` fields pass through `redact_tokens` before persistence. Companion `.log` files also redacted. Evidence logs (for AC-23 credential canary tests) are mode 0o600, banner-headed, auto-deleted on next run.

### Suite-v1 schema + validator (R3-CRIT-01)

`coc-eval/schemas/suite-v1.json` defines the SUITE dict shape. `coc-eval/lib/suite_validator.py::validate_suite()` enforces conformance + INV-PAR-2 criteria-count parity (with `skipped_artifact_shape` carve-out per R2-MED-02).

`coc-eval/run.py <suite> --validate` (FR-16, AC-44) runs the validator + manifest checks; exit 64 on failure.

### Stdlib-only invariants

- **INV-RUN-1**: Python stdlib only. Node permitted only as child process of the launcher.
- **INV-RUN-2**: All `subprocess.run([list], shell=False)`. AC-13 grep guard enforces.
- **INV-RUN-3**: Process-group SIGTERM (5s grace) → SIGKILL via `os.killpg`. Credential symlink fd `O_CLOEXEC`.
- **INV-RUN-4**: No test time-bombs (year-2100+ literals).
- **INV-RUN-5**: No real `~/.claude` writes from non-implementation suites.
- **INV-RUN-6**: concurrency=1 in Phase 1.
- **INV-RUN-7**: Token-budget circuit breaker (5M input / 1M output default).
- **INV-RUN-8**: Cross-suite ordering — non-write before write.

### Auth probe semantics

- **INV-AUTH-1**: One probe per CLI per suite (cached for that suite).
- **INV-AUTH-2**: Missing auth = `skipped_cli_auth`. Wrong-account = `error_invocation`.
- **INV-AUTH-3**: Re-probe between suites. Mid-run `401|invalid_grant|expired_token` stderr triggers re-probe; `auth_state_changed: true` flag in JSONL.

Probe is REAL (`claude --print "ping"` 10s timeout), NOT mtime heuristic (R1-MED-02).

## Settings-key positive allowlist (R1-HIGH-02)

Merged settings post-overlay MUST contain only keys in `{"env", "model", "permissions"}`. `env` filtered to `ANTHROPIC_*` + harness allowlist (rejects `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PATH`). `permissions` validated to `{allow, deny, defaultMode}` keys with simple-string-pattern values.

## Sandbox tooling

- **Linux:** `bwrap --ro-bind / / --tmpfs /home/$USER/.claude --tmpfs /home/$USER/.ssh --tmpfs /home/$USER/.codex --tmpfs /home/$USER/.gemini --tmpfs /home/$USER/.aws --tmpfs /home/$USER/.gnupg --bind <coc-env> /workspace --chdir /workspace <cmd> <args>`. Operator must `apt install bubblewrap` before running implementation suite.
- **macOS:** `sandbox-exec -f coc-eval/sandbox-profiles/write-confined.sb <cmd> <args>`. Profile denies read+write on `~/.{claude,ssh,codex,gemini,aws,gnupg}`. `sandbox-exec` is Apple-deprecated as of macOS 10.10 but functional in Phase 1; v1.1 follow-up to migrate to `sandbox` framework via Rust shim.
- **Windows:** Phase 1 gates implementation suite out at argparse with `error: implementation suite requires sandbox-exec or bwrap; Windows not supported in Phase 1`.

## Fixture-name validator (CRIT-02 + MED-05)

`FIXTURE_NAME_RE = ^[a-zA-Z0-9_-][a-zA-Z0-9._-]*$` AND no `..` AND length ≤ 64. Used for fixture, suite, CLI, profile names. Centralized in `coc-eval/lib/validators.py::validate_name`.

## Tempdir cleanup invariant

`cleanup_eval_tempdirs()` finalizer at run start AND end removes every `/tmp/csq-eval-*` older than the current run. Mkdtemp directories with credential symlinks MUST NOT survive process exit (HIGH-03 #3).

## Loom-csq boundary (ADR-J)

csq owns multi-CLI evaluation harness. Loom owns COC artifact authoring + per-CLI emission (slot composition, parity contract, 60KiB cap). Paired rules in both repos: `csq/.claude/rules/csq-loom-boundary.md` + `loom/.claude/rules/loom-csq-boundary.md`. Schema authority for fixture content (RULE_ID grammar, prompt strings, scoring patterns) is csq's; format authority (slot composition, frontmatter shape) is loom's. Quarterly drift CI runs `git diff loom/.claude/test-harness/fixtures csq/coc-eval/fixtures` against a whitelisted divergence list.

## Cross-references

- `coc-eval/lib/validators.py`, `redact.py`, `launcher.py`, `states.py`, `suite_validator.py` — implementation
- `coc-eval/schemas/v1.0.0.json` — JSONL record schema
- `coc-eval/schemas/suite-v1.json` — SUITE dict schema
- `workspaces/coc-harness-unification/journal/` — decisions, discoveries, risks
- `workspaces/coc-harness-unification/04-validate/` — redteam findings (round 1, 2, 3)
- `csq-core/src/error.rs:161 redact_tokens` — Rust source for the Python port
- `rules/independence.md` §3 — stdlib-only constraint
- `rules/account-terminal-separation.md` — credential-isolation invariants
- `rules/zero-tolerance.md` — pre-existing-failure resolution rule
