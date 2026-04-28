# Non-Functional Requirements & Invariants (R1+R2-revised)

R1 additions: INV-AUTH-3 (re-probe between suites), INV-PERM-1 (runtime permission enforcement), INV-ISO-6 (pre-spawn symlink revalidation), INV-RUN-7 (token-budget circuit breaker). Updates: INV-RUN-3 (process-group SIGTERM/SIGKILL).

**Invariant labels (round-2 clarification, R2-HIGH-01):** INV-RUN-7 = token-budget circuit breaker; INV-RUN-8 = suite-ordering enforcement. The two are distinct and the labels are NOT swappable. Cross-references in `09-security-review.md` use INV-RUN-8 for ordering.

## Test isolation

- **INV-ISO-1 (per-test fixture).** Capability/compliance/safety: every test gets a fresh `$TMPDIR/coc-harness-<suite>-<test>-<cli>-<rand>/` copy. No two tests share a working tree.
- **INV-ISO-2 (no real `~/.claude` writes from non-implementation suites).** These suites embed their own `.claude/` inside the fixture and run with `CLAUDE_CONFIG_DIR=<fixture>/_stub_home/` containing only `.credentials.json` (symlink) + `.claude.json` with `hasCompletedOnboarding: true`, AND `HOME=<fixture>/_stub_root/` where `~/.ssh`, `~/.aws`, `~/.codex`, `~/.gemini`, `~/.gnupg` are absent. User's global rules and credential-shaped paths are invisible. Resolves loom's punted F01 + R1-CRIT-02.
- **INV-ISO-3 (implementation suite stays in `coc-env/`).** Reset via `git clean -fdx && git -C coc-env reset --hard HEAD && rm -rf coc-env/.git/hooks/* && git -C coc-env config --unset core.hooksPath` between tests. Wrapped in `try/finally`. INV-ISO-1 does NOT apply.
- **INV-ISO-4 (cross-run cleanup).** Fixture temp dirs older than 24h are GC'd at harness invocation start. Mkdtemp config dirs older than the current run are removed by a finalizer. mkdtemp directories with credential symlinks MUST NOT survive process exit.
- **INV-ISO-5 (zero state from previous test).** Between tests within a suite, harness verifies new fixture path is fresh (mtime ≤ 5s, dir non-empty, `.git` not symlinked outside `$TMPDIR`).
- **INV-ISO-6 (pre-spawn symlink revalidation, R1-HIGH-09).** Every test launcher MUST re-read the credential symlink target via `os.readlink` and assert `os.stat(target).st_ino == expected_ino` immediately before subprocess spawn. TOCTOU window between symlink-create and CLI-spawn must be closed.

## CLI parity

- **INV-PAR-1 (same prompt).** Within one test, prompt string passed to each CLI is byte-identical.
- **INV-PAR-2 (same scoring criteria count).** `expect[cli]` may differ on marker tokens (CC's CLAUDE.md vs codex's AGENTS.md) but MUST have the same number of criteria with same `kind` distribution. Counts include `fs_assert` kinds (R1-UX-12). **Carve-out (R2-MED-02):** when a cell resolves to `skipped_artifact_shape` (e.g., implementation × {codex, gemini} in Phase 1), that cell is exempt from criteria-count parity. Invariant applies only across CLIs whose cells resolve to a runnable state for the test.
- **INV-PAR-3 (per-CLI timeout calibration).** Timeouts are CLI-specific (cc: 60s, codex: 60s, gemini: 180s). Hard cap per test = `2 × test_timeout`. Schema records `effectiveTimeoutMs` per record.

## Auth preconditions

- **INV-AUTH-1 (probe before suite loop).** One probe per CLI per suite (R1 change: not just per invocation). Cached for that suite's duration.
- **INV-AUTH-2 (skip vs fail on auth).** Missing auth = `skipped_cli_auth`. Wrong-account = `error_invocation`.
- **INV-AUTH-3 (re-probe between suites, R1-HIGH-10).** Auth probe MUST re-run before each suite begins. cc OAuth tokens expire on ~1h boundary; full Phase-1 run is up to 90min. Single probe at t=0 is insufficient. Mid-run expiry detected via stderr regex `401|invalid_grant|expired_token|token_expired|reauth` triggers re-probe; if re-probe fails, test gets `skipped_cli_auth` and JSONL records `auth_state_changed: true`.

## Permission enforcement (R1)

- **INV-PERM-1 (runtime permission enforcement, R1-MED-01).** At subprocess spawn time, the launcher MUST assert `(spec.suite, spec.cli) → spec.permission_mode` matches the per-suite × per-CLI launcher table from `05-launcher-table-contract.md`. Mismatch is a hard panic, not a warning. Suite-level convention is insufficient — runtime enforcement at the spawn boundary catches reordering, bypass via direct launcher invocation, and accidental cross-suite leakage.

## Determinism baseline

- **INV-DET-1 (flake vs fail discrimination).** A failing test re-runs once. Re-run state recorded in JSONL (`attempts: 2`, `attempt_states: ["fail", "pass"] → state: "pass_after_retry"`). State-after-retry is distinct from clean pass.
- **INV-DET-2 (gemini quota retry).** `exhausted your capacity` stderr → 10s `time.sleep` (NOT busy-wait) + single retry. Two consecutive quota stderrs → `skipped_quota`. Generalized to all three CLIs (codex 429 + cc rate-limit signals).
- **INV-DET-3 (model non-determinism is observable).** Same `(suite, test, cli, model)` rerun MUST produce stable pass/fail rate ≥ 80% across 5 trials. Tests below 80% land in `flaky/` quarantine (state `skipped_quarantined`) until rewritten. Quarantine lifecycle in FR-14.

## Output schema stability

- **INV-OUT-1 (semver schema).** JSONL schema versioned in header (`harness_version`, `schema_version`). Independent semvers (ADR-G). Breaking = rename/remove field, change type, remove `state` enum value. Adding optional fields = minor.
- **INV-OUT-2 (one record per test, one header per file).** First line is `{"_header": true, ...}`. Empty files invalid.
- **INV-OUT-3 (state taxonomy is closed with explicit precedence ladder, R1-AD-14, R2-MED-01 split).** Closed enum. Two distinct ladders to avoid conflating per-record predicate resolution with run-loop boundaries:
  - **Within-test predicate precedence** (a single test record resolves to exactly one state): `error_fixture > error_invocation > error_json_parse > error_timeout > skipped_sandbox > skipped_artifact_shape > pass_after_retry > pass > fail`. `pass` and `fail` are mutually exclusive at attempt boundary; the ladder reflects "more-specific state wins."
  - **Across-test invariants** (apply at run-loop boundaries, not within a record): `skipped_cli_missing` (set at suite start when `which <cli>` fails), `skipped_cli_auth` (set when auth probe fails), `skipped_quota` (set after two consecutive quota retries), `skipped_quarantined` (test marked quarantined; not run by default), `error_token_budget` (budget circuit breaker fires; un-run tests stamped). If the budget breaker fires DURING an in-flight test, that test's record uses its in-flight predicate (likely `error_invocation` or `error_timeout`); subsequent un-run tests get `error_token_budget`.
  - Adding state = minor; renaming = major.

## Runtime constraints

- **INV-RUN-1 (Python stdlib only).** Per `independence.md` §3. Node permitted only as child process the launcher invokes; orchestrator is Python.
- **INV-RUN-2 (no shell interpolation).** All `subprocess.run([list], shell=False)`. Fixture paths and prompts MUST NOT be interpolated into a shell string.
- **INV-RUN-3 (process-group timeout, R1-HIGH-06).** SIGTERM at timeout, SIGKILL after 5s grace, **applied to the process group, not just the direct child.** Launcher uses `subprocess.Popen(..., start_new_session=True)`; on timeout, `os.killpg(os.getpgid(p.pid), signal.SIGTERM)`, wait 5s, then SIGKILL the process group. CC/codex/gemini fork sub-processes; orphan-grandchildren accumulation is a credential-leak channel (inherited fds bypass perm re-check). Credential symlink fd opened with `O_CLOEXEC`.
- **INV-RUN-4 (no test time-bombs).** Per `testing.md` Rule 1, any wall-clock literal in a fixture (e.g. fake OAuth `expires_at`) MUST be year-2100+ (`4102444800`).
- **INV-RUN-5 (no real `~/.claude` writes).** Capability/compliance/safety use stub HOMEs only. Implementation suite's writes are scoped to `coc-env/` AND further confined by sandbox profile (CRIT-01).
- **INV-RUN-6 (concurrency=1 in Phase 1).** Sequential execution enforced in code. v1.1 considers parallel suite-level (different fixtures, no shared state).
- **INV-RUN-7 (token-budget circuit breaker, R1-MED-03).** Harness tracks total `input_tokens + output_tokens` across all tests in a single invocation. Default cap: 5,000,000 input tokens / 1,000,000 output tokens. Breach aborts the run with state `error_token_budget` for un-run tests. Override via `--token-budget-input N --token-budget-output N`. Prevents infinite-spend runaway from misconfigured retry paths.
- **INV-RUN-8 (suite-ordering enforcement, R1-CRIT-04).** When multiple suites are selected in a single invocation, non-write suites MUST run before write suites. `coc-eval/run.py implementation safety` exits 64 with `ordering violation: write-mode suite must run last`. `coc-env/` validation: refuse to start if `coc-env/` has untracked files outside the scaffold whitelist, regardless of which suite is requested.

## Cross-references

- `05-launcher-table-contract.md` — INV-PERM-1 implementation site
- `06-jsonl-schema-v1.md` — INV-OUT-1, INV-OUT-2, INV-OUT-3 schema artifacts
- `09-security-review.md` — security findings these invariants address
- `04-validate/01-redteam-round1-findings.md` — origin of R1 additions
