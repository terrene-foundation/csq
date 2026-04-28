# H5 — Capability suite (cc only)

**Goal.** First suite running end-to-end. Validates the contract (launcher + auth probe + JSONL + fixtures all wired up).

**Depends on:** H1, H2, H3, H4.

**Blocks:** H6 (compliance reuses orchestrator), H7, H8.

## Tasks

### Build — capability suite definition

- [ ] Create `coc-eval/suites/capability.py`:
  - `SUITE` dict per `05-launcher-table-contract.md` schema: `name="capability"`, `version="1.0.0"`, `permission_profile="plan"`, `fixture_strategy="per-cli-isolated"`, `tests=[...]`.
  - 4 tests ported from `~/repos/loom/.claude/test-harness/suites/capability.mjs`:
    - C1-baseline-root (per-CLI fixture mapping `{cc: "baseline-cc", codex: "baseline-codex", gemini: "baseline-gemini"}`)
    - C2-baseline-subdir (with `cwdSubdir: "sub"`)
    - C3-pathscoped-canary (fixture `pathscoped`)
    - C4-native-subagent (fixture `subagent`)
  - Each test has `expect[cli]: list[criterion]` with `kind ∈ {contains, absent}` and `pattern` regex.
  - `scoring_backend = "regex"` per test.
  - Phase 1: `expect[codex]` and `expect[gemini]` populated structurally (so H10/H11 don't refactor) but tests run cc-only (H10/H11 activate codex/gemini).

### Build — top-level orchestrator

- [ ] Create `coc-eval/lib/runner.py` (top-level orchestrator):
  - Suite discovery via `SUITE_MANIFEST` import (NOT glob — CRIT-03 fix).
  - Per-test loop: prepare_fixture → launcher.cc_launcher → spawn → score → record_result.
  - Auth-probe gate: skip suite if `auth_probes[cli].ok == False` → records `skipped_cli_auth` for every planned test in that suite × cli.
  - Retry-once-on-fail (INV-DET-1): failed test re-runs once; record `attempts` and `attempt_states`; final state is `pass_after_retry` if attempt 2 passes.
  - Token-budget circuit breaker (INV-RUN-7): tracks cumulative `input_tokens + output_tokens`; breach aborts run with `state: error_token_budget` for un-run tests.

### Build — argparse + run.py entry point

- [ ] Create `coc-eval/run.py`:
  - Positional: `suite` (one of capability/compliance/safety/implementation/all).
  - `--cli` (one of cc/codex/gemini/all; default all).
  - `--test` (comma-list).
  - `--skip-cli` (one or more) (FR-12).
  - `--skip-suite` (one or more) (FR-12).
  - `--validate` (FR-16 / AC-44, R3-CRIT-01) — invokes `lib/suite_validator.validate_suite()`; prints `OK: N tests, M criteria across K CLIs`; exits 64 on schema fail.
  - `--tag <name>` (FR-18 / AC-MED-03) — selects matching tests across suites via `tags: list[str]` per test; composes with `--cli` and `--skip-suite`.
  - **`--format pretty | jsonl | json`** (FR-17 / AC-34, R3-HIGH-04) — default pretty when isatty, jsonl in CI/piped. Pretty formatter prints exactly one RUNNING line + one terminal state line per test; ETA is monotonic-or-decreasing (rolling-average per-CLI runtime).
  - **`--resume <run_id>`** (FR-13 / AC-35-36, R3-CRIT-02) — re-reads `results/<run_id>/INTERRUPTED.json`; skips already-complete (suite, cli) pairs; deletes in-flight `.jsonl` (cleaner than truncating); continues.
  - **`--list-profiles`** (FR-19) — scans `~/.claude/settings-*.json`; prints name + resolved model + `profile_compatible_clis`.
  - **`--token-budget-input N` / `--token-budget-output N`** (FR-20) — wired from H7; flags exposed here for parity but enforcement lands in H7.
  - Custom usage block per UX-13 case D (no args / --help / unknown suite prints full usage with examples).
  - Validate all arg values via `validators.validate_name`.
  - Custom error messages for UX-13 cases A, B, E.
  - First stdout line and last stdout line both contain `run_id=` (AC-45).
  - **First-run zero-auth handling** (AC-32, R3-MED-03): if `auth_probes[*].ok == false` for every selected CLI, exit 78 (EX_CONFIG) with explicit banner naming each CLI's auth source + login command.

### Build — SIGINT handler + INTERRUPTED.json (R3-CRIT-02)

- [ ] `coc-eval/lib/runner.py` SIGINT handler (`signal.signal(SIGINT, ...)`):
  - Writes `results/<run_id>/INTERRUPTED.json` with `{completed_suite_clis: [...], in_flight: [...], interrupted_at: <ISO-8601>}`.
  - Final stderr: `interrupted at run_id=<run_id>; resume with: coc-eval/run.py --resume <run_id>`.
  - Aggregator on a run with `INTERRUPTED.json` prints `WARN: run_id=<X> was interrupted; reporting partial results.`

### Build — .github/workflows/coc-harness.yml (R3-HIGH-01)

- [ ] Create `.github/workflows/coc-harness.yml` (this is the H5 PR's responsibility):
  - Triggers: PR touching `csq/.claude/rules/`, `csq-core/`, `coc-eval/`, `coc-env/`.
  - Steps: setup Python; `apt install bubblewrap` on Linux; `pytest coc-eval/tests/lib/`; `coc-eval/run.py capability --cli cc`; grep guards (SUITE_MANIFEST, no-glob, no `shell=True`, fixture-substitution stub for H6, scaffold-injection stub for H8).
  - Subsequent PRs (H6, H8, H10, H11) ADD steps via diffs.

### Test

- [ ] `coc-eval/tests/integration/test_capability_cc.py`:
  - Run `coc-eval/run.py capability --cli cc`; assert 4 records emit; assert all 4 PASS on cc; assert each record has correct `cli_version`, `runtime_ms`, `score.pass: true`.
  - `coc-eval/run.py capability --cli cc --test C1-baseline-root` produces exactly 1 record + 1 header + 1 log (AC-11).
- [ ] `coc-eval/tests/test_argparse.py`: 5 UX-13 cases (A-E). Each error reproduced; assertions on stderr text (AC-43).
- [ ] `coc-eval/tests/integration/test_resume.py` (R3-CRIT-02): SIGINT a running harness mid-suite; assert INTERRUPTED.json written with correct schema; `--resume <run_id>` skips completed pairs and continues (AC-35, AC-36).
- [ ] `coc-eval/tests/test_format_pretty.py` (R3-HIGH-04): assert `--format pretty` prints one RUNNING + one terminal state line per test; ETA monotonic-or-decreasing across 5-test run (AC-34).
- [ ] `coc-eval/tests/integration/test_zero_auth_first_run.py` (R3-MED-03): mock all auth probes failing → exit 78 with banner (AC-32).
- [ ] `coc-eval/tests/integration/test_flake_discrimination.py` (AC-18): manually-failing test (synthetic CM with deliberately-wrong rule citation) records `attempts: 2`, `state: "fail"` in 5/5 trials.
- [ ] `coc-eval/tests/test_init_overhead.py` (AC-25): `time` first-suite invocation; assert ≤5s overhead before first test runs.
- [ ] `coc-eval/tests/test_cli_registry.py` (AC-42): stub `noop_cli` registered in `CLI_REGISTRY`; produces 4 `skipped_cli_missing` records without touching launcher table internals.

## Gate

- `coc-eval/run.py capability --cli cc` produces 4 JSONL records; C1-C4 all PASS.
- AC-43 argparse cases assert correct error messages.
- AC-45 first/last stdout lines contain run_id.

## Acceptance criteria

- AC-2 (cc subset of capability)
- AC-11 single-test invocation
- AC-18 flake-discrimination 5/5 (R3-MED-03)
- AC-25 init-overhead ≤5s (R3-MED-03)
- AC-32 zero-auth banner exit 78 (R3-MED-03)
- AC-34 pretty format + monotonic ETA (R3-HIGH-04)
- AC-35 / AC-36 resume from interrupt (R3-CRIT-02)
- AC-42 CLI registry stub `noop_cli` (R3-MED-03)
- AC-43 argparse error messages
- AC-44 `--validate` (R3-CRIT-01)
- AC-45 run_id printing
- FR-13 `--resume` (R3-CRIT-02)
- FR-16 `--validate` (R3-CRIT-01)
- FR-17 `--format` (R3-HIGH-04)
- FR-18 `--tag` (R3-MED-03)
- FR-19 `--list-profiles`

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H5 <summary>`
- [ ] Branch name `feat/coc-harness-h5-capability-suite`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)

## Risk

C3 (pathscoped canary) depends on cc auto-injecting rules with `paths:` frontmatter. cc behavior here is empirically observed via loom's redteam — but cc version drift could change it. If C3 fails, document as a model-version observation, not a harness bug; loom's `26-CONVERGED.md` shows C3 is an informational test for codex/gemini specifically.
