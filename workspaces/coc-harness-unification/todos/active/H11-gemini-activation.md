# H11 — Gemini activation

**Goal.** Gemini launcher path live; capability/compliance/safety gemini tests run.

**Depends on:** H1, H2, H3, H4, H5. **(R3-HIGH-05: H6-H9 are SOFT recommends, not hard blockers.)** Independent of H10 (can ship in parallel).

**Blocks:** none.

## Tasks

### Build — gemini launcher

- [ ] Implement `gemini_launcher(LaunchInputs) -> LaunchSpec` in `coc-eval/lib/launcher.py`:
  - Permission-mode mapping: `--approval-mode plan` (default for capability/compliance/safety) / `--approval-mode auto-edit` (implementation; BUT implementation × gemini skipped per ADR-B in Phase 1).
  - **No HOME override env variable** (gemini hierarchy: project-local `.gemini/` wins per Gemini docs). Document this as known measurement caveat in spec.
  - `HOME=home_root` per R1-CRIT-02 (still applies — closes credential-exfil path even without gemini-specific config-dir env).
- [ ] Register gemini entry in `CLI_REGISTRY`: `cli_id="gemini"`, `binary="gemini"`, launcher, probe, timeout overrides (180s for ALL suites per gemini's slow first-token latency), default permission modes.

### Build — gemini auth probe

- [ ] Implement `probe_auth("gemini") -> AuthProbeResult`:
  - `which gemini` succeeds AND `~/.gemini/oauth_creds.json` exists with valid JSON.
  - INV-AUTH-3 re-probe between suites.

### Build — gemini quota retry

- [ ] Implement `run_cli_with_quota_retry` in `coc-eval/lib/launcher.py`:
  - Detect quota stderr regex: `/exhausted your capacity|quota will reset/i`.
  - On match: `time.sleep(QUOTA_RETRY_DELAY_MS=10_000 / 1000)` (NOT busy-wait; F14 fix; LOW-01 follow-through).
  - Single retry; if second attempt also hits quota → state: `skipped_quota`.
  - Generalize to all CLIs (cc + codex too can return 429-ish signals).
  - Cap total wall-clock per test at `2 × test_timeout` to prevent F15 stack-up.

### Build — gemini-specific stub-HOME parallels

- [ ] `build_stub_home("gemini", fixture_dir)`: NO config-dir env; relies on fixture-local `.gemini/` taking precedence per gemini hierarchy. Document as caveat.
- [ ] Fixture-local `.gemini/` is part of the loom fixtures already (subagent fixture has `.gemini/agents/test-agent.md`).

### Build — plan-mode equivalence caveat (MED-08 doc)

- [ ] Document in `specs/08-coc-eval-harness.md`: "Gemini safety-suite results under `--approval-mode plan` are plan-mode behavioral assertions, NOT execution-mode. cc and codex are the two CLIs whose safety scores transfer to non-plan execution. If gemini ships an execution mode (`--approval-mode auto`), re-run safety in that mode."

### Test

- [ ] `coc-eval/tests/integration/test_gemini_capability.py`:
  - Run `coc-eval/run.py capability --cli gemini` (skip if gemini binary or auth missing).
  - Assert C1+C2 PASS (gemini hierarchy walk works).
  - C3: gemini does NOT auto-inject `paths:` → `absent` regex matches → PASS.
  - C4: gemini's `@test-agent` native invocation succeeds.
- [ ] `coc-eval/tests/integration/test_gemini_compliance.py`:
  - Run compliance on gemini; assert ≥6/9 PASS (AC-3 gemini).
- [ ] `coc-eval/tests/integration/test_gemini_safety.py`:
  - Run safety on gemini; assert ≥3/5 PASS (AC-4 gemini).
- [ ] `coc-eval/tests/integration/test_gemini_quota_retry.py`:
  - Synthetic stderr injection of `exhausted your capacity` triggers `state: skipped_quota` (AC-19).
  - Verify `time.sleep` is used (NOT busy-wait): test wall-clock during retry is ~10s without CPU pegging.

### Build — auth-missing integration test (AC-10, R3-MED-03)

- [ ] `coc-eval/tests/integration/test_gemini_auth_missing.py`:
  - Test setup: rename `~/.gemini/oauth_creds.json` → `oauth_creds.json.bak` for the duration.
  - Run `coc-eval/run.py all --cli all`; assert all gemini tests record `skipped_cli_auth`; cc and codex tests still run.
  - Test teardown: restore `oauth_creds.json`.

### Build — per-CLI cumulative wall-clock cap (AC-47, R3-MED-03)

- [ ] Implement per-CLI cumulative wall-clock tracking in `coc-eval/lib/runner.py`:
  - Configurable per-CLI cap; gemini default 25 min hard cap (AC-24c).
  - On breach: subsequent un-run tests for that CLI stamp `state: skipped_budget`; stdout WARN.
  - New state value `skipped_budget` already in INV-OUT-3 ladder.
- [ ] `coc-eval/tests/integration/test_gemini_wall_clock_cap.py` (AC-47):
  - Synthetic 30s sleep injected into 3 gemini tests via fixture; assert 4th gemini test records `skipped_budget`.

### CI integration

- [ ] Update `.github/workflows/coc-harness.yml`: gemini either skipped (default per Flow H to conserve quota) or runs in nightly job.

## Gate

- Compliance gemini ≥6/9, safety gemini ≥3/5, capability gemini C1+C2 PASS.
- Implementation × gemini emits `skipped_artifact_shape`.
- Quota retry path verified via stderr injection test (AC-19).
- Wall-clock under 90 min for full multi-CLI run on M-series Mac broadband (AC-24 revised).

## Acceptance criteria

- AC-3 (gemini)
- AC-4 (gemini)
- AC-10 auth-missing skip behavior (R3-MED-03)
- AC-19 (quota retry)
- AC-24 (revised: ≤90 min full multi-CLI; ≤50 min cc-only; ≤35 min CI-default)
- AC-47 per-CLI wall-clock cap → `skipped_budget` (R3-MED-03)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H11 <summary>`
- [ ] Branch name `feat/coc-harness-h11-gemini-activation`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)

## Risk

Gemini's lack of `HOME`-override config-dir env is a measurement caveat. User's global `~/.gemini/` may contaminate tests where fixture-local `.gemini/` doesn't take precedence. Document explicitly; if contamination is observed in practice, add a v1.1 follow-up (e.g., a Rust shim that intercepts gemini's HOME read).

The 180s gemini timeout is generous but not infinite. Slow-first-token gemini behavior + retry stack can blow through. F09's hard cap (`2 × test_timeout`) is the safety net.
