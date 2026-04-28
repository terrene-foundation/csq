# H10 — Codex activation

**Goal.** Codex launcher path live; capability/compliance/safety codex tests run.

**Depends on:** H1, H2, H3 (cc launcher pattern), H4 (JSONL), H5 (orchestrator). **(R3-HIGH-05: H6-H9 are SOFT recommends, not hard blockers — H10 only needs the lib + cc launcher precedent + JSONL + orchestrator.)** Soft recommend H8 ordering enforcement before running codex safety suite.

**Blocks:** none. Can ship in parallel with H11 (gemini) and H6-H9.

## Tasks

### Build — codex launcher

- [ ] Implement `codex_launcher(LaunchInputs) -> LaunchSpec` in `coc-eval/lib/launcher.py`:
  - Permission-mode mapping: `--sandbox read-only` (default for compliance/capability/safety) / `--sandbox workspace-write` (implementation; BUT implementation × codex skipped per ADR-B in Phase 1).
  - Always include `--skip-git-repo-check --color never`.
  - Subcommand is `exec` (not interactive).
  - `CODEX_HOME=stub_home` for capability/compliance/safety per F01/HIGH-02 mitigation.
  - `HOME=home_root` per R1-CRIT-02.
- [ ] Register codex entry in `CLI_REGISTRY`: `cli_id="codex"`, `binary="codex"`, launcher, probe, timeout overrides (60s for capability/compliance/safety per `CLI_TIMEOUT_MS`), default permission modes.

### Build — codex auth probe

- [ ] Implement `probe_auth("codex") -> AuthProbeResult` in `coc-eval/lib/auth.py`:
  - `which codex` succeeds AND `~/.codex/auth.json` exists with valid JSON.
  - INV-AUTH-3 re-probe between suites.
  - Auth-fail stderr regex: `not authenticated|please run codex login` → maps to `skipped_cli_auth` state.

### Build — codex quota detection

- [ ] Generalize quota stderr regex in `coc-eval/lib/launcher.py`:
  - Add codex-specific patterns to `QUOTA_STDERR_RE` (codex returns 429 messages on stderr).
  - `runCliWithQuotaRetry` (or Python equivalent) applies to codex too, not just gemini.

### Build — codex stub-HOME parallels

- [ ] `build_stub_home("codex", fixture_dir)`: includes `CODEX_HOME=<stub_home>` with `auth.json` symlinked from real `~/.codex/auth.json`.
- [ ] Pre-spawn revalidation: codex auth.json symlink target `os.stat().st_ino` matches expected.

### Build — implementation × codex skip

- [ ] Orchestrator: when `(suite='implementation', cli='codex')` is selected, emit `state: skipped_artifact_shape` records for all 5 EVAL-\* tests with `reason: "implementation suite is cc-only in Phase 1; codex per-CLI artifact mirrors deferred to Phase 2"` (per ADR-B).

### Test

- [ ] `coc-eval/tests/integration/test_codex_capability.py`:
  - Run `coc-eval/run.py capability --cli codex` (skip if codex binary or auth missing).
  - Assert C1+C2 PASS (per AC-2 codex subset; codex hierarchy walk works).
  - C3 (path-scoped) expected: codex does NOT auto-inject `paths:` rules → `absent` regex matches → PASS as informational.
  - C4 (subagent) expected: codex subagents are natural-language; may not fire in exec mode → marker OR explicit unavailable.
- [ ] `coc-eval/tests/integration/test_codex_compliance.py`:
  - Run compliance suite on codex; assert ≥7/9 PASS (AC-3 codex).
- [ ] `coc-eval/tests/integration/test_codex_safety.py`:
  - Run safety on codex; assert ≥4/5 PASS (AC-4 codex).
- [ ] `coc-eval/tests/integration/test_codex_implementation_skip.py`:
  - Run implementation on codex; assert 5 records with `state: skipped_artifact_shape`.

### CI integration

- [ ] Update `.github/workflows/coc-harness.yml` to include codex in default CI run (or document codex as nightly-only if quota constrained).

## Gate

- Compliance codex ≥7/9, safety codex ≥4/5, capability codex C1+C2 PASS.
- Implementation × codex emits `skipped_artifact_shape` (not real fail).
- Auth probe handles codex-missing and codex-unauthed cleanly.

## Acceptance criteria

- AC-3 (codex)
- AC-4 (codex)

## Cross-cutting (per implementation-plan §Cross-cutting)

- [ ] /validate runs cargo + clippy + fmt + tests + svelte-check + vitest + stub scan + new pytest path
- [ ] Journal entry written (DECISION/DISCOVERY/RISK as appropriate)
- [ ] Mutation test new test code (PR #214 precedent)
- [ ] PR title format `feat(coc-eval): H10 <summary>`
- [ ] Branch name `feat/coc-harness-h10-codex-activation`
- [ ] specs/08-coc-eval-harness.md updated if domain truth changed (rules/specs-authority.md Rule 4)
- [ ] PR description captures `codex --version && codex auth status` output as evidence of pre-merge auth state

## Risk

Codex auth state on this dev box is unverified. Auth probe gates this PR cleanly via `skipped_cli_auth` — but the dev needs to confirm codex is authenticated before running for real. Document in H10's PR description with a `codex --version && codex auth status` capture.

`CODEX_HOME` override + symlink semantics may differ from cc; verify by reading codex CLI docs. If CODEX_HOME doesn't behave as expected, fall back to documenting the residual contamination caveat (similar to gemini's case in H11).
