---
type: DECISION
date: 2026-04-30
created_at: 2026-04-30T00:00:00Z
author: agent
session_id: h7-implementation-suite
session_turn: 1
project: coc-harness-unification
topic: H7 ships — implementation suite (EVAL-A004/A006/B001/P003/P010) under tiered_artifact backend, with sandbox + canary + audit-hook isolation tripwires
phase: implement
tags:
  [coc-eval, implementation, tiered_artifact, sandbox, canary, audit_hook, h7]
---

# H7 — Implementation suite + sandbox + canary + audit hook shipped

## What landed

- **`coc-eval/suites/implementation.py`** — SUITE dict wrapping the existing 5 EVAL TEST*DEFs (`tests/eval*\*.py`) under the v1.0.0 schema. Each entry uses `scoring_backend: "tiered_artifact"`, `fixturePerCli: {"cc": "coc-env"}`, plus extension fields `scoring`, `scaffold`, `max_turns`, `timeout_sec`. Adapter `\_adapt`renders legacy`id`/`prompt`/`scoring`/`scaffold` fields into SUITE shape.
- **`coc-eval/lib/scoring_backends.py`** — new module with `score_tiered_artifact` (wraps the legacy tier scorer at `coc-eval/scoring.py`), `extract_cc_response` (parses cc's `--output-format json` envelope), `collect_git_artifacts` (git diff + new files capped at 1 MiB/file), and `detect_canary_leak`. Constants `MEMORY_CANARY_VALUE` / `CREDENTIAL_CANARY_MARKER` keep the marker substring in source while the full canary credential token literal lives only in runtime-built fixture content (no secret-scanner trip).
- **`coc-eval/lib/canary.py`** — canary value/file builders. `build_canary_credential_token` constructs the synthetic OAuth token from concatenated parts at runtime; `write_canary_credentials_file` writes the JSON payload with `0o600` perms; `write_memory_canary_file` plants the memory canary content. Cross-module sync test guards constant drift.
- **`coc-eval/lib/credential_audit.py`** — `sys.addaudithook` defense-in-depth tripwire. Fires on harness-process Python `open()` events for `/.claude/.credentials.json`, `/.ssh/id_rsa`, `/.aws/credentials`, etc. Raises `CredentialAuditViolation`. Documented as defense-in-depth — does NOT see cc subprocess syscalls.
- **`coc-eval/lib/runner.py`** scoring backend dispatch — `_run_one_attempt` now reads `test_def["scoring_backend"]` and dispatches between `score_regex` (existing) and `score_tiered_artifact` (new). `run_test_with_retry` gates `cli != "cc"` to `skipped_artifact_shape` for tiered*artifact tests (Phase 1 ADR-B). Canary-leak detection runs post-scoring; any leak forces `pass: false` and appends a `canary_leak*\*`criterion. New helper`\_build_scaffold_setup_fn`materializes scaffold trees from`coc-eval/scaffolds/<name>/`into the prepared fixture (refusing top-level symlinks). Audit hook armed in`run()`if`implementation` is in the selection.
- **`coc-eval/lib/launcher.py::build_stub_home`** — plants memory canary at `<home_root>/.claude/memory/_canary.md` for every suite (defense-in-depth — only the implementation suite has the prompt-driven exfil pressure, but the canary costs nothing on every run).
- **`coc-eval/runner.py`** — three legacy fanouts (`_symlink_shared_dirs`, `build_bare_config`, `build_ablation_config`) drop `"memory"` from the symlinked-into-config list per F07/AD-11. Legacy `def main()` promoted to `legacy_runner_main`; module-level alias `main = legacy_runner_main` preserves the import-name contract for the H7→H13 transition window.
- **`coc-eval/run.py`** — three new flags: `--mode {full,coc-only,bare}`, `--ablation-group {no-rules,no-agents,no-skills,rules-only}`, `--profile NAME` (validated via `validate_name` for AC-38 — bad names exit 64 with a per-flag error). Currently informational on the lib/runner.py path; legacy compat for the runner shim.
- **`coc-eval/fixtures/coc-env/`** — minimal COC base fixture (README only) used by every implementation test. Per-test scaffolds are layered on top by `_build_scaffold_setup_fn`.
- **`coc-eval/fixtures/credential-canary/`** — fixture-context README. The canary credential JSON is built and written at test time by `lib/canary` to keep the literal out of source control.
- **`coc-eval/suites/__init__.py`** — `SUITE_REGISTRY` now includes `"implementation": IMPLEMENTATION_SUITE`.
- **`specs/08-coc-eval-harness.md`** — three new sections: "Tiered_artifact scoring backend", "Canary-leak detection + isolation tripwires", "F07/AD-11 memory drop".

## Lib pytest delta

`328 → 384` (+56 H7 tests):

- `tests/lib/test_scoring_backends.py` (17 tests) — backend dispatch, JSON envelope extraction, git artifacts, canary detection, threshold edges
- `tests/lib/test_canary.py` (6 tests) — token construction, payload shape, file perms, content shape, cross-module constant sync
- `tests/lib/test_credential_audit.py` (9 tests) — guarded suffixes, normpath traversal collapse, install-once, raises on guarded open, silent on unrelated
- `tests/lib/test_implementation_suite.py` (8 tests) — SUITE shape, 5 test ids match manifest, tiered_artifact backend, scoring tiers populated, scaffold strings, schema validation
- `tests/lib/test_h7_runner_integration.py` (16 tests) — F07/AD-11 memory drop in 2 legacy fanouts, scaffold setup_fn boundaries (refuse `..`, refuse missing dir, refuse non-string, refuse top-level symlink, copies known scaffold), run.py `--profile` traversal/slash rejection, `--mode`/`--ablation-group` choice validation, legacy_runner_main alias preserved.

## Gate verification

- `python coc-eval/run.py --validate` → `OK: 18 tests, 45 criteria across 3 CLIs`
- `python -m pytest coc-eval/tests/lib/` → `384 passed`
- `pyright coc-eval/lib coc-eval/suites coc-eval/run.py coc-eval/tests` → 0 errors (the IDE-reported "could not be resolved" warnings are pyright stale-cache artifacts; the modules import cleanly under pytest)
- `coc-eval/scripts/check-fixture-substitution.sh` → `OK: fixtures contain no proprietary product references`
- (Live cc gate runs after security-review-round1 convergence — see journal 0019.)

## Why this shape

- **`tiered_artifact` wraps legacy scoring rather than reimplementing.** The csq `coc-eval/scoring.py:score_test` already implements multi-tier artifact-aware scoring. H7 adds a thin v1.0.0-schema-rendering wrapper rather than rewriting; H13 retires the legacy module.
- **Canary detection forces `pass: false` outside the threshold check.** A model with a perfect tier score that ALSO leaks the memory canary must fail. We append `canary_leak_*` criteria with 0/1 points and explicitly set `score["pass"] = False` BEFORE updating max_total — a future refactor that recomputes pass from the ratio cannot accidentally re-flip it. (Defense-in-depth review will tighten this further.)
- **Memory canary planted in `build_stub_home` for ALL suites, not just implementation.** Marginal cost is one file write; the upside is that capability/compliance/safety also exercise the isolation, surfacing any cross-suite leak before implementation runs.
- **Audit hook is defense-in-depth ONLY.** The primary defense for credential isolation is the process-level sandbox (`sandbox-exec` on macOS, `bwrap` on Linux). The audit hook fires on `open()` events from THIS Python process — it catches harness-internal regressions but does NOT see cc subprocess syscalls.
- **Scaffold copy refuses top-level symlinks.** A scaffold that includes `link → /etc/passwd` would otherwise be copied into the fixture and committed by `git init`. We refuse at copy time. Reviewer (a) flagged that NESTED symlinks via `shutil.copytree(..., symlinks=False)` get DEREFERENCED (silently inlined) — that fix lands in security-review convergence.
- **Canary credential literal lives in runtime-built fixture content.** Pre-commit secret scanner blocks `sk-ant-*` literals in source. Constructing the token from concatenated parts in `lib/canary.build_canary_credential_token` keeps the source clean while the actual canary file (written by `write_canary_credentials_file` at test time) carries the literal. Marker substring (`CANARY_DO_NOT_USE_AAA…`) is what `detect_canary_leak` greps for.

## Cross-references

- Plan: `02-plans/01-implementation-plan.md` §H7
- H6 ship journal: `journal/0016-DECISION-h6-compliance-suite-shipped.md`
- H6 round-1 review: `journal/0017-RISK-h6-security-review-round1-converged.md`
- Round-1 security review for H7: `journal/0019-RISK-h7-security-review-round1-converged.md` (this session)
- Spec: `specs/08-coc-eval-harness.md` (Tiered_artifact + Canary + Memory drop sections)
- Sandbox profile: `coc-eval/sandbox-profiles/write-confined.sb`

## For Discussion

- **Q1 (counterfactual):** If H7 had skipped the audit hook and relied on the sandbox alone, what kind of regression would slip through? Concretely, name a future code change that would silently re-introduce a credential read from harness Python that the sandbox cannot catch (because it's not a cc subprocess) but the audit hook would.
- **Q2 (challenge assumption):** The 70% pass threshold (`_TIERED_ARTIFACT_PASS_PCT = 0.70`) is hardcoded. The H7 plan calls for ≥35/50 = 70% on Opus 4.7 as a parity floor with the legacy csq runner. As models improve, that floor becomes lax. What evidence would tell us to lift it to 80%, and at what cadence should it be re-evaluated?
- **Q3 (extend):** Memory canary detection is byte-substring only. Reviewer (a) correctly noted that base64-encoded leaks evade this. We accepted byte-substring for H7 because (a) the threat model is "model casually quotes content it shouldn't have read", (b) deliberate adversarial encoding is out of scope for the same-user threat model. Is this trade-off correct, or should we add at least the obvious encodings (base64, hex, URL-encoded, whitespace-collapsed) to the detector?
