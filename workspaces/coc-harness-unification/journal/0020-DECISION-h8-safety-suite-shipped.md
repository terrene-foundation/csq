---
type: DECISION
date: 2026-04-30
created_at: 2026-04-30T00:00:00Z
author: agent
session_id: h8-safety-suite
session_turn: 1
project: coc-harness-unification
topic: H8 ships — safety suite (SF1-SF5) + cross-suite ordering (INV-RUN-8) + setup_fn dispatch
phase: implement
tags: [coc-eval, safety, setup_fn, inv-run-8, h8]
---

# H8 — Safety suite + cross-suite ordering + setup_fn dispatch shipped

## What landed

- **`coc-eval/suites/safety.py`** — SUITE dict with SF1-SF5 ported from loom `suites/safety.mjs`. Per-CLI expect lists (cc has plan-mode-equivalent alt-pattern + anti-blanket-refusal absent check; codex/gemini have parity criteria). SF4 carries a `setup_fn: sf4_setup` callable that writes `notes.md` with embedded SYSTEM-prefixed injection bait — symlink-safe (O_NOFOLLOW, refuses pre-existing symlinks at target).
- **`coc-eval/lib/runner.py`** — new `_resolve_test_setup_fn(test_def)` dispatches between the H7 `scaffold` field and the new `setup_fn` callable; both fields together → `ValueError`. `run_test_with_retry` now catches `ValueError` alongside `RuntimeError` (R1-A-HIGH-1 — was previously uncaught and crashed the whole run on a malformed SUITE entry). `runner.run()` gains `run_id_override` parameter for multi-suite invocations.
- **`coc-eval/run.py`** — positional `suite` changed from `nargs="?"` to `nargs="*"`; multi-suite invocation runs sub-runs sequentially via `runner.run(run_id_override=shared_run_id)` so all sub-runs write to the same `results/<run_id>/` directory (R1-B-HIGH-3). `_normalize_and_validate_suites` enforces canonical order (capability < compliance < safety < implementation); `--validate` skips ordering enforcement (B-MED-3 — schema-only operations don't need runtime ordering). Multi-suite + `--resume` rejected (R1-B-HIGH-1). Sub-run rc=78 short-circuits the loop (R1-B-HIGH-2). Module-load assertion on `set(_CANONICAL_SUITE_ORDER) == set(SUITE_MANIFEST)` (R1-B-HIGH-4).
- **`coc-eval/lib/suite_validator.py`** — at SUITE-load time, refuses entries with both `scaffold` and `setup_fn` set, non-callable `setup_fn`, or bare class `setup_fn` (R1-C-HIGH-2 — defense-in-depth before the runner's runtime check).
- **`coc-eval/suites/__init__.py`** — `SUITE_REGISTRY` now includes `"safety": SAFETY_SUITE` between compliance and implementation in canonical order.
- **`specs/08-coc-eval-harness.md`** — new "Cross-suite ordering (INV-RUN-8 / AC-32-quat)" section + "Per-test setup_fn (H8)" section.

## Lib pytest delta

`404 → 456 passed, 2 skipped` (+52 H8 tests):

- `tests/lib/test_safety_suite.py` (9 tests) — SUITE shape, 5 SF tests, schema validation, sf4_setup file write
- `tests/lib/test_h8_ordering_and_setup_fn.py` (17 tests) — `_normalize_and_validate_suites` (empty/single/all/canonical/inverted/duplicate/mixing), end-to-end exit-64 verification, `_resolve_test_setup_fn` (scaffold/callable/both-rejected/non-callable-rejected)
- `tests/lib/test_h8_security_review_round1.py` (26 tests) — round-1 fixes: regex flags + symlink-safe sf4_setup + ValueError catch + parity + ECDSA/PuTTY coverage + rule-citation \b anchor + bare-class rejection + multi-suite resume/short-circuit/run_id-override + manifest drift + --validate skip-ordering + suite-validator setup_fn checks + dynamic test count + scaffold-callable invocation

## Live cc gate

Pre-fix: SF1-SF5 5/5 pass on cc account 8 (~2 min total runtime). Note: the pre-fix absent-checks were VACUOUSLY passing because Python regex defaults to single-line mode; the H8 R1-A-CRIT-1 fix added `(?m)` inline flags so absent line-anchored checks actually anchor per line. Re-run after fixes confirms the 5/5 pass is still real (the model legitimately did not echo the bare commands).

## Why this shape

- **`setup_fn` callable on the SUITE entry, not a string-keyed registry.** The schema permits unknown properties; storing the callable directly keeps the SUITE as a single source of truth and avoids a second indirection layer. The schema validator catches non-callable / class-shaped values; the runner's `_resolve_test_setup_fn` is the second-line-of-defense.
- **INV-RUN-8 enforced in `run.py`, not `runner.run()`.** The canonical ordering is a CLI-facing UX contract; the run-loop already iterates suites in registry order. Forcing ordering in run.py keeps the runtime layer agnostic — a future programmatic caller can construct multiple `RunSelection`s in any order and run them however; the rejection only fires for the human-typed CLI shape.
- **`--validate` skips ordering.** Schema validation is a static check that doesn't execute tests; forcing canonical order on `--validate implementation safety` would punish operators who type whatever order their muscle memory produces. Duplicates and "all + specific" are still rejected because those are configuration smells regardless of execution.
- **Multi-suite `--resume` rejected, not silently fixed.** The `parse_resume` side effects (delete in-flight JSONL files; INTERRUPTED.json overwrites) make multi-suite resume genuinely tricky. Reject explicitly with a clear error rather than producing corrupted run state. Tracked as a future enhancement under H9+.
- **Single shared `run_id` across multi-suite sub-runs.** AC-45 contract preserved (one run_id printed per invocation start AND end). `run_id_override` parameter added to `runner.run()` to thread the shared id without invoking parse_resume side effects.

## Cross-references

- Plan: `02-plans/01-implementation-plan.md` §H8
- H7 ship journal: `journal/0018-DECISION-h7-implementation-suite-shipped.md`
- H8 round-1 review: `journal/0021-RISK-h8-security-review-round1-converged.md` (this session)
- Spec: `specs/08-coc-eval-harness.md` (new INV-RUN-8 + setup_fn sections)
- Loom source: `~/repos/loom/.claude/test-harness/suites/safety.mjs`

## For Discussion

- **Q1 (challenge assumption):** The `run_id_override` parameter on `runner.run()` is a workaround for the multi-suite `parse_resume` side-effect tangle. A cleaner future shape: extract a `run_inner(ctx, registry, ...)` helper that takes a fully-formed `RunContext` and lets `run.py` orchestrate `RunContext` lifecycle. Is this a worthwhile refactor for H9 (aggregator) or should we keep the parameter shape stable?
- **Q2 (counterfactual):** If H8 had landed setup_fn as a string-keyed registry (`"setup_fn_name": "sf4_setup"` + lookup in the suite module) instead of a direct callable, the schema would be JSON-serializable and the suite-validator could enforce it via plain string-list lookup. We picked direct-callable for simplicity. What's the failure mode that direct-callable risks but string-registry would prevent? (E.g., a SUITE entry that is JSON-roundtripped — does that path exist anywhere in the harness?)
- **Q3 (extend):** SF5 codex/gemini gained `absent CRIT-DEL refusal` criteria for INV-PAR-2 parity. Is this semantically correct for codex/gemini exec/plan modes? The over-refusal failure mode (citing CRIT-DEL to block a SCOPED command) applies regardless of CLI; the parity addition appears justified, but is there a CLI where the pattern could false-positive on a legitimate refusal-explanation flow?
