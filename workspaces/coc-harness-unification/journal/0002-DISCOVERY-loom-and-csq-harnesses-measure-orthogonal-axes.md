---
type: DISCOVERY
date: 2026-04-28
created_at: 2026-04-28T22:35:00+08:00
author: agent
session_id: term-4164
session_turn: 60
project: coc-harness-unification
topic: Loom and csq harnesses measure orthogonal axes; consolidation = addition not replacement
phase: analyze
tags: [harness, evaluation, taxonomy, scoring]
---

# DISCOVERY — Loom and csq harnesses measure orthogonal axes

## What was discovered

Surveying loom's `~/repos/loom/.claude/test-harness/` and csq's `coc-eval/runner.py` side-by-side surfaced that they answer **different questions** — they are not duplicates of each other, and consolidation is an addition operation, not a replacement.

| Harness | Question answered                                                                     | Scoring                                                 | Permission mode                                     |
| ------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------- | --------------------------------------------------- |
| Loom    | Does the CLI follow rules, refuse adversarial prompts, auto-load artifacts correctly? | Regex `contains`/`absent` on stdout+stderr              | plan / read-only (cannot write files)               |
| csq     | Can the model fix real bugs when guided by COC artifacts?                             | 3-tier (artifact diff + full/partial regex + COC bonus) | `--dangerously-skip-permissions` (must write files) |

Loom is a **compliance/safety/capability evaluator**. csq is an **implementation-capability evaluator**. They share zero scoring contract overlap. Loom's RULE_ID-citation tests are uninterpretable as implementation tests; csq's artifact-evidence tier is uncomputable in plan-mode.

The pre-survey assumption (encoded in journal 0074) was that csq would "extend its existing harness to support 3 CLIs" — implying the loom contribution was the CLI-support layer. The actual contribution is **three additional suites of measurements** that csq did not perform before.

## Why this matters

Three downstream effects:

1. **Per-suite permission profile is mandatory.** csq's existing `--dangerously-skip-permissions` drives implementation suite. Loom's `--permission-mode plan` (cc), `--sandbox read-only` (codex), `--approval-mode plan` (gemini) drive the other three. There is no global "harness permission mode" — it varies per suite × per CLI. ADR-E in `01-analysis/07-adrs.md` codifies this.

2. **Two scoring backends.** `regex` (loom-style contains/absent) for capability/compliance/safety; `tiered_artifact` (csq-style) for implementation. Per-test discriminator `scoring_backend`. The JSONL schema must accommodate both (see DECISION journal 0003 for the schema fallout).

3. **Two fixture strategies.** `per-cli-isolated` (loom — cp+git-init per test) for the new suites; `coc-env` (csq — shared mutate-and-reset) for implementation. Per-suite `fixture_strategy`. ADR-D codifies this.

The consequence: PRs in the implementation plan (`02-plans/01-implementation-plan.md`) cannot land suites in arbitrary order. H1-H4 land scaffolding (validators, redaction, fixture lifecycle, JSONL writer); H5-H7 land loom-shape suites; H8 lands implementation suite; H10-H11 activate codex/gemini.

## Counterintuitive finding

The Phase 1 brief hinted that csq's existing 5 EVAL-\* tests might be deprecated in favor of loom's 18-test taxonomy. The orthogonality finding falsifies that. The 5 implementation tests measure something the loom suites cannot — actual code modification under COC guidance. Deprecation would have lost csq's published Foundation evaluation pathway (MiniMax M2.7, Z.AI GLM-5.1, Ollama scored against COC implementation under ablation modes). Per ADR-C, csq's ablation/profile system survives consolidation, scoped to the implementation suite only.

## For Discussion

1. The 4-suite design treats compliance/safety/capability/implementation as peers. Are they actually peer measurements, or does implementation depend on the others passing (a CLI that fails compliance/safety should not be trusted for implementation)? If implementation-suite scoring depends on compliance-suite results, the harness needs a dependency graph between suites — currently absent.

2. Loom's three suites measure CLI behavior (does the CLI's loader respect `paths:` frontmatter? does it cite RULE_ID?). csq's implementation suite measures model behavior (does the model fix the bug?). These are observably different — the CLI is the integration point for the model. If a Phase 2 capability layer (LoRA / structured output / MCP gating) shifts where COC compliance is enforced from CLI to model, the suite split itself becomes a leaky abstraction.

3. Counterfactual — if csq's existing implementation suite hadn't existed, would Phase 1 still have ported loom's three suites, or would we have built a single implementation-style suite for cc/codex/gemini and skipped the rule-citation/safety axes? Loom's red-team convergence (6 rounds) suggests rule-citation is load-bearing for distinguishing rule-adherent refusal from sandbox-enforced refusal — but csq users may not need that distinction if they're measuring "did the bug get fixed."

## References

- `01-analysis/01-research/01-harness-comparison.md` — full comparison matrix
- `01-analysis/02-failure-modes.md` F08 — consequence: implementation suite cc-only Phase 1
- `01-analysis/07-adrs.md` ADR-B, ADR-C, ADR-D, ADR-E — codify the orthogonality consequences
- `~/.claude/accounts/term-4164/projects/-Users-esperie-repos-terrene-contrib-csq/memory/project_csq_loom_relationship.md` — pre-survey framing (now updated)
