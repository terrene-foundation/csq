---
type: DECISION
date: 2026-04-28
created_at: 2026-04-28T14:00:00+08:00
author: co-authored
session_id: term-4164
session_turn: 25
project: csq-v2
topic: csq evolution from session manager to COC-native CLI
phase: analyze
tags: [architecture, multi-cli, capability-layer, roadmap, loom-boundary]
---

# DECISION — csq evolution into a COC-native CLI (Phase 1 + Phase 2a/2b)

## Decision

csq evolves in three sequenced phases beyond v2.3.1:

- **Phase 1 — Multi-CLI test mastery.** Port loom's `.claude/test-harness/` (capability/compliance/safety suites × cc/codex/gemini matrix, 7 fixtures, RULE_ID-citation contract, JSONL output) into csq's existing `coc-eval/` and consolidate. Prove csq can invoke and constrain all three CLIs against COC artifacts.
- **Phase 2a — Capability layer over legacy CLIs.** csq shells out to cc/codex/gemini and sits in the prompt/output pipeline applying STACKED techniques (structured output enforcement, prompt scaffolding, MCP gating, LoRA-style prompt-side adapters). Reads a unified `.coc/` standard with fallback to legacy `.claude/` / `.gemini/` / `AGENTS.md` during transition. Both API-key and CLI-OAuth paths preserved.
- **Phase 2b — Native csq CLI.** Direct API access (Anthropic / OpenAI / Google), same capability layer, no legacy CLI dependency. Triggered when Phase 1 harness scores prove Phase 2a stack works.

## What csq evolution is NOT (corrections from earlier framing)

- NOT a distribution vehicle for COC artifacts. Loom keeps that role; the 12 emission invariants (slot composition, parity contract, Codex 60KiB cap) stay loom's problem.
- NOT a Rust port of `compose.mjs` / `emit.mjs` — that was the wrong problem.
- NOT subject to loom's emission invariants. Those govern per-CLI emission for legacy CLIs, not csq.

## Why

Repos carry COC artifacts; CLIs read them. That separation is structural and unchanged. csq's role is on the CLI side: account switching (existing) plus Phase 2 unification. Loom's role on the artifact side is unchanged — it continues emitting per-CLI variants for legacy CLI users and may additionally emit the unified `.coc/` format as a new derivative.

## Loom-csq symbiotic boundary (rule to draft)

Both repos need a paired rule documenting the boundary: loom emits artifacts; csq dispatches CLIs + applies capability layer. Sync trigger when loom changes `.coc/` shape; csq must regression-test capability layer.

## Specs to draft (next sessions)

- `specs/08-coc-eval-harness.md` — Phase 1 contract: suites, fixtures, RULE_ID schema, per-CLI launcher abstraction, output schema
- `specs/09-unified-coc-artifact-standard.md` — Phase 2a/2b: unified `.coc/` format + per-model translation rules at invocation + coexistence with legacy formats during transition
- `specs/10-coc-model-capability-layer.md` — Phase 2a/2b: stacked techniques architecture, training data sourcing if applicable, harness-as-evaluator contract

## Open decisions (Phase 2 only — Phase 1 is clear)

1. **Unified format design** — clean-sheet `.coc/` directory + top-level `COC.md` primer (recommendation; not yet committed)
2. **Capability layer mechanism** — stacked combinations (recommendation: structured output + prompt scaffolding + MCP gating + post-validation; LoRA only if scores demand)
3. **Phase 2b API access** — direct calls to Anthropic/OpenAI/Google APIs; csq-managed OAuth for Anthropic, separate API keys for OpenAI/Google
4. **Authoring flow** — loom continues authoring; emits unified `.coc/` as new derivative alongside legacy per-CLI artifacts

## For Discussion

1. Phase 1 ports loom's harness wholesale; csq's existing `coc-eval/` 5-test scaffold becomes one of several test surfaces. Should the csq scaffold tests survive as a fourth suite, or be deprecated in favor of loom's converged 18-test capability/compliance/safety taxonomy?
2. The capability layer (Phase 2a) is described as "stacked" — but stacking introduces compounding latency. If the harness shows Phase 2a is 3× slower than bare CLI for the same compliance score, is that an acceptable tradeoff for the unified-format value, or does it kill Phase 2a as a product?
3. Counterfactual — if Phase 1 harness reveals codex or gemini scores significantly lower than cc on COC compliance even with the capability layer, does Phase 2b still ship as a 3-CLI native binary, or does it default to Anthropic-only with codex/gemini as opt-in?

## References

- Memory `project_csq_loom_relationship.md` (corrected Phase 2 framing)
- Loom harness `~/repos/loom/.claude/test-harness/`
- Loom multi-CLI converged spec `~/repos/loom/workspaces/multi-cli-coc/04-validate/26-CONVERGED.md`
- csq `coc-eval/runner.py` (Claude-only baseline to extend)
- csq `csq-cli/src/commands/run.rs:60-84` (per-surface dispatch already shipped at runtime layer)
