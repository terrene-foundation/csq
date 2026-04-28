---
type: CONNECTION
date: 2026-04-28
created_at: 2026-04-28T22:50:00+08:00
author: co-authored
session_id: term-4164
session_turn: 64
project: coc-harness-unification
topic: csq-loom symbiotic boundary post-Phase-1; paired rule needed
phase: analyze
tags: [boundary, ownership, cross-repo, paired-rule, loom-csq]
---

# CONNECTION — csq-loom symbiotic boundary post-Phase-1

## The connection

After Phase 1 ships, csq and loom have a symbiotic but clearly-divided relationship:

| Repo | Owns                                                                                                                  | Does not own                                     |
| ---- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| loom | COC artifact authoring + per-CLI emission (slot composition, 60KiB cap, parity contract for cc/codex/gemini variants) | Multi-CLI evaluation (no longer; csq takes this) |
| csq  | Multi-CLI evaluation harness (4 suites × up to 3 CLIs), capability layer (Phase 2)                                    | COC artifact authoring (loom retains)            |

The orthogonal-axes finding (journal 0002) explains why this split is structural, not accidental. Loom answers "what should the artifacts look like?" csq answers "do CLIs follow them under load?"

## Why a paired rule is needed

The split is clean today (Phase 1 deliverables converge). Without an explicit paired rule in BOTH repos, drift creeps in:

- Loom changes its `RULE_ID` grammar from `COMP-IND-COMM-5K8` to `IND.5K8.COMM`. csq's compliance fixtures (ported from loom) no longer match — silent fake-fail until a human notices.
- Loom emits a new `.coc/` artifact format (Phase 2a target). csq's harness has no test for it — silent gap until a Phase 2 redteam.
- A contributor adds a multi-CLI test harness to loom (forgetting csq took ownership). Two harnesses now exist; CI maintainers don't know which is canonical. Repeat the parallel-infrastructure failure that journal 0074 warned against.

The paired rule (PR H12 in `02-plans/01-implementation-plan.md`):

- `csq/.claude/rules/csq-loom-boundary.md` — csq owns multi-CLI eval harness; loom owns COC artifact authoring + per-CLI emission. Cross-references to journal 0074, journal 0002 (this connection), ADR-J.
- `loom/.claude/rules/loom-csq-boundary.md` — same boundary stated from loom's side; pointer to csq's harness as canonical multi-CLI evaluator.

## Key contracts the paired rule must enforce

Round-1 redteam (R1-HIGH / AD-08) surfaced three gaps in ADR-J that the paired rule must close:

1. **Shape-change protocol.** When loom changes the `.coc/` shape (RULE_ID grammar, prompt strings, scoring patterns), csq's harness MUST regression-test against the new shape. Concretely: csq runs harness against loom's emitted fixtures pre-merge (CI step in csq), OR loom CI runs csq's harness on its own emitted fixtures pre-merge (CI step in loom). Pick one — write it down.

2. **Schema authority.** csq is the authority for fixture content (RULE_ID grammar, prompt strings, scoring patterns) since csq's harness is the canonical evaluator. Loom is the authority for artifact-format details (slot composition, frontmatter shape, file-layout conventions). Disputes default to csq for content, loom for format.

3. **Drift-detection cadence.** Quarterly CI job in csq runs `git diff loom/.claude/test-harness/fixtures csq/coc-eval/fixtures` with a whitelisted divergence list. Un-whitelisted drift fails the job and pages a maintainer. Without a cadence, both repos evolve independently and the boundary erodes.

## What this enables for Phase 2

- Phase 2a (unified `.coc/` standard): loom designs the format; csq's harness validates that csq's CLI (and cc/codex/gemini) respect it. The harness is the test bed for the format design.
- Phase 2b (native csq CLI): csq adds itself as a 4th CLI in the launcher table. The capability layer (LoRA / structured output / MCP gating) is measured against the same 4-suite harness. No new evaluator infrastructure needed.

The paired rule is the durable artifact that ensures these phases inherit the boundary cleanly.

## For Discussion

1. The boundary as drawn says csq owns "schema authority for fixture content" — but the fixtures are ported byte-for-byte from loom (PR H2), then csq becomes the schema authority going forward. There's a transition moment where csq is editing files that originated in loom. Should the paired rule include a one-time "fixture transfer" provision (loom marks its harness deprecated; csq takes ownership; specific files listed) — or is that overengineering for a one-time event?

2. The loom-csq paired rule presupposes both repos have CI. Loom's CI integrates with the multi-CLI harness only via csq, post-Phase-1. If csq's CI breaks (vendor outage, GitHub Actions issue), loom's release path stalls — a coupling that didn't exist before. Is this acceptable centralization, or should loom retain a lightweight smoke-test path independent of csq?

3. Counterfactual — if loom and csq had been in the same repo, the boundary rule wouldn't be needed; the dependency would be a directory move. The paired-rule mechanism is overhead the multi-repo architecture creates. Is the multi-repo architecture itself the right call here, or is the right Phase-2 move to merge them?

## References

- `workspaces/csq-v2/journal/0074-DECISION-csq-as-cli-phase-1-and-2-architecture.md` — pre-Phase-1 framing
- `01-analysis/07-adrs.md` ADR-J — original boundary decision
- `02-plans/01-implementation-plan.md` H12 — paired-rule PR
- `04-validate/01-redteam-round1-findings.md` AD-08 — drift-detection gap
- `~/.claude/accounts/term-4164/projects/-Users-esperie-repos-terrene-contrib-csq/memory/project_csq_loom_relationship.md` — boundary memory
