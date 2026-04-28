---
type: DECISION
date: 2026-04-28
created_at: 2026-04-28T23:55:00+08:00
author: co-authored
session_id: term-4164
session_turn: 90
project: coc-harness-unification
topic: 13-PR todo sequence finalized after redteam round 3 (todo-level)
phase: todos
tags: [todos, planning, pr-sequence, approval-gate]
---

# DECISION — 13-PR todo sequence finalized; ready for `/implement` approval gate

## Decision

The 13 PRs (H1-H13) from `02-plans/01-implementation-plan.md` are decomposed into 13 standalone todo files at `todos/active/H{1..13}*.md`. Each todo is self-contained: goal, dependencies, build/wire/test tasks as checkboxes, gate criteria, AC mapping, cross-cutting checklist, risk note.

After todo-level redteam (round-3-equivalent, 12 findings: 4 CRIT + 5 HIGH + 3 MED) and same-session resolution per `rules/zero-tolerance.md` Rule 5, the todo set is **ready for `/implement` approval gate**.

## What ships in Phase 1

13 PRs, each scoped for one autonomous-execution session (some pairs combinable):

| PR  | Owner                     | Phase-1 outcome                                                                                 |
| --- | ------------------------- | ----------------------------------------------------------------------------------------------- |
| H1  | spec + scaffolding        | `specs/08-coc-eval-harness.md`; validators + redact + launcher dataclasses + suite-v1 schema    |
| H2  | fixture lifecycle         | per-test tmpdir model; loom fixtures ported byte-for-byte                                       |
| H3  | cc launcher + stub-HOME   | cc launcher with `$HOME` override; AC-16 canary validates isolation                             |
| H4  | JSONL writer + schema     | persistence layer with redaction inline; v1.0.0 schema                                          |
| H5  | capability suite + run.py | C1-C4 on cc; CI workflow; `--validate`, `--resume`, `--format pretty`                           |
| H6  | compliance suite          | CM1-CM9 on cc; fixture-substitution audit; `post_assertions` infra (build)                      |
| H7  | implementation suite      | EVAL-\* migration; sandbox + audit hook + synthetic credential canary; token budget             |
| H8  | safety suite + ordering   | SF1-SF5 on cc; INV-PERM-1 bypass canary; AC-14 multi-suite mtime test; `post_assertions` (wire) |
| H9  | aggregator + baselines    | run-scoped Markdown matrix; `baselines.json` gating; auto-quarantine cron                       |
| H10 | codex activation          | codex launcher + auth probe; capability/compliance/safety codex tests                           |
| H11 | gemini activation         | gemini launcher + quota retry; per-CLI wall-clock cap                                           |
| H12 | loom-csq boundary         | paired rules in both repos; quarterly drift CI                                                  |
| H13 | runner.py retirement      | deprecation shim; old JSON aggregate as fallback                                                |

## Round-3 redteam findings + resolutions

12 findings caught gaps the round-1+round-2 analysis missed:

- **4 CRIT**: AC-1 / suite-v1 schema unowned (added to H1); FR-13 / `--resume` unowned (added to H5); FR-15 / `post_assertions` unowned (added H6 build + H8 wire); AC-13 / no-`shell=True` grep guard unowned (added to H1).
- **5 HIGH**: `.github/workflows/coc-harness.yml` ownerless (pinned to H5); FR-20 / `--token-budget` unowned (added to H7); AC-14 was a hope not a test (moved to H8 as integration test); FR-17 / `--format pretty` unowned (added to H5); H10/H11 over-stated H1-H9 dependency (loosened to H1-H5 hard, H6-H9 soft recommend).
- **3 MED**: H7's H6 dep style-only (loosened); per-PR cross-cutting checklist absent (added uniform block to all 13 todos); 8 scattered R1/UX ACs unowned — distributed: AC-10/AC-32/AC-47 → H11; AC-18/AC-25/AC-42 → H5; FR-14 cron → H9; FR-18 `--tag` → H5; AC-49 deletion → H4.

The build/wire pair discipline (skill MUST rule) is now respected — `post_assertions` infra builds in H6 and wires into safety in H8; CI workflow builds in H5 and gets steps added in H6/H8/H10/H11; aggregator builds in H9 and gates baselines via the JSON committed in same PR.

## Why ship in 13 PRs (not fewer)

Each PR has a working slice. Combining adjacent PRs (e.g., H5+H6) saves ceremony but loses the "no PR leaves the harness broken" property. Specifically:

- H7 (implementation suite + sandbox) is a 200+ LOC platform-specific subsystem; combining with H8 (safety) doubles the risk of a single PR landing broken.
- H10 (codex) and H11 (gemini) are independent platform integrations; combining locks them into the same merge cycle, slowing both.
- H12 (paired rule) crosses repos; isolating it as its own PR keeps the cross-repo audit trail clean (per journal 0004 ADR-J).

## Effort estimation (autonomous execution per `rules/autonomous-execution.md`)

Per 10x multiplier (autonomous AI with mature COC institutional knowledge):

- H1+H2: 1 session (scaffolding + fixture port).
- H3: 1 session (stub-HOME architecture is genuinely novel).
- H4+H5: 1 session (JSONL + first suite + run.py + workflow).
- H6: 0.5 session (suite port with substitution layer).
- H7: 1.5 sessions (sandbox + audit hook + parity-floor regression check).
- H8: 0.5 session (safety port + ordering enforcement + mtime test).
- H9: 1 session (aggregator + baselines + cron).
- H10+H11: 1.5 sessions (codex + gemini activation; depends on auth state of dev box).
- H12: 0.5 session (paired rule + drift CI scaffold).
- H13: 0.5 session (retirement shim).

Total: ~9 sessions ≈ 1-2 calendar weeks at full autonomous pace. The 10x multiplier explicitly does NOT apply to "novel architecture decisions" (sandbox, stub-HOME, redact word-boundary parity) — those are budgeted as 1 full session each rather than 1/10th.

## What's NOT in Phase 1 (scope protection)

Per `02-plans/01-implementation-plan.md` §"Out-of-scope reminders":

- Unified `.coc/` artifact format (Phase 2a).
- Capability layer (LoRA / structured output / MCP gating, Phase 2a/2b).
- Native csq CLI with direct API access (Phase 2b).
- Coverage gaps from loom README (hooks, skills auto-activation, slash commands, MCP, settings.json behavior) — v1.1.
- Codex/Gemini implementation suite (per-CLI artifact mirrors) — Phase 2.
- Windows implementation suite (sandbox tooling deprecated/missing) — gated out at argparse in Phase 1.

## For Discussion

1. The 13-PR sequence assumes sequential merge with each gate green. Round-3 redteam loosened H10/H11/H7 dependencies, enabling some parallel work (H6 in parallel with H7 in parallel with H10/H11). Should `/implement` execute strictly H1→H13, or take the parallel paths where dependencies allow? Strict sequential is simpler to reason about; parallel saves calendar time but multiplies merge-conflict risk. The autonomous execution model favors parallelism, but the "no broken harness" invariant favors sequential.

2. The H7 parity-floor risk (Opus 4.7 ≥35/50) is the dominant Phase 1 risk. The todo includes "before-and-after numbers in PR description." Should there be a separate REGRESSION-prevention PR (H7.0?) that captures the baseline measurement BEFORE H7 modifies anything? Without a deliberate baseline, the parity check is "I think it was 35-something."

3. Counterfactual — if `/todos` had only created the 13 PR files without round-3 redteam, the 4 CRIT findings (suite-v1 schema, `--resume`, `post_assertions`, no-`shell=True` guard) would all have been silent gaps shipped to `/implement`. The `/implement` phase would have either (a) re-discovered them mid-PR and slipped, or (b) shipped without them and quietly missed AC-1, AC-13, AC-35-36, FR-15. The redteam round-3 cost was ~30 minutes of analysis time. The blast radius of skipping it would have been ~3 missed Phase-1 ACs. Strong argument for round-3 (todo-level redteam) being a standard part of `/todos`, not an optional step.

## STOP — awaiting human approval

Per `/todos` skill: this is a structural gate. The human approves the plan (what and why). Once approved, `/implement` executes autonomously.

**Approval questions for the user:**

1. Does the 13-PR sequence cover everything you described in the brief? Anything missing?
2. Anything in the 13 PRs you didn't ask for or don't want?
3. Does the dependency order make sense? Any PR that should land earlier than its current slot?
4. Per #1 in §For Discussion: prefer strict sequential merge or allow parallelism where deps permit?
5. Per #2 in §For Discussion: capture an explicit Opus 4.7 baseline measurement before H7?

## References

- `02-plans/01-implementation-plan.md` — source plan
- `04-validate/03-todos-redteam-findings.md` — round-3 findings + resolutions
- `01-analysis/08-acceptance-criteria.md` — full AC list (49 base + lettered)
- `01-analysis/03-functional-requirements.md` — full FR list (FR-1 to FR-20)
- `journal/0001-DECISION-port-loom-harness-to-python-stdlib.md` — Phase 1 framing
- `journal/0005-DECISION-redteam-round2-convergence.md` — pre-todos convergence
