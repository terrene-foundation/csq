# Brief — coc-harness-unification (Phase 1)

## Goal

Consolidate loom's converged multi-CLI test harness (`loom/.claude/test-harness/`) into csq, replacing csq's existing Claude-only `coc-eval/runner.py` (5 EVAL-\* tests) with the loom matrix (3 suites × 3 CLIs × 7 fixtures, 18 tests, RULE_ID-citation contract, JSONL output). After this phase, csq is the single owner of the multi-CLI harness; loom retains artifact authority and may keep its harness as an authoring-side validator or drop it.

## Why now

Journal 0074 (DECISION — csq evolution) frames Phase 1 as the prerequisite for Phase 2. csq cannot legitimately design a unified `.coc/` standard or capability layer for cc/codex/gemini until it has demonstrated proficiency invoking and constraining all three CLIs against COC artifacts. Loom's harness is already converged across 6 redteam rounds; building parallel infrastructure violates the "reuse, don't reinvent" principle in `project_csq_loom_relationship` memory.

## Scope (in)

- Port `lib/harness.mjs` (spawnSync wrapper, scrubbed env, stub HOMEs, scoring, JSONL emit) into csq.
- Port `suites/{capability,compliance,safety}.mjs` (C1-C4, CM1-CM9, SF1-SF5).
- Port `fixtures/{baseline-cc,baseline-codex,baseline-gemini,pathscoped,compliance,safety,subagent}/`.
- Adapt csq's `coc-eval/runner.py:458-473` dispatch to a per-CLI launcher table covering `claude`, `codex`, `gemini`.
- Decide csq's existing 5 EVAL-\* tests' fate: deprecate, migrate to compliance suite, or keep as a fourth implementation suite (open §FD #1 in journal 0074).
- Draft `specs/08-coc-eval-harness.md` defining the consolidated contract: suites, fixtures, RULE_ID schema, launcher table, output schema, isolation invariants.
- Loom-csq symbiotic boundary rule (paired in both repos).

## Scope (out)

- Phase 2a/2b work (capability layer, unified `.coc/` standard, native csq CLI). Those land in `workspaces/coc-cli-phase2/`.
- Loom's per-CLI artifact emission (12 invariants, 60KiB cap, slot composition). Loom keeps that.
- New fixture coverage for hooks/skills-auto-activation/MCP/settings.json (loom README §"Coverage gaps"). May be follow-up; not blocking for this phase.

## Constraints

- csq remains stdlib-only Python for the runner (per `rules/independence.md` §3 — no PyPI runtime deps). The loom harness is Node.js (`mjs`); we either (a) keep it Node and shell out, or (b) port to Python. Decision belongs in 01-analysis.
- All three CLIs (`claude`, `codex`, `gemini`) must be installed locally; harness must detect missing CLIs and skip cleanly, not fail.
- Fixture content reaches third-party model providers (Anthropic, OpenAI, Google). Synthetic markers only; no real secrets.
- API-key strategy for OpenAI/Google is a Phase 2b problem; Phase 1 uses CLI-OAuth surfaces (codex login, gemini auth) that the user already has.

## References

- `workspaces/csq-v2/journal/0074-DECISION-csq-as-cli-phase-1-and-2-architecture.md` — phase framing
- `~/.claude/accounts/term-4164/projects/-Users-esperie-repos-terrene-contrib-csq/memory/project_csq_loom_relationship.md` — boundary doctrine
- `~/repos/loom/.claude/test-harness/README.md` — harness contract (this brief restates it)
- `~/repos/loom/workspaces/multi-cli-coc/04-validate/26-CONVERGED.md` — loom's multi-CLI spec convergence (background, not the harness itself)
- `coc-eval/runner.py` — csq's current Claude-only baseline
- `csq-cli/src/commands/run.rs:60-84` — per-surface dispatch already in csq's runtime layer (precedent for launcher table shape)

## Success criteria for the analyze phase

- `01-analysis/01-research/` documents harness comparison, RULE_ID schema, isolation contract, and a recommended port strategy (Node-as-is vs Python-port).
- `02-plans/01-implementation-plan.md` sequences PRs each scoped for one autonomous-execution session.
- `03-user-flows/` covers operator flows: run-all, run-one-suite, run-one-CLI, debug-one-test, interpret-output.
- Red-team round(s) close with zero CRIT + zero HIGH gaps.
- Open decisions for user: (a) Node vs Python port, (b) fate of EVAL-\* tests, (c) fixture-coverage-gap priority order.
