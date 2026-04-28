---
type: DECISION
date: 2026-04-28
created_at: 2026-04-28T22:30:00+08:00
author: co-authored
session_id: term-4164
session_turn: 60
project: coc-harness-unification
topic: Port loom's Node multi-CLI test harness to Python stdlib inside csq
phase: analyze
tags: [architecture, harness, multi-cli, runtime, independence-rule]
---

# DECISION — Port loom's multi-CLI test harness to Python stdlib in csq

## Decision

Port loom's `~/repos/loom/.claude/test-harness/` (Node.js .mjs, ~380 LOC) to Python stdlib inside `csq/coc-eval/`, consolidating with csq's existing implementation eval (Python stdlib, 5 EVAL-\* tests). Result: one harness, four suites (capability, compliance, safety, implementation), up to three CLIs (cc, codex, gemini).

ADR-A in `01-analysis/07-adrs.md` codifies this. Three options were considered:

1. **(A) Port to Python.** Selected.
2. **(B) Keep Node suites; csq Python orchestrator shells out.**
3. **(C) Polyglot: Python for implementation, Node for the others.**

## Why

csq's `rules/independence.md §3` constrains the runtime to "Python 3 stdlib + POSIX/macOS/Windows system tools + Claude Code itself." Node.js as a runtime dependency would require either (a) an exception to that rule (opening the npm-deps door for future contributors), or (b) bundling a Node runtime in csq's install path (changing csq's install promise from "single bash script" to "platform-dependent native install").

Loom is small enough to port cleanly: `harness.mjs` (~380 LOC) + 3 suite drivers (~150 LOC each) + `aggregate.mjs` (~175 LOC) translates 1:1 to stdlib (`subprocess`, `tempfile`, `json`, `pathlib`, `re`). Port cost is one autonomous session.

Polyglot (C) doubles maintenance surface for zero architectural gain. Shell-out (B) leaves us debugging across `subprocess.run(["node", ...])` boundaries forever and makes structured error propagation lossy.

## Consequences

- csq becomes the canonical owner of the multi-CLI evaluator. Loom retains ownership of COC artifact authoring + per-CLI emission (slot composition, 60KiB cap, parity contract).
- A paired loom-csq boundary rule is required (`csq/.claude/rules/csq-loom-boundary.md` mirror in `loom/.claude/rules/loom-csq-boundary.md`). PR H12 in implementation plan.
- The Python port preserves loom's design wins: per-CLI launcher table, scrubbed env, argv-only invocation (no shell), per-fixture cp+git-init, JSONL output schema, regex contains/absent scoring. Adds: stub-HOME with credential-only symlink (resolves loom's punted contamination), per-suite permission profiles, four-suite extension, run-id-scoped results directory.
- Loom may keep its harness as an authoring-side validator (small, focused subset) or drop it; that is loom's call. Default per ADR-J: keep, with explicit drift-detection cadence.

## For Discussion

1. ADR-A picks Python over Node specifically because of `independence.md §3`. If a future Phase 2 needs to embed a richer evaluator (LLM-as-judge, semantic scoring), do we relax §3 or do we ship a separate evaluator service that csq invokes via subprocess? §3 was written before csq had a multi-CLI harness — does the rule's "no third-party runtime requirements" intent extend to a Node binary csq subprocesses to (Node already runs as `claude`/`codex`/`gemini`), or only to Node csq orchestrators directly?
2. The 380-LOC port estimate assumes 1:1 translation. Loom's `harness.mjs` includes Node-specific shapes (ESM imports, `spawnSync` argv form, `process.env` inheritance) that map cleanly. But the gemini quota busy-wait (lines 184-187) translates to `time.sleep` and the JS-style `runTest` async boundary collapses in Python. Are there other implicit Node assumptions (e.g., `process.platform` for OS-specific paths) that will surface as bugs only after porting?
3. Counterfactual — if loom had been Python from the start, would we still split per-CLI emission (loom's job) from per-CLI evaluation (csq's job)? The orthogonal-axes argument (artifact authoring vs CLI evaluation) holds either way, but the runtime convergence would have removed one reason for the split.

## References

- `workspaces/csq-v2/journal/0074-DECISION-csq-as-cli-phase-1-and-2-architecture.md` — Phase framing
- `01-analysis/01-research/01-harness-comparison.md` — orthogonal-axes finding
- `01-analysis/07-adrs.md` ADR-A — formal decision
- `~/repos/loom/.claude/test-harness/lib/harness.mjs` — port source
- `csq/.claude/rules/independence.md` §3 — runtime constraint
