---
name: v2.0.1 VP-final convergence declaration
description: Two-round red-team convergence complete; zero above-LOW residuals; v2.0.1 ready to tag
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T19:00:00Z
author: co-authored
session_id: post-v2.0.0-planning
session_turn: 30
project: csq
topic: v2.0.1 VP-final red-team convergence
phase: redteam
tags: [v2.0.1, convergence, release-gate, redteam, vp-final]
---

# VP-final Convergence — v2.0.1

## Decision

v2.0.1 is ready to tag. Two red-team rounds executed; all above-LOW findings resolved in-source per `zero-tolerance.md` Rule 5. The VP-final convergence gate from `workspaces/csq-v2/02-plans/05-v2.0.1-patch-plan.md` is closed.

## What shipped in v2.0.1

| Category                                | PRs  | Findings resolved             |
| --------------------------------------- | ---- | ----------------------------- |
| Post-v2.0.0 planning + initial red-team | #150 | 19 plan-time findings         |
| Structural auto-rotate (P0-1 Option A)  | #151 | Auto-rotate restored          |
| Defensive settings re-materialize       | #152 | Journal 0059 half-2 narrowed  |
| OAuth state_store poison recovery       | #153 | P2-3                          |
| Quota schema freeze (spec only)         | #154 | Spec frozen                   |
| Quota dual-read shakedown               | #155 | v2.1 migration pre-shaken     |
| Fixed error-kind log tags               | #156 | L2/L3                         |
| VP-final spec reconciliation            | #157 | R1/R2/R3 spec half            |
| VP-final Group 3 sync guards            | #158 | H1, H2                        |
| VP-final Group 1 schema hardening       | #159 | R1/R2/R3/R4/R5/R6 code half   |
| VP-final Group 2 auto-rotate hardening  | #160 | F1 (CRITICAL), F2, F3, F4, F8 |

## Round 1 findings (13 above-LOW, all resolved)

From the three-agent parallel red-team pass on the v2.0.1 diff:

- 1 × CRITICAL: F1 (3P slot token exfiltration via stale credentials). Resolved in PR #160.
- 6 × HIGH: F2, F4, H1, H2, R2, R3. All resolved in PRs #157-160.
- 6 × MED: F3, F8, R4, R5, R6. All resolved in PRs #157-160.
- 3 × LOW: initial LOW findings slipped to v2.0.2 per `zero-tolerance.md` Rule 5 exception (explicit LOW-slip allowed).

## Round 2 findings (1 LOW, 0 above-LOW)

From a single focused red-team pass on the round-1 fix set:

- 1 × LOW (L1): R5 `parse::<u16>()` accepted "0" and "1000". Tightened to `AccountNum::try_from` in this PR for completeness; technically LOW-slippable.

Round 2's confidence statements per fix group:

- **Group 1 (schema)**: `QuotaFile::empty()` correctly sets `schema_version: 1`, so the R3 degrade + R6 single-write cycle gives users a consistent on-disk shape. No regression.
- **Group 2 (auto-rotate)**: `.swap.lock` is bilateral (both `csq swap` and daemon auto-rotate go through the same `repoint_handle_dir` code path); per-handle-dir scoping eliminates lock-order cycles.
- **Group 3 (sync guards)**: `bind` and `unbind` derive byte-identical `settings.json.lock` paths; concurrent bind+unbind serialize. `Err(_) → Ok(false)` on backsync canonical-corrupt is the correct fail-closed action (refuse-to-overwrite); distinguishing Io from Corrupt further would over-engineer a path whose only safe action is "don't write."

## Gates satisfied

- `cargo test --workspace` — 902+ tests passing
- `cargo clippy --workspace --all-targets -- -D warnings` — clean
- `cargo fmt --all --check` — clean
- Every above-LOW finding resolved (zero-tolerance Rule 5)
- Release notes landed at `docs/releases/v2.0.1.md`
- Release-checklist L2 text corrected in PR #150
- `.session-notes` demoted to scratch per journal 0067 M4
- v2.0.1 backlog inventory committed as journal 0068

## Deferred to v2.0.2

One item: **PR-VP-C1a** — Windows daemon supervisor wiring, feature-flagged OFF. Per journal 0067 H10 user elected Path B (ship v2.0.1 narrow without Windows code changes). VP-C1a + VP-C1b (flag flip after VM smoke) land in v2.0.2.

## For Discussion

1. Round 2 took 1 focused agent and returned in under 2 minutes against the 3-PR diff (#158/#159/#160), finding 1 LOW and 0 above-LOW. If we raised the bar to "round 3 before every tag" for all future releases, would that catch enough marginal findings to justify the cost? Or is 2 rounds with the current agent specialisations (Agent 1 = deep-analyst breadth, Agent 2 = security-reviewer depth, Agent 3 = deep-analyst focused) the efficient frontier?

2. F1 (CRITICAL) was surfaced by a breadth-focused agent that cross-referenced `AccountSource::Anthropic` with the legacy `credentials/N.json` co-existence pattern. It did not appear in any prior red-team on auto-rotate (pre-v2.0.0). What changed about the attack surface such that F1 is now reachable? The v2.0.0 gate-off guard masked it; PR-A1's structural fix re-opened the rotation path. The implication is that **every time we remove a "refuse-to-run" guard, a full red-team pass is mandatory before the gate-off is deleted**. Should this be codified in rules/ or is it already implicit in the /redteam phase protocol?

3. The Group 2 agent's branch became contaminated during parallel execution (three agents in the same working directory checked out different branches and commits bled across). The fix was cherry-pick + force-push-rebase at merge time. Can the `Agent` tool's parallel spawn be safer — one worktree per agent, auto-cleanup on success? If not, what is the documented safe pattern for parallel tdd-implementer delegations?
