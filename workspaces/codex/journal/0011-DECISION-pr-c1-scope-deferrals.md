---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T07:20:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c1
session_turn: 60
project: codex
topic: PR-C1 deferred three plan items (discover_anthropic rename, cooldown re-key, ACCOUNT_BOUND_ITEMS surface-indexing) because rigor analysis during implementation surfaced defects in the plan's filter semantics and showed the other two had no current-world value
phase: implement
tags: [codex, pr-c1, scope, deferral, surface-enum]
---

# Decision — PR-C1 scope: ship the spine, defer three items to their consumer PRs

## Context

`workspaces/codex/02-plans/01-implementation-plan.md` §PR-C1 lists seven deliverables under "SHARED SPINE". During implementation (PR #169) three of those surfaced rigor defects or zero current-world value:

1. **`discover_anthropic` → `discover_refreshable` rename + filter change to `Surface::ClaudeCode`.** The plan's filter semantics conflate two concepts. Today `discover_anthropic` returns mixed accounts (Anthropic OAuth + third-party) and the refresher filters via `source == AccountSource::Anthropic`. A naive flip to `surface == Surface::ClaudeCode` would INCLUDE third-party accounts — which are also ClaudeCode surface but have no OAuth refresh tokens — breaking the refresher.

2. **Cooldowns keyed `(Surface, AccountNum)`.** INV-P09's concern is slot-collision across surfaces (slot-9-Codex vs slot-9-Anthropic). But each usage-poller surface already has its own cooldown map (`cooldowns` for Anthropic, `cooldowns_3p` for third-party, future `cooldowns_codex`). Slot collisions are impossible by construction; the tuple-key refactor pays off only if the maps are merged, and that merge is not planned.

3. **`ACCOUNT_BOUND_ITEMS` surface-indexed.** The Codex item set per spec 07 §7.2.2 differs ENTIRELY from ClaudeCode (auth.json / config.toml / sessions / history.jsonl vs .credentials.json / .csq-account / .current-account / .quota-cursor). A surface-parameterised lookup is more complex than a parallel `create_handle_dir_codex()` function.

## Decision

Ship PR-C1 with the SPINE (Surface enum + AccountInfo.surface + auto_rotate INV-P11 flip + swap_to INV-P10 guard + 5 regression tests). Defer the three items above to their natural consumer PRs:

- **Item 1 (discover rename/filter)** → PR-C3. Codex discovery needs its own function (`discover_codex` reading `~/.codex/auth.json` or the equivalent config dir), and the refresher's filter becomes "accounts with OAuth refresh tokens regardless of surface" which is correctly expressed as a union of two discovery sources, not a surface field check.
- **Item 2 (cooldown re-key)** → PR-C5. Codex poller adds its own `cooldowns_codex` map; no collision risk until a map-merge is actually proposed.
- **Item 3 (handle-dir items surface-indexed)** → PR-C3. `create_handle_dir_codex()` encapsulates the Codex-specific symlink set natively.

## Alternatives considered

**A. Execute the full plan as written.** Would require either (a) shipping known-defective filter semantics in the refresher, to be fixed in a follow-up, or (b) growing PR-C1's scope to include the PR-C3 discovery work. Both options compromise rigor — (a) trades a working invariant for scope adherence, (b) tears down the PR-per-concept boundary that makes bisection effective. REJECTED.

**B. Block PR-C1 on the defect-free decomposition.** Would delay the Surface enum availability, which means PR-G1 (Gemini) also waits. Keeps the plan intact but serialises Codex + Gemini implementation. REJECTED: the spine is the critical path, and every downstream PR can land without the three deferred items.

**C. Ship PR-C1 as-written and fix defects in immediate follow-ups (PR-C1a, C1b, C1c).** Matches the plan letter but produces four PRs where one would do. The deferred items naturally belong in their consumer PRs; splitting them into their own chore PRs is churn without value. REJECTED.

## Consequences

- PR #169 shipped with 958 tests green, clippy clean, fmt clean.
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C1 does NOT match the shipped PR exactly. Future readers should cite journal 0011 alongside the plan.
- PR-C3's scope grows by three small additions (discover_codex + create_handle_dir_codex + refresher dispatch). Each of these would have been rework in C3 anyway if executed per-plan in C1.
- PR-C5's scope grows by one small addition (cooldowns_codex map + helper re-signature). Same rework argument.
- Post-convergence redteam (PR-C9a/b) will verify: no site in the codebase naively uses `surface == ClaudeCode` as a stand-in for "has OAuth refresh tokens" — the refresher filter must stay source-based until merged properly in C3.

## For Discussion

1. **The plan was the product of a /todos + redteam convergence round. Does deferring three of its seven items count as "plan drift" that should feed back into /codify, or is it normal adaptive execution within the envelope?** (Lean: adaptive execution — the envelope is "ship the Codex surface, preserve invariants", not "execute each bullet verbatim". Journal the deltas.)

2. **PR-C3 now carries three additional items (discover_codex, handle-dir-codex, refresher filter). Does PR-C3's scope threaten the small-PR rigor discipline that PRs #167–#169 exemplified, or are those additions structurally inseparable from Codex login orchestration?** (Lean: structurally inseparable — each of the three landed items is a precondition for spawning `codex` successfully.)

3. **If the plan had specified the decomposition we actually shipped (spine-only PR-C1 + consumer-PR delegations), would the redteam convergence round have caught the defect-free-filter concern earlier, or is this a class of issue that only surfaces at implementation time?** (Open question — relevant for future /todos sessions.)

## Cross-references

- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C1 (the plan that was partially deferred)
- `workspaces/csq-v2/journal/0067` H3 (auto_rotate stub flip — the one invariant flip PR-C1 DID ship)
- PR #169 (the shipped PR — commit body documents each deferral)
- Journal 0005–0010 (PR-C00 gates + §5.7 VERIFIED, all pre-conditions for PR-C1)
