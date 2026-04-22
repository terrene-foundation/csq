---
type: DECISION
date: 2026-04-22
created_at: 2026-04-22T09:05:00Z
author: co-authored
session_id: 2026-04-22-codex-pr-c2
session_turn: 15
project: codex
topic: PR-C2 decomposed into C2a (mutex + 0400/0600 mode-flip + surface-param paths) and C2b (CredentialFile enum split across ~134 sites) to keep each PR's structural concern reviewable in isolation
phase: implement
tags: [codex, pr-c2, decomposition, credentials, mutex, mode-flip]
---

# Decision — Split PR-C2 into C2a (spine: paths + mutex + mode-flip) and C2b (enum split)

## Context

`workspaces/codex/02-plans/01-implementation-plan.md` §PR-C2 lists four deliverables:

1. `CredentialFile` surface-tagged enum (`Anthropic { claude_ai_oauth }` vs `Codex { tokens }`)
2. `canonical_path` / `live_path` parameterised by `Surface` → `credentials/codex-<N>.json` + `config-<N>/codex-auth.json`
3. 0400↔0600 mode-flip via `secure_file_readonly()` (helper shipped in PR-C0 / #167)
4. Per-account mutex `DashMap<(Surface, AccountNum), Arc<Mutex<()>>>` (INV-P08, INV-P09)

Item 1 (the enum split) touches ~134 call sites: 28 construction sites build `CredentialFile`/`OAuthPayload` struct literals, and 106 read sites access `.claude_ai_oauth.<field>` directly. Migrating 134 sites lands a large mechanical diff where every hunk is "pattern-match on Anthropic variant". Reviewer attention collapses into rubber-stamping.

Items 2–4 are orthogonal: a `save_canonical(base, account, &creds, surface)` signature, an `AccountMutexTable`, and a 0400→0600→write→0400 sequence can all ship without touching the enum. Today all writers are Anthropic, so `surface` is always `Surface::ClaudeCode`; the spine is ready for Codex consumers without requiring the enum to exist first.

## Decision

Ship the spine in **PR-C2a** (this session), ship the enum split in **PR-C2b** (next session).

- **PR-C2a** lands items 2, 3, 4: surface-parameterised paths, `AccountMutexTable`, and the 0400↔0600 mode-flip around atomic replace. Zero enum churn. Tests cover path derivation per surface, concurrent `save_canonical` serialisation, and the mode-flip round-trip on an existing file.
- **PR-C2b** lands item 1: the `CredentialFile` enum with `Anthropic` and `Codex` variants, ~134 call sites migrated. No mutex / mode-flip code moves — C2b's diff is entirely serde + pattern-match work.

PR-C3 depends on BOTH C2a and C2b: it writes a Codex credential file (needs enum variant + surface-param path + mutex + mode-flip in one call). C2a and C2b can land in either order before C3.

## Alternatives considered

**A. Ship PR-C2 as one monolithic PR.** Matches the plan as written. Rejected because the enum split is a ~134-site rename disguised as an API change; bundling it with the mutex/mode-flip work makes the diff dominated by mechanical pattern-matches and hides the invariant-carrying code (mutex acquire, flip-write-flip ordering) in the noise. Smaller PRs surface structural defects; the same argument applied to PR-C1 per journal 0011.

**B. Enum-first (PR-C2a = enum split, PR-C2b = mutex+mode-flip+paths).** Puts the larger diff first. Rejected because C2a's value to downstream (PR-C3) is enabling Codex writes end-to-end; the mutex+mode-flip+path spine is what's actually required to make `save_canonical` Codex-safe. The enum split alone doesn't add that safety — the writer still needs the mutex and the mode flip. Shipping the spine first means the next downstream read of `save_canonical` is already using the invariant-preserving path, with only the variant type pending.

**C. Do nothing — execute the plan item-by-item in one PR without decomposition.** Rejected for the same reason as A; journal 0011's precedent holds.

## Consequences

- PR-C2a ships as a focused ~200–300 LOC diff: new `AccountMutexTable` type + `save_canonical` signature change + mode-flip sequence + path param. Tests: 3–4 new cases.
- PR-C2b ships as a ~134-site mechanical migration + enum definition + serde shape tests. Reviewer can treat hunk-count as the diff's size and enum-correctness as its substance, rather than untangling them.
- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C2 does not match the shipped sequence exactly. Future readers should cite journal 0012 alongside the plan (same discipline as journal 0011 ↔ §PR-C1).
- PR-C3's scope is unchanged — its prerequisites are just split across two upstream PRs instead of one.
- Post-convergence redteam (PR-C9a/b) verifies: no site in the codebase writes a canonical credential file without the mutex held, and no site writes without the 0400↔0600 dance. The split does not relax that audit.

## For Discussion

1. **PR-C2a ships the mutex + mode-flip invariants without a Codex writer in existence. Is landing the invariant-preserving code path before its first consumer a risk of "dead code that rots", or is it the same structural-spine-first discipline that PR-C1 validated?** (Lean: structural spine — the refresher ALREADY writes Anthropic credentials, and after PR-C2a those writes gain mutex + mode-flip protection even though Anthropic files don't currently live at 0400. This is a strengthening of the Anthropic path, not dead Codex code.)

2. **Journal 0011 established that shipping a spine without its consumers is fine when the spine is invariant-carrying. Journal 0012 extends the pattern — does this start to describe a recurring decomposition principle worth /codify-ing, or is it specific enough to the Codex integration that it doesn't generalise?** (Open — watch whether PR-C3 / PR-C4 follow the same shape.)

3. **If PR-C2b had to land first (reversed ordering), what would break?** (Answer: nothing functionally. Callers of `save_canonical` would pattern-match on the Anthropic variant and write exactly as they do today, but without mutex/mode-flip protection. The Anthropic write path would be no less safe than today; Codex writes would still be blocked until C2a lands. The reversed order is valid; we're picking forward order for downstream-blocking reasons.)

## Cross-references

- `workspaces/codex/02-plans/01-implementation-plan.md` §PR-C2 (the plan being decomposed)
- `workspaces/codex/journal/0011-DECISION-pr-c1-scope-deferrals.md` (precedent for plan decomposition as adaptive execution)
- `specs/07-provider-surface-dispatch.md` §7.5 INV-P08 / INV-P09 (mode-flip mutex coordination, per-account mutex lifecycle)
- `csq-core/src/platform/fs.rs` — `secure_file_readonly` helper shipped in PR-C0 (commit `8898f80`)
