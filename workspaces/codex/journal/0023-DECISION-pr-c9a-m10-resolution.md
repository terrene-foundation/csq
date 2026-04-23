---
type: DECISION
date: 2026-04-23
created_at: 2026-04-23T10:05:00Z
author: co-authored
session_id: 2026-04-23-codex-pr-c9a-continued
session_turn: 8
project: codex
topic: M10 (same-surface Codex→Codex silent exec-replace) resolved by Option A — landed `repoint_handle_dir_codex` as the Codex-aware mirror of `repoint_handle_dir`. The `csq swap` dispatcher now routes (Codex, Codex) to a same-surface in-flight symlink repoint; the prior path went through `cross_surface_exec` which `exec`-replaced the running codex process and silently dropped the user's conversation. Option B (spec-amendment-first to declare exec-replace acceptable) was rejected for v2.1 because the user-visible failure mode (lost conversation, no warning) is exactly the kind of UX that the redteam exists to catch — fixing the code is cheaper than retraining users. Five new regression tests pin happy-path repoint, surface guard against ClaudeCode handle dirs, refusal of non-handle source, refusal on missing canonical credential, refusal on missing `.csq-account`. Workspace tests 1194 → 1199 (+5). Clippy / fmt / svelte-check / vitest all green. PR-C9a round-1 convergence is now structurally complete; only M8 (100 ms heartbeat decision) and the §For Discussion items from journal 0022 remain before commit + PR.
phase: redteam
tags:
  [
    codex,
    pr-c9a,
    m10,
    INV-P05,
    same-surface-codex,
    repoint,
    zero-tolerance,
    journal-0021,
    journal-0022,
  ]
---

# Decision — M10 resolved via Option A (Codex-aware symlink repoint)

## Context

Journal 0022 closed PR-C9a round 1 with 14 of 15 above-LOW findings resolved in-session. The lone exception was M10 — the gap between INV-P05 spec text ("same-surface ClaudeCode swap is in-flight; cross-surface requires confirm + exec") and actual code behavior on the Codex side, where the dispatcher routed `(Codex, Codex)` through `cross_surface_exec`. That path renames the source handle dir to a sweep tombstone and `exec`s the codex binary, replacing the running process and dropping any in-flight conversation with no warning (because `is_cross_surface == false`, the cross-surface confirm prompt is also skipped — the user sees a clean swap and only later realizes their session is gone).

Two forks were on the table per journal 0022 §For Discussion #1:

- **Option A — code-to-spec.** Build a Codex-aware mirror of `repoint_handle_dir` that rewrites the spec 07 §7.2.2 Codex symlink set in-place. Same in-flight semantics as ClaudeCode: codex-cli re-stats `auth.json` before each API call, so the next request resolves through the new symlink. UNIX open-after-rename keeps any in-flight session fds valid until the holding process closes them.
- **Option B — spec-to-code.** Land an INV-P05 amendment in `specs/07-provider-surface-dispatch.md` declaring that exec-replace is acceptable for any Codex-involving swap (same-surface or cross-surface), then add a confirm-style prompt for same-surface Codex so the user is at least warned before the conversation drops.

Per `rules/autonomous-execution.md`, both involve human-authority gates — Option A changes user-visible behavior in v2.1 (the swap is now in-flight where it used to be exec-replace), and Option B changes a spec invariant. In this session the user explicitly chose **Option A**.

## Decision

**Land Option A in PR-C9a.** Implementation:

1. **`csq-core/src/session/handle_dir.rs`** — new public function `repoint_handle_dir_codex(base_dir, handle_dir, target)` mirroring `repoint_handle_dir` for the Codex symlink set. Surface guard refuses ClaudeCode handle dirs (no `auth.json` symlink); pre-flight refuses `term-` source if absent, target `config-<N>` if absent, target `.csq-account` if absent (mirrors VP-final F3), canonical `credentials/codex-<N>.json` if absent. Per-handle `.swap.lock` flock mirrors VP-final F4. Atomic rename-over of each Codex symlink (`.csq-account`, `auth.json`, `config.toml`, `sessions`, `history.jsonl`) via the staged-tmp + rename pattern that `repoint_handle_dir` already uses. `sessions` and `history.jsonl` may legitimately be absent in the target slot (codex-cli creates them lazily) — the function skips them and removes any orphan symlink to avoid a dangling link.

2. **`csq-cli/src/commands/swap.rs`** — dispatcher updated. The `(Surface::Codex, Surface::Codex)` arm now calls a new `same_surface_codex` helper that delegates to `repoint_handle_dir_codex` and notifies the daemon's invalidate-cache endpoint. `cross_surface_exec` now sees only true cross-surface invocations. Module docstring updated to reflect three semantically distinct paths (the prior docstring documented the M10 bug as if it were intentional design; that paragraph is replaced).

3. **Five regression tests** in `handle_dir.rs::tests`:
   - `repoint_handle_dir_codex_repoints_codex_symlinks` — happy path, slot 4 → slot 9, asserts every symlink target resolves to the new slot AND that no `.sweep-tombstone-` sibling was created (the M10 essence: in-flight repoint is observably not the cross-surface tombstone path).
   - `repoint_handle_dir_codex_refuses_non_codex_handle_dir` — symmetric guard to the existing `repoint_handle_dir_refuses_codex_shape_handle_dir`.
   - `repoint_handle_dir_codex_refuses_non_handle_dir_source` — refuses `config-N` and other non-`term-` paths.
   - `repoint_handle_dir_codex_refuses_when_canonical_credential_missing` — pre-flight catches missing `credentials/codex-<target>.json` so `auth.json` cannot end up dangling.
   - `repoint_handle_dir_codex_refuses_when_target_missing_csq_account` — VP-final F3 mirror.

## Quality gates

- `cargo test --workspace`: **1199/1199 passing**, 0 failures (was 1194; +5 M10 regressions).
- `cargo clippy --workspace --all-targets -- -D warnings`: **clean**.
- `cargo fmt --all --check`: **clean** (one inlined match arm + one let-binding rewrap applied automatically).
- `npx svelte-check`: **0 errors / 0 warnings** across 103 files (frontend untouched).
- `npm run test -- --run`: **100/100 passing** (frontend untouched; the two pre-existing a11y warnings on AccountList are R3 from journal 0020, confirmed not a PR-C9a regression).

## Alternatives considered

**Option B — INV-P05 amendment + confirm prompt for same-surface Codex.** Rejected for v2.1. Three sub-arguments:

- _User-visible blast radius._ Option B leaves the conversation-loss behavior in place and adds a prompt — every same-surface Codex swap now blocks waiting for `[y/N]` confirmation, even though the only action the user wanted was `csq swap`. The prompt-fatigue cost compounds; the underlying behavior (lose your conversation) is unchanged.
- _Cost asymmetry._ Option A is a ~150-line mirror of an already-working function with five focused regression tests. Option B requires a structural spec edit (`specs/07-provider-surface-dispatch.md` §7.5) plus the confirm-prompt code plus tests for the prompt path — comparable LoC, but the spec change locks future PRs into the exec-replace model and makes Option A harder to revisit later. Option A keeps both doors open.
- _Symmetry with ClaudeCode._ The `repoint_handle_dir` codepath already proves the in-flight symlink repoint model works with a process holding open fds (CC's `--resume` reads through the symlink set continuously). The argument in the prior swap.rs docstring — "Codex's `sessions/` symlink model means a running codex process holds references into the old `config-<N>/codex-sessions/` dir; symlink-repoint with a live process would orphan those open files" — was wrong by the same reasoning that makes ClaudeCode safe: UNIX open-after-rename keeps the inode alive for the holding process's existing fds, and any new opens hit the new target. The rationale documented an incorrect mental model; the test `repoint_handle_dir_codex_repoints_codex_symlinks` is the empirical refutation.

**Option C — defer to PR-C9b focused round.** Rejected per `rules/zero-tolerance.md` Rule 5 — M10 is above LOW and was carried into this session specifically to close it. PR-C9b is for round-2 redteam findings, not round-1 carryover.

**Option D — keep exec-replace but also rename the source dir to a sweep tombstone explicitly named `.swap-codex-conversation-lost-`.** Rejected — the user-visible symptom is unchanged; only the post-mortem evidence changes. Rule 5 demands the fix, not the receipt.

## Consequences

- **v2.1 user-visible behavior change.** `csq swap` between two Codex slots no longer terminates the running codex-cli process. The user sees a "Swapped to account N — codex will pick up on next API call" message and the next API request authenticates as the new slot. Open fds into the old slot's `codex-sessions/` survive until the codex process closes them — the in-flight session continues writing to its existing session file via the old fd, while any new open (`codex resume`, new session) hits the new slot. This matches the ClaudeCode model.
- **`cross_surface_exec` is now strictly cross-surface.** The dispatcher's `_` arm is no longer a misnomer; the only callers are `(ClaudeCode, Codex)` and `(Codex, ClaudeCode)`, both of which still trigger the cross-surface confirm prompt and the rename-to-tombstone sequence (INV-P10 preserved).
- **INV-P05 spec text now matches code.** `specs/07-provider-surface-dispatch.md` §7.5 reads "Same-surface ClaudeCode is in-flight; cross-surface requires confirm + exec." With Option A landed, "same-surface" symmetrically covers Codex without an amendment. Journal 0019 §Q1 (the proposed amendment) is moot.
- **Journal 0022 §For Discussion #1 is closed.** The remaining two §For Discussion items (whitelist proc-macro, journal citation convention) carry into PR-C9b.
- **No cross-surface behavior change.** `cross_surface_exec` is structurally unchanged — same INV-P05 confirm + INV-P10 rename-to-tombstone + exec sequence. Findings 10 and 13 from journal 0021 still apply unchanged.
- **PR-C9a is now ready to commit.** The remaining outstanding items per the round-1 convergence are: M8 heartbeat (deferred to PR-C9b focused round per journal 0022), §For Discussion #2 and #3 (deferred to PR-C9b discussion), and the operational cleanup of `/Applications/Code Session Quota.app.alpha.4.bak` and `~/.codex.bak-1776836710/`.

## R-state of M10

| Round                              | State                                                          | Note                                                  |
| ---------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------- |
| Round 1 (journal 0021)             | Identified — MEDIUM, deferred pending spec decision            | Same-session fix gated on Option A vs B choice        |
| Round 1 convergence (journal 0022) | Deferred — structural gate per `rules/autonomous-execution.md` | "Both options have meaningful user-visible semantics" |
| Round 1 closeout (this entry)      | **RESOLVED via Option A**                                      | In-flight Codex repoint shipped + 5 regression tests  |

## For Discussion

1. **The new `repoint_handle_dir_codex` skips the `materialize_handle_settings` and `rebuild_claude_json_for_swap` steps that `repoint_handle_dir` runs after the symlink rewrite. This is correct per spec 07 §7.2.2 — Codex configuration lives in `config.toml` (already a per-account symlink) and there is no `.claude.json` analogue — but it means the two repoint paths now have visibly asymmetric tail logic. Should we extract a `RepointStrategy` trait that makes the asymmetry explicit, or is the duplication-with-comments preferable for v2.1? (Lean: leave duplication; the `materialize_handle_settings` post-step is a ClaudeCode-shaped concern and abstracting it costs more in indirection than the duplicated 30 LOC saves.)**

2. **The happy-path test asserts `tombstone_count == 0` to pin "no exec-replace happened." This is a structural assertion on directory state, not a behavior assertion on the codex process. Counterfactual: if a future refactor accidentally routed `(Codex, Codex)` through `cross_surface_exec` AND the tombstone rename was guarded behind a feature flag, this test would still pass while the user's conversation got dropped. Should we add a higher-fidelity test that mocks the codex binary and asserts no `exec` syscall fired? (Lean: no — `cross_surface_exec` is a thin shim and the tombstone rename is its only persistent side effect; mocking `exec` adds Unix-specific test complexity for a regression class that the dispatch-level test already covers.)**

3. **Counterfactual — had the original PR-C7 author treated the `sessions/`-orphan argument as a hypothesis to test rather than a constraint to design around, would M10 have surfaced at PR-C7 review instead of PR-C9a redteam? The argument is plausible-sounding ("a running process holds fds; symlink-repoint orphans them") but trivially refutable by reading `man 2 rename` or running a 10-line test. The tell here is the absence of a journal entry justifying the choice with empirical evidence — only the inline docstring asserting it. Adding a "MUST NOT include design rationales without an empirical reference (journal, test, manpage cite)" clause to `rules/journal.md` would catch this class. (Lean: yes — parallel of journal 0022 §For Discussion #3 which surfaced the same pattern at PR-C1.)**

## Cross-references

- `workspaces/codex/journal/0021-RISK-pr-c9a-redteam-round1-findings.md` — round-1 findings record (M10 first surfaced at finding M10).
- `workspaces/codex/journal/0022-DECISION-pr-c9a-round1-convergence.md` — round-1 convergence; M10 was the lone deferred item, see §For Discussion #1.
- `workspaces/codex/journal/0019-DECISION-pr-c7-swap-cross-surface-and-models-codex-dispatch.md` §Q1 — the proposed INV-P05 amendment, now moot under Option A.
- `workspaces/codex/journal/0020-DECISION-pr-c8-desktop-codex-ui.md` R3 — the pre-existing AccountList a11y warnings confirmed not a PR-C9a regression.
- `specs/07-provider-surface-dispatch.md` §7.2.2 (Codex symlink set) — the spec the new function implements against.
- `specs/07-provider-surface-dispatch.md` §7.5 (INV-P05) — invariant text now matches code without an amendment.
- `csq-core/src/session/handle_dir.rs` `repoint_handle_dir_codex` — new function, lines after the existing `repoint_handle_dir`.
- `csq-cli/src/commands/swap.rs` `same_surface_codex`, dispatcher arm — same-surface Codex routing.
- `.claude/rules/zero-tolerance.md` Rule 5 — policy under which M10 was forced to closure rather than deferred.
- `.claude/rules/autonomous-execution.md` §Structural Gates vs Execution Gates — explained the deferral; user authority cleared the gate this session.
