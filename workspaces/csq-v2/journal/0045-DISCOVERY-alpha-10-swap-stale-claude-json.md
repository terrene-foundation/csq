---
type: DISCOVERY
date: 2026-04-14
created_at: 2026-04-14T10:30:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-10
session_turn: 15
project: csq-v2
topic: csq swap left handle dir .claude.json as stale copy from pre-swap slot, causing CC to display the old account's "you hit your limit" cache indefinitely; fixed by atomic re-materialize on swap preserving session-scoped projects
phase: implement
tags:
  [alpha-10, handle-dir, swap, claude-json, stale-cache, rate-limit, root-cause]
---

# 0045 — DISCOVERY — alpha.10 swap left `.claude.json` stale

**Status**: Fixed in v2.0.0-alpha.10 (branch
`fix/alpha-10-swap-refreshes-claude-json`).
**Predecessor**: 0044 (alpha.9 handle-dir settings materialization).

## Symptom (live session, 2026-04-14 ~10:28)

User in an active `csq run` CC session ran `csq swap 5` to move to an
account with fresh quota. `csq swap 5` reported success. Subsequent
turns in the CC session continued to report "You've hit your limit"
citing the **previous** csq account, not slot 5. Workaround used: CC
`/rename`, `/exit`, then `csq run 5 --resume csq` from a fresh
process. The workaround consistently restored working state.

User quote:

> "csq swap n does not properly swap. For eg. i swap this terminal to
> 5 which has quota, but when i continue it says You've hit your limit
> (previous csq account). I need to /rename, /exit, csq run 5 --resume
> csq to get it working. This never happened before"

## Investigation

Inspected the live handle dir `term-17393` during the broken state:

```
.credentials.json  → config-5/.credentials.json   (symlink; correctly repointed)
.csq-account       → config-5/.csq-account        (symlink; correctly repointed)
.claude.json       real file                      (← the culprit)
```

`.claude.json` contents (current handle dir, post-swap):

| Field                            | Value                                                               |
| -------------------------------- | ------------------------------------------------------------------- |
| `oauthAccount.emailAddress`      | `jack@terrene.foundation` (slot 5 identity)                         |
| `oauthAccount.accountUuid`       | `c2e83170-…-76089b23d05c` (slot 5 UUID)                             |
| `cachedExtraUsageDisabledReason` | `org_level_disabled` (stale, pre-swap state)                        |
| `overageCreditGrantCache` key    | `de65904a-…-c922e6d84093` (**UUID matches no configured slot 1-7**) |

The `overageCreditGrantCache` key is a fossil: a UUID belonging to some
account that once drove this handle dir. `csq swap` repointed the
credential/marker symlinks but left `.claude.json` intact, so CC was
still reading per-account caches from state written when the handle dir
was bound to a different slot. The email was updated (CC rewrites
`oauthAccount` from credential flow after the swap), but the cached
quota state and growth-book flags stuck around.

## Root cause

`csq-core/src/session/handle_dir.rs::repoint_handle_dir` iterates
`ACCOUNT_BOUND_ITEMS` (`.credentials.json`, `.csq-account`,
`.current-account`, `.quota-cursor`) and atomically repoints each
symlink. `.claude.json` is **not** in that list — it is a real file
copied once at handle-dir-creation time via `copy_claude_json_stripped`
and never touched again. Swap did zero work on it.

The file mixes three classes of state:

1. **Per-project state** (`projects` map). CC writes this during the
   session and it must be scoped to the current CWD so `--resume` only
   sees the current session's conversations.
2. **Per-account state** (`oauthAccount`, `overageCreditGrantCache`,
   `cachedExtraUsageDisabledReason`, `cachedGrowthBookFeatures`,
   `additionalModelCostsCache`, `passesLastSeenRemaining`,
   `clientDataCache`, `opusProMigrationComplete`, ...). These should
   reflect the **currently bound** account.
3. **Per-installation state** (`firstStartTime`, `migrationVersion`,
   `autoUpdates`, `numStartups`, ...). These are global to the machine.

Before this fix, swap preserved (1) accidentally by preserving the
whole file, preserved (3) the same way, but **also** preserved (2) —
which is exactly the class that needs to track account identity.

The bug has been latent since the handle-dir model shipped in PR #79.
It only became user-visible when slots diverged in quota state such
that the stale cache from the pre-swap slot materially changed CC's
UI ("You've hit your limit"). Prior sessions that swapped between
fresh slots never saw it because both slots' cached reasons happened
to be absent or identical.

## Fix

`repoint_handle_dir` now calls `rebuild_claude_json_for_swap` after
the symlink repoint loop. The rebuild:

1. Reads `config-<target>/.claude.json` as the new base. This captures
   the target slot's current per-account state (and whatever CC last
   wrote to it from any other handle dir).
2. Reads the **handle dir's existing `.claude.json`** for session-scoped
   project entries. CC has been writing session state here during the
   running session, so these entries are newer than anything in
   `config-<target>/.claude.json` and must survive the swap.
3. Merges: source's projects scoped to CWD first, then overlay
   session-scoped projects from the handle dir (newer wins on key
   conflict).
4. Writes the merged JSON atomically via temp + `atomic_replace`. CC
   may be concurrently reading `.claude.json`; a partial write would
   corrupt its parse.

If the new slot's `.claude.json` is missing or unparseable, the
rebuild **leaves the handle dir's file alone** and logs a WARN. Wiping
it would strand CC with zero state — strictly worse than keeping the
stale copy.

The existing `copy_claude_json_stripped` function was refactored into
`build_scoped_claude_json` (returns the scoped Value) plus two thin
callers: `materialize_handle_claude_json` (create path — non-atomic
write, no handle-dir preserve) and `rebuild_claude_json_for_swap`
(swap path — atomic write, handle-dir preserve).

## Tests

Two new unit tests in `handle_dir::tests`:

- `repoint_rewrites_claude_json_for_new_slot` — two slots with distinct
  identities and stale cache fields. Create handle dir on slot 1,
  verify pre-swap state has slot 1 email + `cachedExtraUsageDisabledReason`.
  Swap to slot 2. Verify post-swap state has slot 2 email AND the
  stale `cachedExtraUsageDisabledReason` / `overageCreditGrantCache`
  from slot 1 are gone.
- `repoint_preserves_session_scoped_projects` — CC writes a
  CWD-scoped project entry into the handle dir after creation. Swap
  to a slot whose own `.claude.json` has a project entry for an
  **unrelated** CWD. Verify post-swap state: slot 2 identity is in
  place, session-scoped project entry survives (the running session's
  continuity is intact), slot 2's foreign-CWD project is stripped.

## Verification

- **704 tests passing** (702 pre-alpha.10 baseline + 2 new swap tests).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo fmt --all -- --check`: clean after a single `cargo fmt --all`.

## Outstanding

The auto-auth investigation from the same session (user reported
`csq` forcing re-login every ~8h on other machines) is **not** yet
resolved. The hypothesis: `credentials/N.json` canonical files are
missing on the affected machines and the refresher silently skips
accounts that `discover_anthropic` doesn't yield. Diagnostics were
requested but the user pivoted to the swap bug before running them.
Alpha.10 ships the swap fix; the auto-auth investigation continues
after confirmation from the affected machines. See session notes for
the exact diagnostic commands and the proposed resurrection pass.

## For Discussion

1. The fix preserves session-scoped projects from the handle dir
   across swaps. An alternative was to strip project entries entirely
   and let CC repopulate from the resume list. What would break if the
   session-scoped preservation were skipped — does `claude --resume`
   actually need the in-handle `projects[cwd]` entry, or does it only
   need `projects/<id>.jsonl` under the symlinked `projects/` directory?

2. `build_scoped_claude_json` refreshes per-account AND per-installation
   fields from the new slot's `.claude.json`. Per-installation fields
   (`firstStartTime`, `numStartups`, `migrationVersion`) are actually
   machine-global and belong in `~/.claude/.claude.json` or a config
   schema update. Counterfactual: if we instead maintained a fresh
   per-handle-dir `.claude.json` composed of (new slot's per-account)
   - (machine-global state from `~/.claude`) + (handle dir's
     per-session), would that have been simpler to design even though
     it'd need three read sources instead of two?

3. The bug was latent since PR #79 (handle-dir model). Why did the
   user only notice now? The simplest explanation is that it takes a
   specific combination — pre-swap slot with cached disabled reason +
   post-swap slot without — to materially change CC's UI. What kind
   of test would have caught this at PR #79 review time without
   requiring the reviewer to know about CC's internal caches?
