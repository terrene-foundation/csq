---
type: DECISION
date: 2026-04-14
created_at: 2026-04-14T01:30:00+08:00
author: co-authored
session_id: 2026-04-14-alpha-9
session_turn: 30
project: csq-v2
topic: Handle dir settings.json materialized as a real file by deep-merging ~/.claude/settings.json (user global) with config-N/settings.json (slot overlay), restoring user statusLine/permissions/plugins under csq run and dissolving the alpha.7 apiKeyHelper bug at its source
phase: implement
tags:
  [
    alpha-9,
    handle-dir,
    settings-merge,
    statusline,
    bypass-permissions,
    apikeyhelper,
    root-cause,
  ]
---

# 0044 — DECISION — alpha.9 handle-dir settings materialization

**Status**: Implemented (branch `fix/alpha-9-handle-dir-settings-merge`).
**Predecessors**: 0042 (alpha.7 — third-party slot binding shipped),
0043 (alpha.8 hotfix — strip apiKeyHelper at the slot-bind sink).

## Symptom (this session, second machine)

User reports on machines where `~/.claude/settings.json` carries the
expected user customization (`statusLine`, `permissions.defaultMode:
bypassPermissions`, `enabledPlugins`, `env.CLAUDE_CODE_EXPERIMENTAL_*`,
`alwaysThinkingEnabled`, etc.):

> "my other machines with .claude are not showing their statusline and
> has bypass permissions on gone"

Confirmed: running `claude` directly on those machines makes everything
reappear. Running `csq run N` makes everything vanish.

## Root cause

CC's settings precedence is `managed > local > project > user`. When
`CLAUDE_CONFIG_DIR` is set, the **user** layer is read from
`$CLAUDE_CONFIG_DIR/settings.json` _instead of_ `~/.claude/settings.json`
— it is a replacement, not an overlay. There is no merge between the
two paths.

The handle-dir model (PR #79) put `settings.json` in
`ACCOUNT_BOUND_ITEMS`, so `term-<pid>/settings.json` was a symlink to
`config-<N>/settings.json`. For OAuth slots this file is usually
absent or near-empty (nothing in csq writes it for OAuth), so CC
under `CLAUDE_CONFIG_DIR=term-<pid>` saw zero user customization.

The bug was latent on the developer machine because an older csq build
had at some point copied `~/.claude/settings.json` into
`config-1/settings.json` (1107 bytes, identical content). Any machine
without that historical copy was broken.

This is the same family of design collision that produced 0043: CC
reads exactly one settings.json, and csq's idea of which file to put
there was unaligned with the user's idea of "my settings."

## Decision: materialize, do not symlink

`term-<pid>/settings.json` is now a **real file**, written by
`handle_dir::materialize_handle_settings` at handle-dir creation time
and rewritten on swap. It is a deep-merge of:

- **base** = `~/.claude/settings.json` (user global — statusLine,
  permissions, plugins, env experiments)
- **overlay** = `config-<N>/settings.json` (slot-specific —
  empty for OAuth slots, env block for 3P slots)

Overlay keys win on merge (so the 3P `env.ANTHROPIC_BASE_URL` and
`ANTHROPIC_AUTH_TOKEN` override the user's `env`), but every other
key the user had — statusLine, permissions, plugins, alwaysThinking,
enabledPlugins, voiceEnabled — flows through untouched.

Atomic write: temp file → `secure_file()` (0o600) → `atomic_replace`.
`secure_file` propagates rather than `.ok()`-ing because the overlay
may contain a 3P access token. Failures fail closed.

`config-<N>/settings.json` is now an internal storage format. It is
read by `discover_per_slot_third_party` and the 3P usage poller (slot
discovery, base-URL routing, model selection), but it is no longer
the file CC reads. The user-facing settings file is the
materialized `term-<pid>/settings.json`.

### Why not symlink-back as a hotfix

Considered: when `config-<N>/settings.json` is missing, point
`term-<pid>/settings.json` at `~/.claude/settings.json`. Would have
fixed OAuth slots in ~10 lines. Rejected because:

1. 3P slots still lose user customization (the symlink would point at
   the 3P env block, not the user's settings).
2. The alpha.7 apiKeyHelper bug (0043) survives — `bind_provider_to_slot`
   still goes through `default_settings` which still inserts
   `apiKeyHelper`. The hotfix in alpha.8 sanitized the sink; the bug
   stays latent for any future caller that touches the same path.
3. Two parallel mechanisms (symlink for OAuth, real file for 3P) is
   harder to reason about than one (real file always).

Materialize-everywhere collapses three open issues into one boundary:
the alpha.7 apiKeyHelper bug, the alpha.8 sink-sanitize patch, and the
alpha.9 catalog cleanup TODO all dissolve because `bind_provider_to_slot`
no longer calls `default_settings` and `default_settings` no longer
writes `apiKeyHelper`.

## Implementation

### 1. `csq-core/src/session/handle_dir.rs`

- Removed `"settings.json"` from `ACCOUNT_BOUND_ITEMS`.
- Added `materialize_handle_settings(handle_dir, claude_home, config_dir)`:
  reads both files (returning `{}` on missing/malformed/non-object,
  with WARN log), runs `merge_settings(&base, &overlay)`, writes the
  result atomically with 0o600.
- Wired into `create_handle_dir` after the symlink loops.
- Wired into `repoint_handle_dir` after the symlink-repoint loop.
  `repoint_handle_dir` now takes a `claude_home: &Path` parameter.

### 2. `csq-cli/src/commands/swap.rs`

Resolves `claude_home` via `super::claude_home()` and passes it to
`repoint_handle_dir`. Single call site.

### 3. `csq-core/src/accounts/third_party.rs::bind_provider_to_slot`

Shrunk from "build full settings via `default_settings` then strip
`apiKeyHelper`" to "build a minimal `{ "env": { BASE_URL, AUTH_TOKEN,
ANTHROPIC_MODEL, ANTHROPIC_DEFAULT_OPUS_MODEL, ... } }`". Discovery and
the 3P usage poller still find what they need (they only read `env.*`).
The `apiKeyHelper` strip is no longer needed because we never write
that field in the first place.

The `bind_strips_api_key_helper` regression test from 0043 is kept as
defense-in-depth — if anyone reintroduces a path through `default_settings`
the assertion still catches it.

### 4. `csq-core/src/providers/settings.rs::default_settings`

Deleted the `apiKeyHelper` insertion. The catalog `system_primer` field
is preserved on `Provider` for possible future system-prompt use but
has no current consumer. This kills the alpha.7 bug at its source.

### 5. Tests

Five new unit tests in `handle_dir::tests`:

- `create_handle_dir_materializes_user_settings` — user has statusLine
  - bypassPermissions + enabledPlugins; all survive into the
    materialized file. Asserts the file is a real file, not a symlink.
- `create_handle_dir_merges_third_party_env_overlay` — user statusline
  - 3P env block both present after merge. User's other env keys
    preserved alongside the 3P overlay.
- `create_handle_dir_tolerates_missing_user_settings` — fresh install,
  no `~/.claude/settings.json` yet.
- `create_handle_dir_tolerates_malformed_user_settings` — typo'd JSON,
  WARN-logged, materialization proceeds with empty base.
- `repoint_rewrites_materialized_settings_for_new_slot` — swap from
  OAuth to 3P re-materializes; user statusline preserved, new env
  block lands.

One new integration smoke test
(`csq-core/tests/settings_materialization_smoke.rs`):

- `materializes_against_real_user_settings_when_present` — drives
  `create_handle_dir` against the developer's actual
  `~/.claude/settings.json`. Asserts every top-level key in the user's
  settings is present and equal in the materialized output. Skipped
  in CI (no `~/.claude/settings.json` there).

Existing tests updated:

- `repoint_handle_dir_changes_targets` and
  `repoint_refuses_legacy_config_dir` updated for the new
  `claude_home` parameter on `repoint_handle_dir`.

### 6. `csq-core/src/session/isolation.rs`

Updated the `ISOLATED_ITEMS` doc comment to note that `settings.json`
is materialized (not symlinked, not per-config-copied) and points at
`materialize_handle_settings` for rationale.

## Verification

- **702 tests passing** (596 csq-core lib + 5 new merge unit tests +
  1 new real-world smoke test + 36 cli + 12 integration + 34 desktop +
  10 daemon + 7 platform).
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo fmt --all -- --check`: clean.
- `cargo build --release -p csq-cli`: clean.
- Real `~/.claude/settings.json` round-trip via the new smoke test:
  every user key present and equal in the materialized output.

## Consequences

### Fixed

- `csq run N` on any machine with a `~/.claude/settings.json` now
  produces a `term-<pid>/settings.json` that includes the user's
  statusline, bypass-permissions mode, enabled plugins, and any
  env experiments.
- `csq swap N` re-materializes the file so swapping from OAuth to
  3P (or vice versa) preserves the user customization while picking
  up the new slot's env overlay.
- The latent alpha.7 `apiKeyHelper` bug is killed at its source. A
  future contributor cannot accidentally reintroduce it by routing a
  new write path through `default_settings`.

### New invariants

- `~/.claude/settings.json` is the single source of truth for user
  global customization. csq never writes to it.
- `config-<N>/settings.json` is internal slot overlay storage. For
  OAuth slots it is absent. For 3P slots it contains exactly
  `{ "env": { BASE_URL, AUTH_TOKEN, MODEL_KEYS... } }`.
- `term-<pid>/settings.json` is the composed view CC reads. Always
  a real file. Always rewritten by `materialize_handle_settings`.
- One-way data flow: user → overlay → composed view. No
  back-propagation.

### Edge case: live user-settings edits

If the user edits `~/.claude/settings.json` while a `csq run` terminal
is live, the change does not propagate until the terminal is relaunched
(CC re-stats `.credentials.json` on every API call but not
`settings.json`). This matches CC's own behavior outside csq and is
documented but not auto-fixed. A daemon watcher that re-merges open
handle dirs on user-settings mtime change is a possible follow-up but
is not required for correctness.

### Spec drift

`specs/02-csq-handle-dir-model.md` lists `settings.json` under the
"account-bound" symlink set (INV-02). This needs an update to reflect
the materialize-not-symlink path. Tracked as alpha.10 spec-update work.

## For Discussion

1. The decision rejected the symlink-back hotfix on three grounds:
   3P customization loss, latent bug survival, and dual-mechanism
   complexity. Of those three, which would have been hardest to spot
   in a future session — and is the answer the same six months from
   now once the hotfix code became "the way it works"?

2. The materialized `term-<pid>/settings.json` does not auto-refresh
   when the user edits `~/.claude/settings.json` mid-session. CC's
   own behavior outside csq has the same property, so we matched it.
   Counterfactual: if CC had a watcher that hot-reloaded settings on
   mtime change, would the right call have been to add the same
   watcher to the daemon, or would we still defer it as nice-to-have?

3. The `system_primer` field stays on `Provider` with no current
   consumer. Three options: (a) delete it now, (b) leave it as a
   placeholder for future system-prompt injection, (c) rename it to
   make the lack of a consumer explicit. The journal recommends (b)
   on the grounds that the catalog already pays the cost of carrying
   it. What's the strongest argument _against_ (b)?
