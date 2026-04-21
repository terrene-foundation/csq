---
type: DISCOVERY
date: 2026-04-21
created_at: 2026-04-22T00:10:00+08:00
author: agent
session_id: 2026-04-21-stable-v2-readiness
session_turn: 40
project: csq-v2
topic: auto_rotate::tick writes swapped credentials into config-N/.credentials.json under the handle-dir model, violating INV-01 and silently corrupting account identity for every user who enables auto-rotation
phase: analyze
tags:
  [
    auto-rotation,
    handle-dir,
    config-n,
    spec-02,
    inv-01,
    identity-contamination,
    credential-corruption,
    p0,
    stable-readiness,
  ]
---

# 0064 — DISCOVERY: auto-rotator writes into `config-N/.credentials.json`, violating INV-01 under the handle-dir model

**Status:** Unresolved. Auto-rotate is opt-in (default `enabled: false`), which is why the bug has not been user-reported yet.
**Severity:** P0 — silent account-identity corruption for any user who enables auto-rotation. No recovery short of manual file surgery.
**Discovered during:** `/analyze` phase of v2.0.0 stable readiness risk sweep (deep-analyst agent).

## Mechanism

Walking `auto_rotate::tick`:

1. `csq-core/src/daemon/auto_rotate.rs:138-148` — iterate `config-*` directories under `base_dir`. Handle dirs (`term-*`) are NOT scanned.
2. Line 154: read `.csq-account` from the config dir. In spec 02, this returns N for `config-N` (marker is permanent).
3. Line 207: `find_target(...)` picks a different account M based on `pick_best`.
4. Line 223: `swap_to(base_dir, &config_dir, target)` — this is `rotation::swap::swap_to`, which:
   - Reads `credentials/M.json` (`swap.rs:48,57`) — account M's canonical creds
   - Writes them to `config_dir/.credentials.json` (`swap.rs:87-88`) — into config-N's slot
   - Updates markers (`swap.rs:110-111`)

The end state: `config-N/.credentials.json` now carries account M's tokens. **INV-01 is violated.**

## Blast radius on a real machine

With `rotation.json` enabled and 3 accounts:

- Tick fires. Auto-rotate sees config-1 with marker "1" at 50%, picks account 3.
- `swap_to` copies `credentials/3.json` into `config-1/.credentials.json`.
- Every `term-<pid>` whose `.credentials.json` symlinks to `config-1/.credentials.json` now points at account 3's tokens.
- CC's next `fs.stat` (spec 01 §1.4) sees the new credentials. Both terminals start making requests as account 3.
- Account 3 was supposed to be used by whoever swapped INTO it explicitly. Now extra sessions burn through its quota.
- `credentials/1.json` (canonical) is untouched. The refresher keeps refreshing account 1's tokens in `credentials/1.json` — but CC never sees them because every handle dir's symlink resolves to config-1/.credentials.json which has account 3's data.
- User sees: "Why is my account 1 usage going up when I haven't used it? And why is account 3 exhausted?"

Self-reinforcing: `fan_out_credentials` monotonicity guard (`csq-core/src/broker/fanout.rs:64-70`) compares access tokens and may skip — meaning config-N stays stuck on account M forever.

## Why this hasn't been reported

`rotation::config::RotationConfig::default().enabled == false` (`rotation/config.rs:23-25, 60-68`). The user must manually create `rotation.json` with `"enabled": true`. No desktop Tauri command writes `rotation.json`. Feature is CLI-config-edit-only. That's the sole reason this P0 hasn't landed in a production bug report.

## Suggested fixes

**Option A (structural, correct):** Auto-rotator walks `term-*` handle dirs and calls `handle_dir::repoint_handle_dir` to swap their symlinks. Config-N MUST NOT be passed to `swap_to`. This is the handle-dir-native implementation of auto-rotation.

**Option B (v2.0-stable-safe, deferrable):** Gate auto-rotation off entirely in handle-dir mode. Detect whether any `term-*` dirs exist; if so, skip the tick with a WARN log. Document the gap in release notes. Cheaper and honest (broken = not running) rather than dishonest (running incorrectly).

**Option C (both):** Gate off in v2.0.0 stable, ship option A in v2.0.1. Release notes say "auto-rotation pending handle-dir redesign."

## Why option B should ship before v2.0.0 stable

Release-readiness brief §1 says "No user-blocking bugs on the golden path" and "No credential-drift risk." Auto-rotate IS a credential-drift risk, even if opt-in. Shipping v2.0.0 stable while knowing a config dial flips an identity-corruption code path is a reputational liability. A one-line `if handle_dirs_exist { return; }` guard at the top of `auto_rotate::tick` plus a test: ~30 minutes of autonomous session time.

## For Discussion

1. Journal 0018 records the decision "tray swap single most recent dir" which acknowledged auto-rotation's shape under handle-dir but did not trace the full write path. Re-reading 0018 §consequences: "Auto-rotation picks the handle dir, not the config dir." This matches option A. Was the auto-rotator code then NEVER updated to actually do this, or was the update reverted?
2. If the handle-dir model had been the original design (no legacy config-dir-as-live), would auto-rotation's design have ever looked like the current code? The current code is recognisably the v1.x "copy into the slot" shape — it's a legacy artifact. Does that mean other code paths in `daemon/`, `rotation/`, or `broker/` could carry similar unexamined legacy assumptions that the handle-dir migration missed?
3. The brief's smoke test does NOT enable auto-rotation. If it did, the identity corruption would surface within 15 minutes. Should the stable-readiness smoke test matrix include "auto-rotation enabled, 3 accounts, 5-minute observation" as a precondition for the cut? If not, what WOULD catch this class of bug before users find it?
