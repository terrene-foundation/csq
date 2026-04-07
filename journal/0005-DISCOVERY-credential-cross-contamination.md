---
type: DISCOVERY
date: 2026-04-01
created_at: 2026-04-01T21:10:00+08:00
author: co-authored
session_id: null
session_turn: 1
project: claude-squad
topic: Credential cross-contamination root cause in multi-terminal rotation
phase: implement
tags: [claude-squad, rotation-engine, credentials, multi-terminal, race-condition]
---

# Discovery: Credential Cross-Contamination in Multi-Terminal Rotation

## Finding

All 7 Claude accounts (stored as `~/.claude/accounts/credentials/{1-7}.json`) were found to contain **identical OAuth credentials** — MD5 hash matched across accounts 1-6, with only account 7 retaining unique credentials. This reduced 7 accounts to effectively 1, making rotation useless.

## Root Cause

Three interacting bugs in `rotation-engine.py`:

1. **`swap_to()` trusted session assignment for credential save-back** (line 382-390). Before swapping keychain to a new account, it saved the current keychain to the "previous account's" file based on the session→account mapping in `assignments.json`. With 15 terminals racing, assignments went stale — terminal A's session was mapped to account 3, but the keychain actually held account 1's creds. Saving to `3.json` overwrote account 3's unique credentials with account 1's. Over time, one token propagated to all files.

2. **`update_and_maybe_rotate()` used a subprocess email check** (line 531-541) to verify keychain ownership before refreshing stored creds. The `claude auth status --json` call was racey — another terminal could swap the keychain between the read and the check.

3. **Shared `.session_id` file** — all terminals wrote to one file, so hook calls from terminal A read terminal B's session ID, causing wrong account lookups.

## Fix Applied

- `swap_to()`: Match by **refresh token** (unique per account) instead of session assignment
- `update_and_maybe_rotate()`: Atomic token comparison, no subprocess
- Per-PPID session ID files (`--ppid` flag)
- `auto-rotate --force`: Bypass stale quota data
- `ccc verify`: Detect contamination by hashing credential files

## Impact

After fix + re-login to all 7 accounts, `ccc verify` confirms all credentials are unique. Rotation now actually switches between different accounts.

## For Discussion

1. Given that the contamination propagated silently over many sessions, what monitoring should detect credential drift earlier — e.g., periodic `verify` in the statusline?
2. If refresh tokens had been identical across accounts (same OAuth client), would the token-matching approach still work? What's the fallback identity signal?
3. If the shared `.session_id` file had been the only bug, would contamination still have occurred through the other two paths alone?
