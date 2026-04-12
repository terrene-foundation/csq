---
type: DECISION
date: 2026-04-13
created_at: 2026-04-13T12:00:00Z
author: agent
project: csq-v2
topic: Red team convergence after implementing all outstanding items
phase: redteam
tags: [redteam, security, oauth, update, windows-ipc, doctor, convergence]
---

# 0033 DECISION: Red Team Convergence on Outstanding Items

## Context

Seven outstanding items from the previous session were implemented in parallel and then validated through 3 rounds of red team testing. The items were:

1. Spec 05 update (sections 5.3/5.4 corrected per journal 0032)
2. Desktop OAuth flow (in-process PKCE replaces `claude auth login` shell-out)
3. Dashboard wiring verification (AccountList, Toast, tray icon states)
4. `csq update` (M7-10) — GitHub Releases + Ed25519 + atomic replacement
5. Windows named-pipe IPC (M8-03)
6. `csq doctor` legacy terminal detection
7. Red team to convergence

## Red Team Findings

### Round 1 — 10 findings (1C, 3H, 6M)

- **C1**: Placeholder Ed25519 key allowed anyone to sign binaries. Fixed by gating `csq update install` behind `is_placeholder_key()`.
- **H1**: Doctor bypassed `AccountNum` validation. Fixed by using `AccountNum::try_from()` + `canonical_path()`.
- **H2**: `submit_oauth_code` blocked the Tauri event loop. Fixed by making it async with `spawn_blocking`.
- **H3**: Duplicated version comparison code between CLI and core. Fixed by removing CLI-local copy, importing from core.
- 6 MEDIUM findings (expect in non-test, dead vars, missing cleanup, etc.) all fixed.

### Round 2 — 0 findings (all round 1 fixes verified)

### Round 3 — 0 findings (convergence achieved)

## Metrics

| Metric          | Before | After         |
| --------------- | ------ | ------------- |
| Tests           | 607    | 645           |
| New files       | 0      | 6             |
| Lines added     | 0      | ~3,200        |
| PRs merged      | #80    | #81, #82      |
| Red team rounds | -      | 3 (converged) |

## For Discussion

1. The placeholder Ed25519 key (C1) was the most significant finding. If `csq update install` had shipped to users before the real Foundation key was configured, any attacker could sign malicious binaries. What's the right gating mechanism for the production key — a compile-time feature flag, an environment variable check, or the `is_placeholder_key()` runtime comparison we used?

2. If the Windows named-pipe IPC had used `GetUserNameW` instead of `%USERNAME%` environment variable (finding M1, deferred to next session), what other Windows-specific environment variables does csq rely on that might have similar mutability concerns?

3. The test coverage gap in `apply.rs` (the happy-path integration test doesn't call `download_and_apply()` end-to-end because `current_exe()` is hard to mock) represents a real verification blind spot. What's the most reliable way to test atomic self-replacement without actually replacing the test binary?
