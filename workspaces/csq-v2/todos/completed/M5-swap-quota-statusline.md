# M5: Swap, Quota & Statusline

Priority: P0 (Launch Blocker)
Effort: 3.5 autonomous sessions
Dependencies: M2 (Credentials), M3 (Account Identity), M4 (Broker/Sync)
Phase: 2, Stream 1

---

## M5-01: Build swap_to() with verification

Read cached creds from `credentials/N.json`, write to `.credentials.json` (atomic), `.csq-account`, `.current-account`. Never calls refresh endpoint. Best-effort keychain write on swap. Quota cursor preserved.

- Scope: 4.1
- Complexity: Complex
- Acceptance:
  - [x] All three files updated atomically
  - [x] Immediate read-back verification succeeds
  - [x] `.quota-cursor` NOT deleted during swap
  - [x] Parity: same credential files as v1.x swap

## M5-02: Build delayed swap verification

Background task checks at +2s if CC overwrote the swap (CC may detect stale creds and re-fetch). If access token changed from what we wrote, log a warning.

- Scope: 4.1 (delayed check)
- Complexity: Moderate
- Depends: M5-01
- Acceptance:
  - [x] 2-second delay fires in background
  - [x] Detects if CC overwrote credentials
  - [x] Warning logged but swap not retried

## M5-03: Build pick_best() and suggest()

`pick_best(exclude)` — selects account with lowest 5-hour usage. If all exhausted, picks earliest reset time. `suggest()` — JSON output: best account to switch to, excludes current, returns `exhausted: true` if all at 100%.

- Scope: 4.2-4.3
- Complexity: Moderate (pick_best), Trivial (suggest)
- Acceptance:
  - [x] Picks lowest 5h usage
  - [x] All exhausted: picks earliest reset
  - [x] Suggest JSON format matches v1.x
  - [x] Current account excluded from suggestion

## M5-04: Build update_quota() with payload-hash cursor

Parse statusline JSON from CC, extract `rate_limits`. Use `live_credentials_account()` for ground-truth account attribution. Payload-hash cursor prevents stale data after swap. File locking on `quota.json`.

- Scope: 6.1, GAP-3
- Complexity: Complex
- Acceptance:
  - [x] Correct account attributed via refresh token match
  - [x] Stale payload after swap: rejected by cursor
  - [x] Concurrent updates: file lock prevents corruption
  - [x] QuotaFile struct per GAP-3 schema

## M5-05: Build quota state management

`load_state()` — loads `quota.json`, auto-clears expired windows based on `resets_at`. Uses `QuotaFile` struct per GAP-3 resolution.

- Scope: 6.2
- Complexity: Trivial
- Acceptance:
  - [x] Expired 5h window cleared on load
  - [x] Expired 7d window cleared on load
  - [x] Missing file: returns empty state

## M5-06: Build statusline_str() with indicators

Compact statusline: `#N:user 5h:X% 7d:Y%`. Stuck-swap warning (`#N!:user`). Broker-failure warning (`LOGIN-NEEDED` prefix). Self-healing stale broker flags (flag older than 24h auto-cleared).

- Scope: 6.4
- Complexity: Moderate
- Acceptance:
  - [x] Normal format matches v1.x exactly
  - [x] Stuck swap: `!` indicator shown
  - [x] Broker failure: `LOGIN-NEEDED` prefix
  - [x] Stale flag (>24h): auto-cleared

## M5-07: Build fmt_time() and fmt_tokens()

`fmt_time(secs)` — "now", "5m", "2h", "1d". `fmt_tokens(n)` — 500 -> "500", 1200 -> "1k", 1500000 -> "1.5M".

- Scope: 6.5, 12.6
- Complexity: Trivial
- Acceptance:
  - [x] Edge cases: 0, 59, 60, 3599, 3600, 86399, 86400
  - [x] Token formatting matches v1.x output

## M5-08: Build csq statusline command

Replaces `statusline-quota.sh` entirely. Reads CC's JSON from stdin. Calls snapshot (synchronous), sync (background), quota update (background). Outputs formatted statusline string. Includes context window, session cost, model, project, git status.

- Scope: 12.1-12.7
- Complexity: Complex
- Acceptance:
  - [x] Same CC JSON input produces identical output as v1.x bash script
  - [x] Completes within 50ms (vs 400ms v1.x baseline)
  - [x] Background sync doesn't block output
  - [x] Git status shows branch + dirty indicator

## M5-09: Build show_status() command

Display all accounts: active marker, email, 5h/7d usage percentages, reset times. Icons: bullet (<80%), half (80-99%), circle (100%).

- Scope: 6.3
- Complexity: Trivial
- Acceptance:
  - [x] Format matches v1.x `csq status` output
  - [x] Active account marked
  - [x] Missing quota: shows "no data"
