# M4: Broker & Sync

Priority: P0 (Launch Blocker)
Effort: 3.5 autonomous sessions
Dependencies: M2 (Credentials), M3 (Account Identity)
Phase: 1, Stream D

---

## M4-01: Build broker_check() with per-account lock

Per-account try-lock. Read canonical credentials, check expiry (2-hour window per ADR-006). If near expiry: acquire lock, refresh via `refresh_token()`, fan out to all config dirs. Non-blocking — skip if another process holds the lock.

- Scope: 5.1
- Complexity: Complex
- Acceptance:
  - [x] 10 concurrent tasks: exactly 1 HTTP refresh call made
  - [x] Token not near expiry: no refresh, returns quickly
  - [x] Lock contention: skips gracefully (no error)
  - [x] Successful refresh: fans out to all matching config dirs

## M4-02: Build broker recovery from live siblings

When canonical RT is dead (CC won a refresh race and rotated the RT): scan all `config-X/.credentials.json` for a live RT that differs from canonical. Promote candidate into canonical, retry refresh. Restore original on total failure.

- Scope: 5.2
- Complexity: Complex
- Acceptance:
  - [x] Dead canonical + live sibling with good RT: promotion + successful refresh
  - [x] All siblings dead: marks broker-failed, returns error
  - [x] Total failure: original canonical restored (rollback)
  - [x] Recovery restores correct state after multi-terminal race

## M4-03: Build config dir scanning

`scan_config_dirs_for_account(account)` — scans `config-*` dirs for matching `.csq-account` markers. Returns list of paths.

- Scope: 5.3
- Complexity: Trivial
- Acceptance:
  - [x] Finds all config dirs with matching marker
  - [x] Ignores dirs without `.csq-account` file
  - [x] Handles corrupt marker gracefully

## M4-04: Build credential fanout

`fan_out_credentials(account, creds)` — writes new credentials to every matching config dir. Atomic per-file. Skips if already in sync (access token matches).

- Scope: 5.4
- Complexity: Moderate
- Acceptance:
  - [x] All matching dirs updated atomically
  - [x] Already-in-sync dirs skipped (no unnecessary writes)
  - [x] Single dir failure doesn't stop fanout to others

## M4-05: Build broker failure flags

Touch `credentials/N.broker-failed` on total broker failure. Remove on successful refresh or `csq login`. Surface `LOGIN-NEEDED` in statusline.

- Scope: 5.5
- Complexity: Trivial
- Acceptance:
  - [x] Flag created on failure
  - [x] Flag removed on recovery or login
  - [x] `is_broker_failed(account)` reads flag

## M4-06: Build backsync with monotonicity guard

Live `.credentials.json` -> canonical `credentials/N.json` when live is newer. Content-match by refresh token (primary) or `.csq-account` marker (fallback for rotated RTs). Per-canonical lock. Monotonicity: only write if `expiresAt` strictly newer. Re-read inside lock.

- Scope: 5.6
- Complexity: Complex
- Acceptance:
  - [x] Live newer: canonical updated
  - [x] Live older: canonical NOT updated (monotonicity)
  - [x] RT match: correct account identified
  - [x] Marker fallback: works when RT has been rotated
  - [x] Re-read inside lock: concurrent backsync safe

## M4-07: Build pullsync with strict-newer check

Canonical `credentials/N.json` -> live `.credentials.json` when canonical is newer. Read marker for account ID. Only write if `expiresAt` strictly newer AND access tokens differ.

- Scope: 5.7
- Complexity: Moderate
- Acceptance:
  - [x] Canonical newer: live updated
  - [x] Canonical older: live NOT updated
  - [x] Same access token: skipped (no unnecessary write)

## M4-08: Integration tests for broker/sync

Mock HTTP server for token refresh. Concurrent broker test (10 tasks, 1 refresh). Backsync + pullsync monotonicity verification. Recovery path end-to-end.

- Scope: Phase 1 test strategy
- Complexity: Complex
- Acceptance:
  - [x] All broker/sync tests pass
  - [x] Race conditions covered by concurrent test
  - [x] Recovery tested with dead canonical + live sibling
