# M8: Daemon Core

Priority: P1 (Fast-Follow)
Effort: 6.5 autonomous sessions
Dependencies: M1-M5 (all P0 core logic)
Phase: 3, Stream 1

---

## M8-01: Build daemon lifecycle

`csq daemon start` — start background process, write PID file, single-instance guard per GAP-9 resolution. `csq daemon stop` — graceful shutdown (SIGTERM), remove PID + socket. `csq daemon status` — report running/stopped + PID.

- Scope: New, GAP-9
- Complexity: Complex
- Acceptance:
  - [x] PID file created at platform-correct path
  - [x] Second daemon rejected: "already running (PID N)"
  - [x] Stop: graceful shutdown, PID + socket removed
  - [x] Status: reports running/stopped

## M8-02: Build IPC server (Unix socket)

macOS/Linux: bind Unix domain socket per GAP-9 resolution. HTTP/1.1 over socket using `hyper`. Accept connections, route to handler.

- Scope: ADR-005, GAP-9
- Complexity: Complex
- Acceptance:
  - [x] Socket created at correct path
  - [x] `curl --unix-socket /path http://localhost/api/health` returns 200
  - [x] Multiple concurrent connections handled
  - [x] Socket cleaned up on shutdown
  - [x] Socket file permissions: `0o600` (same-user only)
  - [x] Verify caller identity via `SO_PEERCRED` (reject different UID)

## M8-03: Build IPC server (Windows named pipe)

Windows: named pipe `\\.\pipe\csq-{username}`. HTTP/1.1 over pipe using `tokio::net::windows::named_pipe` with custom `hyper` connector.

- Scope: ADR-005
- Complexity: Complex
- Acceptance:
  - [ ] Named pipe created
  - [ ] HTTP requests over pipe work
  - [ ] Pipe ACL restricts to current user
  - [ ] Windows CI passes

## M8-04: Build daemon detection protocol

CLI-side: 4-step liveness check per GAP-9 — PID file -> PID alive -> socket connect (100ms) -> health check (200ms). Silent fallback to direct mode on any failure.

- Scope: GAP-9
- Complexity: Moderate
- Acceptance:
  - [x] Missing PID file: direct mode, no warning
  - [x] Stale PID file: cleaned up, direct mode
  - [x] Socket timeout: direct mode with warning
  - [x] Healthy daemon: delegate succeeds

## M8-05: Build background token refresher

Replaces broker subprocess model. Check every 5 minutes, refresh when token expires within 2 hours (ADR-006). Per-account async Mutex. Fanout after refresh. Recovery from CC race (scan siblings). 10-minute cooldown after failure.

- Scope: 8.1-8.5
- Complexity: Complex
- Depends: M4-01 (broker logic), M4-02 (recovery)
- Acceptance:
  - [x] 2-hour-ahead refresh window triggers correctly
  - [x] Per-account lock: 10 concurrent tasks, exactly 1 HTTP refresh
  - [x] Fanout: all matching config dirs updated
  - [x] Recovery: dead canonical + live sibling -> promotion
  - [x] 10-minute cooldown after HTTP failure
  - [x] Monotonicity guard: re-reads inside lock

## M8-06: Build background usage poller

Anthropic: poll `/api/oauth/usage` every 5 minutes with Bearer token. 3P: poll via `max_tokens=1` every 15 minutes, extract rate-limit headers. Staggered initial polls (5s between accounts). Exponential backoff on 429 (doubles, max 8x). 401 marks account as needing re-login.

- Scope: 7.1-7.4
- Complexity: Complex
- Acceptance:
  - [x] Anthropic polling at 5-min intervals
  - [x] 3P polling at 15-min intervals
  - [x] Staggered start (accounts don't all poll simultaneously)
  - [x] 429: exponential backoff
  - [x] 401: account marked expired
  - [x] Bearer tokens handled via `Secret<String>`, never logged (S10)

## M8-07: Build in-memory cache with TTL

Thread-safe `RwLock<HashMap>` with per-entry timestamps. Configurable `max_age_seconds` (default 10 minutes). Get/set/delete/clear operations.

- Scope: 7.5
- Complexity: Trivial
- Acceptance:
  - [x] Set + get within TTL: returns value
  - [x] Get after TTL: returns None
  - [x] Thread-safe: concurrent reads don't block

## M8-08: Build HTTP API routes

Dashboard API: `GET /api/accounts`, `GET /api/account/{id}/usage`, `GET /api/refresh`, `GET /api/tokens`, `GET /api/login/{N}`, `GET /oauth/callback`, `POST /api/accounts`, `POST /api/refresh-token/{id}`, `GET /api/health`. Use `axum` router.

- Scope: 13.1-13.9
- Complexity: Moderate (routing), Complex (OAuth callback)
- Depends: M8-05, M8-06, M8-07
- Acceptance:
  - [x] All routes registered and respond
  - [x] 404 for unknown routes
  - [x] JSON responses with correct content-type
  - [x] OAuth callback completes full PKCE flow
  - [x] Account ID path params validated via `AccountNum` (prevents path traversal)
  - [x] Static file serving with path traversal sanitization (scope 13.11)
  - [x] Rate-limit header extraction implemented for 3P polling (scope 7.3)

## M8-09: Build server lifecycle + subsystem initialization

Initialize all subsystems: cache, poller, refresher, OAuth state store, HTTP server. Graceful shutdown: stop accepting connections, complete in-flight requests (5s deadline), stop background tasks, remove socket + PID file.

- Scope: 13.10, GAP-9
- Complexity: Complex
- Acceptance:
  - [x] All subsystems start correctly
  - [x] Health endpoint shows all subsystems healthy
  - [x] SIGTERM: graceful shutdown within 5s
  - [x] In-flight requests completed before shutdown

## M8-10: Wire CLI commands to daemon IPC

`csq status` — try daemon first (instant), fall back to direct file read. `csq statusline` — try daemon (50ms timeout), fall back to synchronous. `csq swap` — notify daemon after swap. These are modifications to existing M5/M6 commands.

- Scope: CLI-to-daemon delegation
- Complexity: Moderate
- Depends: M8-04
- Acceptance:
  - [x] Status with daemon: <5ms response
  - [x] Status without daemon: direct mode works
  - [x] Statusline with daemon: <50ms
  - [x] Swap: daemon notified to update cache

## M8-11: Build daemon integration tests

Start daemon, verify health. Start second daemon: rejected. CLI with daemon: IPC delegation. CLI without daemon: fallback. Kill daemon: CLI detects stale socket.

- Scope: Phase 3 test strategy
- Complexity: Complex
- Acceptance:
  - [x] Full daemon lifecycle tested
  - [x] Concurrent access tested
  - [x] Fallback behavior verified
