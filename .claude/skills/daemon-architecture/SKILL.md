# Daemon Architecture — csq v2.0

Quick reference for the background daemon's subsystem design, invariants, and security model.

## Subsystem Overview

| Subsystem        | File                               | Interval   | Output                                   |
| ---------------- | ---------------------------------- | ---------- | ---------------------------------------- |
| Token refresher  | `daemon/refresher.rs`              | 5 min      | `RefreshStatus` cache + credential files |
| Anthropic poller | `daemon/usage_poller.rs` tick()    | 5 min      | `quota.json`                             |
| 3P poller        | `daemon/usage_poller.rs` tick_3p() | 15 min     | `quota.json` (with `RateLimitData`)      |
| Auto-rotator     | `daemon/auto_rotate.rs`            | 30s        | Atomic swap via `rotation::swap_to`      |
| HTTP server      | `daemon/server.rs`                 | on-request | JSON over Unix socket                    |
| OAuth callback   | `daemon/oauth_callback.rs`         | on-request | TCP 127.0.0.1:8420                       |

## Key Invariants

### 1. Arc-at-Lifecycle-Scope Ownership (journal 0008)

All shared daemon state is created in `handle_start` (`csq-cli/src/commands/daemon.rs`) and passed as `Arc` clones to subsystems. No subsystem owns shared state internally — they receive it via constructor args.

```
handle_start creates: cache, discovery_cache, shutdown_token, oauth_store
    ├── refresher receives: Arc<cache>, shutdown
    ├── usage_poller receives: shutdown (writes quota.json directly)
    ├── auto_rotator receives: shutdown (reads quota.json + config)
    └── server receives: Arc<cache>, Arc<discovery_cache>, Arc<oauth_store>
```

### 2. Dual-Listener Security Boundary (journal 0011)

| Listener           | Transport | Auth                   | Routes                 |
| ------------------ | --------- | ---------------------- | ---------------------- |
| Unix socket        | HTTP/1.1  | SO_PEERCRED (same UID) | All API routes         |
| TCP 127.0.0.1:8420 | HTTP/1.1  | CSPRNG state token     | `/oauth/callback` only |

New credential-handling routes MUST live on the Unix socket. The TCP listener is exclusively for the browser OAuth redirect.

### 3. Filesystem-as-IPC (journal 0012)

CLI commands (`csq status`, `csq statusline`) poll canonical credential files directly rather than querying daemon HTTP routes. This avoids cache-TTL latency (5s discovery cache) and keeps the CLI functional without a running daemon.

The daemon writes: `credentials/N.json`, `quota.json`, `rotation.json`
The CLI reads: same files directly, with daemon as optional accelerator

### 4. Separate State for Anthropic vs 3P (journal 0014)

Anthropic accounts (IDs 1-999) and 3P accounts (synthetic IDs 901, 902) use **separate** cooldown/backoff maps to prevent ID collision. The tick functions run sequentially in the same async task — no lock ordering issues.

## Transport Injection Pattern

Every network-touching function takes an injectable closure for testability:

| Function               | Closure type                                          | Production impl                |
| ---------------------- | ----------------------------------------------------- | ------------------------------ |
| `refresh_token`        | `HttpPostFn`                                          | `http::post_form`              |
| `poll_anthropic_usage` | `HttpGetFn`                                           | `http::get_bearer`             |
| `poll_3p_usage`        | `HttpPostProbeFn`                                     | `http::post_json_with_headers` |
| `exchange_code`        | `FnOnce(url, body) -> Result<Vec<u8>>`                | `http::post_json`              |
| `validate_key`         | `FnOnce(url, headers, body) -> Result<(u16, String)>` | `http::post_json_probe`        |

Tests inject mocks that return predetermined responses — no HTTP dependency in the test suite.

## Cache Invalidation

`POST /api/invalidate-cache` clears both `discovery_cache` and `cache`. Called by `csq swap` after a successful account switch. Silent on failure (cache expires naturally within 5s TTL).

## Graceful Shutdown

1. `CancellationToken::cancel()` signals all subsystems
2. Each subsystem's `tokio::select!` on the cancellation token exits the loop
3. Server stops accepting new connections, drains in-flight (5s deadline)
4. PID file and socket file removed
