# Daemon Architecture — csq v2.0

Quick reference for the background daemon's subsystem design, invariants, and security model.

## Subsystem Overview

| Subsystem        | File                               | Interval   | Output                                                  |
| ---------------- | ---------------------------------- | ---------- | ------------------------------------------------------- |
| Token refresher  | `daemon/refresher.rs`              | 5 min      | `RefreshStatus` cache + credential files                |
| Anthropic poller | `daemon/usage_poller.rs` tick()    | 5 min      | `quota.json`                                            |
| 3P poller        | `daemon/usage_poller.rs` tick_3p() | 15 min     | `quota.json` (with `RateLimitData`)                     |
| Auto-rotator     | `daemon/auto_rotate.rs`            | 30s        | Atomic swap via `rotation::swap_to`                     |
| Handle-dir sweep | `session/handle_dir.rs`            | 60s        | Removes orphan `term-*` dirs + preserves `image-cache/` |
| Update check     | `update::auto_update_bg`           | 24h cache  | Stderr notice on new release                            |
| HTTP server      | `daemon/server.rs`                 | on-request | JSON over Unix socket                                   |

**Removed 2026-04-11** (see journal 0020): `daemon/oauth_callback.rs` was a TCP listener on `127.0.0.1:8420` serving `/oauth/callback` for the v1 loopback OAuth flow. Anthropic retired loopback for this client_id — the module and its ~1000 LOC are gone. OAuth now uses the paste-code flow via `/api/login/{N}` + `POST /api/oauth/exchange` on the Unix socket.

## Key Invariants

### 0. Account/Terminal Separation (journal 0028)

**Accounts** are independent entities that authenticate, auto-refresh tokens, and poll Anthropic for usage. **Terminals** are CC instances that borrow credentials and display data.

- Only the daemon writes `quota.json` (via usage poller polling `/api/oauth/usage` per account)
- Terminals (`csq statusline`) read and display quota — they NEVER write it
- CC's per-terminal `rate_limits` JSON is NOT used for account quota (terminal-scoped, not account-scoped)
- After login, accounts auto-refresh with no manual action

See `rules/account-terminal-separation.md` for full spec.

**Identity derivation (journal 0029):** `config-N` directory numbers are slot identifiers, NOT account numbers. After any swap or rename, slot and account diverge. All account identity lookups MUST use `.csq-account` marker, not the directory suffix.

**Subscription metadata (journal 0029):** Token endpoint does not return `subscription_type`. CC backfills it at runtime. Swap and fanout operations MUST preserve existing subscription metadata from live credentials when the canonical lacks it. See guards in `rotation/swap.rs` and `broker/fanout.rs`.

**Stale session detection (journal 0029):** CC caches credentials in memory at startup. After a swap, compare `.csq-account` marker mtime with process `started_at` — if marker is newer, session needs restart. See `commands.rs` `needs_restart` field in `SessionView`.

### 1. Arc-at-Lifecycle-Scope Ownership (journal 0008)

All shared daemon state is created in `handle_start` (`csq-cli/src/commands/daemon.rs`) and passed as `Arc` clones to subsystems. No subsystem owns shared state internally — they receive it via constructor args.

```
handle_start creates: cache, discovery_cache, shutdown_token, oauth_store
    ├── refresher receives: Arc<cache>, shutdown
    ├── usage_poller receives: shutdown (writes quota.json directly)
    ├── auto_rotator receives: shutdown (reads quota.json + config)
    └── server receives: Arc<cache>, Arc<discovery_cache>, Arc<oauth_store>
```

### 2. Single-Listener Security Boundary (as of journal 0020)

| Listener    | Transport | Auth                   | Routes         |
| ----------- | --------- | ---------------------- | -------------- |
| Unix socket | HTTP/1.1  | SO_PEERCRED (same UID) | All API routes |

The TCP listener on `127.0.0.1:8420` was retired when Anthropic moved to paste-code OAuth (journal 0020). All credential-handling routes — including the two OAuth routes `GET /api/login/{N}` and `POST /api/oauth/exchange` — live on the Unix socket and are protected by SO_PEERCRED + 0o600 permissions.

**Historical context**: journal 0011 documented the original dual-listener architecture. That design was correct for the v1 loopback OAuth flow where Anthropic redirected a browser to `http://127.0.0.1:8420/oauth/callback`. With paste-code OAuth the user pastes the code directly into the client app (csq-desktop or a CLI wrapper), so there's no browser-initiated callback and no need for TCP at all.

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

## Handle-Dir Sweep + Image-Cache Preservation

The handle-dir sweep removes orphaned `term-<pid>/` directories whose owner process is dead. Two non-obvious invariants make this safe under concurrent `csq run` invocations:

### Authority of `.live-pid`, not the dir name

The dir name's parsed PID (`term-<pid>`) is only a first-pass filter. The authoritative owner is the `.live-pid` file written by `create_handle_dir`. The sweep:

1. Reads `.live-pid` (`markers::read_live_pid`, refuses symlinks)
2. Falls back to the dir-name PID only if the marker is missing or corrupt
3. Re-reads `.live-pid` immediately before the destructive step to catch racing creates
4. Atomic `rename` to `.sweep-tombstone-<pid>-<nanos>` frees the `term-<pid>` path in a single syscall
5. `cleanup_stale_tombstones` runs at the top of every tick to mop up any tombstones from a crashed previous sweep

### Why `image-cache` cannot be in `SHARED_ITEMS`

CC writes pasted images to `$CLAUDE_CONFIG_DIR/image-cache/<session-id>/` and runs `Dv7()` periodically to delete every entry except the current session. If the dir were shared via symlink across handle dirs, two concurrent terminals would race to delete each other's caches.

The fix is per-session preservation on sweep:

- Walk dead `term-<pid>/image-cache/<session-id>/` entries
- For each one whose name passes `is_valid_session_name` (lowercase `[0-9a-f-]{1,64}`):
  - If the destination is clear: atomic `rename` (EXDEV → iterative copy fallback)
  - If the destination collides (`--resume` from another handle): `merge_session_into_existing` walks file-by-file, **live side wins** on filename collision, recurses into subdirs
- 3-layer symlink refusal: source `image-cache/`, per-entry `<sid>/`, destination `~/.claude/image-cache/`

### Windows `.live-cc-pid`

On Unix, `csq run` calls `exec` to replace csq-cli with claude — single PID. On Windows, `csq run` spawns claude as a child and writes the child's PID to `.live-cc-pid`. The sweep checks BOTH `.live-pid` (csq-cli) and `.live-cc-pid` (CC child) before treating a handle dir as orphaned. Closes the case where csq-cli crashes while CC is still running.

`create_handle_dir` invariant: `pid` MUST equal `std::process::id()`. Breaking it opens a sweep race window where the sweep can observe a `term-<pid>` whose dir-name PID is dead while another live process is populating it.

See journals 0035 (Dv7 race), 0036 (preservation design), 0037 (redteam convergence), 0038 (residual-risk resolution).

## Graceful Shutdown

1. `CancellationToken::cancel()` signals all subsystems
2. Each subsystem's `tokio::select!` on the cancellation token exits the loop
3. Server stops accepting new connections, drains in-flight (5s deadline)
4. PID file and socket file removed
