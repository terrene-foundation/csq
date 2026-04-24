# Daemon Architecture — csq v2.1

Quick reference for the background daemon's subsystem design, invariants, and security model.

## Subsystem Overview

| Subsystem          | File                               | Interval   | Output                                                  |
| ------------------ | ---------------------------------- | ---------- | ------------------------------------------------------- |
| Startup reconciler | `daemon/startup_reconciler.rs`     | once       | Pass1-4: clamps invariants before any subsystem starts  |
| Token refresher    | `daemon/refresher.rs`              | 5 min      | `RefreshStatus` cache + credential files (per-surface)  |
| Anthropic poller   | `daemon/usage_poller.rs` tick()    | 5 min      | `quota.json` (schema_v2)                                |
| Codex poller       | `daemon/usage_poller/codex.rs`     | 5 min      | `quota.json` + `codex-wham-raw.json` forensic capture   |
| 3P poller          | `daemon/usage_poller.rs` tick_3p() | 15 min     | `quota.json` (with `RateLimitData`)                     |
| Auto-rotator       | `daemon/auto_rotate.rs`            | 30s        | ClaudeCode-only (INV-P11); refuses Codex handle dirs    |
| Handle-dir sweep   | `session/handle_dir.rs`            | 60s        | Removes orphan `term-*` dirs + preserves `image-cache/` |
| Update check       | `update::auto_update_bg`           | 24h cache  | Stderr notice on new release                            |
| HTTP server        | `daemon/server.rs`                 | on-request | JSON over Unix socket                                   |

## Startup Reconciler (PR-C4 + later)

`run_reconciler(base_dir)` runs synchronously before any subsystem starts and clamps invariants the running daemon later relies on. Four passes:

| Pass | Function                            | Scope | What it does                                                                                  |
| ---- | ----------------------------------- | ----- | --------------------------------------------------------------------------------------------- |
| 1    | `pass1_codex_credential_mode`       | Codex | Flips `credentials/codex-<N>.json` from 0o600 back to 0o400 (INV-P08; per-account mutex)      |
| 2    | `pass2_codex_config_toml`           | Codex | Rewrites `config-<N>/config.toml` if `cli_auth_credentials_store = "file"` is missing/drifted |
| 3    | `pass3_quota_v1_to_v2`              | Quota | Idempotent schema v1 → v2 migration of `quota.json` (PR-C6, ships with v2.1)                  |
| 4    | `pass4_strip_legacy_api_key_helper` | 3P    | Issue #184: strips legacy `apiKeyHelper` from `config-N/settings.json` + `settings-*.json`    |

Outcome counters surface via `ReconcileSummary` (asserted in unit tests; logged at INFO on completion).

**Pass-4 strip predicate is unambiguous-bug:** rewrites only when BOTH `apiKeyHelper` AND `env.ANTHROPIC_AUTH_TOKEN` are present (csq itself never wrote any other shape; user-authored helper scripts at the same key without an env token are preserved). Atomic via `unique_tmp_path` + `secure_file` (clamps to 0o600) + `atomic_replace`. Per `security.md` §5a, every failure branch removes the umask-default tmp file before propagating the error so a partial migration never leaves a token-bearing file at world-readable perms. Mtime is preserved on no-op so CC's mtime-driven re-stat (spec 01 §1.4) doesn't fire for nothing.

The reconciler is the canonical home for **on-disk artifact migrations**. New migrations should land as additional `passN` functions following the same shape: idempotent, mtime-preserving on no-op, structured-logged with `error_kind = "migrate_*"` per file rewrite, retire after a 3-month telemetry window confirms zero hits.

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

### 5. Refresher `is_rate_limited` is Substring-Based and Can Lie (journal 0052)

`broker::check::is_rate_limited` does `e.to_string().to_lowercase().contains("rate_limit")`. When it returns true, the refresher returns `BrokerResult::RateLimited` and enters the cooldown. When it returns false, the refresher falls through to `recover_from_siblings` (which is designed for the old multi-config-N layout and has nothing to scan in the handle-dir model).

**The masking failure mode:** an Anthropic server-side contract change that returns a 400 with some _other_ error type (e.g. `invalid_scope`) fails `is_rate_limited`, hits the recovery dead-end, stacks 10-minute cooldowns, and after enough bad requests Cloudflare actually IP-throttles the daemon for real. The `rate_limited` cache entries that result are the _consequence_ of the cascade, not the original cause.

**When reviewing changes that touch the refresher or broker_check:**

- Any new error classification must distinguish "server-side contract failures" (e.g. `invalid_scope`, `invalid_request`) from "transient throttling". Contract failures should surface to the user, not silently cooldown-loop.
- A multi-account wall of `rate_limited` that persists across multiple 5-minute ticks is a smoke alarm — it usually means the underlying error is something else entirely. See `.claude/skills/provider-integration/SKILL.md` for the manual replay runbook.
- `error::redact_tokens` currently strips ALL tokens from the error string the classifier sees. If Anthropic starts responding with a novel error type, the tag passed to `error_kind_tag` and the log line will not name it. Diagnostic redaction relaxation (a small allowlist of OAuth error-type strings) is tracked but not yet shipped.

## Transport Injection Pattern

Every network-touching function takes an injectable closure for testability:

| Function               | Closure type                                          | Production impl (Anthropic) | Production impl (3P)           |
| ---------------------- | ----------------------------------------------------- | --------------------------- | ------------------------------ |
| `refresh_token`        | `HttpPostFn`                                          | `http::post_json_node`      | n/a                            |
| `poll_anthropic_usage` | `HttpGetFn`                                           | `http::get_bearer_node`     | n/a                            |
| `poll_3p_usage`        | `HttpPostProbeFn`                                     | n/a                         | `http::post_json_with_headers` |
| `exchange_code`        | `FnOnce(url, body) -> Result<Vec<u8>>`                | `http::post_json_node`      | n/a                            |
| `validate_key`         | `FnOnce(url, headers, body) -> Result<(u16, String)>` | n/a                         | `http::post_json_probe`        |

**Anthropic endpoints use Node.js subprocess transport** (journal 0056). Cloudflare JA3/JA4 TLS fingerprinting blocks `reqwest`/`rustls`. The `_node` functions shell out to `node`, piping request bodies via stdin. 3P endpoints use `reqwest` — they don't have Cloudflare's fingerprinting.

Tests inject mocks that return predetermined responses — no HTTP or subprocess dependency in the test suite.

## Refresher Backoff (journal 0056)

Rate-limited accounts use exponential backoff: `FAILURE_COOLDOWN` (10 min) × 2^n, capped at `MAX_BACKOFF` (8 → 80 min). Non-rate-limited failures use the base 10-minute cooldown without backoff escalation.

**Stop-on-rate-limit:** When any account hits a rate limit within a tick, remaining accounts that need refresh (within the 2-hour window) are skipped for that tick. Valid tokens are still checked — they don't make HTTP requests, so skipping them would leave the cache empty. Skipped accounts get a `rate_limited` cache entry so the dashboard shows their state.

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
