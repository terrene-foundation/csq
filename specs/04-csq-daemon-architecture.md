# 04 csq Daemon Architecture

Spec version: 1.14.0 | Status: DRAFT | Governs: daemon subsystems, IPC surface, refresh logic, sweep, supervisor

---

## 4.0 Scope

This spec defines csq's long-running daemon: what subsystems it hosts, how they interact, what the external contract looks like (Unix socket API), and the invariants that the daemon enforces regardless of which CLI or desktop process is talking to it.

## 4.1 Process model

The daemon is a tokio runtime that runs in one of three process hosts:

- **Managed background daemon (canonical on macOS).** `csq daemon start --supervised`, launched by a launchd LaunchAgent (`~/Library/LaunchAgents/foundation.terrene.csq.plist`) with `RunAtLoad=true`, `KeepAlive={SuccessfulExit:false}`, and `ThrottleInterval=10`. It survives the desktop app quitting or crashing and OS restarts, so the token refresher stays live regardless of the UI. The desktop app installs/repairs the plist on every launch (`ensure_managed_daemon_plist` in `csq/src/cli/commands/daemon.rs`), as does `csq daemon install`. `ProgramArguments[0]` is the persistent CLI shim (`resolve_managed_daemon_exe` → the running exe if outside a bundle, else `~/.local/bin/csq`), NEVER the app bundle binary — `mode::detect` (`csq/src/mode.rs`) would misread a `Contents/MacOS/` path as Desktop mode and launch the whole app instead of the daemon.
- **Desktop in-process supervisor.** The Tauri app also hosts the daemon in-process (`csq/src/desktop/daemon_supervisor.rs`) — a cohabiting backup covering the window before the managed daemon loads. It defers to the managed daemon via the PidFile lock.
- **Standalone foreground / background.** `csq daemon start` blocks the terminal; `-d`/`--background` re-execs detached. Used for debugging and on headless Linux, where a systemd user unit (`csq daemon install`) provides the KeepAlive-equivalent auto-restart.

Only one daemon runs per user at a time, enforced by a **kernel-atomic advisory lock**: `PidFile::acquire` (`csq-core/src/daemon/pid.rs`) holds an exclusive `flock` (Unix) / named kernel mutex (Windows, via `csq-core/src/platform/lock.rs`) on a sibling `<pidfile>.lock` for the daemon's whole lifetime, released automatically on process death. A second daemon that loses the lock reports `DaemonError::AlreadyRunning` and (under the supervisor loop) backs off. The Unix socket at `$base_dir/csq.sock` is the IPC transport.

All three hosts drive the same supervisor loop, `csq_core::daemon::supervise::run_forever(base, cancel, run_session)`.

See `csq/src/desktop/daemon_supervisor.rs` for the takeover/defer state machine.

## 4.2 Subsystems

### 4.2.1 Refresher (`daemon::refresher`)

**Responsibility:** keep each account's OAuth tokens fresh ahead of expiry.

**Cadence:** scans every 5 minutes. For each account:

1. Read canonical credentials. Resolve slot N → UUID via `profiles.json::by_slot[N]`; on hit read `identities/<UUID>/credentials.json` (Anthropic) or `identities/<UUID>/credentials-codex.json` (Codex). Legacy fallback to `credentials/<N>.json` / `credentials/codex-<N>.json` only when `by_slot` has no entry for this slot (pure-legacy install). Slot-id channel: per-slot refresh task state (channel (a) per the account/terminal separation rules — the slot id comes from the polling task that already knows which slot it polls, never from terminal-derived state).
2. If `expiresAt - now < REFRESH_AHEAD_SECS` (default 7200 = 2 hours), refresh.
3. Acquire per-account async lock (`tokio::sync::Mutex`).
4. POST to Anthropic's token endpoint with the refresh token.
5. On success: resolve slot N → UUID via `profiles.json::by_slot[N]`, then atomically write the new tokens to `identities/<UUID>/credentials.json` only (`save_canonical_for` returns `NoCredentials` fail-closed when UUID absent). Preserve `subscription_type` and `rate_limit_tier` from the existing file (subscription contamination guard — these fields are not returned by Anthropic's token endpoint, so they MUST be backfilled from the existing file or the account silently loses its subscription tier).
6. On 401: mark account LOGIN-NEEDED, surface via daemon API.
7. On 429: exponential backoff, capped at 80 minutes (`MAX_BACKOFF` = 8 × `FAILURE_COOLDOWN` 10min, `daemon/refresher.rs`).

**Wall-clock-aware tick wait:** between ticks the loop sub-sleeps in `WAKE_PROBE_INTERVAL` (30s) chunks rather than issuing a single monotonic `sleep(REFRESH_INTERVAL)`, breaking on whichever of two channels fires first: (a) a monotonic floor (`Instant::elapsed() >= interval`) — preserves the old steady-state cadence and is immune to wall-clock steps (backward NTP/manual sets never delay a tick past the interval); (b) a `SystemTime` wall-clock deadline (`next_wait_chunk` in `daemon/refresher.rs`) — the monotonic clock pauses while the host is asleep (macOS) but tokens keep aging on the wall clock, so this channel makes the loop tick within one probe granularity (≤30s) of wake instead of stranding an aged (possibly expired) token for a full interval. The per-tick cadence in the awake steady state is unchanged at 5 minutes.

**Handle-dir interaction:** the refresher writes `identities/<UUID>/credentials.json` exactly once per refresh. Every handle dir whose `.credentials.json` symlink points at that identity automatically sees the new content on its next `fs.stat`. There is no per-handle-dir credential fanout; the symlink layer handles propagation for free. The `phase4_gate_check` in `startup_reconciler` refuses daemon start when `store-version` is absent or schema < 2, guaranteeing the identity-keyed path is the live source, and that every `by_slot` UUID has its `identities/<UUID>/credentials.json` seeded before the daemon serves any request.

**Invariants:**

- Only one refresh in flight per account (per-account mutex).
- Writes are atomic (temp file + rename) with `0o600` permissions.
- Subscription metadata preserved on every write.

### 4.2.2 Usage poller (`daemon::usage_poller`)

**Responsibility:** poll Anthropic's `/api/oauth/usage` per account; poll third-party provider endpoints. Write to `quota.json`. Governed in detail by spec 05.

**Cadence:** Anthropic every 5 minutes; 3P every 15 minutes.

**Critical invariant:** the usage poller is the SOLE writer of `quota.json`. No CLI path, no statusline, no terminal-side code writes quota. Terminal-side quota attribution is unreliable, so quota is sourced only from the per-slot poller's own token query against Anthropic — the response IS that slot's usage, unforgeable.

**Hang protection:** the poller's main loop MUST wrap each `spawn_blocking` HTTP call in `tokio::time::timeout(30s, ...)` and MUST be run under a supervisor that respawns the task on panic with logged backtrace. An unguarded HTTP hang (e.g. in `tick_3p`) can otherwise block the loop forever and silently stop all polling.

### 4.2.3 Handle dir sweeper (`daemon::sweep`)

**Responsibility:** remove orphan `term-<pid>/` handle dirs whose owning `claude` process has exited.

**Cadence:** every 30 seconds.

**Actions:**

1. `readdir(accounts/)` and filter to entries matching `term-[0-9]+/`.
2. For each, read `.live-pid`.
3. Check liveness: Unix `kill(pid, 0)` — returns ESRCH if dead; Windows `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, pid)` — returns null if dead.
4. If dead: remove the handle dir (idempotent — ENOENT OK).
5. If alive: skip.

**Invariants:**

- A handle dir whose `.live-pid` file is missing is immediately swept (treated as malformed).
- A handle dir whose PID is alive is NEVER swept, even if its symlinks are broken or stale.
- The sweep is safe to run concurrently with `csq run` creating new handle dirs (atomic `create_dir` on the new one; the sweep only removes, never modifies existing dirs).

### 4.2.4 OAuth callback listener (`daemon::oauth_callback`)

**Responsibility:** serve the single localhost TCP route at `127.0.0.1:8420/oauth/callback` used by the browser OAuth flow. Authenticated by CSPRNG state token.

**Scope:** exactly one route; everything else belongs on the Unix socket. The TCP listener serves no credential-handling routes — TCP is reachable by any process on the machine, so all credential traffic stays on the Unix socket (see §4.2.5 security layers).

### 4.2.5 IPC server (`daemon::server`)

**Responsibility:** serve the Unix socket at `$base_dir/csq.sock`. HTTP/1.1 protocol, JSON bodies. Listed routes:

| Route                        | Purpose                                                                                       | Authentication    |
| ---------------------------- | --------------------------------------------------------------------------------------------- | ----------------- |
| `GET /api/health`            | Liveness check                                                                                | None              |
| `GET /api/accounts`          | List accounts + refresh status + subscription tier                                            | None (local only) |
| `GET /api/usage`             | Return current `quota.json` snapshot                                                          | None              |
| `GET /api/refresh-status`    | Per-account refresh state                                                                     | None              |
| `POST /api/provision`        | Signal that account N was just logged in; start refresh + polling                             | None              |
| `POST /api/invalidate-cache` | Clear in-memory caches (e.g. after a swap)                                                    | None              |
| `POST /api/swap-report`      | Record a swap event for telemetry                                                             | None              |
| `POST /api/audit/record`     | Persist a per-`csq run` audit record (body conforms to the csq-runs JSON schema); see spec 12 | None (local only) |

**Security layers (three-layer):**

1. **Socket file permissions**: umask `0o077` before `bind`, then explicit `chmod 0o600`.
2. **Peer credential verification**: `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) rejects different-UID connections.
3. **Per-user socket directory**: `$XDG_RUNTIME_DIR` or `~/.claude/accounts/`.

### 4.2.6 Cache sweeper budget (`daemon::coc_cache_sweeper`)

**Responsibility:** garbage-collect stale `.coc/.cache/parsed-<lock_sha>.bin` files across the user's known `.coc/` roots. These are parsed-artifact caches keyed by a lockfile content hash; they are safe to delete (regenerated on next read) and fail-open (a missing cache entry is recomputed, never an error).

**Cadence:** every 24 hours.

**Coordination contract:**

1. Sweeper runs on `tokio::task::spawn` (NOT the main daemon loop).
2. Coordinates with the refresher via a bounded mutex (refresher holds during its tick).
3. Per-tick wall-clock cap: 30 seconds. If the sweeper does not finish in 30s, log `sweep_partial: true` + cursor (path of the next directory to scan); resume at the cursor on the next 24-hour tick.
4. Yields every 10 directories scanned (cooperative scheduling).
5. Discovery of `.coc/` roots: `~/.csq/coc-roots-seen.jsonl` (append-only, mode 0600, FIFO-capped at 256 lines) — the sole roots authority.

**Sweep target regex:** `^parsed-[0-9a-f]{64}\.bin$`. Tmp files matching `parsed-<sha>.bin.tmp.<pid>.<counter>` are excluded by construction.

**Sweep criteria:** delete files where (a) `lock_sha` does not match any current `lock_sha` in the user's known `.coc/` roots, OR (b) file mtime > 30 days.

**Per-deletion logging:** `INFO: cache-sweep: deleted <path> (reason: <stale_lock_sha|mtime_30d>)` at structured-log level. NOT WARN.

**Windows behavior:** `ERROR_SHARING_VIOLATION` is logged INFO (NOT WARN/ERROR) and the file is retried on the next 24h tick. Per-file retry-count tracked; if a single file is sharing-violated for 7 consecutive ticks, surface in `csq doctor --json::cache_sweeper.cache_sweep_blocked: <count>` (see §4.2.7).

**Doctor surface coupling:** sweeper state surfaces via `csq doctor --json::cache_sweeper` block per §4.2.7. If `sweep_partial: true` for >24h, top-level `status` field surfaces `degraded` (not `ok`).

### 4.2.7 doctor JSON schema

**Responsibility:** pin the shape of `csq doctor --json` output so external tooling (CI gates, monitoring, recording scripts) can consume it deterministically.

**Top-level shape:**

```json
{
  "status": "ok | degraded | error",
  "csq_version": "<semver string>",
  "daemon_pid": <int>,
  "daemon_started_at": "<ISO-8601 UTC>",
  "quota": {
    "<account_id>": {
      "utilization": <float 0.0-100.0>,
      "subscription_type": "max | pro | free | null",
      "rate_limit_tier": "<string | null>",
      "expires_at": "<ISO-8601 UTC | null>"
    }
  },
  "cache_sweeper": {
    "last_sweep_at": "<ISO-8601 UTC | null>",
    "last_sweep_duration_ms": <int | null>,
    "sweep_partial": <bool>,
    "sweep_lag_minutes": <int>,
    "files_swept_last_run": <int>,
    "files_skipped_last_run": <int>,
    "cache_sweep_blocked": <int>
  }
}
```

**Field semantics:**

- `status`: `ok` if no degraded subsystem; `degraded` if `cache_sweeper.sweep_partial == true && sweep_lag_minutes > 1440`; `error` if any subsystem is panicking.
- `quota.<account_id>.utilization`: 0.0-100.0 percentage from Anthropic's `/api/oauth/usage` (NOT the CC statusline's per-terminal value — that value reflects a single terminal's view and can exceed 100%; the account-level utilization comes from Anthropic's usage API).
- `cache_sweeper.last_sweep_at`: timestamp of last successful or partial sweep run; `null` only at first daemon start.
- `cache_sweeper.sweep_partial`: `true` if the most recent tick exceeded 30s wall-clock cap and resumed via cursor.
- `cache_sweeper.sweep_lag_minutes`: minutes since `sweep_partial` first went `true` (0 if `sweep_partial == false`).
- `cache_sweeper.cache_sweep_blocked`: count of files blocked by `ERROR_SHARING_VIOLATION` for 7+ consecutive ticks (Windows only; always 0 on Unix).

**Schema enforcement:** the schema is validated by a checked-in validator at every baseline recording, and a CI step validates it on every PR touching this section.

**Touches:** `csq/src/cli/commands/doctor.rs`.

### 4.2.8 Audit sweep + drain (`daemon::audit_sweep`)

**Responsibility:** GC stale records under `~/.claude/accounts/csq-runs/` and drain any records csq-cli wrote to `~/.claude/accounts/csq-runs/.pending/` when the daemon was unreachable. Spec 12 governs the JSONL contract; this section governs the daemon-side cadence and contract.

**Cadence:**

1. **Drain — once per daemon start.** Runs as part of the startup reconciler (before any other request is served). Reads every `.pending/*.jsonl`, deserializes against the csq-runs JSON schema, applies via `audit::persist::write_record`, deletes the source on success. Records that fail deserialization are deleted with a structured `audit_drain_invalid` log tag (they are unrecoverable). Drain ordering is `start_ts` ascending — operator-perceptible sequencing across an outage.

2. **Sweep — every 24 hours.** Deletes (a) any file under `csq-runs/*.jsonl` with mtime > 30 days; (b) any file under `csq-runs/.pending/*.jsonl` with mtime > 30 days. The 30-day cutoff matches the audit-trail retention policy (spec 12).

**Wall-clock budget:**

- Drain: 5 seconds (audit dir is JSONL-tiny). If drain exceeds the budget, the daemon proceeds to serve requests with `.pending/` partially drained — every drained record is durable; non-drained records remain in `.pending/` and are picked up on the next start.
- Sweep: 5 seconds per tick. Cooperative yield every 100 files (cheaper than the cache sweeper's 10-dir yield because audit files are tiny JSONL).

**Per-deletion logging:** `INFO: audit-sweep: deleted <path> (reason: mtime_30d)` with structured `audit_sweep_deleted` tag. NOT WARN.

**Single-write-site invariant:** drain MUST call `audit::persist::write_record` (not `fs::write` directly), preserving the single-audited-write-site guarantee. Spec 12 § "Single audited write site" carries the rule; the static grep test under `csq-core/tests/audit_single_writer.rs` enforces it.

**Doctor surface coupling:** sweeper state surfaces via `csq doctor --json::audit_sweeper` block — same shape as `cache_sweeper` per §4.2.7 (last_sweep_at, last_sweep_duration_ms, files_swept_last_run). If a `.pending/` directory has files older than 24 hours that the most recent drain did NOT consume, top-level `status` surfaces `degraded`.

**Touches:** `csq-core/src/audit/{persist,sweep}.rs`. The drain entry-point lives in the startup reconciler (`csq-core/src/daemon/startup_reconciler.rs::pass5_audit_drain`, wired into `run_reconciler`).

### 4.2.9 Identity mint pass (`daemon::identity_mint`)

**Responsibility:** establish the shadow identity layer on first daemon start after upgrade. Idempotent via `accounts/store-version` sentinel.

**Cadence:** once per daemon start, as Pass 0 of the startup reconciler (`startup_reconciler.rs::run_reconciler`) — before the existing reconciler passes. After the sentinel is written, becomes a near-instant no-op on every subsequent start.

**Algorithm:**

1. **Sentinel check.** If `accounts/store-version` is present and parseable, return `MintSummary { already_minted: true, ... }` immediately — no reads, no writes.
2. **Discover slots.** Walk `accounts/config-N/` dirs via `accounts::discovery::discover_anthropic` (filters 3P-bound slots automatically — no manual 3P check needed). For each slot:
   a. Read email from `profiles.json::accounts[N].email` (the `AccountProfile.email` field written by `finalize_login` at login time). Absent or `"unknown"` value = skip slot with `SlotError`.
   b. If email matches an existing `profiles.json.by_email` entry, reuse that UUID (no churn on partial-mint retry).
   c. Otherwise, generate a new UUID v4 via `IdentityId::new_v4()`.
   d. **Write mapping FIRST:** Update `profiles.json.by_slot[N] = uuid` AND `profiles.json.by_email[email] = uuid` via `profiles::add_identity_mapping`. (Write-order invariant: mapping is durable before identity.json; a crash between d and e leaves a resolvable orphan — no UUID without a mapping.)
   e. If `identities/<UUID>/identity.json` already exists on disk, skip write (`AlreadyPresent` outcome) but still call `add_identity_mapping` to reconcile stale `by_slot` entries.
   f. Otherwise, write `identities/<UUID>/identity.json` with **immutable-side-only** content: `{email, provider: "anthropic", created_at: ISO-8601, key_id: null}`.
3. **Sentinel write.** After all slots are processed (including slots with 0 processed — the sentinel is written even when no config-N dirs exist), write `accounts/store-version`: `{"schema": 1, "minted_at": "<ISO-8601>", "source": "config-N-migration"}`. The sentinel write is LAST and is skipped if any slot produced a `SlotError` (partial-mint detection; re-run on next start). Idempotency guarantee: re-run after kill sees no sentinel → re-mints via step 2 reuse path without UUID churn.

**Identity-store credential write (canonical write site):** Every call to `save_canonical_for` in `csq-core/src/credentials/file.rs` writes `identities/<UUID>/credentials.json` as the canonical credential file. The daemon refresher path writes the identity-keyed file exclusively and is fail-closed: if no UUID mapping exists for the slot, the write returns a `NoCredentials` error rather than silently falling back. The initial login/binding paths additionally write the legacy `credentials/<N>.json` for backward-compatible existence detection.

**Codex canonical write:** Every call to `save_canonical_for` for a Codex variant writes `identities/<UUID>/credentials-codex.json`. The chokepoint is `save_codex_canonical_for_uuid` in `csq-core/src/credentials/file.rs` (parallel to `save_uuid_credentials` for Anthropic). See spec 07 §7.2.2 for the per-surface narrative. The `Surface::Gemini` arm of the same `match` is a no-op (Gemini has no canonical credential file; the key flows via `platform::secret::Vault`).

**Credential read path (identity-keyed):** `accounts::discovery::discover_anthropic` is a single-pass walk of `profiles.json::by_slot.iter()` — for each `(slot_str, uuid)`, it resolves `identities/<UUID>/credentials.json` and synthesizes the `AccountInfo`. Pure-legacy fallback (walk `credentials/<N>.json` once) fires only when `by_slot.is_empty()`. Production read sites that route through the identity-keyed path with legacy fallback:

1. `csq-core/src/accounts/discovery.rs:discover_anthropic` — discovery driver.
2. `csq-core/src/daemon/refresher.rs` — Anthropic refresher per-slot expiry read.
3. `csq-core/src/daemon/refresher.rs` — Codex refresher per-slot expiry read.
4. `csq-core/src/daemon/usage_poller/anthropic.rs` — Anthropic usage poller bearer token read.
5. `csq-core/src/daemon/usage_poller/codex.rs` — Codex usage poller bearer token read.
6. `csq-core/src/probe/mod.rs` — operator-run live-wire probe credential read.

Plus three desktop / CLI surface sites:

- `csq/src/desktop/mod.rs` — tray-status credential expiry read.
- `csq/src/desktop/commands/mod.rs` — IPC handler for accounts list (frontend dashboard).
- `csq/src/cli/commands/doctor.rs` — doctor reads (per-slot report, mixed-state check, expiry tally).

Every flipped site routes via `crate::accounts::profiles::resolve_slot_to_uuid(base, slot.get())` → `crate::accounts::identity_store::credentials_path_for(base, uuid)` or `credentials_codex_path_for(base, uuid)`; falls back to `cred_file::canonical_path[_for]` on `None`. **Slot-id channel:** every flipped site receives `slot` from per-slot poller state (channel (a)), an IPC handler validated at the daemon boundary (channel (b)), or an operation parameter from the caller (channel (c)). The UUID resolution does NOT introduce a new slot-id channel — it reads `by_slot[slot]` keyed on the slot-id already in hand. No terminal-derived slot-id ever enters the read path.

**File-existence checks NOT identity-keyed** (intentional): `csq/src/cli/commands/setkey.rs` (Anthropic / Codex binding existence refusal), `csq/src/cli/commands/swap.rs` and `csq/src/cli/commands/doctor.rs` (Gemini binding existence checks) — these test for the legacy canonical file's _presence_, not its _content_, to drive surface-binding refusal logic. The legacy canonical is written by credential-binding paths (e.g., the initial `csq login` exchange writes both the UUID-keyed file and the legacy `credentials/<N>.json` during the OAuth callback), so existence-checks remain semantically correct without the UUID resolution.

**Test surface:** `coexisting_fixture` and `legacy_only_fixture` (in `csq-core/src/testing/identity_fixtures.rs`) are the canonical fixtures for the two reader branches. Auto-rotate test helpers (`csq-core/src/daemon/auto_rotate.rs::setup_slot_uuid` and `csq-core/tests/auto_rotate_integration.rs::setup_slot_uuid`) seed `identities/<UUID>/credentials.json` mirroring the legacy creds — matching the production invariant that the identity-keyed file is always seeded.

**Credential write-order invariants:**

1. **Resolve UUID once.** `resolve_uuid_for_account(base, slot)` is called once at the top of the mutex-held section; the UUID is held through all writes (resolve-once).
2. **UUID-only canonical write (daemon refresher).** `save_canonical_for` writes `identities/<UUID>/credentials.json` only; the numeric `credentials/<N>.json` write is not performed on the refresh path. UUID absent is a fail-closed `NoCredentials` error. All read paths resolve the UUID-keyed path; the legacy fallback path covers pre-mint installs that have no `by_slot` entry. Only the initial login/binding paths retain a legacy write (for backward-compatible existence detection).
3. **Subscription-metadata guard at the canonical site.** `preserve_subscription_metadata(incoming, existing_uuid_path)` is applied to the UUID-keyed write — Anthropic's token endpoint does not return `subscription_type` or `rate_limit_tier`; the guard backfills from the existing `identities/<UUID>/credentials.json`. The Codex call site short-circuits (Codex carries no subscription metadata); structural parity is preserved so future Codex-shape preservation lands without re-plumbing.
4. **Atomic-write cleanup compliance.** `save_uuid_credentials` and `save_codex_canonical_for_uuid` in `credentials/file.rs` use the injectable `write_uuid_credentials_inner<W,S,R>` and `save_codex_canonical_for_uuid_inner<W,S,R>` shapes respectively, with tmp-file cleanup on every failure branch (write / secure_file / atomic_replace) so a secret-bearing temp file is never left readable on disk after a partial write.

**Codex/Gemini chokepoint divergence:** Codex and Gemini do NOT route through `finalize_login`. They have separate authentication flows that do not call the identity mint hook at login time. Codex/Gemini identities are minted only by the daemon Pass 0 walk (when their `config-N/` dirs appear on the next daemon start).

**Error semantics:** `IdentityMintError` at startup MUST NOT stop the daemon. The caller in `run_reconciler` wraps the call in a `match`, logs a `warn!` on `Err`, and continues. The daemon serves requests whether or not Pass 0 succeeded.

**Login hook (`mint_for_login`):** a separate public entry point called by `accounts::login::finalize_login` after a new `config-N/` is written. Does not check the sentinel (login can happen before the daemon starts). Takes `(base_dir, slot, email)` directly — no directory walk needed.

**Atomic-write cleanup compliance:** `write_identity_json` uses the full tmp-cleanup pattern on all three failure branches (write, secure_file, atomic_replace).

**Sentinel write path:** `unique_tmp_path → write → secure_file (best-effort, non-fatal on sentinel) → atomic_replace`. The sentinel payload is path-only (no OAuth tokens), so it is classified non-secret — `secure_file` failure is logged but does not block the rename.

**`ReconcileSummary` change:** `Copy` derive removed (the `identity_mint: Option<MintSummary>` field contains `Vec<SlotError>`, which is not `Copy`). Existing uses that relied on `Copy` must clone.

**Implementation surface (enumerate at audit time — do not trust a named list):** To find all files that implement or call the identity mint subsystem, run:

```bash
grep -rn 'identity_mint\|mint_for_login\|run_identity_mint\|store.version\|MintSummary\|IdentityMintError' \
  --include='*.rs' csq-core csq
```

Current known callsites (may drift with refactors): `csq-core/src/daemon/identity_mint.rs` (primary implementation), `csq-core/src/daemon/startup_reconciler.rs` (Pass 0 wiring + `ReconcileSummary` extension), `csq-core/src/accounts/login.rs` (`finalize_login` hook).

**Fail-closed gate — `phase4_gate_check`:**

The daemon supervisor (`csq/src/desktop/daemon_supervisor.rs`) and the standalone `csq daemon` CLI (`csq/src/cli/commands/daemon.rs`) BOTH invoke `phase4_gate_check(base_dir)` AFTER `run_reconciler` returns and BEFORE any subsystem (refresher, usage poller, IPC server) starts. The gate returns `Err(Phase4GateError)` when the on-disk store does not satisfy the identity-store layout contract; the caller propagates the error as `phase 4 gate refused start: {e}` and the daemon process exits. `Display` strings on every variant carry an operator-actionable next step (`csq login N`, `re-run with a writable accounts dir`) so the failure tells the operator exactly what to do.

The gate performs five sequential checks. Failure of any check short-circuits the gate; per-variant `Display` text names the failing slot (when applicable) and the remediation command.

| #   | Variant                                            | Trigger condition                                                                                                                                                                 | Remediation                                                                           |
| --- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| 1   | `StoreVersionUnset`                                | `accounts/store-version` sentinel absent (Pass 0 has not run, or sentinel was hand-deleted).                                                                                      | Let the reconciler complete a clean start; or `csq doctor --repair` to re-mint.       |
| 2   | `SchemaTooOld { schema, expected }`                | Sentinel present but `schema < STORE_VERSION_SCHEMA_CURRENT`. The Pass 0 bump should have promoted this — a gate-time `SchemaTooOld` means the bump failed.                       | Re-run with a writable accounts dir; fix any disk-full / permission-denied condition. |
| 3   | `IdentityCredentialsUnseeded { slot, uuid_short }` | A slot in `profiles.json::by_slot` has a UUID mapping but `identities/<UUID>/credentials.json` is missing.                                                                        | `csq login <slot>` to seed identity-keyed Anthropic credentials.                      |
| 4   | `SettingsUnseeded { slot, uuid_short }`            | A slot in `profiles.json::by_slot` has a UUID mapping but `identities/<UUID>/settings.json` is missing.                                                                           | `csq login <slot>` to seed per-account settings.                                      |
| 5   | `CodexCredentialsUnseeded { slot, uuid_short }`    | A Codex-bound slot (legacy `credentials/codex-<N>.json` exists on disk) has a UUID mapping in `profiles.json::by_slot` but `identities/<UUID>/credentials-codex.json` is missing. | `csq login <slot>` to seed identity-keyed Codex credentials.                          |

**Codex-binding detection (check 5).** `profiles.json` itself carries no per-surface binding map; the gate uses the same structural signal as `providers::gemini::provisioning::detect_other_surface_binding`: a slot is "Codex-bound" iff the legacy canonical `credentials/codex-<N>.json` exists on disk. Slots with no Codex binding fall through without check 5.

**Match exhaustiveness.** `Phase4GateError` is a closed enum with five variants and no `#[non_exhaustive]` attribute. The compiler refuses to compile any caller whose `match Phase4GateError { ... }` arm-set is incomplete; the current sole caller propagates the error via `format!("{e}")` (which routes through `thiserror`'s derived `Display` per variant), so a future variant addition forces both the spec update (this table) and the `Display` string update at the variant definition. No runtime catch-all arm hides additions.

**Implementation surface (enumerate at audit time — do not trust a named list):** To find every caller of the gate, run:

```bash
grep -rn 'phase4_gate_check\|Phase4GateError' --include='*.rs' csq-core csq
```

Current known callsites (may drift with refactors): `csq-core/src/daemon/startup_reconciler.rs` (gate body), `csq/src/desktop/daemon_supervisor.rs` (in-process daemon), `csq/src/cli/commands/daemon.rs` (standalone `csq daemon`).

**Concurrency model — `ProfilesFileLock`:**

`profiles.json` is written by two independent OS processes: the daemon's Pass 0 walk (`run_if_unsentineled`) and the CLI's `finalize_login` hook. Without serialization, both can perform `load → mutate → atomic_replace` concurrently, and whichever process calls `atomic_replace` last silently overwrites the other process's edits (classic lost-update race).

**Lock file:** `accounts/.profiles.lock` — a plain file used as an `flock(2)` (Unix) / `LockFileEx` (Windows) advisory lock. Readers do NOT acquire the lock — `atomic_replace` guarantees readers never observe a torn write.

**Lock primitive:** `crate::platform::lock::lock_file` (blocking exclusive flock). RAII guard `ProfilesFileLock` in `csq-core/src/accounts/profiles_lock.rs` — lock released on `Drop`.

**Re-entrancy contract:** `flock` is NOT re-entrant within the same OS process on Linux/macOS. To prevent re-acquisition deadlocks, the lock is acquired ONCE at the outermost call site and passed inward as a `&ProfilesFileLock` type-witness parameter. `profiles::add_identity_mapping` takes `_lock: &ProfilesFileLock` as its first argument — the compiler enforces "lock must be held" at every callsite statically. The `_lock` parameter is never read inside the function body; its presence is the proof.

**Lock scopes:**

| Caller                         | Lock acquired           | Lock dropped                       |
| ------------------------------ | ----------------------- | ---------------------------------- |
| `run_if_unsentineled` (Pass 0) | Before the slot loop    | Explicitly before `write_sentinel` |
| `finalize_login`               | Before `profiles::save` | After `mint_for_login` returns     |

**Why the lock is dropped before `write_sentinel`:** the sentinel write is an independent atomic operation that does not depend on `profiles.json` contents. Releasing the lock before the sentinel write minimizes hold time; any sentinel write failure leaves the daemon able to retry Pass 0 on the next start via the sentinel-absent path.

**Security classification:** `.profiles.lock` holds no credential content and is classified non-secret. `secure_file` is applied best-effort AFTER `lock_file` creates the file; on a fresh install the file does not exist until `lock_file` creates it, so calling `secure_file` first would be a silent no-op. Failure to set 0o600 does not block lock acquisition (non-fatal on FAT/network mounts).

### 4.2.10 Audit chain verification

**Responsibility:** verify the local hash-chained audit ledger BEFORE binding the IPC socket.

**Insertion point in startup sequence:** the verification call is inserted AFTER `phase4_gate_check` returns `Ok` AND AFTER `run_reconciler` completes, and BEFORE `daemon::serve()` (the `UnixListener::bind` call). Implementation: `csq/src/cli/commands/daemon.rs` (verify) before (bind).

**Invariant:** a csq CLI client MUST NOT be able to connect to a daemon that has not yet verified its chain. Binding before verification creates a window where CLI calls are accepted against a daemon that subsequently exits with a broken-chain error — those calls produce orphaned pending records with no daemon to drain them. Pre-bind placement closes this window.

**Algorithm:**

1. Read `record_limit` from `CSQ_AUDIT_VERIFY_LIMIT` env var (CLI: `--audit-verify-limit N`; default: 10,000).
2. Read `timeout_secs` from `CSQ_AUDIT_VERIFY_TIMEOUT_SECS` env var (default: 5).
3. Call `audit::verify_chain(base_dir, &config, None)` inside `tokio::task::spawn_blocking` wrapped in `tokio::time::timeout(timeout_secs)`.
4. On **timeout**: log `audit_verify_slow` at WARN and continue (slow verification is not an integrity failure).
5. On **clean verification** (`Ok(_summary)`): proceed to `daemon::serve()`.
6. On **`LedgerError::ChainBroken { seq, .. }`**: log `audit_chain_integrity_failure` at ERROR, emit stderr message, exit non-zero.
7. On **`LedgerError::InvalidSignature { record_id, key_id }`**: same — log + stderr + non-zero exit.
8. On **`LedgerError::KeyNotFound { key_id }`**: log `audit_verify_key_not_found` at ERROR + stderr remediation message naming the missing `key_id` + non-zero exit. Remediation: "the signing key `<key_id>` is no longer in your keychain; if you rotated keys, the outgoing key must be retained — see `csq audit key-history`".
9. On records beyond `record_limit`: emit `audit_verify_limit_exceeded` at WARN (once per over-limit record) and continue.

**Legacy record handling:** records whose JSON contains `"schema_version":"1"` are not `SignedRecord` instances; they are skipped with a single summary log `audit_verify_skipped_v1_records_total: N` (NOT one log per record).

**Sentinel decision:** there is no persistent sentinel file for chain-broken state. `verify_chain` runs on every daemon start and causes a non-zero exit on failure, so no setter/clearer pair is needed.

**`csq audit verify` CLI counterpart:** operators can run `csq audit verify [--full] [--since <ts>] [--json]` independently. Exit codes: 0 clean / 1 integrity failure / 2 partial (key not found). `--json` returns `{status, verified_count, skipped_v1_count, failure_detail?}`.

**Implementation surface:** `csq-core/src/audit/verify.rs` (verify_chain), `csq/src/cli/commands/daemon.rs` (pre-bind wiring), `csq/src/cli/commands/audit.rs` (handle_verify).

**Audit primitive:**

```bash
grep -n 'verify_chain\|daemon::serve\|UnixListener::bind' \
  csq/src/cli/commands/daemon.rs 2>/dev/null | sort -t: -k2 -n
# Expected: verify_chain line number < daemon::serve line number
```

## 4.3 Supervisor

The supervisor loop `csq_core::daemon::supervise::run_forever` (shared by all three § 4.1 hosts) handles:

- **Detect → acquire → run → backoff.** Each iteration detects the current daemon (`detect_daemon`), defers to a healthy/unhealthy external daemon, cleans up a stale one, then acquires the PidFile lock and runs ONE session (`run_session`) until cancellation.
- **Exponential backoff (1s → 60s).** Resets to 1s after a CLEAN session exit (ran, then cancelled); grows on a fast session failure (e.g. a socket-bind error) so a persistent failure is a slow poll, not a hot loop. `run_session` returns `Err(String)` on a startup failure; `Ok(())` on a cancellation-driven clean stop.
- **Two-layer restart.** launchd `KeepAlive={SuccessfulExit:false}` is the OUTER layer — it respawns the whole process on a hard crash (non-zero exit), and leaves a clean `csq daemon stop` (SIGTERM → drain → exit 0) stopped. The in-process `run_forever` backoff is the INNER layer — it restarts a session that fails at startup without a full process respawn.
- **Subsystem-death detection (session-boundary restart).** Each session body collects its long-lived subsystems (refresher, usage poller, auto-rotator, sweeps, ledger writer, log GC) into a uniform set and blocks on `supervise::await_session_stop(&cancel, &mut subsystems)`, which races `cancel` against the first subsystem exit. A subsystem that panics or returns early while the session is still meant to be running resolves as `SessionStop::SubsystemExited(name)`: the session cancels a CHILD shutdown token to drain the siblings (WITHOUT firing the supervisor's `cancel`, so this is a restart not a stop), then returns `Err(String)` → `run_forever` restarts the session with backoff. A graceful `cancel` resolves as `SessionStop::Cancelled` → clean drain, `Ok(())`. The restart is at the SESSION boundary (the whole session is re-run), not an in-place per-subsystem respawn; the subsystems' shutdown token is a `cancel.child_token()`. Shared helper `csq_core::daemon::supervise::{Subsystem, SessionStop, await_session_stop, drain_subsystems}`. The IPC server (`server_join`) is ALSO a monitored member (an internal ticket): a panicked accept loop resolves as `SessionStop::SubsystemExited("ipc_server")` → restart, so a dead IPC socket is no longer invisible until graceful shutdown. It exits on its own `server.shutdown()` token (fired before `drain_subsystems`), so its handle completes inside the single drain loop — no separate drain that would double-poll it.
- **Cohabitation.** The desktop in-process supervisor and the managed launchd daemon both drive `run_forever`; the PidFile lock guarantees exactly one owns the daemon, the other observes and takes over on the owner's exit.
- **Twin parity (INVARIANT).** The two session bodies — `csq/src/cli/commands/daemon.rs::run_daemon_session` and `csq/src/desktop/daemon_supervisor.rs::run_daemon` — MUST supervise the IDENTICAL set of subsystems. They are mutually exclusive at runtime (one PidFile, one socket), so a subsystem wired into only one twin does NOT get covered by the other: it simply never runs for whichever launch mode omits it, with no error, no log line, and no failing test. Enforced fail-closed in CI by `scripts/check-daemon-twin-parity.py`, which compares the two `Vec<daemon::supervise::Subsystem>` label sets; a genuinely one-sided subsystem must be declared in that script's `INTENTIONAL_DIFFERENCES` map with a comment naming the structural reason.

## 4.4 Shutdown

On receipt of SIGTERM (standalone) or desktop app quit (embedded) — the `SessionStop::Cancelled` path:

1. Supervisor signals `CancellationToken` to every subsystem (the child shutdown token cancels when the supervisor's `cancel` fires).
2. Each subsystem drains in-flight work (refresh, poll, sweep) with a 5-second per-handle deadline (`supervise::drain_subsystems`).
3. Supervisor releases the PidFile and unbinds the Unix socket.
4. Process exits.

On a mid-session subsystem exit (the `SessionStop::SubsystemExited` path, § 4.3) the same drain runs — the session cancels the child shutdown token, drains the surviving subsystems and the server, then returns `Err` so `run_forever` restarts the session with backoff instead of exiting.

## 4.5 Cross-references

- `specs/01-cc-credential-architecture.md` — CC's `saveOAuthTokensIfNeeded` write path; the daemon refresher mirrors its subscription-preservation behavior.
- `specs/02-csq-handle-dir-model.md` — handle dir sweep invariants.
- `specs/05-quota-polling-contracts.md` — usage poller endpoint contracts.
- `specs/07-codex-auth.md` — per-surface credential write narrative (Codex).
- `specs/12-audit-trail.md` — full prose contract for `POST /api/audit/record` + §4.2.8 sweep / drain semantics; retention policy; the hash-chained ledger format verified in §4.2.10.

## Revisions

Spec version 1.14.0. This document describes the daemon as it ships in the current community edition.

- 2026-07-25 — 1.14.0 — Daemon-twin parity: §4.3 NEW "Twin parity (INVARIANT)" bullet — the CLI and desktop session bodies MUST supervise the identical subsystem set, enforced fail-closed in CI by `scripts/check-daemon-twin-parity.py`. Fixed in code: `coc_cache_sweeper` (§4.2.6) was supervised by the CLI twin only, so a user whose sole daemon host is the desktop app GC'd zero parse caches and `csq doctor --json::cache_sweeper` reported `never_run` indefinitely — §4.2.6 describes no such carve-out. The desktop twin also resolved `claude_home` without honoring the `$CLAUDE_HOME` override the CLI twin honors, pointing the auto-rotator / handle-dir sweep / usage-ledger writer at the wrong tree for operators who set it.
- 2026-07-25 — 1.13.0 — IPC server (`server_join`) added to the subsystem death-watch (an internal ticket): a panicked accept loop → `SessionStop::SubsystemExited("ipc_server")` → session restart, instead of a dead IPC socket lingering invisibly until graceful shutdown. Separate `server_join` drain removed (would double-poll; `server.shutdown()` fires before the single `drain_subsystems`). §4.3 updated.
- 2026-07-25 — 1.12.0 — Subsystem-death detection (session-boundary restart): §4.3 NEW bullet + §4.4 `SessionStop::SubsystemExited` drain path. Each session now blocks on `supervise::await_session_stop` and restarts the session when a subsystem panics/exits mid-session, instead of leaving a dead refresher invisible until the next full restart. Shared helper `csq_core::daemon::supervise::{Subsystem, SessionStop, await_session_stop, drain_subsystems}` (community-shipped).
