//! Background token refresher.
//!
//! Runs as a tokio task alongside the daemon IPC server. Every
//! [`REFRESH_INTERVAL`] the refresher discovers all Anthropic
//! accounts, decides which ones need a token refresh (expiring
//! within the 2-hour window from ADR-006), and invokes
//! `broker::check::broker_check` for each one. Results are cached
//! so the HTTP API routes (M8.5) can return current state without
//! re-running the check.
//!
//! # Concurrency model
//!
//! One refresher task per daemon. Refreshes happen sequentially
//! inside that task — no per-account parallelism — because:
//!
//! 1. `broker_check` already coordinates across processes via a
//!    per-account file lock (`refresh-lock` next to the canonical
//!    credentials). Multiple daemons racing the same account are
//!    already handled.
//! 2. Anthropic's OAuth endpoint does not benefit from parallel
//!    refreshes for a single user's accounts — if anything, it
//!    prefers steady traffic.
//! 3. The 5-minute interval provides more than enough headroom to
//!    refresh 10+ accounts sequentially even on slow networks.
//!
//! # Cooldown & backoff
//!
//! Any account that fails a refresh enters a 10-minute cooldown.
//! Rate-limited accounts (429 / `rate_limit_error`) use
//! exponential backoff: 10min × 2^n, capped at 80min. This
//! prevents the self-reinforcing cycle where N expired accounts
//! all retry simultaneously after a fixed cooldown, re-trigger
//! the rate limit, and repeat forever.
//!
//! Additionally, when any account hits a rate limit within a tick,
//! the remaining accounts are skipped to avoid amplifying the
//! throttled condition.
//!
//! Subsequent ticks skip cooldown accounts to avoid hammering
//! Anthropic when an account is in a bad state (invalid RT, 500
//! loop, etc.). The cooldown is wall-clock-based and stored **in
//! memory only** — on daemon restart, all accounts get a fresh
//! chance. This is acceptable under the same-user threat model
//! because any attacker who can restart the daemon can already
//! access the credential files directly; cooldown persistence
//! would not protect against a local attacker.
//!
//! # Fanout limits
//!
//! Each tick processes at most [`MAX_ACCOUNTS_PER_TICK`] accounts
//! to bound the HTTP fanout. An attacker who writes files into
//! `base_dir/credentials/` (already a same-user threat) could
//! otherwise create thousands of phantom accounts and force the
//! refresher into a refresh storm that Anthropic may interpret
//! as abuse. 64/tick is well above any legitimate multi-account
//! rotation use case.
//!
//! # Testing
//!
//! The refresher takes an injected `http_post` closure (same
//! contract as `broker::check::broker_check`), so tests can drive
//! the refresh logic without real network calls. The injection
//! propagates all the way through `broker_check` → `refresh_token`.

use super::cache::TtlCache;
use crate::accounts::discovery;
use crate::accounts::AccountSource;
use crate::credentials::{self, file as cred_file};
use crate::http::codex as http_codex;
use crate::providers::catalog::Surface;
use crate::refresh::check::{broker_check, broker_codex_check, BrokerResult};
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default interval between refresher ticks: 5 minutes.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

/// Base cooldown after a failed refresh: 10 minutes.
pub const FAILURE_COOLDOWN: Duration = Duration::from_secs(600);

/// Maximum backoff multiplier for rate-limited accounts.
/// 8 × 10min = 80min — long enough to let Anthropic's IP-level
/// rate limit clear without the daemon re-triggering it.
const MAX_BACKOFF: u32 = 8;

/// Short initial delay before the first tick so the daemon has
/// time to finish starting up (bind sockets, initialize subsystems)
/// before we start making HTTP calls.
pub const STARTUP_DELAY: Duration = Duration::from_secs(3);

/// Sub-sleep granularity while waiting for the next refresh tick.
///
/// A plain `tokio::time::sleep(REFRESH_INTERVAL)` uses a monotonic timer
/// that pauses while the host is asleep (notably macOS), but OAuth tokens
/// keep aging on the wall clock. After a long laptop sleep the monotonic
/// wait can leave a token past its 2h refresh window — and even expired —
/// for up to a full `REFRESH_INTERVAL` after wake before the loop ticks.
///
/// The loop instead sub-sleeps in `WAKE_PROBE_INTERVAL` chunks, breaking on
/// whichever fires first: a monotonic floor (`Instant::elapsed() >= interval`,
/// immune to wall-clock changes — preserves the old `sleep(interval)` behavior
/// for the normal and backward-clock-jump cases) or a wall-clock (`SystemTime`)
/// deadline (see `next_wait_chunk`, which the monotonic clock pause hides, so
/// it is the channel that catches host sleep/wake). After the host wakes, the
/// wall clock has jumped past the deadline, so the next tick fires within one
/// probe granularity (≤30s) instead of ≤5 minutes. Smaller = faster post-wake
/// catch-up but more idle wakeups; 30s balances both. Origin: an internal journal entry Q2.
pub const WAKE_PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// Compute the next sub-sleep chunk while waiting for the refresh `deadline`,
/// or `None` when the deadline has been reached and the loop should tick now.
///
/// Pure + wall-clock-based so the post-wake path is unit-testable without
/// actually sleeping the host: when `now` has jumped past `deadline` (the
/// host woke from sleep and the wall clock advanced), this returns `None`
/// and the caller ticks immediately rather than waiting out a full monotonic
/// interval. Otherwise it returns the shorter of `probe` and the remaining
/// time, so the wait never overshoots the deadline. Origin: an internal journal entry Q2.
fn next_wait_chunk(
    now: std::time::SystemTime,
    deadline: std::time::SystemTime,
    probe: Duration,
) -> Option<Duration> {
    match deadline.duration_since(now) {
        Ok(remaining) if !remaining.is_zero() => {
            let chunk = remaining.min(probe);
            // A zero `probe` would otherwise yield `Some(0)` → busy-spin. The
            // production caller never passes a zero probe, but keep the fn
            // safe in isolation since it is unit-tested standalone.
            (!chunk.is_zero()).then_some(chunk)
        }
        // now >= deadline → tick now. Two sub-cases both collapse here: now ==
        // deadline yields `Ok(Duration::ZERO)` (rejected by the `!is_zero()`
        // guard above), and now > deadline (e.g. the wall clock jumped past it
        // on wake) yields `Err`. Both mean the deadline is in the past.
        _ => None,
    }
}

/// Decide the next sub-sleep chunk for the inter-tick wait, or `None` when the
/// loop should tick now. Folds the two break channels into one pure, testable
/// unit so the floor-precedence is verified directly (not only via `run_loop`):
///
/// - **Monotonic floor** (`elapsed >= interval`): the old `sleep(interval)`
///   semantics — immune to wall-clock steps, so a backward NTP/manual set never
///   delays a tick past the interval. Checked FIRST.
/// - **Wall-clock deadline** (`next_wait_chunk`): the monotonic clock pauses
///   while the host sleeps, so this channel catches sleep/wake — after wake the
///   wall clock has jumped past `deadline` and this returns `None`.
///
/// Origin: an internal journal entry Q2.
fn wait_chunk_or_done(
    elapsed: Duration,
    interval: Duration,
    now: std::time::SystemTime,
    deadline: std::time::SystemTime,
    probe: Duration,
) -> Option<Duration> {
    if elapsed >= interval {
        return None;
    }
    next_wait_chunk(now, deadline, probe)
}

/// Maximum accounts processed per tick. Bounds HTTP fanout against
/// a same-user attacker who writes phantom credential files into
/// `base_dir/credentials/` to trigger a refresh storm.
///
/// Legitimate multi-account use cases are well under 20; 64 is a
/// comfortable ceiling that still fits within a single 5-minute
/// tick on any realistic network.
pub const MAX_ACCOUNTS_PER_TICK: usize = 64;

/// Per-account refresh status captured in the cache. Exposed via
/// the M8.5 HTTP API (read path only — the refresher owns writes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshStatus {
    /// Account number.
    pub account: u16,
    /// Last outcome classified into a small set of strings.
    /// Not an enum so the serialized form stays stable across
    /// refactors — `broker_check` results are lossy-mapped here.
    pub last_result: String,
    /// Token `expiresAt` (Unix millis) at the time of the last
    /// check. Useful for the dashboard to render "next refresh at".
    pub expires_at_ms: u64,
    /// Wall-clock seconds since epoch when the last check completed.
    /// Fractional seconds are truncated.
    pub checked_at_secs: u64,
}

impl RefreshStatus {
    fn from_result(account: AccountNum, expires_at_ms: u64, result: &BrokerResult) -> Self {
        let label = match result {
            BrokerResult::Valid => "valid",
            BrokerResult::Refreshed => "refreshed",
            BrokerResult::Skipped => "skipped",
            BrokerResult::RateLimited => "rate_limited",
            BrokerResult::Failed(_) => "failed",
        };
        Self {
            account: account.get(),
            last_result: label.to_string(),
            expires_at_ms,
            checked_at_secs: now_secs(),
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// HTTP transport closure matching `broker_check`'s `http_post`
/// contract. Defined as a `dyn` trait object so the refresher can
/// be constructed with either the real `csq_core::http::post_form`
/// or a test mock.
pub type HttpPostFn = Arc<dyn Fn(&str, &str) -> Result<Vec<u8>, String> + Send + Sync + 'static>;

/// Date-aware sibling of [`HttpPostFn`] used by the Codex refresh
/// path. Returns `(body, Option<Date header>)` — the Date header
/// drives spec 07 §7.5 INV-P01 clock-skew detection.
pub type HttpPostFnCodex = Arc<
    dyn Fn(&str, &str) -> Result<crate::http::NodeHttpResponse, String> + Send + Sync + 'static,
>;

/// Handle to a running refresher task. Drop does NOT cancel —
/// callers must explicitly cancel the `CancellationToken` passed
/// into [`spawn`] and await the `JoinHandle`.
///
/// The `cache` Arc is the same one passed into `spawn`; returned
/// here as a convenience so tests can read it without threading an
/// extra reference.
pub struct RefresherHandle {
    pub join: tokio::task::JoinHandle<()>,
    pub cache: Arc<TtlCache<u16, RefreshStatus>>,
}

/// Spawns the refresher task on the current tokio runtime.
///
/// # Arguments
///
/// - `base_dir` — csq state directory (`~/.claude/accounts` by default).
/// - `cache` — shared refresh-status cache. Owned by the daemon-
///   start function so other subsystems (HTTP route handlers) can
///   read from the same cache via their own Arc clone.
/// - `http_post` — transport closure. Production callers pass
///   `Arc::new(|u, b| csq_core::http::post_form(u, b))`. Tests pass
///   a mock that returns canned responses.
/// - `shutdown` — shared cancellation token. The task exits as soon
///   as the token is cancelled, regardless of where it is in the
///   refresh cycle.
pub fn spawn(
    base_dir: PathBuf,
    cache: Arc<TtlCache<u16, RefreshStatus>>,
    http_post: HttpPostFn,
    http_post_codex: HttpPostFnCodex,
    shutdown: CancellationToken,
) -> RefresherHandle {
    spawn_with_config(
        base_dir,
        cache,
        http_post,
        http_post_codex,
        shutdown,
        REFRESH_INTERVAL,
        STARTUP_DELAY,
    )
}

/// Like [`spawn`] but with explicit interval + startup delay for
/// testing. Tests pass shorter durations to avoid sleeping the
/// full 5 minutes.
pub fn spawn_with_config(
    base_dir: PathBuf,
    cache: Arc<TtlCache<u16, RefreshStatus>>,
    http_post: HttpPostFn,
    http_post_codex: HttpPostFnCodex,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
) -> RefresherHandle {
    let cache_for_task = Arc::clone(&cache);
    let cooldowns: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let backoffs: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new()));

    let join = tokio::spawn(async move {
        run_loop(
            base_dir,
            http_post,
            http_post_codex,
            cache_for_task,
            cooldowns,
            backoffs,
            shutdown,
            interval,
            startup_delay,
        )
        .await;
    });

    RefresherHandle { join, cache }
}

#[allow(clippy::too_many_arguments)]
async fn run_loop(
    base_dir: PathBuf,
    http_post: HttpPostFn,
    http_post_codex: HttpPostFnCodex,
    cache: Arc<TtlCache<u16, RefreshStatus>>,
    cooldowns: Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: Arc<Mutex<HashMap<u16, u32>>>,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
) {
    info!(interval_secs = interval.as_secs(), "refresher starting");

    // Startup delay gives the daemon time to finish binding
    // sockets before the first HTTP call. Still respects
    // cancellation.
    tokio::select! {
        _ = shutdown.cancelled() => {
            info!("refresher cancelled during startup delay");
            return;
        }
        _ = tokio::time::sleep(startup_delay) => {}
    }

    loop {
        // Run one tick, isolated in its own task (round 9, S-C-1 / D-F1): a
        // bug anywhere on the tick's call graph (the `harvest_gate`
        // `blocking_lock`-on-a-worker panic fixed alongside this change is
        // one instance, but not the only possible one) must never again be
        // able to silently and PERMANENTLY kill this `run_loop` task.
        //
        // `keychain-fix-r10.md` C-B3: `run_loop`'s task IS observed and
        // restarted in production — `daemon.rs`'s and `daemon_supervisor.rs`'s
        // `subsystems` lists register `refresher.join` as a supervised member,
        // and ANY return from it (clean exit or an unwound panic) restarts
        // the WHOLE daemon session (every subsystem, not just this one).
        // `run_tick_supervised`'s per-tick isolation is what makes that outer
        // restart a rare last resort rather than the routine response to one
        // bad tick: a session-wide restart drops in-flight IPC connections,
        // resets every OTHER subsystem's warm state, and costs the daemon's
        // full startup sequence — the task boundary here is CHEAPER, logging
        // the JoinError and continuing to the next scheduled tick instead of
        // paying for that.
        run_tick_supervised(
            base_dir.clone(),
            Arc::clone(&http_post),
            Arc::clone(&http_post_codex),
            Arc::clone(&cache),
            Arc::clone(&cooldowns),
            Arc::clone(&backoffs),
        )
        .await;

        // M20 (F-SEAM-09): sweep timed-out held provenance events. The seam's
        // intra-source counter-gap hold links a held event past an unfilled gap
        // once its wait exceeds PREDECESSOR_WAIT_SECS (300s). This is the
        // sink-INDEPENDENT daemon tick that delivers that bounded timeout — the
        // refresher always runs (unlike the sink-gated anchor task) and its
        // 300s cadence matches the wait bound. Synchronous chain I/O →
        // spawn_blocking so it never stalls the async runtime. Until M18-bind
        // registers a decoder the held store is never populated, so this is a
        // cheap no-op in production today.
        let sweep_base = base_dir.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || run_held_sweep_tick(&sweep_base)).await
        {
            // A panic in the blocking sweep task surfaces as a JoinError. Log it
            // (it does not kill the refresher loop) so a real outbox-drain
            // incident is debuggable rather than silently swallowed.
            //
            // `keychain-fix-r11.md` D-3: JoinError's Display can carry the
            // panic's own message (tokio's impl), and this task's call graph
            // is credential-adjacent — fixed tag + `is_panic` only, never
            // the raw Display.
            tracing::warn!(
                error_kind = "seam_held_sweep_task_panicked",
                panicked = e.is_panic(),
                "held-provenance sweep task panicked"
            );
        }

        // M6 an internal ticket shard B: periodic backstop drain of both durable audit outboxes
        // onto the signed chain. Rides the same 5-min refresher cadence as the
        // held-sweep above; synchronous chain I/O → spawn_blocking so it never
        // stalls the runtime. A panic surfaces as a JoinError and is logged
        // without killing the loop (same posture as the held-sweep).
        let drain_base = base_dir.clone();
        if let Err(e) =
            tokio::task::spawn_blocking(move || run_outbox_drain_tick(&drain_base)).await
        {
            tracing::warn!(
                error_kind = "outbox_periodic_drain_task_panicked",
                error = %e,
                "periodic outbox drain task panicked"
            );
        }

        // Wait for the next interval or cancellation. Two break channels so a
        // host sleep/wake doesn't strand aged tokens for a full interval while
        // a wall-clock step never delays a tick past the monotonic interval:
        //   - monotonic floor: `started.elapsed() >= interval` — the old
        //     `sleep(interval)` semantics; immune to wall-clock steps (incl.
        //     backward NTP/manual sets) but blind to host sleep (clock pauses).
        //   - wall-clock deadline: `next_wait_chunk` — catches host sleep/wake
        //     (wall clock jumps past the deadline while the monotonic clock was
        //     paused), so the loop ticks within one probe granularity of wake.
        // Origin: an internal journal entry Q2.
        let started = Instant::now();
        let deadline = std::time::SystemTime::now() + interval;
        let probe = WAKE_PROBE_INTERVAL.min(interval);
        while let Some(chunk) = wait_chunk_or_done(
            started.elapsed(),
            interval,
            std::time::SystemTime::now(),
            deadline,
            probe,
        ) {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("refresher cancelled, exiting loop");
                    return;
                }
                _ = tokio::time::sleep(chunk) => {}
            }
        }
    }
}

/// Runs one [`tick`] inside its own `tokio::spawn`'d task and awaits it,
/// converting a panic anywhere on the tick's call graph into a `JoinError`
/// instead of unwinding into `run_loop`'s own task.
///
/// `keychain-fix-r10.md` C-B3: `run_loop`'s task IS observed in production —
/// `daemon.rs`'s and `daemon_supervisor.rs`'s `subsystems` lists both watch
/// `RefresherHandle::join` and restart the WHOLE daemon session on any
/// unwound panic reaching it — but that outer restart is a session-wide,
/// every-subsystem, full-startup-sequence remedy. Before THIS wrapper
/// existed, a single panicking call — the
/// `harvest_gate::mark_rate_limited_from_refresher` `blocking_lock`-on-a-worker
/// bug (round 9, S-C-1 / D-F1) was one, but not the only possible one —
/// would have unwound past `run_loop` and forced exactly that expensive
/// outer restart for what is, per-tick, a fully recoverable fault. This
/// wrapper is the CHEAPER remedy: isolate the one bad tick, log it, and
/// keep every other subsystem's warm state and every live IPC connection
/// intact.
///
/// `base_dir` is taken by value (cheap `PathBuf` clone) and the remaining
/// arguments by `Arc` clone so the spawned task can be `'static`; `tick`
/// itself still takes references, borrowed from the clones inside the
/// spawned future.
#[allow(clippy::too_many_arguments)]
async fn run_tick_supervised(
    base_dir: PathBuf,
    http_post: HttpPostFn,
    http_post_codex: HttpPostFnCodex,
    cache: Arc<TtlCache<u16, RefreshStatus>>,
    cooldowns: Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: Arc<Mutex<HashMap<u16, u32>>>,
) {
    // Kept for the panic-recovery sweep below — `base_dir` itself is moved
    // into the spawned task.
    let base_dir_for_panic_sync = base_dir.clone();

    let result = tokio::spawn(async move {
        tick(
            &base_dir,
            &http_post,
            &http_post_codex,
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;
    })
    .await;

    if let Err(join_err) = result {
        // `keychain-fix-r10.md` S-L-2: a `JoinError` for a panic can carry the
        // panic's own message (tokio's `Display` includes it when the panic
        // payload downcasts to `String`/`&str`) — NOT opaque, so redact
        // before logging, same as every other error path in this tick's call
        // graph that touches credential material.
        tracing::error!(
            error_kind = "refresher_tick_panicked",
            panicked = join_err.is_panic(),
            error = %crate::error::redact_tokens(&join_err.to_string()),
            "refresher tick panicked; refresher loop survives and will retry at the next interval"
        );

        // `keychain-fix-r10.md` C-I1: a tick that panicked mid-way may have
        // already refreshed and written one or more accounts' tokens to
        // disk BEFORE the panic — `tick_impl`'s own post-loop keychain
        // sweep (`sync_refreshed_keychains`, gated on `any_anthropic_refreshed`)
        // never ran for THIS tick, since the panic unwound before reaching
        // it. Without this, CC would keep reading the PRE-rotation token
        // from its keychain-first read (spec 01 §1.4) until the NEXT tick
        // happens to refresh the same account again. An empty `refreshed`
        // map means "no fingerprint hints" — `sync_all_handle_dirs` sweeps
        // EVERY live handle dir unconditionally rather than only ones this
        // (aborted) tick knows it touched, since we cannot know which
        // account(s) got as far as their disk write before the panic.
        if let Err(sync_join_err) = tokio::task::spawn_blocking(move || {
            sync_refreshed_keychains(&base_dir_for_panic_sync, &std::collections::HashMap::new());
        })
        .await
        {
            tracing::warn!(
                error_kind = "post_panic_keychain_sync_task_panicked",
                panicked = sync_join_err.is_panic(),
                "post-panic keychain sync task itself panicked (non-fatal)"
            );
        }
    }
}

/// M6 an internal ticket shard B: periodic backstop drain of BOTH durable audit outboxes.
///
/// Runs on every refresher tick (the daemon's existing periodic cadence). Drains
/// the `csq run` audit floor (`csq-runs/.pending/`, community) and — enterprise
/// only — the MCP-gate outbox (`csq-runs/.pending-mcp-gate/`) onto the signed
/// chain, then stamps the drain-cycle time. This backstop bounds the worst-case
/// "queued compliance record not yet on chain" latency to ONE refresher interval
/// instead of "until the next daemon restart" (days, for a long-lived daemon) — it
/// covers every recovery scenario, including the daemon-stays-up signing-cutoff
/// recovery that the startup drain never re-fires for. Startup drain + the
/// event-driven live-path-recovery drain are the other two stamp sites.
///
/// Concurrency: unlike the startup reconciler (which runs before socket bind), this
/// runs while live `POST /api/audit/*` handlers may emit. That is safe — every
/// chain append (drain-side and live-side) is serialized by the `.chain-lock`, the
/// drains leave any lock-contended record queued for an idempotent retry next tick,
/// and each drain snapshots its outbox dir before processing so a concurrently
/// written file is simply picked up next tick. Synchronous chain I/O → invoked via
/// `spawn_blocking` from the async loop so it never stalls the runtime. Best-effort:
/// nothing here ever propagates or panics into the refresher loop.
pub(crate) fn run_outbox_drain_tick(base_dir: &std::path::Path) {
    // Nothing can be queued without the chain dir; skip cleanly (this also avoids
    // a spurious stamp-write warn on a base that has no audit subsystem at all).
    if !base_dir.join("csq-runs").exists() {
        return;
    }

    let run_floor = crate::daemon::startup_reconciler::drain_run_floor(base_dir);
    if run_floor.drained > 0 || run_floor.invalid > 0 || run_floor.unknown_version > 0 {
        info!(
            error_kind = "outbox_periodic_drain_run_floor",
            drained = run_floor.drained,
            invalid = run_floor.invalid,
            unknown_version = run_floor.unknown_version,
            "periodic backstop drained csq-run audit floor"
        );
    }

    #[cfg(feature = "enterprise")]
    {
        let mcp = crate::audit::mcp_gate_outbox::drain_pending(base_dir);
        // Surface the actionable subset in the tick summary too: `write_failed_terminal`
        // is the operator-actionable non-self-healing backlog, and a deferred drain
        // (broken/uninit chain) leaves EVERY queued record unprocessed — the exact
        // scenario that most warrants a per-tick count. (`drain_pending` also emits its
        // own deferred signal; this adds the structured count the operator triages on.)
        if mcp.drained > 0
            || mcp.invalid > 0
            || mcp.write_failed > 0
            || mcp.deferred_chain_unavailable
        {
            info!(
                error_kind = "outbox_periodic_drain_mcp_gate",
                drained = mcp.drained,
                invalid = mcp.invalid,
                write_failed = mcp.write_failed,
                write_failed_terminal = mcp.write_failed_terminal,
                deferred_chain_unavailable = mcp.deferred_chain_unavailable,
                deferred_pending_count = mcp.deferred_pending_count,
                "periodic backstop drained mcp-gate outbox"
            );
        }
    }

    if let Err(e) = crate::audit::outbox_paths::stamp_outbox_drain(base_dir) {
        tracing::warn!(
            error_kind = "outbox_drain_stamp_failed",
            "periodic outbox drain-stamp write failed: {e}"
        );
    }
}

/// M20 (F-SEAM-09): run one held-provenance sweep tick. Links any held event
/// whose intra-source-predecessor wait has exceeded `PREDECESSOR_WAIT_SECS` past
/// the gap with a `predecessor_missing` annotation. Extracted from `run_loop` so
/// the wiring is unit-testable (a direct `sweep_timed_out` call proves the
/// function works; this proves the daemon tick calls it). Synchronous — invoked
/// via `spawn_blocking` from the async loop.
pub(crate) fn run_held_sweep_tick(base_dir: &std::path::Path) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    match crate::audit::seam::sweep_timed_out(base_dir, now) {
        Ok(n) if n > 0 => info!(
            error_kind = "seam_held_sweep_linked",
            linked = n,
            "swept timed-out held provenance events"
        ),
        Ok(_) => {}
        Err(_) => tracing::warn!(
            error_kind = "seam_held_sweep_failed",
            "held-provenance sweep tick failed"
        ),
    }
}

/// After a tick refreshed at least one Anthropic credential, mirror the fresh
/// tokens into the macOS keychain items Claude Code reads.
///
/// Current CC reads OAuth credentials keychain-first, not from the
/// `.credentials.json` file the daemon refreshes — so without this a live handle
/// dir keeps the pre-rotation token and 401s. `csq run`/`csq swap` sync at
/// launch; this closes the mid-session gap (a long-running session whose token
/// rotates under it).
///
/// Sweeps EVERY live handle dir via `keychain::sync_all_handle_dirs` rather than
/// attributing dirs to the refreshed account: each dir is synced from its OWN
/// credential symlink, and the newer-than-keychain guard makes unchanged dirs a
/// no-op — so only the dirs whose token actually rotated this tick write. This
/// deliberately avoids per-account handle-dir attribution, whose marker reader is
/// numeric-only and blind to the UUID `.csq-account` markers modern `csq run`
/// writes (which would make the fan-out silently do nothing). Called only when a
/// refresh occurred this tick, so idle ticks pay nothing.
///
/// Best-effort + test-safe: a base dir with no `term-<pid>/` dirs (every
/// refresher unit test) sweeps nothing, so no keychain syscall fires under
/// `cargo test`; on non-macOS the write is a no-op stub. An aggregate failure is
/// logged with a fixed tag; it never affects the refresh outcome.
// `keychain-fix-r10.md` C-I1: process-wide (not thread-local) storage — this
// function runs inside `tokio::task::spawn_blocking`, a genuine OS thread
// distinct from whatever thread a test's assertion runs on, so a
// thread-local counter would never be visible to the test.
//
// `keychain-fix-r11.md` D-7: keyed PER BASE_DIR, not a single shared total.
// The prior single `AtomicU32`'s own doc comment claimed "interleaving from
// unrelated parallel tests... cannot produce a false positive" — false: with
// `cargo test`'s default parallel runner, a DIFFERENT test's tick (any test
// that refreshes an account and triggers its OWN, legitimate
// `sync_refreshed_keychains` call) can increment the SAME global counter in
// the window between this test's `_before`/`_after` reads, making
// `sync_calls_after > sync_calls_before` true even with the recovery sync
// path DELETED — exactly the false pass this test's own RED depends on not
// happening. Keying per `base_dir` (each test uses its own `TempDir`) closes
// that hole: no other test's tick ever shares this test's path.
#[cfg(test)]
static SYNC_REFRESHED_KEYCHAINS_CALLS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<std::path::PathBuf, u32>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

#[cfg(test)]
pub(crate) fn sync_refreshed_keychains_call_count_for_test(base_dir: &std::path::Path) -> u32 {
    SYNC_REFRESHED_KEYCHAINS_CALLS
        .lock()
        .unwrap()
        .get(base_dir)
        .copied()
        .unwrap_or(0)
}

fn sync_refreshed_keychains(
    base_dir: &std::path::Path,
    refreshed: &std::collections::HashMap<
        AccountNum,
        crate::credentials::token_history::Fingerprint,
    >,
) {
    #[cfg(test)]
    {
        *SYNC_REFRESHED_KEYCHAINS_CALLS
            .lock()
            .unwrap()
            .entry(base_dir.to_path_buf())
            .or_insert(0) += 1;
    }
    let (_synced, _skipped, failed) =
        crate::credentials::keychain::sync_all_handle_dirs(base_dir, refreshed);
    if failed > 0 {
        tracing::warn!(
            error_kind = "cc_keychain_sync_failed",
            failed,
            "post-refresh CC keychain mirror failed for one or more handle dirs (non-fatal)"
        );
    }
}

// `keychain-fix-r10.md` C-I1/C-T-a: test-only panic hook, thread-local
// (mirrors `auto_rotate.rs`'s `PRE_LOCK_TEST_HOOK`) since it is set and
// consumed on the SAME test thread that drives the tick — never touched
// concurrently. Reset to `None` by every test that sets it.
#[cfg(test)]
thread_local! {
    static TICK_TEST_PANIC_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_tick_test_panic_hook_for_test(hook: Option<Box<dyn FnMut()>>) {
    TICK_TEST_PANIC_HOOK.with(|c| *c.borrow_mut() = hook);
}

#[cfg(test)]
fn run_tick_test_panic_hook() {
    TICK_TEST_PANIC_HOOK.with(|c| {
        if let Some(hook) = c.borrow_mut().as_mut() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_tick_test_panic_hook() {}

/// `keychain-fix-r11.md` D-7: RAII guard for [`TICK_TEST_PANIC_HOOK`] — resets
/// the thread-local to `None` on `Drop`, which fires on EVERY exit path
/// including an unwinding panic (e.g. a failed `.expect(...)` earlier in the
/// test body), not only the test's last line. The prior pattern (a bare
/// `set_tick_test_panic_hook_for_test(None)` call at the end of the test)
/// never ran if an assertion above it panicked, leaving the hook installed
/// for whichever LATER test happens to reuse the same OS thread from the
/// test harness's thread pool — a real cross-test leak, not a hypothetical
/// one, since `cargo test` recycles threads across `#[test]` functions.
#[cfg(test)]
pub(crate) struct TickTestPanicHookGuard;

#[cfg(test)]
impl TickTestPanicHookGuard {
    pub(crate) fn install(hook: Box<dyn FnMut()>) -> Self {
        set_tick_test_panic_hook_for_test(Some(hook));
        Self
    }
}

#[cfg(test)]
impl Drop for TickTestPanicHookGuard {
    fn drop(&mut self) {
        set_tick_test_panic_hook_for_test(None);
    }
}

/// `keychain-fix-r10.md` S-M-1/C-B2: whether the token REFRESH call
/// (`broker_check`) should be skipped this tick. Gated ONLY on
/// `refresh_rate_limited_this_tick` — a 429 observed on THIS tick's OWN
/// refresh-endpoint call for an earlier account. It is deliberately NOT
/// gated on the shared, IP-wide validation gate (`rate_limited_this_tick`,
/// seeded from `harvest_gate_is_rate_limited()` and set by the custodian's
/// own `/api/oauth/profile` validate call): that gate is evidence the
/// VALIDATION endpoint is throttled, which is a different endpoint from the
/// refresh (token) endpoint, and is not evidence the refresh endpoint is
/// also throttled. Merging the two flags previously meant an account whose
/// custodian validate call (or an unrelated account's earlier validate
/// call, or even a stale cross-tick observation) hit a 429 would never
/// refresh an expiring token this tick — silently, with no HTTP attempt and
/// no log line distinguishing "genuinely rate-limited on refresh" from
/// "some validation call somewhere hit a 429".
fn refresh_should_be_skipped(refresh_rate_limited_this_tick: bool, needs_refresh: bool) -> bool {
    refresh_rate_limited_this_tick && needs_refresh
}

/// Runs a single refresher tick — discover accounts, check each
/// one, update cache, manage cooldowns.
///
/// Exposed `pub(crate)` so tests can drive a single tick without
/// spawning the whole loop. Thin wrapper over [`tick_impl`] that seeds the
/// validation-only gate from the REAL process-wide singleton
/// (`harvest_gate_is_rate_limited`) — production's only entrypoint.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn tick(
    base_dir: &std::path::Path,
    http_post: &HttpPostFn,
    http_post_codex: &HttpPostFnCodex,
    cache: &Arc<TtlCache<u16, RefreshStatus>>,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
) {
    tick_impl(
        base_dir,
        http_post,
        http_post_codex,
        cache,
        cooldowns,
        backoffs,
        crate::daemon::server::harvest_gate_is_rate_limited(),
    )
    .await
}

/// `keychain-fix-r10.md` S-M-1/C-B2: the real body of [`tick`], with the
/// validation-only gate's SEED made an explicit parameter rather than read
/// unconditionally from `harvest_gate_is_rate_limited()`'s process-wide
/// singleton. Tests MUST NOT call `harvest_gate_is_rate_limited` /
/// `harvest_gate_mark_rate_limited` directly (see `server.rs`'s
/// `ip_rate_limit_gate` doc: that singleton is shared with every OTHER test
/// in this binary) — this seam is what lets a test exercise "the
/// validation-only gate is already set at tick start" hermetically, with a
/// value scoped to the one call, instead of mutating global state that
/// would leak into every other refresher test in this process for the
/// gate's 600s cooldown.
#[allow(clippy::too_many_arguments)]
async fn tick_impl(
    base_dir: &std::path::Path,
    http_post: &HttpPostFn,
    http_post_codex: &HttpPostFnCodex,
    cache: &Arc<TtlCache<u16, RefreshStatus>>,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
    initial_rate_limited_this_tick: bool,
) {
    // `keychain-fix-r10.md` C-I1/C-T-a: a test-only panic point placed
    // directly in `tick_impl`'s own body — deliberately OUTSIDE every
    // `spawn_blocking` this function uses internally (those already convert
    // a panic into a `JoinError` that `tick_impl` itself handles, per
    // `spawn_survives_a_panicking_tick_and_continues_refreshing`'s doc, so a
    // panic there never reaches `run_tick_supervised`'s own boundary at
    // all). This is what makes `run_tick_supervised`'s OWN supervision layer
    // — the outer `tokio::spawn` in that function — independently testable:
    // a panic here unwinds straight up through `tick_impl` and `tick`,
    // exactly like the ORIGINAL D-F1 bug class this file's module doc
    // describes, and is caught only by `run_tick_supervised`'s wrapper.
    run_tick_test_panic_hook();

    // Refresh posture, re-read every tick so an operator can flip a host
    // between leader and follower without restarting the daemon (and without
    // racing the desktop supervisor, which respawns it). Follower mode gates
    // the two refresh call sites below — `broker_check` and
    // `broker_codex_check` — and NOTHING else in this tick: discovery, the
    // keychain custodian, the cache writes, the keychain sweep, the outbox
    // drains and the held-provenance sweep all run identically. See
    // `crate::daemon::posture` for why the switch is a persisted file rather
    // than a CLI flag or env var.
    let posture = crate::daemon::posture::load(base_dir);
    if let crate::daemon::posture::PostureSource::Unreadable(ref why) = posture.source {
        // Never swallowed (zero-tolerance.md Rule 3): a posture file that
        // exists but cannot be read forces the stand-down, and the operator
        // has to be told which file and why, on every tick it persists.
        warn!(
            error_kind = "daemon_posture_unreadable",
            posture = posture.posture.as_str(),
            reason = %why,
            "daemon posture file unreadable; standing down to follower (no refreshes)"
        );
    }
    info!(
        posture = posture.posture.as_str(),
        "refresher tick starting"
    );

    // Discover all refreshable accounts across surfaces.
    //
    // - `discover_anthropic`: Claude OAuth slots (refreshed via
    //   `broker_check`).
    // - `discover_codex`: Codex OAuth slots (PR-C3a primitive). Per
    //   an internal journal entry + spec 07 §7.5 INV-P01, the daemon must OWN
    //   refresh cadence for Codex (2h pre-expiry); PR-C4 wires
    //   `broker_codex_check`. Until then, Codex slots are iterated
    //   but skipped inside the loop so telemetry sees them and
    //   cooldowns / caches keep aligned keys, without us trying to
    //   call Anthropic-only `broker_check` on a Codex credential
    //   shape (which would panic on `expect_anthropic`).
    //
    // Third-party providers (MiniMax, Z.AI, Ollama) are bearer-keyed
    // and have no refresh token; the usage poller handles them.
    let mut accounts = discovery::discover_anthropic(base_dir);
    accounts.extend(discovery::discover_codex(base_dir));

    // Cap fanout per tick. See MAX_ACCOUNTS_PER_TICK docstring.
    if accounts.len() > MAX_ACCOUNTS_PER_TICK {
        warn!(
            discovered = accounts.len(),
            cap = MAX_ACCOUNTS_PER_TICK,
            "account count exceeds per-tick cap; processing first {} only",
            MAX_ACCOUNTS_PER_TICK
        );
        accounts.truncate(MAX_ACCOUNTS_PER_TICK);
    }

    let mut processed = 0usize;
    let mut skipped_cooldown = 0usize;
    // `keychain-fix-r10.md` S-M-1/C-B2: TWO flags, deliberately not one.
    //
    // `rate_limited_this_tick` gates ONLY the custodian's read-only
    // VALIDATION call (`/api/oauth/profile`, D-F6). Anthropic rate-limits
    // per IP, so if one validation request is throttled the rest will be
    // too — sending them just amplifies the condition and extends the
    // rate-limit window. Seeded from the shared, IP-wide gate (`server.rs`'s
    // `harvest_gate` module, via `tick`'s `initial_rate_limited_this_tick`
    // parameter) rather than starting `false` every tick — a 429 observed
    // moments ago by the on-demand harvest route or by auto-rotate is
    // honoured immediately here too, instead of this tick re-discovering it
    // the hard way via its own throttled request.
    let mut rate_limited_this_tick = initial_rate_limited_this_tick;
    // `refresh_rate_limited_this_tick` gates the token REFRESH call
    // (`broker_check`) — see `refresh_should_be_skipped`'s doc for why this
    // is a SEPARATE flag rather than reusing `rate_limited_this_tick` above.
    // Deliberately NOT seeded from the shared gate: the refresh endpoint is
    // a different endpoint from validation, so only a 429 observed on THIS
    // tick's OWN refresh call (below) may set it.
    let mut refresh_rate_limited_this_tick = false;
    // `codex_rate_limited_this_tick` (`keychain-fix-r11.md` D-2): Codex's
    // refresh endpoint is a DIFFERENT upstream from Anthropic's, so a 429
    // observed on a Codex account's own `broker_codex_check` call gates
    // only LATER Codex refreshes THIS tick — it must never set
    // `rate_limited_this_tick` above, which is Anthropic-validation-only
    // (`harvest_gate`'s custodian call talks to Anthropic, not Codex, so a
    // Codex-endpoint 429 says nothing about whether that Anthropic call
    // would also be throttled). Deliberately not seeded from any shared
    // gate — Codex has none — and reset every tick like
    // `refresh_rate_limited_this_tick`.
    let mut codex_rate_limited_this_tick = false;

    let mut codex_processed = 0usize;
    // Set when any Anthropic account's store token changed this tick — by a real
    // refresh (broker_check `Refreshed`) OR by the custodian adopting a harvested
    // live token (Option A). Drives the post-loop CC keychain sweep
    // (`sync_refreshed_keychains`), which redistributes the new token to every live
    // handle dir's keychain.
    let mut any_anthropic_refreshed = false;
    // round 7c D2: each refreshed/adopted account's PRE-refresh identity
    // (raw `.credentials.json` content read before the custodian's adopt or
    // broker_check's refresh landed), so the post-tick sweep can recognize a
    // keychain item CC self-refreshed BEFORE this tick's write as "known"
    // (`KnownTokens::sweep_pre_refresh`) rather than an unmatched foreign
    // login. `None` (unreadable pre-refresh canonical) is simply omitted.
    //
    // `keychain-fix-r8.md` S-LOW-1: a FINGERPRINT, not the raw credential
    // JSON — this map previously held the full pre-refresh
    // `.credentials.json` string (token bytes and all) for the duration of
    // the tick, solely to support an identity comparison `decide_cc_
    // keychain_write` can do just as well against a fingerprint (the same
    // primitive `token_history` already fingerprints every canonical write
    // with).
    let mut refreshed: std::collections::HashMap<
        AccountNum,
        crate::credentials::token_history::Fingerprint,
    > = std::collections::HashMap::new();

    // Custodian (Option A) validation transport: a Node-subprocess GET
    // against `/api/oauth/profile` (Cloudflare-safe —
    // `discovery_cloudflare_tls_fingerprint`), NOT `/api/oauth/usage` — that
    // is the usage poller's own endpoint, a different one. `keychain-fix-r10.md`
    // C-docs. Built once per tick; cheap Arc clone per account.
    let http_get: crate::daemon::usage_poller::HttpGetFn =
        Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
            crate::http::get_bearer_node(url, token, headers)
        });

    for info in accounts {
        // Surface dispatch (PR-C4): Codex slots route to
        // `broker_codex_check` instead of `broker_check`. Both share
        // the per-account cooldown / backoff bookkeeping below.
        if info.source == AccountSource::Codex {
            if !info.has_credentials {
                continue;
            }
            let account = match AccountNum::try_from(info.id) {
                Ok(a) => a,
                Err(_) => continue,
            };
            if in_cooldown(cooldowns, backoffs, info.id) {
                skipped_cooldown += 1;
                debug!(
                    account = info.id,
                    surface = "codex",
                    "in cooldown, skipping"
                );
                continue;
            }

            // Codex's canonical lives at `credentials/codex-<N>.json`
            // and the access-token JWT carries its own exp claim.
            // Reading it here gives us an `expires_at_ms` field for
            // the cache record even when the token is fresh enough
            // that no HTTP fires.
            //
            // M4-4: route through identity-keyed Codex credentials
            // (`identities/<UUID>/credentials-codex.json`) when
            // `profiles.json::by_slot` has a UUID for this slot. Slot-id
            // channel: per-slot refresh task state (channel (a) per
            // `account-terminal-separation.md` MUST Rule 1). UUID
            // resolution does NOT introduce a new slot-id channel — it
            // reads `by_slot[slot]` keyed on the slot-id we already have.
            // Legacy fallback to `credentials/codex-<N>.json` only when
            // no UUID mapping exists; the M4-1 chokepoint
            // (`save_codex_canonical_for_uuid`) seeds the UUID path
            // identity-FIRST on every Codex login.
            let canonical =
                match crate::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()) {
                    Some(uuid) => {
                        crate::accounts::identity_store::credentials_codex_path_for(base_dir, uuid)
                    }
                    None => cred_file::canonical_path_for(base_dir, account, Surface::Codex),
                };
            let codex_creds = match credentials::load(&canonical) {
                Ok(c) => c,
                Err(e) => {
                    // CredentialError::Corrupt's `reason` carries
                    // serde_json's error Display, which can echo input
                    // bytes — and the input here IS credential JSON.
                    // Redact before formatting per security.md MUST Rule 8
                    // / an internal journal entry
                    let redacted = crate::error::redact_tokens(&e.to_string());
                    warn!(
                        account = info.id,
                        surface = "codex",
                        canonical = %canonical.display(),
                        error_kind = "codex_canonical_load_failed",
                        canonical_err = %redacted,
                        "codex canonical credential file unreadable, skipping"
                    );
                    continue;
                }
            };
            let exp_secs = codex_creds
                .codex()
                .and_then(|c| http_codex::jwt_exp_secs(&c.tokens.access_token))
                .unwrap_or(0);
            let expires_at_ms = exp_secs.saturating_mul(1000);

            // Follower: never present this slot's refresh token upstream.
            // `broker_codex_check` owns the real refresh decision, so this
            // re-derives the same 2h pre-expiry window purely to LABEL the
            // cache record — the gate itself is unconditional, so a drift in
            // that window can only mislabel, never leak a refresh.
            if posture.is_follower() {
                let due = is_due_for_refresh(expires_at_ms);
                record_follower_skip(cache, info.id, "codex", expires_at_ms, due);
                codex_processed += 1;
                continue;
            }

            // `keychain-fix-r11.md` D-2: a Codex 429 earlier this tick
            // gates only LATER Codex refreshes — never the Anthropic
            // validation flag (see `codex_rate_limited_this_tick`'s doc
            // above).
            let codex_needs_refresh = is_due_for_refresh(expires_at_ms);
            if refresh_should_be_skipped(codex_rate_limited_this_tick, codex_needs_refresh) {
                debug!(
                    account = info.id,
                    surface = "codex",
                    "codex refresh endpoint rate-limited earlier this tick, skipping refresh"
                );
                let status = RefreshStatus {
                    account: info.id,
                    last_result: "rate_limited".to_string(),
                    expires_at_ms,
                    checked_at_secs: now_secs(),
                };
                cache.set(info.id, status);
                codex_processed += 1;
                continue;
            }

            let base = base_dir.to_path_buf();
            let http = Arc::clone(http_post_codex);
            let result = tokio::task::spawn_blocking(move || {
                let http_closure = move |url: &str, body: &str| http(url, body);
                broker_codex_check(&base, account, http_closure)
            })
            .await;

            match result {
                Ok(Ok(broker_result)) => {
                    let status = RefreshStatus::from_result(account, expires_at_ms, &broker_result);
                    match &broker_result {
                        BrokerResult::Failed(_) => {
                            warn!(
                                account = info.id,
                                surface = "codex",
                                "codex refresh failed, entering cooldown"
                            );
                            set_cooldown(cooldowns, info.id);
                        }
                        BrokerResult::RateLimited => {
                            let factor = get_backoff(backoffs, info.id);
                            let effective = FAILURE_COOLDOWN * factor;
                            warn!(
                                account = info.id,
                                surface = "codex",
                                backoff_factor = factor,
                                cooldown_secs = effective.as_secs(),
                                "codex refresh rate limited, entering backoff cooldown"
                            );
                            increase_backoff(backoffs, info.id);
                            set_cooldown(cooldowns, info.id);
                            // D-2: Codex-endpoint 429 gates only LATER
                            // Codex refreshes this tick — never the
                            // Anthropic-only validation flag.
                            codex_rate_limited_this_tick = true;
                        }
                        BrokerResult::Skipped => {}
                        BrokerResult::Valid | BrokerResult::Refreshed => {
                            clear_cooldown(cooldowns, info.id);
                            clear_backoff(backoffs, info.id);
                        }
                    }
                    cache.set(info.id, status);
                    codex_processed += 1;
                }
                Ok(Err(e)) => {
                    warn!(
                        account = info.id,
                        surface = "codex",
                        error_kind = error_kind_tag(&e),
                        "codex broker_check errored, entering cooldown"
                    );
                    set_cooldown(cooldowns, info.id);
                    let status = RefreshStatus {
                        account: info.id,
                        last_result: "error".to_string(),
                        expires_at_ms,
                        checked_at_secs: now_secs(),
                    };
                    cache.set(info.id, status);
                    codex_processed += 1;
                }
                Err(join_err) => {
                    // S-L-2: a JoinError's Display can carry the panic's own
                    // message — not opaque; redact before logging.
                    warn!(
                        account = info.id,
                        surface = "codex",
                        panicked = join_err.is_panic(),
                        error = %crate::error::redact_tokens(&join_err.to_string()),
                        "codex refresh task panicked"
                    );
                    set_cooldown(cooldowns, info.id);
                    let status = RefreshStatus {
                        account: info.id,
                        last_result: "panic".to_string(),
                        expires_at_ms,
                        checked_at_secs: now_secs(),
                    };
                    cache.set(info.id, status);
                    codex_processed += 1;
                }
            }
            continue;
        }

        if info.source != AccountSource::Anthropic || !info.has_credentials {
            continue;
        }

        let account = match AccountNum::try_from(info.id) {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Cooldown check: skip accounts that recently failed.
        if in_cooldown(cooldowns, backoffs, info.id) {
            skipped_cooldown += 1;
            debug!(account = info.id, "in cooldown, skipping");
            continue;
        }

        // M1-6: Canonicalize the per-account config dir at section entry.
        //
        // This binds all subsequent reads and writes in this section to the
        // resolved inode of `config-N/` as it existed when we entered the
        // section. If `config-N/` is renamed or removed between discovery and
        // this point (e.g. a concurrent `csq move` or a mid-cycle directory
        // rename), `canonicalize` returns an error and we abort cleanly — we
        // NEVER fall back to the unresolved path, which could drift to a
        // different account's directory after a rename.
        //
        // In the steady-state (no rename race), `canonical_config_dir` equals
        // `base_dir/config-N/` and `canonical_base` equals `base_dir`, so
        // downstream callers receive the same path they would have before this
        // guard was introduced. The change is purely defensive.
        //
        // The 1200% cross-contamination class documented in journals 0028/0029
        // arose from post-rename inode drift: the refresher's write path
        // resolved `config-N/` AFTER a rename had repointed the directory
        // name to a different account's inode. Canonicalize-at-section-entry
        // closes that window without touching the IPC contract or the
        // `AccountMutexTable` serialisation (which continues to key on
        // `(Surface, AccountNum)` — this guard is additive).
        let config_dir = base_dir.join(format!("config-{}", account));
        let canonical_config_dir = match std::fs::canonicalize(&config_dir) {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    account = info.id,
                    config_dir = %config_dir.display(),
                    error_kind = "config_dir_canonicalize_failed",
                    io_error = %e,
                    "config dir gone or inaccessible mid-cycle; aborting section \
                     to avoid cross-account contamination"
                );
                continue;
            }
        };
        // Derive canonical_base from the resolved config dir. In normal
        // operation this equals base_dir; under a rename race it is the
        // canonical path of what was base_dir before the rename, preventing
        // writes from following the renamed directory name to a different slot.
        let canonical_base = match canonical_config_dir.parent() {
            Some(p) => p.to_path_buf(),
            None => {
                warn!(
                    account = info.id,
                    canonical_config_dir = %canonical_config_dir.display(),
                    "canonical config dir has no parent; skipping account"
                );
                continue;
            }
        };

        // Read expires_at for the cache record even if no refresh
        // is needed.
        //
        // M4-4: read path retargeted to identity-keyed credentials
        // when `profiles.json::by_slot` has a UUID for this slot.
        // The slot-id channel is the per-slot refresh task's own state
        // (channel (a) per `account-terminal-separation.md` MUST Rule 1 —
        // the daemon's per-slot loop already knows which slot it is
        // processing). UUID resolution does NOT introduce a new
        // slot-id channel — it reads `by_slot[slot]` keyed on the
        // slot-id we already have.
        //
        // Legacy fallback: if no UUID mapping exists for this slot
        // (`by_slot` empty or missing this key), fall back to the
        // legacy `credentials/<N>.json` canonical path. The M3-7
        // `phase3_gate_check` (and M4-5 `phase4_gate_check`) refuses
        // daemon start when identity credentials are unseeded for any
        // `by_slot` entry, so the UUID-keyed branch is guaranteed
        // populated in production once `by_slot` is populated.
        //
        // All paths below are constructed via `canonical_base` (resolved at
        // section entry above) rather than `base_dir` (the raw argument) so
        // that mid-section renames of `config-N/` do not redirect writes.
        let canonical =
            match crate::accounts::profiles::resolve_slot_to_uuid(&canonical_base, account.get()) {
                Some(uuid) => {
                    crate::accounts::identity_store::credentials_path_for(&canonical_base, uuid)
                }
                None => cred_file::canonical_path(&canonical_base, account),
            };
        let mut expires_at_ms = match credentials::load(&canonical) {
            Ok(c) => c.expect_anthropic().claude_ai_oauth.expires_at,
            Err(canonical_err) => {
                // M3-7 / SEC-3-H4: the live-mirror resurrection block
                // is retired. Pre-M3-7, when canonical was unreadable
                // the refresher fell back to `cred_file::live_path()`
                // (= `config-<N>/.credentials.json`), loaded that, and
                // resurrected canonical from it. Post-M3-7 the mirror
                // does not exist — there is no fallback. Canonical is
                // the sole authority. A canonical-miss is a true error
                // that the operator must surface (re-login or restore
                // from `identities/<UUID>/credentials.json` via the
                // store-version reconciler).
                //
                // R1 H1-Sec fix-wave: `canonical_err` is a
                // `CredentialError` whose `Corrupt::reason` carries
                // serde_json's error Display which can echo input bytes
                // (and the input IS credential JSON). Mirror the Codex
                // sibling at :378 above and redact before formatting per
                // security.md MUST Rule 8 / an internal journal entry
                let redacted = crate::error::redact_tokens(&canonical_err.to_string());
                warn!(
                    account = info.id,
                    canonical = %canonical.display(),
                    error_kind = "anthropic_canonical_load_failed",
                    canonical_err = %redacted,
                    "canonical credentials unreadable; live-mirror resurrection retired (M3-7)"
                );
                continue;
            }
        };
        // round 7c D2: captured BEFORE either the custodian's adopt or
        // broker_check's refresh can change `canonical`'s content — the
        // sweep's `sweep_pre_refresh` needs this account's identity as it
        // was before whichever mutation fires below.
        //
        // NIT (`keychain-fix-r9.md`): fingerprint HERE, at the read, and
        // drop the raw string immediately — the fingerprint (a `Copy`
        // 32-byte hash) is all either usage site below needs, and both
        // sites are reached only AFTER a network await (the custodian's
        // `spawn_blocking` validate call, or `broker_check`'s own refresh
        // call). Holding the raw credential JSON (token bytes and all) in
        // scope across those awaits keeps it live in memory for the
        // duration of a network round-trip for no reason; computing the
        // fingerprint up front and letting the `String` drop here shortens
        // that window to the read itself.
        let pre_refresh_fp = std::fs::read_to_string(&canonical)
            .ok()
            .and_then(|raw| crate::credentials::token_history::fingerprint_from_raw_json(&raw));

        // ── Keychain custodian (Option A): harvest → validate → adopt ─────────
        // Before the refresh decision, adopt the freshest LIVE token across this
        // account's live handle-dir keychains into the canonical store. This
        // dissolves the multi-session refresh war: when a sibling CC session
        // self-refreshes (rotating the account's refresh-token and stranding csq's
        // store + other sessions on a now-dead token), the daemon harvests that
        // fresh token and levels the account to it — instead of fighting CC's
        // per-session refresh. Only a server-confirmed-live token (200 on
        // /api/oauth/profile — `keychain-fix-r10.md` C-docs) is adopted
        // (an internal journal entry); a rotated-dead candidate
        // (401, future expiresAt) is discarded. Runs in `spawn_blocking`: harvest
        // does `security` subprocess reads and validate does a node-subprocess
        // HTTPS call, both blocking. broker_check below re-reads the (possibly
        // adopted) canonical INSIDE its lock — it no-ops on a now-fresh token, or
        // refreshes a near-expiry adopted one (strictly better than skipping it).
        //
        // Gated on `!rate_limited_this_tick`: validate issues a live GET to
        // /api/oauth/profile. Once any account this tick has observed a 429 on
        // THAT endpoint (via this custodian call, the shared cross-surface
        // gate, or — belt-and-braces — this tick's own refresh-endpoint 429),
        // the custodian MUST also stand down — it is a best-effort
        // optimization, and the next un-throttled tick re-levels. A
        // custodian-observed 429 itself sets `rate_limited_this_tick` so
        // subsequent accounts' VALIDATION calls short-circuit too.
        // `keychain-fix-r10.md` S-M-1/C-B2: this gate is validation-only — it
        // does NOT stand down the REFRESH call below, which is gated by the
        // separate `refresh_rate_limited_this_tick` instead (see
        // `refresh_should_be_skipped`'s doc).
        if !rate_limited_this_tick {
            if let Some(uuid) =
                crate::accounts::profiles::resolve_slot_to_uuid(&canonical_base, account.get())
            {
                let base_for_custodian = canonical_base.clone();
                let uuid_s = uuid.to_string();
                let http_get_c = Arc::clone(&http_get);
                let outcome = tokio::task::spawn_blocking(move || {
                    crate::daemon::custodian::reconcile_account(
                        &base_for_custodian,
                        account,
                        &uuid_s,
                        &http_get_c,
                    )
                })
                .await;
                use crate::daemon::custodian::ReconcileOutcome;
                match outcome {
                    Ok(ReconcileOutcome::Adopted) => {
                        // Store token changed via adopt → live handle dirs need the new
                        // token redistributed by the post-loop sweep.
                        any_anthropic_refreshed = true;
                        if let Some(fp) = pre_refresh_fp {
                            refreshed.insert(account, fp);
                        }
                        // Re-read the post-adopt expiry so `needs_refresh`, the
                        // rate-limited-skip status, and the cache record below reflect
                        // the freshly adopted token rather than the pre-adopt (often
                        // near-expiry) value the custodian just healed.
                        if let Ok(c) = credentials::load(&canonical) {
                            if let Some(a) = c.anthropic() {
                                expires_at_ms = a.claude_ai_oauth.expires_at;
                            }
                        }
                    }
                    Ok(ReconcileOutcome::RateLimited) => {
                        // The custodian's own validate was throttled — propagate to the
                        // tick's cross-account VALIDATION gate so remaining accounts'
                        // custodian calls stand down. `keychain-fix-r10.md` S-M-1/C-B2:
                        // this does NOT stand down this or any other account's
                        // broker_check refresh — a validation-endpoint 429 is not
                        // evidence the separate refresh endpoint is throttled (see
                        // `refresh_should_be_skipped`'s doc).
                        rate_limited_this_tick = true;
                        // C-F5/S-MEDIUM-2 (`keychain-fix-r8.md`), D-F6: share
                        // this observation with the shared, IP-wide gate
                        // (`server.rs`'s `harvest_gate` module) so an
                        // on-demand harvest, a later auto-rotate tick, and
                        // this refresher's own later ticks all return
                        // `busy`/skip with no HTTP call against an endpoint
                        // already known to be throttling this daemon's IP.
                        // Sync: no `.await` needed (see
                        // `harvest_gate_mark_rate_limited`'s doc — round 9,
                        // S-C-1 / D-F1: the PRIOR per-account
                        // `blocking_lock`-on-a-tokio-Mutex implementation
                        // panicked when called from exactly this async
                        // context; moving the state onto a plain
                        // `std::sync::Mutex` removes the footgun rather than
                        // working around one call site).
                        crate::daemon::server::harvest_gate_mark_rate_limited(account);
                    }
                    Ok(_) => {}
                    Err(join_err) => {
                        // A panic inside reconcile_account (e.g. a poisoned per-account
                        // write mutex) surfaces here as a JoinError. Log it with a fixed
                        // tag — never silently swallow a daemon-task panic.
                        warn!(
                            account = info.id,
                            error_kind = "custodian_task_panicked",
                            panicked = join_err.is_panic(),
                            "custodian reconcile task failed (non-fatal)"
                        );
                        // `keychain-fix-r11.md` D-3: `reconcile_account` may have
                        // ALREADY adopted a harvested token into the canonical
                        // store before panicking on a LATER step (e.g. the
                        // post-adopt re-read) — the panic tells us the task
                        // didn't finish cleanly, not that it wrote nothing.
                        // Conservatively flag the tick for the post-loop
                        // keychain sweep so a real write is never stranded
                        // behind a panicked task; the sweep's newer-than-
                        // keychain guard makes an unnecessary sweep a no-op.
                        any_anthropic_refreshed = true;
                    }
                }
            }
        }

        // Check if this account needs a refresh (within the 2-hour
        // window). If so and we already hit a rate limit this tick,
        // skip the HTTP call but still record the status so the
        // dashboard shows something. Valid tokens are always processed
        // because they don't make HTTP requests.
        let needs_refresh = is_due_for_refresh(expires_at_ms);

        // Follower: never present this slot's refresh token upstream. Gated
        // BEFORE the rate-limit short-circuit so the cache label is always
        // `follower_skipped` for a follower — a follower that never calls the
        // refresh endpoint must not be reported as `rate_limited` just because
        // the custodian's read-only validate was throttled earlier this tick.
        //
        // The custodian above already ran, and deliberately so: it only
        // harvests + validates a token some local CC session minted, which
        // cannot rotate a refresh token. A follower still levels up to the
        // freshest local token; it just never asks Anthropic for a new one.
        if posture.is_follower() {
            record_follower_skip(cache, info.id, "anthropic", expires_at_ms, needs_refresh);
            processed += 1;
            continue;
        }

        if refresh_should_be_skipped(refresh_rate_limited_this_tick, needs_refresh) {
            debug!(
                account = info.id,
                "refresh endpoint rate-limited earlier this tick, skipping refresh"
            );
            let status = RefreshStatus {
                account: info.id,
                last_result: "rate_limited".to_string(),
                expires_at_ms,
                checked_at_secs: now_secs(),
            };
            cache.set(info.id, status);
            processed += 1;
            continue;
        }

        // Run broker_check inside spawn_blocking because it does
        // blocking file IO and may invoke the synchronous HTTP
        // transport. Pass canonical_base (resolved at section entry)
        // so broker_check constructs config-N/ paths from the
        // pre-rename inode rather than the potentially-renamed name.
        let base = canonical_base;
        let http = Arc::clone(http_post);
        let result = tokio::task::spawn_blocking(move || {
            let http_closure = move |url: &str, body: &str| http(url, body);
            broker_check(&base, account, http_closure)
        })
        .await;

        match result {
            Ok(Ok(broker_result)) => {
                let status = RefreshStatus::from_result(account, expires_at_ms, &broker_result);
                match &broker_result {
                    BrokerResult::Failed(_) => {
                        warn!(account = info.id, "refresh failed, entering cooldown");
                        set_cooldown(cooldowns, info.id);
                        // Don't increase backoff for generic failures —
                        // the account might need re-auth, and aggressive
                        // backoff would delay recovery after re-login.
                    }
                    BrokerResult::RateLimited => {
                        // Rate-limited by Anthropic on THIS tick's OWN
                        // refresh (token) call. Set a cooldown with
                        // exponential backoff and stop refreshing remaining
                        // accounts this tick (`refresh_rate_limited_this_tick`
                        // — see `refresh_should_be_skipped`'s doc). Also
                        // marks the validation-only `rate_limited_this_tick`:
                        // a refresh-endpoint 429 is still evidence this
                        // daemon's IP is presently throttled by Cloudflare,
                        // so the custodian's read-only validate call should
                        // stand down too — this direction (refresh 429 also
                        // gates validation) was never the bug; only the
                        // reverse (validation 429 gating refresh) was.
                        let factor = get_backoff(backoffs, info.id);
                        let effective = FAILURE_COOLDOWN * factor;
                        warn!(
                            account = info.id,
                            backoff_factor = factor,
                            cooldown_secs = effective.as_secs(),
                            "refresh rate limited, entering backoff cooldown"
                        );
                        increase_backoff(backoffs, info.id);
                        set_cooldown(cooldowns, info.id);
                        rate_limited_this_tick = true;
                        refresh_rate_limited_this_tick = true;
                    }
                    BrokerResult::Skipped => {
                        // Another process holds the refresh lock.
                        // Leave any existing cooldown alone and
                        // proceed — we'll pick up the refreshed
                        // credentials on the next tick via the
                        // re-read-inside-lock path in broker_check.
                    }
                    BrokerResult::Valid | BrokerResult::Refreshed => {
                        clear_cooldown(cooldowns, info.id);
                        clear_backoff(backoffs, info.id);
                        // CC reads each session's OAuth credential from the macOS
                        // keychain, NOT the `.credentials.json` file we just
                        // refreshed. On a real refresh (token changed) flag the
                        // tick to sweep all live handle dirs' keychains afterward,
                        // or CC keeps the pre-rotation token and 401s. Flag on
                        // `Refreshed` ONLY: `Valid` means unchanged (no rotation),
                        // so it needs no sweep (the newer-than-keychain guard would
                        // skip it anyway). The post-loop sweep is account-agnostic
                        // (see `sync_refreshed_keychains`).
                        if matches!(broker_result, BrokerResult::Refreshed) {
                            any_anthropic_refreshed = true;
                            if let Some(fp) = pre_refresh_fp {
                                refreshed.insert(account, fp);
                            }
                        }
                    }
                }
                cache.set(info.id, status);
                processed += 1;
            }
            Ok(Err(e)) => {
                // Log only a short variant tag, not the full error
                // Display. The Display chain can contain the body
                // of a malformed upstream response that echoes the
                // refresh token back (see credentials::refresh for
                // the redaction that scrubs it at the source), so
                // we defense-in-depth by not logging the raw error
                // string here at all.
                warn!(
                    account = info.id,
                    error_kind = error_kind_tag(&e),
                    "broker_check errored, entering cooldown"
                );
                set_cooldown(cooldowns, info.id);
                // Record the failure in the cache too.
                let status = RefreshStatus {
                    account: info.id,
                    last_result: "error".to_string(),
                    expires_at_ms,
                    checked_at_secs: now_secs(),
                };
                cache.set(info.id, status);
                processed += 1;
            }
            Err(join_err) => {
                // `keychain-fix-r10.md` S-L-2: JoinError is NOT opaque — its
                // `Display` includes the panic's own message when the panic
                // payload downcasts to `String`/`&str` (tokio's `JoinError`
                // impl), and `broker_check`'s call graph handles credential
                // material, so redact before logging rather than assume
                // safety.
                warn!(
                    account = info.id,
                    panicked = join_err.is_panic(),
                    error = %crate::error::redact_tokens(&join_err.to_string()),
                    "refresh task panicked"
                );
                set_cooldown(cooldowns, info.id);
                // `keychain-fix-r11.md` D-3: `broker_check` may have already
                // written a refreshed token to the canonical store before
                // panicking on a LATER step — see the custodian's identical
                // reasoning above. Flag the tick for the post-loop keychain
                // sweep so a real write is never stranded behind a panicked
                // task; the sweep's newer-than-keychain guard makes an
                // unnecessary sweep a no-op.
                any_anthropic_refreshed = true;
                // Write a "panic" entry so `/api/refresh-status`
                // shows something for this account instead of
                // silently omitting it.  Without this, the
                // dashboard sees an empty list until a non-panic
                // tick fires — the 15-min empty window observed
                // in the 2026-04-14 PM session (task #12).
                let status = RefreshStatus {
                    account: info.id,
                    last_result: "panic".to_string(),
                    expires_at_ms,
                    checked_at_secs: now_secs(),
                };
                cache.set(info.id, status);
                processed += 1;
            }
        }
    }

    // If any Anthropic token rotated this tick, mirror the fresh tokens into the
    // keychain items CC reads (CC is keychain-first). Account-agnostic sweep; the
    // newer-than-keychain guard no-ops unchanged dirs. Runs on a real
    // refresh, or once after the keychain stops reading as locked; an idle
    // tick pays one bounded lock-state probe and no `security` calls.
    //
    // Runs in `spawn_blocking`: the sweep shells one or more `security`
    // subprocesses per live handle dir, synchronous but NOT unbounded — every
    // `security` call it can issue is bounded at `KEYCHAIN_OP_TIMEOUT +
    // MIN_POST_EXIT_GRACE` = 5.25s (see `write_raw`'s doc for the derivation),
    // and each dir's own per-handle-dir lock wait is separately bounded at
    // ~20.25s (`HANDLE_LOCK_BOUND_ATTEMPTS`'s doc) — so a single dir's worst
    // case is bounded (lock wait + up to 3 bounded calls), but the SWEEP AS A
    // WHOLE is unbounded in the number of live handle dirs it walks
    // sequentially, so its total wall-clock scales with handle-dir count. The
    // daemon runtime has only 2 worker threads — a direct call would tie up
    // half the runtime and delay socket IPC (mirrors `run_held_sweep_tick`'s
    // wrapper), which is why this still runs off the async runtime even
    // though no individual step blocks forever.
    // Also re-run the sweep once after a period in which keychain calls were
    // skipped because the keychain was locked (see `run_security_bounded`):
    // otherwise a mirror skipped while the screen was locked would wait for
    // the account's next refresh, leaving CC on the previous token.
    // The lock probe is a blocking OS call, so it runs inside the same
    // spawn_blocking as the sweep (once per tick), never on a runtime worker.
    {
        let sweep_base = base_dir.to_path_buf();
        let sweep_refreshed = refreshed;
        if let Err(e) = tokio::task::spawn_blocking(move || {
            if any_anthropic_refreshed || crate::credentials::keychain::keychain_catch_up_due() {
                sync_refreshed_keychains(&sweep_base, &sweep_refreshed);
            }
        })
        .await
        {
            // `keychain-fix-r11.md` D-3: fixed tag + `is_panic` only — the
            // same JoinError-Display concern as the sibling sweep above.
            tracing::warn!(
                error_kind = "cc_keychain_sync_task_panicked",
                panicked = e.is_panic(),
                "post-refresh CC keychain sweep task panicked (non-fatal)"
            );
        }
    }

    info!(
        processed,
        skipped_cooldown, codex_processed, "refresher tick complete"
    );
}

/// Cache label written for a slot the refresher declined to refresh because
/// this daemon is a follower. Distinct from `"skipped"` (another process holds
/// the refresh lock) and from `"valid"` (token is fresh, nothing to do) — an
/// operator reading `/api/refresh-status` must be able to tell "nobody
/// refreshed this because I told this host not to" apart from both.
pub const FOLLOWER_SKIP_LABEL: &str = "follower_skipped";

/// True when `expires_at_ms` falls inside the pre-expiry refresh window a
/// leader would act on. Shared by the two follower gates so both label their
/// cache records against the same window the leader path uses.
fn is_due_for_refresh(expires_at_ms: u64) -> bool {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    expires_at_ms < now_ms + (crate::refresh::check::REFRESH_WINDOW_SECS * 1000)
}

/// Record a follower's declined refresh, and escalate when the token is not
/// merely due but ALREADY EXPIRED.
///
/// The two log levels are the operator contract for follower mode. `due` is
/// routine — the leader host is expected to renew it and this host will pick
/// the new token up. EXPIRED means no leader did, so this host is running
/// unattended and the next API call 401s. That case gets a WARN with a fixed
/// `error_kind` rather than being folded into the routine path, because a
/// follower going stale must be a stated condition and not a mystery
/// (zero-tolerance.md Rule 3).
///
/// Slot id comes from the caller's own per-slot loop state — channel (a) of
/// `account-terminal-separation.md` MUST Rule 1. No new slot-id channel.
fn record_follower_skip(
    cache: &Arc<TtlCache<u16, RefreshStatus>>,
    account: u16,
    surface: &'static str,
    expires_at_ms: u64,
    due: bool,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let expired = expires_at_ms != 0 && expires_at_ms < now_ms;
    if expired {
        warn!(
            account,
            surface,
            error_kind = "follower_credential_expired",
            expired_for_secs = (now_ms - expires_at_ms) / 1000,
            "follower mode: stored token has EXPIRED and this host never \
             refreshes — the leader host is not covering this slot. Either \
             start/repair the leader daemon, or make this host the leader \
             (`csq daemon posture leader`)."
        );
    } else if due {
        debug!(
            account,
            surface, "follower mode: refresh due, deferring to the leader host"
        );
    }
    cache.set(
        account,
        RefreshStatus {
            account,
            last_result: FOLLOWER_SKIP_LABEL.to_string(),
            expires_at_ms,
            checked_at_secs: now_secs(),
        },
    );
}

/// Re-export of the shared `error_kind_tag` so the refresher's
/// warn-log call site keeps its local name. The function itself
/// lives in `crate::error` so every subsystem uses the same
/// vocabulary (logs, broker-failed flag files, dashboard error
/// column all agree on what "broker_token_invalid" means).
use crate::error::error_kind_tag;

// M3-7: `append_resurrection_breadcrumb` retired alongside the
// live-mirror resurrection block at the refresher's section entry.
// The forensic-trail file `.resurrection-log.jsonl` is no longer
// produced; pre-Phase-3 trails on disk are left in place as a
// historical artifact (operators may delete via `csq doctor`).

fn in_cooldown(
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
    account: u16,
) -> bool {
    let guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    match guard.get(&account) {
        Some(t) => {
            let factor = get_backoff(backoffs, account);
            t.elapsed() < FAILURE_COOLDOWN * factor
        }
        None => false,
    }
}

fn get_backoff(backoffs: &Arc<Mutex<HashMap<u16, u32>>>, account: u16) -> u32 {
    let guard = backoffs.lock().unwrap_or_else(|p| p.into_inner());
    *guard.get(&account).unwrap_or(&1)
}

fn increase_backoff(backoffs: &Arc<Mutex<HashMap<u16, u32>>>, account: u16) {
    let mut guard = backoffs.lock().unwrap_or_else(|p| p.into_inner());
    let current = guard.get(&account).copied().unwrap_or(1);
    guard.insert(account, (current * 2).min(MAX_BACKOFF));
}

fn clear_backoff(backoffs: &Arc<Mutex<HashMap<u16, u32>>>, account: u16) {
    let mut guard = backoffs.lock().unwrap_or_else(|p| p.into_inner());
    guard.remove(&account);
}

fn set_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(account, Instant::now());
}

fn clear_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.remove(&account);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::TempDir;

    #[test]
    fn sync_refreshed_keychains_is_noop_without_handle_dirs() {
        // Test-safety invariant: with no `term-<pid>/` handle dirs the sweep
        // enumerates nothing and fires no keychain syscall — which is why every
        // other refresher test (tempdir base, no handle dirs) never touches the
        // real keychain. A panic-free return on an empty base proves it.
        let dir = TempDir::new().unwrap();
        sync_refreshed_keychains(dir.path(), &std::collections::HashMap::new());
        // must not panic / touch keychain
    }

    /// `next_wait_chunk` caps the sub-sleep at `probe`, returns the short tail
    /// near the deadline, and — the load-bearing case for an internal journal entry Q2 —
    /// returns `None` (tick now) when the wall clock has jumped past the
    /// deadline, as it does after the host wakes from sleep. A fixed UNIX-epoch
    /// base keeps the test deterministic (no `SystemTime::now`).
    #[test]
    fn next_wait_chunk_caps_at_probe_and_detects_wake_jump() {
        let base = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let deadline = base + Duration::from_secs(300);
        let probe = Duration::from_secs(30);

        // Far from the deadline → cap at one probe.
        assert_eq!(next_wait_chunk(base, deadline, probe), Some(probe));
        // Close to the deadline → return the short remaining tail, not a probe.
        assert_eq!(
            next_wait_chunk(deadline - Duration::from_secs(5), deadline, probe),
            Some(Duration::from_secs(5)),
        );
        // Exactly at the deadline → tick now.
        assert_eq!(next_wait_chunk(deadline, deadline, probe), None);
        // Post-wake: wall clock jumped 6h past the deadline → tick now, do NOT
        // wait out another full interval.
        assert_eq!(
            next_wait_chunk(base + Duration::from_secs(21_600), deadline, probe),
            None,
        );
        // A zero probe must NOT yield Some(0) (would busy-spin) — tick now.
        assert_eq!(next_wait_chunk(base, deadline, Duration::ZERO), None);
    }

    /// `wait_chunk_or_done` folds the two inter-tick break channels. This pins
    /// the floor-PRECEDENCE that `run_loop` relies on but cannot itself unit-test
    /// (it reads real clocks): the monotonic floor is checked first, so a fully
    /// elapsed interval ticks now even when the wall clock says "keep waiting"
    /// (the backward-clock-step case), and a not-yet-elapsed interval defers to
    /// the wall-clock channel (catching host wake). Origin: an internal journal entry Q2.
    #[test]
    fn wait_chunk_or_done_floor_precedes_wall_clock() {
        let interval = Duration::from_secs(300);
        let probe = Duration::from_secs(30);
        let now = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let future_deadline = now + Duration::from_secs(300); // wall clock says "wait"

        // Monotonic interval fully elapsed → tick now, EVEN THOUGH the wall-clock
        // deadline is still in the future (backward-clock-step immunity).
        assert_eq!(
            wait_chunk_or_done(interval, interval, now, future_deadline, probe),
            None,
        );
        assert_eq!(
            wait_chunk_or_done(
                interval + Duration::from_secs(60),
                interval,
                now,
                future_deadline,
                probe
            ),
            None,
        );
        // Interval not yet elapsed, deadline in the future → defer to wall clock,
        // capped at the probe.
        assert_eq!(
            wait_chunk_or_done(
                Duration::from_secs(10),
                interval,
                now,
                future_deadline,
                probe
            ),
            Some(probe),
        );
        // Interval not yet elapsed but wall clock jumped past the deadline (host
        // woke) → tick now via the wall-clock channel.
        let woke = future_deadline + Duration::from_secs(21_600);
        assert_eq!(
            wait_chunk_or_done(
                Duration::from_secs(10),
                interval,
                woke,
                future_deadline,
                probe
            ),
            None,
        );
    }

    /// Provisions a deterministic UUID mapping in `profiles.json::by_slot` for
    /// the given account number. Required because `save_canonical_for` is
    /// fail-closed (M4-12): it returns `Err(NoCredentials)` when no UUID
    /// mapping exists, which would cause all tests that trigger a write through
    /// `broker_check` or `broker_codex_check` to fail at write time.
    fn provision_uuid_for_account(base: &std::path::Path, account: u16) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            crate::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| crate::accounts::profiles::ProfilesFile::empty())
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert(account.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
    }

    fn make_creds(access: &str, refresh: &str, expires_at_ms: u64) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at: expires_at_ms,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        })
    }

    fn install_account(base: &std::path::Path, account: u16, expires_at_ms: u64) {
        let num = AccountNum::try_from(account).unwrap();
        let creds = make_creds("at", "rt", expires_at_ms);
        // Create the config-N/ directory so M1-6's canonicalize-at-section-entry
        // guard can resolve it. Real account directories always have config-N/;
        // the prior test helper only created credentials/N.json and was
        // therefore incomplete with respect to the on-disk invariant.
        let config_dir = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config_dir).unwrap();
        // M4-12: provision UUID mapping so save_canonical_for (called by
        // broker_check on refresh) can locate the identity write path.
        provision_uuid_for_account(base, account);
        // Write to the numeric canonical path (legacy/compatibility reads).
        credentials::save(&cred_file::canonical_path(base, num), &creds).unwrap();
        // M4-4: tick's read path now resolves UUID when by_slot is populated.
        // Write the same credentials to the UUID-keyed identity path so tick
        // can read expires_at_ms without falling back to the numeric path.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(uuid_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_path, &creds).unwrap();
    }

    /// Writes ONLY the live `config-N/.credentials.json` file —
    /// intentionally skipping the canonical `credentials/N.json`
    /// mirror. Simulates the alpha.11 bug state where a broken
    /// write path orphaned the live copy.
    fn install_live_only(base: &std::path::Path, account: u16, expires_at_ms: u64) {
        let num = AccountNum::try_from(account).unwrap();
        let config = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join(".csq-account"), account.to_string()).unwrap();
        let creds = make_creds("at-live", "rt-live", expires_at_ms);
        credentials::save(&cred_file::live_path(base, num), &creds).unwrap();
    }

    /// Installs a Codex-shape canonical credential file at
    /// `credentials/codex-<N>.json`. Used by PR-C3c's iterate-and-skip
    /// regression test — a tick that discovers this slot must NOT
    /// invoke `broker_check` (which is Anthropic-only) against it.
    fn install_codex_account(base: &std::path::Path, account: u16) {
        use crate::credentials::{CodexCredentialFile, CodexTokensFile};
        let num = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("test-codex-acct".into()),
                access_token: "eyJhbGciOiJIUzI1NiJ9.codex-at.sig".into(),
                refresh_token: Some("rt_codex_test".into()),
                id_token: Some("eyJhbGciOiJIUzI1NiJ9.codex-id.sig".into()),
                extra: Default::default(),
            },
            last_refresh: Some("2026-04-22T00:00:00Z".into()),
            extra: Default::default(),
        });
        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path if broker_codex_check runs on this slot.
        provision_uuid_for_account(base, account);
        credentials::save(
            &cred_file::canonical_path_for(base, num, crate::providers::catalog::Surface::Codex),
            &creds,
        )
        .unwrap();
        // M4-4: tick's Codex read path resolves UUID when by_slot is populated.
        // Write the same credentials to the UUID-keyed identity path so tick
        // can read exp from identities/<UUID>/credentials-codex.json.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let uuid_codex_path =
            crate::accounts::identity_store::credentials_codex_path_for(base, uuid);
        std::fs::create_dir_all(uuid_codex_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_codex_path, &creds).unwrap();
    }

    /// Mock HTTP closure that always succeeds and counts calls.
    fn counting_success(counter: Arc<AtomicU32>) -> HttpPostFn {
        Arc::new(move |_url: &str, _body: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(
                br#"{"access_token":"at-new","refresh_token":"rt-new","expires_in":18000}"#
                    .to_vec(),
            )
        })
    }

    /// Mock HTTP closure that always fails.
    fn counting_failure(counter: Arc<AtomicU32>) -> HttpPostFn {
        Arc::new(move |_url: &str, _body: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Err("401 Unauthorized".to_string())
        })
    }

    /// Mock HTTP closure that PANICS on its first invocation, then always
    /// succeeds. Used to prove `run_tick_supervised` isolates a panic
    /// anywhere on the tick call graph to a single tick, rather than
    /// killing `run_loop`'s own task permanently (round 9, S-C-1 / D-F1).
    fn panicking_then_success(counter: Arc<AtomicU32>) -> HttpPostFn {
        Arc::new(move |_url: &str, _body: &str| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                panic!("injected panic: simulated refresher-tick failure");
            }
            Ok(
                br#"{"access_token":"at-new","refresh_token":"rt-new","expires_in":18000}"#
                    .to_vec(),
            )
        })
    }

    /// No-op Codex HTTP transport for Anthropic-only tests. Counts
    /// calls so a misrouted Anthropic refresh hitting the Codex
    /// closure is detectable.
    fn noop_codex_http(counter: Arc<AtomicU32>) -> HttpPostFnCodex {
        Arc::new(move |_url: &str, _body: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(crate::http::NodeHttpResponse {
                status: 200,
                body: b"{}".to_vec(),
                date: None,
            })
        })
    }

    /// Codex success transport: returns a refresh response whose new
    /// access_token JWT exp is 6h ahead. Counts calls.
    fn counting_codex_success(counter: Arc<AtomicU32>) -> HttpPostFnCodex {
        Arc::new(move |_url: &str, _body: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            let exp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 6 * 3600;
            // header={"alg":"HS256"}, payload={"exp":<exp>}, sig=stub.
            // base64url(payload) is computed via the same encoder used in
            // broker::check tests; reused inline here to keep refresher's
            // test helpers self-contained.
            let payload = format!(r#"{{"exp":{exp}}}"#);
            let payload_b64 = b64url_encode_inline(payload.as_bytes());
            let access = format!("eyJhbGciOiJIUzI1NiJ9.{payload_b64}.testsig");
            let body = format!(
                r#"{{"access_token":"{access}","refresh_token":"rt_new","expires_in":3600}}"#
            );
            Ok(crate::http::NodeHttpResponse {
                status: 200,
                body: body.into_bytes(),
                date: None,
            })
        })
    }

    fn b64url_encode_inline(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in data {
            buf = (buf << 8) | (b as u32);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                let idx = ((buf >> bits) & 0x3f) as usize;
                out.push(ALPHABET[idx] as char);
            }
        }
        if bits > 0 {
            let idx = ((buf << (6 - bits)) & 0x3f) as usize;
            out.push(ALPHABET[idx] as char);
        }
        out
    }

    #[tokio::test]
    async fn tick_does_nothing_with_no_accounts() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(cache.is_empty());
    }

    /// PR-C4 regression: a tick that discovers a Codex slot routes
    /// through the Codex transport (NOT the Anthropic transport).
    /// The Codex slot's stub access_token has no decodeable JWT exp
    /// claim → broker_codex_check treats it as "needs refresh now"
    /// → the codex closure fires.
    #[tokio::test]
    async fn tick_dispatches_codex_to_codex_transport() {
        let dir = TempDir::new().unwrap();
        install_codex_account(dir.path(), 4);

        let anth_counter = Arc::new(AtomicU32::new(0));
        let codex_counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&anth_counter));
        let codex_http = counting_codex_success(Arc::clone(&codex_counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &codex_http,
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            anth_counter.load(Ordering::SeqCst),
            0,
            "Anthropic transport MUST NOT fire for a Codex slot"
        );
        assert_eq!(
            codex_counter.load(Ordering::SeqCst),
            1,
            "Codex transport must fire exactly once for a near-expiry Codex slot"
        );
        assert!(
            cache.get(&4).is_some(),
            "Codex cache entry expected after PR-C4 refresh"
        );
    }

    /// PR-C4 regression: a mixed tick (Anthropic + Codex) routes each
    /// slot to its own transport, with neither closure seeing the
    /// other surface's URL or body.
    #[tokio::test]
    async fn tick_refreshes_anthropic_and_codex_via_separate_transports() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0); // expired Anthropic slot
        install_codex_account(dir.path(), 4); // Codex slot (no exp claim → refresh)

        let anth_counter = Arc::new(AtomicU32::new(0));
        let codex_counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&anth_counter));
        let codex_http = counting_codex_success(Arc::clone(&codex_counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &codex_http,
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            anth_counter.load(Ordering::SeqCst),
            1,
            "Anthropic transport must fire exactly once for slot 1"
        );
        assert_eq!(
            codex_counter.load(Ordering::SeqCst),
            1,
            "Codex transport must fire exactly once for slot 4"
        );
        assert!(cache.get(&1).is_some(), "Anthropic cache entry expected");
        assert!(cache.get(&4).is_some(), "Codex cache entry expected");
    }

    /// PR-C4 regression: two refresher ticks back-to-back where the
    /// Codex slot was successfully refreshed in the first tick must
    /// NOT fire the Codex transport in the second — the new JWT exp
    /// is far in the future, so broker_codex_check returns Valid.
    /// This is the in-process analogue of an internal journal entry's "two-codex-
    /// process never both refresh" guarantee — once one tick lands a
    /// fresh JWT, subsequent ticks within the 2h window are no-ops.
    #[tokio::test]
    async fn tick_after_codex_refresh_does_not_re_fire_inside_window() {
        let dir = TempDir::new().unwrap();
        install_codex_account(dir.path(), 5);

        let anth_counter = Arc::new(AtomicU32::new(0));
        let codex_counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&anth_counter));
        let codex_http = counting_codex_success(Arc::clone(&codex_counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        // First tick — refresh fires.
        tick(
            dir.path(),
            &http,
            &codex_http,
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;
        assert_eq!(codex_counter.load(Ordering::SeqCst), 1);

        // Second tick — token is fresh (6h ahead), broker_codex_check
        // returns Valid without HTTP. The counter MUST NOT increment.
        tick(
            dir.path(),
            &http,
            &codex_http,
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;
        assert_eq!(
            codex_counter.load(Ordering::SeqCst),
            1,
            "second tick must not re-fire Codex refresh while inside 2h window"
        );
    }

    /// M3-7 acceptance test #5 (WBS line 262):
    /// `daemon_refresher_does_not_resurrect_from_live_mirror_on_canonical_miss`.
    ///
    /// Pre-M3-7, the refresher fell back to `config-<N>/.credentials.json`
    /// (the live mirror) when canonical was unreadable, then "resurrected"
    /// canonical from it and refreshed. This was the SEC-3-H4 attack vector
    /// — a hostile mirror file could promote attacker creds to canonical.
    ///
    /// Post-M3-7, the resurrection block is retired. A live-only slot
    /// (no canonical) is now SKIPPED by the refresher rather than
    /// resurrected. The test asserts: no HTTP call (no broker_check ran),
    /// no canonical write, no `.resurrection-log.jsonl` breadcrumb.
    #[tokio::test]
    async fn daemon_refresher_does_not_resurrect_from_live_mirror_on_canonical_miss() {
        let dir = TempDir::new().unwrap();
        // Live-only, expired token. Pre-M3-7 this would have triggered
        // resurrection-from-live + refresh in the same tick.
        install_live_only(dir.path(), 1, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        // M3-7: canonical NOT resurrected from live.
        let canonical = cred_file::canonical_path(dir.path(), AccountNum::try_from(1u16).unwrap());
        assert!(
            !canonical.exists(),
            "M3-7: canonical credentials/1.json MUST NOT be resurrected from live mirror"
        );

        // M3-7: no HTTP call — broker_check did not run for this slot.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "M3-7: no refresh attempted when canonical is absent"
        );

        // M3-7: no resurrection breadcrumb.
        let breadcrumb = dir.path().join(".resurrection-log.jsonl");
        assert!(
            !breadcrumb.exists(),
            "M3-7: .resurrection-log.jsonl MUST NOT be produced (resurrection block retired)"
        );
    }

    #[tokio::test]
    async fn tick_refreshes_expiring_account() {
        let dir = TempDir::new().unwrap();
        // Expired = definitely in the 2-hour refresh window.
        install_account(dir.path(), 1, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one HTTP refresh"
        );
        let status = cache.get(&1).unwrap();
        assert_eq!(status.account, 1);
        assert_eq!(status.last_result, "refreshed");
    }

    // ── follower-mode gate (two-host refresh-token war) ───────────────────
    //
    // The pair below is the discriminating instrument: the SAME fixture (an
    // expired Anthropic credential — unambiguously inside the 2h refresh
    // window) is driven through a tick twice, differing ONLY in the posture
    // file. Leader must issue exactly one refresh; follower must issue zero.
    // Either test alone is vacuous — a zero-call assertion passes on any base
    // that simply has no accounts, and a one-call assertion passes with the
    // gate deleted. Read them together.

    #[tokio::test]
    async fn tick_in_leader_posture_refreshes_a_due_credential() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);
        crate::daemon::posture::save(dir.path(), crate::daemon::posture::DaemonPosture::Leader)
            .unwrap();

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "leader posture must refresh a due credential"
        );
        assert_eq!(cache.get(&1).unwrap().last_result, "refreshed");
    }

    #[tokio::test]
    async fn tick_in_follower_posture_does_not_refresh_a_due_credential() {
        let dir = TempDir::new().unwrap();
        // Identical fixture to the leader test above: expired => due.
        install_account(dir.path(), 1, 0);
        crate::daemon::posture::save(dir.path(), crate::daemon::posture::DaemonPosture::Follower)
            .unwrap();

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let codex_counter = Arc::new(AtomicU32::new(0));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::clone(&codex_counter)),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "follower posture must NOT present a refresh token upstream"
        );
        assert_eq!(
            codex_counter.load(Ordering::SeqCst),
            0,
            "follower must not reach the codex transport either"
        );
        // The slot is still REPORTED — a follower polls and serves; it just
        // does not refresh. A silent omission would be indistinguishable from
        // a crashed refresher.
        let status = cache
            .get(&1)
            .expect("follower still records a status for the slot");
        assert_eq!(status.last_result, FOLLOWER_SKIP_LABEL);
        assert_eq!(status.account, 1);
    }

    #[tokio::test]
    async fn tick_in_follower_posture_does_not_refresh_a_due_codex_credential() {
        let dir = TempDir::new().unwrap();
        // install_codex_account writes an access_token with no parseable exp,
        // so exp resolves to 0 => due (and expired).
        install_codex_account(dir.path(), 3);
        crate::daemon::posture::save(dir.path(), crate::daemon::posture::DaemonPosture::Follower)
            .unwrap();

        let codex_counter = Arc::new(AtomicU32::new(0));
        let anthropic_counter = Arc::new(AtomicU32::new(0));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &counting_success(Arc::clone(&anthropic_counter)),
            &counting_codex_success(Arc::clone(&codex_counter)),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            codex_counter.load(Ordering::SeqCst),
            0,
            "follower posture must NOT refresh a codex credential"
        );
        assert_eq!(cache.get(&3).unwrap().last_result, FOLLOWER_SKIP_LABEL);
    }

    /// The leader default is what every pre-existing install gets: no posture
    /// file at all. Guards against a regression that made the gate fire on the
    /// absent-file path and silently stopped every single-host daemon from
    /// refreshing.
    #[tokio::test]
    async fn tick_with_no_posture_file_refreshes_as_leader() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);
        assert!(
            !crate::daemon::posture::posture_path(dir.path()).exists(),
            "fixture precondition: no posture file"
        );

        let counter = Arc::new(AtomicU32::new(0));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &counting_success(Arc::clone(&counter)),
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "absent posture file must keep the historical leader behaviour"
        );
    }

    /// A posture file that exists but cannot be parsed stands down rather than
    /// silently reverting to refreshing — the whole point of the fail
    /// direction documented in `crate::daemon::posture`.
    #[tokio::test]
    async fn tick_with_corrupt_posture_file_stands_down_and_does_not_refresh() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);
        std::fs::write(
            crate::daemon::posture::posture_path(dir.path()),
            "{ truncated",
        )
        .unwrap();

        let counter = Arc::new(AtomicU32::new(0));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &counting_success(Arc::clone(&counter)),
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "a corrupt posture file must not silently re-enable refreshes"
        );
        assert_eq!(cache.get(&1).unwrap().last_result, FOLLOWER_SKIP_LABEL);
    }

    #[tokio::test]
    async fn tick_skips_valid_token_without_http_call() {
        let dir = TempDir::new().unwrap();
        // Far future expiry (year 2030ish, well outside 2-hour window).
        install_account(dir.path(), 1, 9_999_999_999_999);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(counter.load(Ordering::SeqCst), 0, "no HTTP for valid token");
        let status = cache.get(&1).unwrap();
        assert_eq!(status.last_result, "valid");
    }

    /// M4-4 AC: when `profiles.json::by_slot` is populated, the refresher
    /// reads its expiry hint from `identities/<UUID>/credentials.json`
    /// (not `credentials/<N>.json`). Validated by garbaging the legacy
    /// canonical and seeding only the identity-keyed file with a valid,
    /// non-expiring credential. The refresher must read the identity-keyed
    /// expiry, see a valid token, and skip the HTTP call.
    #[tokio::test]
    async fn refresher_section_reads_identity_credentials_when_by_slot_populated() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Seed `profiles.json` with `by_slot[1] = UUID` and `accounts[1]`.
        let slot: u16 = 1;
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot);
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert(slot.to_string(), uuid);
        profiles.set_profile(
            slot,
            crate::accounts::profiles::AccountProfile {
                email: "m4-4-refresher@test.invalid".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        crate::accounts::profiles::save(&crate::accounts::profiles::profiles_path(base), &profiles)
            .unwrap();

        // Create config-1/ so the M1-6 canonicalize-at-section-entry guard
        // resolves to a real inode (discovery yields the slot; the section
        // entry checks the dir).
        std::fs::create_dir_all(base.join(format!("config-{slot}"))).unwrap();

        // Seed identity-keyed creds with VALID far-future expiry — the
        // refresher should read THIS and skip the HTTP call (no refresh
        // needed).
        let identity_creds = make_creds("at-uuid-keyed", "rt-uuid-keyed", 9_999_999_999_999);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        credentials::save(&uuid_path, &identity_creds).unwrap();

        // Seed the LEGACY canonical with valid creds at a slightly less
        // future expiry — distinct from the UUID-keyed payload. If the
        // refresher reads the legacy path by mistake, the expiry value
        // proves it (different from the identity-keyed file). For the
        // simpler valid-token-path-no-HTTP assertion below we use
        // far-future for both; the structural proof is the load failure
        // we install at the legacy path being IGNORED.
        let num = AccountNum::try_from(slot).unwrap();
        let legacy_creds = make_creds("at-LEGACY", "rt-LEGACY", 9_999_999_999_998);
        credentials::save(&cred_file::canonical_path(base, num), &legacy_creds).unwrap();

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            base,
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        // The refresher should have observed the identity-keyed expiry
        // (far-future) and skipped the HTTP call. The cache entry's
        // `expires_at_ms` must reflect the identity-keyed file, not the
        // legacy file.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "valid identity-keyed token must skip HTTP refresh"
        );
        let status = cache.get(&slot).expect("cache entry for slot 1");
        assert_eq!(status.last_result, "valid");
        assert_eq!(
            status.expires_at_ms, 9_999_999_999_999,
            "cache expires_at_ms MUST match the identity-keyed file (not the legacy 9_999_999_999_998)"
        );
    }

    #[tokio::test]
    async fn tick_failure_enters_cooldown_and_retries_skipped() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_failure(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;
        let first_calls = counter.load(Ordering::SeqCst);
        // broker_check tries refresh once, then recovery once — so 2 http calls.
        assert!(
            first_calls >= 1,
            "expected at least 1 HTTP call, got {first_calls}"
        );
        assert!(
            in_cooldown(&cooldowns, &backoffs, 1),
            "failed account must be in cooldown"
        );
        let status = cache.get(&1).unwrap();
        assert_eq!(status.last_result, "failed");

        // Second tick immediately: cooldown should prevent any new HTTP.
        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;
        let second_calls = counter.load(Ordering::SeqCst);
        assert_eq!(
            second_calls, first_calls,
            "cooldown should suppress second refresh"
        );
    }

    #[tokio::test]
    async fn tick_success_clears_cooldown() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        // Prime a cooldown that has already elapsed (simulate past failure).
        // On fresh CI runners Instant::now() may be less than FAILURE_COOLDOWN
        // since system boot, so naive subtraction would panic. `checked_sub`
        // returns None in that case and we skip — the `tick_failure_sets_cooldown`
        // test exercises the cooldown-write path on the same runner, so losing
        // coverage of the expired-cooldown path here only on fresh-boot runners
        // is an acceptable trade.
        let past = match Instant::now().checked_sub(FAILURE_COOLDOWN + Duration::from_secs(1)) {
            Some(p) => p,
            None => {
                eprintln!(
                    "SKIP tick_success_clears_cooldown: Instant::now() too close \
                     to boot to simulate an expired cooldown"
                );
                return;
            }
        };
        cooldowns.lock().unwrap().insert(1, past);

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(
            !in_cooldown(&cooldowns, &backoffs, 1),
            "expired cooldown should not block"
        );
    }

    #[tokio::test]
    async fn spawn_respects_shutdown_during_startup_delay() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let shutdown = CancellationToken::new();

        install_account(dir.path(), 1, 0);

        let cache = Arc::new(TtlCache::with_default_age());
        let handle = spawn_with_config(
            dir.path().to_path_buf(),
            cache,
            http,
            noop_codex_http(Arc::new(AtomicU32::new(0))),
            shutdown.clone(),
            Duration::from_secs(1),
            Duration::from_millis(500), // long startup delay
        );

        // Cancel immediately — before startup delay fires.
        tokio::time::sleep(Duration::from_millis(10)).await;
        shutdown.cancel();

        // Task should exit within the startup window.
        tokio::time::timeout(Duration::from_secs(2), handle.join)
            .await
            .expect("refresher did not shut down in time")
            .expect("refresher panicked");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "shutdown during startup delay should prevent any HTTP"
        );
    }

    #[tokio::test]
    async fn spawn_runs_tick_then_shutdown() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let shutdown = CancellationToken::new();

        install_account(dir.path(), 1, 0);

        let cache = Arc::new(TtlCache::with_default_age());
        let handle = spawn_with_config(
            dir.path().to_path_buf(),
            cache,
            http,
            noop_codex_http(Arc::new(AtomicU32::new(0))),
            shutdown.clone(),
            Duration::from_secs(60), // long interval so only the first tick runs
            Duration::from_millis(0), // no startup delay
        );

        // Wait for at least one tick to complete.
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown.cancel();

        tokio::time::timeout(Duration::from_secs(2), handle.join)
            .await
            .expect("refresher did not shut down in time")
            .expect("refresher panicked");

        assert!(
            counter.load(Ordering::SeqCst) >= 1,
            "at least one tick should have run"
        );
        // Verify the cache was populated.
        assert!(handle.cache.get(&1).is_some());
    }

    /// Round 9, S-C-1 / D-F1: before `run_tick_supervised` existed, a panic
    /// anywhere on the tick call graph that was NOT already individually
    /// wrapped in its own `spawn_blocking` + `JoinError` handling (the
    /// `harvest_gate` `blocking_lock`-on-a-worker bug fixed alongside this
    /// test was the concrete instance) unwound straight through `run_loop`'s
    /// own task. `keychain-fix-r10.md` C-B3: that task IS observed and
    /// restarted in production (`daemon.rs`/`daemon_supervisor.rs`'s
    /// `subsystems` lists watch `RefresherHandle::join`) — but only via a
    /// session-wide restart of EVERY subsystem, which is what would have
    /// paid for one bad tick without this wrapper.
    ///
    /// This drives a real `spawn_with_config` loop through a tick whose HTTP
    /// transport panics, and asserts the loop is STILL ALIVE to shut down
    /// cleanly on cancellation. It does NOT assert a second, recovered
    /// reconcile call — `broker_check`'s OWN `spawn_blocking` call already
    /// catches this specific panic as a `JoinError` (see `tick`'s
    /// `Err(join_err) => { ...; set_cooldown(...) }` arm) and enters the
    /// account into `FAILURE_COOLDOWN` (10 minutes), exactly as it would for
    /// any other `broker_check` failure — that pre-existing behaviour is
    /// unaffected by `run_tick_supervised` and is not what this test is
    /// checking. What `run_tick_supervised` additionally guarantees — that
    /// `run_loop` survives a panic NOT already caught by an inner call's own
    /// protection — is proven by the mechanism-level test immediately below,
    /// which does not depend on tick()'s specific call graph.
    #[tokio::test]
    async fn spawn_survives_a_panicking_tick_and_continues_refreshing() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = panicking_then_success(Arc::clone(&counter));
        let shutdown = CancellationToken::new();

        install_account(dir.path(), 1, 0);

        let cache = Arc::new(TtlCache::with_default_age());
        let handle = spawn_with_config(
            dir.path().to_path_buf(),
            cache,
            http,
            noop_codex_http(Arc::new(AtomicU32::new(0))),
            shutdown.clone(),
            Duration::from_millis(50), // short interval; only the first tick matters here
            Duration::from_millis(0),  // no startup delay
        );

        // Poll for the first (panicking) tick to have actually run, rather
        // than a fixed sleep.
        tokio::time::timeout(Duration::from_secs(5), async {
            while counter.load(Ordering::SeqCst) < 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("expected the panicking tick to run within 5s");
        shutdown.cancel();

        // The load-bearing assertion: `run_loop`'s own task did NOT panic —
        // it is still alive to observe cancellation and exit cleanly. Before
        // this fix, an unprotected panic on this call graph would have
        // unwound straight through `run_loop` and this `.expect` would fire
        // with "refresher panicked".
        tokio::time::timeout(Duration::from_secs(2), handle.join)
            .await
            .expect("refresher did not shut down in time")
            .expect("refresher panicked");

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one HTTP attempt — broker_check's OWN spawn_blocking \
             catches this panic as a JoinError and enters cooldown, so a \
             second tick within this short test window correctly does NOT \
             retry yet"
        );
        let status = handle
            .cache
            .get(&1)
            .expect("the panicking tick must still have recorded a cache entry");
        assert_eq!(
            status.last_result, "panic",
            "a broker_check panic surfaces via tick()'s OWN dedicated \
             \"panic\" cache status (distinct from a generic \"error\") \
             and cooldown — run_tick_supervised changes nothing about \
             THIS already-protected path"
        );
    }

    /// `keychain-fix-r10.md` C-I1/C-T-a: a panic placed directly in
    /// `tick_impl`'s own body (via `TICK_TEST_PANIC_HOOK`, OUTSIDE every
    /// `spawn_blocking` `tick_impl` uses internally) proves TWO things
    /// `spawn_survives_a_panicking_tick_and_continues_refreshing` cannot,
    /// because that test's panic is caught by `broker_check`'s OWN inner
    /// `spawn_blocking` before ever reaching `run_tick_supervised`'s
    /// boundary: (1) `run_tick_supervised`'s outer supervision genuinely
    /// fires (a second tick runs, `handle.join` returns `Ok`), and (2) the
    /// panic-recovery keychain sync (this round's fix) actually ran.
    ///
    /// RED: reverting `run_tick_supervised` to the pre-fix shape (no
    /// panic-recovery sync call) makes the `sync_calls_after >
    /// sync_calls_before` assertion fail — the delta is `0`, not `>= 1`,
    /// because nothing else in an idle tick with no refreshed accounts ever
    /// calls `sync_refreshed_keychains`.
    ///
    /// `keychain-fix-r11.md` D-7: the counter is keyed on THIS test's own
    /// `dir.path()` (see `SYNC_REFRESHED_KEYCHAINS_CALLS`'s doc — a shared
    /// process-wide total let an unrelated parallel test's own legitimate
    /// sync call mask the very regression this RED is supposed to catch),
    /// and the panic hook is installed via [`TickTestPanicHookGuard`] so it
    /// is reset on every exit path, including an early `.expect(...)` panic,
    /// not only the test's last line.
    #[tokio::test]
    async fn run_tick_supervised_recovers_keychain_sync_after_a_panic() {
        let dir = TempDir::new().unwrap();
        let shutdown = CancellationToken::new();

        // No accounts installed: an idle tick (no refresh, no
        // `any_anthropic_refreshed`) never calls `sync_refreshed_keychains`
        // on its own, so any call observed below is definitely the
        // panic-recovery path, not the tick's ordinary post-loop sweep.
        let hook_fired = Arc::new(AtomicU32::new(0));
        let hook_fired_for_closure = Arc::clone(&hook_fired);
        let _hook_guard = TickTestPanicHookGuard::install(Box::new(move || {
            let n = hook_fired_for_closure.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                panic!("keychain-fix-r10.md C-I1/C-T-a: injected first-tick panic");
            }
        }));

        let sync_calls_before = sync_refreshed_keychains_call_count_for_test(dir.path());

        let cache = Arc::new(TtlCache::with_default_age());
        let handle = spawn_with_config(
            dir.path().to_path_buf(),
            cache,
            counting_success(Arc::new(AtomicU32::new(0))),
            noop_codex_http(Arc::new(AtomicU32::new(0))),
            shutdown.clone(),
            Duration::from_millis(30), // short interval so a second tick runs promptly
            Duration::from_millis(0),  // no startup delay
        );

        // Poll for a SECOND hook invocation — proof the loop survived the
        // first tick's panic and reached a second tick, rather than a fixed
        // sleep hoping the timing lines up.
        tokio::time::timeout(Duration::from_secs(5), async {
            while hook_fired.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("expected a second tick to run within 5s");
        shutdown.cancel();

        tokio::time::timeout(Duration::from_secs(2), handle.join)
            .await
            .expect("refresher did not shut down in time")
            .expect("refresher panicked — run_tick_supervised did not isolate it");

        // `_hook_guard` resets the thread-local hook when it drops at the
        // end of this scope — no manual reset call needed (and none would
        // run anyway if an assertion above had panicked first).

        let sync_calls_after = sync_refreshed_keychains_call_count_for_test(dir.path());
        assert!(
            sync_calls_after > sync_calls_before,
            "a panicked tick must trigger the panic-recovery keychain sync \
             (before={sync_calls_before}, after={sync_calls_after})"
        );
    }

    /// The mechanism `run_tick_supervised` relies on, proven directly and
    /// independent of `tick()`'s own call graph: `tokio::spawn` converts a
    /// panicking future into `Err(JoinError)` when awaited, rather than
    /// unwinding into the awaiting task. This round's `tick()` already
    /// individually wraps every one of ITS OWN blocking sub-calls
    /// (`broker_check`, the custodian, the held-sweep, the outbox drain) in
    /// exactly this pattern, so an http-transport panic never reaches
    /// `run_tick_supervised`'s OWN boundary at all — see
    /// `spawn_survives_a_panicking_tick_and_continues_refreshing`'s doc.
    /// `run_tick_supervised` is the SAME pattern applied one layer further
    /// out, defending against a panic in code that is NOT (yet, or ever)
    /// individually wrapped — exactly the shape of the original D-F1 bug
    /// (`harvest_gate_mark_rate_limited`, called directly with no
    /// `spawn_blocking` around it at all, before that fix).
    ///
    /// RED: there is no code to delete to red this one — it is a proof
    /// about `tokio::spawn` itself, which `run_tick_supervised` composes
    /// unchanged. `rules/instrument-discipline.md` MUST-2 requires exactly
    /// this admission for a test that cannot red by mutation of this crate's
    /// own code.
    #[tokio::test]
    async fn a_panic_inside_spawn_is_caught_as_joinerror_not_propagated() {
        let result = tokio::spawn(async {
            panic!("injected: mechanism proof, not a real bug");
        })
        .await;
        assert!(
            matches!(&result, Err(e) if e.is_panic()),
            "a panicking spawned future must surface as Err(JoinError) to \
             the awaiting task, never as a propagating unwind"
        );
    }

    /// Mock HTTP closure that returns a rate-limit error.
    fn counting_rate_limit(counter: Arc<AtomicU32>) -> HttpPostFn {
        Arc::new(move |_url: &str, _body: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(br#"{"error":{"type":"rate_limit_error","message":"Rate limited"}}"#.to_vec())
        })
    }

    #[tokio::test]
    async fn tick_rate_limit_stops_remaining_accounts() {
        let dir = TempDir::new().unwrap();
        // Two expired accounts.
        install_account(dir.path(), 1, 0);
        install_account(dir.path(), 2, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_rate_limit(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        // Only ONE account should have attempted refresh — the second
        // should be skipped because the first hit a rate limit.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "rate-limited tick must stop after first 429, not attempt remaining accounts"
        );
    }

    #[tokio::test]
    async fn tick_rate_limit_increases_backoff() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_rate_limit(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        // First tick: hits rate limit, backoff goes 1 → 2.
        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;
        assert_eq!(get_backoff(&backoffs, 1), 2);
        assert!(in_cooldown(&cooldowns, &backoffs, 1));

        // Simulate time passing: clear the cooldown timestamp but
        // keep the backoff — this is what happens when the base
        // cooldown (10min) elapses but the backoff-scaled cooldown
        // (20min) has not.
        //
        // On Windows CI runners freshly booted, `Instant::now()` can be
        // closer to the monotonic epoch than FAILURE_COOLDOWN (10min).
        // `checked_sub` returns None in that case; the test skips
        // rather than panicking. Mirrors the sibling
        // `tick_success_clears_cooldown` guard introduced in 439b802.
        let just_past_base =
            match Instant::now().checked_sub(FAILURE_COOLDOWN + Duration::from_secs(1)) {
                Some(p) => p,
                None => {
                    eprintln!(
                        "SKIP tick_rate_limit_increases_backoff: Instant::now() too close \
                     to boot to simulate an expired cooldown"
                    );
                    return;
                }
            };
        cooldowns.lock().unwrap().insert(1, just_past_base);

        // With backoff=2, the effective cooldown is 20min. 10min+1s
        // has elapsed, so 20min hasn't — should still be in cooldown.
        assert!(
            in_cooldown(&cooldowns, &backoffs, 1),
            "backoff×2 cooldown should still be active after base cooldown elapses"
        );
    }

    /// Mock Codex HTTP closure that always returns a real 429 (the fixed
    /// shape a Node-transport call now surfaces via `NodeHttpResponse`).
    fn counting_codex_rate_limit(counter: Arc<AtomicU32>) -> HttpPostFnCodex {
        Arc::new(move |_url: &str, _body: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(crate::http::NodeHttpResponse {
                status: 429,
                body: br#"{"error":{"code":"rate_limit_exceeded"}}"#.to_vec(),
                date: None,
            })
        })
    }

    /// End-to-end regression for the defect this fix closes: before
    /// `parse_refresh_response` used the REAL status, every call site
    /// passed a literal `200`, so `broker_codex_check` could never observe
    /// a genuine upstream 429 as `BrokerResult::RateLimited` — it fell
    /// through to `BrokerResult::Failed` instead, and this tick's own
    /// `codex_rate_limited_this_tick` gate (`keychain-fix-r11.md` D-2,
    /// wired at the call site above) never had a `RateLimited` result to
    /// react to. Two expired Codex accounts, both hitting an always-429
    /// mock: the first sets the gate, the second must be skipped.
    ///
    /// RED: reverting `parse_refresh_response`'s `Some(429) => ...` arm
    /// back to shape-based classification (status ignored) makes this
    /// test fail — both accounts attempt a refresh (`counter == 2`)
    /// because the second slot's `codex_rate_limited_this_tick` gate is
    /// never set (a shape-based 429 with no recognizable envelope falls
    /// through to `CodexHttpError::MalformedResponse`, not `Upstream`,
    /// so `broker_codex_check` never returns `BrokerResult::RateLimited`).
    #[tokio::test]
    async fn tick_codex_rate_limit_stops_remaining_codex_accounts() {
        let dir = TempDir::new().unwrap();
        install_codex_account(dir.path(), 1);
        install_codex_account(dir.path(), 2);

        let counter = Arc::new(AtomicU32::new(0));
        let http_codex = counting_codex_rate_limit(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            // No Anthropic accounts installed in this fixture; unused.
            &counting_success(Arc::new(AtomicU32::new(0))),
            &http_codex,
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "codex rate-limited tick must stop after first 429, not attempt \
             remaining codex accounts"
        );
    }

    /// `keychain-fix-r10.md` S-M-1/C-B2: a validation-only 429 (the shared,
    /// IP-wide gate seeded at tick start — a stale cross-tick observation,
    /// an on-demand harvest route's own 429, or an auto-rotate 429) must
    /// NEVER skip the refresh (token) call. Only a 429 observed on THIS
    /// tick's own refresh-endpoint call may do that (see the sibling test
    /// below). Drives `tick_impl` directly with
    /// `initial_rate_limited_this_tick = true` — never
    /// `harvest_gate_is_rate_limited`/`harvest_gate_mark_rate_limited`
    /// directly, which would mutate the process-wide singleton every OTHER
    /// refresher test in this binary also reads (see `server.rs`'s
    /// `ip_rate_limit_gate` doc).
    ///
    /// RED: reverting `refresh_should_be_skipped(refresh_rate_limited_this_tick,
    /// needs_refresh)` back to the pre-fix `rate_limited_this_tick &&
    /// needs_refresh` (i.e. reusing the validation flag for the refresh
    /// decision) makes this account's refresh call skipped —
    /// `counter.load()` comes back `0` instead of the required `1`. Verified
    /// by executing that exact mutation locally: `cargo test -p csq-core --lib
    /// daemon::refresher::tests::tick_validation_only_gate_does_not_skip_refresh`
    /// failed with `assertion `left == right` failed: a validation-only 429
    /// must not skip the refresh call\n  left: 0\n right: 1` before the
    /// mutation was reverted.
    #[tokio::test]
    async fn tick_validation_only_gate_does_not_skip_refresh() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick_impl(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
            /* initial_rate_limited_this_tick = */ true,
        )
        .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "a validation-only 429 must not skip the refresh call"
        );
        let status = cache.get(&1).expect("cache entry must exist");
        assert_eq!(
            status.last_result, "refreshed",
            "the refresh must actually run (not the rate_limited short-circuit \
             label) when only the validation gate, not the refresh gate, is set"
        );
    }

    /// `keychain-fix-r11.md` D-3: `broker_check`'s own `spawn_blocking` may
    /// panic AFTER it has already written a refreshed token to the
    /// canonical credential store (e.g. on a later step such as the
    /// post-refresh re-read) — the resulting `Err(join_err)` tells us the
    /// task didn't finish cleanly, not that it wrote nothing. This account's
    /// tick must therefore still flag `any_anthropic_refreshed`, so the
    /// post-loop keychain sweep runs and CC's keychain-first read picks up
    /// whatever the panicked task actually wrote — rather than being
    /// silently stranded until the NEXT tick happens to refresh the same
    /// account again.
    ///
    /// The counter this test reads is keyed on THIS test's OWN `dir.path()`
    /// (D-7) — a shared process-wide total would let a concurrently running,
    /// unrelated test's OWN legitimate sync call mask the exact regression
    /// this RED exists to catch.
    ///
    /// RED: removing `any_anthropic_refreshed = true;` from the
    /// `Err(join_err)` arm makes the sweep-call delta `0` instead of `>= 1`.
    /// Verified by executing that exact mutation locally: `cargo test -p
    /// csq-core --lib
    /// daemon::refresher::tests::tick_broker_check_panic_still_triggers_keychain_sweep`
    /// failed with `assertion failed: sync_calls_after > sync_calls_before`
    /// (both `0`) before the line was restored.
    #[tokio::test]
    async fn tick_broker_check_panic_still_triggers_keychain_sweep() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = panicking_then_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        let sync_calls_before = sync_refreshed_keychains_call_count_for_test(dir.path());

        tick_impl(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
            /* initial_rate_limited_this_tick = */ false,
        )
        .await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "the panicking transport must have been invoked exactly once"
        );
        let status = cache.get(&1).expect("cache entry must exist");
        assert_eq!(
            status.last_result, "panic",
            "broker_check's own spawn_blocking must have caught the panic as \
             a JoinError, not propagated it"
        );

        let sync_calls_after = sync_refreshed_keychains_call_count_for_test(dir.path());
        assert!(
            sync_calls_after > sync_calls_before,
            "a panicked broker_check task must still trigger the keychain \
             sweep, in case it wrote a token before panicking \
             (before={sync_calls_before}, after={sync_calls_after})"
        );
    }

    #[tokio::test]
    async fn tick_success_clears_backoff() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);

        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        // Prime a backoff from a prior rate limit.
        backoffs.lock().unwrap().insert(1, 4);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        assert_eq!(
            get_backoff(&backoffs, 1),
            1,
            "successful refresh must clear backoff"
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // M1-6 regression: refresher canonicalization at section entry
    //
    // The 1200% cross-contamination class documented in journals 0028/0029
    // arose from post-rename inode drift: the refresher resolved `config-N/`
    // AFTER a rename had repointed the directory name to a different account's
    // inode. The tests below pin the two acceptance criteria from the task
    // spec:
    //
    //   1. tick() aborts cleanly (no HTTP call, no cache entry) when
    //      `config-N/` is renamed mid-section — the rename race test.
    //   2. tick() does NOT produce cross-account credit contamination
    //      (wrong account receiving a refresh result) when discovery yields
    //      account N but the config dir has been repurposed — the 1200%
    //      contamination regression.
    // ──────────────────────────────────────────────────────────────────────

    /// M1-6 rename-race: if `config-N/` is renamed between discovery and the
    /// per-account section, `canonicalize` fails and the section aborts
    /// cleanly — no HTTP call is made and no cache entry is written.
    ///
    /// Implementation note: `discover_anthropic` is called at the top of
    /// `tick` and produces account info based on the filesystem state AT THAT
    /// MOMENT. We simulate the rename by setting up account 1 (so discovery
    /// finds it) and then renaming the config dir BEFORE the tick runs, so the
    /// canonicalize call at section entry sees the rename.
    #[tokio::test]
    async fn m1_6_config_dir_rename_aborts_section_cleanly() {
        let dir = TempDir::new().unwrap();

        // Install account 1 with an expired token (would trigger an HTTP
        // refresh in the absence of the rename race).
        install_account(dir.path(), 1, 0);

        // Also install the live mirror (config-1/.credentials.json) so
        // discovery finds the account via the config-dir scan.
        install_live_only(dir.path(), 1, 0);

        // Rename config-1/ → config-1.bak/ BEFORE the tick runs.
        // This simulates the rename race: discovery has already seen
        // `config-1/` (in a real daemon the discovery set is computed at
        // tick start), but by the time the per-account section runs the
        // directory is gone under its original name.
        let config1 = dir.path().join("config-1");
        let config1_bak = dir.path().join("config-1.bak");
        std::fs::rename(&config1, &config1_bak).expect("rename should succeed");

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        // canonicalize failed → section aborted → no HTTP, no cache entry.
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "no HTTP call when config-N/ is renamed mid-section"
        );
        assert!(
            cache.get(&1).is_none(),
            "no cache entry when config-N/ is renamed mid-section"
        );
    }

    /// M1-6 cross-contamination regression: even when two accounts exist,
    /// the refresher MUST NOT write account-2's result into account-1's cache
    /// slot (or vice versa). This pins the 1200% phantom-usage class from
    /// journals 0028/0029.
    ///
    /// The contamination scenario: discovery returns N accounts; the
    /// per-account section iterates them. Without canonicalization, a rename
    /// of `config-N/` between discovery and the section could redirect the
    /// broker_check `base_dir` argument to a different account's config,
    /// producing a result that is then stored under the wrong account ID in
    /// the cache. The canonicalize-at-entry guard prevents this by binding the
    /// section to the pre-rename inode (or aborting cleanly if it is gone).
    ///
    /// This test verifies the no-contamination property: after a tick
    /// processing two accounts, each account's cache slot contains a result
    /// that was produced from ITS OWN credentials, identified by the HTTP call
    /// count (one call per expiring account, assigned to the correct slot).
    #[tokio::test]
    async fn m1_6_no_cross_account_contamination() {
        let dir = TempDir::new().unwrap();

        // Account 1: expired (needs refresh — will trigger HTTP).
        install_account(dir.path(), 1, 0);
        // Account 2: valid far-future token (no refresh needed).
        install_account(dir.path(), 2, 9_999_999_999_999);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &noop_codex_http(Arc::new(AtomicU32::new(0))),
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        // Exactly one HTTP call for the expired account (account 1).
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one HTTP call — only the expired account should refresh"
        );

        // Account 1 must have a "refreshed" result (expired → HTTP → success).
        let status_1 = cache.get(&1).expect("account 1 must have a cache entry");
        assert_eq!(
            status_1.account, 1,
            "account 1 cache slot must carry account 1's result, not another account's"
        );
        assert_eq!(
            status_1.last_result, "refreshed",
            "account 1 result must be 'refreshed' (expired token + successful HTTP)"
        );

        // Account 2 must have a "valid" result (no HTTP).
        let status_2 = cache.get(&2).expect("account 2 must have a cache entry");
        assert_eq!(
            status_2.account, 2,
            "account 2 cache slot must carry account 2's result, not account 1's"
        );
        assert_eq!(
            status_2.last_result, "valid",
            "account 2 result must be 'valid' (far-future expiry, no HTTP)"
        );
    }

    /// AC-16 (an internal ticket M3) — daemon-spawn-admissibility invariant pin.
    ///
    /// A Codex `AccountInfo` with `has_credentials: false` MUST NOT proceed
    /// past the daemon's Codex-branch filter in `tick`. The filter is the
    /// load-bearing invariant for Step 3.5's placement argument — if a future
    /// PR removes the `if !info.has_credentials { continue; }` guard from the
    /// Codex iteration path, this test trips and forces the Step 3.5
    /// dispatcher placement to be revisited in the same PR.
    ///
    /// The test uses the existing `tick` function and verifies that a Codex slot
    /// with no credential file produces zero HTTP calls (the daemon skips it
    /// before reaching the broker call).
    #[tokio::test]
    async fn codex_daemon_skips_no_credentials_slot() {
        use crate::accounts::{AccountInfo, AccountSource, BillingMode};
        use crate::providers::catalog::Surface;

        // Verify AccountInfo with has_credentials=false matches the struct.
        // This assertion pins the field name so a rename would require
        // updating this test.
        let info = AccountInfo {
            id: 1,
            label: "codex-1".into(),
            oauth_email: None,
            source: AccountSource::Codex,
            surface: Surface::Codex,
            method: "oauth".into(),
            has_credentials: false,
            billing_mode: BillingMode::Subscription,
        };
        // Verify the has_credentials field is false (guard existence check).
        assert!(
            !info.has_credentials,
            "AccountInfo::has_credentials must be false for a Codex slot with no credential file"
        );

        // Stage a tempdir with a Codex discovery entry that has NO credential
        // file — discover_codex will emit has_credentials: false for this slot.
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        // Write invalid JSON — discover_codex sets has_credentials=false for
        // unparseable files, which is what we want to exercise.
        std::fs::write(creds_dir.join("codex-1.json"), b"{ not valid json").unwrap();

        let http_counter = Arc::new(AtomicU32::new(0));
        let codex_counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&http_counter));
        let http_codex = noop_codex_http(Arc::clone(&codex_counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(
            dir.path(),
            &http,
            &http_codex,
            &cache,
            &cooldowns,
            &backoffs,
        )
        .await;

        // The daemon MUST have skipped the Codex slot with has_credentials=false.
        // Zero HTTP calls proves the `if !info.has_credentials { continue; }` guard fired.
        assert_eq!(
            codex_counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "daemon must NOT call the Codex HTTP transport for a slot with has_credentials=false"
        );
        assert_eq!(
            http_counter.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "daemon must NOT call the Anthropic HTTP transport for a Codex-only slot"
        );
    }

    // ── M6 an internal ticket shard B: periodic outbox-drain backstop tick ──────────────────

    /// The tick stamps the drain cycle when `csq-runs/` exists (drain-liveness
    /// signal for shard D), even when there is nothing to drain.
    #[test]
    fn run_outbox_drain_tick_stamps_when_csq_runs_exists() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("csq-runs")).unwrap();
        assert!(
            crate::audit::outbox_paths::read_outbox_drain_stamp(dir.path()).is_none(),
            "no stamp before the tick"
        );
        run_outbox_drain_tick(dir.path());
        assert!(
            crate::audit::outbox_paths::read_outbox_drain_stamp(dir.path()).is_some(),
            "periodic tick must stamp the drain cycle"
        );
    }

    /// The tick is a clean no-op (no stamp, no dir created, no panic) on a base
    /// with no `csq-runs/` — nothing can be queued without the chain dir.
    #[test]
    fn run_outbox_drain_tick_noop_without_csq_runs() {
        let dir = TempDir::new().unwrap();
        run_outbox_drain_tick(dir.path());
        assert!(
            !dir.path().join("csq-runs").exists(),
            "tick must not create csq-runs/"
        );
        assert!(
            crate::audit::outbox_paths::read_outbox_drain_stamp(dir.path()).is_none(),
            "no csq-runs → no stamp"
        );
    }

    /// Enterprise wiring: the periodic tick actually DRAINS the mcp-gate outbox
    /// (not just stamps) — stages one queued decision against a bootstrapped chain
    /// and asserts the tick drains it. Proves `run_outbox_drain_tick` calls
    /// `mcp_gate_outbox::drain_pending`, not only that the stamp fires.
    #[cfg(feature = "enterprise")]
    #[test]
    fn run_outbox_drain_tick_drains_mcp_gate_outbox() {
        use crate::audit::mcp_gate_outbox::{drain_pending, write_pending, McpGatePendingRecord};
        use crate::audit::persist::write_record_v2;
        use crate::audit::types::{
            Ed25519Signature, EventKind, EventPayload, KeyId, McpGateDecisionPayload, RecordId,
            Sha256Hex, SignedRecord,
        };

        let dir = TempDir::new().unwrap();
        let base = dir.path();

        // Bootstrap a chain genesis (an McpGateDecision seed — stands in for init).
        let boot = SignedRecord {
            schema_version: crate::audit::persist::AUDIT_SCHEMA_VERSION_TEST.to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::McpGateDecision,
            payload: EventPayload::McpGateDecision(McpGateDecisionPayload {
                session_nonce: "bootstrap".to_string(),
                record_seq: 0,
                cli: "codex".to_string(),
                tool: "bootstrap_tool".to_string(),
                verdict: "pass".to_string(),
                enforcement_fidelity: crate::audit::mcp_gate_floor::MCP_ENFORCEMENT_FIDELITY
                    .to_string(),
            }),
            ts: crate::audit::persist::current_iso8601_utc_persist(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        write_record_v2(boot, Some(base)).unwrap();

        write_pending(
            base,
            &McpGatePendingRecord::new("sess-tick", 0, "codex", "mcp__shell__exec", "block"),
        )
        .unwrap();

        run_outbox_drain_tick(base);

        // The queued decision must be gone (drained onto the chain), and the cycle
        // stamped. A residual drain confirms nothing is left to drain.
        let residual = drain_pending(base);
        assert_eq!(
            residual.seen, 0,
            "the periodic tick must have drained the queued mcp-gate decision"
        );
        assert!(
            crate::audit::outbox_paths::read_outbox_drain_stamp(base).is_some(),
            "tick stamps the drain cycle"
        );
    }
}
