//! Background usage poller.
//!
//! Polls `GET /api/oauth/usage` for each Anthropic account on a
//! regular interval, parses the response, and writes quota data
//! directly to the local `quota.json` so both `csq status` and the
//! daemon-delegated `/api/usage` route see fresh numbers.
//!
//! # Endpoint
//!
//! ```text
//! GET {base_url}/api/oauth/usage
//! Authorization: Bearer {access_token}
//! Anthropic-Beta: oauth-2025-04-20
//! Accept: application/json
//! ```
//!
//! Response (observed from v1 Python poller + Playwright):
//!
//! ```json
//! {
//!   "five_hour": { "utilization": 42.0, "resets_at": "2099-01-01T00:00:00Z" },
//!   "seven_day": { "utilization": 15.0, "resets_at": "2099-01-14T00:00:00Z" }
//! }
//! ```
//!
//! # Mapping to `QuotaFile`
//!
//! - `utilization` is already 0–100 (percentage). Store directly as `used_percentage`.
//! - `resets_at` (ISO-8601 string) → epoch `u64`: parse via a minimal
//!   RFC 3339 parser (no chrono dependency).
//!
//! # Error handling
//!
//! - **429** — rate-limited. Enter exponential backoff (2x, capped at 8x).
//! - **401** — token expired or revoked. Mark cooldown, skip until
//!   the refresher obtains a new token.
//! - **Other non-200** — transient failure. Enter normal cooldown.
//! - **Transport error** — timeout/connect refused. Normal cooldown.
//!
//! # Separation from the refresher
//!
//! The usage poller is a **separate background task** from the token
//! refresher (`daemon::refresher`). They share the same
//! `CancellationToken` for coordinated shutdown but have independent:
//!
//! - Intervals (poller: 5 min, refresher: 5 min — same now, but can
//!   diverge for 3P which uses 15 min).
//! - Cooldown maps (poller tracks 429/401 separately from refresh
//!   failures).
//! - Outputs (poller writes `quota.json`, refresher writes
//!   `RefreshStatus` cache + credential files).

pub mod anthropic;
pub mod codex;
pub mod minimax;
pub mod third_party;
pub mod zai;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing::warn;

/// Per-call timeout for blocking HTTP requests. If a single
/// `spawn_blocking` poll exceeds this, the call is abandoned and
/// the account enters cooldown. Prevents the 2026-04-12 12:17 UTC
/// hang where a stuck HTTP call blocked the entire poller.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Default interval between poller ticks: 5 minutes.
pub const POLL_INTERVAL: Duration = Duration::from_secs(300);

/// Short startup delay so the daemon finishes binding sockets
/// before the first HTTP call.
pub const STARTUP_DELAY: Duration = Duration::from_secs(5);

/// Cooldown after a failed poll: 10 minutes.
pub const FAILURE_COOLDOWN: Duration = Duration::from_secs(600);

/// Maximum accounts polled per tick (same rationale as refresher).
pub const MAX_ACCOUNTS_PER_TICK: usize = 64;

/// Default interval between 3P poller ticks: 15 minutes.
pub const POLL_INTERVAL_3P: Duration = Duration::from_secs(900);

/// Rate-limit header prefix. All 3P rate-limit headers start with this.
pub(crate) const RATELIMIT_PREFIX: &str = "anthropic-ratelimit-";

/// HTTP transport closure for the usage GET. Takes `(url, bearer_token,
/// extra_headers)` and returns `(status, body_bytes)`. Production
/// callers pass `http::get_bearer`; tests pass a mock.
pub type HttpGetFn = Arc<
    dyn Fn(&str, &str, &[(&str, &str)]) -> Result<(u16, Vec<u8>), String> + Send + Sync + 'static,
>;

/// HTTP transport closure for the 3P usage probe POST. Takes
/// `(url, headers, body)` and returns `(status, response_headers, body)`.
/// Production callers pass `http::post_json_with_headers`; tests pass
/// a mock. Response headers have lowercase keys.
pub type HttpPostProbeFn = Arc<
    dyn Fn(
            &str,
            &[(String, String)],
            &str,
        ) -> Result<(u16, HashMap<String, String>, String), String>
        + Send
        + Sync
        + 'static,
>;

/// Error from a single usage poll.
#[derive(Debug)]
pub(crate) enum PollError {
    #[allow(dead_code)]
    Transport(String),
    RateLimited,
    Unauthorized,
    HttpError(u16),
    #[allow(dead_code)]
    Parse(String),
}

/// Handle to a running usage poller task.
pub struct PollerHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns the usage poller task on the current tokio runtime.
///
/// Polls Anthropic accounts every 5 minutes and 3P accounts every
/// 15 minutes, using separate transport closures for each.
pub fn spawn(
    base_dir: PathBuf,
    http_get: HttpGetFn,
    http_post_probe: HttpPostProbeFn,
    shutdown: CancellationToken,
) -> PollerHandle {
    spawn_with_config(
        base_dir,
        http_get,
        http_post_probe,
        shutdown,
        POLL_INTERVAL,
        POLL_INTERVAL_3P,
        STARTUP_DELAY,
    )
}

/// Like [`spawn`] but with explicit intervals + startup delay for testing.
pub fn spawn_with_config(
    base_dir: PathBuf,
    http_get: HttpGetFn,
    http_post_probe: HttpPostProbeFn,
    shutdown: CancellationToken,
    interval: Duration,
    interval_3p: Duration,
    mut startup_delay: Duration,
) -> PollerHandle {
    let cooldowns: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let backoffs: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // Separate maps for 3P accounts so synthetic IDs (901, 902)
    // don't collide with Anthropic account IDs in the same range.
    let cooldowns_3p: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let backoffs_3p: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // Codex-surface circuit-breaker state lives per-account and is
    // independent of the Anthropic cooldown/backoff maps so codex's
    // 5-fail threshold cannot interfere with Anthropic's 429 handling.
    let codex_breakers: codex::BreakerMap = Arc::new(Mutex::new(HashMap::new()));

    let join = tokio::spawn(async move {
        // Supervised run loop: restarts on panic with exponential
        // backoff. Prevents a single bad tick from killing the
        // entire poller permanently.
        let mut restart_delay = Duration::from_secs(5);
        let max_restart_delay = Duration::from_secs(300);

        loop {
            let cfg = RunLoopConfig {
                base_dir: base_dir.clone(),
                http_get: Arc::clone(&http_get),
                http_post_probe: Arc::clone(&http_post_probe),
                cooldowns: Arc::clone(&cooldowns),
                backoffs: Arc::clone(&backoffs),
                cooldowns_3p: Arc::clone(&cooldowns_3p),
                backoffs_3p: Arc::clone(&backoffs_3p),
                codex_breakers: Arc::clone(&codex_breakers),
                shutdown: shutdown.clone(),
                interval,
                interval_3p,
                startup_delay,
            };

            let result = tokio::spawn(run_loop(cfg)).await;

            if shutdown.is_cancelled() {
                info!("usage poller supervisor: shutdown requested");
                return;
            }

            match result {
                Ok(()) => {
                    // run_loop exited normally (shutdown)
                    return;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        restart_in_secs = restart_delay.as_secs(),
                        "usage poller panicked — restarting"
                    );
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(restart_delay) => {}
                    }
                    restart_delay = (restart_delay * 2).min(max_restart_delay);
                    // Skip startup delay on restarts
                    startup_delay = Duration::ZERO;
                }
            }
        }
    });

    PollerHandle { join }
}

/// All state needed by the poller run loop.
struct RunLoopConfig {
    base_dir: PathBuf,
    http_get: HttpGetFn,
    http_post_probe: HttpPostProbeFn,
    /// Cooldown/backoff maps for Anthropic accounts (IDs 1..999).
    cooldowns: Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: Arc<Mutex<HashMap<u16, u32>>>,
    /// Separate maps for 3P accounts (synthetic IDs 901, 902) to
    /// prevent ID collision with Anthropic accounts in the same range.
    cooldowns_3p: Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs_3p: Arc<Mutex<HashMap<u16, u32>>>,
    /// Circuit-breaker state keyed per-Codex-account.
    codex_breakers: codex::BreakerMap,
    shutdown: CancellationToken,
    interval: Duration,
    interval_3p: Duration,
    startup_delay: Duration,
}

async fn run_loop(cfg: RunLoopConfig) {
    info!(
        anthropic_secs = cfg.interval.as_secs(),
        thirdparty_secs = cfg.interval_3p.as_secs(),
        "usage poller starting"
    );

    tokio::select! {
        _ = cfg.shutdown.cancelled() => {
            info!("usage poller cancelled during startup delay");
            return;
        }
        _ = tokio::time::sleep(cfg.startup_delay) => {}
    }

    // Track when the 3P tick last ran so we can use the Anthropic
    // interval as the main loop cadence.
    let mut last_3p_tick = Instant::now() - cfg.interval_3p; // triggers on first loop

    loop {
        use tracing::debug;
        debug!("usage poller heartbeat — tick starting");
        anthropic::tick(&cfg.base_dir, &cfg.http_get, &cfg.cooldowns, &cfg.backoffs).await;
        codex::tick(&cfg.base_dir, &cfg.http_get, &cfg.codex_breakers).await;

        if last_3p_tick.elapsed() >= cfg.interval_3p {
            third_party::tick_3p(
                &cfg.base_dir,
                &cfg.http_get,
                &cfg.http_post_probe,
                &cfg.cooldowns_3p,
                &cfg.backoffs_3p,
            )
            .await;
            last_3p_tick = Instant::now();
        }

        tokio::select! {
            _ = cfg.shutdown.cancelled() => {
                info!("usage poller cancelled, exiting loop");
                return;
            }
            _ = tokio::time::sleep(cfg.interval) => {}
        }
    }
}

// ─── Cooldown / backoff helpers ────────────────────────────

pub(crate) fn in_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) -> bool {
    let guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    match guard.get(&account) {
        Some(t) => t.elapsed() < FAILURE_COOLDOWN,
        None => false,
    }
}

pub(crate) fn set_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(account, Instant::now());
}

pub(crate) fn set_cooldown_with_backoff(
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
    account: u16,
) {
    let factor = {
        let guard = backoffs.lock().unwrap_or_else(|p| p.into_inner());
        *guard.get(&account).unwrap_or(&1)
    };
    // Simple approach: use fixed FAILURE_COOLDOWN for now. The 429 is
    // uncommon enough that fixed 10-min cooldown is adequate. The
    // backoff factor is tracked so we can scale it later if needed.
    let _ = factor;
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(account, Instant::now());
}

pub(crate) fn clear_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.remove(&account);
}

pub(crate) fn increase_backoff(backoffs: &Arc<Mutex<HashMap<u16, u32>>>, account: u16) {
    let mut guard = backoffs.lock().unwrap_or_else(|p| p.into_inner());
    let current = guard.get(&account).copied().unwrap_or(1);
    guard.insert(account, (current * 2).min(8));
}

pub(crate) fn clear_backoff(backoffs: &Arc<Mutex<HashMap<u16, u32>>>, account: u16) {
    let mut guard = backoffs.lock().unwrap_or_else(|p| p.into_inner());
    guard.remove(&account);
}
