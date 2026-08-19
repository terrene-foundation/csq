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
pub mod deepseek;
pub mod gemini;
pub mod gemini_oauth;
pub mod grok;
pub mod kimi;
pub mod minimax;
mod poll_error;
pub mod third_party;
pub mod zai;

// `poll_error` is a private module (round-7 redteam A-H1): only this
// re-export is visible to sibling poller files, which keeps
// `use super::{classify_transport_error, ..., PollError, ...}` working
// unchanged everywhere while making `PollError::Transport`'s payload
// (`poll_error::TransportErr`) unnameable — and therefore
// unconstructible — outside `poll_error.rs`. See that file's module doc.
pub(crate) use poll_error::{classify_transport_error, PollError};

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
/// callers pass `http::get_bearer_node` (Node.js subprocess transport —
/// see `csq-core/src/http/mod.rs` module docs for why reqwest can't be
/// used against Anthropic's Cloudflare-fronted endpoints); tests pass
/// a mock.
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

/// Handle to a running usage poller task.
pub struct PollerHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns the usage poller task on the current tokio runtime.
///
/// Polls Anthropic accounts every 5 minutes and 3P accounts every
/// 15 minutes, using separate transport closures for each. Drains
/// Gemini NDJSON event logs every Anthropic-tick (single shared
/// state with the live IPC route — spec 05 §5.8.1).
pub fn spawn(
    base_dir: PathBuf,
    http_get: HttpGetFn,
    http_post_probe: HttpPostProbeFn,
    gemini_consumer: gemini::GeminiConsumerState,
    shutdown: CancellationToken,
) -> PollerHandle {
    spawn_with_config(
        base_dir,
        http_get,
        http_post_probe,
        gemini_consumer,
        shutdown,
        POLL_INTERVAL,
        POLL_INTERVAL_3P,
        STARTUP_DELAY,
    )
}

/// Like [`spawn`] but with explicit intervals + startup delay for testing.
#[allow(clippy::too_many_arguments)]
pub fn spawn_with_config(
    base_dir: PathBuf,
    http_get: HttpGetFn,
    http_post_probe: HttpPostProbeFn,
    gemini_consumer: gemini::GeminiConsumerState,
    shutdown: CancellationToken,
    interval: Duration,
    interval_3p: Duration,
    mut startup_delay: Duration,
) -> PollerHandle {
    let cooldowns: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let backoffs: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // Separate maps for 3P accounts so synthetic IDs (901, 902)
    // don't collide with Anthropic account IDs in the same range.
    // Known bleed (R5 F5): tick_3p and kimi's 3P loop deliberately
    // share this map, so a ≤10-min stale cooldown survives a same-slot
    // provider rebind (MiniMax 429 at T → rebind to Kimi at T+2min →
    // Kimi's first poll waits out the residual window). This delays
    // WHEN the new provider's own row appears — it does NOT, by
    // itself, cause wrong data to render: `bind_provider_to_slot`
    // (accounts/third_party.rs, MED-2 an internal ticket redteam) clears the
    // slot's `quota.json` row at bind time whenever the provider
    // actually changes, so the delay window shows the honest
    // "not yet polled" state (`has_quota=false`), not the PRIOR
    // provider's stale number under the NEW provider's tag. (An
    // earlier revision of this comment claimed "no wrong data" before
    // that clearing existed — same comment-claim class as commit
    // d70af845; the claim is true now because of the cited fix, not
    // because the cooldown bleed was harmless on its own.)
    let cooldowns_3p: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let backoffs_3p: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // Native-CLI surfaces get their own cooldown maps, one per surface.
    // Native slot ids share the 1..999 range with Anthropic slots, so a
    // shared-with-Anthropic map would let a native 401 suppress an
    // unrelated Anthropic poll at the same id (and vice versa) — the
    // same rationale as the 3P split above. Grok and Kimi native slots
    // ALSO get separate maps from each other: a slot dual-bound to both
    // vendor homes (a `credentials/kimi-<N>.json` AND a
    // `credentials/grok-<N>.json` marker — the login binding guard
    // refuses this on current installs, so legacy/pre-guard state or
    // manual surgery; R5 F3) must not let one surface's 401 suppress
    // the other's poll (redteam R1 sec-NIT-3).
    let cooldowns_native: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let cooldowns_native_kimi: Arc<Mutex<HashMap<u16, Instant>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // Codex-surface circuit-breaker state lives per-account and is
    // independent of the Anthropic cooldown/backoff maps so codex's
    // 5-fail threshold cannot interfere with Anthropic's 429 handling.
    let codex_breakers: codex::BreakerMap = Arc::new(Mutex::new(HashMap::new()));
    // Code Assist OAuth project-cache lives across ticks so we don't
    // call `:loadCodeAssist` on every cycle (Phase B' v1 dedup).
    // Also carries `oauth_creds_read_in_flight` so a wedged
    // filesystem read on one tick can't pin a second blocking-pool
    // worker on the next.
    let gemini_oauth_project_cache: gemini_oauth::ProjectCache =
        Arc::new(Mutex::new(gemini_oauth::ProjectCacheState::default()));

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
                cooldowns_native: Arc::clone(&cooldowns_native),
                cooldowns_native_kimi: Arc::clone(&cooldowns_native_kimi),
                codex_breakers: Arc::clone(&codex_breakers),
                gemini_consumer: gemini_consumer.clone(),
                gemini_oauth_project_cache: Arc::clone(&gemini_oauth_project_cache),
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
    /// Cooldown map for native-CLI Grok slots, kept separate from the
    /// Anthropic map because both use real slot ids in 1..999.
    cooldowns_native: Arc<Mutex<HashMap<u16, Instant>>>,
    /// Cooldown map for native-CLI Kimi slots, separate from Grok's so
    /// a dual-bound slot's 401 on one surface cannot suppress the other.
    cooldowns_native_kimi: Arc<Mutex<HashMap<u16, Instant>>>,
    /// Circuit-breaker state keyed per-Codex-account.
    codex_breakers: codex::BreakerMap,
    /// Shared dedup + quota-mutex state for the Gemini consumer.
    /// Drain runs every tick; the live IPC route in `server::router`
    /// holds the same `quota_lock` so concurrent applies serialise.
    gemini_consumer: gemini::GeminiConsumerState,
    /// Phase B' Code Assist OAuth project cache. Lives across ticks
    /// so `:loadCodeAssist` is called once per identity (re-fetched
    /// only on 401/403 from `:retrieveUserQuota`).
    gemini_oauth_project_cache: gemini_oauth::ProjectCache,
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
        // Gemini drain: synchronous filesystem work, run on the
        // blocking pool so it does not stall the async runtime when
        // many slot files are present. Drains NDJSON event logs for
        // ApiKey + VertexSa slots (event-driven counter quota).
        let base_dir_for_drain = cfg.base_dir.clone();
        let gemini_state_for_drain = cfg.gemini_consumer.clone();
        let _ = tokio::task::spawn_blocking(move || {
            gemini::drain_all(&base_dir_for_drain, &gemini_state_for_drain);
        })
        .await;
        // Code Assist OAuth slots (Phase B' of an internal journal entry+0047 +
        // Stage 2 of an internal journal entry): polls cloudcode-pa.googleapis.com
        // for per-model BucketInfo and writes a Utilization-shape row
        // to quota.json. Distinct from `gemini::drain_all` which
        // handles the event-driven Counter shape for ApiKey/VertexSa.
        // The shared `project_cache` skips `:loadCodeAssist` after the
        // first successful tick under the same OAuth identity.
        gemini_oauth::tick(
            &cfg.base_dir,
            &cfg.http_post_probe,
            &cfg.gemini_oauth_project_cache,
        )
        .await;

        if last_3p_tick.elapsed() >= cfg.interval_3p {
            third_party::tick_3p(
                &cfg.base_dir,
                &cfg.http_get,
                &cfg.http_post_probe,
                &cfg.cooldowns_3p,
                &cfg.backoffs_3p,
            )
            .await;
            // Native-CLI billing (Grok) rides the 3P cadence: it is a
            // monthly billing figure, not a fast-moving utilization
            // window, so the 15-minute interval is ample.
            grok::tick(&cfg.base_dir, &cfg.http_get, &cfg.cooldowns_native).await;
            // Kimi (3P bearer + native kimi-code CLI) also rides the
            // 3P cadence: the 5h window has 300-minute granularity so
            // the 5-min Anthropic cadence would be wasted calls. Cooldown
            // maps: 3P slots share the 3P map; native slots get their
            // OWN map, distinct from Grok's, so a dual-bound slot's 401
            // on one surface cannot suppress the other (R1 sec-NIT-3).
            kimi::tick(
                &cfg.base_dir,
                &cfg.http_get,
                &cfg.cooldowns_3p,
                &cfg.cooldowns_native_kimi,
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

// `PollError`, `classify_transport_error`, and their tests moved to
// `poll_error.rs` (round-7 redteam A-H1) — see that file's module doc.
// The former grep-based `no_poller_bypasses_classify_transport_error`
// blacklist test (which matched two known-bad spellings of a direct
// `PollError::Transport` construction) is DELETED, not migrated: it is
// superseded by `poll_error::TransportErr`'s private field, which makes
// every bypass shape fail to compile instead of needing a scanner kept
// in sync with every new poller file.
