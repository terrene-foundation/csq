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

/// HTTP transport closure for the Anthropic usage GET, additionally
/// carrying the response's `retry-after` header as a delay-seconds
/// value. Takes `(url, bearer_token, extra_headers)` and returns
/// `(status, retry_after_seconds, body_bytes)`. Production callers pass
/// `http::get_bearer_node_with_retry_after`; tests pass a mock.
///
/// Deliberately a SIBLING of [`HttpGetFn`], not a widening of it:
/// `HttpGetFn` is threaded through ~8 other poller surfaces (codex,
/// kimi, grok, zai, minimax, deepseek, third_party, the refresher, and
/// `custodian.rs`) plus every mock in their test suites, none of which
/// read `retry-after`. This type is wired ONLY into the Anthropic
/// poller (`anthropic::tick` / `anthropic::poll_anthropic_usage`).
pub type HttpGetWithRetryAfterFn = Arc<
    dyn Fn(&str, &str, &[(&str, &str)]) -> Result<(u16, Option<u64>, Vec<u8>), String>
        + Send
        + Sync
        + 'static,
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
    http_get_retry_after: HttpGetWithRetryAfterFn,
    http_post_probe: HttpPostProbeFn,
    gemini_consumer: gemini::GeminiConsumerState,
    shutdown: CancellationToken,
) -> PollerHandle {
    spawn_with_config(
        base_dir,
        http_get,
        http_get_retry_after,
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
    http_get_retry_after: HttpGetWithRetryAfterFn,
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
                http_get_retry_after: Arc::clone(&http_get_retry_after),
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
    /// Anthropic-only transport that additionally captures `retry-after`.
    /// See [`HttpGetWithRetryAfterFn`].
    http_get_retry_after: HttpGetWithRetryAfterFn,
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
        anthropic::tick(
            &cfg.base_dir,
            &cfg.http_get_retry_after,
            &cfg.cooldowns,
            &cfg.backoffs,
        )
        .await;
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

/// The cooldown map stores the moment a slot becomes ELIGIBLE AGAIN — a
/// DEADLINE, not the moment the failure happened.
///
/// It used to store the start instant, with every reader comparing
/// `elapsed() < FAILURE_COOLDOWN`. That forced a single global duration on
/// every entry, which is precisely why [`set_cooldown_with_backoff`] could
/// compute a backoff factor and then have nowhere to put it (it ended in
/// `let _ = factor;` — see the Origin note on that function). Storing the
/// deadline lets each entry carry its own wait without changing any of the
/// ~68 call sites of these four helpers.
///
/// Pre-existing tests that insert a far-past `Instant` directly to simulate an
/// expired cooldown keep working unchanged: under the old reading a past
/// instant meant "elapsed long ago", and under this one it means "deadline
/// passed". Same verdict, same intent.
pub(crate) fn in_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) -> bool {
    let guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    match guard.get(&account) {
        Some(deadline) => Instant::now() < *deadline,
        None => false,
    }
}

pub(crate) fn set_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(account, Instant::now() + FAILURE_COOLDOWN);
}

/// Cooldown scaled by this account's backoff factor (1, 2, 4, 8 — see
/// [`increase_backoff`]), so repeated rate-limiting backs off instead of
/// retrying on a fixed clock forever.
///
/// # Origin — this function did nothing for the factor it is named after
///
/// It read the factor and discarded it: `let _ = factor;`, under a comment
/// saying "the 429 is uncommon enough that fixed 10-min cooldown is adequate
/// … so we can scale it later if needed". Meanwhile the module header claimed
/// "**429** — rate-limited. Enter exponential backoff (2x, capped at 8x)",
/// which the code did not do — a property claim with no mechanism behind it
/// (`doc-property-claims.md` MUST-1).
///
/// Observed 2026-09-10: an UNAUTHENTICATED `GET api.anthropic.com/api/oauth/usage`
/// returned `429` with `retry-after: 2912` from this host. That single
/// data point does not establish anything about authenticated poller
/// traffic (an unauthenticated request may simply be rejected
/// differently — no comparison was run against the authenticated path,
/// so no throttle claim follows from it; `instrument-discipline.md`
/// MUST-1), and it is NOT a basis for sizing this function's ceiling —
/// see `set_cooldown_with_backoff_and_retry_after` below, which honors
/// whatever `retry-after` value a REAL 429 on the authenticated path
/// actually carries, rather than this function's fixed 8x cap trying to
/// guess it. `refresher.rs` had the correct scaling shape all along
/// (`FAILURE_COOLDOWN * factor` at its own cooldown check), so applying
/// the factor here was a parity gap between two cooldown
/// implementations, one live and one inert — that gap, not any
/// particular wait duration, is what this function fixes.
///
/// The factor-8 CAP itself (`increase_backoff`'s `.min(8)`, and
/// therefore this function's 4800s ceiling on the no-`retry-after`
/// path) is NOT re-derived by this fix and carries no measured
/// justification here — it is inherited from the pre-existing
/// `increase_backoff` and left unverified. `set_cooldown_with_backoff_and_retry_after`
/// sidesteps the question for any 429 that carries a `retry-after`
/// value (it honors that value directly, uncapped by the factor-8
/// ceiling); this function's own 4800s ceiling remains the fallback
/// for every case with no server-stated wait — timeouts, and 429s
/// answered without the header.
pub(crate) fn set_cooldown_with_backoff(
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
    account: u16,
) {
    let factor = {
        let guard = backoffs.lock().unwrap_or_else(|p| p.into_inner());
        *guard.get(&account).unwrap_or(&1)
    };
    let wait = FAILURE_COOLDOWN.saturating_mul(factor);
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(account, Instant::now() + wait);
}

/// Like [`set_cooldown_with_backoff`], but additionally honors the
/// server's `retry-after` value (delay-seconds; already normalised to
/// `None` for anything that wasn't a validated digit run — see
/// [`crate::http::get_bearer_node_with_retry_after`]) by never setting a
/// SHORTER cooldown than either the backoff-scaled wait or the server's
/// stated wait.
///
/// # Why `max`, not "prefer the server value"
///
/// The server's stated wait and this account's own backoff escalation
/// are two INDEPENDENT lower bounds on how long to wait, not two
/// competing estimates of the same thing: `retry-after` describes what
/// THIS response asked for, while the backoff factor accumulates across
/// an account's OWN consecutive failures (`increase_backoff`) and is
/// what stops this poller from re-triggering the exact throttle it is
/// waiting out on a fixed clock (see `set_cooldown_with_backoff`'s
/// Origin note). A server value shorter than the already-escalated
/// backoff is UNDETERMINED evidence that the throttle cleared — not
/// proof of it — and this account already failed enough times to earn
/// the longer wait; honoring the shorter value would erase that
/// escalation the moment ANY `retry-after` came back, including a stale
/// or partially-recovered one. Taking the max means the wait can only
/// ever grow to reflect new information, mirroring how
/// `increase_backoff` itself only escalates and never un-escalates on
/// its own.
///
/// This single `max` also covers every case the header can present
/// without a separate branch: absent (`None` → zero-duration server
/// term → backoff wins, unchanged from `set_cooldown_with_backoff`),
/// unparseable (normalised to `None` upstream, same as absent), and
/// present-and-larger (server term dominates) or present-and-smaller
/// (backoff term dominates) — every one of the four cases this
/// function's test module below pins.
pub(crate) fn set_cooldown_with_backoff_and_retry_after(
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
    account: u16,
    retry_after_secs: Option<u64>,
) {
    let factor = {
        let guard = backoffs.lock().unwrap_or_else(|p| p.into_inner());
        *guard.get(&account).unwrap_or(&1)
    };
    let backoff_wait = FAILURE_COOLDOWN.saturating_mul(factor);
    let server_wait = retry_after_secs
        .map(Duration::from_secs)
        .unwrap_or(Duration::ZERO);
    let wait = backoff_wait.max(server_wait);
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.insert(account, Instant::now() + wait);
}

pub(crate) fn clear_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard.remove(&account);
}

/// Returns the remaining wait until `account`'s cooldown clears, or
/// `None` if it is not currently cooling down. `Instant` is monotonic and
/// carries no wall-clock epoch of its own; callers that need to persist a
/// cooldown deadline (`PollerHealth::cooldown_until`) convert this
/// `Duration` to `now_epoch() + remaining` at the point of use, so the
/// persisted value is read from the SAME map `tick`'s in-memory gating
/// consults, not a second independent computation.
pub(crate) fn cooldown_remaining(
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    account: u16,
) -> Option<Duration> {
    let guard = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
    guard
        .get(&account)
        .map(|deadline| deadline.saturating_duration_since(Instant::now()))
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

#[cfg(test)]
mod cooldown_backoff_tests {
    use super::*;

    /// Named so the pair does not trip `clippy::type_complexity` — CI lints
    /// `--all-targets`, which reaches this test module; a `--lib`-only clippy
    /// does not, which is how this got past a local run.
    type Cooldowns = Arc<Mutex<HashMap<u16, Instant>>>;
    type Backoffs = Arc<Mutex<HashMap<u16, u32>>>;

    fn maps() -> (Cooldowns, Backoffs) {
        (
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashMap::new())),
        )
    }

    /// Remaining wait for `account`, or `None` if it is not in cooldown.
    fn remaining(cooldowns: &Cooldowns, account: u16) -> Option<Duration> {
        let guard = cooldowns.lock().unwrap();
        guard
            .get(&account)
            .map(|d| d.saturating_duration_since(Instant::now()))
    }

    /// THE regression this module shipped: `set_cooldown_with_backoff` read the
    /// factor and threw it away (`let _ = factor;`), so a rate-limited account
    /// retried on a flat 600s clock no matter how many times it was refused.
    ///
    /// Asserted as a RATIO against the un-escalated cooldown rather than against
    /// a wall-clock constant, so the case stays meaningful if FAILURE_COOLDOWN
    /// is ever retuned. A test pinning "3600s" would pass on a broken
    /// implementation the day someone edits the constant to match.
    #[test]
    fn backoff_factor_actually_scales_the_cooldown() {
        let (cooldowns, backoffs) = maps();

        set_cooldown_with_backoff(&cooldowns, &backoffs, 1);
        let base = remaining(&cooldowns, 1).expect("slot 1 should be in cooldown");

        increase_backoff(&backoffs, 2);
        increase_backoff(&backoffs, 2);
        set_cooldown_with_backoff(&cooldowns, &backoffs, 2);
        let scaled = remaining(&cooldowns, 2).expect("slot 2 should be in cooldown");

        let ratio = scaled.as_secs_f64() / base.as_secs_f64();
        assert!(
            (3.9..=4.1).contains(&ratio),
            "backoff factor 4 must scale the cooldown ~4x; got {ratio:.3}x \
             (base {base:?}, scaled {scaled:?}). A ratio of 1.0 is the \
             `let _ = factor;` regression."
        );
    }

    /// The cap is real: 1 -> 2 -> 4 -> 8 -> 8, never 16.
    #[test]
    fn backoff_factor_is_capped_at_eight() {
        let (cooldowns, backoffs) = maps();
        for _ in 0..6 {
            increase_backoff(&backoffs, 7);
        }
        set_cooldown_with_backoff(&cooldowns, &backoffs, 7);
        let scaled = remaining(&cooldowns, 7).expect("slot 7 should be in cooldown");

        set_cooldown(&cooldowns, 8);
        let base = remaining(&cooldowns, 8).expect("slot 8 should be in cooldown");

        let ratio = scaled.as_secs_f64() / base.as_secs_f64();
        assert!(
            (7.9..=8.1).contains(&ratio),
            "backoff must cap at 8x, got {ratio:.3}x"
        );
    }

    // ─── set_cooldown_with_backoff_and_retry_after ────────────
    //
    // The four cases the function's own doc claims it handles: header
    // present and honored, header absent (falls back to backoff), header
    // unparseable (same as absent -- the JS emission layer already
    // normalised it to `None` before this function ever sees it), and a
    // server value SHORTER than the current backoff (backoff wins, never
    // shortened). Ratio-asserted against the plain `set_cooldown_with_backoff`
    // baseline for the same reason `backoff_factor_actually_scales_the_cooldown`
    // above is: a test pinning a wall-clock constant would pass on a broken
    // implementation the day `FAILURE_COOLDOWN` is retuned.

    /// Header present and LARGER than the backoff-scaled wait: the
    /// server's value must win. account 1 has factor 1 (backoff wait =
    /// FAILURE_COOLDOWN, 600s); an arbitrarily large retry-after (2000s
    /// -- a round test constant, not tied to any specific measured
    /// value) must produce a cooldown close to 2000s, not 600s.
    #[test]
    fn retry_after_honored_when_longer_than_backoff() {
        let (cooldowns, backoffs) = maps();
        const SERVER_WAIT_SECS: u64 = 2000;

        set_cooldown_with_backoff_and_retry_after(&cooldowns, &backoffs, 1, Some(SERVER_WAIT_SECS));
        let wait = remaining(&cooldowns, 1).expect("slot 1 should be in cooldown");

        assert!(
            wait.as_secs_f64() > FAILURE_COOLDOWN.as_secs_f64() * 3.0,
            "a {SERVER_WAIT_SECS}s retry-after must dominate a 600s (factor-1)              backoff wait; got {wait:?}"
        );
        // Upper-bound sanity: the server's value, not something larger still
        // (e.g. an accidental double-application of the factor).
        assert!(
            wait.as_secs_f64() <= SERVER_WAIT_SECS as f64 + 1.0,
            "cooldown must not exceed the server's stated wait when it              dominates; got {wait:?}"
        );
    }

    /// Header ABSENT (`None`): falls back to the plain backoff-scaled wait,
    /// unchanged from `set_cooldown_with_backoff`. Ratio-asserted against
    /// that function's own output so this stays meaningful across a
    /// `FAILURE_COOLDOWN` retune.
    #[test]
    fn retry_after_absent_falls_back_to_backoff() {
        let (cooldowns_a, backoffs_a) = maps();
        increase_backoff(&backoffs_a, 1);
        set_cooldown_with_backoff(&cooldowns_a, &backoffs_a, 1);
        let plain = remaining(&cooldowns_a, 1).expect("plain: slot 1 in cooldown");

        let (cooldowns_b, backoffs_b) = maps();
        increase_backoff(&backoffs_b, 1);
        set_cooldown_with_backoff_and_retry_after(&cooldowns_b, &backoffs_b, 1, None);
        let with_none = remaining(&cooldowns_b, 1).expect("with-None: slot 1 in cooldown");

        let ratio = with_none.as_secs_f64() / plain.as_secs_f64();
        assert!(
            (0.95..=1.05).contains(&ratio),
            "a None retry-after must match the plain backoff wait; got              plain={plain:?} with_none={with_none:?} ratio={ratio:.3}"
        );
    }

    /// Header UNPARSEABLE at the transport layer normalises to `None`
    /// before this function is ever called (see
    /// `http::get_bearer_node_with_retry_after`'s doc — the JS side emits
    /// an empty line for anything that fails `/^\d+$/`, and the Rust
    /// side's `retry_after_str.is_empty()` branch turns that into `None`).
    /// This function therefore cannot distinguish "absent" from
    /// "unparseable" by design; this test pins that `None` -- regardless
    /// of which of the two produced it -- never PANICS and never shortens
    /// the wait below the backoff floor, which is the only guarantee this
    /// function itself is responsible for.
    #[test]
    fn retry_after_none_never_panics_or_shortens_below_backoff() {
        let (cooldowns, backoffs) = maps();
        for _ in 0..2 {
            increase_backoff(&backoffs, 1); // factor 4
        }
        let unescalated = FAILURE_COOLDOWN;

        set_cooldown_with_backoff_and_retry_after(&cooldowns, &backoffs, 1, None);
        let wait = remaining(&cooldowns, 1).expect("slot 1 should be in cooldown");

        assert!(
            wait.as_secs_f64() >= unescalated.as_secs_f64() * 3.9,
            "a None retry-after must not shorten the wait below the              factor-4 backoff floor; got {wait:?}"
        );
    }

    /// Header present but SHORTER than the current backoff: backoff wins,
    /// the cooldown is NEVER shortened by a server value. account 1 has
    /// factor 8 (backoff wait = 8 * FAILURE_COOLDOWN = 4800s); a 5s
    /// retry-after must not shrink the wait anywhere near 5s.
    #[test]
    fn retry_after_shorter_than_backoff_never_shortens_it() {
        let (cooldowns, backoffs) = maps();
        for _ in 0..6 {
            increase_backoff(&backoffs, 1); // factor capped at 8
        }

        set_cooldown_with_backoff_and_retry_after(&cooldowns, &backoffs, 1, Some(5));
        let wait = remaining(&cooldowns, 1).expect("slot 1 should be in cooldown");

        assert!(
            wait.as_secs_f64() > FAILURE_COOLDOWN.as_secs_f64() * 7.0,
            "a 5s retry-after must never shorten an already-escalated              (factor 8) backoff wait; got {wait:?}"
        );
    }

    /// `in_cooldown` reads the stored value as a DEADLINE. A far-past instant —
    /// what the pre-existing poller tests insert directly to simulate an expired
    /// cooldown — must still read as "not in cooldown", or this representation
    /// change silently breaks them.
    #[test]
    fn a_past_instant_reads_as_expired_not_active() {
        let (cooldowns, _backoffs) = maps();
        // Windows measures `Instant` from SYSTEM BOOT, so on a freshly-booted CI
        // runner `Instant::now()` can be less than FAILURE_COOLDOWN and a
        // `checked_sub(FAILURE_COOLDOWN + 1s)` underflows to None. This test
        // shipped with `.expect(...)` on that and panicked on windows-latest:
        //
        //   panicked at mod.rs:575: monotonic clock far enough from its epoch
        //
        // `refresher.rs` and `anthropic.rs` already document the same hazard and
        // handle it by SKIPPING when the clock is too close to boot. This does
        // better: a deadline of `now` needs no subtraction at all. By the time
        // `in_cooldown` reads the clock again, monotonicity guarantees the second
        // reading is >= this one, so `Instant::now() < deadline` is false and the
        // slot reads as expired — on every platform, at any distance from boot,
        // with no case skipped and no coverage lost.
        let already_expired = Instant::now();
        cooldowns.lock().unwrap().insert(3, already_expired);
        assert!(
            !in_cooldown(&cooldowns, 3),
            "a deadline in the past must not hold the slot in cooldown"
        );
    }

    /// A freshly-set cooldown IS active — the other half of the pair above,
    /// without which the test cannot distinguish a working `in_cooldown` from
    /// one that always returns false.
    #[test]
    fn a_freshly_set_cooldown_is_active() {
        let (cooldowns, _backoffs) = maps();
        set_cooldown(&cooldowns, 4);
        assert!(
            in_cooldown(&cooldowns, 4),
            "just-set cooldown must be active"
        );
        clear_cooldown(&cooldowns, 4);
        assert!(
            !in_cooldown(&cooldowns, 4),
            "cleared cooldown must be inactive"
        );
    }
}
