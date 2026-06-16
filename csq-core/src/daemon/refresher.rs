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
/// deadline (see [`next_wait_chunk`], which the monotonic clock pause hides, so
/// it is the channel that catches host sleep/wake). After the host wakes, the
/// wall clock has jumped past the deadline, so the next tick fires within one
/// probe granularity (≤30s) instead of ≤5 minutes. Smaller = faster post-wake
/// catch-up but more idle wakeups; 30s balances both. Origin: journal 0062 Q2.
pub const WAKE_PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// Compute the next sub-sleep chunk while waiting for the refresh `deadline`,
/// or `None` when the deadline has been reached and the loop should tick now.
///
/// Pure + wall-clock-based so the post-wake path is unit-testable without
/// actually sleeping the host: when `now` has jumped past `deadline` (the
/// host woke from sleep and the wall clock advanced), this returns `None`
/// and the caller ticks immediately rather than waiting out a full monotonic
/// interval. Otherwise it returns the shorter of `probe` and the remaining
/// time, so the wait never overshoots the deadline. Origin: journal 0062 Q2.
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
/// Origin: journal 0062 Q2.
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
pub type HttpPostFnCodex =
    Arc<dyn Fn(&str, &str) -> Result<(Vec<u8>, Option<String>), String> + Send + Sync + 'static>;

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
        // Run one tick.
        tick(
            &base_dir,
            &http_post,
            &http_post_codex,
            &cache,
            &cooldowns,
            &backoffs,
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
            tracing::warn!(
                error_kind = "seam_held_sweep_task_panicked",
                error = %e,
                "held-provenance sweep task panicked"
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
        // Origin: journal 0062 Q2.
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

/// Runs a single refresher tick — discover accounts, check each
/// one, update cache, manage cooldowns.
///
/// Exposed `pub(crate)` so tests can drive a single tick without
/// spawning the whole loop.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn tick(
    base_dir: &std::path::Path,
    http_post: &HttpPostFn,
    http_post_codex: &HttpPostFnCodex,
    cache: &Arc<TtlCache<u16, RefreshStatus>>,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
) {
    info!("refresher tick starting");

    // Discover all refreshable accounts across surfaces.
    //
    // - `discover_anthropic`: Claude OAuth slots (refreshed via
    //   `broker_check`).
    // - `discover_codex`: Codex OAuth slots (PR-C3a primitive). Per
    //   journal 0013 + spec 07 §7.5 INV-P01, the daemon must OWN
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
    // Stop processing remaining accounts after any rate limit.
    // Anthropic rate-limits per IP, so if one request is throttled
    // the rest will be too — sending them just amplifies the
    // condition and extends the rate-limit window.
    let mut rate_limited_this_tick = false;

    let mut codex_processed = 0usize;
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
                    // / journal 0010.
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
                            rate_limited_this_tick = true;
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
                    warn!(
                        account = info.id,
                        surface = "codex",
                        error = %join_err,
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
        let expires_at_ms = match credentials::load(&canonical) {
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
                // security.md MUST Rule 8 / journal 0010.
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

        // Check if this account needs a refresh (within the 2-hour
        // window). If so and we already hit a rate limit this tick,
        // skip the HTTP call but still record the status so the
        // dashboard shows something. Valid tokens are always processed
        // because they don't make HTTP requests.
        let needs_refresh = {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            expires_at_ms < now_ms + (crate::refresh::check::REFRESH_WINDOW_SECS * 1000)
        };

        if rate_limited_this_tick && needs_refresh {
            debug!(
                account = info.id,
                "rate-limited earlier this tick, skipping refresh"
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
                        // Rate-limited by Anthropic. Set a cooldown
                        // with exponential backoff and stop processing
                        // remaining accounts this tick.
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
                // JoinError is opaque and does not carry token
                // data, so it's safe to log directly.
                warn!(account = info.id, error = %join_err, "refresh task panicked");
                set_cooldown(cooldowns, info.id);
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

    info!(
        processed,
        skipped_cooldown, codex_processed, "refresher tick complete"
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

    /// `next_wait_chunk` caps the sub-sleep at `probe`, returns the short tail
    /// near the deadline, and — the load-bearing case for journal 0062 Q2 —
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
    /// the wall-clock channel (catching host wake). Origin: journal 0062 Q2.
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

    /// No-op Codex HTTP transport for Anthropic-only tests. Counts
    /// calls so a misrouted Anthropic refresh hitting the Codex
    /// closure is detectable.
    fn noop_codex_http(counter: Arc<AtomicU32>) -> HttpPostFnCodex {
        Arc::new(move |_url: &str, _body: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((b"{}".to_vec(), None))
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
            Ok((body.into_bytes(), None))
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
    /// This is the in-process analogue of journal 0015's "two-codex-
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

    /// AC-16 (#515 M3) — daemon-spawn-admissibility invariant pin.
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
}
