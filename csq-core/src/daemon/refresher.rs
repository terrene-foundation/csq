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
//! # Cooldown
//!
//! Any account that fails a refresh enters a 10-minute cooldown.
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
use crate::broker::check::{broker_check, BrokerResult};
use crate::credentials::{self, file as cred_file};
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

/// Cooldown after a failed refresh: 10 minutes.
pub const FAILURE_COOLDOWN: Duration = Duration::from_secs(600);

/// Short initial delay before the first tick so the daemon has
/// time to finish starting up (bind sockets, initialize subsystems)
/// before we start making HTTP calls.
pub const STARTUP_DELAY: Duration = Duration::from_secs(3);

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
            BrokerResult::Recovered => "recovered",
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
    shutdown: CancellationToken,
) -> RefresherHandle {
    spawn_with_config(
        base_dir,
        cache,
        http_post,
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
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
) -> RefresherHandle {
    let cache_for_task = Arc::clone(&cache);
    let cooldowns: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    let join = tokio::spawn(async move {
        run_loop(
            base_dir,
            http_post,
            cache_for_task,
            cooldowns,
            shutdown,
            interval,
            startup_delay,
        )
        .await;
    });

    RefresherHandle { join, cache }
}

async fn run_loop(
    base_dir: PathBuf,
    http_post: HttpPostFn,
    cache: Arc<TtlCache<u16, RefreshStatus>>,
    cooldowns: Arc<Mutex<HashMap<u16, Instant>>>,
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
        tick(&base_dir, &http_post, &cache, &cooldowns).await;

        // Wait for the next interval or cancellation.
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("refresher cancelled, exiting loop");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// Runs a single refresher tick — discover accounts, check each
/// one, update cache, manage cooldowns.
///
/// Exposed `pub(crate)` so tests can drive a single tick without
/// spawning the whole loop.
pub(crate) async fn tick(
    base_dir: &std::path::Path,
    http_post: &HttpPostFn,
    cache: &Arc<TtlCache<u16, RefreshStatus>>,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
) {
    debug!("refresher tick starting");

    // Discover all Anthropic accounts. (Third-party accounts do not
    // have refresh tokens; the usage poller in M8.5 handles them.)
    let mut accounts = discovery::discover_anthropic(base_dir);

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

    for info in accounts {
        if info.source != AccountSource::Anthropic || !info.has_credentials {
            continue;
        }

        let account = match AccountNum::try_from(info.id) {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Cooldown check: skip accounts that recently failed.
        if in_cooldown(cooldowns, info.id) {
            skipped_cooldown += 1;
            debug!(account = info.id, "in cooldown, skipping");
            continue;
        }

        // Read expires_at for the cache record even if no refresh
        // is needed.
        let canonical = cred_file::canonical_path(base_dir, account);
        let expires_at_ms = match credentials::load(&canonical) {
            Ok(c) => c.claude_ai_oauth.expires_at,
            Err(e) => {
                debug!(account = info.id, error = %e, "could not read canonical");
                continue;
            }
        };

        // Run broker_check inside spawn_blocking because it does
        // blocking file IO and may invoke the synchronous HTTP
        // transport.
        let base = base_dir.to_path_buf();
        let http = Arc::clone(http_post);
        let result = tokio::task::spawn_blocking(move || {
            let http_closure = move |url: &str, body: &str| http(url, body);
            broker_check(&base, account, http_closure)
        })
        .await;

        match result {
            Ok(Ok(broker_result)) => {
                let status = RefreshStatus::from_result(account, expires_at_ms, &broker_result);
                if matches!(broker_result, BrokerResult::Failed(_)) {
                    warn!(account = info.id, "refresh failed, entering cooldown");
                    set_cooldown(cooldowns, info.id);
                } else {
                    clear_cooldown(cooldowns, info.id);
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
            }
        }
    }

    debug!(processed, skipped_cooldown, "refresher tick complete");
}

/// Re-export of the shared `error_kind_tag` so the refresher's
/// warn-log call site keeps its local name. The function itself
/// lives in `crate::error` so every subsystem uses the same
/// vocabulary (logs, broker-failed flag files, dashboard error
/// column all agree on what "broker_token_invalid" means).
use crate::error::error_kind_tag;

fn in_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) -> bool {
    let guard = cooldowns.lock().expect("cooldown lock poisoned");
    match guard.get(&account) {
        Some(t) => t.elapsed() < FAILURE_COOLDOWN,
        None => false,
    }
}

fn set_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().expect("cooldown lock poisoned");
    guard.insert(account, Instant::now());
}

fn clear_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().expect("cooldown lock poisoned");
    guard.remove(&account);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::TempDir;

    fn make_creds(access: &str, refresh: &str, expires_at_ms: u64) -> CredentialFile {
        CredentialFile {
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
        }
    }

    fn install_account(base: &std::path::Path, account: u16, expires_at_ms: u64) {
        let num = AccountNum::try_from(account).unwrap();
        let creds = make_creds("at", "rt", expires_at_ms);
        credentials::save(&cred_file::canonical_path(base, num), &creds).unwrap();
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

    #[tokio::test]
    async fn tick_does_nothing_with_no_accounts() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_success(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cache, &cooldowns).await;

        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(cache.is_empty());
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

        tick(dir.path(), &http, &cache, &cooldowns).await;

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

        tick(dir.path(), &http, &cache, &cooldowns).await;

        assert_eq!(counter.load(Ordering::SeqCst), 0, "no HTTP for valid token");
        let status = cache.get(&1).unwrap();
        assert_eq!(status.last_result, "valid");
    }

    #[tokio::test]
    async fn tick_failure_enters_cooldown_and_retries_skipped() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1, 0);

        let counter = Arc::new(AtomicU32::new(0));
        let http = counting_failure(Arc::clone(&counter));
        let cache = Arc::new(TtlCache::with_default_age());
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cache, &cooldowns).await;
        let first_calls = counter.load(Ordering::SeqCst);
        // broker_check tries refresh once, then recovery once — so 2 http calls.
        assert!(
            first_calls >= 1,
            "expected at least 1 HTTP call, got {first_calls}"
        );
        assert!(
            in_cooldown(&cooldowns, 1),
            "failed account must be in cooldown"
        );
        let status = cache.get(&1).unwrap();
        assert_eq!(status.last_result, "failed");

        // Second tick immediately: cooldown should prevent any new HTTP.
        tick(dir.path(), &http, &cache, &cooldowns).await;
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

        // Prime a cooldown that has already elapsed (simulate past failure).
        cooldowns.lock().unwrap().insert(
            1,
            Instant::now() - FAILURE_COOLDOWN - Duration::from_secs(1),
        );

        tick(dir.path(), &http, &cache, &cooldowns).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(
            !in_cooldown(&cooldowns, 1),
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
}
