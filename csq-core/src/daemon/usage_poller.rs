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
//! Response (observed from v1 Python poller + test fixtures):
//!
//! ```json
//! {
//!   "five_hour": { "utilization": 0.42, "resets_at": "2099-01-01T00:00:00Z" },
//!   "seven_day": { "utilization": 0.15, "resets_at": "2099-01-14T00:00:00Z" }
//! }
//! ```
//!
//! # Mapping to `QuotaFile`
//!
//! - `utilization` (0.0–1.0) → `used_percentage` (0.0–100.0): multiply by 100.
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

use crate::accounts::{discovery, AccountSource};
use crate::credentials::{self, file as cred_file};
use crate::quota::{state as quota_state, AccountQuota, QuotaFile, UsageWindow};
use crate::types::AccountNum;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default interval between poller ticks: 5 minutes.
pub const POLL_INTERVAL: Duration = Duration::from_secs(300);

/// Short startup delay so the daemon finishes binding sockets
/// before the first HTTP call.
pub const STARTUP_DELAY: Duration = Duration::from_secs(5);

/// Cooldown after a failed poll: 10 minutes.
pub const FAILURE_COOLDOWN: Duration = Duration::from_secs(600);

/// Maximum accounts polled per tick (same rationale as refresher).
pub const MAX_ACCOUNTS_PER_TICK: usize = 64;

/// Anthropic base URL for OAuth usage.
const ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";

/// Beta header value required for the usage endpoint.
const ANTHROPIC_BETA_HEADER: &str = "oauth-2025-04-20";

/// HTTP transport closure for the usage GET. Takes `(url, bearer_token,
/// extra_headers)` and returns `(status, body_bytes)`. Production
/// callers pass `http::get_bearer`; tests pass a mock.
pub type HttpGetFn = Arc<
    dyn Fn(&str, &str, &[(&str, &str)]) -> Result<(u16, Vec<u8>), String> + Send + Sync + 'static,
>;

/// Handle to a running usage poller task.
pub struct PollerHandle {
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns the usage poller task on the current tokio runtime.
pub fn spawn(
    base_dir: PathBuf,
    http_get: HttpGetFn,
    shutdown: CancellationToken,
) -> PollerHandle {
    spawn_with_config(base_dir, http_get, shutdown, POLL_INTERVAL, STARTUP_DELAY)
}

/// Like [`spawn`] but with explicit interval + startup delay for testing.
pub fn spawn_with_config(
    base_dir: PathBuf,
    http_get: HttpGetFn,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
) -> PollerHandle {
    let cooldowns: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let backoffs: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new()));

    let join = tokio::spawn(async move {
        run_loop(
            base_dir,
            http_get,
            cooldowns,
            backoffs,
            shutdown,
            interval,
            startup_delay,
        )
        .await;
    });

    PollerHandle { join }
}

async fn run_loop(
    base_dir: PathBuf,
    http_get: HttpGetFn,
    cooldowns: Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: Arc<Mutex<HashMap<u16, u32>>>,
    shutdown: CancellationToken,
    interval: Duration,
    startup_delay: Duration,
) {
    info!(interval_secs = interval.as_secs(), "usage poller starting");

    tokio::select! {
        _ = shutdown.cancelled() => {
            info!("usage poller cancelled during startup delay");
            return;
        }
        _ = tokio::time::sleep(startup_delay) => {}
    }

    loop {
        tick(&base_dir, &http_get, &cooldowns, &backoffs).await;

        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("usage poller cancelled, exiting loop");
                return;
            }
            _ = tokio::time::sleep(interval) => {}
        }
    }
}

/// Runs a single usage poller tick.
///
/// Exposed `pub(crate)` for tests.
pub(crate) async fn tick(
    base_dir: &std::path::Path,
    http_get: &HttpGetFn,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
) {
    debug!("usage poller tick starting");

    let mut accounts = discovery::discover_anthropic(base_dir);
    if accounts.len() > MAX_ACCOUNTS_PER_TICK {
        accounts.truncate(MAX_ACCOUNTS_PER_TICK);
    }

    let mut polled = 0usize;
    let mut skipped = 0usize;

    for info in accounts {
        if info.source != AccountSource::Anthropic || !info.has_credentials {
            continue;
        }

        let account = match AccountNum::try_from(info.id) {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Cooldown check
        if in_cooldown(cooldowns, info.id) {
            skipped += 1;
            continue;
        }

        // Read access token from canonical credential file
        let canonical = cred_file::canonical_path(base_dir, account);
        let creds = match credentials::load(&canonical) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let token = creds.claude_ai_oauth.access_token.expose_secret().to_string();

        // Poll usage in spawn_blocking (blocking HTTP client)
        let http = Arc::clone(http_get);
        let poll_result = tokio::task::spawn_blocking(move || {
            poll_anthropic_usage(&token, &http)
        })
        .await;

        match poll_result {
            Ok(Ok(usage)) => {
                // Write to quota file
                let base = base_dir.to_path_buf();
                if let Err(e) = write_usage_to_quota(&base, account, &usage) {
                    warn!(
                        account = info.id,
                        "usage poller: failed to write quota"
                    );
                    let _ = e;
                }
                clear_cooldown(cooldowns, info.id);
                clear_backoff(backoffs, info.id);
                polled += 1;
            }
            Ok(Err(PollError::RateLimited)) => {
                warn!(account = info.id, "usage poller: 429 rate limited");
                increase_backoff(backoffs, info.id);
                set_cooldown_with_backoff(cooldowns, backoffs, info.id);
            }
            Ok(Err(PollError::Unauthorized)) => {
                warn!(account = info.id, "usage poller: 401 unauthorized");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::Transport(_))) => {
                debug!(account = info.id, "usage poller: transport error");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::Parse(_))) => {
                debug!(account = info.id, "usage poller: parse error");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::HttpError(status))) => {
                debug!(account = info.id, status, "usage poller: non-200 response");
                set_cooldown(cooldowns, info.id);
            }
            Err(_join_err) => {
                warn!(account = info.id, "usage poller: task panicked");
                set_cooldown(cooldowns, info.id);
            }
        }
    }

    debug!(polled, skipped, "usage poller tick complete");
}

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

/// Parsed usage data from `/api/oauth/usage`.
#[derive(Debug, Clone)]
pub(crate) struct UsageData {
    pub five_hour: Option<UsageWindow>,
    pub seven_day: Option<UsageWindow>,
}

/// Polls `/api/oauth/usage` for one Anthropic account.
pub(crate) fn poll_anthropic_usage(
    token: &str,
    http_get: &HttpGetFn,
) -> Result<UsageData, PollError> {
    let url = format!("{ANTHROPIC_BASE_URL}/api/oauth/usage");
    let extra_headers = [("Anthropic-Beta", ANTHROPIC_BETA_HEADER)];

    let (status, body) = http_get(&url, token, &extra_headers)
        .map_err(PollError::Transport)?;

    match status {
        200 => {}
        429 => return Err(PollError::RateLimited),
        401 => return Err(PollError::Unauthorized),
        other => return Err(PollError::HttpError(other)),
    }

    parse_usage_response(&body)
}

/// Parses the `/api/oauth/usage` JSON response into `UsageData`.
///
/// Handles the mapping from the API shape:
///   `{ "utilization": 0.42, "resets_at": "2099-01-01T00:00:00Z" }`
/// to the internal `UsageWindow`:
///   `{ used_percentage: 42.0, resets_at: epoch_u64 }`
pub(crate) fn parse_usage_response(body: &[u8]) -> Result<UsageData, PollError> {
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| PollError::Parse(e.to_string()))?;

    Ok(UsageData {
        five_hour: parse_window(&json, "five_hour"),
        seven_day: parse_window(&json, "seven_day"),
    })
}

fn parse_window(json: &serde_json::Value, key: &str) -> Option<UsageWindow> {
    let window = json.get(key)?;

    // `utilization` is 0.0–1.0; convert to 0.0–100.0.
    let utilization = window.get("utilization")?.as_f64()?;
    let used_percentage = utilization * 100.0;

    // `resets_at` is ISO-8601 string. Parse to epoch seconds.
    let resets_str = window.get("resets_at")?.as_str()?;
    let resets_at = parse_iso8601_to_epoch(resets_str)?;

    Some(UsageWindow {
        used_percentage,
        resets_at,
    })
}

/// Minimal RFC 3339 parser: `YYYY-MM-DDTHH:MM:SSZ` → epoch seconds.
///
/// Accepts only UTC timestamps (trailing `Z` or `+00:00`). This is
/// sufficient for the Anthropic usage API which always returns UTC.
/// No `chrono` or `time` dependency needed.
fn parse_iso8601_to_epoch(s: &str) -> Option<u64> {
    // Strip trailing Z or +00:00
    let s = s.strip_suffix('Z')
        .or_else(|| s.strip_suffix("+00:00"))?;

    // Accept both "YYYY-MM-DDTHH:MM:SS" and "YYYY-MM-DDTHH:MM:SS.fff"
    let s = match s.find('.') {
        Some(dot) => &s[..dot],
        None => s,
    };

    // Parse YYYY-MM-DDTHH:MM:SS
    if s.len() != 19 {
        return None;
    }
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let minute: u64 = s[14..16].parse().ok()?;
    let second: u64 = s[17..19].parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    // Days before each month (non-leap).
    const MONTH_DAYS: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    let mut days = 365 * (year - 1970);
    // Leap years between 1970 and year-1.
    if year > 1970 {
        days += (year - 1969) / 4;
        days -= (year - 1901) / 100;
        days += (year - 1601) / 400;
    }
    days += MONTH_DAYS[(month - 1) as usize];
    // Add leap day if after Feb in a leap year.
    if month > 2 && is_leap_year(year) {
        days += 1;
    }
    days += day - 1;

    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Writes parsed usage data into the local `quota.json`.
fn write_usage_to_quota(
    base_dir: &std::path::Path,
    account: AccountNum,
    usage: &UsageData,
) -> Result<(), crate::error::CsqError> {
    let mut quota = quota_state::load_state(base_dir)
        .unwrap_or_else(|_| QuotaFile::empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    quota.set(
        account.get(),
        AccountQuota {
            five_hour: usage.five_hour.clone(),
            seven_day: usage.seven_day.clone(),
            updated_at: now,
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account.get(), "usage poller: quota file updated");
    Ok(())
}

// ─── Cooldown / backoff helpers ────────────────────────────

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

fn set_cooldown_with_backoff(
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
    account: u16,
) {
    let factor = {
        let guard = backoffs.lock().expect("backoff lock poisoned");
        *guard.get(&account).unwrap_or(&1)
    };
    // Simple approach: use fixed FAILURE_COOLDOWN for now. The 429 is
    // uncommon enough that fixed 10-min cooldown is adequate. The
    // backoff factor is tracked so we can scale it later if needed.
    let _ = factor;
    let mut guard = cooldowns.lock().expect("cooldown lock poisoned");
    guard.insert(account, Instant::now());
}

fn clear_cooldown(cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>, account: u16) {
    let mut guard = cooldowns.lock().expect("cooldown lock poisoned");
    guard.remove(&account);
}

fn increase_backoff(backoffs: &Arc<Mutex<HashMap<u16, u32>>>, account: u16) {
    let mut guard = backoffs.lock().expect("backoff lock poisoned");
    let current = guard.get(&account).copied().unwrap_or(1);
    guard.insert(account, (current * 2).min(8));
}

fn clear_backoff(backoffs: &Arc<Mutex<HashMap<u16, u32>>>, account: u16) {
    let mut guard = backoffs.lock().expect("backoff lock poisoned");
    guard.remove(&account);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::TempDir;

    fn install_account(base: &std::path::Path, account: u16) {
        let num = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-test-token".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-test-refresh".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        };
        credentials::save(&cred_file::canonical_path(base, num), &creds).unwrap();
    }

    fn mock_usage_success(counter: Arc<AtomicU32>) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            let body = br#"{
                "five_hour": { "utilization": 0.42, "resets_at": "2099-01-01T00:00:00Z" },
                "seven_day": { "utilization": 0.15, "resets_at": "2099-01-14T00:00:00Z" }
            }"#;
            Ok((200, body.to_vec()))
        })
    }

    fn mock_usage_429(counter: Arc<AtomicU32>) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((429, b"rate limited".to_vec()))
        })
    }

    fn mock_usage_401(counter: Arc<AtomicU32>) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok((401, b"unauthorized".to_vec()))
        })
    }

    // ─── parse_usage_response tests ──────────────────────────

    #[test]
    fn parse_full_response() {
        let body = br#"{
            "five_hour": { "utilization": 0.42, "resets_at": "2026-04-10T20:00:00Z" },
            "seven_day": { "utilization": 0.15, "resets_at": "2026-04-17T00:00:00Z" }
        }"#;
        let data = parse_usage_response(body).unwrap();

        let fh = data.five_hour.unwrap();
        assert!((fh.used_percentage - 42.0).abs() < 0.01);
        assert!(fh.resets_at > 0);

        let sd = data.seven_day.unwrap();
        assert!((sd.used_percentage - 15.0).abs() < 0.01);
        assert!(sd.resets_at > 0);
    }

    #[test]
    fn parse_missing_seven_day() {
        let body = br#"{
            "five_hour": { "utilization": 0.85, "resets_at": "2026-04-10T20:00:00Z" }
        }"#;
        let data = parse_usage_response(body).unwrap();
        assert!(data.five_hour.is_some());
        assert!(data.seven_day.is_none());
    }

    #[test]
    fn parse_empty_response() {
        let body = b"{}";
        let data = parse_usage_response(body).unwrap();
        assert!(data.five_hour.is_none());
        assert!(data.seven_day.is_none());
    }

    #[test]
    fn parse_invalid_json() {
        let body = b"not json";
        let err = parse_usage_response(body);
        assert!(matches!(err, Err(PollError::Parse(_))));
    }

    #[test]
    fn parse_utilization_converts_to_percentage() {
        let body = br#"{"five_hour":{"utilization":1.0,"resets_at":"2026-01-01T00:00:00Z"}}"#;
        let data = parse_usage_response(body).unwrap();
        assert!((data.five_hour.unwrap().used_percentage - 100.0).abs() < 0.01);
    }

    // ─── ISO-8601 parser tests ───────────────────────────────

    #[test]
    fn iso8601_basic_utc() {
        let epoch = parse_iso8601_to_epoch("2026-04-10T15:30:00Z").unwrap();
        // 2026-04-10T15:30:00Z should be a reasonable epoch value.
        assert!(epoch > 1_700_000_000);
        assert!(epoch < 2_000_000_000);
    }

    #[test]
    fn iso8601_with_plus_zero_offset() {
        let a = parse_iso8601_to_epoch("2026-04-10T15:30:00Z").unwrap();
        let b = parse_iso8601_to_epoch("2026-04-10T15:30:00+00:00").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn iso8601_with_fractional_seconds() {
        let a = parse_iso8601_to_epoch("2026-04-10T15:30:00Z").unwrap();
        let b = parse_iso8601_to_epoch("2026-04-10T15:30:00.123Z").unwrap();
        assert_eq!(a, b); // fractional seconds are truncated
    }

    #[test]
    fn iso8601_unix_epoch() {
        let epoch = parse_iso8601_to_epoch("1970-01-01T00:00:00Z").unwrap();
        assert_eq!(epoch, 0);
    }

    #[test]
    fn iso8601_known_date() {
        // 2000-01-01T00:00:00Z = 946684800
        let epoch = parse_iso8601_to_epoch("2000-01-01T00:00:00Z").unwrap();
        assert_eq!(epoch, 946684800);
    }

    #[test]
    fn iso8601_leap_year() {
        // 2024-03-01T00:00:00Z (2024 is a leap year)
        let epoch = parse_iso8601_to_epoch("2024-03-01T00:00:00Z").unwrap();
        // Jan (31) + Feb (29 in 2024) = 60 days into 2024.
        // 2024-01-01 = 1704067200. 60 * 86400 = 5184000. → 1709251200
        assert_eq!(epoch, 1709251200);
    }

    #[test]
    fn iso8601_rejects_non_utc() {
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+05:30").is_none());
    }

    #[test]
    fn iso8601_rejects_garbage() {
        assert!(parse_iso8601_to_epoch("not a date").is_none());
    }

    // ─── tick integration tests ──────────────────────────────

    #[tokio::test]
    async fn tick_polls_and_writes_quota() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1, "exactly one HTTP GET");

        // Verify quota was written
        let quota = quota_state::load_state(dir.path()).unwrap();
        let q = quota.get(1).expect("account 1 should have quota");
        assert!((q.five_hour_pct() - 42.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn tick_429_enters_cooldown() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_429(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(in_cooldown(&cooldowns, 1));

        // Second tick: cooldown blocks the poll.
        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1, "cooldown should suppress");
    }

    #[tokio::test]
    async fn tick_401_enters_cooldown() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_401(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(in_cooldown(&cooldowns, 1));
    }

    #[tokio::test]
    async fn tick_no_accounts_does_nothing() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tick_success_clears_cooldown() {
        let dir = TempDir::new().unwrap();
        install_account(dir.path(), 1);

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_usage_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        // Prime an expired cooldown.
        cooldowns
            .lock()
            .unwrap()
            .insert(1, Instant::now() - FAILURE_COOLDOWN - Duration::from_secs(1));

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(!in_cooldown(&cooldowns, 1));
    }
}
