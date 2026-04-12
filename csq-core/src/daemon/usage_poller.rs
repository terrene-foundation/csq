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
use crate::providers::settings::load_settings;
use crate::quota::{state as quota_state, AccountQuota, QuotaFile, RateLimitData, UsageWindow};
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

/// Default interval between 3P poller ticks: 15 minutes.
pub const POLL_INTERVAL_3P: Duration = Duration::from_secs(900);

/// Anthropic API version header for 3P probe requests.
const ANTHROPIC_VERSION_HEADER: &str = "2023-06-01";

/// Rate-limit header prefix. All 3P rate-limit headers start with this.
const RATELIMIT_PREFIX: &str = "anthropic-ratelimit-";

/// Builds the minimal probe request body for a given model.
///
/// Uses `max_tokens=1` to minimise cost — the goal is only to receive
/// `anthropic-ratelimit-*` response headers, not a real completion.
fn build_probe_body(model: &str) -> String {
    format!(
        r#"{{"model":"{}","max_tokens":1,"messages":[{{"role":"user","content":"hi"}}]}}"#,
        model
    )
}

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
    startup_delay: Duration,
) -> PollerHandle {
    let cooldowns: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let backoffs: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // Separate maps for 3P accounts so synthetic IDs (901, 902)
    // don't collide with Anthropic account IDs in the same range.
    let cooldowns_3p: Arc<Mutex<HashMap<u16, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let backoffs_3p: Arc<Mutex<HashMap<u16, u32>>> = Arc::new(Mutex::new(HashMap::new()));

    let join = tokio::spawn(async move {
        run_loop(RunLoopConfig {
            base_dir,
            http_get,
            http_post_probe,
            cooldowns,
            backoffs,
            cooldowns_3p,
            backoffs_3p,
            shutdown,
            interval,
            interval_3p,
            startup_delay,
        })
        .await;
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
        tick(&cfg.base_dir, &cfg.http_get, &cfg.cooldowns, &cfg.backoffs).await;

        if last_3p_tick.elapsed() >= cfg.interval_3p {
            tick_3p(
                &cfg.base_dir,
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
        let token = creds
            .claude_ai_oauth
            .access_token
            .expose_secret()
            .to_string();

        // Poll usage in spawn_blocking (blocking HTTP client)
        let http = Arc::clone(http_get);
        let poll_result =
            tokio::task::spawn_blocking(move || poll_anthropic_usage(&token, &http)).await;

        match poll_result {
            Ok(Ok(usage)) => {
                // Write to quota file
                let base = base_dir.to_path_buf();
                if let Err(e) = write_usage_to_quota(&base, account, &usage) {
                    warn!(account = info.id, "usage poller: failed to write quota");
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

    let (status, body) = http_get(&url, token, &extra_headers).map_err(PollError::Transport)?;

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
    let s = s.strip_suffix('Z').or_else(|| s.strip_suffix("+00:00"))?;

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

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
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
    let mut quota = quota_state::load_state(base_dir).unwrap_or_else(|_| QuotaFile::empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    quota.set(
        account.get(),
        AccountQuota {
            five_hour: usage.five_hour.clone(),
            seven_day: usage.seven_day.clone(),
            rate_limits: None,
            updated_at: now,
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account.get(), "usage poller: quota file updated");
    Ok(())
}

// ─── 3P (third-party) polling ─────────────────────────────

/// Runs a single 3P usage poller tick.
///
/// Discovers 3P accounts (Z.AI, MiniMax), reads their API keys from
/// settings files, sends a minimal `max_tokens=1` probe, and extracts
/// `anthropic-ratelimit-*` headers from the response.
///
/// Handles **both** discovery sources:
/// 1. **Per-slot bindings** — `config-N/settings.json` pointing at a
///    3P provider. Slot N is the displayed account number (e.g.
///    slot 9 = MiniMax). API key is read from the same per-slot
///    file. Quota is written to `quota.json` keyed on slot N so the
///    dashboard Accounts tab sees it without further plumbing.
/// 2. **Legacy global** — `settings-mm.json` / `settings-zai.json`
///    at the base dir level, synthetic slots 901/902. Still
///    supported for backward compat but suppressed by `discover_all`
///    when a per-slot binding exists for the same provider.
pub(crate) async fn tick_3p(
    base_dir: &std::path::Path,
    http_post_probe: &HttpPostProbeFn,
    cooldowns: &Arc<Mutex<HashMap<u16, Instant>>>,
    backoffs: &Arc<Mutex<HashMap<u16, u32>>>,
) {
    debug!("3P usage poller tick starting");

    // `discover_all` returns OAuth + per-slot 3P + legacy global 3P
    // with de-duplication. We filter to just the 3P rows here.
    let accounts: Vec<_> = discovery::discover_all(base_dir)
        .into_iter()
        .filter(|a| matches!(a.source, AccountSource::ThirdParty { .. }))
        .collect();

    let mut polled = 0usize;
    let mut skipped = 0usize;

    for info in accounts {
        let provider_id = match &info.source {
            AccountSource::ThirdParty { provider } => provider_id_from_label(provider),
            _ => continue,
        };

        let provider_id = match provider_id {
            Some(id) => id,
            None => continue,
        };

        // Cooldown check
        if in_cooldown(cooldowns, info.id) {
            skipped += 1;
            continue;
        }

        // Load API key. For per-slot bindings (info.id < 900) the
        // canonical source is `config-<info.id>/settings.json`.
        // For legacy global bindings (info.id >= 900 i.e. 901/902)
        // fall back to the base-dir-level `settings-{mm,zai}.json`.
        let api_key = if info.id < 900 {
            match load_3p_api_key_for_slot(base_dir, info.id, provider_id) {
                Some(key) => key,
                None => {
                    debug!(
                        account = info.id,
                        provider = provider_id,
                        "3P poller: per-slot API key not found"
                    );
                    continue;
                }
            }
        } else {
            match load_3p_api_key(base_dir, provider_id) {
                Some(key) => key,
                None => {
                    debug!(
                        account = info.id,
                        provider = provider_id,
                        "3P poller: global API key not found"
                    );
                    continue;
                }
            }
        };

        // Load base URL and default model from the provider catalog
        // as a fallback, then override the base URL with the
        // per-slot binding's `env.ANTHROPIC_BASE_URL` if set. The
        // user may be hitting a non-default host (e.g. the
        // `api.minimax.io` regional shard vs the catalog's
        // `api.minimax.chat`), and we must respect that.
        let (catalog_base_url, default_model) =
            match crate::providers::catalog::get_provider(provider_id) {
                Some(p) => (
                    p.default_base_url.unwrap_or("https://api.anthropic.com"),
                    p.default_model,
                ),
                None => continue,
            };
        let base_url_owned = if info.id < 900 {
            load_3p_base_url_for_slot(base_dir, info.id)
                .unwrap_or_else(|| catalog_base_url.to_string())
        } else {
            catalog_base_url.to_string()
        };

        // Poll in spawn_blocking (blocking HTTP client).
        // expose_secret() at the HTTP boundary — raw key lives only
        // for the duration of the blocking probe.
        let http = Arc::clone(http_post_probe);
        let url = format!("{}/v1/messages", base_url_owned);
        let model = default_model.to_string();
        let raw_key = api_key.expose_secret().to_string();
        let poll_result =
            tokio::task::spawn_blocking(move || poll_3p_usage(&url, &raw_key, &model, &http)).await;

        match poll_result {
            Ok(Ok(rate_limits)) => {
                let base = base_dir.to_path_buf();
                if let Err(e) = write_3p_usage_to_quota(&base, info.id, &rate_limits) {
                    warn!(account = info.id, "3P poller: failed to write quota");
                    let _ = e;
                }
                clear_cooldown(cooldowns, info.id);
                clear_backoff(backoffs, info.id);
                polled += 1;
            }
            Ok(Err(PollError::RateLimited)) => {
                warn!(account = info.id, "3P poller: 429 rate limited");
                increase_backoff(backoffs, info.id);
                set_cooldown_with_backoff(cooldowns, backoffs, info.id);
            }
            Ok(Err(PollError::Unauthorized)) => {
                warn!(account = info.id, "3P poller: 401 unauthorized");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::Transport(_))) => {
                debug!(account = info.id, "3P poller: transport error");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::Parse(_))) => {
                debug!(account = info.id, "3P poller: parse error");
                set_cooldown(cooldowns, info.id);
            }
            Ok(Err(PollError::HttpError(status))) => {
                debug!(account = info.id, status, "3P poller: non-200 response");
                set_cooldown(cooldowns, info.id);
            }
            Err(_join_err) => {
                warn!(account = info.id, "3P poller: task panicked");
                set_cooldown(cooldowns, info.id);
            }
        }
    }

    debug!(polled, skipped, "3P usage poller tick complete");
}

/// Maps a 3P provider display label to its catalog ID.
fn provider_id_from_label(label: &str) -> Option<&'static str> {
    match label {
        "Z.AI" => Some("zai"),
        "MiniMax" => Some("mm"),
        _ => None,
    }
}

/// Loads the API key for a 3P provider from its global settings
/// file (`{base}/settings-{mm,zai}.json`).
///
/// Returns the key wrapped in [`ApiKey`] so the raw value is never
/// held as a plain `String`. Callers expose at the HTTP boundary
/// via [`ApiKey::expose_secret`].
fn load_3p_api_key(base_dir: &std::path::Path, provider_id: &str) -> Option<crate::types::ApiKey> {
    let settings = load_settings(base_dir, provider_id).ok()?;
    settings.get_api_key()
}

/// Loads the API key for a per-slot 3P provider binding from
/// `{base}/config-<slot>/settings.json`.
///
/// Returns `None` if the file is missing, malformed, or does not
/// contain `env.ANTHROPIC_AUTH_TOKEN`. The key env var is shared
/// between MiniMax and Z.AI (both use the same bearer-in-env-var
/// convention) so the caller's `provider_id` is used only to
/// validate that the caller's intent matches the catalog — not to
/// pick a different env var.
fn load_3p_api_key_for_slot(
    base_dir: &std::path::Path,
    slot: u16,
    _provider_id: &str,
) -> Option<crate::types::ApiKey> {
    let path = base_dir
        .join(format!("config-{slot}"))
        .join("settings.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    // Canonical location is `env.ANTHROPIC_AUTH_TOKEN`; top-level
    // `ANTHROPIC_AUTH_TOKEN` is a fallback for hand-edited files.
    let token = json
        .get("env")
        .and_then(|e| e.get("ANTHROPIC_AUTH_TOKEN"))
        .or_else(|| json.get("ANTHROPIC_AUTH_TOKEN"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())?;
    Some(crate::types::ApiKey::new(token.to_string()))
}

/// Reads the `env.ANTHROPIC_BASE_URL` override from a per-slot
/// `config-<slot>/settings.json`. Returns `None` when the file is
/// missing or the field is not set, letting the caller fall back
/// to the provider catalog default.
fn load_3p_base_url_for_slot(base_dir: &std::path::Path, slot: u16) -> Option<String> {
    let path = base_dir
        .join(format!("config-{slot}"))
        .join("settings.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("env")
        .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
        .or_else(|| json.get("ANTHROPIC_BASE_URL"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Polls a 3P provider by sending a minimal `max_tokens=1` request.
///
/// Extracts `anthropic-ratelimit-*` headers from the response (even
/// on error responses, since 3P providers often include rate-limit
/// headers on 4xx).
///
/// `model` is the provider's configured model (from the catalog's
/// `default_model` field). It is injected here so the probe body is
/// never hardcoded in source and survives model-ID deprecations.
pub(crate) fn poll_3p_usage(
    url: &str,
    api_key: &str,
    model: &str,
    http_post: &HttpPostProbeFn,
) -> Result<RateLimitData, PollError> {
    let headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("x-api-key".to_string(), api_key.to_string()),
        (
            "anthropic-version".to_string(),
            ANTHROPIC_VERSION_HEADER.to_string(),
        ),
        ("Accept".to_string(), "application/json".to_string()),
    ];

    let probe_body = build_probe_body(model);
    let (status, resp_headers, _body) =
        http_post(url, &headers, &probe_body).map_err(PollError::Transport)?;

    // Extract rate-limit headers even on non-200 responses
    let rate_limits = extract_rate_limit_headers(&resp_headers);

    // If we got rate-limit data, return it regardless of status
    if rate_limits.has_data() {
        return Ok(rate_limits);
    }

    // No rate-limit headers — classify by status
    match status {
        200..=299 => Ok(rate_limits), // empty but successful
        429 => Err(PollError::RateLimited),
        401 => Err(PollError::Unauthorized),
        other => Err(PollError::HttpError(other)),
    }
}

/// Extracts `anthropic-ratelimit-*` headers into a [`RateLimitData`].
///
/// Header keys must be lowercase (as returned by `http::post_json_with_headers`).
pub(crate) fn extract_rate_limit_headers(headers: &HashMap<String, String>) -> RateLimitData {
    let get_u64 = |suffix: &str| -> Option<u64> {
        headers
            .get(&format!("{RATELIMIT_PREFIX}{suffix}"))
            .and_then(|v| v.parse::<u64>().ok())
    };

    RateLimitData {
        requests_limit: get_u64("requests-limit"),
        requests_remaining: get_u64("requests-remaining"),
        tokens_limit: get_u64("tokens-limit"),
        tokens_remaining: get_u64("tokens-remaining"),
        input_tokens_limit: get_u64("input-tokens-limit"),
        output_tokens_limit: get_u64("output-tokens-limit"),
    }
}

/// Writes 3P rate-limit data into the local `quota.json`.
fn write_3p_usage_to_quota(
    base_dir: &std::path::Path,
    account_id: u16,
    rate_limits: &RateLimitData,
) -> Result<(), crate::error::CsqError> {
    let mut quota = quota_state::load_state(base_dir).unwrap_or_else(|_| QuotaFile::empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    // Compute token usage percentage for the five_hour display slot
    // so that existing statusline formatting works for 3P accounts.
    // Use far-future resets_at so clear_expired() never removes it;
    // the poller refreshes every 15 min so stale data is replaced
    // naturally.
    let five_hour = rate_limits.token_usage_pct().map(|pct| UsageWindow {
        used_percentage: pct,
        resets_at: 4_102_444_800, // 2100-01-01T00:00:00Z
    });

    quota.set(
        account_id,
        AccountQuota {
            five_hour,
            seven_day: None,
            rate_limits: Some(rate_limits.clone()),
            updated_at: now,
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account_id, "3P poller: quota file updated");
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
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "cooldown should suppress"
        );
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
        cooldowns.lock().unwrap().insert(
            1,
            Instant::now() - FAILURE_COOLDOWN - Duration::from_secs(1),
        );

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(!in_cooldown(&cooldowns, 1));
    }

    // ─── 3P polling tests ───────────────────────────────────

    fn install_3p_account(base: &std::path::Path, provider: &str, key: &str) {
        let filename = match provider {
            "zai" => "settings-zai.json",
            "mm" => "settings-mm.json",
            _ => panic!("unknown provider"),
        };
        // Discovery checks for top-level ANTHROPIC_AUTH_TOKEN.
        // ProviderSettings::get_api_key() reads from env.ANTHROPIC_AUTH_TOKEN.
        // Write both locations so discovery finds the account AND the
        // API key is loadable.
        let content = format!(
            r#"{{"ANTHROPIC_AUTH_TOKEN":"{}","ANTHROPIC_BASE_URL":"https://api.example.com","env":{{"ANTHROPIC_AUTH_TOKEN":"{}","ANTHROPIC_BASE_URL":"https://api.example.com"}}}}"#,
            key, key
        );
        std::fs::write(base.join(filename), content).unwrap();
    }

    fn mock_3p_success(counter: Arc<AtomicU32>) -> HttpPostProbeFn {
        Arc::new(
            move |_url: &str, _headers: &[(String, String)], _body: &str| {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut headers = HashMap::new();
                headers.insert(
                    "anthropic-ratelimit-requests-limit".to_string(),
                    "1000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-requests-remaining".to_string(),
                    "800".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-tokens-limit".to_string(),
                    "100000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-tokens-remaining".to_string(),
                    "60000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-input-tokens-limit".to_string(),
                    "50000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-output-tokens-limit".to_string(),
                    "50000".to_string(),
                );
                Ok((200, headers, r#"{"id":"msg_test"}"#.to_string()))
            },
        )
    }

    fn mock_3p_429(counter: Arc<AtomicU32>) -> HttpPostProbeFn {
        Arc::new(
            move |_url: &str, _headers: &[(String, String)], _body: &str| {
                counter.fetch_add(1, Ordering::SeqCst);
                // 429 with no rate-limit headers
                Ok((429, HashMap::new(), "rate limited".to_string()))
            },
        )
    }

    fn mock_3p_401(counter: Arc<AtomicU32>) -> HttpPostProbeFn {
        Arc::new(
            move |_url: &str, _headers: &[(String, String)], _body: &str| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok((401, HashMap::new(), "unauthorized".to_string()))
            },
        )
    }

    fn mock_3p_429_with_headers(counter: Arc<AtomicU32>) -> HttpPostProbeFn {
        Arc::new(
            move |_url: &str, _headers: &[(String, String)], _body: &str| {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut headers = HashMap::new();
                headers.insert(
                    "anthropic-ratelimit-tokens-limit".to_string(),
                    "100000".to_string(),
                );
                headers.insert(
                    "anthropic-ratelimit-tokens-remaining".to_string(),
                    "0".to_string(),
                );
                Ok((429, headers, "rate limited".to_string()))
            },
        )
    }

    // ─── extract_rate_limit_headers tests ────────────────────

    #[test]
    fn extract_full_rate_limit_headers() {
        let mut headers = HashMap::new();
        headers.insert("anthropic-ratelimit-requests-limit".into(), "1000".into());
        headers.insert(
            "anthropic-ratelimit-requests-remaining".into(),
            "800".into(),
        );
        headers.insert("anthropic-ratelimit-tokens-limit".into(), "100000".into());
        headers.insert(
            "anthropic-ratelimit-tokens-remaining".into(),
            "60000".into(),
        );
        headers.insert(
            "anthropic-ratelimit-input-tokens-limit".into(),
            "50000".into(),
        );
        headers.insert(
            "anthropic-ratelimit-output-tokens-limit".into(),
            "50000".into(),
        );

        let rl = extract_rate_limit_headers(&headers);
        assert_eq!(rl.requests_limit, Some(1000));
        assert_eq!(rl.requests_remaining, Some(800));
        assert_eq!(rl.tokens_limit, Some(100000));
        assert_eq!(rl.tokens_remaining, Some(60000));
        assert_eq!(rl.input_tokens_limit, Some(50000));
        assert_eq!(rl.output_tokens_limit, Some(50000));
        assert!(rl.has_data());
    }

    #[test]
    fn extract_partial_rate_limit_headers() {
        let mut headers = HashMap::new();
        headers.insert("anthropic-ratelimit-tokens-limit".into(), "100000".into());
        headers.insert(
            "anthropic-ratelimit-tokens-remaining".into(),
            "75000".into(),
        );

        let rl = extract_rate_limit_headers(&headers);
        assert_eq!(rl.tokens_limit, Some(100000));
        assert_eq!(rl.tokens_remaining, Some(75000));
        assert!(rl.requests_limit.is_none());
        assert!(rl.has_data());
    }

    #[test]
    fn extract_empty_headers() {
        let headers = HashMap::new();
        let rl = extract_rate_limit_headers(&headers);
        assert!(!rl.has_data());
    }

    #[test]
    fn extract_ignores_non_numeric() {
        let mut headers = HashMap::new();
        headers.insert(
            "anthropic-ratelimit-tokens-limit".into(),
            "not_a_number".into(),
        );

        let rl = extract_rate_limit_headers(&headers);
        assert!(rl.tokens_limit.is_none());
        assert!(!rl.has_data());
    }

    // ─── RateLimitData helper tests ─────────────────────────

    #[test]
    fn token_usage_pct_computes_correctly() {
        let rl = RateLimitData {
            requests_limit: None,
            requests_remaining: None,
            tokens_limit: Some(100000),
            tokens_remaining: Some(60000),
            input_tokens_limit: None,
            output_tokens_limit: None,
        };
        let pct = rl.token_usage_pct().unwrap();
        assert!((pct - 40.0).abs() < 0.01);
    }

    #[test]
    fn token_usage_pct_fully_used() {
        let rl = RateLimitData {
            requests_limit: None,
            requests_remaining: None,
            tokens_limit: Some(100000),
            tokens_remaining: Some(0),
            input_tokens_limit: None,
            output_tokens_limit: None,
        };
        let pct = rl.token_usage_pct().unwrap();
        assert!((pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn token_usage_pct_none_when_missing() {
        let rl = RateLimitData {
            requests_limit: Some(1000),
            requests_remaining: Some(800),
            tokens_limit: None,
            tokens_remaining: None,
            input_tokens_limit: None,
            output_tokens_limit: None,
        };
        assert!(rl.token_usage_pct().is_none());
    }

    #[test]
    fn request_usage_pct_computes_correctly() {
        let rl = RateLimitData {
            requests_limit: Some(1000),
            requests_remaining: Some(800),
            tokens_limit: None,
            tokens_remaining: None,
            input_tokens_limit: None,
            output_tokens_limit: None,
        };
        let pct = rl.request_usage_pct().unwrap();
        assert!((pct - 20.0).abs() < 0.01);
    }

    // ─── poll_3p_usage unit tests ───────────────────────────

    // ─── build_probe_body tests ─────────────────────────────

    #[test]
    fn build_probe_body_contains_model() {
        let body = build_probe_body("test-model");
        let parsed: serde_json::Value =
            serde_json::from_str(&body).expect("build_probe_body must produce valid JSON");
        assert_eq!(parsed["model"], "test-model");
        assert_eq!(parsed["max_tokens"], 1);
        assert_eq!(parsed["messages"][0]["role"], "user");
        assert_eq!(parsed["messages"][0]["content"], "hi");
    }

    #[test]
    fn build_probe_body_uses_provided_model_not_hardcoded() {
        let a = build_probe_body("model-a");
        let b = build_probe_body("model-b");
        let pa: serde_json::Value = serde_json::from_str(&a).unwrap();
        let pb: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(pa["model"], "model-a");
        assert_eq!(pb["model"], "model-b");
        assert_ne!(pa["model"], pb["model"]);
    }

    // ─── poll_3p_usage unit tests ───────────────────────────

    #[test]
    fn poll_3p_success_extracts_headers() {
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_success(Arc::clone(&counter));
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        assert!(result.is_ok());
        let rl = result.unwrap();
        assert_eq!(rl.tokens_limit, Some(100000));
        assert_eq!(rl.tokens_remaining, Some(60000));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poll_3p_429_no_headers_returns_ratelimited() {
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_429(Arc::clone(&counter));
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        assert!(matches!(result, Err(PollError::RateLimited)));
    }

    #[test]
    fn poll_3p_429_with_headers_returns_data() {
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_429_with_headers(Arc::clone(&counter));
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        // Even on 429, if headers are present, return them
        assert!(result.is_ok());
        let rl = result.unwrap();
        assert_eq!(rl.tokens_remaining, Some(0));
    }

    #[test]
    fn poll_3p_401_returns_unauthorized() {
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_401(Arc::clone(&counter));
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        assert!(matches!(result, Err(PollError::Unauthorized)));
    }

    #[test]
    fn poll_3p_transport_error() {
        let http: HttpPostProbeFn =
            Arc::new(|_url: &str, _headers: &[(String, String)], _body: &str| {
                Err("connection refused".to_string())
            });
        let result = poll_3p_usage(
            "https://api.example.com/v1/messages",
            "test-key",
            "test-model",
            &http,
        );
        assert!(matches!(result, Err(PollError::Transport(_))));
    }

    // ─── tick_3p integration tests ──────────────────────────

    #[tokio::test]
    async fn tick_3p_polls_and_writes_quota() {
        let dir = TempDir::new().unwrap();
        install_3p_account(dir.path(), "zai", "test-api-key");

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick_3p(dir.path(), &http, &cooldowns, &backoffs).await;

        assert_eq!(counter.load(Ordering::SeqCst), 1, "exactly one HTTP POST");

        // Verify quota was written
        let quota = quota_state::load_state(dir.path()).unwrap();
        let q = quota.get(901).expect("Z.AI account 901 should have quota");
        // tokens: 100000 limit, 60000 remaining → 40% used
        assert!((q.five_hour_pct() - 40.0).abs() < 0.01);
        assert!(q.rate_limits.is_some());
        let rl = q.rate_limits.as_ref().unwrap();
        assert_eq!(rl.tokens_limit, Some(100000));
    }

    #[tokio::test]
    async fn tick_3p_429_enters_cooldown() {
        let dir = TempDir::new().unwrap();
        install_3p_account(dir.path(), "zai", "test-api-key");

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_429(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick_3p(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(in_cooldown(&cooldowns, 901));

        // Second tick: cooldown blocks the poll
        tick_3p(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "cooldown should suppress"
        );
    }

    #[tokio::test]
    async fn tick_3p_no_accounts_does_nothing() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick_3p(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tick_3p_multiple_providers() {
        let dir = TempDir::new().unwrap();
        install_3p_account(dir.path(), "zai", "zai-key");
        install_3p_account(dir.path(), "mm", "mm-key");

        let counter = Arc::new(AtomicU32::new(0));
        let http = mock_3p_success(Arc::clone(&counter));
        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick_3p(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 2, "both providers polled");

        let quota = quota_state::load_state(dir.path()).unwrap();
        assert!(quota.get(901).is_some(), "Z.AI should have quota");
        assert!(quota.get(902).is_some(), "MiniMax should have quota");
    }

    // ─── quota round-trip with rate_limits field ────────────

    #[test]
    fn quota_rate_limits_serialization_round_trip() {
        let dir = TempDir::new().unwrap();
        let mut qf = QuotaFile::empty();
        qf.set(
            901,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: 40.0,
                    resets_at: 4_102_444_800,
                }),
                seven_day: None,
                rate_limits: Some(RateLimitData {
                    requests_limit: Some(1000),
                    requests_remaining: Some(800),
                    tokens_limit: Some(100000),
                    tokens_remaining: Some(60000),
                    input_tokens_limit: Some(50000),
                    output_tokens_limit: Some(50000),
                }),
                updated_at: 100.0,
            },
        );

        quota_state::save_state(dir.path(), &qf).unwrap();
        let loaded = quota_state::load_state(dir.path()).unwrap();

        let q = loaded.get(901).expect("account 901 should exist");
        let rl = q.rate_limits.as_ref().expect("rate_limits should exist");
        assert_eq!(rl.tokens_limit, Some(100000));
        assert_eq!(rl.tokens_remaining, Some(60000));
        assert!((q.five_hour_pct() - 40.0).abs() < 0.01);
    }

    #[test]
    fn quota_without_rate_limits_deserializes() {
        // Backward compat: old quota.json without rate_limits field
        let json = r#"{"accounts":{"1":{"five_hour":{"used_percentage":42.0,"resets_at":9999999999},"seven_day":null,"updated_at":100.0}}}"#;
        let qf: QuotaFile = serde_json::from_str(json).unwrap();
        let q = qf.get(1).unwrap();
        assert!(q.rate_limits.is_none());
        assert!((q.five_hour_pct() - 42.0).abs() < 0.01);
    }

    // ── per-slot 3P key / base-url loaders ─────────────────

    fn write_slot_settings(base: &std::path::Path, slot: u16, base_url: &str, token: &str) {
        let dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&dir).unwrap();
        let json = format!(
            r#"{{"env":{{"ANTHROPIC_BASE_URL":"{base_url}","ANTHROPIC_AUTH_TOKEN":"{token}"}}}}"#
        );
        std::fs::write(dir.join("settings.json"), json).unwrap();
    }

    #[test]
    fn load_3p_api_key_for_slot_reads_per_slot_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_slot_settings(
            tmp.path(),
            9,
            "https://api.minimax.io/anthropic",
            "tok-mm-9",
        );
        let key = load_3p_api_key_for_slot(tmp.path(), 9, "mm").unwrap();
        assert_eq!(key.expose_secret(), "tok-mm-9");
    }

    #[test]
    fn load_3p_api_key_for_slot_returns_none_on_missing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(load_3p_api_key_for_slot(tmp.path(), 9, "mm").is_none());
    }

    #[test]
    fn load_3p_api_key_for_slot_returns_none_on_empty_token() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Empty string is treated as "not set" — otherwise the
        // poller would emit 401 for every tick on a stub slot.
        write_slot_settings(tmp.path(), 9, "https://api.minimax.io/anthropic", "");
        assert!(load_3p_api_key_for_slot(tmp.path(), 9, "mm").is_none());
    }

    #[test]
    fn load_3p_base_url_for_slot_reads_per_slot_url() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_slot_settings(tmp.path(), 10, "https://api.z.ai/api/anthropic", "tok");
        let url = load_3p_base_url_for_slot(tmp.path(), 10).unwrap();
        assert_eq!(url, "https://api.z.ai/api/anthropic");
    }

    #[test]
    fn load_3p_base_url_for_slot_returns_none_on_missing() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(load_3p_base_url_for_slot(tmp.path(), 7).is_none());
    }

    #[test]
    fn load_3p_base_url_for_slot_accepts_non_default_host() {
        // The user's real setup uses `api.minimax.io`, not the
        // catalog's `api.minimax.chat`. The loader must not second-
        // guess the URL — whatever's in settings.json wins.
        let tmp = tempfile::TempDir::new().unwrap();
        write_slot_settings(tmp.path(), 9, "https://api.minimax.io/anthropic", "tok");
        assert_eq!(
            load_3p_base_url_for_slot(tmp.path(), 9).unwrap(),
            "https://api.minimax.io/anthropic"
        );
    }
}
