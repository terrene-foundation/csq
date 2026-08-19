//! Anthropic account usage polling.
//!
//! Polls `GET /api/oauth/usage` for each Anthropic account, parses
//! the response, and writes quota data to `quota.json`.

use crate::accounts::{discovery, AccountSource};
use crate::credentials::{self, file as cred_file};
use crate::quota::{state as quota_state, AccountQuota, UsageWindow};
use crate::types::AccountNum;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{debug, warn};

use super::{
    classify_transport_error, clear_backoff, clear_cooldown, in_cooldown, increase_backoff,
    set_cooldown, set_cooldown_with_backoff, HttpGetFn, PollError, CALL_TIMEOUT,
    MAX_ACCOUNTS_PER_TICK,
};

/// Anthropic base URL for OAuth usage.
pub(crate) const ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";

/// Beta header value required for the usage endpoint.
pub(crate) const ANTHROPIC_BETA_HEADER: &str = "oauth-2025-04-20";

/// Runs a single Anthropic usage poller tick.
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

        // Read access token from canonical credential file.
        //
        // M4-4: route through identity-keyed credentials when
        // `profiles.json::by_slot` has a UUID for this slot. Slot-id
        // channel: per-slot poller state (channel (a) per
        // `account-terminal-separation.md` MUST Rule 1 — the poller's
        // own loop already knows which slot it is polling). UUID
        // resolution does NOT introduce a new slot-id channel — it
        // reads `by_slot[slot]` keyed on the slot-id we already have.
        // Legacy fallback to `credentials/<N>.json` only when no UUID
        // mapping exists; the M3-7/M4-5 gate guarantees identity
        // credentials are seeded in production once `by_slot` is
        // populated.
        let canonical =
            match crate::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()) {
                Some(uuid) => crate::accounts::identity_store::credentials_path_for(base_dir, uuid),
                None => cred_file::canonical_path(base_dir, account),
            };
        let creds = match credentials::load(&canonical) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // Short-lived heap String passed into spawn_blocking; dropped
        // when the blocking task completes. Never logged or stored in
        // long-lived collections. Acceptable per security.md rule 8.
        let token = creds
            .expect_anthropic()
            .claude_ai_oauth
            .access_token
            .expose_secret()
            .to_string();

        // Poll usage in spawn_blocking with a timeout to prevent
        // the 2026-04-12 hang where a stuck HTTP call blocked the
        // entire poller indefinitely.
        let http = Arc::clone(http_get);
        let join_handle = tokio::task::spawn_blocking(move || poll_anthropic_usage(&token, &http));
        let poll_result = tokio::time::timeout(CALL_TIMEOUT, join_handle).await;

        // Flatten: timeout → join → poll result
        let poll_result = match poll_result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                warn!(account = info.id, "usage poller: call timed out after 30s");
                set_cooldown(cooldowns, info.id);
                continue;
            }
        };

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
            Ok(Err(PollError::BadUrl(_))) => {
                // Reachable for TWO distinct reasons (round-2 redteam
                // R6-rust corrected this comment — it previously claimed
                // "unreachable in practice"): (1) this poller's own URL is
                // the fixed `ANTHROPIC_BASE_URL` constant, so the outbound
                // char/https/userinfo/unparseable guards can never reject
                // it — that half of the original reasoning still holds;
                // but (2) the TOKEN guard (`ERR_TOKEN_UNSAFE_CHARS`) and
                // the process-wide `ERR_NO_JS_RUNTIME` /
                // `ERR_ENCODE_FAILED` pre-flight failures check the
                // credential and the runtime environment, NOT the URL —
                // now that this call site routes through
                // `classify_transport_error`, a corrupted stored access
                // token trips this arm too. WARN is correct for both: a
                // malformed fixed URL means the constant itself somehow
                // became corrupted; a malformed token means the account's
                // stored credential needs re-login — neither is a
                // transient network blip.
                warn!(
                    account = info.id,
                    error_kind = "anthropic_poll_bad_url",
                    "usage poller: outbound url or token rejected pre-flight — check the account's stored credentials"
                );
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

    let (status, body) = http_get(&url, token, &extra_headers).map_err(classify_transport_error)?;

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

    // `utilization` is already 0.0–100.0 (percentage).
    // Anthropic's `/api/oauth/usage` returns e.g. `58.0` for 58%.
    let used_percentage = window.get("utilization")?.as_f64()?;

    // `resets_at` is ISO-8601 string. Parse to epoch seconds.
    let resets_str = window.get("resets_at")?.as_str()?;
    let resets_at = parse_iso8601_to_epoch(resets_str)?;

    Some(UsageWindow {
        used_percentage,
        resets_at,
    })
}

/// Minimal RFC 3339 parser: `YYYY-MM-DDTHH:MM:SS` + timezone → epoch
/// seconds.
///
/// Accepts a trailing `Z` (UTC) or a numeric `±HH:MM` offset. The
/// Anthropic usage API always returns UTC (`Z`/`+00:00`); the Kimi
/// usages API is China-based, so a `+08:00` contract drift must not
/// make BOTH windows unparseable → perpetual cooldown (redteam R1).
/// No `chrono` or `time` dependency needed.
pub(crate) fn parse_iso8601_to_epoch(s: &str) -> Option<u64> {
    // RFC 3339 timestamps are pure ASCII. Reject anything else up front
    // so the fixed-offset slicing below can never land on a non-char
    // boundary — a 19-byte input containing a multi-byte char panicked
    // the byte-slicing parser (redteam R1 sec-NIT-1).
    if !s.is_ascii() {
        return None;
    }

    // Split the timezone designator: trailing `Z`, or `±HH:MM`.
    let (s, offset_secs): (&str, i64) = if let Some(r) = s.strip_suffix('Z') {
        (r, 0)
    } else if s.len() >= 6 {
        let (body, tz) = s.split_at(s.len() - 6);
        let tz_bytes = tz.as_bytes();
        let sign: i64 = match tz_bytes[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        if tz_bytes[3] != b':' {
            return None;
        }
        // RFC 3339 time-numoffset is `±2DIGIT:2DIGIT` — Rust's i64
        // FromStr accepts a sign, so "+-8:00" would otherwise parse as
        // −08:00 (a silently INVERTED offset) and "++8:00" as +08:00.
        // Fail closed on any non-digit (R4 NIT).
        if !tz_bytes[1].is_ascii_digit()
            || !tz_bytes[2].is_ascii_digit()
            || !tz_bytes[4].is_ascii_digit()
            || !tz_bytes[5].is_ascii_digit()
        {
            return None;
        }
        let off_hour: i64 = tz[1..3].parse().ok()?;
        let off_min: i64 = tz[4..6].parse().ok()?;
        if off_hour > 23 || off_min > 59 {
            return None;
        }
        (body, sign * (off_hour * 3600 + off_min * 60))
    } else {
        return None;
    };

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
    // `365 * (year - 1970)` below would underflow u64 for a pre-epoch
    // year — reject it rather than panic (same containment class as
    // the ASCII guard above; the parser runs inside spawn_blocking,
    // but a panic there still costs a cooldown cycle).
    if year < 1970 {
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

    let naive = days * 86400 + hour * 3600 + minute * 60 + second;
    // RFC 3339: local = UTC + offset → UTC = local − offset. Clamp at
    // 0: a pre-1970 local time at a positive offset has no u64 epoch.
    let epoch = (naive as i64 - offset_secs).max(0);
    Some(epoch as u64)
}

fn is_leap_year(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Writes parsed usage data into the local `quota.json`.
///
/// Acquires `quota.json.lock` for mutual exclusion with any other
/// writer (see RT finding #1 — consistency with `state::update_quota`).
pub(crate) fn write_usage_to_quota(
    base_dir: &std::path::Path,
    account: AccountNum,
    usage: &UsageData,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    // MED-1 (an internal ticket redteam): load_state_or_skip fails closed instead of
    // falling back to QuotaFile::empty() — a load failure here must SKIP
    // the write, not persist a one-row file that wipes every sibling
    // account's row (mirrors usage_poller::gemini_oauth::write_quota).
    let mut quota = match quota_state::load_state_or_skip(base_dir) {
        Ok(qf) => qf,
        Err(e) => {
            warn!(
                account = account.get(),
                error_kind = "quota_load_failed",
                reason = %crate::error::redact_tokens(&e.to_string()),
                "usage poller: quota.json unreadable, skipping write to avoid clobbering sibling rows"
            );
            return Ok(());
        }
    };

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
            ..Default::default()
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account.get(), "usage poller: quota file updated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{
        self, file as cred_file, AnthropicCredentialFile, CredentialFile, OAuthPayload,
    };
    use crate::quota::state as quota_state;
    use crate::types::{AccessToken, AccountNum, RefreshToken};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    fn install_account(base: &std::path::Path, account: u16) {
        let num = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
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
        });
        credentials::save(&cred_file::canonical_path(base, num), &creds).unwrap();
    }

    fn mock_usage_success(counter: Arc<AtomicU32>) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            counter.fetch_add(1, Ordering::SeqCst);
            // Anthropic returns utilization as 0-100 percentage directly
            let body = br#"{
                "five_hour": { "utilization": 42.0, "resets_at": "2099-01-01T00:00:00Z" },
                "seven_day": { "utilization": 15.0, "resets_at": "2099-01-14T00:00:00Z" }
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
        // Anthropic returns utilization as 0-100 percentage directly
        let body = br#"{
            "five_hour": { "utilization": 42.0, "resets_at": "2026-04-10T20:00:00Z" },
            "seven_day": { "utilization": 15.0, "resets_at": "2026-04-17T00:00:00Z" }
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
    fn parse_utilization_is_direct_percentage() {
        // Anthropic returns utilization as percentage (100.0 = 100%)
        let body = br#"{"five_hour":{"utilization":100.0,"resets_at":"2026-01-01T00:00:00Z"}}"#;
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
    fn iso8601_applies_positive_numeric_offset() {
        // 2000-01-01T08:00:00 at +08:00 == 2000-01-01T00:00:00Z.
        let epoch = parse_iso8601_to_epoch("2000-01-01T08:00:00+08:00").unwrap();
        assert_eq!(epoch, 946684800);
        // 2000-01-01T00:00:00 at +05:30 == 946684800 − 19800.
        let epoch = parse_iso8601_to_epoch("2000-01-01T00:00:00+05:30").unwrap();
        assert_eq!(epoch, 946684800 - 19800);
    }

    #[test]
    fn iso8601_applies_negative_numeric_offset() {
        // 1999-12-31T19:00:00 at −05:00 == 2000-01-01T00:00:00Z.
        let epoch = parse_iso8601_to_epoch("1999-12-31T19:00:00-05:00").unwrap();
        assert_eq!(epoch, 946684800);
    }

    #[test]
    fn iso8601_rejects_invalid_offsets_and_missing_timezone() {
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+24:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+05:60").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+0500").is_none());
        // Malformed signs must fail closed, never invert (R4 NIT):
        // "+-8:00" would otherwise parse as −08:00.
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+-8:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00++8:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+0a:00").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00+08:b0").is_none());
    }

    #[test]
    fn iso8601_multibyte_input_returns_none_not_panic() {
        // 19 bytes after the Z-strip but containing a multi-byte char —
        // the byte-slicing parser panicked on this shape (R1 sec-NIT-1).
        assert!(parse_iso8601_to_epoch("202é-01-01T00:00:0Z").is_none());
        assert!(parse_iso8601_to_epoch("2026-04-10T15:30:00±08:00").is_none());
    }

    #[test]
    fn iso8601_pre_epoch_year_rejected_not_underflow() {
        assert!(parse_iso8601_to_epoch("1960-01-01T00:00:00Z").is_none());
    }

    #[test]
    fn iso8601_positive_offset_past_epoch_clamps_to_zero() {
        // naive 1800 − offset 3600 would go negative; the contract is
        // clamp-to-zero (an instantly-expired window), never a wrap or
        // panic (R3 NIT — pin the chosen behavior).
        let epoch = parse_iso8601_to_epoch("1970-01-01T00:30:00+01:00").unwrap();
        assert_eq!(epoch, 0);
    }

    #[test]
    fn iso8601_fractional_seconds_with_numeric_offset() {
        // The tz split happens BEFORE the dot truncation, so a
        // fractional+offset timestamp (plausible China-region drift —
        // the case the offset arm was added for) parses correctly.
        let epoch = parse_iso8601_to_epoch("2000-01-01T08:00:00.841665+08:00").unwrap();
        assert_eq!(epoch, 946684800);
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

    /// M4-4 AC: when `profiles.json::by_slot` is populated, the Anthropic
    /// usage poller reads the bearer token from
    /// `identities/<UUID>/credentials.json`. Validated by seeding the
    /// identity-keyed file with a distinctive token and the legacy path
    /// with a DIFFERENT token; the mock HTTP closure captures the token
    /// it was given and we assert it matches the identity-keyed value.
    #[tokio::test]
    async fn anthropic_usage_poller_reads_identity_credentials() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot: u16 = 1;

        // Seed `profiles.json::by_slot` so the poller routes UUID-keyed.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(slot);
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert(slot.to_string(), uuid);
        profiles.set_profile(
            slot,
            crate::accounts::profiles::AccountProfile {
                email: "m4-4-anthropic-poller@test.invalid".into(),
                method: "oauth".into(),
                extra: Default::default(),
            },
        );
        crate::accounts::profiles::save(&crate::accounts::profiles::profiles_path(base), &profiles)
            .unwrap();

        // Identity-keyed: distinctive token. This is what the poller MUST read.
        let identity_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        let identity_creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-IDENTITY-KEYED-TOKEN".into()),
                refresh_token: RefreshToken::new("rt-identity".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        credentials::save(&identity_path, &identity_creds).unwrap();

        // Legacy path: DIFFERENT token. The poller must NOT read this.
        let num = AccountNum::try_from(slot).unwrap();
        let legacy_creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-LEGACY-TOKEN-DO-NOT-READ".into()),
                refresh_token: RefreshToken::new("rt-legacy".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        credentials::save(&cred_file::canonical_path(base, num), &legacy_creds).unwrap();

        // Mock HTTP that captures the bearer token.
        let captured_token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured_token_clone = Arc::clone(&captured_token);
        let http: HttpGetFn =
            Arc::new(move |_url: &str, token: &str, _headers: &[(&str, &str)]| {
                *captured_token_clone.lock().unwrap() = Some(token.to_string());
                let body = br#"{
                "five_hour": { "utilization": 42.0, "resets_at": "2099-01-01T00:00:00Z" },
                "seven_day": { "utilization": 15.0, "resets_at": "2099-01-14T00:00:00Z" }
            }"#;
                Ok((200, body.to_vec()))
            });

        let cooldowns = Arc::new(Mutex::new(HashMap::new()));
        let backoffs = Arc::new(Mutex::new(HashMap::new()));

        tick(base, &http, &cooldowns, &backoffs).await;

        let captured = captured_token.lock().unwrap().clone();
        assert_eq!(
            captured.as_deref(),
            Some("sk-ant-oat01-IDENTITY-KEYED-TOKEN"),
            "poller MUST read the bearer token from identities/<UUID>/credentials.json, \
             not from credentials/<N>.json"
        );

        // Quota was written for the slot.
        let quota = quota_state::load_state(base).unwrap();
        let q = quota.get(slot).expect("quota for slot 1");
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

        // Prime an expired cooldown. On fresh CI runners Instant::now() may
        // be less than FAILURE_COOLDOWN since boot, so checked_sub returns
        // None — skip the test rather than panic. See refresher.rs for the
        // same pattern and a full explanation of the trade-off.
        let past = match Instant::now()
            .checked_sub(super::super::FAILURE_COOLDOWN + Duration::from_secs(1))
        {
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

        tick(dir.path(), &http, &cooldowns, &backoffs).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert!(!in_cooldown(&cooldowns, 1));
    }

    /// MED-1 (an internal ticket redteam): a schema-drifted `quota.json` (from a
    /// newer csq build) must NOT be clobbered by this write leg. Before
    /// the fix, `load_state_or_warn`'s `QuotaFile::empty()` fallback let
    /// `write_usage_to_quota` persist a ONE-row file for slot 3, wiping
    /// slots 1 and 2. The fixed `load_state_or_skip` path returns `Ok(())`
    /// without touching the file at all.
    #[test]
    fn write_usage_to_quota_skips_on_poisoned_file_preserving_siblings() {
        let dir = TempDir::new().unwrap();
        let poisoned = r#"{
            "schema_version": 99,
            "accounts": {
                "1": {"five_hour": {"used_percentage": 50.0, "resets_at": 4102444800}, "updated_at": 1.0},
                "2": {"five_hour": {"used_percentage": 80.0, "resets_at": 4102444800}, "updated_at": 1.0}
            }
        }"#;
        std::fs::write(quota_state::quota_path(dir.path()), poisoned).unwrap();

        let account = AccountNum::try_from(3u16).unwrap();
        let usage = UsageData {
            five_hour: Some(crate::quota::UsageWindow {
                used_percentage: 12.0,
                resets_at: 4_102_444_800,
            }),
            seven_day: None,
        };
        let result = write_usage_to_quota(dir.path(), account, &usage);
        assert!(result.is_ok(), "skip must be Ok(()), not an error");

        let raw = std::fs::read_to_string(quota_state::quota_path(dir.path())).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            v["accounts"]["1"]["five_hour"]["used_percentage"].as_f64(),
            Some(50.0),
            "slot 1 must survive untouched"
        );
        assert_eq!(
            v["accounts"]["2"]["five_hour"]["used_percentage"].as_f64(),
            Some(80.0),
            "slot 2 must survive untouched"
        );
        assert!(
            v["accounts"].get("3").is_none(),
            "slot 3 write must have been skipped entirely, not persisted"
        );
    }
}
