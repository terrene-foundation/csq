//! Z.AI direct quota API polling.
//!
//! Polls `GET https://api.z.ai/api/monitor/usage/quota/limit`
//! for authoritative usage data (5-hour and 7-day windows).

use crate::quota::{state as quota_state, AccountQuota, QuotaFile, UsageWindow};
use tracing::debug;

use super::{HttpGetFn, PollError};

/// Z.AI quota data parsed from `/api/monitor/usage/quota/limit`.
///
/// Same shape as MiniMax: both 5h and 7d windows.
#[derive(Debug, Clone)]
pub(crate) struct ZaiQuota {
    pub five_hour: Option<UsageWindow>,
    pub seven_day: Option<UsageWindow>,
}

/// Polls Z.AI's quota API for authoritative usage data.
///
/// Endpoint: `GET https://api.z.ai/api/monitor/usage/quota/limit`
/// Auth: `Authorization: Bearer <API_KEY>` (same key used for messages)
///
/// Response shape (live-verified 2026-04-12):
/// ```json
/// { "code": 200, "data": { "limits": [
///   { "type": "TOKENS_LIMIT", "unit": 3, "percentage": 6, "nextResetTime": 1776025018977 },
///   { "type": "TOKENS_LIMIT", "unit": 6, "percentage": 11, "nextResetTime": 1776389633997 }
/// ], "level": "max" } }
/// ```
///
/// Unit mapping: 3 = 5-hour, 6 = 7-day. `percentage` is already 0-100.
pub(crate) fn poll_zai_quota(api_key: &str, http_get: &HttpGetFn) -> Result<ZaiQuota, PollError> {
    let url = "https://api.z.ai/api/monitor/usage/quota/limit";
    let extra_headers = [("Accept", "application/json")];

    let (status, body) = http_get(url, api_key, &extra_headers).map_err(PollError::Transport)?;

    match status {
        429 => return Err(PollError::RateLimited),
        401 => return Err(PollError::Unauthorized),
        200 => {}
        other => return Err(PollError::HttpError(other)),
    }

    let json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| PollError::Parse(e.to_string()))?;

    let limits = json
        .get("data")
        .and_then(|d| d.get("limits"))
        .and_then(|l| l.as_array())
        .ok_or_else(|| PollError::Parse("missing data.limits array".into()))?;

    let mut five_hour = None;
    let mut seven_day = None;

    for lim in limits {
        let lim_type = lim.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let unit = lim.get("unit").and_then(|v| v.as_u64()).unwrap_or(0);
        let pct = lim.get("percentage").and_then(|v| v.as_f64());
        let reset_ms = lim.get("nextResetTime").and_then(|v| v.as_u64());

        if lim_type != "TOKENS_LIMIT" {
            continue;
        }

        if let (Some(pct), Some(reset_ms)) = (pct, reset_ms) {
            let window = UsageWindow {
                used_percentage: pct,
                resets_at: reset_ms / 1000, // ms → epoch seconds
            };
            match unit {
                3 => five_hour = Some(window), // unit 3 = 5-hour
                6 => seven_day = Some(window), // unit 6 = 7-day
                _ => {}
            }
        }
    }

    Ok(ZaiQuota {
        five_hour,
        seven_day,
    })
}

/// Writes Z.AI quota data (both 5h and 7d windows) into `quota.json`.
pub(crate) fn write_zai_quota(
    base_dir: &std::path::Path,
    account_id: u16,
    zai: &ZaiQuota,
) -> Result<(), crate::error::CsqError> {
    let lock_path = quota_state::quota_path(base_dir).with_extension("lock");
    let _guard = crate::platform::lock::lock_file(&lock_path)?;
    let mut quota = quota_state::load_state(base_dir).unwrap_or_else(|_| QuotaFile::empty());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    quota.set(
        account_id,
        AccountQuota {
            five_hour: zai.five_hour.clone(),
            seven_day: zai.seven_day.clone(),
            rate_limits: None,
            updated_at: now,
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account_id, "Z.AI poller: quota file updated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn mock_zai_get_static(response: &'static str) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            Ok((200, response.as_bytes().to_vec()))
        })
    }

    #[test]
    fn poll_zai_parses_both_windows() {
        let response = r#"{"code":200,"data":{"limits":[{"type":"TOKENS_LIMIT","unit":3,"percentage":6,"nextResetTime":1776025018977},{"type":"TOKENS_LIMIT","unit":6,"percentage":11,"nextResetTime":1776389633997}],"level":"max"}}"#;
        let http = mock_zai_get_static(response);
        let result = poll_zai_quota("key", &http);
        assert!(result.is_ok());
        let zai = result.unwrap();

        let fh = zai.five_hour.unwrap();
        assert!((fh.used_percentage - 6.0).abs() < 0.01);
        assert_eq!(fh.resets_at, 1776025018); // ms → s

        let sd = zai.seven_day.unwrap();
        assert!((sd.used_percentage - 11.0).abs() < 0.01);
        assert_eq!(sd.resets_at, 1776389633);
    }

    #[test]
    fn poll_zai_ignores_non_token_limits() {
        // TIME_LIMIT entries should be skipped
        let response = r#"{"code":200,"data":{"limits":[{"type":"TIME_LIMIT","unit":5,"percentage":6,"nextResetTime":1776000000000},{"type":"TOKENS_LIMIT","unit":3,"percentage":42,"nextResetTime":1776025018977}],"level":"max"}}"#;
        let http = mock_zai_get_static(response);
        let result = poll_zai_quota("key", &http).unwrap();
        assert!(result.five_hour.is_some());
        assert!((result.five_hour.unwrap().used_percentage - 42.0).abs() < 0.01);
        assert!(result.seven_day.is_none()); // no unit=6 entry
    }

    #[test]
    fn poll_zai_401_returns_unauthorized() {
        let http: HttpGetFn = Arc::new(|_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            Ok((401, b"unauthorized".to_vec()))
        });
        let result = poll_zai_quota("bad-key", &http);
        assert!(matches!(result, Err(PollError::Unauthorized)));
    }
}
