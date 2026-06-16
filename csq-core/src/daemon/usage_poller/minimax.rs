//! MiniMax direct quota API polling.
//!
//! Polls `GET https://platform.minimax.io/v1/api/openplatform/coding_plan/remains`
//! for authoritative usage data (5-hour and 7-day windows).

use crate::quota::{state as quota_state, AccountQuota, QuotaFile, UsageWindow};
use tracing::debug;

use super::{HttpGetFn, PollError};

/// MiniMax quota data parsed from the `/coding_plan/remains` endpoint.
///
/// Carries both the 5-hour interval and 7-day weekly windows so the
/// caller can write a complete `AccountQuota` entry.
#[derive(Debug, Clone)]
pub(crate) struct MiniMaxQuota {
    /// 5-hour interval: used percentage and reset epoch.
    pub five_hour: Option<UsageWindow>,
    /// 7-day weekly: used percentage and reset epoch.
    pub seven_day: Option<UsageWindow>,
}

/// Polls MiniMax's direct quota API for authoritative usage data.
///
/// Endpoint: `GET https://platform.minimax.io/v1/api/openplatform/coding_plan/remains`
/// Auth: `Authorization: Bearer <API_KEY>`
///
/// **CRITICAL**: The endpoint is `/remains` — field names contain
/// "usage_count" but the values are REMAINING counts, not consumed
/// counts. `current_interval_usage_count: 29957` out of `total: 30000`
/// means 29957 REMAIN and only 43 were USED.
///
/// `used_percentage = (total - remaining) / total * 100`
pub(crate) fn poll_minimax_quota(
    api_key: &str,
    group_id: Option<&str>,
    model: &str,
    http_get: &HttpGetFn,
) -> Result<MiniMaxQuota, PollError> {
    // GroupId is optional — the API returns data for all models
    // without it. If provided, it scopes to a specific org.
    let url = match group_id {
        Some(gid) if !gid.is_empty() => format!(
            "https://platform.minimax.io/v1/api/openplatform/coding_plan/remains?GroupId={}",
            gid
        ),
        _ => "https://platform.minimax.io/v1/api/openplatform/coding_plan/remains".to_string(),
    };
    let extra_headers = [("Content-Type", "application/json")];

    let (status, body) = http_get(&url, api_key, &extra_headers).map_err(PollError::Transport)?;

    match status {
        429 => return Err(PollError::RateLimited),
        401 => return Err(PollError::Unauthorized),
        200 => {}
        other => return Err(PollError::HttpError(other)),
    }

    let json: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| PollError::Parse(e.to_string()))?;

    let model_remains = json
        .get("model_remains")
        .and_then(|v| v.as_array())
        .ok_or_else(|| PollError::Parse("missing model_remains array".into()))?;

    // Find the matching model entry. Accept prefix match so
    // "MiniMax-M2" matches "MiniMax-M2.7-highspeed". Also match
    // the wildcard "MiniMax-M*" which is the coding plan entry.
    let entry = model_remains
        .iter()
        .find(|e| {
            e.get("model_name")
                .and_then(|v| v.as_str())
                .is_some_and(|name| name.starts_with(model) || model.starts_with(name))
        })
        .or_else(|| model_remains.first())
        .ok_or_else(|| PollError::Parse("model_remains array is empty".into()))?;

    // 5-hour interval window.
    // CRITICAL: "usage_count" is the REMAINING count (endpoint = /remains).
    // used = total - remaining.
    let five_hour = match (
        entry
            .get("current_interval_total_count")
            .and_then(|v| v.as_u64()),
        entry
            .get("current_interval_usage_count")
            .and_then(|v| v.as_u64()),
        entry.get("end_time").and_then(|v| v.as_u64()),
    ) {
        (Some(total), Some(remaining), Some(end_ms)) if total > 0 => {
            let used = total.saturating_sub(remaining);
            Some(UsageWindow {
                used_percentage: used as f64 / total as f64 * 100.0,
                resets_at: end_ms / 1000, // ms → epoch seconds
            })
        }
        _ => None,
    };

    // 7-day weekly window (same remaining semantics).
    let seven_day = match (
        entry
            .get("current_weekly_total_count")
            .and_then(|v| v.as_u64()),
        entry
            .get("current_weekly_usage_count")
            .and_then(|v| v.as_u64()),
        entry.get("weekly_end_time").and_then(|v| v.as_u64()),
    ) {
        (Some(total), Some(remaining), Some(end_ms)) if total > 0 => {
            let used = total.saturating_sub(remaining);
            Some(UsageWindow {
                used_percentage: used as f64 / total as f64 * 100.0,
                resets_at: end_ms / 1000,
            })
        }
        _ => None,
    };

    Ok(MiniMaxQuota {
        five_hour,
        seven_day,
    })
}

/// Writes MiniMax quota data (both 5h and 7d windows) into `quota.json`.
pub(crate) fn write_minimax_quota(
    base_dir: &std::path::Path,
    account_id: u16,
    mm: &MiniMaxQuota,
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
            five_hour: mm.five_hour.clone(),
            seven_day: mm.seven_day.clone(),
            updated_at: now,
            ..Default::default()
        },
    );

    quota_state::save_state(base_dir, &quota)?;
    debug!(account = account_id, "MiniMax poller: quota file updated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn mock_minimax_get(response: &'static str) -> HttpGetFn {
        Arc::new(move |_url: &str, _token: &str, _headers: &[(&str, &str)]| {
            Ok((200, response.as_bytes().to_vec()))
        })
    }

    #[test]
    fn poll_minimax_parses_both_windows() {
        // usage_count = REMAINING (endpoint is /remains), NOT consumed.
        // total=30000, remaining=29850 → used=150 → 0.5%
        let response = r#"{"model_remains":[{
            "model_name":"MiniMax-M2.7",
            "current_interval_total_count":30000,
            "current_interval_usage_count":29850,
            "end_time":1776024000000,
            "current_weekly_total_count":300000,
            "current_weekly_usage_count":289000,
            "weekly_end_time":1776038400000
        }]}"#;
        let http = mock_minimax_get(response);
        let result = poll_minimax_quota("key", Some("123"), "MiniMax-M2", &http);
        assert!(result.is_ok());
        let mm = result.unwrap();

        let fh = mm.five_hour.unwrap();
        // used = 30000 - 29850 = 150, pct = 150/30000*100 = 0.5%
        assert!((fh.used_percentage - 0.5).abs() < 0.01);
        assert_eq!(fh.resets_at, 1776024000); // ms → s

        let sd = mm.seven_day.unwrap();
        // used = 300000 - 289000 = 11000, pct = 11000/300000*100 = 3.67%
        assert!((sd.used_percentage - 3.67).abs() < 0.1);
        assert_eq!(sd.resets_at, 1776038400);
    }

    #[test]
    fn poll_minimax_matches_model_prefix() {
        let response = r#"{"model_remains":[
            {"model_name":"MiniMax-M2.7-highspeed","current_interval_total_count":30000,"current_interval_usage_count":29000,"end_time":1776024000000,"current_weekly_total_count":300000,"current_weekly_usage_count":290000,"weekly_end_time":1776038400000},
            {"model_name":"MiniMax-M1","current_interval_total_count":10000,"current_interval_usage_count":9500,"end_time":1776024000000,"current_weekly_total_count":70000,"current_weekly_usage_count":60000,"weekly_end_time":1776038400000}
        ]}"#;
        let http = mock_minimax_get(response);
        let result = poll_minimax_quota("key", Some("123"), "MiniMax-M2", &http);
        let mm = result.unwrap();
        // Should match the M2.7-highspeed entry (used = 30000-29000 = 1000)
        let fh = mm.five_hour.unwrap();
        assert!((fh.used_percentage - 3.33).abs() < 0.1);
    }

    #[test]
    fn poll_minimax_works_without_group_id() {
        let response = r#"{"model_remains":[{"model_name":"MiniMax-M2","current_interval_total_count":1000,"current_interval_usage_count":800,"end_time":1776024000000,"current_weekly_total_count":7000,"current_weekly_usage_count":6000,"weekly_end_time":1776038400000}]}"#;
        let http = mock_minimax_get(response);
        let result = poll_minimax_quota("key", None, "MiniMax-M2", &http);
        assert!(result.is_ok());
        // used = 1000-800 = 200 → 20%
        let fh = result.unwrap().five_hour.unwrap();
        assert!((fh.used_percentage - 20.0).abs() < 0.01);
    }

    #[test]
    fn poll_minimax_works_with_empty_group_id() {
        let response = r#"{"model_remains":[{"model_name":"MiniMax-M2","current_interval_total_count":1000,"current_interval_usage_count":200,"end_time":1776024000000,"current_weekly_total_count":7000,"current_weekly_usage_count":6000,"weekly_end_time":1776038400000}]}"#;
        let http = mock_minimax_get(response);
        let result = poll_minimax_quota("key", Some(""), "MiniMax-M2", &http);
        assert!(result.is_ok());
    }

    #[test]
    fn poll_minimax_falls_back_to_first_model() {
        let response = r#"{"model_remains":[{"model_name":"SomeOtherModel","current_interval_total_count":5000,"current_interval_usage_count":4900,"end_time":1776024000000,"current_weekly_total_count":35000,"current_weekly_usage_count":34000,"weekly_end_time":1776038400000}]}"#;
        let http = mock_minimax_get(response);
        let result = poll_minimax_quota("key", Some("123"), "MiniMax-M2", &http);
        let mm = result.unwrap();
        // Falls back to first entry: used = 5000-4900 = 100 → 2%
        let fh = mm.five_hour.unwrap();
        assert!((fh.used_percentage - 2.0).abs() < 0.01);
    }
}
