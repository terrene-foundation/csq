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

    // Select the model entry whose quota Claude Code consumes:
    //  1. prefix match on the configured model (`MiniMax-M2` ↔ `MiniMax-M2.7`) —
    //     the count-metered coding-plan shape whose model_name is a `MiniMax-M*`;
    //  2. else the `general` text-generation entry — the percentage-metered
    //     coding-plan shape (model_name is `general`, not a `MiniMax-M*` name);
    //  3. else the first entry. Preferring `general` over `.first()` avoids
    //     depending on the array order (the response also carries `video`/`music`
    //     rows whose quota is irrelevant to CC text usage).
    let entry = model_remains
        .iter()
        .find(|e| {
            e.get("model_name")
                .and_then(|v| v.as_str())
                .is_some_and(|name| name.starts_with(model) || model.starts_with(name))
        })
        .or_else(|| {
            model_remains
                .iter()
                .find(|e| e.get("model_name").and_then(|v| v.as_str()) == Some("general"))
        })
        .or_else(|| model_remains.first())
        .ok_or_else(|| PollError::Parse("model_remains array is empty".into()))?;

    let five_hour = window_from_entry(
        entry,
        "current_interval_total_count",
        "current_interval_usage_count",
        "current_interval_remaining_percent",
        "end_time",
    );
    let seven_day = window_from_entry(
        entry,
        "current_weekly_total_count",
        "current_weekly_usage_count",
        "current_weekly_remaining_percent",
        "weekly_end_time",
    );

    Ok(MiniMaxQuota {
        five_hour,
        seven_day,
    })
}

/// Builds a [`UsageWindow`] from a `model_remains` entry, handling BOTH MiniMax
/// coding-plan metering shapes:
///
///  - **count-metered** (`*_total_count` > 0): `used = total - remaining` where
///    "usage_count" is the REMAINING count (the endpoint is `/remains`).
///  - **percentage-metered** (`*_total_count` is 0/absent — the coding plan's
///    `general` shape): `used = 100 - *_remaining_percent`. Without this fallback
///    a percentage-metered plan (the live 2026-07 coding-plan shape) yielded no
///    window at all, so slot rendered `not quota-polled` despite valid usage data.
///
/// Returns `None` only when neither signal is present or the reset timestamp is
/// missing (parity with the prior count-only behavior).
fn window_from_entry(
    entry: &serde_json::Value,
    total_key: &str,
    usage_key: &str,
    remaining_pct_key: &str,
    end_key: &str,
) -> Option<UsageWindow> {
    let resets_at = entry
        .get(end_key)
        .and_then(|v| v.as_u64())
        .map(|ms| ms / 1000)?;

    // Count-metered plans: used = total - remaining (guarded total > 0).
    if let (Some(total), Some(remaining)) = (
        entry.get(total_key).and_then(|v| v.as_u64()),
        entry.get(usage_key).and_then(|v| v.as_u64()),
    ) {
        if total > 0 {
            let used = total.saturating_sub(remaining);
            return Some(UsageWindow {
                used_percentage: used as f64 / total as f64 * 100.0,
                resets_at,
            });
        }
    }

    // Percentage-metered plans (coding plan): used = 100 - remaining_percent.
    if let Some(rem_pct) = entry.get(remaining_pct_key).and_then(|v| v.as_f64()) {
        return Some(UsageWindow {
            used_percentage: (100.0 - rem_pct).clamp(0.0, 100.0),
            resets_at,
        });
    }

    None
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

    #[test]
    fn poll_minimax_percentage_metered_coding_plan() {
        // The live 2026-07 coding-plan `/remains` shape: percentage-metered,
        // `total_count` is 0, quota is in `*_remaining_percent`. The `general`
        // (text) entry is the one CC consumes; the `video` entry is irrelevant.
        // Regression for slot rendering `not quota-polled` despite valid usage.
        let response = r#"{"model_remains":[
            {"model_name":"general","current_interval_total_count":0,"current_interval_usage_count":0,"end_time":1783350000000,"current_interval_remaining_percent":99,"current_weekly_total_count":0,"current_weekly_usage_count":0,"weekly_end_time":1783900800000,"current_weekly_remaining_percent":97},
            {"model_name":"video","current_interval_total_count":5,"current_interval_usage_count":5,"end_time":1783350000000,"current_interval_remaining_percent":100,"current_weekly_total_count":35,"current_weekly_usage_count":35,"weekly_end_time":1783900800000,"current_weekly_remaining_percent":100}
        ]}"#;
        let http = mock_minimax_get(response);
        // Configured model "MiniMax-M3" matches no entry → prefers `general`.
        let mm = poll_minimax_quota("key", None, "MiniMax-M3", &http).unwrap();

        let fh = mm
            .five_hour
            .expect("five_hour must be populated from remaining_percent");
        // used = 100 - 99 = 1%
        assert!(
            (fh.used_percentage - 1.0).abs() < 0.01,
            "got {}",
            fh.used_percentage
        );
        assert_eq!(fh.resets_at, 1783350000);

        let sd = mm
            .seven_day
            .expect("seven_day must be populated from remaining_percent");
        // used = 100 - 97 = 3%
        assert!(
            (sd.used_percentage - 3.0).abs() < 0.01,
            "got {}",
            sd.used_percentage
        );
        assert_eq!(sd.resets_at, 1783900800);
    }
}
