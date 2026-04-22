//! Quota tracking — usage windows, state management, and formatting.

pub mod format;
pub mod state;
pub mod status;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level quota file. Maps account numbers (as strings) to usage data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaFile {
    /// Schema version. v1 files (pre-PR-C6) omit this and default to 1.
    /// v2 files (post-PR-C6) set this to 2. Unknown values error on parse.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub accounts: HashMap<String, AccountQuota>,
}

fn default_schema_version() -> u32 {
    1
}

impl QuotaFile {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            accounts: HashMap::new(),
        }
    }

    /// Gets quota for an account, or None if not tracked.
    pub fn get(&self, account: u16) -> Option<&AccountQuota> {
        self.accounts.get(&account.to_string())
    }

    /// Sets quota for an account.
    pub fn set(&mut self, account: u16, quota: AccountQuota) {
        self.accounts.insert(account.to_string(), quota);
    }
}

/// Usage data for a single account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountQuota {
    // ── v2 mandatory-with-default ───────────────────────────────────────────
    /// Surface that produced this quota record.
    /// Defaults to `"claude-code"` on v1 files (field absent).
    /// Allowed: `"claude-code"` | `"codex"` | `"gemini"`.
    #[serde(default = "default_surface")]
    pub surface: String,
    /// Quota kind: `"utilization"` (Anthropic/Codex) | `"counter"` (Gemini)
    /// | `"unknown"` (schema-drift degradation state).
    /// Defaults to `"utilization"` on v1 files (field absent).
    #[serde(default = "default_kind")]
    pub kind: String,

    // ── v1 utilization fields (unchanged) ──────────────────────────────────
    pub five_hour: Option<UsageWindow>,
    pub seven_day: Option<UsageWindow>,
    /// Rate-limit data from 3P providers (extracted from response headers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<RateLimitData>,
    pub updated_at: f64,

    // ── v2 Gemini-reserved counter fields (all optional) ───────────────────
    /// Requests issued by the CLI this `resets_at_tz` day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<u64>,
    /// Daily cap if known (from RESOURCE_EXHAUSTED 429 body).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<u64>,
    /// IANA TZ identifier of reset cadence (e.g. `"America/Los_Angeles"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at_tz: Option<String>,
    /// Model the user requested (as written in settings.json model.name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_model: Option<String>,
    /// Model Gemini actually used (per-response modelVersion field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_model: Option<String>,
    /// Count of responses where effective_model != selected_model today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mismatch_count_today: Option<u32>,
    /// Derived: true when mismatch_count_today >= DOWNGRADE_DEBOUNCE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_downgrade: Option<bool>,
}

fn default_surface() -> String {
    "claude-code".into()
}

fn default_kind() -> String {
    "utilization".into()
}

impl Default for AccountQuota {
    fn default() -> Self {
        Self {
            surface: default_surface(),
            kind: default_kind(),
            five_hour: None,
            seven_day: None,
            rate_limits: None,
            updated_at: 0.0,
            counter: None,
            rate_limit: None,
            resets_at_tz: None,
            selected_model: None,
            effective_model: None,
            mismatch_count_today: None,
            is_downgrade: None,
        }
    }
}

/// Rate-limit data extracted from `anthropic-ratelimit-*` response headers.
///
/// 3P providers (Z.AI, MiniMax) return these headers on every API call.
/// We poll with a minimal `max_tokens=1` request to capture them without
/// consuming real quota.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitData {
    pub requests_limit: Option<u64>,
    pub requests_remaining: Option<u64>,
    pub tokens_limit: Option<u64>,
    pub tokens_remaining: Option<u64>,
    pub input_tokens_limit: Option<u64>,
    pub output_tokens_limit: Option<u64>,
}

impl RateLimitData {
    /// Returns `true` if at least one rate-limit field was populated.
    pub fn has_data(&self) -> bool {
        self.requests_limit.is_some()
            || self.requests_remaining.is_some()
            || self.tokens_limit.is_some()
            || self.tokens_remaining.is_some()
            || self.input_tokens_limit.is_some()
            || self.output_tokens_limit.is_some()
    }

    /// Computes token usage as a percentage (0.0–100.0).
    ///
    /// Uses `(limit - remaining) / limit * 100`. Returns `None` if
    /// both `tokens_limit` and `tokens_remaining` are missing.
    pub fn token_usage_pct(&self) -> Option<f64> {
        match (self.tokens_limit, self.tokens_remaining) {
            (Some(limit), Some(remaining)) if limit > 0 => {
                let used = limit.saturating_sub(remaining);
                Some(used as f64 / limit as f64 * 100.0)
            }
            _ => None,
        }
    }

    /// Computes request usage as a percentage (0.0–100.0).
    pub fn request_usage_pct(&self) -> Option<f64> {
        match (self.requests_limit, self.requests_remaining) {
            (Some(limit), Some(remaining)) if limit > 0 => {
                let used = limit.saturating_sub(remaining);
                Some(used as f64 / limit as f64 * 100.0)
            }
            _ => None,
        }
    }
}

impl AccountQuota {
    /// Clears expired windows based on current time.
    pub fn clear_expired(&mut self, now_secs: u64) {
        if let Some(ref w) = self.five_hour {
            if w.resets_at <= now_secs {
                self.five_hour = None;
            }
        }
        if let Some(ref w) = self.seven_day {
            if w.resets_at <= now_secs {
                self.seven_day = None;
            }
        }
    }

    /// Returns the 5-hour usage percentage (0-100), or 0 if no data.
    pub fn five_hour_pct(&self) -> f64 {
        self.five_hour
            .as_ref()
            .map(|w| w.used_percentage)
            .unwrap_or(0.0)
    }

    /// Returns the 7-day usage percentage (0-100), or 0 if no data.
    pub fn seven_day_pct(&self) -> f64 {
        self.seven_day
            .as_ref()
            .map(|w| w.used_percentage)
            .unwrap_or(0.0)
    }
}

/// A single usage window (5-hour or 7-day).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageWindow {
    pub used_percentage: f64,
    pub resets_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_expired_removes_old_windows() {
        let mut quota = AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: 80.0,
                resets_at: 1000,
            }),
            seven_day: Some(UsageWindow {
                used_percentage: 50.0,
                resets_at: 2000,
            }),
            updated_at: 500.0,
            ..Default::default()
        };

        quota.clear_expired(1500); // 5h expired, 7d not
        assert!(quota.five_hour.is_none());
        assert!(quota.seven_day.is_some());

        quota.clear_expired(2500); // both expired
        assert!(quota.seven_day.is_none());
    }

    #[test]
    fn clear_expired_keeps_active_windows() {
        let mut quota = AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: 80.0,
                resets_at: 5000,
            }),
            seven_day: Some(UsageWindow {
                used_percentage: 50.0,
                resets_at: 10000,
            }),
            updated_at: 500.0,
            ..Default::default()
        };

        quota.clear_expired(1000);
        assert!(quota.five_hour.is_some());
        assert!(quota.seven_day.is_some());
    }

    #[test]
    fn pct_helpers() {
        let quota = AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: 94.0,
                resets_at: 5000,
            }),
            ..Default::default()
        };

        assert_eq!(quota.five_hour_pct(), 94.0);
        assert_eq!(quota.seven_day_pct(), 0.0);
    }

    #[test]
    fn quota_file_get_set() {
        let mut qf = QuotaFile::empty();
        assert!(qf.get(1).is_none());

        qf.set(
            1,
            AccountQuota {
                updated_at: 123.0,
                ..Default::default()
            },
        );
        assert!(qf.get(1).is_some());
        assert_eq!(qf.get(1).unwrap().updated_at, 123.0);
    }
}
