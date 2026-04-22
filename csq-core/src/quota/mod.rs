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

    // ── §7.4.2 canonical consumer tests (PR-B8) ──────────────────────────

    /// 1. Parse v1 file unchanged — legacy file reads exactly as before spec 07.
    #[test]
    fn parses_v1_file_unchanged() {
        // Arrange — v1 shape: no schema_version, no surface/kind, classic fields.
        let json = r#"{
            "accounts": {
                "1": {
                    "five_hour": {"used_percentage": 42.0, "resets_at": 4102444800},
                    "seven_day": {"used_percentage": 8.0, "resets_at": 4102444800},
                    "updated_at": 1775722800.0
                }
            }
        }"#;

        // Act
        let qf: QuotaFile = serde_json::from_str(json).unwrap();

        // Assert
        assert_eq!(
            qf.schema_version, 1,
            "missing schema_version must default to 1"
        );
        let account = qf.accounts.get("1").expect("account 1 must parse");
        assert_eq!(
            account.surface, "claude-code",
            "v1 surface must default to claude-code"
        );
        assert_eq!(
            account.kind, "utilization",
            "v1 kind must default to utilization"
        );
        assert_eq!(account.five_hour.as_ref().unwrap().used_percentage, 42.0);
        assert_eq!(account.seven_day.as_ref().unwrap().used_percentage, 8.0);
        // All Gemini-reserved optional fields must be None
        assert!(account.counter.is_none());
        assert!(account.rate_limit.is_none());
        assert!(account.resets_at_tz.is_none());
        assert!(account.selected_model.is_none());
        assert!(account.effective_model.is_none());
        assert!(account.mismatch_count_today.is_none());
        assert!(account.is_downgrade.is_none());
    }

    /// 2. Parse v2 file with Claude-only accounts — migrated v1 with explicit fields.
    #[test]
    fn parses_v2_file_with_claude_only_accounts() {
        // Arrange
        let json = r#"{
            "schema_version": 2,
            "accounts": {
                "1": {
                    "surface": "claude-code",
                    "kind": "utilization",
                    "five_hour": {"used_percentage": 42.0, "resets_at": 4102444800},
                    "seven_day": {"used_percentage": 8.0, "resets_at": 4102444800},
                    "updated_at": 1775722800.0
                }
            }
        }"#;

        // Act
        let qf: QuotaFile = serde_json::from_str(json).unwrap();

        // Assert
        assert_eq!(qf.schema_version, 2);
        let account = qf.accounts.get("1").expect("account 1 must parse");
        assert_eq!(account.surface, "claude-code");
        assert_eq!(account.kind, "utilization");
        assert_eq!(account.five_hour.as_ref().unwrap().used_percentage, 42.0);
        assert_eq!(account.seven_day.as_ref().unwrap().used_percentage, 8.0);
        // No Gemini fields on a claude-code account
        assert!(account.counter.is_none());
        assert!(account.resets_at_tz.is_none());
    }

    /// 3. Parse v2 file with mixed surfaces — the spec §7.4.1 example file.
    #[test]
    fn parses_v2_file_with_mixed_surfaces() {
        // Arrange — exact example from spec §7.4.1
        let json = r#"{
            "schema_version": 2,
            "accounts": {
                "1": {
                    "surface": "claude-code",
                    "kind": "utilization",
                    "five_hour": {"used_percentage": 42.0, "resets_at": 1775726400},
                    "seven_day": {"used_percentage": 8.0, "resets_at": 1776196800},
                    "rate_limits": null,
                    "updated_at": 1775722800.0
                },
                "2": {
                    "surface": "codex",
                    "kind": "utilization",
                    "five_hour": {"used_percentage": 18.0, "resets_at": 1775726400},
                    "seven_day": null,
                    "rate_limits": null,
                    "updated_at": 1775722800.0
                },
                "3": {
                    "surface": "gemini",
                    "kind": "counter",
                    "updated_at": 1775722800.0,
                    "counter": 42,
                    "rate_limit": 1000,
                    "resets_at_tz": "America/Los_Angeles",
                    "selected_model": "gemini-2.5-pro",
                    "effective_model": "gemini-2.5-pro",
                    "mismatch_count_today": 0,
                    "is_downgrade": false
                }
            }
        }"#;

        // Act
        let qf: QuotaFile = serde_json::from_str(json).unwrap();

        // Assert — account 1 (claude-code)
        assert_eq!(qf.schema_version, 2);
        let a1 = qf.accounts.get("1").expect("account 1");
        assert_eq!(a1.surface, "claude-code");
        assert_eq!(a1.kind, "utilization");
        assert_eq!(a1.five_hour.as_ref().unwrap().used_percentage, 42.0);

        // Assert — account 2 (codex)
        let a2 = qf.accounts.get("2").expect("account 2");
        assert_eq!(a2.surface, "codex");
        assert_eq!(a2.kind, "utilization");
        assert_eq!(a2.five_hour.as_ref().unwrap().used_percentage, 18.0);
        assert!(a2.seven_day.is_none());

        // Assert — account 3 (gemini counter)
        let a3 = qf.accounts.get("3").expect("account 3");
        assert_eq!(a3.surface, "gemini");
        assert_eq!(a3.kind, "counter");
        assert_eq!(a3.counter, Some(42));
        assert_eq!(a3.rate_limit, Some(1000));
        assert_eq!(a3.resets_at_tz.as_deref(), Some("America/Los_Angeles"));
        assert_eq!(a3.selected_model.as_deref(), Some("gemini-2.5-pro"));
        assert_eq!(a3.effective_model.as_deref(), Some("gemini-2.5-pro"));
        assert_eq!(a3.mismatch_count_today, Some(0));
        assert_eq!(a3.is_downgrade, Some(false));
    }

    /// 4. Parse v2 file missing optional Gemini fields — null-defaults applied without panic.
    #[test]
    fn parses_v2_file_missing_optional_gemini_fields() {
        // Arrange — Gemini account with surface/kind but no counter fields
        let json = r#"{
            "schema_version": 2,
            "accounts": {
                "5": {
                    "surface": "gemini",
                    "kind": "counter",
                    "updated_at": 1775722800.0
                }
            }
        }"#;

        // Act
        let qf: QuotaFile = serde_json::from_str(json).unwrap();

        // Assert
        let a5 = qf.accounts.get("5").expect("account 5");
        assert_eq!(a5.surface, "gemini");
        assert_eq!(a5.kind, "counter");
        // All optional Gemini fields default to None without panic
        assert!(a5.counter.is_none());
        assert!(a5.rate_limit.is_none());
        assert!(a5.resets_at_tz.is_none());
        assert!(a5.selected_model.is_none());
        assert!(a5.effective_model.is_none());
        assert!(a5.mismatch_count_today.is_none());
        assert!(a5.is_downgrade.is_none());
    }

    /// 5. Parse v2 file with schema_version=3 errors with actionable message.
    #[test]
    fn parses_v2_file_with_schema_version_3_errors() {
        use crate::error::ConfigError;
        use tempfile::TempDir;

        // Arrange — write a file with schema_version 3
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("quota.json");
        let json = r#"{"schema_version":3,"accounts":{}}"#;
        std::fs::write(&path, json).unwrap();

        // Act — load_state must enforce the version range
        let result = super::state::load_state(dir.path());

        // Assert — must be an error containing "schema_version" and "3"/"newer"
        assert!(result.is_err(), "schema_version 3 must be rejected");
        let err = result.unwrap_err();
        match &err {
            ConfigError::InvalidJson { reason, .. } => {
                assert!(
                    reason.contains("schema_version"),
                    "error must mention schema_version, got: {reason}"
                );
                assert!(
                    reason.contains("3") || reason.contains("newer"),
                    "error must name the version or 'newer', got: {reason}"
                );
            }
            other => panic!("expected InvalidJson, got: {other:?}"),
        }
    }

    /// 6. Round-trip v2 → save → load identical — no drift across the write path.
    #[test]
    fn round_trip_v2_load_save_identical() {
        use tempfile::TempDir;

        // Arrange — construct a v2 file with one Claude and one Gemini account
        let dir = TempDir::new().unwrap();
        let mut original = QuotaFile {
            schema_version: 2,
            accounts: std::collections::HashMap::new(),
        };
        original.set(
            1,
            AccountQuota {
                surface: "claude-code".into(),
                kind: "utilization".into(),
                five_hour: Some(UsageWindow {
                    used_percentage: 42.0,
                    resets_at: 4_102_444_800,
                }),
                seven_day: Some(UsageWindow {
                    used_percentage: 8.0,
                    resets_at: 4_102_444_800,
                }),
                updated_at: 1_775_722_800.0,
                ..Default::default()
            },
        );
        original.set(
            3,
            AccountQuota {
                surface: "gemini".into(),
                kind: "counter".into(),
                updated_at: 1_775_722_800.0,
                counter: Some(42),
                rate_limit: Some(1000),
                resets_at_tz: Some("America/Los_Angeles".into()),
                selected_model: Some("gemini-2.5-pro".into()),
                effective_model: Some("gemini-2.5-pro".into()),
                mismatch_count_today: Some(0),
                is_downgrade: Some(false),
                ..Default::default()
            },
        );

        // Act — save, then reload
        super::state::save_state(dir.path(), &original).unwrap();
        let reloaded = super::state::load_state(dir.path()).unwrap();

        // Assert — schema_version and per-account fields round-trip stably
        assert_eq!(reloaded.schema_version, original.schema_version);

        let a1_orig = original.accounts.get("1").unwrap();
        let a1_reload = reloaded.accounts.get("1").unwrap();
        assert_eq!(a1_reload.surface, a1_orig.surface);
        assert_eq!(a1_reload.kind, a1_orig.kind);
        assert_eq!(
            a1_reload.five_hour.as_ref().unwrap().used_percentage,
            a1_orig.five_hour.as_ref().unwrap().used_percentage
        );
        assert_eq!(
            a1_reload.seven_day.as_ref().unwrap().used_percentage,
            a1_orig.seven_day.as_ref().unwrap().used_percentage
        );

        let a3_orig = original.accounts.get("3").unwrap();
        let a3_reload = reloaded.accounts.get("3").unwrap();
        assert_eq!(a3_reload.surface, a3_orig.surface);
        assert_eq!(a3_reload.kind, a3_orig.kind);
        assert_eq!(a3_reload.counter, a3_orig.counter);
        assert_eq!(a3_reload.rate_limit, a3_orig.rate_limit);
        assert_eq!(a3_reload.resets_at_tz, a3_orig.resets_at_tz);
        assert_eq!(a3_reload.selected_model, a3_orig.selected_model);
        assert_eq!(a3_reload.effective_model, a3_orig.effective_model);
        assert_eq!(a3_reload.mismatch_count_today, a3_orig.mismatch_count_today);
        assert_eq!(a3_reload.is_downgrade, a3_orig.is_downgrade);
    }
}
