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
    /// v2 files (post-PR-C6) set this to 2.
    /// schema_version > 2 degrades to empty + WARN (R3: rollback UX).
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

/// Per-day request counter state for Surface::Gemini.
///
/// Tracks the number of requests issued today and when the daily window resets.
/// Per spec 7.4.1: resets_at_tz is the IANA TZ for the reset cadence
/// (always "America/Los_Angeles" for Gemini); last_reset is optional.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct CounterState {
    /// CLI-sent request count since last reset.
    #[serde(default)]
    pub requests_today: u64,
    /// IANA TZ identifier of reset cadence (always "America/Los_Angeles" for Gemini).
    #[serde(default)]
    pub resets_at_tz: String,
    /// ISO-8601 timestamp of last midnight-TZ reset; null before first reset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reset: Option<String>,
}

/// 429 retry state for Surface::Gemini (generic enough for any 429-driven surface).
///
/// Per spec 7.4.1. All fields optional on the outer struct; inner fields have
/// their own defaults. active defaults to false.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RateLimitState {
    /// true during the 429 retry window.
    #[serde(default)]
    pub active: bool,
    /// ISO-8601 timestamp when the 429 retry window ends; null if unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_at: Option<String>,
    /// Most recent retryDelay from RESOURCE_EXHAUSTED body (diagnostic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_retry_delay_s: Option<u64>,
    /// Most recent quotaMetric from RESOURCE_EXHAUSTED body (diagnostic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_quota_metric: Option<String>,
    /// Daily cap (quotaValue) if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<u64>,
}

/// Usage data for a single account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountQuota {
    // -- v2 mandatory-with-default -------------------------------------------
    /// Surface that produced this quota record.
    /// Defaults to "claude-code" on v1 files (field absent).
    /// Allowed: "claude-code" | "codex" | "gemini".
    #[serde(default = "default_surface")]
    pub surface: String,
    /// Quota kind: "utilization" (Anthropic/Codex) | "counter" (Gemini)
    /// | "unknown" (schema-drift degradation state).
    /// Defaults to "utilization" on v1 files (field absent).
    #[serde(default = "default_kind")]
    pub kind: String,

    // -- v1 utilization fields (unchanged) -----------------------------------
    pub five_hour: Option<UsageWindow>,
    pub seven_day: Option<UsageWindow>,
    /// Rate-limit data from 3P providers (extracted from response headers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limits: Option<RateLimitData>,
    pub updated_at: f64,

    // -- v2 Gemini-reserved counter fields (all optional, nested structs) ----
    // VP-final R1: promoted from flat scalars to nested structs per spec 7.4.1.
    /// Per-day request counter state (nested CounterState).
    /// None on non-Gemini accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<CounterState>,
    /// 429 retry state (nested RateLimitState).
    /// None on non-Gemini accounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitState>,
    /// Model the user requested (as written in settings.json model.name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_model: Option<String>,
    /// Model Gemini actually used (per-response modelVersion field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_model: Option<String>,
    /// ISO-8601 first observation of current effective_model (drives is_downgrade debounce).
    /// Added per VP-final R1 to match spec 7.4.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_model_first_seen_at: Option<String>,
    /// Count of responses where effective_model != selected_model today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mismatch_count_today: Option<u32>,
    /// Derived: true when mismatch_count_today >= DOWNGRADE_DEBOUNCE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_downgrade: Option<bool>,

    // -- R2 escape-hatch field for unreserved surface-specific data ----------
    /// Surface-specific data outside the reserved schema.
    /// Never emitted by csq v2.0.1's v1 writer; preserved on round-trip.
    /// Consumers MUST tolerate unknown keys inside extras.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extras: Option<serde_json::Value>,
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
            selected_model: None,
            effective_model: None,
            effective_model_first_seen_at: None,
            mismatch_count_today: None,
            is_downgrade: None,
            extras: None,
        }
    }
}

impl AccountQuota {
    /// Creates a new AccountQuota with updated_at populated and all other fields
    /// at their v1-compatible defaults.
    ///
    /// Per VP-final red-team R4: prevents the silent-zero-epoch regression where
    /// ..Default::default() leaves updated_at=0.0. Use this instead of struct-update
    /// when the call site needs only to set updated_at.
    pub fn new_at(updated_at: f64) -> Self {
        Self {
            updated_at,
            ..Default::default()
        }
    }

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

/// Rate-limit data extracted from anthropic-ratelimit-* response headers.
///
/// 3P providers (Z.AI, MiniMax) return these headers on every API call.
/// We poll with a minimal max_tokens=1 request to capture them without
/// consuming real quota.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RateLimitData {
    pub requests_limit: Option<u64>,
    pub requests_remaining: Option<u64>,
    pub tokens_limit: Option<u64>,
    pub tokens_remaining: Option<u64>,
    pub input_tokens_limit: Option<u64>,
    pub output_tokens_limit: Option<u64>,
}

impl RateLimitData {
    /// Returns true if at least one rate-limit field was populated.
    pub fn has_data(&self) -> bool {
        self.requests_limit.is_some()
            || self.requests_remaining.is_some()
            || self.tokens_limit.is_some()
            || self.tokens_remaining.is_some()
            || self.input_tokens_limit.is_some()
            || self.output_tokens_limit.is_some()
    }

    /// Computes token usage as a percentage (0.0-100.0).
    ///
    /// Uses (limit - remaining) / limit * 100. Returns None if
    /// both tokens_limit and tokens_remaining are missing.
    pub fn token_usage_pct(&self) -> Option<f64> {
        match (self.tokens_limit, self.tokens_remaining) {
            (Some(limit), Some(remaining)) if limit > 0 => {
                let used = limit.saturating_sub(remaining);
                Some(used as f64 / limit as f64 * 100.0)
            }
            _ => None,
        }
    }

    /// Computes request usage as a percentage (0.0-100.0).
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

/// A single usage window (5-hour or 7-day).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

    #[test]
    fn new_at_constructor_sets_updated_at() {
        // Arrange / Act
        let q = AccountQuota::new_at(1775722800.0);

        // Assert -- updated_at is set, all else at zero/none defaults (R4)
        assert_eq!(q.updated_at, 1775722800.0);
        assert_eq!(q.surface, "claude-code");
        assert_eq!(q.kind, "utilization");
        assert!(q.five_hour.is_none());
        assert!(q.counter.is_none());
        assert!(q.extras.is_none());
    }

    // -- 7.4.2 canonical consumer tests (PR-B8 / VP-final) ------------------

    /// 1. Parse v1 file unchanged -- legacy file reads exactly as before spec 07.
    #[test]
    fn parses_v1_file_unchanged() {
        // Arrange -- v1 shape: no schema_version, no surface/kind, classic fields.
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
        assert!(account.selected_model.is_none());
        assert!(account.effective_model.is_none());
        assert!(account.effective_model_first_seen_at.is_none());
        assert!(account.mismatch_count_today.is_none());
        assert!(account.is_downgrade.is_none());
        assert!(account.extras.is_none());
    }

    /// 2. Parse v2 file with Claude-only accounts -- migrated v1 with explicit fields.
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
        assert!(account.rate_limit.is_none());
        assert!(account.extras.is_none());
    }

    /// 3. Parse v2 file with mixed surfaces -- the spec 7.4.1 example file.
    ///    Updated per VP-final R1: counter and rate_limit are nested structs.
    #[test]
    fn parses_v2_file_with_mixed_surfaces() {
        // Arrange -- exact example from spec 7.4.1 with nested counter/rate_limit
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
                    "counter": {
                        "requests_today": 42,
                        "resets_at_tz": "America/Los_Angeles",
                        "last_reset": "2026-04-22T00:00:00-07:00"
                    },
                    "rate_limit": {
                        "active": false,
                        "reset_at": null,
                        "last_retry_delay_s": null,
                        "last_quota_metric": null,
                        "cap": 1000
                    },
                    "selected_model": "gemini-2.5-pro",
                    "effective_model": "gemini-2.5-pro",
                    "effective_model_first_seen_at": "2026-04-22T14:12:00Z",
                    "mismatch_count_today": 0,
                    "is_downgrade": false
                }
            }
        }"#;

        // Act
        let qf: QuotaFile = serde_json::from_str(json).unwrap();

        // Assert -- account 1 (claude-code)
        assert_eq!(qf.schema_version, 2);
        let a1 = qf.accounts.get("1").expect("account 1");
        assert_eq!(a1.surface, "claude-code");
        assert_eq!(a1.kind, "utilization");
        assert_eq!(a1.five_hour.as_ref().unwrap().used_percentage, 42.0);

        // Assert -- account 2 (codex)
        let a2 = qf.accounts.get("2").expect("account 2");
        assert_eq!(a2.surface, "codex");
        assert_eq!(a2.kind, "utilization");
        assert_eq!(a2.five_hour.as_ref().unwrap().used_percentage, 18.0);
        assert!(a2.seven_day.is_none());

        // Assert -- account 3 (gemini counter) with nested structs per 7.4.1
        let a3 = qf.accounts.get("3").expect("account 3");
        assert_eq!(a3.surface, "gemini");
        assert_eq!(a3.kind, "counter");

        let counter = a3.counter.as_ref().expect("CounterState must be present");
        assert_eq!(counter.requests_today, 42);
        assert_eq!(counter.resets_at_tz, "America/Los_Angeles");
        assert_eq!(
            counter.last_reset.as_deref(),
            Some("2026-04-22T00:00:00-07:00")
        );

        let rl = a3
            .rate_limit
            .as_ref()
            .expect("RateLimitState must be present");
        assert!(!rl.active);
        assert!(rl.reset_at.is_none());
        assert!(rl.last_retry_delay_s.is_none());
        assert!(rl.last_quota_metric.is_none());
        assert_eq!(rl.cap, Some(1000));

        assert_eq!(a3.selected_model.as_deref(), Some("gemini-2.5-pro"));
        assert_eq!(a3.effective_model.as_deref(), Some("gemini-2.5-pro"));
        assert_eq!(
            a3.effective_model_first_seen_at.as_deref(),
            Some("2026-04-22T14:12:00Z")
        );
        assert_eq!(a3.mismatch_count_today, Some(0));
        assert_eq!(a3.is_downgrade, Some(false));
    }

    /// 4. Parse v2 file missing optional Gemini fields -- null-defaults applied without panic.
    ///    Updated per VP-final R1: assert CounterState/RateLimitState are None (not inner fields).
    #[test]
    fn parses_v2_file_missing_optional_gemini_fields() {
        // Arrange -- Gemini account with surface/kind but no counter fields
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

        // Assert -- the nested structs themselves are None, not their inner scalar fields
        let a5 = qf.accounts.get("5").expect("account 5");
        assert_eq!(a5.surface, "gemini");
        assert_eq!(a5.kind, "counter");
        // Nested structs are None -- not their inner scalar fields
        assert!(a5.counter.is_none(), "CounterState should be None");
        assert!(a5.rate_limit.is_none(), "RateLimitState should be None");
        assert!(a5.selected_model.is_none());
        assert!(a5.effective_model.is_none());
        assert!(a5.effective_model_first_seen_at.is_none());
        assert!(a5.mismatch_count_today.is_none());
        assert!(a5.is_downgrade.is_none());
        assert!(a5.extras.is_none());
    }

    /// 5. Parse v2 file with schema_version=3 DEGRADES not errors.
    ///    Per VP-final R3: reader returns Ok(QuotaFile::empty()) + WARN instead of Err.
    ///    Calls via state::load_state so the degrade path exercises.
    #[test]
    fn parses_v2_file_with_schema_version_3_degrades() {
        use tempfile::TempDir;

        // Arrange -- write a file with schema_version 3
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("quota.json");
        // Non-empty accounts to confirm degrade returns empty (not pass-through)
        let json = r#"{"schema_version":3,"accounts":{"1":{"surface":"gemini","kind":"counter","updated_at":1775722800.0}}}"#;
        std::fs::write(&path, json).unwrap();

        // Act -- load_state must degrade gracefully, not hard-error
        let result = super::state::load_state(dir.path());

        // Assert -- must be Ok(empty) per R3 (rollback UX: degrade, don't crash)
        assert!(
            result.is_ok(),
            "schema_version 3 must degrade to empty, not error: {:?}",
            result.unwrap_err()
        );
        let qf = result.unwrap();
        assert!(
            qf.accounts.is_empty(),
            "degraded QuotaFile must have no accounts"
        );
        assert_eq!(
            qf.schema_version, 1,
            "degraded QuotaFile must report schema_version 1"
        );
    }

    /// 6. Round-trip v2 in-memory -> save -> load preserves Gemini fields.
    ///    Per PR-C6: the v2.1 writer now stamps schema_version=2 on disk
    ///    (previously forced to 1 under VP-final R6 while v2.0.1 shook out
    ///    the read path). Test asserts (a) schema_version on disk is 2,
    ///    (b) nested Gemini fields survive.
    #[test]
    fn round_trip_v2_read_via_v2_write_preserves_gemini_fields() {
        use tempfile::TempDir;

        // Arrange -- construct in-memory with schema_version=2 + nested Gemini fields
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
                counter: Some(CounterState {
                    requests_today: 42,
                    resets_at_tz: "America/Los_Angeles".into(),
                    last_reset: Some("2026-04-22T00:00:00-07:00".into()),
                }),
                rate_limit: Some(RateLimitState {
                    active: false,
                    reset_at: None,
                    last_retry_delay_s: None,
                    last_quota_metric: None,
                    cap: Some(1000),
                }),
                selected_model: Some("gemini-2.5-pro".into()),
                effective_model: Some("gemini-2.5-pro".into()),
                effective_model_first_seen_at: Some("2026-04-22T14:12:00Z".into()),
                mismatch_count_today: Some(0),
                is_downgrade: Some(false),
                ..Default::default()
            },
        );

        // Act -- save via state::save_state, then reload
        super::state::save_state(dir.path(), &original).unwrap();
        let reloaded = super::state::load_state(dir.path()).unwrap();

        // Assert (a): schema_version on disk is 2 (PR-C6 write-path flip)
        let raw = std::fs::read_to_string(dir.path().join("quota.json")).unwrap();
        let on_disk: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            on_disk["schema_version"].as_u64(),
            Some(2),
            "v2.1 writer (PR-C6) must stamp schema_version=2 on disk"
        );

        // Assert (b): nested Gemini fields survive the round-trip via serde defaults
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

        // Nested CounterState preserved
        let cs_orig = a3_orig.counter.as_ref().unwrap();
        let cs_reload = a3_reload
            .counter
            .as_ref()
            .expect("CounterState must survive");
        assert_eq!(cs_reload.requests_today, cs_orig.requests_today);
        assert_eq!(cs_reload.resets_at_tz, cs_orig.resets_at_tz);
        assert_eq!(cs_reload.last_reset, cs_orig.last_reset);

        // Nested RateLimitState preserved
        let rl_orig = a3_orig.rate_limit.as_ref().unwrap();
        let rl_reload = a3_reload
            .rate_limit
            .as_ref()
            .expect("RateLimitState must survive");
        assert_eq!(rl_reload.active, rl_orig.active);
        assert_eq!(rl_reload.cap, rl_orig.cap);

        assert_eq!(a3_reload.selected_model, a3_orig.selected_model);
        assert_eq!(a3_reload.effective_model, a3_orig.effective_model);
        assert_eq!(
            a3_reload.effective_model_first_seen_at,
            a3_orig.effective_model_first_seen_at
        );
        assert_eq!(a3_reload.mismatch_count_today, a3_orig.mismatch_count_today);
        assert_eq!(a3_reload.is_downgrade, a3_orig.is_downgrade);
    }

    /// 7. Reject non-numeric account keys -- per VP-final R5.
    ///    load_state must error with InvalidJson when any account key fails u16 parse.
    #[test]
    fn rejects_non_numeric_account_keys() {
        use crate::error::ConfigError;
        use tempfile::TempDir;

        // Arrange -- JSON with a non-numeric account key "gemini-5"
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("quota.json");
        let json = r#"{
            "schema_version": 2,
            "accounts": {
                "1": {
                    "surface": "claude-code",
                    "kind": "utilization",
                    "updated_at": 1775722800.0
                },
                "gemini-5": {
                    "surface": "gemini",
                    "kind": "counter",
                    "updated_at": 1775722800.0
                }
            }
        }"#;
        std::fs::write(&path, json).unwrap();

        // Act
        let result = super::state::load_state(dir.path());

        // Assert -- must be Err(InvalidJson) naming the bad key
        assert!(result.is_err(), "non-numeric account key must be rejected");
        let err = result.unwrap_err();
        match &err {
            ConfigError::InvalidJson { reason, .. } => {
                assert!(
                    reason.contains("gemini-5"),
                    "error must name the bad key, got: {reason}"
                );
            }
            other => panic!("expected InvalidJson, got: {other:?}"),
        }
    }

    /// 8. extras field survives round-trip -- per VP-final R2.
    ///    Arbitrary shapes inside extras are preserved byte-identical.
    #[test]
    fn extras_field_survives_round_trip() {
        use tempfile::TempDir;

        // Arrange -- construct with extras containing arbitrary data
        let dir = TempDir::new().unwrap();
        let extras_value = serde_json::json!({"codex_plan": "team", "nested": {"x": 42}});
        let mut original = QuotaFile::empty();
        original.set(
            1,
            AccountQuota {
                surface: "codex".into(),
                kind: "utilization".into(),
                updated_at: 1_775_722_800.0,
                extras: Some(extras_value.clone()),
                ..Default::default()
            },
        );

        // Act -- save then reload
        super::state::save_state(dir.path(), &original).unwrap();
        let reloaded = super::state::load_state(dir.path()).unwrap();

        // Assert -- extras preserved byte-identical
        let a1 = reloaded.accounts.get("1").expect("account 1 must exist");
        let extras_reloaded = a1.extras.as_ref().expect("extras must be preserved");
        assert_eq!(
            extras_reloaded, &extras_value,
            "extras must round-trip byte-identical"
        );
    }
}
