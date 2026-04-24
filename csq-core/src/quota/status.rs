//! Multi-account status display for `csq status` command.

use super::format::{account_label, fmt_time};
use super::state;
use crate::accounts::{discovery, AccountInfo, AccountSource};
use crate::providers::catalog::Surface;
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Status entry for a single account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatus {
    pub id: u16,
    pub label: String,
    pub is_active: bool,
    pub five_hour_pct: Option<f64>,
    pub five_hour_resets_in: Option<u64>,
    pub seven_day_pct: Option<f64>,
    pub seven_day_resets_in: Option<u64>,
    /// Account source (Anthropic OAuth, Codex OAuth, third-party API
    /// key, manual). Older JSON without this field deserialises to
    /// `AccountSource::Anthropic` via the default.
    #[serde(default = "default_source")]
    pub source: AccountSource,
    /// Upstream surface (`claude-code` or `codex`). Defaults to
    /// `ClaudeCode` for backwards compatibility with snapshots that
    /// predate this field.
    #[serde(default)]
    pub surface: Surface,
}

fn default_source() -> AccountSource {
    AccountSource::Anthropic
}

impl AccountStatus {
    /// Returns the icon for 5-hour usage:
    /// - `●` (bullet) for <80%
    /// - `◐` (half) for 80-99%
    /// - `○` (circle) for 100%
    /// - `·` (middle dot) for no data
    pub fn five_hour_icon(&self) -> &'static str {
        match self.five_hour_pct {
            None => "·",
            Some(p) if p < 80.0 => "●",
            Some(p) if p < 100.0 => "◐",
            Some(_) => "○",
        }
    }

    /// Surface tag shown after the label, e.g. ` [codex]` or
    /// ` [minimax]`. Empty for vanilla Anthropic OAuth rows so existing
    /// output is byte-identical for Anthropic-only setups.
    fn surface_tag(&self) -> String {
        match (&self.surface, &self.source) {
            (Surface::Codex, _) => " [codex]".to_string(),
            (_, AccountSource::ThirdParty { provider }) => {
                format!(" [{}]", provider.to_ascii_lowercase())
            }
            (_, AccountSource::Manual) => " [manual]".to_string(),
            _ => String::new(),
        }
    }

    /// Formats the status line for this account.
    ///
    /// Anthropic OAuth and Codex rows include 5h/7d quota fields when
    /// the poller has data (Codex quota lands alongside Anthropic per
    /// spec 07 §7.4). Third-party and manual rows omit the quota
    /// suffix — csq does not poll those providers' quotas today.
    pub fn format_line(&self) -> String {
        let marker = if self.is_active { "*" } else { " " };
        let icon = self.five_hour_icon();
        let tag = self.surface_tag();

        // Third-party / manual slots: no quota polling, render a
        // bound-state suffix instead of "5h:— 7d:—" so the user can
        // tell "no data yet" from "no polling".
        let polled = matches!(self.source, AccountSource::Anthropic | AccountSource::Codex);
        if !polled {
            let suffix = if self.has_any_quota_data() {
                self.quota_suffix()
            } else {
                "(api-key)".to_string()
            };
            return format!(
                "{} #{} {} {}{}  {}",
                marker, self.id, icon, self.label, tag, suffix
            );
        }

        let suffix = self.quota_suffix();
        format!(
            "{} #{} {} {}{}  {}",
            marker, self.id, icon, self.label, tag, suffix
        )
    }

    fn has_any_quota_data(&self) -> bool {
        self.five_hour_pct.is_some() || self.seven_day_pct.is_some()
    }

    fn quota_suffix(&self) -> String {
        let usage = match self.five_hour_pct {
            Some(p) => {
                let resets = self
                    .five_hour_resets_in
                    .map(fmt_time)
                    .unwrap_or_else(|| "?".into());
                format!("5h:{:.0}% ({}) ", p, resets)
            }
            None => "5h:— ".to_string(),
        };
        let weekly = match self.seven_day_pct {
            Some(p) => format!("7d:{:.0}%", p),
            None => "7d:—".to_string(),
        };
        format!("{}{}", usage, weekly)
    }
}

/// Returns the status of all discovered accounts.
///
/// Convenience wrapper for the direct (non-daemon) path: runs
/// [`discovery::discover_all`] and hands the result to
/// [`compose_status`]. The daemon-delegated path calls
/// [`compose_status`] directly with accounts parsed from
/// `/api/accounts`.
///
/// Before alpha.N this function called `discover_anthropic`, which
/// silently dropped Codex + third-party (MiniMax/Z.AI/Ollama) + manual
/// slots. `discover_all` composes every source in priority order so
/// `csq status` now renders the full configured set.
pub fn show_status(base_dir: &Path, active: Option<AccountNum>) -> Vec<AccountStatus> {
    let accounts = discovery::discover_all(base_dir);
    compose_status(base_dir, accounts, active)
}

/// Composes status entries from a pre-discovered account list.
///
/// Joins the account list with the local quota file and produces
/// the filtered, sorted [`AccountStatus`] entries the CLI displays.
/// The quota file is a local read in both paths — the daemon does
/// not currently expose quota over HTTP.
///
/// Used by both the direct path (via [`show_status`]) and the
/// daemon-delegated path (`csq status` after parsing
/// `/api/accounts`), so the two paths are guaranteed to produce
/// identical output for the same `(accounts, quota)` pair.
pub fn compose_status(
    base_dir: &Path,
    accounts: Vec<AccountInfo>,
    active: Option<AccountNum>,
) -> Vec<AccountStatus> {
    let quota = state::load_state(base_dir).unwrap_or_else(|_| super::QuotaFile::empty());

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    accounts
        .into_iter()
        .filter(|a| a.has_credentials)
        .map(|a| {
            let q = quota.get(a.id);
            let account_num = AccountNum::try_from(a.id).ok();
            let label = if a.label == "unknown" {
                account_num
                    .map(|n| account_label(base_dir, n))
                    .unwrap_or_else(|| a.label.clone())
            } else {
                a.label.clone()
            };

            AccountStatus {
                id: a.id,
                label,
                is_active: active.map(|c| c.get() == a.id).unwrap_or(false),
                five_hour_pct: q
                    .map(|q| q.five_hour_pct())
                    .filter(|p| *p > 0.0 || q.is_some_and(|q| q.five_hour.is_some())),
                five_hour_resets_in: q.and_then(|q| {
                    q.five_hour
                        .as_ref()
                        .map(|w| w.resets_at.saturating_sub(now_secs))
                }),
                seven_day_pct: q
                    .map(|q| q.seven_day_pct())
                    .filter(|p| *p > 0.0 || q.is_some_and(|q| q.seven_day.is_some())),
                seven_day_resets_in: q.and_then(|q| {
                    q.seven_day
                        .as_ref()
                        .map(|w| w.resets_at.saturating_sub(now_secs))
                }),
                source: a.source,
                surface: a.surface,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::quota::{AccountQuota, QuotaFile, UsageWindow};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn setup(base: &Path, account: u16, pct: f64) {
        let target = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(format!("at-{account}")),
                refresh_token: RefreshToken::new(format!("rt-{account}")),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });
        credentials::save(&credentials::file::canonical_path(base, target), &creds).unwrap();

        let mut quota = state::load_state(base).unwrap_or_else(|_| QuotaFile::empty());
        quota.set(
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: pct,
                    resets_at: 9999999999,
                }),
                ..Default::default()
            },
        );
        state::save_state(base, &quota).unwrap();
    }

    #[test]
    fn show_status_returns_all_accounts() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 20.0);
        setup(dir.path(), 2, 85.0);
        setup(dir.path(), 3, 100.0);

        let active = AccountNum::try_from(2u16).unwrap();
        let status = show_status(dir.path(), Some(active));

        assert_eq!(status.len(), 3);
        assert!(status.iter().find(|s| s.id == 2).unwrap().is_active);
        assert!(!status.iter().find(|s| s.id == 1).unwrap().is_active);
    }

    fn anthropic_status(id: u16) -> AccountStatus {
        AccountStatus {
            id,
            label: "x".into(),
            is_active: false,
            five_hour_pct: Some(20.0),
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
        }
    }

    #[test]
    fn status_icons_by_usage() {
        let s_low = anthropic_status(1);
        assert_eq!(s_low.five_hour_icon(), "●");

        let s_high = AccountStatus {
            five_hour_pct: Some(90.0),
            ..s_low.clone()
        };
        assert_eq!(s_high.five_hour_icon(), "◐");

        let s_full = AccountStatus {
            five_hour_pct: Some(100.0),
            ..s_low.clone()
        };
        assert_eq!(s_full.five_hour_icon(), "○");

        let s_none = AccountStatus {
            five_hour_pct: None,
            ..s_low
        };
        assert_eq!(s_none.five_hour_icon(), "·");
    }

    #[test]
    fn format_line_active_marker() {
        let s = AccountStatus {
            id: 3,
            label: "test@example.com".into(),
            is_active: true,
            five_hour_pct: Some(42.0),
            five_hour_resets_in: Some(3600),
            seven_day_pct: Some(15.0),
            seven_day_resets_in: Some(86400),
            source: AccountSource::Anthropic,
            surface: Surface::ClaudeCode,
        };
        let line = s.format_line();
        assert!(line.starts_with("* #3"));
        assert!(line.contains("test@example.com"));
        assert!(line.contains("42%"));
        assert!(line.contains("15%"));
        // Anthropic rows carry no surface tag — keeps existing output byte-identical.
        assert!(!line.contains("["));
    }

    #[test]
    fn format_line_third_party_minimax_shows_tag_and_api_key_suffix() {
        let s = AccountStatus {
            id: 9,
            label: "MiniMax".into(),
            is_active: false,
            five_hour_pct: None,
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
            source: AccountSource::ThirdParty {
                provider: "MiniMax".into(),
            },
            surface: Surface::ClaudeCode,
        };
        let line = s.format_line();
        assert!(line.contains("#9"), "missing id: {line}");
        assert!(line.contains("[minimax]"), "missing provider tag: {line}");
        assert!(line.contains("(api-key)"), "missing api-key suffix: {line}");
        // 3P rows must NOT render quota placeholders — quota isn't
        // polled for MiniMax/Z.AI/Ollama today, so `5h:—` would imply
        // "no data yet" which is misleading.
        assert!(!line.contains("5h:"), "unexpected quota suffix: {line}");
        assert!(!line.contains("7d:"), "unexpected quota suffix: {line}");
    }

    #[test]
    fn format_line_codex_shows_codex_tag_and_quota() {
        let s = AccountStatus {
            id: 4,
            label: "user@openai.test".into(),
            is_active: true,
            five_hour_pct: Some(12.0),
            five_hour_resets_in: Some(1800),
            seven_day_pct: Some(3.0),
            seven_day_resets_in: Some(86400),
            source: AccountSource::Codex,
            surface: Surface::Codex,
        };
        let line = s.format_line();
        assert!(line.starts_with("* #4"), "line: {line}");
        assert!(line.contains("[codex]"), "missing codex tag: {line}");
        // Codex is a polled surface (spec 07 §7.4) so quota suffix
        // must render like Anthropic.
        assert!(line.contains("5h:12%"), "missing 5h quota: {line}");
        assert!(line.contains("7d:3%"), "missing 7d quota: {line}");
    }

    #[test]
    fn show_status_no_accounts() {
        let dir = TempDir::new().unwrap();
        let status = show_status(dir.path(), None);
        assert!(status.is_empty());
    }

    /// `compose_status` is the composition step used by both the
    /// direct path (via [`show_status`]) and the daemon-delegated
    /// path (via `csq status` after parsing `/api/accounts`).
    /// This test feeds it a synthetic account list mirroring the
    /// shape the daemon route returns — validating that the CLI's
    /// daemon path produces identical output to the direct path
    /// for the same `(accounts, quota)` pair.
    #[test]
    fn compose_status_with_daemon_shaped_accounts() {
        let dir = TempDir::new().unwrap();
        // Populate quota file + credentials so compose_status has
        // something to join against.
        setup(dir.path(), 1, 20.0);
        setup(dir.path(), 2, 85.0);

        // Synthetic AccountInfo list as if returned from
        // `GET /api/accounts`. Label is already resolved (daemon
        // hits profiles.json server-side), has_credentials=true.
        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "alice@example.com".into(),
                source: AccountSource::Anthropic,
                surface: crate::providers::catalog::Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
            },
            AccountInfo {
                id: 2,
                label: "bob@example.com".into(),
                source: AccountSource::Anthropic,
                surface: crate::providers::catalog::Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
            },
        ];

        let active = AccountNum::try_from(2u16).unwrap();
        let status = compose_status(dir.path(), accounts, Some(active));

        assert_eq!(status.len(), 2);
        let first = status.iter().find(|s| s.id == 1).unwrap();
        assert_eq!(first.label, "alice@example.com");
        assert!(!first.is_active);
        let second = status.iter().find(|s| s.id == 2).unwrap();
        assert_eq!(second.label, "bob@example.com");
        assert!(second.is_active);
    }

    /// `compose_status` must filter out accounts with
    /// `has_credentials == false` — these are placeholders the
    /// daemon may list (e.g., after a failed credential parse).
    #[test]
    fn compose_status_filters_accounts_without_credentials() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 20.0);

        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "real@example.com".into(),
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
            },
            AccountInfo {
                id: 7,
                label: "broken@example.com".into(),
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: false,
            },
        ];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 1);
        assert_eq!(status[0].id, 1);
    }

    /// Multi-surface coverage: the same mix a real user sees —
    /// Anthropic OAuth on slot 1, Codex OAuth on slot 4, per-slot
    /// MiniMax binding on slot 9, and Ollama (local) on slot 10.
    /// `compose_status` must carry the surface/source through so
    /// `format_line` can render each correctly.
    #[test]
    fn compose_status_multi_surface_mix() {
        let dir = TempDir::new().unwrap();
        setup(dir.path(), 1, 25.0); // Anthropic quota only
        let accounts = vec![
            AccountInfo {
                id: 1,
                label: "anthro@example.com".into(),
                source: AccountSource::Anthropic,
                surface: Surface::ClaudeCode,
                method: "oauth".into(),
                has_credentials: true,
            },
            AccountInfo {
                id: 4,
                label: "openai-user".into(),
                source: AccountSource::Codex,
                surface: Surface::Codex,
                method: "oauth".into(),
                has_credentials: true,
            },
            AccountInfo {
                id: 9,
                label: "MiniMax".into(),
                source: AccountSource::ThirdParty {
                    provider: "MiniMax".into(),
                },
                surface: Surface::ClaudeCode,
                method: "api_key".into(),
                has_credentials: true,
            },
            AccountInfo {
                id: 10,
                label: "Ollama".into(),
                source: AccountSource::ThirdParty {
                    provider: "Ollama".into(),
                },
                surface: Surface::ClaudeCode,
                method: "api_key".into(),
                has_credentials: true,
            },
        ];

        let status = compose_status(dir.path(), accounts, None);
        assert_eq!(status.len(), 4, "all four slots must be composed");

        let anth = status.iter().find(|s| s.id == 1).unwrap();
        assert!(matches!(anth.source, AccountSource::Anthropic));
        assert_eq!(anth.surface, Surface::ClaudeCode);

        let codex = status.iter().find(|s| s.id == 4).unwrap();
        assert!(matches!(codex.source, AccountSource::Codex));
        assert_eq!(codex.surface, Surface::Codex);
        assert!(codex.format_line().contains("[codex]"));

        let mm = status.iter().find(|s| s.id == 9).unwrap();
        match &mm.source {
            AccountSource::ThirdParty { provider } => assert_eq!(provider, "MiniMax"),
            other => panic!("expected ThirdParty MiniMax, got {:?}", other),
        }
        assert!(mm.format_line().contains("[minimax]"));

        let ol = status.iter().find(|s| s.id == 10).unwrap();
        match &ol.source {
            AccountSource::ThirdParty { provider } => assert_eq!(provider, "Ollama"),
            other => panic!("expected ThirdParty Ollama, got {:?}", other),
        }
        assert!(ol.format_line().contains("[ollama]"));
    }

    /// Back-compat regression: an AccountStatus JSON written by an
    /// older csq (no `source`/`surface` fields) must deserialise.
    #[test]
    fn account_status_deserializes_without_new_fields() {
        let legacy = r#"{
            "id": 1,
            "label": "alice@example.com",
            "is_active": true,
            "five_hour_pct": 12.0,
            "five_hour_resets_in": 3600,
            "seven_day_pct": 3.0,
            "seven_day_resets_in": 86400
        }"#;
        let parsed: AccountStatus = serde_json::from_str(legacy).expect("legacy JSON parses");
        assert_eq!(parsed.id, 1);
        assert!(matches!(parsed.source, AccountSource::Anthropic));
        assert_eq!(parsed.surface, Surface::ClaudeCode);
    }
}
