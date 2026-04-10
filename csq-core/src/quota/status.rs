//! Multi-account status display for `csq status` command.

use super::format::{account_label, fmt_time};
use super::state;
use crate::accounts::discovery;
use crate::types::AccountNum;
use std::path::Path;

/// Status entry for a single account.
#[derive(Debug, Clone)]
pub struct AccountStatus {
    pub id: u16,
    pub label: String,
    pub is_active: bool,
    pub five_hour_pct: Option<f64>,
    pub five_hour_resets_in: Option<u64>,
    pub seven_day_pct: Option<f64>,
    pub seven_day_resets_in: Option<u64>,
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

    /// Formats the status line for this account.
    pub fn format_line(&self) -> String {
        let marker = if self.is_active { "*" } else { " " };
        let icon = self.five_hour_icon();

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

        format!(
            "{} #{} {} {}  {}{}",
            marker, self.id, icon, self.label, usage, weekly
        )
    }
}

/// Returns the status of all discovered accounts.
pub fn show_status(base_dir: &Path, active: Option<AccountNum>) -> Vec<AccountStatus> {
    let accounts = discovery::discover_anthropic(base_dir);
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
            let label = if a.label == "unknown" {
                account_label(base_dir, AccountNum::try_from(a.id).unwrap())
            } else {
                a.label
            };

            AccountStatus {
                id: a.id,
                label,
                is_active: active.map(|c| c.get() == a.id).unwrap_or(false),
                five_hour_pct: q.map(|q| q.five_hour_pct()).filter(|p| *p > 0.0 || q.is_some_and(|q| q.five_hour.is_some())),
                five_hour_resets_in: q.and_then(|q| {
                    q.five_hour
                        .as_ref()
                        .map(|w| w.resets_at.saturating_sub(now_secs))
                }),
                seven_day_pct: q.map(|q| q.seven_day_pct()).filter(|p| *p > 0.0 || q.is_some_and(|q| q.seven_day.is_some())),
                seven_day_resets_in: q.and_then(|q| {
                    q.seven_day
                        .as_ref()
                        .map(|w| w.resets_at.saturating_sub(now_secs))
                }),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{self, CredentialFile, OAuthPayload};
    use crate::quota::{AccountQuota, QuotaFile, UsageWindow};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn setup(base: &Path, account: u16, pct: f64) {
        let target = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile {
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
        };
        credentials::save(&credentials::file::canonical_path(base, target), &creds).unwrap();

        let mut quota = state::load_state(base).unwrap_or_else(|_| QuotaFile::empty());
        quota.set(
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: pct,
                    resets_at: 9999999999,
                }),
                seven_day: None,
                updated_at: 0.0,
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

    #[test]
    fn status_icons_by_usage() {
        let s_low = AccountStatus {
            id: 1,
            label: "x".into(),
            is_active: false,
            five_hour_pct: Some(20.0),
            five_hour_resets_in: None,
            seven_day_pct: None,
            seven_day_resets_in: None,
        };
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
        };
        let line = s.format_line();
        assert!(line.starts_with("* #3"));
        assert!(line.contains("test@example.com"));
        assert!(line.contains("42%"));
        assert!(line.contains("15%"));
    }

    #[test]
    fn show_status_no_accounts() {
        let dir = TempDir::new().unwrap();
        let status = show_status(dir.path(), None);
        assert!(status.is_empty());
    }
}
