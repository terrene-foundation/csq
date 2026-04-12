//! Formatting helpers for statusline output.

use super::AccountQuota;
use crate::accounts::markers;
use crate::accounts::profiles;
use crate::types::AccountNum;
use std::path::Path;

/// Maximum age of a broker-failed flag before it's auto-cleared (24 hours).
pub const BROKER_FLAG_STALE_SECS: u64 = 24 * 3600;

/// Formats a duration in seconds as a compact string.
///
/// Examples: "now", "5m", "2h", "1d"
pub fn fmt_time(secs: u64) -> String {
    if secs < 60 {
        "now".to_string()
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Formats a token count as a compact string.
///
/// Examples: 500 → "500", 1200 → "1k", 1500000 → "1.5M"
pub fn fmt_tokens(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        let k = n as f64 / 1_000.0;
        if k >= 10.0 {
            format!("{}k", k.round() as u64)
        } else {
            format!("{:.1}k", k)
        }
    } else {
        let m = n as f64 / 1_000_000.0;
        if m >= 10.0 {
            format!("{}M", m.round() as u64)
        } else {
            format!("{:.1}M", m)
        }
    }
}

/// Formats the statusline string for an account.
///
/// Format: `#N:label 5h:X% 7d:Y%`
/// With indicators:
///   - `#N!:label` if swap is stuck
///   - `LOGIN-NEEDED #N:label 5h:X% 7d:Y%` if broker failed
pub fn statusline_str(
    account: AccountNum,
    label: &str,
    quota: Option<&AccountQuota>,
    stuck_swap: bool,
    broker_failed: bool,
) -> String {
    let stuck = if stuck_swap { "!" } else { "" };
    let prefix = if broker_failed { "LOGIN-NEEDED " } else { "" };

    match quota {
        Some(q) => {
            format!(
                "{}#{}{}:{} 5h:{:.0}% 7d:{:.0}%",
                prefix,
                account,
                stuck,
                label,
                q.five_hour_pct(),
                q.seven_day_pct()
            )
        }
        None => {
            format!("{}#{}{}:{} no data", prefix, account, stuck, label)
        }
    }
}

/// Resolves the display label for an account from profiles.json.
///
/// Falls back to "account-N" if no profile exists.
pub fn account_label(base_dir: &Path, account: AccountNum) -> String {
    let profiles_path = profiles::profiles_path(base_dir);
    match profiles::load(&profiles_path) {
        Ok(p) => p
            .get_email(account.get())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("account-{}", account)),
        Err(_) => format!("account-{}", account),
    }
}

/// Checks if a broker-failed flag is stale (older than 24h) and should be ignored.
///
/// Returns true if the flag should be treated as cleared.
pub fn is_broker_flag_stale(base_dir: &Path, account: AccountNum) -> bool {
    let path = base_dir
        .join("credentials")
        .join(format!("{}.broker-failed", account));

    match std::fs::metadata(&path) {
        Ok(metadata) => {
            if let Ok(modified) = metadata.modified() {
                if let Ok(age) = modified.elapsed() {
                    return age.as_secs() > BROKER_FLAG_STALE_SECS;
                }
            }
            false
        }
        Err(_) => true, // No flag = treat as stale (cleared)
    }
}

/// Self-healing check: returns true if broker-failed flag should be reported.
/// Auto-clears stale flags (>24h old).
pub fn should_report_broker_failed(base_dir: &Path, account: AccountNum) -> bool {
    let path = base_dir
        .join("credentials")
        .join(format!("{}.broker-failed", account));

    if !path.exists() {
        return false;
    }

    if is_broker_flag_stale(base_dir, account) {
        let _ = std::fs::remove_file(&path);
        return false;
    }

    true
}

/// Checks whether a swap is stuck — the live access token differs from
/// what we most recently wrote. Used as a swap verification indicator.
pub fn is_swap_stuck(config_dir: &Path, base_dir: &Path) -> bool {
    let Some(account) = markers::read_csq_account(config_dir) else {
        return false;
    };

    let live_path = config_dir.join(".credentials.json");
    let Ok(live) = crate::credentials::load(&live_path) else {
        return false;
    };

    let canonical_path = crate::credentials::file::canonical_path(base_dir, account);
    let Ok(canonical) = crate::credentials::load(&canonical_path) else {
        return false;
    };

    live.claude_ai_oauth.access_token.expose_secret()
        != canonical.claude_ai_oauth.access_token.expose_secret()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota::UsageWindow;

    #[test]
    fn fmt_time_edge_cases() {
        assert_eq!(fmt_time(0), "now");
        assert_eq!(fmt_time(59), "now");
        assert_eq!(fmt_time(60), "1m");
        assert_eq!(fmt_time(3599), "59m");
        assert_eq!(fmt_time(3600), "1h");
        assert_eq!(fmt_time(86399), "23h");
        assert_eq!(fmt_time(86400), "1d");
        assert_eq!(fmt_time(172800), "2d");
    }

    #[test]
    fn fmt_tokens_edge_cases() {
        assert_eq!(fmt_tokens(0), "0");
        assert_eq!(fmt_tokens(500), "500");
        assert_eq!(fmt_tokens(999), "999");
        assert_eq!(fmt_tokens(1000), "1.0k");
        assert_eq!(fmt_tokens(1200), "1.2k");
        assert_eq!(fmt_tokens(9999), "10.0k");
        assert_eq!(fmt_tokens(10000), "10k");
        assert_eq!(fmt_tokens(1_000_000), "1.0M");
        assert_eq!(fmt_tokens(1_500_000), "1.5M");
        assert_eq!(fmt_tokens(10_000_000), "10M");
    }

    #[test]
    fn statusline_normal() {
        let quota = AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: 42.0,
                resets_at: 9999999999,
            }),
            seven_day: Some(UsageWindow {
                used_percentage: 15.0,
                resets_at: 9999999999,
            }),
            rate_limits: None,
            updated_at: 0.0,
        };
        let s = statusline_str(
            AccountNum::try_from(3u16).unwrap(),
            "user@test.com",
            Some(&quota),
            false,
            false,
        );
        assert_eq!(s, "#3:user@test.com 5h:42% 7d:15%");
    }

    #[test]
    fn statusline_stuck_swap() {
        let quota = AccountQuota {
            five_hour: Some(UsageWindow {
                used_percentage: 0.0,
                resets_at: 9999999999,
            }),
            seven_day: None,
            rate_limits: None,
            updated_at: 0.0,
        };
        let s = statusline_str(
            AccountNum::try_from(1u16).unwrap(),
            "user",
            Some(&quota),
            true,
            false,
        );
        assert_eq!(s, "#1!:user 5h:0% 7d:0%");
    }

    #[test]
    fn statusline_broker_failed() {
        let s = statusline_str(
            AccountNum::try_from(2u16).unwrap(),
            "user",
            None,
            false,
            true,
        );
        assert!(s.starts_with("LOGIN-NEEDED"));
        assert!(s.contains("#2:user"));
    }

    #[test]
    fn statusline_no_data() {
        let s = statusline_str(
            AccountNum::try_from(5u16).unwrap(),
            "user",
            None,
            false,
            false,
        );
        assert_eq!(s, "#5:user no data");
    }

    #[test]
    fn is_broker_flag_stale_missing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        assert!(is_broker_flag_stale(dir.path(), account));
    }

    #[test]
    fn should_report_broker_failed_no_flag() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        assert!(!should_report_broker_failed(dir.path(), account));
    }

    #[test]
    fn should_report_broker_failed_fresh_flag() {
        let dir = tempfile::TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();
        crate::broker::fanout::set_broker_failed(dir.path(), account, "test").unwrap();
        // Fresh flag should be reported
        assert!(should_report_broker_failed(dir.path(), account));
    }
}
