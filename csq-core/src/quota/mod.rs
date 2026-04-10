//! Quota tracking — usage windows, state management, and formatting.

pub mod format;
pub mod state;
pub mod status;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level quota file. Maps account numbers (as strings) to usage data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaFile {
    pub accounts: HashMap<String, AccountQuota>,
}

impl QuotaFile {
    pub fn empty() -> Self {
        Self {
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
    pub five_hour: Option<UsageWindow>,
    pub seven_day: Option<UsageWindow>,
    pub updated_at: f64,
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
        self.five_hour.as_ref().map(|w| w.used_percentage).unwrap_or(0.0)
    }

    /// Returns the 7-day usage percentage (0-100), or 0 if no data.
    pub fn seven_day_pct(&self) -> f64 {
        self.seven_day.as_ref().map(|w| w.used_percentage).unwrap_or(0.0)
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
            seven_day: None,
            updated_at: 0.0,
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
                five_hour: None,
                seven_day: None,
                updated_at: 123.0,
            },
        );
        assert!(qf.get(1).is_some());
        assert_eq!(qf.get(1).unwrap().updated_at, 123.0);
    }
}
