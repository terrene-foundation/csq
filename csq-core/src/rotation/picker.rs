//! Account picker — selects the best account for rotation.

use crate::accounts::discovery;
use crate::quota::{state as quota_state, AccountQuota};
use crate::types::AccountNum;
use serde::Serialize;
use std::path::Path;

/// Picks the best account to switch to, excluding the given account.
///
/// Strategy:
/// 1. Prefer accounts with the lowest 5-hour usage
/// 2. If all accounts are exhausted (>=100%), pick the one with the earliest reset time
/// 3. Only considers accounts with valid credentials (has `credentials/N.json`)
///
/// Returns None if no eligible accounts exist.
pub fn pick_best(base_dir: &Path, exclude: Option<AccountNum>) -> Option<AccountNum> {
    let accounts = discovery::discover_anthropic(base_dir);
    let quota = quota_state::load_state(base_dir).ok()?;

    let mut candidates: Vec<(AccountNum, Option<&AccountQuota>)> = accounts
        .into_iter()
        .filter(|a| a.has_credentials)
        .filter_map(|a| {
            let num = AccountNum::try_from(a.id).ok()?;
            if Some(num) == exclude {
                return None;
            }
            Some((num, None))
        })
        .collect();

    // Attach quota info
    for (num, quota_ref) in &mut candidates {
        *quota_ref = quota.get(num.get());
    }

    if candidates.is_empty() {
        return None;
    }

    // Separate exhausted from non-exhausted
    let non_exhausted: Vec<_> = candidates
        .iter()
        .filter(|(_, q)| q.map(|q| q.five_hour_pct() < 100.0).unwrap_or(true))
        .collect();

    if !non_exhausted.is_empty() {
        // Pick lowest 5h usage (None = 0)
        return non_exhausted
            .iter()
            .min_by(|(_, a), (_, b)| {
                let a_pct = a.map(|q| q.five_hour_pct()).unwrap_or(0.0);
                let b_pct = b.map(|q| q.five_hour_pct()).unwrap_or(0.0);
                a_pct.partial_cmp(&b_pct).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(num, _)| *num);
    }

    // All exhausted — pick earliest reset
    candidates
        .iter()
        .min_by_key(|(_, q)| {
            q.and_then(|q| q.five_hour.as_ref().map(|w| w.resets_at))
                .unwrap_or(u64::MAX)
        })
        .map(|(num, _)| *num)
}

/// Suggestion output for the `csq suggest` CLI command.
#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    /// Best account to switch to, or null if all exhausted.
    pub suggested: Option<u16>,
    /// True if all non-excluded accounts are at 100% usage.
    pub exhausted: bool,
    /// Current account (excluded from suggestion).
    pub current: Option<u16>,
}

/// Returns a JSON-serializable suggestion.
pub fn suggest(base_dir: &Path, current: Option<AccountNum>) -> Suggestion {
    let best = pick_best(base_dir, current);
    let quota = quota_state::load_state(base_dir).unwrap_or_else(|_| crate::quota::QuotaFile::empty());

    let all_exhausted = discovery::discover_anthropic(base_dir)
        .iter()
        .filter(|a| a.has_credentials)
        .filter(|a| current.map(|c| c.get() != a.id).unwrap_or(true))
        .all(|a| {
            quota
                .get(a.id)
                .map(|q| q.five_hour_pct() >= 100.0)
                .unwrap_or(false)
        });

    Suggestion {
        suggested: best.map(|a| a.get()),
        exhausted: all_exhausted && best.is_some(),
        current: current.map(|c| c.get()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{self, CredentialFile, OAuthPayload};
    use crate::quota::{QuotaFile, UsageWindow};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn setup_account(base: &Path, account: u16) {
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
        credentials::save(
            &credentials::file::canonical_path(base, target),
            &creds,
        )
        .unwrap();
    }

    fn setup_quota(base: &Path, account: u16, five_hour_pct: f64, resets_at: u64) {
        let mut quota = quota_state::load_state(base).unwrap_or_else(|_| QuotaFile::empty());
        quota.set(
            account,
            AccountQuota {
                five_hour: Some(UsageWindow {
                    used_percentage: five_hour_pct,
                    resets_at,
                }),
                seven_day: None,
                rate_limits: None,
                updated_at: 0.0,
            },
        );
        quota_state::save_state(base, &quota).unwrap();
    }

    #[test]
    fn pick_best_lowest_usage() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_account(dir.path(), 3);
        setup_quota(dir.path(), 1, 80.0, 9999999999);
        setup_quota(dir.path(), 2, 20.0, 9999999999);
        setup_quota(dir.path(), 3, 50.0, 9999999999);

        let best = pick_best(dir.path(), None);
        assert_eq!(best, Some(AccountNum::try_from(2u16).unwrap()));
    }

    #[test]
    fn pick_best_excludes_current() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 10.0, 9999999999);
        setup_quota(dir.path(), 2, 50.0, 9999999999);

        let current = AccountNum::try_from(1u16).unwrap();
        let best = pick_best(dir.path(), Some(current));
        assert_eq!(best, Some(AccountNum::try_from(2u16).unwrap()));
    }

    #[test]
    fn pick_best_all_exhausted_picks_earliest_reset() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        // Future reset times — account 2 resets earlier but still in future
        setup_quota(dir.path(), 1, 100.0, 9999999999);
        setup_quota(dir.path(), 2, 100.0, 9999999000);

        let best = pick_best(dir.path(), None);
        // Account 2 resets earlier
        assert_eq!(best, Some(AccountNum::try_from(2u16).unwrap()));
    }

    #[test]
    fn pick_best_returns_none_when_no_accounts() {
        let dir = TempDir::new().unwrap();
        let best = pick_best(dir.path(), None);
        assert_eq!(best, None);
    }

    #[test]
    fn pick_best_accounts_without_quota_treated_as_zero() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 50.0, 9999999999);
        // Account 2 has no quota data — treated as 0

        let best = pick_best(dir.path(), None);
        assert_eq!(best, Some(AccountNum::try_from(2u16).unwrap()));
    }

    #[test]
    fn suggest_returns_structure() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 80.0, 9999999999);
        setup_quota(dir.path(), 2, 20.0, 9999999999);

        let current = AccountNum::try_from(1u16).unwrap();
        let suggestion = suggest(dir.path(), Some(current));

        assert_eq!(suggestion.suggested, Some(2));
        assert!(!suggestion.exhausted);
        assert_eq!(suggestion.current, Some(1));
    }

    #[test]
    fn suggest_all_exhausted() {
        let dir = TempDir::new().unwrap();
        setup_account(dir.path(), 1);
        setup_account(dir.path(), 2);
        setup_quota(dir.path(), 1, 100.0, 9999999999);
        setup_quota(dir.path(), 2, 100.0, 9999999000);

        let suggestion = suggest(dir.path(), None);
        assert!(suggestion.suggested.is_some());
        assert!(suggestion.exhausted);
    }
}
