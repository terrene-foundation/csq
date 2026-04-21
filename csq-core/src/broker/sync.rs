//! Bidirectional credential sync between canonical and live files.
//!
//! - **Backsync**: live `.credentials.json` → canonical `credentials/N.json`
//!   when CC refreshes a token (live is newer).
//! - **Pullsync**: canonical → live when the daemon refreshed (canonical is newer).
//!
//! Both enforce monotonicity: only write if `expiresAt` is strictly newer.

use crate::accounts::identity;
use crate::accounts::markers;
use crate::credentials::{self, file};
use crate::platform::lock;
use std::path::Path;
use tracing::debug;

/// Backsyncs a live credential file into canonical storage.
///
/// When CC refreshes a token directly (bypassing csq), the live
/// `.credentials.json` may be newer than `credentials/N.json`.
/// This function detects that and updates canonical.
///
/// Identity resolution: matches by refresh token first (primary),
/// falls back to `.csq-account` marker if RT was rotated.
///
/// Monotonicity guard: only writes if live `expiresAt` > canonical
/// `expiresAt`. Re-reads canonical inside the lock to prevent races.
pub fn backsync(config_dir: &Path, base_dir: &Path) -> Result<bool, crate::error::CsqError> {
    let live_path = config_dir.join(".credentials.json");
    let live_creds = match credentials::load(&live_path) {
        Ok(c) => c,
        Err(_) => return Ok(false), // no live creds, nothing to sync
    };

    // Resolve account: RT match first, then marker fallback
    let account = identity::match_refresh_token(
        base_dir,
        live_creds.claude_ai_oauth.refresh_token.expose_secret(),
    )
    .or_else(|| markers::read_csq_account(config_dir));

    let account = match account {
        Some(a) => a,
        None => {
            debug!(dir = %config_dir.display(), "backsync: cannot determine account");
            return Ok(false);
        }
    };

    let canonical_path = file::canonical_path(base_dir, account);
    let lock_path = canonical_path.with_extension("lock");

    // Acquire per-canonical lock
    let _guard = lock::lock_file(&lock_path)?;

    // Re-read canonical inside lock (monotonicity guard AND
    // subscription-metadata preservation source, journal 0063 P1-1).
    let canonical_existing = credentials::load(&canonical_path).ok();
    let canonical_expires = canonical_existing
        .as_ref()
        .map(|c| c.claude_ai_oauth.expires_at)
        .unwrap_or(0);

    if live_creds.claude_ai_oauth.expires_at <= canonical_expires {
        debug!(account = %account, "backsync: live is not newer, skipping");
        return Ok(false);
    }

    // Subscription preservation guard — mirror the shape from
    // `rotation::swap_to` and `broker::fanout::fan_out_credentials`.
    // Anthropic's token endpoint does NOT return `subscription_type`
    // or `rate_limit_tier`; CC backfills them into the live file on
    // its first API call after a fresh login. If CC just wrote a
    // fresh `.credentials.json` (post-re-login) and backsync fires
    // before CC makes its first API call, live carries `None` for
    // both fields. Without this guard we'd overwrite canonical's
    // `Some(max)` with `None` and the user's Max tier vanishes until
    // the next daemon refresh backfills it — typically up to 5
    // hours. Preserve canonical's value when live is None.
    let mut to_save = live_creds.clone();
    if let Some(existing) = canonical_existing.as_ref() {
        if to_save.claude_ai_oauth.subscription_type.is_none() {
            to_save.claude_ai_oauth.subscription_type =
                existing.claude_ai_oauth.subscription_type.clone();
        }
        if to_save.claude_ai_oauth.rate_limit_tier.is_none() {
            to_save.claude_ai_oauth.rate_limit_tier =
                existing.claude_ai_oauth.rate_limit_tier.clone();
        }
    }

    // Live is newer — update canonical
    credentials::save(&canonical_path, &to_save)?;
    debug!(account = %account, "backsync: canonical updated from live");
    Ok(true)
}

/// Pullsyncs canonical credentials into a live config directory.
///
/// When the daemon refreshes a token, the canonical file is newer
/// than the live file in each CC session's config dir.
///
/// Only writes if: (1) canonical `expiresAt` > live `expiresAt`, and
/// (2) access tokens differ (avoids unnecessary writes).
pub fn pullsync(config_dir: &Path, base_dir: &Path) -> Result<bool, crate::error::CsqError> {
    let account = match markers::read_csq_account(config_dir) {
        Some(a) => a,
        None => return Ok(false),
    };

    let canonical_path = file::canonical_path(base_dir, account);
    let canonical_creds = match credentials::load(&canonical_path) {
        Ok(c) => c,
        Err(_) => return Ok(false),
    };

    let live_path = config_dir.join(".credentials.json");
    let live_expires = match credentials::load(&live_path) {
        Ok(c) => {
            // Skip if same access token (already in sync)
            if c.claude_ai_oauth.access_token.expose_secret()
                == canonical_creds.claude_ai_oauth.access_token.expose_secret()
            {
                return Ok(false);
            }
            c.claude_ai_oauth.expires_at
        }
        Err(_) => 0, // no live file — canonical is newer
    };

    if canonical_creds.claude_ai_oauth.expires_at <= live_expires {
        debug!(account = %account, "pullsync: canonical is not newer, skipping");
        return Ok(false);
    }

    // Canonical is newer — update live
    credentials::save(&live_path, &canonical_creds)?;
    debug!(account = %account, "pullsync: live updated from canonical");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, AccountNum, RefreshToken};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn make_creds(access: &str, refresh: &str, expires_at: u64) -> CredentialFile {
        CredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        }
    }

    fn setup_backsync(
        base: &Path,
        account: u16,
        canonical_expires: u64,
        live_expires: u64,
    ) -> PathBuf {
        let config = base.join(format!("config-{account}"));
        std::fs::create_dir_all(&config).unwrap();

        let acct = AccountNum::try_from(account).unwrap();
        markers::write_csq_account(&config, acct).unwrap();

        let rt = format!("rt-{account}");
        let canonical = make_creds(&format!("at-can-{account}"), &rt, canonical_expires);
        credentials::save(&file::canonical_path(base, acct), &canonical).unwrap();

        let live = make_creds(&format!("at-live-{account}"), &rt, live_expires);
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        config
    }

    #[test]
    fn backsync_live_newer_updates_canonical() {
        let dir = TempDir::new().unwrap();
        let config = setup_backsync(dir.path(), 1, 1000, 2000);

        let synced = backsync(&config, dir.path()).unwrap();
        assert!(synced);

        let acct = AccountNum::try_from(1u16).unwrap();
        let canonical = credentials::load(&file::canonical_path(dir.path(), acct)).unwrap();
        assert_eq!(canonical.claude_ai_oauth.expires_at, 2000);
    }

    #[test]
    fn backsync_live_older_skips() {
        let dir = TempDir::new().unwrap();
        let config = setup_backsync(dir.path(), 2, 2000, 1000);

        let synced = backsync(&config, dir.path()).unwrap();
        assert!(!synced);

        let acct = AccountNum::try_from(2u16).unwrap();
        let canonical = credentials::load(&file::canonical_path(dir.path(), acct)).unwrap();
        assert_eq!(canonical.claude_ai_oauth.expires_at, 2000);
    }

    #[test]
    fn backsync_no_live_creds() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-3");
        std::fs::create_dir_all(&config).unwrap();

        let synced = backsync(&config, dir.path()).unwrap();
        assert!(!synced);
    }

    /// Regression for journal 0063 P1-1: when live.subscription_type is
    /// None (Anthropic's token endpoint doesn't include it; CC backfills
    /// on first API call), backsync must preserve canonical's Some(max)
    /// rather than overwriting with None. Without the guard, the user's
    /// Max tier silently disappears until the next daemon refresh.
    #[test]
    fn backsync_preserves_subscription_type_when_live_has_none() {
        let dir = TempDir::new().unwrap();
        let acct = AccountNum::try_from(5u16).unwrap();

        // Canonical has Max.
        let mut canonical = make_creds("at-canonical", "rt-5", 1000);
        canonical.claude_ai_oauth.subscription_type = Some("max".to_string());
        canonical.claude_ai_oauth.rate_limit_tier = Some("tier_4".to_string());
        credentials::save(&file::canonical_path(dir.path(), acct), &canonical).unwrap();

        // Live is fresh (newer expires_at) but subscription fields
        // are None — matches the post-re-login state before CC
        // makes its first API call.
        let config = dir.path().join("config-5");
        std::fs::create_dir_all(&config).unwrap();
        markers::write_csq_account(&config, acct).unwrap();
        let live = make_creds("at-live-fresh", "rt-5", 2000);
        assert!(live.claude_ai_oauth.subscription_type.is_none());
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        // Act
        let synced = backsync(&config, dir.path()).unwrap();
        assert!(synced, "live is newer — backsync must update canonical");

        // Assert: expires_at updated (freshness carried over) AND
        // subscription_type/rate_limit_tier preserved from canonical.
        let post = credentials::load(&file::canonical_path(dir.path(), acct)).unwrap();
        assert_eq!(post.claude_ai_oauth.expires_at, 2000);
        assert_eq!(
            post.claude_ai_oauth.subscription_type.as_deref(),
            Some("max"),
            "subscription_type must be preserved when live has None"
        );
        assert_eq!(
            post.claude_ai_oauth.rate_limit_tier.as_deref(),
            Some("tier_4"),
            "rate_limit_tier must be preserved when live has None"
        );
    }

    /// When live has a subscription_type (e.g. CC already made its
    /// first API call and backfilled), backsync must take live's
    /// value — not cling to canonical's stale one.
    #[test]
    fn backsync_takes_live_subscription_type_when_present() {
        let dir = TempDir::new().unwrap();
        let acct = AccountNum::try_from(6u16).unwrap();

        let mut canonical = make_creds("at-canonical", "rt-6", 1000);
        canonical.claude_ai_oauth.subscription_type = Some("max".to_string());
        credentials::save(&file::canonical_path(dir.path(), acct), &canonical).unwrap();

        let config = dir.path().join("config-6");
        std::fs::create_dir_all(&config).unwrap();
        markers::write_csq_account(&config, acct).unwrap();
        let mut live = make_creds("at-live", "rt-6", 2000);
        live.claude_ai_oauth.subscription_type = Some("pro".to_string());
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        backsync(&config, dir.path()).unwrap();

        let post = credentials::load(&file::canonical_path(dir.path(), acct)).unwrap();
        assert_eq!(
            post.claude_ai_oauth.subscription_type.as_deref(),
            Some("pro"),
            "live's Some value must win over canonical's when present"
        );
    }

    #[test]
    fn pullsync_canonical_newer_updates_live() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-4");
        std::fs::create_dir_all(&config).unwrap();
        let acct = AccountNum::try_from(4u16).unwrap();
        markers::write_csq_account(&config, acct).unwrap();

        // Canonical is newer
        let canonical = make_creds("at-new", "rt-4", 3000);
        credentials::save(&file::canonical_path(dir.path(), acct), &canonical).unwrap();

        // Live is older
        let live = make_creds("at-old", "rt-4", 1000);
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        let synced = pullsync(&config, dir.path()).unwrap();
        assert!(synced);

        let updated = credentials::load(&config.join(".credentials.json")).unwrap();
        assert_eq!(
            updated.claude_ai_oauth.access_token.expose_secret(),
            "at-new"
        );
    }

    #[test]
    fn pullsync_canonical_older_skips() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-5");
        std::fs::create_dir_all(&config).unwrap();
        let acct = AccountNum::try_from(5u16).unwrap();
        markers::write_csq_account(&config, acct).unwrap();

        let canonical = make_creds("at-old", "rt-5", 1000);
        credentials::save(&file::canonical_path(dir.path(), acct), &canonical).unwrap();

        let live = make_creds("at-new", "rt-5", 3000);
        credentials::save(&config.join(".credentials.json"), &live).unwrap();

        let synced = pullsync(&config, dir.path()).unwrap();
        assert!(!synced);
    }

    #[test]
    fn pullsync_same_access_token_skips() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-6");
        std::fs::create_dir_all(&config).unwrap();
        let acct = AccountNum::try_from(6u16).unwrap();
        markers::write_csq_account(&config, acct).unwrap();

        let creds = make_creds("at-same", "rt-6", 5000);
        credentials::save(&file::canonical_path(dir.path(), acct), &creds).unwrap();
        credentials::save(&config.join(".credentials.json"), &creds).unwrap();

        let synced = pullsync(&config, dir.path()).unwrap();
        assert!(!synced);
    }

    #[test]
    fn pullsync_no_marker() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-7");
        std::fs::create_dir_all(&config).unwrap();
        // No .csq-account marker

        let synced = pullsync(&config, dir.path()).unwrap();
        assert!(!synced);
    }
}
