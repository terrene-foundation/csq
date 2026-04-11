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

    // Re-read canonical inside lock (monotonicity guard)
    let canonical_expires = match credentials::load(&canonical_path) {
        Ok(c) => c.claude_ai_oauth.expires_at,
        Err(_) => 0, // no canonical yet — any live is newer
    };

    if live_creds.claude_ai_oauth.expires_at <= canonical_expires {
        debug!(account = %account, "backsync: live is not newer, skipping");
        return Ok(false);
    }

    // Live is newer — update canonical
    credentials::save(&canonical_path, &live_creds)?;
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
