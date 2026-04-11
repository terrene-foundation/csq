//! Config dir scanning and credential fanout.
//!
//! Scans `config-*` directories for matching account markers and
//! distributes refreshed credentials to all matching sessions.

use crate::accounts::markers;
use crate::credentials::{self, CredentialFile};
use crate::error::CredentialError;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Scans `config-*` directories for those belonging to the given account.
///
/// Returns paths to config directories whose `.csq-account` marker
/// matches the given account number.
pub fn scan_config_dirs(base_dir: &Path, account: AccountNum) -> Vec<PathBuf> {
    let mut matches = Vec::new();

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return matches,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if !name.starts_with("config-") {
            continue;
        }

        // Check if this config dir belongs to the target account
        if let Some(marker_account) = markers::read_csq_account(&path) {
            if marker_account == account {
                matches.push(path);
            }
        }
    }

    matches
}

/// Fans out credentials to all config directories belonging to the given account.
///
/// Writes atomically to each dir's `.credentials.json`. Skips dirs where
/// the access token already matches (already in sync). A failure on one
/// dir does not stop fanout to others.
pub fn fan_out_credentials(base_dir: &Path, account: AccountNum, creds: &CredentialFile) -> usize {
    let dirs = scan_config_dirs(base_dir, account);
    let new_token = creds.claude_ai_oauth.access_token.expose_secret();
    let mut updated = 0;

    for dir in &dirs {
        let live_path = dir.join(".credentials.json");

        // Skip if already in sync
        if let Ok(existing) = credentials::load(&live_path) {
            if existing.claude_ai_oauth.access_token.expose_secret() == new_token {
                debug!(dir = %dir.display(), "already in sync, skipping");
                continue;
            }
        }

        match credentials::save(&live_path, creds) {
            Ok(()) => {
                debug!(dir = %dir.display(), "fanout complete");
                updated += 1;
            }
            Err(e) => {
                warn!(dir = %dir.display(), error = %e, "fanout failed for dir");
            }
        }
    }

    updated
}

// ── Broker failure flags ──────────────────────────────────────────────

/// Returns the path to the broker-failed flag file.
fn broker_failed_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join("credentials")
        .join(format!("{}.broker-failed", account))
}

/// Checks whether broker has failed for the given account (LOGIN-NEEDED).
pub fn is_broker_failed(base_dir: &Path, account: AccountNum) -> bool {
    broker_failed_path(base_dir, account).exists()
}

/// Sets the broker-failed flag for the given account.
pub fn set_broker_failed(base_dir: &Path, account: AccountNum) -> Result<(), CredentialError> {
    let path = broker_failed_path(base_dir, account);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, b"").map_err(|e| CredentialError::Io { path, source: e })
}

/// Clears the broker-failed flag (on successful refresh or login).
pub fn clear_broker_failed(base_dir: &Path, account: AccountNum) {
    let path = broker_failed_path(base_dir, account);
    let _ = std::fs::remove_file(&path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn make_creds(access: &str, refresh: &str) -> CredentialFile {
        CredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        }
    }

    fn setup_config_dir(base: &Path, n: u16) -> PathBuf {
        let dir = base.join(format!("config-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let account = AccountNum::try_from(n).unwrap();
        markers::write_csq_account(&dir, account).unwrap();
        dir
    }

    #[test]
    fn scan_finds_matching_dirs() {
        let dir = TempDir::new().unwrap();
        setup_config_dir(dir.path(), 3);
        setup_config_dir(dir.path(), 3); // same account, different dir won't happen in practice
        let other = dir.path().join("config-5");
        std::fs::create_dir_all(&other).unwrap();
        markers::write_csq_account(&other, AccountNum::try_from(5u16).unwrap()).unwrap();

        let account = AccountNum::try_from(3u16).unwrap();
        let matches = scan_config_dirs(dir.path(), account);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn scan_ignores_dirs_without_marker() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("config-1")).unwrap();
        // No .csq-account marker

        let account = AccountNum::try_from(1u16).unwrap();
        let matches = scan_config_dirs(dir.path(), account);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_empty_base_dir() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        let matches = scan_config_dirs(dir.path(), account);
        assert!(matches.is_empty());
    }

    #[test]
    fn fanout_updates_matching_dirs() {
        let dir = TempDir::new().unwrap();
        let config = setup_config_dir(dir.path(), 2);

        // Write initial creds to the config dir
        let old_creds = make_creds("old-access", "old-refresh");
        credentials::save(&config.join(".credentials.json"), &old_creds).unwrap();

        // Fan out new creds
        let new_creds = make_creds("new-access", "new-refresh");
        let account = AccountNum::try_from(2u16).unwrap();
        let updated = fan_out_credentials(dir.path(), account, &new_creds);

        assert_eq!(updated, 1);
        let live = credentials::load(&config.join(".credentials.json")).unwrap();
        assert_eq!(
            live.claude_ai_oauth.access_token.expose_secret(),
            "new-access"
        );
    }

    #[test]
    fn fanout_skips_already_synced() {
        let dir = TempDir::new().unwrap();
        let config = setup_config_dir(dir.path(), 1);

        let creds = make_creds("same-access", "same-refresh");
        credentials::save(&config.join(".credentials.json"), &creds).unwrap();

        // Fan out same creds — should skip
        let account = AccountNum::try_from(1u16).unwrap();
        let updated = fan_out_credentials(dir.path(), account, &creds);
        assert_eq!(updated, 0);
    }

    #[test]
    fn broker_failed_flag_lifecycle() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(4u16).unwrap();

        assert!(!is_broker_failed(dir.path(), account));

        set_broker_failed(dir.path(), account).unwrap();
        assert!(is_broker_failed(dir.path(), account));

        clear_broker_failed(dir.path(), account);
        assert!(!is_broker_failed(dir.path(), account));
    }
}
