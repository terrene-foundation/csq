//! Account swap — copy canonical credentials into a config dir.
//!
//! `swap_to(target)` reads `credentials/N.json` and writes it to the
//! target config dir's `.credentials.json`, along with `.csq-account`
//! and `.current-account` markers. Never calls the refresh endpoint —
//! uses cached credentials only.

use crate::accounts::markers;
use crate::credentials::{self, file};
use crate::error::{CredentialError, CsqError};
use crate::types::AccountNum;
use std::path::Path;
use tracing::{debug, warn};

/// Swaps the active account in a config directory.
///
/// Reads canonical credentials for `target`, writes them to
/// `config_dir/.credentials.json` (atomic), and updates markers.
///
/// Preserves `.quota-cursor` (NOT deleted during swap).
/// Best-effort keychain write.
pub fn swap_to(
    base_dir: &Path,
    config_dir: &Path,
    target: AccountNum,
) -> Result<SwapResult, CsqError> {
    let canonical_path = file::canonical_path(base_dir, target);
    let creds = credentials::load(&canonical_path)?;

    let live_path = config_dir.join(".credentials.json");
    credentials::save(&live_path, &creds)?;

    // Verify by reading back
    let verify = credentials::load(&live_path).map_err(|e| {
        warn!(error = %e, "swap verification read failed");
        e
    })?;
    if verify.claude_ai_oauth.access_token.expose_secret()
        != creds.claude_ai_oauth.access_token.expose_secret()
    {
        return Err(CsqError::Credential(CredentialError::Corrupt {
            path: live_path.clone(),
            reason: "verification: access token mismatch after write".into(),
        }));
    }

    // Update markers
    markers::write_csq_account(config_dir, target)?;
    markers::write_current_account(config_dir, target)?;

    // Best-effort keychain write
    credentials::keychain::write(config_dir, &creds);

    debug!(account = %target, "swap complete");
    Ok(SwapResult {
        account: target,
        expires_at_ms: creds.claude_ai_oauth.expires_at,
    })
}

/// Performs a delayed verification check.
///
/// Called +2s after `swap_to`. If CC detected stale credentials and
/// re-fetched, the access token will differ from what we wrote. This
/// function logs a warning but does not retry.
///
/// Returns `true` if the swap is still intact, `false` if CC overwrote it.
pub fn verify_swap_after_delay(
    config_dir: &Path,
    expected_access_token: &str,
) -> bool {
    let live_path = config_dir.join(".credentials.json");
    match credentials::load(&live_path) {
        Ok(creds) => {
            let intact = creds.claude_ai_oauth.access_token.expose_secret() == expected_access_token;
            if !intact {
                warn!(
                    config_dir = %config_dir.display(),
                    "delayed swap verification: CC overwrote credentials"
                );
            }
            intact
        }
        Err(e) => {
            warn!(error = %e, "delayed swap verification: failed to read live creds");
            false
        }
    }
}

/// Result of a successful swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapResult {
    pub account: AccountNum,
    pub expires_at_ms: u64,
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

    #[test]
    fn swap_to_writes_all_files() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-2");
        std::fs::create_dir_all(&config).unwrap();
        let target = AccountNum::try_from(3u16).unwrap();

        // Set up canonical
        let creds = make_creds("at-3", "rt-3");
        credentials::save(&file::canonical_path(dir.path(), target), &creds).unwrap();

        let result = swap_to(dir.path(), &config, target).unwrap();
        assert_eq!(result.account, target);

        // Live file written
        let live = credentials::load(&config.join(".credentials.json")).unwrap();
        assert_eq!(live.claude_ai_oauth.access_token.expose_secret(), "at-3");

        // Markers written
        assert_eq!(markers::read_csq_account(&config), Some(target));
        assert_eq!(markers::read_current_account(&config), Some(target));
    }

    #[test]
    fn swap_preserves_quota_cursor() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();
        let target = AccountNum::try_from(1u16).unwrap();

        // Pre-existing quota cursor
        let cursor_path = config.join(".quota-cursor");
        std::fs::write(&cursor_path, "existing-cursor-hash").unwrap();

        // Set up canonical and swap
        let creds = make_creds("at-1", "rt-1");
        credentials::save(&file::canonical_path(dir.path(), target), &creds).unwrap();
        swap_to(dir.path(), &config, target).unwrap();

        // Cursor must still exist
        assert!(cursor_path.exists());
        assert_eq!(
            std::fs::read_to_string(&cursor_path).unwrap(),
            "existing-cursor-hash"
        );
    }

    #[test]
    fn swap_fails_if_canonical_missing() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();
        let target = AccountNum::try_from(9u16).unwrap();

        let result = swap_to(dir.path(), &config, target);
        assert!(result.is_err());
    }

    #[test]
    fn verify_swap_after_delay_intact() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let creds = make_creds("at-expected", "rt-1");
        credentials::save(&config.join(".credentials.json"), &creds).unwrap();

        assert!(verify_swap_after_delay(&config, "at-expected"));
    }

    #[test]
    fn verify_swap_after_delay_overwritten() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let creds = make_creds("at-different", "rt-1");
        credentials::save(&config.join(".credentials.json"), &creds).unwrap();

        assert!(!verify_swap_after_delay(&config, "at-expected"));
    }
}
