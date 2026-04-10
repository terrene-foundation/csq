//! Account identity resolution — determines which account a CC session
//! belongs to via a three-step fallback chain.

use super::markers;
use super::profiles;
use crate::credentials;
use crate::types::AccountNum;
use std::path::Path;
use tracing::debug;

/// Resolves which account a CC session is using.
///
/// Three-step fallback chain:
/// 1. **Fast path**: read `.current-account` from the config dir
/// 2. **Dir name**: extract N from `config-N` directory name
/// 3. **CC auth**: run `claude auth status --json` and match email to profiles
///
/// Returns None if identity cannot be determined.
pub fn which_account(config_dir: &Path, base_dir: &Path) -> Option<AccountNum> {
    // Step 1: fast path — .current-account marker
    if let Some(account) = markers::read_current_account(config_dir) {
        debug!(account = %account, "identity via .current-account");
        return Some(account);
    }

    // Step 2: extract N from config-N directory name
    if let Some(account) = account_from_dir_name(config_dir) {
        debug!(account = %account, "identity via dir name");
        return Some(account);
    }

    // Step 3: CC auth — run claude auth status and match email
    if let Some(account) = account_from_cc_auth(config_dir, base_dir) {
        debug!(account = %account, "identity via CC auth");
        return Some(account);
    }

    debug!(config_dir = %config_dir.display(), "could not determine account");
    None
}

/// Extracts account number from a `config-N` directory name.
pub fn account_from_dir_name(config_dir: &Path) -> Option<AccountNum> {
    let name = config_dir.file_name()?.to_str()?;
    let n = name.strip_prefix("config-")?;
    n.parse().ok()
}

/// Matches access token in the given config dir against all credential files.
///
/// Returns the account number whose credential file contains a matching
/// access token. Returns None if no match (e.g., token was refreshed).
pub fn match_access_token(base_dir: &Path, access_token: &str) -> Option<AccountNum> {
    match_token_in_credentials(base_dir, |payload| {
        payload.access_token.expose_secret() == access_token
    })
}

/// Matches refresh token against all credential files.
///
/// More reliable than access token matching because CC refreshes the
/// access token but the refresh token stays the same until csq rotates it.
pub fn match_refresh_token(base_dir: &Path, refresh_token: &str) -> Option<AccountNum> {
    match_token_in_credentials(base_dir, |payload| {
        payload.refresh_token.expose_secret() == refresh_token
    })
}

/// Linear scan of credentials/N.json files, calling `predicate` on each.
fn match_token_in_credentials<F>(base_dir: &Path, predicate: F) -> Option<AccountNum>
where
    F: Fn(&credentials::OAuthPayload) -> bool,
{
    let creds_dir = base_dir.join("credentials");
    let entries = std::fs::read_dir(&creds_dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        // Extract account number from filename (e.g., "3.json" -> 3)
        let stem = path.file_stem()?.to_str()?;
        let account: AccountNum = stem.parse().ok()?;

        if let Ok(cred_file) = credentials::load(&path) {
            if predicate(&cred_file.claude_ai_oauth) {
                return Some(account);
            }
        }
    }
    None
}

/// Attempts to resolve account by running `claude auth status --json`
/// and matching the email against profiles.json.
fn account_from_cc_auth(config_dir: &Path, base_dir: &Path) -> Option<AccountNum> {
    let output = std::process::Command::new("claude")
        .args(["auth", "status", "--json"])
        .env("CLAUDE_CONFIG_DIR", config_dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Parse the JSON output for email
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    let email = json.get("email")?.as_str()?;

    // Look up email in profiles
    let profiles_path = profiles::profiles_path(base_dir);
    let profiles = profiles::load(&profiles_path).ok()?;

    for (key, profile) in &profiles.accounts {
        if profile.email == email {
            return key.parse().ok();
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{self, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn write_cred(dir: &Path, account: u16, access: &str, refresh: &str) {
        let creds = CredentialFile {
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
        };
        let path = dir.join("credentials").join(format!("{account}.json"));
        credentials::save(&path, &creds).unwrap();
    }

    #[test]
    fn which_account_fast_path() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-3");
        std::fs::create_dir_all(&config).unwrap();

        let account = AccountNum::try_from(3u16).unwrap();
        markers::write_current_account(&config, account).unwrap();

        assert_eq!(which_account(&config, dir.path()), Some(account));
    }

    #[test]
    fn which_account_dir_name_fallback() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-7");
        std::fs::create_dir_all(&config).unwrap();

        let expected = AccountNum::try_from(7u16).unwrap();
        assert_eq!(which_account(&config, dir.path()), Some(expected));
    }

    #[test]
    fn which_account_returns_none_for_unknown() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("unknown-dir");
        std::fs::create_dir_all(&config).unwrap();

        assert_eq!(which_account(&config, dir.path()), None);
    }

    #[test]
    fn account_from_dir_name_variants() {
        assert_eq!(
            account_from_dir_name(Path::new("/tmp/config-1")),
            Some(AccountNum::try_from(1u16).unwrap())
        );
        assert_eq!(
            account_from_dir_name(Path::new("/tmp/config-999")),
            Some(AccountNum::try_from(999u16).unwrap())
        );
        assert_eq!(account_from_dir_name(Path::new("/tmp/config-0")), None);
        assert_eq!(account_from_dir_name(Path::new("/tmp/other")), None);
        assert_eq!(account_from_dir_name(Path::new("/tmp/config-abc")), None);
    }

    #[test]
    fn match_access_token_finds_correct_account() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1, "at-1", "rt-1");
        write_cred(dir.path(), 2, "at-2", "rt-2");
        write_cred(dir.path(), 3, "at-3", "rt-3");

        assert_eq!(
            match_access_token(dir.path(), "at-2"),
            Some(AccountNum::try_from(2u16).unwrap())
        );
    }

    #[test]
    fn match_refresh_token_finds_correct_account() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1, "at-1", "rt-1");
        write_cred(dir.path(), 5, "at-5", "rt-5");

        assert_eq!(
            match_refresh_token(dir.path(), "rt-5"),
            Some(AccountNum::try_from(5u16).unwrap())
        );
    }

    #[test]
    fn match_token_returns_none_when_not_found() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1, "at-1", "rt-1");

        assert_eq!(match_access_token(dir.path(), "at-nonexistent"), None);
        assert_eq!(match_refresh_token(dir.path(), "rt-nonexistent"), None);
    }

    #[test]
    fn match_token_no_credentials_dir() {
        let dir = TempDir::new().unwrap();
        assert_eq!(match_access_token(dir.path(), "at-1"), None);
    }
}
