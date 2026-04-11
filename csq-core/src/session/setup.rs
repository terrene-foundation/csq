//! Session setup — onboarding flag, credential copy, stale PID cleanup.

use super::isolation;
use crate::credentials::{self, file};
use crate::error::CredentialError;
use crate::types::AccountNum;
use serde_json::{Map, Value};
use std::path::Path;
use tracing::debug;

/// Marks the onboarding flag in `config_dir/.claude.json` so CC's setup
/// wizard doesn't run again.
///
/// Preserves any existing fields in `.claude.json`. If the file doesn't
/// exist, creates it with just the flag.
pub fn mark_onboarding_complete(config_dir: &Path) -> Result<(), CredentialError> {
    let path = config_dir.join(".claude.json");

    let mut value: Value = match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => {
            // Try to parse; if corrupt, attempt repair
            serde_json::from_str(&content).unwrap_or_else(|_| {
                super::merge::repair_truncated_json(&content)
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Object(Map::new()))
            })
        }
        _ => Value::Object(Map::new()),
    };

    if let Some(obj) = value.as_object_mut() {
        obj.insert("hasCompletedOnboarding".to_string(), Value::Bool(true));
    }

    let json = serde_json::to_string_pretty(&value).map_err(|e| CredentialError::Corrupt {
        path: path.clone(),
        reason: format!("serialize .claude.json: {e}"),
    })?;

    // Atomic write
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    crate::platform::fs::atomic_replace(&tmp, &path).map_err(|e| CredentialError::Io {
        path: path.clone(),
        source: std::io::Error::other(e.to_string()),
    })?;

    Ok(())
}

/// Copies canonical credentials into the given config dir for a session.
///
/// This is step 1 of `csq run` — read the refreshed credentials from
/// `credentials/N.json` and write them atomically to `config-N/.credentials.json`.
pub fn copy_credentials_for_session(
    base_dir: &Path,
    config_dir: &Path,
    account: AccountNum,
) -> Result<(), CredentialError> {
    let canonical = file::canonical_path(base_dir, account);
    let creds = credentials::load(&canonical)?;

    let live = config_dir.join(".credentials.json");
    credentials::save(&live, &creds)?;

    debug!(account = %account, "credentials copied for session");
    Ok(())
}

/// Removes the stale `.live-pid` file from a config directory.
///
/// Re-exported from isolation for convenience.
pub fn cleanup_stale_pid(config_dir: &Path) {
    isolation::remove_stale_pid(config_dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn mark_onboarding_creates_new_file() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        mark_onboarding_complete(&config).unwrap();

        let content = std::fs::read_to_string(config.join(".claude.json")).unwrap();
        let value: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            value.get("hasCompletedOnboarding").unwrap(),
            &Value::Bool(true)
        );
    }

    #[test]
    fn mark_onboarding_preserves_existing_fields() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-2");
        std::fs::create_dir_all(&config).unwrap();

        std::fs::write(
            config.join(".claude.json"),
            r#"{"existingField": "preserved", "nested": {"a": 1}}"#,
        )
        .unwrap();

        mark_onboarding_complete(&config).unwrap();

        let content = std::fs::read_to_string(config.join(".claude.json")).unwrap();
        let value: Value = serde_json::from_str(&content).unwrap();

        assert_eq!(
            value.get("existingField").unwrap().as_str().unwrap(),
            "preserved"
        );
        assert_eq!(value.get("nested").unwrap().get("a").unwrap(), 1);
        assert_eq!(
            value.get("hasCompletedOnboarding").unwrap(),
            &Value::Bool(true)
        );
    }

    #[test]
    fn mark_onboarding_repairs_truncated_file() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-3");
        std::fs::create_dir_all(&config).unwrap();

        // Truncated file
        std::fs::write(config.join(".claude.json"), r#"{"existingField": "value""#).unwrap();

        mark_onboarding_complete(&config).unwrap();

        let content = std::fs::read_to_string(config.join(".claude.json")).unwrap();
        let value: Value = serde_json::from_str(&content).unwrap();
        // Repair succeeded
        assert_eq!(
            value.get("existingField").unwrap().as_str().unwrap(),
            "value"
        );
        assert_eq!(
            value.get("hasCompletedOnboarding").unwrap(),
            &Value::Bool(true)
        );
    }

    #[test]
    fn copy_credentials_for_session_works() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-1");
        std::fs::create_dir_all(&config).unwrap();

        let account = AccountNum::try_from(1u16).unwrap();
        let creds = CredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at-1".into()),
                refresh_token: RefreshToken::new("rt-1".into()),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        };
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        copy_credentials_for_session(dir.path(), &config, account).unwrap();

        let live = credentials::load(&config.join(".credentials.json")).unwrap();
        assert_eq!(live.claude_ai_oauth.access_token.expose_secret(), "at-1");
    }
}
