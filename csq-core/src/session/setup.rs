//! Session setup — onboarding flag and stale PID cleanup.
//!
//! M3-7 (R1 C1 fix-wave): the prior `copy_credentials_for_session` writer was
//! retired. Pre-M3-7, `csq run N` copied `credentials/N.json` (canonical) into
//! `config-N/.credentials.json` (legacy live mirror) so the handle dir's
//! `.credentials.json` symlink would resolve to a populated target. Post-M3-7
//! the handle dir symlink resolves to `identities/<UUID>/credentials.json`
//! (M3-3 retarget), which is seeded by `csq login`'s `finalize_login`
//! (`save_canonical` + the post-mint UUID seed in `accounts/login.rs`) and
//! refreshed by the daemon (`broker_check` → `save_canonical`). The legacy
//! mirror is no longer a credential reader for any production code path, so
//! a per-run copy was a dead write. See the writer-surface retirement table
//! in `internal-design-docs`.

use super::isolation;
use crate::error::CredentialError;
use serde_json::{Map, Value};
use std::path::Path;

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

    // Atomic write with §5a cleanup: .claude.json carries CC session
    // metadata (oauthAccount, GrowthBook flags, recent dirs) — not OAuth
    // tokens directly, but partial-failure leaves session state at
    // umask 0o644 which is a downgrade from the user's default privacy.
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: tmp,
            source: e,
        });
    }
    if let Err(e) = crate::platform::fs::atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CredentialError::Io {
            path: path.clone(),
            source: std::io::Error::other(e.to_string()),
        });
    }

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

    /// §5a regression (security.md MUST Rule 5a, an internal journal entry B2,
    /// /redteam round 3 2026-05-09): when `mark_onboarding_complete`
    /// fails after the tmp file would have been created (parent dir
    /// read-only → write fails), no `.tmp.` file must remain.
    ///
    /// `.claude.json` carries CC session metadata (oauthAccount,
    /// GrowthBook flags, recent dirs); a partial-failure must not
    /// leave session state at umask 0o644.
    #[cfg(unix)]
    #[test]
    fn mark_onboarding_partial_failure_cleans_tmp_file() {
        // Arrange: create a valid .claude.json so the parent dir exists.
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("config-3");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join(".claude.json"),
            r#"{"existingField": "preserved"}"#,
        )
        .unwrap();
        // Verify the happy path works first.
        mark_onboarding_complete(&config).unwrap();

        // Act + Assert: read-only parent → write fails → no tmp leak.
        crate::platform::fs::assert_no_tmp_leak_on_readonly_parent(&config, || {
            mark_onboarding_complete(&config)
        });
    }
}
