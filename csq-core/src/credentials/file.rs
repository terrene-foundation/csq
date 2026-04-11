//! Credential file I/O — load, save, and canonical save with mirroring.

use super::CredentialFile;
use crate::error::CredentialError;
use crate::platform::fs::{atomic_replace, secure_file};
use crate::types::AccountNum;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Loads a credential file from disk.
///
/// Returns `CredentialError::NotFound` if the file does not exist,
/// `CredentialError::Corrupt` if the JSON is invalid.
pub fn load(path: &Path) -> Result<CredentialFile, CredentialError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CredentialError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            CredentialError::Io {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;

    if content.trim().is_empty() {
        return Err(CredentialError::Corrupt {
            path: path.to_path_buf(),
            reason: "empty file".into(),
        });
    }

    serde_json::from_str(&content).map_err(|e| CredentialError::Corrupt {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Saves a credential file to disk with atomic write + secure permissions.
pub fn save(path: &Path, creds: &CredentialFile) -> Result<(), CredentialError> {
    let json = serde_json::to_string_pretty(creds).map_err(|e| CredentialError::Corrupt {
        path: path.to_path_buf(),
        reason: format!("serialization failed: {e}"),
    })?;

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| CredentialError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    // Use a unique temp file name to prevent race conditions when
    // multiple callers save to the same path concurrently (per-PID
    // AND per-thread via atomic counter).
    let tmp = crate::platform::fs::unique_tmp_path(path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: e,
    })?;

    // Set permissions on the temp file BEFORE rename so the credential
    // file is never world-readable at its final path.
    secure_file(&tmp).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: std::io::Error::other(e.to_string()),
    })?;

    atomic_replace(&tmp, path).map_err(|e| CredentialError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?;

    Ok(())
}

/// Saves credentials to both canonical (`credentials/N.json`) and
/// live (`config-N/.credentials.json`) paths atomically.
///
/// If the canonical write succeeds but the live write fails, a warning
/// is logged but the error is not propagated — the canonical file is
/// the authoritative source.
pub fn save_canonical(
    base_dir: &Path,
    account: AccountNum,
    creds: &CredentialFile,
) -> Result<(), CredentialError> {
    let canonical = canonical_path(base_dir, account);
    save(&canonical, creds)?;

    let live = live_path(base_dir, account);
    if let Err(e) = save(&live, creds) {
        warn!(
            account = %account,
            error = %e,
            "failed to mirror credentials to live config dir (canonical save succeeded)"
        );
    }

    Ok(())
}

/// Returns the canonical credential file path: `{base_dir}/credentials/{N}.json`
pub fn canonical_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join("credentials")
        .join(format!("{}.json", account))
}

/// Returns the live credential file path: `{base_dir}/config-{N}/.credentials.json`
pub fn live_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join(format!("config-{}", account))
        .join(".credentials.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn sample_creds() -> CredentialFile {
        CredentialFile {
            claude_ai_oauth: crate::credentials::OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-test".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-test".into()),
                expires_at: 1775726524877,
                scopes: vec!["user:inference".into()],
                subscription_type: Some("max".into()),
                rate_limit_tier: Some("default_claude_max_20x".into()),
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        }
    }

    #[test]
    fn round_trip_load_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");

        let original = sample_creds();
        save(&path, &original).unwrap();

        let loaded = load(&path).unwrap();
        assert_eq!(
            loaded.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-test"
        );
        assert_eq!(loaded.claude_ai_oauth.expires_at, 1775726524877);
    }

    #[test]
    fn load_missing_file_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");

        match load(&path) {
            Err(CredentialError::NotFound { .. }) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn load_corrupt_file_returns_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();

        match load(&path) {
            Err(CredentialError::Corrupt { .. }) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn load_empty_file_returns_corrupt() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();

        match load(&path) {
            Err(CredentialError::Corrupt { reason, .. }) => {
                assert!(reason.contains("empty"), "reason: {reason}");
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_has_600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");

        save(&path, &sample_creds()).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn save_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nested").join("deep").join("creds.json");

        save(&path, &sample_creds()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn canonical_save_writes_both_files() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(3u16).unwrap();

        save_canonical(dir.path(), account, &sample_creds()).unwrap();

        assert!(canonical_path(dir.path(), account).exists());
        assert!(live_path(dir.path(), account).exists());
    }

    #[test]
    fn canonical_and_live_paths_correct() {
        let base = Path::new("/home/user/.claude/accounts");
        let account = AccountNum::try_from(7u16).unwrap();

        assert_eq!(
            canonical_path(base, account),
            PathBuf::from("/home/user/.claude/accounts/credentials/7.json")
        );
        assert_eq!(
            live_path(base, account),
            PathBuf::from("/home/user/.claude/accounts/config-7/.credentials.json")
        );
    }

    #[test]
    fn flatten_preserves_unknown_fields() {
        let json = r#"{
            "claudeAiOauth": {
                "accessToken": "sk-ant-oat01-t",
                "refreshToken": "sk-ant-ort01-t",
                "expiresAt": 1000,
                "scopes": [],
                "futureField": 42
            },
            "futureTopLevel": "hello"
        }"#;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rt.json");

        let creds: CredentialFile = serde_json::from_str(json).unwrap();
        save(&path, &creds).unwrap();

        let loaded = load(&path).unwrap();
        let reserialized = serde_json::to_value(&loaded).unwrap();

        assert_eq!(reserialized["futureTopLevel"], "hello");
        assert_eq!(reserialized["claudeAiOauth"]["futureField"], 42);
    }
}
