//! profiles.json management — maps account numbers to email/method pairs.

use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Top-level profiles file. Maps account numbers (as strings) to profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilesFile {
    pub accounts: HashMap<String, AccountProfile>,

    /// Forward-compat: preserve unknown top-level keys.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Profile entry for a single account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProfile {
    /// Email address (or "apikey" for 3P accounts).
    pub email: String,
    /// Authentication method. Known values: "oauth", "api_key".
    pub method: String,

    /// Forward-compat: preserve unknown fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl ProfilesFile {
    /// Returns an empty profiles file.
    pub fn empty() -> Self {
        Self {
            accounts: HashMap::new(),
            extra: HashMap::new(),
        }
    }

    /// Gets the email for a given account number, or None if not found.
    pub fn get_email(&self, account: u16) -> Option<&str> {
        self.accounts
            .get(&account.to_string())
            .map(|p| p.email.as_str())
    }

    /// Gets the profile for a given account number.
    pub fn get_profile(&self, account: u16) -> Option<&AccountProfile> {
        self.accounts.get(&account.to_string())
    }

    /// Sets or updates the profile for an account number.
    pub fn set_profile(&mut self, account: u16, profile: AccountProfile) {
        self.accounts.insert(account.to_string(), profile);
    }
}

/// Loads profiles.json from disk. Returns an empty ProfilesFile if
/// the file doesn't exist (not an error — profiles are optional).
pub fn load(path: &Path) -> Result<ProfilesFile, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            if content.trim().is_empty() {
                return Ok(ProfilesFile::empty());
            }
            serde_json::from_str(&content).map_err(|e| ConfigError::InvalidJson {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProfilesFile::empty()),
        Err(e) => Err(ConfigError::InvalidJson {
            path: path.to_path_buf(),
            reason: e.to_string(),
        }),
    }
}

/// Saves profiles.json to disk with atomic write.
pub fn save(path: &Path, profiles: &ProfilesFile) -> Result<(), ConfigError> {
    let json = serde_json::to_string_pretty(profiles).map_err(|e| ConfigError::InvalidJson {
        path: path.to_path_buf(),
        reason: format!("serialization: {e}"),
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("write: {e}"),
    })?;

    secure_file(&tmp).ok();

    atomic_replace(&tmp, path).map_err(|e| ConfigError::InvalidJson {
        path: path.to_path_buf(),
        reason: format!("atomic replace: {e}"),
    })?;

    Ok(())
}

/// Returns the path to profiles.json within a base directory.
pub fn profiles_path(base_dir: &Path) -> std::path::PathBuf {
    base_dir.join("profiles.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn round_trip_profiles() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("profiles.json");

        let mut profiles = ProfilesFile::empty();
        profiles.set_profile(
            1,
            AccountProfile {
                email: "user@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        profiles.set_profile(
            8,
            AccountProfile {
                email: "other@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        save(&path, &profiles).unwrap();
        let loaded = load(&path).unwrap();

        assert_eq!(loaded.get_email(1), Some("user@example.com"));
        assert_eq!(loaded.get_email(8), Some("other@example.com"));
        assert_eq!(loaded.get_email(99), None);
    }

    #[test]
    fn load_missing_returns_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.json");

        let profiles = load(&path).unwrap();
        assert!(profiles.accounts.is_empty());
    }

    #[test]
    fn flatten_preserves_unknown_fields() {
        let json = r#"{
            "accounts": {
                "1": {
                    "email": "test@test.com",
                    "method": "oauth",
                    "futureField": true
                }
            },
            "topLevelExtra": "preserved"
        }"#;

        let profiles: ProfilesFile = serde_json::from_str(json).unwrap();
        let reserialized = serde_json::to_value(&profiles).unwrap();

        assert_eq!(reserialized["topLevelExtra"], "preserved");
        assert_eq!(reserialized["accounts"]["1"]["futureField"], true);
    }

    #[test]
    fn set_profile_preserves_others() {
        let mut profiles = ProfilesFile::empty();
        profiles.set_profile(
            1,
            AccountProfile {
                email: "a@a.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        profiles.set_profile(
            2,
            AccountProfile {
                email: "b@b.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        // Update account 1, account 2 should be preserved
        profiles.set_profile(
            1,
            AccountProfile {
                email: "updated@a.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );

        assert_eq!(profiles.get_email(1), Some("updated@a.com"));
        assert_eq!(profiles.get_email(2), Some("b@b.com"));
    }
}
