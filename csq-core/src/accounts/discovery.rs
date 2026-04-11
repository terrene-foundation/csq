//! Account discovery — finds all configured accounts from multiple sources.
//!
//! Sources: Anthropic credentials, third-party settings, manual accounts.

use super::profiles;
use super::{AccountInfo, AccountSource};
use crate::credentials;
use std::collections::HashMap;
use std::path::Path;
use tracing::warn;

/// Discovers all configured accounts from all sources, deduplicating by ID.
///
/// Sources are checked in priority order: Anthropic → 3P → Manual.
/// First source wins on duplicate IDs.
pub fn discover_all(base_dir: &Path) -> Vec<AccountInfo> {
    let mut seen: HashMap<u16, ()> = HashMap::new();
    let mut accounts = Vec::new();

    // Priority 1: Anthropic OAuth accounts
    for info in discover_anthropic(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 2: Third-party provider accounts
    for info in discover_third_party(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 3: Manual accounts
    for info in discover_manual(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    accounts
}

/// Discovers Anthropic OAuth accounts from `credentials/*.json`.
/// Cross-references with `profiles.json` for email labels.
pub fn discover_anthropic(base_dir: &Path) -> Vec<AccountInfo> {
    let creds_dir = base_dir.join("credentials");
    let entries = match std::fs::read_dir(&creds_dir) {
        Ok(entries) => entries,
        Err(_) => return vec![],
    };

    let profiles_path = profiles::profiles_path(base_dir);
    let profiles =
        profiles::load(&profiles_path).unwrap_or_else(|_| profiles::ProfilesFile::empty());

    let mut accounts = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };

        let id: u16 = match stem.parse() {
            Ok(n) if n >= 1 => n,
            _ => continue,
        };

        let has_credentials = match credentials::load(&path) {
            Ok(_) => true,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "skipping invalid credential file");
                false
            }
        };

        let email = profiles.get_email(id).unwrap_or("unknown").to_string();

        accounts.push(AccountInfo {
            id,
            label: email,
            source: AccountSource::Anthropic,
            method: "oauth".into(),
            has_credentials,
        });
    }

    accounts.sort_by_key(|a| a.id);
    accounts
}

/// Discovers third-party provider accounts from settings files.
/// Checks `settings-zai.json` and `settings-mm.json`.
pub fn discover_third_party(base_dir: &Path) -> Vec<AccountInfo> {
    let mut accounts = Vec::new();

    let providers = [
        ("settings-zai.json", "Z.AI", 901u16),
        ("settings-mm.json", "MiniMax", 902u16),
    ];

    for (file, provider, synthetic_id) in &providers {
        let path = base_dir.join(file);
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                // Check for ANTHROPIC_AUTH_TOKEN at the top level OR
                // inside the `env` subobject (which is where
                // ProviderSettings::get_api_key reads from).
                let has_top_level = json.get("ANTHROPIC_AUTH_TOKEN").is_some()
                    || json.get("ANTHROPIC_BASE_URL").is_some();
                let has_env_key = json
                    .get("env")
                    .and_then(|env| {
                        env.get("ANTHROPIC_AUTH_TOKEN")
                            .or_else(|| env.get("ANTHROPIC_BASE_URL"))
                    })
                    .is_some();
                if has_top_level || has_env_key {
                    accounts.push(AccountInfo {
                        id: *synthetic_id,
                        label: provider.to_string(),
                        source: AccountSource::ThirdParty {
                            provider: provider.to_string(),
                        },
                        method: "api_key".into(),
                        has_credentials: true,
                    });
                }
            }
        }
    }

    accounts
}

/// Discovers manually configured accounts from `dashboard-accounts.json`.
pub fn discover_manual(base_dir: &Path) -> Vec<AccountInfo> {
    let path = base_dir.join("dashboard-accounts.json");
    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str::<Vec<AccountInfo>>(&content).unwrap_or_default(),
        Err(_) => vec![],
    }
}

/// Saves a manual account to `dashboard-accounts.json`.
pub fn save_manual_account(
    base_dir: &Path,
    info: AccountInfo,
) -> Result<(), crate::error::ConfigError> {
    let path = base_dir.join("dashboard-accounts.json");
    let mut accounts = discover_manual(base_dir);

    // Replace existing entry with same ID, or append
    if let Some(pos) = accounts.iter().position(|a| a.id == info.id) {
        accounts[pos] = info;
    } else {
        accounts.push(info);
    }

    let json = serde_json::to_string_pretty(&accounts).map_err(|e| {
        crate::error::ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("serialization: {e}"),
        }
    })?;

    let tmp = crate::platform::fs::unique_tmp_path(&path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| crate::error::ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("write: {e}"),
    })?;

    crate::platform::fs::secure_file(&tmp).ok();
    crate::platform::fs::atomic_replace(&tmp, &path).map_err(|e| {
        crate::error::ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("atomic replace: {e}"),
        }
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{self, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use tempfile::TempDir;

    fn write_cred(dir: &Path, account: u16) {
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
        let path = dir.join("credentials").join(format!("{account}.json"));
        credentials::save(&path, &creds).unwrap();
    }

    #[test]
    fn discover_anthropic_finds_credential_files() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);
        write_cred(dir.path(), 3);
        write_cred(dir.path(), 7);

        let accounts = discover_anthropic(dir.path());
        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].id, 1);
        assert_eq!(accounts[1].id, 3);
        assert_eq!(accounts[2].id, 7);
        assert!(accounts
            .iter()
            .all(|a| a.source == AccountSource::Anthropic));
    }

    #[test]
    fn discover_anthropic_with_profiles() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);

        let mut profiles = profiles::ProfilesFile::empty();
        profiles.set_profile(
            1,
            profiles::AccountProfile {
                email: "user@test.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        profiles::save(&profiles::profiles_path(dir.path()), &profiles).unwrap();

        let accounts = discover_anthropic(dir.path());
        assert_eq!(accounts[0].label, "user@test.com");
    }

    #[test]
    fn discover_anthropic_missing_profile_shows_unknown() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);

        let accounts = discover_anthropic(dir.path());
        assert_eq!(accounts[0].label, "unknown");
    }

    #[test]
    fn discover_anthropic_no_credentials_dir() {
        let dir = TempDir::new().unwrap();
        let accounts = discover_anthropic(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn discover_anthropic_skips_invalid_json() {
        let dir = TempDir::new().unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("1.json"), "not json").unwrap();

        let accounts = discover_anthropic(dir.path());
        assert_eq!(accounts.len(), 1);
        assert!(!accounts[0].has_credentials);
    }

    #[test]
    fn discover_third_party_zai() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("settings-zai.json"),
            r#"{"ANTHROPIC_AUTH_TOKEN": "key", "ANTHROPIC_BASE_URL": "https://api.zai.com"}"#,
        )
        .unwrap();

        let accounts = discover_third_party(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].label, "Z.AI");
        assert_eq!(
            accounts[0].source,
            AccountSource::ThirdParty {
                provider: "Z.AI".into()
            }
        );
    }

    #[test]
    fn discover_third_party_env_nested_key() {
        // Regression test: settings files with keys ONLY in the `env`
        // subobject (the canonical location per ProviderSettings)
        // must still be discovered.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("settings-mm.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"key","ANTHROPIC_BASE_URL":"https://api.mm.com"}}"#,
        )
        .unwrap();

        let accounts = discover_third_party(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].label, "MiniMax");
        assert_eq!(accounts[0].id, 902);
    }

    #[test]
    fn discover_third_party_no_settings() {
        let dir = TempDir::new().unwrap();
        let accounts = discover_third_party(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn discover_manual_round_trip() {
        let dir = TempDir::new().unwrap();
        let info = AccountInfo {
            id: 100,
            label: "Manual Account".into(),
            source: AccountSource::Manual,
            method: "api_key".into(),
            has_credentials: true,
        };

        save_manual_account(dir.path(), info.clone()).unwrap();
        let accounts = discover_manual(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, 100);
        assert_eq!(accounts[0].label, "Manual Account");
    }

    #[test]
    fn discover_all_deduplicates() {
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);

        // Also create a manual account with ID 1 — should be deduped
        let manual = AccountInfo {
            id: 1,
            label: "Manual Duplicate".into(),
            source: AccountSource::Manual,
            method: "manual".into(),
            has_credentials: false,
        };
        save_manual_account(dir.path(), manual).unwrap();

        let accounts = discover_all(dir.path());
        // Only 1 entry for ID 1 (Anthropic wins)
        let count_id_1 = accounts.iter().filter(|a| a.id == 1).count();
        assert_eq!(count_id_1, 1);
        assert_eq!(
            accounts.iter().find(|a| a.id == 1).unwrap().source,
            AccountSource::Anthropic
        );
    }

    #[test]
    fn discover_all_empty_sources() {
        let dir = TempDir::new().unwrap();
        let accounts = discover_all(dir.path());
        assert!(accounts.is_empty());
    }
}
