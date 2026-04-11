//! Account discovery — finds all configured accounts from multiple sources.
//!
//! Sources: Anthropic credentials, per-slot third-party bindings, global
//! third-party settings, manual accounts.

use super::profiles;
use super::{AccountInfo, AccountSource};
use crate::credentials;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::warn;

/// Discovers all configured accounts from all sources, deduplicating by ID.
///
/// Sources checked in priority order:
/// 1. Anthropic OAuth (`credentials/N.json`)
/// 2. Per-slot third-party bindings (`config-N/settings.json` with a 3P
///    `ANTHROPIC_BASE_URL`) — these take numbered slots (9, 10, …)
///    alongside OAuth accounts so users see one unified list.
/// 3. Global third-party bindings (`settings-mm.json` / `settings-zai.json`
///    at the base dir level, synthetic slots 901/902) — suppressed if the
///    same provider is already bound to a numbered slot above.
/// 4. Manual accounts (`dashboard-accounts.json`)
///
/// First source wins on duplicate slot IDs.
pub fn discover_all(base_dir: &Path) -> Vec<AccountInfo> {
    let mut seen: HashMap<u16, ()> = HashMap::new();
    let mut accounts = Vec::new();

    // Priority 1: Anthropic OAuth accounts
    for info in discover_anthropic(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 2: Per-slot third-party bindings. These occupy real
    // numbered slots (e.g. 9 = MiniMax, 10 = Z.AI) and should appear
    // in the dashboard alongside OAuth accounts 1-8.
    let mut per_slot_providers: HashSet<String> = HashSet::new();
    for info in discover_per_slot_third_party(base_dir) {
        if let AccountSource::ThirdParty { provider } = &info.source {
            per_slot_providers.insert(provider.clone());
        }
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 3: Global third-party bindings at synthetic 9xx slots.
    // Suppress entries whose provider already appears as a per-slot
    // binding — otherwise the user sees both "9 MiniMax" and "902
    // MiniMax" for the same underlying setup.
    for info in discover_third_party(base_dir) {
        if let AccountSource::ThirdParty { provider } = &info.source {
            if per_slot_providers.contains(provider) {
                continue;
            }
        }
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    // Priority 4: Manual accounts
    for info in discover_manual(base_dir) {
        if seen.insert(info.id, ()).is_none() {
            accounts.push(info);
        }
    }

    accounts
}

/// Classifies an `ANTHROPIC_BASE_URL` into a known provider name.
///
/// Returns `None` for `api.anthropic.com` (native Anthropic is handled
/// via OAuth discovery, not 3P) and for any URL that doesn't match a
/// known host. Returns a display name like `"MiniMax"` / `"Z.AI"` /
/// `"Ollama"` otherwise.
///
/// The match is host-substring-based so variant hostnames like
/// `api.minimax.io` (vs. the catalog default `api.minimax.chat`)
/// still classify correctly.
pub(crate) fn provider_from_base_url(base_url: &str) -> Option<&'static str> {
    let lower = base_url.to_ascii_lowercase();
    // Native Anthropic is not a 3P account — skip it.
    if lower.contains("api.anthropic.com") {
        return None;
    }
    if lower.contains("minimax") {
        return Some("MiniMax");
    }
    if lower.contains("z.ai") {
        return Some("Z.AI");
    }
    if lower.contains("localhost") || lower.contains("127.0.0.1") {
        return Some("Ollama");
    }
    None
}

/// Walks `base_dir/config-N/settings.json` files and emits one
/// `AccountInfo` per slot that has a 3P provider binding.
///
/// A "3P binding" means the slot's `settings.json` has
/// `env.ANTHROPIC_BASE_URL` pointing at a host other than
/// `api.anthropic.com`. The provider name is derived from the URL
/// via `provider_from_base_url`. `has_credentials` reflects whether
/// `env.ANTHROPIC_AUTH_TOKEN` is present (required for bearer-auth
/// providers).
///
/// Slot IDs are taken from the `config-<N>` dir name, 1..=999.
/// Symlinks are rejected to prevent traversal outside base_dir.
pub fn discover_per_slot_third_party(base_dir: &Path) -> Vec<AccountInfo> {
    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut accounts = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // Reject symlinks — a config-N symlinked outside base_dir
        // would let IPC-side account listing escape the boundary.
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        let Some(num_str) = name.strip_prefix("config-") else {
            continue;
        };
        let id: u16 = match num_str.parse() {
            Ok(n) if (1..=999).contains(&n) => n,
            _ => continue,
        };

        let settings_path = entry.path().join("settings.json");
        let content = match std::fs::read_to_string(&settings_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    path = %settings_path.display(),
                    error = %e,
                    "skipping per-slot settings.json with invalid JSON"
                );
                continue;
            }
        };

        // Extract env.ANTHROPIC_BASE_URL. `ANTHROPIC_BASE_URL` at the
        // top level is also accepted for forward-compat, but the
        // canonical location is under `env.`.
        let env = json.get("env");
        let base_url = env
            .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
            .or_else(|| json.get("ANTHROPIC_BASE_URL"))
            .and_then(|v| v.as_str());
        let Some(base_url) = base_url else { continue };

        let Some(provider_name) = provider_from_base_url(base_url) else {
            continue;
        };

        let has_token = env
            .and_then(|e| e.get("ANTHROPIC_AUTH_TOKEN"))
            .or_else(|| json.get("ANTHROPIC_AUTH_TOKEN"))
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        accounts.push(AccountInfo {
            id,
            label: provider_name.to_string(),
            source: AccountSource::ThirdParty {
                provider: provider_name.to_string(),
            },
            method: "api_key".into(),
            has_credentials: has_token,
        });
    }

    // Deterministic ordering by slot id for dashboard stability.
    accounts.sort_by_key(|a| a.id);
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

    // ── provider_from_base_url ─────────────────────────────

    #[test]
    fn provider_from_url_detects_minimax_on_any_host() {
        assert_eq!(
            provider_from_base_url("https://api.minimax.chat/anthropic"),
            Some("MiniMax")
        );
        assert_eq!(
            provider_from_base_url("https://api.minimax.io/anthropic"),
            Some("MiniMax")
        );
    }

    #[test]
    fn provider_from_url_detects_zai() {
        assert_eq!(
            provider_from_base_url("https://api.z.ai/api/anthropic"),
            Some("Z.AI")
        );
    }

    #[test]
    fn provider_from_url_detects_ollama() {
        assert_eq!(
            provider_from_base_url("http://localhost:11434"),
            Some("Ollama")
        );
        assert_eq!(
            provider_from_base_url("http://127.0.0.1:11434"),
            Some("Ollama")
        );
    }

    #[test]
    fn provider_from_url_skips_native_anthropic() {
        // Native Anthropic is OAuth — not a 3P binding.
        assert_eq!(provider_from_base_url("https://api.anthropic.com"), None);
    }

    #[test]
    fn provider_from_url_unknown_host_returns_none() {
        assert_eq!(provider_from_base_url("https://example.com/api"), None);
    }

    // ── discover_per_slot_third_party ──────────────────────

    /// Writes a `{base}/config-N/settings.json` with the given base
    /// URL and auth token.
    fn write_slot_settings(base: &Path, slot: u16, base_url: &str, token: &str) {
        let dir = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&dir).unwrap();
        let json = format!(
            r#"{{"env":{{"ANTHROPIC_BASE_URL":"{base_url}","ANTHROPIC_AUTH_TOKEN":"{token}"}}}}"#
        );
        std::fs::write(dir.join("settings.json"), json).unwrap();
    }

    #[test]
    fn per_slot_discovers_minimax_and_zai_as_numbered_slots() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "tok-mm");
        write_slot_settings(dir.path(), 10, "https://api.z.ai/api/anthropic", "tok-zai");

        let accounts = discover_per_slot_third_party(dir.path());
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].id, 9);
        assert_eq!(accounts[0].label, "MiniMax");
        assert!(accounts[0].has_credentials);
        assert_eq!(accounts[1].id, 10);
        assert_eq!(accounts[1].label, "Z.AI");
    }

    #[test]
    fn per_slot_ignores_slots_without_settings_json() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("config-5")).unwrap();
        let accounts = discover_per_slot_third_party(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn per_slot_ignores_slots_bound_to_native_anthropic() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 3, "https://api.anthropic.com", "tok");
        let accounts = discover_per_slot_third_party(dir.path());
        assert!(
            accounts.is_empty(),
            "native Anthropic slot must not appear as a 3P account"
        );
    }

    #[test]
    fn per_slot_ignores_unknown_base_urls() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 7, "https://my.custom.proxy/anthropic", "tok");
        let accounts = discover_per_slot_third_party(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn per_slot_marks_empty_token_as_missing_credentials() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "");
        let accounts = discover_per_slot_third_party(dir.path());
        assert_eq!(accounts.len(), 1);
        assert!(!accounts[0].has_credentials);
    }

    #[test]
    fn per_slot_rejects_out_of_range_slot_numbers() {
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 0, "https://api.minimax.io/anthropic", "tok");
        // Manual dir creation for 1000 since write_slot_settings uses u16.
        std::fs::create_dir_all(dir.path().join("config-1000")).unwrap();
        std::fs::write(
            dir.path().join("config-1000").join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.z.ai/api/anthropic","ANTHROPIC_AUTH_TOKEN":"tok"}}"#,
        )
        .unwrap();

        let accounts = discover_per_slot_third_party(dir.path());
        assert!(
            accounts.is_empty(),
            "out-of-range slot numbers must be rejected"
        );
    }

    #[test]
    fn per_slot_rejects_non_config_dirs() {
        let dir = TempDir::new().unwrap();
        // `other-9/settings.json` with a valid 3P binding.
        let other = dir.path().join("other-9");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(
            other.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.minimax.io","ANTHROPIC_AUTH_TOKEN":"tok"}}"#,
        )
        .unwrap();
        let accounts = discover_per_slot_third_party(dir.path());
        assert!(accounts.is_empty());
    }

    #[test]
    fn per_slot_returns_deterministic_order() {
        let dir = TempDir::new().unwrap();
        // Insert in non-sorted order; expect ascending output.
        write_slot_settings(dir.path(), 10, "https://api.z.ai/api/anthropic", "tok");
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "tok");

        let accounts = discover_per_slot_third_party(dir.path());
        assert_eq!(
            accounts.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![9, 10]
        );
    }

    // ── discover_all with per-slot 3P suppression ──────────

    #[test]
    fn discover_all_per_slot_3p_suppresses_global_duplicate() {
        // User has BOTH a per-slot binding (config-9 → MiniMax) AND
        // a legacy global settings-mm.json. The per-slot entry wins
        // and the global 902 is dropped so the dashboard shows one
        // MiniMax row, not two.
        let dir = TempDir::new().unwrap();
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "tok");
        std::fs::write(
            dir.path().join("settings-mm.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"legacy","ANTHROPIC_BASE_URL":"https://api.mm.com"}}"#,
        )
        .unwrap();

        let accounts = discover_all(dir.path());
        let minimax: Vec<_> = accounts
            .iter()
            .filter(|a| matches!(&a.source, AccountSource::ThirdParty { provider } if provider == "MiniMax"))
            .collect();
        assert_eq!(
            minimax.len(),
            1,
            "global 3P entry must be suppressed when per-slot binding exists"
        );
        assert_eq!(minimax[0].id, 9);
    }

    #[test]
    fn discover_all_global_3p_preserved_when_no_per_slot() {
        // Only the global settings-zai.json — no per-slot binding.
        // Should still emit the synthetic 901 entry for backward compat.
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("settings-zai.json"),
            r#"{"env":{"ANTHROPIC_AUTH_TOKEN":"tok","ANTHROPIC_BASE_URL":"https://api.z.ai"}}"#,
        )
        .unwrap();

        let accounts = discover_all(dir.path());
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, 901);
        assert_eq!(accounts[0].label, "Z.AI");
    }

    #[test]
    fn discover_all_mixed_oauth_and_per_slot_3p() {
        // Canonical happy path: OAuth slots 1-3, per-slot 3P slots 9-10.
        let dir = TempDir::new().unwrap();
        write_cred(dir.path(), 1);
        write_cred(dir.path(), 2);
        write_cred(dir.path(), 3);
        write_slot_settings(dir.path(), 9, "https://api.minimax.io/anthropic", "tok-mm");
        write_slot_settings(dir.path(), 10, "https://api.z.ai/api/anthropic", "tok-zai");

        let accounts = discover_all(dir.path());
        let ids: Vec<u16> = accounts.iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![1, 2, 3, 9, 10]);
        let providers: Vec<_> = accounts
            .iter()
            .map(|a| match &a.source {
                AccountSource::Anthropic => "Anthropic",
                AccountSource::ThirdParty { provider } => provider.as_str(),
                AccountSource::Manual => "Manual",
            })
            .collect();
        assert_eq!(
            providers,
            vec!["Anthropic", "Anthropic", "Anthropic", "MiniMax", "Z.AI"]
        );
    }
}
