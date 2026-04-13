//! Bind a third-party provider (MiniMax, Z.AI, etc.) to a numbered slot.
//!
//! A 3P slot is a `config-<N>/` directory whose `settings.json` contains
//! `env.ANTHROPIC_BASE_URL` pointing at a non-Anthropic host plus
//! `env.ANTHROPIC_AUTH_TOKEN`. CC reads both on startup and routes every
//! request through the provider. There is no `credentials/<N>.json` — 3P
//! slots are intentionally OAuth-free.
//!
//! `bind_provider_to_slot` is the single write path. It:
//!   1. Writes `config-<N>/settings.json` (env block with base URL, token,
//!      and default model keys).
//!   2. Upserts `profiles.json[N]` with `method = "api_key"` and a
//!      `provider` tag for dashboard display.
//!   3. Writes the `.csq-account` marker so handle-dir sweeps and CLI
//!      utilities can identify the slot.

use crate::accounts::markers;
use crate::accounts::profiles::{self, AccountProfile};
use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use crate::providers::{self, settings as provider_settings};
use crate::types::AccountNum;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

/// Binds a provider's API key to a numbered slot.
///
/// After a successful bind, `csq run <slot>` can launch CC against this
/// provider and the dashboard will show the slot labelled with the
/// provider name.
///
/// # Errors
///
/// - Provider id is unknown
/// - Provider has no base URL or key env var (can't be slot-bound)
/// - Key is empty
/// - Any filesystem or JSON error during the write
pub fn bind_provider_to_slot(
    base_dir: &Path,
    provider_id: &str,
    slot: AccountNum,
    key: &str,
) -> Result<(), ConfigError> {
    if key.is_empty() {
        return Err(ConfigError::MergeConflict {
            key: "api key is empty".into(),
        });
    }

    let provider =
        providers::get_provider(provider_id).ok_or_else(|| ConfigError::ProfileNotFound {
            name: provider_id.to_string(),
        })?;

    let base_url = provider
        .default_base_url
        .ok_or_else(|| ConfigError::MergeConflict {
            key: format!("provider {provider_id} has no default base URL"),
        })?;
    let key_env_var = provider
        .key_env_var
        .ok_or_else(|| ConfigError::MergeConflict {
            key: format!("provider {provider_id} is keyless"),
        })?;
    let base_url_env_var = provider
        .base_url_env_var
        .ok_or_else(|| ConfigError::MergeConflict {
            key: format!("provider {provider_id} has no base URL env var"),
        })?;

    let config_dir = base_dir.join(format!("config-{}", slot));
    std::fs::create_dir_all(&config_dir).map_err(|e| ConfigError::InvalidJson {
        path: config_dir.clone(),
        reason: format!("create_dir_all: {e}"),
    })?;

    // 1. Build settings.json from the provider's defaults and inject the key.
    //    `default_settings` already populates base URL and all model keys.
    let mut settings_value = provider_settings::default_settings(provider);
    if let Some(obj) = settings_value.as_object_mut() {
        let env_obj = obj
            .entry("env".to_string())
            .or_insert_with(|| Value::Object(Default::default()));
        if let Some(env) = env_obj.as_object_mut() {
            env.insert(key_env_var.to_string(), Value::String(key.to_string()));
            // Defensive: re-assert base URL even though default_settings set it,
            // so a future provider catalog change that drops the default can't
            // silently write an incomplete settings file.
            env.insert(
                base_url_env_var.to_string(),
                Value::String(base_url.to_string()),
            );
        }
    }

    let settings_path = config_dir.join("settings.json");
    // SECURITY: the JSON value carries the API key. The reason field is a
    // fixed string (not `format!("...: {e}")`) so a future serialize impl
    // that included the value in its error message could not echo the key
    // through `ConfigError::InvalidJson`.
    let json =
        serde_json::to_string_pretty(&settings_value).map_err(|_| ConfigError::InvalidJson {
            path: settings_path.clone(),
            reason: "settings serialize failed".into(),
        })?;

    let tmp = crate::platform::fs::unique_tmp_path(&settings_path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("write: {e}"),
    })?;
    // SECURITY: propagate (not `.ok()`) — a silent permission failure would
    // publish the credential file at the umask default, potentially
    // world-readable. Fail closed.
    secure_file(&tmp).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("secure_file: {e}"),
    })?;
    atomic_replace(&tmp, &settings_path).map_err(|e| ConfigError::InvalidJson {
        path: settings_path.clone(),
        reason: format!("atomic replace: {e}"),
    })?;

    // 2. Upsert profiles.json entry.
    let profiles_path = profiles::profiles_path(base_dir);
    let mut profiles_file =
        profiles::load(&profiles_path).unwrap_or_else(|_| profiles::ProfilesFile::empty());

    let mut extra = HashMap::new();
    extra.insert(
        "provider".to_string(),
        Value::String(provider_id.to_string()),
    );
    profiles_file.set_profile(
        slot.get(),
        AccountProfile {
            email: format!("apikey:{provider_id}"),
            method: "api_key".to_string(),
            extra,
        },
    );
    profiles::save(&profiles_path, &profiles_file)?;

    // 3. Marker.
    markers::write_csq_account(&config_dir, slot).map_err(|e| ConfigError::InvalidJson {
        path: config_dir.join(".csq-account"),
        reason: format!("write marker: {e}"),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::discovery;
    use tempfile::TempDir;

    #[test]
    fn bind_writes_settings_json_with_env() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();

        bind_provider_to_slot(dir.path(), "mm", slot, "sk-test-minimax-12345").unwrap();

        let settings_path = dir.path().join("config-9/settings.json");
        assert!(settings_path.exists());

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();
        let env = json.get("env").unwrap();
        assert_eq!(
            env.get("ANTHROPIC_AUTH_TOKEN").unwrap(),
            "sk-test-minimax-12345"
        );
        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").unwrap(),
            "https://api.minimax.io/anthropic"
        );
        assert!(env.get("ANTHROPIC_MODEL").is_some());
    }

    #[test]
    fn bind_creates_profile_entry() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();

        bind_provider_to_slot(dir.path(), "zai", slot, "key-zai-123").unwrap();

        let profiles_file = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        let p = profiles_file.get_profile(9).unwrap();
        assert_eq!(p.method, "api_key");
        assert_eq!(p.email, "apikey:zai");
        assert_eq!(
            p.extra.get("provider").and_then(|v| v.as_str()),
            Some("zai")
        );
    }

    #[test]
    fn bind_writes_csq_account_marker() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(7u16).unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, "key-7").unwrap();

        let marker = dir.path().join("config-7/.csq-account");
        assert!(marker.exists());
        let contents = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(contents.trim(), "7");
    }

    #[test]
    fn bind_makes_slot_discoverable_as_third_party() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(12u16).unwrap();

        bind_provider_to_slot(dir.path(), "mm", slot, "key-discover").unwrap();

        let slots = discovery::discover_per_slot_third_party(dir.path());
        let found = slots.iter().find(|a| a.id == 12).expect("slot 12 missing");
        assert_eq!(found.label, "MiniMax");
        assert_eq!(found.method, "api_key");
        assert!(found.has_credentials);
    }

    #[test]
    fn bind_rejects_empty_key() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "mm", slot, "");
        assert!(err.is_err());
    }

    #[test]
    fn bind_rejects_unknown_provider() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "bogus", slot, "k");
        assert!(err.is_err());
    }

    #[test]
    fn bind_overwrites_existing_slot_settings() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(4u16).unwrap();

        bind_provider_to_slot(dir.path(), "mm", slot, "first-key").unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, "second-key").unwrap();

        let settings_path = dir.path().join("config-4/settings.json");
        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert_eq!(
            json.get("env")
                .unwrap()
                .get("ANTHROPIC_AUTH_TOKEN")
                .unwrap(),
            "second-key"
        );
    }

    #[test]
    fn bind_preserves_other_profile_entries() {
        let dir = TempDir::new().unwrap();

        // Pre-seed profiles.json with another account.
        let profiles_path = profiles::profiles_path(dir.path());
        let mut pf = profiles::ProfilesFile::empty();
        pf.set_profile(
            1,
            AccountProfile {
                email: "alice@example.com".into(),
                method: "oauth".into(),
                extra: HashMap::new(),
            },
        );
        profiles::save(&profiles_path, &pf).unwrap();

        bind_provider_to_slot(dir.path(), "mm", AccountNum::try_from(9u16).unwrap(), "k").unwrap();

        let loaded = profiles::load(&profiles_path).unwrap();
        assert_eq!(loaded.get_email(1), Some("alice@example.com"));
        assert_eq!(loaded.get_profile(9).unwrap().method, "api_key");
    }
}
