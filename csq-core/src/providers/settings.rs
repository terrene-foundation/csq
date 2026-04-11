//! Provider settings — load/save `settings-<provider>.json` files.

use super::catalog::{get_provider, Provider};
use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use crate::session::merge::{repair_truncated_json, set_model};
use crate::types::ApiKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use tracing::warn;

/// Wrapper around a settings JSON Value with provider metadata.
///
/// **SAFETY**: `settings` contains raw API keys inside
/// `env.ANTHROPIC_AUTH_TOKEN`. This struct MUST NOT be returned
/// over IPC or serialized to logs. Use [`get_api_key`] (which
/// returns [`ApiKey`]) for any access that crosses a trust boundary.
/// The `Serialize` derive exists solely for [`save_settings`] (disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSettings {
    pub provider_id: String,
    pub settings: Value,
}

impl ProviderSettings {
    /// Returns the API key stored in this settings file, wrapped in
    /// [`ApiKey`] for zeroize-on-drop and masked Display/Debug.
    pub fn get_api_key(&self) -> Option<ApiKey> {
        let provider = get_provider(&self.provider_id)?;
        let env_var = provider.key_env_var?;
        self.settings
            .get("env")
            .and_then(|env| env.get(env_var))
            .and_then(|v| v.as_str())
            .map(|s| ApiKey::new(s.to_string()))
    }

    /// Returns the model configured in this settings file.
    pub fn get_model(&self) -> Option<&str> {
        self.settings
            .get("env")
            .and_then(|env| env.get("ANTHROPIC_MODEL"))
            .and_then(|v| v.as_str())
    }

    /// Sets the API key in this settings file.
    pub fn set_api_key(&mut self, key: &str) -> Result<(), ConfigError> {
        let provider =
            get_provider(&self.provider_id).ok_or_else(|| ConfigError::ProfileNotFound {
                name: self.provider_id.clone(),
            })?;

        let env_var = provider
            .key_env_var
            .ok_or_else(|| ConfigError::MergeConflict {
                key: "keyless provider has no env var".into(),
            })?;

        let obj = self
            .settings
            .as_object_mut()
            .ok_or_else(|| ConfigError::MergeConflict {
                key: "settings is not an object".into(),
            })?;

        let env_obj = obj
            .entry("env".to_string())
            .or_insert_with(|| Value::Object(Map::new()));

        if let Some(env) = env_obj.as_object_mut() {
            env.insert(env_var.to_string(), Value::String(key.to_string()));
        }

        Ok(())
    }

    /// Sets the active model, updating all MODEL_KEYS.
    pub fn set_model(&mut self, model_id: &str) {
        self.settings = set_model(&self.settings, model_id);
    }

    /// Returns a masked fingerprint of the API key: "prefix6...suffix4".
    /// Delegates to [`ApiKey::fingerprint`] so the raw value is never
    /// handled as a plain string.
    pub fn key_fingerprint(&self) -> String {
        match self.get_api_key() {
            None => "(none)".into(),
            Some(k) => k.fingerprint(),
        }
    }
}

/// Returns the default settings object for a provider.
pub fn default_settings(provider: &Provider) -> Value {
    let mut env = Map::new();

    if let Some(base) = provider.default_base_url {
        if let Some(env_var) = provider.base_url_env_var {
            env.insert(env_var.to_string(), Value::String(base.to_string()));
        }
    }

    // Model defaults
    for key in crate::session::merge::MODEL_KEYS {
        env.insert(
            key.to_string(),
            Value::String(provider.default_model.to_string()),
        );
    }

    let mut settings = Map::new();
    settings.insert("env".to_string(), Value::Object(env));

    // Non-Claude: add system primer
    if let Some(primer) = provider.system_primer {
        settings.insert(
            "apiKeyHelper".to_string(),
            Value::String(primer.to_string()),
        );
    }

    Value::Object(settings)
}

/// Loads provider settings from disk.
///
/// Returns the default settings if the file doesn't exist. Attempts
/// JSON auto-repair if the file is truncated.
pub fn load_settings(base_dir: &Path, provider_id: &str) -> Result<ProviderSettings, ConfigError> {
    let provider = get_provider(provider_id).ok_or_else(|| ConfigError::ProfileNotFound {
        name: provider_id.to_string(),
    })?;

    let path = base_dir.join(provider.settings_filename);

    let settings: Value = match std::fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => {
            match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(_) => {
                    // Try repair
                    warn!(path = %path.display(), "settings file corrupt, attempting repair");
                    if let Some(repaired) = repair_truncated_json(&content) {
                        serde_json::from_str(&repaired).map_err(|e| ConfigError::InvalidJson {
                            path: path.clone(),
                            reason: format!("repair failed: {e}"),
                        })?
                    } else {
                        return Err(ConfigError::InvalidJson {
                            path,
                            reason: "unrepairable JSON".into(),
                        });
                    }
                }
            }
        }
        _ => default_settings(provider),
    };

    Ok(ProviderSettings {
        provider_id: provider_id.to_string(),
        settings,
    })
}

/// Saves provider settings to disk with atomic write and 0o600 permissions.
pub fn save_settings(base_dir: &Path, settings: &ProviderSettings) -> Result<(), ConfigError> {
    let provider =
        get_provider(&settings.provider_id).ok_or_else(|| ConfigError::ProfileNotFound {
            name: settings.provider_id.clone(),
        })?;

    let path = base_dir.join(provider.settings_filename);

    let json =
        serde_json::to_string_pretty(&settings.settings).map_err(|e| ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("serialize: {e}"),
        })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = crate::platform::fs::unique_tmp_path(&path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("write: {e}"),
    })?;

    secure_file(&tmp).ok();
    atomic_replace(&tmp, &path).map_err(|e| ConfigError::InvalidJson {
        path: path.clone(),
        reason: format!("atomic replace: {e}"),
    })?;

    Ok(())
}

/// Returns the path to a provider settings file.
pub fn settings_path(base_dir: &Path, provider_id: &str) -> Option<PathBuf> {
    get_provider(provider_id).map(|p| base_dir.join(p.settings_filename))
}

/// Lists all provider settings files that currently exist.
pub fn list_configured(base_dir: &Path) -> Vec<ProviderSettings> {
    super::PROVIDERS
        .iter()
        .filter_map(|p| {
            let path = base_dir.join(p.settings_filename);
            if path.exists() {
                load_settings(base_dir, p.id).ok()
            } else {
                None
            }
        })
        .collect()
}

/// Removes a provider settings file.
pub fn remove_settings(base_dir: &Path, provider_id: &str) -> Result<bool, ConfigError> {
    let path =
        settings_path(base_dir, provider_id).ok_or_else(|| ConfigError::ProfileNotFound {
            name: provider_id.to_string(),
        })?;

    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| ConfigError::InvalidJson {
            path,
            reason: format!("remove: {e}"),
        })?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn default_settings_for_claude() {
        let p = get_provider("claude").unwrap();
        let s = default_settings(p);
        assert!(s.get("env").is_some());
        let env = s.get("env").unwrap();
        assert!(env.get("ANTHROPIC_BASE_URL").is_some());
    }

    #[test]
    fn default_settings_includes_model_keys() {
        let p = get_provider("mm").unwrap();
        let s = default_settings(p);
        let env = s.get("env").unwrap();
        for key in crate::session::merge::MODEL_KEYS {
            assert_eq!(env.get(*key).unwrap().as_str().unwrap(), "MiniMax-M2");
        }
    }

    #[test]
    fn load_missing_returns_defaults() {
        let dir = TempDir::new().unwrap();
        let s = load_settings(dir.path(), "claude").unwrap();
        assert_eq!(s.provider_id, "claude");
        assert!(s.settings.get("env").is_some());
    }

    #[test]
    fn round_trip_save_load() {
        let dir = TempDir::new().unwrap();
        let mut s = load_settings(dir.path(), "mm").unwrap();
        s.set_api_key("test-key-123").unwrap();
        save_settings(dir.path(), &s).unwrap();

        let loaded = load_settings(dir.path(), "mm").unwrap();
        assert_eq!(
            loaded.get_api_key().unwrap().expose_secret(),
            "test-key-123"
        );
    }

    #[test]
    fn load_repairs_truncated_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings-mm.json");
        std::fs::write(&path, r#"{"env": {"ANTHROPIC_AUTH_TOKEN": "key""#).unwrap();

        let loaded = load_settings(dir.path(), "mm").unwrap();
        assert_eq!(loaded.get_api_key().unwrap().expose_secret(), "key");
    }

    #[test]
    fn set_model_updates_all_keys() {
        let dir = TempDir::new().unwrap();
        let mut s = load_settings(dir.path(), "claude").unwrap();
        s.set_model("claude-sonnet-4-6");

        assert_eq!(s.get_model(), Some("claude-sonnet-4-6"));

        let env = s.settings.get("env").unwrap();
        for key in crate::session::merge::MODEL_KEYS {
            assert_eq!(
                env.get(*key).unwrap().as_str().unwrap(),
                "claude-sonnet-4-6"
            );
        }
    }

    #[test]
    fn fingerprint_masks_key() {
        let dir = TempDir::new().unwrap();
        let mut s = load_settings(dir.path(), "mm").unwrap();
        // 24-char key: abcdef012345678901234xyz
        //   first 6 = "abcdef"
        //   last  4 = "4xyz"
        s.set_api_key("abcdef012345678901234xyz").unwrap();

        let fp = s.key_fingerprint();
        assert_eq!(fp, "abcdef...4xyz");
        // Middle is not leaked
        assert!(!fp.contains("012345678"));
    }

    #[test]
    fn fingerprint_short_key_hidden() {
        let dir = TempDir::new().unwrap();
        let mut s = load_settings(dir.path(), "mm").unwrap();
        // 19-char key (under 20 threshold)
        s.set_api_key("abcdef01234567890xy").unwrap();
        assert_eq!(s.key_fingerprint(), "(short)");
    }

    #[test]
    fn list_configured_empty() {
        let dir = TempDir::new().unwrap();
        assert!(list_configured(dir.path()).is_empty());
    }

    #[test]
    fn list_configured_after_save() {
        let dir = TempDir::new().unwrap();
        let mut s = load_settings(dir.path(), "mm").unwrap();
        s.set_api_key("key").unwrap();
        save_settings(dir.path(), &s).unwrap();

        let configured = list_configured(dir.path());
        assert_eq!(configured.len(), 1);
        assert_eq!(configured[0].provider_id, "mm");
    }

    #[test]
    fn remove_settings_deletes_file() {
        let dir = TempDir::new().unwrap();
        let mut s = load_settings(dir.path(), "zai").unwrap();
        s.set_api_key("k").unwrap();
        save_settings(dir.path(), &s).unwrap();

        let removed = remove_settings(dir.path(), "zai").unwrap();
        assert!(removed);
        assert!(!dir.path().join("settings-zai.json").exists());
    }

    #[test]
    fn remove_missing_returns_false() {
        let dir = TempDir::new().unwrap();
        let removed = remove_settings(dir.path(), "zai").unwrap();
        assert!(!removed);
    }
}
