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
/// over IPC or serialized to logs. Use `get_api_key` (which
/// returns [`ApiKey`]) for any access that crosses a trust boundary.
/// The `Serialize` derive exists solely for [`save_settings`] (disk).
///
/// **Custody contract** (`specs/19-direct-api-security-prerequisites.md`
/// §19.3–§19.4): the key is wrapped in [`ApiKey`] (a `SecretString`,
/// zeroize-on-drop, masked `Display`/`Debug`) at the point of read by
/// [`ProviderSettings::get_api_key`]. Direct-API (Phase-2b) clients MUST
/// read the key at request-construction time and MUST NOT hold a resident
/// copy in a struct field or `HashMap`; `expose_secret()` is unwrapped
/// only inside the single HTTP-header construction call.
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

    /// Returns the MiniMax GroupId stored in this settings file.
    ///
    /// Stored in `env.MINIMAX_GROUP_ID` (the user's MiniMax org ID).
    /// Required for the MiniMax quota API endpoint.
    pub fn get_group_id(&self) -> Option<&str> {
        self.settings
            .get("env")
            .and_then(|env| env.get("MINIMAX_GROUP_ID"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Sets the MiniMax GroupId in this settings file.
    pub fn set_group_id(&mut self, group_id: &str) {
        let obj = self.settings.as_object_mut().unwrap();
        let env_obj = obj
            .entry("env".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(env) = env_obj.as_object_mut() {
            env.insert(
                "MINIMAX_GROUP_ID".to_string(),
                Value::String(group_id.to_string()),
            );
        }
    }

    /// Overlays `(env_key, value)` pairs into this settings file's `env` block,
    /// preserving every other key. Used by the Azure OpenAI / Vertex AI native
    /// direct-API bindings (#962), which persist multi-field endpoint config
    /// (`AZURE_OPENAI_RESOURCE`/`_DEPLOYMENT`/`_API_VERSION` + the api-key;
    /// `VERTEX_PROJECT`/`_REGION` + the access token) rather than the single
    /// `ANTHROPIC_AUTH_TOKEN` the 3P passthrough bind writes.
    ///
    /// # Why this is distinct from [`set_api_key`](Self::set_api_key)
    ///
    /// `set_api_key` writes a single value keyed on the catalog `key_env_var`,
    /// which is `None` for azure/vertex (they are native, key read explicitly by
    /// the client). This method takes the env var names EXPLICITLY, so the
    /// native-client config keys — which the catalog does not model as a single
    /// `key_env_var` — can be written in one atomic settings save.
    pub fn set_env_kv(&mut self, pairs: &[(&str, &str)]) {
        if !self.settings.is_object() {
            self.settings = Value::Object(Map::new());
        }
        let obj = self.settings.as_object_mut().expect("ensured object above");
        let env_obj = obj
            .entry("env".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !env_obj.is_object() {
            *env_obj = Value::Object(Map::new());
        }
        if let Some(env) = env_obj.as_object_mut() {
            for (k, v) in pairs {
                env.insert((*k).to_string(), Value::String((*v).to_string()));
            }
        }
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
            Some(k) => k.fingerprint(),
            // Native direct-API providers (azure/vertex, #962) have catalog
            // `key_env_var: None`, so `get_api_key()` can't resolve their
            // credential. Fall back to the known native cred env var so EVERY
            // fingerprint surface (`csq listkeys`, etc.) shows the real masked
            // key — not just the setkey handler that calls `key_fingerprint_for`
            // directly (#962 redteam MED-1: `listkeys` showed `Key: (none)` for a
            // correctly-configured azure/vertex slot).
            None => match native_cred_env_var(&self.provider_id) {
                Some(env_var) => self.key_fingerprint_for(env_var),
                None => "(none)".into(),
            },
        }
    }

    /// Masked fingerprint of the value at an EXPLICIT `env.<env_var>`, for
    /// native direct-API providers (azure/vertex, #962) whose catalog
    /// `key_env_var` is `None` so [`key_fingerprint`](Self::key_fingerprint)
    /// cannot resolve the credential env var. The raw value is wrapped in
    /// [`ApiKey`] before fingerprinting so it is never handled as a plain string.
    pub fn key_fingerprint_for(&self, env_var: &str) -> String {
        match self
            .settings
            .get("env")
            .and_then(|env| env.get(env_var))
            .and_then(|v| v.as_str())
        {
            None => "(none)".into(),
            Some(s) => ApiKey::new(s.to_string()).fingerprint(),
        }
    }
}

/// Maps a native direct-API provider id (#962) to the `env.<var>` holding its
/// credential. These providers have catalog `key_env_var: None` (their
/// credential is multi-field / non-Bearer and read at request time by the
/// phase2b native client), so the generic `key_env_var` fingerprint path can't
/// resolve them. Returns `None` for every other provider.
///
/// String literals — NOT the `phase2b` client constants — because this module
/// ships to the community edition where the `phase2b` tree is moat-stripped; the
/// env-var NAMES are non-secret provider-agnostic data, safe to carry publicly.
fn native_cred_env_var(provider_id: &str) -> Option<&'static str> {
    match provider_id {
        "azure" => Some("AZURE_OPENAI_API_KEY"),
        "vertex" => Some("VERTEX_ACCESS_TOKEN"),
        _ => None,
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

    // Keyless providers (Ollama) need a placeholder ANTHROPIC_AUTH_TOKEN
    // because CC always sends an auth header. The literal value is
    // irrelevant to the provider itself.
    if let Some(token) = provider.default_auth_token {
        env.insert(
            "ANTHROPIC_AUTH_TOKEN".to_string(),
            Value::String(token.to_string()),
        );
    }

    // Model defaults — uniform fan-out to every key in MODEL_KEYS.
    for key in crate::session::merge::MODEL_KEYS {
        env.insert(
            key.to_string(),
            Value::String(provider.default_model.to_string()),
        );
    }

    // Provider-specific overrides + extra env vars (e.g. DeepSeek's
    // asymmetric tier defaults: haiku=flash, plus CC-native subagent
    // model + effort-level keys outside MODEL_KEYS). Applied AFTER the
    // uniform fan-out so the provider's published per-tier
    // recommendations win.
    for (key, value) in provider.extra_env {
        env.insert((*key).to_string(), Value::String((*value).to_string()));
    }

    let mut settings = Map::new();
    settings.insert("env".to_string(), Value::Object(env));

    // NOTE: `Provider::system_primer` is intentionally NOT serialized
    // anywhere. It used to land under `apiKeyHelper`, which CC reads as
    // a shell command that returns an API key — a misuse that triggered
    // the alpha.7→alpha.8 auth-conflict bug when the same Value was
    // written to `config-<N>/settings.json`. The primer field is kept
    // on the catalog struct for possible future use as a system-prompt
    // injection mechanism but has no current consumer.

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

/// Resolves the model id configured for a slot by reading
/// `config-<slot>/settings.json`'s `env.ANTHROPIC_MODEL`.
///
/// This is the SAME code the daemon usage poller uses to read the slot
/// model (`daemon::usage_poller::third_party::load_3p_model_for_slot`
/// delegates here) — the slot's on-disk settings, NOT the process
/// environment. Terminal
/// surfaces (the statusline) MUST use this rather than
/// `std::env::var("ANTHROPIC_MODEL")`: csq strips every `ANTHROPIC_*`
/// var from CC's spawn environment (`strip_sensitive_env`), so the model
/// id is present ONLY in the settings file, and whether CC re-exports it
/// to a spawned statusLine subprocess is a CC-internal behavior csq does
/// not control. Reading the file depends only on the slot number the
/// caller already resolved.
///
/// Returns `None` when the file is absent/unparseable or carries no
/// `ANTHROPIC_MODEL` (OAuth/Anthropic slots) — the caller falls back to
/// CC's own context percentage in that case.
pub fn model_id_for_slot(base_dir: &Path, slot: u16) -> Option<String> {
    let path = base_dir
        .join(format!("config-{slot}"))
        .join("settings.json");
    let content = std::fs::read_to_string(&path).ok()?;
    let json: Value = serde_json::from_str(&content).ok()?;
    json.get("env")
        .and_then(|e| e.get("ANTHROPIC_MODEL"))
        .or_else(|| json.get("ANTHROPIC_MODEL"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

/// Returns `true` when `config-<slot>/settings.json` pins
/// `env.ANTHROPIC_BASE_URL` — i.e. the slot is a 3P / env-transport slot
/// (DeepSeek, Z.AI, MiniMax, Ollama) whose base URL and auth token are
/// injected into Claude Code's **process environment at startup**, not
/// re-read per request.
///
/// This is the single discriminator between the two ClaudeCode auth
/// transports:
/// - **OAuth (Anthropic)**: credentials live in `.credentials.json`, which
///   CC re-stats before every API call — an in-flight symlink repoint (`csq
///   swap`, daemon auto-rotate) switches accounts without a restart.
/// - **Env-transport (3P/Ollama)**: `env.ANTHROPIC_BASE_URL` +
///   `env.ANTHROPIC_AUTH_TOKEN` are baked into the CC process env at launch
///   and FROZEN for the process lifetime. An in-flight repoint cannot change
///   them; switching to/from such a slot REQUIRES an exec-replace so a fresh
///   CC reads the new settings.json env.
///
/// Callers use this to refuse an in-flight repoint that would either (a)
/// silently keep hitting the old endpoint (functional break) or (b) send an
/// Anthropic OAuth token to a frozen 3P endpoint (token exfiltration — see
/// `daemon::auto_rotate` VP-F1 and `cli::commands::swap`).
///
/// Returns `false` on any I/O or parse error (fail-safe: a missing or
/// unparseable settings.json means no detectable 3P binding). The check reads
/// only the slot's on-disk settings, never the process environment.
pub fn slot_pins_anthropic_base_url(base_dir: &Path, slot: u16) -> bool {
    let path = base_dir
        .join(format!("config-{slot}"))
        .join("settings.json");
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };
    json.get("env")
        .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
        .or_else(|| json.get("ANTHROPIC_BASE_URL"))
        .is_some()
}

/// Saves provider settings to disk with atomic write and 0o600 permissions.
pub fn save_settings(base_dir: &Path, settings: &ProviderSettings) -> Result<(), ConfigError> {
    let provider =
        get_provider(&settings.provider_id).ok_or_else(|| ConfigError::ProfileNotFound {
            name: settings.provider_id.clone(),
        })?;

    // M5: residency gate (enterprise-only) — the GLOBAL provider-settings write
    // path's enforcement point. Refuse to persist a provider the operating
    // envelope's `data_access.model_residency` policy forbids; no policy declared
    // → no-op. `save_settings` (not `default_settings`) is the choke point ALL
    // global callers funnel through (CLI `setkey`, desktop `set_provider_key`),
    // including rebinds of an existing settings file. The per-slot path is gated
    // in `accounts::third_party::bind_provider_to_slot`. The community build
    // compiles this out (the symbol lives in the moat-stripped `phase2b` tree).
    #[cfg(feature = "enterprise")]
    crate::phase2b::residency::enforce_provider_write(base_dir, &settings.provider_id)?;

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
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        // `std::fs::write` may partially write before returning Err,
        // leaving a tmp file containing the token at umask-default
        // permissions. Clean up before propagating.
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: format!("write: {e}"),
        });
    }

    // SECURITY: propagate (not `.ok()`). This file holds 3P API
    // tokens (ANTHROPIC_AUTH_TOKEN for MiniMax / Z.AI) under the
    // env block — a silent chmod failure on an exotic filesystem
    // (network mount, restrictive-ACL tmpfs) would publish the
    // credential file at the umask default. Fail closed. Journal
    // 0063 P1-4, red-team B2. On failure the tmp file must be
    // removed — `std::fs::write` above created it at umask-default
    // permissions, so leaving it behind would defeat the fail-
    // closed intent. Uses a fixed reason string so a future
    // secure_file implementation that included the path or file
    // contents in its error message could not echo the key.
    if secure_file(&tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: "secure_file: chmod failed".into(),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("atomic replace: {e}"),
        });
    }

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

    /// #962: `set_env_kv` overlays the azure config env keys and preserves
    /// pre-existing unrelated keys; `key_fingerprint_for` reads the explicit
    /// credential env var (catalog `key_env_var` is `None` for azure).
    #[test]
    fn set_env_kv_overlays_azure_config_and_preserves_other_keys() {
        let mut settings = ProviderSettings {
            provider_id: "azure".to_string(),
            settings: serde_json::json!({ "env": { "NODE_ENV": "prod" }, "other": 1 }),
        };
        settings.set_env_kv(&[
            ("AZURE_OPENAI_API_KEY", "azure-key-xyz123"),
            ("AZURE_OPENAI_RESOURCE", "my-resource"),
            ("AZURE_OPENAI_DEPLOYMENT", "gpt-5-5"),
        ]);
        let env = &settings.settings["env"];
        assert_eq!(env["AZURE_OPENAI_API_KEY"], "azure-key-xyz123");
        assert_eq!(env["AZURE_OPENAI_RESOURCE"], "my-resource");
        assert_eq!(env["AZURE_OPENAI_DEPLOYMENT"], "gpt-5-5");
        // Unrelated keys preserved.
        assert_eq!(env["NODE_ENV"], "prod");
        assert_eq!(settings.settings["other"], 1);
        // Explicit-env fingerprint masks the key (not "(none)", not the raw value).
        let fp = settings.key_fingerprint_for("AZURE_OPENAI_API_KEY");
        assert_ne!(fp, "(none)");
        assert!(
            !fp.contains("azure-key-xyz123"),
            "raw key must not leak: {fp}"
        );
        // A missing env var yields "(none)".
        assert_eq!(
            settings.key_fingerprint_for("VERTEX_ACCESS_TOKEN"),
            "(none)"
        );
    }

    /// #962: `set_env_kv` initializes `env` when the settings object has none.
    #[test]
    fn set_env_kv_creates_env_when_absent() {
        let mut settings = ProviderSettings {
            provider_id: "vertex".to_string(),
            settings: serde_json::json!({}),
        };
        settings.set_env_kv(&[
            ("VERTEX_ACCESS_TOKEN", "ya29.token"),
            ("VERTEX_PROJECT", "proj"),
            ("VERTEX_REGION", "us-central1"),
        ]);
        assert_eq!(settings.settings["env"]["VERTEX_PROJECT"], "proj");
        assert_eq!(settings.settings["env"]["VERTEX_REGION"], "us-central1");
    }

    /// #962: an azure global settings round-trip (set_env_kv → save → load)
    /// preserves the config, and the native-client read path
    /// (`read_native_env_string` shape) resolves it. Also exercises that the
    /// `settings-azure.json` filename is the write target.
    #[test]
    fn azure_settings_round_trip_through_save_load() {
        let dir = TempDir::new().unwrap();
        let mut settings = load_settings(dir.path(), "azure").unwrap();
        settings.set_env_kv(&[
            ("AZURE_OPENAI_API_KEY", "azure-key-roundtrip"),
            ("AZURE_OPENAI_RESOURCE", "res-rt"),
        ]);
        save_settings(dir.path(), &settings).unwrap();
        assert!(
            dir.path().join("settings-azure.json").exists(),
            "azure config must write to settings-azure.json"
        );
        let reloaded = load_settings(dir.path(), "azure").unwrap();
        assert_eq!(reloaded.settings["env"]["AZURE_OPENAI_RESOURCE"], "res-rt");
        assert_eq!(
            reloaded.settings["env"]["AZURE_OPENAI_API_KEY"],
            "azure-key-roundtrip"
        );
    }

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
            assert_eq!(env.get(*key).unwrap().as_str().unwrap(), p.default_model);
        }
    }

    #[test]
    fn model_id_for_slot_reads_env_anthropic_model() {
        // #984: the statusline resolves the true context window from this
        // on-disk source, NOT the process env.
        let dir = TempDir::new().unwrap();
        let cfg = dir.path().join("config-11");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic","ANTHROPIC_MODEL":"deepseek-v4-pro"}}"#,
        )
        .unwrap();
        assert_eq!(
            model_id_for_slot(dir.path(), 11).as_deref(),
            Some("deepseek-v4-pro")
        );
    }

    #[test]
    fn model_id_for_slot_none_when_absent_or_empty() {
        let dir = TempDir::new().unwrap();
        // Missing config dir entirely.
        assert_eq!(model_id_for_slot(dir.path(), 3), None);
        // Present but no ANTHROPIC_MODEL (OAuth/Anthropic slot).
        let cfg = dir.path().join("config-4");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(cfg.join("settings.json"), r#"{"env":{}}"#).unwrap();
        assert_eq!(model_id_for_slot(dir.path(), 4), None);
        // Empty-string model is filtered to None.
        let cfg5 = dir.path().join("config-5");
        std::fs::create_dir_all(&cfg5).unwrap();
        std::fs::write(
            cfg5.join("settings.json"),
            r#"{"env":{"ANTHROPIC_MODEL":""}}"#,
        )
        .unwrap();
        assert_eq!(model_id_for_slot(dir.path(), 5), None);
    }

    #[test]
    fn slot_pins_anthropic_base_url_detects_env_transport() {
        let dir = TempDir::new().unwrap();
        // 3P slot: env.ANTHROPIC_BASE_URL present → env-transport (needs exec-replace).
        let cfg = dir.path().join("config-7");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.z.ai/api/anthropic","ANTHROPIC_AUTH_TOKEN":"sk-x"}}"#,
        )
        .unwrap();
        assert!(slot_pins_anthropic_base_url(dir.path(), 7));

        // Top-level fallback location (no nested env).
        let cfg2 = dir.path().join("config-8");
        std::fs::create_dir_all(&cfg2).unwrap();
        std::fs::write(
            cfg2.join("settings.json"),
            r#"{"ANTHROPIC_BASE_URL":"http://localhost:11434"}"#,
        )
        .unwrap();
        assert!(slot_pins_anthropic_base_url(dir.path(), 8));
    }

    #[test]
    fn slot_pins_anthropic_base_url_false_for_oauth_and_missing() {
        let dir = TempDir::new().unwrap();
        // Missing config dir entirely → false (fail-safe).
        assert!(!slot_pins_anthropic_base_url(dir.path(), 3));
        // Anthropic OAuth slot: settings.json present but no ANTHROPIC_BASE_URL.
        let cfg = dir.path().join("config-4");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(cfg.join("settings.json"), r#"{"env":{}}"#).unwrap();
        assert!(!slot_pins_anthropic_base_url(dir.path(), 4));
        // Malformed JSON → false (fail-safe).
        let cfg5 = dir.path().join("config-5");
        std::fs::create_dir_all(&cfg5).unwrap();
        std::fs::write(cfg5.join("settings.json"), b"{not json").unwrap();
        assert!(!slot_pins_anthropic_base_url(dir.path(), 5));
    }

    /// M5: write an EU-only residency activation gate so the enterprise residency
    /// hook in `save_settings` has a policy to enforce.
    #[cfg(feature = "enterprise")]
    fn write_eu_only_gate(dir: &std::path::Path) {
        let gate = serde_json::json!({
            "provider": "claude",
            "schema": { "type": "object" },
            "max_tokens": 1024,
            "envelope": {
                "version": "1.3", "role": "D1-R1",
                "allowed_operations": [], "denied_operations": [], "require_approval_for": [],
                "declared_posture": "autonomous", "posture_floor": "supervised",
                "data_access": { "model_residency": {
                    "policy_name": "eu-only", "allowed_regions": ["eu", "on-prem"],
                    "default_action": "deny"
                }}
            }
        })
        .to_string();
        std::fs::write(
            dir.join(crate::daemon::interactive_live::GATE_FILENAME),
            gate,
        )
        .unwrap();
    }

    /// M5 (T5.2 global write path): with an EU-only residency policy in force,
    /// `save_settings` for a China-resident provider (`mm`) is REFUSED before the
    /// settings file is written.
    #[cfg(feature = "enterprise")]
    #[test]
    fn save_settings_blocked_by_residency_policy() {
        let dir = TempDir::new().unwrap();
        write_eu_only_gate(dir.path());
        let p = get_provider("mm").unwrap();
        let settings = ProviderSettings {
            provider_id: "mm".to_string(),
            settings: default_settings(p),
        };
        let err = save_settings(dir.path(), &settings).unwrap_err();
        assert!(
            matches!(err, ConfigError::ResidencyDenied { .. }),
            "expected ResidencyDenied, got {err:?}"
        );
        // Fail-closed before the write: the settings file must not exist.
        assert!(!dir.path().join(p.settings_filename).exists());
    }

    /// M5: without an activation gate (no residency policy), `save_settings`
    /// proceeds unrestricted — enforcement is opt-in.
    #[cfg(feature = "enterprise")]
    #[test]
    fn save_settings_unrestricted_without_policy() {
        let dir = TempDir::new().unwrap();
        let p = get_provider("mm").unwrap();
        let settings = ProviderSettings {
            provider_id: "mm".to_string(),
            settings: default_settings(p),
        };
        save_settings(dir.path(), &settings).expect("save succeeds with no residency policy");
        assert!(dir.path().join(p.settings_filename).exists());
    }

    #[test]
    fn key_fingerprint_falls_back_to_native_cred_env_var() {
        // #962 MED-1: azure/vertex have catalog `key_env_var: None`, so
        // `get_api_key()` returns None; `key_fingerprint()` must fall back to the
        // native cred env var so `csq listkeys` shows the real masked key, not
        // "(none)" (which read as "the key didn't save").
        let azure = ProviderSettings {
            provider_id: "azure".to_string(),
            settings: serde_json::json!({
                "env": { "AZURE_OPENAI_API_KEY": "sk-azure-abcdef123456" }
            }),
        };
        let fp = azure.key_fingerprint();
        assert_ne!(fp, "(none)", "azure fingerprint must not be (none)");
        assert!(fp.contains("..."), "expected masked fingerprint, got {fp}");

        let vertex = ProviderSettings {
            provider_id: "vertex".to_string(),
            settings: serde_json::json!({
                "env": { "VERTEX_ACCESS_TOKEN": "ya29.abcdef1234567890" }
            }),
        };
        assert_ne!(vertex.key_fingerprint(), "(none)");

        // An unconfigured azure slot still reports (none) — the fallback resolves
        // the env var but finds no value.
        let empty = ProviderSettings {
            provider_id: "azure".to_string(),
            settings: serde_json::json!({ "env": {} }),
        };
        assert_eq!(empty.key_fingerprint(), "(none)");
    }

    /// DeepSeek's published tier asymmetry: opus/sonnet → pro, haiku
    /// → flash, subagent → flash, effort → max. The MODEL_KEYS uniform
    /// fan-out writes pro to all four; `extra_env` overrides haiku to
    /// flash and adds the two CC-native keys outside MODEL_KEYS.
    #[test]
    fn default_settings_deepseek_applies_asymmetric_tier_defaults() {
        let p = get_provider("deepseek").unwrap();
        let s = default_settings(p);
        let env = s.get("env").unwrap();

        // Opus + Sonnet stay at pro (uniform fan-out, no override).
        assert_eq!(
            env.get("ANTHROPIC_DEFAULT_OPUS_MODEL").unwrap().as_str(),
            Some("deepseek-v4-pro")
        );
        assert_eq!(
            env.get("ANTHROPIC_DEFAULT_SONNET_MODEL").unwrap().as_str(),
            Some("deepseek-v4-pro")
        );

        // Haiku is overridden to flash.
        assert_eq!(
            env.get("ANTHROPIC_DEFAULT_HAIKU_MODEL").unwrap().as_str(),
            Some("deepseek-v4-flash")
        );

        // CC-native subagent + effort keys present.
        assert_eq!(
            env.get("CLAUDE_CODE_SUBAGENT_MODEL").unwrap().as_str(),
            Some("deepseek-v4-flash")
        );
        assert_eq!(
            env.get("CLAUDE_CODE_EFFORT_LEVEL").unwrap().as_str(),
            Some("max")
        );
    }

    /// `set_model` must NOT clobber keys outside `MODEL_KEYS`. After
    /// switching DeepSeek to flash uniformly, the CC-native subagent +
    /// effort keys persist (they belong to the user's per-provider
    /// configuration, not the active-model selection).
    #[test]
    fn set_model_preserves_extra_env_keys_outside_model_keys() {
        let p = get_provider("deepseek").unwrap();
        let initial = default_settings(p);

        let switched = crate::session::merge::set_model(&initial, "deepseek-v4-flash");
        let env = switched.get("env").unwrap();

        // MODEL_KEYS now uniformly flash.
        for key in crate::session::merge::MODEL_KEYS {
            assert_eq!(env.get(*key).unwrap().as_str(), Some("deepseek-v4-flash"));
        }
        // Extras outside MODEL_KEYS still there.
        assert_eq!(
            env.get("CLAUDE_CODE_SUBAGENT_MODEL").unwrap().as_str(),
            Some("deepseek-v4-flash")
        );
        assert_eq!(
            env.get("CLAUDE_CODE_EFFORT_LEVEL").unwrap().as_str(),
            Some("max")
        );
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
