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
use crate::providers;
use crate::session::merge::MODEL_KEYS;
use crate::types::AccountNum;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;

/// Minimum byte length for a usable provider API key.
///
/// Real keys are much longer (MiniMax JWTs are kilobytes, Z.AI keys are
/// 40+ chars). The floor exists to reject obvious garbage — in
/// particular, the 1-byte `"\x1b"` token that fell through the
/// pre-journal-0058 setkey prompt when the user pressed ESC then ENTER.
/// Set generously enough that no real provider key should ever fail it.
const MIN_KEY_LEN: usize = 8;

/// Rejects an API key that is obviously not a real credential.
///
/// Defense-in-depth layer behind the setkey prompt's ESC handler: even
/// if a future regression re-opens the "control bytes in the key
/// buffer" path, the bound slot can't be written because the key
/// shape gate fires first. The rejected-for-control-chars error
/// message intentionally mentions ESC so a confused user immediately
/// connects the dots.
fn validate_key_shape(key: &str) -> Result<(), ConfigError> {
    if key.is_empty() {
        return Err(ConfigError::MergeConflict {
            key: "api key is empty".into(),
        });
    }
    if key.len() < MIN_KEY_LEN {
        return Err(ConfigError::MergeConflict {
            key: format!("api key too short (need at least {MIN_KEY_LEN} bytes)"),
        });
    }
    if key.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ConfigError::MergeConflict {
            key: "api key contains control characters — cancel the prompt with ESC or Ctrl-C and try again".into(),
        });
    }
    Ok(())
}

/// Binds a provider to a numbered slot.
///
/// `key` is required for keyed providers (MiniMax, Z.AI, Claude api-key)
/// and MUST be `None` for keyless providers (Ollama). Keyless providers
/// use `Provider::default_auth_token` as the placeholder value CC sends
/// on the wire.
///
/// `model` overrides the provider's catalog `default_model` for the
/// written `ANTHROPIC_MODEL` / `ANTHROPIC_DEFAULT_*_MODEL` env keys.
/// Pass `None` to accept the catalog default (MM/ZAI one canonical
/// model; Ollama falls back to `gemma4` which may not be installed).
/// The value is written verbatim; callers are responsible for
/// validating that it's a real model id (Ollama: walk `ollama list`;
/// MM/ZAI: see the provider catalog).
///
/// After a successful bind, `csq run <slot>` can launch CC against this
/// provider and the dashboard will show the slot labelled with the
/// provider name.
///
/// # Errors
///
/// - Provider id is unknown
/// - Provider has no base URL (can't be slot-bound)
/// - Keyed provider called with `key = None`, or keyless provider
///   called with `key = Some(_)`
/// - Key is empty or obviously malformed (control chars, too short)
/// - Any filesystem or JSON error during the write
pub fn bind_provider_to_slot(
    base_dir: &Path,
    provider_id: &str,
    slot: AccountNum,
    key: Option<&str>,
    model: Option<&str>,
) -> Result<(), ConfigError> {
    let provider =
        providers::get_provider(provider_id).ok_or_else(|| ConfigError::ProfileNotFound {
            name: provider_id.to_string(),
        })?;

    let base_url = provider
        .default_base_url
        .ok_or_else(|| ConfigError::MergeConflict {
            key: format!("provider {provider_id} has no default base URL"),
        })?;
    let base_url_env_var = provider
        .base_url_env_var
        .ok_or_else(|| ConfigError::MergeConflict {
            key: format!("provider {provider_id} has no base URL env var"),
        })?;

    // Resolve the token written to `env.ANTHROPIC_AUTH_TOKEN`:
    //   - Keyed provider: user-supplied key, validated.
    //   - Keyless provider (Ollama): `default_auth_token` placeholder;
    //     caller MUST NOT pass a key.
    let (key_env_var, token) = match (provider.key_env_var, key) {
        (Some(env_var), Some(k)) => {
            validate_key_shape(k)?;
            (env_var, k.to_string())
        }
        (Some(_), None) => {
            return Err(ConfigError::MergeConflict {
                key: format!("provider {provider_id} requires an API key"),
            });
        }
        (None, Some(_)) => {
            return Err(ConfigError::MergeConflict {
                key: format!("provider {provider_id} is keyless — do not pass a key"),
            });
        }
        (None, None) => {
            let token = provider
                .default_auth_token
                .ok_or_else(|| ConfigError::MergeConflict {
                    key: format!("keyless provider {provider_id} has no default auth token"),
                })?;
            ("ANTHROPIC_AUTH_TOKEN", token.to_string())
        }
    };

    let config_dir = base_dir.join(format!("config-{}", slot));
    std::fs::create_dir_all(&config_dir).map_err(|e| ConfigError::InvalidJson {
        path: config_dir.clone(),
        reason: format!("create_dir_all: {e}"),
    })?;

    // 1. Read-modify-write the per-slot settings.json. We overlay
    //    the 3P env keys (ANTHROPIC_BASE_URL, ANTHROPIC_AUTH_TOKEN,
    //    ANTHROPIC_*_MODEL) onto whatever env block is already there
    //    and preserve every other top-level field (permissions,
    //    plugins, feedbackSurveyState, user-custom env vars like
    //    NODE_ENV). Journal 0063 P1-2: earlier revisions built a
    //    minimal settings object from scratch via `Map::new()`, which
    //    silently destroyed any field the user had hand-edited on
    //    the slot. This shape mirrors `unbind_provider_from_slot`
    //    (same file), which has been preserving unrelated fields
    //    since introduction and has a test
    //    (`unbind_preserves_non_3p_env_keys`) anchoring the contract.
    //
    //    Discovery (`discover_per_slot_third_party`) and the 3P
    //    usage poller both read `env.ANTHROPIC_BASE_URL` /
    //    `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_MODEL` from this file,
    //    so the env block is the source of truth for slot identity
    //    and must be written here.
    let settings_path = config_dir.join("settings.json");
    let mut settings_value: Value = match std::fs::read_to_string(&settings_path) {
        Ok(content) if !content.trim().is_empty() => {
            serde_json::from_str(&content).unwrap_or_else(|_| {
                // On parse failure, fall back to an empty object so
                // the bind still completes. The alternative —
                // refusing — would strand the user on a slot they
                // can no longer bind to. Overwriting an unparseable
                // file is the lesser evil.
                Value::Object(Map::new())
            })
        }
        _ => Value::Object(Map::new()),
    };

    // Ensure top-level is an object.
    if !settings_value.is_object() {
        settings_value = Value::Object(Map::new());
    }
    let settings_obj = settings_value
        .as_object_mut()
        .expect("ensured object above");

    // Ensure `env` is an object; preserve any user-custom keys.
    let env_value = settings_obj
        .entry("env".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !env_value.is_object() {
        *env_value = Value::Object(Map::new());
    }
    let env = env_value.as_object_mut().expect("ensured object above");

    // Overlay the 3P-specific env keys. Any key already present is
    // overwritten (e.g. rebinding with a new API key updates the
    // AUTH_TOKEN); user-custom keys (NODE_ENV, CUSTOM_API_URL) are
    // untouched.
    env.insert(
        base_url_env_var.to_string(),
        Value::String(base_url.to_string()),
    );
    env.insert(key_env_var.to_string(), Value::String(token));
    let model_to_write = model.unwrap_or(provider.default_model);
    for model_key in MODEL_KEYS {
        env.insert(
            (*model_key).to_string(),
            Value::String(model_to_write.to_string()),
        );
    }

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

/// Strips a third-party provider binding from a slot's `settings.json`.
///
/// Removes the 3P env keys (`ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`,
/// and every entry in `session::merge::MODEL_KEYS`). If the resulting
/// `env` object is empty it is removed; if the resulting settings file
/// is empty it is deleted outright.
///
/// Called by `accounts::login::finalize_login` so that `csq login N`
/// on a slot currently bound to MiniMax / Z.AI transitions the slot
/// back to OAuth cleanly — otherwise CC would keep routing through
/// the 3P endpoint because `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN`
/// in `settings.json` take precedence over OAuth credentials.
///
/// Returns `true` if any 3P keys were actually removed (useful for a
/// one-line "unbound MiniMax from slot N" log). Returns `false` when
/// the file is absent, isn't valid JSON, or doesn't hold any 3P keys.
///
/// # Errors
///
/// Propagated only from the filesystem write path. Missing files,
/// malformed JSON, and already-unbound slots all return `Ok(false)` —
/// never an error — because `finalize_login` treats this as cleanup
/// and should not fail a login just because settings.json is weird.
pub fn unbind_provider_from_slot(base_dir: &Path, slot: AccountNum) -> Result<bool, ConfigError> {
    let settings_path = base_dir
        .join(format!("config-{}", slot))
        .join("settings.json");

    let content = match std::fs::read_to_string(&settings_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(ConfigError::InvalidJson {
                path: settings_path.clone(),
                reason: format!("read: {e}"),
            });
        }
    };

    let mut settings: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        // Malformed JSON: leave it alone. Login shouldn't blow up on
        // a pre-existing corrupted file, and silently truncating it
        // could destroy user customisations we don't recognise.
        Err(_) => return Ok(false),
    };

    let Some(obj) = settings.as_object_mut() else {
        return Ok(false);
    };
    let Some(env) = obj.get_mut("env").and_then(|v| v.as_object_mut()) else {
        return Ok(false);
    };

    let mut removed = false;
    removed |= env.remove("ANTHROPIC_BASE_URL").is_some();
    removed |= env.remove("ANTHROPIC_AUTH_TOKEN").is_some();
    for key in MODEL_KEYS {
        removed |= env.remove(*key).is_some();
    }

    if !removed {
        return Ok(false);
    }

    // Collapse empty containers rather than leave `"env": {}` or `{}`
    // lying around — some downstream readers treat a present-but-empty
    // settings.json differently from an absent one.
    if env.is_empty() {
        obj.remove("env");
    }

    if obj.is_empty() {
        // Whole file would be `{}`. Delete instead so the slot looks
        // truly OAuth-only to discovery and the handle-dir materialiser.
        std::fs::remove_file(&settings_path).map_err(|e| ConfigError::InvalidJson {
            path: settings_path.clone(),
            reason: format!("remove: {e}"),
        })?;
        return Ok(true);
    }

    // Partial settings still present (user had customisations beyond the
    // 3P env block) — write the reduced object back atomically.
    let json = serde_json::to_string_pretty(&settings).map_err(|_| ConfigError::InvalidJson {
        path: settings_path.clone(),
        reason: "settings serialize failed".into(),
    })?;
    let tmp = crate::platform::fs::unique_tmp_path(&settings_path);
    std::fs::write(&tmp, json.as_bytes()).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("write: {e}"),
    })?;
    secure_file(&tmp).map_err(|e| ConfigError::InvalidJson {
        path: tmp.clone(),
        reason: format!("secure_file: {e}"),
    })?;
    atomic_replace(&tmp, &settings_path).map_err(|e| ConfigError::InvalidJson {
        path: settings_path.clone(),
        reason: format!("atomic replace: {e}"),
    })?;

    Ok(true)
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

        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-minimax-12345"), None).unwrap();

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

    /// Regression for journal 0063 P1-2: bind_provider_to_slot must
    /// preserve every user-edited field in config-N/settings.json.
    /// Earlier revisions built a minimal settings from scratch via
    /// `Map::new()`, silently destroying permissions, plugins, and
    /// user-custom env keys. Matches the preservation contract that
    /// `unbind_provider_from_slot` has via
    /// `unbind_preserves_non_3p_env_keys`.
    #[test]
    fn bind_preserves_user_customisations_in_settings_json() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();
        let config_dir = dir.path().join("config-9");
        std::fs::create_dir_all(&config_dir).unwrap();
        let settings_path = config_dir.join("settings.json");

        // User hand-edits settings.json BEFORE running `csq setkey`.
        let seed = serde_json::json!({
            "env": {
                "NODE_ENV": "development",
                "CUSTOM_API_URL": "https://internal.example.com"
            },
            "permissions": { "read": true, "write": false },
            "plugins": ["foo", "bar"],
            "effortLevel": "high",
            "feedbackSurveyState": { "dismissed": true }
        });
        std::fs::write(&settings_path, serde_json::to_string_pretty(&seed).unwrap()).unwrap();

        // Act: bind MiniMax to the slot.
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-mm-abc123"), None).unwrap();

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();

        // 3P keys were overlaid correctly.
        let env = json.get("env").unwrap().as_object().unwrap();
        assert_eq!(
            env.get("ANTHROPIC_AUTH_TOKEN").unwrap(),
            "sk-test-mm-abc123"
        );
        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").unwrap(),
            "https://api.minimax.io/anthropic"
        );

        // User-custom env keys survived.
        assert_eq!(env.get("NODE_ENV").unwrap(), "development");
        assert_eq!(
            env.get("CUSTOM_API_URL").unwrap(),
            "https://internal.example.com"
        );

        // Top-level user fields all survived.
        let perms = json.get("permissions").unwrap();
        assert_eq!(perms.get("read").unwrap(), true);
        assert_eq!(perms.get("write").unwrap(), false);

        let plugins = json.get("plugins").unwrap().as_array().unwrap();
        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0], "foo");
        assert_eq!(plugins[1], "bar");

        assert_eq!(json.get("effortLevel").unwrap(), "high");
        assert_eq!(
            json.get("feedbackSurveyState")
                .unwrap()
                .get("dismissed")
                .unwrap(),
            true
        );
    }

    /// Rebinding with a new key must overwrite the old AUTH_TOKEN
    /// but still preserve unrelated fields.
    #[test]
    fn bind_rebinding_updates_token_and_preserves_other_fields() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();

        // First bind.
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-old-key"), None).unwrap();
        let settings_path = dir.path().join("config-9/settings.json");

        // User edits settings.json between binds.
        let content = std::fs::read_to_string(&settings_path).unwrap();
        let mut json: Value = serde_json::from_str(&content).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("permissions".to_string(), serde_json::json!({"read": true}));
        std::fs::write(&settings_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        // Rebind with a fresh key.
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-new-key"), None).unwrap();

        let content = std::fs::read_to_string(&settings_path).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();

        // Token updated.
        assert_eq!(
            json.get("env")
                .unwrap()
                .get("ANTHROPIC_AUTH_TOKEN")
                .unwrap(),
            "sk-test-new-key"
        );
        // Permissions survived the rebind.
        assert_eq!(json.get("permissions").unwrap().get("read").unwrap(), true);
    }

    #[test]
    fn bind_creates_profile_entry() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();

        bind_provider_to_slot(dir.path(), "zai", slot, Some("key-zai-123"), None).unwrap();

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
        bind_provider_to_slot(dir.path(), "mm", slot, Some("key-long-7"), None).unwrap();

        let marker = dir.path().join("config-7/.csq-account");
        assert!(marker.exists());
        let contents = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(contents.trim(), "7");
    }

    #[test]
    fn bind_makes_slot_discoverable_as_third_party() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(12u16).unwrap();

        bind_provider_to_slot(dir.path(), "mm", slot, Some("key-discover"), None).unwrap();

        let slots = discovery::discover_per_slot_third_party(dir.path());
        let found = slots.iter().find(|a| a.id == 12).expect("slot 12 missing");
        assert_eq!(found.label, "MiniMax");
        assert_eq!(found.method, "api_key");
        assert!(found.has_credentials);
    }

    #[test]
    fn bind_strips_api_key_helper() {
        // Regression for alpha.7 auth-conflict bug: `default_settings`
        // wrote the provider's system_primer into `apiKeyHelper`, which
        // CC reads as a shell command returning an API key. Combined
        // with `env.ANTHROPIC_AUTH_TOKEN`, CC warned about an auth
        // conflict and refused to use the token cleanly. The slot-bind
        // path MUST strip `apiKeyHelper` before writing.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-cp-test"), None).unwrap();

        let settings_path = dir.path().join("config-9/settings.json");
        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        assert!(
            json.get("apiKeyHelper").is_none(),
            "apiKeyHelper must not be written to slot-bound settings.json: {}",
            json
        );
        // Sanity: the token is still there.
        assert_eq!(
            json.get("env")
                .unwrap()
                .get("ANTHROPIC_AUTH_TOKEN")
                .unwrap(),
            "sk-cp-test"
        );
    }

    #[test]
    fn bind_rejects_empty_key() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "mm", slot, Some(""), None);
        assert!(err.is_err());
    }

    #[test]
    fn bind_rejects_key_shorter_than_min() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "mm", slot, Some("short"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn bind_rejects_key_with_control_char() {
        // The pre-fix bug: ESC (0x1b) slipped through the hidden-key
        // prompt and was saved as the provider token. This test
        // asserts the defense-in-depth gate in `bind_provider_to_slot`
        // rejects any key containing ASCII control bytes, even if the
        // prompt ever regresses.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "mm", slot, Some("good-\x1b-bad"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("control characters"), "got: {err}");
    }

    #[test]
    fn bind_rejects_just_escape_byte() {
        // The exact historical failure mode: user pressed ESC, then
        // ENTER, producing a 1-byte key `"\x1b"`. Must fail at the
        // shape gate before any filesystem write happens.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "mm", slot, Some("\x1b"), None);
        assert!(err.is_err());
        // Confirm no settings.json was created.
        assert!(!dir.path().join("config-3/settings.json").exists());
    }

    #[test]
    fn bind_rejects_unknown_provider() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "bogus", slot, Some("k"), None);
        assert!(err.is_err());
    }

    #[test]
    fn bind_keyless_ollama_uses_default_auth_token() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();

        bind_provider_to_slot(dir.path(), "ollama", slot, None, None).unwrap();

        let settings_path = dir.path().join("config-5/settings.json");
        assert!(settings_path.exists());
        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        let env = json.get("env").unwrap();
        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").unwrap(),
            "http://localhost:11434"
        );
        // Keyless provider — placeholder token so CC can send an
        // auth header; value is irrelevant to Ollama itself.
        assert_eq!(env.get("ANTHROPIC_AUTH_TOKEN").unwrap(), "ollama");
        assert!(env.get("ANTHROPIC_MODEL").is_some());
    }

    #[test]
    fn bind_keyless_rejects_passed_key() {
        // Passing a key to a keyless provider is a caller bug — reject
        // so we don't silently overwrite the placeholder with user input.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "ollama", slot, Some("something"), None);
        assert!(err.is_err());
    }

    #[test]
    fn bind_keyed_rejects_missing_key() {
        // Symmetric: MM/Z.AI must have a key.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "mm", slot, None, None);
        assert!(err.is_err());
    }

    #[test]
    fn bind_with_model_override_writes_chosen_model() {
        // Ollama users pick a model from their local `ollama list`.
        // The override must land in every MODEL_KEYS entry.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(6u16).unwrap();
        bind_provider_to_slot(dir.path(), "ollama", slot, None, Some("qwen3:latest")).unwrap();

        let settings_path = dir.path().join("config-6/settings.json");
        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        let env = json.get("env").unwrap();
        for model_key in MODEL_KEYS {
            assert_eq!(
                env.get(*model_key).unwrap().as_str().unwrap(),
                "qwen3:latest",
                "{model_key} should reflect the model override"
            );
        }
    }

    #[test]
    fn bind_without_model_uses_catalog_default() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(7u16).unwrap();
        bind_provider_to_slot(dir.path(), "ollama", slot, None, None).unwrap();

        let settings_path = dir.path().join("config-7/settings.json");
        let json: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        let env = json.get("env").unwrap();
        let provider = providers::get_provider("ollama").unwrap();
        assert_eq!(
            env.get("ANTHROPIC_MODEL").unwrap().as_str().unwrap(),
            provider.default_model
        );
    }

    #[test]
    fn bind_overwrites_existing_slot_settings() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(4u16).unwrap();

        bind_provider_to_slot(dir.path(), "mm", slot, Some("first-key"), None).unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, Some("second-key"), None).unwrap();

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

        bind_provider_to_slot(
            dir.path(),
            "mm",
            AccountNum::try_from(9u16).unwrap(),
            Some("test-key-8"),
            None,
        )
        .unwrap();

        let loaded = profiles::load(&profiles_path).unwrap();
        assert_eq!(loaded.get_email(1), Some("alice@example.com"));
        assert_eq!(loaded.get_profile(9).unwrap().method, "api_key");
    }

    // ── unbind_provider_from_slot ───────────────────────────

    #[test]
    fn unbind_removes_3p_env_block_and_deletes_empty_file() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(1u16).unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-minimax-12345"), None).unwrap();

        let settings_path = dir.path().join("config-1/settings.json");
        assert!(settings_path.exists(), "bind should have created the file");

        let removed = unbind_provider_from_slot(dir.path(), slot).unwrap();
        assert!(removed);
        assert!(
            !settings_path.exists(),
            "whole file should be deleted when env block was its only content"
        );
    }

    #[test]
    fn unbind_after_bind_reclassifies_slot_as_non_third_party() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(1u16).unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-minimax-12345"), None).unwrap();

        let pre = discovery::discover_per_slot_third_party(dir.path());
        assert!(
            pre.iter().any(|a| a.id == 1),
            "slot 1 should be 3P before unbind"
        );

        unbind_provider_from_slot(dir.path(), slot).unwrap();

        let post = discovery::discover_per_slot_third_party(dir.path());
        assert!(
            !post.iter().any(|a| a.id == 1),
            "slot 1 should not be 3P after unbind"
        );
    }

    #[test]
    fn unbind_no_op_when_file_missing() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(1u16).unwrap();
        let removed = unbind_provider_from_slot(dir.path(), slot).unwrap();
        assert!(!removed);
    }

    #[test]
    fn unbind_preserves_non_3p_env_keys() {
        // A user who hand-edited config-N/settings.json to add, say,
        // `NODE_ENV` or a custom env var should not have those wiped
        // by `csq login N`. Only the known 3P keys get stripped.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(2u16).unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-minimax-12345"), None).unwrap();

        // Hand-patch: add a user env key.
        let settings_path = dir.path().join("config-2/settings.json");
        let mut json: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        json.as_object_mut()
            .unwrap()
            .get_mut("env")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("NODE_ENV".into(), Value::String("development".into()));
        std::fs::write(&settings_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        unbind_provider_from_slot(dir.path(), slot).unwrap();

        // File still exists, the 3P keys are gone, NODE_ENV survives.
        assert!(settings_path.exists());
        let after: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        let env = after.get("env").expect("env block should still exist");
        assert!(env.get("ANTHROPIC_BASE_URL").is_none());
        assert!(env.get("ANTHROPIC_AUTH_TOKEN").is_none());
        assert!(env.get("ANTHROPIC_MODEL").is_none());
        assert_eq!(
            env.get("NODE_ENV").and_then(|v| v.as_str()),
            Some("development")
        );
    }

    #[test]
    fn unbind_ignores_malformed_json() {
        // A corrupted settings.json should not make login fail. The
        // function reports "nothing removed" and leaves the file as-is
        // for the user to investigate.
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(3u16).unwrap();
        let config_dir = dir.path().join("config-3");
        std::fs::create_dir_all(&config_dir).unwrap();
        let settings_path = config_dir.join("settings.json");
        std::fs::write(&settings_path, b"not valid json {{{").unwrap();

        let removed = unbind_provider_from_slot(dir.path(), slot).unwrap();
        assert!(!removed);
        // Preserved unchanged.
        assert_eq!(
            std::fs::read_to_string(&settings_path).unwrap(),
            "not valid json {{{"
        );
    }
}
