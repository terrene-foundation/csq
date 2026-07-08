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
use crate::accounts::profiles;
#[cfg(test)]
use crate::accounts::profiles::AccountProfile;
use crate::accounts::profiles_lock::ProfilesFileLock;
use crate::error::ConfigError;
use crate::platform::fs::{atomic_replace, secure_file};
use crate::providers;
use crate::providers::catalog::Surface;
use crate::session::merge::MODEL_KEYS;
use crate::types::AccountNum;
use serde_json::{Map, Value};
#[cfg_attr(not(test), allow(unused_imports))]
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
///
/// **Public** because the setkey CLI calls this on the global save
/// path too (no `--slot`), which previously bypassed the gate
/// entirely. Security review HIGH-3: a key with embedded `\r\n` would
/// otherwise survive to the validation probe's `Authorization: Bearer
/// {key}` header construction and could split the request.
pub fn validate_key_shape(key: &str) -> Result<(), ConfigError> {
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

/// Removes the catalog-declared `extra_env` keys belonging to whatever
/// provider currently owns this slot's `env` block, identified via
/// `ANTHROPIC_BASE_URL` → host classification → catalog id → provider
/// entry. Returns `true` if any key was removed.
///
/// Called at the start of every bind (so a rebind to a new provider
/// purges the old provider's extras before overlay) and at the start
/// of every unbind (so the slot's env block is clean for whoever binds
/// next). Centralizes a chain that was previously hand-written in two
/// places.
///
/// If the slot's `ANTHROPIC_BASE_URL` is missing, points at an unknown
/// host, or maps to a catalog provider with empty `extra_env`, this is
/// a no-op (returns `false`). That's the correct behavior for slots
/// that were never bound to a 3P provider, slots bound to providers
/// without extras (mm, zai, ollama), or slots whose previous provider
/// was removed from the catalog.
fn purge_previous_provider_extras(env: &mut Map<String, Value>) -> bool {
    let extras = env
        .get("ANTHROPIC_BASE_URL")
        .and_then(|v| v.as_str())
        .and_then(crate::accounts::discovery::provider_from_base_url)
        .and_then(providers::id_from_display_name)
        .and_then(providers::get_provider)
        .map(|p| p.extra_env)
        .unwrap_or(&[]);

    let mut removed = false;
    for (extra_key, _) in extras {
        removed |= env.remove(*extra_key).is_some();
    }
    removed
}

/// The non-3P OAuth/device-auth surface that slot `slot` is currently bound to
/// and that a per-slot provider-key write would clobber, or `None` if the slot
/// is free for a 3P bind (including a 3P→3P re-key).
///
/// Identity-store-aware (`account-terminal-separation.md` MUST Rule 4): keyed on
/// `by_slot` → `identities/<UUID>/` (provider tag + credential presence) with the
/// M4-12-retired legacy mirrors kept only as a pre-A++ `symlink_metadata`
/// fallback inside the predicates. The prior surface guards stat-ed the legacy
/// mirrors directly and were blind to every post-A++ login.
///
/// Codex is checked before Anthropic so a (rare) dual-bound slot reports the
/// Codex surface; the `csq logout <N>` remediation is surface-agnostic, so the
/// single-surface message stays actionable in either reading.
///
/// The Anthropic branch has NO `provider.surface` gate on purpose: every 3P
/// provider (mm / deepseek / zai / ollama) AND `claude` share
/// `Surface::ClaudeCode` (they all speak the Anthropic protocol via a base-URL
/// override), so the presence of an Anthropic OAuth binding — not the provider's
/// surface — is the refusal signal. A direct-API key write would override the
/// live subscription token.
pub fn conflicting_bound_surface(
    base_dir: &Path,
    slot: AccountNum,
    provider: &providers::Provider,
) -> Option<Surface> {
    use crate::accounts::identity_store;

    if identity_store::is_codex_bound_slot_identity_aware(base_dir, slot)
        && provider.surface != Surface::Codex
    {
        return Some(Surface::Codex);
    }
    if crate::providers::gemini::provisioning::is_gemini_bound_slot(base_dir, slot)
        && provider.surface != Surface::Gemini
    {
        return Some(Surface::Gemini);
    }
    if identity_store::is_anthropic_bound_slot(base_dir, slot) {
        return Some(Surface::ClaudeCode);
    }
    None
}

/// Human-facing label for a conflicting bound surface, used in the
/// [`ConfigError::SlotSurfaceConflict`] message.
pub fn bound_surface_label(surface: Surface) -> &'static str {
    match surface {
        Surface::ClaudeCode => "Claude (Anthropic OAuth)",
        Surface::Codex => "Codex",
        Surface::Gemini => "Gemini",
    }
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
/// - Slot is bound to a non-3P surface ([`ConfigError::SlotSurfaceConflict`];
///   see [`conflicting_bound_surface`])
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

    // M5: residency gate (enterprise-only) — the PER-SLOT provider-binding write
    // path's enforcement point (sibling of `providers::settings::save_settings`).
    // Refuse to bind a provider the operating envelope's residency policy forbids,
    // BEFORE any filesystem mutation (no profiles lock taken, no settings written).
    // No policy declared → no-op. Covers every per-slot caller (CLI `setkey --slot`,
    // desktop `bind_keyed_provider` / `bind_keyless_provider`). Community compiles
    // it out (the symbol is in the moat-stripped `phase2b` tree).
    #[cfg(feature = "enterprise")]
    crate::phase2b::residency::enforce_provider_write(base_dir, provider_id)?;

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

    // PD-3: acquire ProfilesFileLock BEFORE the settings.json lock.
    // Lock ordering: ProfilesFileLock FIRST, then settings.json lock.
    // This serializes against csq logout, daemon Pass-0 mint, daemon
    // backfill (M6), and set_slot_identity writes. The profiles lock is
    // held for the ENTIRE function body (dropped on return via RAII).
    let _profiles_lock =
        ProfilesFileLock::acquire(base_dir).map_err(|e| ConfigError::InvalidJson {
            path: base_dir.join(".profiles.lock"),
            reason: format!("profiles lock: {e}"),
        })?;

    // Surface-conflict guard (identity-store-aware) — refuse to clobber a slot
    // bound to Codex / Anthropic OAuth / Gemini. This is the STRUCTURAL backstop
    // shared by the CLI `setkey` pre-flight AND the desktop
    // `bind_keyed_provider` / `bind_keyless_provider` commands, so the #995
    // 3P-clobber (silent OAuth override + orphaned `by_slot`) cannot reach the
    // write path from any surface. Checked UNDER the profiles lock so a
    // concurrent `csq logout` cannot open a check→write TOCTOU. The CLI keeps a
    // pre-flight copy of this check purely for UX (early refusal + exit code 2,
    // before the interactive key prompt); this is the authoritative one.
    if let Some(surface) = conflicting_bound_surface(base_dir, slot, provider) {
        return Err(ConfigError::SlotSurfaceConflict {
            slot: slot.get(),
            bound_surface: bound_surface_label(surface).to_string(),
        });
    }

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
    //    NODE_ENV). an internal journal entry P1-2: earlier revisions built a
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
    //
    //    VP-H1 (HIGH): concurrent `csq setkey` or desktop setkey
    //    calls on the same slot race on this RMW. Without a lock,
    //    the last atomic_replace wins and the other's overlay is
    //    silently dropped. We hold the flock for the full RMW span
    //    so only one writer can read-modify-write at a time.
    let settings_path = config_dir.join("settings.json");
    let settings_lock_path = settings_path.with_extension("lock");
    let _settings_lock = crate::platform::lock::lock_file(&settings_lock_path).map_err(|e| {
        ConfigError::InvalidJson {
            path: settings_lock_path.clone(),
            reason: format!("lock: {e}"),
        }
    })?;
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

    // Purge any previous provider's catalog-declared extras BEFORE
    // overlaying the new provider's. Without this, rebinding a slot
    // from one provider to another leaves the prior provider's
    // extra_env keys orphaned in the env block — e.g. binding slot 6
    // to DeepSeek then to MiniMax would leave
    // CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash visible to every
    // MiniMax invocation. Mirrors the same purge in
    // unbind_provider_from_slot. Code review HIGH-1.
    purge_previous_provider_extras(env);

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

    // Apply provider.extra_env AFTER the MODEL_KEYS fan-out so per-tier
    // overrides (e.g. DeepSeek's haiku → flash) and non-MODEL_KEYS env
    // vars (CLAUDE_CODE_SUBAGENT_MODEL, CLAUDE_CODE_EFFORT_LEVEL) seed
    // correctly on bind. Mirrors providers::settings::default_settings.
    // Without this, the per-slot path silently drops the catalog's
    // published per-provider defaults — observed on slot 6 DeepSeek
    // bind in csq 2.5.0.
    for (extra_key, extra_value) in provider.extra_env {
        env.insert(
            (*extra_key).to_string(),
            Value::String((*extra_value).to_string()),
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
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: format!("write: {e}"),
        });
    }
    // SECURITY: propagate (not `.ok()`) — a silent permission failure would
    // publish the credential file at the umask default, potentially
    // world-readable. Fail closed. Red-team B2: `std::fs::write` above
    // created `tmp` at umask-default permissions with the token in
    // plaintext; on any failure path below we MUST `remove_file`
    // before propagating so the token isn't left readable on disk.
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: format!("secure_file: {e}"),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &settings_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: settings_path.clone(),
            reason: format!("atomic replace: {e}"),
        });
    }

    // 2. Profiles.json: M4-9 (release N affordance, an internal ticket Phase 4).
    //
    // The v1 `profiles.accounts` field is empty-write in production. 3P
    // bindings have NO OAuth identity (no `by_slot` UUID, no `by_email`
    // mapping) because the api-key flow does not run `mint_for_login`.
    // The 3P binding identity is now carried by `settings.json` at the
    // slot level (provider_id, model keys, env keys) plus the
    // `.csq-account` marker — both written above and below this block.
    //
    // The v1 row that previously held `{email: "apikey:{provider_id}",
    // method: "api_key"}` is no longer persisted. M4-13 (release N+1)
    // deletes the v1 field.

    // M7: write the non-OAuth identity label in the same ProfilesFileLock
    // window as the settings env-block fan-out. The label literal is the
    // canonical "apikey:<provider_id>" form that get_email step 1.5 returns
    // directly and that the M6 backfill reconciler would otherwise produce
    // from the same data — writing here synchronously skips the backfill
    // path for fresh binds, leaving backfill as the legacy-upgrade path only.
    let identity_label = format!("apikey:{}", provider.id);
    profiles::set_slot_identity(&_profiles_lock, base_dir, slot.get(), &identity_label)?;

    // 3. Marker.
    //
    // M4-7: 3P (api-key) bindings have no OAuth identity, so the marker
    // content is the legacy decimal slot id. Identity-keyed marker
    // content is reserved for OAuth slots whose `by_slot` entry resolves
    // to a UUID in `profiles.json`.
    markers::write_csq_account_legacy(&config_dir, slot).map_err(|e| ConfigError::InvalidJson {
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
///
/// # Lock-ordering contract (AB-BA deadlock avoidance)
///
/// The caller MUST NOT hold [`crate::accounts::profiles_lock::ProfilesFileLock`]
/// when calling this function. [`bind_provider_to_slot`] (the sibling rebind
/// path) acquires `ProfilesFileLock` FIRST, then the `settings.json` flock
/// (the lock this function acquires inside). A caller that already holds
/// `ProfilesFileLock` and then calls this function would acquire the locks
/// in the opposite order (settings.json flock first, ProfilesFileLock second),
/// forming an AB-BA cycle the moment a concurrent `bind_provider_to_slot`
/// is in flight on the same slot.
///
/// Today's only production caller (`finalize_login` via
/// `accounts/login.rs::finalize_login`) does not hold `ProfilesFileLock` at
/// the unbind call site, so no cycle exists in current code. This contract
/// exists to forbid future callers from introducing the cycle. If a future
/// caller needs both locks held across the unbind, the correct fix is to
/// drop `ProfilesFileLock` before calling here and re-acquire after.
pub fn unbind_provider_from_slot(base_dir: &Path, slot: AccountNum) -> Result<bool, ConfigError> {
    let settings_path = base_dir
        .join(format!("config-{}", slot))
        .join("settings.json");

    // VP-H1 (HIGH): concurrent bind and unbind on the same slot race on this
    // RMW. Hold the flock (same lock path as bind_provider_to_slot) for the
    // full read-check-write span so the two operations serialize correctly.
    let settings_lock_path = settings_path.with_extension("lock");
    // Ensure the parent directory exists before trying to create the lock
    // file — unbind may be called on a slot that never had settings.json.
    if let Some(parent) = settings_lock_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _settings_lock = crate::platform::lock::lock_file(&settings_lock_path).map_err(|e| {
        ConfigError::InvalidJson {
            path: settings_lock_path.clone(),
            reason: format!("lock: {e}"),
        }
    })?;

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

    // Purge the bound provider's catalog-declared extras using the
    // shared helper (same code path bind uses on rebind). Must run
    // BEFORE removing ANTHROPIC_BASE_URL because the helper derives
    // the previous provider from that URL.
    let extras_removed = purge_previous_provider_extras(env);

    let mut removed = extras_removed;
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
    // Red-team B2: any failure on the tmp file must delete it
    // before propagating. Even though unbind's path no longer
    // holds the 3P token (we just removed the env block), the
    // unrelated settings fields that DO remain (permissions,
    // plugins, user env vars) may still be sensitive, and the
    // umask-default artifact would be surprising.
    let tmp = crate::platform::fs::unique_tmp_path(&settings_path);
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: format!("write: {e}"),
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: tmp.clone(),
            reason: format!("secure_file: {e}"),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &settings_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ConfigError::InvalidJson {
            path: settings_path.clone(),
            reason: format!("atomic replace: {e}"),
        });
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::discovery;
    use tempfile::TempDir;

    /// Plant the post-M4-12 host shape: `by_slot` → `identities/<uuid>/` with the
    /// given provider + matching credential, and NO legacy mirror. This is the
    /// state a current login leaves; the pre-fix legacy-mirror guards were blind
    /// to it (the #995 class this shard closes).
    fn bind_identity_oauth(base: &Path, slot: u16, provider: &str) {
        use crate::accounts::identity_store::{
            credentials_codex_path_for, credentials_path_for, identity_path, IdentityId,
        };
        use crate::accounts::profiles::{profiles_path, save, ProfilesFile};
        let uuid = IdentityId::new_v4();
        let idir = identity_path(base, uuid);
        std::fs::create_dir_all(&idir).unwrap();
        std::fs::write(
            idir.join("identity.json"),
            format!(r#"{{"email":"x","provider":"{provider}","created_at":"t","key_id":null}}"#),
        )
        .unwrap();
        let cred = if provider == "codex" {
            credentials_codex_path_for(base, uuid)
        } else {
            credentials_path_for(base, uuid)
        };
        std::fs::write(cred, b"{}").unwrap();
        let mut pf = ProfilesFile::empty();
        pf.by_slot.insert(slot.to_string(), uuid);
        save(&profiles_path(base), &pf).unwrap();
    }

    fn prov(id: &str) -> &'static providers::Provider {
        providers::get_provider(id).unwrap()
    }

    #[test]
    fn conflicting_bound_surface_detects_identity_only_anthropic() {
        let dir = TempDir::new().unwrap();
        bind_identity_oauth(dir.path(), 3, "anthropic");
        assert!(
            !dir.path().join("credentials/3.json").exists(),
            "precondition: no legacy mirror (post-M4-12 shape)"
        );
        let slot = AccountNum::try_from(3u16).unwrap();
        assert_eq!(
            conflicting_bound_surface(dir.path(), slot, prov("mm")),
            Some(crate::providers::catalog::Surface::ClaudeCode),
        );
        // `claude` (direct API key) also refused — shares Surface::ClaudeCode,
        // so the binding presence, not the surface, is the signal.
        assert_eq!(
            conflicting_bound_surface(dir.path(), slot, prov("claude")),
            Some(crate::providers::catalog::Surface::ClaudeCode),
        );
    }

    #[test]
    fn conflicting_bound_surface_detects_identity_only_codex() {
        let dir = TempDir::new().unwrap();
        bind_identity_oauth(dir.path(), 9, "codex");
        assert!(!dir.path().join("credentials/codex-9.json").exists());
        let slot = AccountNum::try_from(9u16).unwrap();
        assert_eq!(
            conflicting_bound_surface(dir.path(), slot, prov("mm")),
            Some(crate::providers::catalog::Surface::Codex),
        );
    }

    #[test]
    fn conflicting_bound_surface_detects_gemini() {
        // Gemini's marker (`credentials/gemini-<N>.json`) is NOT M4-12-retired —
        // it is the live write target — so `is_gemini_bound_slot` remains the
        // correct signal. Plant it via the production writer and assert a 3P
        // bind is refused with the Gemini surface.
        use crate::providers::gemini::provisioning::{write_binding, AuthMode, GeminiBinding};
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(8u16).unwrap();
        write_binding(
            dir.path(),
            slot,
            &GeminiBinding::new(AuthMode::ApiKey, "auto"),
        )
        .unwrap();
        assert_eq!(
            conflicting_bound_surface(dir.path(), slot, prov("mm")),
            Some(Surface::Gemini),
        );
        // A Gemini-surface provider is NOT blocked on its own slot.
        assert_eq!(
            conflicting_bound_surface(dir.path(), slot, prov("gemini")),
            None,
        );
    }

    #[test]
    fn conflicting_bound_surface_none_for_unbound_and_3p_slot() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();
        // Unbound.
        assert_eq!(
            conflicting_bound_surface(dir.path(), slot, prov("mm")),
            None
        );
        // 3P-bound: a real bind writes by_slot_identity (synthetic label), NOT
        // by_slot → resolve_slot_to_uuid → None → no conflict (3P→3P allowed).
        bind_provider_to_slot(
            dir.path(),
            "deepseek",
            slot,
            Some("sk-deepseek-xxxxxxxx"),
            None,
        )
        .unwrap();
        assert_eq!(
            conflicting_bound_surface(dir.path(), slot, prov("mm")),
            None,
            "3P→3P rebind must not be blocked"
        );
    }

    #[test]
    fn bind_provider_to_slot_refuses_identity_only_anthropic_slot() {
        // THE #995 origin, now blocked at the core write path (covers CLI setkey
        // AND desktop bind_keyed/keyless).
        let dir = TempDir::new().unwrap();
        bind_identity_oauth(dir.path(), 3, "anthropic");
        let slot = AccountNum::try_from(3u16).unwrap();
        let err = bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-minimax-123"), None)
            .expect_err("must refuse a 3P bind over an Anthropic OAuth slot");
        match err {
            ConfigError::SlotSurfaceConflict {
                slot: s,
                bound_surface,
            } => {
                assert_eq!(s, 3);
                assert!(
                    bound_surface.contains("Anthropic OAuth"),
                    "surface label: {bound_surface}"
                );
            }
            other => panic!("wrong error variant: {other:?}"),
        }
        // The slot's settings.json must NOT have been written.
        assert!(!dir.path().join("config-3/settings.json").exists());
    }

    #[test]
    fn bind_provider_to_slot_refuses_identity_only_codex_slot() {
        let dir = TempDir::new().unwrap();
        bind_identity_oauth(dir.path(), 9, "codex");
        let slot = AccountNum::try_from(9u16).unwrap();
        let err =
            bind_provider_to_slot(dir.path(), "deepseek", slot, Some("sk-deepseek-123"), None)
                .expect_err("must refuse a 3P bind over a Codex slot");
        assert!(matches!(
            err,
            ConfigError::SlotSurfaceConflict { slot: 9, .. }
        ));
    }

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

    /// M5: write an EU-only residency activation gate so the enterprise residency
    /// hook in `bind_provider_to_slot` has a policy to enforce.
    #[cfg(feature = "enterprise")]
    fn write_eu_only_gate(dir: &Path) {
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

    /// M5 (T5.2 per-slot write path): with an EU-only residency policy in force,
    /// binding a China-resident provider (`mm`) is REFUSED before any write — no
    /// `config-N/settings.json` is created.
    #[cfg(feature = "enterprise")]
    #[test]
    fn bind_provider_to_slot_blocked_by_residency_policy() {
        let dir = TempDir::new().unwrap();
        write_eu_only_gate(dir.path());
        let slot = AccountNum::try_from(9u16).unwrap();
        let err =
            bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-minimax-12345"), None)
                .unwrap_err();
        assert!(
            matches!(err, ConfigError::ResidencyDenied { .. }),
            "expected ResidencyDenied, got {err:?}"
        );
        // Fail-closed BEFORE any filesystem mutation: no settings.json written.
        assert!(!dir.path().join("config-9/settings.json").exists());
    }

    /// M5: without an activation gate (no residency policy), the per-slot bind
    /// proceeds unrestricted — enforcement is opt-in.
    #[cfg(feature = "enterprise")]
    #[test]
    fn bind_provider_to_slot_unrestricted_without_policy() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-minimax-12345"), None)
            .expect("bind succeeds with no residency policy");
        assert!(dir.path().join("config-9/settings.json").exists());
    }

    /// `csq setkey claude --slot N --key sk-ant-...` binds the slot
    /// to Claude via direct API key (the dual-mode reality of Claude:
    /// `auth_type = OAuth` AND `key_env_var = "ANTHROPIC_API_KEY"`).
    /// The bind writes the key to `env.ANTHROPIC_API_KEY` (NOT
    /// `ANTHROPIC_AUTH_TOKEN` — Anthropic's API expects the former,
    /// `_AUTH_TOKEN` is the third-party convention used by MiniMax /
    /// Z.AI / DeepSeek which proxy-translate to the Anthropic shape).
    #[test]
    fn bind_claude_direct_api_key_writes_anthropic_api_key_env() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(11u16).unwrap();

        bind_provider_to_slot(
            dir.path(),
            "claude",
            slot,
            Some("sk-ant-api03-TESTxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            None,
        )
        .unwrap();

        let settings_path = dir.path().join("config-11/settings.json");
        let content = std::fs::read_to_string(&settings_path).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();
        let env = json.get("env").unwrap();
        assert_eq!(
            env.get("ANTHROPIC_API_KEY").unwrap(),
            "sk-ant-api03-TESTxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "claude key MUST land in ANTHROPIC_API_KEY (the Anthropic-native env var), \
             not ANTHROPIC_AUTH_TOKEN (the 3P-bridge convention)"
        );
        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").unwrap(),
            "https://api.anthropic.com"
        );
        assert!(env.get("ANTHROPIC_MODEL").is_some());
    }

    /// Regression for an internal journal entry P1-2: bind_provider_to_slot must
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
    /// Regression: per-slot bind MUST apply `provider.extra_env` after
    /// the MODEL_KEYS fan-out. Observed bug on csq 2.5.0 slot 6
    /// DeepSeek bind — file shipped with `ANTHROPIC_DEFAULT_HAIKU_MODEL
    /// = pro` (uniform fan-out) and was missing
    /// `CLAUDE_CODE_SUBAGENT_MODEL` + `CLAUDE_CODE_EFFORT_LEVEL`
    /// because the slot path did not honor `extra_env`.
    #[test]
    fn bind_applies_provider_extra_env_after_model_keys_fanout() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(6u16).unwrap();

        bind_provider_to_slot(dir.path(), "deepseek", slot, Some("sk-test-deepseek"), None)
            .unwrap();

        let content = std::fs::read_to_string(dir.path().join("config-6/settings.json")).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();
        let env = json.get("env").unwrap();

        // MODEL_KEYS fan-out: opus + sonnet + ANTHROPIC_MODEL +
        // ANTHROPIC_SMALL_FAST_MODEL stay at pro (the default_model).
        assert_eq!(
            env.get("ANTHROPIC_DEFAULT_OPUS_MODEL").unwrap(),
            "deepseek-v4-pro"
        );
        assert_eq!(
            env.get("ANTHROPIC_DEFAULT_SONNET_MODEL").unwrap(),
            "deepseek-v4-pro"
        );
        // extra_env override: haiku is flash, NOT pro.
        assert_eq!(
            env.get("ANTHROPIC_DEFAULT_HAIKU_MODEL").unwrap(),
            "deepseek-v4-flash"
        );
        // Non-MODEL_KEYS extras are present.
        assert_eq!(
            env.get("CLAUDE_CODE_SUBAGENT_MODEL").unwrap(),
            "deepseek-v4-flash"
        );
        assert_eq!(env.get("CLAUDE_CODE_EFFORT_LEVEL").unwrap(), "max");
    }

    /// Regression: rebinding a slot from one provider to another MUST
    /// purge the previous provider's `extra_env` keys. Code review
    /// HIGH-1: without this, binding slot 6 to DeepSeek then to
    /// MiniMax leaves CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash
    /// visible to every MiniMax invocation on that slot.
    #[test]
    fn rebind_from_deepseek_to_mm_purges_deepseek_extras() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(6u16).unwrap();

        // Step 1: bind DeepSeek (writes the asymmetric extras).
        bind_provider_to_slot(dir.path(), "deepseek", slot, Some("sk-test-deepseek"), None)
            .unwrap();
        let path = dir.path().join("config-6/settings.json");
        let after_ds: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            after_ds
                .get("env")
                .unwrap()
                .get("CLAUDE_CODE_SUBAGENT_MODEL")
                .unwrap(),
            "deepseek-v4-flash"
        );

        // Step 2: rebind to MiniMax (whose extra_env is empty). The
        // DeepSeek extras must NOT survive into the MiniMax-bound
        // slot's env block.
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-mm-12345678"), None).unwrap();
        let after_mm: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let env = after_mm.get("env").unwrap();

        assert!(
            env.get("CLAUDE_CODE_SUBAGENT_MODEL").is_none(),
            "DeepSeek's CLAUDE_CODE_SUBAGENT_MODEL must be purged on rebind to MiniMax"
        );
        assert!(
            env.get("CLAUDE_CODE_EFFORT_LEVEL").is_none(),
            "DeepSeek's CLAUDE_CODE_EFFORT_LEVEL must be purged on rebind to MiniMax"
        );
        // Sanity: MiniMax-shaped keys are present.
        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").unwrap(),
            "https://api.minimax.io/anthropic"
        );
    }

    /// Inverse of `rebind_from_deepseek_to_mm_purges_deepseek_extras`:
    /// rebinding from MiniMax (no extras) to DeepSeek (3 extras) must
    /// land DeepSeek's extras cleanly. Round 2 LOW-1.
    #[test]
    fn rebind_from_mm_to_deepseek_lands_deepseek_extras() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(7u16).unwrap();

        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-mm-12345678"), None).unwrap();
        bind_provider_to_slot(dir.path(), "deepseek", slot, Some("sk-test-deepseek"), None)
            .unwrap();

        let path = dir.path().join("config-7/settings.json");
        let json: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let env = json.get("env").unwrap();

        assert_eq!(
            env.get("ANTHROPIC_BASE_URL").unwrap(),
            "https://api.deepseek.com/anthropic"
        );
        assert_eq!(
            env.get("ANTHROPIC_DEFAULT_HAIKU_MODEL").unwrap(),
            "deepseek-v4-flash"
        );
        assert_eq!(
            env.get("CLAUDE_CODE_SUBAGENT_MODEL").unwrap(),
            "deepseek-v4-flash"
        );
        assert_eq!(env.get("CLAUDE_CODE_EFFORT_LEVEL").unwrap(), "max");
    }

    /// Regression: unbind MUST also remove `provider.extra_env` keys
    /// that bind wrote, otherwise rebinding to a different provider
    /// inherits orphan extras.
    #[test]
    fn unbind_removes_provider_extra_env_keys() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(6u16).unwrap();

        bind_provider_to_slot(dir.path(), "deepseek", slot, Some("sk-test-deepseek"), None)
            .unwrap();
        unbind_provider_from_slot(dir.path(), slot).unwrap();

        let content =
            std::fs::read_to_string(dir.path().join("config-6/settings.json")).unwrap_or_default();
        // Either the file is gone (env block emptied + collapsed) or
        // the env block is empty / missing the extras.
        if !content.is_empty() {
            let json: Value = serde_json::from_str(&content).unwrap();
            if let Some(env) = json.get("env") {
                assert!(
                    env.get("CLAUDE_CODE_SUBAGENT_MODEL").is_none(),
                    "CLAUDE_CODE_SUBAGENT_MODEL must be removed by unbind"
                );
                assert!(
                    env.get("CLAUDE_CODE_EFFORT_LEVEL").is_none(),
                    "CLAUDE_CODE_EFFORT_LEVEL must be removed by unbind"
                );
            }
        }
    }

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

    /// M4-9 (release N affordance, an internal ticket Phase 4): the test
    /// formerly named `bind_creates_profile_entry` is REPLACED here
    /// with the M4-9-compliant assertion. 3P bindings no longer
    /// populate the v1 `profiles.accounts` map; the slot's provider
    /// identity is carried by `settings.json` (env keys, model keys,
    /// provider-id stash) plus the `.csq-account` marker. Discovery
    /// reads provider identity from `settings.json`, not from
    /// `profiles.accounts` — see `bind_makes_slot_discoverable_as_third_party`.
    #[test]
    fn bind_third_party_does_not_populate_v1_accounts_map() {
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(9u16).unwrap();

        bind_provider_to_slot(dir.path(), "zai", slot, Some("key-zai-123"), None).unwrap();

        // M4-13: accounts struct field removed; verify the key is absent from
        // extra (or is an empty object) to confirm bind_provider_to_slot does
        // not write v1 accounts entries.
        let profiles_file = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        let accounts_in_extra = profiles_file
            .extra
            .get("accounts")
            .and_then(|v| v.as_object());
        assert!(
            accounts_in_extra.is_none() || accounts_in_extra.is_some_and(|m| m.is_empty()),
            "M4-9/M4-13: bind_provider_to_slot MUST NOT populate v1 accounts map; \
             got extra[\"accounts\"]: {:?}",
            profiles_file.extra.get("accounts")
        );
        // Sanity: the marker write still happened.
        let marker = dir.path().join("config-9/.csq-account");
        assert!(marker.exists(), "marker write must still happen");
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

    /// M4-9 update: `bind_provider_to_slot` no longer populates the v1
    /// `accounts[slot]` row, but it MUST still preserve any v1
    /// `accounts` entries that EXIST on disk (the v2.6.x downgrade
    /// compat seam or a populated row from `update_email`'s rename
    /// channel). The bind code path goes through `profiles::load` +
    /// `profiles::save` to preserve the file's overall shape.
    #[test]
    fn bind_preserves_other_profile_entries() {
        let dir = TempDir::new().unwrap();

        // Pre-seed profiles.json with another account's v1 row (simulates
        // either a v2.6.x downgrade re-save OR a user-renamed slot label).
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
        // Pre-existing extra["accounts"][1] survives the bind operation.
        // M4-13: get_email no longer reads from extra["accounts"]; use accounts_for_test.
        assert_eq!(
            loaded
                .accounts_for_test()
                .get("1")
                .map(|p| p.email.as_str()),
            Some("alice@example.com"),
            "extra[accounts][1].email must survive bind_provider_to_slot"
        );
        // M4-9: bind does NOT populate accounts[9] (the post-M4-9 contract).
        assert!(
            loaded.get_profile(9).is_none(),
            "M4-9: bind MUST NOT populate v1 accounts[9]; got: {:?}",
            loaded.get_profile(9)
        );
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
    // ── M7: by_slot_identity write hook ───────────────────────────────────

    /// M7: `bind_provider_to_slot` must write `by_slot_identity[N] =
    /// "apikey:<provider_id>"` into `profiles.json` in the same
    /// `ProfilesFileLock` window as the settings env-block fan-out.
    #[test]
    fn bind_provider_to_slot_writes_by_slot_identity() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let slot = AccountNum::try_from(5u16).unwrap();

        // Act
        bind_provider_to_slot(dir.path(), "mm", slot, Some("sk-test-mm-abc123"), None).unwrap();

        // Assert: profiles.json contains by_slot_identity["5"] == "apikey:mm"
        let profiles_file = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert_eq!(
            profiles_file.by_slot_identity.get("5").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[5] must be 'apikey:mm' after bind; got: {:?}",
            profiles_file.by_slot_identity.get("5")
        );
    }

    /// M7 / PD-3: `bind_provider_to_slot` acquires `ProfilesFileLock`
    /// before touching profiles.json. We verify this by holding the lock
    /// in a background thread and asserting the foreground call blocks
    /// until the lock is released. Mirrors the `logout_acquires_profiles_lock`
    /// (R5-MED-1) pattern in `accounts::logout`.
    #[test]
    fn bind_provider_to_slot_acquires_profiles_lock() {
        use crate::accounts::profiles_lock::ProfilesFileLock;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        // Arrange
        let dir = TempDir::new().unwrap();

        // Shared flag: set to true when bind completes
        let bind_completed = Arc::new(Mutex::new(false));
        let bind_completed_bg = Arc::clone(&bind_completed);

        let dir_path = dir.path().to_path_buf();

        // Hold the lock in a background thread for a short window, then
        // signal when acquired so the main thread can proceed.
        let (tx_locked, rx_locked) = std::sync::mpsc::channel::<()>();
        let (tx_release, rx_release) = std::sync::mpsc::channel::<()>();

        let _bg = std::thread::spawn(move || {
            let _lock = ProfilesFileLock::acquire(&dir_path).unwrap();
            tx_locked.send(()).unwrap();
            // Hold until signalled
            rx_release.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(_lock);
            *bind_completed_bg.lock().unwrap() = true;
        });

        // Wait until background thread holds the lock
        rx_locked
            .recv_timeout(Duration::from_secs(2))
            .expect("background thread must acquire lock");

        // Kick off bind in another thread (it will block on the ProfilesFileLock)
        let dir_path2 = dir.path().to_path_buf();
        let bind_done = Arc::new(Mutex::new(false));
        let bind_done2 = Arc::clone(&bind_done);

        let bind_thread = std::thread::spawn(move || {
            // This will block until the background lock is released
            bind_provider_to_slot(
                &dir_path2,
                "mm",
                AccountNum::try_from(5u16).unwrap(),
                Some("sk-test-mm-locktest"),
                None,
            )
            .unwrap();
            *bind_done2.lock().unwrap() = true;
        });

        // Give the bind thread a moment to start and block on the lock
        std::thread::sleep(Duration::from_millis(50));

        // Verify it hasn't completed yet (still blocked on ProfilesFileLock)
        assert!(
            !*bind_done.lock().unwrap(),
            "bind_provider_to_slot must not complete while ProfilesFileLock is held by another thread"
        );

        // Release the background lock
        tx_release.send(()).unwrap();

        // Wait for bind thread to finish
        bind_thread.join().expect("bind thread must not panic");

        // Verify bind completed after lock was released
        assert!(
            *bind_done.lock().unwrap(),
            "bind_provider_to_slot must complete after ProfilesFileLock is released"
        );

        // Sanity: by_slot_identity was written correctly after the lock race
        let profiles_file = profiles::load(&profiles::profiles_path(dir.path())).unwrap();
        assert_eq!(
            profiles_file.by_slot_identity.get("5").map(|s| s.as_str()),
            Some("apikey:mm"),
            "by_slot_identity[5] must be 'apikey:mm' after lock-raced bind"
        );
    }

    // ── VP-H1 concurrency guards ───────────────────────────────────────────

    /// VP-H1 (HIGH): two threads both calling `bind_provider_to_slot` on
    /// the same slot with different providers must serialize their RMWs.
    /// The final settings.json must contain exactly ONE provider's env
    /// block — no merge corruption or lost update is acceptable.
    ///
    /// We cannot assert WHICH provider wins (scheduling-dependent),
    /// but we can assert the JSON is well-formed and contains exactly one
    /// consistent ANTHROPIC_BASE_URL (not a partial overlay from both).
    #[test]
    fn bind_provider_serializes_concurrent_binds() {
        {
            let dir = TempDir::new().unwrap();
            let slot = AccountNum::try_from(8u16).unwrap();
            let base = dir.path().to_path_buf();

            let base_mm = base.clone();
            let t1 = std::thread::spawn(move || {
                {
                    bind_provider_to_slot(
                        &base_mm,
                        "mm",
                        slot,
                        Some("sk-test-minimax-thread1"),
                        None,
                    )
                }
            });
            let base_zai = base.clone();
            let t2 = std::thread::spawn(move || {
                {
                    bind_provider_to_slot(&base_zai, "zai", slot, Some("sk-test-zai-thread2"), None)
                }
            });

            t1.join().unwrap().expect("bind mm must succeed");
            t2.join().unwrap().expect("bind zai must succeed");

            // The resulting file must be valid JSON — no partial write or
            // interleaving that corrupts the structure.
            let settings_path = base.join("config-8/settings.json");
            let content = std::fs::read_to_string(&settings_path).unwrap();
            let json: Value = serde_json::from_str(&content)
                .expect("settings.json must be valid JSON after concurrent binds");

            // The env block must have a consistent ANTHROPIC_BASE_URL
            // (either MiniMax's or Z.AI's — not a mixed or missing value).
            let base_url = json
                .get("env")
                .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
                .and_then(|v| v.as_str())
                .expect("ANTHROPIC_BASE_URL must be present");
            let valid_urls = [
                "https://api.minimax.io/anthropic",
                "https://api.z.ai/api/anthropic",
            ];
            assert!(
                valid_urls.contains(&base_url),
                "ANTHROPIC_BASE_URL must be one complete provider URL, got: {base_url}"
            );

            // The auth token must be one of the two exact keys — no interleaving.
            let auth_token = json
                .get("env")
                .and_then(|e| e.get("ANTHROPIC_AUTH_TOKEN"))
                .and_then(|v| v.as_str())
                .expect("ANTHROPIC_AUTH_TOKEN must be present");
            assert!(
                auth_token == "sk-test-minimax-thread1" || auth_token == "sk-test-zai-thread2",
                "ANTHROPIC_AUTH_TOKEN must be one of the two written keys, got: {auth_token}"
            );
        }
    }

    /// VP-H1 (HIGH): one thread binds while another unbinds concurrently
    /// on the same slot. The final state must be deterministic — either
    /// fully bound or fully unbound (not interleaved or corrupted).
    #[test]
    fn bind_and_unbind_serialize_same_lock() {
        {
            let dir = TempDir::new().unwrap();
            let slot = AccountNum::try_from(9u16).unwrap();
            let base = dir.path().to_path_buf();

            // Pre-seed the slot so unbind has something to remove.
            bind_provider_to_slot(&base, "mm", slot, Some("sk-test-mm-seed-key12"), None).unwrap();

            let base_bind = base.clone();
            let t_bind = std::thread::spawn(move || {
                {
                    bind_provider_to_slot(
                        &base_bind,
                        "zai",
                        slot,
                        Some("sk-test-zai-rebind-key"),
                        None,
                    )
                }
            });
            let base_unbind = base.clone();
            let t_unbind =
                std::thread::spawn(move || unbind_provider_from_slot(&base_unbind, slot));

            t_bind.join().unwrap().expect("bind must succeed");
            t_unbind.join().unwrap().expect("unbind must succeed");

            let settings_path = base.join("config-9/settings.json");

            // Outcome A: unbind won — file is gone or has no 3P keys.
            // Outcome B: bind won — file has a valid 3P env block from zai.
            // Both are acceptable. What is NOT acceptable: malformed JSON.
            if settings_path.exists() {
                {
                    let content = std::fs::read_to_string(&settings_path).unwrap();
                    let json: Value = serde_json::from_str(&content)
                        .expect("settings.json must be valid JSON after concurrent bind+unbind");
                    assert!(
                        json.is_object(),
                        "settings.json root must be a JSON object, got: {json}"
                    );
                }
            }
        }
    }
}
