//! Shared settings-write helpers used by both CLI and desktop model-switch
//! paths.
//!
//! # Phase 2 UUID routing
//!
//! `write_slot_model_with_uuid_routing` is the single chokepoint for the
//! "switch active model for a slot" operation. It resolves the settings.json
//! write target through the UUID identity store when a UUID mapping is present
//! (Phase 2 canonical path), falling back to `config-{slot}/settings.json`
//! when not.
//!
//! Both callers (CLI `csq models --set` and desktop `set_slot_model`) MUST call
//! this function — never inline the routing logic separately. Single source
//! eliminates the bypass class that manifested as HIGH in M2-7 redteam round 1.
//!
//! See `internal-design-docs § M2-7`.

use std::path::{Path, PathBuf};

use crate::accounts::identity_store::settings_path_for;
use crate::accounts::profiles;
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use crate::session::merge::MODEL_KEYS;
use crate::types::AccountNum;
use serde_json::Value;

/// Writes `model_id` into every `MODEL_KEYS` entry in the slot's active
/// `settings.json`, routing through UUID-canonical path when present.
///
/// # Resolution order (Phase 2)
///
/// 1. If `profiles.json` maps `slot` to a UUID **and**
///    `identities/<UUID>/settings.json` exists → use that file.
/// 2. Otherwise fall back to `config-{slot}/settings.json`.
///
/// # §5a invariant
///
/// The tmp file written by this function may carry an `ANTHROPIC_AUTH_TOKEN`
/// env var. All failure branches `remove_file` the tmp before returning.
///
/// # Errors
///
/// Returns a `String` error (Tauri-command-compatible) rather than `anyhow::Error`
/// so the function is callable from both CLI (`anyhow::Error` via `.map_err`)
/// and desktop (`String` result boundary).
pub fn write_slot_model_with_uuid_routing(
    base_dir: &Path,
    slot: AccountNum,
    model_id: &str,
) -> Result<(), String> {
    // PATH-BUILDER: legacy fallback — only used when UUID path is absent.
    // The UUID path (below) is the Phase 2 READER target.
    // Unchanged through Phase 2 — see 03-phase2-readiness.md § M2-7.
    let legacy_path = legacy_settings_path(base_dir, slot);

    // M2-7 READER routing: resolve UUID first.
    let settings_path = profiles::resolve_slot_to_uuid(base_dir, slot.get())
        .map(|uuid| settings_path_for(base_dir, uuid))
        .filter(|p| p.exists())
        .unwrap_or(legacy_path);

    let content = std::fs::read_to_string(&settings_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "slot {slot} is not bound — add it via the Add Account modal or `csq setkey` first"
            )
        } else {
            format!(
                "read {}: {e}",
                crate::cli_deps::sanitize::redact_path(&settings_path)
            )
        }
    })?;

    let mut value: Value = serde_json::from_str(&content).map_err(|e| {
        format!(
            "{} is not valid JSON: {e}",
            crate::cli_deps::sanitize::redact_path(&settings_path)
        )
    })?;

    let env = value
        .as_object_mut()
        .and_then(|o| o.get_mut("env"))
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| {
            format!(
                "{} has no `env` object — can't set model",
                crate::cli_deps::sanitize::redact_path(&settings_path)
            )
        })?;

    for key in MODEL_KEYS {
        env.insert((*key).to_string(), Value::String(model_id.to_string()));
    }

    let json = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("serialize slot settings: {e}"))?;

    let tmp = unique_tmp_path(&settings_path);
    // §5a: settings.json may carry ANTHROPIC_AUTH_TOKEN — clean up tmp on
    // every error branch so a partial write doesn't leak the token at
    // umask-default 0o644.
    if let Err(e) = std::fs::write(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "write tmp {}: {e}",
            crate::cli_deps::sanitize::redact_path(&tmp)
        ));
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("secure_file: {e}"));
    }
    if let Err(e) = atomic_replace(&tmp, &settings_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("atomic replace: {e}"));
    }
    Ok(())
}

/// Returns `<base_dir>/config-{slot}/settings.json` — the legacy (Phase 1)
/// settings path, used as a fallback when no UUID mapping is present.
///
/// This is a PATH-BUILDER: it constructs a path string and does NOT read
/// settings content. Phase 3 will retire this helper once all slots have
/// UUID mappings and the legacy mirror is removed.
fn legacy_settings_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    base_dir
        .join(format!("config-{}", slot))
        .join("settings.json")
}

#[cfg(any(test, feature = "test-utils"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::identity_fixtures::{coexisting_fixture, fixture_uuid_for_slot};
    use tempfile::TempDir;

    /// Verify that the shared chokepoint routes to `identities/<UUID>/settings.json`
    /// when a UUID mapping is present, and does NOT touch the legacy path.
    ///
    /// This mirrors the CLI acceptance criterion
    /// `models_command_resolves_settings_from_uuid_when_present` but tests the
    /// shared helper directly, confirming both CLI and desktop call the same logic.
    #[test]
    fn write_slot_model_routes_to_uuid_when_present() {
        use crate::accounts::identity_store::settings_path_for;
        use crate::credentials::write_uuid_settings;

        let slot_num: u16 = 5;
        let slot = AccountNum::try_from(slot_num).unwrap();

        // Use coexisting_fixture to set up the slot→UUID mapping + config-N/
        // (creates slots 1..=5 with both legacy config-N/ and identities/<UUID>/)
        let dir = coexisting_fixture(slot_num);
        let base = dir.path();

        // Write UUID settings.json with a known value.
        let uuid = fixture_uuid_for_slot(slot_num);
        let uuid_json =
            r#"{"env":{"ANTHROPIC_MODEL":"uuid-original","CLAUDE_MODEL":"uuid-original"}}"#;
        write_uuid_settings(base, uuid, uuid_json.as_bytes()).unwrap();

        // Write legacy settings.json with a different value.
        let legacy_settings = base
            .join(format!("config-{slot_num}"))
            .join("settings.json");
        std::fs::create_dir_all(legacy_settings.parent().unwrap()).unwrap();
        std::fs::write(
            &legacy_settings,
            r#"{"env":{"ANTHROPIC_MODEL":"legacy-model","CLAUDE_MODEL":"legacy-model"}}"#,
        )
        .unwrap();

        // Act.
        write_slot_model_with_uuid_routing(base, slot, "new-model").unwrap();

        // Assert UUID settings.json has new-model.
        let uuid_content = std::fs::read_to_string(settings_path_for(base, uuid)).unwrap();
        let uuid_val: serde_json::Value = serde_json::from_str(&uuid_content).unwrap();
        for key in MODEL_KEYS {
            assert_eq!(
                uuid_val
                    .pointer(&format!("/env/{key}"))
                    .and_then(|x| x.as_str()),
                Some("new-model"),
                "UUID settings.json must have new-model for {key}"
            );
        }

        // Assert legacy settings.json is NOT updated.
        let legacy_content = std::fs::read_to_string(&legacy_settings).unwrap();
        let legacy_val: serde_json::Value = serde_json::from_str(&legacy_content).unwrap();
        assert_eq!(
            legacy_val
                .pointer("/env/ANTHROPIC_MODEL")
                .and_then(|x| x.as_str()),
            Some("legacy-model"),
            "legacy settings.json must NOT be updated when UUID path is present"
        );
    }

    /// Without a UUID mapping (or with UUID settings.json absent), the helper
    /// falls back to the legacy config-N/settings.json path.
    #[test]
    fn write_slot_model_falls_back_to_legacy_when_no_uuid() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot_num: u16 = 2;
        let slot = AccountNum::try_from(slot_num).unwrap();

        // Only legacy settings.json — no profiles.json, no UUID dir.
        let legacy_settings = base
            .join(format!("config-{slot_num}"))
            .join("settings.json");
        std::fs::create_dir_all(legacy_settings.parent().unwrap()).unwrap();
        std::fs::write(
            &legacy_settings,
            r#"{"env":{"ANTHROPIC_MODEL":"old-model","CLAUDE_MODEL":"old-model"}}"#,
        )
        .unwrap();

        write_slot_model_with_uuid_routing(base, slot, "switched-model").unwrap();

        let content = std::fs::read_to_string(&legacy_settings).unwrap();
        let val: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            val.pointer("/env/ANTHROPIC_MODEL").and_then(|x| x.as_str()),
            Some("switched-model")
        );
    }
}
