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
use crate::platform::fs::{atomic_replace, unique_tmp_path, write_new_private};
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
    let context_window = crate::providers::models::ModelCatalog::load(base_dir)
        .map_err(|_| "model manifest is invalid — can't size the context window".to_string())?
        .find(model_id)
        .and_then(|m| m.context_window);
    // Lock order is setkey's (accounts::third_party PD-3): ProfilesFileLock
    // FIRST — so the slot -> UUID routing below cannot change under us — then
    // the chosen file's `<file>.lock`; the file is read only under both.
    let _profiles = crate::accounts::profiles_lock::ProfilesFileLock::acquire(base_dir)
        .map_err(|_| format!("slot {slot} profiles lock unavailable (held by another csq process, or unusable) — retry"))?;
    // PATH-BUILDER: legacy fallback — only used when UUID path is absent.
    // The UUID path (below) is the Phase 2 READER target.
    // Unchanged through Phase 2 — see 03-phase2-readiness.md § M2-7.
    let legacy_path = legacy_settings_path(base_dir, slot);

    // M2-7 READER routing: resolve UUID first.
    let settings_path = profiles::resolve_slot_to_uuid(base_dir, slot.get())
        .map(|uuid| settings_path_for(base_dir, uuid))
        .filter(|p| p.exists())
        .unwrap_or(legacy_path);

    // An unbound slot has no settings dir to hold a lock file in: report it
    // as unbound (not as lock contention) before locking. The read below
    // still handles a file removed after this check.
    if matches!(std::fs::symlink_metadata(&settings_path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Err(format!(
            "slot {slot} is not bound — add it via the Add Account modal or `csq setkey` first"
        ));
    }
    // H1: hold the same `<file>.lock` that `csq setkey` / bind / unbind and
    // the Kimi migration hold, across this read -> modify -> write, so a
    // concurrent re-key is never overwritten by this switch's stale copy.
    // Expiry refuses the switch (fail closed). No caller (CLI `csq models
    // switch`, desktop `set_slot_model`) holds either lock.
    let _lock =
        match crate::platform::lock::lock_credential_file(&settings_path.with_extension("lock")) {
            Ok(Some(guard)) => guard,
            Ok(None) => {
                return Err(format!(
                    "slot {slot} settings are locked by another csq process — retry"
                ))
            }
            // COR LOW-3: the slot dir vanished after the unbound check —
            // that is "not bound", not lock contention.
            Err(crate::error::PlatformError::Io(e))
                if e.kind() == std::io::ErrorKind::NotFound =>
            {
                return Err(format!(
                    "slot {slot} is not bound — add it via the Add Account modal or `csq setkey` first"
                ))
            }
            // Not contention: the lock file itself cannot be opened/locked.
            Err(_) => {
                return Err(format!(
                    "slot {slot} settings lock could not be opened — check the slot directory's permissions"
                ))
            }
        };

    // COR LOW-1: under both locks, so the read must never block (a FIFO
    // would hang inside ProfilesFileLock) or follow a symlink: the bounded
    // no-follow read, 1 MiB cap.
    let content =
        match crate::platform::fs::read_regular_nofollow_bounded(&settings_path, 1024 * 1024) {
            Ok(Some(bytes)) => String::from_utf8(bytes).map_err(|_| {
                format!(
                    "{} is not valid UTF-8",
                    crate::cli_deps::sanitize::redact_path(&settings_path)
                )
            })?,
            Ok(None) => {
                return Err(format!(
                "slot {slot} is not bound — add it via the Add Account modal or `csq setkey` first"
            ))
            }
            Err(e) => {
                return Err(format!(
                    "read {}: not a regular file, too large, or I/O error ({})",
                    crate::cli_deps::sanitize::redact_path(&settings_path),
                    e.kind()
                ))
            }
        };

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

    // The window keys follow the selected model's manifest window (runtime
    // manifest, the same one `csq models switch` resolved the id against).
    crate::session::merge::set_model_env_for(env, model_id, context_window);

    write_settings_json_private(&settings_path, &value)
}

/// The one §5a writer for a slot/profile `settings.json` (it may carry
/// `ANTHROPIC_AUTH_TOKEN`): pretty JSON into a tmp created at 0o600
/// (`write_new_private`), then `atomic_replace`. Every failure branch removes
/// the tmp before returning. Shared by the model-switch chokepoint above and
/// the Kimi default-model migration (`session::kimi_migration`).
pub(crate) fn write_settings_json_private(
    settings_path: &Path,
    value: &Value,
) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(value).map_err(|e| format!("serialize slot settings: {e}"))?;
    write_settings_bytes_private(settings_path, json.as_bytes())
}

/// The byte-level half of [`write_settings_json_private`], for a caller that
/// already holds the exact bytes to persist (the Kimi migration's
/// order-preserving in-place edit). Same §5a contract.
pub(crate) fn write_settings_bytes_private(
    settings_path: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    let tmp = unique_tmp_path(settings_path);
    // §5a: settings.json may carry ANTHROPIC_AUTH_TOKEN. `write_new_private`
    // creates the tmp file at 0o600 at creation, closing the window a
    // separate std::fs::write + secure_file pair left open.
    if let Err(e) = write_new_private(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "write tmp {}: {e}",
            crate::cli_deps::sanitize::redact_path(&tmp)
        ));
    }
    if let Err(e) = atomic_replace(&tmp, settings_path) {
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
    use crate::session::merge::MODEL_KEYS;
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

    /// COR LOW-1: a FIFO at the slot settings path is refused at once,
    /// never blocking inside the switch's ProfilesFileLock.
    #[cfg(unix)]
    #[test]
    fn write_slot_model_refuses_a_fifo_without_blocking() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let slot = AccountNum::try_from(3u16).unwrap();
        let path = base.join("config-3").join("settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path for the call's duration.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let err = write_slot_model_with_uuid_routing(base, slot, "k3.1-pro").unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
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
