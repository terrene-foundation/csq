//! Settings drift reassertion — `reassert_settings_drift`
//! (layer-OFF back-compat wrapper) +
//! `reassert_settings_drift_with_system_instruction` (layer-ON
//! path with explicit directive).
//!
//! **Earlier revisions** of this module shipped these symbols as
//! `reassert_api_key_selected_type[_with_system_instruction]` and framed
//! the work as a ToS-driven defense that always pinned
//! `security.auth.selectedType = "gemini-api-key"` on every spawn. That
//! framing was retracted in journal 0048 — the selectedType pin is a UX
//! shortcut for API-key slots so gemini-cli does not interactively
//! prompt on first spawn, not policy enforcement. Stage 2 of journal
//! 0048 renamed the symbols to match the actual semantic surface and
//! made the writer binding-mode-aware: write `selectedType` ONLY for
//! slots bound to an API key (or Vertex SA — same UX-shortcut shape);
//! Code Assist OAuth slots leave the field unset so gemini-cli's
//! auto-discovery picks up `~/.gemini/oauth_creds.json`.
//!
//! Called from [`super::spawn::spawn_gemini`] before every exec
//! (layer-OFF) and from csq-cli's `launch_gemini` with-layer arm
//! (layer-ON, PR-CA8b commit 4).
//!
//! Per OPEN-G01 (journal 0003 RESOLVED): the handle-dir variant
//! fully wins over user-level `~/.gemini/settings.json`, so
//! re-assertion is a cheap atomic write — NOT a rename of the
//! user's home-directory file.
//!
//! # `system_instruction` ownership semantics (round-3 R3-H1)
//!
//! csq owns the field ONLY when the capability layer is active for a
//! spawn. The layer-OFF (Inherit) path through
//! `reassert_settings_drift` PRESERVES any existing
//! `system_instruction` value verbatim — whether user-authored OR
//! written by a prior layer-on spawn. This avoids silent user-
//! content loss (the same failure mode round-1 H2 was created to
//! prevent for codex `instructions`).

use super::provisioning::AuthMode;
use super::settings::{
    extract_model_name, extract_selected_type, extract_system_instruction,
    merge_managed_into_existing, SELECTED_TYPE_API_KEY, SELECTED_TYPE_OAUTH_PERSONAL,
};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use std::path::{Path, PathBuf};

/// Maps a binding's auth mode to the `pin_selected_type` parameter
/// the settings writer expects.
///
/// - `ApiKey` / `VertexSa` → `Some(SELECTED_TYPE_API_KEY)` — UX
///   shortcut so gemini-cli does not interactively prompt for auth
///   choice on first spawn.
/// - `CodeAssistOAuth` → `Some(SELECTED_TYPE_OAUTH_PERSONAL)`. Journal
///   0054 — gemini-cli v0.41.2 does NOT auto-discover
///   `~/.gemini/oauth_creds.json` when `selectedType` is unset; it
///   prompts for auth method interactively on every first-run-into-a-
///   project. Pinning `"oauth-personal"` tells gemini-cli "use the
///   existing OAuth creds at ~/.gemini/oauth_creds.json, skip the
///   picker." This matches the value gemini-cli itself writes after
///   the user selects "Sign in with Google" interactively.
fn pin_selected_type_for(auth_mode: &AuthMode) -> Option<&'static str> {
    match auth_mode {
        AuthMode::ApiKey | AuthMode::VertexSa { .. } => Some(SELECTED_TYPE_API_KEY),
        AuthMode::CodeAssistOAuth => Some(SELECTED_TYPE_OAUTH_PERSONAL),
    }
}

/// Errors raised by the settings-reassertion writer.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// Could not stat or read the handle-dir's settings file path
    /// for reasons other than file-not-found (which is
    /// handled silently — a missing file is just "drifted from
    /// empty").
    #[error("settings.json read I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Atomic rewrite failure. The file may be in an inconsistent
    /// state and the spawn MUST be aborted.
    #[error("settings.json rewrite failed at {path}: {reason}")]
    RewriteFailed { path: PathBuf, reason: String },
}

/// Outcome of one settings-reassertion pass — exposed so the audit
/// log and `csq doctor` can report whether re-assertion fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftOutcome {
    /// settings.json was missing or empty — wrote a fresh template.
    SeededFresh,
    /// settings.json was present and ALL csq-managed fields matched
    /// the requested values — no rewrite needed.
    AlreadyCorrect,
    /// settings.json was present but at least one csq-managed field
    /// drifted — re-asserted the managed fields (preserving any
    /// unmanaged top-level keys).
    Corrected,
}

/// Layer-OFF back-compat wrapper. Re-asserts the two permanently-csq-
/// managed fields (`security.auth.selectedType` and `model.name`)
/// while PRESERVING any existing `system_instruction` value verbatim
/// (whether user-authored or written by a prior layer-on spawn).
///
/// Round-3 R3-H1 semantics: csq owns `system_instruction` only when
/// the capability layer is active for a spawn. The layer-OFF
/// (Inherit) path delegates here; the layer-ON path calls
/// [`reassert_settings_drift_with_system_instruction`]
/// directly with the requested directive.
///
/// Idempotent. Atomic. Mode 0o600 enforced via `secure_file` after
/// the rewrite.
pub fn reassert_settings_drift(
    handle_dir: &Path,
    model_name: &str,
    auth_mode: &AuthMode,
) -> Result<DriftOutcome, ProbeError> {
    // Read existing system_instruction (if any) and forward it as
    // the "requested" value — preserve-not-strip semantics on the
    // layer-OFF path.
    let preserved_instruction = read_existing_system_instruction(handle_dir);
    reassert_with_system_instruction_internal(
        handle_dir,
        model_name,
        preserved_instruction.as_deref(),
        auth_mode,
    )
}

/// Layer-ON path. Re-asserts all THREE csq-managed fields including
/// `system_instruction` (the capability-layer scaffold). Overwrites
/// any prior `system_instruction` value — csq owns the field while
/// the layer is engaged.
///
/// Called from csq-cli's `launch_gemini` with-layer arm with the
/// scaffold built by `ScaffoldStage`. Idempotent.
pub fn reassert_settings_drift_with_system_instruction(
    handle_dir: &Path,
    model_name: &str,
    requested_system_instruction: Option<&str>,
    auth_mode: &AuthMode,
) -> Result<DriftOutcome, ProbeError> {
    reassert_with_system_instruction_internal(
        handle_dir,
        model_name,
        requested_system_instruction,
        auth_mode,
    )
}

/// Read-side helper. Returns the existing `system_instruction` value
/// from the handle-dir settings.json, or `None` if the file is
/// missing, malformed, or has no such field.
fn read_existing_system_instruction(handle_dir: &Path) -> Option<String> {
    let settings_path = handle_dir.join(".gemini").join("settings.json");
    let content = std::fs::read_to_string(&settings_path).ok()?;
    extract_system_instruction(&content)
}

/// Shared implementation. Read existing → AlreadyCorrect gate
/// matches all 3 csq-managed fields → JSON-merge writer (preserves
/// unmanaged top-level keys) → atomic write.
fn reassert_with_system_instruction_internal(
    handle_dir: &Path,
    model_name: &str,
    requested_system_instruction: Option<&str>,
    auth_mode: &AuthMode,
) -> Result<DriftOutcome, ProbeError> {
    let gemini_dir = handle_dir.join(".gemini");
    let settings_path = gemini_dir.join("settings.json");
    let pin = pin_selected_type_for(auth_mode);

    let existing = match std::fs::read_to_string(&settings_path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(ProbeError::Io {
                path: settings_path,
                source: e,
            });
        }
    };

    // Widened AlreadyCorrect gate (round-3 C3): ALL csq-managed
    // fields must match. Prior PR-CA7c gated only on selectedType,
    // which silently dropped per-spawn directive injection on every
    // post-first spawn.
    //
    // Stage 2 of journal 0048: for OAuth bindings (`pin == None`),
    // the writer does not manage `selectedType`, so the gate skips
    // that comparison.
    if let Some(content) = &existing {
        let selected_correct = match pin {
            Some(expected) => extract_selected_type(content).as_deref() == Some(expected),
            None => true, // not csq-managed for OAuth bindings
        };
        let model_correct = extract_model_name(content).as_deref() == Some(model_name);
        let instruction_correct =
            extract_system_instruction(content).as_deref() == requested_system_instruction;
        if selected_correct && model_correct && instruction_correct {
            return Ok(DriftOutcome::AlreadyCorrect);
        }
    }

    // (Re)write the JSON-merged template. Always recreate the parent
    // dir; on SeededFresh the parent may not exist yet.
    if let Err(e) = std::fs::create_dir_all(&gemini_dir) {
        return Err(ProbeError::Io {
            path: gemini_dir,
            source: e,
        });
    }
    let body = merge_managed_into_existing(
        existing.as_deref(),
        model_name,
        requested_system_instruction,
        pin,
    );
    let tmp = unique_tmp_path(&settings_path);
    if let Err(e) = std::fs::write(&tmp, body.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProbeError::Io {
            path: tmp,
            source: e,
        });
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProbeError::RewriteFailed {
            path: settings_path,
            reason: format!("secure_file: {e}"),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &settings_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ProbeError::RewriteFailed {
            path: settings_path,
            reason: format!("atomic replace: {e}"),
        });
    }

    Ok(if existing.is_some() {
        DriftOutcome::Corrected
    } else {
        DriftOutcome::SeededFresh
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn seeds_fresh_when_missing() {
        let dir = TempDir::new().unwrap();
        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::ApiKey).unwrap();
        assert_eq!(outcome, DriftOutcome::SeededFresh);
        let written = std::fs::read_to_string(dir.path().join(".gemini/settings.json")).unwrap();
        assert_eq!(
            extract_selected_type(&written).as_deref(),
            Some("gemini-api-key")
        );
    }

    #[test]
    fn no_op_when_already_correct() {
        let dir = TempDir::new().unwrap();
        // Seed first.
        reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::ApiKey).unwrap();
        let path = dir.path().join(".gemini/settings.json");
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        // Tiny sleep to ensure mtime resolution would tick if rewritten.
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Second call must be AlreadyCorrect.
        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::ApiKey).unwrap();
        assert_eq!(outcome, DriftOutcome::AlreadyCorrect);
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "must not rewrite when correct");
    }

    #[test]
    fn corrects_when_drifted_to_oauth_personal() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#,
        )
        .unwrap();

        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::ApiKey).unwrap();
        assert_eq!(outcome, DriftOutcome::Corrected);
        let written = std::fs::read_to_string(gemini_dir.join("settings.json")).unwrap();
        assert_eq!(
            extract_selected_type(&written).as_deref(),
            Some("gemini-api-key")
        );
    }

    #[test]
    fn corrects_unparseable_content_by_overwriting() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(gemini_dir.join("settings.json"), "{ this is not json").unwrap();

        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::ApiKey).unwrap();
        // Unparseable counts as "selectedType not present" → drifted.
        assert_eq!(outcome, DriftOutcome::Corrected);
    }

    // ============================================================
    // Stage 2 of journal 0048 — binding-mode-aware writer
    // ============================================================

    /// Journal 0054 — OAuth bindings now PIN
    /// `selectedType="oauth-personal"` on a fresh handle dir. Previously
    /// (Stage 2 of journal 0048) the field was left unset on the
    /// assumption that gemini-cli would auto-discover
    /// `~/.gemini/oauth_creds.json`. v0.41.2 disproved that assumption:
    /// without `selectedType` pinned, gemini-cli prompts interactively
    /// for auth method on every first-run-into-a-project.
    #[test]
    fn oauth_binding_seeds_fresh_with_oauth_personal_selected_type() {
        let dir = TempDir::new().unwrap();
        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::CodeAssistOAuth)
                .unwrap();
        assert_eq!(outcome, DriftOutcome::SeededFresh);
        let written = std::fs::read_to_string(dir.path().join(".gemini/settings.json")).unwrap();
        assert_eq!(
            extract_selected_type(&written).as_deref(),
            Some("oauth-personal"),
            "OAuth binding must pin selectedType=oauth-personal (journal 0054), got: {written}"
        );
        // model.name still pinned (csq-managed for all modes).
        assert_eq!(
            extract_model_name(&written).as_deref(),
            Some("gemini-2.5-pro")
        );
    }

    /// OAuth bindings PRESERVE an existing
    /// `selectedType=oauth-personal` (no rewrite needed when value
    /// already matches the pinned target).
    #[test]
    fn oauth_binding_preserves_existing_oauth_personal_selected_type() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{"security":{"auth":{"selectedType":"oauth-personal"}},"model":{"name":"gemini-2.5-pro"}}"#,
        )
        .unwrap();

        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::CodeAssistOAuth)
                .unwrap();
        // Journal 0054: pinned target == existing value → AlreadyCorrect.
        assert_eq!(outcome, DriftOutcome::AlreadyCorrect);
        let written = std::fs::read_to_string(gemini_dir.join("settings.json")).unwrap();
        assert_eq!(
            extract_selected_type(&written).as_deref(),
            Some("oauth-personal"),
            "OAuth binding must preserve existing selectedType: {written}"
        );
    }

    /// Journal 0054 — when an OAuth binding's handle dir has a stale
    /// `selectedType=gemini-api-key` (e.g. user previously had an API
    /// key in this slot, then re-bound to OAuth), reassert_settings_drift
    /// MUST overwrite with `oauth-personal` so gemini-cli does not
    /// fall back to API-key prompt.
    #[test]
    fn oauth_binding_corrects_stale_api_key_selected_type() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{"security":{"auth":{"selectedType":"gemini-api-key"}},"model":{"name":"gemini-2.5-pro"}}"#,
        )
        .unwrap();

        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::CodeAssistOAuth)
                .unwrap();
        assert_eq!(outcome, DriftOutcome::Corrected);
        let written = std::fs::read_to_string(gemini_dir.join("settings.json")).unwrap();
        assert_eq!(
            extract_selected_type(&written).as_deref(),
            Some("oauth-personal"),
            "stale gemini-api-key must be overwritten to oauth-personal: {written}"
        );
    }

    // ============================================================
    // PR-CA8b commit 4 — layer-ON / layer-OFF split (round-3 R3-H1)
    // ============================================================

    /// PR-CA8b R3-H1: layer-OFF wrapper preserves user-authored
    /// `system_instruction` value verbatim. Critical regression
    /// guard against the round-3 finding that the back-compat
    /// wrapper would otherwise strip user content.
    #[test]
    fn gemini_writer_layer_off_preserves_user_authored_system_instruction() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{
                "security": {"auth": {"selectedType": "gemini-api-key"}},
                "model": {"name": "gemini-2.5-pro"},
                "system_instruction": "user said: be terse"
            }"#,
        )
        .unwrap();

        // Layer-OFF call (the back-compat wrapper).
        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::ApiKey).unwrap();
        // AlreadyCorrect — preserved instruction matches itself.
        assert_eq!(outcome, DriftOutcome::AlreadyCorrect);
        let written = std::fs::read_to_string(gemini_dir.join("settings.json")).unwrap();
        assert_eq!(
            extract_system_instruction(&written).as_deref(),
            Some("user said: be terse")
        );
    }

    /// PR-CA8b R3-H1: layer-OFF wrapper preserves prior-layer scaffold
    /// (a layer-on spawn happened earlier; the layer-off bare-CLI
    /// spawn must not strip what the layer wrote).
    #[test]
    fn gemini_writer_layer_off_preserves_prior_layer_written_system_instruction() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{
                "security": {"auth": {"selectedType": "gemini-api-key"}},
                "model": {"name": "gemini-2.5-pro"},
                "system_instruction": "prior layer-on scaffold body"
            }"#,
        )
        .unwrap();

        let outcome =
            reassert_settings_drift(dir.path(), "gemini-2.5-pro", &AuthMode::ApiKey).unwrap();
        assert_eq!(outcome, DriftOutcome::AlreadyCorrect);
        let written = std::fs::read_to_string(gemini_dir.join("settings.json")).unwrap();
        assert!(
            written.contains("prior layer-on scaffold body"),
            "layer-off must preserve prior-layer content: {written}"
        );
    }

    /// PR-CA8b R3-H1: layer-ON path overwrites any existing
    /// `system_instruction` value (csq-owned during layer-on).
    #[test]
    fn gemini_writer_layer_on_overwrites_existing_system_instruction() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{
                "security": {"auth": {"selectedType": "gemini-api-key"}},
                "model": {"name": "gemini-2.5-pro"},
                "system_instruction": "old prior-layer scaffold"
            }"#,
        )
        .unwrap();

        // Layer-ON call with a NEW directive.
        let outcome = reassert_settings_drift_with_system_instruction(
            dir.path(),
            "gemini-2.5-pro",
            Some("NEW layer scaffold body"),
            &AuthMode::ApiKey,
        )
        .unwrap();
        assert_eq!(outcome, DriftOutcome::Corrected);
        let written = std::fs::read_to_string(gemini_dir.join("settings.json")).unwrap();
        assert_eq!(
            extract_system_instruction(&written).as_deref(),
            Some("NEW layer scaffold body")
        );
        assert!(
            !written.contains("old prior-layer scaffold"),
            "layer-on must overwrite prior content"
        );
    }

    /// PR-CA8b round-3 C3: widened AlreadyCorrect gate fires only
    /// when ALL THREE csq-managed fields match. If the directive
    /// changes, the gate must NOT fire (forces rewrite).
    #[test]
    fn reassert_settings_drift_with_system_instruction_forces_rewrite_when_directive_changes() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{
                "security": {"auth": {"selectedType": "gemini-api-key"}},
                "model": {"name": "gemini-2.5-pro"},
                "system_instruction": "OLD"
            }"#,
        )
        .unwrap();

        let outcome = reassert_settings_drift_with_system_instruction(
            dir.path(),
            "gemini-2.5-pro",
            Some("NEW"),
            &AuthMode::ApiKey,
        )
        .unwrap();
        assert_eq!(
            outcome,
            DriftOutcome::Corrected,
            "directive change must force rewrite"
        );
    }

    /// PR-CA8b: AlreadyCorrect when ALL three match.
    #[test]
    fn reassert_settings_drift_with_system_instruction_skips_when_already_correct() {
        let dir = TempDir::new().unwrap();
        // Seed via layer-on call.
        reassert_settings_drift_with_system_instruction(
            dir.path(),
            "gemini-2.5-pro",
            Some("scaffold body"),
            &AuthMode::ApiKey,
        )
        .unwrap();
        // Second call with identical inputs → AlreadyCorrect.
        let outcome = reassert_settings_drift_with_system_instruction(
            dir.path(),
            "gemini-2.5-pro",
            Some("scaffold body"),
            &AuthMode::ApiKey,
        )
        .unwrap();
        assert_eq!(outcome, DriftOutcome::AlreadyCorrect);
    }

    /// PR-CA8b R1-H2: writer preserves user-authored unmanaged
    /// top-level keys (mcpServers, ui.theme, etc.).
    #[test]
    fn gemini_settings_writer_preserves_unmanaged_keys() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{
                "security": {"auth": {"selectedType": "oauth-personal"}},
                "mcpServers": {"filesystem": {"command": "mcp-fs"}},
                "ui": {"theme": "dark"}
            }"#,
        )
        .unwrap();

        let outcome = reassert_settings_drift_with_system_instruction(
            dir.path(),
            "gemini-2.5-pro",
            Some("scaffold body"),
            &AuthMode::ApiKey,
        )
        .unwrap();
        assert_eq!(outcome, DriftOutcome::Corrected);
        let written = std::fs::read_to_string(gemini_dir.join("settings.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["mcpServers"]["filesystem"]["command"], "mcp-fs");
        assert_eq!(v["ui"]["theme"], "dark");
    }
}
