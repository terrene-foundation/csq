//! EP1 drift detector — `reassert_api_key_selected_type`.
//!
//! Called from [`super::spawn::spawn_gemini`] before every exec.
//! Reads `<handle_dir>/.gemini/settings.json`, verifies
//! `security.auth.selectedType == "gemini-api-key"`, and rewrites
//! the file when drifted.
//!
//! Per OPEN-G01 (journal 0003 RESOLVED): the handle-dir variant
//! fully wins over user-level `~/.gemini/settings.json`, so
//! re-assertion is a cheap atomic write — NOT a rename of the
//! user's home-directory file. This is the lower-effort branch the
//! plan flagged as conditional on the OPEN-G01 outcome.

use super::settings::{extract_selected_type, render, SELECTED_TYPE_API_KEY};
use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
use std::path::{Path, PathBuf};

/// Errors raised by the drift detector.
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

/// Outcome of one drift-detector pass — exposed so the audit log
/// and `csq doctor` can report whether re-assertion fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftOutcome {
    /// settings.json was missing or empty — wrote a fresh template.
    SeededFresh,
    /// settings.json was present and `selectedType ==
    /// "gemini-api-key"` — no action.
    AlreadyCorrect,
    /// settings.json was present but `selectedType` was something
    /// else — re-asserted to `"gemini-api-key"`.
    Corrected,
}

/// Re-asserts `security.auth.selectedType = "gemini-api-key"` in
/// the given handle dir's `.gemini/settings.json`. Idempotent.
/// Atomic. Mode 0o600 enforced via `secure_file` after the rewrite.
///
/// `model_name` is included in the rendered template only when
/// re-asserting (`SeededFresh` / `Corrected`); the `AlreadyCorrect`
/// branch leaves the file untouched and does NOT clobber the
/// caller's model selection.
pub fn reassert_api_key_selected_type(
    handle_dir: &Path,
    model_name: &str,
) -> Result<DriftOutcome, ProbeError> {
    let gemini_dir = handle_dir.join(".gemini");
    let settings_path = gemini_dir.join("settings.json");

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

    if let Some(content) = &existing {
        if extract_selected_type(content).as_deref() == Some(SELECTED_TYPE_API_KEY) {
            return Ok(DriftOutcome::AlreadyCorrect);
        }
    }

    // (Re)write the template. Always recreate the parent dir; on
    // SeededFresh the parent may not exist yet.
    if let Err(e) = std::fs::create_dir_all(&gemini_dir) {
        return Err(ProbeError::Io {
            path: gemini_dir,
            source: e,
        });
    }
    let body = render(model_name);
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
        let outcome = reassert_api_key_selected_type(dir.path(), "gemini-2.5-pro").unwrap();
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
        reassert_api_key_selected_type(dir.path(), "gemini-2.5-pro").unwrap();
        let path = dir.path().join(".gemini/settings.json");
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        // Tiny sleep to ensure mtime resolution would tick if rewritten.
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Second call must be AlreadyCorrect.
        let outcome = reassert_api_key_selected_type(dir.path(), "gemini-2.5-pro").unwrap();
        assert_eq!(outcome, DriftOutcome::AlreadyCorrect);
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after, "must not rewrite when correct");
    }

    #[test]
    fn corrects_when_drifted_to_oauth_personal() {
        // Simulates the shadow-auth scenario: user-level OAuth was
        // somehow populated into the handle dir (real path: never;
        // defensive path: still re-asserted).
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("settings.json"),
            r#"{"security":{"auth":{"selectedType":"oauth-personal"}}}"#,
        )
        .unwrap();

        let outcome = reassert_api_key_selected_type(dir.path(), "gemini-2.5-pro").unwrap();
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

        let outcome = reassert_api_key_selected_type(dir.path(), "gemini-2.5-pro").unwrap();
        // Unparseable counts as "selectedType not present" → drifted.
        assert_eq!(outcome, DriftOutcome::Corrected);
    }
}
