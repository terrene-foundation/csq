//! Vertex SA JSON file validation and permission enforcement.
//!
//! Vertex AI service-account JSON files are signing material — they
//! sign JWTs against the customer's GCP project. Per security review
//! §5 ("Vertex SA path" row), the file MUST be `0o400` and
//! provisioning MUST refuse paths that are world-readable unless the
//! caller passes an explicit `allow_insecure_mode` override (which
//! the UI does not surface — it exists for advanced CLI use only).
//!
//! This module does NOT load or parse the JSON. The path is the
//! addressable artefact stored via `platform::secret`; the file
//! contents are only ever read at spawn time by `gemini-cli` itself,
//! never by csq.

use std::path::Path;

/// Errors raised by Vertex SA path validation.
#[derive(Debug, thiserror::Error)]
pub enum VertexKeyfileError {
    /// The path does not exist on disk.
    #[error("Vertex service-account JSON file not found at {path}")]
    NotFound { path: std::path::PathBuf },
    /// The path exists but is not a regular file (directory, symlink
    /// to nowhere, FIFO, etc.). Refused defensively — reading
    /// signing material from anything but a regular file is a sign
    /// of misconfiguration or attack.
    #[error("Vertex SA path is not a regular file: {path}")]
    NotRegularFile { path: std::path::PathBuf },
    /// File mode allows reading by group or world (`& 0o077 != 0`).
    /// The caller must either fix the mode (recommended) or pass
    /// the `allow_insecure_mode` override.
    #[error(
        "Vertex SA file has insecure mode {mode:o} at {path} \
         (group/world readable); chmod 0400 to fix, or pass --insecure-leave-permissions"
    )]
    InsecureMode { path: std::path::PathBuf, mode: u32 },
    /// I/O error reading the path metadata.
    #[error("Vertex SA file I/O error at {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Validates a Vertex SA JSON path for use as a Gemini secret. On
/// Unix, also tightens the file mode to `0o400` when
/// `tighten_to_readonly` is true and the current mode allows write.
///
/// Returns `Ok(())` when the path is acceptable. Returns a
/// [`VertexKeyfileError`] otherwise. `allow_insecure_mode` bypasses
/// the mode check — provisioned for advanced CLI users who manage
/// permissions outside csq.
pub fn validate(
    path: &Path,
    allow_insecure_mode: bool,
    tighten_to_readonly: bool,
) -> Result<(), VertexKeyfileError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VertexKeyfileError::NotFound {
                path: path.to_path_buf(),
            });
        }
        Err(e) => {
            return Err(VertexKeyfileError::Io {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    if !metadata.file_type().is_file() {
        return Err(VertexKeyfileError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        let group_or_world_readable = (mode & 0o077) != 0;
        if group_or_world_readable && !allow_insecure_mode {
            return Err(VertexKeyfileError::InsecureMode {
                path: path.to_path_buf(),
                mode,
            });
        }
        if tighten_to_readonly && (mode & 0o200) != 0 {
            // Mode currently allows write; tighten to read-only owner.
            let new_perm = std::fs::Permissions::from_mode(0o400);
            if let Err(e) = std::fs::set_permissions(path, new_perm) {
                return Err(VertexKeyfileError::Io {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Windows ACLs are NOT mode-based. Per security review §1,
        // DPAPI provides the at-rest protection on Windows; the file
        // mode is not the load-bearing primitive there. We accept
        // any regular file on Windows.
        let _ = (allow_insecure_mode, tighten_to_readonly);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_with_mode(dir: &Path, name: &str, mode: u32) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"{\"type\": \"service_account\"}").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        p
    }

    #[test]
    fn validate_missing_file() {
        let dir = TempDir::new().unwrap();
        let err = validate(&dir.path().join("nope.json"), false, false).unwrap_err();
        assert!(matches!(err, VertexKeyfileError::NotFound { .. }));
    }

    #[test]
    fn validate_directory_rejected() {
        let dir = TempDir::new().unwrap();
        let err = validate(dir.path(), false, false).unwrap_err();
        assert!(matches!(err, VertexKeyfileError::NotRegularFile { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn validate_world_readable_rejected_without_override() {
        let dir = TempDir::new().unwrap();
        let p = write_with_mode(dir.path(), "sa.json", 0o644);
        let err = validate(&p, false, false).unwrap_err();
        assert!(matches!(err, VertexKeyfileError::InsecureMode { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn validate_world_readable_accepted_with_override() {
        let dir = TempDir::new().unwrap();
        let p = write_with_mode(dir.path(), "sa.json", 0o644);
        validate(&p, true, false).expect("override must accept insecure mode");
    }

    #[test]
    #[cfg(unix)]
    fn validate_owner_readonly_passes() {
        let dir = TempDir::new().unwrap();
        let p = write_with_mode(dir.path(), "sa.json", 0o400);
        validate(&p, false, false).expect("0o400 should pass");
    }

    #[test]
    #[cfg(unix)]
    fn validate_tightens_to_readonly_when_requested() {
        let dir = TempDir::new().unwrap();
        let p = write_with_mode(dir.path(), "sa.json", 0o600);
        validate(&p, false, true).expect("validate ok");
        use std::os::unix::fs::PermissionsExt;
        let after = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            after, 0o400,
            "expected mode tightened to 0o400, got {after:o}"
        );
    }
}
