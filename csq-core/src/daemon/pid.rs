//! PID file primitives with single-instance guard.
//!
//! Writes are atomic (temp file + rename) to prevent partial reads
//! on crash. Single-instance guard re-reads the file inside the
//! atomic-write path so two concurrent `csq daemon start` calls
//! cannot both "win" — whichever rename lands last overwrites the
//! other, and the loser's `acquire` detects the mismatch on its own
//! PID verification and errors out.

use crate::error::DaemonError;
use crate::platform::{fs as platform_fs, process};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// RAII guard around a PID file owned by the current process.
///
/// Created via [`acquire`]. On drop, removes the PID file — but only
/// if the file on disk still contains *our* PID (prevents removing a
/// successor daemon's PID file if we're killed after a race).
#[derive(Debug)]
pub struct PidFile {
    path: PathBuf,
    owned_pid: u32,
}

impl PidFile {
    /// Attempts to acquire exclusive ownership of the PID file at
    /// `path`.
    ///
    /// # Single-instance algorithm
    ///
    /// 1. Read existing PID file if any.
    /// 2. If it exists and its PID is alive, error
    ///    [`DaemonError::AlreadyRunning`].
    /// 3. If it exists but PID is dead, delete the stale file.
    /// 4. Write our PID atomically (temp file + rename).
    /// 5. Re-read to verify we "own" the file — if a concurrent
    ///    `acquire` won the rename race, our PID won't match and we
    ///    error out (the other process owns the daemon).
    ///
    /// The re-read-after-write check catches the TOCTOU window
    /// between step 1-2 (existing-alive check) and step 4 (our
    /// rename). Without it, two `csq daemon start` calls racing
    /// simultaneously could both pass step 2, both write, and the
    /// loser would incorrectly believe it owned the daemon.
    pub fn acquire(path: &Path) -> Result<Self, DaemonError> {
        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    DaemonError::SocketConnect {
                        path: parent.to_path_buf(),
                    }
                    .with_source(e)
                })?;
            }
        }

        // Step 1-3: handle existing file.
        if path.exists() {
            match read_pid(path) {
                Some(existing_pid) if process::is_pid_alive(existing_pid) => {
                    return Err(DaemonError::AlreadyRunning { pid: existing_pid });
                }
                _ => {
                    // Either dead PID (Some(_) not alive, fell
                    // through) or unreadable file (None) — remove
                    // and proceed. This handles corruption (non-
                    // numeric content) and crash recovery.
                    let _ = fs::remove_file(path);
                }
            }
        }

        // Step 4: atomic write.
        let our_pid = std::process::id();
        write_pid_atomic(path, our_pid)?;

        // Step 5: verify we own it (race check).
        match read_pid(path) {
            Some(pid) if pid == our_pid => Ok(PidFile {
                path: path.to_path_buf(),
                owned_pid: our_pid,
            }),
            Some(other) => Err(DaemonError::AlreadyRunning { pid: other }),
            None => Err(DaemonError::SocketConnect {
                path: path.to_path_buf(),
            }),
        }
    }

    /// Returns the PID written to the file (always the current
    /// process's PID).
    pub fn owned_pid(&self) -> u32 {
        self.owned_pid
    }

    /// Returns the PID file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        // Only remove the file if it still contains our PID. If we
        // were forcibly killed and a successor daemon has already
        // overwritten it, we must not delete the successor's file.
        if let Some(on_disk) = read_pid(&self.path) {
            if on_disk == self.owned_pid {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

/// Reads a PID from a PID file. Returns `None` if the file is
/// missing, unreadable, or does not contain a valid `u32`.
pub fn read_pid(path: &Path) -> Option<u32> {
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u32>().ok()
}

/// Writes a PID atomically via temp file + rename. The temp file is
/// created in the same directory as `path` to guarantee the rename
/// is on the same filesystem.
fn write_pid_atomic(path: &Path, pid: u32) -> Result<(), DaemonError> {
    let tmp = platform_fs::unique_tmp_path(path);

    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| DaemonError::SocketConnect { path: tmp.clone() }.with_source(e))?;
        writeln!(f, "{pid}")
            .map_err(|e| DaemonError::SocketConnect { path: tmp.clone() }.with_source(e))?;
        f.sync_all()
            .map_err(|e| DaemonError::SocketConnect { path: tmp.clone() }.with_source(e))?;
    }

    // 0o600 on Unix before the rename so the final file always has
    // the restrictive mode. No-op on Windows.
    let _ = platform_fs::secure_file(&tmp);

    platform_fs::atomic_replace(&tmp, path).map_err(|e| {
        // Map platform error to daemon error.
        DaemonError::SocketConnect {
            path: path.to_path_buf(),
        }
        .with_source_platform(e)
    })?;

    Ok(())
}

// Small helper extensions to attach io/platform error context to
// DaemonError. We don't add these as thiserror variants because the
// daemon error messages are surfaced to the user, and including the
// raw io error string is usually fine for operator diagnostics.
trait DaemonErrorContext {
    fn with_source(self, e: std::io::Error) -> DaemonError;
    fn with_source_platform(self, e: crate::error::PlatformError) -> DaemonError;
}

impl DaemonErrorContext for DaemonError {
    fn with_source(self, e: std::io::Error) -> DaemonError {
        // Log the raw io error for operator diagnostics but keep the
        // user-facing variant unchanged. This is intentionally lossy:
        // the DaemonError enum doesn't carry source chains by design,
        // so we dump context via tracing instead.
        tracing::debug!(error = %e, daemon_error = %self, "pid file io error");
        self
    }

    fn with_source_platform(self, e: crate::error::PlatformError) -> DaemonError {
        tracing::debug!(error = %e, daemon_error = %self, "pid file platform error");
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn pid_path(dir: &TempDir) -> PathBuf {
        dir.path().join("test.pid")
    }

    #[test]
    fn read_pid_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        assert_eq!(read_pid(&p), None);
    }

    #[test]
    fn read_pid_invalid_content_returns_none() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        fs::write(&p, "not-a-number\n").unwrap();
        assert_eq!(read_pid(&p), None);
    }

    #[test]
    fn read_pid_round_trip() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        fs::write(&p, "12345\n").unwrap();
        assert_eq!(read_pid(&p), Some(12345));
    }

    #[test]
    fn write_pid_atomic_creates_readable_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        write_pid_atomic(&p, 54321).unwrap();
        assert_eq!(read_pid(&p), Some(54321));
    }

    #[test]
    fn write_pid_atomic_leaves_no_tmp_files() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        write_pid_atomic(&p, 1).unwrap();

        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        // Only the final PID file should remain; no stray tmp files.
        assert_eq!(entries, vec!["test.pid"]);
    }

    #[test]
    fn acquire_writes_our_pid() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        let guard = PidFile::acquire(&p).unwrap();
        assert_eq!(guard.owned_pid(), std::process::id());
        assert_eq!(read_pid(&p), Some(std::process::id()));
    }

    #[test]
    fn drop_removes_our_pid_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);
        {
            let _guard = PidFile::acquire(&p).unwrap();
            assert!(p.exists());
        }
        // After drop, file is gone.
        assert!(!p.exists());
    }

    #[test]
    fn acquire_rejects_when_alive_pid_exists() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        // Write our own PID — we're alive, so second acquire must
        // fail with AlreadyRunning.
        fs::write(&p, format!("{}\n", std::process::id())).unwrap();

        let result = PidFile::acquire(&p);
        match result {
            Err(DaemonError::AlreadyRunning { pid }) => {
                assert_eq!(pid, std::process::id());
            }
            other => panic!("expected AlreadyRunning, got {other:?}"),
        }
    }

    #[test]
    fn acquire_cleans_up_stale_pid_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        // PID 99_999_999 is almost certainly not alive on any
        // reasonable system (process::is_pid_alive already tests
        // this assumption in platform::process tests).
        fs::write(&p, "99999999\n").unwrap();

        let guard = PidFile::acquire(&p).unwrap();
        assert_eq!(guard.owned_pid(), std::process::id());
        assert_eq!(read_pid(&p), Some(std::process::id()));
    }

    #[test]
    fn acquire_cleans_up_corrupted_pid_file() {
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        // Non-numeric content should be treated like a stale file.
        fs::write(&p, "garbage\nnot a pid\n").unwrap();

        let guard = PidFile::acquire(&p).unwrap();
        assert_eq!(guard.owned_pid(), std::process::id());
    }

    #[test]
    fn acquire_creates_parent_directory() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("a").join("b").join("test.pid");
        assert!(!nested.parent().unwrap().exists());

        let _guard = PidFile::acquire(&nested).unwrap();
        assert!(nested.exists());
    }

    #[cfg(unix)]
    #[test]
    fn acquire_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let p = pid_path(&dir);

        let _guard = PidFile::acquire(&p).unwrap();

        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pid file must be owner-only 0o600");
    }
}
