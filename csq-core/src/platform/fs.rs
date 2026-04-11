//! Secure file operations: permissions and atomic replacement.

use crate::error::PlatformError;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-local counter to disambiguate temp file names within the same process
/// across threads. Combined with PID, this prevents the intra-process collision
/// that would occur if two threads in the same process wrote to the same path
/// simultaneously.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generates a unique temporary file path next to `target`, using PID + a
/// per-process atomic counter. Returns `target.with_extension("tmp.{pid}.{counter}")`.
pub fn unique_tmp_path(target: &Path) -> PathBuf {
    let counter = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    target.with_extension(format!("tmp.{}.{}", std::process::id(), counter))
}

/// Sets file permissions to owner-only read/write (0o600) on Unix.
/// No-op on Windows (ACL defaults handle this).
pub fn secure_file(path: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Atomically replaces `target` with `tmp_path`.
///
/// On Unix this is a single `rename(2)` call (atomic on the same filesystem).
/// On Windows, files may be locked by other processes, so we retry with
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` up to 5 times with 100ms delay.
pub fn atomic_replace(tmp_path: &Path, target: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        std::fs::rename(tmp_path, target)?;
    }
    #[cfg(windows)]
    {
        atomic_replace_windows(tmp_path, target)?;
    }
    Ok(())
}

#[cfg(windows)]
fn atomic_replace_windows(tmp_path: &Path, target: &Path) -> Result<(), PlatformError> {
    use std::os::windows::ffi::OsStrExt;
    use tracing::warn;

    // MOVEFILE_REPLACE_EXISTING = 0x1
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MAX_RETRIES: u32 = 5;
    const RETRY_DELAY_MS: u64 = 100;

    extern "system" {
        fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> i32;
        fn GetLastError() -> u32;
    }

    fn to_wide(s: &Path) -> Vec<u16> {
        s.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let src = to_wide(tmp_path);
    let dst = to_wide(target);

    for attempt in 0..MAX_RETRIES {
        let result = unsafe { MoveFileExW(src.as_ptr(), dst.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
        if result != 0 {
            return Ok(());
        }
        let err_code = unsafe { GetLastError() };
        if attempt + 1 < MAX_RETRIES {
            warn!(
                attempt = attempt + 1,
                error_code = err_code,
                "atomic_replace retry (file may be locked)"
            );
            std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
        } else {
            return Err(PlatformError::Win32 {
                code: err_code,
                message: format!(
                    "MoveFileExW failed after {MAX_RETRIES} attempts: {} -> {}",
                    tmp_path.display(),
                    target.display()
                ),
            });
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn atomic_replace_basic() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp.txt");
        let target = dir.path().join("target.txt");

        fs::write(&target, b"old").unwrap();
        fs::write(&tmp, b"new").unwrap();

        atomic_replace(&tmp, &target).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert!(!tmp.exists(), "tmp file should be gone after rename");
    }

    #[test]
    fn atomic_replace_creates_target_if_missing() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("tmp.txt");
        let target = dir.path().join("new_target.txt");

        fs::write(&tmp, b"data").unwrap();
        atomic_replace(&tmp, &target).unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "data");
    }

    #[test]
    fn atomic_replace_nonexistent_tmp_fails() {
        let dir = TempDir::new().unwrap();
        let tmp = dir.path().join("nonexistent.txt");
        let target = dir.path().join("target.txt");

        let result = atomic_replace(&tmp, &target);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secure_file_sets_600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.txt");
        fs::write(&path, b"sensitive").unwrap();

        // Start with permissive mode
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_ne!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        secure_file(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn secure_file_nonexistent_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.txt");
        // On Unix this should fail; on Windows it's a no-op so it succeeds
        #[cfg(unix)]
        assert!(secure_file(&path).is_err());
        #[cfg(windows)]
        assert!(secure_file(&path).is_ok());
    }

    #[test]
    fn atomic_replace_concurrent_writers() {
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("shared.txt");
        fs::write(&target, b"initial").unwrap();

        let target_arc = Arc::new(target.clone());
        let dir_path = Arc::new(dir.path().to_path_buf());

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let target = Arc::clone(&target_arc);
                let dir_path = Arc::clone(&dir_path);
                thread::spawn(move || {
                    for j in 0..100 {
                        let tmp = dir_path.join(format!("tmp_{i}_{j}.txt"));
                        let data = format!("writer_{i}_iter_{j}");
                        fs::write(&tmp, data.as_bytes()).unwrap();
                        // Ignore errors from concurrent renames — we only care
                        // that the final file is not corrupted
                        let _ = atomic_replace(&tmp, &target);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        // The target file must exist and contain valid data from some writer
        let content = fs::read_to_string(&target).unwrap();
        assert!(content.starts_with("writer_"), "content: {content}");
    }
}
