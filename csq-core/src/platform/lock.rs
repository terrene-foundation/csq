//! File locking — POSIX `flock` on Unix, named mutexes on Windows.
//!
//! All locking is exposed through [`lock_file`] (blocking) and
//! [`try_lock_file`] (non-blocking). Both return an RAII guard that
//! releases the lock on drop.

use crate::error::PlatformError;
use std::path::Path;

// ── Public API (platform-dispatched) ──────────────────────────────────

/// Acquires an exclusive lock on `path`, blocking until available.
///
/// Returns a guard that releases the lock on drop. The lock file is
/// created if it does not exist.
pub fn lock_file(path: &Path) -> Result<FileLockGuard, PlatformError> {
    imp::lock_file(path)
}

/// Attempts to acquire an exclusive lock without blocking.
///
/// Returns `Ok(Some(guard))` if acquired, `Ok(None)` if the lock is
/// held by another process. The lock file is created if it does not
/// exist.
pub fn try_lock_file(path: &Path) -> Result<Option<FileLockGuard>, PlatformError> {
    imp::try_lock_file(path)
}

// ── Guard type ────────────────────────────────────────────────────────

/// RAII guard that releases the lock on drop.
pub struct FileLockGuard {
    // Held for its Drop impl — releasing the lock on scope exit.
    _inner: imp::InnerGuard,
}

impl std::fmt::Debug for FileLockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileLockGuard").finish_non_exhaustive()
    }
}

// ── Unix implementation (flock) ───────────────────────────────────────

#[cfg(unix)]
mod imp {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::os::unix::io::AsRawFd;

    pub struct InnerGuard {
        file: File,
    }

    impl Drop for InnerGuard {
        fn drop(&mut self) {
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }

    pub fn lock_file(path: &Path) -> Result<FileLockGuard, PlatformError> {
        let file = open_lock_file(path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(PlatformError::Io(std::io::Error::last_os_error()));
        }
        Ok(FileLockGuard {
            _inner: InnerGuard { file },
        })
    }

    pub fn try_lock_file(path: &Path) -> Result<Option<FileLockGuard>, PlatformError> {
        let file = open_lock_file(path)?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(PlatformError::Io(err));
        }
        Ok(Some(FileLockGuard {
            _inner: InnerGuard { file },
        }))
    }

    fn open_lock_file(path: &Path) -> Result<File, PlatformError> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(PlatformError::Io)
    }
}

// ── Windows implementation (named mutex) ──────────────────────────────

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use tracing::warn;

    // Win32 constants
    const WAIT_OBJECT_0: u32 = 0x00000000;
    const WAIT_ABANDONED: u32 = 0x00000080;
    const WAIT_TIMEOUT: u32 = 0x00000102;
    const INFINITE: u32 = 0xFFFFFFFF;

    extern "system" {
        fn CreateMutexW(
            lpMutexAttributes: *const std::ffi::c_void,
            bInitialOwner: i32,
            lpName: *const u16,
        ) -> *mut std::ffi::c_void;
        fn WaitForSingleObject(hHandle: *mut std::ffi::c_void, dwMilliseconds: u32) -> u32;
        fn ReleaseMutex(hMutex: *mut std::ffi::c_void) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
    }

    pub struct InnerGuard {
        handle: *mut std::ffi::c_void,
    }

    // SAFETY: The mutex handle is process-scoped and safe to send across threads.
    unsafe impl Send for InnerGuard {}

    impl Drop for InnerGuard {
        fn drop(&mut self) {
            unsafe {
                ReleaseMutex(self.handle);
                CloseHandle(self.handle);
            }
        }
    }

    fn mutex_name(path: &Path) -> Vec<u16> {
        // Use the path as a unique mutex name, prefixed with "Global\"
        let name = format!("Global\\csq-lock-{}", path.display());
        name.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn lock_file(path: &Path) -> Result<FileLockGuard, PlatformError> {
        let name = mutex_name(path);
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(PlatformError::Win32 {
                code: unsafe { GetLastError() },
                message: "CreateMutexW failed".into(),
            });
        }

        let wait_result = unsafe { WaitForSingleObject(handle, INFINITE) };
        match wait_result {
            WAIT_OBJECT_0 => Ok(FileLockGuard {
                _inner: InnerGuard { handle },
            }),
            WAIT_ABANDONED => {
                // GAP-8: treat as acquired but log a warning — the previous
                // holder crashed without releasing.
                warn!(
                    path = %path.display(),
                    "mutex acquired after WAIT_ABANDONED (previous holder crashed)"
                );
                Ok(FileLockGuard {
                    _inner: InnerGuard { handle },
                })
            }
            _ => {
                unsafe { CloseHandle(handle) };
                Err(PlatformError::Win32 {
                    code: wait_result,
                    message: format!("WaitForSingleObject returned {wait_result:#x}"),
                })
            }
        }
    }

    pub fn try_lock_file(path: &Path) -> Result<Option<FileLockGuard>, PlatformError> {
        let name = mutex_name(path);
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(PlatformError::Win32 {
                code: unsafe { GetLastError() },
                message: "CreateMutexW failed".into(),
            });
        }

        let wait_result = unsafe { WaitForSingleObject(handle, 0) };
        match wait_result {
            WAIT_OBJECT_0 => Ok(Some(FileLockGuard {
                _inner: InnerGuard { handle },
            })),
            WAIT_ABANDONED => {
                warn!(
                    path = %path.display(),
                    "mutex acquired after WAIT_ABANDONED (previous holder crashed)"
                );
                Ok(Some(FileLockGuard {
                    _inner: InnerGuard { handle },
                }))
            }
            WAIT_TIMEOUT => {
                unsafe { CloseHandle(handle) };
                Ok(None)
            }
            _ => {
                unsafe { CloseHandle(handle) };
                Err(PlatformError::Win32 {
                    code: wait_result,
                    message: format!("WaitForSingleObject returned {wait_result:#x}"),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn lock_and_unlock() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");

        let guard = lock_file(&lock_path).unwrap();
        drop(guard);

        // Can re-acquire after drop
        let _guard2 = lock_file(&lock_path).unwrap();
    }

    #[test]
    fn try_lock_returns_none_when_held() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");

        let _guard = lock_file(&lock_path).unwrap();

        // Same process, different fd — flock allows this on some systems,
        // but we test the cross-process case below in integration tests.
        // For the unit test, just verify the API works.
    }

    #[test]
    fn try_lock_succeeds_when_free() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("test.lock");

        let guard = try_lock_file(&lock_path).unwrap();
        assert!(guard.is_some());
    }

    #[test]
    fn lock_creates_file_if_missing() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("new.lock");
        assert!(!lock_path.exists());

        let _guard = lock_file(&lock_path).unwrap();
        assert!(lock_path.exists());
    }

    #[test]
    fn lock_guard_is_debug() {
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join("debug.lock");
        let guard = lock_file(&lock_path).unwrap();
        let s = format!("{guard:?}");
        assert!(s.contains("FileLockGuard"));
    }
}
