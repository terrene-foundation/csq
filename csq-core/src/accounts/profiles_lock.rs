//! Cross-process file lock for `accounts/profiles.json`.
//!
//! # Why this exists
//!
//! `accounts/profiles.json` is written by two independent OS processes:
//!
//! - **`csqd`** (daemon) — Pass 0 walks every `config-N/` directory and calls
//!   `profiles::add_identity_mapping` for each slot.
//! - **`csq login N`** (CLI or desktop) — `accounts::login::finalize_login` writes
//!   the account profile row, then calls `daemon::identity_mint::mint_for_login`
//!   which calls `profiles::add_identity_mapping`.
//!
//! Both paths perform a **read-modify-write** cycle (load JSON, mutate,
//! `atomic_replace`). Without serialization, the second writer's `atomic_replace`
//! clobbers the first writer's modifications, producing a silent lost-update.
//!
//! The lock file `<base_dir>/.profiles.lock` serializes cross-process writers
//! via `platform::lock::lock_file` (blocking `flock` on Unix, `LockFileEx` on
//! Windows). The lock is advisory for **readers** — `profiles::load` and pure
//! accessors (`resolve_slot_to_uuid`, `resolve_email_to_uuid`) skip the lock
//! because `atomic_replace` guarantees a reader never observes a torn write.
//!
//! # Re-entrancy contract
//!
//! `flock` IS re-entrant for duplicated fds within the same process (dup/dup2
//! share the open file description), but TWO `open()` calls to the same path
//! from the same process produce independent open file descriptions, and
//! `flock(LOCK_EX)` on the second WILL BLOCK on the first holder's lock —
//! producing a self-deadlock when both opens happen on the same thread. Within
//! a single-threaded flow (e.g. `finalize_login` holds the lock and calls
//! `mint_for_login` which calls `add_identity_mapping`), we avoid re-acquisition
//! by **passing the lock by reference** to `add_identity_mapping`. The
//! type-witness pattern — requiring a `&ProfilesFileLock` parameter on
//! `profiles::add_identity_mapping` — makes lock-held callsites statically
//! visible and structurally prevents the self-deadlock.
//!
//! # Lock file lifecycle
//!
//! The lock file itself is empty (it exists only as a kernel lock target). It
//! is created if missing. It is NOT deleted on release — keeping the inode
//! stable prevents a race between `unlink` and re-`open` on concurrent
//! processes. The lock file carries no secrets, so a `secure_file` call is
//! made for consistency with other lock artefacts in csq, but failure is
//! best-effort (non-fatal on FAT or network mounts).

use crate::error::ConfigError;
use crate::platform::{fs::secure_file, lock};
use std::path::{Path, PathBuf};

/// RAII guard holding the exclusive file lock for `accounts/profiles.json`.
///
/// Acquire via [`ProfilesFileLock::acquire`]; the lock is released on `Drop`.
///
/// Pass a reference to any function that performs a `load + mutate + save`
/// cycle on `profiles.json` to enforce the "lock must be held" precondition
/// at the type level.
pub struct ProfilesFileLock {
    /// The underlying platform file-lock guard.
    _guard: lock::FileLockGuard,
    /// Path to the lock file (for diagnostics and tests).
    path: PathBuf,
}

impl ProfilesFileLock {
    /// Returns the path to `.profiles.lock` within `base_dir`.
    pub fn lock_path(base_dir: &Path) -> PathBuf {
        base_dir.join(".profiles.lock")
    }

    /// Acquires the exclusive lock on `<base_dir>/.profiles.lock`.
    ///
    /// Blocks until the lock is available (no timeout — Pass 0 is rare
    /// and `finalize_login` runs at human interaction pace; contention
    /// windows are bounded). Returns the RAII guard on success.
    ///
    /// The lock file is created if it does not exist. `secure_file` is
    /// called best-effort AFTER `lock_file` creates the file (non-fatal
    /// on filesystems that cannot honour 0o600).
    pub fn acquire(base_dir: &Path) -> Result<Self, ConfigError> {
        let path = Self::lock_path(base_dir);

        // Ensure the parent dir exists before creating the lock file.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        // Create (or open) the lock file and acquire the exclusive flock.
        // `lock_file` creates the file if it is absent.
        let guard = lock::lock_file(&path).map_err(|e| ConfigError::InvalidJson {
            path: path.clone(),
            reason: format!("profiles lock: {e}"),
        })?;

        // Best-effort secure_file AFTER lock_file — on a fresh install
        // the file does not exist before lock_file creates it, so calling
        // secure_file before lock_file is a silent no-op.  The lock file
        // carries no secrets; failure is non-fatal on FAT/network mounts.
        secure_file(&path).ok();

        Ok(Self {
            _guard: guard,
            path,
        })
    }

    /// Returns the lock file path. Useful for tests and diagnostics.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for ProfilesFileLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfilesFileLock")
            .field("path", &self.path)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── basic acquire / release ────────────────────────────────────────────

    #[test]
    fn acquire_succeeds_on_fresh_dir() {
        // Arrange
        let dir = TempDir::new().unwrap();

        // Act
        let result = ProfilesFileLock::acquire(dir.path());

        // Assert
        assert!(
            result.is_ok(),
            "acquire must succeed on a fresh dir: {:?}",
            result.err()
        );
        let guard = result.unwrap();
        assert!(
            guard.path().ends_with(".profiles.lock"),
            "lock path must end with .profiles.lock"
        );
    }

    #[test]
    fn lock_creates_lock_file_if_missing() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join(".profiles.lock");
        assert!(
            !lock_path.exists(),
            "lock file must not exist before acquire"
        );

        // Act
        let _guard = ProfilesFileLock::acquire(dir.path()).unwrap();

        // Assert: the lock file was created (Unix path; on Windows the
        // lock is a named mutex, not a file, so only assert on Unix)
        #[cfg(unix)]
        assert!(
            lock_path.exists(),
            "lock file must exist after acquire on Unix"
        );
    }

    #[test]
    fn lock_released_after_drop() {
        // Arrange
        let dir = TempDir::new().unwrap();

        // Act: acquire and drop
        {
            let _guard = ProfilesFileLock::acquire(dir.path()).unwrap();
        }

        // Assert: can acquire again immediately (lock was released)
        let result = ProfilesFileLock::acquire(dir.path());
        assert!(
            result.is_ok(),
            "second acquire must succeed after drop: {:?}",
            result.err()
        );
    }

    /// Validates that releasing the lock on panic still allows re-acquisition.
    /// Relevant to `lock_released_on_panic` requirement.
    #[test]
    fn lock_released_on_panic() {
        // Arrange
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        // Act: acquire in a thread that panics while holding the lock
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _guard = ProfilesFileLock::acquire(&dir_path).unwrap();
                // Notify main thread that we hold the lock
                tx.send(()).unwrap();
                panic!("simulated panic while holding profiles lock");
            }));
        });

        // Wait for the thread to acquire before we join
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .expect("thread should have acquired lock");
        let _ = handle.join(); // catches the unwind

        // Assert: after panic + unwind, the lock is released
        let result = ProfilesFileLock::acquire(dir.path());
        assert!(
            result.is_ok(),
            "lock must be released after panic-induced drop: {:?}",
            result.err()
        );
    }

    #[test]
    fn lock_path_is_dot_profiles_lock_under_base_dir() {
        let dir = TempDir::new().unwrap();
        let path = ProfilesFileLock::lock_path(dir.path());
        assert_eq!(path, dir.path().join(".profiles.lock"));
    }

    /// R3-LOW-2: `secure_file` must run AFTER `lock_file` creates the file.
    ///
    /// On a fresh install the `.profiles.lock` file does not exist before
    /// `acquire` is called.  If `secure_file` ran first it would either error
    /// silently (the file is absent) or be a no-op.  This test verifies that
    /// after `acquire` the lock file exists AND has 0o600 permissions —
    /// meaning `secure_file` executed on an existing file, not before
    /// `lock_file` created it.
    #[cfg(unix)]
    #[test]
    fn lock_file_exists_at_0o600_after_acquire_on_fresh_dir() {
        use std::os::unix::fs::PermissionsExt;

        // Arrange: fresh dir with no .profiles.lock
        let dir = TempDir::new().unwrap();
        let lock_path = dir.path().join(".profiles.lock");
        assert!(
            !lock_path.exists(),
            "lock file must not exist before acquire"
        );

        // Act
        let guard = ProfilesFileLock::acquire(dir.path()).expect("acquire must succeed");

        // Assert: lock file exists
        assert!(
            lock_path.exists(),
            "lock file must exist after acquire (lock_file creates it)"
        );

        // Assert: permissions are 0o600 (secure_file ran after lock_file)
        let mode = std::fs::metadata(&lock_path)
            .expect("lock file metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "lock file must be 0o600 after acquire — secure_file ran after lock_file; mode={mode:o}"
        );

        drop(guard);
    }
}
