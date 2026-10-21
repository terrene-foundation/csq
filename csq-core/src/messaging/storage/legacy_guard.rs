//! One non-waiting hold of the original JSON message lock and directory identity.

use crate::sessions::directives::DirectiveError;
#[cfg(unix)]
use crate::sessions::directives::{acquire_store_lock_attempts_as, StoreLock};
use std::path::Path;

/// Holds the original `messages/.lock`, without switching authority or lock namespaces.
/// Revalidation is cooperative; it does not exclude a hostile concurrent path writer.
#[cfg(unix)]
pub struct LegacyGuard {
    directory: std::fs::File,
    path: std::path::PathBuf,
    lock: StoreLock,
}

/// Unsupported platforms refuse before opening or creating filesystem state.
#[cfg(not(unix))]
pub struct LegacyGuard;

impl LegacyGuard {
    /// Try the original lock exactly once. The messages directory must already exist.
    #[cfg(unix)]
    pub fn try_acquire(accounts_base: &Path) -> Result<Self, DirectiveError> {
        use std::os::unix::fs::OpenOptionsExt;
        if !accounts_base.is_absolute() {
            return Err(refused());
        }
        let path = crate::messaging::store::store_dir(accounts_base);
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|_| refused())?;
        check_directory(&directory, &path)?;
        let lock_path = path.join(".lock");
        match std::fs::symlink_metadata(&lock_path) {
            Ok(meta) => check_lock_metadata(&meta)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(refused()),
        }
        let lock = acquire_store_lock_attempts_as("message storage", &lock_path, 1)?;
        let guard = Self {
            directory,
            path,
            lock,
        };
        guard.check()?;
        Ok(guard)
    }

    /// Recheck the held and named original directory and lock before a protected use.
    #[cfg(unix)]
    pub fn check(&self) -> Result<(), DirectiveError> {
        check_directory(&self.directory, &self.path)?;
        self.lock.matches_path(&self.path.join(".lock"))?;
        check_directory(&self.directory, &self.path)
    }

    /// Non-Unix original-inode guarding is unsupported, before any filesystem writes.
    #[cfg(not(unix))]
    pub fn try_acquire(_accounts_base: &Path) -> Result<Self, DirectiveError> {
        Err(refused())
    }

    /// Non-Unix original-inode guarding remains unsupported.
    #[cfg(not(unix))]
    pub fn check(&self) -> Result<(), DirectiveError> {
        Err(refused())
    }
}

fn refused() -> DirectiveError {
    DirectiveError::undet("message storage: original lock identity unavailable")
}

#[cfg(unix)]
fn check_directory(file: &std::fs::File, path: &Path) -> Result<(), DirectiveError> {
    use std::os::unix::fs::MetadataExt;
    let held = file.metadata().map_err(|_| refused())?;
    let named = std::fs::symlink_metadata(path).map_err(|_| refused())?;
    // SAFETY: geteuid has no arguments and no Rust memory preconditions.
    let uid = unsafe { libc::geteuid() };
    for meta in [&held, &named] {
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o7777 != 0o700 {
            return Err(refused());
        }
    }
    if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
        return Err(refused());
    }
    Ok(())
}

#[cfg(unix)]
fn check_lock_metadata(meta: &std::fs::Metadata) -> Result<(), DirectiveError> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no arguments and no Rust memory preconditions.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_file() || meta.uid() != uid || meta.mode() & 0o7777 != 0o600 || meta.nlink() != 1 {
        return Err(refused());
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fn fixture() -> tempfile::TempDir {
        let d = tempfile::TempDir::new().unwrap();
        let path = crate::messaging::store::store_dir(d.path());
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn replacement(path: &Path) {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
    }

    #[test]
    fn held_original_lock_rejects_named_inode_replacement() {
        let d = fixture();
        let guard = LegacyGuard::try_acquire(d.path()).unwrap();
        assert!(guard.check().is_ok(), "actual original guard must be held");
        let path = crate::messaging::store::store_dir(d.path()).join(".lock");
        assert!(
            acquire_store_lock_attempts_as("fixture", &path, 1).is_err(),
            "original inode is busy"
        );
        // Rename rather than unlink: the held inode retains nlink==1, so only
        // the named-vs-held inequality refusal discriminates this substitution.
        let old_path = d.path().join("held-original-lock");
        std::fs::rename(&path, &old_path).unwrap();
        assert!(acquire_store_lock_attempts_as("fixture", &old_path, 1).is_err());
        replacement(&path);
        let other = acquire_store_lock_attempts_as("fixture", &path, 1).unwrap();
        assert!(
            guard.check().is_err(),
            "named replacement must not satisfy held original lock"
        );
        drop(other);
    }

    #[test]
    fn original_lock_is_try_once_busy_and_reusable_after_drop() {
        let d = fixture();
        let held = LegacyGuard::try_acquire(d.path()).unwrap();
        assert!(LegacyGuard::try_acquire(d.path()).is_err());
        assert!(held.check().is_ok());
        drop(held);
        assert!(LegacyGuard::try_acquire(d.path()).is_ok());
    }

    #[test]
    fn held_original_lock_rejects_original_directory_replacement() {
        let d = fixture();
        let guard = LegacyGuard::try_acquire(d.path()).unwrap();
        assert!(guard.check().is_ok());
        let path = crate::messaging::store::store_dir(d.path());
        std::fs::rename(&path, d.path().join("old-messages")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        replacement(&path.join(".lock"));
        assert!(guard.check().is_err());
    }

    #[test]
    fn original_lock_refuses_nonregular_or_missing_namespace_without_creation() {
        let d = tempfile::TempDir::new().unwrap();
        assert!(LegacyGuard::try_acquire(d.path()).is_err());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
        let path = crate::messaging::store::store_dir(d.path());
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(path.join(".lock")).unwrap();
        assert!(LegacyGuard::try_acquire(d.path()).is_err());
        std::fs::remove_dir(path.join(".lock")).unwrap();
        let old = d.path().join("old-messages");
        std::fs::rename(&path, &old).unwrap();
        std::os::unix::fs::symlink(&old, &path).unwrap();
        assert!(LegacyGuard::try_acquire(d.path()).is_err());
        assert!(LegacyGuard::try_acquire(Path::new("relative-accounts")).is_err());
    }

    #[test]
    fn original_lock_refuses_symlink_hardlink_and_private_mode_changes() {
        let d = fixture();
        let path = crate::messaging::store::store_dir(d.path());
        let target = d.path().join("target");
        replacement(&target);
        std::os::unix::fs::symlink(&target, path.join(".lock")).unwrap();
        assert!(LegacyGuard::try_acquire(d.path()).is_err());
        std::fs::remove_file(path.join(".lock")).unwrap();
        std::fs::hard_link(&target, path.join(".lock")).unwrap();
        assert!(LegacyGuard::try_acquire(d.path()).is_err());
        std::fs::remove_file(path.join(".lock")).unwrap();
        let guard = LegacyGuard::try_acquire(d.path()).unwrap();
        std::fs::set_permissions(path.join(".lock"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        assert!(guard.check().is_err());
        std::fs::set_permissions(path.join(".lock"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(guard.check().is_err());
    }
}

#[cfg(all(test, not(unix)))]
mod unsupported_tests {
    use super::*;
    #[test]
    fn original_lock_unsupported_refuses_before_writes() {
        let d = tempfile::TempDir::new().unwrap();
        assert!(LegacyGuard::try_acquire(d.path()).is_err());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }
}
