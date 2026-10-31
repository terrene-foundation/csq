//! Held private database file acquisition; JSON remains the active message authority.
//!
//! This does not open a SQLite connection: rusqlite's pathname open would introduce
//! a separate acquisition boundary. Callers must not treat this file guard as proof
//! that a separately opened connection uses the same inode. Checks are cooperative
//! observations, not atomic exclusion of a hostile same-UID writer.
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureDatabaseError {
    InvalidPath,
    UnsafeDirectory,
    UnsafeFile,
    NamespaceChanged,
    Unavailable,
    OperationFailed,
    UnsupportedPlatform,
}

impl std::fmt::Display for SecureDatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPath => "database path refused",
            Self::UnsafeDirectory => "database directory refused",
            Self::UnsafeFile => "database file refused",
            Self::NamespaceChanged => "database namespace changed",
            Self::Unavailable => "database acquisition unavailable",
            Self::OperationFailed => "database operation failed",
            Self::UnsupportedPlatform => "database acquisition unsupported",
        })
    }
}
impl std::error::Error for SecureDatabaseError {}

/// Keeps directory ancestry, database and sidecars observed during checks open.
/// Existing directories are never created or chmodded. `acquire` creates a missing
/// DB exclusively at mode0600 (Unix) or with the owner-only DACL applied at
/// creation (Windows) after ancestry checks; `acquire_existing` refuses absence
/// through its no-create open path. Existing files are not truncated.
pub struct SecureDatabase {
    #[cfg(unix)]
    held: unix::HeldDatabase,
    #[cfg(windows)]
    held: windows::HeldDatabase,
}

/// The Windows process token's user SID. An unreadable token is a refusal, never
/// an empty identity.
#[cfg(windows)]
fn current_user() -> Result<crate::platform::fs_windows_acl::UserSid, SecureDatabaseError> {
    crate::platform::fs_windows_acl::UserSid::current()
        .map_err(|_| SecureDatabaseError::Unavailable)
}

/// Which leaf a caller guarantees. `Strict` is the default: an at-creation
/// protected leaf and at-creation sidecars. `PoolLedger` is the ONE mode for the
/// directory SQLite writes into: the leaf carries the INHERITABLE owner-only
/// shape and a sidecar is accepted only as a child that inherited it. Only the
/// pool execution ledger uses the pool mode (R1 M2); on unix both modes are the
/// same code path.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LeafPolicy {
    Strict,
    PoolLedger,
}

impl SecureDatabase {
    pub fn acquire(
        private_dir: &Path,
        name: &std::ffi::OsStr,
    ) -> Result<Self, SecureDatabaseError> {
        Self::acquire_with(private_dir, name, LeafPolicy::Strict)
    }

    /// The pool-ledger mode: the leaf is the INHERITING owner-only directory
    /// SQLite creates its sidecars in, and a sidecar is accepted only in the
    /// shape it inherited from that leaf. Every other caller stays on `acquire`.
    pub fn acquire_pool_ledger(
        private_dir: &Path,
        name: &std::ffi::OsStr,
    ) -> Result<Self, SecureDatabaseError> {
        Self::acquire_with(private_dir, name, LeafPolicy::PoolLedger)
    }

    fn acquire_with(
        private_dir: &Path,
        name: &std::ffi::OsStr,
        policy: LeafPolicy,
    ) -> Result<Self, SecureDatabaseError> {
        #[cfg(unix)]
        {
            let _ = policy;
            // SAFETY: geteuid has no preconditions and changes no process state.
            let uid = unsafe { libc::geteuid() };
            Ok(Self {
                held: unix::HeldDatabase::acquire(private_dir, name, uid)?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                held: windows::HeldDatabase::acquire(private_dir, name, &current_user()?, policy)?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (private_dir, name, policy);
            Err(SecureDatabaseError::UnsupportedPlatform)
        }
    }

    /// Acquire a previously initialized database without any creation fallback.
    /// The same no-follow open and held-file checks as `acquire` apply; ENOENT
    /// returns an error at that open boundary, including if the file disappears.
    pub fn acquire_existing(
        private_dir: &Path,
        name: &std::ffi::OsStr,
    ) -> Result<Self, SecureDatabaseError> {
        Self::acquire_existing_with(private_dir, name, LeafPolicy::Strict)
    }

    /// [`Self::acquire_existing`] in the pool-ledger leaf mode.
    pub fn acquire_pool_ledger_existing(
        private_dir: &Path,
        name: &std::ffi::OsStr,
    ) -> Result<Self, SecureDatabaseError> {
        Self::acquire_existing_with(private_dir, name, LeafPolicy::PoolLedger)
    }

    fn acquire_existing_with(
        private_dir: &Path,
        name: &std::ffi::OsStr,
        policy: LeafPolicy,
    ) -> Result<Self, SecureDatabaseError> {
        #[cfg(unix)]
        {
            let _ = policy;
            // SAFETY: geteuid has no preconditions and changes no process state.
            let uid = unsafe { libc::geteuid() };
            Ok(Self {
                held: unix::HeldDatabase::acquire_existing(private_dir, name, uid)?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                held: windows::HeldDatabase::acquire_existing(
                    private_dir,
                    name,
                    &current_user()?,
                    policy,
                )?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (private_dir, name, policy);
            Err(SecureDatabaseError::UnsupportedPlatform)
        }
    }

    pub fn recheck(&self) -> Result<(), SecureDatabaseError> {
        #[cfg(any(unix, windows))]
        {
            self.held.recheck()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(SecureDatabaseError::UnsupportedPlatform)
        }
    }

    /// Recheck immediately before and after a synchronous operation on the held
    /// file. An error after the operation does not imply its effects were undone.
    /// The callback must not retain/clone the descriptor as a new unchecked API.
    pub fn with_file<T>(
        &self,
        operation: impl FnOnce(&std::fs::File) -> std::io::Result<T>,
    ) -> Result<T, SecureDatabaseError> {
        #[cfg(any(unix, windows))]
        {
            self.recheck()?;
            let result = operation(self.database_file());
            self.recheck()?;
            result.map_err(|_| SecureDatabaseError::OperationFailed)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = operation;
            Err(SecureDatabaseError::UnsupportedPlatform)
        }
    }

    /// The held database handle the operation may use; never a fresh open.
    #[cfg(any(unix, windows))]
    fn database_file(&self) -> &std::fs::File {
        &self.held.database.file
    }
}

#[cfg(windows)]
#[path = "secure_windows.rs"]
mod windows;

#[cfg(unix)]
mod unix {
    use super::SecureDatabaseError as Error;
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{File, Metadata};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    };
    use std::path::{Component, Path, PathBuf};

    const DIR_FLAGS: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    /// Ancestors only need to be traversed, so on Linux they are held with `O_PATH`: a
    /// directory that is searchable but not readable (`0o710`, `0o711`, an ACL) cannot be
    /// opened for reading yet is a valid, checked ancestor. The final private directory
    /// is still opened readable.
    #[cfg(target_os = "linux")]
    const ANCESTOR_FLAGS: i32 =
        libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    /// macOS spells the same intent `O_SEARCH` (`O_EXEC | O_DIRECTORY`): search permission
    /// only, no read permission needed.
    #[cfg(target_os = "macos")]
    const ANCESTOR_FLAGS: i32 = libc::O_SEARCH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const ANCESTOR_FLAGS: i32 = DIR_FLAGS;
    const FILE_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    const SUFFIXES: [&str; 3] = ["-wal", "-shm", "-journal"];

    pub(super) struct HeldDatabase {
        directories: Vec<Entry>,
        pub(super) database: Entry,
        sidecars: std::sync::Mutex<Vec<Option<Entry>>>,
        uid: u32,
    }
    pub(super) struct Entry {
        pub(super) file: File,
        path: PathBuf,
    }

    fn invalid() -> Error {
        Error::InvalidPath
    }
    fn name_cstring(name: &OsStr) -> Result<CString, Error> {
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 255
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
        {
            return Err(invalid());
        }
        CString::new(bytes).map_err(|_| invalid())
    }
    fn open_at(parent: &File, name: &OsStr, flags: i32) -> std::io::Result<File> {
        let c = name_cstring(name)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        // SAFETY: parent is held open; c is a live NUL-terminated single component.
        // The mode is used only by O_CREAT and grants no group/other permissions.
        let fd = unsafe { libc::openat(parent.as_raw_fd(), c.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a newly owned descriptor, transferred exactly once.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn same(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    pub(super) fn directory_policy(owner: u32, mode: u32, uid: u32, private: bool) -> bool {
        if private {
            owner == uid && mode == 0o700
        } else {
            crate::platform::fs::untrusted_directory_reason(owner, mode, uid).is_none()
        }
    }
    fn directory(meta: &Metadata, uid: u32, private: bool) -> Result<(), Error> {
        if !meta.is_dir() || !directory_policy(meta.uid(), meta.mode() & 0o7777, uid, private) {
            return Err(Error::UnsafeDirectory);
        }
        Ok(())
    }
    /// A held directory carries no extended ACL (macOS, or Linux NFSv4) that lets someone
    /// else change its entries; the leaf private store directory (`private`) allows no
    /// non-owner ALLOW (beyond the server-synthesized attribute/ACL-read/synchronize bits on
    /// Linux) and no macOS inheritable ALLOW (see
    /// `platform::fs::directory_acl_refusal` / `private_directory_acl_refusal`).
    fn acl_clear(entry: &Entry, private: bool) -> Result<(), Error> {
        let refusal = if private {
            crate::platform::fs::private_directory_acl_refusal(entry.file.as_raw_fd())
        } else {
            crate::platform::fs::directory_acl_refusal(entry.file.as_raw_fd())
        };
        match refusal {
            None => Ok(()),
            Some(_) => Err(Error::UnsafeDirectory),
        }
    }
    fn directories_recheck(entries: &[Entry], uid: u32) -> Result<(), Error> {
        let last = entries.len().checked_sub(1).ok_or(Error::Unavailable)?;
        for (index, entry) in entries.iter().enumerate() {
            directory(&metadata(entry)?, uid, index == last)?;
            acl_clear(entry, index == last)?;
        }
        Ok(())
    }
    fn private_file(meta: &Metadata, uid: u32) -> Result<(), Error> {
        if !meta.is_file()
            || meta.uid() != uid
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
        {
            return Err(Error::UnsafeFile);
        }
        Ok(())
    }
    /// A held private file: the mode check plus no extended ACL ALLOW entry for another
    /// principal (macOS ACL, or Linux NFSv4; an ACL inherited from the parent directory can
    /// grant a read the `0o600` mode does not show).
    fn private_entry(entry: &Entry, uid: u32) -> Result<(), Error> {
        private_file(&metadata(entry)?, uid)?;
        match crate::platform::fs::private_file_acl_refusal(entry.file.as_raw_fd()) {
            None => Ok(()),
            Some(_) => Err(Error::UnsafeFile),
        }
    }
    /// The held descriptor and the path observed an unchanged object. A directory's link
    /// count is its subdirectory count, so it moves whenever a sibling is created or
    /// removed under it (a shared TMPDIR, `~/.claude/accounts` gaining a handle dir) and
    /// can differ between the two observations; only a file's count is identity.
    ///
    /// A held directory whose link count is 0 has been removed (the descriptor outlived its
    /// name), so a directory is identity only while it is still linked.
    pub(super) fn same_identity(held: &Metadata, named: &Metadata) -> bool {
        identity_matches(&Identity::of(held), &Identity::of(named))
    }
    /// The comparable facts of one observation, separate from `Metadata` so the policy can
    /// be exercised with values a given filesystem may not produce (btrfs reports 1 for every
    /// directory link count).
    #[derive(Clone, Copy, Debug)]
    pub(super) struct Identity {
        pub(super) dev: u64,
        pub(super) ino: u64,
        pub(super) uid: u32,
        /// The full `st_mode`, so the file type is part of the comparison.
        pub(super) mode: u32,
        pub(super) nlink: u64,
    }
    impl Identity {
        fn of(meta: &Metadata) -> Self {
            Self {
                dev: meta.dev(),
                ino: meta.ino(),
                uid: meta.uid(),
                mode: meta.mode(),
                nlink: meta.nlink(),
            }
        }
        // `S_IFMT`/`S_IFDIR` are `u32` on Linux and `u16` on macOS, so the cast is needed on
        // one platform and flagged on the other.
        #[allow(clippy::unnecessary_cast)]
        fn is_dir(&self) -> bool {
            self.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
        }
    }
    pub(super) fn identity_matches(held: &Identity, named: &Identity) -> bool {
        held.dev == named.dev
            && held.ino == named.ino
            && held.uid == named.uid
            && held.mode == named.mode
            && if held.is_dir() {
                held.nlink != 0
            } else {
                held.nlink == named.nlink
            }
    }
    fn metadata(entry: &Entry) -> Result<Metadata, Error> {
        let held = entry.file.metadata().map_err(|_| Error::Unavailable)?;
        let named = std::fs::symlink_metadata(&entry.path).map_err(|_| Error::NamespaceChanged)?;
        if !same_identity(&held, &named) {
            return Err(Error::NamespaceChanged);
        }
        Ok(held)
    }
    fn sidecar_name(name: &OsStr, suffix: &str) -> OsString {
        let mut full = name.to_os_string();
        full.push(suffix);
        full
    }
    fn sidecar(parent: &File, path: &Path, name: &OsStr, uid: u32) -> Result<Option<Entry>, Error> {
        match open_at(parent, name, libc::O_RDONLY | FILE_FLAGS) {
            Ok(file) => {
                let entry = Entry {
                    file,
                    path: path.to_path_buf(),
                };
                private_entry(&entry, uid)?;
                Ok(Some(entry))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A dangling symlink is not genuine absence.
                match std::fs::symlink_metadata(path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    _ => Err(Error::UnsafeFile),
                }
            }
            Err(_) => Err(Error::UnsafeFile),
        }
    }

    fn sidecars_recheck(
        parent: &Entry,
        name: &OsStr,
        entries: &mut [Option<Entry>],
        uid: u32,
    ) -> Result<(), Error> {
        for (index, suffix) in SUFFIXES.into_iter().enumerate() {
            if let Some(entry) = &entries[index] {
                private_entry(entry, uid)?;
            }
            #[cfg(test)]
            super::tests::sidecar_interposition();
            let side_name = sidecar_name(name, suffix);
            let current = sidecar(&parent.file, &parent.path.join(&side_name), &side_name, uid)?;
            let sidecar_changed = match (&entries[index], &current) {
                (Some(held), Some(fresh)) => !same(
                    &held.file.metadata().map_err(|_| Error::Unavailable)?,
                    &fresh.file.metadata().map_err(|_| Error::Unavailable)?,
                ),
                (Some(_), None) => true,
                _ => false,
            };
            if sidecar_changed {
                return Err(Error::NamespaceChanged);
            }
            if entries[index].is_none() {
                entries[index] = current;
            }
        }
        Ok(())
    }

    impl HeldDatabase {
        pub(super) fn acquire(dir: &Path, name: &OsStr, uid: u32) -> Result<Self, Error> {
            Self::acquire_mode(dir, name, uid, true)
        }
        pub(super) fn acquire_existing(dir: &Path, name: &OsStr, uid: u32) -> Result<Self, Error> {
            Self::acquire_mode(dir, name, uid, false)
        }
        fn acquire_mode(dir: &Path, name: &OsStr, uid: u32, create: bool) -> Result<Self, Error> {
            name_cstring(name)?;
            if name.as_bytes().len() > 247
                || !dir.is_absolute()
                || dir
                    .as_os_str()
                    .as_bytes()
                    .split(|c| *c == b'/')
                    .any(|c| c == b"." || c == b"..")
            {
                return Err(invalid());
            }
            let root = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(if dir == Path::new("/") {
                    DIR_FLAGS
                } else {
                    ANCESTOR_FLAGS
                })
                .open("/")
                .map_err(|_| Error::Unavailable)?;
            let mut directories = vec![Entry {
                file: root,
                path: PathBuf::from("/"),
            }];
            directory(&metadata(&directories[0])?, uid, dir == Path::new("/"))?;
            acl_clear(&directories[0], dir == Path::new("/"))?;
            let components: Vec<_> = dir.components().skip(1).collect();
            for (index, component) in components.iter().enumerate() {
                let Component::Normal(name) = component else {
                    return Err(invalid());
                };
                let parent = directories.last().ok_or(Error::Unavailable)?;
                let path = parent.path.join(name);
                let flags = if index + 1 == components.len() {
                    DIR_FLAGS
                } else {
                    ANCESTOR_FLAGS
                };
                let file =
                    open_at(&parent.file, name, flags).map_err(|_| Error::UnsafeDirectory)?;
                let entry = Entry { file, path };
                directory(&metadata(&entry)?, uid, entry.path == dir)?;
                acl_clear(&entry, entry.path == dir)?;
                directories.push(entry);
            }
            let parent = directories.last().ok_or(Error::Unavailable)?;
            let mut sidecars = Vec::new();
            for suffix in SUFFIXES {
                let side_name = sidecar_name(name, suffix);
                sidecars.push(sidecar(
                    &parent.file,
                    &dir.join(&side_name),
                    &side_name,
                    uid,
                )?);
            }
            let path = dir.join(name);
            let file = match open_at(&parent.file, name, libc::O_RDWR | FILE_FLAGS) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                    directories_recheck(&directories, uid)?;
                    sidecars_recheck(parent, name, &mut sidecars, uid)?;
                    open_at(
                        &parent.file,
                        name,
                        libc::O_RDWR | FILE_FLAGS | libc::O_CREAT | libc::O_EXCL,
                    )
                    .map_err(|_| Error::Unavailable)?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(Error::Unavailable)
                }
                Err(_) => return Err(Error::UnsafeFile),
            };
            let database = Entry { file, path };
            private_entry(&database, uid)?;
            let held = Self {
                directories,
                database,
                sidecars: std::sync::Mutex::new(sidecars),
                uid,
            };
            held.recheck()?;
            Ok(held)
        }
        pub(super) fn recheck(&self) -> Result<(), Error> {
            let last = self
                .directories
                .len()
                .checked_sub(1)
                .ok_or(Error::Unavailable)?;
            directories_recheck(&self.directories, self.uid)?;
            private_entry(&self.database, self.uid)?;
            let parent = &self.directories[last];
            let name = self.database.path.file_name().ok_or_else(invalid)?;
            let mut sidecars = self.sidecars.lock().map_err(|_| Error::Unavailable)?;
            sidecars_recheck(parent, name, &mut sidecars, self.uid)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    #[cfg(unix)]
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    std::thread_local! {
        static SIDECAR_INTERPOSITION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    }
    #[cfg(unix)]
    pub(super) fn sidecar_interposition() {
        let action = SIDECAR_INTERPOSITION.with(|slot| slot.borrow_mut().take());
        if let Some(action) = action {
            action();
        }
    }
    #[cfg(unix)]
    struct Interposition;
    #[cfg(unix)]
    impl Interposition {
        fn install(action: impl FnOnce() + 'static) -> Self {
            SIDECAR_INTERPOSITION.with(|slot| {
                assert!(slot.borrow().is_none());
                *slot.borrow_mut() = Some(Box::new(action));
            });
            Self
        }
    }
    #[cfg(unix)]
    impl Drop for Interposition {
        fn drop(&mut self) {
            SIDECAR_INTERPOSITION.with(|slot| {
                slot.borrow_mut().take();
            });
        }
    }
    #[cfg(unix)]
    struct Fixture {
        _tmp: TempDir,
        prior_umask: libc::mode_t,
    }
    #[cfg(unix)]
    impl Drop for Fixture {
        fn drop(&mut self) {
            // SAFETY: every caller holds the shared test_env lock until after this drop.
            unsafe {
                libc::umask(self.prior_umask);
            }
        }
    }
    #[cfg(unix)]
    fn fixture() -> (Fixture, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let dir = fs::canonicalize(tmp.path()).unwrap().join("private");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: the caller holds test_env; Fixture restores on success or panic.
        let prior_umask = unsafe { libc::umask(0o077) };
        (
            Fixture {
                _tmp: tmp,
                prior_umask,
            },
            dir,
        )
    }
    #[cfg(unix)]
    fn private_file(path: &Path) {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        std::io::Write::write_all(&mut file, b"fixture").unwrap();
        // Fixture mode is explicit even under an inherited restrictive umask.
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
    }
    #[cfg(unix)]
    fn acquire(dir: &Path) -> Result<SecureDatabase, SecureDatabaseError> {
        SecureDatabase::acquire(dir, OsStr::new("messages.sqlite"))
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_existing_only_absence_never_creates_a_file() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let path = dir.join("messages.sqlite");
        let result = SecureDatabase::acquire_existing(&dir, OsStr::new("messages.sqlite"));
        assert!(
            !path.exists(),
            "existing-only acquisition must never create the missing database"
        );
        assert!(matches!(result, Err(SecureDatabaseError::Unavailable)));
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_existing_only_accepts_safe_file_without_truncation() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let path = dir.join("messages.sqlite");
        private_file(&path);
        let database =
            SecureDatabase::acquire_existing(&dir, OsStr::new("messages.sqlite")).unwrap();
        database.recheck().unwrap();
        assert_eq!(fs::read(path).unwrap(), b"fixture");
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_existing_only_refuses_symlink_without_touching_target() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let target = dir.join("target");
        private_file(&target);
        let path = dir.join("messages.sqlite");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(matches!(
            SecureDatabase::acquire_existing(&dir, OsStr::new("messages.sqlite")),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        assert_eq!(fs::read(target).unwrap(), b"fixture");
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_rejects_hardlinked_private_file() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let path = dir.join("messages.sqlite");
        private_file(&path);
        fs::hard_link(&path, dir.join("alias")).unwrap();
        assert!(
            matches!(acquire(&dir), Err(SecureDatabaseError::UnsafeFile)),
            "hardlinked private database must be refused"
        );
        assert_eq!(fs::read(path).unwrap(), b"fixture");
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_acquires_and_uses_existing_held_file() {
        use std::io::Write;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let path = dir.join("messages.sqlite");
        private_file(&path);
        let database = acquire(&dir).unwrap();
        database
            .with_file(|mut file| file.write_all(b"changed"))
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"changed");
        database.recheck().unwrap();
    }

    // A directory's link count moves with sibling creation and is not comparable between the
    // held fstat and the path lstat; a file's count is identity; a removed (nlink 0) directory
    // is not. Synthetic observations, so the result does not depend on the filesystem
    // (btrfs reports 1 for every directory). Old code compared nlink for directories too.
    #[cfg(unix)]
    #[test]
    #[allow(clippy::unnecessary_cast)] // mode_t is u32 on Linux, u16 on macOS
    fn same_identity_ignores_directory_link_count_but_not_file_link_count() {
        use unix::{identity_matches, Identity};
        let dir = |nlink| Identity {
            dev: 7,
            ino: 42,
            uid: 501,
            mode: libc::S_IFDIR as u32 | 0o700,
            nlink,
        };
        let file = |nlink| Identity {
            dev: 7,
            ino: 43,
            uid: 501,
            mode: libc::S_IFREG as u32 | 0o600,
            nlink,
        };
        assert!(
            identity_matches(&dir(2), &dir(3)),
            "sibling created between observations"
        );
        assert!(identity_matches(&dir(1), &dir(1)));
        assert!(
            !identity_matches(&dir(0), &dir(0)),
            "removed directory (held nlink 0)"
        );
        assert!(identity_matches(&file(1), &file(1)));
        assert!(!identity_matches(&file(1), &file(2)), "hard-link alias");
        let mut moved = dir(2);
        moved.ino = 99;
        assert!(!identity_matches(&dir(2), &moved), "different object");
        let mut other_owner = dir(2);
        other_owner.uid = 0;
        assert!(!identity_matches(&dir(2), &other_owner));
        let mut as_file = dir(2);
        as_file.mode = libc::S_IFREG as u32 | 0o700;
        assert!(
            !identity_matches(&dir(2), &as_file),
            "file substituted for directory"
        );
    }

    // The real descriptor/path pair of an unchanged directory still matches.
    #[cfg(unix)]
    #[test]
    fn same_identity_accepts_an_unchanged_real_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let held = std::fs::File::open(tmp.path()).unwrap().metadata().unwrap();
        let named = fs::symlink_metadata(tmp.path()).unwrap();
        assert!(unix::same_identity(&held, &named));
    }

    /// Restores a directory's mode on drop so the tempdir can be removed after a panic.
    #[cfg(unix)]
    struct RestoreMode(std::path::PathBuf);
    #[cfg(unix)]
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    // Production hosts routinely carry a searchable-but-unreadable ancestor (`/home` at
    // 0o711, a root-owned 0o710 staging mount). The ancestry walk only needs to traverse
    // it, so it must not demand read permission. Old code opened every ancestor
    // `O_RDONLY` and refused with `UnsafeDirectory` (EACCES) here.
    #[cfg(unix)]
    #[test]
    fn secure_database_accepts_searchable_but_unreadable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let ancestor = dir.parent().unwrap().to_path_buf();
        let _restore = RestoreMode(ancestor.clone());
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o300)).unwrap();
        let database = acquire(&dir).unwrap();
        database.recheck().unwrap();
    }

    // The ancestor policy for the shapes a hardened host produces. `root:root 0750` plus a
    // POSIX ACL cannot be built unprivileged, so the policy is driven with the owner and mode
    // a `stat` of such an ancestor reports. Read bits and the ACL are irrelevant to trust;
    // write bits, a foreign owner and the private-leaf rule are not.
    #[cfg(unix)]
    #[test]
    fn directory_policy_ignores_read_bits_but_refuses_writable_or_foreign_ancestors() {
        let me = 501;
        for (owner, mode) in [
            (0, 0o750),
            (0, 0o710),
            (0, 0o700),
            (0, 0o755),
            (me, 0o750),
            (me, 0o710),
            (me, 0o100),
            (0, 0o1777),
        ] {
            assert!(
                unix::directory_policy(owner, mode, me, false),
                "ancestor owner {owner} mode {mode:o} must be accepted"
            );
        }
        for (owner, mode) in [
            (0, 0o770),
            (0, 0o757),
            (0, 0o777),
            (me, 0o770),
            (me, 0o707),
            (me, 0o1777),
            (me + 1, 0o750),
            (me + 1, 0o700),
        ] {
            assert!(
                !unix::directory_policy(owner, mode, me, false),
                "ancestor owner {owner} mode {mode:o} must be refused"
            );
        }
        assert!(unix::directory_policy(me, 0o700, me, true));
        assert!(!unix::directory_policy(0, 0o700, me, true), "leaf is ours");
        assert!(!unix::directory_policy(me, 0o750, me, true), "leaf is 0700");
    }

    // Search-only ancestors of every owner-class shape are traversed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn secure_database_accepts_every_search_only_ancestor_mode() {
        use std::os::unix::fs::PermissionsExt;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let ancestor = dir.parent().unwrap().to_path_buf();
        let _restore = RestoreMode(ancestor.clone());
        for mode in [0o100, 0o300] {
            fs::set_permissions(&ancestor, fs::Permissions::from_mode(mode)).unwrap();
            acquire(&dir)
                .unwrap_or_else(|e| panic!("search-only ancestor {mode:o} refused: {e:?}"))
                .recheck()
                .unwrap();
        }
    }

    // Unreadable is not the same as trusted: an ancestor another user could rename or
    // replace is refused whatever its read bits, and nothing is created beneath it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn secure_database_refuses_unreadable_but_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let ancestor = dir.parent().unwrap().to_path_buf();
        let _restore = RestoreMode(ancestor.clone());
        for mode in [0o370, 0o307, 0o330, 0o303] {
            fs::set_permissions(&ancestor, fs::Permissions::from_mode(mode)).unwrap();
            let outcome = acquire(&dir);
            fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
            assert!(
                matches!(outcome, Err(SecureDatabaseError::UnsafeDirectory)),
                "writable ancestor {mode:o} accepted"
            );
            assert!(!dir.join("messages.sqlite").exists());
        }
        acquire(&dir).unwrap();
    }

    // A symlinked ancestor is refused even when the target is search-only.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn secure_database_refuses_symlinked_ancestor_over_unreadable_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let outer = dir.parent().unwrap().to_path_buf();
        let real = outer.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let private = real.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let link = outer.join("link");
        symlink(&real, &link).unwrap();
        let _restore = RestoreMode(real.clone());
        fs::set_permissions(&real, fs::Permissions::from_mode(0o300)).unwrap();
        let through_link = link.join("private");
        let outcome = acquire(&through_link);
        let control = acquire(&private);
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            matches!(outcome, Err(SecureDatabaseError::UnsafeDirectory)),
            "symlinked ancestor accepted"
        );
        control.expect("the same target without the symlink is accepted");
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_creates_missing_database_at_private_mode() {
        use std::os::unix::fs::MetadataExt;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let database = acquire(&dir).unwrap();
        database.recheck().unwrap();
        let meta = fs::metadata(dir.join("messages.sqlite")).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!(meta.nlink(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_rejects_symlink_and_special_database() {
        use std::os::unix::fs::symlink;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let path = dir.join("messages.sqlite");
        let victim = dir.join("victim");
        private_file(&victim);
        symlink(&victim, &path).unwrap();
        assert!(acquire(&dir).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"fixture");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(acquire(&dir).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_rejects_wrong_private_modes_before_operation() {
        use std::os::unix::fs::PermissionsExt;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            acquire(&dir),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert!(!dir.join("messages.sqlite").exists());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("messages.sqlite");
        private_file(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            acquire(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        assert_eq!(fs::read(path).unwrap(), b"fixture");
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_refuses_synthetic_different_owner() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        // Only expected UID is synthetic; real held metadata remains the OS result.
        // SAFETY: geteuid is observational and has no preconditions.
        let other = unsafe { libc::geteuid() }.wrapping_add(1);
        assert!(matches!(
            unix::HeldDatabase::acquire(&dir, OsStr::new("messages.sqlite"), other),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert!(!dir.join("messages.sqlite").exists());
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_refuses_parent_symlink_and_namespace_substitution() {
        use std::os::unix::fs::symlink;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let alias = dir.with_file_name("alias");
        symlink(&dir, &alias).unwrap();
        assert!(matches!(
            acquire(&alias),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert!(!dir.join("messages.sqlite").exists());
        let database = acquire(&dir).unwrap();
        let old = dir.with_file_name("retired");
        fs::rename(&dir, &old).unwrap();
        fs::create_dir(&dir).unwrap();
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::NamespaceChanged)
        ));
        let mut called = false;
        assert!(database
            .with_file(|_| {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called, "namespace refusal must precede callback");
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_refuses_file_replacement_before_and_after_use() {
        use std::io::Write;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let path = dir.join("messages.sqlite");
        private_file(&path);
        let database = acquire(&dir).unwrap();
        let result = database.with_file(|mut file| {
            fs::rename(&path, dir.join("old.sqlite"))?;
            private_file(&path);
            file.write_all(b"changed")
        });
        assert!(matches!(result, Err(SecureDatabaseError::NamespaceChanged)));
        assert_eq!(fs::read(&path).unwrap(), b"fixture");
        assert_eq!(fs::read(dir.join("old.sqlite")).unwrap(), b"changed");
        let mut called = false;
        assert!(database
            .with_file(|_| {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called);
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_validates_each_existing_sidecar_before_creation() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        for suffix in ["-wal", "-shm", "-journal"] {
            let side = dir.join(format!("messages.sqlite{suffix}"));
            private_file(&side);
            fs::hard_link(&side, dir.join("alias")).unwrap();
            assert!(matches!(
                acquire(&dir),
                Err(SecureDatabaseError::UnsafeFile)
            ));
            assert!(!dir.join("messages.sqlite").exists());
            fs::remove_file(dir.join("alias")).unwrap();
            fs::set_permissions(&side, fs::Permissions::from_mode(0o640)).unwrap();
            assert!(acquire(&dir).is_err());
            fs::remove_file(&side).unwrap();
            symlink(dir.join("missing"), &side).unwrap();
            assert!(acquire(&dir).is_err());
            fs::remove_file(&side).unwrap();
            fs::create_dir(&side).unwrap();
            assert!(acquire(&dir).is_err());
            fs::remove_dir(&side).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_rechecks_existing_and_new_sidecars() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let side = dir.join("messages.sqlite-wal");
        private_file(&side);
        let database = acquire(&dir).unwrap();
        database.recheck().unwrap();
        fs::rename(&side, dir.join("old-wal")).unwrap();
        private_file(&side);
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::NamespaceChanged)
        ));
        let database = acquire(&dir).unwrap();
        let new_side = dir.join("messages.sqlite-shm");
        private_file(&new_side);
        database.recheck().unwrap();
        fs::rename(&new_side, dir.join("old-shm")).unwrap();
        private_file(&new_side);
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::NamespaceChanged)
        ));
        let database = acquire(&dir).unwrap();
        fs::hard_link(&new_side, dir.join("alias")).unwrap();
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::UnsafeFile)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_refuses_relative_path_and_component_escape() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        assert!(matches!(
            acquire(Path::new("relative")),
            Err(SecureDatabaseError::InvalidPath)
        ));
        for name in ["", ".", "..", "nested/db", "bad\0name"] {
            assert!(matches!(
                SecureDatabase::acquire(&dir, OsStr::new(name)),
                Err(SecureDatabaseError::InvalidPath)
            ));
        }
        assert!(matches!(
            acquire(&dir.join("..")),
            Err(SecureDatabaseError::InvalidPath)
        ));
        assert!(!dir.join("messages.sqlite").exists());
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_rejects_other_user_writable_ancestor() {
        // Synthetic ownership exercises the SAME classifier used on every held
        // ancestor's real fstat. No chown or claim of a real foreign-owned fixture.
        let uid = 1001;
        let foreign = 1002;
        assert!(
            !unix::directory_policy(foreign, 0o755, uid, false),
            "foreign owner can replace child entries"
        );
        assert!(!unix::directory_policy(foreign, 0o1777, uid, false));
        assert!(unix::directory_policy(0, 0o1777, uid, false));
        assert!(unix::directory_policy(uid, 0o755, uid, false));
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_rejects_nonsticky_world_writable_ancestor_before_creation() {
        use std::os::unix::fs::PermissionsExt;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let parent = dir.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            acquire(&dir),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert!(!dir.join("messages.sqlite").exists());
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    }

    // MED-A: an ALLOW ACL granting entry changes on an ancestor refuses the database
    // before anything is created, though the mode bits are clean.
    #[cfg(target_os = "macos")]
    #[test]
    fn secure_database_rejects_an_acl_granting_entry_changes_on_an_ancestor() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let parent = dir.parent().unwrap();
        crate::platform::fs::tests::chmod_add_acl(parent, "everyone allow add_file");
        assert!(matches!(
            acquire(&dir),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert!(!dir.join("messages.sqlite").exists());
    }

    // S-MED-2: a read grant on the database file (what a parent-directory ACL inherits)
    // widens access beyond the `0o600` mode; the file is refused, the directory path is not.
    #[cfg(target_os = "macos")]
    #[test]
    fn secure_database_rejects_an_acl_read_grant_on_the_database_file() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let path = dir.join("messages.sqlite");
        private_file(&path);
        acquire(&dir).expect("control: no ACL on the file");
        crate::platform::fs::tests::chmod_add_acl(&path, "everyone allow read");
        assert!(
            matches!(acquire(&dir), Err(SecureDatabaseError::UnsafeFile)),
            "ACL read grant on the database accepted"
        );
    }

    // A sidecar (`-wal`) carries the same rule.
    #[cfg(target_os = "macos")]
    #[test]
    fn secure_database_rejects_an_acl_read_grant_on_a_sidecar() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let side = dir.join("messages.sqlite-wal");
        private_file(&side);
        crate::platform::fs::tests::chmod_add_acl(&side, "everyone allow read");
        assert!(
            matches!(acquire(&dir), Err(SecureDatabaseError::UnsafeFile)),
            "ACL read grant on a sidecar accepted"
        );
    }

    // A regular file where an ancestor directory should be is refused.
    #[cfg(unix)]
    #[test]
    fn secure_database_refuses_a_non_directory_ancestor() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = fixture();
        let file = dir.join("not-a-dir");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(
            acquire(&file.join("private")),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn secure_database_refuses_sidecar_change_between_held_and_fresh_observation() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let _env = crate::platform::test_env::lock();
        for replacement in [false, true] {
            let (_tmp, dir) = fixture();
            let side = dir.join("messages.sqlite-wal");
            private_file(&side);
            let database = acquire(&dir).unwrap();
            let interposed = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&interposed);
            let action_side = side.clone();
            let retired = dir.join("retired-wal");
            let action_retired = retired.clone();
            let _interposition = Interposition::install(move || {
                if replacement {
                    fs::rename(&action_side, &action_retired).unwrap();
                    private_file(&action_side);
                } else {
                    fs::remove_file(&action_side).unwrap();
                }
                observed.store(true, Ordering::SeqCst);
            });
            let mut called = false;
            let result = database.with_file(|_| {
                called = true;
                Ok(())
            });
            assert!(
                interposed.load(Ordering::SeqCst),
                "real structural interposition must execute"
            );
            assert!(!called, "fresh sidecar mismatch must prevent callback");
            assert!(matches!(result, Err(SecureDatabaseError::NamespaceChanged)));
            if replacement {
                assert_eq!(fs::read(&side).unwrap(), b"fixture");
                assert_eq!(fs::read(retired).unwrap(), b"fixture");
            } else {
                assert!(!side.exists());
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn secure_database_nonunix_refuses_before_writes() {
        let _env = crate::platform::test_env::lock();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("not-created");
        assert!(matches!(
            SecureDatabase::acquire(&dir, OsStr::new("messages.sqlite")),
            Err(SecureDatabaseError::UnsupportedPlatform)
        ));
        assert!(!dir.exists());
        assert!(!dir.join("messages.sqlite").exists());
    }

    // Native Windows only: cross compilation checks the code, never the ACLs and
    // share modes these tests observe. The fixture leaf is created with the
    // INHERITABLE owner-only descriptor, as the pool's directory is; its
    // ancestors are the ordinary %TEMP% chain, so the ancestry policy is
    // exercised against real Windows default ACLs.
    #[cfg(windows)]
    fn windows_fixture() -> (TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        crate::platform::fs_windows_acl::create_private_directory_inheriting(&dir).unwrap();
        (tmp, dir)
    }
    /// R1 F4: libtest captures `print!`/`eprintln!` from a PASSING test unless
    /// the run passes `--nocapture`; a direct stderr write is not captured, so
    /// these native diagnostics reach the CI log with no workflow change.
    #[cfg(windows)]
    fn emit_diagnostic(line: &str) {
        use std::io::Write as _;
        let _ = std::io::stderr().write_all(format!("{line}\n").as_bytes());
    }
    #[cfg(windows)]
    fn windows_private_file(path: &std::path::Path) {
        drop(crate::platform::fs_windows_acl::create_new_private_file(path).unwrap());
    }
    #[cfg(windows)]
    fn windows_acquire(dir: &std::path::Path) -> Result<SecureDatabase, SecureDatabaseError> {
        // The fixture leaf is the POOL shape (inheriting), so the pool mode is
        // the one that applies to it (R1 M2); strict mode is tested separately.
        SecureDatabase::acquire_pool_ledger(dir, OsStr::new("messages.sqlite"))
    }
    #[cfg(windows)]
    fn windows_acquire_existing(
        dir: &std::path::Path,
    ) -> Result<SecureDatabase, SecureDatabaseError> {
        SecureDatabase::acquire_pool_ledger_existing(dir, OsStr::new("messages.sqlite"))
    }
    /// The strict (default) constructors, for the mode-separation tests.
    #[cfg(windows)]
    fn windows_strict_acquire(
        dir: &std::path::Path,
    ) -> Result<SecureDatabase, SecureDatabaseError> {
        SecureDatabase::acquire(dir, OsStr::new("messages.sqlite"))
    }
    #[cfg(windows)]
    fn windows_strict_acquire_existing(
        dir: &std::path::Path,
    ) -> Result<SecureDatabase, SecureDatabaseError> {
        SecureDatabase::acquire_existing(dir, OsStr::new("messages.sqlite"))
    }
    /// A SID from its sub-authorities under SECURITY_NT_AUTHORITY (5).
    #[cfg(windows)]
    fn windows_sid(parts: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, parts.len() as u8, 0, 0, 0, 0, 0, 5];
        for part in parts {
            bytes.extend(part.to_le_bytes());
        }
        bytes
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_existing_only_absence_never_creates_a_file() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let path = dir.join("messages.sqlite");
        let result = windows_acquire_existing(&dir);
        assert!(
            !path.exists(),
            "existing-only acquisition must never create the missing database"
        );
        assert!(matches!(result, Err(SecureDatabaseError::Unavailable)));
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_refuses_a_broad_dacl_database() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let path = dir.join("messages.sqlite");
        // Owner-only DACL replaced by Everyone full control: the shape the old
        // UnsupportedPlatform stub could never see.
        drop(
            crate::platform::fs_windows_acl_tests::file_with_sddl(&path, "D:P(A;;FA;;;WD)")
                .unwrap(),
        );
        assert!(
            matches!(windows_acquire(&dir), Err(SecureDatabaseError::UnsafeFile)),
            "a database readable and writable by Everyone must be refused"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_refuses_synthetic_different_owner() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        // Only the expected identity is synthetic: a foreign-OWNED file cannot be
        // constructed on an unprivileged host, so the SAME owner policy is driven
        // with a SID that is not the token's.
        let foreign =
            crate::platform::fs_windows_acl::UserSid::synthetic(&windows_sid(&[21, 42, 8]));
        assert!(matches!(
            super::windows::HeldDatabase::acquire(
                &dir,
                OsStr::new("messages.sqlite"),
                &foreign,
                LeafPolicy::PoolLedger,
            ),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert!(!dir.join("messages.sqlite").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_rejects_a_hardlinked_database() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let path = dir.join("messages.sqlite");
        windows_private_file(&path);
        std::fs::hard_link(&path, dir.join("alias")).unwrap();
        assert!(
            matches!(windows_acquire(&dir), Err(SecureDatabaseError::UnsafeFile)),
            "hardlinked private database must be refused"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_refuses_a_symlink_at_the_database_path() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let target = dir.join("target");
        windows_private_file(&target);
        let path = dir.join("messages.sqlite");
        std::os::windows::fs::symlink_file(&target, &path)
            .expect("creating a file symlink needs Developer Mode or elevation");
        assert!(matches!(
            windows_acquire(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_recheck_detects_a_replaced_database() {
        use std::io::Write;
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let path = dir.join("messages.sqlite");
        windows_private_file(&path);
        let database = windows_acquire(&dir).unwrap();
        database.recheck().unwrap();
        std::fs::rename(&path, dir.join("retired.sqlite")).unwrap();
        windows_private_file(&path);
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::NamespaceChanged)
        ));
        let mut called = false;
        assert!(database
            .with_file(|_| {
                called = true;
                Ok(())
            })
            .is_err());
        assert!(!called, "namespace refusal must precede callback");
        assert!(database
            .with_file(|mut file| file.write_all(b"changed"))
            .is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_creates_a_missing_database_privately() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let database = windows_acquire(&dir).unwrap();
        database.recheck().unwrap();
        let path = dir.join("messages.sqlite");
        let file = crate::platform::fs_windows_acl::open_private_shared(&path, false)
            .expect("the created database carries the owner-only descriptor");
        drop(file);
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_acquires_and_uses_existing_held_file() {
        use std::io::{Read, Seek, Write};
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let path = dir.join("messages.sqlite");
        windows_private_file(&path);
        let database = windows_acquire(&dir).unwrap();
        database
            .with_file(|mut file| file.write_all(b"changed"))
            .unwrap();
        // Read back through the SAME held handle: the write went to the guarded
        // file, not to some path that merely shares its name.
        let contents = database
            .with_file(|mut file| {
                file.seek(std::io::SeekFrom::Start(0))?;
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                Ok(contents)
            })
            .unwrap();
        assert_eq!(contents, "changed");
        database.recheck().unwrap();
        // A co-opening client uses the Win32 default share mode, which our held
        // access must not violate; this is the SQLite open sequence.
        let peer = crate::platform::fs_windows_acl::open_private_shared(&path, true).unwrap();
        drop(peer);
        database.recheck().unwrap();
    }

    // Each sidecar is validated BEFORE the database is created, as on unix: a
    // broad-DACL `-wal` refuses acquisition and nothing is created beside it.
    #[cfg(windows)]
    #[test]
    fn windows_secure_database_validates_an_existing_sidecar_before_creation() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let side = dir.join("messages.sqlite-wal");
        drop(
            crate::platform::fs_windows_acl_tests::file_with_sddl(&side, "D:P(A;;FA;;;WD)")
                .unwrap(),
        );
        assert!(matches!(
            windows_acquire(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        assert!(!dir.join("messages.sqlite").exists());
        std::fs::remove_file(&side).unwrap();
        // A dangling symlink at a sidecar name is not genuine absence either.
        std::os::windows::fs::symlink_file(dir.join("missing"), &side)
            .expect("creating a file symlink needs Developer Mode or elevation");
        assert!(matches!(
            windows_acquire(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        std::fs::remove_file(&side).unwrap();
        assert!(windows_acquire(&dir).is_ok(), "control: absent sidecars");
    }

    // The sidecar SQLite creates for itself: a plain `CreateFileW` inside the
    // leaf, so the DACL and the NW|NR label are INHERITED rather than written by
    // csq. That is the shape the pool's journal has, and it must be accepted —
    // while the database itself keeps the explicit protected shape.
    #[cfg(windows)]
    #[test]
    fn windows_secure_database_accepts_a_sidecar_that_inherited_the_private_shape() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let side = dir.join("messages.sqlite-wal");
        std::fs::File::create(&side).unwrap();
        // Control: the file really did inherit (the exact check refuses it) and
        // the inherited-aware check is what accepts it.
        let inherited = crate::platform::fs_windows_acl::open_unchecked_shared_handle(&side, false)
            .expect("the inherited grant allows a read handle");
        // Native diagnostic (ROOT condition 1): print the runner's REAL owner and
        // DACL for the leaf and the SQLite-style sidecar BEFORE any assertion, so
        // a red run shows which token/owner path was exercised. Fixed tag.
        emit_diagnostic(&format!(
            "[pool-sidecar-sddl] sidecar={}",
            crate::platform::fs_windows_acl::observed_sddl(&inherited)
                .unwrap_or_else(|_| "<unreadable>".to_string())
        ));
        emit_diagnostic(&format!(
            "[pool-sidecar-sddl] leaf={}",
            crate::platform::fs_windows_acl::observed_sddl_at(&dir)
                .unwrap_or_else(|_| "<unreadable>".to_string())
        ));
        assert!(
            crate::platform::fs_windows_acl::check_private_handle(&inherited).is_err(),
            "an inherited DACL is not the at-creation protected shape"
        );
        assert!(
            crate::platform::fs_windows_acl::check_private_inherited_handle_as(
                &inherited,
                &crate::platform::fs_windows_acl::UserSid::current().unwrap()
            )
            .is_ok()
        );
        drop(inherited);
        let database = windows_acquire(&dir).expect("an inherited private sidecar is accepted");
        emit_diagnostic(&format!(
            "[pool-sidecar-sddl] database={}",
            crate::platform::fs_windows_acl::observed_sddl_at(&dir.join("messages.sqlite"))
                .unwrap_or_else(|_| "<unreadable>".to_string())
        ));
        database.recheck().unwrap();
        assert!(dir.join("messages.sqlite").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_secure_database_rejects_relative_path_and_component_escape() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        assert!(matches!(
            windows_acquire(std::path::Path::new("relative")),
            Err(SecureDatabaseError::InvalidPath)
        ));
        for name in [
            "",
            ".",
            "..",
            "nested/db",
            "nested\\db",
            "bad:name",
            "bad\0name",
        ] {
            assert!(
                matches!(
                    SecureDatabase::acquire(&dir, OsStr::new(name)),
                    Err(SecureDatabaseError::InvalidPath)
                ),
                "{name:?} must be refused"
            );
        }
        assert!(matches!(
            windows_acquire(&dir.join("..")),
            Err(SecureDatabaseError::InvalidPath)
        ));
        assert!(!dir.join("messages.sqlite").exists());
    }

    // R1 M2 census: the pool mode has exactly ONE production caller (the pool
    // execution ledger). Comment-only mentions (docs) do not count. Reds if a
    // second call site appears anywhere in the Rust sources.
    #[test]
    fn only_the_execution_ledger_calls_the_pool_mode() {
        let root = crate::testing::manifest_dir(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("the workspace root above csq-core")
            .to_path_buf();
        let allowed = ["csq-core/src/pool/execution_ledger.rs"];
        let mut offenders = Vec::new();
        let mut files = 0_usize;
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("scan a workspace directory") {
                let entry = entry.expect("directory entry");
                let name = entry.file_name();
                // Hidden directories are tooling, not sources — they include the
                // repo's `.csq-wt/` worktree root, whose full copies of the crate
                // would otherwise appear as a second "caller" of this path.
                if name.to_string_lossy().starts_with('.')
                    || name == "target"
                    || name == "node_modules"
                {
                    continue;
                }
                let path = entry.path();
                if entry.file_type().expect("entry type").is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|extension| extension != "rs") {
                    continue;
                }
                files += 1;
                let text = std::fs::read_to_string(&path).expect("read a Rust source");
                let call = text.lines().any(|line| {
                    let line = line.trim_start();
                    !line.starts_with("//") && line.contains("acquire_pool_ledger")
                });
                let relative = path
                    .strip_prefix(&root)
                    .expect("path under the workspace root")
                    .to_string_lossy()
                    .replace('\\', "/");
                // This module defines the mode and exercises it in its tests.
                let defining_module = relative == "csq-core/src/messaging/storage/secure.rs";
                if call && !defining_module && !allowed.contains(&relative.as_str()) {
                    offenders.push(relative);
                }
            }
        }
        assert!(
            files > 100,
            "the census must have scanned the workspace, saw {files} Rust files"
        );
        assert!(
            offenders.is_empty(),
            "the pool mode must have one production caller, found {offenders:?}"
        );
    }

    // R1 M1: a sidecar in the AT-CREATION (Exact) shape can only have been
    // planted there — csq never creates a sidecar — so pool mode refuses it.
    #[cfg(windows)]
    #[test]
    fn windows_pool_mode_refuses_an_at_creation_shaped_sidecar() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        windows_private_file(&dir.join("messages.sqlite-wal"));
        assert!(matches!(
            windows_acquire(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        assert!(!dir.join("messages.sqlite").exists());
    }

    // R1 F1: breaking inheritance on a sidecar (`icacls /inheritance:d`) gives
    // a PROTECTED DACL — refused on recheck and again on reopen, untouched.
    #[cfg(windows)]
    #[test]
    fn windows_pool_mode_refuses_a_sidecar_whose_inheritance_was_converted() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let side = dir.join("messages.sqlite-wal");
        drop(std::fs::File::create(&side).unwrap());
        let database = windows_acquire(&dir).expect("the inherited sidecar is accepted");
        let sid = crate::platform::fs_windows_acl::current_user_sid_text().unwrap();
        // `icacls /inheritance:d`: a PROTECTED DACL. The unprotected setter
        // re-inherits the leaf's ACE, which is not the converted shape.
        crate::platform::fs_windows_acl::set_file_dacl_protected(
            &side,
            &format!("D:P(A;;FA;;;{sid})"),
        )
        .unwrap();
        let converted_acl = crate::platform::fs_windows_acl::observed_acl_at(&side).unwrap();
        assert!(
            converted_acl.dacl_protected(),
            "premise: the DACL is protected (AI beside P is legal): {converted_acl:?}"
        );
        assert_eq!(
            converted_acl.dacl.len(),
            1,
            "premise: exactly the owner ACE: {converted_acl:?}"
        );
        let converted_ace = &converted_acl.dacl[0];
        assert!(
            converted_ace.is_access_allowed()
                && converted_ace.is_file_all_access()
                && converted_ace.sid == sid,
            "premise: the owner-only FILE_ALL_ACCESS grant: {converted_acl:?}"
        );
        assert_eq!(
            converted_ace.flags, 0,
            "premise: the converted ACE does not inherit: {converted_acl:?}"
        );
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        assert!(matches!(
            database.with_file(|_| Ok(())),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        drop(database);
        assert!(matches!(
            windows_acquire_existing(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        assert_eq!(
            crate::platform::fs_windows_acl::observed_acl_at(&side).unwrap(),
            converted_acl,
            "a refusal must not re-ACL the sidecar"
        );
    }

    // R1 F1: a label-stripped sidecar is refused and never re-stamped (csq has
    // no stamping fallback for a third-party file).
    #[cfg(windows)]
    #[test]
    fn windows_pool_mode_refuses_a_label_stripped_sidecar_without_restamping() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let side = dir.join("messages.sqlite-wal");
        drop(std::fs::File::create(&side).unwrap());
        let database = windows_acquire(&dir).expect("the inherited sidecar is accepted");
        crate::platform::fs_windows_acl::clear_file_label(&side).unwrap();
        let stripped = crate::platform::fs_windows_acl::observed_acl_at(&side).unwrap();
        assert!(
            stripped.label.is_empty(),
            "premise: no label ACE remains: {stripped:?}"
        );
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        drop(database);
        assert!(matches!(
            windows_acquire_existing(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        assert_eq!(
            crate::platform::fs_windows_acl::observed_acl_at(&side).unwrap(),
            stripped,
            "a refused label-stripped sidecar must not be re-stamped"
        );
    }

    // R1 F2 condition 4: an ACE added to the DATABASE after acquisition is
    // refused on recheck and on reopen.
    #[cfg(windows)]
    #[test]
    fn windows_database_with_an_added_ace_is_refused_on_recheck_and_reopen() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let database = windows_acquire(&dir).expect("the ledger database is created");
        let path = dir.join("messages.sqlite");
        let sid = crate::platform::fs_windows_acl::current_user_sid_text().unwrap();
        crate::platform::fs_windows_acl::set_file_dacl(
            &path,
            &format!("D:P(A;;FA;;;{sid})(A;;FR;;;WD)"),
        )
        .unwrap();
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        drop(database);
        assert!(matches!(
            windows_acquire_existing(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
    }

    // R1 F2 condition 4: an explicit ACE added to an INHERITED sidecar keeps
    // the DACL unprotected and leaves two ACEs — refused on recheck and reopen.
    #[cfg(windows)]
    #[test]
    fn windows_pool_mode_refuses_a_sidecar_with_an_added_ace() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let side = dir.join("messages.sqlite-wal");
        drop(std::fs::File::create(&side).unwrap());
        let database = windows_acquire(&dir).expect("the inherited sidecar is accepted");
        crate::platform::fs_windows_acl::set_file_dacl(&side, "D:(A;;FR;;;WD)").unwrap();
        let added = crate::platform::fs_windows_acl::observed_acl_at(&side).unwrap();
        // Parsed premise (R2 N6): the DACL stays auto-inherited and now carries
        // an Everyone ACE beside the user's inherited grant.
        assert!(
            !added.dacl_protected(),
            "premise: the sidecar's DACL stays auto-inherited: {added:?}"
        );
        assert!(
            added
                .dacl
                .iter()
                .any(|ace| ace.is_access_allowed() && ace.sid == "S-1-1-0"),
            "premise: the added Everyone ACE is present: {added:?}"
        );
        let sid = crate::platform::fs_windows_acl::current_user_sid_text().unwrap();
        assert!(
            added.dacl_sids().contains(&sid.as_str()),
            "premise: the user's inherited ACE remains: {added:?}"
        );
        assert!(matches!(
            database.recheck(),
            Err(SecureDatabaseError::UnsafeFile)
        ));
        drop(database);
        assert!(matches!(
            windows_acquire_existing(&dir),
            Err(SecureDatabaseError::UnsafeFile)
        ));
    }

    // R1 F8: an EXACT protected non-inheriting leaf is refused in pool mode,
    // untouched, and the fixture really is the strict shape.
    #[cfg(windows)]
    #[test]
    fn windows_pool_mode_refuses_a_strict_leaf_untouched() {
        let _env = crate::platform::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("strict");
        crate::platform::fs_windows_acl::create_private_directory(&dir).unwrap();
        let before = crate::platform::fs_windows_acl::observed_acl_at(&dir).unwrap();
        assert!(
            before.dacl_protected() && before.dacl.len() == 1,
            "premise: a protected single-ACE leaf: {before:?}"
        );
        let grant = &before.dacl[0];
        assert!(
            grant.is_access_allowed()
                && grant.is_file_all_access()
                && !grant.inherits_to_children(),
            "premise: the strict non-inheriting FILE_ALL_ACCESS leaf: {before:?}"
        );
        assert!(
            crate::platform::fs_windows_acl::open_private_directory_inheriting(&dir).is_err(),
            "premise: the strict leaf is not the inheriting shape"
        );
        assert!(matches!(
            windows_acquire(&dir),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert_eq!(
            crate::platform::fs_windows_acl::observed_acl_at(&dir).unwrap(),
            before,
            "a wrong-shape leaf must never be adopted or re-ACLed"
        );
        assert!(!dir.join("messages.sqlite").exists());
    }

    // R1 F8: an inheriting leaf carrying an EXTRA ACE is refused untouched.
    #[cfg(windows)]
    #[test]
    fn windows_pool_mode_refuses_an_inheriting_leaf_with_an_extra_ace() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        let sid = crate::platform::fs_windows_acl::current_user_sid_text().unwrap();
        crate::platform::fs_windows_acl::set_file_dacl(
            &dir,
            &format!("D:P(A;OICI;FA;;;{sid})(A;;FR;;;WD)"),
        )
        .unwrap();
        let before = crate::platform::fs_windows_acl::observed_acl_at(&dir).unwrap();
        assert!(
            before.dacl_protected(),
            "premise: the planted leaf DACL is protected: {before:?}"
        );
        assert!(
            before
                .dacl
                .iter()
                .any(|ace| ace.is_access_allowed() && ace.sid == "S-1-1-0"),
            "premise: the extra Everyone ACE is present: {before:?}"
        );
        assert!(
            before
                .dacl
                .iter()
                .any(|ace| ace.sid == sid && ace.is_access_allowed() && ace.inherits_to_children()),
            "premise: the user's inheriting ACE is present: {before:?}"
        );
        assert!(matches!(
            windows_acquire(&dir),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert_eq!(
            crate::platform::fs_windows_acl::observed_acl_at(&dir).unwrap(),
            before,
            "a wrong-shape leaf must never be adopted or re-ACLed"
        );
        assert!(!dir.join("messages.sqlite").exists());
    }

    // R1 F8: an inheriting leaf with NO label is refused untouched.
    #[cfg(windows)]
    #[test]
    fn windows_pool_mode_refuses_an_inheriting_leaf_without_a_label() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, dir) = windows_fixture();
        crate::platform::fs_windows_acl::clear_file_label(&dir).unwrap();
        let before = crate::platform::fs_windows_acl::observed_acl_at(&dir).unwrap();
        assert!(
            before.label.is_empty(),
            "premise: the leaf has no label: {before:?}"
        );
        assert!(matches!(
            windows_acquire(&dir),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert_eq!(
            crate::platform::fs_windows_acl::observed_acl_at(&dir).unwrap(),
            before,
            "a wrong-shape leaf must never be adopted or re-ACLed"
        );
    }

    // R1 M2: the default constructors stay STRICT on Windows — an inheriting
    // leaf is refused, while strict mode creates and accepts its own leaf.
    #[cfg(windows)]
    #[test]
    fn windows_strict_mode_refuses_an_inheriting_leaf_and_keeps_its_own_shape() {
        let _env = crate::platform::test_env::lock();
        let (_tmp, inheriting) = windows_fixture();
        assert!(matches!(
            windows_strict_acquire(&inheriting),
            Err(SecureDatabaseError::UnsafeDirectory)
        ));
        assert!(!inheriting.join("messages.sqlite").exists());
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("strict");
        let database = windows_strict_acquire(&dir).expect("strict mode creates its leaf");
        database.recheck().unwrap();
        drop(database);
        // The strict EXISTING path stays available over the same leaf.
        let existing =
            windows_strict_acquire_existing(&dir).expect("strict mode reopens its own database");
        existing.recheck().unwrap();
        drop(existing);
        drop(
            crate::platform::fs_windows_acl::open_private_directory(&dir)
                .expect("strict mode's leaf is the at-creation protected shape"),
        );
        assert!(
            crate::platform::fs_windows_acl::open_private_directory_inheriting(&dir).is_err(),
            "strict mode must not create the pool shape"
        );
    }
}
