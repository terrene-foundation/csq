//! Unix symlink-exclusive primitive.
//!
//! Provides `symlink_exclusive` for Linux and macOS with platform-specific
//! atomicity semantics:
//!
//! - **Linux**: `symlinkat(2)` into a random tmp name under a parent fd opened
//!   with `O_DIRECTORY | O_NOFOLLOW`, then `renameat2(RENAME_NOREPLACE)` to
//!   atomically move the symlink into place without overwriting an existing
//!   entry. If `renameat2` returns `EEXIST` the tmp is unlinked and
//!   `PlatformError::AlreadyExists` is returned. This is the strongest
//!   atomicity available on Linux — no TOCTOU window.
//!
//! - **macOS**: `symlinkat(2)` guarded by `fstatat(AT_SYMLINK_NOFOLLOW)` on a
//!   parent fd opened with `O_NOFOLLOW`. The pre-existence check and the
//!   `symlinkat` call are NOT a single atomic syscall on macOS (no
//!   `renameat2` equivalent), so a narrow TOCTOU window exists between the
//!   `fstatat` (returns `ENOENT`) and the `symlinkat`. This window is bounded
//!   by the same-user threat model documented in
//!   `rules/account-terminal-separation.md` — an attacker racing this
//!   window must have the same UID and knowledge of the exact tmp path.
//!
//! Both paths open the parent directory with `O_NOFOLLOW` so a symlinked
//! parent is rejected (`ENOTDIR` / `ELOOP`), preventing directory traversal
//! via a malicious parent symlink.
//!
//! Origin: issue #292 Phase 1 M1-3.

use crate::error::PlatformError;
use libc::c_int;
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Convert a `&Path` to a `CString`, returning an `io::Error` if the path
/// contains interior NUL bytes.
fn to_cstring(p: &Path) -> Result<CString, std::io::Error> {
    let bytes = OsStr::new(p).as_bytes();
    CString::new(bytes).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL byte")
    })
}

/// Open a directory at `path` with `O_DIRECTORY | O_NOFOLLOW | O_RDONLY`.
///
/// `O_NOFOLLOW` ensures the final component of `path` is not itself a symlink.
/// Returns a raw file descriptor on success.
fn open_dir_nofollow(path: &Path) -> Result<c_int, std::io::Error> {
    let cpath = to_cstring(path)?;
    let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

// ── Linux implementation ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::error::PlatformError;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SYMLINK_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    // `renameat2` with `RENAME_NOREPLACE` (flag = 1) — glibc does not expose
    // this directly; we call the syscall via `libc::syscall`.
    //
    // `RENAME_NOREPLACE`: if the destination exists, return `EEXIST` instead
    // of atomically replacing it. This is the kernel-level exclusion gate.
    const RENAME_NOREPLACE: libc::c_uint = 1;

    // SYS_renameat2 numbers for the three architectures we care about.
    // The syscall was added in Linux 3.15; all reasonable CI images have it.
    #[cfg(target_arch = "x86_64")]
    const SYS_RENAMEAT2: i64 = 316;
    #[cfg(target_arch = "aarch64")]
    const SYS_RENAMEAT2: i64 = 276;
    #[cfg(target_arch = "arm")]
    const SYS_RENAMEAT2: i64 = 382;
    // Catch-all for architectures not enumerated above (e.g. riscv64, s390x,
    // loongarch64). CI only runs x86_64 + aarch64 so this is a compile guard.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
    const SYS_RENAMEAT2: i64 = {
        compile_error!("SYS_RENAMEAT2 not mapped for this architecture; add the syscall number.")
    };

    unsafe fn renameat2_noreplace(
        old_dirfd: c_int,
        old_name: &CString,
        new_dirfd: c_int,
        new_name: &CString,
    ) -> c_int {
        libc::syscall(
            SYS_RENAMEAT2,
            old_dirfd as libc::c_long,
            old_name.as_ptr(),
            new_dirfd as libc::c_long,
            new_name.as_ptr(),
            RENAME_NOREPLACE as libc::c_ulong,
        ) as c_int
    }

    /// Linux: `symlinkat` into tmp, then `renameat2(RENAME_NOREPLACE)`.
    ///
    /// The parent fd is opened with `O_DIRECTORY | O_NOFOLLOW` so a symlinked
    /// parent directory is rejected with `ENOTDIR` or `ELOOP`.
    pub fn symlink_exclusive_impl(target: &Path, link: &Path) -> Result<(), PlatformError> {
        let parent = link.parent().ok_or_else(|| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link path has no parent",
            ))
        })?;
        let link_name = link.file_name().ok_or_else(|| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link path has no file name",
            ))
        })?;

        // Open the parent directory with O_NOFOLLOW.
        let parent_fd = open_dir_nofollow(parent)?;
        let _guard = FdGuard(parent_fd);

        // Build a unique tmp name within the parent directory.
        let counter = SYMLINK_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_name_str = format!(".csq-sl-tmp.{}.{}", unsafe { libc::getpid() }, counter);
        let tmp_cname = CString::new(tmp_name_str.as_str()).map_err(|_| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tmp name contains NUL",
            ))
        })?;

        let link_cname = CString::new(OsStr::new(link_name).as_bytes()).map_err(|_| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link name contains NUL",
            ))
        })?;
        let target_cname = to_cstring(target)?;

        // Step 1: create the symlink under the tmp name in the parent dir.
        let rc = unsafe { libc::symlinkat(target_cname.as_ptr(), parent_fd, tmp_cname.as_ptr()) };
        if rc != 0 {
            return Err(PlatformError::Io(std::io::Error::last_os_error()));
        }

        // Step 2: atomically rename tmp → link_name with RENAME_NOREPLACE.
        // If the destination already exists, renameat2 returns EEXIST.
        let rc = unsafe { renameat2_noreplace(parent_fd, &tmp_cname, parent_fd, &link_cname) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // Unlink the tmp symlink on any failure — §5a-style cleanup.
            unsafe {
                libc::unlinkat(parent_fd, tmp_cname.as_ptr(), 0);
            }
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Err(PlatformError::AlreadyExists);
            }
            return Err(PlatformError::Io(err));
        }

        Ok(())
    }

    /// RAII guard that closes a raw fd on drop.
    struct FdGuard(c_int);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
}

// ── macOS implementation ─────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use crate::error::PlatformError;

    /// macOS: `fstatat(AT_SYMLINK_NOFOLLOW)` pre-existence check, then
    /// `symlinkat` on the parent fd opened with `O_NOFOLLOW`.
    ///
    /// # TOCTOU note
    ///
    /// There is a narrow window between the `fstatat` returning `ENOENT` and
    /// the `symlinkat` completing. macOS provides no `renameat2` equivalent
    /// (F_ADDSIG / `renamex_np` with `RENAME_EXCL` is only available on APFS
    /// volumes and not exposed through libc). The window is bounded by the
    /// same-user threat model documented in
    /// `rules/account-terminal-separation.md`: an attacker racing this window
    /// must be the same UID and must know the exact link path.
    pub fn symlink_exclusive_impl(target: &Path, link: &Path) -> Result<(), PlatformError> {
        let parent = link.parent().ok_or_else(|| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link path has no parent",
            ))
        })?;
        let link_name = link.file_name().ok_or_else(|| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link path has no file name",
            ))
        })?;

        // Open the parent directory with O_NOFOLLOW — rejects symlinked parents.
        let parent_fd = open_dir_nofollow(parent)?;
        let _guard = FdGuard(parent_fd);

        let link_cname = CString::new(OsStr::new(link_name).as_bytes()).map_err(|_| {
            PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "link name contains NUL",
            ))
        })?;
        let target_cname = to_cstring(target)?;

        // Step 1: pre-existence check via fstatat(AT_SYMLINK_NOFOLLOW).
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                parent_fd,
                link_cname.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            // Entry exists — including the race case where another thread just
            // won the symlinkat before us.
            return Err(PlatformError::AlreadyExists);
        }
        let stat_err = std::io::Error::last_os_error();
        if stat_err.raw_os_error() != Some(libc::ENOENT) {
            return Err(PlatformError::Io(stat_err));
        }

        // Step 2: create the symlink. If another thread raced past step 1 and
        // created the link, symlinkat returns EEXIST.
        let rc = unsafe { libc::symlinkat(target_cname.as_ptr(), parent_fd, link_cname.as_ptr()) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Err(PlatformError::AlreadyExists);
            }
            return Err(PlatformError::Io(err));
        }

        Ok(())
    }

    struct FdGuard(c_int);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe { libc::close(self.0) };
        }
    }
}

// ── Public dispatcher ─────────────────────────────────────────────────────────

/// Creates a symlink at `link` pointing to `target`.
///
/// Returns `Err(PlatformError::AlreadyExists)` if `link` already exists at
/// the time of creation — including via a concurrent race with another thread
/// or process attempting the same operation.
///
/// See the module documentation for the platform-specific atomicity guarantees.
pub fn symlink_exclusive(target: &Path, link: &Path) -> Result<(), PlatformError> {
    // Create parent directories if they don't exist.
    if let Some(parent) = link.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        linux::symlink_exclusive_impl(target, link)
    }
    #[cfg(target_os = "macos")]
    {
        macos::symlink_exclusive_impl(target, link)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fallback for other Unix platforms (FreeBSD, etc.) — pre-existence
        // check + symlink, same TOCTOU caveat as macOS.
        let _ = (target, link);
        Err(PlatformError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlink_exclusive not implemented for this Unix platform",
        )))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn basic_symlink_created() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        fs::write(&target, b"hello").unwrap();

        symlink_exclusive(&target, &link).unwrap();

        assert!(link.exists(), "link should exist");
        assert_eq!(fs::read_to_string(&link).unwrap(), "hello");
    }

    #[test]
    fn returns_already_exists_when_link_present() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        fs::write(&target, b"hello").unwrap();

        symlink_exclusive(&target, &link).unwrap();

        let err = symlink_exclusive(&target, &link).unwrap_err();
        assert!(
            matches!(err, PlatformError::AlreadyExists),
            "expected AlreadyExists, got {err:?}"
        );
    }

    #[test]
    fn creates_parent_directories() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("a").join("b").join("link");
        fs::write(&target, b"data").unwrap();

        symlink_exclusive(&target, &link).unwrap();
        assert!(link.exists());
    }

    /// Linux-only: assert that exactly 1 of 1000 concurrent callers succeeds
    /// against the same link path, and all others get AlreadyExists.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_concurrent_1000_exactly_one_wins() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        fs::write(&target, b"x").unwrap();

        let target = Arc::new(target);
        let link = Arc::new(link);
        let success_count = Arc::new(AtomicUsize::new(0));
        let already_exists_count = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..1000)
            .map(|_| {
                let t = Arc::clone(&target);
                let l = Arc::clone(&link);
                let sc = Arc::clone(&success_count);
                let ec = Arc::clone(&already_exists_count);
                thread::spawn(move || match symlink_exclusive(&t, &l) {
                    Ok(()) => {
                        sc.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(PlatformError::AlreadyExists) => {
                        ec.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        panic!("unexpected error: {e:?}");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let successes = success_count.load(Ordering::Relaxed);
        let existing = already_exists_count.load(Ordering::Relaxed);

        assert_eq!(successes, 1, "exactly 1 thread should win; got {successes}");
        assert_eq!(
            existing, 999,
            "exactly 999 threads should get AlreadyExists; got {existing}"
        );
    }

    /// macOS-only: `O_NOFOLLOW` causes open_dir_nofollow to reject a symlinked
    /// parent directory.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_nofollow_rejects_symlinked_parent() {
        let dir = TempDir::new().unwrap();
        let real_parent = dir.path().join("real");
        let symlinked_parent = dir.path().join("sym_parent");
        fs::create_dir(&real_parent).unwrap();

        // Create a symlink pointing at the real directory.
        std::os::unix::fs::symlink(&real_parent, &symlinked_parent).unwrap();

        let target = dir.path().join("target");
        let link = symlinked_parent.join("link");
        fs::write(&target, b"x").unwrap();

        // Opening sym_parent with O_NOFOLLOW must fail (ENOTDIR or ELOOP on macOS).
        let result = symlink_exclusive(&target, &link);
        assert!(
            result.is_err(),
            "symlink_exclusive through a symlinked parent must fail"
        );
        // The error should NOT be AlreadyExists — it should be an IO error.
        assert!(
            !matches!(result.unwrap_err(), PlatformError::AlreadyExists),
            "error should be IO (ELOOP/ENOTDIR), not AlreadyExists"
        );
    }

    /// Verify that no temporary symlink artifacts are left on the filesystem
    /// after a successful or failed call.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_no_tmp_artifacts_after_race_loss() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        fs::write(&target, b"x").unwrap();

        // First call succeeds.
        symlink_exclusive(&target, &link).unwrap();
        // Second call loses the race.
        let _ = symlink_exclusive(&target, &link);

        // No .csq-sl-tmp.* files should remain.
        let tmp_count = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with(".csq-sl-tmp."))
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(tmp_count, 0, "tmp artifacts leaked: {tmp_count}");
    }
}
