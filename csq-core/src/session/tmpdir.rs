//! Per-session `TMPDIR`: a private temp directory under the terminal's own
//! handle dir (an internal ticket).
//!
//! Every csq-launched session used to inherit the shared system temp dir
//! (`$TMPDIR` — the per-user folder macOS sets, or `/tmp` on Linux). Agent
//! sessions create thousands of sandboxes there with a bare `mktemp -d`, and a
//! folder in a SHARED temp dir has no owner — no reaper can tell a finished
//! session's sandbox from someone's unsaved work, so they pile up (maintainer
//! Mac, 2026-11-04: 10,274 folders, 461 of them up to 76 GiB, written in the
//! last 72 h).
//!
//! Giving each session `<handle_dir>/tmp` makes every leftover attributable to
//! exactly one terminal, and the handle-dir reaper already deletes the terminal
//! directory — so the temp tree is reclaimed by containment when the session
//! ends, with no second reaper and no second name registry
//! (`reconciler-cleanup-parity.md`).
//!
//! The directory is owner-only (0700 on Unix) and must be a REAL directory
//! owned by this user: a `tmp` entry that is a symlink or any other
//! non-directory is REFUSED, never followed — the child's temp writes must not
//! be redirected anywhere csq did not create (`guard-reader-writer-parity.md`
//! MUST-2: on a refusing path, "cannot verify" fails closed).
//!
//! There is NO fallback to the shared default. Every failure is the fixed
//! [`SESSION_TMPDIR_TAG`]; the launch path turns that into a refused launch
//! rather than silently recreating the leak this module exists to close.

use crate::session::recycle::Tag;
use std::path::{Path, PathBuf};

/// Fixed-vocabulary tag for every [`ensure_session_tmpdir`] failure. It never
/// carries a path, token or OS error text (`security.md` MUST-2); callers may
/// surface it verbatim.
pub const SESSION_TMPDIR_TAG: &str = "session_tmpdir_unavailable";

/// Name of the per-session temp directory inside the handle dir.
///
/// The name is what the launch env exports as `TMPDIR`, and it is deliberately
/// spelled in one place so the reaper's containment claim (the handle dir is
/// removed wholesale), the launch env and every diagnostic can never disagree.
pub const SESSION_TMPDIR_DIR: &str = "tmp";

/// Ensures `<handle_dir>/tmp` exists as an owner-only directory (0700 on Unix)
/// owned by the current user, and returns that path.
///
/// The caller exports the returned path as the child session's `TMPDIR`. The
/// launch MUST call this before spawning any session child and MUST treat
/// `Err(SESSION_TMPDIR_TAG)` as a refused launch — a fallback to the shared
/// default would put session temp files back into the ownerless folder this
/// exists to eliminate.
///
/// Creation and verification both go through the crate's SEC-2.15 directory
/// helper: a leaf that is a symlink or any other non-directory is refused
/// BEFORE anything is created, every missing level is created with mode 0700,
/// and the leaf is then re-opened `O_DIRECTORY | O_NOFOLLOW` and verified on
/// that same descriptor to be a directory owned by this euid.
///
/// On Windows the mode half is a no-op (ACL defaults restrict access to the
/// creating user, see [`crate::platform::fs::ensure_private_dir`]); the
/// no-follow and directory checks still apply.
pub fn ensure_session_tmpdir(handle_dir: &Path) -> Result<PathBuf, Tag> {
    let tmp = handle_dir.join(SESSION_TMPDIR_DIR);
    crate::platform::fs::ensure_private_dir(&tmp).map_err(|_| SESSION_TMPDIR_TAG)?;
    // `ensure_private_dir` only CLEARS group/other bits on an existing dir; it
    // deliberately preserves a stricter owner mode (e.g. 0500, an explicitly
    // locked-down root). For a child's TMPDIR that end state is wrong — the
    // child must be able to create files — so the owner bits are set to
    // exactly `rwx` here as well.
    #[cfg(unix)]
    reassert_owner_only_mode(&tmp).map_err(|_| SESSION_TMPDIR_TAG)?;
    Ok(tmp)
}

/// Whether `path` is a REAL directory owned by the current user AND the launch
/// could re-assert its mode — the exact state [`ensure_session_tmpdir`]
/// requires — checked WITHOUT creating or changing anything, so a diagnostic
/// reports what a launch would actually do (`guard-reader-writer-parity.md`
/// MUST-1: the reader recognises exactly the forms the writer accepts).
///
/// On Unix the leaf is opened `O_DIRECTORY | O_NOFOLLOW` and verified on that
/// descriptor, so a symlink is never followed and a foreign-owned directory is
/// never reported as usable. The mode re-assert is an `fchmod`, which fails on
/// a READ-ONLY filesystem even when the mode is already 0700, so a mount the
/// kernel reports as write-refusing is not usable either (N3: the doctor said
/// `present` while every launch refused). On Windows the directory check
/// mirrors [`crate::platform::fs::ensure_private_dir`]'s ACL-based behaviour.
#[must_use]
pub fn session_tmpdir_is_usable(path: &Path) -> bool {
    session_tmpdir_is_usable_with(path, &filesystem_refuses_writes)
}

/// [`session_tmpdir_is_usable`] with the read-only probe injected, so a test
/// can exercise the refusal without a read-only mount.
fn session_tmpdir_is_usable_with(path: &Path, refuses_writes: &dyn Fn(&Path) -> bool) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
        else {
            return false;
        };
        let Ok(meta) = file.metadata() else {
            return false;
        };
        // SAFETY: geteuid has no memory or synchronization preconditions.
        let owned = meta.is_dir() && meta.uid() == unsafe { libc::geteuid() };
        owned && !refuses_writes(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) && !refuses_writes(path)
    }
}

/// Whether `dir` sits on a filesystem that refuses writes (`EROFS`).
///
/// `access(2)` with `W_OK` is a read-only probe that reports `EROFS` on a
/// read-only mount; any OTHER denial (e.g. a 0500 mode) is not a read-only
/// filesystem and does not count — the launch's `fchmod` would still succeed
/// there. Only the mount property matters, because that is what makes the mode
/// re-assert fail for a directory that is otherwise exactly right.
#[cfg(unix)]
fn filesystem_refuses_writes(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `access` only inspects permissions and writes nothing; the path
    // is a valid NUL-terminated C string.
    let rc = unsafe { libc::access(c_path.as_ptr(), libc::W_OK) };
    rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EROFS)
}

#[cfg(not(unix))]
fn filesystem_refuses_writes(_dir: &Path) -> bool {
    false
}

/// Forces EXACTLY 0700 on `dir`, through a no-follow directory descriptor.
///
/// Re-opens the leaf `O_DIRECTORY | O_NOFOLLOW` (a symlink swapped in after
/// [`ensure_session_tmpdir`]'s first check makes this open fail instead of
/// redirecting the chmod), re-verifies on that descriptor that it is a real
/// directory owned by this euid, and `fchmod`s the descriptor — never a path
/// that could be re-pointed between the check and the mode change.
#[cfg(unix)]
fn reassert_owner_only_mode(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    let meta = file.metadata()?;
    if !meta.is_dir() {
        return Err(std::io::Error::other("not a directory"));
    }
    // SAFETY: geteuid has no memory or synchronization preconditions.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::other("directory is not owned by this user"));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    /// A handle dir to hang the temp dir under, as a launch mints it.
    fn handle_dir(base: &Path) -> PathBuf {
        let dir = base.join(crate::session::handle_dir::term_handle_dir_name(4242));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).unwrap().mode() & 0o777
    }

    #[test]
    fn ensure_session_tmpdir_creates_the_dir_and_returns_its_path() {
        let base = TempDir::new().unwrap();
        let handle = handle_dir(base.path());
        let tmp = ensure_session_tmpdir(&handle).unwrap();
        assert_eq!(tmp, handle.join(SESSION_TMPDIR_DIR));
        assert!(tmp.is_dir(), "the helper must create the directory");
        // The child must be able to write its temp files here.
        std::fs::write(tmp.join("scratch"), b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(&tmp).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o700, "must be owner-only");
            // SAFETY: geteuid has no memory or synchronization preconditions.
            assert_eq!(meta.uid(), unsafe { libc::geteuid() }, "must be ours");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_session_tmpdir_tightens_an_existing_permissive_dir() {
        let base = TempDir::new().unwrap();
        let handle = handle_dir(base.path());
        let tmp = handle.join(SESSION_TMPDIR_DIR);
        std::fs::create_dir(&tmp).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o777)).unwrap();

        assert_eq!(ensure_session_tmpdir(&handle).unwrap(), tmp);
        assert_eq!(
            mode_of(&tmp),
            0o700,
            "an old umask-default dir is tightened"
        );

        // Idempotent on its own output.
        assert_eq!(ensure_session_tmpdir(&handle).unwrap(), tmp);
        assert_eq!(mode_of(&tmp), 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn ensure_session_tmpdir_restores_owner_write_access_to_a_read_only_dir() {
        // `ensure_private_dir` preserves a stricter-than-0700 owner mode by
        // design; a TMPDIR the child cannot write into is unusable, so this
        // helper re-asserts exactly 0700 instead.
        let base = TempDir::new().unwrap();
        let handle = handle_dir(base.path());
        let tmp = handle.join(SESSION_TMPDIR_DIR);
        std::fs::create_dir(&tmp).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o500)).unwrap();

        assert_eq!(ensure_session_tmpdir(&handle).unwrap(), tmp);
        assert_eq!(
            mode_of(&tmp),
            0o700,
            "a read-only owner mode is raised to 0700"
        );
        std::fs::write(tmp.join("scratch"), b"x").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ensure_session_tmpdir_refuses_a_symlinked_tmp_without_following_it() {
        use std::os::unix::fs::symlink;

        let base = TempDir::new().unwrap();
        let handle = handle_dir(base.path());
        let target = base.path().join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        // Permissive, so a follow would be visible in the mode as well.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, handle.join(SESSION_TMPDIR_DIR)).unwrap();

        let err = ensure_session_tmpdir(&handle).expect_err("a symlinked tmp must be refused");
        assert_eq!(err, SESSION_TMPDIR_TAG);
        assert!(!err.contains('/'), "the tag never carries a path: {err}");
        assert_eq!(
            mode_of(&target),
            0o755,
            "the symlink target must not be chmodded"
        );
        assert!(
            std::fs::symlink_metadata(handle.join(SESSION_TMPDIR_DIR))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the refusing path must not replace or delete the entry"
        );
    }

    #[test]
    fn ensure_session_tmpdir_refuses_a_non_directory_at_tmp() {
        let base = TempDir::new().unwrap();
        let handle = handle_dir(base.path());
        std::fs::write(handle.join(SESSION_TMPDIR_DIR), b"not a dir").unwrap();

        assert_eq!(ensure_session_tmpdir(&handle), Err(SESSION_TMPDIR_TAG));
    }

    /// macOS `sun_path` is 104 bytes INCLUDING the NUL terminator, so a
    /// bindable pathname is at most 103 bytes. Asserted on every host (the
    /// strictest supported platform) so Linux CI cannot mask a regression.
    const MACOS_SUN_PATH_BYTES: usize = 104;

    /// AC2 (an internal ticket): the worst-case per-session `TMPDIR` plus a typical Unix
    /// socket name stays under the macOS Unix-socket path limit.
    ///
    /// The three components are the real ones, not copies: the handle-dir name
    /// comes from [`crate::session::handle_dir::term_handle_dir_name`] with the
    /// widest pid csq can mint (`u32::MAX`), the temp leaf from this module's
    /// own [`SESSION_TMPDIR_DIR`], and the socket leaf is `rpc.sock` — the
    /// codex app-server socket csq itself places inside a handle dir
    /// (`providers::codex::managed_backend::SOCKET`), the longest-lived Unix
    /// socket a session's private temp root is expected to hold.
    #[test]
    fn worst_case_session_tmpdir_plus_a_typical_socket_fits_the_macos_sun_path_limit() {
        // A long-but-plausible macOS short name (32 bytes). The exact ceiling
        // is reported below so a future longer home layout is caught here.
        let user = "u".repeat(32);
        let accounts_root = Path::new("/Users")
            .join(&user)
            .join(".claude")
            .join("accounts");
        let handle = accounts_root.join(crate::session::handle_dir::term_handle_dir_name(u32::MAX));
        let socket = handle.join(SESSION_TMPDIR_DIR).join("rpc.sock");
        let path_bytes = socket.as_os_str().len();

        assert!(
            path_bytes < MACOS_SUN_PATH_BYTES,
            "worst-case TMPDIR + socket path is {path_bytes} bytes, at/over the \
             {MACOS_SUN_PATH_BYTES}-byte macOS sun_path field: {}",
            socket.display()
        );
        // "Well under": leave at least 8 bytes below the field (which also has
        // to hold the terminating NUL).
        assert!(
            path_bytes <= MACOS_SUN_PATH_BYTES - 1 - 8,
            "only {} bytes of slack below the macOS sun_path field: {} ({path_bytes} bytes)",
            MACOS_SUN_PATH_BYTES - 1 - path_bytes,
            socket.display()
        );

        // Re-derive the budget from the real components: the fixed part is
        // `/Users/` + `/.claude/accounts` + `/term-<u32::MAX>` + `/tmp` +
        // `/rpc.sock`; a user name up to `max_user` bytes still fits a NUL.
        let fixed = path_bytes - user.len();
        let max_user = (MACOS_SUN_PATH_BYTES - 1).saturating_sub(fixed);
        assert_eq!(
            fixed, 53,
            "the fixed path shape changed; re-derive the socket-path budget"
        );
        assert!(
            max_user >= 50,
            "a default macOS home must fit a 50-byte user name, got {max_user}"
        );
    }

    /// an internal ticket R2 N3: a launch's mode re-assert is an `fchmod`, which fails on a
    /// read-only mount even when the directory is a real 0700 dir owned by us.
    /// The doctor's reader must report the same refusal, or it shows `present`
    /// for a terminal that cannot launch (`diagnostic-surface-parity.md`).
    /// The read-only probe is injected so no actual read-only mount is needed.
    #[test]
    fn a_read_only_mount_is_not_usable_even_for_a_real_dir() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("tmp");
        std::fs::create_dir(&dir).unwrap();

        assert!(
            session_tmpdir_is_usable(&dir),
            "a normal writable dir is usable"
        );
        assert!(
            !session_tmpdir_is_usable_with(&dir, &|_| true),
            "a read-only mount must be refused: the launch's fchmod would fail"
        );
        assert!(
            session_tmpdir_is_usable_with(&dir, &|_| false),
            "a writable mount keeps the dir usable"
        );
    }

    /// The production entry point must actually consult the read-only probe —
    /// a helper-only green would survive the wiring being dropped.
    #[test]
    fn the_production_check_consults_the_read_only_probe() {
        let src = include_str!("tmpdir.rs");
        let needle = concat!(
            "session_tmpdir_is_usable_with(path, &filesystem",
            "_refuses_writes)"
        );
        assert_eq!(
            src.matches(needle).count(),
            1,
            "session_tmpdir_is_usable must pass the real read-only probe"
        );
    }
}
