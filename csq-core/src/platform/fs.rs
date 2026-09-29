//! Secure file operations: permissions and atomic replacement.
//!
//! THRESHOLD — secure-write pattern home.
//! The canonical `unique_tmp_path → write → secure_file → atomic_replace`
//! pipeline (with §5a tmp-cleanup on every failure branch) is currently
//! documented in 4 places: `.claude/rules/security.md` §5a,
//! `.claude/skills/daemon-architecture` migration-pattern subsection,
//! `.claude/skills/provider-integration` Gemini provisioning subsection,
//! and the in-source doc-blocks at `daemon/migrate_legacy_api_key_helper.rs`
//! and `providers/gemini/provisioning.rs`. When a 5th subsystem adopts
//! the pattern (e.g. Bedrock or Vertex provisioning), move the
//! canonical doc into a doc-block on `unique_tmp_path` here per
//! an internal journal entry §FD #2 and an internal journal entry §FD #2 so there is a single
//! source of truth for the pipeline shape.

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

/// Sets file permissions to owner-only read (0o400) on Unix.
///
/// Sibling of [`secure_file`] for files that should be immutable outside of a
/// narrow refresh/write window — primarily canonical credential files
/// (`credentials/codex-<N>.json`, `credentials/<N>.json`). The refresh flow
/// acquires the per-account mutex, flips to 0o600 via [`secure_file`],
/// writes via [`atomic_replace`], then calls this helper to flip back to
/// 0o400 before releasing the mutex. Derived from spec 07 INV-P08
/// (credential mode-flip mutex coordination) + internal-design-docs
/// risk-analysis §2 R7 / ADR-C13.
///
/// No-op on Windows — ACL defaults produce read/write for the owner, and
/// Windows has no standard notion of "read-only but not readable-by-others"
/// at the POSIX mode level. The same security posture is achieved on
/// Windows via DACLs set at file-creation time in the credential writer.
pub fn secure_file_readonly(path: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o400);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Sets directory permissions to owner-only (0o700) on Unix.
///
/// Called after `create_dir_all` on the `identities/<UUID>/` directory to
/// prevent other users from enumerating credential filenames inside the dir
/// even though the credential files themselves are 0o600. Implements the
/// SEC-2.15 Phase 2 trust-boundary requirement.
///
/// No-op on Windows — ACL defaults produced at `create_dir_all` time restrict
/// access to the creating user; there is no equivalent `chmod` for directories.
pub fn secure_dir(path: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Creates `path` and writes `bytes` to it, refusing if `path` already
/// exists — as a regular file OR as a symlink — and setting mode 0o600 AT
/// CREATION on Unix, ahead of the first byte.
///
/// This closes the window `unique_tmp_path → std::fs::write → secure_file`
/// leaves open: `std::fs::write` creates its target at the process's
/// umask-default mode (typically 0o644) and only the subsequent
/// `secure_file` call narrows it, so a secret-bearing tmp file is briefly
/// world-readable and — because `write` follows an existing path, including
/// a symlink — a pre-planted symlink at `path` would have its target
/// overwritten. `create_new(true)` refuses both: an existing regular file
/// and an existing symlink both make the `open` call fail with
/// `AlreadyExists`, before any byte is written.
///
/// On any error writing the bytes, the file this call created is removed
/// before the error is returned (`security.md` §5a) — this function never
/// leaves a partially-written file behind. It does not create parent
/// directories; the caller is expected to have done so already (matching
/// every existing `unique_tmp_path` callsite, which calls
/// `create_dir_all` on the parent before computing `tmp`).
///
/// Non-unix: the same `create_new` exclusivity guarantee holds (refuses an
/// existing file); there is no POSIX mode bit to set, so the file is left
/// at whatever mode the platform's `OpenOptions::create_new` produces. No
/// production path currently relies on this branch achieving 0o600-shaped
/// protection on non-Unix — Windows credential writers use DACLs set at
/// file-creation time, as `secure_dir`'s doc block notes for directories.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), PlatformError> {
    write_new_private_impl(path, bytes, false)
}

/// Like [`write_new_private`], but additionally `fsync`s the file before
/// returning success.
///
/// For callers where the write must be durable before the NEXT step reads
/// or acts on it (e.g. a config file a caller immediately hands to a
/// subprocess, or that a concurrent process may `rename`/swap onto) —
/// matching the fsync-before-rename discipline `copy_into_staging` already
/// applies to the `atomic_replace` `EXDEV` fallback. Plain
/// [`write_new_private`] does not fsync, matching the pre-existing
/// `std::fs::write`-based pipeline's behaviour at every site it replaced.
pub fn write_new_private_synced(path: &Path, bytes: &[u8]) -> Result<(), PlatformError> {
    write_new_private_impl(path, bytes, true)
}

fn write_new_private_impl(path: &Path, bytes: &[u8], sync: bool) -> Result<(), PlatformError> {
    use std::io::Write as _;

    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;

    // From here `path` exists and is ours: any failure removes it before
    // propagating, so the caller never has to distinguish "never created"
    // from "created but incomplete" — both look like `Err` with nothing on
    // disk (security.md §5a).
    if let Err(e) = file.write_all(bytes) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e.into());
    }
    if sync {
        if let Err(e) = file.sync_all() {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(e.into());
        }
    }
    Ok(())
}

/// Atomically replaces `target` with `tmp_path`.
///
/// On Unix this is a single `rename(2)` call (atomic on the same filesystem),
/// with an explicit `EXDEV` fallback for the case where `tmp_path` and
/// `target` sit on different filesystems — see `atomic_replace_unix` for the
/// fallback contract and what it does and does not guarantee.
/// On Windows, files may be locked by other processes, so we retry with
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` up to 5 times with 100ms delay.
pub fn atomic_replace(tmp_path: &Path, target: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        atomic_replace_unix(tmp_path, target, |from, to| std::fs::rename(from, to))?;
    }
    #[cfg(windows)]
    {
        atomic_replace_windows(tmp_path, target)?;
    }
    Ok(())
}

/// `true` only for the kernel's cross-filesystem rename refusal.
///
/// Mechanism, so the claim is checkable rather than asserted: `rename(2)` is
/// specified to fail with `EXDEV` when `oldpath` and `newpath` are on
/// different mounted filesystems, and `io::Error` derived from that errno
/// reports `ErrorKind::CrossesDevices`. Both forms are accepted because an
/// error that never passed through errno (a test seam, or a std path that
/// synthesises the kind) carries only the kind, while one built from
/// `from_raw_os_error` carries both.
#[cfg(unix)]
fn is_cross_device(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EXDEV) || err.kind() == std::io::ErrorKind::CrossesDevices
}

/// Copies `tmp_path`'s bytes into an already-created staging file, then fsyncs.
///
/// Split out of [`atomic_replace_unix`] so the single caller has one failure
/// branch to clean up rather than three.
#[cfg(unix)]
fn copy_into_staging(tmp_path: &Path, dst: &mut std::fs::File) -> std::io::Result<()> {
    let mut src = std::fs::File::open(tmp_path)?;
    std::io::copy(&mut src, dst)?;
    // fsync before the rename: the rename is only atomic with respect to
    // WHICH inode `target` names, not to whether that inode's data reached
    // the disk. Without this, a crash between rename and writeback can leave
    // `target` pointing at a zero-length credential file.
    dst.sync_all()?;
    Ok(())
}

/// Unix `atomic_replace` with the rename step injected.
///
/// `rename` is `std::fs::rename` in production; tests substitute a closure to
/// drive the `EXDEV` branch, which is otherwise unreachable without mounting a
/// second filesystem. Only the FIRST rename goes through the seam — the
/// fallback's own rename is always the real one, because that step's whole
/// purpose is that it happens within the target directory.
///
/// # Fallback contract (`EXDEV` only)
///
/// Every other error propagates unchanged and unretried. On `EXDEV`:
///
/// 1. Stage a sibling of `target` (via [`unique_tmp_path`]), so the final step
///    is a same-directory rename and therefore still atomic AT THE TARGET: no
///    reader ever observes `target` absent or partially written.
/// 2. Create that staging file at 0o600 BEFORE the first byte is written, so a
///    secret never exists at umask-default mode (`security.md` MUST-5).
/// 3. Copy, `fsync`, then restore `tmp_path`'s own mode onto the staging file
///    — the same-filesystem `rename(2)` path carries the source's mode across,
///    so the fallback must too.
/// 4. Rename staging onto `target`, then remove `tmp_path`, because `rename(2)`
///    would have consumed it and callers rely on that.
///
/// # What is NOT preserved
///
/// The copy is not atomic with respect to `tmp_path`: a crash mid-fallback can
/// leave both `tmp_path` and a staging sibling on disk. Both are 0o600 and the
/// staging file is removed on every failure branch this function can observe
/// (`security.md` §5a); `tmp_path` is left for the caller to remove, exactly as
/// the same-filesystem path leaves it after a failed rename.
#[cfg(unix)]
fn atomic_replace_unix<R>(tmp_path: &Path, target: &Path, rename: R) -> Result<(), PlatformError>
where
    R: Fn(&Path, &Path) -> std::io::Result<()>,
{
    match rename(tmp_path, target) {
        Ok(()) => Ok(()),
        Err(e) if is_cross_device(&e) => atomic_replace_cross_device(tmp_path, target),
        Err(e) => Err(e.into()),
    }
}

/// The `EXDEV` fallback body. See [`atomic_replace_unix`] for the contract.
#[cfg(unix)]
fn atomic_replace_cross_device(tmp_path: &Path, target: &Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let src_mode = std::fs::metadata(tmp_path)?.permissions().mode() & 0o7777;
    let staging = unique_tmp_path(target);

    // `create_new` so a pre-existing file at this path is never adopted — and
    // therefore never deleted by the cleanup branches below, which would
    // destroy a file this call did not create. `mode(0o600)` applies at
    // creation, ahead of the first byte.
    let mut dst = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staging)?;

    // From here down `staging` exists and is ours: every failure branch
    // removes it before propagating (`security.md` §5a).
    if let Err(e) = copy_into_staging(tmp_path, &mut dst) {
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }
    drop(dst);

    if let Err(e) = std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(src_mode)) {
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }

    if let Err(e) = std::fs::rename(&staging, target) {
        let _ = std::fs::remove_file(&staging);
        return Err(e.into());
    }

    // `rename(2)` consumes the source; the fallback must too, or the caller is
    // left holding a secret-bearing tmp file it believes was moved away.
    let _ = std::fs::remove_file(tmp_path);
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

/// Creates a symlink at `link` pointing to `target`, failing if `link` already exists.
///
/// This is the cross-platform primitive for atomic-exclusive symlink creation.
/// It underpins the handle-dir model (Phase 3 of an internal ticket A++): each
/// `term-<pid>/` handle dir's symlinks are created via this function so that
/// two concurrent `csq swap` calls against the same link path produce exactly
/// one winner.
///
/// # Platform semantics
///
/// | Platform | Mechanism | TOCTOU window |
/// |----------|-----------|---------------|
/// | Linux | `symlinkat` + `renameat2(RENAME_NOREPLACE)` | None — kernel atomic |
/// | macOS | `fstatat(AT_SYMLINK_NOFOLLOW)` + `symlinkat` | Narrow — same-user threat model |
/// | Windows | NTFS junction via `FSCTL_SET_REPARSE_POINT` + `GetFileAttributesW` | Narrow — same-user threat model |
///
/// # Errors
///
/// - `PlatformError::AlreadyExists` — `link` already exists (including via race).
/// - `PlatformError::Io` — filesystem error (parent not found, permission denied, etc.).
/// - `PlatformError::Win32` — Windows-specific IOCTL failure.
///
/// # Zero production callsites in Phase 1
///
/// This function is intentionally unreferenced by production code in Phase 1.
/// It sits on the shelf and soaks in CI (Linux + macOS + Windows matrix) until
/// Phase 3 wires the handle-dir symlinks.
pub fn symlink_exclusive(target: &Path, link: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        super::fs_symlink_unix::symlink_exclusive(target, link)
    }
    #[cfg(windows)]
    {
        super::fs_symlink_windows::symlink_exclusive(target, link)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link);
        Err(PlatformError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlink_exclusive not implemented for this platform",
        )))
    }
}

/// Bumps `path`'s modification time strictly above `min_mtime_ns` and the
/// file's current mtime, advancing to at least `now()`.
///
/// an internal ticket motivation: `csq swap N` repoints the runtime
/// `<handle_dir>/.credentials.json` symlink. `repoint_handle_dir` selects
/// `<base_dir>/identities/<UUID>/credentials.json` when the target slot resolves
/// to a UUID; only when it does not resolve does it select the legacy
/// `<base_dir>/config-<N>/.credentials.json` path. The mtime bump uses that SAME
/// resolved target. CC re-stats the symlink before every API call and reloads
/// credentials only when `mtimeMs !== lastCredentialsMtimeMs` (spec 01 §1.4 —
/// strict inequality). When old and new targets share an mtime (refresh timing
/// or filesystem precision), CC can skip the reload and the swap "appears not
/// to take effect". Calling this helper before the rename addresses that
/// collision; it is not an atomic guarantee against concurrent target writes.
///
/// The new mtime is `max(now(), min_mtime_ns + 1, current_mtime_ns + 1)`.
/// Pass `min_mtime_ns = 0` when no baseline is required (current + 1 wins).
///
/// Errors are returned but the caller should typically log and continue —
/// observability MUST NOT alter swap semantics. The post-swap collision warn
/// in `repoint_handle_dir` (`session::handle_dir`) acts as a regression
/// detector if this helper silently fails to advance the mtime.
///
/// `repoint_handle_dir` passes the selected identity-keyed or legacy credential
/// target described above, not the handle-dir symlink. If a caller passes a
/// symlink, `OpenOptions::open` follows it on both Unix and Windows so the
/// target's mtime is advanced, not the link's.
pub fn bump_mtime_above(path: &Path, min_mtime_ns: i128) -> Result<(), PlatformError> {
    use std::time::{Duration, SystemTime};

    let current_mtime = std::fs::metadata(path)?.modified()?;
    // Defensive cast: `Duration::as_nanos` returns u128. A pathological
    // mtime far in the future could exceed i128::MAX (saturate, don't wrap)
    // — silent wrap to negative would mis-rank baseline against the max()
    // formula. saturating_to_i128 keeps the ordering monotone.
    let current_ns = current_mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0);

    let now_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0);

    // Granularity 100ns — NTFS FILETIME stores mtime in 100-nanosecond
    // ticks (Windows kernel `SetFileTime` rounds DOWN to the nearest tick).
    // Writing `baseline + 1` on Windows rounds back to `baseline`, breaking
    // the strict-advance invariant. POSIX nanosecond-resolution filesystems
    // (ext4, APFS, btrfs) preserve 100ns increments trivially, so 100 is the
    // smallest cross-platform value that guarantees strict advance. Origin:
    // an internal ticket (Windows test `bump_mtime_above_advances_when_baseline_is_in_future`).
    const MTIME_TICK_NS: i128 = 100;
    let target_ns = now_ns
        .max(min_mtime_ns.saturating_add(MTIME_TICK_NS))
        .max(current_ns.saturating_add(MTIME_TICK_NS));
    // u64::MAX nanoseconds = year ~2554. Saturating to u64::MAX (rather
    // than falling back to 0 = epoch) preserves the strict-advance
    // invariant: an mtime regression to 1970 would still satisfy
    // `mtimeMs !== lastCredentialsMtimeMs` for the immediate swap, but
    // operators inspecting `ls -la` would see nonsense and a subsequent
    // bump from a baseline > 1970 would re-trigger the same regression.
    let target_ns_u64 = u64::try_from(target_ns).unwrap_or(u64::MAX);
    let target_time = SystemTime::UNIX_EPOCH + Duration::from_nanos(target_ns_u64);

    // Cross-platform mtime advance:
    //
    // - **Unix:** open read-only (not write(true)) so the call succeeds even
    //   when the target file is mode 0o400 (Codex canonical credential files
    //   per INV-P08). POSIX `futimens(fd, times)` requires the caller to own
    //   the file, NOT to have write permission on it, so an O_RDONLY fd is
    //   sufficient. Confirmed on macOS/Linux: `File::set_modified` uses
    //   `futimens` internally, and `open(O_WRONLY)` on a 0o400 file returns
    //   EACCES even for the file owner, while `open(O_RDONLY)` succeeds and
    //   `futimens` advances the mtime correctly.
    //
    // - **Windows:** `File::set_modified` calls `SetFileTime(HANDLE, ...)`
    //   which requires `FILE_WRITE_ATTRIBUTES` (0x0100) access on the handle.
    //   `OpenOptions::read(true)` maps to `GENERIC_READ` which does NOT
    //   include `FILE_WRITE_ATTRIBUTES`, so opening read-only fails
    //   `SetFileTime` with `ERROR_ACCESS_DENIED` (5). We need a handle that
    //   carries both `FILE_WRITE_ATTRIBUTES` (for the mtime write) and
    //   `FILE_READ_ATTRIBUTES` (0x0080, harmless to grant; some kernels
    //   require it implicitly for any attribute manipulation). This is the
    //   minimum-privilege handle that satisfies `SetFileTime` and does NOT
    //   require `GENERIC_WRITE`, so files whose Windows ACLs deny write data
    //   still allow the mtime bump. Origin: an internal ticket.
    #[cfg(unix)]
    let file = std::fs::OpenOptions::new().read(true).open(path)?;

    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES — minimum access for
        // `SetFileTime`. Avoids GENERIC_READ + GENERIC_WRITE.
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .open(path)?
    };

    file.set_modified(target_time)?;
    Ok(())
}

/// Test helper: drives `op` with the parent directory read-only, then asserts
/// (a) `op` returns `Err`, and (b) no `*.tmp.*` files remain in `dir`.
///
/// This is the canonical §5a regression fixture. Every site that uses the
/// `unique_tmp_path → write → secure_file → atomic_replace` pipeline MUST
/// have a test using this helper (or an inline duplicate in csq-cli /
/// csq-desktop, which cannot reach `pub(crate)` across crate boundaries).
///
/// Origin: security.md §5a, an internal journal entry B2, /redteam round 3 (2026-05-09).
#[cfg(all(test, unix))]
pub(crate) fn assert_no_tmp_leak_on_readonly_parent<F, E>(dir: &std::path::Path, op: F)
where
    F: FnOnce() -> Result<(), E>,
    E: std::fmt::Debug,
{
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = op();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        result.is_err(),
        "op must fail under read-only parent; got Ok"
    );
    let leaked: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.contains(".tmp."))
                .unwrap_or(false)
        })
        .collect();
    assert!(leaked.is_empty(), "§5a leaked tmp files: {leaked:?}");
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

    // ---- EXDEV cross-filesystem fallback ------------------------------
    //
    // `rename(2)` refuses with EXDEV when source and destination are on
    // different mounted filesystems. csq now symlinks into `shared-state/`
    // and `identities/`, which an operator may place on another volume, so
    // the branch is reachable in production. It cannot be reached in a unit
    // test without mounting a second filesystem, so the rename step is
    // injected through the `atomic_replace_unix` seam instead.

    /// An `io::Error` shaped exactly like the kernel's EXDEV refusal:
    /// `raw_os_error() == Some(18)`, `kind() == CrossesDevices`.
    #[cfg(unix)]
    fn exdev_error() -> std::io::Error {
        std::io::Error::from_raw_os_error(libc::EXDEV)
    }

    /// Names of every `*.tmp.*` file left in `dir` — the §5a leak check.
    #[cfg(unix)]
    fn tmp_files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_owned))
            .filter(|n| n.contains(".tmp."))
            .collect();
        names.sort();
        names
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_exdev_falls_back_to_copy_into_place() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("credentials.json");
        let tmp = unique_tmp_path(&target);
        fs::write(&target, b"stale").unwrap();
        fs::write(&tmp, br#"{"access_token":"fresh"}"#).unwrap();
        secure_file(&tmp).unwrap();

        let calls = std::cell::Cell::new(0usize);
        let result = atomic_replace_unix(&tmp, &target, |_, _| {
            calls.set(calls.get() + 1);
            Err(exdev_error())
        });

        result.expect("EXDEV must be recovered, not propagated");
        assert_eq!(calls.get(), 1, "rename attempted exactly once");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            r#"{"access_token":"fresh"}"#,
            "target must hold the new bytes"
        );
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600,
            "security.md MUST-5: the replaced credential file stays 0o600"
        );
        assert!(
            !tmp.exists(),
            "the fallback must consume the source, as rename(2) would"
        );
        assert!(
            tmp_files(dir.path()).is_empty(),
            "security.md §5a: staging file leaked: {:?}",
            tmp_files(dir.path())
        );
    }

    /// The same-filesystem `rename(2)` carries the source's mode across, so
    /// the fallback must too — a canonical Codex credential sits at 0o400
    /// (INV-P08) and must not silently come back as 0o600.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_exdev_preserves_source_mode_0o400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("codex-creds.json");
        let tmp = unique_tmp_path(&target);
        fs::write(&tmp, b"canonical").unwrap();
        secure_file_readonly(&tmp).unwrap();

        atomic_replace_unix(&tmp, &target, |_, _| Err(exdev_error()))
            .expect("EXDEV must be recovered");

        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o400,
            "source mode must survive the copy fallback"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "canonical");
    }

    /// zero-tolerance Rule 3: only EXDEV is recovered. Any other errno keeps
    /// its current behaviour exactly — propagated, unretried, unchanged.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_non_exdev_error_is_not_retried() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("credentials.json");
        let tmp = unique_tmp_path(&target);
        fs::write(&target, b"stale").unwrap();
        fs::write(&tmp, b"never-lands").unwrap();
        secure_file(&tmp).unwrap();

        let calls = std::cell::Cell::new(0usize);
        let result = atomic_replace_unix(&tmp, &target, |_, _| {
            calls.set(calls.get() + 1);
            Err(std::io::Error::from_raw_os_error(libc::EACCES))
        });

        match result {
            Err(PlatformError::Io(e)) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EACCES),
                "the original errno must survive"
            ),
            other => panic!("expected the EACCES io error to propagate, got {other:?}"),
        }
        assert_eq!(calls.get(), 1, "a non-EXDEV failure must not be retried");
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "stale",
            "target must be untouched when the rename fails"
        );
        assert!(
            tmp.exists(),
            "the caller owns tmp cleanup on a propagated error (§5a); the \
             fallback must not have consumed it"
        );
        assert_eq!(
            tmp_files(dir.path()),
            vec![tmp.file_name().unwrap().to_str().unwrap().to_owned()],
            "no staging file may be created on a non-EXDEV path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_happy_path_renames_without_fallback() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.txt");
        let tmp = unique_tmp_path(&target);
        fs::write(&target, b"old").unwrap();
        fs::write(&tmp, b"new").unwrap();

        let calls = std::cell::Cell::new(0usize);
        atomic_replace_unix(&tmp, &target, |from, to| {
            calls.set(calls.get() + 1);
            std::fs::rename(from, to)
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert!(!tmp.exists());
        assert!(tmp_files(dir.path()).is_empty());
    }

    /// security.md §5a: when the fallback fails AFTER the staging file exists,
    /// that secret-bearing file must be removed before the error propagates.
    /// A non-empty directory at `target` makes the final rename fail with the
    /// staging file already written — the only reachable branch that leaves
    /// one behind.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_exdev_removes_staging_when_final_rename_fails() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("occupied");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("resident"), b"blocks the rename").unwrap();
        let tmp = unique_tmp_path(&target);
        fs::write(&tmp, b"secret").unwrap();
        secure_file(&tmp).unwrap();

        let result = atomic_replace_unix(&tmp, &target, |_, _| Err(exdev_error()));

        assert!(
            result.is_err(),
            "renaming onto a non-empty directory must fail"
        );
        assert_eq!(
            tmp_files(dir.path()),
            vec![tmp.file_name().unwrap().to_str().unwrap().to_owned()],
            "§5a: the staging file must be removed before the error propagates"
        );
        assert!(target.is_dir(), "target must be untouched");
    }

    /// zero-tolerance Rule 3 again, from the other side: when the fallback
    /// itself cannot proceed it fails LOUDLY and leaks nothing.
    #[cfg(unix)]
    #[test]
    fn atomic_replace_unix_exdev_fails_loudly_when_staging_cannot_be_created() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("credentials.json");
        let tmp = unique_tmp_path(&target);
        fs::write(&target, b"stale").unwrap();
        fs::write(&tmp, b"fresh").unwrap();
        secure_file(&tmp).unwrap();

        // Read-only parent: the staging file cannot be created.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = atomic_replace_unix(&tmp, &target, |_, _| Err(exdev_error()));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            result.is_err(),
            "an unwritable target dir must surface, not be swallowed"
        );
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "stale",
            "target must be untouched"
        );
        assert_eq!(
            tmp_files(dir.path()),
            vec![tmp.file_name().unwrap().to_str().unwrap().to_owned()],
            "§5a: no staging file may survive a failed fallback"
        );
    }

    // ---- Production-wiring coverage: `atomic_replace` itself, real device --
    //
    // The six tests above drive `atomic_replace_unix` DIRECTLY through the
    // injected-rename seam. That proves the EXDEV fallback's logic; it does
    // NOT prove `atomic_replace` (the public production entry point, this
    // file's line ~111) actually reaches it — reverting that call site to a
    // bare `std::fs::rename(tmp_path, target)?` leaves every test above
    // green, because none of them ever calls `atomic_replace`.
    //
    // This test closes that gap by driving the PUBLIC entry point across a
    // genuine filesystem boundary: a throwaway HFS+ RAM disk, created and
    // torn down at runtime via `hdiutil`/`diskutil`, with device identity
    // (`st_dev`) verified BEFORE anything is asserted. Per
    // `.claude/skills/test-skip-discipline`, the gate is on environment
    // CAPABILITY (can a RAM disk be created here at all?), never on what
    // `atomic_replace` returns — so it skips loudly when the capability is
    // absent and otherwise asserts unconditionally.

    /// A throwaway HFS+ volume backed by a RAM-only block device
    /// (`hdiutil attach ram://`), unmounted on every exit path — including
    /// panic, via `Drop` — so a failed assertion never leaves a mounted
    /// volume behind. macOS-only: `hdiutil`/`diskutil ram://` have no analog
    /// exercised here on other platforms, and `/dev/shm` (the Linux
    /// equivalent used by `kailash-coc-rs`-style harnesses) does not exist
    /// on macOS.
    #[cfg(target_os = "macos")]
    struct RamDisk {
        device: String,
        mount_point: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl RamDisk {
        /// `None` on ANY failure — no admin rights, `hdiutil` sandboxed out,
        /// `diskutil` unavailable, etc. Every intermediate resource is torn
        /// down before returning `None`, so a partial failure never leaks a
        /// device or a mount.
        fn try_create(size_kb: u32) -> Option<Self> {
            let attach = std::process::Command::new("hdiutil")
                .args(["attach", "-nomount", &format!("ram://{size_kb}")])
                .output()
                .ok()?;
            if !attach.status.success() {
                return None;
            }
            let device = String::from_utf8_lossy(&attach.stdout).trim().to_string();
            if device.is_empty() {
                return None;
            }
            let volname = format!("csqtest{}", std::process::id());
            let erase_ok = std::process::Command::new("diskutil")
                .args(["eraseVolume", "HFS+", &volname, &device])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !erase_ok {
                let _ = std::process::Command::new("hdiutil")
                    .args(["detach", &device, "-force"])
                    .output();
                return None;
            }
            let mount_point = PathBuf::from(format!("/Volumes/{volname}"));
            if !mount_point.is_dir() {
                let _ = std::process::Command::new("hdiutil")
                    .args(["detach", &device, "-force"])
                    .output();
                return None;
            }
            Some(Self {
                device,
                mount_point,
            })
        }

        fn path(&self) -> &Path {
            &self.mount_point
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for RamDisk {
        fn drop(&mut self) {
            // `-force` so a lingering open fd (e.g. this test's own failure
            // path) does not leave the volume mounted after the test exits.
            let _ = std::process::Command::new("hdiutil")
                .args(["detach", &self.device, "-force"])
                .output();
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn atomic_replace_public_entry_point_crosses_real_device_boundary() {
        use std::os::unix::fs::MetadataExt;

        let Some(ram_disk) = RamDisk::try_create(2048) else {
            eprintln!(
                "SKIP atomic_replace_public_entry_point_crosses_real_device_boundary: \
                 could not create a throwaway RAM disk via `hdiutil attach ram://` + \
                 `diskutil eraseVolume` on this host (sandboxed CI, no hdiutil access, \
                 or similar) — no second filesystem is available to prove a genuine \
                 EXDEV boundary here. Test did not execute; this is NOT a pass."
            );
            return;
        };

        let same_fs_dir = TempDir::new().unwrap();
        let tmp = same_fs_dir.path().join("staged-credentials.tmp");
        let target = ram_disk.path().join("credentials.json");

        fs::write(&tmp, br#"{"access_token":"fresh-from-real-exdev"}"#).unwrap();
        secure_file(&tmp).unwrap();

        // Verify the boundary is real BEFORE asserting anything about the
        // call under test — a false "yes, cross-device" here would make the
        // whole test vacuous in the other direction (instrument-discipline
        // MUST-1: name what would falsify the setup, not just the claim).
        let tmp_dev = fs::metadata(&tmp).unwrap().dev();
        let target_dir_dev = fs::metadata(ram_disk.path()).unwrap().dev();
        assert_ne!(
            tmp_dev, target_dir_dev,
            "setup invalid: RAM disk reports the SAME st_dev as the tmpdir — \
             this host does not give the two paths distinct devices, so this \
             run cannot exercise a real EXDEV boundary"
        );

        atomic_replace(&tmp, &target)
            .expect("atomic_replace (the PUBLIC entry point) must recover a genuine EXDEV");

        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            r#"{"access_token":"fresh-from-real-exdev"}"#,
            "target on the RAM disk must hold the new bytes"
        );
        assert!(
            !tmp.exists(),
            "the fallback must consume tmp_path, as rename(2) would"
        );
        let leaked = tmp_files(ram_disk.path());
        assert!(
            leaked.is_empty(),
            "security.md §5a: staging file leaked on the RAM disk: {leaked:?}"
        );
    }

    #[test]
    fn bump_mtime_above_advances_when_baseline_equals_current() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"{}").unwrap();

        let baseline = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(baseline).unwrap();
        drop(f);

        let baseline_ns = baseline
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;

        bump_mtime_above(&path, baseline_ns).unwrap();

        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            new_mtime > baseline,
            "bump_mtime_above must advance strictly above baseline; got {new_mtime:?} <= {baseline:?}"
        );
    }

    #[test]
    fn bump_mtime_above_advances_when_baseline_is_in_future() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"{}").unwrap();

        // Baseline far in the future — clock-skew defense. The bump must
        // still produce a strictly-greater mtime, not silently drop to now().
        let future = SystemTime::now() + Duration::from_secs(86_400 * 365);
        let future_ns = future
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;

        bump_mtime_above(&path, future_ns).unwrap();

        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        let new_ns = new_mtime
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;
        assert!(
            new_ns > future_ns,
            "bump_mtime_above must advance above future baseline; got {new_ns} <= {future_ns}"
        );
    }

    #[test]
    fn bump_mtime_above_zero_baseline_advances_above_current() {
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"{}").unwrap();

        let original = SystemTime::UNIX_EPOCH + Duration::from_secs(1_500_000_000);
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(original).unwrap();
        drop(f);

        // baseline = 0 means "no minimum, just advance above current"
        bump_mtime_above(&path, 0).unwrap();

        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            new_mtime > original,
            "bump_mtime_above with baseline=0 must still advance above current mtime"
        );
    }

    #[test]
    fn bump_mtime_above_nonexistent_path_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let result = bump_mtime_above(&path, 0);
        assert!(
            result.is_err(),
            "bump_mtime_above on missing path must error"
        );
    }

    /// INV-P08 compatibility: `bump_mtime_above` MUST succeed on a 0o400
    /// (owner-read-only) file. Codex canonical credential files live at 0o400
    /// between refresh windows (per `secure_file_readonly`). The helper must
    /// use O_RDONLY + `futimens`, not O_WRONLY (which returns EACCES for the
    /// owner of a 0o400 file on POSIX).
    #[cfg(unix)]
    #[test]
    fn bump_mtime_above_succeeds_on_mode_400_file() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, SystemTime};

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("codex-creds.json");
        fs::write(&path, b"{}").unwrap();

        // Pin mtime to a known past value.
        let pinned = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_modified(pinned).unwrap();
        drop(f);

        // Flip to 0o400 — the INV-P08 mode that Codex canonicals sit at.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

        let pinned_ns = pinned
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;

        // Must not return EACCES; must advance the mtime.
        bump_mtime_above(&path, pinned_ns).unwrap();

        // Restore to writable before reading metadata (just in case).
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            new_mtime > pinned,
            "bump_mtime_above must advance mtime on a 0o400 file (INV-P08 \
             codex canonical compatibility); got {new_mtime:?} <= {pinned:?}"
        );
    }

    /// SEC-3-H3 (M3-4): extend the 0o400 coverage to the UUID-keyed credential
    /// path (`identities/<UUID>/credentials.json`).  The file is placed under
    /// an identity-style directory structure to prove that `bump_mtime_above`
    /// works correctly regardless of whether the file is at a slot path or an
    /// identity path.  This pins an internal journal entry D3 (test fixture matches production
    /// permission mode) for the identity-keyed case.
    ///
    /// The key invariant: `bump_mtime_above` uses `OpenOptions::new().read(true)`
    /// (POSIX `futimens` requires ownership, not write permission — an internal journal entry D1).
    /// Using `O_RDONLY` means a 0o400 file owned by the caller is accessible;
    /// `O_WRONLY` would fail with `EACCES` even for the owner on POSIX.
    #[cfg(unix)]
    #[cfg(any(test, feature = "test-utils"))]
    #[test]
    fn bump_mtime_above_succeeds_on_mode_0o400_identity_credentials_json() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, SystemTime};

        // Arrange: create an identity-style directory structure with credentials.json
        // at 0o400 — matching the production mode Codex auth files sit at.
        let dir = TempDir::new().unwrap();
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let identity_dir = dir.path().join("identities").join(uuid_str);
        fs::create_dir_all(&identity_dir).unwrap();
        let path = identity_dir.join("credentials.json");
        fs::write(&path, b"{}").unwrap();

        // Pin mtime to a known past value.
        let pinned = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001);
        {
            let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.set_modified(pinned).unwrap();
        }

        // Flip to 0o400 — the INV-P08 mode.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

        let pinned_ns = pinned
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as i128;

        // Act: must NOT return EACCES; must advance the mtime on the UUID path.
        bump_mtime_above(&path, pinned_ns).unwrap();

        // Restore to writable so metadata() can be read.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        // Assert: mtime advanced above the pinned baseline.
        let new_mtime = fs::metadata(&path).unwrap().modified().unwrap();
        assert!(
            new_mtime > pinned,
            "bump_mtime_above must advance mtime on a 0o400 identity credentials.json \
             (SEC-3-H3 / INV-P08 compatibility); got {new_mtime:?} <= {pinned:?}"
        );
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

    #[cfg(unix)]
    #[test]
    fn secure_file_readonly_sets_400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("canonical-cred.json");
        fs::write(&path, b"\"token\":\"...\"").unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );

        secure_file_readonly(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }

    /// Canonical credential-file lifecycle (spec 07 INV-P08):
    /// 0o400 → flip to 0o600 for write → write → flip back to 0o400.
    #[cfg(unix)]
    #[test]
    fn secure_file_roundtrip_400_600_400() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("creds.json");
        fs::write(&path, b"initial").unwrap();

        secure_file_readonly(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );

        // Begin refresh window — flip to writable.
        secure_file(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Refresh writes.
        fs::write(&path, b"refreshed").unwrap();

        // Close refresh window — flip back to read-only.
        secure_file_readonly(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }

    #[test]
    fn secure_file_readonly_nonexistent_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope.json");
        #[cfg(unix)]
        assert!(secure_file_readonly(&path).is_err());
        #[cfg(windows)]
        assert!(secure_file_readonly(&path).is_ok());
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

    // ---- write_new_private ---------------------------------------------
    //
    // security.md §5a: the write-then-secure window. These pin the three
    // properties the helper exists to guarantee — mode set AT creation
    // regardless of umask, and refusal of both an existing file and an
    // existing symlink so a pre-planted symlink's target is never touched.

    /// Mutation: drop `.mode(0o600)` from `write_new_private` -> this REDs,
    /// because the file would then be created at `0o666 & !umask`, and
    /// under the 0o022 umask set here that is 0o644, not 0o600.
    ///
    /// The umask is deliberately tightened to a KNOWN permissive value
    /// (0o022, a common default) for the duration of this test, rather than
    /// trusting the ambient umask — if the ambient umask already happened to
    /// be 0o077 or stricter, dropping `.mode(0o600)` would still yield 0o600
    /// by coincidence (0o666 & !0o077 == 0o600) and the mutation would NOT
    /// RED, silently masking the regression this test exists to catch.
    ///
    /// `libc::umask` is process-global (same hazard class as
    /// `platform::test_env::signal_lock`'s process-wide signal
    /// disposition), so this test serializes via the shared
    /// `platform::test_env` mutex rather than introducing a new one —
    /// no other test in this workspace calls `libc::umask` (the only other
    /// call site is `daemon::server`'s socket-bind path, which does not run
    /// under `cargo test`), so the shared env-mutation lock is reused here
    /// as the closest existing "process-global mutable OS state" guard.
    #[cfg(unix)]
    #[test]
    fn write_new_private_sets_mode_0o600_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.tmp");

        // SAFETY: libc::umask is always safe to call; the previous value is
        // restored unconditionally immediately below, under the same lock.
        let old_umask = unsafe { libc::umask(0o022) };
        let result = write_new_private(&path, b"secret-bytes");
        // SAFETY: same as above — restoring the saved mask.
        unsafe {
            libc::umask(old_umask);
        }

        result.expect("write_new_private must succeed for a fresh path");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "mode must be 0o600 regardless of a permissive process umask"
        );
    }

    /// `write_new_private_synced` shares `write_new_private_impl` with
    /// `sync=true`; this pins that it still creates at 0o600 (the shared
    /// mode/create_new guarantee) and additionally that the bytes are
    /// durable — read back via a FRESH `File::open`, not the writer's own
    /// handle, so a bug that skipped `sync_all` but left the OS page cache
    /// coherent would still be caught by anything that re-opens the path.
    #[test]
    fn write_new_private_synced_sets_mode_and_persists_bytes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.tmp");

        write_new_private_synced(&path, b"durable-secret").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(fs::read(&path).unwrap(), b"durable-secret");
    }

    /// Mutation: drop `create_new(true)` (replace with plain `.write(true)`,
    /// which would need `.truncate(true)` or `.create(true)` to be usable at
    /// all) -> this REDs, because the call would then silently truncate and
    /// overwrite the pre-existing file's content instead of refusing.
    #[test]
    fn write_new_private_refuses_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("secret.tmp");
        fs::write(&path, b"pre-existing").unwrap();

        let result = write_new_private(&path, b"new-secret");

        assert!(
            result.is_err(),
            "write_new_private must refuse an existing regular file"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            b"pre-existing",
            "the pre-existing file's content must be untouched"
        );
    }

    /// Mutation: same as above (`create_new(true)` removed) -> this REDs
    /// because `std::fs::write`-shaped semantics follow a symlink and would
    /// overwrite ITS TARGET — exactly the attack `create_new` exists to
    /// close (a pre-planted symlink at the tmp path pointing at a file the
    /// attacker wants overwritten with attacker-controlled or truncated
    /// content).
    #[cfg(unix)]
    #[test]
    fn write_new_private_refuses_existing_symlink_and_leaves_target_untouched() {
        let dir = TempDir::new().unwrap();
        let victim = dir.path().join("victim.txt");
        let link = dir.path().join("secret.tmp");
        fs::write(&victim, b"do-not-touch").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let result = write_new_private(&link, b"attacker-controlled");

        assert!(
            result.is_err(),
            "write_new_private must refuse a path that already exists as a symlink"
        );
        assert_eq!(
            fs::read(&victim).unwrap(),
            b"do-not-touch",
            "the symlink's target must be untouched — create_new must not follow it"
        );
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must be untouched, not replaced"
        );
    }

    // Cleanup-on-write-failure (the `write_all` Err branch removing the file
    // it just created) is NOT covered by an executed test: no portable,
    // non-fragile trigger for a write(2) failure AFTER a successful
    // create_new/open exists across this workspace's macOS + Linux + Windows
    // CI matrix. `/dev/full` is Linux-only; forcing EFBIG via
    // `setrlimit(RLIMIT_FSIZE)` requires handling `SIGXFSZ` (whose default
    // disposition is to terminate the process) and would itself mutate
    // process-global signal state guarded by `test_env::signal_lock` for an
    // unrelated reason. Stated per COMMON.md Evidence rather than claimed:
    // this branch is structurally identical in shape to
    // `atomic_replace_cross_device`'s `copy_into_staging` failure arm (same
    // "remove what this call created, then propagate" pattern), which IS
    // exercised via a forced rename failure in
    // `atomic_replace_unix_exdev_removes_staging_when_final_rename_fails`.
}
