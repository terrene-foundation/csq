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
//! journal 0014 §FD #2 and journal 0073 §FD #2 so there is a single
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
/// (credential mode-flip mutex coordination) + workspaces/codex/01-analysis
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

/// Creates a symlink at `link` pointing to `target`, failing if `link` already exists.
///
/// This is the cross-platform primitive for atomic-exclusive symlink creation.
/// It underpins the handle-dir model (Phase 3 of issue #292 A++): each
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
/// Issue #270 fix: `csq swap N` repoints `handle_dir/.credentials.json`'s
/// symlink to `config-<N>/.credentials.json`. CC re-stats the symlink before
/// every API call and reloads credentials only when
/// `mtimeMs !== lastCredentialsMtimeMs` (spec 01 §1.4 — strict inequality).
/// When `config-<current>/.credentials.json` and `config-<N>/.credentials.json`
/// happen to share an mtime (both refreshed within the same nanosecond by the
/// daemon, or filesystem precision clamps), CC silently skips the reload and
/// the swap "appears not to take effect" until something else perturbs the
/// file. Calling this helper on the new target's canonical path BEFORE the
/// symlink rename guarantees CC sees a fresh mtime on the next stat.
///
/// The new mtime is `max(now(), min_mtime_ns + 1, current_mtime_ns + 1)`.
/// Pass `min_mtime_ns = 0` when no baseline is required (current + 1 wins).
///
/// Errors are returned but the caller should typically log and continue —
/// observability MUST NOT alter swap semantics. The post-swap collision warn
/// in `repoint_handle_dir` (`session::handle_dir`) acts as a regression
/// detector if this helper silently fails to advance the mtime.
///
/// Production callers pass the canonical credential file path directly
/// (`config-N/.credentials.json`, `credentials/codex-N.json`), not the
/// handle-dir symlink. If a future caller passes a symlink, `OpenOptions::open`
/// follows it on both Unix and Windows so the target's mtime is advanced,
/// not the link's.
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
    // issue #437 (Windows test `bump_mtime_above_advances_when_baseline_is_in_future`).
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
    //   still allow the mtime bump. Origin: issue #437.
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
/// Origin: security.md §5a, journal 0065 B2, /redteam round 3 (2026-05-09).
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
    /// identity path.  This pins journal 0013 D3 (test fixture matches production
    /// permission mode) for the identity-keyed case.
    ///
    /// The key invariant: `bump_mtime_above` uses `OpenOptions::new().read(true)`
    /// (POSIX `futimens` requires ownership, not write permission — journal 0013 D1).
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
}
