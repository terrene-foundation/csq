//! Windows symlink-exclusive primitive — directory junction via NTFS reparse points.
//!
//! # Why junctions, not symlinks
//!
//! Windows developer-mode symlinks (`CreateSymbolicLinkW`) require either
//! elevated privileges or the Developer Mode system setting, which is not
//! reliable in CI or on end-user machines. NTFS directory junctions
//! (`IO_REPARSE_TAG_MOUNT_POINT`, set via `FSCTL_SET_REPARSE_POINT`) do not
//! require elevation. They are a stable NTFS feature present on every
//! Windows version since Windows 2000 and are resolved transparently by the
//! kernel at path-traversal time.
//!
//! Phase 3 uses `symlink_exclusive` to wire handle-dir symlinks (per
//! `specs/02-csq-handle-dir-model.md`). On Windows these become junctions.
//! `std::fs::read_link` resolves NTFS junctions correctly since Rust 1.x, so
//! the cross-platform acceptance test applies without modification.
//!
//! # Pre-existence check
//!
//! There is a TOCTOU window between the `GetFileAttributesW` existence check
//! and the `DeviceIoControl(FSCTL_SET_REPARSE_POINT)` call. Windows provides
//! no `renameat2(RENAME_NOREPLACE)` equivalent for symlinks/junctions. The
//! window is bounded by the same-user threat model documented in
//! `rules/account-terminal-separation.md`.
//!
//! # `windows-sys` dependency
//!
//! This module uses the `windows-sys` crate (already present in
//! `csq-core/Cargo.toml` under `[target.'cfg(target_os = "windows")'.dependencies]`
//! for the Win32 session discovery code). No new dependency is introduced.
//! The additional feature flags required by this module
//! (`Win32_Storage_FileSystem` and `Win32_System_IO`) are already declared.
//!
//! Origin: issue #292 Phase 1 M1-3.

use crate::error::PlatformError;
use std::path::Path;

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt as _;

// ── Windows-only implementation ───────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub fn symlink_exclusive(target: &Path, link: &Path) -> Result<(), PlatformError> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileAttributesW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // FSCTL_SET_REPARSE_POINT = 0x000900A4
    const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;
    // IO_REPARSE_TAG_MOUNT_POINT (junction) = 0xA0000003
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;
    // FILE_ATTRIBUTE_DIRECTORY
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    // CreateFileW disposition
    const OPEN_ALWAYS: u32 = 4;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

    // Encode a &Path as a null-terminated wide string.
    fn to_wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0u16))
            .collect()
    }

    // Encode a &str as a wide string (no NUL terminator).
    fn str_to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    // ── Step 1: Create parent directories ────────────────────────────────────
    if let Some(parent) = link.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // ── Step 2: Pre-existence check ───────────────────────────────────────────
    let link_wide = to_wide(link);
    let attrs = unsafe { GetFileAttributesW(link_wide.as_ptr()) };
    if attrs != INVALID_FILE_ATTRIBUTES {
        // A file or directory already exists at the link path.
        return Err(PlatformError::AlreadyExists);
    }
    // INVALID_FILE_ATTRIBUTES can also mean a real error (e.g. access denied).
    let last_err = unsafe { GetLastError() };
    // ERROR_FILE_NOT_FOUND (2) and ERROR_PATH_NOT_FOUND (3) are the expected
    // codes when the entry is absent. Anything else is a real error.
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    if last_err != ERROR_FILE_NOT_FOUND && last_err != ERROR_PATH_NOT_FOUND {
        return Err(PlatformError::Win32 {
            code: last_err,
            message: format!("GetFileAttributesW on {} failed", link.display()),
        });
    }

    // ── Step 3: Create a directory for the junction point ─────────────────────
    // NTFS junctions require an actual directory to exist at the link path
    // before FSCTL_SET_REPARSE_POINT is applied.
    std::fs::create_dir(link).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            PlatformError::AlreadyExists
        } else {
            PlatformError::Io(e)
        }
    })?;

    // ── Step 4: Open the newly-created directory ──────────────────────────────
    let handle: HANDLE = unsafe {
        CreateFileW(
            link_wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            0, // no template
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        // Clean up the directory we just created.
        let _ = std::fs::remove_dir(link);
        return Err(PlatformError::Win32 {
            code,
            message: format!("CreateFileW on {} failed", link.display()),
        });
    }

    // ── Step 5: Build the MOUNT_POINT reparse buffer ─────────────────────────
    //
    // The reparse buffer for IO_REPARSE_TAG_MOUNT_POINT has the following
    // layout (all offsets in bytes, little-endian):
    //
    //   ReparseDataBuffer header (12 bytes):
    //     u32 ReparseTag
    //     u16 ReparseDataLength      = sizeof(PathBuffer portion)
    //     u16 Reserved               = 0
    //   MountPointReparseBuffer (8 + path bytes):
    //     u16 SubstituteNameOffset   = 0
    //     u16 SubstituteNameLength   = len(subst_wide) * 2
    //     u16 PrintNameOffset        = SubstituteNameLength + 2  (past NUL)
    //     u16 PrintNameLength        = len(print_wide) * 2
    //     PathBuffer: [subst_wide || 0u16 || print_wide || 0u16]
    //
    // SubstituteName is the NT path (\??\<absolute path>).
    // PrintName is the display path (the original path without the \??\).
    //
    // References:
    //   https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/reparse-point-tag-values
    //   https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-reparse_data_buffer

    // Build the absolute NT path for the target.
    // `target` may be relative — canonicalize it first. On Windows
    // `canonicalize` returns the verbatim Win32 form `\\?\C:\path\...`.
    // The NT-namespace prefix for reparse-point substitute names is `\??\`
    // — prepending that to `\\?\C:\path\...` yields `\??\\\?\C:\path\...`
    // which is malformed (double prefix); the kernel resolves it to
    // garbage and Win32 callers traversing the junction get
    // `ERROR_INVALID_NAME` (code 123). Strip the `\\?\` verbatim prefix
    // before prepending `\??\`. Origin: issue #437.
    let target_abs = target.canonicalize().map_err(PlatformError::Io)?;
    let target_full = target_abs.to_string_lossy();
    let target_str = target_full.strip_prefix(r"\\?\").unwrap_or(&target_full);
    // NT namespace prefix: \??\
    let subst_str = format!("\\??\\{}", target_str);
    let print_str = target_str;

    let mut subst_wide = str_to_wide(&subst_str);
    let mut print_wide: Vec<u16> = print_str.encode_utf16().collect();

    // PathBuffer = subst_wide + NUL + print_wide + NUL
    let mut path_buf: Vec<u16> = Vec::new();
    path_buf.extend_from_slice(&subst_wide);
    path_buf.push(0u16);
    path_buf.extend_from_slice(&print_wide);
    path_buf.push(0u16);
    let path_buf_bytes: Vec<u8> = path_buf.iter().flat_map(|w| w.to_le_bytes()).collect();

    // MountPointReparseBuffer header (8 bytes) + path data.
    let subst_len = (subst_wide.len() * 2) as u16;
    let print_len = (print_wide.len() * 2) as u16;
    let print_offset = subst_len + 2u16; // past the NUL after SubstituteName

    let mut reparse_data: Vec<u8> = Vec::new();
    // SubstituteNameOffset
    reparse_data.extend_from_slice(&0u16.to_le_bytes());
    // SubstituteNameLength
    reparse_data.extend_from_slice(&subst_len.to_le_bytes());
    // PrintNameOffset
    reparse_data.extend_from_slice(&print_offset.to_le_bytes());
    // PrintNameLength
    reparse_data.extend_from_slice(&print_len.to_le_bytes());
    // PathBuffer
    reparse_data.extend_from_slice(&path_buf_bytes);

    // Full ReparseDataBuffer header (8 bytes: tag u32 + data_len u16 + reserved u16).
    let reparse_data_length = reparse_data.len() as u16;
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes()); // ReparseTag
    buf.extend_from_slice(&reparse_data_length.to_le_bytes()); // ReparseDataLength
    buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    buf.extend_from_slice(&reparse_data);

    // ── Step 6: Apply the reparse point ──────────────────────────────────────
    let mut bytes_returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr() as *const std::ffi::c_void,
            buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        let code = unsafe { GetLastError() };
        // Clean up the directory.
        let _ = std::fs::remove_dir(link);
        if code == ERROR_ALREADY_EXISTS || code == ERROR_FILE_EXISTS {
            return Err(PlatformError::AlreadyExists);
        }
        return Err(PlatformError::Win32 {
            code,
            message: format!("FSCTL_SET_REPARSE_POINT on {} failed", link.display()),
        });
    }

    Ok(())
}

// ── Non-Windows stub (this module is only compiled on Windows) ────────────────

#[cfg(not(target_os = "windows"))]
pub fn symlink_exclusive(_target: &Path, _link: &Path) -> Result<(), PlatformError> {
    Err(PlatformError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "fs_symlink_windows is Windows-only",
    )))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn junction_created_and_readable() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target_dir");
        let link = dir.path().join("junction");

        fs::create_dir(&target).unwrap();
        fs::write(target.join("canary.txt"), b"hello").unwrap();

        symlink_exclusive(&target, &link).unwrap();

        // Junction-traversal acceptance (two structural checks):
        //
        //   1. `symlink_metadata` confirms the link is a reparse point
        //      (symlink/junction), not a plain directory copy.
        //   2. A canary file written under `target` is readable through
        //      `link`, proving end-to-end junction traversal.
        //
        // The naive `fs::read_link(&link)` string-comparison approach was
        // brittle: read_link returns the raw substitute name with the NT
        // namespace prefix (`\\?\\??\C:\Users\runneradmin\...`), and
        // `TempDir` on the GH-Actions windows-latest runner returns an 8.3
        // short name (`C:\Users\RUNNER~1\...`) — two unrelated layers of
        // inequality. `fs::canonicalize(&link)` looked promising but fails
        // on Windows with `ERROR_INVALID_NAME` (code 123) for junctions
        // whose substitute name uses the `\??\` NT-namespace prefix —
        // Win32 `GetFinalPathNameByHandle` does not normalise that prefix.
        //
        // The functional check (canary read) is the actual user-facing
        // behaviour we care about. Issue #437.
        let link_meta = fs::symlink_metadata(&link).unwrap();
        assert!(
            link_meta.file_type().is_symlink(),
            "junction must be a reparse point, not a plain directory; got {:?}",
            link_meta.file_type()
        );

        assert_eq!(
            fs::read_to_string(link.join("canary.txt")).unwrap(),
            "hello",
            "canary file under target must be readable through the junction"
        );
    }

    #[test]
    fn returns_already_exists_when_link_present() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target_dir");
        let link = dir.path().join("junction");
        fs::create_dir(&target).unwrap();

        symlink_exclusive(&target, &link).unwrap();

        let err = symlink_exclusive(&target, &link).unwrap_err();
        assert!(
            matches!(err, PlatformError::AlreadyExists),
            "expected AlreadyExists, got {err:?}"
        );
    }
}
