//! Private filesystem identity and platform publication primitives.
#[cfg(unix)]
use super::io_error;
#[cfg(windows)]
use super::io_error_at;
use super::{Directory, StoreError};
use std::{
    fs::{File, Metadata, OpenOptions},
    io::{self, Write},
    path::Path,
};
/// File identity: (volume, id, `wide`). `wide` is true for the 128-bit
/// `FileIdInfo` identity (and every unix inode), false for the Windows
/// 32-bit-volume / 64-bit-index fallback. Two identities from different sources
/// are never equal, so a comparison that mixed sources fails closed.
#[derive(PartialEq, Eq)]
pub(super) struct Node(pub(super) u64, pub(super) u128, bool);

/// `FileIdInfo` is unsupported (some SMB redirectors, older filesystems) when
/// the call fails with ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED or
/// ERROR_INVALID_PARAMETER; only then is the 64-bit index identity used.
#[cfg(any(windows, test))]
fn file_id_unsupported(code: Option<i32>) -> bool {
    matches!(code, Some(1 | 50 | 87))
}

pub(super) fn check(meta: &Metadata, directory: bool) -> Result<(), StoreError> {
    if (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
        || meta.file_type().is_symlink()
    {
        return Err(StoreError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid takes no arguments and accesses no Rust memory.
        if meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || (!directory && meta.nlink() != 1)
        {
            return Err(StoreError::UnsafePath);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(StoreError::UnsafePath);
        }
    }
    Ok(())
}

/// Windows parity with the unix `nlink == 1` rule in `check`: an opened
/// transcript, lock or temp is refused when it has another hard link, which
/// would share its content with a path the store does not control.
#[cfg(windows)]
pub(super) fn check_single_link(file: &File) -> Result<(), StoreError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: zero is a valid buffer; the API fills it synchronously from the
    // live borrowed handle and retains no pointer.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut info) } == 0 {
        return Err(StoreError::io_os("link_query", &io::Error::last_os_error()));
    }
    (info.nNumberOfLinks == 1)
        .then_some(())
        .ok_or(StoreError::UnsafePath)
}

pub(super) fn node(file: &File) -> Result<Node, StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata().map_err(io_error)?;
        Ok(Node(m.dev(), u128::from(m.ino()), true))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
            BY_HANDLE_FILE_INFORMATION, FILE_ID_INFO,
        };
        // 128-bit identity (ReFS file IDs do not fit 64 bits).
        // SAFETY: zero is a valid initial buffer; the API fills exactly
        // size_of::<FILE_ID_INFO>() bytes synchronously from a live handle.
        let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as isize,
                FileIdInfo,
                std::ptr::addr_of_mut!(info).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        } != 0
        {
            return Ok(Node(
                info.VolumeSerialNumber,
                u128::from_le_bytes(info.FileId.Identifier),
                true,
            ));
        }
        let error = io::Error::last_os_error();
        if !file_id_unsupported(error.raw_os_error()) {
            return Err(StoreError::io_os("file_id_info", &error));
        }
        // SAFETY: zero is a valid buffer; the API fills it synchronously from
        // the live borrowed handle and retains no pointer.
        let mut basic: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut basic) } == 0 {
            return Err(StoreError::io_os(
                "file_id_basic",
                &io::Error::last_os_error(),
            ));
        }
        Ok(Node(
            u64::from(basic.dwVolumeSerialNumber),
            u128::from((u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow)),
            false,
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(StoreError::io("unsupported_platform"))
    }
}

pub(super) fn open_directory(path: &Path) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0200_0000 | 0x0020_0000);
    }
    options.open(path).map_err(|_| StoreError::UnsafePath)
}

pub(super) fn open_directory_child(parent: &Directory, name: &str) -> Result<File, StoreError> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new(name).map_err(|_| StoreError::UnsafePath)?;
        // SAFETY: owned parent fd, generated component; newly opened descriptor
        // transfers into File, and O_NOFOLLOW refuses a planted child symlink.
        let fd = unsafe {
            libc::openat(
                parent.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(StoreError::UnsafePath);
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    #[cfg(not(unix))]
    {
        #[cfg(windows)]
        {
            // Verifies owner + DACL + label, stamping the label on a directory
            // written before it existed (through this same handle).
            open_private_directory(&parent.path.join(name))
        }
        #[cfg(not(windows))]
        {
            open_directory(&parent.path.join(name))
        }
    }
}

pub(super) fn sync_directory(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        file.sync_all()
    }
    #[cfg(windows)]
    {
        let _ = file;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[cfg(all(test, windows))]
thread_local! {
    /// Test seam: fail the flush that follows a successful rename, once. The
    /// failure is injected as the RESULT of the flush, so the production
    /// `map_err` to `DurabilityUnknown` is the code under test.
    pub(super) static FAIL_POST_RENAME_SYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Test seam: skip the `FileRenameInfoEx` attempt, as if the filesystem
    /// returned ERROR_INVALID_PARAMETER, forcing the legacy-class fallback.
    pub(super) static FORCE_LEGACY_RENAME: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    /// Test seam: runs once immediately before the first rename attempt, with
    /// the verified handle still held. The test probes the temp from outside.
    pub(super) static BEFORE_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    /// Test seam: runs once immediately before the `NtSetInformationFile` fallback
    /// call, with the verified handle still held (probes the temp from outside).
    pub(super) static BEFORE_LEGACY_RENAME: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    /// Test seam: count renames that took the legacy-class fallback.
    pub(super) static LEGACY_RENAMES: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
}

/// The only leaf ever published by rename: a canonical `<uuid>.jsonl` transcript.
/// Anything else is `UnsafePath`.
#[cfg(windows)]
fn validate_leaf(leaf: &str) -> Result<(), StoreError> {
    let id = leaf.strip_suffix(".jsonl").ok_or(StoreError::UnsafePath)?;
    super::canonical_id(id).map_err(|_| StoreError::UnsafePath)
}

/// Create the publish temp ONCE, exclusively, with the owner-only DACL applied
/// at creation and the access the whole lifecycle needs (write data, DELETE,
/// READ_CONTROL, FILE_READ_ATTRIBUTES) and share mode READ only: while this
/// handle lives no other handle can open the file for write or delete, so its
/// identity and content cannot change between write and publish.
#[cfg(windows)]
pub(super) fn create_private_temp(path: &Path) -> Result<File, StoreError> {
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_WRITE_DATA,
    };
    const READ_CONTROL: u32 = 0x0002_0000;
    crate::platform::fs_windows_acl::create_new_private_file_with(
        path,
        DELETE | FILE_WRITE_DATA | READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,
    )
    .map_err(|e| acl_error("create_temp", e))
}

// Keep transcript publication and the general atomic writer on the same
// unsupported-class policy; access/sharing failures must not select fallback.
#[cfg(windows)]
use crate::platform::fs::windows_rename_class_unsupported as rename_class_unsupported;

/// Publish `source` (the open handle the caller created through
/// `create_private_temp`) as `leaf` inside `directory`, REPLACING any existing
/// entry, THROUGH that same handle: nothing is reopened by path, so no swap or
/// content rewrite can occur between verification and rename. This is the only
/// rename in the store; creations (the store directory, a new transcript) are
/// exclusive creates at their final name and never rename.
///
/// The handle is verified (regular file, not a reparse point, link count 1,
/// private DACL) and renamed with `NtSetInformationFile(FileRenameInformationEx)`
/// (`REPLACE_IF_EXISTS | POSIX_SEMANTICS`, `RootDirectory` = the pinned directory
/// handle, `FileName` = the leaf only); POSIX semantics unlink a replaced entry at
/// once even while another process holds it open with FILE_SHARE_DELETE. The kernel32
/// `SetFileInformationByHandle(FileRenameInfoEx)` wrapper is NOT used: Windows CI
/// (run 39014859238) showed it returns ERROR_INVALID_PARAMETER (87) for a
/// handle-relative `RootDirectory` rename of a file as well as of a directory. ONLY
/// when the NT call reports the class unsupported (`rename_class_unsupported`) does
/// it retry, logged, with the legacy `FileRenameInformation` class through the SAME
/// handle, root and leaf; that class cannot replace a target another handle holds
/// open (ACCESS_DENIED), so it is a compatibility floor, not the expected path.
/// Never a full-path rename. A failed fallback reports both calls' statuses
/// (`ex_nt_status`, `ex_os_error` are the first attempt). Any failure AFTER the rename
/// succeeded is `DurabilityUnknown` (published). The file is flushed; the directory
/// entry is not separately flushed on Windows.
#[cfg(windows)]
pub(super) fn publish_handle(
    directory: &File,
    source: &File,
    leaf: &str,
) -> Result<(), StoreError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile;
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_RENAME_INFO,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 0x1;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 0x2;
    // ntifs.h FILE_INFORMATION_CLASS: FileRenameInformation (10) and
    // FileRenameInformationEx (65). Both take FILE_RENAME_INFORMATION[_EX], whose
    // layout is the one of FILE_RENAME_INFO (a BOOLEAN/ULONG-Flags union, RootDirectory,
    // FileNameLength, FileName), asserted below for the 64-bit ABI.
    const FILE_RENAME_INFORMATION_CLASS: i32 = 10;
    const FILE_RENAME_INFORMATION_EX_CLASS: i32 = 65;
    #[cfg(target_pointer_width = "64")]
    const _: () = {
        assert!(std::mem::offset_of!(FILE_RENAME_INFO, RootDirectory) == 8);
        assert!(std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength) == 16);
        assert!(std::mem::offset_of!(FILE_RENAME_INFO, FileName) == 20);
    };
    validate_leaf(leaf)?;
    // SAFETY: zero is a valid buffer; the API fills it synchronously from the
    // live borrowed handle and retains no pointer.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(source.as_raw_handle() as isize, &mut info) } == 0 {
        return Err(StoreError::io_os(
            "publish_query",
            &io::Error::last_os_error(),
        ));
    }
    if info.dwFileAttributes & (0x400 | FILE_ATTRIBUTE_DIRECTORY) != 0 || info.nNumberOfLinks != 1 {
        return Err(StoreError::UnsafePath);
    }
    check_private_handle(source)?;
    let leaf: Vec<u16> = leaf.encode_utf16().collect();
    // Header plus the UTF-16 leaf (the struct already holds one u16 of it),
    // in a u64 buffer so the HANDLE field is 8-aligned.
    let name_bytes = leaf.len() * 2;
    let total = std::mem::size_of::<FILE_RENAME_INFO>() + name_bytes;
    let mut buffer = vec![0u64; total.div_ceil(8)];
    let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: the zeroed buffer is >= size_of::<FILE_RENAME_INFO>() + name_bytes
    // and 8-aligned; the leaf is copied within its bounds (FileName is the
    // trailing flexible array). RootDirectory is the live borrowed directory
    // handle. Only this function reads or writes the buffer.
    unsafe {
        (*rename).RootDirectory = directory.as_raw_handle() as isize;
        (*rename).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(
            leaf.as_ptr(),
            std::ptr::addr_of_mut!((*rename).FileName).cast::<u16>(),
            leaf.len(),
        );
    }
    // One NtSetInformationFile call of `class` with the union set by `flags`.
    // SAFETY (closure): `source` is a live handle opened with DELETE; the buffer is
    // the initialised structure above of exactly `total` bytes; the union write is
    // in bounds and `IO_STATUS_BLOCK` is a valid zeroed out-parameter. The call reads
    // the buffer synchronously and retains no pointer.
    let nt = |class: i32, flags: u32| -> i32 {
        unsafe {
            (*rename).Anonymous.Flags = flags;
            let mut block: IO_STATUS_BLOCK = std::mem::zeroed();
            NtSetInformationFile(
                source.as_raw_handle() as isize,
                &mut block,
                rename.cast(),
                total as u32,
                class,
            )
        }
    };
    // Classifies a failed status like the main path (NotFound / AlreadyExists stay
    // typed); an Io keeps the stage, the status and the first attempt's codes.
    let failed = |stage: &'static str, status: i32, first: Option<i32>| -> StoreError {
        // SAFETY: pure status-to-code translation, no pointers.
        let dos = |s: i32| unsafe { RtlNtStatusToDosError(s) } as i32;
        match io_error_at(stage, io::Error::from_raw_os_error(dos(status))) {
            StoreError::Io(failure) => StoreError::Io(super::IoFailure {
                nt_status: Some(status),
                ex_nt_status: first,
                ex_os_error: first.map(dos),
                ..failure
            }),
            typed => typed,
        }
    };
    let skip_ex = {
        #[cfg(test)]
        {
            FORCE_LEGACY_RENAME.with(|f| f.get())
        }
        #[cfg(not(test))]
        {
            false
        }
    };
    #[cfg(test)]
    if let Some(hook) = BEFORE_RENAME.with(|c| c.borrow_mut().take()) {
        hook();
    }
    let ex_status = if skip_ex {
        0xC000_0003_u32 as i32 // as if the class were unknown to this OS
    } else {
        nt(
            FILE_RENAME_INFORMATION_EX_CLASS,
            FILE_RENAME_FLAG_POSIX_SEMANTICS | FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
        )
    };
    if ex_status < 0 {
        if !rename_class_unsupported(ex_status) {
            return Err(failed("rename_nt_ex", ex_status, None));
        }
        // Once per process: every publish on such a volume would otherwise log.
        static LOGGED: std::sync::Once = std::sync::Once::new();
        LOGGED.call_once(|| {
            tracing::warn!(
                error_kind = "chat_posix_rename_unsupported",
                "POSIX-semantics rename is unsupported here; using the legacy rename class"
            );
        });
        #[cfg(test)]
        {
            LEGACY_RENAMES.with(|c| c.set(c.get() + 1));
            if let Some(hook) = BEFORE_LEGACY_RENAME.with(|c| c.borrow_mut().take()) {
                hook();
            }
        }
        // The legacy class's union is a BOOLEAN ReplaceIfExists (its low byte).
        let legacy = nt(FILE_RENAME_INFORMATION_CLASS, 1);
        if legacy < 0 {
            return Err(failed("rename_nt_legacy", legacy, Some(ex_status)));
        }
    }
    // Published. Write-through parity with the legacy flag: flush the file; a
    // failure here cannot be rolled back, so durability is unknown.
    flush_after_publish(source).map_err(|_| StoreError::DurabilityUnknown)
}

#[cfg(windows)]
fn flush_after_publish(source: &File) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_POST_RENAME_SYNC.with(|f| f.replace(false)) {
        return Err(io::Error::other("injected post-rename flush failure"));
    }
    source.sync_all()
}

pub(super) struct CappedBuffer {
    pub(super) bytes: Vec<u8>,
    pub(super) cap: u64,
    pub(super) full: bool,
}
impl Write for CappedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.cap.saturating_sub(self.bytes.len() as u64) {
            self.full = true;
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// The owner-only DACL primitive lives in `platform::fs_windows_acl` (shared
// with `platform::fs::write_new_private*`); these wrappers only map its error
// into `StoreError`, preserving the store's pre-move error vocabulary.
#[cfg(windows)]
fn acl_error(
    stage: &'static str,
    error: crate::platform::fs_windows_acl::PrivateAclError,
) -> StoreError {
    use crate::platform::fs_windows_acl::PrivateAclError;
    match error {
        PrivateAclError::Os(e) => io_error_at(stage, e),
        PrivateAclError::Descriptor => StoreError::io(stage),
        PrivateAclError::UnsafePath | PrivateAclError::InheritedLabel => StoreError::UnsafePath,
    }
}
#[cfg(windows)]
pub(super) fn create_private_directory(path: &Path) -> Result<(), StoreError> {
    crate::platform::fs_windows_acl::create_private_directory(path)
        .map_err(|e| acl_error("create_dir", e))
}
#[cfg(windows)]
pub(super) fn open_private_file(
    path: &Path,
    create: bool,
    exclusive: bool,
) -> Result<File, StoreError> {
    crate::platform::fs_windows_acl::open_private_file(path, create, exclusive)
        .map_err(|e| acl_error("open_private", e))
}
/// Private directory open with the pre-label upgrade; a failed open keeps the
/// store's historical `UnsafePath` (same as `open_directory`).
#[cfg(windows)]
pub(super) fn open_private_directory(path: &Path) -> Result<File, StoreError> {
    use crate::platform::fs_windows_acl::{open_private_directory, PrivateAclError};
    open_private_directory(path).map_err(|e| match e {
        PrivateAclError::Os(_) => StoreError::UnsafePath,
        other => acl_error("open_private_dir", other),
    })
}
/// Read-only open of an operator-owned file with the pre-label upgrade (the pool
/// `.env`): a missing label is stamped, a wrong owner, DACL or label is refused.
#[cfg(windows)]
pub(super) fn open_private_readable(path: &Path) -> Result<File, StoreError> {
    crate::platform::fs_windows_acl::open_private_readable(path)
        .map_err(|e| acl_error("open_private_readable", e))
}
#[cfg(windows)]
pub(super) fn check_private_handle(file: &File) -> Result<(), StoreError> {
    crate::platform::fs_windows_acl::check_private_handle(file)
        .map_err(|e| acl_error("check_acl", e))
}

#[cfg(all(test, windows))]
#[path = "chat_sessions_windows_acl_tests.rs"]
mod windows_acl_tests;

#[cfg(test)]
mod identity_tests {
    use super::{file_id_unsupported, Node};
    // The 128-bit identity is replaced by the 64-bit-index fallback only for the
    // three "unsupported" codes (1, 50, 87); any other failure stays an error.
    #[test]
    fn only_the_unsupported_codes_select_the_fallback_identity() {
        for code in [1, 50, 87] {
            assert!(file_id_unsupported(Some(code)), "{code}");
        }
        for code in [Some(5), Some(6), Some(0), None] {
            assert!(!file_id_unsupported(code), "{code:?}");
        }
    }
    // Identities from different sources are never equal even with equal numbers,
    // so a comparison that mixed sources fails closed.
    #[test]
    fn identities_from_different_sources_never_compare_equal() {
        assert!(Node(1, 2, true) == Node(1, 2, true));
        assert!(Node(1, 2, true) != Node(1, 2, false));
    }
}
