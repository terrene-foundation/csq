//! Windows cooperative admission and per-installer retained-process lease.
//! The release receipt means only that the installer attested commit/rollback
//! closure and the lease was released. It is not a launch or ownership ACK.
use super::S2Backend;
#[cfg(test)]
use crate::platform::fs_windows_acl::create_private_directory;
use crate::{
    platform::fs_windows_acl::{
        check_private_handle, object_owned_by_current_user, OwnerOnlyObjectSecurity,
    },
    update::upgrade_guard::{
        self,
        windows::{VerifiedProcess, WindowsBackend},
        Backend, Candidate, Inspected, QuitChannel,
    },
};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    marker::PhantomData,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};
use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        NtCreateFile, NtQueryInformationFile, NtSetInformationFile, FILE_CREATE,
        FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION, FILE_LINKS_INFORMATION,
        FILE_LINK_ENTRY_INFORMATION, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
        FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
    },
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, DuplicateHandle, GetLastError, LocalFree, RtlNtStatusToDosError,
        ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME, ERROR_PIPE_CONNECTED,
        FILETIME, HANDLE, INVALID_HANDLE_VALUE, UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Globalization::{CompareStringOrdinal, CSTR_EQUAL},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        GetSecurityDescriptorControl, GetSecurityDescriptorLength, GetTokenInformation, IsValidSid,
        TokenElevation, TokenSessionId, TokenUser, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, FileIdInfo, FlushFileBuffers, GetFileInformationByHandle,
        GetFileInformationByHandleEx, GetVolumeInformationByHandleW, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, CreatePipe, DisconnectNamedPipe,
            GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, PeekNamedPipe,
            PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            CreateEventW, CreateMutexW, GetCurrentProcess, GetCurrentProcessId, GetProcessId,
            GetProcessTimes, OpenEventW, OpenMutexW, OpenProcess, OpenProcessToken,
            QueryFullProcessImageNameW, ReleaseMutex, WaitForSingleObject, PROCESS_DUP_HANDLE,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
        IO::IO_STATUS_BLOCK,
    },
};
const READ_CONTROL: u32 = 0x0002_0000;
const MAX_FRAME: usize = 16384;
const CONTROL_WAIT: Duration = Duration::from_secs(15);
const FILE_TRAVERSE: u32 = 0x20;
const FILE_READ_ATTRIBUTES_ACCESS: u32 = 0x0000_0080;
// FILE_ADD_FILE is a write-class right requested by the innermost pin; it
// participates in sharing checks even though child lookup is handle-relative.
const FILE_ADD_FILE_ACCESS: u32 = 0x0000_0002;
const FILE_DELETE_ACCESS: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
#[cfg(test)]
type NamespaceChildHook = (&'static str, Box<dyn FnOnce()>);
#[cfg(test)]
std::thread_local! {
    /// Test seam: runs after a published secret is closed and before the
    /// bounded reopen, so a test can delete the final on every wake.
    static AFTER_PUBLISH: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        std::cell::RefCell::new(None);
    static BEFORE_NAMESPACE_CHILD: std::cell::RefCell<Option<NamespaceChildHook>> =
        std::cell::RefCell::new(None);
    static LAST_NAMESPACE_CHILD_ERROR: std::cell::Cell<Option<u32>> =
        const { std::cell::Cell::new(None) };
}
const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
fn pipe_client_security_flags() -> u32 {
    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
}

fn holder_ready_budget() -> Result<Duration> {
    // The policy may observe one daemon and then one desktop, each with its
    // complete role budget; control/setup/receipt handling gets CONTROL_WAIT.
    upgrade_guard::shutdown_observer_budget()?
        .checked_mul(2)
        .and_then(|budget| budget.checked_add(CONTROL_WAIT))
        .context("control_unavailable")
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: owns one non-pseudo handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn wide(s: &OsStr) -> Result<Vec<u16>> {
    let v: Vec<_> = s.encode_wide().collect();
    if v.contains(&0) {
        bail!("invalid_request");
    }
    Ok(v.into_iter().chain(Some(0)).collect())
}
fn text_wide(s: &str) -> Result<Vec<u16>> {
    wide(OsStr::new(s))
}
fn birth(h: HANDLE) -> Result<u64> {
    let (mut b, mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { std::mem::zeroed() }; // SAFETY: zeroed C outputs.
                                       // SAFETY: retained query process handle; initialized outputs.
    if unsafe { GetProcessTimes(h, &mut b, &mut e, &mut k, &mut u) } == 0 {
        bail!("identity_unavailable");
    }
    let value = (u64::from(b.dwHighDateTime) << 32) | u64::from(b.dwLowDateTime);
    if value == 0 {
        bail!("identity_unavailable");
    }
    Ok(value)
}
fn sid(h: HANDLE) -> Result<String> {
    let mut raw = 0;
    // SAFETY: retained query process and valid token output.
    if unsafe { OpenProcessToken(h, TOKEN_QUERY, &mut raw) } == 0 {
        bail!("identity_unavailable");
    }
    let token = Handle(raw);
    let mut size = 0;
    // SAFETY: documented zero-size query.
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut size);
    }
    if !(std::mem::size_of::<TOKEN_USER>() as u32..=65536).contains(&size) {
        bail!("identity_unavailable");
    }
    let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    let capacity = size;
    // SAFETY: aligned buffer contains capacity bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            data.as_mut_ptr().cast(),
            capacity,
            &mut size,
        )
    } == 0
        || size > capacity
    {
        bail!("identity_unavailable");
    }
    // SAFETY: successful TOKEN_USER output has the header capacity checked above.
    let p = unsafe { (*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let start = data.as_ptr() as usize;
    let end = start
        .checked_add(size as usize)
        .context("identity_unavailable")?;
    let at = p as usize;
    if at < start || at.checked_add(8).is_none_or(|v| v > end) {
        bail!("identity_unavailable");
    }
    // SAFETY: the SID header has been proved in range.
    let count = unsafe { *(p.cast::<u8>().add(1)) } as usize;
    if count > 15 || at.checked_add(8 + 4 * count).is_none_or(|v| v > end) {
        bail!("identity_unavailable");
    }
    // SAFETY: whole SID lies in the retained buffer.
    if unsafe { IsValidSid(p) } == 0 {
        bail!("identity_unavailable");
    }
    let mut out = std::ptr::null_mut();
    // SAFETY: validated live SID; output receives LocalAlloc memory.
    if unsafe { ConvertSidToStringSidW(p, &mut out) } == 0 {
        bail!("identity_unavailable");
    }
    let mut len = 0;
    // SAFETY: successful API result is NUL-terminated, bounded to a SID's limit.
    unsafe {
        while len < 256 && *out.add(len) != 0 {
            len += 1;
        }
    }
    let result = if len == 256 {
        Err(anyhow::anyhow!("identity_unavailable"))
    } else {
        // SAFETY: measured string range remains allocated.
        String::from_utf16(unsafe { std::slice::from_raw_parts(out, len) })
            .context("identity_unavailable")
    };
    // SAFETY: sole LocalAlloc result, after its final read.
    unsafe {
        LocalFree(out.cast());
    }
    result
}
fn current_sid() -> Result<String> {
    // SAFETY: borrowed pseudo-handle never closed.
    sid(unsafe { GetCurrentProcess() })
}
fn process(pid: u32) -> Result<Handle> {
    process_with_rights(pid, 0)
}
fn process_with_rights(pid: u32, extra: u32) -> Result<Handle> {
    if pid == 0 {
        bail!("identity_unavailable");
    }
    // SAFETY: non-inherited handle with minimum query/wait rights.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | extra,
            0,
            pid,
        )
    };
    if raw == 0 {
        bail!("identity_unavailable");
    }
    let h = Handle(raw);
    if sid(h.0)? != current_sid()? {
        bail!("foreign_user");
    }
    Ok(h)
}
/// A snapshot PID disappearing before OpenProcess grants no retained authority.
fn census_process(pid: u32) -> Result<Option<Handle>> {
    if pid == 0 {
        return Ok(None);
    }
    // SAFETY: fresh noninherited query/synchronize handle; 87 is captured immediately.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw == 0 {
        if unsafe { GetLastError() } == 87 {
            return Ok(None);
        }
        bail!("identity_unavailable");
    }
    let retained = Handle(raw);
    // A terminated handle is absence even if its token can no longer be queried.
    if !alive(retained.0)? {
        return Ok(None);
    }
    if sid(retained.0)? != current_sid()? {
        bail!("foreign_user");
    }
    Ok(Some(retained))
}
fn alive(h: HANDLE) -> Result<bool> {
    // SAFETY: retained synchronize handle.
    match unsafe { WaitForSingleObject(h, 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        _ => bail!("identity_unavailable"),
    }
}
fn image(h: HANDLE) -> Result<PathBuf> {
    let mut v = vec![0u16; 32768];
    let mut n = v.len() as u32;
    // SAFETY: query handle and output length/capacity agree.
    if unsafe { QueryFullProcessImageNameW(h, 0, v.as_mut_ptr(), &mut n) } == 0
        || n == 0
        || n as usize >= v.len()
    {
        bail!("identity_unavailable");
    }
    PathBuf::from(OsString::from_wide(&v[..n as usize]))
        .canonicalize()
        .context("identity_unavailable")
}
fn parent(pid: u32) -> Result<u32> {
    // SAFETY: bounded snapshot enumeration, not stop authority.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        bail!("identity_unavailable");
    }
    let snap = Handle(raw);
    // SAFETY: initialized C output with required size.
    let mut row: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    row.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: valid snapshot/output.
    let mut ok = unsafe { Process32FirstW(snap.0, &mut row) };
    while ok != 0 {
        if row.th32ProcessID == pid {
            return Ok(row.th32ParentProcessID);
        } // SAFETY: retained snapshot/output.
        ok = unsafe { Process32NextW(snap.0, &mut row) };
    }
    bail!("identity_unavailable")
}
fn same_path(a: &Path, b: &Path) -> bool {
    let a: Vec<u16> = a.as_os_str().encode_wide().collect();
    let b: Vec<u16> = b.as_os_str().encode_wide().collect();
    if a.len() > 32768 || b.len() > 32768 {
        return false;
    }
    // SAFETY: bounded, initialized UTF-16 slices stay live; comparison error is false.
    unsafe {
        CompareStringOrdinal(a.as_ptr(), a.len() as i32, b.as_ptr(), b.len() as i32, 1)
            == CSTR_EQUAL
    }
}
// Final secret is published once per token-native profile and never rotated or
// deleted. Interrupted private temps never occupy its stable published name.
const SECRET_FILE: &str = "namespace.secret";
const SECRET_BYTES: usize = 16;
#[link(name = "userenv")]
unsafe extern "system" {
    fn GetUserProfileDirectoryW(token: HANDLE, path: *mut u16, size: *mut u32) -> i32;
}
fn profile_directory() -> Result<PathBuf> {
    let mut token = 0;
    // SAFETY: borrowed process handle and initialized token output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        bail!("namespace_profile_unavailable");
    }
    let token = Handle(token);
    let mut size = 0;
    // SAFETY: documented size query; the token remains live.
    unsafe { GetUserProfileDirectoryW(token.0, std::ptr::null_mut(), &mut size) };
    if !(2..=32768).contains(&size) {
        bail!("namespace_profile_unavailable");
    }
    let mut path = vec![0u16; size as usize];
    // SAFETY: capacity equals the supplied UTF-16 count.
    if unsafe { GetUserProfileDirectoryW(token.0, path.as_mut_ptr(), &mut size) } == 0
        || size < 2
        || size as usize > path.len()
        || path[size as usize - 1] != 0
        || path[..size as usize - 1].contains(&0)
    {
        bail!("namespace_profile_unavailable");
    }
    let path = PathBuf::from(OsString::from_wide(&path[..size as usize - 1]));
    if !path.is_absolute() {
        bail!("namespace_profile_unavailable");
    }
    Ok(path)
}
fn pin_namespace_directory(path: &Path) -> Result<File> {
    pin_namespace_directory_with(path, false)
}
/// Opens the same innermost pin shape for synthetic namespace fixtures.
#[cfg(test)]
fn pin_installation_directory(path: &Path) -> Result<File> {
    pin_namespace_directory_with(path, true)
}
fn pin_namespace_directory_with(path: &Path, create_children: bool) -> Result<File> {
    // Pin only the token profile and descendants. Ancestor system directories
    // are outside this per-user custody and need not deny delete sharing.
    //
    // The pin holds FILE_TRAVERSE — the same bit as FILE_EXECUTE, a read-class
    // access that takes part in the share check — and shares READ | WRITE but
    // never DELETE. Tests measure the guarantee rather than this comment stating
    // it: pinned_directory_refuses_rename_and_remove_until_the_pin_is_dropped
    // drives a real rename and remove_dir against a held pin and asserts
    // ERROR_SHARING_VIOLATION(32), with a remove-after-drop control, and
    // control_a_read_control_only_holder_does_not_block_the_delete_probe shows
    // the probe can tell a non-participating holder from a participating one.
    //
    // Profile and .csq pins remain read-class for existing share-READ holders.
    // Only the innermost FILE_ADD_FILE pin refuses conflicting readers.
    let mut access = READ_CONTROL | FILE_TRAVERSE | FILE_READ_ATTRIBUTES_ACCESS | SYNCHRONIZE;
    if create_children {
        access |= FILE_ADD_FILE_ACCESS;
    }
    let file = std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(32) {
                anyhow::anyhow!("namespace_path_busy")
            } else {
                anyhow::anyhow!("namespace_path_unsafe")
            }
        })?;
    let meta = file.metadata().context("namespace_path_unsafe")?;
    if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("namespace_path_unsafe");
    }
    Ok(file)
}
fn namespace_secret() -> Result<[u8; SECRET_BYTES]> {
    namespace_secret_from_profile(&profile_directory()?)
}
fn create_namespace_directory_if_absent(parent: &File, leaf: &str, writable: bool) -> Result<File> {
    // Native handles need explicit attribute access for metadata and identity checks.
    let access = READ_CONTROL
        | FILE_TRAVERSE
        | FILE_READ_ATTRIBUTES_ACCESS
        | if writable { FILE_ADD_FILE_ACCESS } else { 0 };
    let open = || {
        open_relative_kind(
            parent,
            leaf,
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            std::ptr::null(),
            FILE_DIRECTORY_FILE,
        )
    };
    // Existing ancestry stays read-class even while another reader shares READ only.
    let directory = match open() {
        Ok(directory) => directory,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            match create_private_relative(
                parent,
                leaf,
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_DIRECTORY_FILE,
            ) {
                Ok(directory) => directory,
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
                {
                    open()?
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    };
    require_unreparsed_namespace_directory(parent)?;
    require_unreparsed_namespace_directory(&directory)?;
    require_namespace_child(parent, &directory, leaf)?;
    Ok(directory)
}
fn verify_namespace_parent(file: &File) -> Result<()> {
    let mut owner = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: retained directory with READ_CONTROL; outputs belong to one SD.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let result = (|| {
        if status != 0 || descriptor.is_null() || owner.is_null() || dacl.is_null() {
            bail!("namespace_parent_unsafe");
        }
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: successful GetSecurityInfo returns a live self-relative SD.
        let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
        if !(20..=131072).contains(&length)
            || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & 0x4 == 0
        {
            bail!("namespace_parent_unsafe");
        }
        let base = descriptor as usize;
        let end = base
            .checked_add(length)
            .context("namespace_parent_unsafe")?;
        let bounded = |pointer: *const u8, bytes: usize| {
            let start = pointer as usize;
            start >= base && start.checked_add(bytes).is_some_and(|v| v <= end)
        };
        let owner = owner.cast::<u8>();
        let dacl = dacl.cast::<u8>();
        if !bounded(owner, 8) || !bounded(dacl, 8) {
            bail!("namespace_parent_unsafe");
        }
        // SAFETY: both eight-byte headers proved in the live allocation.
        let owner_length = 8 + 4 * usize::from(unsafe { *owner.add(1) });
        let acl_length =
            usize::from(unsafe { std::ptr::read_unaligned(dacl.add(2).cast::<u16>()) });
        if !bounded(owner, owner_length) || !bounded(dacl, acl_length) {
            bail!("namespace_parent_unsafe");
        }
        // SAFETY: entire counted SID/ACL slices proved within retained SD.
        let safe = super::namespace_acl::parent_acl_safe(
            unsafe { std::slice::from_raw_parts(owner, owner_length) },
            &current_sid()?,
            Some(unsafe { std::slice::from_raw_parts(dacl, acl_length) }),
        );
        if !safe {
            bail!("namespace_parent_unsafe");
        }
        Ok(())
    })();
    // SAFETY: sole GetSecurityInfo allocation after all borrowed reads.
    unsafe {
        LocalFree(descriptor);
    }
    result
}
fn namespace_secret_from_profile(profile: &Path) -> Result<[u8; SECRET_BYTES]> {
    let profile_pin = pin_namespace_directory(profile)?;
    verify_namespace_parent(&profile_pin)?;
    let parent_pin = create_namespace_directory_if_absent(&profile_pin, ".csq", false)
        .context("namespace_directory_unavailable")?;
    verify_namespace_parent(&parent_pin)?;
    let directory_pin =
        create_namespace_directory_if_absent(&parent_pin, "installer-admission-v2", true)
            .context("namespace_directory_unavailable")?;
    check_private_handle(&directory_pin)
        .map_err(|_| anyhow::anyhow!("namespace_directory_unsafe"))?;
    // The secret is created, written, published and read back through THIS
    // handle, never through `directory.join(SECRET_FILE)`. If the retained
    // directory becomes a reparse point, child operations refuse distinctly.
    namespace_secret_at(&directory_pin)
}
fn verify_namespace_secret(file: &File) -> Result<()> {
    let meta = file.metadata().context("namespace_secret_unavailable")?;
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("namespace_secret_unsafe");
    }
    // This does NOT stamp or repair anything: exact owner, protected user-only
    // DACL and explicit Medium NW|NR label must already be present.
    check_private_handle(file).map_err(|_| anyhow::anyhow!("namespace_secret_acl"))?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: retained file handle and fully initialized output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        bail!("namespace_secret_unavailable");
    }
    if info.nNumberOfLinks != 1 {
        bail!("namespace_secret_unsafe");
    }
    Ok(())
}
fn read_namespace_secret(mut file: File) -> Result<[u8; SECRET_BYTES]> {
    verify_namespace_secret(&file)?;
    if file
        .metadata()
        .context("namespace_secret_unavailable")?
        .len()
        != SECRET_BYTES as u64
    {
        bail!("namespace_secret_size");
    }
    let mut secret = [0u8; SECRET_BYTES];
    file.read_exact(&mut secret)
        .context("namespace_secret_unavailable")?;
    verify_namespace_secret(&file)?;
    Ok(secret)
}
#[derive(Debug)]
struct NamespaceDirectoryReparsed;
impl std::fmt::Display for NamespaceDirectoryReparsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("namespace_directory_reparsed")
    }
}
impl std::error::Error for NamespaceDirectoryReparsed {}
#[derive(Debug, thiserror::Error)]
#[error("namespace_filesystem_unsupported")]
struct NamespaceFilesystemUnsupported;
fn require_unreparsed_namespace_directory(directory: &File) -> Result<()> {
    let meta = directory
        .metadata()
        .context("namespace_directory_unavailable")?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(NamespaceDirectoryReparsed.into());
    }
    if !meta.is_dir() {
        bail!("namespace_path_unsafe");
    }
    Ok(())
}
fn namespace_child_error(code: u32) -> anyhow::Error {
    #[cfg(test)]
    LAST_NAMESPACE_CHILD_ERROR.with(|last| last.set(Some(code)));
    // ERROR_CANT_ACCESS_FILE / ERROR_CANT_RESOLVE_FILENAME also cover native
    // reparse refusal between the retained-handle check and I/O.
    if matches!(code, 1920 | 1921) {
        NamespaceDirectoryReparsed.into()
    } else {
        std::io::Error::from_raw_os_error(code as i32).into()
    }
}
/// Opens one leaf relative to a retained directory handle.
///
/// `leaf` is one component resolved from the retained object, without a pathname
/// fallback. A directory that becomes a reparse point refuses; the pin does not
/// promise continued child access after that mutation. FILE_OPEN_REPARSE_POINT
/// opens a reparse leaf itself for subsequent rejection by the secret verifier;
/// FILE_NON_DIRECTORY_FILE keeps the open on a file.
fn open_relative(
    directory: &File,
    leaf: &str,
    access: u32,
    share: u32,
    disposition: u32,
    security: *const std::ffi::c_void,
) -> Result<File> {
    open_relative_kind(
        directory,
        leaf,
        access,
        share,
        disposition,
        security,
        FILE_NON_DIRECTORY_FILE,
    )
}
fn open_relative_kind(
    directory: &File,
    leaf: &str,
    access: u32,
    share: u32,
    disposition: u32,
    security: *const std::ffi::c_void,
    kind: u32,
) -> Result<File> {
    require_unreparsed_namespace_directory(directory)?;
    let name = leaf_name(leaf)?;
    let unicode = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: directory.as_raw_handle() as HANDLE,
        ObjectName: &unicode,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE
        SecurityDescriptor: security,
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut raw: HANDLE = INVALID_HANDLE_VALUE;
    // SAFETY: `name` and `unicode` outlive the call; `attributes` points at them
    // and at the live borrowed directory handle. `block` and `raw` are valid
    // out-parameters, `security` is null or the caller's live descriptor, and
    // the kernel reads the object attributes synchronously without retaining a
    // pointer.
    #[cfg(test)]
    BEFORE_NAMESPACE_CHILD.with(|hook| {
        let pending = if hook
            .borrow()
            .as_ref()
            .is_some_and(|(name, _)| *name == leaf)
        {
            hook.borrow_mut().take()
        } else {
            None
        };
        if let Some((_, hook)) = pending {
            hook();
        }
    });
    let status = unsafe {
        NtCreateFile(
            &mut raw,
            // FILE_SYNCHRONOUS_IO_NONALERT requires the explicit SYNCHRONIZE
            // right at this native call, even when access has generic bits.
            access | SYNCHRONIZE,
            &attributes,
            &mut block,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            FILE_OPEN_REPARSE_POINT | kind | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: pure NTSTATUS-to-Win32 translation, no pointers.
        let code = unsafe { RtlNtStatusToDosError(status) };
        if kind == FILE_DIRECTORY_FILE && code == 32 {
            bail!("namespace_path_busy");
        }
        return Err(namespace_child_error(code));
    }
    // SAFETY: successful NtCreateFile transfers sole ownership of the handle.
    Ok(unsafe { File::from_raw_handle(raw as *mut std::ffi::c_void) })
}

/// Validates a single-component leaf and returns its UTF-16 form.
fn leaf_name(leaf: &str) -> std::io::Result<Vec<u16>> {
    if leaf.is_empty()
        || leaf == "."
        || leaf == ".."
        || leaf.chars().any(|c| matches!(c, '\\' | '/' | ':' | '\0'))
    {
        return Err(std::io::Error::from_raw_os_error(ERROR_INVALID_NAME as i32));
    }
    Ok(leaf.encode_utf16().collect())
}

/// Removes a file through a handle the caller already owns, so the removal is
/// relative to the pinned directory rather than resolved through a path.
fn remove_open_file(file: &File) -> std::io::Result<()> {
    // ntifs.h FILE_INFORMATION_CLASS: FileDispositionInformation = 13.
    const FILE_DISPOSITION_INFORMATION_CLASS: i32 = 13;
    let mut info = FILE_DISPOSITION_INFORMATION { DeleteFile: 1 };
    let mut block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: the caller's live handle; `info` and `block` are valid for the
    // synchronous call, which retains no pointer.
    let status = unsafe {
        NtSetInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut block,
            std::ptr::from_mut(&mut info).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FILE_DISPOSITION_INFORMATION_CLASS,
        )
    };
    if status < 0 {
        // SAFETY: pure status translation.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(std::io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

fn create_namespace_secret(directory: &File, leaf: &str) -> Result<File> {
    create_private_relative(
        directory,
        leaf,
        READ_CONTROL | 0xC000_0000 | FILE_DELETE_ACCESS,
        0,
        FILE_NON_DIRECTORY_FILE,
    )
}
fn create_private_relative(
    directory: &File,
    leaf: &str,
    access: u32,
    share: u32,
    kind: u32,
) -> Result<File> {
    let descriptor_text = text_wide(&format!(
        "O:{0}D:P(A;;FA;;;{0})S:(ML;;NWNR;;;ME)",
        current_sid()?
    ))?;
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: valid NUL-terminated SDDL; output is LocalAlloc-owned.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        bail!("namespace_secret_acl");
    }
    // FILE_CREATE never reuses an existing entry. Secret temps request zero
    // sharing and DELETE for publication or cleanup through their owned handle.
    let result = open_relative_kind(
        directory,
        leaf,
        access,
        share,
        FILE_CREATE,
        descriptor.cast(),
        kind,
    );
    // SAFETY: sole descriptor allocation, after synchronous NtCreateFile.
    unsafe {
        LocalFree(descriptor);
    }
    result
}
fn namespace_ntfs_identity(file: &File) -> Result<FILE_ID_INFO> {
    let mut filesystem = [0u16; 16];
    // SAFETY: retained handle and bounded UTF-16 output; unused outputs are null.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle() as HANDLE,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        bail!("namespace_secret_unavailable");
    }
    if filesystem[..5] != [78, 84, 70, 83, 0] {
        return Err(NamespaceFilesystemUnsupported.into());
    }
    let mut identity: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: initialized identity output is exactly the declared byte capacity.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            std::ptr::from_mut(&mut identity).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        bail!("namespace_secret_unavailable");
    }
    if identity.FileId.Identifier == [0; 16] || identity.FileId.Identifier == [u8::MAX; 16] {
        bail!("namespace_secret_unsafe");
    }
    Ok(identity)
}
/// Verify an entry's actual parent from its kernel hard-link record, never
/// from a pathname that could be redirected or replaced after capture.
fn require_namespace_child(directory: &File, file: &File, leaf: &str) -> Result<()> {
    require_unreparsed_namespace_directory(directory)?;
    let parent = namespace_ntfs_identity(directory)?;
    let child = namespace_ntfs_identity(file)?;
    let mut legacy: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: retained handle and initialized output; used only for link count.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut legacy) } == 0 {
        bail!("namespace_secret_unavailable");
    }
    let mut buffer = [0u64; 128];
    let capacity = std::mem::size_of_val(&buffer);
    let mut block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: aligned, writable buffer of the supplied byte capacity, live file
    // handle and initialized status output. FileHardLinkInformation = 46.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut block,
            buffer.as_mut_ptr().cast(),
            capacity as u32,
            46,
        )
    };
    let length = block.Information;
    if status < 0 || length < std::mem::size_of::<FILE_LINKS_INFORMATION>() || length > capacity {
        bail!("namespace_secret_unavailable");
    }
    // SAFETY: successful query and validated size/alignment cover the fixed
    // record. The flexible filename is bounded separately before being read.
    let links = unsafe { &*buffer.as_ptr().cast::<FILE_LINKS_INFORMATION>() };
    let name = leaf_name(leaf)?;
    let name_offset = std::mem::offset_of!(FILE_LINKS_INFORMATION, Entry)
        + std::mem::offset_of!(FILE_LINK_ENTRY_INFORMATION, FileName);
    let name_end = name_offset + name.len() * 2;
    if links.EntriesReturned != 1
        || links.BytesNeeded as usize > length
        || links.Entry.NextEntryOffset != 0
        || links.Entry.FileNameLength as usize != name.len()
        || name_end > length
        || matches!(links.Entry.ParentFileId as u64, 0 | u64::MAX)
    {
        bail!("namespace_secret_unsafe");
    }
    // SAFETY: name_end above bounds this initialized UTF-16 tail in the buffer.
    let actual_name = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(name_offset).cast::<u16>(),
            name.len(),
        )
    };
    let mut expected_parent = [0u8; 16];
    expected_parent[..8].copy_from_slice(&(links.Entry.ParentFileId as u64).to_le_bytes());
    if legacy.nNumberOfLinks != 1
        || child.VolumeSerialNumber != parent.VolumeSerialNumber
        || parent.FileId.Identifier != expected_parent
        || actual_name != name
    {
        return Err(NamespaceDirectoryReparsed.into());
    }
    require_unreparsed_namespace_directory(directory)
}
/// Creates a private temp inside the pinned directory and returns its leaf and
/// its still-open handle. The handle stays open so publication renames through
/// it; a caller that never publishes must drop it (a failed one is removed via
/// remove_open_file before returning).
fn prepare_namespace_secret(directory: &File) -> Result<(String, File)> {
    for _ in 0..8 {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| anyhow::anyhow!("namespace_random_unavailable"))?;
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let leaf = format!(".namespace-secret-{suffix}.tmp");
        let mut file = match create_namespace_secret(directory, &leaf) {
            Ok(file) => file,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                continue
            }
            Err(error) if error.is::<NamespaceDirectoryReparsed>() => return Err(error),
            Err(_) => bail!("namespace_secret_create"),
        };
        let result = (|| {
            require_namespace_child(directory, &file, &leaf)?;
            verify_namespace_secret(&file)?;
            let mut secret = [0u8; SECRET_BYTES];
            getrandom::getrandom(&mut secret)
                .map_err(|_| anyhow::anyhow!("namespace_random_unavailable"))?;
            file.write_all(&secret).context("namespace_secret_write")?;
            // SAFETY: uniquely owned writable FILE_CREATE temp handle. The final
            // name stays absent until this flush succeeds and the temp is
            // published; a crash leaves only this private temp.
            if unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) } == 0 {
                bail!("namespace_secret_write");
            }
            verify_namespace_secret(&file)?;
            Ok(())
        })();
        if let Err(error) = result {
            // This invocation owns only its FILE_CREATE temp, never an existing
            // final or another writer's temp. The removal goes through the same
            // handle, so it cannot follow anything on the directory's path.
            let cleanup = remove_open_file(&file);
            drop(file);
            if cleanup.is_err() {
                return Err(error.context("namespace_secret_cleanup"));
            }
            return Err(error);
        }
        return Ok((leaf, file));
    }
    bail!("namespace_secret_create")
}
fn publish_namespace_secret(directory: &File, temporary: &File) -> Result<bool> {
    publish_namespace_secret_using(temporary, |leaf| {
        rename_namespace_secret(directory, temporary, leaf)
    })
}
/// Renames the open temp to `leaf` INSIDE the pinned directory. The source is
/// the caller's open handle (opened with DELETE) and the destination is a
/// single leaf under RootDirectory, so neither side is resolved through a path.
fn rename_namespace_secret(directory: &File, source: &File, leaf: &str) -> Result<()> {
    require_unreparsed_namespace_directory(directory)?;
    // ntifs.h FILE_INFORMATION_CLASS: FileRenameInformation = 10. Its
    // FILE_RENAME_INFORMATION union carries ReplaceIfExists (BOOLEAN), which is
    // 0 here: an existing final is never replaced.
    const FILE_RENAME_INFORMATION_CLASS: i32 = 10;
    let name = leaf_name(leaf)?;
    let name_bytes = name.len() * 2;
    let total = std::mem::size_of::<FILE_RENAME_INFORMATION>() + name_bytes;
    let mut buffer = vec![0u64; total.div_ceil(8)];
    let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    // SAFETY: the zeroed buffer is >= size_of::<FILE_RENAME_INFORMATION>() +
    // name_bytes and 8-aligned; the leaf is copied within its bounds (FileName
    // is the trailing flexible array) and RootDirectory is the live borrowed
    // directory handle. Only this function reads or writes the buffer.
    unsafe {
        (*rename).Anonymous.ReplaceIfExists = 0;
        (*rename).RootDirectory = directory.as_raw_handle() as HANDLE;
        (*rename).FileNameLength = name_bytes as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*rename).FileName).cast::<u16>(),
            name.len(),
        );
    }
    let mut block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    // SAFETY: `source` is a live handle opened with DELETE; the buffer is the
    // initialised structure above of exactly `total` bytes; `block` is a valid
    // out-parameter. The call is synchronous and retains no pointer.
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut block,
            rename.cast(),
            total as u32,
            FILE_RENAME_INFORMATION_CLASS,
        )
    };
    if status < 0 {
        // SAFETY: pure status translation.
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(namespace_child_error(code));
    }
    Ok(())
}
fn publish_namespace_secret_using(
    temporary: &File,
    mut attempt: impl FnMut(&str) -> Result<()>,
) -> Result<bool> {
    let publication = (|| {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            // The temp's randomized leaf is never a publication destination.
            let error = match attempt(SECRET_FILE) {
                Ok(()) => return Ok(true),
                Err(error) => error,
            };
            if error.is::<NamespaceDirectoryReparsed>() {
                return Err(error);
            }
            let io = error.downcast_ref::<std::io::Error>();
            if io.is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) {
                return Ok(false);
            }
            if !io.is_some_and(|e| e.raw_os_error() == Some(32)) {
                bail!("namespace_secret_publish");
            }
            if Instant::now() >= until {
                bail!("namespace_secret_busy");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    if !matches!(publication, Ok(true)) {
        // The loser or the failed publisher owns only its own FILE_CREATE temp;
        // removal goes through that handle, never through a path.
        let cleanup = remove_open_file(temporary);
        if cleanup.is_err() {
            return match publication {
                Err(error) => Err(error.context("namespace_secret_cleanup")),
                Ok(_) => Err(anyhow::anyhow!("namespace_secret_cleanup")),
            };
        }
    }
    publication
}
fn namespace_secret_at(directory: &File) -> Result<[u8; SECRET_BYTES]> {
    namespace_secret_until(directory, Instant::now() + Duration::from_secs(2))
}
fn namespace_secret_until(directory: &File, until: Instant) -> Result<[u8; SECRET_BYTES]> {
    // Whether this call has already created a secret. A same-user process that
    // deletes the final on every wake must not spin this loop forever: after the
    // first publication the deadline applies to the reopen too. The one
    // exception is the FIRST publish finishing past the deadline — reopening the
    // winner once there is how a slow publish is told apart from a busy secret.
    let mut created = false;
    loop {
        let open = open_relative(
            directory,
            SECRET_FILE,
            READ_CONTROL | 0x8000_0000,
            FILE_SHARE_READ,
            FILE_OPEN,
            std::ptr::null(),
        );
        match open {
            Ok(file) => return read_namespace_secret(file),
            Err(error) if error.is::<NamespaceDirectoryReparsed>() => return Err(error),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                if created && Instant::now() >= until {
                    bail!("namespace_secret_busy");
                }
                let (_, temporary) = prepare_namespace_secret(directory)?;
                publish_namespace_secret(directory, &temporary)?;
                drop(temporary);
                created = true;
                #[cfg(test)]
                AFTER_PUBLISH.with(|hook| {
                    if let Some(hook) = hook.borrow_mut().as_mut() {
                        hook();
                    }
                });
                continue;
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.raw_os_error() == Some(32)) =>
            {
                if Instant::now() >= until {
                    bail!("namespace_secret_busy");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => bail!("namespace_secret_unavailable"),
        }
        if Instant::now() >= until {
            bail!("namespace_secret_busy");
        }
    }
}
fn namespace_tag(secret: &[u8; SECRET_BYTES], kind: &str, sid: &str) -> Result<String> {
    if !matches!(kind, "lease" | "capability" | "pipe") {
        bail!("invalid_request");
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| anyhow::anyhow!("namespace_crypto_unavailable"))?;
    mac.update(format!("csq-v2|{kind}|{sid}").as_bytes());
    let bytes = mac.finalize().into_bytes();
    Ok(bytes[..16].iter().map(|b| format!("{b:02x}")).collect())
}
fn namespace_component(kind: &str) -> Result<String> {
    let secret = namespace_secret()?;
    Ok(format!(
        "csq-installer-{kind}-v2-{}",
        namespace_tag(&secret, kind, &current_sid()?)?
    ))
}
fn kernel_name(kind: &str) -> Result<Vec<u16>> {
    text_wide(&format!("Local\\{}", namespace_component(kind)?))
}
fn capability_name(pid: u32, b: u64) -> Result<Vec<u16>> {
    text_wide(&format!(
        "Local\\{}-{pid}-{b:016x}",
        namespace_component("capability")?
    ))
}
fn pipe_name() -> Result<Vec<u16>> {
    // NPFS pipe names are enumerable. Expose a keyed, domain-separated digest,
    // NEVER the reusable secret or a digest reusable as another object's key.
    text_wide(&format!(r"\\.\pipe\{}", namespace_component("pipe")?))
}
fn lease_object_name() -> Result<String> {
    let mut token = 0;
    // SAFETY: borrowed process handle and valid initialized output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        bail!("identity_unavailable");
    }
    let token = Handle(token);
    let mut session = 0u32;
    let mut bytes = 0u32;
    // SAFETY: TokenSessionId returns exactly one DWORD into the live output.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenSessionId,
            (&mut session as *mut u32).cast(),
            4,
            &mut bytes,
        )
    } == 0
        || bytes != 4
    {
        bail!("identity_unavailable");
    }
    if session == 0 {
        bail!("identity_unavailable");
    }
    let prefix = format!(r"\Sessions\{session}\BaseNamedObjects");
    let frame = format!(
        "CSQ_INSTALL_V1 LEASE_OBJECT_NAME {prefix}\\{}",
        namespace_component("lease")?
    );
    if frame.len() + 2 > 512 {
        bail!("identity_unavailable");
    }
    Ok(frame)
}

/// Any extant lease object fences startup, even after helper crash abandons
/// mutex ownership. The installer retains its own noninheritable reference
/// until checked commit/release or process exit. Unreadable owner always refuses.
pub fn check() -> Result<()> {
    // SAFETY: bounded NUL-terminated name; read-only, noninherited handle.
    let raw = unsafe { OpenMutexW(READ_CONTROL, 0, kernel_name("lease")?.as_ptr()) };
    if raw == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            return Ok(());
        }
        bail!("control_unavailable");
    }
    let h = Handle(raw);
    if !object_owned_by_current_user(h.0)? {
        bail!("foreign_user");
    }
    // Never wait/acquire/release here: an unlocked or abandoned but referenced
    // kernel object still belongs to an install transaction whose copy may run.
    bail!("lease_busy")
}
/// Lifetime proof that this process executed the S2 common admission gate.
/// It is distinct from S1's bound quit endpoint and grants no stop authority alone.
pub struct Registration {
    _event: Handle,
}
pub fn enter_process() -> Result<Registration> {
    check()?;
    // SAFETY: process pseudo handle/ID are borrowed identity queries.
    let name = capability_name(
        unsafe { GetCurrentProcessId() },
        birth(unsafe { GetCurrentProcess() })?,
    )?;
    let security = OwnerOnlyObjectSecurity::current_user()?;
    let attrs = security.attributes();
    // SAFETY: descriptor and NUL terminated name remain live; no inheritance.
    let raw = unsafe { CreateEventW(&attrs, 1, 0, name.as_ptr()) };
    if raw == 0 {
        bail!("identity_unavailable");
    }
    // SAFETY: capture immediately after CreateEventW.
    let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let event = Handle(raw);
    if existed {
        bail!("identity_unavailable");
    }
    Ok(Registration { _event: event })
}
fn capable(pid: u32, b: u64) -> Result<bool> {
    let process = process(pid)?;
    if birth(process.0)? != b || !alive(process.0)? {
        bail!("identity_unavailable");
    }
    // SAFETY: read-only capability probe with owner verification; never signals.
    let raw = unsafe { OpenEventW(READ_CONTROL, 0, capability_name(pid, b)?.as_ptr()) };
    if raw == 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            return Ok(false);
        }
        bail!("identity_unavailable");
    }
    let event = Handle(raw);
    Ok(object_owned_by_current_user(event.0)?)
}
struct Lease {
    handle: Handle,
    held: bool,
    _thread: PhantomData<Rc<()>>,
}
impl Lease {
    fn acquire() -> Result<Self> {
        let security = OwnerOnlyObjectSecurity::current_user()?;
        let attrs = security.attributes();
        // SAFETY: descriptor/name live; a newly created mutex is owned on this
        // thread. Existing objects are NEVER reused, whatever their wait state.
        let raw = unsafe { CreateMutexW(&attrs, 1, kernel_name("lease")?.as_ptr()) };
        if raw == 0 {
            bail!("control_unavailable");
        }
        // SAFETY: immediate last-error capture before another Win32 call.
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let handle = Handle(raw);
        if !object_owned_by_current_user(handle.0)? {
            bail!("foreign_user");
        }
        if existed {
            bail!("lease_busy");
        }
        Ok(Self {
            handle,
            held: true,
            _thread: PhantomData,
        })
    }
    fn duplicate_to_installer(&self, installer: HANDLE) -> Result<u32> {
        if !self.held || !alive(installer)? {
            bail!("installer_exited");
        }
        let mut remote = 0;
        // SAFETY: source is this thread's retained lease. Target is the retained
        // same-SID/birth-verified installer handle with PROCESS_DUP_HANDLE. The
        // new reference has READ_CONTROL only and bInheritHandle=FALSE. It is
        // owned by the installer, not by a local Handle destructor.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.handle.0,
                installer,
                &mut remote,
                READ_CONTROL,
                0,
                0,
            )
        } == 0
        {
            bail!("control_unavailable");
        }
        let token =
            u32::try_from(remote as usize).map_err(|_| anyhow::anyhow!("identity_unavailable"))?;
        if token == 0 || token == u32::MAX {
            bail!("identity_unavailable");
        }
        // Before READY failure authorizes no copy; even an unreported reference
        // is automatically closed by the installer's mandatory failure exit.
        Ok(token)
    }
    fn release(&mut self) -> Result<()> {
        if !self.held {
            bail!("transaction_unproven");
        }
        // SAFETY: !Send guard stays on the thread that acquired this mutex.
        if unsafe { ReleaseMutex(self.handle.0) } == 0 {
            bail!("control_unavailable");
        }
        self.held = false;
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if self.held {
            // SAFETY: !Send guard stays on its owning thread.
            unsafe {
                ReleaseMutex(self.handle.0);
            }
        }
    }
}

/// Takes over NSIS's pinned GUID executable/ancestry custody on entry. NSIS
/// retains its pins until controller exit, or installer exit after timeout. The
/// controller then proves the retained installer is still alive before spawn.
/// Therefore a late-scheduled controller cannot reopen changed bytes and spawn
/// after the installer has already released its own pins.
fn pin_executable() -> Result<Vec<File>> {
    let executable = std::env::current_exe()?;
    if !executable
        .as_os_str()
        .to_string_lossy()
        .starts_with(r"\\?\Volume{")
    {
        bail!("unsafe_path");
    }
    pin_ancestry(&executable)
}
/// Pins an executable and every ancestor directory: the file denies all
/// sharing, each directory denies delete sharing. Split out of pin_executable
/// so the rename/delete guarantee is measurable on a disposable tree.
fn pin_ancestry(executable: &Path) -> Result<Vec<File>> {
    let mut pins = Vec::new();
    for (index, path) in executable.ancestors().enumerate() {
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if index > 0 {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        let access = READ_CONTROL
            | if index == 0 {
                0x8000_0000
            } else {
                FILE_TRAVERSE | SYNCHRONIZE
            };
        // Directories allow sibling writes but cannot be renamed/deleted while
        // retained: each holds FILE_TRAVERSE (the same bit as FILE_EXECUTE, a
        // read-class access that takes part in the share check) and shares
        // READ | WRITE, never DELETE. The file pin additionally denies all
        // sharing. pinned_executable_ancestor_refuses_a_delete_open_until_the_pins_drop
        // measures the directory claim by opening the ancestor with DELETE
        // access while the pins are held.
        let share = FILE_SHARE_READ | if index > 0 { FILE_SHARE_WRITE } else { 0 };
        let file = std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(share)
            .custom_flags(flags)
            .open(path)
            .context("unsafe_path")?;
        let metadata = file.metadata().context("unsafe_path")?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (index == 0 && !metadata.is_file())
            || (index > 0 && !metadata.is_dir())
        {
            bail!("unsafe_path");
        }
        if index < 2 && !file_owned(&file)? {
            bail!("foreign_user");
        }
        pins.push(file);
    }
    if pins.len() < 3 {
        bail!("unsafe_path");
    }
    Ok(pins)
}

/// Existing or future root, anchored to a retained user-owned existing ancestor.
/// Existing components reject reparse. Ancestors deny delete sharing; the
/// target directory itself permits deletion so standalone uninstall can remove
/// it. Every destructive phase revalidates the root; this is not an OS fence.
struct Root {
    path: PathBuf,
    _anchors: Vec<File>,
}
fn file_owned(file: &File) -> Result<bool> {
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: live file handle READ_CONTROL; outputs owned until LocalFree.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    let result = (|| {
        if status != 0 || owner.is_null() {
            bail!("identity_unavailable");
        } // SAFETY: API returned SID in live descriptor.
        if unsafe { IsValidSid(owner) } == 0 {
            bail!("identity_unavailable");
        }
        let mut text = std::ptr::null_mut(); // SAFETY: valid owner SID, output allocated by API.
        if unsafe { ConvertSidToStringSidW(owner, &mut text) } == 0 {
            bail!("identity_unavailable");
        }
        let mut n = 0; // SAFETY: bounded NUL-terminated API result.
        unsafe {
            while n < 256 && *text.add(n) != 0 {
                n += 1;
            }
        }
        let s = if n < 256 {
            // SAFETY: measured result remains allocated.
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, n) }).ok()
        } else {
            None
        }; // SAFETY: free sole converted SID after read.
        unsafe {
            LocalFree(text.cast());
        }
        Ok(s.as_deref() == Some(current_sid()?.as_str()))
    })(); // SAFETY: sole GetSecurityInfo allocation, also on refusal paths.
    if !descriptor.is_null() {
        unsafe {
            LocalFree(descriptor);
        }
    }
    result
}
fn validate_root(path: &Path) -> Result<Root> {
    if !path.is_absolute()
        || path
            .components()
            .any(|v| matches!(v, Component::ParentDir | Component::CurDir))
    {
        bail!("unsafe_path");
    }
    let mut existing = path.to_path_buf();
    let mut missing = Vec::new();
    while !existing.try_exists().context("unsafe_path")? {
        missing.push(existing.file_name().context("unsafe_path")?.to_os_string());
        existing = existing.parent().context("unsafe_path")?.to_path_buf();
    }
    let mut anchors = Vec::new();
    for component in existing.ancestors() {
        let share = FILE_SHARE_READ
            | FILE_SHARE_WRITE
            | if same_path(component, path) {
                FILE_SHARE_DELETE
            } else {
                0
            };
        // Anchors deny delete sharing, so the tree cannot be renamed or deleted
        // while retained: each holds FILE_TRAVERSE (the same bit as
        // FILE_EXECUTE, a read-class access that takes part in the share check)
        // and shares READ | WRITE, never DELETE. The target directory itself
        // permits deletion so a standalone uninstall can remove it.
        // pinned_directory_refuses_rename_and_remove_until_the_pin_is_dropped
        // measures the same flags on the namespace pin: a real rename and
        // remove_dir against the held pin fail with ERROR_SHARING_VIOLATION(32),
        // and the remove succeeds after the pin is dropped.
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_TRAVERSE | SYNCHRONIZE)
            .share_mode(share)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(component)
            .context("unsafe_path")?;
        let metadata = file.metadata().context("unsafe_path")?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("unsafe_path");
        }
        if anchors.is_empty() && !file_owned(&file)? {
            bail!("foreign_user");
        }
        anchors.push(file);
    }
    let mut canonical = existing.canonicalize().context("unsafe_path")?;
    for part in missing.into_iter().rev() {
        canonical.push(part);
    }
    Ok(Root {
        path: canonical,
        _anchors: anchors,
    })
}
fn validate_images(root: &Root, images: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if images.is_empty() || images.len() > 16 {
        bail!("invalid_request");
    }
    let mut result: Vec<PathBuf> = Vec::new();
    for path in images {
        if !path.is_absolute()
            || path
                .components()
                .any(|v| matches!(v, Component::ParentDir | Component::CurDir))
        {
            bail!("unsafe_path");
        }
        let parent = path.parent().context("unsafe_path")?;
        let parent_root = validate_root(parent)?;
        if !same_path(&parent_root.path, &root.path) {
            bail!("unsafe_path");
        }
        let name = path.file_name().context("unsafe_path")?;
        if name
            .to_str()
            .is_none_or(|v| !v.to_ascii_lowercase().ends_with(".exe"))
        {
            bail!("unsafe_path");
        }
        let normalized = root.path.join(name);
        if normalized.try_exists().context("unsafe_path")? {
            let file = std::fs::OpenOptions::new()
                .access_mode(READ_CONTROL)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&normalized)
                .context("unsafe_path")?;
            let metadata = file.metadata().context("unsafe_path")?;
            if !metadata.is_file()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || !file_owned(&file)?
            {
                bail!("unsafe_path");
            }
            if !same_path(
                &normalized.canonicalize().context("unsafe_path")?,
                &normalized,
            ) {
                bail!("unsafe_path");
            }
        }
        if !result.iter().any(|p| same_path(p, &normalized)) {
            result.push(normalized);
        }
    }
    Ok(result)
}

/// Adapts planned absent images without weakening the frozen S1 backend. Full
/// image identity is read before calling its exact-existing-image inspection;
/// the retained birth is cross-checked against the resulting backend handle.
struct Census {
    inner: WindowsBackend,
}
impl Census {
    fn new() -> Result<Self> {
        Ok(Self {
            inner: WindowsBackend::new(None)?,
        })
    }
}
impl Backend for Census {
    type Handle = VerifiedProcess;
    fn scan(&mut self) -> Result<Vec<Candidate>> {
        self.inner.scan()
    }
    fn legacy_event_present(&mut self) -> Result<bool> {
        self.inner.legacy_event_present()
    }
    fn inspect(
        &mut self,
        row: &Candidate,
        selected: &[PathBuf],
    ) -> Result<Option<Inspected<Self::Handle>>> {
        // SAFETY: current process identity is borrowed. Standalone helper is not an application writer.
        if row.pid == unsafe { GetCurrentProcessId() } {
            return Ok(None);
        }
        let Some(retained) = census_process(row.pid)? else {
            return Ok(None);
        };
        if !alive(retained.0)? {
            return Ok(None);
        }
        let actual = image(retained.0)?;
        let start = birth(retained.0)?;
        let Some(mut found) = self.inner.inspect_actual_image(row, &actual)? else {
            return Ok(None);
        };
        if WindowsBackend::birth(&found.handle) != start {
            bail!("identity_unavailable");
        }
        found.installed = selected.iter().any(|p| same_path(p, &actual));
        found.handle.set_installed(found.installed);
        Ok(Some(found))
    }
    fn pid(h: &Self::Handle) -> u32 {
        WindowsBackend::pid(h)
    }
    fn birth(h: &Self::Handle) -> u64 {
        WindowsBackend::birth(h)
    }
    fn quit_channel(&mut self, h: &Self::Handle) -> Result<QuitChannel> {
        self.inner.quit_channel(h)
    }
    fn request_quit(&mut self, h: &Self::Handle, c: QuitChannel) -> Result<()> {
        self.inner.request_quit(h, c)
    }
    fn exited(&mut self, h: &Self::Handle) -> Result<bool> {
        self.inner.exited(h)
    }
    fn elapsed(&self) -> Duration {
        self.inner.elapsed()
    }
    fn pause(&mut self, d: Duration) {
        self.inner.pause(d)
    }
}
fn refuse_live(images: &[PathBuf], old_uninstall: bool) -> Result<()> {
    let mut census = Census::new()?;
    let start = Instant::now();
    let snapshot = census.scan()?;
    if snapshot.len() > 32768 {
        bail!("identity_unavailable");
    }
    for row in snapshot {
        if start.elapsed() > CONTROL_WAIT {
            bail!("identity_unavailable");
        }
        if row.pid == 0 || !upgrade_guard::basename_may_match(&row, images) {
            continue;
        }
        if let Some(target) = census.inspect(&row, images)? {
            let main_basename = row.basename.as_ref().is_none_or(|name| {
                images
                    .iter()
                    .filter_map(|p| p.file_name())
                    .any(|main| same_path(Path::new(name), Path::new(main)))
            });
            if super::refuses_live(
                target.installed,
                target.role,
                old_uninstall,
                main_basename,
                !census.exited(&target.handle)?,
            ) {
                bail!("legacy_running");
            }
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
struct Request {
    operation: String,
    installer: u32,
    birth: u64,
    root: PathBuf,
    images: Vec<PathBuf>,
    phase: String,
    committed: bool,
    rollback_closed: bool,
}
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Request> {
    let mut args = args.into_iter();
    let operation = args
        .next()
        .context("invalid_request")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("invalid_request"))?;
    if !matches!(
        operation.as_str(),
        "begin" | "recheck" | "commit-release" | "uninstall-admit" | "__hold"
    ) {
        bail!("invalid_request");
    }
    let mut request = Request {
        operation,
        installer: 0,
        birth: 0,
        root: PathBuf::new(),
        images: vec![],
        phase: String::new(),
        committed: false,
        rollback_closed: false,
    };
    while let Some(key) = args.next() {
        match key.to_str() {
            Some("--transaction-committed") if !request.committed => request.committed = true,
            Some("--rollback-closed") if !request.rollback_closed => request.rollback_closed = true,
            Some("--installer-pid") if request.installer == 0 => {
                request.installer = args
                    .next()
                    .context("invalid_request")?
                    .to_str()
                    .context("invalid_request")?
                    .parse()
                    .context("invalid_request")?
            }
            Some("--installer-birth") if request.birth == 0 => {
                request.birth = args
                    .next()
                    .context("invalid_request")?
                    .to_str()
                    .context("invalid_request")?
                    .parse()
                    .context("invalid_request")?
            }
            Some("--install-root") if request.root.as_os_str().is_empty() => {
                request.root = PathBuf::from(args.next().context("invalid_request")?)
            }
            Some("--image") if request.images.len() < 16 => request
                .images
                .push(PathBuf::from(args.next().context("invalid_request")?)),
            Some("--phase") if request.phase.is_empty() => {
                request.phase = args
                    .next()
                    .context("invalid_request")?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("invalid_request"))?
            }
            _ => bail!("invalid_request"),
        }
    }
    if request.installer == 0 {
        bail!("invalid_request");
    }
    match request.operation.as_str() {
        "begin" | "uninstall-admit" | "__hold"
            if request.root.as_os_str().is_empty() || request.images.is_empty() =>
        {
            bail!("invalid_request")
        }
        "recheck"
            if !matches!(
                request.phase.as_str(),
                "old-uninstall" | "preinstall" | "copy" | "delete"
            ) =>
        {
            bail!("invalid_request")
        }
        "commit-release" if !request.committed || !request.rollback_closed => {
            bail!("transaction_unproven")
        }
        _ => {}
    }
    if request.operation != "__hold" && request.birth != 0 {
        bail!("invalid_request");
    }
    Ok(request)
}
fn principal(h: HANDLE) -> Result<()> {
    if sid(h)? != current_sid()? {
        bail!("foreign_user");
    }
    let mut token = 0;
    // SAFETY: retained process handle and valid token output.
    if unsafe { OpenProcessToken(h, TOKEN_QUERY, &mut token) } == 0 {
        bail!("identity_unavailable");
    }
    let token = Handle(token);
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut size = 0; // SAFETY: zero-initialized C output.
                      // SAFETY: correct TOKEN_ELEVATION size and live token.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    } == 0
        || elevation.TokenIsElevated != 0
    {
        bail!("foreign_user");
    }
    let token_session = |handle: HANDLE| -> Result<u32> {
        let mut token = 0;
        // SAFETY: query process handle and live output slot.
        if unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) } == 0 {
            bail!("identity_unavailable");
        }
        let token = Handle(token);
        let mut session = 0u32;
        let mut size = 0;
        // SAFETY: TokenSessionId writes exactly one u32 into the declared buffer.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenSessionId,
                (&mut session as *mut u32).cast(),
                4,
                &mut size,
            )
        } == 0
            || size != 4
        {
            bail!("identity_unavailable");
        }
        Ok(session)
    };
    let session = token_session(h)?;
    // SAFETY: borrowed current process handle.
    if session == 0 || session != token_session(unsafe { GetCurrentProcess() })? {
        bail!("foreign_user");
    }
    Ok(())
}
fn direct_installer(pid: u32) -> Result<Handle> {
    // SAFETY: current process identity without ownership transfer.
    if parent(unsafe { GetCurrentProcessId() })? != pid {
        bail!("identity_unavailable");
    }
    let h = process(pid)?;
    principal(h.0)?;
    // A reused parent PID would have a birth after this already-running helper.
    // SAFETY: current process pseudo-handle is borrowed.
    if birth(h.0)? > birth(unsafe { GetCurrentProcess() })? {
        bail!("identity_unavailable");
    }
    if !alive(h.0)? {
        bail!("installer_exited");
    }
    Ok(h)
}
/// Authenticates kernel-observed ancestry, keeping every ancestor open and
/// requiring birth order. No supplied ancestor PID is itself authority.
fn lineage(client: u32, root: u32, root_birth: u64, direct: bool) -> Result<Vec<Handle>> {
    let mut chain = vec![process(client)?];
    let mut pid = client;
    for depth in 0..8 {
        let current = chain.last().context("identity_unavailable")?;
        if !alive(current.0)? {
            bail!("identity_unavailable");
        }
        let parent_pid = parent(pid)?;
        let ancestor = process(parent_pid)?;
        if birth(ancestor.0)? > birth(current.0)? {
            bail!("identity_unavailable");
        }
        if parent_pid == root {
            if birth(ancestor.0)? != root_birth || !alive(ancestor.0)? {
                bail!("installer_exited");
            }
            chain.push(ancestor);
            return Ok(chain);
        }
        if direct || depth == 7 {
            bail!("identity_unavailable");
        }
        if chain
            .iter()
            .any(|h| unsafe { GetProcessId(h.0) } == parent_pid)
        {
            bail!("identity_unavailable");
        } // SAFETY: retained query handles.
        chain.push(ancestor);
        pid = parent_pid;
    }
    bail!("identity_unavailable")
}
fn wait_bytes(file: &File, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        let mut available = 0;
        // SAFETY: synchronous pipe handle, no data read, valid output slot.
        if unsafe {
            PeekNamedPipe(
                file.as_raw_handle() as HANDLE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        } == 0
        {
            bail!("control_unavailable");
        }
        if available > 0 {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            bail!("control_unavailable");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn read_frame(file: &mut File, timeout: Duration) -> Result<Vec<u8>> {
    let start = Instant::now();
    let mut result = Vec::new();
    let mut size = None;
    loop {
        wait_bytes(file, timeout.saturating_sub(start.elapsed()))?;
        let mut byte = [0];
        file.read_exact(&mut byte).context("control_unavailable")?;
        result.push(byte[0]);
        if result.len() == 4 {
            let n = u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
            if n == 0 || n > MAX_FRAME {
                bail!("invalid_request");
            }
            size = Some(n);
        }
        if size.is_some_and(|n| result.len() == n + 4) {
            return Ok(result.split_off(4));
        }
        if start.elapsed() >= timeout {
            bail!("control_unavailable");
        }
    }
}
fn write_frame(file: &mut File, value: &[u8]) -> Result<()> {
    if value.is_empty() || value.len() > MAX_FRAME {
        bail!("invalid_request");
    }
    file.write_all(&(value.len() as u32).to_le_bytes())
        .context("control_unavailable")?;
    file.write_all(value).context("control_unavailable")?;
    Ok(())
}
fn connect() -> Result<Option<File>> {
    // SAFETY: known user-specific pipe path, synchronous non-inherited handle.
    let raw = unsafe {
        CreateFileW(
            pipe_name()?.as_ptr(),
            0xC0000000,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            pipe_client_security_flags(),
            0,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            return Ok(None);
        }
        bail!("control_unavailable");
    }
    // SAFETY: transfer the unique valid owned handle into File.
    Ok(Some(unsafe { File::from_raw_handle(raw as _) }))
}
fn controller(mut request: Request) -> Result<String> {
    let installer = direct_installer(request.installer)?;
    request.birth = birth(installer.0)?;
    if request.operation == "begin" {
        return spawn_holder(request, false);
    }
    if request.operation == "uninstall-admit" {
        if let Some(mut pipe) = connect()? {
            return exchange(&mut pipe, &request);
        }
        check()?;
        return spawn_holder(request, true);
    }
    let mut pipe = connect()?.context("control_unavailable")?;
    exchange(&mut pipe, &request)
}
fn exchange(pipe: &mut File, request: &Request) -> Result<String> {
    let mut server_pid = 0;
    // SAFETY: valid pipe handle and output slot.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle() as HANDLE, &mut server_pid) } == 0
    {
        bail!("identity_unavailable");
    }
    let server = process(server_pid)?;
    principal(server.0)?;
    if !same_path(&image(server.0)?, &std::env::current_exe()?.canonicalize()?) {
        bail!("identity_unavailable");
    }
    write_frame(pipe, &serde_json::to_vec(request)?)?;
    let reply = String::from_utf8(read_frame(pipe, CONTROL_WAIT)?).context("invalid_request")?;
    write_frame(pipe, b"RECEIVED")?;
    validate_reply(&reply)?;
    Ok(reply)
}
fn ready_reference(reply: &str) -> Option<u32> {
    let token = reply
        .strip_prefix("CSQ_INSTALL_V1 READY ")
        .or_else(|| reply.strip_prefix("CSQ_INSTALL_V1 UNINSTALL_READY "))?;
    let hex = token.strip_prefix("0x")?;
    if hex.len() != 8
        || !hex
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'A'..=b'F').contains(&v))
    {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    if value == 0 || value == u32::MAX {
        None
    } else {
        Some(value)
    }
}
fn validate_reply(reply: &str) -> Result<()> {
    if reply.len() > 512 || reply.contains(['\r', '\n']) {
        bail!("invalid_request");
    }
    let ready = ready_reference(reply).is_some();
    let valid = ready
        || matches!(
            reply,
            "CSQ_INSTALL_V1 RELEASED" | "CSQ_INSTALL_V1 UNINSTALL_REUSE_OK"
        )
        || ["old-uninstall", "preinstall", "copy", "delete"]
            .iter()
            .any(|p| reply == format!("CSQ_INSTALL_V1 RECHECK_OK {p}"));
    if valid {
        Ok(())
    } else if let Some(tag) = reply.strip_prefix("CSQ_INSTALL_V1 REFUSED ") {
        if refusal_tag(tag) == tag {
            bail!("{tag}");
        }
        bail!("invalid_request")
    } else {
        bail!("invalid_request")
    }
}
/// Quote according to CommandLineToArgvW's backslash/quote rules; every
/// argument is quoted, including executable and trailing directory separators.
fn holder_command_line(arguments: &[OsString]) -> Result<Vec<u16>> {
    let mut result = Vec::new();
    for argument in arguments {
        let value = wide(argument)?;
        if !result.is_empty() {
            result.push(b' ' as u16);
        }
        result.push(b'"' as u16);
        let mut slashes = 0;
        for &unit in &value[..value.len() - 1] {
            if unit == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            result.extend(std::iter::repeat_n(
                b'\\' as u16,
                if unit == b'"' as u16 {
                    slashes * 2 + 1
                } else {
                    slashes
                },
            ));
            slashes = 0;
            result.push(unit);
        }
        result.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        result.push(b'"' as u16);
    }
    if result.len() >= 32767 {
        bail!("invalid_request");
    }
    result.push(0);
    Ok(result)
}
fn spawn_with_handle_allowlist(
    executable: &Path,
    arguments: &[OsString],
) -> Result<(Handle, File)> {
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };
    use windows_sys::Win32::{Foundation::DUPLICATE_SAME_ACCESS, Security::SECURITY_ATTRIBUTES};
    let (mut read, mut write) = (0, 0);
    // SAFETY: initialized outputs; neither endpoint is initially inheritable.
    if unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) } == 0 {
        bail!("control_unavailable");
    }
    let read = Handle(read);
    let write = Handle(write);
    let mut inherited_write = 0;
    // SAFETY: sole owned pipe handle; make only this duplicate inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            write.0,
            GetCurrentProcess(),
            &mut inherited_write,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        bail!("control_unavailable");
    }
    let inherited_write = Handle(inherited_write);
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: NUL-terminated reserved device name, inheritable stdio only.
    let null = unsafe {
        CreateFileW(
            text_wide("NUL")?.as_ptr(),
            0xC0000000,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attrs,
            OPEN_EXISTING,
            0,
            0,
        )
    };
    if null == INVALID_HANDLE_VALUE {
        bail!("control_unavailable");
    }
    let null = Handle(null);
    let allowed = [inherited_write.0, null.0];
    let mut bytes = 0;
    // SAFETY: documented size query; allocation is capped and aligned below.
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
    }
    if bytes == 0 || bytes > 65536 {
        bail!("control_unavailable");
    }
    let mut storage = vec![0usize; bytes.div_ceil(std::mem::size_of::<usize>())];
    let list = storage.as_mut_ptr().cast();
    // SAFETY: aligned storage has at least queried bytes and stays live through spawn.
    if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) } == 0 {
        bail!("control_unavailable");
    }
    struct Attributes(windows_sys::Win32::System::Threading::LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for Attributes {
        fn drop(&mut self) {
            // SAFETY: one initialized list, dropped before its backing allocation.
            unsafe {
                DeleteProcThreadAttributeList(self.0);
            }
        }
    }
    let list = Attributes(list);
    // SAFETY: exactly these two inheritable stdio handles form the entire list.
    if unsafe {
        UpdateProcThreadAttribute(
            list.0,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            allowed.as_ptr().cast(),
            std::mem::size_of_val(&allowed),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    } == 0
    {
        bail!("control_unavailable");
    }
    // SAFETY: zero initialization is valid for these Win32 C output/input structs.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null.0;
    startup.StartupInfo.hStdError = null.0;
    startup.StartupInfo.hStdOutput = inherited_write.0;
    startup.lpAttributeList = list.0;
    let mut command = holder_command_line(arguments)?;
    // SAFETY: application is explicit; mutable command and all list/stdio storage
    // remains live. bInheritHandles is bounded by HANDLE_LIST, not ambient handles.
    if unsafe {
        CreateProcessW(
            wide(executable.as_os_str())?.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut process,
        )
    } == 0
    {
        bail!("control_unavailable");
    }
    let process_handle = Handle(process.hProcess);
    let _thread = Handle(process.hThread);
    let raw = read.0;
    std::mem::forget(read);
    // SAFETY: transfer sole read endpoint to File; controller closes all writes.
    Ok((process_handle, unsafe { File::from_raw_handle(raw as _) }))
}
fn spawn_holder(mut request: Request, uninstall: bool) -> Result<String> {
    let parent_process = process(request.installer)?;
    request.birth = birth(parent_process.0)?;
    let executable = std::env::current_exe()?;
    // NSIS pins and hashes this volume-GUID path through begin's exit. Preserve
    // that exact namespace for the internal broker exec, or refuse. In
    // particular canonicalize() may reconstruct a DOS alias and is forbidden.
    if !executable
        .as_os_str()
        .to_string_lossy()
        .starts_with(r"\\?\Volume{")
    {
        bail!("unsafe_path");
    }
    let mut arguments = vec![
        executable.as_os_str().to_owned(),
        "__hold".into(),
        "--installer-pid".into(),
        request.installer.to_string().into(),
        "--installer-birth".into(),
        request.birth.to_string().into(),
        "--install-root".into(),
        request.root.into_os_string(),
    ];
    if uninstall {
        arguments.extend(["--phase".into(), "uninstall".into()]);
    }
    for path in request.images {
        arguments.extend(["--image".into(), path.into_os_string()]);
    }
    let (_child, mut file) = spawn_with_handle_allowlist(&executable, &arguments)?;
    let reply = String::from_utf8(read_frame(&mut file, holder_ready_budget()?)?)
        .context("invalid_request")?;
    validate_reply(&reply)?;
    Ok(reply)
}
fn holder(request: Request) -> Result<String> {
    if request.birth == 0 {
        bail!("invalid_request");
    }
    // The broker must be a child of the exact helper image, and that helper a
    // direct child of the bound installer. Birth checks reject PID reuse.
    let own = unsafe { GetCurrentProcessId() }; // SAFETY: borrowed current identity.
    let client_pid = parent(own)?;
    let client = process(client_pid)?;
    if !same_path(&image(client.0)?, &std::env::current_exe()?.canonicalize()?) {
        bail!("identity_unavailable");
    }
    let _client_chain = lineage(client_pid, request.installer, request.birth, true)?;
    let installer = process_with_rights(request.installer, PROCESS_DUP_HANDLE)?;
    principal(installer.0)?;
    if birth(installer.0)? != request.birth {
        bail!("identity_unavailable");
    }
    let watcher = process(request.installer)?;
    // The dedicated helper owns no application writers. Process exit on the
    // retained installer handle signaling releases every kernel lease even if
    // a control client stalls. No application process is signaled or killed.
    fn watch_installer(watcher: Handle) {
        // SAFETY: owned synchronize handle remains on this thread until exit.
        if unsafe { WaitForSingleObject(watcher.0, u32::MAX) } == WAIT_OBJECT_0 {
            std::process::exit(0);
        }
        std::process::exit(2);
    }
    std::thread::Builder::new()
        .name("installer-lifetime".into())
        .spawn(move || watch_installer(watcher))
        .context("control_unavailable")?;
    let mut lease = Some(Lease::acquire()?);
    let root = validate_root(&request.root)?;
    let mut images = validate_images(&root, &request.images)?;
    let mut backend = S2Backend::new(Census::new()?, capable as fn(u32, u64) -> Result<bool>);
    upgrade_guard::stop_installed(&mut backend, &images, upgrade_guard::Limits::default())
        .context("drain_refused")?;
    refuse_live(&images, false)?;
    let security = OwnerOnlyObjectSecurity::current_user()?;
    let attrs = security.attributes();
    // SAFETY: explicit owner-only descriptor; one server and no remote clients.
    let raw = unsafe {
        CreateNamedPipeW(
            pipe_name()?.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_FRAME as u32,
            MAX_FRAME as u32,
            0,
            &attrs,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        bail!("control_unavailable");
    }
    let mut pipe = unsafe { File::from_raw_handle(raw as _) }; // SAFETY: transfer unique successful pipe handle.
    let installer_reference = lease
        .as_ref()
        .context("transaction_unproven")?
        .duplicate_to_installer(installer.0)?;
    let prefix = if request.phase == "uninstall" {
        "CSQ_INSTALL_V1 UNINSTALL_READY"
    } else {
        "CSQ_INSTALL_V1 READY"
    };
    let ready = format!("{prefix} 0x{installer_reference:08X}");
    let bytes = ready.as_bytes();
    let mut out = std::io::stdout().lock();
    out.write_all(&(bytes.len() as u32).to_le_bytes())?;
    out.write_all(bytes)?;
    out.flush()?;
    drop(out);
    loop {
        if !alive(installer.0)? {
            bail!("installer_exited");
        }
        // SAFETY: synchronous server pipe. Watcher independently observes parent exit.
        let connected =
            unsafe { ConnectNamedPipe(pipe.as_raw_handle() as HANDLE, std::ptr::null_mut()) };
        if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            bail!("control_unavailable");
        } // SAFETY: immediate last-error read.
        let outcome = (|| -> Result<(String, bool)> {
            let mut client_pid = 0;
            // SAFETY: connected pipe and initialized client-PID output.
            if unsafe {
                GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut client_pid)
            } == 0
            {
                bail!("identity_unavailable");
            }
            let incoming: Request = serde_json::from_slice(&read_frame(&mut pipe, CONTROL_WAIT)?)
                .context("invalid_request")?;
            let reuse = incoming.operation == "uninstall-admit";
            let _chain = lineage(client_pid, request.installer, request.birth, !reuse)?;
            // Controller clients must be the hash-bound staged helper image.
            let caller = process(client_pid)?;
            if !same_path(&image(caller.0)?, &std::env::current_exe()?.canonicalize()?) {
                bail!("identity_unavailable");
            }
            let observed_parent = parent(client_pid)?;
            if incoming.installer != observed_parent
                || birth(process(observed_parent)?.0)? != incoming.birth
            {
                bail!("identity_unavailable");
            }
            if !reuse
                && (incoming.installer != request.installer || incoming.birth != request.birth)
            {
                bail!("identity_unavailable");
            }
            if !alive(installer.0)? || lease.is_none() {
                bail!("installer_exited");
            }
            let current_root = validate_root(&root.path)?;
            if !same_path(&current_root.path, &root.path) {
                bail!("unsafe_path");
            }
            if !incoming.root.as_os_str().is_empty()
                && !same_path(&validate_root(&incoming.root)?.path, &root.path)
            {
                bail!("unsafe_path");
            }
            if !incoming.images.is_empty() {
                for path in validate_images(&root, &incoming.images)? {
                    if !images.iter().any(|v| same_path(v, &path)) {
                        if images.len() >= 16 {
                            bail!("invalid_request");
                        }
                        images.push(path);
                    }
                }
            }
            match incoming.operation.as_str() {
                "recheck"
                    if matches!(
                        incoming.phase.as_str(),
                        "old-uninstall" | "preinstall" | "copy" | "delete"
                    ) =>
                {
                    refuse_live(&images, incoming.phase == "old-uninstall")?;
                    Ok((
                        format!("CSQ_INSTALL_V1 RECHECK_OK {}", incoming.phase),
                        false,
                    ))
                }
                "uninstall-admit" => {
                    refuse_live(&images, true)?;
                    Ok(("CSQ_INSTALL_V1 UNINSTALL_REUSE_OK".into(), false))
                }
                "commit-release" if incoming.committed && incoming.rollback_closed => {
                    lease.as_mut().context("transaction_unproven")?.release()?;
                    drop(lease.take());
                    Ok(("CSQ_INSTALL_V1 RELEASED".into(), true))
                }
                "commit-release" => bail!("transaction_unproven"),
                _ => bail!("invalid_request"),
            }
        })();
        let (reply, released) = match outcome {
            Ok(value) => value,
            Err(e) => (format!("CSQ_INSTALL_V1 REFUSED {}", classify(&e)), false),
        };
        let sent = write_frame(&mut pipe, reply.as_bytes()).and_then(|()| {
            let ack = read_frame(&mut pipe, CONTROL_WAIT)?;
            if ack != b"RECEIVED" {
                bail!("invalid_request");
            }
            Ok(())
        });
        // SAFETY: connected server pipe; disconnect only after receipt or deadline.
        unsafe {
            DisconnectNamedPipe(pipe.as_raw_handle() as HANDLE);
        }
        sent?;
        if released {
            return Ok(String::new());
        }
    }
}
fn refusal_tag(tag: &str) -> &str {
    match tag {
        "legacy_running"
        | "foreign_user"
        | "identity_unavailable"
        | "lease_busy"
        | "installer_exited"
        | "invalid_request"
        | "unsafe_path"
        | "drain_refused"
        | "control_unavailable"
        | "transaction_unproven"
        | "namespace_path_busy"
        | "namespace_directory_reparsed"
        | "namespace_filesystem_unsupported" => tag,
        _ => "identity_unavailable",
    }
}
/// Fixed-vocabulary diagnostic category; never formats secret or path material.
pub fn classify(error: &anyhow::Error) -> &'static str {
    if error
        .chain()
        .any(|source| source.to_string() == "namespace_path_busy")
    {
        return "namespace_path_busy";
    }
    if error.is::<NamespaceFilesystemUnsupported>() {
        return "namespace_filesystem_unsupported";
    }
    if error.is::<NamespaceDirectoryReparsed>() {
        return "namespace_directory_reparsed";
    }
    for source in error.chain() {
        match source.to_string().as_str() {
            "namespace_profile_unavailable" => return "namespace_profile_unavailable",
            "namespace_path_busy" => return "namespace_path_busy",
            "namespace_path_unsafe" => return "namespace_path_unsafe",
            "namespace_parent_unsafe" => return "namespace_parent_unsafe",
            "namespace_directory_unavailable" => return "namespace_directory_unavailable",
            "namespace_directory_unsafe" => return "namespace_directory_unsafe",
            "namespace_directory_reparsed" => return "namespace_directory_reparsed",
            "namespace_filesystem_unsupported" => return "namespace_filesystem_unsupported",
            "namespace_secret_unavailable" => return "namespace_secret_unavailable",
            "namespace_secret_unsafe" => return "namespace_secret_unsafe",
            "namespace_secret_acl" => return "namespace_secret_acl",
            "namespace_secret_size" => return "namespace_secret_size",
            "namespace_random_unavailable" => return "namespace_random_unavailable",
            "namespace_secret_write" => return "namespace_secret_write",
            "namespace_secret_create" => return "namespace_secret_create",
            "namespace_secret_publish" => return "namespace_secret_publish",
            "namespace_secret_cleanup" => return "namespace_secret_cleanup",
            "namespace_secret_busy" => return "namespace_secret_busy",
            "namespace_crypto_unavailable" => return "namespace_crypto_unavailable",
            "legacy_running" => return "legacy_running",
            "foreign_user" => return "foreign_user",
            "lease_busy" => return "lease_busy",
            "installer_exited" => return "installer_exited",
            "invalid_request" => return "invalid_request",
            "unsafe_path" => return "unsafe_path",
            "transaction_unproven" => return "transaction_unproven",
            "drain_refused" => return "drain_refused",
            "control_unavailable" => return "control_unavailable",
            _ => {}
        }
    }
    "identity_unavailable"
}
/// Dedicated helper entry. Never enters CLI, app, daemon or credential startup.
pub fn run(args: impl IntoIterator<Item = OsString>) -> i32 {
    use windows_sys::Win32::System::LibraryLoader::{
        SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    // SAFETY: restrict subsequent DLL lookup before any path/protocol input.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        println!("CSQ_INSTALL_V1 REFUSED identity_unavailable");
        return 2;
    }
    let arguments: Vec<OsString> = args.into_iter().collect();
    let broker = arguments.first().is_some_and(|v| v == "__hold");
    let result = (|| {
        let _executable_pins = pin_executable()?;
        if arguments.len() == 1 && arguments[0] == "lease-object-name" {
            return lease_object_name();
        }
        let request = parse(arguments)?;
        if broker {
            holder(request)
        } else {
            controller(request)
        }
    })();
    match result {
        Ok(reply) => {
            if !reply.is_empty() {
                println!("{reply}");
            }
            0
        }
        Err(e) => {
            let reply = format!("CSQ_INSTALL_V1 REFUSED {}", classify(&e));
            if broker {
                let mut out = std::io::stdout().lock();
                let bytes = reply.as_bytes();
                let _ = out
                    .write_all(&(bytes.len() as u32).to_le_bytes())
                    .and_then(|()| out.write_all(bytes))
                    .and_then(|()| out.flush());
            } else {
                println!("{reply}");
            }
            2
        }
    }
}

#[cfg(test)]
mod request_tests {
    use super::{parse, ready_reference};
    use std::ffi::OsString;
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(|v| OsString::from(*v)).collect()
    }
    #[test]
    fn installer_reference_grammar_is_bounded_and_never_accepts_pseudo_handles() {
        assert_eq!(
            ready_reference("CSQ_INSTALL_V1 READY 0x000001AC"),
            Some(0x1AC)
        );
        assert_eq!(
            ready_reference("CSQ_INSTALL_V1 UNINSTALL_READY 0x000001AC"),
            Some(0x1AC)
        );
        for invalid in [
            "CSQ_INSTALL_V1 READY",
            "CSQ_INSTALL_V1 READY 0x00000000",
            "CSQ_INSTALL_V1 READY 0xFFFFFFFF",
            "CSQ_INSTALL_V1 READY 0x000001ac",
            "CSQ_INSTALL_V1 READY 0x100000000",
            "CSQ_INSTALL_V1 READY 0x000001AC extra",
            "CSQ_INSTALL_V1 UNINSTALL_REUSE_OK 0x000001AC",
        ] {
            assert_eq!(ready_reference(invalid), None);
        }
    }
    #[test]
    fn release_requires_both_transaction_attestations() {
        assert!(parse(args(&["commit-release", "--installer-pid", "10"])).is_err());
        assert!(parse(args(&[
            "commit-release",
            "--installer-pid",
            "10",
            "--transaction-committed"
        ]))
        .is_err());
        assert!(parse(args(&[
            "commit-release",
            "--installer-pid",
            "10",
            "--rollback-closed"
        ]))
        .is_err());
        assert!(parse(args(&[
            "commit-release",
            "--installer-pid",
            "10",
            "--transaction-committed",
            "--rollback-closed"
        ]))
        .is_ok());
    }
    #[test]
    fn external_caller_cannot_supply_birth_or_restore_deferred_launch_protocol() {
        assert!(parse(args(&[
            "commit-release",
            "--installer-pid",
            "10",
            "--installer-birth",
            "20",
            "--transaction-committed",
            "--rollback-closed"
        ]))
        .is_err());
        assert!(parse(args(&["launch", "--installer-pid", "10"])).is_err());
    }
    #[test]
    fn fixed_refusals_survive_error_context() {
        for tag in [
            "drain_refused",
            "control_unavailable",
            "namespace_path_busy",
            "namespace_secret_publish",
            "namespace_secret_cleanup",
            "namespace_directory_unsafe",
            "namespace_filesystem_unsupported",
        ] {
            let error = anyhow::anyhow!(tag).context("controller request failed");
            assert_eq!(super::classify(&error), tag);
        }
    }
    #[test]
    fn reparsed_refusal_survives_the_controller_reply_boundary() {
        for tag in [
            "namespace_directory_reparsed",
            "namespace_path_busy",
            "namespace_filesystem_unsupported",
        ] {
            let error =
                super::validate_reply(&format!("CSQ_INSTALL_V1 REFUSED {tag}")).unwrap_err();
            assert_eq!(super::classify(&error), tag);
        }
    }
    #[test]
    fn readiness_budget_covers_both_roles_and_control_margin() {
        let role = crate::update::upgrade_guard::shutdown_observer_budget().unwrap();
        assert_eq!(
            super::holder_ready_budget().unwrap(),
            role * 2 + super::CONTROL_WAIT
        );
    }
    #[test]
    fn holder_arguments_roundtrip_embedded_quotes_and_trailing_slashes() {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};
        use windows_sys::Win32::{Foundation::LocalFree, UI::Shell::CommandLineToArgvW};
        let arguments: Vec<OsString> =
            [r"C:\stage dir\helper.exe", "", r"C:\install dir\", "a\\\"b"]
                .iter()
                .map(OsString::from)
                .collect();
        let command = super::holder_command_line(&arguments).unwrap();
        let mut count = 0;
        // SAFETY: terminated generated command line and initialized output count.
        let argv = unsafe { CommandLineToArgvW(command.as_ptr(), &mut count) };
        assert!(!argv.is_null());
        assert_eq!(count as usize, arguments.len());
        let mut observed = Vec::new();
        for index in 0..count as usize {
            // SAFETY: API returned count pointers to terminated UTF-16 arguments.
            let arg = unsafe { *argv.add(index) };
            let mut length = 0;
            unsafe {
                while *arg.add(length) != 0 {
                    length += 1;
                }
            }
            observed.push(OsString::from_wide(unsafe {
                std::slice::from_raw_parts(arg, length)
            }));
        }
        // SAFETY: exactly the allocation returned by CommandLineToArgvW.
        unsafe {
            LocalFree(argv.cast());
        }
        assert_eq!(observed, arguments);
    }
    #[test]
    fn census_fixture_child() {
        let Some(base) = std::env::var_os("CSQ_CENSUS_OWNED_FIXTURE") else {
            return;
        };
        let base = std::path::PathBuf::from(base);
        std::fs::write(base.with_extension("ready"), b"ready").unwrap();
        let start = std::time::Instant::now();
        while !base.with_extension("stop").exists()
            && start.elapsed() < std::time::Duration::from_secs(45)
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    #[test]
    fn census_accepts_two_distinct_live_images_including_upgrade_controller() {
        let _env = crate::platform::test_env::lock();
        use crate::update::upgrade_guard::{Backend, Candidate};
        use std::{
            path::PathBuf,
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };
        struct OwnedChild(Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                // Only this test's spawned fixture process; never discovered host processes.
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let mut children = Vec::new();
        let mut paths = Vec::new();
        for name in ["csq.exe", "csq-upgrade-helper.exe"] {
            let path = temp.path().join(name);
            std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
            let marker = temp.path().join(format!("{name}-owned"));
            let mut command = Command::new(&path);
            command
                .arg("update::installer_admission::windows::request_tests::census_fixture_child")
                .args(["--exact", "--nocapture"])
                .env_clear()
                .env("CSQ_CENSUS_OWNED_FIXTURE", &marker)
                .env("CSQ_BASE_DIR", temp.path())
                .env("USERPROFILE", temp.path())
                .env("HOME", temp.path())
                .env("TEMP", temp.path())
                .env("TMP", temp.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Some(root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", root);
            }
            let mut child = OwnedChild(command.spawn().unwrap());
            let start = Instant::now();
            while !marker.with_extension("ready").exists() {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "fixture exited before ready"
                );
                assert!(
                    start.elapsed() < Duration::from_secs(15),
                    "fixture setup timed out"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            paths.push(path.canonicalize().unwrap());
            children.push(child);
        }
        let mut census = super::Census::new().unwrap();
        for (child, path) in children.iter().zip(&paths) {
            let row = Candidate {
                pid: child.0.id(),
                basename: path.file_name().map(|v| v.to_owned()),
            };
            let inspected = census
                .inspect(&row, &paths)
                .unwrap()
                .expect("live selected fixture");
            assert!(inspected.installed);
            assert!(!census.exited(&inspected.handle).unwrap());
            let noninstalled = census.inspect(&row, &[]).unwrap().unwrap();
            assert!(!noninstalled.installed);
            let error = census.quit_channel(&noninstalled.handle).unwrap_err();
            assert!(error
                .to_string()
                .contains("refusing quit preflight for non-installed PID"));
            let error = census
                .request_quit(
                    &noninstalled.handle,
                    crate::update::upgrade_guard::QuitChannel::Bound,
                )
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("refusing to signal non-installed upgrade PID"));
        }
        // Exit through the fixture's own release condition and retain a real
        // handle across exit. No terminated handle may count as a live blocker.
        let row = Candidate {
            pid: children[0].0.id(),
            basename: Some("csq.exe".into()),
        };
        let inspected = census.inspect(&row, &paths).unwrap().unwrap();
        std::fs::write(
            temp.path().join("csq.exe-owned").with_extension("stop"),
            b"stop",
        )
        .unwrap();
        children[0].0.wait().unwrap();
        assert!(census.exited(&inspected.handle).unwrap());
        assert!(census.inspect(&row, &paths).unwrap().is_none());
        let vanished = Candidate {
            pid: u32::MAX,
            basename: Some("csq.exe".into()),
        };
        assert!(census
            .inspect(&vanished, &[PathBuf::from(&paths[0])])
            .unwrap()
            .is_none());
    }

    #[test]
    fn allowlist_fixture_child() {
        use super::*;
        let executable = std::env::current_exe().unwrap();
        let stem = executable.file_stem().unwrap().to_string_lossy();
        let Some(value) = stem.strip_prefix("csq-allowlist-") else {
            return;
        };
        let (raw, parent) = value.split_once('-').unwrap();
        let raw: isize = raw.parse().unwrap();
        let mut duplicate = 0;
        // SAFETY: negative test of an alleged inherited handle; duplicate, if
        // successful, is owned locally before any new named-event handle opens.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                raw,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return;
        }
        let duplicate = Handle(duplicate);
        let name = text_wide(&format!("Local\\csq-inheritance-fixture-{parent}")).unwrap();
        // SAFETY: fixed owned fixture name and read/query access only.
        let event = unsafe { OpenEventW(READ_CONTROL, 0, name.as_ptr()) };
        assert_ne!(event, 0);
        let event = Handle(event);
        // SAFETY: both handles retained. Equality proves ambient canary inheritance.
        assert_eq!(
            unsafe { windows_sys::Win32::Foundation::CompareObjectHandles(duplicate.0, event.0) },
            0,
            "unlisted inheritable canary reached holder"
        );
    }
    #[test]
    fn holder_spawn_does_not_inherit_unlisted_controller_handles() {
        use super::*;
        use windows_sys::Win32::System::Threading::GetExitCodeProcess;
        let temp = tempfile::tempdir().unwrap();
        let parent = unsafe { GetCurrentProcessId() };
        let name = text_wide(&format!("Local\\csq-inheritance-fixture-{parent}")).unwrap();
        let security = OwnerOnlyObjectSecurity::current_user().unwrap();
        let mut attrs = security.attributes();
        attrs.bInheritHandle = 1;
        // SAFETY: this test creates a fresh owner-only canary, not application state.
        let raw = unsafe { CreateEventW(&attrs, 1, 0, name.as_ptr()) };
        assert_ne!(raw, 0);
        let canary = Handle(raw);
        let path = temp
            .path()
            .join(format!("csq-allowlist-{}-{parent}.exe", canary.0));
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let arguments = vec![
            path.as_os_str().to_owned(),
            "update::installer_admission::windows::request_tests::allowlist_fixture_child".into(),
            "--exact".into(),
            "--nocapture".into(),
        ];
        let (child, mut output) = spawn_with_handle_allowlist(&path, &arguments).unwrap();
        // SAFETY: exact test-created process handle, never an enumerated PID.
        assert_eq!(
            unsafe { WaitForSingleObject(child.0, 15000) },
            WAIT_OBJECT_0
        );
        let mut code = 999;
        assert_ne!(unsafe { GetExitCodeProcess(child.0, &mut code) }, 0);
        let mut log = String::new();
        output.read_to_string(&mut log).unwrap();
        assert_eq!(code, 0, "fixture failed: {log}");
    }

    #[test]
    fn pipe_client_requests_identification_without_impersonation() {
        // Win32 SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, rather than
        // CreateFile's default SecurityImpersonation token delegation.
        assert_eq!(super::pipe_client_security_flags(), 0x0011_0000);
    }
}

#[cfg(test)]
mod namespace_tests {
    use super::*;
    /// DELETE access (renames and deletions need it) for the share-check probes.
    const DELETE_ACCESS: u32 = 0x0001_0000;
    /// Opens a fixture directory with the same handle the production namespace
    /// path uses for the secret root: every secret operation then goes through
    /// the handle, never a path, so these tests exercise the real
    /// (handle-relative) production code. The installation-directory shape is
    /// the one that may create children (FILE_ADD_FILE).
    fn pin(dir: &Path) -> File {
        pin_installation_directory(dir).unwrap()
    }
    // A TempDir's inherited ACL and default owner come from the test host, not
    // the token-profile contract. Build an explicitly owned synthetic profile
    // with intentional inheritable trusted grants before testing later gates.
    fn safe_profile(sandbox: &Path) -> PathBuf {
        let profile = sandbox.join("profile");
        create_private_directory(&profile).unwrap();
        let profile_pin = pin_namespace_directory(&profile).unwrap();
        assert!(file_owned(&profile_pin).unwrap());
        check_private_handle(&profile_pin).unwrap();
        drop(profile_pin);
        set_fixture_parent_dacl(&profile, "");
        assert_fixture_parent_safe(&profile);
        profile
    }
    fn assert_fixture_parent_safe(path: &Path) {
        let pin = pin_namespace_directory(path).unwrap();
        verify_namespace_parent(&pin).expect("the unmodified synthetic ancestry must be safe");
    }
    const FILE_WRITE_DATA_ACCESS: u32 = 0x0000_0002;
    const FILE_WRITE_ATTRIBUTES_ACCESS: u32 = 0x0000_0100;
    #[test]
    fn keyed_names_are_domain_separated_and_match_standard_hmac() {
        let secret = std::array::from_fn(|n| n as u8);
        let lease = namespace_tag(&secret, "lease", "S-1-5-21-42").unwrap();
        assert_eq!(lease, "6f7bc2f81b139cf4628971017a127a94");
        let capability = namespace_tag(&secret, "capability", "S-1-5-21-42").unwrap();
        let pipe = namespace_tag(&secret, "pipe", "S-1-5-21-42").unwrap();
        assert_ne!(lease, capability);
        assert_ne!(lease, pipe);
        assert_ne!(capability, pipe);
        assert_ne!(
            lease,
            namespace_tag(&secret, "lease", "S-1-5-21-43").unwrap()
        );
        assert_ne!(
            lease,
            namespace_tag(&[99; SECRET_BYTES], "lease", "S-1-5-21-42").unwrap()
        );
        assert!(namespace_tag(&secret, "control|lease", "S-1-5-21-42").is_err());
    }
    #[test]
    fn persistent_secret_create_race_converges_without_rotation() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let path = sandbox.path().join(SECRET_FILE);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let directory = sandbox.path().to_path_buf();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    // Each invocation holds its own pin, as production does.
                    let pin = pin(&directory);
                    namespace_secret_at(&pin).unwrap()
                })
            })
            .collect();
        let values: Vec<_> = workers.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(values.iter().all(|value| *value == values[0]));
        assert_eq!(std::fs::read(&path).unwrap(), values[0]);
        let pin = pin(sandbox.path());
        assert_eq!(namespace_secret_at(&pin).unwrap(), values[0]);
        assert!(std::fs::read_dir(sandbox.path())
            .unwrap()
            .all(|entry| entry.unwrap().path() == path));
    }
    #[test]
    fn hardlinked_secret_is_rejected_on_every_read() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let path = sandbox.path().join(SECRET_FILE);
        let pin = pin(sandbox.path());
        let bytes = namespace_secret_at(&pin).unwrap();
        std::fs::hard_link(&path, sandbox.path().join("alias")).unwrap();
        let error = namespace_secret_at(&pin).unwrap_err();
        assert_eq!(classify(&error), "namespace_secret_unsafe");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    fn grant_null_dacl(path: &Path) {
        use windows_sys::Win32::Security::{
            Authorization::SetNamedSecurityInfoW, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let name = wide(path.as_os_str()).unwrap();
        // SAFETY: only the owned TempDir fixture; NULL DACL intentionally broad.
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
    }
    #[test]
    fn inherited_existing_csq_parent_allows_new_private_namespace_directory() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        let parent = profile.join(".csq");
        std::fs::create_dir(&parent).unwrap();
        assert_fixture_parent_safe(&parent);
        let bytes = namespace_secret_from_profile(&profile).unwrap();
        let directory = parent.join("installer-admission-v2");
        check_private_handle(&pin_namespace_directory(&directory).unwrap()).unwrap();
        assert_eq!(
            std::fs::read(directory.join("namespace.secret")).unwrap(),
            bytes
        );
        assert!(!parent.join("installer-admission-v2.secret").exists());
        // The inherited parent was not replaced with an exact-private DACL.
        assert!(check_private_handle(&pin_namespace_directory(&parent).unwrap()).is_err());
    }
    #[test]
    fn unsafe_existing_dedicated_namespace_directory_refuses_without_repair() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        let parent = profile.join(".csq");
        std::fs::create_dir(&parent).unwrap();
        assert_fixture_parent_safe(&parent);
        let directory = parent.join("installer-admission-v2");
        std::fs::create_dir(&directory).unwrap();
        grant_null_dacl(&directory);
        let error = namespace_secret_from_profile(&profile).unwrap_err();
        assert_eq!(classify(&error), "namespace_directory_unsafe");
        assert!(!directory.join(SECRET_FILE).exists());
        assert!(check_private_handle(&pin_namespace_directory(&directory).unwrap()).is_err());
    }
    #[test]
    fn interrupted_private_temp_does_not_occupy_published_secret_name() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        let parent = profile.join(".csq");
        std::fs::create_dir(&parent).unwrap();
        assert_fixture_parent_safe(&parent);
        let directory = parent.join("installer-admission-v2");
        create_private_directory(&directory).unwrap();
        let stray = directory.join(".namespace-secret-interrupted.tmp");
        let pin = pin(&directory);
        drop(create_namespace_secret(&pin, ".namespace-secret-interrupted.tmp").unwrap());
        let bytes = namespace_secret_from_profile(&profile).unwrap();
        assert_eq!(std::fs::read(directory.join(SECRET_FILE)).unwrap(), bytes);
        assert_eq!(bytes.len(), 16);
        assert!(stray.exists());
        assert!(std::fs::read(stray).unwrap().is_empty());
    }
    #[test]
    fn prepared_secret_is_private_and_unpublished_until_atomic_publication() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let pin = pin(sandbox.path());
        let path = sandbox.path().join(SECRET_FILE);
        let (leaf, interrupted) = prepare_namespace_secret(&pin).unwrap();
        let interrupted_path = sandbox.path().join(&leaf);
        assert!(
            !path.exists(),
            "unflushed/unpublished creation must not occupy the final name"
        );
        // The temp is created share-0, so it is checked through its own handle
        // (a second open on the path is refused by design).
        assert_eq!(interrupted.metadata().unwrap().len(), 16);
        check_private_handle(&interrupted).unwrap();
        let bytes = namespace_secret_at(&pin).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        require_namespace_child(&pin, &interrupted, &leaf).unwrap();
        println!(
            "S2A_NATIVE_CONTAINMENT_POSITIVE parent_volume_leaf=verified secret_written_bytes=16"
        );
        assert!(
            interrupted_path.exists(),
            "another invocation must not delete a foreign temp"
        );
        drop(interrupted);
    }
    #[test]
    fn profile_held_read_shared_does_not_block_admission() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        let parent = profile.join(".csq");
        std::fs::create_dir(&parent).unwrap();
        assert_fixture_parent_safe(&parent);
        let directory = parent.join("installer-admission-v2");
        create_private_directory(&directory).unwrap();
        // A same-user process holds the PROFILE with a data access of its own
        // and shares only READ. A write-class request on the profile pin
        // (FILE_ADD_FILE) would be refused here, so admission succeeds only
        // while the profile and `.csq` pins stay read-class.
        let _holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&profile)
            .unwrap();
        assert!(namespace_secret_from_profile(&profile).is_ok());
    }
    #[test]
    fn read_shared_parent_and_installation_holders_report_namespace_path_busy() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        let parent = profile.join(".csq");
        create_private_directory(&parent).unwrap();
        let directory = parent.join("installer-admission-v2");
        create_private_directory(&directory).unwrap();
        let _holders: Vec<_> = [&parent, &directory]
            .into_iter()
            .map(|path| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                    .open(path)
                    .unwrap()
            })
            .collect();
        let error = namespace_secret_from_profile(&profile).unwrap_err();
        assert_eq!(classify(&error), "namespace_path_busy");
        assert!(!directory.join(SECRET_FILE).exists());
    }
    #[test]
    fn namespace_secret_until_bails_when_the_final_is_deleted_after_every_publish() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let pin = pin(sandbox.path());
        let path = sandbox.path().join(SECRET_FILE);
        // Seam: remove the published final before the bounded reopen — exactly
        // what a same-user process does to spin the loop forever.
        let deletions = Rc::new(std::cell::Cell::new(0));
        let hook_deletions = Rc::clone(&deletions);
        let deleted_path = path.clone();
        AFTER_PUBLISH.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::remove_file(&deleted_path)
                    .expect("the published final must exist and be deletable before reopen");
                hook_deletions.set(hook_deletions.get() + 1);
            }));
        });
        let result = namespace_secret_until(&pin, Instant::now() + Duration::from_millis(150));
        AFTER_PUBLISH.with(|hook| *hook.borrow_mut() = None);
        assert!(deletions.get() > 0, "the deletion hook must execute");
        assert!(!path.exists(), "the final must actually have been deleted");
        assert_eq!(
            classify(&result.unwrap_err()),
            "namespace_secret_busy",
            "a deleted-on-every-wake final must hit the deadline, not loop"
        );
    }
    #[test]
    fn profile_scope_does_not_pin_its_parent_directory() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        // The holder must carry a data access of its own — any read, write or
        // delete-class access — or it cannot block anything: a READ_CONTROL-only
        // share_mode(0) holder blocked neither a pin nor a rename in carrier run
        // 39901770273, while a writer-held temp does block write/rename/delete
        // (chat_sessions control, same run). Read access makes this test able to
        // fail.
        let _exclusive_parent = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(sandbox.path())
            .unwrap();
        assert!(namespace_secret_from_profile(&profile).is_ok());
    }
    #[test]
    fn publication_loser_removes_own_temp_without_replacing_winner() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let pin = pin(sandbox.path());
        let path = sandbox.path().join(SECRET_FILE);
        let winner = namespace_secret_at(&pin).unwrap();
        let (leaf, temporary) = prepare_namespace_secret(&pin).unwrap();
        assert!(!publish_namespace_secret(&pin, &temporary).unwrap());
        drop(temporary);
        assert!(!sandbox.path().join(&leaf).exists());
        assert_eq!(namespace_secret_at(&pin).unwrap(), winner);
        assert_eq!(std::fs::read(path).unwrap(), winner);
    }
    #[test]
    fn existing_zero_length_final_refuses_without_repair_or_removal() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let pin = pin(sandbox.path());
        let path = sandbox.path().join(SECRET_FILE);
        // Explicit legacy/unsafe FINAL fixture, not the new creation protocol.
        drop(create_namespace_secret(&pin, SECRET_FILE).unwrap());
        assert_eq!(
            classify(&namespace_secret_at(&pin).unwrap_err()),
            "namespace_secret_size"
        );
        assert!(path.exists());
        assert!(std::fs::read(path).unwrap().is_empty());
    }
    #[test]
    fn pinned_directory_sharing_violation_has_distinct_transient_tag() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        // The blocker must hold a data access of its own — any read, write or
        // delete-class access. A handle opened with READ_CONTROL only and
        // share_mode(0) did not make the directory busy on Windows Server 2025
        // (carrier run 39901770273: this pin returned Ok under it); read access
        // does, as the chat_sessions control shows on the same OS.
        let exclusive = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(sandbox.path())
            .unwrap();
        let error = pin_namespace_directory(sandbox.path()).unwrap_err();
        assert_eq!(classify(&error), "namespace_path_busy");
        drop(exclusive);
        assert!(pin_namespace_directory(sandbox.path()).is_ok());
    }
    #[test]
    fn pinned_directory_refuses_rename_and_remove_until_the_pin_is_dropped() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let pinned = sandbox.path().join("namespace");
        std::fs::create_dir(&pinned).unwrap();
        let moved = sandbox.path().join("namespace-moved");
        let pin = pin_namespace_directory(&pinned).unwrap();
        // Positive half: the held pin shares READ | WRITE but never DELETE, and
        // a rename or a removal needs delete access. Assert the share-check
        // refusal itself (ERROR_SHARING_VIOLATION, 32), not any error.
        let rename = std::fs::rename(&pinned, &moved).unwrap_err();
        assert_eq!(
            rename.raw_os_error(),
            Some(32),
            "rename while pinned: {rename:?}"
        );
        assert!(pinned.is_dir(), "a refused rename must leave the directory");
        assert!(
            !moved.exists(),
            "a refused rename must not create its target"
        );
        let remove = std::fs::remove_dir(&pinned).unwrap_err();
        assert_eq!(
            remove.raw_os_error(),
            Some(32),
            "remove_dir while pinned: {remove:?}"
        );
        assert!(
            pinned.is_dir(),
            "a refused removal must leave the directory"
        );
        // Negative control: once the pin is dropped the same removal succeeds,
        // so the refusals above are attributable to the held pin.
        drop(pin);
        std::fs::remove_dir(&pinned).expect("remove_dir must succeed after the pin is released");
        assert!(!pinned.exists());
    }
    #[test]
    fn control_a_read_control_only_holder_does_not_block_the_delete_probe() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let directory = sandbox.path().join("control");
        std::fs::create_dir(&directory).unwrap();
        // Instrument control for the pin tests. This holder requests only
        // standard rights and share_mode(0), so it asks for none of the
        // read/write/delete classes the share check compares and must NOT block
        // a DELETE open. That is the shape carrier run 39901770273 measured as
        // non-blocking (it blocked neither a pin nor a rename). If this holder
        // blocked the probe, the probe could not tell a non-participating pin
        // from a participating one.
        let holder = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | SYNCHRONIZE)
            .share_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&directory)
            .unwrap();
        let probe = delete_probe(&directory)
            .expect("a READ_CONTROL | SYNCHRONIZE holder must not block a DELETE open");
        drop(probe);
        drop(holder);
    }
    /// Opens a directory with DELETE access and every share flag — the shape a
    /// rename or a delete of it needs — so the pins' share mode is the only
    /// thing that can refuse it.
    fn delete_probe(directory: &Path) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .access_mode(DELETE_ACCESS)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(directory)
    }
    #[test]
    fn pinned_executable_ancestor_refuses_a_delete_open_until_the_pins_drop() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let ancestor = sandbox.path().join("ancestor");
        create_private_directory(&ancestor).unwrap();
        let ancestor_handle =
            crate::platform::fs_windows_acl::open_private_directory(&ancestor).unwrap();
        assert!(file_owned(&ancestor_handle).unwrap());
        drop(ancestor_handle);
        let executable = ancestor.join("csq.exe");
        let mut executable_handle =
            crate::platform::fs_windows_acl::create_new_private_file(&executable).unwrap();
        executable_handle.write_all(b"fixture").unwrap();
        assert!(file_owned(&executable_handle).unwrap());
        drop(executable_handle);
        let mut pins = pin_ancestry(&executable).unwrap();
        // The file pin denies ALL sharing, so while it is held anything inside
        // the ancestor fails for that reason alone and cannot discriminate the
        // directory pins (R1 finding). Drop it first: this test is about the
        // ancestor DIRECTORY pin, probed directly.
        drop(pins.remove(0));
        let error = delete_probe(&ancestor).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(32),
            "DELETE open of a pinned ancestor: {error:?}"
        );
        // Negative control: drop only the directory pins; the same open succeeds.
        drop(pins);
        drop(
            delete_probe(&ancestor)
                .expect("the DELETE open must succeed once the directory pins are dropped"),
        );
    }
    /// Reads the secret back through the pin and returns its file identity, so a
    /// test can prove the bytes came from the directory OBJECT the pin holds
    /// rather than from whatever the path currently resolves to.
    fn read_by_handle_and_id(directory: &File) -> ([u8; SECRET_BYTES], (u32, u32, u32)) {
        let bytes = namespace_secret_at(directory).unwrap();
        let first = open_relative(
            directory,
            SECRET_FILE,
            READ_CONTROL | 0x8000_0000,
            FILE_SHARE_READ,
            FILE_OPEN,
            std::ptr::null(),
        )
        .unwrap();
        let id = file_id(&first);
        drop(first);
        let second = open_relative(
            directory,
            SECRET_FILE,
            READ_CONTROL | 0x8000_0000,
            FILE_SHARE_READ,
            FILE_OPEN,
            std::ptr::null(),
        )
        .unwrap();
        assert_eq!(
            file_id(&second),
            id,
            "the handle-relative read must be stable"
        );
        drop(second);
        (bytes, id)
    }
    fn file_id(file: &File) -> (u32, u32, u32) {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: live retained handle and initialized output structure.
        assert_ne!(
            unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) },
            0
        );
        (
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        )
    }
    #[test]
    fn pinned_directory_junction_refuses_without_partial_secret_or_redirection() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let positive = sandbox.path().join("positive");
        create_private_directory(&positive).unwrap();
        let positive_pin = pin(&positive);
        let (bytes, id) = read_by_handle_and_id(&positive_pin);
        assert_eq!(namespace_secret_at(&positive_pin).unwrap(), bytes);
        assert_ne!(id, (0, 0, 0));
        let target = sandbox.path().join("target");
        create_private_directory(&target).unwrap();
        let directory = sandbox.path().join("namespace");
        create_private_directory(&directory).unwrap();
        let pin = pin(&directory);
        let original_id = file_id(&pin);
        let absent = open_relative(
            &pin,
            SECRET_FILE,
            READ_CONTROL | 0x8000_0000,
            FILE_SHARE_READ,
            FILE_OPEN,
            std::ptr::null(),
        )
        .unwrap_err();
        assert_eq!(
            absent
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(2)
        );
        let control = Rc::new(std::cell::RefCell::new(None));
        let saved_control = Rc::clone(&control);
        let planted_directory = directory.clone();
        let planted_target = target.clone();
        // Plant a real junction AFTER the retained metadata check. This forces
        // the native reparse-resolution race branch, not just the precheck.
        BEFORE_NAMESPACE_CHILD.with(|hook| {
            *hook.borrow_mut() = Some((
                SECRET_FILE,
                Box::new(move || {
                    *saved_control.borrow_mut() = Some(
                        set_mount_point(&planted_directory, &planted_target)
                            .expect("the synthetic junction must actually be set"),
                    );
                }),
            ));
        });
        let error = namespace_secret_at(&pin)
            .unwrap_err()
            .context("namespace_secret_unavailable");
        assert!(error.is::<NamespaceDirectoryReparsed>());
        assert_eq!(classify(&error), "namespace_directory_reparsed");
        LAST_NAMESPACE_CHILD_ERROR.with(|last| assert_eq!(last.get(), Some(1921)));
        assert_ne!(
            pin.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert_eq!(file_id(&pin), original_id);
        // The already-reparsed precheck covers open, CREATE_NEW and publication.
        assert!(namespace_secret_at(&pin)
            .unwrap_err()
            .is::<NamespaceDirectoryReparsed>());
        assert!(create_namespace_secret(&pin, "probe.tmp")
            .unwrap_err()
            .is::<NamespaceDirectoryReparsed>());
        let (leaf, temporary) = prepare_namespace_secret(&positive_pin).unwrap();
        assert!(publish_namespace_secret(&pin, &temporary)
            .unwrap_err()
            .is::<NamespaceDirectoryReparsed>());
        drop(temporary);
        assert!(
            !positive.join(leaf).exists(),
            "owned temp cleanup must still run"
        );
        assert!(std::fs::read_dir(&target).unwrap().next().is_none());
        // Clear ONLY the junction this test set, using its retained setter
        // handle. Then inspect the original directory for secret/temp residue.
        clear_test_mount_point(control.borrow().as_ref().expect("junction setter ran")).unwrap();
        assert_eq!(
            pin.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert_eq!(file_id(&pin), original_id);
        assert!(std::fs::read_dir(&directory).unwrap().next().is_none());
        assert!(std::fs::read_dir(&target).unwrap().next().is_none());
    }
    #[test]
    fn empty_pinned_csq_parent_junction_refuses_relative_child_creation() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        let parent = profile.join(".csq");
        create_private_directory(&parent).unwrap();
        let target = sandbox.path().join("target");
        create_private_directory(&target).unwrap();
        let control = Rc::new(std::cell::RefCell::new(None));
        let saved_control = Rc::clone(&control);
        let planted_parent = parent.clone();
        let planted_target = target.clone();
        // The hook runs after the parent's retained-handle metadata check,
        // immediately before the native child DIRECTORY open/create.
        BEFORE_NAMESPACE_CHILD.with(|hook| {
            *hook.borrow_mut() = Some((
                "installer-admission-v2",
                Box::new(move || {
                    *saved_control.borrow_mut() = Some(
                        set_mount_point(&planted_parent, &planted_target)
                            .expect("the empty pinned .csq junction must actually be set"),
                    );
                }),
            ));
        });
        let error = namespace_secret_from_profile(&profile).unwrap_err();
        assert!(error.is::<NamespaceDirectoryReparsed>());
        assert_eq!(classify(&error), "namespace_directory_reparsed");
        LAST_NAMESPACE_CHILD_ERROR.with(|last| assert_eq!(last.get(), Some(1921)));
        assert!(std::fs::read_dir(&target).unwrap().next().is_none());
        clear_test_mount_point(control.borrow().as_ref().expect("junction setter ran")).unwrap();
        assert!(std::fs::read_dir(&parent).unwrap().next().is_none());
        assert!(std::fs::read_dir(&target).unwrap().next().is_none());
    }
    #[test]
    fn created_file_parent_identity_must_match_the_retained_namespace() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let first = sandbox.path().join("first");
        let second = sandbox.path().join("second");
        create_private_directory(&first).unwrap();
        create_private_directory(&second).unwrap();
        let first_pin = pin(&first);
        let second_pin = pin(&second);
        let file = create_namespace_secret(&first_pin, "unwritten.tmp").unwrap();
        require_namespace_child(&first_pin, &file, "unwritten.tmp").unwrap();
        let error = require_namespace_child(&second_pin, &file, "unwritten.tmp").unwrap_err();
        assert!(error.is::<NamespaceDirectoryReparsed>());
        assert_eq!(file.metadata().unwrap().len(), 0);
        remove_open_file(&file).unwrap();
        drop(file);
        assert!(std::fs::read_dir(&first).unwrap().next().is_none());
        assert!(std::fs::read_dir(&second).unwrap().next().is_none());
    }
    #[test]
    fn publication_and_cleanup_failures_preserve_typed_reparse_and_cleanup_context() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let path = sandbox.path().join("nonsecret-cleanup-failure-probe");
        std::fs::write(&path, b"probe").unwrap();
        // A real file handle without DELETE makes native handle cleanup fail.
        let file = File::open(&path).unwrap();
        let error =
            publish_namespace_secret_using(&file, |_| Err(NamespaceDirectoryReparsed.into()))
                .unwrap_err();
        assert!(error.is::<NamespaceDirectoryReparsed>());
        assert_eq!(classify(&error), "namespace_directory_reparsed");
        assert!(error
            .chain()
            .any(|e| e.to_string() == "namespace_secret_cleanup"));
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
    fn clear_test_mount_point(directory: &File) -> std::io::Result<()> {
        use windows_sys::Win32::System::IO::DeviceIoControl;
        let header = [0xA000_0003u32, 0]; // Microsoft mount-point tag; zero data length.
        let mut returned = 0;
        // SAFETY: exact test-created junction's retained writable setter handle;
        // the eight-byte header names only that tag, and no pathname is resolved.
        let ok = unsafe {
            DeviceIoControl(
                directory.as_raw_handle() as HANDLE,
                0x0009_00AC,
                header.as_ptr().cast(),
                8,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[test]
    fn nonempty_unpinned_parent_refuses_junction_and_pinned_child_keeps_custody() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let target = sandbox.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let control = sandbox.path().join("empty-control");
        std::fs::create_dir(&control).unwrap();
        set_mount_point(&control, &target)
            .expect("the same junction operation must succeed on an empty directory");
        let parent = sandbox.path().join("parent");
        std::fs::create_dir(&parent).unwrap();
        let directory = parent.join("child");
        std::fs::create_dir(&directory).unwrap();
        let pin = pin(&directory);
        // A parent containing the pinned child is nonempty. The native junction
        // operation refuses that precondition; the empty control above proves
        // the probe itself works. The separate pinned-empty-directory test
        // exercises typed refusal while retaining handle custody.
        let error = set_mount_point(&parent, &target).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(145),
            "nonempty parent: {error:?}"
        );
        assert_eq!(
            std::fs::symlink_metadata(&parent)
                .unwrap()
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT,
            0,
            "the refused operation must leave the parent unreparsed"
        );
        let (bytes, _) = read_by_handle_and_id(&pin);
        assert_eq!(bytes.len(), 16);
        let entries: Vec<_> = std::fs::read_dir(&target).unwrap().collect();
        assert!(
            entries.is_empty(),
            "a parent junction must not receive the secret, found {entries:?}"
        );
        drop(pin);
    }
    #[test]
    fn already_junctioned_namespace_directory_refuses_the_next_admission() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        let target = sandbox.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let parent = profile.join(".csq");
        std::fs::create_dir(&parent).unwrap();
        assert_fixture_parent_safe(&parent);
        let directory = parent.join("installer-admission-v2");
        std::fs::create_dir(&directory).unwrap();
        // An attacker leaves the dedicated directory as a junction. The next
        // admission must refuse it, never follow it, and leave the target empty.
        set_mount_point(&directory, &target).expect("the junction must set before admission");
        let error = namespace_secret_from_profile(&profile).unwrap_err();
        assert_eq!(classify(&error), "namespace_directory_reparsed");
        let entries: Vec<_> = std::fs::read_dir(&target).unwrap().collect();
        assert!(
            entries.is_empty(),
            "a refused junction must receive nothing, found {entries:?}"
        );
    }
    /// Sets a directory junction (IO_REPARSE_TAG_MOUNT_POINT) on an EXISTING
    /// directory, the way an attacker would redirect a pinned path. Both arms
    /// target a fixture directory inside the sandbox, never the system drive.
    fn set_mount_point(directory: &Path, target: &Path) -> std::io::Result<File> {
        use windows_sys::Win32::System::IO::DeviceIoControl;
        const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
        const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
        let target_abs = target.canonicalize()?;
        let target_full = target_abs.to_string_lossy();
        let target_str = target_full.strip_prefix(r"\\?\").unwrap_or(&target_full);
        let substitute: Vec<u16> = format!(r"\??\{target_str}").encode_utf16().collect();
        let print: Vec<u16> = target_str.encode_utf16().collect();
        let mut path_buf: Vec<u16> = Vec::new();
        path_buf.extend_from_slice(&substitute);
        path_buf.push(0);
        path_buf.extend_from_slice(&print);
        path_buf.push(0);
        let path_bytes: Vec<u8> = path_buf.iter().flat_map(|w| w.to_le_bytes()).collect();
        let substitute_len = (substitute.len() * 2) as u16;
        let print_len = (print.len() * 2) as u16;
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
        buffer.extend_from_slice(&((8 + path_bytes.len()) as u16).to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buffer.extend_from_slice(&substitute_len.to_le_bytes());
        buffer.extend_from_slice(&(substitute_len + 2).to_le_bytes()); // PrintNameOffset
        buffer.extend_from_slice(&print_len.to_le_bytes());
        buffer.extend_from_slice(&path_bytes);
        let handle = std::fs::OpenOptions::new()
            .access_mode(
                FILE_WRITE_DATA_ACCESS | FILE_WRITE_ATTRIBUTES_ACCESS | READ_CONTROL | SYNCHRONIZE,
            )
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(directory)?;
        let mut returned = 0u32;
        // SAFETY: the handle is live for the call, the buffer is a fully
        // initialised mount-point REPARSE_DATA_BUFFER, and the control code
        // takes no output buffer.
        let ok = unsafe {
            DeviceIoControl(
                handle.as_raw_handle() as HANDLE,
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(handle)
    }
    #[test]
    fn broad_secret_dacl_refuses_without_rewriting_existing_bytes() {
        let _env = crate::platform::test_env::lock();
        use windows_sys::Win32::Security::{
            Authorization::SetNamedSecurityInfoW, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let sandbox = tempfile::tempdir().unwrap();
        let pin = pin(sandbox.path());
        let path = sandbox.path().join(SECRET_FILE);
        let bytes = namespace_secret_at(&pin).unwrap();
        let name = wide(path.as_os_str()).unwrap();
        // SAFETY: own disposable fixture, NULL DACL intentionally grants all.
        assert_eq!(
            unsafe {
                SetNamedSecurityInfoW(
                    name.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let error = namespace_secret_at(&pin).unwrap_err();
        assert_eq!(classify(&error), "namespace_secret_acl");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
    fn set_fixture_parent_dacl(path: &Path, grants: &str) {
        use windows_sys::Win32::Security::{
            Authorization::SetNamedSecurityInfoW, GetSecurityDescriptorDacl,
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let text = text_wide(&format!(
            "D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){grants}",
            current_sid().unwrap()
        ))
        .unwrap();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: test-owned SDDL, API allocates one descriptor.
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl = std::ptr::null_mut();
        // SAFETY: live API-created descriptor and initialized outputs.
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        let name = wide(path.as_os_str()).unwrap();
        // SAFETY: only this test's disposable TempDir object is modified.
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        // SAFETY: sole descriptor after final borrowed DACL use.
        unsafe {
            LocalFree(descriptor);
        }
        assert_eq!(status, 0);
    }
    #[test]
    fn null_dacl_profile_and_csq_parent_refuse_before_secret_creation() {
        let _env = crate::platform::test_env::lock();
        for poison_profile in [true, false] {
            let sandbox = tempfile::tempdir().unwrap();
            let profile = safe_profile(sandbox.path());
            let parent = profile.join(".csq");
            std::fs::create_dir(&parent).unwrap();
            assert_fixture_parent_safe(&parent);
            grant_null_dacl(if poison_profile { &profile } else { &parent });
            let error = namespace_secret_from_profile(&profile).unwrap_err();
            assert_eq!(classify(&error), "namespace_parent_unsafe");
            assert!(!parent.join("installer-admission-v2").exists());
        }
    }
    #[test]
    fn foreign_mutation_grants_on_profile_and_parent_refuse() {
        let _env = crate::platform::test_env::lock();
        for mask in [
            0x00010000u32,
            0x40,
            4,
            0x02,
            0x100,
            0x00040000,
            0x00080000,
            0x40000000,
            0x10000000,
        ] {
            for poison_profile in [true, false] {
                let sandbox = tempfile::tempdir().unwrap();
                let profile = safe_profile(sandbox.path());
                let parent = profile.join(".csq");
                std::fs::create_dir(&parent).unwrap();
                assert_fixture_parent_safe(&parent);
                let poisoned = if poison_profile { &profile } else { &parent };
                set_fixture_parent_dacl(poisoned, &format!("(A;;0x{mask:08x};;;WD)"));
                let error = namespace_secret_from_profile(&profile).unwrap_err();
                assert_eq!(
                    classify(&error),
                    "namespace_parent_unsafe",
                    "mask={mask:08x}"
                );
                assert!(!parent.join("installer-admission-v2").exists());
            }
        }
    }
    #[test]
    fn harmless_foreign_read_and_inherit_only_parent_grants_pass() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let profile = safe_profile(sandbox.path());
        let parent = profile.join(".csq");
        std::fs::create_dir(&parent).unwrap();
        assert_fixture_parent_safe(&parent);
        set_fixture_parent_dacl(&parent, "(A;;GRGX;;;WD)(A;OIIO;GA;;;WD)(A;OIIO;GA;;;CO)");
        assert!(namespace_secret_from_profile(&profile).is_ok());
    }
    #[test]
    fn completed_first_publication_is_reopened_after_initial_deadline() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let pin = pin(sandbox.path());
        let path = sandbox.path().join(SECRET_FILE);
        let bytes = namespace_secret_until(&pin, Instant::now() - Duration::from_secs(1)).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    #[test]
    fn publication_retries_a_transient_sharing_violation_before_the_deadline() {
        let _env = crate::platform::test_env::lock();
        let sandbox = tempfile::tempdir().unwrap();
        let pin = pin(sandbox.path());
        let path = sandbox.path().join(SECRET_FILE);
        let (leaf, temporary) = prepare_namespace_secret(&pin).unwrap();
        // A second in-process holder on the temp is no longer constructible: the
        // temp is created share-0 and STAYS open because publication renames
        // through that handle. The seam injects the same
        // ERROR_SHARING_VIOLATION(32) that an external holder (scanner,
        // indexer) causes on Windows; the second attempt is the REAL
        // handle-relative rename through the pin.
        let mut calls = 0;
        assert!(publish_namespace_secret_using(&temporary, |leaf| {
            assert_eq!(leaf, SECRET_FILE, "publication must target the final leaf");
            calls += 1;
            if calls == 1 {
                Err(std::io::Error::from_raw_os_error(32).into())
            } else {
                rename_namespace_secret(&pin, &temporary, leaf)
            }
        })
        .unwrap());
        assert_eq!(calls, 2);
        // Publication retains the renamed share-0 handle until the caller
        // closes it. Production closes it before reopening the final too.
        drop(temporary);
        assert!(!sandbox.path().join(&leaf).exists());
        assert_eq!(namespace_secret_at(&pin).unwrap().len(), 16);
        assert_eq!(std::fs::read(path).unwrap().len(), 16);
    }
}
