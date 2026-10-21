//! At-creation protected owner-only DACLs; existing broad ACLs are refused.
//!
//! The ONE owner-only Windows file primitive in csq-core. A file or
//! directory is created with the protected descriptor
//! `O:<user-sid>D:P(A;;FA;;;<user-sid>)S:(ML;;NWNR;;;ME)` passed to
//! `CreateFileW` / `CreateDirectoryW`: no inherited ACE ever applies to the DACL, and
//! the Medium label with no-write-up and no-read-up is meant to keep a
//! Low-integrity process of the same user from reading it. Every opened handle is
//! re-checked against that shape ([`check_private_handle`]).
//!
//! The SACL is deliberately NOT marked protected, at creation or when stamping:
//! inference from Windows CI run 39017142175 (os error 1314, ERROR_PRIVILEGE_NOT_HELD,
//! on every write once `S:P(...)` and `PROTECTED_SACL_SECURITY_INFORMATION` were used,
//! while the unprotected forms passed natively in run 39014859238) is that changing
//! SACL protection is a SACL control change needing `SeSecurityPrivilege`. csq never
//! touches SACL protection, so a parent's inheritable AUDIT ACEs propagate as usual.
//!
//! Scope of that read protection: it holds for objects csq CREATED or STAMPED
//! since the label was introduced. A file written by an older csq has the owner
//! and DACL but no label, so it stays readable at Low integrity until csq next
//! writes or opens it: [`super::fs_windows_stamp::ensure_private_handle`] then stamps the label through the
//! owner's own handle (needs `WRITE_OWNER`) and re-verifies, failing closed when it
//! cannot; [`check_private_handle`] itself never accepts a missing label. Objects
//! csq never opens or rewrites stay as they were. The owner, DACL, link-count and
//! reparse conditions of the callers still apply on top.
//!
//! Inherited labels. The SACL is not protected, so a parent's inheritable label can
//! come to sit beside ours, but only by PROPAGATION onto an existing object (the parent
//! is labeled after the object was made). NATIVE EVIDENCE (Windows
//! run 39043270693): CREATING a file with csq's explicit `S:(ML;;NWNR;;;ME)` under a
//! parent with an inheritable Medium label yields ONLY the explicit ACE; the inherited
//! label does not stack at creation, so a new csq file carries one label ACE whatever its
//! parent's inheritable label is. The two-ACE layout was observed only by labeling the
//! parent after the file existed (`SetNamedSecurityInfoW`); a legacy file with no SACL
//! under such a parent carries just the inherited ACE. Among the label ACEs that APPLY to
//! the object (an inherited inherit-only ACE does not), `Present` requires exactly ONE
//! explicit label ACE that is exactly Medium NW|NR and comes FIRST, plus zero or more
//! inherited ACEs that are each exactly Medium AND carry the full NW|NR mask. An inherited
//! Medium NW|NR label next to our explicit one is harmless in the cases we can reason
//! about: same level, so the integrity comparison is identical, and the policy bits are
//! the same. NOT verified: how Windows evaluates several label ACEs on one object. The
//! documented model is a single mandatory label and the kernel is believed to use the
//! first label ACE it finds; requiring ours first, and every other applicable label to
//! carry NW|NR too, means that either evaluation (first wins, or policies merged) yields
//! no-read-up at Medium. Any other layout is refused (fail closed) rather than reasoned
//! about. An inherited label below Medium (Low-writable; a Low planter can give the object
//! the exact owner and DACL), above it (stamping would lower it), short of NW or NR, or
//! malformed is refused with `PrivateAclError::InheritedLabel` and never stamped. So a
//! legacy file (no SACL) under a parent carrying only an NW-only inheritable Medium label
//! (the default `icacls /setintegritylevel (OI)(CI)M`), and an object that acquires such a
//! label by propagation, are refused, not stamped (`open_private_*` fail closed); a NEW
//! csq file under that parent is not affected (it carries only its explicit ACE). The
//! refusal is logged once per process (`note_refusal`), not per file. With no explicit
//! label and only acceptable inherited ones (or none) the object is `Absent`:
//! [`super::fs_windows_stamp::ensure_private_handle`] stamps our label (`LABEL_SECURITY_INFORMATION` only) and
//! re-verifies. An explicit label that is not exactly ours is refused, never rewritten.
//! Consumers: `platform::fs::write_new_private*` and the chat-session store,
//! which maps [`PrivateAclError`] into its own error type.
use super::fs_windows_stamp::ensure_private_handle;
use super::label_level::{inherited_label_may_sit_beside, label_rid, MEDIUM_RID};
use std::{
    ffi::c_void,
    fs::File,
    io, mem,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, LocalFree, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
        },
        EqualSid, GetAce, GetSecurityDescriptorControl, GetTokenInformation, IsValidSid, TokenUser,
        ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, TOKEN_QUERY,
        TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, CREATE_NEW, DELETE, FILE_ALL_ACCESS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_ALWAYS, OPEN_EXISTING, WRITE_OWNER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// Failure of an owner-only ACL operation.
#[derive(Debug)]
pub enum PrivateAclError {
    /// The OS refused the create/open itself; carries the OS error so a
    /// caller can still distinguish `AlreadyExists` / `NotFound`.
    Os(io::Error),
    /// Building the owner-only security descriptor (process token, SID
    /// text, SDDL conversion) failed. Fail-closed: no file was opened.
    Descriptor,
    /// The path is unusable (interior NUL) or the opened handle does not carry
    /// the private shape: owner, exactly the protected owner-only DACL, and the
    /// one explicit Medium NW|NR label (a legacy object lacking only the label is
    /// upgraded by `ensure_private_handle`, not refused by it).
    UnsafePath,
    /// The object carries an INHERITED mandatory label that is not exactly one csq may
    /// sit beside (a different level, no NR, or malformed): a parent was relabelled.
    /// Refused like `UnsafePath`; distinct so the cause is diagnosable.
    InheritedLabel,
}
impl std::fmt::Display for PrivateAclError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Os(e) => write!(f, "owner-only open failed: {e}"),
            Self::Descriptor => f.write_str("owner-only security descriptor setup failed"),
            Self::UnsafePath => f.write_str("path is not owner-only"),
            Self::InheritedLabel => f.write_str("path carries an unacceptable inherited label"),
        }
    }
}
impl std::error::Error for PrivateAclError {}
impl From<PrivateAclError> for io::Error {
    fn from(error: PrivateAclError) -> Self {
        match error {
            PrivateAclError::Os(e) => e,
            PrivateAclError::Descriptor => {
                io::Error::other("owner-only security descriptor setup failed")
            }
            PrivateAclError::UnsafePath => {
                io::Error::new(io::ErrorKind::PermissionDenied, "path is not owner-only")
            }
            PrivateAclError::InheritedLabel => io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path carries an unacceptable inherited label",
            ),
        }
    }
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one successful token handle.
        if unsafe { CloseHandle(self.0) } == 0 {
            tracing::warn!(
                error_kind = "private_acl_token_close_failed",
                "owner-only ACL security handle cleanup failed"
            );
        }
    }
}
/// Owns one `LocalAlloc`-backed buffer (security descriptors, SID strings) and frees it on
/// drop. The pointer is private: a `Local` can only be built by the `unsafe`
/// [`Local::from_local_alloc`], whose caller vouches that the pointer is the sole owner of
/// a `LocalAlloc` allocation (or null), and read through [`Local::as_ptr`].
pub(super) struct Local(*mut c_void);
impl Local {
    /// # Safety
    /// `ptr` must be null or a pointer returned by a `LocalAlloc`-backed API
    /// (`ConvertStringSecurityDescriptorToSecurityDescriptorW`, `ConvertSidToStringSidW`,
    /// `GetSecurityInfo`'s descriptor, ...) that nothing else frees, so that `LocalFree`
    /// on drop is the one release.
    pub(super) unsafe fn from_local_alloc(ptr: *mut c_void) -> Self {
        Self(ptr)
    }
    /// The borrowed pointer; valid for as long as `self` lives.
    pub(super) fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: all wrapped buffers were allocated by LocalAlloc-backed APIs.
        if !self.0.is_null() && !unsafe { LocalFree(self.0) }.is_null() {
            tracing::warn!(
                error_kind = "private_acl_security_cleanup_failed",
                "owner-only ACL security allocation cleanup failed"
            );
        }
    }
}
struct User(Vec<usize>);
impl User {
    fn current() -> Result<Self, PrivateAclError> {
        let mut handle = 0;
        // SAFETY: pseudo process handle is valid; output points to a live slot.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
            return Err(PrivateAclError::Descriptor);
        }
        let token = Handle(handle);
        let mut needed = 0;
        // SAFETY: null zero-length buffer is the documented size query.
        unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
        if needed < mem::size_of::<TOKEN_USER>() as u32 || needed > 65536 {
            return Err(PrivateAclError::Descriptor);
        }
        let mut buffer = vec![0usize; (needed as usize).div_ceil(mem::size_of::<usize>())];
        // SAFETY: usize storage supplies TOKEN_USER alignment and needed capacity.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(PrivateAclError::Descriptor);
        }
        Ok(Self(buffer))
    }
    fn sid(&self) -> *mut c_void {
        // SAFETY: buffer was filled successfully as TOKEN_USER and remains owned.
        unsafe { (*(self.0.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}
fn descriptor() -> Result<Local, PrivateAclError> {
    descriptor_with(DescriptorKind::File)
}
/// Which owner-only descriptor [`descriptor_text`] renders.
#[derive(Clone, Copy, Debug)]
pub(super) enum DescriptorKind {
    /// Files and directories: `O:<sid>D:P(A;;FA;;;<sid>)S:(ML;;NWNR;;;ME)` —
    /// owner, protected DACL and the Medium mandatory label with no-write-up
    /// and no-read-up. [`check_private_handle`] re-checks exactly this shape.
    File,
    /// Named kernel objects (the `platform::lock` mutexes):
    /// `O:<sid>D:P(A;;GA;;;<sid>)S:(ML;;NW;;;ME)`.
    Object,
}
/// The label every private file and directory carries: Medium integrity, no
/// write up (`NW`) and no read up (`NR`). Without it the object has the implicit
/// Medium label with only no-write-up, so a Low-integrity process of the same
/// user (a sandboxed child) could READ it past the owner-only DACL. Not protected
/// (`S:P`): changing SACL protection needs a privilege csq does not hold.
pub(super) const FILE_LABEL_SDDL: &str = "S:(ML;;NWNR;;;ME)";
/// `SYSTEM_MANDATORY_LABEL_ACE_TYPE` (WinNT.h).
const LABEL_ACE_TYPE: u8 = 0x11;
/// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP`.
const LABEL_MASK: u32 = 0x1 | 0x2;
/// ACE flags (WinNT.h): `INHERIT_ONLY_ACE`, `INHERITED_ACE`.
const INHERIT_ONLY_ACE: u8 = 0x08;
const INHERITED_ACE: u8 = 0x10;

/// The SDDL text for an owner-only descriptor of `kind` owned by `sid`.
///
/// The `Object` form adds an explicit Medium mandatory label with the
/// no-write-up policy, so the mutex's integrity level never depends on the
/// creator's token: an elevated (High) and an unelevated (Medium) csq
/// process of the same user both open the SAME mutex. `CreateMutexW` on an
/// existing object requests `MUTEX_ALL_ACCESS`; at a Medium label a Medium
/// opener passes the integrity check for every right, so only the DACL
/// (owner-only) decides. A creator may set a label at or below its own
/// integrity level without `SeRelabelPrivilege`, so a High or Medium creator
/// sets `ME`; a Low-integrity creator cannot, and `CreateMutexW` then fails
/// — closed, no mutex. `NW` (no-write-up) denies a lower-integrity opener the
/// object's write rights (`DELETE`, `WRITE_DAC`, `WRITE_OWNER`, the generic
/// write mapping); `SYNCHRONIZE`, the right `WaitForSingleObject` needs, is
/// in the generic-execute mapping and is not blocked by `NW`.
pub(super) fn descriptor_text(sid: &str, kind: DescriptorKind) -> String {
    match kind {
        DescriptorKind::File => format!("O:{sid}D:P(A;;FA;;;{sid}){FILE_LABEL_SDDL}"),
        DescriptorKind::Object => format!("O:{sid}D:P(A;;GA;;;{sid})S:(ML;;NW;;;ME)"),
    }
}
/// Owner-only protected security descriptor for a named kernel object (the
/// `platform::lock` mutexes), rendered by [`descriptor_text`] as
/// [`DescriptorKind::Object`]. Generic all maps to the object's full rights
/// for the owner; the protected DACL carries no other ACE, so no other
/// principal can open the object; the explicit Medium label keeps elevated
/// and unelevated same-user processes on one mutex.
pub(crate) struct OwnerOnlyObjectSecurity(Local);
impl OwnerOnlyObjectSecurity {
    pub(crate) fn current_user() -> Result<Self, PrivateAclError> {
        descriptor_with(DescriptorKind::Object).map(Self)
    }
    /// Borrows the descriptor: the returned struct points into `self` and
    /// MUST NOT outlive it.
    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        attributes(&self.0)
    }
}
fn descriptor_with(kind: DescriptorKind) -> Result<Local, PrivateAclError> {
    let user = User::current()?;
    let mut string = ptr::null_mut();
    // SAFETY: SID resides in the live token-user buffer; output is LocalAlloc memory.
    if unsafe { ConvertSidToStringSidW(user.sid(), &mut string) } == 0 {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: `ConvertSidToStringSidW` succeeded: `string` is its LocalAlloc buffer.
    let string = unsafe { Local::from_local_alloc(string.cast()) };
    let mut len = 0;
    // SAFETY: API returned a NUL-terminated string; bound SID text to 256 chars.
    unsafe {
        while len < 256 && *string.as_ptr().cast::<u16>().add(len) != 0 {
            len += 1;
        }
    }
    if len == 256 {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: measured range belongs to the live returned string.
    let sid = String::from_utf16(unsafe {
        std::slice::from_raw_parts(string.as_ptr().cast::<u16>(), len)
    })
    .map_err(|_| PrivateAclError::Descriptor)?;
    let text: Vec<u16> = descriptor_text(&sid, kind)
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut result = ptr::null_mut();
    // SAFETY: complete NUL-terminated SDDL and live output slot; revision 1.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut result,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: the conversion succeeded: `result` is its LocalAlloc descriptor.
    Ok(unsafe { Local::from_local_alloc(result) })
}
/// `Ok(true)` iff the object behind `handle` is owned by the current user.
///
/// Used by `platform::lock` when `CreateMutexW` opened an EXISTING mutex, so
/// csq's own descriptor was never applied. `handle` MUST carry
/// `READ_CONTROL`. An owner that cannot be read is `Err` — callers refuse
/// (fail closed), never treat it as same-user.
pub(crate) fn object_owned_by_current_user(handle: HANDLE) -> Result<bool, PrivateAclError> {
    let user = User::current()?;
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: caller passes a live handle; output slots are valid and the
    // owner SID points into the returned descriptor, freed by `Local`.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    // SAFETY: `GetSecurityInfo` allocates the descriptor with LocalAlloc (null on failure).
    let descriptor = unsafe { Local::from_local_alloc(descriptor) };
    // SAFETY: owner is checked non-null and validated before comparison;
    // both SIDs stay alive (descriptor and token buffer) for the calls.
    if status != 0
        || descriptor.as_ptr().is_null()
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
    {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: as above.
    Ok(unsafe { EqualSid(owner, user.sid()) } != 0)
}
fn wide(path: &Path) -> Result<Vec<u16>, PrivateAclError> {
    let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(PrivateAclError::UnsafePath);
    }
    Ok(encoded.into_iter().chain(Some(0)).collect())
}
fn attributes(descriptor: &Local) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    }
}
pub(crate) fn create_private_directory(path: &Path) -> Result<(), PrivateAclError> {
    let path = wide(path)?;
    let security = descriptor()?;
    let attributes = attributes(&security);
    // SAFETY: path and descriptor stay alive throughout synchronous creation.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(PrivateAclError::Os(io::Error::last_os_error()));
    }
    Ok(())
}
/// Opens (or, with `create`, opens-or-creates) a private file and ENSURES it is
/// private ([`super::fs_windows_stamp::ensure_private_handle`]): a file written before the integrity
/// label existed is stamped through this owner handle, then re-verified.
///
/// An `exclusive` create is [`create_new_private_file`]: a handle that fails the
/// check is removed rather than leaving a non-private zero-byte file at the final
/// name. `WRITE_OWNER` (needed only to stamp the label) is requested on the open
/// path; when the OS denies that mask the file is reopened without it, and the
/// check then judges it (a foreign or broad file is refused, never rewritten).
pub(crate) fn open_private_file(
    path: &Path,
    create: bool,
    exclusive: bool,
) -> Result<File, PrivateAclError> {
    if exclusive {
        return create_new_private_file(path);
    }
    let disposition = if create { OPEN_ALWAYS } else { OPEN_EXISTING };
    open_ensured(path, disposition, GENERIC_READ | GENERIC_WRITE)
}
/// Opens an EXISTING file read-only (`GENERIC_READ`, plus `WRITE_OWNER` only for the
/// label stamp, dropped on ACCESS_DENIED) and ensures it is private. For a file
/// the operator owns and csq only reads (the pool `.env`): a missing label is
/// stamped, which only tightens; a wrong owner, broad DACL or other label is refused.
pub(crate) fn open_private_readable(path: &Path) -> Result<File, PrivateAclError> {
    open_ensured(path, OPEN_EXISTING, GENERIC_READ)
}
fn open_ensured(
    path: &Path,
    disposition: windows_sys::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
    access: u32,
) -> Result<File, PrivateAclError> {
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let file = match open_with_descriptor(path, disposition, access | WRITE_OWNER, share) {
        Err(PrivateAclError::Os(error)) if error.raw_os_error() == Some(5) => {
            open_with_descriptor(path, disposition, access, share)?
        }
        other => other?,
    };
    ensure_private_handle(&file)?;
    Ok(file)
}
/// Opens an EXISTING private directory (no create, reparse point opened
/// itself) with `READ_CONTROL` and `WRITE_OWNER` and ensures it is private
/// ([`super::fs_windows_stamp::ensure_private_handle`]). Same denied-mask fallback as [`open_private_file`].
pub(crate) fn open_private_directory(path: &Path) -> Result<File, PrivateAclError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    let open = |access: u32| {
        std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    };
    let file = match open(GENERIC_READ | WRITE_OWNER) {
        Err(error) if error.raw_os_error() == Some(5) => open(GENERIC_READ),
        other => other,
    }
    .map_err(PrivateAclError::Os)?;
    ensure_private_handle(&file)?;
    Ok(file)
}
/// Like [`create_new_private_file`] but with the caller's `access` mask and
/// `share` mode, so one handle can serve a whole create-write-verify-rename
/// lifecycle (e.g. share READ only: no other handle can open it for write or
/// delete while it is held). Same exclusive creation, owner-only DACL at
/// creation and cleanup-on-failed-check as [`create_new_private_file`].
pub(crate) fn create_new_private_file_with(
    path: &Path,
    access: u32,
    share: u32,
) -> Result<File, PrivateAclError> {
    let file = open_with_descriptor(path, CREATE_NEW, access | DELETE, share)?;
    if let Err(error) = check_private_handle(&file) {
        super::fs_windows_delete::delete_created(&file);
        return Err(error);
    }
    Ok(file)
}
/// Creates `path` exclusively (`CREATE_NEW`: an existing file, directory or
/// reparse point at `path` is refused with `AlreadyExists`, never followed or
/// re-ACLed) with the protected owner-only DACL applied AT creation, then
/// re-checks the handle. If that check fails, the file this call just created
/// is removed before the error is returned (`security.md` §5a).
pub(crate) fn create_new_private_file(path: &Path) -> Result<File, PrivateAclError> {
    let file = open_with_descriptor(
        path,
        CREATE_NEW,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    if let Err(error) = check_private_handle(&file) {
        super::fs_windows_delete::delete_created(&file);
        return Err(error);
    }
    Ok(file)
}
fn open_with_descriptor(
    path: &Path,
    disposition: windows_sys::Win32::Storage::FileSystem::FILE_CREATION_DISPOSITION,
    access: u32,
    share: u32,
) -> Result<File, PrivateAclError> {
    let path = wide(path)?;
    let security = descriptor()?;
    let attributes = attributes(&security);
    // SAFETY: path/security are valid for the call. No inherited handle or truncation;
    // reparse final component is opened itself and subsequently rejected by caller.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            &attributes,
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(PrivateAclError::Os(io::Error::last_os_error()));
    }
    // SAFETY: successful CreateFileW transferred one uniquely owned handle.
    Ok(unsafe { File::from_raw_handle(handle as *mut c_void) })
}
/// Whether an owner-only object carries the exact private integrity label.
pub(super) enum Label {
    Present,
    Absent,
}
/// `Ok(())` iff the handle's owner, protected DACL AND mandatory label are
/// exactly the private shape. A missing label is refused here; pre-label objects
/// are upgraded only through [`super::fs_windows_stamp::ensure_private_handle`]. Needs `READ_CONTROL`.
pub(crate) fn check_private_handle(file: &File) -> Result<(), PrivateAclError> {
    match inspect(file).map_err(note_refusal)? {
        Label::Present => Ok(()),
        Label::Absent => Err(PrivateAclError::UnsafePath),
    }
}
/// Set once the inherited-label refusal has been logged in this process.
static INHERITED_LABEL_LOGGED: AtomicBool = AtomicBool::new(false);
/// `true` exactly once per `flag`.
fn first_time(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::SeqCst)
}
/// Passes `error` through; the first [`PrivateAclError::InheritedLabel`] of the process
/// also logs a WARN. A parent carrying an unacceptable inheritable label refuses EVERY
/// private file under it, so a per-file WARN would flood the log with one line per
/// object; the fixed tag names the cause once and the error itself still reaches each
/// caller.
pub(super) fn note_refusal(error: PrivateAclError) -> PrivateAclError {
    if matches!(error, PrivateAclError::InheritedLabel) && first_time(&INHERITED_LABEL_LOGGED) {
        tracing::warn!(
            error_kind = "private_acl_inherited_label_refused",
            "an inherited mandatory label is not acceptable beside csq's; private files \
             under that parent are refused (logged once per process)"
        );
    }
    error
}
/// Test seam for the once-per-process gate.
#[cfg(test)]
pub(super) fn first_time_for_test(flag: &AtomicBool) -> bool {
    first_time(flag)
}
pub(super) fn inspect(file: &File) -> Result<Label, PrivateAclError> {
    let user = User::current()?;
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut sacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: live owned file handle and output slots. SID/ACL pointers belong to SD.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            &mut sacl,
            &mut descriptor,
        )
    };
    // SAFETY: `GetSecurityInfo` allocates the descriptor with LocalAlloc (null on failure).
    let descriptor = unsafe { Local::from_local_alloc(descriptor) };
    if status != 0 || descriptor.as_ptr().is_null() || owner.is_null() || dacl.is_null() {
        return Err(PrivateAclError::UnsafePath);
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: API-returned descriptor/owner/ACL stay alive, lengths are OS validated.
    unsafe {
        if GetSecurityDescriptorControl(descriptor.as_ptr(), &mut control, &mut revision) == 0
            || control & SE_DACL_PROTECTED == 0
            || IsValidSid(owner) == 0
            || EqualSid(owner, user.sid()) == 0
            || (*dacl).AceCount != 1
        {
            return Err(PrivateAclError::UnsafePath);
        }
        let mut ace = ptr::null_mut();
        if GetAce(dacl, 0, &mut ace) == 0 || ace.is_null() {
            return Err(PrivateAclError::UnsafePath);
        }
        let header = &*ace.cast::<ACE_HEADER>();
        // ACCESS_ALLOWED_ACE_TYPE is 0 in WinNT.h. Refuse other ACE layouts
        // before reading a mask or SID from the access-allowed structure.
        if header.AceType != 0 || header.AceSize < 16 {
            return Err(PrivateAclError::UnsafePath);
        }
        let sid_offset = mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let sid_bytes = usize::from(header.AceSize)
            .checked_sub(sid_offset)
            .ok_or(PrivateAclError::UnsafePath)?;
        if sid_bytes < 8 {
            return Err(PrivateAclError::UnsafePath);
        }
        // Derive SID from the full API allocation, never a narrow SidStart
        // field reference. SID header is 8 bytes and contains its DWORD count.
        let sid_raw = ace.cast::<u8>().add(sid_offset);
        let subauthorities = usize::from(*sid_raw.add(1));
        if 8 + 4 * subauthorities > sid_bytes {
            return Err(PrivateAclError::UnsafePath);
        }
        let sid = sid_raw.cast();
        let ace = &*ace.cast::<ACCESS_ALLOWED_ACE>();
        if ace.Header.AceType != 0
            || ace.Header.AceFlags != 0
            || ace.Mask != FILE_ALL_ACCESS
            || IsValidSid(sid) == 0
            || EqualSid(sid, user.sid()) == 0
        {
            return Err(PrivateAclError::UnsafePath);
        }
        // Owner and DACL are exactly private. Now the label (see the module doc,
        // "Inherited labels"). Among the label ACEs that APPLY to this object (an
        // inherited inherit-only ACE, 0x18, does not): exactly one explicit ACE,
        // exactly Medium NW|NR and FIRST; every inherited one exactly Medium and
        // carrying NR. No explicit ACE and only such inherited ones (or none) is
        // `Absent`.
        let count = if sacl.is_null() { 0 } else { (*sacl).AceCount };
        let (mut explicit, mut inherited) = (0, 0);
        for index in 0..u32::from(count) {
            let mut ace = ptr::null_mut();
            if GetAce(sacl, index, &mut ace) == 0 || ace.is_null() {
                return Err(PrivateAclError::UnsafePath);
            }
            let header = &*ace.cast::<ACE_HEADER>();
            // SYSTEM_MANDATORY_LABEL_ACE: header, mask, then the label SID
            // (S-1-16-<rid>, 12 bytes). A label-query ACE of any other type or size
            // is malformed: refuse.
            let sid_offset = mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            if header.AceType != LABEL_ACE_TYPE || usize::from(header.AceSize) < sid_offset + 12 {
                return Err(PrivateAclError::UnsafePath);
            }
            let sid = std::slice::from_raw_parts(ace.cast::<u8>().add(sid_offset), 12);
            let rid = label_rid(sid);
            let mask = ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>());
            if header.AceFlags & INHERITED_ACE != 0 {
                if header.AceFlags & INHERIT_ONLY_ACE != 0 {
                    continue; // does not apply to this object
                }
                // Only exactly Medium, with the FULL NW|NR mask, may sit beside ours.
                // Below Medium the object is Low-writable and a Low planter can give it
                // the exact owner and DACL; above it stamping would LOWER the level;
                // without NR the read protection could be lost, and without NW the
                // write protection, if the kernel took the inherited policy. Refuse,
                // never stamp; an unknown level is refused too.
                if !inherited_label_may_sit_beside(rid, mask) {
                    // Not logged here: `inspect` runs per file; callers log through
                    // `note_refusal`, once per process.
                    return Err(PrivateAclError::InheritedLabel);
                }
                inherited += 1;
                continue;
            }
            // Ours must precede every applicable inherited label ACE.
            if inherited > 0 {
                return Err(PrivateAclError::UnsafePath);
            }
            explicit += 1;
            if header.AceFlags != 0 || mask != LABEL_MASK || rid != Some(MEDIUM_RID) {
                return Err(PrivateAclError::UnsafePath);
            }
        }
        if explicit > 1 {
            return Err(PrivateAclError::UnsafePath);
        }
        Ok(if explicit == 1 {
            Label::Present
        } else {
            Label::Absent
        })
    }
}
