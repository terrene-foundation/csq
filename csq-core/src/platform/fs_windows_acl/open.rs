use super::*;
/// `WRITE_OWNER | READ_CONTROL` file handle, no-follow — the least access that
/// sets an owner. Used only for the identity-bound sidecar tightening.
pub(crate) fn open_owner_write_handle(path: &Path) -> Result<File, PrivateAclError> {
    open_with_descriptor(
        path,
        OPEN_EXISTING,
        WRITE_OWNER | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
}
/// `GENERIC_READ` directory handle, no-follow, for the check-only adopt path.
pub(crate) fn open_directory_check_handle(path: &Path) -> Result<File, PrivateAclError> {
    open_directory_handle_readonly(path)
}
/// Opens an EXISTING directory with `WRITE_DAC | WRITE_OWNER | READ_CONTROL`,
/// no-follow — the least access that re-applies a descriptor and a label.
pub(crate) fn open_directory_adopt_handle(path: &Path) -> Result<File, PrivateAclError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    std::fs::OpenOptions::new()
        .access_mode(WRITE_DAC | WRITE_OWNER | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(PrivateAclError::Os)
}
/// Re-applies the INHERITING owner-only descriptor through the HELD HANDLE with
/// `SetKernelObjectSecurity` — R2 NEW-2's NON-PROPAGATING adoption step.
///
/// `SetSecurityInfo` — the path- and handle-based Win32 setters — asks the
/// filesystem to re-inherit a directory's existing children from the new
/// inheritable ACEs. `SetKernelObjectSecurity` writes the object's descriptor
/// through its own handle and does not request that propagation: the adoption
/// caller validates every child first and re-ACLs each one explicitly through
/// its held handle. A native test captures a child descriptor at the seam
/// between the two steps and asserts the root step left it unchanged.
pub(crate) fn apply_inheriting_directory_nonpropagating(
    file: &File,
) -> Result<(), PrivateAclError> {
    let descriptor = descriptor_with(DescriptorKind::InheritingDirectory)?;
    // SAFETY: live handle and descriptor; the API copies what it needs and the
    // descriptor outlives the call.
    if unsafe {
        SetKernelObjectSecurity(
            file.as_raw_handle() as HANDLE,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    } == 0
    {
        return Err(PrivateAclError::Os(std::io::Error::last_os_error()));
    }
    Ok(())
}
/// Opens an adoption CHILD (a direct entry of a pool root) no-follow with
/// `WRITE_DAC | WRITE_OWNER | READ_CONTROL`, holding it WITHOUT
/// `FILE_SHARE_DELETE` so no one can swap it between validation and re-ACL
/// (R2 NEW-2).
pub(crate) fn open_adoption_child_handle(path: &Path) -> Result<File, PrivateAclError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    std::fs::OpenOptions::new()
        .access_mode(WRITE_DAC | WRITE_OWNER | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(PrivateAclError::Os)
}
/// The adoption gate for a CHILD of a pool root: its owner and every allow ACE
/// must be within the adoption trust set (user / SYSTEM / Administrators,
/// byte-exact). A foreign principal that can create or write entries inside the
/// root is refused, whatever its mask (R2 NEW-1).
pub(crate) fn check_adoption_child(file: &File) -> Result<(), PrivateAclError> {
    let owner = observed_owner(file)?;
    let current = UserSid::current()?;
    if !adoption_trusted(&owner, current.bytes()) {
        return Err(PrivateAclError::UnsafePath);
    }
    check_no_foreign_write_for_adoption(file)
}
/// Re-ACLs an adopted child to the shape `Shape::Inherited` requires — an
/// UNPROTECTED DACL with one non-inheriting `FILE_ALL_ACCESS` ACE for the user
/// and the INHERITED Medium NW|NR label — through its held handle, so the entry
/// cannot be swapped underneath the write.
pub(crate) fn apply_adopted_child_descriptor(file: &File) -> Result<(), PrivateAclError> {
    let sid = current_user_sid_string()?;
    let sddl = format!("D:(A;;FA;;;{sid})S:AI(ML;ID;NWNR;;;ME)");
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: complete NUL-terminated SDDL and live output slot; revision 1.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: the conversion succeeded: `result` is its LocalAlloc descriptor.
    let descriptor = unsafe { Local::from_local_alloc(descriptor) };
    // SAFETY: live handle and descriptor; the API copies what it needs.
    if unsafe {
        SetKernelObjectSecurity(
            file.as_raw_handle() as HANDLE,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            descriptor.as_ptr(),
        )
    } == 0
    {
        return Err(PrivateAclError::Os(std::io::Error::last_os_error()));
    }
    Ok(())
}
pub(super) fn wide(path: &Path) -> Result<Vec<u16>, PrivateAclError> {
    let encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(PrivateAclError::UnsafePath);
    }
    Ok(encoded.into_iter().chain(Some(0)).collect())
}
pub(super) fn attributes(descriptor: &Local) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    }
}
pub(crate) fn create_private_directory(path: &Path) -> Result<(), PrivateAclError> {
    create_directory_with(path, DescriptorKind::File)
}
/// Creates an EXCLUSIVE directory with the INHERITABLE owner-only descriptor
/// ([`DescriptorKind::InheritingDirectory`]): an existing entry at `path` is
/// refused with `AlreadyExists`, never re-ACLed. For the one private directory
/// a third party writes files into — see [`open_private_directory_inheriting`].
pub(crate) fn create_private_directory_inheriting(path: &Path) -> Result<(), PrivateAclError> {
    create_directory_with(path, DescriptorKind::InheritingDirectory)
}
/// Opens (or, with `create`, opens-or-creates) a private file and ENSURES it is
/// private ([`crate::platform::fs_windows_stamp::ensure_private_handle`]): a file written before the integrity
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
/// Opens an EXISTING private file with exactly `GENERIC_READ`, or
/// `GENERIC_READ | GENERIC_WRITE`, and shares read/write/delete.
///
/// Windows' share check looks only at the DATA and `DELETE` access bits a held
/// handle requests: a guard asking for `DELETE` (or a data read/write the peer's
/// share mode does not cover) makes a peer that opens the same path with the
/// Win32 default `FILE_SHARE_READ | FILE_SHARE_WRITE` (SQLite's VFS) fail with a
/// sharing violation; metadata rights (`WRITE_OWNER`, `WRITE_DAC`,
/// `READ_CONTROL`, `FILE_READ_ATTRIBUTES`) take no part (R1 F6). No `DELETE` is
/// requested here, and the private shape is [checked, not
/// repaired](check_private_handle): a pre-label object is refused and must be
/// upgraded through [`open_private_file`] / [`open_private_readable`], whose
/// handle does hold `WRITE_OWNER`.
pub(crate) fn open_private_shared(path: &Path, write: bool) -> Result<File, PrivateAclError> {
    let file = open_unchecked_shared_handle(path, write)?;
    check_private_handle(&file)?;
    Ok(file)
}
/// [`open_private_shared`] WITHOUT a shape check — the name says so: the caller
/// applies its own (a sidecar must have inherited its private DACL; see
/// [`check_private_inherited_handle_as`]). An unchecked handle must never be
/// handed to anything that trusts it before that check.
pub(crate) fn open_unchecked_shared_handle(
    path: &Path,
    write: bool,
) -> Result<File, PrivateAclError> {
    let access = if write {
        GENERIC_READ | GENERIC_WRITE
    } else {
        GENERIC_READ
    };
    open_with_descriptor(
        path,
        OPEN_EXISTING,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
    .map_err(note_refusal)
}
pub(super) fn open_ensured(
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
/// ([`crate::platform::fs_windows_stamp::ensure_private_handle`]). Same denied-mask fallback as [`open_private_file`].
pub(crate) fn open_private_directory(path: &Path) -> Result<File, PrivateAclError> {
    let file = open_directory_handle(path)?;
    ensure_private_handle(&file)?;
    Ok(file)
}
/// Opens the leaf directory a third-party writer puts files in and verifies the
/// INHERITABLE owner-only shape ([`check_private_directory_inheriting`]). The
/// label is required, never stamped: only [`create_private_directory_inheriting`]
/// makes this shape, so a missing label is a foreign directory, not a legacy csq
/// one.
pub(crate) fn open_private_directory_inheriting(path: &Path) -> Result<File, PrivateAclError> {
    // Check-only: the inheriting leaf is never stamped, so the handle carries
    // `GENERIC_READ` alone — no WRITE_OWNER it would not use (R1 L4).
    let file = open_directory_handle_readonly(path)?;
    check_private_directory_inheriting(&file)?;
    Ok(file)
}
/// Least-privilege directory open for the check-only path: `GENERIC_READ` only,
/// no fallback (a failure is a refusal, never a wider access).
pub(super) fn open_directory_handle_readonly(path: &Path) -> Result<File, PrivateAclError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(PrivateAclError::Os)
}
/// The no-follow directory handle every directory opener starts from.
pub(super) fn open_directory_handle(path: &Path) -> Result<File, PrivateAclError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    let open = |access: u32| {
        std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    };
    match open(GENERIC_READ | WRITE_OWNER) {
        Err(error) if error.raw_os_error() == Some(5) => open(GENERIC_READ),
        other => other,
    }
    .map_err(PrivateAclError::Os)
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
pub(super) fn open_with_descriptor(
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
