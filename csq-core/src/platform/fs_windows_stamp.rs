//! Stamping the private integrity label on an object that is exactly private except
//! for the label (written by a csq before the label existed). See the module doc of
//! `fs_windows_acl` for the label shape and the inherited-label rules.
use super::fs_windows_acl::{
    check_private_handle, inspect, note_refusal, Label, Local, PrivateAclError, FILE_LABEL_SDDL,
};
use std::{fs::File, os::windows::io::AsRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SE_FILE_OBJECT,
        },
        GetSecurityDescriptorSacl, ACL, LABEL_SECURITY_INFORMATION,
    },
};

/// [`check_private_handle`], except an object whose owner and DACL are exactly
/// private but which has NO label (written before the label existed) gets the
/// label stamped through this handle, then is verified again. Upgrade, not
/// acceptance: it fails closed (`UnsafePath`) when the stamp cannot be applied
/// (the handle lacks `WRITE_OWNER`, or the OS refuses) or the re-check is not
/// the exact shape; a wrong owner, broad DACL or different label is never
/// rewritten. Needs `READ_CONTROL`, plus `WRITE_OWNER` to upgrade.
pub(crate) fn ensure_private_handle(file: &File) -> Result<(), PrivateAclError> {
    match ensure_private_handle_detailed(file) {
        Ok(_) => Ok(()),
        Err(EnsureFailure::Refused(error)) => Err(error),
        Err(EnsureFailure::StampFailed) => Err(PrivateAclError::UnsafePath),
    }
}
/// What [`ensure_private_handle_detailed`] did on success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ensured {
    /// Already exactly private, label included.
    Already,
    /// The label was missing and was stamped, then verified.
    Stamped,
}
/// Why [`ensure_private_handle_detailed`] failed.
#[derive(Debug)]
pub(crate) enum EnsureFailure {
    /// The object is not (or not exactly) private: left untouched.
    Refused(PrivateAclError),
    /// Owner and DACL were exactly private and only the label was missing, but the
    /// stamp (or its verification) failed: the object is still unlabeled.
    StampFailed,
}
/// [`ensure_private_handle`], reporting whether it stamped and separating a failed
/// stamp (a private object that STAYED unlabeled; a WARN with a fixed `error_kind`)
/// from a refusal (not private; untouched).
pub(crate) fn ensure_private_handle_detailed(file: &File) -> Result<Ensured, EnsureFailure> {
    match inspect(file)
        .map_err(note_refusal)
        .map_err(EnsureFailure::Refused)?
    {
        Label::Present => return Ok(Ensured::Already),
        Label::Absent => (),
    }
    let stamped = stamp_label(file).is_ok() && check_private_handle(file).is_ok();
    if !stamped {
        tracing::warn!(
            error_kind = "private_acl_label_stamp_failed",
            "a private object lacked the integrity label and it could not be stamped"
        );
        return Err(EnsureFailure::StampFailed);
    }
    tracing::debug!("owner-only ACL integrity label stamped on a pre-label private object");
    Ok(Ensured::Stamped)
}
fn stamp_label(file: &File) -> Result<(), PrivateAclError> {
    let text: Vec<u16> = FILE_LABEL_SDDL.encode_utf16().chain(Some(0)).collect();
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
    let descriptor = unsafe { Local::from_local_alloc(result) };
    let (mut present, mut defaulted, mut sacl) = (0, 0, ptr::null_mut::<ACL>());
    // SAFETY: the descriptor was just converted and lives to the end of this
    // function; the SACL pointer is borrowed from it and checked non-null.
    if unsafe {
        GetSecurityDescriptorSacl(descriptor.as_ptr(), &mut present, &mut sacl, &mut defaulted)
    } == 0
        || present == 0
        || sacl.is_null()
    {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: live handle; only the label is set, from the SACL borrowed above.
    // Needs WRITE_OWNER on the handle; any failure is fail-closed below.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            sacl,
        )
    };
    if status != 0 {
        return Err(PrivateAclError::UnsafePath);
    }
    Ok(())
}
