use super::*;
pub(super) fn descriptor() -> Result<Local, PrivateAclError> {
    descriptor_with(DescriptorKind::File)
}
/// Which owner-only descriptor [`descriptor_text`] renders.
#[derive(Clone, Copy, Debug)]
pub(in crate::platform) enum DescriptorKind {
    /// Files and directories: `O:<sid>D:P(A;;FA;;;<sid>)S:(ML;;NWNR;;;ME)` —
    /// owner, protected DACL and the Medium mandatory label with no-write-up
    /// and no-read-up. [`check_private_handle`] re-checks exactly this shape.
    File,
    /// A private DIRECTORY whose single owner-only ACE, and whose explicit
    /// label, carry `OBJECT_INHERIT | CONTAINER_INHERIT`:
    /// `O:<sid>D:P(A;OICI;FA;;;<sid>)S:(ML;OICI;NWNR;;;ME)`. Every child then
    /// inherits owner-only access and the no-read-up label. A store whose files
    /// a third party (SQLite's `-journal`/`-wal`/`-shm`) creates needs this
    /// form: a protected non-inheriting parent propagates nothing, so those
    /// children would be born with an empty DACL.
    InheritingDirectory,
    /// Named kernel objects (the `platform::lock` mutexes):
    /// `O:<sid>D:P(A;;GA;;;<sid>)S:(ML;;NW;;;ME)`.
    Object,
}
/// The label every private file and directory carries: Medium integrity, no
/// write up (`NW`) and no read up (`NR`). Without it the object has the implicit
/// Medium label with only no-write-up, so a Low-integrity process of the same
/// user (a sandboxed child) could READ it past the owner-only DACL. Not protected
/// (`S:P`): changing SACL protection needs a privilege csq does not hold.
pub(in crate::platform) const FILE_LABEL_SDDL: &str = "S:(ML;;NWNR;;;ME)";
/// `SYSTEM_MANDATORY_LABEL_ACE_TYPE` (WinNT.h).
pub(super) const LABEL_ACE_TYPE: u8 = 0x11;
/// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP | SYSTEM_MANDATORY_LABEL_NO_READ_UP`.
pub(super) const LABEL_MASK: u32 = 0x1 | 0x2;
/// ACE flags (WinNT.h): `INHERIT_ONLY_ACE`, `INHERITED_ACE`.
pub(super) const INHERIT_ONLY_ACE: u8 = 0x08;
pub(super) const INHERITED_ACE: u8 = 0x10;
/// ACE flags (WinNT.h): `OBJECT_INHERIT_ACE`, `CONTAINER_INHERIT_ACE`.
pub(super) const OBJECT_INHERIT_ACE: u8 = 0x01;
pub(super) const CONTAINER_INHERIT_ACE: u8 = 0x02;
pub(super) const INHERIT_BOTH: u8 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

/// Which of the three private shapes [`inspect_shape`] must find.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Shape {
    /// A csq-created object: a PROTECTED DACL with one non-inherited
    /// `FILE_ALL_ACCESS` ACE for the current user, and one explicit
    /// non-inherited Medium NW|NR label ACE.
    Exact,
    /// A private DIRECTORY created by [`create_private_directory_inheriting`]:
    /// the same single-owner DACL and label, but the ACEs carry
    /// `OBJECT_INHERIT | CONTAINER_INHERIT`, so every child inherits the shape
    /// instead of an empty DACL. A store whose files a third party (SQLite)
    /// creates needs this form; the child of a protected non-inheriting parent
    /// inherits nothing.
    InheritingDirectory,
    /// A child of that directory: one `FILE_ALL_ACCESS` ACE for the current
    /// user on an UNPROTECTED DACL, with flags EXACTLY `{}` or `{ID}` (ROOT R2
    /// ruling). The native Windows runner copies the leaf's grant to a
    /// NULL-attribute child with every DACL flag cleared while the label arrives
    /// `ID`-flagged (run 41151503624), so both forms must be accepted. The label
    /// must be INHERITED — at least one applicable inherited Medium NW|NR ACE
    /// and no explicit label ACE.
    Inherited,
}

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
pub(in crate::platform) fn descriptor_text(sid: &str, kind: DescriptorKind) -> String {
    match kind {
        DescriptorKind::File => format!("O:{sid}D:P(A;;FA;;;{sid}){FILE_LABEL_SDDL}"),
        DescriptorKind::InheritingDirectory => {
            format!("O:{sid}D:P(A;OICI;FA;;;{sid})S:(ML;OICI;NWNR;;;ME)")
        }
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
pub(super) fn descriptor_with(kind: DescriptorKind) -> Result<Local, PrivateAclError> {
    let sid = current_user_sid_string()?;
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
