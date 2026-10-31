use super::*;
pub(super) struct Handle(HANDLE);
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
pub(in crate::platform) struct Local(*mut c_void);
impl Local {
    /// # Safety
    /// `ptr` must be null or a pointer returned by a `LocalAlloc`-backed API
    /// (`ConvertStringSecurityDescriptorToSecurityDescriptorW`, `ConvertSidToStringSidW`,
    /// `GetSecurityInfo`'s descriptor, ...) that nothing else frees, so that `LocalFree`
    /// on drop is the one release.
    pub(in crate::platform) unsafe fn from_local_alloc(ptr: *mut c_void) -> Self {
        Self(ptr)
    }
    /// The borrowed pointer; valid for as long as `self` lives.
    pub(in crate::platform) fn as_ptr(&self) -> *mut c_void {
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
pub(super) struct User(Vec<usize>);
impl User {
    pub(super) fn current() -> Result<Self, PrivateAclError> {
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
    pub(super) fn sid(&self) -> *mut c_void {
        // SAFETY: buffer was filled successfully as TOKEN_USER and remains owned.
        unsafe { (*(self.0.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}
/// `SECURITY_MAX_SID_SIZE` (WinNT.h): the largest SID, in bytes.
pub(super) const MAX_SID_LEN: usize = 68;
/// A user SID copied out of a process token.
///
/// Owned bytes rather than a borrowed token pointer, so an owner/SID comparison
/// stays valid after the token buffer is dropped, and so a test can drive the
/// same owner policy with a synthetic identity (a foreign-owned object cannot be
/// constructed on an unprivileged host).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UserSid(Vec<u8>);
impl UserSid {
    /// The current process token's user SID.
    pub(crate) fn current() -> Result<Self, PrivateAclError> {
        let user = User::current()?;
        let sid = user.sid();
        // SAFETY: `sid` belongs to the live token-user buffer and was validated
        // by GetTokenInformation; GetLengthSid only reads the SID header.
        let length = unsafe { GetLengthSid(sid) } as usize;
        if !(8..=MAX_SID_LEN).contains(&length) {
            return Err(PrivateAclError::Descriptor);
        }
        // SAFETY: a valid SID of the measured length; copied before `user` drops.
        Ok(Self(
            unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec(),
        ))
    }
    /// The process token's DEFAULT OWNER SID — the owner Windows assigns to an
    /// object created with a NULL security descriptor, never inherited from the
    /// parent. The user for a non-elevated token, but `BUILTIN\Administrators`
    /// for an elevated one (`platform::lock` documents the same token field for
    /// the mutexes). Needed because SQLite creates its sidecars with NULL
    /// security attributes: their owner is this SID, not necessarily the user.
    pub(super) fn token_default_owner() -> Result<Self, PrivateAclError> {
        let mut handle = 0;
        // SAFETY: pseudo process handle is valid; output points to a live slot.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
            return Err(PrivateAclError::Descriptor);
        }
        let token = Handle(handle);
        let mut needed = 0;
        // SAFETY: null zero-length buffer is the documented size query.
        unsafe { GetTokenInformation(token.0, TokenOwner, ptr::null_mut(), 0, &mut needed) };
        if needed < mem::size_of::<TOKEN_OWNER>() as u32 || needed > 65536 {
            return Err(PrivateAclError::Descriptor);
        }
        let mut buffer = vec![0usize; (needed as usize).div_ceil(mem::size_of::<usize>())];
        // SAFETY: usize storage supplies TOKEN_OWNER alignment and needed capacity.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenOwner,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(PrivateAclError::Descriptor);
        }
        // SAFETY: buffer was filled successfully as TOKEN_OWNER; its Owner SID
        // lives inside that buffer until it drops at the end of this function.
        let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_OWNER>())).Owner };
        if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
            return Err(PrivateAclError::Descriptor);
        }
        // SAFETY: a valid SID; GetLengthSid only reads the SID header.
        let length = unsafe { GetLengthSid(sid) } as usize;
        if !(8..=MAX_SID_LEN).contains(&length) {
            return Err(PrivateAclError::Descriptor);
        }
        // SAFETY: a valid SID of the measured length; copied before `buffer` drops.
        Ok(Self(
            unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec(),
        ))
    }

    /// A SID from raw bytes, for exercising the owner policy. Test-only: a
    /// production caller must never choose who "the current user" is.
    #[cfg(test)]
    pub(crate) fn synthetic(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
    /// `true` iff `sid` is this SID. Byte-for-byte `EqualSid`.
    ///
    /// # Safety
    /// `sid` must point to a valid SID that outlives this call (a value from a
    /// live security descriptor or token buffer).
    pub(crate) unsafe fn matches(&self, sid: *mut c_void) -> bool {
        EqualSid(self.0.as_ptr().cast_mut().cast(), sid) != 0
    }
}
/// `SECURITY_NT_AUTHORITY`, the identifier authority of every SID compared below.
pub(super) const SECURITY_NT_AUTHORITY: u64 = 5;
/// The sub-authorities of `sid`, `None` when the bytes are not a well-formed SID.
pub(super) fn sub_authorities(sid: &[u8]) -> Option<&[u8]> {
    let count = usize::from(*sid.get(1)?);
    if sid.len() < 8 || sid.len() != 8 + count * 4 {
        return None;
    }
    Some(&sid[8..])
}
pub(super) fn sub_authority(sid: &[u8], index: usize) -> Option<u32> {
    let part = sub_authorities(sid)?.get(index * 4..index * 4 + 4)?;
    Some(u32::from_le_bytes([part[0], part[1], part[2], part[3]]))
}
pub(super) fn authority(sid: &[u8]) -> Option<u64> {
    if sid.len() < 8 {
        return None;
    }
    Some(sid[2..8].iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)))
}
/// `true` iff a grant to `sid` cannot be exercised by an unrelated user, so it
/// does not make an ancestor untrusted: the current user, `LocalSystem`
/// (`S-1-5-18`), `Administrators` (`S-1-5-32-544`), or one of the Windows
/// service accounts (`S-1-5-80-*`; `TrustedInstaller`, which owns a drive root
/// and `Program Files`, is one). Every other principal — including a group the
/// current user happens to belong to, because membership is not proof about the
/// rest of the group — can put another user's rights on the object.
pub(super) fn principal_trusted(sid: &[u8], current: &[u8]) -> bool {
    if sid == current {
        return true;
    }
    if authority(sid) != Some(SECURITY_NT_AUTHORITY) {
        return false;
    }
    match sub_authority(sid, 0) {
        // SECURITY_LOCAL_SYSTEM_RID
        Some(18) => true,
        // SECURITY_BUILTIN_DOMAIN_RID / DOMAIN_ALIAS_RID_ADMINS
        Some(32) => sub_authority(sid, 1) == Some(544),
        // SERVICE_* SIDs minted by the service control manager.
        Some(80) => true,
        _ => false,
    }
}
/// `NT AUTHORITY\SYSTEM` (`S-1-5-18`) as SID bytes.
pub(super) const SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
/// The ADOPTION-ONLY trust rule for a pre-existing pool root (ROOT R1 F5 ruling):
/// a grant is tolerable only when it is held by the current user, `LocalSystem`
/// (`S-1-5-18`, byte-exact) or `BUILTIN\Administrators` (`S-1-5-32-544`,
/// byte-exact) — the Windows profile defaults. NARROWER than
/// [`principal_trusted`], which also tolerates `S-1-5-80-*` service accounts for
/// ANCESTRY: those are "other SIDs" for adoption and are refused.
pub(super) fn adoption_trusted(sid: &[u8], current: &[u8]) -> bool {
    sid == current || sid == SYSTEM_SID || sid == ADMINISTRATORS_SID
}
/// Whether `observed` may OWN a sidecar SQLite created inside the private leaf.
///
/// Exact SID equality only — never group membership. The owner is the token
/// user SID, or the token's DEFAULT OWNER SID, and that second form is accepted
/// only when the default owner is byte-exactly `BUILTIN\Administrators`: an
/// elevated/admin token stamps Administrators on a NULL-attribute child
/// (inheritance never carries the owner), and refusing it would make the ledger
/// unusable on every elevated host, while accepting any OTHER owner-capable
/// group would widen the policy past that one documented token shape. The DACL
/// and label still grant only the user, so this admits no one the elevated
/// admin token could not already reach.
pub(super) fn sidecar_owner_acceptable(observed: &[u8], user: &[u8], default_owner: &[u8]) -> bool {
    observed == user || (observed == ADMINISTRATORS_SID && default_owner == ADMINISTRATORS_SID)
}
// The token owner used by the sidecar policy. Test seam: `cfg(test)` can
// replace the token value so the Administrators branch is exercised on a host
// that is not elevated (an unprivileged test cannot create an
// Administrators-owned object). THREAD-LOCAL (R2 N7): a process-wide value let
// a concurrent pool test observe another test's synthetic owner.
#[cfg(test)]
thread_local! {
    pub(super) static DEFAULT_OWNER_OVERRIDE: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn with_default_owner_for_test<T>(owner: Option<&[u8]>, op: impl FnOnce() -> T) -> T {
    struct Restore(Option<Vec<u8>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            DEFAULT_OWNER_OVERRIDE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let previous = DEFAULT_OWNER_OVERRIDE
        .with(|slot| std::mem::replace(&mut *slot.borrow_mut(), owner.map(<[u8]>::to_vec)));
    let _restore = Restore(previous);
    op()
}
// Test seam over the OBSERVED owner inside [`inspect_shape`] (R2 N2): a test
// can synthesise an Administrators-owned descriptor on a non-elevated token, so
// the point-of-use `owner_policy_ok` call can be made to fail a test. Thread-
// local, and consulted only in test builds.
#[cfg(test)]
thread_local! {
    pub(super) static OBSERVED_OWNER_OVERRIDE: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn with_observed_owner_for_test<T>(owner: Option<&[u8]>, op: impl FnOnce() -> T) -> T {
    struct Restore(Option<Vec<u8>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVED_OWNER_OVERRIDE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let previous = OBSERVED_OWNER_OVERRIDE
        .with(|slot| std::mem::replace(&mut *slot.borrow_mut(), owner.map(<[u8]>::to_vec)));
    let _restore = Restore(previous);
    op()
}
pub(crate) fn sidecar_default_owner() -> Result<UserSid, PrivateAclError> {
    #[cfg(test)]
    if let Some(bytes) = DEFAULT_OWNER_OVERRIDE.with(|slot| slot.borrow().clone()) {
        return Ok(UserSid::synthetic(&bytes));
    }
    UserSid::token_default_owner()
}
/// Reads the process token's default-owner SID, or the test seam's value.
#[cfg(test)]
pub(crate) fn sidecar_default_owner_for_test() -> Result<Vec<u8>, PrivateAclError> {
    sidecar_default_owner().map(|sid| sid.bytes().to_vec())
}
/// `true` iff a sidecar owner was accepted ONLY through the Administrators
/// default-owner branch — the one case worth tightening back to the user SID
/// (R1 M3). This IS the production decision: the tightening calls it with the
/// owner it observed and the token's default owner, and it is pure so the
/// matrix is testable with the TokenOwner seam.
pub(crate) fn sidecar_owner_needs_tightening(
    observed: &[u8],
    user: &[u8],
    default_owner: &[u8],
) -> bool {
    observed != user && sidecar_owner_acceptable(observed, user, default_owner)
}
/// Set once the pool-sidecar owner refusal has been logged in this process.
pub(super) static SIDECAR_OWNER_REFUSED_LOGGED: AtomicBool = AtomicBool::new(false);
/// The held handle's owner SID bytes. Needs `READ_CONTROL`; an unreadable or
/// malformed owner is `Err`, which every caller treats as a refusal (fail
/// closed), never as same-user. This is the one owner reader: the pool
/// tightening compares these bytes against the token user and the token's
/// default owner ([`sidecar_owner_needs_tightening`]).
pub(crate) fn observed_owner(file: &File) -> Result<Vec<u8>, PrivateAclError> {
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: live handle and output slots; the descriptor is LocalAlloc.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
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
    if status != 0
        || descriptor.as_ptr().is_null()
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
    {
        return Err(PrivateAclError::UnsafePath);
    }
    // SAFETY: validated descriptor-owned SID; the copy is made before it drops.
    unsafe {
        let length = GetLengthSid(owner) as usize;
        if !(8..=MAX_SID_LEN).contains(&length) {
            return Err(PrivateAclError::UnsafePath);
        }
        Ok(std::slice::from_raw_parts(owner.cast::<u8>(), length).to_vec())
    }
}
/// `true` iff the held handle's owner is the token user SID. Needs `READ_CONTROL`.
pub(crate) fn owner_is_user(file: &File, user: &UserSid) -> Result<bool, PrivateAclError> {
    Ok(observed_owner(file)? == user.bytes())
}
/// `true` iff the held handle's DACL is marked `SE_DACL_PROTECTED`, i.e. the
/// object does NOT inherit its DACL from its parent. The F5 adoption applies
/// only to an UNPROTECTED (default-inherited) pool root; a protected leaf in the
/// wrong private shape is refused, never adopted, however tidy its owner is.
pub(crate) fn dacl_is_protected(file: &File) -> Result<bool, PrivateAclError> {
    let mut descriptor = ptr::null_mut();
    // SAFETY: live handle and output slot; the descriptor is LocalAlloc.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    // SAFETY: `GetSecurityInfo` allocates the descriptor with LocalAlloc (null on failure).
    let descriptor = unsafe { Local::from_local_alloc(descriptor) };
    if status != 0 || descriptor.as_ptr().is_null() {
        return Err(PrivateAclError::UnsafePath);
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: a live returned descriptor and output slots; reads the control word only.
    if unsafe { GetSecurityDescriptorControl(descriptor.as_ptr(), &mut control, &mut revision) }
        == 0
    {
        return Err(PrivateAclError::UnsafePath);
    }
    Ok(control & SE_DACL_PROTECTED != 0)
}
/// Sets the handle's owner to the process token's user SID — a TIGHTENING only
/// (the owner never gains rights this call takes away). The handle must carry
/// `WRITE_OWNER`; an elevated admin token holds `SeTakeOwnershipPrivilege`, which
/// is what lets it give an Administrators-owned object back to the user.
pub(crate) fn set_owner_to_current_user(file: &File) -> Result<(), PrivateAclError> {
    let user = User::current()?;
    // SAFETY: live handle and token-owned SID; only the owner is set.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            user.sid(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(PrivateAclError::Descriptor);
    }
    Ok(())
}
/// The current token user's SID as SDDL text. Production helper behind
/// [`descriptor_with`] and [`apply_adopted_child_descriptor`].
pub(super) fn current_user_sid_string() -> Result<String, PrivateAclError> {
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
    String::from_utf16(unsafe { std::slice::from_raw_parts(string.as_ptr().cast::<u16>(), len) })
        .map_err(|_| PrivateAclError::Descriptor)
}
pub(super) fn effective_mask(mask: u32) -> u32 {
    let mut mapped = mask & !0xf000_0000;
    if mask & GENERIC_ALL != 0 {
        mapped |= FILE_ALL_ACCESS;
    }
    if mask & GENERIC_WRITE != 0 {
        mapped |= 0x0012_0116;
    }
    mapped
}
/// The rights that let the grantee REMOVE, RENAME or RE-SECURE an entry of the
/// directory its ACE sits on. `FILE_WRITE_DATA`/`FILE_APPEND_DATA` (on a
/// directory: create a file / create a subdirectory) are deliberately absent,
/// and the policy does not extend them to the child: Windows deletes or renames
/// an existing child only under `DELETE` on the child or `FILE_DELETE_CHILD` on
/// the parent, and neither is granted here. A foreign principal able to create
/// entries beside ours therefore still cannot replace ours, which is what the
/// private leaf's exact-owner checks refuse if it wins a create race.
pub(super) const ENTRY_REMOVING: u32 = DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;
