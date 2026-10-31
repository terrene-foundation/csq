use super::*;
/// Test seam for the once-per-process gate.
#[cfg(test)]
pub(in crate::platform) fn first_time_for_test(flag: &AtomicBool) -> bool {
    first_time(flag)
}
/// Renders a held handle's OWNER, DACL and mandatory label as SDDL. TEST-ONLY:
/// the native-Windows run prints the real shape of the pool leaf, its database
/// and a SQLite-created sidecar with a fixed tag, so an operator can see which
/// owner and token path the runner actually exercised (ROOT condition 1 — a
/// refusal must be diagnosable from its descriptor).
#[cfg(test)]
pub(crate) fn observed_sddl(file: &File) -> Result<String, PrivateAclError> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
    };
    let information =
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    let mut descriptor = ptr::null_mut();
    // SAFETY: live handle; the API allocates the descriptor with LocalAlloc and
    // retains no pointer after returning.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            information,
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
    let mut string = ptr::null_mut();
    let mut length = 0;
    // SAFETY: live descriptor and output slots; the API allocates the string with
    // LocalAlloc and writes its UTF-16 length into `length`.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.as_ptr(),
            SDDL_REVISION_1,
            information,
            &mut string,
            &mut length,
        )
    } == 0
    {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: the conversion succeeded: `string` is its LocalAlloc buffer.
    let string = unsafe { Local::from_local_alloc(string.cast()) };
    if string.as_ptr().is_null() || length == 0 || length > 8192 {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: `length` UTF-16 units belong to the live returned string. The API
    // counts the NUL terminator in some builds (native run 41157525966 printed
    // trailing `\0`s), so trim at the first terminator.
    let units =
        unsafe { std::slice::from_raw_parts(string.as_ptr().cast::<u16>(), length as usize) };
    let end = units
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(units.len());
    String::from_utf16(&units[..end]).map_err(|_| PrivateAclError::Descriptor)
}
/// [`observed_sddl`] for a path, opened with the least access that reads owner,
/// DACL and label; no-follow, so a reparse point is rendered as itself.
#[cfg(test)]
pub(crate) fn observed_sddl_at(path: &Path) -> Result<String, PrivateAclError> {
    observed_sddl(&open_observed(path)?)
}
/// Opens `path` with the least access that reads owner, DACL and label;
/// no-follow, so a reparse point is observed as itself. TEST-ONLY.
#[cfg(test)]
pub(super) fn open_observed(path: &Path) -> Result<File, PrivateAclError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, READ_CONTROL,
    };
    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | READ_CONTROL)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(PrivateAclError::Os)
}
/// TEST-ONLY parsed view of a handle's security descriptor: the owner SID as
/// text, the DACL CONTROL BITS and each DACL/label ACE as (type, mask, flags,
/// SID). Tests assert control bits plus this parsed list — never an SDDL
/// substring: `SetSecurityInfo` stores `SE_DACL_AUTO_INHERITED` beside
/// `SE_DACL_PROTECTED` (native run 41157525966 observed `D:PAI(…)` for a
/// descriptor requested as `D:P(…)`), so a `D:P(` substring is not a shape.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservedAcl {
    pub(crate) owner: String,
    control: u16,
    pub(crate) dacl: Vec<ObservedAce>,
    pub(crate) label: Vec<ObservedAce>,
}
#[cfg(test)]
impl ObservedAcl {
    /// `true` iff the DACL carries `SE_DACL_PROTECTED`. `SE_DACL_AUTO_INHERITED`
    /// is independent of it and legal beside it (native run 41157525966 observed
    /// `D:PAI(…)` for a descriptor requested as `D:P(…)`), so this is a BIT test
    /// and never an equality check.
    pub(crate) fn dacl_protected(&self) -> bool {
        self.control & SE_DACL_PROTECTED != 0
    }
    /// The DACL SIDs in ACE order, as text.
    pub(crate) fn dacl_sids(&self) -> Vec<&str> {
        self.dacl.iter().map(|ace| ace.sid.as_str()).collect()
    }
}
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservedAce {
    pub(crate) ace_type: u8,
    pub(crate) mask: u32,
    pub(crate) flags: u8,
    pub(crate) sid: String,
}
#[cfg(test)]
impl ObservedAce {
    /// `ACCESS_ALLOWED_ACE_TYPE`.
    pub(crate) fn is_access_allowed(&self) -> bool {
        self.ace_type == 0
    }
    /// `SYSTEM_MANDATORY_LABEL_ACE_TYPE`.
    pub(crate) fn is_label(&self) -> bool {
        self.ace_type == LABEL_ACE_TYPE
    }
    /// The ACE's mask is exactly `FILE_ALL_ACCESS`.
    pub(crate) fn is_file_all_access(&self) -> bool {
        self.mask == FILE_ALL_ACCESS
    }
    /// The ACE carries both `OBJECT_INHERIT_ACE` and `CONTAINER_INHERIT_ACE`.
    pub(crate) fn inherits_to_children(&self) -> bool {
        self.flags & INHERIT_BOTH == INHERIT_BOTH
    }
}
/// Parses `file`'s owner, DACL control bits and DACL/label ACE lists. TEST-ONLY.
#[cfg(test)]
pub(crate) fn observed_acl(file: &File) -> Result<ObservedAcl, PrivateAclError> {
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut sacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: live owned file handle and output slots.
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
    if status != 0 || descriptor.as_ptr().is_null() || owner.is_null() {
        return Err(PrivateAclError::UnsafePath);
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: the descriptor is live for the whole function.
    if unsafe { GetSecurityDescriptorControl(descriptor.as_ptr(), &mut control, &mut revision) }
        == 0
    {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: the validated owner SID lives in the descriptor held above.
    let owner = unsafe { sid_from_ptr(owner)? };
    // SAFETY: both ACL pointers belong to the descriptor held above; null is an
    // empty list here (the private-shape callers refuse a null DACL themselves).
    let dacl = unsafe { observed_aces(dacl)? };
    let label = unsafe { observed_aces(sacl)? };
    Ok(ObservedAcl {
        owner,
        control,
        dacl,
        label,
    })
}
/// [`observed_acl`] for a path, opened no-follow. TEST-ONLY.
#[cfg(test)]
pub(crate) fn observed_acl_at(path: &Path) -> Result<ObservedAcl, PrivateAclError> {
    observed_acl(&open_observed(path)?)
}
/// Reads a SID pointer's byte form and renders it as SDDL text.
/// SAFETY: `sid` must point at a valid SID that outlives the call.
#[cfg(test)]
pub(super) unsafe fn sid_from_ptr(sid: *mut core::ffi::c_void) -> Result<String, PrivateAclError> {
    // SAFETY: the caller guarantees a valid SID pointer.
    unsafe {
        if IsValidSid(sid) == 0 {
            return Err(PrivateAclError::UnsafePath);
        }
        let length = GetLengthSid(sid) as usize;
        if !(8..=MAX_SID_LEN).contains(&length) {
            return Err(PrivateAclError::UnsafePath);
        }
        sid_text(std::slice::from_raw_parts(sid.cast::<u8>(), length))
    }
}
/// Walks one ACL into [`ObservedAce`]s. Null is an empty list.
/// SAFETY: `acl` must be null or point at a valid ACL that outlives the call.
#[cfg(test)]
pub(super) unsafe fn observed_aces(acl: *mut ACL) -> Result<Vec<ObservedAce>, PrivateAclError> {
    if acl.is_null() {
        return Ok(Vec::new());
    }
    let mut aces = Vec::new();
    // SAFETY: the caller guarantees a valid ACL pointer.
    unsafe {
        for index in 0..u32::from((*acl).AceCount) {
            let mut ace = ptr::null_mut();
            if GetAce(acl, index, &mut ace) == 0 || ace.is_null() {
                return Err(PrivateAclError::UnsafePath);
            }
            let header = &*ace.cast::<ACE_HEADER>();
            let sid_offset = mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            let sid_len = usize::from(header.AceSize)
                .checked_sub(sid_offset)
                .ok_or(PrivateAclError::UnsafePath)?;
            if sid_len < 8 {
                return Err(PrivateAclError::UnsafePath);
            }
            let sid_raw = ace.cast::<u8>().add(sid_offset);
            let subauthorities = usize::from(*sid_raw.add(1));
            if 8 + 4 * subauthorities > sid_len {
                return Err(PrivateAclError::UnsafePath);
            }
            let mask = ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>());
            let sid = sid_text(std::slice::from_raw_parts(sid_raw, 8 + 4 * subauthorities))?;
            aces.push(ObservedAce {
                ace_type: header.AceType,
                mask,
                flags: header.AceFlags,
                sid,
            });
        }
    }
    Ok(aces)
}
/// Renders a SID's bytes as SDDL text (`S-1-5-21-…`). TEST-ONLY.
#[cfg(test)]
pub(super) fn sid_text(bytes: &[u8]) -> Result<String, PrivateAclError> {
    // A SID's sub-authorities are 4-byte aligned; copy into word storage so the
    // pointer handed to the API carries that alignment.
    let mut words = vec![0u32; bytes.len().div_ceil(4)];
    // SAFETY: `words` has at least `bytes.len()` bytes of capacity and neither
    // buffer overlaps.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().cast::<u8>(), bytes.len())
    };
    let mut string = ptr::null_mut();
    // SAFETY: `words` holds a valid SID for the whole call; output is LocalAlloc.
    if unsafe { ConvertSidToStringSidW(words.as_ptr().cast_mut().cast(), &mut string) } == 0 {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: the conversion succeeded: `string` is its LocalAlloc buffer.
    let string = unsafe { Local::from_local_alloc(string.cast()) };
    let mut len = 0;
    // SAFETY: NUL-terminated string; bound the scan to 256 units.
    unsafe {
        while len < 256 && *string.as_ptr().cast::<u16>().add(len) != 0 {
            len += 1;
        }
    }
    if len == 256 {
        return Err(PrivateAclError::Descriptor);
    }
    // SAFETY: the measured range belongs to the live returned string.
    String::from_utf16(unsafe { std::slice::from_raw_parts(string.as_ptr().cast::<u16>(), len) })
        .map_err(|_| PrivateAclError::Descriptor)
}
/// The current user's SID as SDDL text (`S-1-5-21-…`). TEST-ONLY: fixtures
/// build descriptors and assert on observed SDDL without guessing the SID.
#[cfg(test)]
pub(crate) fn current_user_sid_text() -> Result<String, PrivateAclError> {
    sid_text(UserSid::current()?.bytes())
}
/// Replaces `path`'s DACL with `dacl_sddl` (a full SDDL string carrying at least
/// a `D:` section), leaving owner and label alone. TEST-ONLY: fixtures build the
/// unsafe pre-existing roots (a default DACL, a foreign ACE) that a broad
/// upgrade must judge, and production never edits another object's DACL.
#[cfg(test)]
pub(crate) fn set_file_dacl(path: &Path, dacl_sddl: &str) -> Result<(), PrivateAclError> {
    set_file_dacl_with(path, dacl_sddl, false)
}
/// [`set_file_dacl`] that also PROTECTS the DACL, i.e. the `icacls
/// /inheritance:d` result: exactly the ACEs in `dacl_sddl` and nothing
/// inherited. The unprotected form MERGES the parent's inheritable ACEs back in
/// (native run 41155302330: an intended `D:P(A;;FA;;;U)` arrived as
/// `D:AI(A;;FA;;;U)(A;ID;FA;;;U)`), so a fixture that means "converted" must use
/// this one. TEST-ONLY.
#[cfg(test)]
pub(crate) fn set_file_dacl_protected(path: &Path, dacl_sddl: &str) -> Result<(), PrivateAclError> {
    set_file_dacl_with(path, dacl_sddl, true)
}
#[cfg(test)]
pub(super) fn set_file_dacl_with(
    path: &Path,
    dacl_sddl: &str,
    protected: bool,
) -> Result<(), PrivateAclError> {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION;
    let text: Vec<u16> = dacl_sddl.encode_utf16().chain(Some(0)).collect();
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
    // SAFETY: the conversion succeeded: `descriptor` is its LocalAlloc buffer.
    let descriptor = unsafe { Local::from_local_alloc(descriptor) };
    let mut present = 0;
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: descriptor lives for the whole function; the DACL is borrowed from it.
    if unsafe {
        GetSecurityDescriptorDacl(descriptor.as_ptr(), &mut present, &mut dacl, &mut defaulted)
    } == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(PrivateAclError::Descriptor);
    }
    let name = wide(path)?;
    let information = if protected {
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
    } else {
        DACL_SECURITY_INFORMATION
    };
    // SAFETY: NUL-terminated path and descriptor-owned DACL; only the DACL is set.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            information,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if status != 0 {
        return Err(PrivateAclError::Descriptor);
    }
    Ok(())
}
/// The handle's hard-link count
/// (`BY_HANDLE_FILE_INFORMATION::nNumberOfLinks`) — the same field the adoption
/// gate reads. TEST-ONLY: std's `Metadata::number_of_links` is still unstable
/// (rust-lang/rust#63010).
#[cfg(test)]
pub(crate) fn hard_link_count(file: &File) -> Result<u32, PrivateAclError> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: `BY_HANDLE_FILE_INFORMATION` is plain old data; a zeroed value is
    // fully initialised and the API fills it for a live handle.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    // SAFETY: live handle and a valid output slot.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(PrivateAclError::Os(std::io::Error::last_os_error()));
    }
    Ok(info.nNumberOfLinks)
}
/// Replaces `path`'s whole SACL with the label ACE(s) in `sacl_sddl` (e.g.
/// `S:(ML;;NWNR;;;LW)` for a Low label). TEST-ONLY: R2 N4 lowers the label of
/// an otherwise acceptable ancestor to prove the ancestry label check is
/// load-bearing. Needs `WRITE_OWNER` on the object.
#[cfg(test)]
pub(crate) fn set_file_label(path: &Path, sacl_sddl: &str) -> Result<(), PrivateAclError> {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    let text: Vec<u16> = sacl_sddl.encode_utf16().chain(Some(0)).collect();
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
    // SAFETY: the conversion succeeded: `descriptor` is its LocalAlloc buffer.
    let descriptor = unsafe { Local::from_local_alloc(descriptor) };
    let mut present = 0;
    let mut sacl: *mut ACL = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: descriptor lives for the whole function; the SACL is borrowed from it.
    if unsafe {
        GetSecurityDescriptorSacl(descriptor.as_ptr(), &mut present, &mut sacl, &mut defaulted)
    } == 0
        || present == 0
        || sacl.is_null()
    {
        return Err(PrivateAclError::Descriptor);
    }
    let name = wide(path)?;
    // SAFETY: NUL-terminated path and descriptor-owned SACL; only the label is set.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            sacl,
        )
    };
    if status != 0 {
        return Err(PrivateAclError::Descriptor);
    }
    Ok(())
}
/// Removes `path`'s mandatory label (its explicit label ACE; an inherited one
/// returns only on the next propagation event). TEST-ONLY: builds the
/// label-stripped sidecar that pool mode must refuse without re-stamping.
#[cfg(test)]
pub(crate) fn clear_file_label(path: &Path) -> Result<(), PrivateAclError> {
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    let name = wide(path)?;
    // SAFETY: NUL-terminated path; a NULL SACL removes the label. Needs WRITE_DAC.
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
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
#[cfg(all(test, windows))]
pub(super) mod tests {
    use super::*;
    use windows_sys::Win32::Storage::FileSystem::{FILE_APPEND_DATA, FILE_WRITE_DATA};
    /// `S-1-5-21-<sub…>`: an ordinary user account SID.
    fn user_sid(parts: &[u32]) -> Vec<u8> {
        sid(SECURITY_NT_AUTHORITY, parts)
    }
    fn sid(authority: u64, parts: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, parts.len() as u8];
        // A SID header is revision(1) + count(1) + a SIX-byte identifier
        // authority, big-endian. Writing all eight bytes of the u64 shifts every
        // sub-authority by two and makes the fixture a malformed SID (native run
        // 41151503624: `principal_trusted(LocalSystem)` then read authority 0).
        bytes.extend(&authority.to_be_bytes()[2..]);
        for part in parts {
            bytes.extend(part.to_le_bytes());
        }
        bytes
    }
    // The ancestor policy is a pure function of the SID bytes, so every
    // principal class is exercised without constructing foreign-owned objects.
    #[test]
    fn only_self_and_system_principals_are_trusted() {
        let me = user_sid(&[21, 42, 7]);
        let other_user = user_sid(&[21, 42, 8]);
        assert!(principal_trusted(&me, &me));
        assert!(!principal_trusted(&other_user, &me), "another user account");
        assert!(principal_trusted(&sid(5, &[18]), &me), "LocalSystem");
        assert!(
            principal_trusted(&sid(5, &[32, 544]), &me),
            "Administrators"
        );
        // TrustedInstaller, which owns a drive root and Program Files.
        assert!(principal_trusted(
            &sid(
                5,
                &[80, 956008885, 3418522649, 1831038044, 1853292631, 2271478464]
            ),
            &me
        ));
        // Groups are not trusted even when the current user belongs to them: the
        // group also carries unrelated users.
        assert!(
            !principal_trusted(&sid(5, &[11]), &me),
            "Authenticated Users"
        );
        assert!(!principal_trusted(&sid(5, &[32, 545]), &me), "Users");
        assert!(!principal_trusted(&sid(1, &[0]), &me), "Everyone");
        // Malformed and empty SIDs are refused, never trusted.
        assert!(!principal_trusted(&[], &me));
        assert!(!principal_trusted(&[1, 9, 0, 0, 0, 0, 0, 5], &me));
    }
    // ROOT's F5 refinement: ADOPTION tolerates exactly the user, LocalSystem and
    // BUILTIN\Administrators, byte-exact — NARROWER than the ancestry rule
    // above, which also tolerates S-1-5-80-* service accounts.
    #[test]
    fn adoption_trusts_only_the_user_system_and_administrators() {
        let me = user_sid(&[21, 42, 7]);
        assert!(adoption_trusted(&me, &me));
        assert!(adoption_trusted(&sid(5, &[18]), &me), "LocalSystem");
        assert!(adoption_trusted(&sid(5, &[32, 544]), &me), "Administrators");
        assert!(
            !adoption_trusted(&sid(5, &[80, 1, 2]), &me),
            "a service account is 'another SID' for adoption"
        );
        assert!(!adoption_trusted(&sid(5, &[32, 545]), &me), "Users");
        assert!(!adoption_trusted(&sid(1, &[0]), &me), "Everyone");
        assert!(
            !adoption_trusted(&user_sid(&[21, 42, 8]), &me),
            "another user"
        );
    }
    #[test]
    fn only_entry_removing_rights_are_matched_after_generic_mapping() {
        for mask in [DELETE, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER] {
            assert_eq!(effective_mask(mask) & ENTRY_REMOVING, mask, "{mask:08x}");
        }
        // Generic all maps onto the full file mask, which contains all four.
        assert_eq!(effective_mask(GENERIC_ALL) & ENTRY_REMOVING, ENTRY_REMOVING);
        // Create-only rights on a directory are tolerated; they cannot displace an
        // existing entry (delete/rename needs DELETE on the child or
        // FILE_DELETE_CHILD here), and the private leaf refuses a planted object.
        for mask in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            GENERIC_WRITE,
            GENERIC_READ,
        ] {
            assert_eq!(effective_mask(mask) & ENTRY_REMOVING, 0, "{mask:08x}");
        }
    }
    #[test]
    fn descriptor_text_renders_the_inheriting_directory_form() {
        let sid = "S-1-5-21-42";
        assert_eq!(
            descriptor_text(sid, DescriptorKind::InheritingDirectory),
            format!("O:{sid}D:P(A;OICI;FA;;;{sid})S:(ML;OICI;NWNR;;;ME)")
        );
    }
    // The shape the pool's leaf must have, and the shape its SQLite sidecars then
    // get: a child created with NO explicit descriptor inherits the owner-only
    // grant and the NW|NR label. The exact check still refuses it (its DACL is
    // auto-inherited, not protected), which is why the inherited-aware one exists.
    #[test]
    fn an_inheriting_private_directory_admits_a_private_child() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        create_private_directory_inheriting(&dir).unwrap();
        drop(open_private_directory_inheriting(&dir).unwrap());
        let child_path = dir.join("child");
        drop(std::fs::File::create(&child_path).unwrap());
        let child = open_unchecked_shared_handle(&child_path, false).unwrap();
        assert!(
            check_private_handle(&child).is_err(),
            "control: an inherited DACL is not the at-creation protected shape"
        );
        check_private_inherited_handle_as(&child, &UserSid::current().unwrap())
            .expect("an inherited private child is accepted");
    }
    // A synthetic SID that is not the token's own must never pass the private
    // owner check, while the real token SID does. No foreign-OWNED file is
    // constructible unprivileged, so the identity is what is synthetic here; the
    // file itself is real.
    #[test]
    fn a_foreign_identity_is_refused_for_a_real_private_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = create_new_private_file(&tmp.path().join("private.bin")).unwrap();
        assert!(
            check_private_handle(&file).is_ok(),
            "control: exactly private"
        );
        let foreign = UserSid::synthetic(&user_sid(&[21, 42, 8]));
        assert_ne!(foreign.bytes(), UserSid::current().unwrap().bytes());
        assert!(
            matches!(
                check_private_handle_as(&file, &foreign),
                Err(PrivateAclError::UnsafePath)
            ),
            "the private owner check must be bound to the identity it is given"
        );
    }
    // ROOT's owner policy for an INHERITED sidecar. Reds if the accepted set
    // widens: any SID beyond the token user SID, or beyond the token default
    // owner when that value is byte-exactly BUILTIN\Administrators, must be
    // refused — group membership is never consulted.
    #[test]
    fn sidecar_owner_policy_accepts_only_the_user_or_an_administrators_default_owner() {
        let user = user_sid(&[21, 42, 7]);
        let administrators = user_sid(&[32, 544]);
        let other_group = user_sid(&[32, 545]);
        let foreign = user_sid(&[21, 42, 8]);
        // The constant really is S-1-5-32-544 under SECURITY_NT_AUTHORITY.
        assert_eq!(authority(&ADMINISTRATORS_SID), Some(SECURITY_NT_AUTHORITY));
        assert_eq!(sub_authority(&ADMINISTRATORS_SID, 0), Some(32));
        assert_eq!(sub_authority(&ADMINISTRATORS_SID, 1), Some(544));
        assert_eq!(administrators, ADMINISTRATORS_SID);
        // The user's own SID is accepted under any token default owner.
        assert!(sidecar_owner_acceptable(&user, &user, &user));
        assert!(sidecar_owner_acceptable(&user, &user, &administrators));
        // Administrators is accepted ONLY when the token's default owner is
        // exactly Administrators (the elevated-token shape).
        assert!(sidecar_owner_acceptable(
            &administrators,
            &user,
            &administrators
        ));
        assert!(!sidecar_owner_acceptable(
            &administrators,
            &user,
            &other_group
        ));
        // A different owner-capable group grants nothing, even when it is the
        // token's default owner.
        assert!(!sidecar_owner_acceptable(&other_group, &user, &other_group));
        // Any other SID is refused.
        assert!(!sidecar_owner_acceptable(&foreign, &user, &administrators));
    }
    // R2 N2: the PRODUCTION predicate over raw bytes, not `adoption_trusted` or
    // `sidecar_owner_acceptable` alone. An Administrators-observed owner is
    // accepted ONLY with an Administrators default owner, and is refused on a
    // user token's default owner — the exact case a test feeding a synthetic
    // observed owner depends on.
    #[test]
    fn the_owner_policy_predicate_refuses_administrators_under_a_user_default_owner() {
        let user = UserSid::synthetic(&user_sid(&[21, 42, 7]));
        let administrators = UserSid::synthetic(&ADMINISTRATORS_SID);
        assert!(
            !owner_policy_ok(&ADMINISTRATORS_SID, &user, Some(&user)),
            "Administrators observed on a user default owner must be refused"
        );
        assert!(
            owner_policy_ok(&ADMINISTRATORS_SID, &user, Some(&administrators)),
            "Administrators observed under an Administrators default owner is accepted"
        );
        assert!(
            owner_policy_ok(user.bytes(), &user, Some(&user)),
            "the user's own SID is accepted"
        );
        assert!(
            !owner_policy_ok(&ADMINISTRATORS_SID, &user, None),
            "the exact-shape policy accepts only the user SID"
        );
    }
    // The INHERITED checker stays bound to the identity it is handed: the
    // control (the real token user) accepts the inherited child, and a
    // synthetic foreign identity is refused on the DACL grant alone.
    #[test]
    fn the_inherited_checker_is_bound_to_its_identity() {
        let _env = crate::platform::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        create_private_directory_inheriting(&dir).unwrap();
        let child_path = dir.join("child");
        drop(std::fs::File::create(&child_path).unwrap());
        let child = open_unchecked_shared_handle(&child_path, false).unwrap();
        check_private_inherited_handle_as(&child, &UserSid::current().unwrap())
            .expect("control: the token user accepts the inherited private child");
        let foreign = UserSid::synthetic(&user_sid(&[21, 42, 8]));
        assert!(
            matches!(
                check_private_inherited_handle_as(&child, &foreign),
                Err(PrivateAclError::UnsafePath)
            ),
            "the inherited checker must refuse an identity the child does not grant"
        );
    }
    // The seam feeds the SAME function the sidecar checker reads, so the
    // Administrators branch can be exercised on a host that is not elevated
    // (an unprivileged test cannot create an Administrators-owned object).
    #[test]
    fn the_default_owner_seam_feeds_the_sidecar_owner_policy() {
        let _env = crate::platform::test_env::lock();
        let administrators = user_sid(&[32, 544]);
        let token_before = sidecar_default_owner_for_test().expect("token default owner readable");
        let observed = with_default_owner_for_test(
            Some(administrators.as_slice()),
            sidecar_default_owner_for_test,
        )
        .expect("seam value");
        assert_eq!(observed, administrators);
        let token_after = sidecar_default_owner_for_test().expect("token default owner readable");
        assert_eq!(
            token_before, token_after,
            "the seam must restore the token's own value"
        );
        assert!(
            token_after.len() >= 8,
            "the token's default owner is a real SID"
        );
    }
    // R1 M3: only the Administrators default-owner branch is worth tightening;
    // a user-owned sidecar and every refused owner are not.
    #[test]
    fn only_the_administrators_default_owner_branch_needs_tightening() {
        let user = user_sid(&[21, 42, 7]);
        let administrators = ADMINISTRATORS_SID.to_vec();
        assert!(!sidecar_owner_needs_tightening(
            &user,
            &user,
            &administrators
        ));
        assert!(sidecar_owner_needs_tightening(
            &administrators,
            &user,
            &administrators
        ));
        // Refused owners are never tightened (the checker refuses them first).
        assert!(!sidecar_owner_needs_tightening(
            &administrators,
            &user,
            &user_sid(&[21, 42, 7])
        ));
        let other = user_sid(&[21, 42, 8]);
        assert!(!sidecar_owner_needs_tightening(
            &other,
            &user,
            &administrators
        ));
    }
    // R1 F3: the owner policy runs INSIDE the inherited checker (point of use),
    // against the owner the object really has. On the elevated native runner
    // SQLite's NULL-attribute child is owned by Administrators: the same child
    // is refused when the token default owner says user and accepted when it
    // says Administrators; forcing the policy to `true` reddens the refusal.
    #[test]
    fn the_sidecar_owner_policy_is_applied_at_point_of_use() {
        let _env = crate::platform::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        create_private_directory_inheriting(&dir).unwrap();
        let child_path = dir.join("sidecar");
        drop(std::fs::File::create(&child_path).unwrap());
        let child = open_unchecked_shared_handle(&child_path, false).unwrap();
        let user = UserSid::current().unwrap();
        let administrators = ADMINISTRATORS_SID.to_vec();
        let observed = observed_owner(&child).unwrap();
        let user_owned = observed == user.bytes();
        assert!(
            user_owned || observed == administrators,
            "premise: a child created with no descriptor is owned by the token \
             user or BUILTIN\\Administrators ({} bytes observed)",
            observed.len()
        );
        // The accepting direction holds on every host: the token default owner
        // is exactly what created this child.
        with_default_owner_for_test(Some(administrators.as_slice()), || {
            check_private_inherited_handle_as(&child, &user)
        })
        .expect("the production owner set is accepted with its default owner");
        // The refusing direction on the elevated shape: the SAME child, judged
        // with a default owner that is not its owner.
        if !user_owned {
            let refused = with_default_owner_for_test(Some(user.bytes()), || {
                check_private_inherited_handle_as(&child, &user)
            });
            assert!(
                matches!(refused, Err(PrivateAclError::UnsafePath)),
                "an Administrators-owned sidecar must be refused when the \
                 token's default owner is the user"
            );
        }
        // The point-of-use predicate against the REAL observed owner with a
        // foreign default owner: true only through the user-SID branch.
        let foreign_default = UserSid::synthetic(&user_sid(&[21, 42, 8]));
        assert_eq!(
            owner_policy_ok(&observed, &user, Some(&foreign_default)),
            user_owned,
            "a foreign default owner admits only the user's own SID"
        );
    }
    // R2 N2 (continued): the point-of-use call can be made to FAIL on an
    // unprivileged runner. The observed-owner seam synthesises an
    // Administrators-owned descriptor; under a USER default owner the same
    // private child the control accepts must be refused. Stubbing the
    // `owner_policy_ok` call in `inspect_shape` to `true` reddens the refusal —
    // the native mutation proof recorded with the fix delta.
    #[test]
    fn a_synthetic_administrators_owner_is_refused_at_the_point_of_use() {
        let _env = crate::platform::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("private");
        create_private_directory_inheriting(&dir).unwrap();
        let child_path = dir.join("sidecar");
        drop(std::fs::File::create(&child_path).unwrap());
        let child = open_unchecked_shared_handle(&child_path, false).unwrap();
        let user = UserSid::current().unwrap();
        // Control: the real owner (the user SID) is accepted under a user
        // default owner — so the refusal below is the observed owner's.
        with_default_owner_for_test(Some(user.bytes()), || {
            with_observed_owner_for_test(Some(user.bytes()), || {
                check_private_inherited_handle_as(&child, &user)
            })
        })
        .expect("control: the real owner is accepted");
        // Only the OBSERVED owner changes here.
        let refused = with_default_owner_for_test(Some(user.bytes()), || {
            with_observed_owner_for_test(Some(&ADMINISTRATORS_SID), || {
                check_private_inherited_handle_as(&child, &user)
            })
        });
        assert!(
            matches!(refused, Err(PrivateAclError::UnsafePath)),
            "an Administrators-observed sidecar under a user default owner must \
             be refused at the point of use"
        );
    }
    // R2 NEW-1: ADOPTION refuses ANY foreign allow ACE, whatever its mask —
    // read-only, create-only, inherit-only and numeric — where the ancestry
    // rule tolerates a grant that cannot displace an entry. The DACL is planted
    // PROTECTED so no parent ACE merges in and the premise is exact.
    #[test]
    fn adoption_refuses_any_foreign_allow_ace_whatever_its_mask() {
        let _env = crate::platform::test_env::lock();
        let sid = current_user_sid_text().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let control_path = tmp.path().join("control");
        drop(std::fs::File::create(&control_path).unwrap());
        set_file_dacl_protected(
            &control_path,
            &format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"),
        )
        .unwrap();
        let control = open_unchecked_shared_handle(&control_path, false).unwrap();
        check_no_foreign_write_for_adoption(&control)
            .expect("control: the user, SYSTEM and Administrators are trusted");
        for (name, ace) in [
            ("read-only BU", "(A;OICI;FR;;;BU)"),
            ("numeric-mask BU", "(A;;0x1201bf;;;BU)"),
            ("create-only other user", "(A;CI;0x6;;;S-1-5-21-42-8)"),
            ("inherit-only Everyone", "(A;OIIO;FA;;;WD)"),
        ] {
            let path = tmp.path().join(name.replace(' ', "-"));
            // The adoption gate judges a DIRECTORY root, so the matrix is
            // planted on directories. Windows DROPS an inherit-only ACE on a
            // non-container (native run 41164586693: the file case came back
            // with 3 ACEs and the premise, not the production refusal, failed).
            std::fs::create_dir(&path).unwrap();
            set_file_dacl_protected(
                &path,
                &format!("D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA){ace}"),
            )
            .unwrap();
            // Premise: the foreign ACE really is in the DACL the gate reads.
            let planted = observed_acl_at(&path).unwrap();
            assert_eq!(
                planted.dacl.len(),
                4,
                "premise: the planted ACE is present for {name}: {planted:?}"
            );
            let file = open_directory_check_handle(&path).unwrap();
            assert!(
                matches!(
                    check_no_foreign_write_for_adoption(&file),
                    Err(PrivateAclError::UnsafePath)
                ),
                "adoption must refuse a foreign allow ACE: {name}"
            );
        }
    }
    // R2 N4: the L2 branch is load-bearing. A directory that is otherwise
    // acceptable is refused once its mandatory label is lowered to Low, and
    // accepted again when the label returns to Medium — only the label differs
    // between the two measurements.
    #[test]
    fn a_low_integrity_label_on_the_directory_refuses_ancestry() {
        let _env = crate::platform::test_env::lock();
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ancestor");
        create_private_directory_inheriting(&dir).unwrap();
        let handle = open_directory_check_handle(&dir).unwrap();
        check_no_foreign_write(&handle).expect("control: the Medium label is accepted");
        set_file_label(&dir, "S:(ML;;NWNR;;;LW)").expect("lower the label to Low");
        assert!(
            matches!(
                check_no_foreign_write(&handle),
                Err(PrivateAclError::UnsafePath)
            ),
            "a Low mandatory label on the directory must refuse ancestry"
        );
        set_file_label(&dir, "S:(ML;;NWNR;;;ME)").expect("raise the label back to Medium");
        check_no_foreign_write(&handle).expect("the Medium label is accepted again");
    }
}
