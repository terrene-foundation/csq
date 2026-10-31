use super::*;
/// Whether an owner-only object carries the exact private integrity label.
pub(in crate::platform) enum Label {
    Present,
    Absent,
}
/// `Ok(())` iff the handle's owner, protected DACL AND mandatory label are
/// exactly the private shape. A missing label is refused here; pre-label objects
/// are upgraded only through [`crate::platform::fs_windows_stamp::ensure_private_handle`]. Needs `READ_CONTROL`.
pub(crate) fn check_private_handle(file: &File) -> Result<(), PrivateAclError> {
    check_private_handle_as(file, &UserSid::current()?)
}
/// [`check_private_handle`] against an explicit identity. Production passes the
/// process token's own SID ([`check_private_handle`]); the parameter exists so
/// the SAME owner policy can be exercised with a synthetic foreign SID, which an
/// unprivileged host cannot otherwise construct.
pub(crate) fn check_private_handle_as(file: &File, user: &UserSid) -> Result<(), PrivateAclError> {
    match inspect_as(file, user).map_err(note_refusal)? {
        Label::Present => Ok(()),
        Label::Absent => Err(PrivateAclError::UnsafePath),
    }
}
/// [`check_private_handle`] for a DIRECTORY created by
/// [`create_private_directory_inheriting`]: one owner-only `FILE_ALL_ACCESS`
/// ACE and one explicit label ACE, both carrying `OBJECT_INHERIT` and
/// `CONTAINER_INHERIT`, so children inherit the private shape. The stricter
/// exact check refuses this form on purpose: only the directory a third-party
/// writer creates files in may carry inheritable ACEs.
pub(crate) fn check_private_directory_inheriting(file: &File) -> Result<(), PrivateAclError> {
    check_private_directory_inheriting_as(file, &UserSid::current()?)
}
/// [`check_private_directory_inheriting`] against an explicit identity.
pub(crate) fn check_private_directory_inheriting_as(
    file: &File,
    user: &UserSid,
) -> Result<(), PrivateAclError> {
    match inspect_shape(file, user, Shape::InheritingDirectory, None).map_err(note_refusal)? {
        (Label::Present, _) => Ok(()),
        (Label::Absent, _) => Err(PrivateAclError::UnsafePath),
    }
}
/// `Ok(())` iff `file` is a SIDECAR: a child of an inheriting private directory
/// — an UNPROTECTED DACL with the single `FILE_ALL_ACCESS` ACE for the current
/// user (ACE flags EXACTLY `{}` or exactly `{INHERITED_ACE}` — the native runner
/// clears them; any object/container-inherit or inherit-only bit is refused, see
/// [`Shape::Inherited`]), and an INHERITED
/// Medium NW|NR label. Every other shape is REFUSED: the at-creation form (csq
/// never creates a sidecar, so a planted one must not be trusted), a DACL with
/// inheritance broken (`icacls /inheritance:d`, which protects it), an explicit
/// label (csq never stamps a sidecar), and a label-stripped child (R1 M1).
///
/// The owner follows [`sidecar_owner_acceptable`]: the token user SID, or the
/// token's default owner when that value is byte-exactly `BUILTIN\Administrators`
/// (an elevated token stamps that on a NULL-attribute child). The DACL grant is
/// still exactly `user`, so the identity argument stays load-bearing.
pub(crate) fn check_private_inherited_handle_as(
    file: &File,
    user: &UserSid,
) -> Result<(), PrivateAclError> {
    let default_owner = sidecar_default_owner()?;
    let (label, inherited) =
        inspect_shape(file, user, Shape::Inherited, Some(&default_owner)).map_err(note_refusal)?;
    // An explicit label is refused inside `inspect_shape`; the only accepted
    // state is therefore Absent WITH at least one applicable inherited label.
    match label {
        Label::Absent if inherited > 0 => Ok(()),
        _ => Err(PrivateAclError::UnsafePath),
    }
}
/// `Ok(())` iff no principal other than the current user (or a system-level one,
/// see [`principal_trusted`]) holds a right that can remove, rename or re-secure
/// an entry of this directory, and the directory's owner is such a principal.
///
/// This is the ancestor rule, not the private-file rule: unlike
/// [`check_private_handle`] it accepts inherited broad READ grants and ordinary
/// create-only rights, because a drive root, `C:\Users` and a profile's
/// `AppData` chain all carry them and none of them lets a foreigner displace an
/// existing entry. A null DACL (everyone full control), an unreadable or
/// malformed descriptor, a foreign owner (an owner always holds `WRITE_DAC` and
/// so can re-secure the directory), an object ACE the grantee cannot be
/// classified from, an unknown ACE type, and a mandatory label BELOW Medium (a
/// Low-integrity same-user process could then replace entries) are all refused.
/// Needs `READ_CONTROL`.
///
/// The pool-root ADOPTION uses the narrower
/// [`check_no_foreign_write_for_adoption`] trust set; every other caller keeps
/// this ancestry rule unchanged.
pub(crate) fn check_no_foreign_write(file: &File) -> Result<(), PrivateAclError> {
    check_no_foreign_write_with(file, principal_trusted, TrustMode::Ancestry)
}
/// [`check_no_foreign_write`] under the ADOPTION-ONLY trust rule (ROOT R1 F5
/// ruling): exactly the current user, `LocalSystem` and `BUILTIN\Administrators`,
/// byte-exact — no `S-1-5-80-*` service accounts, which the ancestry rule
/// tolerates. Adoption also judges EVERY allow ACE by its principal, whatever
/// its mask and even when it is inherit-only (R2 NEW-1): a foreign principal
/// that can merely create or write entries inside the root is not tolerated.
/// Used only by the pool-root adopt-and-tighten.
pub(crate) fn check_no_foreign_write_for_adoption(file: &File) -> Result<(), PrivateAclError> {
    check_no_foreign_write_with(file, adoption_trusted, TrustMode::Adoption)
}
/// How an ACCESS_ALLOWED ACE is judged.
#[derive(Clone, Copy)]
pub(super) enum TrustMode {
    /// Ancestry: only entry-removing rights matter, and an inherit-only ACE
    /// does not apply to this object.
    Ancestry,
    /// Adoption: every applicable allow ACE must name a trusted principal,
    /// whatever its mask. Deny ACEs stay harmless (they grant nothing).
    Adoption,
}
pub(super) fn check_no_foreign_write_with(
    file: &File,
    trust: fn(&[u8], &[u8]) -> bool,
    mode: TrustMode,
) -> Result<(), PrivateAclError> {
    let current = UserSid::current()?;
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
    if status != 0 || descriptor.as_ptr().is_null() || owner.is_null() {
        return Err(PrivateAclError::UnsafePath);
    }
    // SAFETY: the validated SID and ACL live in the descriptor held above.
    unsafe {
        if IsValidSid(owner) == 0 {
            return Err(PrivateAclError::UnsafePath);
        }
        // A `u32` length; the widening cast cannot truncate.
        let length = GetLengthSid(owner) as usize;
        if !(8..=MAX_SID_LEN).contains(&length) {
            return Err(PrivateAclError::UnsafePath);
        }
        if !trust(
            std::slice::from_raw_parts(owner.cast::<u8>(), length),
            current.bytes(),
        ) {
            return Err(PrivateAclError::UnsafePath);
        }
        // A null DACL grants every principal full control.
        if dacl.is_null() {
            return Err(PrivateAclError::UnsafePath);
        }
        for index in 0..u32::from((*dacl).AceCount) {
            let mut ace = ptr::null_mut();
            if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
                return Err(PrivateAclError::UnsafePath);
            }
            let header = &*ace.cast::<ACE_HEADER>();
            match header.AceType {
                // ACCESS_ALLOWED_ACE_TYPE.
                0 => {
                    // An inherit-only ACE does not apply to this object — but
                    // ADOPTION still judges its principal (R2 NEW-1).
                    if matches!(mode, TrustMode::Ancestry)
                        && header.AceFlags & INHERIT_ONLY_ACE != 0
                    {
                        continue;
                    }
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
                    let sid = std::slice::from_raw_parts(sid_raw, 8 + 4 * subauthorities);
                    let trusted = trust(sid, current.bytes());
                    match mode {
                        TrustMode::Ancestry => {
                            if effective_mask(mask) & ENTRY_REMOVING != 0 && !trusted {
                                return Err(PrivateAclError::UnsafePath);
                            }
                        }
                        // Adoption refuses ANY foreign allow ACE, whatever its
                        // mask: create-only or read-only rights still let another
                        // principal plant entries inside a root csq would then
                        // declare private.
                        TrustMode::Adoption => {
                            if !trusted {
                                return Err(PrivateAclError::UnsafePath);
                            }
                        }
                    }
                }
                // Deny ACEs, mandatory labels (never effective in a DACL) and the
                // DACL-only resource-attribute/scoped-policy ACE types grant nothing.
                1 | 0x11 | 0x12 | 0x13 => {}
                // Object ACEs and unknown types: the grantee cannot be classified.
                _ => return Err(PrivateAclError::UnsafePath),
            }
        }
        // A mandatory label BELOW Medium on an ancestor lets a Low-integrity
        // same-user process replace entries of this directory; refuse. No label
        // is the implicit Medium level and is accepted. Non-label SACL ACEs
        // (audit) are ignored; a malformed label ACE is refused.
        if !sacl.is_null() {
            for index in 0..u32::from((*sacl).AceCount) {
                let mut ace = ptr::null_mut();
                if GetAce(sacl, index, &mut ace) == 0 || ace.is_null() {
                    return Err(PrivateAclError::UnsafePath);
                }
                let header = &*ace.cast::<ACE_HEADER>();
                if header.AceType != LABEL_ACE_TYPE {
                    continue;
                }
                let sid_offset = mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
                if usize::from(header.AceSize) < sid_offset + 12 {
                    return Err(PrivateAclError::UnsafePath);
                }
                if header.AceFlags & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                let sid = std::slice::from_raw_parts(ace.cast::<u8>().add(sid_offset), 12);
                match label_rid(sid) {
                    Some(rid) if rid >= MEDIUM_RID => {}
                    _ => return Err(PrivateAclError::UnsafePath),
                }
            }
        }
    }
    Ok(())
}
/// Set once the inherited-label refusal has been logged in this process.
pub(super) static INHERITED_LABEL_LOGGED: AtomicBool = AtomicBool::new(false);
/// `true` exactly once per `flag`.
pub(super) fn first_time(flag: &AtomicBool) -> bool {
    !flag.swap(true, Ordering::SeqCst)
}
/// Passes `error` through; the first [`PrivateAclError::InheritedLabel`] of the process
/// also logs a WARN. A parent carrying an unacceptable inheritable label refuses EVERY
/// private file under it, so a per-file WARN would flood the log with one line per
/// object; the fixed tag names the cause once and the error itself still reaches each
/// caller.
pub(in crate::platform) fn note_refusal(error: PrivateAclError) -> PrivateAclError {
    if matches!(error, PrivateAclError::InheritedLabel) && first_time(&INHERITED_LABEL_LOGGED) {
        tracing::warn!(
            error_kind = "private_acl_inherited_label_refused",
            "an inherited mandatory label is not acceptable beside csq's; private files \
             under that parent are refused (logged once per process)"
        );
    }
    error
}
pub(in crate::platform) fn inspect(file: &File) -> Result<Label, PrivateAclError> {
    inspect_as(file, &UserSid::current()?)
}
/// [`inspect`] against an explicit identity; see [`check_private_handle_as`].
pub(in super::super) fn inspect_as(file: &File, user: &UserSid) -> Result<Label, PrivateAclError> {
    inspect_shape(file, user, Shape::Exact, None).map(|(label, _)| label)
}
/// The label state plus the number of applicable INHERITED label ACEs, for the
/// caller that may accept an inherited-only label ([`check_private_inherited_handle_as`]).
/// `sidecar_owner` is `Some` only for a child of the inheriting pool leaf, where
/// the owner policy of [`sidecar_owner_acceptable`] applies; every other shape
/// compares the owner exactly.
pub(super) fn inspect_shape(
    file: &File,
    user: &UserSid,
    shape: Shape,
    sidecar_owner: Option<&UserSid>,
) -> Result<(Label, usize), PrivateAclError> {
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
        if GetSecurityDescriptorControl(descriptor.as_ptr(), &mut control, &mut revision) == 0 {
            return Err(PrivateAclError::UnsafePath);
        }
        // A csq-created object's DACL is explicitly protected; an object that
        // inherited its private shape from [`Shape::InheritingDirectory`] is
        // auto-inherited instead, which is not the same control bit.
        // A sidecar's DACL must be UNPROTECTED (auto-inherited from the leaf):
        // a protected one means someone broke inheritance on a third-party
        // file, which is tampering, not the shape SQLite creates (R1 M1).
        let protection_ok = match shape {
            Shape::Exact | Shape::InheritingDirectory => control & SE_DACL_PROTECTED != 0,
            Shape::Inherited => control & SE_DACL_PROTECTED == 0,
        };
        if !protection_ok || IsValidSid(owner) == 0 || (*dacl).AceCount != 1 {
            return Err(PrivateAclError::UnsafePath);
        }
        // The owner must be the token user SID; a SIDECAR may instead be owned
        // by a token whose DEFAULT owner is exactly BUILTIN\Administrators —
        // exact SID equality, never group membership (see
        // `sidecar_owner_acceptable`); every other shape keeps the exact check.
        let length = GetLengthSid(owner) as usize;
        if !(8..=MAX_SID_LEN).contains(&length) {
            return Err(PrivateAclError::UnsafePath);
        }
        let observed_sid = std::slice::from_raw_parts(owner.cast::<u8>(), length);
        // Test builds can synthesise the observed owner so the point-of-use
        // policy call is exercised on an unprivileged runner (R2 N2).
        #[cfg(test)]
        let observed: &[u8] = &OBSERVED_OWNER_OVERRIDE
            .with(|slot| slot.borrow().clone())
            .unwrap_or_else(|| observed_sid.to_vec());
        #[cfg(not(test))]
        let observed: &[u8] = observed_sid;
        if !owner_policy_ok(observed, user, sidecar_owner) {
            if sidecar_owner.is_some() && first_time(&SIDECAR_OWNER_REFUSED_LOGGED) {
                tracing::warn!(
                    error_kind = "pool_sidecar_owner_refused",
                    "a pool sidecar's owner is neither the token user nor an \
                     Administrators default owner; the ledger is unavailable \
                     (logged once per process)"
                );
            }
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
        // The ACE flags are the only difference between the shapes: a directory
        // csq created for a third-party writer carries both inherit bits so its
        // children inherit the grant. A FILE sidecar's ACE is exactly `{}` or
        // `{ID}` (ROOT R2 ruling): the native Windows runner (run 41151503624)
        // produced a NULL-attribute child of the inheriting leaf whose DACL ACE
        // was `(A;;FA;;;S-1-5-21-…-1005)` — the grant copied with every flag
        // cleared, DACL unprotected, while its label arrived `ID`-flagged. OI/CI
        // are meaningless on a file and INHERIT_ONLY/audit bits would mean the
        // ACE does not even apply, so no other combination is accepted. Every
        // shape still grants exactly FILE_ALL_ACCESS to exactly the current user
        // and nobody else.
        let flags_ok = match shape {
            Shape::Exact => ace.Header.AceFlags == 0,
            Shape::InheritingDirectory => ace.Header.AceFlags == INHERIT_BOTH,
            Shape::Inherited => ace.Header.AceFlags == 0 || ace.Header.AceFlags == INHERITED_ACE,
        };
        if ace.Header.AceType != 0
            || !flags_ok
            || ace.Mask != FILE_ALL_ACCESS
            || IsValidSid(sid) == 0
            || !user.matches(sid)
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
            // Our own label ACE: non-inherited on a csq-created object, and
            // carrying both inherit bits on the directory whose children inherit it.
            let label_flags_ok = match shape {
                Shape::Exact => header.AceFlags == 0,
                Shape::InheritingDirectory => header.AceFlags == INHERIT_BOTH,
                // A sidecar's label is INHERITED from the leaf; csq never
                // stamps a sidecar, so an explicit label ACE there was written
                // by someone else and the file is refused (R1 M1).
                Shape::Inherited => false,
            };
            if !label_flags_ok || mask != LABEL_MASK || rid != Some(MEDIUM_RID) {
                return Err(PrivateAclError::UnsafePath);
            }
        }
        if explicit > 1 {
            return Err(PrivateAclError::UnsafePath);
        }
        Ok((
            if explicit == 1 {
                Label::Present
            } else {
                Label::Absent
            },
            inherited,
        ))
    }
}
