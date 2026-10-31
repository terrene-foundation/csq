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
//!
//! A second, deliberately looser primitive serves ANCESTRY: [`check_no_foreign_write`]
//! refuses a directory in which a principal other than the current user (or a
//! system-level one) holds a right that can remove, rename or re-secure entries.
//! It is not an owner-only check — an ancestor such as a drive root is never owned
//! by the user — and its exact policy is documented at its definition.
//!
//! [`create_private_directory_inheriting`] is the one form that PROPAGATES: its
//! single owner-only ACE and its label carry `OBJECT_INHERIT | CONTAINER_INHERIT`,
//! so files a third party (SQLite's sidecars) creates in that directory inherit
//! the same private grant and the same no-read-up label instead of an empty DACL.
//! [`check_private_directory_inheriting`] verifies that directory and
//! [`check_private_inherited_handle_as`] accepts such a child; the plain
//! [`check_private_handle`] still requires the at-creation shape and is what every
//! other private object is judged by, so the inheritable form exists only where a
//! third party writes.
use super::fs_windows_delete;
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
        CloseHandle, LocalFree, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
        },
        EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
        IsValidSid, SetKernelObjectSecurity, TokenOwner, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER,
        DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        SECURITY_ATTRIBUTES, SE_DACL_PROTECTED, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, CREATE_NEW, DELETE, FILE_ALL_ACCESS, FILE_DELETE_CHILD,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
// TEST-ONLY: the DACL/SACL getters and the `ACL` type are used by the fixture
// writers and the parsed-descriptor reader only; production reads descriptors
// through `GetSecurityInfo` into inferred pointers.
#[cfg(test)]
use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, GetSecurityDescriptorSacl, ACL};

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

/// `BUILTIN\Administrators` (`S-1-5-32-544`) as SID bytes: revision 1, two
/// sub-authorities under `SECURITY_NT_AUTHORITY` (32, 544), little-endian.
const ADMINISTRATORS_SID: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0];
/// The owner decision over RAW observed bytes — the exact check for every shape,
/// and [`sidecar_owner_acceptable`] for a sidecar. Separated from the descriptor
/// walk so the Administrators branch can be driven with synthetic observed bytes
/// on a host that cannot construct an Administrators-owned object (R1 L5a).
fn owner_policy_ok(observed: &[u8], user: &UserSid, sidecar_owner: Option<&UserSid>) -> bool {
    match sidecar_owner {
        None => observed == user.bytes(),
        Some(default_owner) => {
            sidecar_owner_acceptable(observed, user.bytes(), default_owner.bytes())
        }
    }
}

fn create_directory_with(path: &Path, kind: DescriptorKind) -> Result<(), PrivateAclError> {
    let path = wide(path)?;
    let security = descriptor_with(kind)?;
    let attributes = attributes(&security);
    // SAFETY: path and descriptor stay alive throughout synchronous creation.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(PrivateAclError::Os(io::Error::last_os_error()));
    }
    Ok(())
}

mod check;
mod descriptor;
mod open;
mod sid;
#[cfg(all(test, windows))]
mod windows_tests;

pub(crate) use check::*;
pub(crate) use descriptor::*;
pub(crate) use open::*;
pub(crate) use sid::*;
#[cfg(all(test, windows))]
pub(crate) use windows_tests::*;
