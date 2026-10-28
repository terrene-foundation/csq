//! Native Windows tests: `write_new_private*` births an owner-only file.
//! Cross compilation is not runtime proof; these run only on a Windows host.
use super::fs::{atomic_replace, write_new_private, write_new_private_synced};
use super::fs_windows_acl::{
    check_private_handle, create_new_private_file, descriptor_text, open_private_file,
    DescriptorKind, PrivateAclError,
};
use std::{
    ffi::c_void,
    fs::File,
    mem,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
            SetNamedSecurityInfoW, SE_FILE_OBJECT,
        },
        GetAce, GetSecurityDescriptorSacl, ACE_HEADER, ACL, LABEL_SECURITY_INFORMATION,
        SACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};

struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: owned ConvertStringSecurityDescriptor allocation, freed once.
        assert!(unsafe { LocalFree(self.0) }.is_null());
    }
}

/// A directory whose DACL grants Everyone full access AND marks that ACE
/// inheritable to child files and directories — the worst parent a
/// "private" file can be created under.
fn inheritable_everyone_directory(path: &Path) {
    directory_with_sddl(path, "D:P(A;OICI;FA;;;WD)");
}
/// A directory created with an explicit descriptor (to plant inheritable ACEs or labels).
fn directory_with_sddl(path: &Path, sddl: &str) {
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    // SAFETY: live NUL-terminated SDDL and output slot; API allocates descriptor.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut raw,
                ptr::null_mut(),
            )
        },
        0
    );
    let descriptor = Descriptor(raw);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    assert_ne!(unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) }, 0);
}
/// A file created with an explicit descriptor; `Err` is the Win32 error code.
pub(crate) fn file_with_sddl(path: &Path, sddl: &str) -> Result<File, u32> {
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    // SAFETY: live NUL-terminated SDDL and output slot; API allocates descriptor.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut raw,
                ptr::null_mut(),
            )
        },
        0
    );
    let descriptor = Descriptor(raw);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap() as u32);
    }
    // SAFETY: successful creation transfers exactly one handle to File.
    Ok(unsafe { File::from_raw_handle(handle as *mut c_void) })
}
/// The `(flags, mask)` of every mandatory-label ACE on `file` (READ_CONTROL only).
pub(crate) fn label_aces(file: &File) -> Vec<(u8, u32)> {
    let mut sacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: live handle and output slots; the SACL points into `descriptor`.
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as isize,
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sacl,
                &mut descriptor,
            )
        },
        0
    );
    let _descriptor = Descriptor(descriptor);
    let mut found = Vec::new();
    if sacl.is_null() {
        return found;
    }
    // SAFETY: the SACL and each ACE it yields stay valid while `_descriptor` lives.
    unsafe {
        for index in 0..u32::from((*sacl).AceCount) {
            let mut ace = ptr::null_mut();
            assert_ne!(GetAce(sacl, index, &mut ace), 0);
            let header = &*ace.cast::<ACE_HEADER>();
            assert_eq!(header.AceType, 0x11, "only label ACEs are expected");
            found.push((
                header.AceFlags,
                ptr::read_unaligned(ace.cast::<u8>().add(4).cast::<u32>()),
            ));
        }
    }
    found
}
/// The private label shape: ONE explicit NW|NR ACE first, then only inherited ACEs
/// (the parent's Medium labels; their level is checked by the production `inspect`,
/// which every caller here also runs). Without a protected SACL a parent's inheritable
/// label may sit beside ours or be dropped by the stamp; both are accepted.
pub(crate) fn assert_private_label_shape(aces: &[(u8, u32)]) {
    assert_eq!(
        aces.first(),
        Some(&(0, 0x3)),
        "explicit label first: {aces:?}"
    );
    assert!(
        aces[1..].iter().all(|(flags, _)| flags & 0x10 != 0),
        "only inherited ACEs beside ours: {aces:?}"
    );
}
/// A file whose DACL is INHERITED from its (broad) parent but whose label is the exact
/// private one, so a refusal is about the DACL, never the missing label.
fn labeled_inherited_file(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    file_with_sddl(path, "S:(ML;;NWNR;;;ME)")
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

fn is_private(path: &Path) -> bool {
    let file = File::open(path).expect("open for READ_CONTROL");
    match check_private_handle(&file) {
        Ok(()) => true,
        Err(PrivateAclError::UnsafePath) => false,
        Err(other) => panic!("ACL check did not run: {other}"),
    }
}

/// Non-vacuity anchor: a file created the pre-fix way (`std::fs::write`,
/// inherited DACL) under the inheritable-Everyone parent is NOT private, so
/// the positive assertions below discriminate.
#[test]
fn native_windows_inherited_file_is_not_private() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("broad");
    inheritable_everyone_directory(&dir);
    let path = dir.join("inherited.json");
    labeled_inherited_file(&path, b"x");
    assert_eq!(
        label_aces(&File::open(&path).unwrap()),
        [(0, 0x3)],
        "fixture: exact explicit label, so the refusal below is the DACL's"
    );
    assert!(
        !is_private(&path),
        "inherited Everyone ACE must fail the check"
    );
}

#[test]
fn native_windows_write_new_private_is_owner_only_under_broad_parent() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("broad");
    inheritable_everyone_directory(&dir);
    let plain = dir.join("plain.json");
    write_new_private(&plain, b"secret-bytes").unwrap();
    assert!(is_private(&plain), "write_new_private must be owner-only");
    assert_eq!(std::fs::read(&plain).unwrap(), b"secret-bytes");
    let synced = dir.join("synced.json");
    write_new_private_synced(&synced, b"durable-secret").unwrap();
    assert!(
        is_private(&synced),
        "write_new_private_synced must be owner-only"
    );
    assert_eq!(std::fs::read(&synced).unwrap(), b"durable-secret");
}

#[test]
fn native_windows_write_new_private_refuses_existing_inherited_file_untouched() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("broad");
    inheritable_everyone_directory(&dir);
    let path = dir.join("existing.json");
    labeled_inherited_file(&path, b"original");
    for result in [
        write_new_private(&path, b"replacement"),
        write_new_private_synced(&path, b"replacement"),
    ] {
        match result {
            Err(crate::error::PlatformError::Io(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists)
            }
            other => panic!("existing target must be refused, got {other:?}"),
        }
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"original");
    assert!(
        !is_private(&path),
        "refusal must not re-ACL the existing file"
    );
}

/// The publish step must not re-open the token to inheritance: a target that
/// was born with an inherited Everyone DACL is replaced by an owner-only tmp
/// via `atomic_replace`, and the PUBLISHED file must carry the tmp's protected
/// owner-only DACL. RED if the replace kept (or re-inherited) the old DACL.
#[test]
fn native_windows_atomic_replace_publishes_owner_only_dacl_over_inherited_target() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("broad");
    inheritable_everyone_directory(&dir);
    let target = dir.join("credentials.json");
    labeled_inherited_file(&target, b"old-token");
    assert!(
        !is_private(&target),
        "fixture: the pre-publish target must carry the inherited broad DACL"
    );
    let tmp = dir.join("credentials.json.tmp");
    write_new_private(&tmp, b"new-token").unwrap();
    atomic_replace(&tmp, &target).unwrap();
    assert!(
        is_private(&target),
        "published target must keep the owner-only DACL"
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"new-token");
    assert!(!tmp.exists(), "tmp must be consumed by the publish");
}

/// The file descriptor is owner + protected DACL + the Medium mandatory label with
/// no-write-up AND no-read-up, so a Low-integrity process of the same user cannot
/// read a private file either. The object form (the mutexes) stays no-write-up
/// only; both are pinned so the two cannot swap.
#[test]
fn file_descriptor_text_has_the_private_label_and_object_text_the_write_label() {
    let sid = "S-1-5-21-1-2-3-1001";
    assert_eq!(
        descriptor_text(sid, DescriptorKind::File),
        format!("O:{sid}D:P(A;;FA;;;{sid})S:(ML;;NWNR;;;ME)")
    );
    assert_eq!(
        descriptor_text(sid, DescriptorKind::Object),
        format!("O:{sid}D:P(A;;GA;;;{sid})S:(ML;;NW;;;ME)")
    );
}

/// A parent carrying an INHERITABLE Medium label (`icacls /setintegritylevel (OI)(CI)M`)
/// does not stack its label on a file CREATED with csq's explicit one (native, run
/// 39043270693: only the explicit ACE is present); either way the created file has exactly
/// one explicit NW|NR Medium ACE first, only inherited ones (if any) after it, and passes
/// the strict check. The plain file proves the parent really propagates a
/// label (inherited flag 0x10), so the assertion discriminates.
#[test]
fn native_windows_write_new_private_has_one_explicit_label_under_an_inheritable_label_parent() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("labeled-parent");
    directory_with_sddl(&dir, "D:P(A;OICI;FA;;;WD)S:(ML;OICI;NWNR;;;ME)");
    let plain = dir.join("plain.json");
    std::fs::write(&plain, b"x").unwrap();
    let inherited = label_aces(&File::open(&plain).unwrap());
    assert!(
        inherited.len() == 1 && inherited[0].0 & 0x10 != 0,
        "fixture: the parent must propagate an inherited label, got {inherited:?}"
    );
    let created = dir.join("created.json");
    write_new_private(&created, b"secret").unwrap();
    let file = File::open(&created).unwrap();
    check_private_handle(&file).unwrap();
    assert_private_label_shape(&label_aces(&file));
}

/// Creates `path` exclusively with exactly `access`, through `CreateFileW`: std's
/// `OpenOptions` refuses a create without write access, which is the very handle this
/// helper must be able to build (no `DELETE`).
fn open_new(path: &Path, access: u32) -> File {
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: valid NUL-terminated path; null security attributes; synchronous call.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            0,
        )
    };
    assert_ne!(
        handle,
        INVALID_HANDLE_VALUE,
        "fixture create_new {access:#x}: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful CreateFileW transferred one uniquely owned handle.
    unsafe { File::from_raw_handle(handle as *mut c_void) }
}

/// With `DELETE` on the handle, `delete_created` removes the file once the handle
/// closes, by the handle and not by path. Without `DELETE` the request is refused
/// (returns false), the failure is logged by the helper, and the file REMAINS, so a
/// caller returning its original error is not hiding a successful delete. Reds if the
/// disposition were requested without the handle's DELETE right mattering.
#[test]
fn native_windows_delete_created_needs_delete_access_and_reports_a_refusal() {
    use super::fs_windows_delete::delete_created;
    const DELETE: u32 = 0x0001_0000;
    let base = tempfile::tempdir().unwrap();
    let with = base.path().join("with-delete.tmp");
    let file = open_new(&with, GENERIC_READ | GENERIC_WRITE | DELETE);
    assert!(delete_created(&file));
    drop(file);
    assert!(!with.exists(), "deleted through the handle once it closed");
    let without = base.path().join("no-delete.tmp");
    // Write data (so the create is allowed) but not DELETE.
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    let file = open_new(&without, GENERIC_READ | FILE_WRITE_DATA);
    assert!(!delete_created(&file), "no DELETE access: refused");
    drop(file);
    assert!(without.exists(), "a refused delete leaves the file");
}

// The inherited-label refusal is logged once per process, not once per refused file.
// Reds if the gate returned true on every call (the WARN had been in `inspect`).
#[test]
fn the_inherited_label_log_gate_opens_exactly_once() {
    use std::sync::atomic::AtomicBool;
    let flag = AtomicBool::new(false);
    assert!(super::fs_windows_acl::first_time_for_test(&flag));
    assert!(!super::fs_windows_acl::first_time_for_test(&flag));
    assert!(!super::fs_windows_acl::first_time_for_test(&flag));
}

// ── Does an inheritable AUDIT ACE on a parent reach csq's private files? ──────────────
//
// A reviewer claimed that, now SACL protection is gone, a parent's inheritable audit ACE
// (`SYSTEM_AUDIT_ACE`) would reach every csq private file and `inspect` (which refuses any
// non-label ACE type) would then refuse every private create and open. `inspect` queries
// `GetSecurityInfo` with OWNER|DACL|LABEL_SECURITY_INFORMATION only, and per the Windows
// documentation a label-only query returns only mandatory-label ACEs. This test settles it
// natively, for both ways an inherited ACE can arrive: at CREATION and by PROPAGATION onto
// a file that already exists. Elevation is needed to read and write a SACL.

const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
const READ_CONTROL: u32 = 0x0002_0000;
/// `SYSTEM_AUDIT_ACE_TYPE`.
const AUDIT_ACE_TYPE: u8 = 0x02;
/// `INHERITED_ACE`.
const INHERITED: u8 = 0x10;

/// Enables `SeSecurityPrivilege` on the process token (needed for `ACCESS_SYSTEM_SECURITY`
/// and for setting a SACL); `false` when the token does not hold it (not elevated).
fn enable_security_privilege() -> bool {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GetLastError, LUID},
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };
    let mut token = 0;
    // SAFETY: pseudo process handle is valid; output points to a live slot.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    } == 0
    {
        return false;
    }
    let name: Vec<u16> = "SeSecurityPrivilege"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut state = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 0,
                HighPart: 0,
            },
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: NUL-terminated name, live LUID slot, live token handle and state; the
    // success of AdjustTokenPrivileges is not enough (ERROR_NOT_ALL_ASSIGNED = 1300 means
    // the privilege is not held), so the last error is read immediately after it.
    let enabled = unsafe {
        LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut state.Privileges[0].Luid) != 0
            && AdjustTokenPrivileges(token, 0, &state, 0, ptr::null_mut(), ptr::null_mut()) != 0
            && GetLastError() == 0
    };
    // SAFETY: the token handle was opened above and is closed once.
    unsafe { CloseHandle(token) };
    enabled
}

/// Sets the SACL of the directory `dir` from `sddl` and lets the OS propagate its
/// inheritable ACEs to children that already exist. Needs `SeSecurityPrivilege` enabled.
fn set_sacl_and_propagate(dir: &Path, sddl: &str) {
    let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut raw = ptr::null_mut();
    // SAFETY: live NUL-terminated SDDL and output slot; API allocates descriptor.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut raw,
                ptr::null_mut(),
            )
        },
        0
    );
    let descriptor = Descriptor(raw);
    let (mut present, mut defaulted, mut sacl) = (0, 0, ptr::null_mut::<ACL>());
    // SAFETY: the SACL pointer is borrowed from the live descriptor and checked non-null.
    assert!(
        unsafe { GetSecurityDescriptorSacl(descriptor.0, &mut present, &mut sacl, &mut defaulted) }
            != 0
            && present != 0
            && !sacl.is_null(),
        "fixture: the SDDL carries a SACL"
    );
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: valid NUL-terminated path; only the SACL is set, from the ACL above.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            sacl,
        )
    };
    assert_eq!(
        status, 0,
        "fixture: set the parent's audit ACE (error {status})"
    );
}

/// `(ace_type, ace_flags)` of EVERY ACE in the SACL of `path` (labels and audit ACEs
/// alike), read with `SACL_SECURITY_INFORMATION`; needs `SeSecurityPrivilege` enabled.
fn sacl_aces(path: &Path) -> Vec<(u8, u8)> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | ACCESS_SYSTEM_SECURITY)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .expect("open with ACCESS_SYSTEM_SECURITY (SeSecurityPrivilege enabled)");
    let mut sacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: live handle and output slots; the SACL points into `descriptor`.
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as isize,
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sacl,
                &mut descriptor,
            )
        },
        0
    );
    let _descriptor = Descriptor(descriptor);
    let mut found = Vec::new();
    if sacl.is_null() {
        return found;
    }
    // SAFETY: the SACL and each ACE it yields stay valid while `_descriptor` lives.
    unsafe {
        for index in 0..u32::from((*sacl).AceCount) {
            let mut ace = ptr::null_mut();
            assert_ne!(GetAce(sacl, index, &mut ace), 0);
            let header = &*ace.cast::<ACE_HEADER>();
            found.push((header.AceType, header.AceFlags));
        }
    }
    found
}

fn has_inherited_audit(aces: &[(u8, u8)]) -> bool {
    aces.iter()
        .any(|(kind, flags)| *kind == AUDIT_ACE_TYPE && flags & INHERITED != 0)
}

#[test]
fn native_windows_an_inheritable_audit_ace_does_not_make_inspect_refuse_private_files() {
    if !enable_security_privilege() {
        assert!(
            std::env::var_os("CI").is_none(),
            "SeSecurityPrivilege cannot be enabled on CI; the runner must be elevated"
        );
        eprintln!("skipped: SeSecurityPrivilege is not held (not elevated)");
        return;
    }
    let base = tempfile::tempdir().unwrap();
    let audit = "S:(AU;OICISA;FA;;;WD)";

    // Fixture proof: a plain file in a parent with the inheritable audit ACE really
    // inherits it, so the assertions below discriminate.
    let parent = base.path().join("audited-parent");
    directory_with_sddl(&parent, "D:P(A;OICI;FA;;;WD)");
    set_sacl_and_propagate(&parent, audit);
    let plain = parent.join("plain.json");
    std::fs::write(&plain, b"x").unwrap();
    let plain_aces = sacl_aces(&plain);
    assert!(
        has_inherited_audit(&plain_aces),
        "fixture: the parent must propagate an inherited audit ACE, got {plain_aces:?}"
    );

    // CREATION: csq creates a private file in that parent. Whether the audit ACE reaches
    // it is recorded (not assumed); the create and the strict check must succeed either way.
    let created = parent.join("created.json");
    let file = create_new_private_file(&created)
        .expect("create_new_private_file must succeed under an inheritable audit ACE");
    check_private_handle(&file).expect("check_private_handle must pass on the created file");
    drop(file);
    eprintln!(
        "observed SACL ACEs (type, flags) of a csq-created file under an inheritable audit ACE: {:?}",
        sacl_aces(&created)
    );
    check_private_handle(&open_private_file(&created, false, false).unwrap()).unwrap();

    // PROPAGATION: a csq private file that already exists, then the parent gets the
    // inheritable audit ACE and the OS propagates it onto the file. This is the layout in
    // which the audit ACE certainly reaches a private file.
    let late_parent = base.path().join("late-parent");
    directory_with_sddl(&late_parent, "D:P(A;OICI;FA;;;WD)");
    let existing = late_parent.join("existing.json");
    drop(create_new_private_file(&existing).unwrap());
    assert!(
        !has_inherited_audit(&sacl_aces(&existing)),
        "fixture: no audit ACE before the parent is audited"
    );
    set_sacl_and_propagate(&late_parent, audit);
    let after = sacl_aces(&existing);
    assert!(
        has_inherited_audit(&after),
        "fixture: the audit ACE must have propagated onto the existing private file, got {after:?}"
    );
    let reopened = open_private_file(&existing, false, false)
        .expect("open_private_file must succeed with an inherited audit ACE on the file");
    check_private_handle(&reopened)
        .expect("check_private_handle must pass: inspect's label-only query hides audit ACEs");
}
