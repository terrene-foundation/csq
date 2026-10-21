//! Synthetic native Windows ACL tests. Cross compilation is not runtime proof.
use super::super::{ChatMessage, SessionStore, StoreError};
use super::{check_private_handle, create_private_directory, open_directory, open_private_file};
use crate::platform::fs_windows_acl_tests::{
    assert_private_label_shape, file_with_sddl, label_aces,
};
use crate::platform::label_upgrade::run_label_upgrade_with;
use std::{
    ffi::c_void,
    fs::{self, File},
    mem,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SetNamedSecurityInfoW, SetSecurityInfo, SE_FILE_OBJECT,
        },
        GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorSacl,
        ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
        UNPROTECTED_DACL_SECURITY_INFORMATION,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};
const ID: &str = "550e8400-e29b-41d4-a716-446655440000";

struct Descriptor(*mut c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: owned ConvertStringSecurityDescriptor allocation, freed once.
        assert!(unsafe { LocalFree(self.0) }.is_null());
    }
}
fn everyone_descriptor(inherit: bool) -> Descriptor {
    let sddl = if inherit {
        "D:P(A;OICI;FA;;;WD)S:(ML;;NWNR;;;ME)"
    } else {
        "D:P(A;;FA;;;WD)S:(ML;;NWNR;;;ME)"
    };
    from_sddl(sddl)
}
fn from_sddl(sddl: &str) -> Descriptor {
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: live NUL-terminated SDDL and output; API allocates descriptor.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        },
        0
    );
    Descriptor(descriptor)
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
fn attributes(descriptor: &Descriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}
fn broad_directory(path: &Path, inherit: bool) {
    let descriptor = everyone_descriptor(inherit);
    let attributes = attributes(&descriptor);
    let path = wide(path);
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    assert_ne!(unsafe { CreateDirectoryW(path.as_ptr(), &attributes) }, 0);
}
fn broad_file(path: &Path) {
    let descriptor = everyone_descriptor(false);
    let attributes = attributes(&descriptor);
    let path = wide(path);
    // SAFETY: synthetic path; creates a new empty file with explicit broad ACL.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            0,
        )
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    // SAFETY: this fixture owns the returned handle and closes it once.
    assert_ne!(unsafe { CloseHandle(handle) }, 0);
}
fn broad_base() -> (tempfile::TempDir, std::path::PathBuf) {
    let temporary = tempfile::Builder::new()
        .prefix("csq-chat-acl-")
        .tempdir()
        .unwrap();
    let base = temporary.path().join("broad-base");
    broad_directory(&base, true);
    assert_eq!(
        check_private_handle(&open_directory(&base).unwrap()),
        Err(StoreError::UnsafePath)
    );
    (temporary, base)
}

#[test]
fn native_windows_creates_private_directory_and_files_under_broad_base() {
    let (_temporary, base) = broad_base();
    let private = base.join("private");
    create_private_directory(&private).unwrap();
    check_private_handle(&open_directory(&private).unwrap()).unwrap();
    for name in ["transcript.jsonl", "writer.lock", "snapshot.tmp"] {
        let file = open_private_file(&private.join(name), true, true).unwrap();
        check_private_handle(&file).unwrap();
        drop(file);
        check_private_handle(&open_private_file(&private.join(name), false, false).unwrap())
            .unwrap();
    }
}

#[test]
fn native_windows_refuses_explicit_everyone_file_without_rewriting_acl_or_bytes() {
    let (_temporary, base) = broad_base();
    let path = base.join("broad.jsonl");
    broad_file(&path);
    let before = fs::read(&path).unwrap();
    assert!(matches!(
        open_private_file(&path, false, false),
        Err(StoreError::UnsafePath)
    ));
    assert!(matches!(
        open_private_file(&path, true, false),
        Err(StoreError::UnsafePath)
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        check_private_handle(&File::open(&path).unwrap()),
        Err(StoreError::UnsafePath)
    );
}

#[test]
fn native_windows_refuses_inherited_store_directory_without_migration() {
    let (_temporary, base) = broad_base();
    let child = base.join("chat-sessions");
    fs::create_dir(&child).unwrap();
    let marker = child.join("preserved.txt");
    fs::write(&marker, b"synthetic fixture").unwrap();
    assert!(matches!(
        SessionStore::open(&base, 4096),
        Err(StoreError::UnsafePath)
    ));
    assert_eq!(fs::read(&marker).unwrap(), b"synthetic fixture");
    assert_eq!(
        check_private_handle(&open_directory(&child).unwrap()),
        Err(StoreError::UnsafePath)
    );
}

#[test]
fn native_windows_store_replacement_roundtrip_retains_private_acl_and_lock() {
    let (_temporary, base) = broad_base();
    let store = SessionStore::open(&base, 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer
        .append(ChatMessage {
            role: "user".into(),
            content: "first synthetic message".into(),
        })
        .unwrap();
    writer
        .append(ChatMessage {
            role: "assistant".into(),
            content: "second synthetic message".into(),
        })
        .unwrap();
    let expected = writer.entries().to_vec();
    let child = base.join("chat-sessions");
    check_private_handle(&open_directory(&child).unwrap()).unwrap();
    for extension in ["jsonl", "lock"] {
        check_private_handle(&File::open(child.join(format!("{ID}.{extension}"))).unwrap())
            .unwrap();
    }
    assert_eq!(fs::read_dir(&child).unwrap().count(), 2);
    assert!(matches!(store.resume(ID), Err(StoreError::Busy)));
    drop(writer);
    let resumed = SessionStore::open(&base, 4096).unwrap().resume(ID).unwrap();
    assert_eq!(resumed.entries(), expected);
}

fn msg(content: &str) -> ChatMessage {
    ChatMessage {
        role: "user".into(),
        content: content.into(),
    }
}

/// Probes every publish temp in `dir` from outside while the writer's single
/// handle is held: no other handle may open it for write, rename it or delete
/// it (share mode READ only). Non-vacuous: at least one temp must be found.
fn assert_temp_untouchable(dir: &Path) {
    let mut found = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.to_string_lossy().contains(".tmp.") {
            continue;
        }
        found += 1;
        for write in [
            fs::OpenOptions::new().write(true).open(&path),
            fs::OpenOptions::new().append(true).open(&path),
        ] {
            assert_eq!(write.unwrap_err().raw_os_error(), Some(32), "write open");
        }
        assert!(fs::rename(&path, path.with_extension("moved")).is_err());
        assert!(fs::remove_file(&path).is_err());
    }
    assert_eq!(found, 1, "exactly one live temp must have been probed");
}
fn probe_before_rename(dir: std::path::PathBuf) {
    super::BEFORE_RENAME
        .with(|c| *c.borrow_mut() = Some(Box::new(move || assert_temp_untouchable(&dir))));
}
/// A creator cannot set a label above its own integrity level: a non-elevated process
/// building a High fixture gets ERROR_PRIVILEGE_NOT_HELD (1314) or ERROR_INVALID_ACL
/// (1336) depending on the API. Returns true (skip, reported) ONLY off CI; on CI
/// (`CI` set) a skip would be silent coverage loss, so it panics instead.
fn cannot_label_above_own_level(code: u32, what: &str) -> bool {
    assert!(matches!(code, 1314 | 1336), "fixture {what}: {code}");
    assert!(
        std::env::var_os("CI").is_none(),
        "fixture {what} cannot be built on CI (error {code}); the runner must be elevated"
    );
    eprintln!("skipped {what}: creator cannot set a label above its own level");
    true
}
fn legacy_probe_before_nt_rename(dir: std::path::PathBuf) {
    super::BEFORE_LEGACY_RENAME
        .with(|c| *c.borrow_mut() = Some(Box::new(move || assert_temp_untouchable(&dir))));
}
/// A probe seam that was armed must have been consumed: a hook that never ran
/// proves nothing about the handle.
fn assert_probe_consumed() {
    assert!(
        super::BEFORE_RENAME.with(|c| c.borrow().is_none()),
        "BEFORE_RENAME probe never ran"
    );
    assert!(
        super::BEFORE_LEGACY_RENAME.with(|c| c.borrow().is_none()),
        "BEFORE_LEGACY_RENAME probe never ran"
    );
}
fn chat_dir(base: &Path) -> std::path::PathBuf {
    base.join("chat-sessions")
}

// Reds if the rename used legacy MoveFileExW(REPLACE_EXISTING) semantics: with the
// transcript open in another handle (std `File::open` shares read/write/delete) that
// fails with ERROR_ACCESS_DENIED, so `append` returns Err; the POSIX-semantics
// handle-bound rename returns Ok.
#[test]
fn native_windows_append_succeeds_while_another_handle_holds_the_transcript_open() {
    let (_temporary, base) = broad_base();
    let store = SessionStore::open(&base, 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(msg("first")).unwrap();
    let transcript = base.join("chat-sessions").join(format!("{ID}.jsonl"));
    let _reader = File::open(&transcript).unwrap();
    writer.append(msg("second")).unwrap();
    let text = fs::read_to_string(&transcript).unwrap();
    assert!(text.contains("first") && text.contains("second"));
    assert_eq!(writer.entries().len(), 2);
}

// Reds on the old code: a flush failure after the rename returned StoreError::Io and
// the writer stayed usable with a stale `serialized`; now it is DurabilityUnknown,
// the writer is poisoned and the published entry is recorded. The seam injects the
// failure as the RESULT of `sync_all`, so replacing the production
// `map_err(|_| DurabilityUnknown)` (e.g. with `io_error`, giving Io) reds this test.
#[test]
fn native_windows_post_rename_flush_failure_is_durability_unknown_and_poisons() {
    let (_temporary, base) = broad_base();
    let store = SessionStore::open(&base, 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(msg("first")).unwrap();
    super::FAIL_POST_RENAME_SYNC.with(|f| f.set(true));
    assert_eq!(
        writer.append(msg("second")),
        Err(StoreError::DurabilityUnknown)
    );
    assert!(writer.poisoned);
    assert_eq!(writer.entries().len(), 2);
    assert_eq!(writer.append(msg("third")), Err(StoreError::Poisoned));
    let transcript = base.join("chat-sessions").join(format!("{ID}.jsonl"));
    assert!(fs::read_to_string(&transcript).unwrap().contains("second"));
}

// One handle from create to publish: a swap (rename/delete + recreate) of the temp
// and a content rewrite are both impossible, because the writer's handle denies
// write/delete sharing. The probe runs with the handle held, immediately before the
// rename. Reds if the temp were created or reopened with FILE_SHARE_WRITE/DELETE (the
// probe's open/rename/remove would succeed) and if the published bytes were not the
// writer's.
#[test]
fn native_windows_swap_and_content_rewrite_of_the_temp_are_impossible() {
    let (_temporary, base) = broad_base();
    let store = SessionStore::open(&base, 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(msg("first")).unwrap();
    probe_before_rename(chat_dir(&base));
    writer.append(msg("second")).unwrap();
    assert_probe_consumed();
    let transcript = chat_dir(&base).join(format!("{ID}.jsonl"));
    assert_eq!(fs::read(&transcript).unwrap(), writer.serialized);
    assert_eq!(fs::read_dir(chat_dir(&base)).unwrap().count(), 2);
}

// Same, through the legacy-class fallback (forced by seam, as ERROR_INVALID_PARAMETER
// would): the fallback is `NtSetInformationFile(FileRenameInformation)` with the SAME
// handle and the pinned `RootDirectory`, so the probe still finds the
// temp untouchable and the published bytes are the writer's. Reds if the fallback
// dropped the handle and moved by path (probe succeeds), or never ran (counter 0).
#[test]
fn native_windows_legacy_fallback_renames_through_the_same_handle() {
    let (_temporary, base) = broad_base();
    let store = SessionStore::open(&base, 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(msg("first")).unwrap();
    super::LEGACY_RENAMES.with(|c| c.set(0));
    super::FORCE_LEGACY_RENAME.with(|f| f.set(true));
    probe_before_rename(chat_dir(&base));
    // Probes again immediately before the NtSetInformationFile call, with the
    // handle still held: a fallback that dropped it and moved by path is seen here.
    legacy_probe_before_nt_rename(chat_dir(&base));
    let result = writer.append(msg("second"));
    super::FORCE_LEGACY_RENAME.with(|f| f.set(false));
    result.unwrap();
    assert_probe_consumed();
    assert_eq!(super::LEGACY_RENAMES.with(|c| c.get()), 1);
    let transcript = chat_dir(&base).join(format!("{ID}.jsonl"));
    assert_eq!(fs::read(&transcript).unwrap(), writer.serialized);
}

// Creation never renames: the transcript is an exclusive `CREATE_NEW` at its final name
// with the owner-only DACL applied at creation. Reds if a second create replaced or
// truncated the file (it must be AlreadyExists, bytes unchanged), if the file were not
// private, or if a temp were left behind (exactly the transcript and its lock remain).
#[test]
fn native_windows_create_transcript_is_exclusive_private_and_never_clobbers() {
    let (_temporary, base) = broad_base();
    let store = SessionStore::open(&base, 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(msg("kept")).unwrap();
    drop(writer);
    let transcript = chat_dir(&base).join(format!("{ID}.jsonl"));
    check_private_handle(&File::open(&transcript).unwrap()).unwrap();
    let before = fs::read(&transcript).unwrap();
    assert!(matches!(store.create(ID), Err(StoreError::AlreadyExists)));
    assert_eq!(fs::read(&transcript).unwrap(), before);
    assert_eq!(
        fs::read_dir(chat_dir(&base)).unwrap().count(),
        2,
        "no temp left"
    );
}

// The store directory is created at its final name with the owner-only DACL applied at
// creation (no temp directory, no rename), and reopening an existing private one works.
// Reds if a `chat-sessions.tmp.*` sibling were left, or the directory were not private.
#[test]
fn native_windows_store_directory_is_created_private_at_its_final_name() {
    let (_temporary, base) = broad_base();
    drop(SessionStore::open(&base, 4096).unwrap());
    let names: Vec<_> = fs::read_dir(&base)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["chat-sessions"]);
    check_private_handle(&open_directory(&chat_dir(&base)).unwrap()).unwrap();
    drop(SessionStore::open(&base, 4096).unwrap());
}

// A leaf that is not a canonical `<uuid>.jsonl` is refused before any rename (the store
// directory is no longer a rename target). Reds if the weak "no separators" check returns.
#[test]
fn native_windows_publish_refuses_non_canonical_leaves() {
    let (_temporary, base) = broad_base();
    let store = SessionStore::open(&base, 4096).unwrap();
    let dir = open_directory(&chat_dir(&base)).unwrap();
    for leaf in [
        "evil.txt",
        "a.jsonl",
        "..",
        "chat-sessions",
        "x.jsonl.stream",
        "con",
        &format!("{ID}.JSONL"),
    ] {
        let temp = chat_dir(&base).join("probe.tmp");
        let file = super::create_private_temp(&temp).unwrap();
        assert_eq!(
            super::publish_handle(&dir, &file, leaf),
            Err(StoreError::UnsafePath),
            "{leaf}"
        );
        drop(file);
        fs::remove_file(&temp).unwrap();
    }
    drop(store);
}

fn current_owner_text(file: &File) -> String {
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: held file and live outputs; owner is backed by returned descriptor.
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as isize,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let _descriptor = Descriptor(descriptor);
    let mut text = ptr::null_mut();
    // SAFETY: owner SID stays valid while its owning descriptor is retained.
    assert_ne!(unsafe { ConvertSidToStringSidW(owner, &mut text) }, 0);
    let _text = Descriptor(text.cast());
    let mut length = 0;
    // SAFETY: API supplies NUL-terminated SID text; bounded by SID format limits.
    unsafe {
        while length < 256 && *text.add(length) != 0 {
            length += 1;
        }
    }
    assert!(length < 256);
    // SAFETY: measured range within live API allocation.
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).unwrap()
}

/// Re-applies `security`'s DACL to `file` as an UNPROTECTED DACL and asserts
/// the result reads back unprotected.
///
/// `CreateFileW` with an explicit creator DACL does not produce that shape:
/// the creator DACL is applied without auto-inheritance, and the
/// inheritance-aware `GetSecurityInfo` reports a DACL that is not
/// auto-inherited as protected (inference from Windows CI run 38993121327,
/// where a `D:(…)` fixture passed `check_private_handle`'s protected test).
/// `SetSecurityInfo` with `UNPROTECTED_DACL_SECURITY_INFORMATION` is how a
/// real file's protection is cleared (Explorer, `icacls /inheritance:e`): it
/// marks the DACL auto-inherited and merges the parent's inheritable ACEs.
/// The read-back makes an unfaithful fixture fail here, not pass the check.
fn make_unprotected(file: &File, security: &Descriptor) {
    let (mut present, mut defaulted) = (0, 0);
    let mut dacl = ptr::null_mut();
    // SAFETY: live descriptor from ConvertStringSecurityDescriptor; outputs
    // are local slots and `dacl` points into `security`, which outlives use.
    assert_ne!(
        unsafe { GetSecurityDescriptorDacl(security.0, &mut present, &mut dacl, &mut defaulted) },
        0
    );
    assert!(present != 0 && !dacl.is_null(), "fixture DACL present");
    // SAFETY: held file opened with WRITE_DAC; `dacl` is a valid ACL.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle() as isize,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    assert_eq!(status, 0, "SetSecurityInfo unprotected");
    let mut read_dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: held file and live outputs; read_dacl is backed by descriptor.
    assert_eq!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as isize,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut read_dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        },
        0
    );
    let descriptor = Descriptor(descriptor);
    let (mut control, mut revision) = (0, 0);
    // SAFETY: API-returned descriptor retained above.
    assert_ne!(
        unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
        0
    );
    assert_eq!(
        control & SE_DACL_PROTECTED,
        0,
        "fixture must read back unprotected"
    );
    // Isolation: the read-back DACL must be exactly the one explicit,
    // non-inherited owner ACE `check_private_handle` would otherwise accept,
    // so the SE_DACL_PROTECTED test is the ONLY check that can refuse it.
    // A parent with inheritable broad ACEs would add inherited ACEs and let
    // the ACE-count/flags checks refuse it even with the protection check
    // removed.
    assert!(!read_dacl.is_null(), "read-back DACL present");
    // SAFETY: read_dacl is non-null and backed by the retained descriptor.
    assert_eq!(unsafe { (*read_dacl).AceCount }, 1, "no inherited ACEs");
    let mut ace = ptr::null_mut();
    // SAFETY: index 0 of a one-ACE ACL owned by the retained descriptor.
    assert_ne!(unsafe { GetAce(read_dacl, 0, &mut ace) }, 0);
    // SAFETY: GetAce returned a pointer to a valid ACE header.
    assert_eq!(
        unsafe { (*ace.cast::<ACE_HEADER>()).AceFlags },
        0,
        "ACE must not be inherited"
    );
}

#[test]
fn native_windows_refuses_noncanonical_dacl_shapes_with_actual_handles() {
    let (_temporary, base) = broad_base();
    let probe = open_private_file(&base.join("owner-probe"), true, true).unwrap();
    let owner = current_owner_text(&probe);
    // Every fixture carries the exact private label, so each refusal is for its own
    // owner/DACL reason and would not survive removing the DACL checks.
    const LABEL: &str = "S:(ML;;NWNR;;;ME)";
    let cases = [
        (
            "user-and-everyone",
            format!("O:{owner}D:P(A;;FA;;;{owner})(A;;FA;;;WD){LABEL}"),
        ),
        (
            "unprotected",
            format!("O:{owner}D:(A;;FA;;;{owner}){LABEL}"),
        ),
        ("deny", format!("O:{owner}D:P(D;;0x2;;;{owner}){LABEL}")),
        (
            "inherit-flags",
            format!("O:{owner}D:P(A;OICI;FA;;;{owner}){LABEL}"),
        ),
        ("null-dacl", format!("O:{owner}D:NO_ACCESS_CONTROL{LABEL}")),
    ];
    // The unprotected case lives under a parent whose only ACE is a
    // NON-inheritable owner ACE, so nothing is inherited into the fixture and
    // protection is the sole thing separating it from a private file.
    let owner_only_parent = base.join("owner-only-parent");
    {
        let parent_security = from_sddl(&format!("O:{owner}D:P(A;;FA;;;{owner})"));
        let parent_attributes = attributes(&parent_security);
        let parent_wide = wide(&owner_only_parent);
        // SAFETY: valid path and descriptor live until synchronous creation returns.
        assert_ne!(
            unsafe { CreateDirectoryW(parent_wide.as_ptr(), &parent_attributes) },
            0
        );
    }
    for (name, sddl) in cases {
        let security = from_sddl(&sddl);
        let attributes = attributes(&security);
        let path = if name == "unprotected" {
            owner_only_parent.join(name)
        } else {
            base.join(name)
        };
        let encoded = wide(&path);
        // SAFETY: explicit synthetic SD; READ_CONTROL (0x0002_0000) plus
        // FILE_READ_ATTRIBUTES (0x80), and WRITE_DAC (0x0004_0000) for the
        // unprotected case only. READ_CONTROL inspects deny-only ACLs;
        // FILE_READ_ATTRIBUTES is what `File::metadata` (GetFileInformationByHandle)
        // needs for the zero-length assertion below; WRITE_DAC lets
        // `make_unprotected` clear protection. None grants payload read/write.
        let access = if name == "unprotected" {
            0x0006_0080
        } else {
            0x0002_0080
        };
        let handle = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                0,
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE, "fixture creation: {name}");
        // SAFETY: successful creation transfers exactly one handle to File.
        let file = unsafe { File::from_raw_handle(handle as *mut c_void) };
        if name == "unprotected" {
            make_unprotected(&file, &security);
        }
        assert_eq!(
            check_private_handle(&file),
            Err(StoreError::UnsafePath),
            "{name}"
        );
        assert_eq!(file.metadata().unwrap().len(), 0);
        drop(file);
        assert!(open_private_file(&path, false, false).is_err(), "{name}");
    }
}

/// A file/directory exactly as csq wrote it BEFORE the integrity label existed:
/// owner + protected owner-only DACL, no SACL.
fn legacy_descriptor(owner: &str) -> Descriptor {
    from_sddl(&format!("O:{owner}D:P(A;;FA;;;{owner})"))
}
fn legacy_file(path: &Path, owner: &str, bytes: &[u8]) {
    use std::io::Write;
    let security = legacy_descriptor(owner);
    let attributes = attributes(&security);
    let encoded = wide(path);
    // SAFETY: synthetic path and descriptor live until synchronous creation returns.
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            0,
        )
    };
    assert_ne!(handle, INVALID_HANDLE_VALUE);
    // SAFETY: successful creation transfers exactly one handle to File.
    let mut file = unsafe { File::from_raw_handle(handle as *mut c_void) };
    file.write_all(bytes).unwrap();
}
/// The platform layer (below the chat store, which maps every refusal to `UnsafePath`)
/// refuses `path` with exactly `InheritedLabel`: reds if the cause were reported as a
/// wrong owner or DACL, or the file were accepted.
fn assert_inherited_label_refusal(path: &Path) {
    use crate::platform::fs_windows_acl::{open_private_file, PrivateAclError};
    let error = open_private_file(path, false, false).unwrap_err();
    assert!(
        matches!(error, PrivateAclError::InheritedLabel),
        "expected InheritedLabel, got {error:?}"
    );
}
fn owner_of_this_user(base: &Path) -> String {
    let probe = open_private_file(&base.join("owner-probe"), true, true).unwrap();
    current_owner_text(&probe)
}

// Every csq-created file is born with the Medium NW|NR label, and `check` REQUIRES it:
// the pre-label legacy shape (owner + exact DACL, no SACL) is refused by the strict
// check, so this reds if the label were dropped from creation or from the check.
#[test]
fn native_windows_private_file_is_born_labeled_and_check_requires_the_label() {
    let (_temporary, base) = broad_base();
    let created = open_private_file(&base.join("born.jsonl"), true, true).unwrap();
    check_private_handle(&created).unwrap();
    let owner = owner_of_this_user(&base);
    let legacy = base.join("legacy.jsonl");
    legacy_file(&legacy, &owner, b"x");
    assert_eq!(
        check_private_handle(&File::open(&legacy).unwrap()),
        Err(StoreError::UnsafePath),
        "an unlabeled file must not pass the strict check"
    );
}

// UPGRADE: a transcript written before the label (owner + exact DACL, no label) is
// neither refused nor accepted unlabeled: opening stamps the label through the owner
// handle and re-verifies, the bytes are untouched, and the label persists on disk.
#[test]
fn native_windows_pre_label_file_is_upgraded_in_place_by_open() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let path = base.join("old.jsonl");
    legacy_file(&path, &owner, b"old transcript bytes");
    let file = open_private_file(&path, false, false).unwrap();
    check_private_handle(&file).unwrap();
    drop(file);
    check_private_handle(&File::open(&path).unwrap()).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"old transcript bytes");
}

// UPGRADE for the store directory written by an older csq: `SessionStore::open`
// succeeds, stamps the directory label, and the store works afterwards.
#[test]
fn native_windows_pre_label_store_directory_is_upgraded_by_open() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let child = chat_dir(&base);
    let security = legacy_descriptor(&owner);
    let attributes = attributes(&security);
    let encoded = wide(&child);
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    assert_ne!(
        unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) },
        0
    );
    assert_eq!(
        check_private_handle(&open_directory(&child).unwrap()),
        Err(StoreError::UnsafePath),
        "fixture: the legacy directory is unlabeled"
    );
    let store = SessionStore::open(&base, 4096).unwrap();
    check_private_handle(&open_directory(&child).unwrap()).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(msg("after upgrade")).unwrap();
}

// The upgrade is not an acceptance of anything else: a file whose DACL is private but
// whose EXPLICIT label is not the exact Medium NW|NR one (Low, High, Medium NW-only) is
// refused and its label left as found. HI needs an elevated creator; a non-elevated
// host cannot build that fixture (see `cannot_label_above_own_level`).
#[test]
fn native_windows_a_different_explicit_label_is_refused_and_not_rewritten() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    for (name, label) in [
        ("low", "S:(ML;;NWNR;;;LW)"),
        ("high", "S:(ML;;NWNR;;;HI)"),
        ("medium-write-only", "S:(ML;;NW;;;ME)"),
    ] {
        let path = base.join(format!("{name}.jsonl"));
        let sddl = format!("O:{owner}D:P(A;;FA;;;{owner}){label}");
        match file_with_sddl(&path, &sddl) {
            Ok(file) => drop(file),
            Err(code) if cannot_label_above_own_level(code, name) => continue,
            Err(code) => panic!("fixture {name}: {code}"),
        }
        assert!(open_private_file(&path, false, false).is_err(), "{name}");
        let after = File::open(&path).unwrap();
        assert_eq!(
            check_private_handle(&after),
            Err(StoreError::UnsafePath),
            "{name}"
        );
        let want = if name == "medium-write-only" {
            0x1
        } else {
            0x3
        };
        assert_eq!(
            label_aces(&after),
            [(0, want)],
            "{name}: label left as found"
        );
    }
}

// (Inherited Medium labels beside ours must carry NR; see the NW-only refusal test.)
// A parent with an INHERITABLE label gives a legacy object (private DACL, no explicit
// label) an inherited label ACE (flag 0x10). That is not csq's label: the strict check
// refuses it, and `open` stamps the explicit one (unprotected), leaving one
// explicit NW|NR ACE first (a Medium inherited one may remain), bytes untouched.
#[test]
fn native_windows_an_inherited_label_is_restamped_not_accepted() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let parent = base.join("labeled-parent");
    let security = from_sddl(&format!(
        "O:{owner}D:P(A;OICI;FA;;;{owner})S:(ML;OICI;NWNR;;;ME)"
    ));
    let attributes = attributes(&security);
    let encoded = wide(&parent);
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    assert_ne!(
        unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) },
        0
    );
    // A legacy-shaped file (explicit protected DACL, NO SACL): the label is inherited.
    let path = parent.join("legacy.jsonl");
    legacy_file(&path, &owner, b"legacy bytes");
    let inherited = label_aces(&File::open(&path).unwrap());
    assert!(
        inherited.len() == 1 && inherited[0].0 & 0x10 != 0,
        "fixture: the label must be inherited, got {inherited:?}"
    );
    let file = open_private_file(&path, false, false).unwrap();
    check_private_handle(&file).unwrap();
    assert_private_label_shape(&label_aces(&file));
    assert_eq!(fs::read(&path).unwrap(), b"legacy bytes");
}

// A parent with an inheritable LOW label (LocalLow style) gives a legacy-shaped child
// (exact owner + DACL, as a Low planter can arrange) an inherited Low label: it is
// Low-writable, so it is refused and NOT stamped; the label is left as found. The
// medium-label test above is the contrast: an inherited Medium label is stamped.
#[test]
fn native_windows_an_inherited_low_label_is_refused_and_not_stamped() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let parent = base.join("low-parent");
    let security = from_sddl(&format!(
        "O:{owner}D:P(A;OICI;FA;;;{owner})S:(ML;OICI;NW;;;LW)"
    ));
    let attributes = attributes(&security);
    let encoded = wide(&parent);
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    assert_ne!(
        unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) },
        0
    );
    let path = parent.join("planted.jsonl");
    legacy_file(&path, &owner, b"planted");
    let before = label_aces(&File::open(&path).unwrap());
    assert!(
        before.len() == 1 && before[0].0 & 0x10 != 0,
        "fixture: the Low label must be inherited, got {before:?}"
    );
    assert!(open_private_file(&path, false, false).is_err());
    assert_inherited_label_refusal(&path);
    let after = File::open(&path).unwrap();
    assert_eq!(check_private_handle(&after), Err(StoreError::UnsafePath));
    assert_eq!(label_aces(&after), before, "label left as found");
}

// An inherited Medium label WITHOUT no-read-up (the default `icacls ... (OI)(CI)M`) is
// refused with the distinct inherited-label error and left as found: the read
// protection could be lost if the kernel took the inherited policy.
#[test]
fn native_windows_an_inherited_medium_label_without_nr_is_refused() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let parent = base.join("nw-parent");
    let security = from_sddl(&format!(
        "O:{owner}D:P(A;OICI;FA;;;{owner})S:(ML;OICI;NW;;;ME)"
    ));
    let attributes = attributes(&security);
    let encoded = wide(&parent);
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    assert_ne!(
        unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) },
        0
    );
    let path = parent.join("legacy.jsonl");
    legacy_file(&path, &owner, b"legacy");
    let before = label_aces(&File::open(&path).unwrap());
    assert!(before.len() == 1 && before[0].0 & 0x10 != 0 && before[0].1 == 0x1);
    assert!(open_private_file(&path, false, false).is_err());
    // The chat store folds every refusal into `UnsafePath`; the platform layer must name
    // the cause: an INHERITED label, not a wrong owner or DACL.
    assert_inherited_label_refusal(&path);
    assert_eq!(label_aces(&File::open(&path).unwrap()), before);
}

// An inherited label ABOVE Medium is refused too: stamping it down to Medium would
// lower it, which "only tightens" forbids. Needs an elevated creator for the fixture.
#[test]
fn native_windows_an_inherited_high_label_is_refused_and_not_stamped() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let parent = base.join("high-parent");
    let security = from_sddl(&format!(
        "O:{owner}D:P(A;OICI;FA;;;{owner})S:(ML;OICI;NW;;;HI)"
    ));
    let attributes = attributes(&security);
    let encoded = wide(&parent);
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    if unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) } == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap() as u32;
        assert!(cannot_label_above_own_level(code, "high-parent"));
        return;
    }
    let path = parent.join("planted.jsonl");
    legacy_file(&path, &owner, b"planted");
    let before = label_aces(&File::open(&path).unwrap());
    assert!(
        before.len() == 1 && before[0].0 & 0x10 != 0,
        "fixture: the High label must be inherited, got {before:?}"
    );
    assert!(open_private_file(&path, false, false).is_err());
    assert_inherited_label_refusal(&path);
    let after = File::open(&path).unwrap();
    assert_eq!(check_private_handle(&after), Err(StoreError::UnsafePath));
    assert_eq!(label_aces(&after), before, "label left as found");
}

// "Explicit label survives parent propagation": a file carrying csq's explicit private label
// keeps ONLY that ACE when its parent later gains an inheritable Medium label, and stays
// `Present` with its bytes untouched.
//
// Native facts: CREATING a file with an explicit `S:(ML;;NWNR;;;ME)` under a parent with an
// inheritable Medium label yields only the explicit ACE (Windows run 39043270693), and
// PROPAGATING an inheritable label to an existing child through `SetNamedSecurityInfoW` also
// leaves only the explicit ACE (run 39048692734: `got [(0, 3)]`). So "explicit plus an inherited
// label ACE" is not a state either path produces; this test pins the propagation fact the
// explicit-first classifier relies on, instead of a fixture Windows cannot build.
#[test]
fn native_windows_an_explicit_label_is_not_joined_by_a_propagated_inherited_label() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let parent = base.join("medium-parent");
    let security = from_sddl(&format!("O:{owner}D:P(A;OICI;FA;;;{owner})"));
    let attributes = attributes(&security);
    let encoded = wide(&parent);
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    assert_ne!(
        unsafe { CreateDirectoryW(encoded.as_ptr(), &attributes) },
        0
    );
    let path = parent.join("mixed.jsonl");
    let sddl = format!("O:{owner}D:P(A;;FA;;;{owner})S:(ML;;NWNR;;;ME)");
    {
        use std::io::Write;
        file_with_sddl(&path, &sddl)
            .unwrap()
            .write_all(b"mixed bytes")
            .unwrap();
    }
    let created = label_aces(&File::open(&path).unwrap());
    assert_eq!(
        created,
        vec![(0, 0x3)],
        "fixture: before the parent is labeled the file has only its explicit ACE"
    );
    set_inheritable_label_and_propagate(&parent, "S:(ML;OICI;NWNR;;;ME)");
    let after = label_aces(&File::open(&path).unwrap());
    assert_eq!(
        after,
        vec![(0, 0x3)],
        "native fact: propagation does not add an inherited label beside the explicit one"
    );
    let file = open_private_file(&path, false, false).unwrap();
    check_private_handle(&file).unwrap();
    assert_private_label_shape(&label_aces(&file));
    assert_eq!(fs::read(&path).unwrap(), b"mixed bytes");
}

/// Sets the label of the directory `dir` from the SACL of `sddl` and lets the OS propagate
/// its inheritable ACEs to the children that already exist (`SetNamedSecurityInfoW`; a
/// handle-based `SetSecurityInfo` is not relied on to propagate).
fn set_inheritable_label_and_propagate(dir: &Path, sddl: &str) {
    let descriptor = from_sddl(sddl);
    let (mut present, mut defaulted, mut sacl) = (0, 0, ptr::null_mut::<ACL>());
    // SAFETY: the descriptor was just converted and outlives this function; the SACL
    // pointer is borrowed from it and checked non-null.
    assert!(
        unsafe { GetSecurityDescriptorSacl(descriptor.0, &mut present, &mut sacl, &mut defaulted) }
            != 0
            && present != 0
            && !sacl.is_null(),
        "fixture: the SDDL carries a SACL"
    );
    let encoded = wide(dir);
    // SAFETY: valid NUL-terminated path; only the label is set, from the SACL above.
    let status = unsafe {
        SetNamedSecurityInfoW(
            encoded.as_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null(),
            sacl,
        )
    };
    assert_eq!(status, 0, "fixture: set and propagate the parent's label");
}

// The daemon-start upgrade pass over csq's secret locations: a legacy unlabeled private
// file in `credentials/` is stamped; a foreign-DACL file is left untouched (no label
// appears) and counted; a junction is never traversed, so the legacy-shaped file behind
// it stays unlabeled (the file would be stamped if the walk followed the link); a
// second run is a no-op that finds the stamped file already labeled.
#[test]
fn native_windows_label_upgrade_stamps_legacy_secrets_and_leaves_the_rest() {
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let creds = base.join("credentials");
    fs::create_dir(&creds).unwrap();
    let legacy = creds.join("1.json");
    legacy_file(&legacy, &owner, b"{}");
    let born = creds.join("2.json");
    drop(open_private_file(&born, true, true).unwrap());
    let foreign = creds.join("3.json");
    drop(file_with_sddl(&foreign, "D:P(A;;FA;;;WD)").unwrap());
    let outside = tempfile::tempdir().unwrap();
    let behind = outside.path().join("secret.json");
    legacy_file(&behind, &owner, b"behind the link");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(creds.join("link"))
        .arg(outside.path())
        .status()
        .unwrap();
    assert!(status.success(), "fixture: junction");
    assert_eq!(
        check_private_handle(&File::open(&legacy).unwrap()),
        Err(StoreError::UnsafePath),
        "fixture: the legacy file is unlabeled"
    );

    // Hermetic: the gemini file lives in a temp home, never the real one.
    let home = tempfile::tempdir().unwrap();
    fs::create_dir(home.path().join(".gemini")).unwrap();
    let gemini = home.path().join(".gemini").join("oauth_creds.json");
    legacy_file(&gemini, &owner, b"{}");
    // A second hard link to a legacy file is refused, not stamped.
    let linked = creds.join("4.json");
    legacy_file(&linked, &owner, b"{}");
    fs::hard_link(&linked, creds.join("4-alias.json")).unwrap();
    // Depth: a secret two levels below a top-level dir the base listing reaches first.
    let deep = base.join("messaging").join("x").join("secret.json");
    fs::create_dir_all(deep.parent().unwrap()).unwrap();
    legacy_file(&deep, &owner, b"{}");
    // A legacy-shaped file under a top-level dir whose inheritable label is Medium NW-only
    // (the default `icacls ... (OI)(CI)M`): refused as an inherited label, never stamped.
    let nw_parent = base.join("nw-parent");
    let nw_security = from_sddl(&format!(
        "O:{owner}D:P(A;OICI;FA;;;{owner})S:(ML;OICI;NW;;;ME)"
    ));
    let nw_attributes = attributes(&nw_security);
    let nw_encoded = wide(&nw_parent);
    // SAFETY: valid path and descriptor live until synchronous creation returns.
    assert_ne!(
        unsafe { CreateDirectoryW(nw_encoded.as_ptr(), &nw_attributes) },
        0
    );
    let inherited = nw_parent.join("legacy.jsonl");
    legacy_file(&inherited, &owner, b"{}");
    let inherited_before = label_aces(&File::open(&inherited).unwrap());
    assert!(
        inherited_before.len() == 1 && inherited_before[0].0 & 0x10 != 0,
        "fixture: the NW label must be inherited, got {inherited_before:?}"
    );
    let report = run_label_upgrade_with(&base, Some(home.path())).unwrap();
    assert_eq!(report.inherited_label_refused, 1, "{report:?}");
    assert_eq!(
        label_aces(&File::open(&inherited).unwrap()),
        inherited_before,
        "an inherited-label file is left as found"
    );
    assert_eq!(
        (report.unresolvable, report.outside_roots),
        (0, 0),
        "a clean tree resolves every object: {report:?}"
    );
    check_private_handle(&File::open(&gemini).unwrap()).unwrap();
    check_private_handle(&File::open(&deep).unwrap()).unwrap();
    assert_eq!(report.multi_linked, 2, "{report:?}");
    assert!(label_aces(&File::open(&linked).unwrap()).is_empty());
    assert!(!report.capped && !report.budget_exhausted, "{report:?}");
    assert_eq!(report.files_stamped, 3, "{report:?}");
    check_private_handle(&File::open(&legacy).unwrap()).unwrap();
    assert_eq!(fs::read(&legacy).unwrap(), b"{}");
    assert!(report.not_private >= 1, "{report:?}");
    assert!(
        label_aces(&File::open(&foreign).unwrap()).is_empty(),
        "a foreign-DACL file must be left untouched"
    );
    assert!(report.reparse_skipped >= 1, "{report:?}");
    assert!(
        label_aces(&File::open(&behind).unwrap()).is_empty(),
        "the file behind a junction must not be reached"
    );
    let again = run_label_upgrade_with(&base, Some(home.path())).unwrap();
    assert_eq!(again.inherited_label_refused, 1, "{again:?}");
    assert_eq!(again.files_stamped, 0, "{again:?}");
    assert!(again.already_labeled >= 3, "{again:?}");
}

// A MIDDLE path component that is a junction to a directory outside the base: the walk
// lists by path, so a component swapped for a junction after the listing hands the applier
// a path whose final object lies elsewhere. The applier must refuse it (`Reparse`) and
// stamp nothing; the same legacy-shaped file really under the base IS stamped (contrast),
// so the refusal comes from containment, not from the file's shape. Reds if
// `Roots::refusal` always returned `None` (containment forced true): the file behind the
// junction would be stamped and the outcome would be `Stamped`.
#[test]
fn native_windows_a_middle_junction_outside_the_base_is_reparse_and_nothing_is_stamped() {
    use crate::platform::label_upgrade::{apply_one_for_test, Kind, Outcome};
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let outside = tempfile::tempdir().unwrap();
    let inner = outside.path().join("inner");
    fs::create_dir(&inner).unwrap();
    let behind = inner.join("secret.json");
    legacy_file(&behind, &owner, b"behind the middle link");
    let link = base.join("mid");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(outside.path())
        .status()
        .unwrap();
    assert!(status.success(), "fixture: junction");
    let through = link.join("inner").join("secret.json");
    assert!(through.is_file(), "fixture: reachable through the junction");

    // Contrast: a legacy-shaped file really under the base is stamped by the same applier.
    let credentials = base.join("credentials");
    fs::create_dir(&credentials).unwrap();
    let genuine = credentials.join("1.json");
    legacy_file(&genuine, &owner, b"{}");
    assert_eq!(
        apply_one_for_test(&base, None, &genuine, Kind::File),
        Outcome::Stamped,
        "contrast: the applier does stamp a legacy file inside the base"
    );

    assert_eq!(
        apply_one_for_test(&base, None, &through, Kind::File),
        Outcome::Reparse
    );
    assert!(
        label_aces(&File::open(&behind).unwrap()).is_empty(),
        "nothing behind the junction is stamped"
    );
    assert_eq!(
        check_private_handle(&File::open(&behind).unwrap()),
        Err(StoreError::UnsafePath),
        "still the unlabeled legacy shape"
    );
    assert_eq!(fs::read(&behind).unwrap(), b"behind the middle link");
}

// The operator's pool `.env` (owner + exact DACL, no label) is opened through the same
// ensure: the missing label is stamped and the file is then accepted with its bytes
// readable; a wrong-label `.env` is refused.
#[test]
fn native_windows_pool_env_file_is_stamped_then_accepted_and_a_wrong_label_refused() {
    use std::io::Read;
    let (_temporary, base) = broad_base();
    let owner = owner_of_this_user(&base);
    let env = base.join("pool.env");
    legacy_file(&env, &owner, b"KEY=value");
    let mut file = crate::chat_sessions::open_private_env_file(&env).unwrap();
    check_private_handle(&file).unwrap();
    let mut text = String::new();
    file.read_to_string(&mut text).unwrap();
    assert_eq!(text, "KEY=value");
    let wrong = base.join("wrong.env");
    let sddl = format!("O:{owner}D:P(A;;FA;;;{owner})S:(ML;;NWNR;;;LW)");
    drop(file_with_sddl(&wrong, &sddl).unwrap());
    assert!(crate::chat_sessions::open_private_env_file(&wrong).is_err());
}

// Windows parity with the unix nlink==1 rule: a transcript with a second hard link is
// refused when the store opens it.
#[test]
fn native_windows_a_hard_linked_transcript_is_refused() {
    let (_temporary, base) = broad_base();
    let store = SessionStore::open(&base, 4096).unwrap();
    drop(store.create(ID).unwrap());
    let transcript = chat_dir(&base).join(format!("{ID}.jsonl"));
    fs::hard_link(&transcript, chat_dir(&base).join("alias.jsonl")).unwrap();
    assert!(matches!(store.resume(ID), Err(StoreError::UnsafePath)));
}
