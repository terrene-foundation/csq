//! S5 default-community boundary tests: actual JSONL files and writer custody.
use csq_core::chat_sessions::{ChatMessage, SessionStore, StoreError};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
const ID: &str = "00000000-0000-4000-8000-000000000001";
const OTHER: &str = "00000000-0000-4000-8000-000000000002";
const CAP: u64 = 8192;
fn fixture() -> tempfile::TempDir {
    #[cfg(unix)]
    let temp = tempfile::Builder::new()
        .prefix("csq-chat-test-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    chmod(temp.path(), 0o700);
    temp
}
fn path(base: &Path, id: &str) -> PathBuf {
    base.join("chat-sessions").join(format!("{id}.jsonl"))
}
fn msg(content: &str) -> ChatMessage {
    ChatMessage {
        role: "user".into(),
        content: content.into(),
    }
}
fn line(message: &ChatMessage) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(message).unwrap();
    bytes.push(b'\n');
    bytes
}
fn seed(base: &Path, bytes: &[u8]) {
    let store = SessionStore::open(base, CAP).unwrap();
    drop(store.create(ID).unwrap());
    fs::write(path(base, ID), bytes).unwrap();
}
fn entries_on_disk(file: &Path) -> Vec<ChatMessage> {
    let bytes = fs::read(file).unwrap();
    assert!(bytes.is_empty() || bytes.ends_with(b"\n"));
    std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|row| serde_json::from_str(row).unwrap())
        .collect()
}
#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn persistence_resumes_same_id_and_keeps_other_ids_independent() {
    let base = fixture();
    let store = SessionStore::open(base.path(), CAP).unwrap();
    let mut writer = store.create(ID).unwrap();
    assert_eq!(writer.id(), ID);
    assert!(writer.entries().is_empty());
    writer.append(msg("hello\nquoted \"world\"")).unwrap();
    let expected = writer.entries().to_vec();
    let mut other = store.create(OTHER).unwrap();
    other.append(msg("other session")).unwrap();
    drop(writer);
    let resumed = SessionStore::open(base.path(), CAP)
        .unwrap()
        .resume(ID)
        .unwrap();
    assert_eq!(resumed.id(), ID);
    assert_eq!(resumed.entries(), expected);
    assert_eq!(entries_on_disk(&path(base.path(), ID)), expected);
    assert_eq!(other.entries(), &[msg("other session")]);
}

#[test]
fn every_atomic_rewrite_redacts_old_and_new_role_and_content() {
    let base = fixture();
    let raw = ChatMessage {
        role: "sk-ant-oat01-OLDROLE".into(),
        content: "old ya29.OLDCONTENT".into(),
    };
    seed(base.path(), &line(&raw));
    let store = SessionStore::open(base.path(), CAP).unwrap();
    let mut writer = store.resume(ID).unwrap();
    let before = fs::read(path(base.path(), ID)).unwrap();
    assert_eq!(before, line(&raw), "resume alone cannot rewrite evidence");
    let mut prior_file = fs::File::open(path(base.path(), ID)).unwrap();
    writer
        .append(ChatMessage {
            role: "sk-ant-ort01-NEWROLE".into(),
            content: "new sk-FAKETESTIJKLMNOPQRSTUVWX".into(),
        })
        .unwrap();
    let bytes = fs::read(path(base.path(), ID)).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    for secret in [
        "OLDROLE",
        "OLDCONTENT",
        "NEWROLE",
        "ABCDEFGHIJKLMNOPQRSTUVWX",
    ] {
        assert!(
            !text.contains(secret),
            "synthetic token must not reach persisted JSONL"
        );
    }
    let expected = vec![
        ChatMessage {
            role: "[REDACTED]".into(),
            content: "old [REDACTED]".into(),
        },
        ChatMessage {
            role: "[REDACTED]".into(),
            content: "new [REDACTED]".into(),
        },
    ];
    assert_eq!(writer.entries(), expected);
    assert_eq!(entries_on_disk(&path(base.path(), ID)), expected);
    let mut retained = Vec::new();
    prior_file.read_to_end(&mut retained).unwrap();
    assert_eq!(
        retained, before,
        "atomic replacement must preserve the previously opened file, not truncate it"
    );
    let mut names: Vec<std::ffi::OsString> = fs::read_dir(base.path().join("chat-sessions"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            std::ffi::OsString::from(format!("{ID}.jsonl")),
            std::ffi::OsString::from(format!("{ID}.lock")),
        ],
        "no raw-token temp or leaked temporary file remains"
    );
}

#[test]
fn same_process_writer_exclusivity_and_drop_release() {
    let base = fixture();
    let first = SessionStore::open(base.path(), CAP).unwrap();
    let second = SessionStore::open(base.path(), CAP).unwrap();
    let writer = first.create(ID).unwrap();
    assert!(matches!(second.resume(ID), Err(StoreError::Busy)));
    assert!(matches!(
        second.create(ID),
        Err(StoreError::Busy | StoreError::AlreadyExists)
    ));
    drop(writer);
    let resumed = second.resume(ID).unwrap();
    assert_eq!(resumed.id(), ID);
    drop(resumed);
    assert!(
        base.path()
            .join("chat-sessions")
            .join(format!("{ID}.lock"))
            .is_file(),
        "stable lock inode remains after release"
    );
}

#[test]
fn cross_process_writer_is_exclusive_and_released_on_drop() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let base = fixture();
    let probe = |mode: &str| {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .env("HOME", base.path())
            .env("CSQ_BASE_DIR", base.path())
            .env("TMPDIR", base.path())
            .env("PATH", "/usr/bin:/bin")
            .env("CSQ_CHAT_CHILD_MODE", mode)
            .args(["--exact", "process_writer_probe"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        for key in ["SYSTEMROOT", "SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("cross-process writer probe exceeded 10s");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert!(status.success(), "child must establish {mode} contract");
        assert_eq!(
            fs::read(base.path().join(format!("probe-{mode}"))).unwrap(),
            mode.as_bytes(),
            "the selected child helper must actually execute"
        );
    };
    let store = SessionStore::open(base.path(), CAP).unwrap();
    let writer = store.create(ID).unwrap();
    probe("busy");
    drop(writer);
    probe("released");
    assert_eq!(
        entries_on_disk(&path(base.path(), ID)),
        vec![msg("child owns released writer")]
    );
}

#[test]
fn process_writer_probe() {
    // Ordinary collection performs no helper work; the parent selects this exact
    // test in a cleaned subprocess with its private base explicitly supplied.
    let Some(mode) = std::env::var_os("CSQ_CHAT_CHILD_MODE") else {
        return;
    };
    let base = PathBuf::from(std::env::var_os("CSQ_BASE_DIR").unwrap());
    let store = SessionStore::open(&base, CAP).unwrap();
    if mode == "busy" {
        assert!(matches!(store.resume(ID), Err(StoreError::Busy)));
    } else {
        assert_eq!(mode, "released");
        let mut writer = store.resume(ID).unwrap();
        writer.append(msg("child owns released writer")).unwrap();
    }
    let mode = mode.to_str().unwrap();
    fs::write(base.join(format!("probe-{mode}")), mode.as_bytes()).unwrap();
}

#[test]
fn torn_last_line_is_uncommitted_and_preserved_until_append() {
    let base = fixture();
    let committed = msg("committed");
    let mut bytes = line(&committed);
    bytes.extend_from_slice(br#"{"role":"user","content":"uncommitted"}"#);
    seed(base.path(), &bytes);
    let store = SessionStore::open(base.path(), CAP).unwrap();
    let mut writer = store.resume(ID).unwrap();
    assert_eq!(writer.entries(), std::slice::from_ref(&committed));
    assert_eq!(fs::read(path(base.path(), ID)).unwrap(), bytes);
    writer.append(msg("next")).unwrap();
    assert_eq!(
        entries_on_disk(&path(base.path(), ID)),
        vec![committed, msg("next")]
    );
}

#[test]
fn invalid_utf8_in_complete_record_or_torn_tail_never_modifies_evidence() {
    for bytes in [
        vec![0xff, b'\n'],
        [line(&msg("prefix")), vec![0xff]].concat(),
    ] {
        let base = fixture();
        seed(base.path(), &bytes);
        let store = SessionStore::open(base.path(), CAP).unwrap();
        assert!(matches!(store.resume(ID), Err(StoreError::InvalidUtf8)));
        assert_eq!(fs::read(path(base.path(), ID)).unwrap(), bytes);
    }
}

#[test]
fn malformed_complete_line_is_refused_instead_of_discarded() {
    for invalid in [
        b"{not-json sk-ant-oat01-FAKETESTONTENT}\n".as_slice(),
        b"{}\n",
        b"\n",
    ] {
        let base = fixture();
        let bytes = [line(&msg("prefix")), invalid.to_vec()].concat();
        seed(base.path(), &bytes);
        let error = match SessionStore::open(base.path(), CAP).unwrap().resume(ID) {
            Err(error) => error,
            Ok(_) => panic!("malformed complete record must be refused"),
        };
        assert!(matches!(error, StoreError::InvalidTranscript));
        assert!(!error.to_string().contains(base.path().to_str().unwrap()));
        // StoreError::InvalidTranscript renders a FIXED string (chat_sessions.rs:
        // `"invalid chat transcript"`), so a "does not contain the fixture" needle
        // can never fail. Assert the exact rendering instead: it reds the moment
        // the Display starts embedding any line content.
        assert_eq!(error.to_string(), "invalid chat transcript");
        assert_eq!(fs::read(path(base.path(), ID)).unwrap(), bytes);
    }
}

#[test]
fn bounded_read_and_append_refuse_without_modifying_committed_state() {
    let base = fixture();
    assert!(matches!(
        SessionStore::open(base.path(), u64::MAX),
        Err(StoreError::TooLarge)
    ));
    assert!(
        !base.path().join("chat-sessions").exists(),
        "overflow cap refusal must precede namespace creation"
    );
    let bytes = vec![b'x'; 65];
    seed(base.path(), &bytes);
    assert!(matches!(
        SessionStore::open(base.path(), 64).unwrap().resume(ID),
        Err(StoreError::TooLarge)
    ));
    assert_eq!(fs::read(path(base.path(), ID)).unwrap(), bytes);
    let base = fixture();
    let first = msg("exact cap\n\"quoted\"\\escaped\t");
    let cap = line(&first).len() as u64;
    let store = SessionStore::open(base.path(), cap).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(first.clone()).unwrap();
    let before = fs::read(path(base.path(), ID)).unwrap();
    assert_eq!(before.len() as u64, cap);
    assert!(matches!(
        writer.append(msg("exceeds")),
        Err(StoreError::TooLarge)
    ));
    assert_eq!(writer.entries(), &[first]);
    assert_eq!(fs::read(path(base.path(), ID)).unwrap(), before);
}

#[test]
fn create_refuses_existing_resume_refuses_absent_and_ids_cannot_traverse() {
    let base = fixture();
    let store = SessionStore::open(base.path(), CAP).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(msg("keep")).unwrap();
    drop(writer);
    let before = fs::read(path(base.path(), ID)).unwrap();
    assert!(matches!(store.create(ID), Err(StoreError::AlreadyExists)));
    assert!(matches!(store.resume(OTHER), Err(StoreError::NotFound)));
    for id in [
        "",
        "../escape",
        "/absolute",
        "not-a-uuid",
        "00000000000040008000000000000001",
        "00000000-0000-4000-8000-00000000000A",
    ] {
        assert!(matches!(store.create(id), Err(StoreError::InvalidId)));
        assert!(matches!(store.resume(id), Err(StoreError::InvalidId)));
    }
    assert_eq!(fs::read(path(base.path(), ID)).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn unix_private_modes_symlink_hardlink_and_nonregular_paths_are_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let base = fixture();
    let store = SessionStore::open(base.path(), CAP).unwrap();
    drop(store.create(ID).unwrap());
    assert_eq!(
        fs::metadata(base.path().join("chat-sessions"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(path(base.path(), ID))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    chmod(&path(base.path(), ID), 0o644);
    assert!(matches!(store.resume(ID), Err(StoreError::UnsafePath)));
    chmod(&path(base.path(), ID), 0o600);
    let outside = base.path().join("outside");
    fs::write(&outside, b"outside-canary").unwrap();
    fs::remove_file(path(base.path(), ID)).unwrap();
    symlink(&outside, path(base.path(), ID)).unwrap();
    assert!(matches!(store.resume(ID), Err(StoreError::UnsafePath)));
    assert_eq!(fs::read(&outside).unwrap(), b"outside-canary");
    fs::remove_file(path(base.path(), ID)).unwrap();
    fs::hard_link(&outside, path(base.path(), ID)).unwrap();
    chmod(&outside, 0o600);
    assert!(matches!(store.resume(ID), Err(StoreError::UnsafePath)));
    fs::remove_file(path(base.path(), ID)).unwrap();
    fs::create_dir(path(base.path(), ID)).unwrap();
    assert!(matches!(store.resume(ID), Err(StoreError::UnsafePath)));
    let lock = base
        .path()
        .join("chat-sessions")
        .join(format!("{OTHER}.lock"));
    symlink(&outside, &lock).unwrap();
    assert!(matches!(store.create(OTHER), Err(StoreError::UnsafePath)));
    let other = fixture();
    symlink(
        base.path().join("chat-sessions"),
        other.path().join("chat-sessions"),
    )
    .unwrap();
    assert!(matches!(
        SessionStore::open(other.path(), CAP),
        Err(StoreError::UnsafePath)
    ));
    let alias = fixture();
    symlink(base.path(), alias.path().join("base-link")).unwrap();
    assert!(matches!(
        SessionStore::open(alias.path().join("base-link"), CAP),
        Err(StoreError::UnsafePath)
    ));
}

#[cfg(unix)]
#[test]
fn unwritable_directory_refuses_even_for_privileged_uid_and_preserves_entries() {
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            chmod(&self.0, 0o700);
        }
    }
    let base = fixture();
    let store = SessionStore::open(base.path(), CAP).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(msg("preserved")).unwrap();
    let before = fs::read(path(base.path(), ID)).unwrap();
    let dir = base.path().join("chat-sessions");
    let _restore = Restore(dir.clone());
    chmod(&dir, 0o500);
    assert!(writer.append(msg("must refuse")).is_err());
    assert_eq!(writer.entries(), &[msg("preserved")]);
    assert_eq!(fs::read(path(base.path(), ID)).unwrap(), before);
    assert!(matches!(
        SessionStore::open(base.path(), CAP),
        Err(StoreError::UnsafePath)
    ));
}
