use super::*;
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

const ID: &str = "550e8400-e29b-41d4-a716-446655440000";
fn base() -> tempfile::TempDir {
    let root = tempfile::Builder::new()
        .prefix("csq-chat-fault-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn message() -> ChatMessage {
    ChatMessage {
        role: "user".into(),
        content: "safe persisted message".into(),
    }
}
fn bytes(root: &Path) -> Vec<u8> {
    fs::read(root.join("chat-sessions").join(format!("{ID}.jsonl"))).unwrap()
}
fn refused_sync(_: &File) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::PermissionDenied))
}

#[test]
fn namespace_parent_sync_failure_and_retry_never_claim_durability() {
    let root = base();
    for _ in 0..2 {
        let mut invoked = false;
        let result = SessionStore::open_with_sync(root.path(), 4096, |parent| {
            invoked = true;
            assert!(node(parent).unwrap() == node(&File::open(root.path()).unwrap()).unwrap());
            let child = root.path().join("chat-sessions");
            assert!(child.is_dir());
            assert_eq!(fs::metadata(child).unwrap().mode() & 0o7777, 0o700);
            refused_sync(parent)
        });
        assert!(invoked, "new and existing child both require parent sync");
        assert!(matches!(result, Err(StoreError::DurabilityUnknown)));
        assert_eq!(
            fs::read_dir(root.path().join("chat-sessions"))
                .unwrap()
                .count(),
            0
        );
    }
    let store = SessionStore::open(root.path(), 4096).unwrap();
    assert!(store.create(ID).is_ok());
}

#[test]
fn post_rename_sync_failure_retains_redacted_snapshot_poisons_and_resumes() {
    let root = base();
    let store = SessionStore::open(root.path(), 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(message()).unwrap();
    let previous = bytes(root.path());
    let candidate = ChatMessage {
        role: "user".into(),
        content: format!("Bearer {}", "a".repeat(64)),
    };
    let sanitized = ChatMessage {
        role: redact_chat(&candidate.role),
        content: redact_chat(&candidate.content),
    };
    assert_ne!(
        sanitized.content, candidate.content,
        "fixture must trigger real redaction"
    );
    let result = writer.append_with_sync(candidate, |directory| {
        assert!(
            node(directory).unwrap()
                == node(&File::open(root.path().join("chat-sessions")).unwrap()).unwrap()
        );
        let published = bytes(root.path());
        assert_ne!(published, previous, "failure occurs after real rename");
        let disk: Vec<ChatMessage> = std::str::from_utf8(&published)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(disk, vec![message(), sanitized.clone()]);
        refused_sync(directory)
    });
    assert_eq!(result, Err(StoreError::DurabilityUnknown));
    assert_eq!(writer.entries(), &[message(), sanitized.clone()]);
    let published = bytes(root.path());
    assert_eq!(writer.append(message()), Err(StoreError::Poisoned));
    assert_eq!(bytes(root.path()), published);
    assert!(matches!(store.resume(ID), Err(StoreError::Busy)));
    drop(writer);
    let independent = SessionStore::open(root.path(), 4096).unwrap();
    let mut resumed = independent.resume(ID).unwrap();
    assert_eq!(resumed.entries(), &[message(), sanitized]);
    assert_eq!(bytes(root.path()), published);
    resumed.append(message()).unwrap();
    assert_eq!(resumed.entries().len(), 3);
    assert_eq!(
        fs::read_dir(root.path().join("chat-sessions"))
            .unwrap()
            .count(),
        2
    );
}

#[test]
fn renamed_base_refuses_append_without_changing_retained_transcript() {
    let root = base();
    let path = root.path().join("base");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let store = SessionStore::open(&path, 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(message()).unwrap();
    let before = bytes(&path);
    let retained = root.path().join("retained-base");
    fs::rename(&path, &retained).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(writer.append(message()), Err(StoreError::UnsafePath));
    assert_eq!(writer.entries(), &[message()]);
    assert_eq!(bytes(&retained), before);
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
}

#[test]
fn replaced_child_refuses_append_without_changing_retained_transcript() {
    let root = base();
    let store = SessionStore::open(root.path(), 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(message()).unwrap();
    let before = bytes(root.path());
    let retained = root.path().join("retained-child");
    fs::rename(root.path().join("chat-sessions"), &retained).unwrap();
    let replacement = root.path().join("chat-sessions");
    fs::create_dir(&replacement).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(writer.append(message()), Err(StoreError::UnsafePath));
    assert_eq!(writer.entries(), &[message()]);
    assert_eq!(
        fs::read(retained.join(format!("{ID}.jsonl"))).unwrap(),
        before
    );
    assert_eq!(fs::read_dir(replacement).unwrap().count(), 0);
}

#[test]
fn replaced_lock_refuses_publication_and_preserves_both_lock_inodes() {
    let root = base();
    let store = SessionStore::open(root.path(), 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(message()).unwrap();
    let before = bytes(root.path());
    let directory = root.path().join("chat-sessions");
    let lock = directory.join(format!("{ID}.lock"));
    let retained = directory.join("retained.lock");
    fs::rename(&lock, &retained).unwrap();
    use std::os::unix::fs::OpenOptionsExt;
    let replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock)
        .unwrap();
    assert_eq!(writer.append(message()), Err(StoreError::UnsafePath));
    assert_eq!(writer.entries(), &[message()]);
    assert_eq!(bytes(root.path()), before);
    assert_eq!(replacement.metadata().unwrap().len(), 0);
    assert_eq!(fs::metadata(&retained).unwrap().len(), 0);
    assert_ne!(
        node(&replacement).unwrap().1,
        node(&writer.lock.0).unwrap().1
    );
    drop(writer);
    assert!(lock.exists() && retained.exists());
}

#[test]
fn production_shards_keep_numeric_load_bearing_line_budget() {
    let load_bearing = |source: &str| {
        source
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with("//"))
            .count()
    };
    for source in [
        include_str!("chat_sessions.rs"),
        include_str!("chat_sessions_platform.rs"),
        include_str!("chat_sessions_cleanup.rs"),
        include_str!("chat_sessions_directory.rs"),
        include_str!("chat_sessions_failure.rs"),
        // fs_windows_acl is a directory module: every PRODUCTION shard is
        // budgeted here. `windows_tests.rs` is excluded — it holds the cfg(test)
        // helpers and the windows-only unit tests, exactly the code the
        // former inline `#[cfg(test)]` items carried.
        include_str!("platform/fs_windows_acl/mod.rs"),
        include_str!("platform/fs_windows_acl/sid.rs"),
        include_str!("platform/fs_windows_acl/descriptor.rs"),
        include_str!("platform/fs_windows_acl/open.rs"),
        include_str!("platform/fs_windows_acl/check.rs"),
    ] {
        assert!(load_bearing(source) <= 500);
    }
}

#[test]
fn oversized_raw_message_is_refused_before_redaction_callback() {
    let candidate = ChatMessage {
        role: "user".into(),
        content: "x".repeat(65),
    };
    let calls = std::cell::Cell::new(0);
    let result = redact_message_checked(&candidate, 64, |text| {
        calls.set(calls.get() + 1);
        text.to_owned()
    });
    assert_eq!(result, Err(StoreError::TooLarge));
    assert_eq!(
        calls.get(),
        0,
        "oversized input must not reach an allocating redactor"
    );
    let accepted = redact_message_checked(&message(), 4096, |text| {
        calls.set(calls.get() + 1);
        text.to_owned()
    })
    .unwrap();
    assert_eq!(accepted, message());
    assert_eq!(
        calls.get(),
        2,
        "accepted role and content both reach the real seam"
    );
}

#[test]
fn prepublication_failure_removes_actual_temp_preserves_snapshot_and_allows_retry() {
    let root = base();
    let store = SessionStore::open(root.path(), 4096).unwrap();
    let mut writer = store.create(ID).unwrap();
    writer.append(message()).unwrap();
    let previous = bytes(root.path());
    let mut temporary = None;
    let sync_called = std::cell::Cell::new(false);
    let candidate = ChatMessage {
        role: "assistant".into(),
        content: "new safe response".into(),
    };
    let result = writer.append_with_hooks(
        candidate.clone(),
        |_| {
            sync_called.set(true);
            Ok(())
        },
        |path| {
            assert!(
                path.is_file(),
                "failure must occur after actual temp creation"
            );
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o600);
            let records: Vec<ChatMessage> = std::str::from_utf8(&fs::read(path).unwrap())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(records, vec![message(), candidate.clone()]);
            temporary = Some(path.to_owned());
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        },
    );
    assert!(
        matches!(result, Err(StoreError::Io(failure)) if failure.stage == "io" && failure.os_error.is_none()),
        "{result:?}"
    );
    assert!(
        !sync_called.get(),
        "publication sync must not occur on prepublication failure"
    );
    assert!(
        !temporary.unwrap().exists(),
        "failed operation must remove its actual temp"
    );
    assert_eq!(
        fs::read_dir(root.path().join("chat-sessions"))
            .unwrap()
            .count(),
        2
    );
    assert_eq!(bytes(root.path()), previous);
    assert_eq!(writer.entries(), &[message()]);
    assert!(!writer.poisoned, "a failure before rename is safe to retry");
    writer.append(candidate.clone()).unwrap();
    assert_eq!(writer.entries(), &[message(), candidate]);
}

#[test]
fn resume_redacts_memory_without_rewriting_disk_then_preserves_sanitized_prefix() {
    let root = base();
    let store = SessionStore::open(root.path(), 4096).unwrap();
    drop(store.create(ID).unwrap());
    let legacy = ChatMessage {
        role: format!("Bearer {}", "a".repeat(64)),
        content: format!("Bearer {}", "b".repeat(64)),
    };
    let mut original = serde_json::to_vec(&legacy).unwrap();
    original.push(b'\n');
    let path = root
        .path()
        .join("chat-sessions")
        .join(format!("{ID}.jsonl"));
    fs::write(&path, &original).unwrap();
    let mut writer = store.resume(ID).unwrap();
    let sanitized = ChatMessage {
        role: redact_chat(&legacy.role),
        content: redact_chat(&legacy.content),
    };
    assert_ne!(sanitized.role, legacy.role);
    assert_ne!(sanitized.content, legacy.content);
    assert_eq!(writer.entries(), std::slice::from_ref(&sanitized));
    assert_eq!(
        bytes(root.path()),
        original,
        "resume must not modify the transcript"
    );
    writer.append(message()).unwrap();
    let mut expected = serde_json::to_vec(&sanitized).unwrap();
    expected.push(b'\n');
    assert!(bytes(root.path()).starts_with(&expected));
    drop(writer);
    assert_eq!(store.resume(ID).unwrap().entries(), &[sanitized, message()]);
}

#[test]
fn chat_message_debug_never_formats_caller_owned_role_or_content() {
    let candidate = ChatMessage {
        role: "synthetic-role-secret".into(),
        content: "synthetic-content-secret".into(),
    };
    for formatted in [format!("{candidate:?}"), format!("{candidate:#?}")] {
        assert!(!formatted.contains(&candidate.role));
        assert!(!formatted.contains(&candidate.content));
        assert!(formatted.contains("ChatMessage"));
    }
}

fn orphan(root: &Path, id: &str) -> PathBuf {
    root.join("chat-sessions")
        .join(format!("{id}.tmp.{}", uuid::Uuid::new_v4()))
}
fn private_file(path: &Path) {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
}

#[test]
fn create_and_resume_sweep_only_owned_session_canonical_orphans_under_lock() {
    const OTHER: &str = "550e8400-e29b-41d4-a716-446655440001";
    let root = base();
    let store = SessionStore::open(root.path(), 4096).unwrap();
    let own = orphan(root.path(), ID);
    let other = orphan(root.path(), OTHER);
    let malformed = root
        .path()
        .join("chat-sessions")
        .join(format!("{ID}.tmp.not-a-uuid"));
    for path in [&own, &other, &malformed] {
        private_file(path);
    }
    let writer = store.create(ID).unwrap();
    assert!(!own.exists());
    assert!(other.exists() && malformed.exists());
    let pending = orphan(root.path(), ID);
    private_file(&pending);
    assert!(matches!(store.resume(ID), Err(StoreError::Busy)));
    assert!(
        pending.exists(),
        "a competing writer cannot sweep before acquiring the lock"
    );
    drop(writer);
    drop(store.resume(ID).unwrap());
    assert!(!pending.exists());
    assert!(other.exists() && malformed.exists());
}

#[test]
fn orphan_sweep_refuses_symlink_hardlink_and_nonprivate_files_without_deletion() {
    for kind in 0..3 {
        let root = base();
        let store = SessionStore::open(root.path(), 4096).unwrap();
        drop(store.create(ID).unwrap());
        let target = root.path().join("retained-private");
        private_file(&target);
        let candidate = orphan(root.path(), ID);
        match kind {
            0 => std::os::unix::fs::symlink(&target, &candidate).unwrap(),
            1 => fs::hard_link(&target, &candidate).unwrap(),
            _ => {
                private_file(&candidate);
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        let before = bytes(root.path());
        assert!(matches!(store.resume(ID), Err(StoreError::UnsafePath)));
        assert!(fs::symlink_metadata(&candidate).is_ok());
        assert!(target.exists());
        assert_eq!(bytes(root.path()), before);
    }
}

#[test]
fn append_redacts_only_new_entry_and_retains_sanitized_prefix() {
    let root = base();
    let store = SessionStore::open(root.path(), 4096).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut writer = store.create(&id).unwrap();
    let calls = std::cell::Cell::new(0);
    for content in ["password=first-secret", "password=second-secret"] {
        writer
            .append_with_redactor(
                ChatMessage {
                    role: "user".into(),
                    content: content.into(),
                },
                sync_directory,
                |_| Ok(()),
                |value| {
                    calls.set(calls.get() + 1);
                    redact_chat(value)
                },
            )
            .unwrap();
    }
    assert_eq!(
        calls.get(),
        4,
        "only the two strings of each new entry are redacted"
    );
    assert!(writer
        .entries()
        .iter()
        .all(|entry| entry.content == "password=[REDACTED]"));
}

// The Debug a failing test prints must name the stage and the raw OS code (and only
// those): a bare `Io` cost a whole Windows CI round to localise.
#[test]
fn io_failures_carry_a_stage_tag_and_the_raw_os_code_only() {
    let raw = io::Error::from_raw_os_error(5);
    assert_eq!(
        io_error_at("rename_ex", raw),
        StoreError::Io(IoFailure {
            stage: "rename_ex",
            os_error: Some(5),
            ex_os_error: None,
            ex_nt_status: None,
            nt_status: None
        })
    );
    let shown = format!(
        "{:?}",
        StoreError::io_os("rename_ex", &io::Error::from_raw_os_error(5))
    );
    assert_eq!(
        shown,
        "Io(IoFailure { stage: \"rename_ex\", os_error: Some(5), ex_os_error: None, ex_nt_status: None, nt_status: None })"
    );
    assert_eq!(
        StoreError::Io(IoFailure {
            stage: "x",
            os_error: None,
            ex_os_error: None,
            ex_nt_status: None,
            nt_status: None
        })
        .to_string(),
        "chat session storage operation failed"
    );
    // Kind-based classes are still reclassified, never wrapped as Io.
    assert_eq!(
        io_error_at("rename_ex", io::Error::from(io::ErrorKind::NotFound)),
        StoreError::NotFound
    );
    assert_eq!(
        io_error_at("rename_ex", io::Error::from(io::ErrorKind::AlreadyExists)),
        StoreError::AlreadyExists
    );
}

#[path = "chat_sessions_redaction_tests.rs"]
mod redaction;
