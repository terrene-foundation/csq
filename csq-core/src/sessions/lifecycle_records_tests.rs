use super::*;
fn fixture() -> (tempfile::TempDir, PathBuf, Dir, Launch) {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap().join("accounts");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let root = store(&base, true).unwrap();
    // Synthetic DTO validates storage shape, never claims a managed native launch.
    let l = Launch {
        schema: 1,
        generation: uuid::Uuid::new_v4().to_string(),
        boot: boot().unwrap(),
        uid: unsafe { libc::geteuid() },
        pid: 1,
        exact: 1,
        units: start_units().into(),
        handle: base.join("synthetic-handle"),
        handle_dev: 1,
        handle_ino: 1,
        cwd: base.clone(),
        created: now().unwrap(),
    };
    (temp, base, root, l)
}
/// G2b item 2 — same class as the login lock: `child(..., create=true)`
/// takes the flock on its parent `Dir`'s descriptor, and a forked child
/// inherits it. Dropping the parent MUST release explicitly (LOCK_UN),
/// or the next writer's `lock()` still sees the store held.
#[cfg(unix)]
#[test]
fn fork_child_does_not_hold_the_store_lock_past_drop() {
    let (_temp, base, root, l) = fixture();

    // Production shape: the STORE dir takes the lock in child(create=true)
    // (the base dir refuses a UUID child — names() admits only UUID entries).
    let _gen_dir = root.child(&l.generation, true).unwrap();
    let child = crate::fork_harness::ForkedChild::spawn();
    drop(root);

    let reopened = store(&base, true).unwrap();
    lock(&reopened).expect("the store lock must be free once its holder drops");
    drop(child);
}

/// Same class for the report's READ lock: `lock_shared` must mark the Dir so its drop
/// unlocks explicitly, or a forked duplicate keeps the shared lock and the next
/// writer's `lock()` is refused.
#[cfg(unix)]
#[test]
fn fork_child_does_not_hold_the_shared_store_lock_past_drop() {
    let (_temp, base, root, l) = fixture();
    let _gen_dir = root.child(&l.generation, true).unwrap();
    drop(_gen_dir);
    drop(root);
    let reader = store(&base, false).unwrap();
    lock_shared(&reader).unwrap();
    let child = crate::fork_harness::ForkedChild::spawn();
    drop(reader);

    let writer = store(&base, true).unwrap();
    lock(&writer).expect("the shared store lock must be free once its holder drops");
    drop(child);
}

#[test]
fn private_record_roundtrip_is_immutable_and_bounded() {
    let (_temp, _base, root, l) = fixture();
    let d = root.child(&l.generation, true).unwrap();
    d.write("launch", &l).unwrap();
    let parsed: Launch = d.read("launch").unwrap().unwrap();
    assert_eq!(parsed.generation, l.generation);
    assert!(d.write("launch", &l).is_err());
    assert!(d.write("oversize", &vec![0u8; MAX_BYTES + 1]).is_err());
    use std::os::unix::fs::MetadataExt;
    assert_eq!(d.0.metadata().unwrap().mode() & 0o077, 0);
}
#[test]
fn file_symlink_and_oversize_fail_closed() {
    use std::os::unix::fs::symlink;
    let (_temp, base, root, l) = fixture();
    let d = root.child(&l.generation, true).unwrap();
    d.write("launch", &l).unwrap();
    let path = base.join("session-lifecycle").join(&l.generation);
    fs::rename(path.join("launch"), path.join("preserved")).unwrap();
    symlink("preserved", path.join("launch")).unwrap();
    assert!(d.read::<Launch>("launch").is_err());
    fs::write(path.join("large"), vec![b'x'; MAX_BYTES + 1]).unwrap();
    assert!(d.read::<Launch>("large").is_err());
}
#[test]
fn component_escape_cannot_reach_real_sibling_directory() {
    use std::os::unix::fs::PermissionsExt;
    let (_temp, base, root, _l) = fixture();
    let sibling = base.join("sibling");
    fs::create_dir(&sibling).unwrap();
    fs::set_permissions(&sibling, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(root.child("../sibling", false).is_err());
    assert!(root.write("../escaped", &1).is_err());
    assert!(!base.join("escaped").exists());
}
#[test]
fn existing_reader_never_initializes_missing_store() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    assert!(store(&base, false).is_err());
    assert_eq!(fs::read_dir(&base).unwrap().count(), 0);
}
#[test]
fn schema_clock_boot_and_shape_validation_are_independent() {
    let (_temp, _base, _root, l) = fixture();
    assert!(validate_launch(&l, &l.generation).is_ok());
    for bad in 0..5 {
        let mut value = l.clone();
        match bad {
            0 => value.boot = "foreign".into(),
            1 => value.created = now().unwrap() + 60,
            2 => value.handle = PathBuf::from("relative"),
            3 => value.handle_ino = 0,
            _ => value.units = "wrong".into(),
        };
        assert!(validate_launch(&value, &l.generation).is_err());
    }
    assert!(validate_event(
        Some(&End {
            observed: l.created + 60,
            reason: "raw_esrch".into()
        }),
        &l,
        &["raw_esrch"]
    )
    .is_err());
}
#[test]
fn strict_record_enumeration_is_nonvacuous_and_rejects_unknown_entry() {
    let (_temp, base, root, l) = fixture();
    root.child(&l.generation, true).unwrap();
    assert_eq!(root.names().unwrap(), vec![l.generation]);
    fs::write(base.join("session-lifecycle").join("unexpected"), b"x").unwrap();
    assert!(root.names().is_err());
}

thread_local! {
    static AFTER_COUNT:std::cell::RefCell<Option<std::sync::Arc<std::sync::Barrier>>>=const {std::cell::RefCell::new(None)};
}
pub(super) fn after_count() {
    AFTER_COUNT.with(|gate| {
        if let Some(gate) = gate.borrow().as_ref() {
            gate.wait();
        }
    });
}
#[test]
fn independent_parents_cannot_race_past_generation_capacity() {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::{Arc, Barrier};
    let (_temp, base, root, _launch) = fixture();
    let path = base.join("session-lifecycle");
    for index in 0..MAX_RECORDS - 1 {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path.join(uuid::Uuid::from_u128(index as u128).to_string()))
            .unwrap();
    }
    assert_eq!(root.names().unwrap().len(), MAX_RECORDS - 1);
    drop(root);
    let before = Arc::new(Barrier::new(3));
    let after = Arc::new(Barrier::new(2));
    let workers = (0..2)
        .map(|index| {
            let base = base.clone();
            let before = before.clone();
            let after = after.clone();
            std::thread::spawn(move || {
                let parent = store(&base, false).unwrap();
                AFTER_COUNT.with(|gate| *gate.borrow_mut() = Some(after.clone()));
                before.wait();
                let name = uuid::Uuid::from_u128((MAX_RECORDS + index) as u128).to_string();
                let result = parent.child(&name, true);
                // With serialization the loser never reaches after-count; release the winner.
                if result.is_err() {
                    after.wait();
                }
                result.is_ok()
            })
        })
        .collect::<Vec<_>>();
    before.wait();
    let successes = workers
        .into_iter()
        .map(|w| usize::from(w.join().unwrap()))
        .sum::<usize>();
    assert_eq!(
        fs::read_dir(&path).unwrap().count(),
        MAX_RECORDS,
        "actual namespace overshot capacity"
    );
    assert_eq!(successes, 1);
}

// An ancestor that is searchable but not readable (`0o300` for the owner here; `0o711`/`0o710`
// on real hosts) must not refuse the store: ancestors are only traversed. Old code opened every
// component `O_RDONLY` and failed with EACCES.
#[test]
fn searchable_but_unreadable_ancestor_is_traversable() {
    use std::os::unix::fs::PermissionsExt;
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let ancestor = fs::canonicalize(temp.path()).unwrap().join("outer");
    fs::create_dir(&ancestor).unwrap();
    let base = ancestor.join("accounts");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let _restore = Restore(ancestor.clone());
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o300)).unwrap();
    Dir::open(&base).unwrap();
}

// An ancestor another user could rename or replace (world- or group-writable, not a root-owned
// sticky directory) must refuse the store, as `SecureDatabase` does for its ancestors.
#[test]
fn group_or_world_writable_ancestor_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }
    for mode in [0o777, 0o770, 0o707] {
        let temp = tempfile::tempdir().unwrap();
        let ancestor = fs::canonicalize(temp.path()).unwrap().join("outer");
        fs::create_dir(&ancestor).unwrap();
        let base = ancestor.join("accounts");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let _restore = Restore(ancestor.clone());
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(mode)).unwrap();
        assert!(Dir::open(&base).is_err(), "ancestor mode {mode:o} accepted");
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
        Dir::open(&base).unwrap();
    }
}

// Search-only ancestors of every owner-class shape are traversed, but unreadable is not
// trusted: a group- or other-writable one is refused whatever its read bits.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn unreadable_ancestor_is_accepted_only_when_not_writable() {
    use std::os::unix::fs::PermissionsExt;
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let ancestor = fs::canonicalize(temp.path()).unwrap().join("outer");
    fs::create_dir(&ancestor).unwrap();
    let base = ancestor.join("accounts");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let _restore = Restore(ancestor.clone());
    for mode in [0o100, 0o300] {
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(mode)).unwrap();
        Dir::open(&base).unwrap_or_else(|e| panic!("search-only {mode:o} refused: {e}"));
    }
    for mode in [0o370, 0o307, 0o330, 0o303] {
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(mode)).unwrap();
        let error = Dir::open(&base)
            .err()
            .unwrap_or_else(|| panic!("unreadable writable ancestor {mode:o} accepted"));
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "{mode:o}: {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("refused") && message.contains("writable"),
            "{mode:o}: {message}"
        );
        assert!(
            message.contains(ancestor.to_str().unwrap()),
            "names the ancestor: {message}"
        );
    }
}

// An our-owned `1777` ancestor is refused end to end: the sticky bit only excuses a
// root-owned directory (`/tmp`), so another user could still plant an entry.
#[test]
fn our_owned_sticky_world_writable_ancestor_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let ancestor = fs::canonicalize(temp.path()).unwrap().join("outer");
    fs::create_dir(&ancestor).unwrap();
    let base = ancestor.join("accounts");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
    Dir::open(&base).expect("control: a private ancestor is accepted");
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o1777)).unwrap();
    let error = Dir::open(&base).err().expect("1777 ancestor accepted");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    assert!(error.to_string().contains("writable"), "{error}");
}

// A regular file where an ancestor directory should be is refused, not traversed.
#[test]
fn non_directory_ancestor_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let file = root.join("not-a-dir");
    fs::write(&file, b"x").unwrap();
    let error = Dir::open(&file.join("accounts"))
        .err()
        .expect("file ancestor accepted");
    assert_eq!(error.raw_os_error(), Some(libc::ENOTDIR), "{error}");
}

// A symlinked ancestor is refused even when its target is search-only.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn symlinked_ancestor_over_unreadable_target_is_refused() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    let base = real.join("accounts");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real, root.join("link")).unwrap();
    let _restore = Restore(real.clone());
    fs::set_permissions(&real, fs::Permissions::from_mode(0o300)).unwrap();
    assert!(
        Dir::open(&root.join("link").join("accounts")).is_err(),
        "symlinked ancestor accepted"
    );
    Dir::open(&base).expect("the same target without the symlink is accepted");
}

// MED-A: an ALLOW ACL that lets a grantee change entries on an ancestor, or on the store
// directory itself, refuses the store although the mode bits are clean.
#[cfg(target_os = "macos")]
#[test]
fn acl_granting_entry_changes_on_an_ancestor_or_the_store_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let ancestor = fs::canonicalize(temp.path()).unwrap().join("outer");
    fs::create_dir(&ancestor).unwrap();
    let base = ancestor.join("accounts");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    Dir::open(&base).unwrap();
    crate::platform::fs::tests::chmod_add_acl(&ancestor, "everyone allow add_file");
    assert!(Dir::open(&base).is_err(), "ancestor ACL accepted");
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap().join("accounts");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    Dir::open(&base).unwrap();
    crate::platform::fs::tests::chmod_add_acl(&base, "everyone allow add_subdirectory");
    assert!(Dir::open(&base).is_err(), "store ACL accepted");
}
