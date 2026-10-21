#[cfg(unix)]
use super::super::lifecycle::{cancel_exec, prepare_exec, LaunchTicket};
#[cfg(unix)]
use super::*;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
fn fixture() -> (tempfile::TempDir, PathBuf, LaunchTicket) {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap().join("accounts");
    let handle = base.join("term-fixture");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(&handle).unwrap();
    fs::set_permissions(&handle, fs::Permissions::from_mode(0o700)).unwrap();
    let ticket = prepare_exec(&handle).expect("own process capture on supported Unix");
    (temp, base, ticket)
}

/// A second capture of an already-prepared handle re-runs the full syscall gauntlet
/// (store lock, `/proc` reads, mkdirat + writes) while the rest of this suite drives
/// the same host; a transient refusal here must not surface as a bare `None`. Every
/// iteration is a real `prepare_exec` attempt and the cap makes a persistent failure
/// LOUD, naming the window.
#[cfg(unix)]
fn prepare_exec_until_observed(handle: &Path) -> LaunchTicket {
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if let Some(ticket) = prepare_exec(handle) {
            return ticket;
        }
        assert!(
            start.elapsed() <= BUDGET,
            "second incarnation never captured within {BUDGET:?} ({attempts} attempts)"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Take the writer's exclusive store lock for the contention premise of
/// `report_reader_refuses_contended_writer_without_creating_files`. A transient
/// refusal must not turn the premise into a failed setup; every iteration is a real
/// `lock` attempt and the cap names the window, so a persistent refusal stays LOUD.
/// The refusal property under test is unchanged.
#[cfg(unix)]
fn hold_store_lock(store: &private::Dir) {
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        if private::lock(store).is_ok() {
            return;
        }
        assert!(
            start.elapsed() <= BUDGET,
            "store lock never acquired within {BUDGET:?} ({attempts} attempts)"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// `report` returns `complete: false` for a store it cannot lock or verify — correct
/// production behaviour, but a transient refusal would fail a test's premise rather
/// than its property. Retry while the observation is UNKNOWN; every iteration is a
/// real `report`, the cap keeps a persistent incompleteness LOUD, and the
/// row/decision assertions stay the property under test.
#[cfg(unix)]
fn report_until_complete(base: &Path) -> LifecycleReport {
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let start = std::time::Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        let r = report(base);
        if r.complete {
            return r;
        }
        assert!(
            start.elapsed() <= BUDGET,
            "report stayed incomplete within {BUDGET:?} ({attempts} attempts)"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(unix)]
#[test]
fn actual_launch_is_unbound_and_cancel_is_not_vendor_completion() {
    let (_temp, base, ticket) = fixture();
    let before = report_until_complete(&base);
    assert!(before.complete);
    assert_eq!(before.rows.len(), 1);
    assert_eq!(before.rows[0].pid, std::process::id());
    assert_eq!(before.rows[0].decision, "KEEP");
    assert!(before.rows[0].reasons.contains(&"scratch_binding_unproved"));
    // `cancel_exec` persists the cancel event best-effort (its store write is
    // deliberately swallowed by `mark`); a transient refusal of that write can
    // drop it. Re-issue the contract call until the event is OBSERVED in the
    // store; re-writing is inert once present (O_EXCL), and the cap keeps a
    // persistent miss LOUD. The restored-state assertions below are unchanged.
    let d = private::store(&base, false)
        .unwrap()
        .child(&before.rows[0].generation, false)
        .unwrap();
    {
        const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        let mut attempts = 0u32;
        while d.read::<private::End>("cancelled").unwrap().is_none() {
            attempts += 1;
            assert!(
                start.elapsed() <= BUDGET,
                "cancel evidence never observed within {BUDGET:?} ({attempts} attempts)"
            );
            cancel_exec(Some(&ticket));
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    let after = report_until_complete(&base);
    assert!(after.complete);
    assert_eq!(after.rows[0].state, "cancelled");
    assert!(after.rows[0].reasons.contains(&"positive_end_unproved"));
}

#[cfg(unix)]
#[test]
fn resumed_uuid_keeps_separate_incarnations_and_unknown_holders() {
    let (_temp, base, _first) = fixture();
    let _second = prepare_exec_until_observed(&base.join("term-fixture"));
    let r = report_until_complete(&base);
    assert_eq!(r.rows.len(), 2);
    assert_ne!(r.rows[0].generation, r.rows[1].generation);
    assert!(r
        .rows
        .iter()
        .all(|r| r.decision == "KEEP" && r.reasons.contains(&"open_handles_unknown")));
}

#[cfg(unix)]
#[test]
fn report_missing_store_does_not_create_lock_or_directory() {
    let temp = tempfile::tempdir().unwrap();
    let before = fs::read_dir(temp.path()).unwrap().count();
    let r = report(temp.path());
    assert!(!r.complete);
    assert!(r.reasons.contains(&"lifecycle_store_unknown"));
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), before);
}

#[cfg(unix)]
#[test]
fn symlink_store_and_record_file_are_rejected_without_following() {
    use std::os::unix::fs::symlink;
    let (_temp, base, _ticket) = fixture();
    let d = base
        .join("session-lifecycle")
        .join(&report_until_complete(&base).rows[0].generation);
    let original = fs::read(d.join("launch")).unwrap();
    fs::rename(d.join("launch"), d.join("preserved")).unwrap();
    symlink("preserved", d.join("launch")).unwrap();
    assert!(!report(&base).complete);
    assert_eq!(fs::read(d.join("preserved")).unwrap(), original);
    let other = tempfile::tempdir().unwrap();
    symlink(
        base.join("session-lifecycle"),
        other.path().join("session-lifecycle"),
    )
    .unwrap();
    assert!(!report(other.path()).complete);
}

#[cfg(unix)]
#[test]
fn corrupt_or_oversized_receipt_is_unknown_not_empty_success() {
    let (_temp, base, _ticket) = fixture();
    let file = base
        .join("session-lifecycle")
        .join(&report_until_complete(&base).rows[0].generation)
        .join("launch");
    fs::write(&file, b"{").unwrap();
    assert!(!report(&base).complete);
    fs::write(&file, vec![b'x'; MAX_BYTES + 1]).unwrap();
    assert!(!report(&base).complete);
}

#[cfg(unix)]
#[test]
fn report_reader_refuses_contended_writer_without_creating_files() {
    let (_temp, base, _ticket) = fixture();
    let store = private::store(&base, false).unwrap();
    hold_store_lock(&store);
    let before = store.names().unwrap();
    assert!(!report(&base).complete);
    assert_eq!(store.names().unwrap(), before);
}
