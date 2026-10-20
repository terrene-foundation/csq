//! Event retry tests admit real directory/flock IO; they do not claim launch provenance.
use super::*;
use std::cell::Cell;
use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
use std::time::{Duration, Instant};

// G2c item 6: the fixture wrapper's manual LOCK_UN is retired — `Dir::drop`
// now releases any lock the Dir itself took, across fork-inherited
// duplicates, so the store is used directly.

fn fixture() -> (tempfile::TempDir, LaunchTicket) {
    let temp = tempfile::Builder::new()
        .prefix("csq-lifecycle-retry-")
        .tempdir_in("/tmp")
        .unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let generation = uuid::Uuid::new_v4().to_string();
    let store = private::store(&base, true).unwrap();
    drop(store.child(&generation, true).unwrap());
    // The event writer needs an admitted existing private generation and opaque
    // ticket. Avoid an unrelated capture/process-probe syscall as fixture setup.
    (temp, LaunchTicket { base, generation })
}
fn event() -> End {
    End {
        observed: now().unwrap(),
        reason: "direct_wait".into(),
    }
}
fn event_path(ticket: &LaunchTicket, name: &str) -> PathBuf {
    ticket
        .base
        .join("session-lifecycle")
        .join(&ticket.generation)
        .join(name)
}
fn tree(base: &Path) -> Vec<PathBuf> {
    fn visit(path: &Path, all: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            all.push(entry.path());
            if entry.file_type().unwrap().is_dir() {
                visit(&entry.path(), all);
            }
        }
    }
    let mut all = Vec::new();
    visit(base, &mut all);
    all.sort();
    all
}

#[test]
fn event_transient_real_lock_refusals_retry_same_fd_and_persist_immutable_end() {
    let (_temp, ticket) = fixture();
    let holder = private::store(&ticket.base, false).unwrap();
    private::lock(&holder).unwrap();
    let mut holder = Some(holder);
    let mut attempts = 0;
    let mut refused = 0;
    let mut first_fd = None;
    let end = event();
    write_event_with_lock(&ticket, "ended", &end, |store| {
        attempts += 1;
        let fd = store.0.as_raw_fd();
        assert_eq!(
            *first_fd.get_or_insert(fd),
            fd,
            "retry must retain one opened store descriptor"
        );
        if attempts == 3 {
            drop(holder.take());
        }
        let result = private::lock(store);
        if let Err(error) = &result {
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            refused += 1;
        }
        result
    })
    .expect("a released actual writer lock must allow durable end persistence");
    assert_eq!(
        refused, 2,
        "premise requires two observed actual flock refusals"
    );
    assert_eq!(attempts, 3);
    let store = private::store(&ticket.base, false).unwrap();
    let leaf = store.child(&ticket.generation, false).unwrap();
    let persisted = leaf.read::<End>("ended").unwrap().unwrap();
    assert_eq!(persisted.reason, "direct_wait");
    assert_eq!(persisted.observed, end.observed);
    let original = fs::read(event_path(&ticket, "ended")).unwrap();
    let error = write_event_with_lock(
        &ticket,
        "ended",
        &End {
            observed: end.observed + 1,
            reason: "different-canary".into(),
        },
        private::lock,
    )
    .unwrap_err();
    assert_eq!(
        error.kind(),
        io::ErrorKind::AlreadyExists,
        "O_EXCL duplicate remains an explicit refusal"
    );
    assert_eq!(fs::read(event_path(&ticket, "ended")).unwrap(), original);
}

#[test]
fn event_noncontention_error_does_not_retry_or_create_receipt() {
    let (_temp, ticket) = fixture();
    let before = tree(&ticket.base);
    let attempts = Cell::new(0);
    let error = write_event_with_lock(&ticket, "ended", &event(), |_| {
        attempts.set(attempts.get() + 1);
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        attempts.get(),
        1,
        "terminal refusal must never enter a retry loop"
    );
    assert!(!event_path(&ticket, "ended").exists());
    assert_eq!(tree(&ticket.base), before);
}

#[test]
fn event_persistent_real_lock_refusal_exhausts_boundedly_without_creation() {
    let (_temp, ticket) = fixture();
    let holder = private::store(&ticket.base, false).unwrap();
    private::lock(&holder).unwrap();
    let before = tree(&ticket.base);
    let thread_ticket = LaunchTicket {
        base: ticket.base.clone(),
        generation: ticket.generation.clone(),
    };
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let attempts = Cell::new(0);
        let first_fd = Cell::new(None);
        let started = Instant::now();
        let result = write_event_with_lock(&thread_ticket, "ended", &event(), |store| {
            attempts.set(attempts.get() + 1);
            let fd = store.0.as_raw_fd();
            match first_fd.get() {
                None => first_fd.set(Some(fd)),
                Some(first) => assert_eq!(fd, first),
            }
            private::lock(store)
        });
        send.send((result, attempts.get(), started.elapsed()))
            .unwrap();
    });
    let (result, attempts, elapsed) = receive
        .recv_timeout(Duration::from_secs(5))
        .expect("retry exhaustion must complete rather than hang the test");
    worker.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!((2..=EVENT_LOCK_MAX_ATTEMPTS).contains(&attempts));
    assert!(
        elapsed <= Duration::from_secs(5),
        "2-second retry budget plus scheduler grace must be finite"
    );
    assert!(!event_path(&ticket, "ended").exists());
    assert_eq!(
        tree(&ticket.base),
        before,
        "exhaustion may not create a receipt or generation"
    );
    drop(holder);
    write_event_with_lock(&ticket, "ended", &event(), private::lock).unwrap();
    assert_eq!(
        private::store(&ticket.base, false)
            .unwrap()
            .child(&ticket.generation, false)
            .unwrap()
            .read::<End>("ended")
            .unwrap()
            .unwrap()
            .reason,
        "direct_wait"
    );
}

#[test]
fn event_missing_generation_after_lock_release_is_not_recreated_or_retried() {
    let (_temp, ticket) = fixture();
    let leaf = ticket
        .base
        .join("session-lifecycle")
        .join(&ticket.generation);
    fs::remove_dir(&leaf).unwrap();
    let holder = private::store(&ticket.base, false).unwrap();
    private::lock(&holder).unwrap();
    let mut holder = Some(holder);
    let attempts = Cell::new(0);
    let before = tree(&ticket.base);
    let error = write_event_with_lock(&ticket, "cancelled", &event(), |store| {
        attempts.set(attempts.get() + 1);
        if attempts.get() == 2 {
            drop(holder.take());
        }
        private::lock(store)
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        attempts.get(),
        2,
        "only lock contention retries; missing generation does not"
    );
    assert!(!leaf.exists());
    assert_eq!(tree(&ticket.base), before);
}
