use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct Fields(BTreeMap<String, String>);
impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
}
struct Capture(Arc<Mutex<Vec<(tracing::Level, Fields)>>>);
impl tracing::Subscriber for Capture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }
    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::WARN)
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.0
            .lock()
            .unwrap()
            .push((*event.metadata().level(), fields));
    }
}
fn captured_report(base: &Path) -> (LifecycleReport, Vec<(tracing::Level, Fields)>) {
    // Retain shared dispatcher/filter custody until with_default has torn down.
    let _capture = crate::testing::TRACING_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let events = Arc::new(Mutex::new(Vec::new()));
    let report = tracing::subscriber::with_default(Capture(events.clone()), || {
        tracing::callsite::rebuild_interest_cache();
        report(base)
    });
    // Read through the lock (take, as the events are not Clone): a dispatcher clone may outlive with_default, so
    // sole ownership of the Arc is not guaranteed (an internal ticket).
    let events = std::mem::take(&mut *events.lock().unwrap());
    (report, events)
}
fn fixture_base() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    // Explicit absolute parent avoids inherited TMPDIR or live HOME entirely.
    let temp = tempfile::Builder::new()
        .prefix("csq-lifecycle-report-diagnostics-")
        .tempdir_in("/tmp")
        .unwrap();
    // The lifecycle store admits only a private current-UID base. Pin the
    // premise rather than depending on tempfile's inherited umask behavior.
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    temp
}
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, current: &Path, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                out.insert(path.strip_prefix(root).unwrap().to_owned(), None);
                visit(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_owned(),
                    Some(fs::read(&path).unwrap()),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
fn assert_safe_failure(events: &[(tracing::Level, Fields)]) {
    assert_eq!(events.len(), 1, "one failed report must emit one warning");
    assert_eq!(events[0].0, tracing::Level::WARN);
    assert_eq!(
        events[0].1 .0,
        BTreeMap::from([
            ("error_kind".into(), "lifecycle_report_failed".into()),
            (
                "message".into(),
                "lifecycle evidence report incomplete".into()
            ),
        ]),
        "only fixed safe fields may be logged; no IO error, path, or PII"
    );
}

#[test]
fn report_lock_refusal_has_closed_reason_safe_warning_and_no_mutation() {
    let temp = fixture_base();
    let base = fs::canonicalize(temp.path()).unwrap();
    let store = private::store(&base, true).unwrap();
    // A stored opaque canary proves that failed report never touches receipt bytes.
    let generation = uuid::Uuid::new_v4().to_string();
    let record = store.child(&generation, true).unwrap();
    drop(record);
    fs::write(
        base.join("session-lifecycle")
            .join(generation)
            .join("launch"),
        b"private-receipt-canary",
    )
    .unwrap();
    private::lock(&store).expect("hold the writer's actual exclusive flock");
    let before = snapshot(&base);
    let (report, events) = captured_report(&base);
    assert_eq!(report.schema, "csq.session-disk.v1");
    assert!(!report.complete);
    assert!(report.rows.is_empty());
    assert_eq!(
        report.reasons,
        vec![
            "open_handles_unknown",
            "current_session_union_unknown",
            "keep_protocol_unknown",
            "store_lock_refused",
            "lifecycle_store_unknown",
        ]
    );
    assert_safe_failure(&events);
    assert_eq!(
        snapshot(&base),
        before,
        "reader must create nothing and preserve every receipt byte"
    );
}

#[test]
fn report_missing_store_warns_without_claiming_lock_refusal_or_creating_state() {
    let temp = fixture_base();
    let base = fs::canonicalize(temp.path()).unwrap();
    let before = snapshot(&base);
    let (report, events) = captured_report(&base);
    assert_eq!(report.schema, "csq.session-disk.v1");
    assert!(!report.complete);
    assert!(report.rows.is_empty());
    assert_eq!(
        report.reasons,
        vec![
            "open_handles_unknown",
            "current_session_union_unknown",
            "keep_protocol_unknown",
            "lifecycle_store_unknown",
        ]
    );
    assert_safe_failure(&events);
    assert_eq!(snapshot(&base), before);
}

#[test]
fn report_complete_empty_store_has_no_failure_warning_or_lock_refusal_reason() {
    let temp = fixture_base();
    let base = fs::canonicalize(temp.path()).unwrap();
    drop(private::store(&base, true).unwrap());
    let before = snapshot(&base);
    let (report, events) = captured_report(&base);
    assert!(report.complete);
    assert!(report.rows.is_empty());
    assert_eq!(
        report.reasons,
        vec![
            "open_handles_unknown",
            "current_session_union_unknown",
            "keep_protocol_unknown",
        ]
    );
    assert!(events.is_empty());
    assert_eq!(snapshot(&base), before);
}

#[test]
fn report_corrupt_receipt_warns_without_claiming_lock_refusal_or_mutating_bytes() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    let temp = fixture_base();
    let base = fs::canonicalize(temp.path()).unwrap();
    let store = private::store(&base, true).unwrap();
    let generation = uuid::Uuid::new_v4().to_string();
    drop(store.child(&generation, true).unwrap());
    let launch = base
        .join("session-lifecycle")
        .join(generation)
        .join("launch");
    fs::write(&launch, b"{").unwrap();
    fs::set_permissions(&launch, fs::Permissions::from_mode(0o600)).unwrap();
    // `store.child(.., true)` takes LOCK_EX on `store`'s open file description (child calls
    // `lock(self)`, which marks the Dir so `Dir::drop` issues LOCK_UN). The explicit unlock
    // in `Dir::drop` is what releases it; a mere close would not while a duplicate exists.
    // sessions::directives forks without exec in this process: a child forked while `store`
    // was open keeps a duplicate. `straggler` is such a duplicate, made deterministically,
    // to prove the report still reads the lock as released after `drop(store)` because
    // LOCK_UN acts on the description whatever copies exist.
    // SAFETY: dup of a live fixture-owned descriptor; the new descriptor is owned below.
    let duplicated = unsafe { libc::dup(store.0.as_raw_fd()) };
    assert!(
        duplicated >= 0,
        "dup failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `duplicated` is a fresh descriptor nothing else owns.
    let straggler = unsafe { <fs::File as std::os::fd::FromRawFd>::from_raw_fd(duplicated) };
    // SAFETY: live owned descriptor; LOCK_UN accesses no Rust memory.
    assert_eq!(
        unsafe { libc::flock(store.0.as_raw_fd(), libc::LOCK_UN) },
        0
    );
    drop(store);
    let before = snapshot(&base);
    let (report, events) = captured_report(&base);
    // The duplicate is still open: only LOCK_UN can have released the lock.
    drop(straggler);
    assert!(!report.complete);
    assert!(report.rows.is_empty());
    assert_eq!(
        report.reasons,
        vec![
            "open_handles_unknown",
            "current_session_union_unknown",
            "keep_protocol_unknown",
            "lifecycle_store_unknown",
        ]
    );
    assert_safe_failure(&events);
    assert_eq!(snapshot(&base), before);
}
