use super::*;
use std::{
    collections::BTreeMap,
    os::unix::process::ExitStatusExt,
    sync::{Arc, Mutex},
};

const CANARY: &str = "SYNTHETIC-LIFECYCLE-TOKEN-CANARY";
#[derive(Debug, Default)]
struct Event {
    level: Option<tracing::Level>,
    fields: BTreeMap<String, String>,
}
impl tracing::field::Visit for Event {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields.insert(field.name().into(), value.into());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().into(), format!("{value:?}"));
    }
}
struct Capture(Arc<Mutex<Vec<Event>>>);
impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::TRACE)
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut captured = Event {
            level: Some(*event.metadata().level()),
            ..Event::default()
        };
        event.record(&mut captured);
        self.0.lock().unwrap().push(captured);
    }
}
fn logs(run: impl FnOnce()) -> Vec<Event> {
    let _tracing = crate::testing::TRACING_CAPTURE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let events = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Capture(events.clone()), || {
        tracing::callsite::rebuild_interest_cache();
        run()
    });
    // Read through the lock (take, as the events are not Clone): a dispatcher clone may outlive with_default, so
    // sole ownership of the Arc is not guaranteed (an internal ticket).
    // The named binding is deliberate: the `MutexGuard` temporary must drop at the end of this statement,
    // BEFORE `events` goes out of scope at function end (a tail expression would keep it alive past `events`).
    let captured = std::mem::take(&mut *events.lock().unwrap());
    captured
}
fn assert_warning(event: &Event, kind: &str, message: &str, root: &Path) {
    assert_eq!(event.level, Some(tracing::Level::WARN));
    assert_eq!(
        event.fields.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["error_kind", "message"]
    );
    assert_eq!(event.fields["error_kind"], kind);
    assert_eq!(event.fields["message"], message);
    let formatted = format!("{event:?}");
    for private in [
        root.to_str().unwrap(),
        CANARY,
        "No such file or directory",
        "os error",
    ] {
        assert!(
            !formatted.contains(private),
            "diagnostic leaked fixture or raw error"
        );
    }
}
fn root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("csq-lifecycle-diagnostic-")
        .tempdir_in("/tmp")
        .unwrap()
}
// Include directories and file bytes, so warnings cannot mask accidental writes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn visit(root: &Path, path: &Path, rows: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(!meta.file_type().is_symlink());
            rows.insert(
                path.strip_prefix(root).unwrap().to_path_buf(),
                if meta.is_dir() {
                    None
                } else {
                    Some(fs::read(&path).unwrap())
                },
            );
            if meta.is_dir() {
                visit(root, &path, rows);
            }
        }
    }
    let mut rows = BTreeMap::new();
    visit(root, root, &mut rows);
    rows
}
fn valid_ticket(root: &Path) -> LaunchTicket {
    use std::os::unix::fs::PermissionsExt;
    let base = root.canonicalize().unwrap().join("accounts");
    let handle = base.join("term-fixture");
    fs::create_dir(&base).unwrap();
    fs::create_dir(&handle).unwrap();
    for path in [&base, &handle] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    prepare_exec(&handle).expect("current-process trusted capture")
}

#[test]
fn lifecycle_capture_failure_warns_once_without_private_context_or_mutation() {
    let _env = crate::platform::test_env::lock();
    let root = root();
    fs::write(root.path().join("fixture-canary"), CANARY).unwrap();
    let before = snapshot(root.path());
    let events = logs(|| assert!(prepare_exec(&root.path().join(CANARY)).is_none()));
    assert_eq!(events.len(), 1);
    assert_warning(
        &events[0],
        "lifecycle_capture_unknown",
        "managed launch receipt unavailable",
        root.path(),
    );
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn lifecycle_event_failure_warns_without_private_context_or_mutation() {
    let _env = crate::platform::test_env::lock();
    let root = root();
    let ticket = valid_ticket(root.path());
    let leaf = ticket
        .base
        .join("session-lifecycle")
        .join(&ticket.generation);
    fs::rename(&leaf, leaf.with_file_name(CANARY)).unwrap();
    let before = snapshot(root.path());
    let events = logs(|| {
        cancel_exec(Some(&ticket));
        waited(Some(&ticket), &std::process::ExitStatus::from_raw(0));
    });
    assert_eq!(
        events.len(),
        2,
        "both trusted event callers report write refusal"
    );
    for event in events {
        assert_warning(
            &event,
            "lifecycle_event_write_failed",
            "managed lifecycle event unavailable",
            root.path(),
        );
    }
    assert_eq!(snapshot(root.path()), before);
    assert!(!leaf.exists(), "missing generation must not be recreated");
}

#[test]
fn lifecycle_successful_events_and_none_are_warning_free() {
    let _env = crate::platform::test_env::lock();
    let root = root();
    let ticket = valid_ticket(root.path());
    let before_none = snapshot(root.path());
    assert!(logs(|| {
        cancel_exec(None);
        waited(None, &std::process::ExitStatus::from_raw(0));
    })
    .is_empty());
    assert_eq!(snapshot(root.path()), before_none);
    assert!(logs(|| {
        cancel_exec(Some(&ticket));
        waited(Some(&ticket), &std::process::ExitStatus::from_raw(0));
    })
    .is_empty());
    let store = private::store(&ticket.base, false).unwrap();
    let leaf = store.child(&ticket.generation, false).unwrap();
    assert_eq!(
        leaf.read::<End>("cancelled").unwrap().unwrap().reason,
        "exec_failed"
    );
    assert_eq!(
        leaf.read::<End>("ended").unwrap().unwrap().reason,
        "direct_wait"
    );
}
