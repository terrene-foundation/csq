//! Private proposal: crate-internal child of messaging::mcp, Unix only.
//! Real handle_line -> request -> store -> real_fs; no fake operation errors.
//! Synthetic pinned caller/liveness and owned registry are explicit Backend seams.
use super::*;
use crate::messaging::model::Sender;
use crate::sessions::directives::real_fs;
use crate::sessions::directives::{DirectiveError, UndeterminedCause as Cause};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use tempfile::TempDir;

const NOW: u64 = 1_000_000;
const START: u64 = 5_000;
const TARGET: u32 = 200;
const WORKERS: usize = 4;
const EACH: usize = 5;

struct HomeGuard(Option<OsString>);
impl HomeGuard {
    fn install(home: &Path) -> Self {
        let old = std::env::var_os("HOME");
        std::env::set_var("HOME", home);
        Self(old)
    }
}
impl Drop for HomeGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }
}

// No new tracing dependency: this captures the real synchronous subscriber API.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<BTreeMap<String, String>>>>);
struct EventFields(BTreeMap<String, String>);
impl tracing::field::Visit for EventFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().into(), format!("{value:?}"));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().into(), value.to_string());
    }
}
impl tracing::Subscriber for Captured {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = EventFields(BTreeMap::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}
impl Captured {
    fn rows(&self) -> Vec<BTreeMap<String, String>> {
        self.0.lock().unwrap().clone()
    }
    fn assert_safe(&self, canaries: &[&str]) {
        for row in self.rows().iter().filter(|row| {
            matches!(
                row.get("event").map(String::as_str),
                Some("store_lock" | "message_request")
            )
        }) {
            for (key, value) in row {
                assert!(
                    ["event", "stage", "outcome", "cause", "elapsed_ms"].contains(&key.as_str()),
                    "new diagnostic event must expose only approved fields"
                );
                for canary in canaries {
                    assert!(
                        !value.contains(canary),
                        "raw callback/body/path canary leaked to diagnostic trace"
                    );
                }
                if key == "elapsed_ms" {
                    value.parse::<u64>().unwrap();
                }
                if key == "stage" {
                    assert!([
                        "lock_wait",
                        "ledger_write",
                        "registry_read",
                        "wake",
                        "recovery"
                    ]
                    .contains(&value.as_str()));
                }
                if key == "outcome" {
                    assert!(
                        [
                            "start",
                            "acquired",
                            "admission_timeout",
                            "error",
                            "complete"
                        ]
                        .contains(&value.as_str()),
                        "MCP diagnostic outcome must be a fixed token"
                    );
                }
                if key == "cause" {
                    assert!([
                        "unknown",
                        "lock_timeout",
                        "lock_unavailable",
                        "ledger_read",
                        "ledger_write",
                        "clock",
                        "sender_identity",
                        "registry_read",
                        "record_uncertain"
                    ]
                    .contains(&value.as_str()));
                }
            }
        }
    }
}

#[cfg(test)]
fn caller(root: &Path, pid: u32) -> VerifiedSession {
    VerifiedSession::from_resolved(Sender {
        pid,
        started_at: START,
        started_exact: Some(START),
        surface: Surface::Codex,
        handle_dir_hash: format!("fixture{pid}"),
        handle_dir: root.join("caller").to_string_lossy().into_owned(),
        name: None,
    })
}

fn write_registry(root: &Path, complete: bool) {
    let data = json!({"complete":complete,"pid":TARGET,"started_at":START,"label":"fixture-peer"});
    std::fs::write(root.join("registry.json"), data.to_string()).unwrap();
}

fn registry(root: &Path) -> SessionList {
    // The fixture owns this registry file; production discovery is not asserted here.
    let bytes = std::fs::read(root.join("registry.json")).unwrap();
    let data: Value = serde_json::from_slice(&bytes).unwrap();
    SessionList {
        complete: data["complete"].as_bool().unwrap(),
        entries: vec![SessionEntry {
            pid: u32::try_from(data["pid"].as_u64().unwrap()).unwrap(),
            started_at: data["started_at"].as_u64().unwrap(),
            surface: "codex",
            name: None,
            label: Some(data["label"].as_str().unwrap().into()),
            label_source: NameSource::SelfSet,
            repo: None,
            branch: None,
            repo_key: None,
            cwd: root.to_string_lossy().into_owned(),
            label_fallback: false,
        }],
    }
}

fn invoke(root: &Path, pid: u32, arguments: Value) -> (bool, Value) {
    let fs = real_fs();
    let now = || Ok(NOW);
    let live = |_: &Recipient| Liveness::Live;
    let me = || Ok(caller(root, pid));
    let resolve = |p: u32, start: u64| {
        let row = registry(root)
            .entries
            .into_iter()
            .find(|r| r.pid == p && r.started_at == start)
            .expect("fixture resolver must find its owned registry row");
        Ok(Recipient {
            pid: row.pid,
            started_at: row.started_at,
            surface: Surface::Codex,
            started_exact: Some(START),
        })
    };
    let sessions = || Ok(registry(root));
    let set_name = |_: &VerifiedSession, _: Option<&str>| Ok(());
    let wake = |_: &Recipient| "codex_woken";
    let be = Backend {
        base_dir: root,
        now: &now,
        fs: &fs,
        live: &live,
        caller: &me,
        resolve: &resolve,
        sessions: &sessions,
        set_name: &set_name,
        wake: &wake,
    };
    let line = json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"send","arguments":arguments}}).to_string();
    let response = handle_line(&be, &line).unwrap();
    assert!(
        response.get("error").is_none(),
        "real backend must reach tools/call"
    );
    let out = &response["result"];
    let text = out["content"][0]["text"].as_str().unwrap();
    (
        out["isError"].as_bool().unwrap(),
        serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.into())),
    )
}

fn arguments(body: &str, key: Option<&str>) -> Value {
    let mut v = json!({"to":{"name":"fixture-peer"},"body":body});
    if let Some(key) = key {
        v["idempotency_key"] = json!(key);
    }
    v
}

fn key_from_error(text: &str) -> String {
    let key = text
        .split("idempotency_key=")
        .nth(1)
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    request::validate(key, NOW).unwrap();
    key.into()
}

fn count_records(root: &Path) -> usize {
    std::fs::read_dir(store::store_dir(root))
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry.file_name().to_str().is_some_and(|name| {
                name.strip_suffix(".json")
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
            })
        })
        .count()
}

/// Bounded same-key re-issues allowed per send when admission times out before
/// acquisition (`lock_timeout`): nothing is written under the timed-out attempt,
/// and the product's UND recovery for this class is a same-key re-issue.
///
/// Derived, not tuned: the store lock admits one holder at a time and a healthy holder
/// releases it, so an admission timeout means another send held it for the whole
/// admission budget and that send then finished. A send can therefore lose at most once
/// per OTHER send in the run, `WORKERS * EACH - 1`, however slow the host's fsync makes
/// each hold. The cap only bounds a regression where nothing ever completes.
const REISSUE_CAP: u32 = (WORKERS * EACH - 1) as u32;

/// The refusal's typed cause, read through the closed `UndeterminedCause`
/// vocabulary: the token after the `; cause=` delimiter must equal one of the
/// enum's own tokens, so no other text can classify as a retryable refusal.
fn refusal_cause(receipt: &Value) -> Option<Cause> {
    let text = receipt.as_str()?;
    let (_, rest) = text.split_once("; cause=")?;
    let token = rest.split(';').next().unwrap_or(rest);
    [
        Cause::Unknown,
        Cause::LockTimeout,
        Cause::LockUnavailable,
        Cause::LedgerRead,
        Cause::LedgerWrite,
        Cause::Clock,
        Cause::SenderIdentity,
        Cause::RegistryRead,
        Cause::RecordUncertain,
    ]
    .into_iter()
    .find(|cause| cause.as_str() == token)
}

/// A send plus whether it adopted the refusal's minted key (cold mode).
struct SendOutcome {
    error: bool,
    receipt: Value,
    adopted_key: Option<String>,
}

/// Bounded same-key re-issue for a send that refuses with the typed
/// `lock_timeout` cause: admission timed out before it was acquired, nothing
/// was written under that attempt, and the refusal's own message instructs the
/// caller to re-issue the same call (mirrors `request_retry`). A cold-mode
/// caller has no key until the refusal mints one — it adopts that key, so a
/// retry is the same send, never a fresh one. Any other refusal returns as-is.
fn invoke_reissuing(root: &Path, pid: u32, args: &mut Value) -> SendOutcome {
    let (mut error, mut receipt) = invoke(root, pid, args.clone());
    let mut adopted_key = None;
    let mut attempt = 0;
    while error && attempt < REISSUE_CAP && refusal_cause(&receipt) == Some(Cause::LockTimeout) {
        attempt += 1;
        if args.get("idempotency_key").is_none() {
            if let Some(text) = receipt.as_str() {
                let key = key_from_error(text);
                args["idempotency_key"] = json!(key);
                adopted_key = Some(key);
            }
        }
        let (next_error, next_receipt) = invoke(root, pid, args.clone());
        error = next_error;
        receipt = next_receipt;
    }
    SendOutcome {
        error,
        receipt,
        adopted_key,
    }
}

/// Re-call a lock-taking fixture step ONLY for the typed `lock_timeout` cause
/// (bounded by `REISSUE_CAP`); success and every other refusal return as-is.
fn reissuing<T>(mut step: impl FnMut() -> Result<T, DirectiveError>) -> Result<T, DirectiveError> {
    let mut attempt = 0;
    loop {
        match step() {
            Err(e) if e.cause == Some(Cause::LockTimeout) && attempt < REISSUE_CAP => {
                attempt += 1;
            }
            other => return other,
        }
    }
}

fn concurrent(root: &Path, supplied: bool) {
    let gate = Arc::new(Barrier::new(WORKERS));
    let results = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for worker in 0..WORKERS {
            let gate = Arc::clone(&gate);
            threads.push(scope.spawn(move || {
                gate.wait();
                let mut rows = Vec::new();
                for n in 0..EACH {
                    let pid = 100 + u32::try_from(worker).unwrap();
                    let body = format!("healthy fixture {worker} {n}");
                    let key = supplied.then(|| request::mint(NOW));
                    let mut args = arguments(&body, key.as_deref());
                    // Contract: under scheduling starvation a healthy store may refuse
                    // admission with the typed `lock_timeout` cause — admission timed out
                    // before it was acquired, nothing was written under that attempt, and
                    // the refusal's own message instructs the caller to re-issue the same
                    // call (mirrors request_retry). Model a contract-following caller:
                    // bounded same-key re-issue for THAT cause only, first send and replay
                    // alike; every other refusal still fails the test — an observed UND is
                    // never turned into baseline GREEN.
                    let send = invoke_reissuing(root, pid, &mut args);
                    assert!(
                        !send.error,
                        "healthy actual MCP send returned an unexpected refusal or UND: {}",
                        send.receipt
                    );
                    if let Some(adopted) = &send.adopted_key {
                        // Cold mode: the re-issue adopted the key the refusal minted, so
                        // the retry landed as the SAME request — prove positive authority.
                        match reissuing(|| {
                            request::lookup(root, NOW, &real_fs(), &caller(root, pid), adopted)
                        })
                        .unwrap()
                        {
                            request::Lookup::Stored(found, _) => {
                                assert_eq!(json!(found.id), send.receipt["id"])
                            }
                            request::Lookup::NotStored => {
                                panic!("adopted same-key re-issue must retain positive authority")
                            }
                        }
                    }
                    if let Some(key) = key {
                        let replay = invoke_reissuing(root, pid, &mut args);
                        assert!(
                            !replay.error,
                            "healthy same-key replay returned unexpected UND: {}",
                            replay.receipt
                        );
                        assert_eq!(
                            replay.receipt["id"], send.receipt["id"],
                            "same key must preserve actual receipt"
                        );
                        match reissuing(|| {
                            request::lookup(root, NOW, &real_fs(), &caller(root, pid), &key)
                        })
                        .unwrap()
                        {
                            request::Lookup::Stored(found, _) => {
                                assert_eq!(json!(found.id), send.receipt["id"])
                            }
                            request::Lookup::NotStored => {
                                panic!("successful receipt must have retained positive authority")
                            }
                        }
                    }
                    rows.push(send.receipt["id"].as_str().unwrap().to_owned());
                }
                rows
            }));
        }
        threads
            .into_iter()
            .flat_map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.len(), WORKERS * EACH);
    assert_eq!(
        results.iter().collect::<BTreeSet<_>>().len(),
        WORKERS * EACH
    );
    assert_eq!(
        count_records(root),
        WORKERS * EACH,
        "healthy concurrent requests must commit exactly once each"
    );
}

#[test]
fn und_healthy_cold_automatic_mcp_real_store_concurrent_sends() {
    let _env = crate::platform::test_env::lock();
    let owned = TempDir::new().unwrap();
    let _home = HomeGuard::install(owned.path());
    write_registry(owned.path(), true);
    concurrent(owned.path(), false);
}

#[test]
fn und_healthy_warm_supplied_mcp_real_store_concurrent_replays() {
    let _env = crate::platform::test_env::lock();
    let owned = TempDir::new().unwrap();
    let _home = HomeGuard::install(owned.path());
    write_registry(owned.path(), true);
    reissuing(|| request::initialize(owned.path(), NOW, &real_fs())).unwrap();
    concurrent(owned.path(), true);
}

#[test]
fn und_actual_incomplete_registry_repeated_same_key_notstored_then_recovery() {
    let _env = crate::platform::test_env::lock();
    let owned = TempDir::new().unwrap();
    let _home = HomeGuard::install(owned.path());
    write_registry(owned.path(), false);
    let (failed, first) = invoke(owned.path(), 100, arguments("registry fixture", None));
    assert!(failed);
    let text = first.as_str().unwrap();
    assert!(text.starts_with("undetermined:"));
    assert!(
        text.contains("cause=registry_read"),
        "actual incomplete registry must preserve its typed cause"
    );
    assert!(!text.contains("registry fixture"));
    assert!(!text.contains(owned.path().to_str().unwrap()));
    let key = key_from_error(text);
    assert_eq!(
        request::lookup(
            owned.path(),
            NOW,
            &real_fs(),
            &caller(owned.path(), 100),
            &key
        )
        .unwrap(),
        request::Lookup::NotStored
    );
    assert_eq!(count_records(owned.path()), 0);
    for _ in 0..3 {
        let (failed, again) = invoke(owned.path(), 100, arguments("registry fixture", Some(&key)));
        assert!(
            failed,
            "incomplete registry is still unresolved; retry must not invent success"
        );
        let text = again.as_str().unwrap();
        assert!(
            text.contains("cause=registry_read"),
            "repeated incomplete registry must retain originating cause"
        );
        assert_eq!(
            key_from_error(text),
            key,
            "repeated UND must retain the canonical original key"
        );
        assert_eq!(
            request::lookup(
                owned.path(),
                NOW,
                &real_fs(),
                &caller(owned.path(), 100),
                &key
            )
            .unwrap(),
            request::Lookup::NotStored
        );
        assert_eq!(count_records(owned.path()), 0);
    }
    write_registry(owned.path(), true);
    let (failed, receipt) = invoke(owned.path(), 100, arguments("registry fixture", Some(&key)));
    assert!(!failed);
    let (failed, replay) = invoke(owned.path(), 100, arguments("registry fixture", Some(&key)));
    assert!(!failed);
    assert_eq!(replay["id"], receipt["id"]);
    assert_eq!(
        count_records(owned.path()),
        1,
        "resolved registry admits exactly one original send"
    );
}

#[test]
fn und_actual_symlink_original_lock_is_unavailable_and_preserves_key() {
    let _env = crate::platform::test_env::lock();
    let owned = TempDir::new().unwrap();
    let _home = HomeGuard::install(owned.path());
    write_registry(owned.path(), true);
    request::initialize(owned.path(), NOW, &real_fs()).unwrap();
    let lock = store::store_dir(owned.path()).join(".lock");
    let target = owned.path().join("private-lock-target");
    std::fs::write(&target, b"untouched").unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::os::unix::fs::symlink(&target, &lock).unwrap();
    let (failed, first) = invoke(owned.path(), 100, arguments("unsafe lock fixture", None));
    assert!(failed);
    let text = first.as_str().unwrap();
    assert!(
        text.contains("cause=lock_unavailable"),
        "real unsafe original lock must carry unavailable cause"
    );
    assert!(!text.contains("unsafe lock fixture"));
    assert!(!text.contains(owned.path().to_str().unwrap()));
    let key = key_from_error(text);
    for _ in 0..3 {
        let (failed, value) = invoke(
            owned.path(),
            100,
            arguments("unsafe lock fixture", Some(&key)),
        );
        assert!(failed);
        let text = value.as_str().unwrap();
        assert!(
            text.contains("cause=lock_unavailable"),
            "existing lock refusal must retain unavailable cause"
        );
        assert_eq!(key_from_error(text), key);
    }
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    assert_eq!(count_records(owned.path()), 0);
    std::fs::remove_file(&lock).unwrap();
    // Recreate only the named original lock in this owned fixture, not a host namespace.
    drop(crate::sessions::directives::acquire_message_store_lock_as("fixture", &lock).unwrap());
    let (failed, receipt) = invoke(
        owned.path(),
        100,
        arguments("unsafe lock fixture", Some(&key)),
    );
    assert!(!failed);
    let (failed, replay) = invoke(
        owned.path(),
        100,
        arguments("unsafe lock fixture", Some(&key)),
    );
    assert!(!failed);
    assert_eq!(receipt["id"], replay["id"]);
    assert_eq!(count_records(owned.path()), 1);
}

#[test]
fn und_actual_held_original_lock_times_out_then_same_key_recovers_once() {
    let _env = crate::platform::test_env::lock();
    let owned = TempDir::new().unwrap();
    let _home = HomeGuard::install(owned.path());
    write_registry(owned.path(), true);
    request::initialize(owned.path(), NOW, &real_fs()).unwrap();
    let lock = store::store_dir(owned.path()).join(".lock");
    let held =
        crate::sessions::directives::acquire_message_store_lock_as("fixture", &lock).unwrap();
    let started = std::time::Instant::now();
    let captured = Captured::default();
    let (failed, first) = tracing::subscriber::with_default(captured.clone(), || {
        invoke(owned.path(), 100, arguments("held lock fixture", None))
    });
    assert!(failed);
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(9_800),
        "actual exhaustion must include its 98 scheduled 100ms waits"
    );
    let text = first.as_str().unwrap();
    assert!(
        text.contains("cause=lock_timeout"),
        "real contention exhaustion must retain timeout cause"
    );
    assert!(!text.contains("held lock fixture"));
    assert!(!text.contains(owned.path().to_str().unwrap()));
    let key = key_from_error(text);
    let rows = captured.rows();
    let locks: Vec<_> = rows
        .iter()
        .filter(|r| r.get("event").map(String::as_str) == Some("store_lock"))
        .collect();
    assert!(
        locks
            .iter()
            .any(|r| r.get("outcome").map(String::as_str) == Some("start")),
        "actual lock wait must trace its start"
    );
    let timeout = locks
        .iter()
        .find(|r| r.get("outcome").map(String::as_str) == Some("admission_timeout"))
        .expect("actual timeout trace is required");
    assert_eq!(
        timeout.get("cause").map(String::as_str),
        Some("lock_timeout")
    );
    // Two rounds of 50 attempts sleep only between attempts: 2 * 49 * 100ms.
    // The 10s cooperative deadline is a maximum admission budget, not a minimum.
    assert!(timeout["elapsed_ms"].parse::<u64>().unwrap() >= 9_800);
    assert!(
        !locks
            .iter()
            .any(|r| r.get("outcome").map(String::as_str) == Some("acquired")),
        "held lock must never trace successful admission"
    );
    captured.assert_safe(&["held lock fixture", owned.path().to_str().unwrap(), &key]);
    assert_eq!(count_records(owned.path()), 0);
    drop(held);
    assert_eq!(
        request::lookup(
            owned.path(),
            NOW,
            &real_fs(),
            &caller(owned.path(), 100),
            &key
        )
        .unwrap(),
        request::Lookup::NotStored
    );
    let (failed, receipt) = invoke(
        owned.path(),
        100,
        arguments("held lock fixture", Some(&key)),
    );
    assert!(!failed);
    let (failed, replay) = invoke(
        owned.path(),
        100,
        arguments("held lock fixture", Some(&key)),
    );
    assert!(!failed);
    assert_eq!(receipt["id"], replay["id"]);
    assert_eq!(count_records(owned.path()), 1);
}

#[test]
fn und_unknown_callback_canary_is_absent_from_envelope_and_recovery_trace() {
    let _env = crate::platform::test_env::lock();
    let captured = Captured::default();
    // This is an error-decoration contract test, not a synthetic send/repro.
    let canary = "RAW_CALLBACK_PATH_BODY_CANARY_1042";
    let error = tracing::subscriber::with_default(captured.clone(), || {
        request::with_key::<()>(Ok(NOW), None, |_, _| Err(DirectiveError::undet(canary)))
            .unwrap_err()
    });
    assert_eq!(error.code, SdkErrorCode::Undetermined);
    assert!(
        error.message.contains("cause=unknown"),
        "unknown callback must be safely classified"
    );
    assert!(!error.message.contains(canary));
    let key = key_from_error(&error.message);
    assert!(error
        .message
        .contains(&format!("retry the same call with key={key}")));
    assert!(
        captured
            .rows()
            .iter()
            .any(|r| r.get("stage").map(String::as_str) == Some("recovery")
                && r.get("cause").map(String::as_str) == Some("unknown")),
        "safe recovery trace must actually execute"
    );
    captured.assert_safe(&[canary, &key]);
}

#[test]
fn und_typed_origin_survives_fallback_and_initial_clock_without_invented_key() {
    let _env = crate::platform::test_env::lock();
    let originating =
        DirectiveError::undet("RAW_TYPED_ORIGIN_CANARY").with_cause(Cause::LedgerWrite);
    let carried = originating
        .with_cause(Cause::RegistryRead)
        .with_cause(Cause::Clock);
    assert_eq!(
        carried.cause,
        Some(Cause::LedgerWrite),
        "fallback must preserve the precise originating cause"
    );
    let captured = Captured::default();
    let called = std::cell::Cell::new(false);
    let error = tracing::subscriber::with_default(captured.clone(), || {
        request::with_key::<()>(Err(carried), None, |_, _| {
            called.set(true);
            Ok(())
        })
        .unwrap_err()
    });
    assert!(!called.get());
    assert_eq!(
        error.cause,
        Some(Cause::LedgerWrite),
        "initial time wrapper must not erase typed origin"
    );
    assert!(error.message.contains("cause=ledger_write"));
    assert!(!error.message.contains("RAW_TYPED_ORIGIN_CANARY"));
    assert!(
        !error.message.contains("idempotency_key="),
        "failed initial clock cannot invent a recovery key"
    );
    captured.assert_safe(&["RAW_TYPED_ORIGIN_CANARY"]);
    let clock = request::with_key::<()>(
        Err(DirectiveError::undet("RAW_CLOCK_CANARY").with_cause(Cause::Clock)),
        None,
        |_, _| panic!("unavailable initial clock must not execute send"),
    )
    .unwrap_err();
    assert_eq!(clock.cause, Some(Cause::Clock));
    assert!(clock.message.contains("cause=clock"));
    assert!(!clock.message.contains("RAW_CLOCK_CANARY"));
    let definite =
        DirectiveError::rate_limited("fixed rate refusal", Some(NOW + 10)).with_cause(Cause::Clock);
    assert!(definite.cause.is_none());
    let definite = request::with_key::<()>(Ok(NOW), None, |_, _| Err(definite)).unwrap_err();
    assert_eq!(definite.code, SdkErrorCode::RateLimited);
    assert_eq!(definite.next_allowed_at, Some(NOW + 10));
    assert_eq!(definite.message, "fixed rate refusal");
}

#[test]
fn und_actual_success_traces_lock_and_ledger_without_peer_or_key_leaks() {
    let _env = crate::platform::test_env::lock();
    let owned = TempDir::new().unwrap();
    let _home = HomeGuard::install(owned.path());
    write_registry(owned.path(), true);
    let captured = Captured::default();
    let body = "SUCCESS_BODY_CANARY_1042";
    let key = request::mint(NOW);
    let (failed, receipt) = tracing::subscriber::with_default(captured.clone(), || {
        invoke(owned.path(), 100, arguments(body, Some(&key)))
    });
    assert!(!failed);
    assert_eq!(receipt["delivery"], json!("codex_woken"));
    let rows = captured.rows();
    for (event, stage, outcome) in [
        ("store_lock", "lock_wait", "start"),
        ("store_lock", "lock_wait", "acquired"),
        ("message_request", "ledger_write", "start"),
        ("message_request", "ledger_write", "complete"),
        ("message_request", "registry_read", "start"),
        ("message_request", "registry_read", "complete"),
        ("message_request", "wake", "start"),
        ("message_request", "wake", "complete"),
    ] {
        assert!(
            rows.iter()
                .any(|r| r.get("event").map(String::as_str) == Some(event)
                    && r.get("stage").map(String::as_str) == Some(stage)
                    && r.get("outcome").map(String::as_str) == Some(outcome)),
            "actual successful lock/ledger stage trace is required"
        );
    }
    captured.assert_safe(&[body, &key, owned.path().to_str().unwrap()]);
    assert_eq!(count_records(owned.path()), 1);
}

#[test]
fn und_actual_malformed_ledger_repeated_refusal_preserves_read_cause_and_key() {
    let _env = crate::platform::test_env::lock();
    let owned = TempDir::new().unwrap();
    let _home = HomeGuard::install(owned.path());
    write_registry(owned.path(), true);
    request::initialize(owned.path(), NOW, &real_fs()).unwrap();
    let ledger = store::store_dir(owned.path()).join("requests/ledger.json");
    let original = std::fs::read(&ledger).unwrap();
    std::fs::write(&ledger, b"{malformed-ledger-canary").unwrap();
    let (failed, first) = invoke(owned.path(), 100, arguments("ledger read fixture", None));
    assert!(failed);
    let text = first.as_str().unwrap();
    assert!(
        text.contains("cause=ledger_read"),
        "actual malformed authority must carry ledger read cause"
    );
    assert!(!text.contains("malformed-ledger-canary"));
    assert!(!text.contains("ledger read fixture"));
    let key = key_from_error(text);
    for _ in 0..3 {
        let (failed, repeated) = invoke(
            owned.path(),
            100,
            arguments("ledger read fixture", Some(&key)),
        );
        assert!(failed);
        let text = repeated.as_str().unwrap();
        assert!(
            text.contains("cause=ledger_read"),
            "retained malformed ledger must preserve read cause"
        );
        assert_eq!(key_from_error(text), key);
    }
    assert_eq!(count_records(owned.path()), 0);
    // Restoring the exact retained owned fixture authority is not resetting host history.
    std::fs::write(&ledger, original).unwrap();
    let (failed, receipt) = invoke(
        owned.path(),
        100,
        arguments("ledger read fixture", Some(&key)),
    );
    assert!(!failed);
    let (failed, replay) = invoke(
        owned.path(),
        100,
        arguments("ledger read fixture", Some(&key)),
    );
    assert!(!failed);
    assert_eq!(receipt["id"], replay["id"]);
    assert_eq!(count_records(owned.path()), 1);
}

#[test]
fn und_actual_prepared_record_missing_preserves_uncertain_cause_and_original_key() {
    let _env = crate::platform::test_env::lock();
    let owned = TempDir::new().unwrap();
    let _home = HomeGuard::install(owned.path());
    write_registry(owned.path(), true);
    let key = request::mint(NOW);
    let args = arguments("prepared record fixture", Some(&key));
    let (failed, receipt) = invoke(owned.path(), 100, args.clone());
    assert!(!failed);
    let id = receipt["id"].as_str().unwrap();
    let ledger_path = store::store_dir(owned.path()).join("requests/ledger.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&ledger_path).unwrap()).unwrap();
    // Controlled Prepared-state shape using a real writer-produced entry/receipt/digest.
    // This does not claim to reproduce a live publication fault or its ordering.
    assert_eq!(ledger["entries"][id]["committed"], json!(true));
    ledger["entries"][id]["committed"] = json!(false);
    std::fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    std::fs::remove_file(store::store_dir(owned.path()).join(format!("{id}.json"))).unwrap();
    let (failed, error) = invoke(owned.path(), 100, args);
    assert!(
        failed,
        "missing Prepared public record must refuse without a new send"
    );
    let text = error.as_str().unwrap();
    assert!(
        text.contains("cause=record_uncertain"),
        "missing Prepared record must preserve its exact typed cause"
    );
    assert_eq!(key_from_error(text), key);
    assert!(!text.contains("prepared record fixture"));
    assert_eq!(count_records(owned.path()), 0);
}

include!("mcp_clock_admission_tests.rs");
