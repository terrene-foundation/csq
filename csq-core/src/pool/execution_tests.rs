//! Synthetic-provider integration tests with isolated custody and a durable ledger.
use super::{execute_with_clock, execute_with_transport, PoolClock, PoolExecRequest};
use crate::platform::secret::{
    file::FileVault, NamedKey, NamedWorkerState, SecretError, SlotKey, Vault,
};
use crate::pool::execution_ledger::{BudgetError, BudgetLedger, ReserveResult};
use crate::pool::execution_transport::{PoolTransport, TransportError};
use crate::pool::store::ExecutionCandidate;
use crate::pool::{Pool, PoolName};
use csq_sdk::{Completion, FinishReason, SdkError, SdkErrorCode, Usage};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

const MODEL: &str = "pool-fixture-model";
use crate::pool::REAL_WAIT_CAP;
// 1000 full-context input tokens at $1/M + 10 maximum output tokens at $2/M.
const HOLD: u64 = 1_020_000;

struct Fixture {
    dir: TempDir,
    vault: Arc<dyn Vault>,
    /// Frozen floor of this fixture's UTC; see `Fixture::utc`.
    utc0: chrono::DateTime<chrono::Utc>,
}
impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let vault = Arc::new(FileVault::open_test(&dir.path().join("fixture-vault")).unwrap());
        let fixture = Self {
            dir,
            vault,
            utc0: chrono::Utc::now(),
        };
        fixture.write_manifest(manifest());
        fixture
    }
    /// The fixture's frozen UTC: the floor, or the latest stored key `added_at`
    /// when that is later (the ledger requires admission time >= `added_at`, and
    /// key creation stamps the real wall clock). It depends only on stored data,
    /// never on how much real time has passed, so every run and ledger assertion
    /// between two key additions sees one identical instant.
    fn utc(&self) -> chrono::DateTime<chrono::Utc> {
        let bytes = match std::fs::read(self.base().join("pool/manifest.json")) {
            Ok(bytes) => bytes,
            // No key has been added yet: nothing can be later than the floor.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return self.utc0,
            Err(error) => panic!("fixture manifest must be readable: {error}"),
        };
        let manifest: Value =
            serde_json::from_slice(&bytes).expect("fixture manifest must be valid JSON");
        manifest["entries"]
            .as_array()
            .expect("fixture manifest must have an entries array")
            .iter()
            .map(|row| {
                let added = row["entry"]["added_at"]
                    .as_str()
                    .expect("every stored entry must carry added_at");
                chrono::DateTime::parse_from_rfc3339(added)
                    .expect("stored added_at must be RFC 3339")
                    .with_timezone(&chrono::Utc)
            })
            .fold(self.utc0, std::cmp::max)
    }
    fn base(&self) -> &Path {
        self.dir.path()
    }
    fn pool(&self) -> Pool {
        Pool::with_vault(
            self.base(),
            Box::new(FileVault::open_test(&self.base().join("fixture-vault")).unwrap()),
        )
    }
    fn add(&self, name: &str, cap: f64) {
        self.add_for(name, "anthropic", cap);
    }
    fn add_for(&self, name: &str, provider: &str, cap: f64) {
        self.pool()
            .add(
                name,
                provider,
                SecretString::from(format!("synthetic-{name}")),
                None,
                Some(cap),
            )
            .unwrap();
    }
    fn add_uncapped(&self, name: &str) {
        self.pool()
            .add(
                name,
                "anthropic",
                SecretString::from(format!("synthetic-{name}")),
                None,
                None,
            )
            .unwrap();
    }
    fn ledger(&self) -> FixtureLedger<'_> {
        FixtureLedger(self)
    }
    fn resolve(&self, name: &str) -> Result<(), SdkError> {
        Pool::with_default_vault_for_test(self.vault.clone(), || {
            with_frozen_clock(self.utc(), |clock| {
                super::resolve_with_clock(self.base(), &PoolName::new(name).unwrap(), clock)
            })
        })
    }
    fn write_manifest(&self, value: Value) {
        std::fs::write(
            self.base().join("model-rates.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        crate::providers::model_manifest::ModelManifest::load(self.base()).unwrap();
    }
    fn run(
        &self,
        request: PoolExecRequest,
        transport: &dyn PoolTransport,
    ) -> Result<Completion, SdkError> {
        Pool::with_default_vault_for_test(self.vault.clone(), || {
            run_on_frozen_clock(self.base(), self.utc(), request, transport)
        })
    }
}
/// One frozen monotonic + UTC clock for resolve/rebaseline, matching `run_on_frozen_clock`.
fn with_frozen_clock<R>(
    utc0: chrono::DateTime<chrono::Utc>,
    operation: impl FnOnce(&PoolClock<'_>) -> R,
) -> R {
    let origin = std::time::Instant::now();
    let monotonic = move || origin;
    let utc = move || utc0;
    operation(&PoolClock::new(&monotonic, &utc))
}
/// Runs one execution on a monotonic clock that never advances by itself, so the
/// verdict of a fixture-driven test cannot depend on how long the host takes.
/// Tests that need time to pass drive their own clock through `execute_with_clock`.
fn run_on_frozen_clock(
    base: &Path,
    utc0: chrono::DateTime<chrono::Utc>,
    request: PoolExecRequest,
    transport: &dyn PoolTransport,
) -> Result<Completion, SdkError> {
    let origin = std::time::Instant::now();
    execute_with_clock(utc0, base, request, transport, &|| origin)
}
// Real custody + identity-bound ledger, without carrying a connection across HTTP.
struct FixtureLedger<'a>(&'a Fixture);
impl FixtureLedger<'_> {
    fn reserve(
        &mut self,
        candidate: &ExecutionCandidate,
        hold: u64,
        now: i64,
    ) -> Result<ReserveResult, BudgetError> {
        let deadline = std::time::Instant::now() + REAL_WAIT_CAP;
        self.0
            .pool()
            .with_ledger_identity(deadline, |anchor, salt_id| {
                BudgetLedger::with_bound(self.0.base(), anchor, salt_id, |ledger| {
                    ledger.reserve(
                        candidate,
                        hold,
                        now,
                        now.checked_add(30).ok_or(BudgetError::Unavailable)?,
                    )
                })
            })
            .map_err(|_| BudgetError::Unavailable)?
    }
}
fn manifest() -> Value {
    json!({"schema_version":1,"revision":"pool-execution-synthetic",
        "models":[{"id":MODEL,"name":"Synthetic model","provider":"claude",
            "context_window":1000,"output_limit":100,"aliases":["fixture-alias"]}],
        "rates":[{"match_kind":"exact","patterns":[MODEL],"strip_context_hint":false,
            "evidence":"Synthetic test prices; never provider evidence",
            "epochs":[{"start_unix":null,"end_unix":null,"peak":null,"rate":{
                "input_per_1m_usd":1.0,"output_per_1m_usd":2.0,
                "cache_read_per_1m_usd":null,"cache_write_per_1m_usd":null}}]}]})
}
fn request() -> PoolExecRequest {
    PoolExecRequest {
        provider: "anthropic".into(),
        model: MODEL.into(),
        prompt: "x".into(),
        system: None,
        max_tokens: 10,
        max_input_bytes: 200_000,
        timeout_secs: 30,
    }
}
fn completion() -> Completion {
    Completion::new("synthetic answer", MODEL, "anthropic", FinishReason::Stop).with_usage(
        Usage::default()
            .with_input_tokens(1u64)
            .with_output_tokens(1u64),
    )
}
struct Transport<F>(F);
impl<F> PoolTransport for Transport<F>
where
    F: Fn(&PoolExecRequest, SecretString, Duration) -> Result<Completion, TransportError>,
{
    fn complete(
        &self,
        request: &PoolExecRequest,
        key: SecretString,
        remaining: Duration,
    ) -> Result<Completion, TransportError> {
        (self.0)(request, key, remaining)
    }
}
fn never() -> impl PoolTransport {
    Transport(
        |_: &PoolExecRequest, _: SecretString, _: Duration| -> Result<Completion, TransportError> {
            panic!("invalid or blocked request must not dispatch")
        },
    )
}
fn assert_code(error: SdkError, code: SdkErrorCode) {
    assert_eq!(error.code, code, "message={}", error.message.as_str());
    let wire = serde_json::to_string(&error).unwrap();
    assert!(!wire.contains("synthetic-"));
    assert!(!wire.contains("private-key-label"));
}

type RecordedFields = Vec<(String, String)>;
type RecordedEvents = Vec<RecordedFields>;
type WarningObserver = Arc<dyn Fn(&RecordedFields) + Send + Sync>;
#[derive(Clone, Default)]
struct RecordedWarnings(Arc<Mutex<RecordedEvents>>, Option<WarningObserver>);
impl tracing::Subscriber for RecordedWarnings {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() == tracing::Level::WARN
            || (*metadata.level() == tracing::Level::INFO
                && metadata.fields().field("event_kind").is_some())
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(Vec<(String, String)>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push((field.name().into(), format!("{value:?}")));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.push((field.name().into(), value.into()));
            }
        }
        let mut fields = Fields(Vec::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0.clone());
        if let Some(observer) = &self.1 {
            observer(&fields.0);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[derive(Clone, Default)]
struct CandidateAdmissionTraces(RecordedWarnings);
impl tracing::Subscriber for CandidateAdmissionTraces {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.fields().field("admission_branch").is_some()
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::Subscriber::new_span(&self.0, attrs)
    }
    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        tracing::Subscriber::record(&self.0, span, values);
    }
    fn record_follows_from(&self, span: &tracing::span::Id, follows: &tracing::span::Id) {
        tracing::Subscriber::record_follows_from(&self.0, span, follows);
    }
    fn event(&self, event: &tracing::Event<'_>) {
        tracing::Subscriber::event(&self.0, event);
        let events = self.0 .0.lock().unwrap();
        eprintln!(
            "POOL_CANDIDATE_TRACE {}",
            serde_json::to_string(events.last().unwrap()).unwrap()
        );
    }
    fn enter(&self, span: &tracing::span::Id) {
        tracing::Subscriber::enter(&self.0, span);
    }
    fn exit(&self, span: &tracing::span::Id) {
        tracing::Subscriber::exit(&self.0, span);
    }
}

#[derive(Debug)]
struct ReservationStallObservation {
    elapsed: Duration,
    reservation_deadline: i64,
    observed_unix: i64,
}
type ReservationStallProbe = Arc<Mutex<Vec<ReservationStallObservation>>>;
type VirtualStall = std::rc::Rc<dyn Fn()>;
thread_local! {
    static RESERVATION_STALL_PROBE: std::cell::RefCell<Option<ReservationStallProbe>> = const { std::cell::RefCell::new(None) };
    static VIRTUAL_RESERVATION_STALL: std::cell::RefCell<Option<VirtualStall>> = const { std::cell::RefCell::new(None) };
}
pub(super) fn before_reservation_probe(reservation_deadline: i64) {
    // A virtual stall advances only the injected clock; no real time passes.
    let virtual_stall = VIRTUAL_RESERVATION_STALL.with(|slot| slot.borrow().clone());
    if let Some(stall) = virtual_stall {
        stall();
    }
    let probe = RESERVATION_STALL_PROBE.with(|slot| slot.borrow().clone());
    if let Some(probe) = probe {
        let started = std::time::Instant::now();
        let utc_target = chrono::DateTime::<chrono::Utc>::from_timestamp(reservation_deadline, 0)
            .unwrap()
            + chrono::Duration::milliseconds(25);
        let until_utc = (utc_target - chrono::Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        // The requested fault is a real stalled admission, not a fake clock
        // advance. Cross both the one-second caller budget and rounded UTC
        // ledger deadline; the observation below validates that it happened.
        std::thread::sleep(until_utc.max(Duration::from_millis(1100)));
        let observation = ReservationStallObservation {
            elapsed: started.elapsed(),
            reservation_deadline,
            observed_unix: chrono::Utc::now().timestamp(),
        };
        eprintln!(
            "POOL_RESERVATION_STALL elapsed_ms={} minimum_ms=1100 utc_deadline_crossed={}",
            observation.elapsed.as_millis(),
            observation.observed_unix >= reservation_deadline
        );
        probe.lock().unwrap().push(observation);
    }
}

fn with_virtual_reservation_stall<T>(
    stall: impl Fn() + 'static,
    operation: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<VirtualStall>);
    impl Drop for Restore {
        fn drop(&mut self) {
            VIRTUAL_RESERVATION_STALL.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let stall: VirtualStall = std::rc::Rc::new(stall);
    let _restore = Restore(VIRTUAL_RESERVATION_STALL.with(|slot| slot.replace(Some(stall))));
    operation()
}

fn with_reservation_stall_probe<T>(
    probe: ReservationStallProbe,
    operation: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<ReservationStallProbe>);
    impl Drop for Restore {
        fn drop(&mut self) {
            RESERVATION_STALL_PROBE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(RESERVATION_STALL_PROBE.with(|slot| slot.replace(Some(probe))));
    operation()
}

// An injected clock has its own epoch. Keep it demonstrably separate from
// real time so a wall-clock comparison cannot silently pass these fixtures.
fn virtual_deadline_origin(timeout_secs: u64) -> std::time::Instant {
    std::time::Instant::now()
        .checked_sub(Duration::from_secs(timeout_secs.checked_add(1).unwrap()))
        .expect("virtual deadline fixture must support a distinct past epoch")
}

#[test]
fn custody_uses_injected_clock_after_a_real_stall_while_lock_is_held() {
    let f = Fixture::new();
    f.add("a", 1.0);
    let pool = f.pool();
    let origin = std::time::Instant::now();
    let deadline = origin + Duration::from_secs(1);
    let observed = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed_in_hook = std::rc::Rc::clone(&observed);
    let result = Pool::with_custody_phase_observer_for_test(
        move || {
            let started = std::time::Instant::now();
            std::thread::sleep(Duration::from_millis(1100));
            let elapsed = started.elapsed();
            observed_in_hook.borrow_mut().push(elapsed);
        },
        || {
            pool.execution_candidates_bound_with_clock(
                "anthropic",
                deadline,
                &PoolClock::new(&|| origin, &chrono::Utc::now),
            )
        },
    );
    let observed = observed.borrow();
    assert_eq!(
        observed.len(),
        1,
        "the held-custody phase probe must run once"
    );
    assert!(
        observed[0] > Duration::from_secs(1),
        "the custody probe must cross one real second"
    );
    assert!(std::time::Instant::now() >= deadline);
    assert_eq!(deadline.duration_since(origin), Duration::from_secs(1));
    let candidates =
        result.expect("custody must retain the injected one-second budget after a real stall");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].entry.name.as_str(), "a");
    assert!(!f.base().join("pool/execution-ledger.sqlite3").exists());
}

#[test]
fn custody_refuses_an_expired_injected_deadline_before_acquiring() {
    let f = Fixture::new();
    f.add("a", 1.0);
    let pool = f.pool();
    let origin = virtual_deadline_origin(1);
    let elapsed = std::cell::Cell::new(Duration::ZERO);
    let clock = || origin + elapsed.get();
    let deadline = origin + Duration::from_secs(1);
    assert_eq!(
        pool.execution_candidates_bound_with_clock(
            "anthropic",
            deadline,
            &PoolClock::new(&clock, &chrono::Utc::now),
        )
        .unwrap()
        .len(),
        1
    );
    elapsed.set(Duration::from_secs(1));
    let acquired = std::rc::Rc::new(std::cell::Cell::new(false));
    let acquired_in_hook = std::rc::Rc::clone(&acquired);
    let result = Pool::with_custody_phase_observer_for_test(
        move || acquired_in_hook.set(true),
        || {
            pool.execution_candidates_bound_with_clock(
                "anthropic",
                deadline,
                &PoolClock::new(&clock, &chrono::Utc::now),
            )
        },
    );
    assert!(matches!(result, Err(crate::pool::PoolError::Busy)));
    assert!(
        !acquired.get(),
        "an expired virtual deadline must refuse before custody acquisition"
    );
}

#[cfg(unix)]
#[test]
fn failed_unknown_annotation_emits_only_fixed_warning_and_preserves_original_hold() {
    let f = Fixture::new();
    f.add("private-key-label", HOLD as f64 / 1_000_000_000.0);
    let database = f.base().join("pool/execution-ledger.sqlite3");
    let retained = f.base().join("pool/retained-database.sqlite3");
    let transport = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
        std::fs::rename(&database, &retained).unwrap();
        Err(TransportError::Unknown)
    });
    let warnings = RecordedWarnings::default();
    let error =
        tracing::subscriber::with_default(warnings.clone(), || f.run(request(), &transport))
            .unwrap_err();
    assert_code(error, SdkErrorCode::Undetermined);
    let events = warnings.0.lock().unwrap();
    let event = events
        .iter()
        .find(|event| {
            event
                .iter()
                .any(|(name, value)| name == "error_kind" && value == "pool_retain_unknown_failed")
        })
        .expect("failed uncertainty annotation must emit its fixed diagnostic");
    assert_eq!(
        event,
        &vec![("error_kind".into(), "pool_retain_unknown_failed".into())]
    );
    drop(events);
    assert!(!database.exists());
    std::fs::rename(&retained, &database).unwrap();
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::InFlightBlocked
    ));
}

#[test]
fn successful_postdeadline_settlement_uses_cleanup_and_emits_no_failure_warning() {
    let f = Fixture::new();
    f.add("a", 0.002);
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let reservation = match f
        .ledger()
        .reserve(&candidate, HOLD, f.utc().timestamp())
        .unwrap()
    {
        ReserveResult::Held(reservation) => reservation,
        _ => panic!("fixture must reserve budget"),
    };
    let deadline = std::time::Instant::now();
    let warnings = RecordedWarnings::default();
    tracing::subscriber::with_default(warnings.clone(), || {
        super::cleanup_ledger(
            &f.pool(),
            f.base(),
            deadline,
            &PoolClock::new(&|| deadline, &chrono::Utc::now),
            |ledger| ledger.settle(&reservation, 3000),
        )
    })
    .unwrap();
    assert!(warnings.0.lock().unwrap().is_empty());
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1_997_000, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::InFlightBlocked
    ));
}

#[cfg(unix)]
#[test]
fn failed_postdeadline_settlement_warns_and_preserves_hold() {
    let f = Fixture::new();
    f.add("private-key-label", HOLD as f64 / 1_000_000_000.0);
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let reservation = match f
        .ledger()
        .reserve(&candidate, HOLD, f.utc().timestamp())
        .unwrap()
    {
        ReserveResult::Held(reservation) => reservation,
        _ => panic!("fixture must reserve budget"),
    };
    let database = f.base().join("pool/execution-ledger.sqlite3");
    let retained = f.base().join("pool/retained-after-deadline.sqlite3");
    let deadline = std::time::Instant::now();
    let warnings = RecordedWarnings::default();
    let result = tracing::subscriber::with_default(warnings.clone(), || {
        super::cleanup_ledger(
            &f.pool(),
            f.base(),
            deadline,
            &PoolClock::new(&|| deadline, &chrono::Utc::now),
            |ledger| {
                std::fs::rename(&database, &retained).unwrap();
                ledger.settle(&reservation, 3000)
            },
        )
    });
    assert!(result.is_err());
    assert_eq!(
        *warnings.0.lock().unwrap(),
        vec![vec![(
            "error_kind".into(),
            "pool_settle_after_deadline_failed".into()
        )]]
    );
    assert!(!database.exists());
    std::fs::rename(&retained, &database).unwrap();
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::InFlightBlocked
    ));
}

#[cfg(unix)]
#[test]
fn failed_postdeadline_retain_emits_both_fixed_warnings_and_preserves_hold() {
    let f = Fixture::new();
    f.add("private-key-label", HOLD as f64 / 1_000_000_000.0);
    let database = f.base().join("pool/execution-ledger.sqlite3");
    let retained = f.base().join("pool/retained-after-timeout.sqlite3");
    let origin = std::time::Instant::now();
    let elapsed = Mutex::new(Duration::ZERO);
    let clock = || origin + *elapsed.lock().unwrap();
    let transport = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
        std::fs::rename(&database, &retained).unwrap();
        *elapsed.lock().unwrap() = Duration::from_secs(3600);
        Err(TransportError::Unknown)
    });
    let warnings = RecordedWarnings::default();
    let mut r = request();
    r.timeout_secs = 3600;
    let error = tracing::subscriber::with_default(warnings.clone(), || {
        Pool::with_default_vault_for_test(f.vault.clone(), || {
            super::execute_with_clock(f.utc(), f.base(), r, &transport, &clock)
        })
    })
    .unwrap_err();
    assert_code(error, SdkErrorCode::Undetermined);
    let mut labels = warnings.0.lock().unwrap().clone();
    labels.sort();
    assert_eq!(
        labels,
        vec![
            vec![("error_kind".into(), "pool_retain_unknown_failed".into())],
            vec![(
                "error_kind".into(),
                "pool_settle_after_deadline_failed".into()
            )],
        ]
    );
    std::fs::rename(&retained, &database).unwrap();
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::InFlightBlocked
    ));
}

#[test]
fn resolve_known_oversized_or_overflow_actual_refuses_with_fixed_invariant_error() {
    for actual in [HOLD + 1, u64::MAX] {
        let f = Fixture::new();
        f.add("private-key-label", 1.0);
        let candidate = f
            .pool()
            .execution_candidates("anthropic")
            .unwrap()
            .remove(0);
        let reservation = match f
            .ledger()
            .reserve(&candidate, HOLD, f.utc().timestamp())
            .unwrap()
        {
            ReserveResult::Held(reservation) => reservation,
            _ => panic!("fixture must reserve budget"),
        };
        let result = f
            .pool()
            .with_ledger_identity(
                std::time::Instant::now() + REAL_WAIT_CAP,
                |anchor, salt_id| {
                    BudgetLedger::with_bound(f.base(), anchor, salt_id, |ledger| {
                        ledger.settle(&reservation, actual)
                    })
                },
            )
            .unwrap();
        assert!(matches!(result, Err(BudgetError::Undetermined)));
        let error = f.resolve("private-key-label").unwrap_err();
        assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
        assert_eq!(error.message.as_str(), "pool_resolve_invariant_violation");
        assert!(matches!(
            f.ledger()
                .reserve(&candidate, 1, f.utc().timestamp())
                .unwrap(),
            ReserveResult::Unresolved
        ));
    }
}

#[test]
fn valid_pool_request_preserves_completion_and_settles_actual_usage() {
    let f = Fixture::new();
    f.add("private-key-label", 0.002);
    let transport = Transport(
        |r: &PoolExecRequest, key: SecretString, remaining: Duration| {
            assert_eq!(r.model, MODEL);
            assert!(key.expose_secret() == "synthetic-private-key-label");
            assert!(remaining > Duration::ZERO && remaining <= Duration::from_secs(30));
            Ok(completion())
        },
    );
    let actual = f.run(request(), &transport).unwrap();
    assert_eq!(
        serde_json::to_value(actual).unwrap(),
        serde_json::to_value(completion()).unwrap()
    );
    // Trusted 1 input + 1 output costs 3000 nanos, so exactly this balance remains.
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let mut ledger = f.ledger();
    assert!(matches!(
        ledger
            .reserve(&candidate, 1_997_000, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        ledger.reserve(&candidate, 1, f.utc().timestamp()).unwrap(),
        ReserveResult::InFlightBlocked | ReserveResult::CapBlocked
    ));
}

#[test]
fn invalid_request_values_refuse_before_custody_or_reservation() {
    let f = Fixture::new();
    for case in 0..7 {
        let mut r = request();
        match case {
            0 => r.prompt.clear(),
            1 => r.max_tokens = 0,
            2 => r.max_tokens = 101,
            3 => r.timeout_secs = 0,
            4 => r.max_input_bytes = 0,
            5 => {
                r.prompt = "é".into();
                r.max_input_bytes = 1;
            }
            _ => {
                r.system = Some("ab".into());
                r.prompt = "cd".into();
                r.max_input_bytes = 3;
            }
        }
        assert_code(f.run(r, &never()).unwrap_err(), SdkErrorCode::InvalidInput);
    }
    assert!(!f.base().join("pool/execution-ledger.sqlite3").exists());
}

#[test]
fn already_expired_caller_deadline_refuses_before_custody_or_dispatch() {
    let f = Fixture::new();
    // With no configured pool, even a missing deadline guard cannot touch a key
    // or reach HTTP; it would instead return PoolUnavailable and create custody.
    let deadline = std::time::Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap();
    let error = super::execute_with_deadline(f.base(), request(), deadline).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::Timeout);
    assert_eq!(error.message.as_str(), "pool_deadline_exceeded");
    assert!(!f.base().join("pool").exists());
}

#[test]
fn caller_deadline_and_request_timeout_both_bound_the_transport_budget() {
    let _traces = tracing::subscriber::set_default(CandidateAdmissionTraces::default());
    let f = Fixture::new();
    f.add("a", 1.0);
    let origin = virtual_deadline_origin(60);
    for (caller_secs, expected_secs) in [(1, 1), (60, 30)] {
        let transport = Transport(
            |_: &PoolExecRequest, _: SecretString, remaining: Duration| {
                assert_eq!(remaining, Duration::from_secs(expected_secs));
                Ok(completion())
            },
        );
        Pool::with_default_vault_for_test(f.vault.clone(), || {
            super::execute_with_clock_and_deadline(
                f.utc(),
                f.base(),
                request(),
                &transport,
                &|| origin,
                Some(origin + Duration::from_secs(caller_secs)),
            )
        })
        .unwrap();
    }
}

#[test]
fn real_admission_stall_cannot_expire_an_injected_clock_budget() {
    // Load-independent reproduction of the fleet-load reds: the host stalls for
    // real wall time between admission and reservation while the injected clock
    // (the only clock tests drive) still reports a full one-second budget.
    let f = Fixture::new();
    f.add("a", 1.0);
    let origin = std::time::Instant::now();
    let observations = Arc::new(Mutex::new(Vec::new()));
    let calls = Mutex::new(0);
    let mut r = request();
    r.timeout_secs = 1;
    let result = with_reservation_stall_probe(observations.clone(), || {
        Pool::with_default_vault_for_test(f.vault.clone(), || {
            super::execute_with_clock(
                f.utc(),
                f.base(),
                r,
                &Transport(|_: &PoolExecRequest, _: SecretString, budget: Duration| {
                    *calls.lock().unwrap() += 1;
                    assert_eq!(budget, Duration::from_secs(1));
                    Ok(completion())
                }),
                &|| origin,
            )
        })
    });
    let observed = observations.lock().unwrap();
    assert_eq!(observed.len(), 1, "the stall probe must run exactly once");
    assert!(
        observed[0].elapsed > Duration::from_secs(1),
        "the injected stall must cross one real second"
    );
    assert!(
        observed[0].observed_unix >= observed[0].reservation_deadline,
        "the injected stall must cross the rounded ledger UTC deadline"
    );
    drop(observed);
    result.expect("a real stall must not expire a budget the injected clock still reports");
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn fixture_run_budget_is_not_consumed_by_real_elapsed_time() {
    // Every fixture-driven test must be load-independent: a real stall (here
    // 1.1 s against a 1 s budget) must not spend a budget the test clock holds.
    let f = Fixture::new();
    f.add("a", 1.0);
    let observations = Arc::new(Mutex::new(Vec::new()));
    let mut r = request();
    r.timeout_secs = 1;
    let result = with_reservation_stall_probe(observations.clone(), || {
        f.run(
            r,
            &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
        )
    });
    assert_eq!(observations.lock().unwrap().len(), 1);
    result.expect("a real stall must not expire the fixture's test-clock budget");
}

#[test]
fn fixture_cooldown_is_decided_by_the_test_clock_not_real_elapsed_time() {
    // A 1 second quota cooldown must still hold after 1.2 REAL seconds, because
    // both fixture runs share one frozen UTC. A per-run real UTC anchor would
    // let the cooldown lapse between the runs on any slow host.
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            if key.expose_secret() == "synthetic-a" {
                Err(TransportError::Quota {
                    retry_after_secs: 1,
                })
            } else {
                Ok(completion())
            }
        }),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    let seen = Mutex::new(Vec::new());
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            seen.lock().unwrap().push(key.expose_secret().to_owned());
            Ok(completion())
        }),
    )
    .unwrap();
    assert_eq!(*seen.lock().unwrap(), ["synthetic-b"]);
}

// The tests below go through the PUBLIC wrappers with PoolClock::system(). Every
// other test drives an injected clock, so without these nothing would notice the
// production clock wiring being swapped for another source.
/// Request budget for the public-wrapper tests that assert WIRING, never timing.
/// `request()` carries a 30 second real budget, which a host stalled for 30 real
/// seconds spends before the reservation (D2 sign-off: `pool_deadline_exceeded`).
/// These tests run on the real system clock on purpose, so their budget must be
/// one no host load can expire; the real waits they do make are bounded by
/// `REAL_WAIT_CAP`. Tests whose subject IS elapsed time set their own budget.
const WIRING_BUDGET_SECS: u64 = 86_400;
fn wiring_request() -> PoolExecRequest {
    let mut r = request();
    r.timeout_secs = WIRING_BUDGET_SECS;
    r
}
fn run_public(
    f: &Fixture,
    request: PoolExecRequest,
    transport: &dyn PoolTransport,
) -> Result<Completion, SdkError> {
    Pool::with_default_vault_for_test(f.vault.clone(), || {
        execute_with_transport(f.base(), request, transport)
    })
}

#[test]
fn system_pool_clock_readings_are_bracketed_by_the_real_clocks() {
    let (mono_before, utc_before) = (std::time::Instant::now(), chrono::Utc::now());
    let clock = PoolClock::system();
    let (mono, utc) = (clock.now(), clock.utc());
    let (mono_after, utc_after) = (std::time::Instant::now(), chrono::Utc::now());
    assert!(
        mono_before <= mono && mono <= mono_after,
        "the system monotonic reading must be the real Instant::now"
    );
    assert!(
        utc_before <= utc && utc <= utc_after,
        "the system UTC reading must be the real Utc::now"
    );
}

#[test]
fn public_execution_settles_and_cools_on_the_real_system_clock() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    let completion = run_public(
        &f,
        wiring_request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            if key.expose_secret() == "synthetic-a" {
                Err(TransportError::Quota {
                    retry_after_secs: 3600,
                })
            } else {
                Ok(completion())
            }
        }),
    )
    .expect("a quota rejection must rotate to the healthy key on the system clock");
    assert_eq!(completion.text, "synthetic answer");
    let a = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.entry.name.as_str() == "a")
        .unwrap();
    assert!(
        matches!(
            f.ledger()
                .reserve(&a, 1, chrono::Utc::now().timestamp())
                .unwrap(),
            ReserveResult::Cooling
        ),
        "a one hour cooldown recorded from the system UTC must still hold at the real now"
    );
}

#[test]
fn public_execution_never_completes_a_really_stalled_dispatch_past_its_deadline() {
    // Real time is the SUBJECT: the transport stalls 1.2 real seconds against a
    // 1 second budget. If a loaded host expires the budget before dispatch the
    // request is refused as a timeout instead; neither outcome is a completion.
    let f = Fixture::new();
    f.add("a", 1.0);
    let dispatched = Mutex::new(false);
    let mut r = request();
    r.timeout_secs = 1;
    let error = run_public(
        &f,
        r,
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
            *dispatched.lock().unwrap() = true;
            std::thread::sleep(Duration::from_millis(1200));
            Ok(completion())
        }),
    )
    .expect_err("a completion that arrives after the deadline must not be returned");
    if *dispatched.lock().unwrap() {
        assert_code(error, SdkErrorCode::Undetermined);
    } else {
        assert_code(error, SdkErrorCode::Timeout);
    }
}

#[test]
fn public_resolve_charges_unknown_holds_on_the_real_system_clock() {
    let f = Fixture::new();
    f.add("a", 0.002);
    assert_code(
        run_public(
            &f,
            wiring_request(),
            &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
                Err(TransportError::Unknown)
            }),
        )
        .unwrap_err(),
        SdkErrorCode::Undetermined,
    );
    Pool::with_default_vault_for_test(f.vault.clone(), || {
        super::resolve(f.base(), &PoolName::new("a").unwrap())
    })
    .unwrap();
    let error = run_public(&f, wiring_request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolExhausted);
    assert_eq!(error.message.as_str(), "pool_budget_cap_reached");
}

#[test]
fn public_resolve_settles_expired_holds_and_keeps_live_ones_by_the_real_utc() {
    // The assertions land AFTER the call under test: resolve decides each pending
    // hold from the UTC it is given, and the ledger row records that decision.
    let hold_state = |f: &Fixture| -> i64 {
        rusqlite::Connection::open(f.base().join("pool/execution-ledger.sqlite3"))
            .unwrap()
            .query_row("SELECT state FROM reservations", [], |row| row.get(0))
            .unwrap()
    };
    for (reserved_at_offset, expected_state, why) in [
        (
            -100_i64,
            1_i64,
            "a hold expired at the real now must be charged",
        ),
        (3000, 0, "a hold live at the real now must stay pending"),
    ] {
        let f = Fixture::new();
        f.add("a", 0.002);
        // Backdate key creation so a hold can be admitted in the past.
        let manifest_path = f.base().join("pool/manifest.json");
        let mut pool_manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let added = (chrono::Utc::now() - chrono::Duration::seconds(300)).to_rfc3339();
        for row in pool_manifest["entries"].as_array_mut().unwrap() {
            row["entry"]["added_at"] = json!(added);
        }
        std::fs::write(&manifest_path, serde_json::to_vec(&pool_manifest).unwrap()).unwrap();
        let candidate = f
            .pool()
            .execution_candidates("anthropic")
            .unwrap()
            .remove(0);
        assert!(matches!(
            f.ledger()
                .reserve(
                    &candidate,
                    1,
                    chrono::Utc::now().timestamp() + reserved_at_offset
                )
                .unwrap(),
            ReserveResult::Held(_)
        ));
        assert_eq!(hold_state(&f), 0, "the fixture hold must start pending");
        Pool::with_default_vault_for_test(f.vault.clone(), || {
            super::resolve(f.base(), &PoolName::new("a").unwrap())
        })
        .unwrap();
        assert_eq!(hold_state(&f), expected_state, "{why}");
    }
}

#[test]
fn public_rebaseline_clock_records_the_real_system_utc() {
    let f = Fixture::new();
    f.add("a", 1.0);
    run_public(
        &f,
        wiring_request(),
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .unwrap();
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    // Push the admission high-water mark an hour ahead so a rebaseline has work to do.
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, chrono::Utc::now().timestamp() + 3600)
            .unwrap(),
        ReserveResult::Held(_)
    ));
    let before = chrono::Utc::now().timestamp();
    Pool::with_default_vault_for_test(f.vault.clone(), || super::rebaseline_clock(f.base()))
        .unwrap();
    let after = chrono::Utc::now().timestamp();
    let recorded: i64 = rusqlite::Connection::open(f.base().join("pool/execution-ledger.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT max_admission FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        before <= recorded && recorded <= after,
        "rebaseline must record the system UTC, got {recorded} outside [{before}, {after}]"
    );
}

#[test]
fn stalled_admission_reports_deadline_exceeded_without_dispatch_or_hold() {
    let f = Fixture::new();
    f.add("a", 1.0);
    // Publish an empty active ledger before starting the short request budget.
    // No earlier request or hold is needed to make this boundary deterministic.
    f.pool()
        .with_ledger_identity(
            std::time::Instant::now() + REAL_WAIT_CAP,
            |anchor, salt_id| BudgetLedger::with_bound(f.base(), anchor, salt_id, |_| Ok(())),
        )
        .unwrap()
        .unwrap();
    let origin = virtual_deadline_origin(1);
    let elapsed = std::rc::Rc::new(std::cell::Cell::new(Duration::ZERO));
    let clock_elapsed = std::rc::Rc::clone(&elapsed);
    let clock = move || origin + clock_elapsed.get();
    let stalls = std::rc::Rc::new(std::cell::Cell::new(0));
    let counted = std::rc::Rc::clone(&stalls);
    let stalled = std::rc::Rc::clone(&elapsed);
    let calls = Mutex::new(0);
    let traces = CandidateAdmissionTraces::default();
    let result = tracing::subscriber::with_default(traces.clone(), || {
        // The stall advances only the injected clock, beyond the one-second
        // caller budget and the outward-rounded ledger UTC deadline.
        with_virtual_reservation_stall(
            move || {
                counted.set(counted.get() + 1);
                stalled.set(Duration::from_millis(2100));
            },
            || {
                Pool::with_default_vault_for_test(f.vault.clone(), || {
                    super::execute_with_clock_and_deadline(
                        f.utc(),
                        f.base(),
                        request(),
                        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
                            *calls.lock().unwrap() += 1;
                            Ok(completion())
                        }),
                        &clock,
                        Some(origin + Duration::from_secs(1)),
                    )
                })
            },
        )
    });
    assert_eq!(
        stalls.get(),
        1,
        "the stall must reach the reservation boundary, not an earlier custody timeout"
    );
    let error = result.unwrap_err();
    assert_eq!(
        error.message.as_str(),
        "pool_deadline_exceeded",
        "an expired admission deadline must not be reported as candidate unavailable"
    );
    assert_code(error, SdkErrorCode::Timeout);
    assert_eq!(
        *calls.lock().unwrap(),
        0,
        "an expired admission must never dispatch"
    );
    assert!(
        traces.0 .0.lock().unwrap().iter().any(|fields| fields
            .iter()
            .any(|(name, value)| name == "admission_branch" && value == "ledger_error")),
        "the stall must reproduce the ledger error path before request-level classification"
    );
    let ledger =
        rusqlite::Connection::open(f.base().join("pool/execution-ledger.sqlite3")).unwrap();
    let rows: i64 = ledger
        .query_row("SELECT count(*) FROM reservations", [], |row| row.get(0))
        .unwrap();
    let totals: i64 = ledger
        .query_row("SELECT count(*) FROM settled_totals", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        (rows, totals),
        (0, 0),
        "an expired admission must create neither spend nor holds"
    );
}

#[test]
fn unknown_provider_and_wrong_provider_model_do_not_fall_back_to_slots_or_environment() {
    let f = Fixture::new();
    f.add("a", 1.0);
    let mut r = request();
    r.provider = "unsupportedprovider".into();
    assert_code(
        f.run(r, &never()).unwrap_err(),
        SdkErrorCode::ProviderNotFound,
    );
    let mut r = request();
    r.provider = "openai".into();
    assert_code(f.run(r, &never()).unwrap_err(), SdkErrorCode::Unsupported);
    for model in ["unknown-model", "fixture-alias", "pool-fixture-model[1m]"] {
        let mut r = request();
        r.model = model.into();
        assert_code(f.run(r, &never()).unwrap_err(), SdkErrorCode::Unsupported);
    }
}

#[test]
fn absent_configuration_is_unavailable_and_does_not_dispatch() {
    let f = Fixture::new();
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
    assert_eq!(error.message.as_str(), "no_pool_configured");
}

#[test]
fn configured_empty_pool_is_exhausted_rather_than_unavailable() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.pool().remove("a").unwrap();
    assert_code(
        f.run(request(), &never()).unwrap_err(),
        SdkErrorCode::PoolExhausted,
    );
}

#[test]
fn unreadable_ledger_is_unavailable_without_dispatch_or_error_detail_leak() {
    let f = Fixture::new();
    f.add("private-key-label", 1.0);
    let path = f.base().join("pool/execution-ledger.sqlite3");
    // Born private through the production primitive: on Windows `secure_file`
    // is a documented no-op, so a plain write would leave a file with the
    // parent's inherited DACL. The corruption must be what makes this ledger
    // unavailable, never a broad ACL the platform refuses first.
    crate::platform::fs::write_new_private_synced(
        &path,
        b"synthetic-corrupt-ledger-private-key-label",
    )
    .unwrap();
    assert_code(
        f.run(request(), &never()).unwrap_err(),
        SdkErrorCode::PoolUnavailable,
    );
}

#[test]
fn tiny_prompt_still_requires_full_context_worst_case_hold() {
    let f = Fixture::new();
    // A byte-based input estimate fits; the mandatory full 1000-token context does not.
    f.add("private-key-label", 0.001019999);
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolExhausted);
    assert_eq!(error.message.as_str(), "pool_cap_below_worst_case_hold");
}

#[test]
fn uncapped_keys_are_ineligible_and_do_not_prevent_using_a_capped_key() {
    let f = Fixture::new();
    f.add_uncapped("a");
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolExhausted);
    assert_eq!(error.message.as_str(), "pool_key_has_no_cap");
    f.add("b", 1.0);
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-b");
            Ok(completion())
        }),
    )
    .unwrap();
}

#[test]
fn local_pre_dispatch_failure_releases_hold_and_does_not_rotate() {
    let f = Fixture::new();
    f.add("a", HOLD as f64 / 1_000_000_000.0);
    f.add("b", 1.0);
    let calls = Mutex::new(0);
    let error = f
        .run(
            request(),
            &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
                *calls.lock().unwrap() += 1;
                Err(TransportError::LocalFailure)
            }),
        )
        .unwrap_err();
    assert_code(error.clone(), SdkErrorCode::Internal);
    assert_eq!(error.message.as_str(), "pool_local_pre_dispatch_failed");
    assert_eq!(*calls.lock().unwrap(), 1);
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-a");
            Ok(completion())
        }),
    )
    .unwrap();
}

#[test]
fn deleting_an_anchored_ledger_refuses_without_dispatch_or_recreating_spend() {
    let f = Fixture::new();
    f.add("private-key-label", 1.0);
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .unwrap();
    let database = f.base().join("pool/execution-ledger.sqlite3");
    std::fs::remove_file(&database).unwrap();
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
    assert_eq!(error.message.as_str(), "pool_ledger_identity_mismatch");
    assert!(!database.exists());
}

#[test]
fn admission_clock_regression_is_unavailable_before_dispatch() {
    let f = Fixture::new();
    f.add("private-key-label", 1.0);
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let future = chrono::Utc::now().timestamp() + 3600;
    assert!(matches!(
        f.ledger().reserve(&candidate, 1, future).unwrap(),
        ReserveResult::Held(_)
    ));
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
    assert_eq!(error.message.as_str(), "pool_clock_regressed");
}

#[test]
fn resolve_current_name_charges_renamed_key_unknown_holds_at_full_bound() {
    let f = Fixture::new();
    f.add("a", 0.002);
    let unknown =
        Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Err(TransportError::Unknown));
    assert_code(
        f.run(request(), &unknown).unwrap_err(),
        SdkErrorCode::Undetermined,
    );
    f.pool().remove("a").unwrap();
    f.pool()
        .add(
            "renamed",
            "anthropic",
            SecretString::from("synthetic-a".to_owned()),
            None,
            Some(0.002),
        )
        .unwrap();
    f.resolve("renamed").unwrap();
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolExhausted);
    // The retained hold is now spent, not refunded or still unresolved/in flight.
    assert_eq!(error.message.as_str(), "pool_budget_cap_reached");
}

#[test]
fn committed_resolution_survives_mirror_publication_failure_and_retry_does_not_recharge() {
    let f = Fixture::new();
    f.add("a", HOLD as f64 / 1_000_000_000.0);
    let unknown =
        Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Err(TransportError::Unknown));
    assert_code(
        f.run(request(), &unknown).unwrap_err(),
        SdkErrorCode::Undetermined,
    );
    let fault = Pool::ledger_mirror_and_lag_record_failure_for_test();
    let warnings = RecordedWarnings::default();
    let result = tracing::subscriber::with_default(warnings.clone(), || f.resolve("a"));
    assert!(
        result.is_ok(),
        "a committed resolve must report success when only mirror publication fails"
    );
    assert!(
        warnings.0.lock().unwrap().iter().any(|event| event
            == &vec![(
                "error_kind".into(),
                "pool_accounting_mirror_unavailable".into()
            )]),
        "a committed resolve with failed publication must emit its fixed accounting warning"
    );
    let accounting = || {
        let ledger =
            rusqlite::Connection::open(f.base().join("pool/execution-ledger.sqlite3")).unwrap();
        let reservation: (i64, i64, i64) = ledger
            .query_row(
                "SELECT count(*),sum(actual),sum(state=1) FROM reservations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let uncertain: i64 = ledger
            .query_row("SELECT sum(uncertain) FROM generations", [], |row| {
                row.get(0)
            })
            .unwrap();
        (reservation, uncertain)
    };
    let settled = accounting();
    assert_eq!(
        settled,
        ((1, HOLD as i64, 1), 0),
        "the successful resolve must have charged its one uncertain hold exactly once"
    );
    tracing::subscriber::with_default(warnings.clone(), || f.resolve("a")).expect(
        "retrying a committed resolve during the same publication outage must report success",
    );
    assert_eq!(
        accounting(),
        settled,
        "retrying a committed resolve must not recharge or change reservation disposition"
    );
    // Resolve still commits a metadata transaction, so its ledger sequence may
    // advance; the retry is a no-op for spend and reservation disposition.
    drop(fault);
    let exhausted = f.run(request(), &never()).unwrap_err();
    assert_code(exhausted.clone(), SdkErrorCode::PoolExhausted);
    assert_eq!(exhausted.message.as_str(), "pool_budget_cap_reached");
}

#[test]
fn resolving_missing_current_name_returns_fixed_not_found() {
    let f = Fixture::new();
    f.add("a", 1.0);
    let error = f.resolve("private-key-label").unwrap_err();
    assert_code(error.clone(), SdkErrorCode::NotFound);
    assert_eq!(error.message.as_str(), "pool_key_not_found");
}

#[test]
fn hard_hold_includes_highest_applicable_cache_input_dimension() {
    let f = Fixture::new();
    f.add("a", 0.0015);
    let mut m = manifest();
    m["rates"][0]["epochs"][0]["rate"]["cache_write_per_1m_usd"] = json!(2.0);
    f.write_manifest(m);
    assert_code(
        f.run(request(), &never()).unwrap_err(),
        SdkErrorCode::PoolExhausted,
    );
}

#[test]
fn exact_full_context_hold_fits_and_settled_spend_prevents_another_admission() {
    let f = Fixture::new();
    f.add("a", HOLD as f64 / 1_000_000_000.0);
    let ok = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion()));
    f.run(request(), &ok).unwrap();
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolExhausted);
    assert_ne!(
        error.message.as_str(),
        "pool_budget_held_for_in_flight_worst_case"
    );
}

#[test]
fn pending_transport_holds_budget_across_independent_execution_invocations() {
    let f = Fixture::new();
    f.add("a", 0.0015);
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            f.run(
                request(),
                &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
                    entered_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(REAL_WAIT_CAP)
                        .unwrap();
                    Ok(completion())
                }),
            )
        });
        entered_rx.recv_timeout(REAL_WAIT_CAP).unwrap();
        // Reopen the ledger while the provider call is pending: the hold survives connections.
        let error = f.run(request(), &never()).unwrap_err();
        release_tx.send(()).unwrap();
        let first_result = first.join().unwrap();
        assert_code(error.clone(), SdkErrorCode::PoolExhausted);
        assert_eq!(
            error.message.as_str(),
            "pool_budget_held_for_in_flight_worst_case"
        );
        first_result.unwrap();
    });
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .unwrap();
}

#[test]
fn definite_quota_rejection_releases_hold_cools_key_and_attempts_next_once() {
    let f = Fixture::new();
    // Insert reverse order; execution order is ASCII by name, independent of manifest order.
    f.add("b", 1.0);
    f.add("a", 1.0);
    let seen = Mutex::new(Vec::new());
    let transport = Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
        let key = key.expose_secret().to_owned();
        seen.lock().unwrap().push(key.clone());
        if key == "synthetic-a" {
            Err(TransportError::Quota {
                retry_after_secs: 30,
            })
        } else {
            Ok(completion())
        }
    });
    f.run(request(), &transport).unwrap();
    f.run(request(), &transport).unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        ["synthetic-a", "synthetic-b", "synthetic-b"]
    );
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.entry.name.as_str() == "a")
        .unwrap();
    let mut ledger = f.ledger();
    assert!(matches!(
        ledger.reserve(&candidate, 1, f.utc().timestamp()).unwrap(),
        ReserveResult::Cooling
    ));
}

#[test]
fn unknown_dispatch_stops_this_invocation_and_later_requests_skip_unresolved_generation() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    let calls = Mutex::new(0);
    let transport = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
        *calls.lock().unwrap() += 1;
        Err(TransportError::Unknown)
    });
    assert_code(
        f.run(request(), &transport).unwrap_err(),
        SdkErrorCode::Undetermined,
    );
    assert_eq!(*calls.lock().unwrap(), 1);
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-b");
            Ok(completion())
        }),
    )
    .unwrap();
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Unresolved
    ));
}

#[test]
fn all_unresolved_generations_are_exhausted_without_dispatch() {
    let f = Fixture::new();
    f.add("a", 1.0);
    let unknown =
        Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Err(TransportError::Unknown));
    assert_code(
        f.run(request(), &unknown).unwrap_err(),
        SdkErrorCode::Undetermined,
    );
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolExhausted);
    assert_eq!(error.message.as_str(), "pool_generation_outcome_unresolved");
}

#[test]
fn expired_pending_generation_is_skipped_while_its_hold_remains() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    // A crashed request must have been admitted after its key existed. Backdate
    // only this isolated fixture's admission metadata before selecting a key.
    let manifest_path = f.base().join("pool/manifest.json");
    let mut pool_manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let added = (chrono::Utc::now() - chrono::Duration::seconds(120)).to_rfc3339();
    for row in pool_manifest["entries"].as_array_mut().unwrap() {
        row["entry"]["added_at"] = json!(added);
    }
    std::fs::write(&manifest_path, serde_json::to_vec(&pool_manifest).unwrap()).unwrap();
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let now = f.utc().timestamp();
    let reservation = f
        .pool()
        .with_ledger_identity(
            std::time::Instant::now() + REAL_WAIT_CAP,
            |anchor, salt_id| {
                BudgetLedger::with_bound(f.base(), anchor, salt_id, |ledger| {
                    ledger.reserve(&candidate, HOLD, now - 60, now - 30)
                })
            },
        )
        .unwrap()
        .unwrap();
    assert!(matches!(reservation, ReserveResult::Held(_)));
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-b");
            Ok(completion())
        }),
    )
    .unwrap();
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Unresolved
    ));
}

#[test]
fn missing_or_inconsistent_accounting_retains_unknown_hold_without_fallback() {
    for case in 0..6 {
        let f = Fixture::new();
        f.add("a", 1.0);
        f.add("b", 1.0);
        let transport = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
            let mut c = completion();
            match case {
                0 => c.model = "unexpected-model".into(),
                1 => c.provider = "openai".into(),
                2 => c.usage = None,
                3 => c.usage = Some(Usage::default().with_input_tokens(1u64)),
                4 => {
                    c.usage = Some(
                        Usage::default()
                            .with_input_tokens(1u64)
                            .with_output_tokens(11u64),
                    )
                }
                _ => {
                    c.usage = Some(
                        Usage::default()
                            .with_input_tokens(1u64)
                            .with_output_tokens(1u64)
                            .with_cache_creation_input_tokens(1u64),
                    )
                }
            }
            Ok(c)
        });
        assert_code(
            f.run(request(), &transport).unwrap_err(),
            SdkErrorCode::Undetermined,
        );
        f.run(
            request(),
            &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
                assert!(key.expose_secret() == "synthetic-b");
                Ok(completion())
            }),
        )
        .unwrap();
    }
}

#[test]
fn missing_bounds_or_prices_refuse_admission_without_invented_fallbacks() {
    for case in 0..3 {
        let f = Fixture::new();
        f.add("a", 1.0);
        let mut m = manifest();
        match case {
            0 => m["models"][0]["context_window"] = Value::Null,
            1 => m["models"][0]["output_limit"] = Value::Null,
            _ => m["rates"][0]["patterns"] = json!(["some-other-model"]),
        }
        f.write_manifest(m);
        assert_code(
            f.run(request(), &never()).unwrap_err(),
            SdkErrorCode::Unsupported,
        );
        assert!(!f.base().join("pool/execution-ledger.sqlite3").exists());
    }
}

#[test]
fn pricing_coverage_gap_refuses_before_custody() {
    let f = Fixture::new();
    let mut m = manifest();
    let gap_start = chrono::Utc::now().timestamp() + 3600;
    m["rates"][0]["epochs"][0]["end_unix"] = json!(gap_start);
    let mut future = m["rates"][0]["epochs"][0].clone();
    future["start_unix"] = json!(gap_start + 1800);
    future["end_unix"] = Value::Null;
    m["rates"][0]["epochs"].as_array_mut().unwrap().push(future);
    f.write_manifest(m);
    let mut r = request();
    r.timeout_secs = 7200;
    assert_code(f.run(r, &never()).unwrap_err(), SdkErrorCode::Unsupported);
    assert!(!f.base().join("pool").exists());
}

#[test]
fn prices_outside_request_deadline_do_not_block_admission() {
    for peak in [false, true] {
        let f = Fixture::new();
        f.add("a", 0.0015);
        let mut m = manifest();
        if peak {
            // This weekly peak is several days away, outside the 30-second deadline.
            let mut prices = m["rates"][0]["epochs"][0]["rate"].clone();
            prices["input_per_1m_usd"] = json!(2.0);
            let weekday = chrono::Datelike::weekday(&chrono::Utc::now()).number_from_monday();
            let distant_weekday = (weekday + 2) % 7 + 1;
            m["rates"][0]["epochs"][0]["peak"] = json!({
                "weekdays":[distant_weekday],"windows_utc":[[0,1440]],"rate":prices});
        } else {
            // Far-future literal intentionally outlives the codebase (year 2100).
            m["rates"][0]["epochs"][0]["end_unix"] = json!(4_102_444_800i64);
            let mut future = m["rates"][0]["epochs"][0].clone();
            future["start_unix"] = json!(4_102_444_800i64);
            future["end_unix"] = Value::Null;
            future["rate"]["input_per_1m_usd"] = json!(2.0);
            m["rates"][0]["epochs"].as_array_mut().unwrap().push(future);
        }
        f.write_manifest(m);
        f.run(
            request(),
            &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
        )
        .unwrap();
        let candidate = f
            .pool()
            .execution_candidates("anthropic")
            .unwrap()
            .remove(0);
        let mut ledger = f.ledger();
        assert!(matches!(
            ledger
                .reserve(&candidate, 1_497_000, f.utc().timestamp())
                .unwrap(),
            ReserveResult::Held(_)
        ));
        assert!(matches!(
            ledger.reserve(&candidate, 1, f.utc().timestamp()).unwrap(),
            ReserveResult::InFlightBlocked | ReserveResult::CapBlocked
        ));
    }
}

#[test]
fn settlement_uses_same_worst_deadline_interval_prices_as_admission() {
    let f = Fixture::new();
    f.add("a", 0.003);
    let mut m = manifest();
    // Computed relative fixture: the cutover lies within this request's two-hour
    // budget, while the synthetic transport completes at the lower current price.
    let cutover = chrono::Utc::now().timestamp() + 3600;
    m["rates"][0]["epochs"][0]["end_unix"] = json!(cutover);
    let mut future = m["rates"][0]["epochs"][0].clone();
    future["start_unix"] = json!(cutover);
    future["end_unix"] = Value::Null;
    future["rate"]["input_per_1m_usd"] = json!(2.0);
    m["rates"][0]["epochs"].as_array_mut().unwrap().push(future);
    f.write_manifest(m);
    let mut r = request();
    r.timeout_secs = 7200;
    f.run(
        r,
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .unwrap();
    // One input at interval-max $2/M + one output at $2/M = 4000 nanos.
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let mut ledger = f.ledger();
    assert!(matches!(
        ledger
            .reserve(&candidate, 2_996_000, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        ledger.reserve(&candidate, 1, f.utc().timestamp()).unwrap(),
        ReserveResult::InFlightBlocked | ReserveResult::CapBlocked
    ));
}

#[test]
fn request_keeps_one_price_snapshot_even_if_manifest_changes_during_dispatch() {
    let f = Fixture::new();
    f.add("a", 0.002);
    let transport = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
        let mut changed = manifest();
        changed["rates"][0]["epochs"][0]["rate"]["input_per_1m_usd"] = json!(1000.0);
        f.write_manifest(changed);
        Ok(completion())
    });
    f.run(request(), &transport).unwrap();
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let mut ledger = f.ledger();
    assert!(matches!(
        ledger
            .reserve(&candidate, 1_997_000, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Held(_)
    ));
}

#[test]
fn changed_candidate_snapshot_is_refused_before_dispatching_replacement_generation() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    let calls = Mutex::new(0);
    let transport = Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
        *calls.lock().unwrap() += 1;
        assert!(key.expose_secret() == "synthetic-a");
        f.pool().remove("b").unwrap();
        f.add("b", 1.0);
        Err(TransportError::Quota {
            retry_after_secs: 30,
        })
    });
    // The replacement belongs to a later invocation, not this invocation's snapshot.
    assert!(f.run(request(), &transport).is_err());
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn quota_rotation_uses_one_overall_monotonic_deadline() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    let origin = virtual_deadline_origin(1);
    let elapsed = Mutex::new(Duration::ZERO);
    let clock = || origin + *elapsed.lock().unwrap();
    let remaining = Mutex::new(Vec::new());
    let transport = Transport(|_: &PoolExecRequest, key: SecretString, budget: Duration| {
        remaining.lock().unwrap().push(budget);
        if key.expose_secret() == "synthetic-a" {
            *elapsed.lock().unwrap() = Duration::from_millis(20);
            Err(TransportError::Quota {
                retry_after_secs: 30,
            })
        } else {
            Ok(completion())
        }
    });
    let mut r = request();
    r.timeout_secs = 1;
    Pool::with_default_vault_for_test(f.vault.clone(), || {
        super::execute_with_clock(f.utc(), f.base(), r, &transport, &clock)
    })
    .expect("quota rotation must preserve one injected deadline across both dispatches");
    let remaining = remaining.lock().unwrap();
    assert_eq!(remaining.len(), 2);
    assert_eq!(
        *remaining,
        [Duration::from_secs(1), Duration::from_millis(980)]
    );
}

#[test]
fn deadline_after_definite_quota_releases_without_poisoning_or_next_dispatch() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    let origin = virtual_deadline_origin(1);
    let elapsed = Mutex::new(Duration::ZERO);
    let clock = || origin + *elapsed.lock().unwrap();
    let transport = Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
        assert!(key.expose_secret() == "synthetic-a");
        *elapsed.lock().unwrap() = Duration::from_secs(1);
        Err(TransportError::Quota {
            retry_after_secs: 30,
        })
    });
    let mut r = request();
    r.timeout_secs = 1;
    let error = Pool::with_default_vault_for_test(f.vault.clone(), || {
        super::execute_with_clock(f.utc(), f.base(), r, &transport, &clock)
    })
    .unwrap_err();
    assert_code(error.clone(), SdkErrorCode::Timeout);
    assert_eq!(error.message.as_str(), "pool_deadline_exceeded");
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Cooling
    ));
}

#[test]
fn completion_after_deadline_retains_hold_and_later_requests_skip_that_generation() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    let origin = virtual_deadline_origin(1);
    let elapsed = Mutex::new(Duration::ZERO);
    let clock = || origin + *elapsed.lock().unwrap();
    let transport = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
        *elapsed.lock().unwrap() = Duration::from_secs(1);
        Ok(completion())
    });
    let mut r = request();
    r.timeout_secs = 1;
    let warnings = RecordedWarnings::default();
    let result = tracing::subscriber::with_default(warnings.clone(), || {
        Pool::with_default_vault_for_test(f.vault.clone(), || {
            super::execute_with_clock(f.utc(), f.base(), r, &transport, &clock)
        })
    });
    assert_code(result.unwrap_err(), SdkErrorCode::Undetermined);
    assert!(warnings.0.lock().unwrap().is_empty());
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-b");
            Ok(completion())
        }),
    )
    .unwrap();
}

#[test]
fn provider_specific_cache_accounting_preserves_raw_usage_and_settles_exact_charge() {
    for openai in [false, true] {
        let f = Fixture::new();
        let provider = if openai { "openai" } else { "anthropic" };
        f.add_for("a", provider, 0.002);
        let mut m = manifest();
        m["models"][0]["provider"] = json!(if openai { "codex" } else { "claude" });
        let prices = &mut m["rates"][0]["epochs"][0]["rate"];
        prices["cache_read_per_1m_usd"] = json!(0.5);
        prices["cache_write_per_1m_usd"] = json!(1.25);
        f.write_manifest(m);
        let usage = Usage::default()
            .with_input_tokens(11u64)
            .with_output_tokens(1u64)
            .with_cache_read_input_tokens(3u64)
            .with_cache_creation_input_tokens(if openai { 0u64 } else { 2u64 });
        let expected =
            Completion::new("answer", MODEL, provider, FinishReason::Stop).with_usage(usage);
        let transport =
            Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(expected.clone()));
        let mut r = request();
        r.provider = provider.into();
        let actual = f.run(r, &transport).unwrap();
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        // OpenAI: (11-3)*1000 + 3*500 + 1*2000 = 11500 nanos.
        // Anthropic: 11*1000 + 3*500 + 2*1250 + 1*2000 = 17000 nanos.
        let charge = if openai { 11_500 } else { 17_000 };
        let candidate = f.pool().execution_candidates(provider).unwrap().remove(0);
        let mut ledger = f.ledger();
        assert!(matches!(
            ledger
                .reserve(&candidate, 2_000_000 - charge, f.utc().timestamp())
                .unwrap(),
            ReserveResult::Held(_)
        ));
        assert!(matches!(
            ledger.reserve(&candidate, 1, f.utc().timestamp()).unwrap(),
            ReserveResult::InFlightBlocked | ReserveResult::CapBlocked
        ));
    }
}

#[test]
fn rotated_env_key_executes_twice_with_fresh_generation() {
    let f = Fixture::new();
    let env = f.base().join("execution-fixture.env");
    crate::platform::fs::write_new_private_synced(&env, b"a=synthetic-env-original\n").unwrap();
    f.pool()
        .add_env_file(&env, &["a".into()], "anthropic", None, Some(1.0))
        .unwrap();
    f.add("b", 1.0);
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-env-original");
            Ok(completion())
        }),
    )
    .unwrap();
    let selected = f
        .pool()
        .execution_candidates_bound("anthropic", std::time::Instant::now() + REAL_WAIT_CAP)
        .unwrap()
        .remove(0);
    std::fs::write(&env, "a=synthetic-env-rotated\n").unwrap();
    assert!(matches!(
        f.pool().with_execution_key_bound(
            &selected,
            std::time::Instant::now() + REAL_WAIT_CAP,
            |_, _, _| { panic!("stale selected env generation must not reserve or dispatch") }
        ),
        Err(crate::pool::PoolError::MutationRefused)
    ));
    for _ in 0..2 {
        f.run(
            request(),
            &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
                assert!(key.expose_secret() == "synthetic-env-rotated");
                Ok(completion())
            }),
        )
        .unwrap();
    }
    std::fs::write(&env, "# key a deliberately absent\n").unwrap();
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-b");
            Ok(completion())
        }),
    )
    .unwrap();
}

#[test]
fn candidate_local_reservation_failure_does_not_block_healthy_next_key() {
    let f = Fixture::new();
    f.add("a", 1.0);
    f.add("b", 1.0);
    let mut old = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    // Seed the generation/fingerprint mismatch produced by the old env-rotation
    // writer through the real ledger API, without modifying a database schema.
    old.fingerprint = "c".repeat(64);
    assert!(matches!(
        f.ledger().reserve(&old, 1, f.utc().timestamp()).unwrap(),
        ReserveResult::Held(_)
    ));
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-b");
            Ok(completion())
        }),
    )
    .unwrap();
}

#[test]
fn missing_unrelated_env_key_does_not_block_native_execution() {
    let f = Fixture::new();
    f.add("a", 1.0);
    let env = f.base().join("unrelated-fixture.env");
    crate::platform::fs::write_new_private_synced(&env, b"unrelated=synthetic-unrelated\n")
        .unwrap();
    f.pool()
        .add_env_file(&env, &["unrelated".into()], "openai", None, Some(1.0))
        .unwrap();
    std::fs::remove_file(&env).unwrap();
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-a");
            Ok(completion())
        }),
    )
    .unwrap();
}

#[test]
fn predispatch_deadline_after_durable_reservation_releases_without_charge() {
    let f = Fixture::new();
    f.add("a", HOLD as f64 / 1_000_000_000.0);
    let origin = virtual_deadline_origin(3600);
    let observed_publication = std::cell::Cell::new(false);
    // Observe the actual durable publication boundary, not a clock-call count.
    let clock = || {
        let bytes = std::fs::read(f.base().join("pool/manifest.json")).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        if value["ledger_identity"]["sequence"]
            .as_u64()
            .is_some_and(|sequence| sequence > 0)
        {
            observed_publication.set(true);
            origin + Duration::from_secs(3600)
        } else {
            origin
        }
    };
    let mut r = request();
    r.timeout_secs = 3600;
    let error = Pool::with_default_vault_for_test(f.vault.clone(), || {
        super::execute_with_clock(f.utc(), f.base(), r, &never(), &clock)
    })
    .unwrap_err();
    assert!(
        observed_publication.get(),
        "predispatch expiry must observe a durable reservation before refusing dispatch"
    );
    assert_code(error, SdkErrorCode::Timeout);
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .expect("definitely unsent reservation must be fully released");
}

#[test]
fn definite_authentication_after_deadline_releases_and_preserves_provider_error() {
    let f = Fixture::new();
    f.add("a", HOLD as f64 / 1_000_000_000.0);
    let origin = virtual_deadline_origin(3600);
    let elapsed = Mutex::new(Duration::ZERO);
    let clock = || origin + *elapsed.lock().unwrap();
    let transport = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
        *elapsed.lock().unwrap() = Duration::from_secs(3600);
        Err(TransportError::Authentication)
    });
    let mut r = request();
    r.timeout_secs = 3600;
    let error = Pool::with_default_vault_for_test(f.vault.clone(), || {
        super::execute_with_clock(f.utc(), f.base(), r, &transport, &clock)
    })
    .unwrap_err();
    assert_code(error.clone(), SdkErrorCode::ProviderError);
    assert_eq!(error.message.as_str(), "pool_authentication_failed");
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .expect("definitely nonbilled authentication refusal must not poison budget");
}

#[test]
fn definite_outcome_survives_a_concurrent_full_hold_resolution() {
    for quota in [false, true] {
        let f = Fixture::new();
        f.add("a", 1.0);
        f.add("b", 1.0);
        let transport = Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            if key.expose_secret() == "synthetic-b" {
                return Ok(completion());
            }
            let count = f
                .pool()
                .with_resolution_identity(
                    &PoolName::new("a").unwrap(),
                    std::time::Instant::now() + REAL_WAIT_CAP,
                    |fingerprint, generation, anchor, salt_id| {
                        BudgetLedger::with_bound(f.base(), anchor, salt_id, |ledger| {
                            ledger.resolve(fingerprint, generation, f.utc().timestamp() + 60)
                        })
                    },
                )
                .unwrap()
                .unwrap();
            assert_eq!(count, 1);
            if quota {
                Err(TransportError::Quota {
                    retry_after_secs: 30,
                })
            } else {
                Err(TransportError::Authentication)
            }
        });
        let result = f.run(request(), &transport);
        if quota {
            result.expect("already recorded definite quota must still reach healthy b");
        } else {
            let error = result.unwrap_err();
            assert_code(error.clone(), SdkErrorCode::ProviderError);
            assert_eq!(error.message.as_str(), "pool_authentication_failed");
        }
    }
}

#[test]
fn rebaseline_clock_preserves_held_budget_and_emits_fixed_audit() {
    let f = Fixture::new();
    f.pool()
        .add(
            "a",
            "anthropic",
            SecretString::from("synthetic-a".to_owned()),
            Some(crate::pool::Reset::Date {
                date: "2100-01-01".into(),
            }),
            Some(HOLD as f64 / 1_000_000_000.0),
        )
        .unwrap();
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let future = chrono::Utc::now().timestamp() + 3600;
    assert!(matches!(
        f.ledger().reserve(&candidate, HOLD, future).unwrap(),
        ReserveResult::Held(_)
    ));
    let events = RecordedWarnings::default();
    tracing::subscriber::with_default(events.clone(), || {
        Pool::with_default_vault_for_test(f.vault.clone(), || {
            with_frozen_clock(f.utc(), |clock| {
                super::rebaseline_clock_with_clock(f.base(), clock)
            })
        })
    })
    .unwrap();
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![vec![("event_kind".into(), "pool_clock_rebaselined".into())]]
    );
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::InFlightBlocked
    ));
}

#[test]
fn old_generation_oversized_history_does_not_block_current_generation_resolution() {
    let f = Fixture::new();
    f.add("a", 1.0);
    let old = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let reservation = match f.ledger().reserve(&old, HOLD, f.utc().timestamp()).unwrap() {
        ReserveResult::Held(reservation) => reservation,
        _ => panic!("fixture must reserve budget"),
    };
    let settled = f
        .pool()
        .with_ledger_identity(
            std::time::Instant::now() + REAL_WAIT_CAP,
            |anchor, salt_id| {
                BudgetLedger::with_bound(f.base(), anchor, salt_id, |ledger| {
                    ledger.settle(&reservation, HOLD + 1)
                })
            },
        )
        .unwrap();
    assert!(matches!(settled, Err(BudgetError::Undetermined)));
    f.pool().remove("a").unwrap();
    f.pool()
        .add(
            "current",
            "anthropic",
            SecretString::from("synthetic-a".to_owned()),
            None,
            Some(1.0),
        )
        .unwrap();
    assert_code(
        f.run(
            request(),
            &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
                Err(TransportError::Unknown)
            }),
        )
        .unwrap_err(),
        SdkErrorCode::Undetermined,
    );
    f.resolve("current")
        .expect("historical oversized generation must not disable current resolution");
    let current = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    assert!(matches!(
        f.ledger()
            .reserve(&current, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        f.ledger().reserve(&old, 1, f.utc().timestamp()).unwrap(),
        ReserveResult::Unresolved
    ));
}

#[test]
fn selected_env_failure_skips_to_healthy_key_or_reports_candidate_unavailable() {
    for healthy in [false, true] {
        let f = Fixture::new();
        let env = f.base().join("malformed-fixture.env");
        crate::platform::fs::write_new_private_synced(&env, b"a=synthetic-selected-env\n").unwrap();
        f.pool()
            .add_env_file(&env, &["a".into()], "anthropic", None, Some(1.0))
            .unwrap();
        if healthy {
            f.add("b", 1.0);
        }
        std::fs::write(&env, [0xff]).unwrap();
        if healthy {
            f.run(
                request(),
                &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
                    assert!(key.expose_secret() == "synthetic-b");
                    Ok(completion())
                }),
            )
            .expect("a malformed selected env row must not block healthy b");
        } else {
            let error = f.run(request(), &never()).unwrap_err();
            assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
            assert_eq!(error.message.as_str(), "pool_candidate_unavailable");
        }
    }
}

#[test]
fn custody_mirror_and_unrelated_failures_have_distinct_fixed_messages() {
    for (error, message) in [
        (
            crate::pool::PoolError::LedgerMirrorUnavailable,
            "pool_ledger_mirror_unavailable",
        ),
        (
            crate::pool::PoolError::UnrelatedKeyUnavailable,
            "pool_unrelated_key_unavailable",
        ),
        (
            crate::pool::PoolError::ManifestWriteUnavailable,
            "pool_custody_unavailable",
        ),
    ] {
        let result = super::custody_error(error);
        assert_code(result.clone(), SdkErrorCode::PoolUnavailable);
        assert_eq!(result.message.as_str(), message);
    }
}

#[test]
fn mixed_unreadable_and_settled_cap_reports_proven_cap_exhaustion() {
    let f = Fixture::new();
    let env = f.base().join("mixed-eligibility.env");
    crate::platform::fs::write_new_private_synced(&env, b"a=synthetic-unreadable\n").unwrap();
    f.pool()
        .add_env_file(&env, &["a".into()], "anthropic", None, Some(1.0))
        .unwrap();
    f.add("b", HOLD as f64 / 1_000_000_000.0);
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.entry.name.as_str() == "b")
        .unwrap();
    let reservation = match f
        .ledger()
        .reserve(&candidate, HOLD, f.utc().timestamp())
        .unwrap()
    {
        ReserveResult::Held(reservation) => reservation,
        _ => panic!("fixture must reserve full cap"),
    };
    f.pool()
        .with_ledger_identity(
            std::time::Instant::now() + REAL_WAIT_CAP,
            |anchor, salt_id| {
                BudgetLedger::with_bound(f.base(), anchor, salt_id, |ledger| {
                    ledger.settle(&reservation, HOLD)
                })
            },
        )
        .unwrap()
        .unwrap();
    std::fs::write(&env, [0xff]).unwrap();
    let error = f.run(request(), &never()).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolExhausted);
    assert_eq!(error.message.as_str(), "pool_budget_cap_reached");
}

#[test]
fn first_execution_after_env_rotation_resnapshots_once_and_serves_new_generation() {
    let f = Fixture::new();
    let env = f.base().join("one-shot-rotation.env");
    crate::platform::fs::write_new_private_synced(&env, b"a=synthetic-initial\n").unwrap();
    f.pool()
        .add_env_file(&env, &["a".into()], "anthropic", None, Some(1.0))
        .unwrap();
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .unwrap();
    std::fs::write(&env, "a=synthetic-first-rotation\n").unwrap();
    let calls = Mutex::new(0);
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            *calls.lock().unwrap() += 1;
            assert!(key.expose_secret() == "synthetic-first-rotation");
            Ok(completion())
        }),
    )
    .expect("first execution after a rotation must use the newly minted generation");
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn repeated_env_rotation_is_bounded_and_keeps_other_healthy_keys_reachable() {
    let f = Fixture::new();
    let env = f.base().join("repeated-rotation.env");
    crate::platform::fs::write_new_private_synced(&env, b"a=synthetic-initial\n").unwrap();
    f.pool()
        .add_env_file(&env, &["a".into()], "anthropic", None, Some(1.0))
        .unwrap();
    f.add("b", 1.0);
    let original = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0)
        .generation;
    std::fs::write(&env, "a=synthetic-rotation-one\n").unwrap();
    let rotated_again = Mutex::new(false);
    let origin = std::time::Instant::now();
    let clock = || {
        let bytes = std::fs::read(f.base().join("pool/manifest.json")).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let generation = value["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["entry"]["name"] == "a")
            .unwrap()["generation"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut repeated = rotated_again.lock().unwrap();
        if generation != original && !*repeated {
            std::fs::write(&env, "a=synthetic-rotation-two\n").unwrap();
            *repeated = true;
        }
        origin
    };
    let calls = Mutex::new(0);
    Pool::with_default_vault_for_test(f.vault.clone(), || {
        super::execute_with_clock(
            f.utc(),
            f.base(),
            request(),
            &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
                *calls.lock().unwrap() += 1;
                assert!(key.expose_secret() == "synthetic-b");
                Ok(completion())
            }),
            &clock,
        )
    })
    .expect("a second rotation must stop refreshing that row and permit healthy b");
    assert!(*rotated_again.lock().unwrap());
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn active_mirror_lag_preserves_execution_and_next_open_keeps_actual_spend() {
    let f = Fixture::new();
    f.add("private-key-label", 0.0025);
    let ok = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion()));
    f.run(request(), &ok).unwrap();
    let events = RecordedWarnings::default();
    tracing::subscriber::with_default(events.clone(), || {
        Pool::with_ledger_mirror_failure_for_test(|| f.run(request(), &ok))
    })
    .expect("an active mirror write failure must not orphan a committed admission");
    let events = events.0.lock().unwrap();
    assert!(
        !events.is_empty(),
        "mirror failure injection must be observed"
    );
    assert!(events.iter().all(|event| event == &vec![("error_kind".into(),
        "pool_ledger_mirror_lagging".into())]), "mirror lag must emit fixed fields only");
    drop(events);
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 2_494_000, f.utc().timestamp())
            .unwrap(),
        ReserveResult::Held(_)
    ));
    assert!(matches!(
        f.ledger()
            .reserve(&candidate, 1, f.utc().timestamp())
            .unwrap(),
        ReserveResult::InFlightBlocked
    ));
}

#[test]
fn pending_initial_mirror_failure_never_dispatches_and_releases_unsent_hold() {
    let f = Fixture::new();
    f.add("private-key-label", HOLD as f64 / 1_000_000_000.0);
    let error =
        Pool::with_ledger_mirror_failure_for_test(|| f.run(request(), &never())).unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
    assert_eq!(error.message.as_str(), "pool_ledger_finalization_pending");
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .expect("next open must finalize and reuse the definitely unsent full hold");
}

#[test]
fn failed_unsent_hold_release_emits_only_its_fixed_warning_and_retains_the_hold() {
    let f = Fixture::new();
    f.add("private-key-label", HOLD as f64 / 1_000_000_000.0);
    let candidate = f
        .pool()
        .execution_candidates("anthropic")
        .unwrap()
        .remove(0);
    let reservation = match f
        .ledger()
        .reserve(&candidate, HOLD, f.utc().timestamp())
        .unwrap()
    {
        ReserveResult::Held(reservation) => reservation,
        _ => panic!("fixture must reserve the full hold"),
    };
    let database = f.base().join("pool/execution-ledger.sqlite3");
    let retained = f.base().join("pool/retained-unsent-ledger.sqlite3");
    std::fs::rename(&database, &retained).unwrap();
    // Frozen clock: the failed release is classified as pre-deadline whatever
    // the host's real elapsed time, so only the fixed release diagnostic fires.
    let origin = std::time::Instant::now();
    let deadline = origin + Duration::from_secs(30);
    let warnings = RecordedWarnings::default();
    let result = tracing::subscriber::with_default(warnings.clone(), || {
        super::release_unsent_hold(
            &f.pool(),
            f.base(),
            &reservation,
            deadline,
            &PoolClock::new(&|| origin, &chrono::Utc::now),
        )
    });
    assert!(
        result.is_err(),
        "a missing authoritative ledger must refuse the release"
    );
    assert_eq!(
        *warnings.0.lock().unwrap(),
        vec![vec![(
            "error_kind".into(),
            "pool_unsent_hold_release_failed".into()
        )]],
        "an unsent release failure must emit only its fixed diagnostic"
    );
    std::fs::rename(&retained, &database).unwrap();
    assert!(
        matches!(
            f.ledger()
                .reserve(&candidate, 1, f.utc().timestamp())
                .unwrap(),
            ReserveResult::InFlightBlocked
        ),
        "a failed release must retain the conservative hold"
    );
}

fn assert_public_unsent_release_failed(f: &Fixture, warnings: &RecordedWarnings, retained: &Path) {
    let database = f.base().join("pool/execution-ledger.sqlite3");
    std::fs::rename(retained, &database).unwrap();
    assert!(
        warnings.0.lock().unwrap().iter().any(|event| event
            == &vec![(
                "error_kind".into(),
                "pool_unsent_hold_release_failed".into()
            )]),
        "the public exec call site must emit the fixed unsent-hold release failure warning"
    );
    let ledger = rusqlite::Connection::open(&database).unwrap();
    let row: (i64, i64) = ledger
        .query_row("SELECT state,held FROM reservations", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!(
        row,
        (0, HOLD as i64),
        "a failed public unsent release must retain the full durable hold"
    );
}

#[test]
fn pending_finalization_exec_release_failure_warns_and_retains_the_full_hold() {
    let f = Fixture::new();
    f.add("a", HOLD as f64 / 1_000_000_000.0);
    let database = f.base().join("pool/execution-ledger.sqlite3");
    let retained = f.base().join("pool/retained-pending-unsent.sqlite3");
    let retained_for_observer = retained.clone();
    let renamed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let renamed_for_observer = renamed.clone();
    let warnings = RecordedWarnings(
        Default::default(),
        Some(Arc::new(move |fields| {
            if fields
                .iter()
                .any(|(name, value)| name == "error_kind" && value == "pool_ledger_mirror_lagging")
                && !renamed_for_observer.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                // This event occurs after reservation commit and before the public
                // pending-finalization branch attempts its definitely-unsent release.
                std::fs::rename(&database, &retained_for_observer).unwrap();
            }
        })),
    );
    let result = tracing::subscriber::with_default(warnings.clone(), || {
        Pool::with_ledger_mirror_failure_for_test(|| f.run(request(), &never()))
    });
    assert!(
        result.is_err(),
        "failed pending finalization must not dispatch"
    );
    assert!(
        renamed.load(std::sync::atomic::Ordering::SeqCst),
        "the committed-ledger release fault must be injected"
    );
    assert_public_unsent_release_failed(&f, &warnings, &retained);
}

#[test]
fn expired_predispatch_exec_release_failure_warns_and_retains_the_full_hold() {
    let f = Fixture::new();
    f.add("a", HOLD as f64 / 1_000_000_000.0);
    let origin = std::time::Instant::now();
    let database = f.base().join("pool/execution-ledger.sqlite3");
    let retained = f.base().join("pool/retained-expired-unsent.sqlite3");
    let renamed = std::cell::Cell::new(false);
    let clock = || {
        let bytes = std::fs::read(f.base().join("pool/manifest.json")).unwrap();
        let manifest: Value = serde_json::from_slice(&bytes).unwrap();
        if manifest["ledger_identity"]["sequence"]
            .as_u64()
            .is_some_and(|sequence| sequence > 0)
        {
            if !renamed.replace(true) {
                // The durable admission boundary, not a clock-call count, seats
                // the real I/O fault immediately before dispatch is refused.
                std::fs::rename(&database, &retained).unwrap();
            }
            origin + Duration::from_secs(3600)
        } else {
            origin
        }
    };
    let mut r = request();
    r.timeout_secs = 3600;
    let warnings = RecordedWarnings::default();
    let result = tracing::subscriber::with_default(warnings.clone(), || {
        Pool::with_default_vault_for_test(f.vault.clone(), || {
            super::execute_with_clock(f.utc(), f.base(), r, &never(), &clock)
        })
    });
    assert!(
        result.is_err(),
        "an expired pre-dispatch request must not dispatch"
    );
    assert!(
        renamed.get(),
        "the committed-ledger release fault must be injected"
    );
    assert_public_unsent_release_failed(&f, &warnings, &retained);
}

#[test]
fn paid_settlement_preserves_completion_on_mirror_lag_faults_and_next_admission_stops() {
    for stage in ["record", "read", "clear"] {
        let f = Fixture::new();
        f.add("a", 1.0);
        f.run(
            request(),
            &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
        )
        .unwrap();
        let fault: std::cell::RefCell<Option<Box<dyn std::any::Any>>> =
            std::cell::RefCell::new(None);
        let calls = Mutex::new(0);
        let transport = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
            *calls.lock().unwrap() += 1;
            if fault.borrow().is_none() {
                let guard: Box<dyn std::any::Any> = match stage {
                    "record" => Box::new(Pool::ledger_mirror_and_lag_record_failure_for_test()),
                    "read" => Box::new(Pool::ledger_lag_read_failure_for_test()),
                    "clear" => {
                        let manifest: Value = serde_json::from_slice(
                            &std::fs::read(f.base().join("pool/manifest.json")).unwrap(),
                        )
                        .unwrap();
                        crate::platform::fs::write_new_private_synced(
                            &f.base().join("pool/ledger-mirror-lag.json"),
                            &serde_json::to_vec(&manifest["ledger_identity"]).unwrap(),
                        )
                        .unwrap();
                        Box::new(Pool::ledger_lag_clear_failure_for_test())
                    }
                    _ => unreachable!(),
                };
                *fault.borrow_mut() = Some(guard);
            }
            Ok(completion())
        });
        let warnings = RecordedWarnings::default();
        let response = tracing::subscriber::with_default(warnings.clone(), || f.run(request(), &transport))
            .expect("a committed paid settlement must preserve its completion when mirror accounting publication fails");
        assert_eq!(response.text, "synthetic answer");
        assert!(
            warnings.0.lock().unwrap().iter().any(|event| event
                == &vec![(
                    "error_kind".into(),
                    "pool_accounting_mirror_unavailable".into()
                )]),
            "a preserved paid completion must emit the fixed accounting mirror warning"
        );
        let stopped = f.run(request(), &transport);
        assert_eq!(
            *calls.lock().unwrap(),
            1,
            "the next admission under the same mirror outage must refuse before spend"
        );
        assert!(
            stopped.is_err(),
            "an ongoing mirror outage must stop the next admission"
        );
        drop(fault.borrow_mut().take());
    }
}

#[test]
fn add_after_native_vault_loss_refuses_and_exec_never_sends() {
    let f = openai_native_and_env_fixture();
    let vault_path = f.base().join("fixture-vault/pool-vault-store.json");
    std::fs::remove_file(&vault_path).unwrap();
    let result = Pool::with_default_vault_for_test(f.vault.clone(), || {
        Pool::new(f.base()).add(
            "c",
            "openai",
            SecretString::from("synthetic-c"),
            None,
            Some(1.0),
        )
    });
    assert_eq!(
        result,
        Err(crate::pool::PoolError::StoreUnavailable),
        "adding a key must refuse before recreating a vault referenced by native rows"
    );
    assert!(
        !vault_path.exists(),
        "refused add must not recreate the lost vault"
    );
    assert_custody_failure_without_dispatch(&f, openai_request());
}

struct MissingBeforeNamedWriteVault {
    inner: Arc<dyn Vault>,
    path: std::path::PathBuf,
    armed: std::sync::atomic::AtomicBool,
}
impl MissingBeforeNamedWriteVault {
    fn lose_before_write(&self) {
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            std::fs::remove_file(&self.path).unwrap();
        }
    }
}
impl Vault for MissingBeforeNamedWriteVault {
    fn named_store_present(&self) -> Result<bool, SecretError> {
        self.inner.named_store_present()
    }
    fn set_named(&self, key: &NamedKey, secret: &SecretString) -> Result<(), SecretError> {
        self.lose_before_write();
        self.inner.set_named(key, secret)
    }
    fn set_named_existing(&self, key: &NamedKey, secret: &SecretString) -> Result<(), SecretError> {
        self.lose_before_write();
        self.inner.set_named_existing(key, secret)
    }
    fn get_named(&self, key: &NamedKey) -> Result<SecretString, SecretError> {
        self.inner.get_named(key)
    }
    fn delete_named(&self, key: &NamedKey) -> Result<(), SecretError> {
        self.inner.delete_named(key)
    }
    fn contains_named(&self, key: &NamedKey) -> Result<bool, SecretError> {
        self.inner.contains_named(key)
    }
    fn named_worker_state(&self, key: &NamedKey) -> NamedWorkerState {
        self.inner.named_worker_state(key)
    }
    fn set(&self, key: SlotKey, secret: &SecretString) -> Result<(), SecretError> {
        self.inner.set(key, secret)
    }
    fn get(&self, key: SlotKey) -> Result<SecretString, SecretError> {
        self.inner.get(key)
    }
    fn delete(&self, key: SlotKey) -> Result<(), SecretError> {
        self.inner.delete(key)
    }
    fn list_slots(
        &self,
        surface: &'static str,
    ) -> Result<Vec<crate::types::AccountNum>, SecretError> {
        self.inner.list_slots(surface)
    }
    fn backend_id(&self) -> &'static str {
        self.inner.backend_id()
    }
}

fn assert_named_write_race_refuses_and_exec_stops(remove: bool) {
    let mut f = openai_native_and_env_fixture();
    let vault = Arc::new(MissingBeforeNamedWriteVault {
        inner: f.vault.clone(),
        path: f.base().join("fixture-vault/pool-vault-store.json"),
        armed: std::sync::atomic::AtomicBool::new(true),
    });
    f.vault = vault.clone();
    let result = Pool::with_default_vault_for_test(f.vault.clone(), || {
        let pool = Pool::new(f.base());
        if remove {
            pool.remove("a")
        } else {
            pool.add(
                "c",
                "openai",
                SecretString::from("synthetic-c"),
                None,
                Some(1.0),
            )
        }
    });
    assert!(
        result.is_err(),
        "a vault lost between presence check and named write must refuse the pool mutation"
    );
    assert!(
        !vault.armed.load(std::sync::atomic::Ordering::SeqCst),
        "the real vault loss must occur at the named write after presence checking"
    );
    assert!(
        !vault.path.exists(),
        "the refused named write must never re-create the lost vault"
    );
    assert_custody_failure_without_dispatch(&f, openai_request());
}

#[test]
fn add_write_race_never_recreates_a_vault_and_exec_does_not_dispatch() {
    assert_named_write_race_refuses_and_exec_stops(false);
}

#[test]
fn remove_backup_write_race_never_recreates_a_vault_and_exec_does_not_dispatch() {
    assert_named_write_race_refuses_and_exec_stops(true);
}

#[test]
fn missing_other_provider_native_vault_blocks_env_first_until_native_row_removed() {
    let f = Fixture::new();
    let env = f.base().join("env-first-recovery.env");
    crate::platform::fs::write_new_private_synced(&env, b"a=synthetic-env-first\n").unwrap();
    f.pool()
        .add_env_file(&env, &["a".into()], "anthropic", None, Some(1.0))
        .unwrap();
    f.add_for("z", "openai", 1.0);
    std::fs::remove_file(f.base().join("fixture-vault/pool-vault-store.json")).unwrap();
    assert_custody_failure_without_dispatch(&f, request());
    let removed = Pool::with_default_vault_for_test(f.vault.clone(), || {
        Pool::new(f.base()).remove_with_outcome("z")
    })
    .expect("a confirmed absent vault must allow removal of its dangling native row");
    assert!(
        removed,
        "removal must report that the native vault file was missing"
    );
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
            assert!(key.expose_secret() == "synthetic-env-first");
            Ok(completion())
        }),
    )
    .expect("removing all missing native rows must restore execution through remaining env keys");
}

#[cfg(any(unix, windows))]
#[test]
fn unreadable_native_vault_removal_refuses_and_exec_still_stops() {
    let f = openai_native_and_env_fixture();
    let _unreadable = UnreadableFixturePath::set(f.base().join("fixture-vault"));
    let result = Pool::with_default_vault_for_test(f.vault.clone(), || {
        Pool::new(f.base()).remove_with_outcome("a")
    });
    assert_eq!(
        result,
        Err(crate::pool::PoolError::StoreUnavailable),
        "an unreadable vault must never be treated as confirmed absent during removal"
    );
    assert_custody_failure_without_dispatch(&f, openai_request());
}

fn openai_native_and_env_fixture() -> Fixture {
    let f = Fixture::new();
    let mut rates = manifest();
    // Catalog metadata uses codex; the execution and billing surface is openai.
    rates["models"][0]["provider"] = json!("codex");
    rates["rates"][0]["epochs"][0]["rate"]["cache_read_per_1m_usd"] = json!(0.5);
    f.write_manifest(rates);
    let request = openai_request();
    let admission = chrono::Utc::now();
    let pricing = crate::pool::execution_pricing::prepare(
        &crate::providers::model_manifest::ModelManifest::load(f.base()).unwrap(),
        &request,
        admission,
        admission + chrono::Duration::seconds(30),
    )
    .expect("OpenAI custody fixture must pass model and complete pricing admission");
    let mut response = completion();
    response.provider = request.provider.clone();
    assert!(
        pricing.price_completion(&response).is_some(),
        "the synthetic OpenAI response must be valid if a broken guard dispatches it"
    );
    f.add_for("a", "openai", 1.0);
    let env = f.base().join("healthy-openai.env");
    crate::platform::fs::write_new_private_synced(&env, b"b=synthetic-healthy-env\n").unwrap();
    f.pool()
        .add_env_file(&env, &["b".into()], "openai", None, Some(1.0))
        .unwrap();
    f
}

fn openai_request() -> PoolExecRequest {
    let mut value = request();
    value.provider = "openai".into();
    value
}

fn assert_custody_failure_without_dispatch(f: &Fixture, request: PoolExecRequest) {
    let calls = Mutex::new(0);
    let result = f.run(
        request,
        &Transport(|request: &PoolExecRequest, _: SecretString, _: Duration| {
            *calls.lock().unwrap() += 1;
            let mut response = completion();
            response.provider = request.provider.clone();
            Ok(response)
        }),
    );
    assert_eq!(
        *calls.lock().unwrap(),
        0,
        "a store-wide outage must not dispatch a healthy fallback key"
    );
    let error = result.unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
    assert_eq!(error.message.as_str(), "pool_custody_unavailable");
}

#[test]
fn removed_native_vault_stops_before_a_healthy_env_key_dispatches() {
    let f = openai_native_and_env_fixture();
    std::fs::remove_file(f.base().join("fixture-vault/pool-vault-store.json")).unwrap();
    assert_custody_failure_without_dispatch(&f, openai_request());
}

// ---------------------------------------------------------------------------
// Unreadable-vault fault injection.
//
// The vault-store fault is "this platform cannot read the native vault store",
// expressed with the mechanism each platform actually enforces. It is NOT a
// permission assertion: every test below keeps the same assertion and only the
// injection changes.
// ---------------------------------------------------------------------------

/// Holds the fixture's native vault store unreadable for the guard's lifetime
/// and restores access on drop.
///
/// `target` is the `fixture-vault` directory or the store file itself.
///
/// unix: the target's mode bits are cleared (restored on drop), so every open
/// under it fails with `EACCES`.
///
/// Windows: `platform::fs::secure_file` is a documented no-op there, so the
/// platform's equivalent of cleared mode bits is an ACCESS fault.
///
/// * store FILE: an exclusive handle — `read(true)` plus `share_mode(0)` — so
///   every later open fails with `ERROR_SHARING_VIOLATION` (32). The holder
///   takes read access deliberately: the installer-admission tests measured
///   that a `READ_CONTROL`-only `share_mode(0)` holder blocks nothing.
/// * DIRECTORY: a share-mode handle does NOT block child opens (measured in
///   native run 41155302330 — the engine opened the store straight through the
///   exclusive directory handle), and a directory DENY ACE would not either:
///   every interactive token holds `SeChangeNotifyPrivilege`, which bypasses
///   the traversal check, so the folder's DACL is not consulted for a child
///   path. The real, privilege-independent fault is a NON-DIRECTORY at the
///   folder's own path — the folder is moved aside and a regular file takes its
///   place, so the store file under the moved-aside `fixture-vault` directory
///   fails name resolution with `ERROR_DIRECTORY` for every open. `Drop`
///   removes the file and moves the folder back. `set` proves the fault with a
///   canary child first.
struct UnreadableFixturePath {
    #[cfg(unix)]
    path: std::path::PathBuf,
    #[cfg(unix)]
    permissions: std::fs::Permissions,
    #[cfg(windows)]
    _holder: Option<std::fs::File>,
    /// Directory case: (the folder's path, where it was moved aside), restored
    /// in `Drop`.
    #[cfg(windows)]
    _restore: Option<(std::path::PathBuf, std::path::PathBuf)>,
}
#[cfg(any(unix, windows))]
impl UnreadableFixturePath {
    fn set(target: std::path::PathBuf) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::metadata(&target).unwrap().permissions();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o0)).unwrap();
            Self {
                path: target,
                permissions,
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            if target.is_dir() {
                let aside = target.with_file_name("fixture-vault.moved");
                std::fs::rename(&target, &aside).expect("move the vault directory aside");
                std::fs::File::create(&target).expect("place a file at the vault-directory path");
                // Premise: the store really is unopenable through the fault; if
                // it ever stops being so, this fixture would silently stop
                // exercising the directory case.
                let canary = std::fs::OpenOptions::new()
                    .read(true)
                    .open(target.join("pool-vault-store.json"));
                // The STORE decides absence from this failure's KIND, so record
                // what the runner really produces (libtest captures print! and
                // eprintln!, so write to stderr directly).
                {
                    use std::io::Write as _;
                    let detail = match &canary {
                        Ok(_) => "ok".to_string(),
                        Err(error) => format!(
                            "kind={:?} raw_os_error={:?}",
                            error.kind(),
                            error.raw_os_error()
                        ),
                    };
                    let _ = writeln!(std::io::stderr(), "[unreadable-dir-canary] {detail}");
                }
                assert!(
                    canary.is_err(),
                    "the directory fixture must make the store unopenable through it"
                );
                Self {
                    _holder: None,
                    _restore: Some((target, aside)),
                }
            } else {
                let holder = std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .open(&target)
                    .expect("the exclusive vault-store holder must open before the vault does");
                Self {
                    _holder: Some(holder),
                    _restore: None,
                }
            }
        }
    }
}
#[cfg(unix)]
impl Drop for UnreadableFixturePath {
    fn drop(&mut self) {
        std::fs::set_permissions(&self.path, self.permissions.clone()).unwrap();
    }
}
#[cfg(windows)]
impl Drop for UnreadableFixturePath {
    fn drop(&mut self) {
        if let Some((dir, aside)) = self._restore.take() {
            // Teardown: remove the stand-in file and move the vault folder
            // back. A failure here is reported by the temp-dir cleanup, not
            // fatal inside Drop.
            let _ = std::fs::remove_file(&dir);
            let _ = std::fs::rename(&aside, &dir);
        }
    }
}

#[cfg(any(unix, windows))]
#[test]
fn unreadable_native_vault_file_stops_before_a_healthy_env_key_dispatches() {
    let f = openai_native_and_env_fixture();
    let _unreadable =
        UnreadableFixturePath::set(f.base().join("fixture-vault/pool-vault-store.json"));
    assert_custody_failure_without_dispatch(&f, openai_request());
}

#[cfg(any(unix, windows))]
#[test]
fn unreadable_native_vault_directory_stops_before_a_healthy_env_key_dispatches() {
    let f = openai_native_and_env_fixture();
    let _unreadable = UnreadableFixturePath::set(f.base().join("fixture-vault"));
    assert_custody_failure_without_dispatch(&f, openai_request());
}

#[cfg(unix)]
#[test]
fn rotated_env_manifest_write_failure_stops_before_another_key_dispatches() {
    let f = Fixture::new();
    let env = f.base().join("rotation-before-write-failure.env");
    crate::platform::fs::write_new_private_synced(&env, b"a=synthetic-original-env\n").unwrap();
    f.pool()
        .add_env_file(&env, &["a".into()], "anthropic", None, Some(1.0))
        .unwrap();
    f.add("b", 1.0);
    // Existing ledger/journal files remain writable: the failing operation is
    // publishing the rotated manifest into the unwritable pool directory.
    f.run(
        request(),
        &Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| Ok(completion())),
    )
    .unwrap();
    std::fs::write(&env, "a=synthetic-rotated-env\n").unwrap();
    // Custody secures its directory before key reads. The fixture therefore
    // makes that directory unwritable at the actual manifest write, after
    // custody acquisition, and restores it before any later operation.
    Pool::with_manifest_write_failure_for_test(|| {
        assert_custody_failure_without_dispatch(&f, request());
    });
}

#[test]
fn consecutive_mirror_failures_stop_the_next_dispatch_and_success_clears_lag() {
    let f = Fixture::new();
    f.add("a", 1.0);
    let calls = Arc::new(Mutex::new(0));
    let ok = Transport(|_: &PoolExecRequest, _: SecretString, _: Duration| {
        *calls.lock().unwrap() += 1;
        Ok(completion())
    });
    f.run(request(), &ok).unwrap();
    Pool::with_ledger_mirror_failure_for_test(|| f.run(request(), &ok))
        .expect("the first active mirror lag may preserve its committed dispatch");
    assert_eq!(*calls.lock().unwrap(), 2);
    let stopped = Pool::with_ledger_mirror_failure_for_test(|| f.run(request(), &ok));
    assert_eq!(
        *calls.lock().unwrap(),
        2,
        "consecutive mirror failures must not dispatch"
    );
    let error = stopped.unwrap_err();
    assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
    assert_eq!(error.message.as_str(), "pool_ledger_finalization_pending");
    f.run(request(), &ok)
        .expect("a successful mirror publish clears durable lag");
    Pool::with_ledger_mirror_failure_for_test(|| f.run(request(), &ok))
        .expect("a cleared lag permits a later isolated first publication failure");
    assert_eq!(*calls.lock().unwrap(), 4);
}

struct NamedReadFailureVault {
    inner: Arc<dyn Vault>,
    global: bool,
}
impl Vault for NamedReadFailureVault {
    fn set_named(
        &self,
        key: &crate::platform::secret::NamedKey,
        value: &SecretString,
    ) -> Result<(), crate::platform::secret::SecretError> {
        self.inner.set_named(key, value)
    }
    fn get_named(
        &self,
        key: &crate::platform::secret::NamedKey,
    ) -> Result<SecretString, crate::platform::secret::SecretError> {
        use crate::platform::secret::SecretError;
        if self.global {
            return Err(SecretError::Locked);
        }
        let value = self.inner.get_named(key)?;
        if value.expose_secret() == "synthetic-a" {
            Err(SecretError::NamedItemUnreadable)
        } else {
            Ok(value)
        }
    }
    fn delete_named(
        &self,
        key: &crate::platform::secret::NamedKey,
    ) -> Result<(), crate::platform::secret::SecretError> {
        self.inner.delete_named(key)
    }
    fn contains_named(
        &self,
        key: &crate::platform::secret::NamedKey,
    ) -> Result<bool, crate::platform::secret::SecretError> {
        self.inner.contains_named(key)
    }
    fn named_worker_state(
        &self,
        key: &crate::platform::secret::NamedKey,
    ) -> crate::platform::secret::NamedWorkerState {
        self.inner.named_worker_state(key)
    }
    fn set(
        &self,
        key: crate::platform::secret::SlotKey,
        value: &SecretString,
    ) -> Result<(), crate::platform::secret::SecretError> {
        self.inner.set(key, value)
    }
    fn get(
        &self,
        key: crate::platform::secret::SlotKey,
    ) -> Result<SecretString, crate::platform::secret::SecretError> {
        self.inner.get(key)
    }
    fn delete(
        &self,
        key: crate::platform::secret::SlotKey,
    ) -> Result<(), crate::platform::secret::SecretError> {
        self.inner.delete(key)
    }
    fn list_slots(
        &self,
        surface: &'static str,
    ) -> Result<Vec<crate::types::AccountNum>, crate::platform::secret::SecretError> {
        self.inner.list_slots(surface)
    }
    fn backend_id(&self) -> &'static str {
        self.inner.backend_id()
    }
}

#[test]
fn native_item_failure_skips_one_key_but_vault_wide_failure_stops_execution() {
    for global in [false, true] {
        let f = Fixture::new();
        f.add("a", 1.0);
        f.add("b", 1.0);
        let vault = Arc::new(NamedReadFailureVault {
            inner: f.vault.clone(),
            global,
        });
        let result = Pool::with_default_vault_for_test(vault, || {
            if global {
                run_on_frozen_clock(f.base(), f.utc(), request(), &never())
            } else {
                run_on_frozen_clock(
                    f.base(),
                    f.utc(),
                    request(),
                    &Transport(|_: &PoolExecRequest, key: SecretString, _: Duration| {
                        assert!(key.expose_secret() == "synthetic-b");
                        Ok(completion())
                    }),
                )
            }
        });
        if global {
            let error = result.unwrap_err();
            assert_code(error.clone(), SdkErrorCode::PoolUnavailable);
            assert_eq!(error.message.as_str(), "pool_custody_unavailable");
        } else {
            result.expect("per-item read failure must not block a healthy native key");
        }
    }
}
