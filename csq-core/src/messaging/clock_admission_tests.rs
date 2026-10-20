//! Successor uses the explicit production AdmissionClock route, not parent-v1 TLS repair.
use super::*;
use crate::sessions::directives::real_fs;
use std::cell::Cell;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
use tempfile::TempDir;
const HONEST: u64 = 1_000_000;

struct Probe {
    contender: std::fs::File,
    samples: Cell<usize>,
    outside: Cell<usize>,
    honest: u64,
}
impl Probe {
    fn new(base: &Path, honest: u64) -> Self {
        Self {
            contender: std::fs::OpenOptions::new()
                .read(true)
                .open(store::store_dir(base).join(".lock"))
                .unwrap(),
            samples: Cell::new(0),
            outside: Cell::new(0),
            honest,
        }
    }
    fn read(&self) -> Result<u64, DirectiveError> {
        self.samples.set(self.samples.get() + 1);
        let rc = unsafe { libc::flock(self.contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            self.outside.set(self.outside.get() + 1);
            unsafe {
                libc::flock(self.contender.as_raw_fd(), libc::LOCK_UN);
            }
        } else {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        Ok(self.honest)
    }
    fn assert_admitted(&self) {
        assert!(
            self.samples.get() > 0,
            "explicit honest provider must be consumed"
        );
        assert_eq!(
            self.outside.get(),
            0,
            "honest provider must be sampled after actual lock admission"
        );
    }
}
fn authority(base: &Path) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(store::store_dir(base).join("requests/ledger.json")).unwrap(),
    )
    .unwrap()
}
fn publish(base: &Path, original: Clock, probe: &Probe) -> Result<u64, DirectiveError> {
    let wall = || probe.read();
    under_lock_with_admission_clock(
        base,
        AdmissionClock::new(original, &wall),
        |dir, observed, upper| {
            assert!(upper >= observed);
            open(dir, observed, upper, &real_fs(), false).map(|ledger| ledger.clock)
        },
    )
}
#[test]
fn stale_capture_beyond_tolerance_samples_after_real_admission() {
    let owned = TempDir::new().unwrap();
    initialize(owned.path(), HONEST - 10, &real_fs()).unwrap();
    let before = authority(owned.path());
    under_lock(owned.path(), HONEST + 10, |dir, observed, upper| {
        open(dir, observed, upper, &real_fs(), false).map(|_| ())
    })
    .unwrap();
    let b = Probe::new(owned.path(), HONEST + 10);
    let result = publish(owned.path(), Clock::from(HONEST), &b);
    assert!(
        result.is_ok(),
        "stale capture beyond two seconds requires actual post-admission UTC refresh"
    );
    assert_eq!(result.unwrap(), HONEST + 10);
    b.assert_admitted();
    let after = authority(owned.path());
    assert_eq!(after["init"], before["init"]);
    assert_eq!(after["entries"], before["entries"]);
    assert_eq!(after["clock"], HONEST + 10);
}
#[test]
fn expiry_projection_stays_separate_on_explicit_provider_route() {
    let owned = TempDir::new().unwrap();
    initialize(owned.path(), HONEST - 10, &real_fs()).unwrap();
    let original = Clock {
        observed: HONEST,
        initial: HONEST,
        started: Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap(),
    };
    let conservative = original.upper(Instant::now());
    assert!(
        conservative > HONEST,
        "fixture must carry a projected expiry bound"
    );
    let probe = Probe::new(owned.path(), HONEST);
    let wall = || probe.read();
    under_lock_with_admission_clock(
        owned.path(),
        AdmissionClock::new(original, &wall),
        |dir, observed, upper| {
            assert_eq!(
                observed, HONEST,
                "conservative expiry upper must not become observed UTC"
            );
            assert!(
                upper > observed,
                "original expiry projection must be retained separately"
            );
            let ledger = open(dir, observed, upper, &real_fs(), false)?;
            assert_eq!(
                ledger.clock, HONEST,
                "projected expiry must not poison persisted ledger UTC"
            );
            Ok(())
        },
    )
    .unwrap();
    probe.assert_admitted();
    let next = Probe::new(owned.path(), HONEST);
    assert_eq!(
        publish(owned.path(), Clock::from(HONEST), &next).unwrap(),
        HONEST
    );
    next.assert_admitted();
}
#[test]
fn explicit_policy_boundary_does_not_change_honest_utc_or_genuine_rollback() {
    // The two-second authority-ahead allowance is a pending normative policy, not a measured
    // scheduling bound. Root must obtain approval before dispatching this candidate assertion.
    for marker in [false, true] {
        for ahead in [2, 3] {
            let owned = TempDir::new().unwrap();
            initialize(
                owned.path(),
                if marker { HONEST + ahead } else { HONEST - 10 },
                &real_fs(),
            )
            .unwrap();
            under_lock(owned.path(), HONEST + ahead, |dir, observed, upper| {
                open(dir, observed, upper, &real_fs(), false).map(|_| ())
            })
            .unwrap();
            let ledger_path = store::store_dir(owned.path()).join("requests/ledger.json");
            let before = std::fs::read(&ledger_path).unwrap();
            let probe = Probe::new(owned.path(), HONEST);
            let result = publish(owned.path(), Clock::from(HONEST), &probe);
            probe.assert_admitted();
            if ahead == 2 {
                assert_eq!(
                    result.unwrap(),
                    HONEST + 2,
                    "approved authority watermark must stay monotonic"
                );
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.code, csq_sdk::SdkErrorCode::Undetermined);
                assert_eq!(
                    error.cause,
                    Some(Cause::LedgerRead),
                    "authority beyond explicit allowance must refuse"
                );
                assert_eq!(
                    std::fs::read(&ledger_path).unwrap(),
                    before,
                    "refused authority must not mutate ledger"
                );
            }
        }
    }
    let owned = TempDir::new().unwrap();
    initialize(owned.path(), HONEST - 10, &real_fs()).unwrap();
    let before =
        std::fs::read(store::store_dir(owned.path()).join("requests/ledger.json")).unwrap();
    let probe = Probe::new(owned.path(), HONEST);
    let error = publish(owned.path(), Clock::from(HONEST + 1), &probe).unwrap_err();
    assert_eq!(
        error.cause,
        Some(Cause::Clock),
        "provider rollback below original capture must stay strict"
    );
    assert_eq!(
        std::fs::read(store::store_dir(owned.path()).join("requests/ledger.json")).unwrap(),
        before
    );
    probe.assert_admitted();
}
