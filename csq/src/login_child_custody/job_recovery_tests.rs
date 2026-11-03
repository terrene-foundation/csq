//! Portable Unix owner-loop probes for typed Windows Job refusals. These do
//! not qualify the Windows kernel; native Job/descendant qualification is separate.
use super::{ChildKey, ChildRegistration, CredentialWrites, LoginProvider, WritePermit};
use crate::login_child_custody::{group, DeliveryPhase, LoginWatchdog, OwnedLoginChild};
use std::io;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const ENTRY: &str = "desktop::login_custody::job_recovery_tests::private_job_recovery_actor";
const ROOT: &str = "CSQ_PRIVATE_JOB_RECOVERY_ROOT";
const UNKNOWN: &str = "JOB_RECOVERY_OBSERVATION_UNDETERMINED";
const SETUP: Duration = Duration::from_secs(5);
// This exceeds the current 2s terminalization boundary by 300ms. Actor safety
// lifetime is 30s, beyond setup+hold+cancel+cleanup (<=17.3s).
const HOLD: Duration = Duration::from_millis(2300);
type Owner = OwnedLoginChild<(WritePermit, Arc<ChildRegistration>)>;

#[derive(Clone, Copy)]
enum Refusal {
    Nonempty,
    Unavailable,
}
impl Refusal {
    fn error(self) -> io::Error {
        io::Error::other(match self {
            Self::Nonempty => group::CensusRefusal::Nonempty,
            Self::Unavailable => group::CensusRefusal::Unavailable,
        })
    }
}
fn command(root: &Path) -> io::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .env_clear()
        .args([
            ENTRY,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(root)
        .env(ROOT, root)
        .env("HOME", root.join("home"))
        .env("CSQ_BASE_DIR", root.join("base"))
        .env("PATH", root.join("bin"))
        .env("TMPDIR", root.join("tmp"))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("CSQ_SECRET_BACKEND", "in-memory")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(root.join("stderr"))?);
    Ok(command)
}
fn poll_for(budget: Duration, mut ready: impl FnMut() -> io::Result<bool>) -> io::Result<()> {
    let until = Instant::now() + budget;
    loop {
        if ready()? {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(io::Error::other(UNKNOWN));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
struct Fixture {
    sandbox: Option<tempfile::TempDir>,
    root: PathBuf,
    owner: Option<Owner>,
    gate: CredentialWrites,
    key: ChildKey,
    refusal: Arc<AtomicBool>,
    eof: Arc<AtomicBool>,
    reader: Option<JoinHandle<io::Result<()>>>,
    joined: bool,
    actual_status: Option<ExitStatus>,
    cleaned: bool,
}
impl Fixture {
    fn start(kind: Refusal) -> io::Result<Self> {
        let sandbox = tempfile::tempdir()?;
        let root = sandbox.path().to_path_buf();
        for name in ["home", "base", "bin", "tmp"] {
            std::fs::create_dir(root.join(name))?;
        }
        let gate = CredentialWrites::default();
        let key = ChildKey::new(
            LoginProvider::Claude,
            csq_core::types::AccountNum::try_from(1).map_err(io::Error::other)?,
        );
        let watchdog = LoginWatchdog::new(Duration::from_secs(60), DeliveryPhase::Unknown);
        let permit = gate.admit().map_err(io::Error::other)?;
        let registration = gate
            .reserve_child(key, watchdog.clone())
            .map_err(io::Error::other)?;
        let (child, group) = group::spawn(&mut command(&root)?, group::StdinPolicy::Null)?;
        let owner = OwnedLoginChild::adopt_group(
            child,
            group,
            watchdog,
            (permit, Arc::clone(&registration)),
        );
        registration.attach(owner.shared_child(), owner.group_control());
        drop(registration);
        let mut fixture = Self {
            sandbox: Some(sandbox),
            root,
            owner: Some(owner),
            gate,
            key,
            refusal: Arc::new(AtomicBool::new(true)),
            eof: Arc::new(AtomicBool::new(false)),
            reader: None,
            joined: false,
            actual_status: None,
            cleaned: false,
        };
        let mut stdout = fixture
            .owner
            .as_ref()
            .ok_or_else(|| io::Error::other(UNKNOWN))?
            .shared_child()
            .lock()
            .map_err(|_| io::Error::other(UNKNOWN))?
            .stdout
            .take()
            .ok_or_else(|| io::Error::other(UNKNOWN))?;
        let eof = Arc::clone(&fixture.eof);
        fixture.reader = Some(
            std::thread::Builder::new()
                .name("job-recovery-actual-reader".into())
                .spawn(move || {
                    io::copy(&mut stdout, &mut io::sink())?;
                    eof.store(true, Ordering::Release);
                    Ok(())
                })?,
        );
        let refusal = Arc::clone(&fixture.refusal);
        fixture
            .owner
            .as_mut()
            .ok_or_else(|| io::Error::other(UNKNOWN))?
            .set_wait_observer(move |group, child, joined| {
                // Only a typed upstream gate failure is injected. Every Some status
                // and successful finalization still comes from production try_reap.
                if refusal.load(Ordering::Acquire) {
                    Err(kind.error())
                } else {
                    group.try_reap(child, joined)
                }
            });
        poll_for(SETUP, || Ok(fixture.root.join("ready").exists()))?;
        Ok(fixture)
    }
    fn join_reader(&mut self) -> io::Result<bool> {
        if self.joined {
            return Ok(true);
        }
        if self.eof.load(Ordering::Acquire)
            && self
                .reader
                .as_ref()
                .is_some_and(|reader| reader.is_finished())
        {
            if let Some(reader) = self.reader.take() {
                reader.join().map_err(|_| io::Error::other(UNKNOWN))??;
            }
            self.joined = true;
            if let Some(owner) = self.owner.as_ref() {
                owner.group_control().mark_readers_joined();
            }
        }
        Ok(self.joined)
    }
    fn poll(&mut self) -> io::Result<()> {
        let joined = self.join_reader()?;
        if let Some(owner) = self.owner.as_mut() {
            owner.observe_kill_intent();
            owner.poll_child(joined);
        }
        Ok(())
    }
    fn hold_refusal(&mut self, kind: Refusal, after_stop: bool) -> io::Result<()> {
        let started = Instant::now();
        loop {
            self.poll()?;
            if after_stop {
                // Exercise the production stop_deadline tail with the same
                // typed upstream gate error, without changing old observer routing.
                if let Some(owner) = self.owner.as_mut() {
                    owner.observe_result(Err(kind.error()));
                }
            }
            if started.elapsed() >= HOLD {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    fn retire_if_finalized(&mut self) -> bool {
        if self
            .owner
            .as_ref()
            .is_some_and(OwnedLoginChild::custody_finalized)
        {
            self.actual_status = self.owner.as_ref().and_then(OwnedLoginChild::reaped_status);
            drop(self.owner.take());
            return true;
        }
        false
    }
    fn cleanup(&mut self) -> io::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        // The independent cooperative marker addresses only this private actor.
        std::fs::write(self.root.join("release"), b"release")?;
        let until = Instant::now() + SETUP;
        while self.owner.is_some() && self.actual_status.is_none() {
            let original = self
                .owner
                .as_ref()
                .ok_or_else(|| io::Error::other(UNKNOWN))?
                .shared_child();
            self.actual_status = original
                .lock()
                .map_err(|_| io::Error::other(UNKNOWN))?
                .try_wait()?;
            if self.actual_status.is_some() {
                break;
            }
            if Instant::now() >= until {
                return Err(io::Error::other(UNKNOWN));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        poll_for(SETUP, || self.join_reader())?;
        if let Some(owner) = self.owner.as_mut() {
            // Independent fixture accounting AFTER the saved semantic verdict:
            // actual original Child reap + real EOF/join permit test-only guard
            // retirement. No synthetic status, vendor grant or PID signal.
            owner.account_completed_fixture_for_test()?;
        }
        drop(self.owner.take());
        if !self
            .gate
            .pending_logins()
            .map_err(io::Error::other)?
            .is_empty()
        {
            return Err(io::Error::other(UNKNOWN));
        }
        self.cleaned = true;
        eprintln!("JOB_RECOVERY_PRIVATE_CLEANUP: actual_original_status={:?}; captured_eof_joined=true; registration_retired=true; numeric_signals=false", self.actual_status);
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            if let Some(sandbox) = self.sandbox.take() {
                let _ = sandbox.keep();
            }
            if let Some(owner) = self.owner.take() {
                std::mem::forget(owner);
            }
            eprintln!("{UNKNOWN}: fixture cleanup: {error}");
        }
    }
}

#[test]
#[ignore = "private inert self-exec actor only"]
fn private_job_recovery_actor() {
    let _environment = csq_core::platform::test_env::lock();
    let root = PathBuf::from(std::env::var_os(ROOT).expect("private fixture root"));
    assert_eq!(
        std::env::var_os("HOME").as_deref(),
        Some(root.join("home").as_os_str())
    );
    assert_eq!(
        std::env::var("CSQ_SECRET_BACKEND").as_deref(),
        Ok("in-memory")
    );
    std::fs::write(root.join("ready"), b"ready").unwrap();
    let until = Instant::now() + Duration::from_secs(30);
    while Instant::now() < until && !root.join("release").exists() {
        std::thread::sleep(Duration::from_millis(10));
    }
    std::io::stdout()
        .write_all(b"actual fixture completion\n")
        .unwrap();
}

fn recovery_case(kind: Refusal) {
    let _environment = csq_core::platform::test_env::lock();
    let mut fixture =
        Fixture::start(kind).unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
    std::fs::write(fixture.root.join("release"), b"release").unwrap();
    poll_for(SETUP, || fixture.join_reader())
        .unwrap_or_else(|error| panic!("{UNKNOWN}: EOF: {error}"));
    fixture.hold_refusal(kind, false).unwrap();
    let retained = fixture
        .owner
        .as_ref()
        .is_some_and(|owner| owner.recovery_pending_for_test())
        && fixture.gate.pending_logins().unwrap().len() == 1;
    fixture.refusal.store(false, Ordering::Release);
    let until = Instant::now() + SETUP;
    while Instant::now() < until {
        fixture.poll().unwrap();
        if fixture.retire_if_finalized() {
            break;
        }
        if fixture.owner.as_ref().is_some_and(|owner| {
            !owner.recovery_pending_for_test() && owner.reaped_status().is_none()
        }) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let actual_retirement = fixture.owner.is_none()
        && fixture.actual_status.is_some_and(|status| status.success())
        && fixture.joined
        && fixture.gate.pending_logins().unwrap().is_empty();
    eprintln!("JOB_RECOVERY_BEFORE_PRIVATE_CLEANUP: retained_after_budget={retained}; actual_retirement={actual_retirement}");
    fixture
        .cleanup()
        .unwrap_or_else(|error| panic!("{UNKNOWN}: {error}"));
    assert!(
        retained && actual_retirement,
        "JOB_REFUSAL_MUST_RECOVER_THROUGH_ACTUAL_CHILD_AND_READER"
    );
}
#[test]
fn job_nonempty_beyond_stop_budget_later_empty_retires_actual_owner() {
    recovery_case(Refusal::Nonempty);
}
#[test]
fn job_unavailable_beyond_stop_budget_later_readable_retires_actual_owner() {
    recovery_case(Refusal::Unavailable);
}

#[test]
fn quit_during_long_job_refusal_retains_cancel_authority_and_drains_actual_owner() {
    let _environment = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::start(Refusal::Nonempty)
        .unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
    fixture.hold_refusal(Refusal::Nonempty, false).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let gate = fixture.gate.clone();
    let operation = gate
        .pending_logins()
        .unwrap()
        .into_iter()
        .next()
        .expect("actual registration")
        .operation_id;
    let drain = gate.close_for_quit().expect("actual Quit admission close");
    let cancel = runtime.block_on(async {
        let cancel = gate.cancel_child_with_confirmation(fixture.key, &operation, true, || async { Ok(true) });
        tokio::pin!(cancel);
        let until = tokio::time::Instant::now() + SETUP;
        loop {
            tokio::select! {
                result = &mut cancel => break result,
                _ = tokio::time::sleep(Duration::from_millis(20)) => {
                    fixture.poll().unwrap(); fixture.retire_if_finalized();
                },
                _ = tokio::time::sleep_until(until) => break Err("JOB_RECOVERY_CANCEL_BOUNDED_WAIT".into()),
            }
        }
    });
    let drained = runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(100), drain.wait())
            .await
            .is_ok_and(|result| result.is_ok())
    });
    let actually_killed = fixture
        .actual_status
        .is_some_and(|status| status.signal() == Some(libc::SIGKILL));
    let retired = fixture.owner.is_none() && fixture.gate.pending_logins().unwrap().is_empty();
    eprintln!("JOB_QUIT_BEFORE_PRIVATE_CLEANUP: cancel={cancel:?}; actual_kill={actually_killed}; retired={retired}; drain={drained}");
    fixture
        .cleanup()
        .unwrap_or_else(|error| panic!("{UNKNOWN}: {error}"));
    assert!(
        cancel == Ok(true) && actually_killed && retired && drained,
        "JOB_REFUSAL_QUIT_MUST_KEEP_ORIGINAL_CANCEL_CAPABILITY"
    );
}

#[test]
fn unavailable_job_after_explicit_stop_budget_can_still_recover_actual_completion() {
    let _environment = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::start(Refusal::Unavailable)
        .unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
    let group = fixture.owner.as_ref().unwrap().group_control();
    group
        .signal(group::GroupSignal::Kill)
        .expect("actual retained group stop");
    fixture.owner.as_mut().unwrap().observe_kill_intent();
    // The real child is killed and the real reader closes, but the upstream
    // census remains unavailable. No actual reap is allowed during this hold.
    let started = Instant::now();
    while started.elapsed() < HOLD {
        fixture.join_reader().unwrap();
        fixture
            .owner
            .as_mut()
            .unwrap()
            .observe_result(Err(Refusal::Unavailable.error()));
        std::thread::sleep(Duration::from_millis(20));
    }
    let retained = fixture
        .owner
        .as_ref()
        .is_some_and(|owner| owner.recovery_pending_for_test());
    fixture.refusal.store(false, Ordering::Release);
    fixture.poll().unwrap();
    let retired = fixture.retire_if_finalized()
        && fixture
            .actual_status
            .is_some_and(|status| status.signal() == Some(libc::SIGKILL));
    eprintln!("JOB_STOP_CENSUS_BEFORE_PRIVATE_CLEANUP: retained_after_stop_budget={retained}; actual_retirement={retired}");
    fixture
        .cleanup()
        .unwrap_or_else(|error| panic!("{UNKNOWN}: {error}"));
    assert!(
        retained && retired,
        "JOB_STOP_CENSUS_MUST_REMAIN_RECOVERABLE"
    );
}

#[test]
fn bounded_quit_observer_reports_pending_job_then_later_actual_completion_drains() {
    let _environment = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::start(Refusal::Unavailable)
        .unwrap_or_else(|error| panic!("{UNKNOWN}: setup: {error}"));
    fixture.hold_refusal(Refusal::Unavailable, false).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let gate = fixture.gate.clone();
    let operation = gate
        .pending_logins()
        .unwrap()
        .into_iter()
        .next()
        .expect("actual retained registration")
        .operation_id;
    let drain = gate.close_for_quit().expect("actual Quit admission close");
    let started = Instant::now();
    let cancel = runtime.block_on(async {
        let cancel = gate.cancel_child_with_confirmation(fixture.key, &operation, true, || async { Ok(true) });
        tokio::pin!(cancel);
        let until = tokio::time::Instant::now() + SETUP;
        loop {
            tokio::select! {
                result = &mut cancel => break result,
                _ = tokio::time::sleep(Duration::from_millis(20)) => {
                    fixture.join_reader().unwrap();
                    let owner = fixture.owner.as_mut().expect("retained original owner");
                    owner.observe_kill_intent();
                    // The authorized native stop is real. Only the upstream
                    // census remains unavailable, so no child reap is injected.
                    owner.observe_result(Err(Refusal::Unavailable.error()));
                },
                _ = tokio::time::sleep_until(until) => break Err("JOB_RECOVERY_OBSERVER_DID_NOT_REPORT".into()),
            }
        }
    });
    let elapsed = started.elapsed();
    let reported_pending = cancel
        .as_ref()
        .is_err_and(|message| message.starts_with("login_group_custody_unresolved:"))
        && elapsed >= group::STOP_DRAIN_BUDGET;
    let retained_before_recovery = fixture.owner.as_ref().is_some_and(|owner| {
        owner.recovery_pending_for_test() && !owner.hard_unresolved_for_test()
    }) && gate.pending_logins().unwrap().len() == 1;
    let falsely_drained = runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(100), drain.wait())
            .await
            .is_ok_and(|result| result.is_ok())
    });
    fixture.refusal.store(false, Ordering::Release);
    let until = Instant::now() + SETUP;
    while Instant::now() < until {
        fixture.poll().unwrap();
        if fixture.retire_if_finalized() {
            break;
        }
        if fixture.owner.as_ref().is_some_and(|owner| {
            !owner.recovery_pending_for_test() && owner.reaped_status().is_none()
        }) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let actually_killed = fixture
        .actual_status
        .is_some_and(|status| status.signal() == Some(libc::SIGKILL));
    let retired = fixture.owner.is_none() && gate.pending_logins().unwrap().is_empty();
    let drained_after_recovery = runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(100), drain.wait())
            .await
            .is_ok_and(|result| result.is_ok())
    });
    eprintln!("JOB_QUIT_BOUNDED_OBSERVER_BEFORE_PRIVATE_CLEANUP: cancel={cancel:?}; elapsed={elapsed:?}; retained={retained_before_recovery}; falsely_drained={falsely_drained}; original_actually_killed={actually_killed}; retired={retired}; recovered_drain={drained_after_recovery}");
    fixture
        .cleanup()
        .unwrap_or_else(|error| panic!("{UNKNOWN}: {error}"));
    assert!(
        reported_pending
            && retained_before_recovery
            && !falsely_drained
            && actually_killed
            && retired
            && drained_after_recovery,
        "JOB_QUIT_OBSERVER_MUST_REPORT_WITHOUT_DISCARDING_LATER_RECOVERY"
    );
}
