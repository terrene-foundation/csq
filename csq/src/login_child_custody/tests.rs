// Synthetic owned native children only: no vendor, auth, network or keychain.
use super::*;
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::types::AccountNum;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const FIXTURE_ROLE: &str = "CSQ_PRIVATE_LOGIN_VENDOR_ROLE";
const FIXTURE_ROOT: &str = "CSQ_PRIVATE_LOGIN_VENDOR_ROOT";
const FIXTURE_ENTRY: &str = "login_child_custody::tests::owned_vendor_entry";

struct VendorControl {
    input: Option<ChildStdin>,
    root: PathBuf,
    sequence: u64,
}

impl VendorControl {
    fn ping_after_timeout(&mut self) -> bool {
        self.sequence += 1;
        let nonce = format!("owned-ping-{}", self.sequence);
        let command = format!("ping:{nonce}\n");
        let Some(input) = self.input.as_mut() else {
            return false;
        };
        if input
            .write_all(command.as_bytes())
            .and_then(|()| input.flush())
            .is_err()
        {
            return false;
        }
        poll_private(Duration::from_secs(5), || {
            std::fs::read(self.root.join("ping-ack")).ok().as_deref() == Some(nonce.as_bytes())
        })
    }

    fn release(&mut self, exit: i32) -> std::io::Result<()> {
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| std::io::Error::other("private control closed"))?;
        writeln!(input, "release:{exit}")?;
        input.flush()
    }

    fn close(&mut self) {
        self.input.take();
    }
}

impl Drop for VendorControl {
    fn drop(&mut self) {
        self.close();
    }
}

struct VendorFixture {
    child: Option<Child>,
    group: Option<group::GroupControl>,
    sandbox: Option<tempfile::TempDir>,
    reaped: bool,
    spawned_pid: u32,
}

impl VendorFixture {
    fn spawn(role: &str) -> std::io::Result<(Self, VendorControl)> {
        Self::spawn_with_stdout(role, None)
    }
    fn spawn_with_stdout(
        role: &str,
        stdout: Option<Stdio>,
    ) -> std::io::Result<(Self, VendorControl)> {
        let sandbox = tempfile::tempdir()?;
        let root = sandbox.path().to_path_buf();
        for name in ["home", "base", "config", "local", "appdata", "tmp", "bin"] {
            std::fs::create_dir(root.join(name))?;
        }
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .args([
                FIXTURE_ENTRY,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(&root)
            .env(FIXTURE_ROLE, role)
            .env(FIXTURE_ROOT, &root)
            .env("HOME", root.join("home"))
            .env("CSQ_HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("CSQ_BASE_DIR", root.join("base"))
            .env("CLAUDE_CONFIG_DIR", root.join("config"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("LOCALAPPDATA", root.join("local"))
            .env("APPDATA", root.join("appdata"))
            .env("TMPDIR", root.join("tmp"))
            .env("TEMP", root.join("tmp"))
            .env("TMP", root.join("tmp"))
            .env("PATH", root.join("bin"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(match stdout {
                Some(stdout) => stdout,
                None => Stdio::from(std::fs::File::create(root.join("stdout.log"))?),
            })
            .stderr(std::fs::File::create(root.join("stderr.log"))?);
        for key in ["SYSTEMROOT", "SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        let (mut child, group) = group::spawn_controlled_fixture_for_test(&mut command)?;
        let input = child.stdin.take();
        let spawned_pid = child.id();
        let fixture = Self {
            child: Some(child),
            group: Some(group),
            sandbox: Some(sandbox),
            reaped: false,
            spawned_pid,
        };
        Ok((
            fixture,
            VendorControl {
                input,
                root,
                sequence: 0,
            },
        ))
    }

    fn root(&self) -> &Path {
        self.sandbox.as_ref().expect("owned sandbox").path()
    }
    fn take_group(&mut self) -> group::GroupControl {
        self.group.take().expect("one owned group transfer")
    }
    fn take_child(&mut self) -> Child {
        self.child.take().expect("one owned child transfer")
    }
    fn record_helper_receipt<K>(
        &mut self,
        owner: &OwnedLoginChild<K>,
        result: &Result<ExitStatus, LoginChildRefusal>,
    ) -> Option<ExitStatus> {
        let result_status = match result {
            Ok(status) => Some(*status),
            Err(error) => error.status,
        };
        let status = owner.reaped_status()?;
        let shared = owner.shared_child();
        if shared.lock().ok()?.id() != self.spawned_pid || result_status != Some(status) {
            return None;
        }
        self.reaped = true;
        Some(status)
    }
    fn started(&self) -> bool {
        poll_private(Duration::from_secs(5), || {
            self.root().join("started").is_file()
                && std::fs::read_to_string(self.root().join("entry-reached")).ok()
                    == Some(self.spawned_pid.to_string())
        })
    }
    fn observe_driver(&mut self, control: &mut VendorControl) -> Result<ExitStatus, &'static str> {
        self.observe_driver_budget(control, Duration::from_secs(20))
    }
    fn observe_driver_budget(
        &mut self,
        control: &mut VendorControl,
        budget: Duration,
    ) -> Result<ExitStatus, &'static str> {
        let deadline = Instant::now() + budget;
        loop {
            match self.child.as_mut().expect("owned driver").try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    return Ok(status);
                }
                Ok(None) if Instant::now() < deadline => std::thread::yield_now(),
                _ => break,
            }
        }
        control.close();
        let cleanup = Instant::now() + Duration::from_secs(2);
        while Instant::now() < cleanup {
            if matches!(
                self.child.as_mut().expect("owned driver").try_wait(),
                Ok(Some(_))
            ) {
                self.reaped = true;
                break;
            }
            std::thread::yield_now();
        }
        self.keep_unknown();
        Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: owned driver observation unavailable")
    }
    fn completed(&self) -> bool {
        std::fs::read(self.root().join("transaction-completed"))
            .ok()
            .as_deref()
            == Some(&b"inert transaction completed\n"[..])
    }
    fn keep_unknown(&mut self) {
        if let Some(sandbox) = self.sandbox.take() {
            eprintln!(
                "LOGIN_FIXTURE_CUSTODY_UNKNOWN: {}",
                sandbox.keep().display()
            );
        }
    }
}

impl Drop for VendorFixture {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        if let Some(child) = self.child.as_mut() {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        self.reaped = true;
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => std::thread::yield_now(),
                    _ => break,
                }
            }
        }
        if !self.reaped {
            self.keep_unknown();
        }
    }
}

fn poll_private(budget: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::yield_now();
    }
}

#[test]
#[ignore = "private subprocess dispatcher"]
fn owned_vendor_entry() {
    let _env_guard = csq_core::platform::test_env::lock();
    let Some(role) = std::env::var_os(FIXTURE_ROLE) else {
        return;
    };
    let role = role.to_str().expect("private role");
    assert!(matches!(
        role,
        "hold"
            | "success"
            | "driver-post"
            | "driver-unknown"
            | "driver-success"
            | "driver-missing-eof"
            | "signal-target"
            | "hold-until-signal"
    ));
    let root = PathBuf::from(std::env::var_os(FIXTURE_ROOT).expect("private root"));
    assert!(root.is_dir());
    for (key, relative) in [
        ("HOME", "home"),
        ("CSQ_HOME", "home"),
        ("USERPROFILE", "home"),
        ("CSQ_BASE_DIR", "base"),
        ("CLAUDE_CONFIG_DIR", "config"),
        ("PATH", "bin"),
        ("TMPDIR", "tmp"),
        ("TEMP", "tmp"),
        ("TMP", "tmp"),
        ("APPDATA", "appdata"),
        ("LOCALAPPDATA", "local"),
    ] {
        assert_eq!(
            std::env::var_os(key).as_deref(),
            Some(root.join(relative).as_os_str())
        );
    }
    #[cfg(unix)]
    if role == "signal-target" {
        // Only this isolated synthetic child resets dispositions and disables
        // its own core dumps. No host/global/session signal policy is touched.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: valid initialized output/input structures and known signals.
        unsafe {
            assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &limit), 0);
            let mut signals: libc::sigset_t = std::mem::zeroed();
            assert_eq!(libc::sigemptyset(&mut signals), 0);
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                assert_ne!(libc::signal(signal, libc::SIG_DFL), libc::SIG_ERR);
                assert_eq!(libc::sigaddset(&mut signals, signal), 0);
            }
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()),
                0
            );
        }
    }
    // Reached entry is bound to this exact spawned Child ID before Started.
    std::fs::write(root.join("entry-reached"), std::process::id().to_string())
        .expect("entry receipt");
    std::fs::write(root.join("started"), b"owned native fixture ready\n").expect("started marker");
    #[cfg(unix)]
    if role == "driver-missing-eof" {
        match run_missing_captured_eof(&root) {
            Ok(proof) => {
                std::fs::write(root.join("missing-eof-proof"), proof).expect("missing EOF receipt");
                std::process::exit(0);
            }
            Err(error) => {
                std::fs::write(root.join("failure-marker"), error).expect("missing EOF failure");
                std::process::exit(8);
            }
        }
    }
    if role.starts_with("driver-") {
        match run_owned_waiter(role, &root) {
            Ok(proof) => {
                std::fs::write(root.join("reaped-proof"), proof).expect("actual receipt");
                std::process::exit(if role == "driver-success" { 0 } else { 7 });
            }
            Err(error) => {
                std::fs::write(root.join("failure-marker"), error).expect("failure receipt");
                std::process::exit(8);
            }
        }
    }
    if role == "success" {
        std::fs::write(
            root.join("transaction-completed"),
            b"inert transaction completed\n",
        )
        .expect("inert marker");
        std::process::exit(0);
    }
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            std::process::exit(91);
        };
        if let Some(nonce) = line.strip_prefix("ping:") {
            // Never panic on a transport error: a panicking child would exit
            // and read as a stopped one. The parent's 5s bound reports an
            // unanswered ping instead.
            if let Err(error) = std::fs::write(root.join("ping-ack"), nonce.as_bytes()) {
                eprintln!("PRIVATE_PING_ACK_WRITE_FAILED: {error}");
            }
        } else if let Some(code) = line.strip_prefix("release:") {
            let code = code.parse::<i32>().expect("private exit code");
            assert!(matches!(code, 0 | 7));
            std::fs::write(
                root.join("transaction-completed"),
                b"inert transaction completed\n",
            )
            .expect("inert marker");
            std::process::exit(code);
        } else {
            std::process::exit(92);
        }
    }
    if role == "hold-until-signal" {
        // Stdin EOF never ends this actor: only a signal (or the fixture's
        // retained-handle kill) can, so a "killed" status proves the stop.
        loop {
            std::thread::park();
        }
    }
    // Cooperative fixture cleanup is never graceful vendor/publication evidence.
    std::process::exit(90);
}

const RETAIN_ASSERTION: &str =
    "watchdog timeout must retain the live owned child until explicit release";

fn acquired(base: &Path) -> Result<AccountLoginLock, &'static str> {
    match AccountLoginLock::acquire(base, AccountNum::try_from(1_u16).expect("fixture account")) {
        Ok(AcquireOutcome::Acquired(guard)) => Ok(guard),
        _ => Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: could not acquire private account lock"),
    }
}

fn held(base: &Path) -> bool {
    matches!(
        AccountLoginLock::acquire(base, AccountNum::try_from(1_u16).expect("fixture account")),
        Ok(AcquireOutcome::Held { .. })
    )
}

fn join_controller<T>(handle: std::thread::JoinHandle<T>) -> Result<T, &'static str> {
    if !poll_private(Duration::from_secs(6), || handle.is_finished()) {
        return Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: controller not joined");
    }
    handle
        .join()
        .map_err(|_| "LOGIN_FIXTURE_CUSTODY_UNKNOWN: controller panicked")
}

fn run_owned_waiter(role: &str, receipt_root: &Path) -> Result<String, &'static str> {
    let base = receipt_root.join("base");
    let keepalive = acquired(&base)?;
    let success = role == "driver-success";
    let expected_kind = if role == "driver-post" {
        DeliveryKind::PostDelivery
    } else {
        DeliveryKind::Unknown
    };
    let (mut fixture, mut control) = VendorFixture::spawn(if success { "success" } else { "hold" })
        .map_err(|_| "LOGIN_FIXTURE_CUSTODY_UNKNOWN: child spawn failed")?;
    if !fixture.started() {
        control.close();
        return Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: exact selected vendor entry did not start");
    }
    let phase = if role == "driver-post" {
        DeliveryPhase::PostDelivery
    } else {
        DeliveryPhase::Unknown
    };
    let watchdog = LoginWatchdog::new(
        if success {
            login_timeout()
        } else {
            Duration::ZERO
        },
        phase,
    );
    let mut owner = OwnedLoginChild::adopt_group(
        fixture.take_child(),
        fixture.take_group(),
        watchdog.clone(),
        keepalive,
    );
    // Getter must preserve the reader proof; only the actual waiter may set it.
    let group = owner.group_control();
    let getter_preserved_reader_proof = !group.readers_joined();
    let pump_observation = Arc::new(Mutex::new(None));
    let actual_pump_observation = Arc::clone(&pump_observation);
    group.set_signal_pump(move |group| {
        let lease = group.check_wait_lease();
        *actual_pump_observation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((group.id(), lease.is_ok()));
        lease
    });
    // This binding drops before owner on every return/unwind, allowing private EOF cleanup.
    let mut control = control;
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let eof_cancelled = std::sync::Arc::clone(&cancelled);
    // Fixture-only lifetime thread. Never joined/graceful-vendor proof: process exit
    // ends it. Parent EOF asks the bounded policy controller to close vendor stdin.
    let _cleanup_thread = std::thread::Builder::new()
        .name("private-login-eof".into())
        .spawn(move || {
            let mut byte = [0_u8; 1];
            loop {
                match std::io::Read::read(&mut std::io::stdin(), &mut byte) {
                    Ok(0) | Err(_) => {
                        eof_cancelled.store(true, std::sync::atomic::Ordering::Release);
                        break;
                    }
                    Ok(_) => {}
                }
            }
        })
        .map_err(|_| "LOGIN_FIXTURE_CUSTODY_UNKNOWN: cleanup control thread unavailable")?;
    let mut notices = Vec::new();
    let mut controller_result = Ok(());
    let release_code = if role == "driver-unknown" { 0 } else { 7 };
    let result = if success {
        owner.wait_vendor(
            || Ok(true),
            |notice| notices.push(notice),
            || {
                Err(std::io::Error::other(
                    "UNKNOWN fixture must not receive graceful stop",
                ))
            },
        )
    } else {
        let (send, receive) = std::sync::mpsc::sync_channel::<TimeoutNotice>(1);
        let base_for_controller = base.clone();
        let controller = std::thread::spawn(move || -> Result<(), &'static str> {
            let deadline = Instant::now() + Duration::from_secs(5);
            let notice = loop {
                if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                    return Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: parent requested fixture cleanup");
                }
                match receive.try_recv() {
                    Ok(notice) => break notice,
                    Err(std::sync::mpsc::TryRecvError::Empty) if Instant::now() < deadline => {
                        std::thread::yield_now();
                    }
                    _ => return Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: timeout action not observed"),
                }
            };
            if notice.disposition != TimeoutDisposition::Retained {
                return Err(RETAIN_ASSERTION);
            }
            if notice.phase != expected_kind
                || notice.reason != RefusalReason::Timeout
                || notice.tag() != "login_timeout_refused"
            {
                return Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: wrong timeout action receipt");
            }
            if !held(&base_for_controller) {
                return Err("timeout must retain the actual account guard while child is live");
            }
            if !control.ping_after_timeout() {
                return Err(RETAIN_ASSERTION);
            }
            control
                .release(release_code)
                .map_err(|_| "LOGIN_FIXTURE_CUSTODY_UNKNOWN: release delivery failed")?;
            Ok(())
        });
        let result = owner.wait_vendor(
            || Ok(true),
            |notice| {
                let _ = send.send(notice);
            },
            || {
                Err(std::io::Error::other(
                    "POST/UNKNOWN fixture must not receive graceful stop",
                ))
            },
        );
        controller_result = join_controller(controller)?;
        result
    };
    // No externally set boolean or second Child::try_wait may create this proof.
    // The exact helper return receipt, actual owner getter and original Child ID agree.
    let status = fixture
        .record_helper_receipt(&owner, &result)
        .ok_or("LOGIN_FIXTURE_CUSTODY_UNKNOWN: no matching actual helper reap receipt")?;
    controller_result?;
    let publication = usize::from(result.as_ref().is_ok_and(|status| status.success()));
    if success {
        if !status.success()
            || result.is_err()
            || !notices.is_empty()
            || !fixture.completed()
            || publication != 1
        {
            return Err(
                "on-time owned vendor completion must authorize exactly one inert post callback",
            );
        }
    } else {
        let error = result
            .as_ref()
            .err()
            .ok_or("timed-out vendor must remain refused after actual exit")?;
        if error.reason != RefusalReason::Timeout
            || error.status != Some(status)
            || error.tag() != "login_timeout_refused"
            || publication != 0
        {
            return Err("timed-out vendor must not authorize canonical publication");
        }
        if status.code() != Some(release_code) || !fixture.completed() {
            return Err("released owned child must finish inert transaction before actual reap");
        }
    }
    let vendor_pid = fixture.spawned_pid;
    let finalized = owner.custody_finalized();
    let actual_refusal = watchdog.is_refused();
    let actual_pump_observation = *pump_observation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let ended_lease_refused = group.check_wait_lease().is_err();
    drop(owner);
    // Success means a new actual lock acquisition, not PID-sidecar absence.
    drop(acquired(&base)?);
    // Native original Child reap, cooperative transaction completion, controller
    // join and actual lock reacquisition above dominate every new semantic check.
    let controller_joined = if success { "not_applicable" } else { "true" };
    let cleanup_receipt = format!("vendor_pid={vendor_pid}\nvendor_code={:?}\nactual_original_child_reaped=true\nactual_controller_joined={controller_joined}\nactual_account_lock_reacquired=true\n", status.code());
    let mut cleanup_file = std::fs::File::create(receipt_root.join("portable-api-cleanup"))
        .map_err(|_| "LOGIN_FIXTURE_CUSTODY_UNKNOWN: portable API cleanup receipt unavailable")?;
    cleanup_file
        .write_all(cleanup_receipt.as_bytes())
        .and_then(|()| cleanup_file.sync_all())
        .map_err(|_| "LOGIN_FIXTURE_CUSTODY_UNKNOWN: portable API cleanup receipt unavailable")?;
    if !getter_preserved_reader_proof {
        return Err("LOGIN_PORTABLE_API_G01_GETTER_READER_PROOF");
    }
    if !finalized {
        return Err("LOGIN_PORTABLE_API_G02_ACTUAL_FINALIZATION");
    }
    if actual_refusal == success {
        return Err("LOGIN_PORTABLE_API_G03_ACTUAL_REFUSAL");
    }
    if actual_pump_observation != Some((vendor_pid, true)) {
        return Err("LOGIN_PORTABLE_API_G04_ACTUAL_LEASE_PUMP");
    }
    if !ended_lease_refused {
        return Err("LOGIN_PORTABLE_API_G05_ENDED_LEASE_REFUSAL");
    }
    Ok(format!("vendor_pid={vendor_pid}\nactual_reaped=true\nvendor_code={:?}\npublication={publication}\ncontroller_joined={controller_joined}\n", status.code()))
}

fn assert_owned_waiter_process(role: &str, exit: i32, vendor_code: i32, publication: usize) {
    let controller_joined = if role == "driver-success" {
        "not_applicable"
    } else {
        "true"
    };
    let _env_guard = csq_core::platform::test_env::lock();
    let (mut fixture, mut control) =
        VendorFixture::spawn(role).expect("spawn private owned waiter");
    if !fixture.started() {
        control.close();
        panic!("LOGIN_FIXTURE_CUSTODY_UNKNOWN: exact selected waiter entry did not start");
    }
    let status = fixture
        .observe_driver(&mut control)
        .unwrap_or_else(|error| panic!("{error}"));
    let failure = std::fs::read_to_string(fixture.root().join("failure-marker")).ok();
    match failure.as_deref() {
        Some(RETAIN_ASSERTION) => assert!(
            failure.as_deref() != Some(RETAIN_ASSERTION),
            "{RETAIN_ASSERTION}"
        ),
        Some(
            error @ ("LOGIN_PORTABLE_API_G01_GETTER_READER_PROOF"
            | "LOGIN_PORTABLE_API_G02_ACTUAL_FINALIZATION"
            | "LOGIN_PORTABLE_API_G03_ACTUAL_REFUSAL"
            | "LOGIN_PORTABLE_API_G04_ACTUAL_LEASE_PUMP"
            | "LOGIN_PORTABLE_API_G05_ENDED_LEASE_REFUSAL"),
        ) => {
            let cleanup = std::fs::read_to_string(fixture.root().join("portable-api-cleanup"))
                .expect("LOGIN_FIXTURE_CUSTODY_UNKNOWN: missing portable API cleanup receipt");
            let exact_code = format!("vendor_code=Some({vendor_code})\n");
            let vendor_pid = cleanup
                .lines()
                .next()
                .and_then(|line| line.strip_prefix("vendor_pid=")?.parse::<u32>().ok());
            if status.code() != Some(8)
                || vendor_pid.is_none_or(|pid| pid == 0)
                || !cleanup.contains(&exact_code)
                || !cleanup.contains("actual_original_child_reaped=true\n")
                || !cleanup.contains(&format!("actual_controller_joined={controller_joined}\n"))
                || !cleanup.contains("actual_account_lock_reacquired=true\n")
            {
                panic!("LOGIN_FIXTURE_CUSTODY_UNKNOWN: incomplete portable API cleanup proof");
            }
            eprintln!("\nLOGIN_PORTABLE_API_CLEANUP: actual_driver_reaped=true driver_code=8 actual_original_vendor_reaped=true vendor_code={vendor_code} actual_controller_joined={controller_joined} actual_account_lock_reacquired=true");
            let stderr = std::fs::read_to_string(fixture.root().join("stderr.log"))
                .expect("LOGIN_FIXTURE_CUSTODY_UNKNOWN: private driver diagnostics unavailable");
            for line in stderr.lines() {
                if matches!(
                    line,
                    "LOGIN_PORTABLE_API_MUTANT_REACHED_G01"
                        | "LOGIN_PORTABLE_API_MUTANT_REACHED_G02"
                        | "LOGIN_PORTABLE_API_MUTANT_REACHED_G03"
                        | "LOGIN_PORTABLE_API_MUTANT_REACHED_G04"
                        | "LOGIN_PORTABLE_API_MUTANT_REACHED_G05"
                ) {
                    eprintln!("{line}");
                }
            }
            panic!("{error}");
        }
        Some(error) => panic!("LOGIN_FIXTURE_CUSTODY_UNKNOWN: {error}"),
        None => {}
    }
    assert_eq!(
        status.code(),
        Some(exit),
        "actual owned waiter process must have the agreed exit"
    );
    let proof = std::fs::read_to_string(fixture.root().join("reaped-proof"))
        .expect("actual helper receipt must exist");
    assert!(
        proof.contains("actual_reaped=true\n")
            && proof.contains(&format!("controller_joined={controller_joined}\n")),
        "exact helper reap and controller join receipts are required"
    );
    assert!(proof.contains(&format!("vendor_code=Some({vendor_code})\n")));
    assert!(proof.contains(&format!("publication={publication}\n")));
    eprintln!("\nLOGIN_PORTABLE_API_CLEANUP: actual_driver_reaped=true driver_code={exit} actual_original_vendor_reaped=true vendor_code={vendor_code} actual_controller_joined={controller_joined} actual_account_lock_reacquired=true");
}

#[test]
fn post_timeout_retains_live_child_lock_then_reaps_and_exits_nonzero() {
    assert_owned_waiter_process("driver-post", 7, 7, 0);
}

#[test]
fn unknown_timeout_matches_post_and_late_zero_never_publishes() {
    assert_owned_waiter_process("driver-unknown", 7, 0, 0);
}

#[test]
fn on_time_completion_preserves_success_control() {
    assert_owned_waiter_process("driver-success", 0, 0, 1);
}

#[test]
fn expired_actual_completion_cannot_seal_on_time_success() {
    let _env_guard = csq_core::platform::test_env::lock();
    let (mut fixture, mut control) =
        VendorFixture::spawn("hold").expect("owned inert seal fixture");
    if !fixture.started() {
        control.close();
        panic!("LOGIN_FIXTURE_CUSTODY_UNKNOWN: exact seal fixture entry did not start");
    }
    // Constructor follows the actual Started barrier; no scheduler-duration assertion.
    let watchdog = LoginWatchdog::new(Duration::ZERO, DeliveryPhase::Unknown);
    control.release(0).expect("release inert completion");
    // This row isolates the actual seal method. The fixture is the sole reaper
    // here; the real Child status is supplied, never ExitStatusExt fabrication.
    let status = fixture
        .observe_driver(&mut control)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(status.code(), Some(0));
    assert!(fixture.completed());
    assert!(
        watchdog.refusal().is_none(),
        "no observer may pre-latch refusal for this regression"
    );
    let result = watchdog.seal_vendor(status);
    assert!(
        matches!(result, Err(LoginChildRefusal { reason: RefusalReason::Timeout, status: Some(actual), .. }) if actual == status),
        "expired vendor completion must never seal on-time success"
    );
}

#[test]
fn explicit_cancel_after_timeout_is_permitted_without_replacing_first_reason() {
    let watchdog = LoginWatchdog::new(Duration::ZERO, DeliveryPhase::Unknown);
    assert!(watchdog.observe_deadline());
    assert!(
        watchdog.refuse_cancelled(),
        "explicit cancel after timeout must remain permitted"
    );
    assert_eq!(
        watchdog.refusal().map(|error| error.reason),
        Some(RefusalReason::Timeout),
        "user cancel must preserve the first refusal reason"
    );
}

#[test]
fn explicit_cancel_seal_blocks_actual_late_success() {
    let _env_guard = csq_core::platform::test_env::lock();
    let (mut fixture, mut control) =
        VendorFixture::spawn("hold").expect("owned cancellation fixture");
    if !fixture.started() {
        control.close();
        panic!("LOGIN_FIXTURE_CUSTODY_UNKNOWN: cancellation fixture did not start");
    }
    let watchdog = LoginWatchdog::new(parse_timeout(None), DeliveryPhase::Unknown);
    assert!(
        watchdog.refuse_cancelled(),
        "running operation must permit confirmed cancel"
    );
    control
        .release(0)
        .expect("release actual cancelled fixture");
    let status = fixture
        .observe_driver(&mut control)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(status.code(), Some(0));
    assert!(
        matches!(watchdog.seal_vendor(status), Err(LoginChildRefusal { reason: RefusalReason::Cancelled, status: Some(actual), .. }) if actual == status),
        "confirmed cancel must prevent actual late success from publishing"
    );
}

#[test]
fn explicit_cancel_after_verified_on_time_completion_is_denied() {
    let _env_guard = csq_core::platform::test_env::lock();
    let (mut fixture, mut control) =
        VendorFixture::spawn("hold").expect("owned sealed cancellation fixture");
    if !fixture.started() {
        control.close();
        panic!("LOGIN_FIXTURE_CUSTODY_UNKNOWN: sealed fixture did not start");
    }
    control.release(0).expect("release actual on-time fixture");
    let status = fixture
        .observe_driver(&mut control)
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(status.code(), Some(0));
    let watchdog = LoginWatchdog::new(parse_timeout(None), DeliveryPhase::Unknown);
    assert!(watchdog.seal_vendor(status).is_ok());
    assert!(
        !watchdog.refuse_cancelled(),
        "verified on-time completion must deny later user cancel"
    );
    assert!(
        watchdog.refusal().is_none(),
        "user cancel must not unseal authorized completion"
    );
}

#[test]
fn deadline_overflow_refuses_spawn_authorization() {
    // Pure pre-spawn authorization: no vendor, subprocess or credentials.
    let overflow = LoginWatchdog::new(Duration::MAX, DeliveryPhase::Unknown);
    assert!(
        overflow.deadline().is_none(),
        "unrepresentable duration must have no usable child deadline"
    );
    let refusal = overflow
        .check_spawn_allowed()
        .expect_err("overflow must refuse child spawn authorization");
    assert_eq!(refusal.reason, RefusalReason::DeadlineOverflow);
    assert!(
        refusal.status.is_none(),
        "pre-spawn refusal must not fabricate an actual child reap"
    );
    let ordinary = LoginWatchdog::new(parse_timeout(None), DeliveryPhase::Unknown);
    assert!(
        ordinary.deadline().is_some(),
        "ordinary configured duration must produce a usable deadline"
    );
    assert!(
        ordinary.check_spawn_allowed().is_ok(),
        "ordinary watchdog must authorize spawn before vendor work begins"
    );
}

#[cfg(unix)]
#[test]
fn echild_is_immediate_terminal_refusal_decision() {
    let mut budget = group::ErrorBudget::default();
    assert_eq!(
        budget.record(&std::io::Error::from_raw_os_error(libc::ECHILD)),
        group::ErrorAction::LostLease
    );
}
#[cfg(unix)]
#[test]
fn exactly_three_consecutive_eio_require_owned_group_stop() {
    let mut budget = group::ErrorBudget::default();
    for _ in 0..2 {
        assert_eq!(
            budget.record(&std::io::Error::from_raw_os_error(libc::EIO)),
            group::ErrorAction::Continue
        );
    }
    assert_eq!(
        budget.record(&std::io::Error::from_raw_os_error(libc::EIO)),
        group::ErrorAction::StopGroup
    );
    budget.reset();
    assert_eq!(
        budget.record(&std::io::Error::from_raw_os_error(libc::EIO)),
        group::ErrorAction::Continue
    );
}
#[test]
fn timeout_notice_names_both_terminal_interrupt_actions() {
    let text = TimeoutNotice {
        phase: DeliveryKind::Unknown,
        disposition: TimeoutDisposition::Retained,
        reason: RefusalReason::Timeout,
    }
    .to_string();
    assert!(text.contains("in this terminal press Ctrl-C once"));
    assert!(text.contains("then again"));
    assert!(text.contains("deadline alone never kills"));
}

// Error injection reaches the SAME poll_child in production wait and Drop.
// The semantic RED recipe reverts ErrorBudget decisions, never this observer API.
#[cfg(unix)]
fn actual_owned_wait_error_case(drop_owner: bool, raw: i32) {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let _env_guard = csq_core::platform::test_env::lock();
    let (mut fixture, control) = VendorFixture::spawn("hold").expect("owned error fixture");
    assert!(fixture.started(), "exact private vendor must start");
    let watchdog = LoginWatchdog::new(Duration::from_secs(30), DeliveryPhase::Unknown);
    let mut owner = OwnedLoginChild::adopt_group(
        fixture.take_child(),
        fixture.take_group(),
        watchdog.clone(),
        (),
    );
    let child = owner.shared_child();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    owner.group.mark_readers_joined(); // fixture captures stdout/stderr to files, no readers
                                       // ECHILD is synthetic loss of our wait lease; cooperative fixture cleanup is
                                       // explicit and occurs after the actual production refusal under test.
    owner.set_wait_observer(move |group, child, joined| {
        let n = observed.fetch_add(1, Ordering::SeqCst) + 1;
        if raw == libc::ECHILD && n == 1 || raw == libc::EIO && n <= 3 {
            Err(std::io::Error::from_raw_os_error(raw))
        } else {
            group.try_reap(child, joined)
        }
    });
    // An external fixture controller bounds the semantic mutant: it releases the
    // inert vendor rather than killing any process on a deadline. It also gives
    // us an independently observed actual EOF transaction completion receipt.
    let controller = std::thread::spawn(move || {
        let mut control = control;
        let at = Instant::now() + Duration::from_secs(4);
        while Instant::now() < at {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = control.release(0);
    });
    let refused = if drop_owner {
        drop(owner);
        true
    } else {
        let refused = owner
            .wait_vendor_cancelled(|| Ok(true), |_| {}, || Ok(()), || false)
            .is_err();
        drop(owner);
        refused
    };
    let calls_seen = calls.load(Ordering::SeqCst);
    let uncertain = watchdog.custody_unresolved();
    let killed = raw == libc::EIO
        && child
            .lock()
            .expect("actual owned child")
            .try_wait()
            .expect("actual reap receipt")
            .is_some();
    controller
        .join()
        .expect("owned fixture controller completion");
    // Cleanup is outside the production outcome: only the original actual Child
    // is observed. Never signal a numeric PGID after synthetic ECHILD.
    let at = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child
            .lock()
            .expect("owned actual child")
            .try_wait()
            .expect("fixture reap")
        {
            break status;
        }
        assert!(
            Instant::now() < at,
            "LOGIN_FIXTURE_CUSTODY_UNKNOWN: actual child not reaped"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    fixture.reaped = true;
    assert!(refused, "wait errors must refuse publication");
    if raw == libc::ECHILD {
        assert_eq!(
            calls_seen, 1,
            "ECHILD must terminate production custody immediately"
        );
        assert!(uncertain, "lost wait lease must retain unfinalized custody");
        assert_eq!(
            status.code(),
            Some(0),
            "ECHILD must never signal numeric PGID"
        );
    } else {
        // Inspect the actual owned child's outcome before internal poll counts:
        // the unbounded-wait mutant survives until the fixture releases exit0.
        assert!(
            !status.success(),
            "three EIO must stop the owned vendor before cooperative fixture release"
        );
        assert_eq!(
            calls_seen, 3,
            "exactly three consecutive EIO must switch to owned group stop/native reap"
        );
        assert!(
            killed,
            "three EIO must stop and actually reap the owned writer"
        );
        assert!(
            !uncertain,
            "actual reap plus reader completion must finalize despite unknown membership"
        );
    }
}
#[cfg(unix)]
#[test]
fn production_wait_echild_terminal_and_no_signal() {
    actual_owned_wait_error_case(false, libc::ECHILD);
}
#[cfg(unix)]
#[test]
fn production_drop_echild_terminal_and_no_signal() {
    actual_owned_wait_error_case(true, libc::ECHILD);
}
#[cfg(unix)]
#[test]
fn production_wait_three_eio_stops_owned_group_and_reaps() {
    actual_owned_wait_error_case(false, libc::EIO);
}
#[cfg(unix)]
#[test]
fn production_drop_three_eio_stops_owned_group_and_reaps() {
    actual_owned_wait_error_case(true, libc::EIO);
}

#[test]
fn cloneable_cleanup_runs_only_after_actual_exit_and_reader_join() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct GrantProbe {
        watchdog: LoginWatchdog,
        group: group::GroupControl,
        receipt: Arc<AtomicUsize>,
    }
    impl Drop for GrantProbe {
        fn drop(&mut self) {
            let finalized = self.watchdog.reaped_status().is_some() && self.group.readers_joined();
            self.receipt
                .store(if finalized { 1 } else { 99 }, Ordering::SeqCst);
        }
    }
    let _env_guard = csq_core::platform::test_env::lock();
    let (mut fixture, mut control) =
        VendorFixture::spawn("hold").expect("owned cleanup-order fixture");
    assert!(fixture.started(), "actual private writer must start");
    let watchdog = LoginWatchdog::new(Duration::from_secs(30), DeliveryPhase::Unknown);
    let group = fixture.take_group();
    let receipt = Arc::new(AtomicUsize::new(0));
    let grant = Arc::new(GrantProbe {
        watchdog: watchdog.clone(),
        group: group.clone(),
        receipt: Arc::clone(&receipt),
    });
    let mut owner =
        OwnedLoginChild::adopt_group(fixture.take_child(), group, watchdog, Arc::clone(&grant));
    drop(grant); // early shared-wrapper drop cannot clean a still-owned writer grant
    assert_eq!(receipt.load(Ordering::SeqCst), 0);
    control
        .release(0)
        .expect("cooperatively finish actual writer");
    let result = owner.wait_vendor(|| Ok(true), |_| {}, || Ok(()));
    let status = fixture.record_helper_receipt(&owner, &result);
    drop(owner);
    assert_eq!(status.and_then(|s| s.code()), Some(0));
    assert_eq!(
        receipt.load(Ordering::SeqCst),
        1,
        "final clone cleanup must follow actual writer reap and reader joins"
    );
}

#[cfg(unix)]
fn finish_missing_eof_fixture(
    fixture: &mut VendorFixture,
    control: &mut VendorControl,
) -> Result<ExitStatus, &'static str> {
    let _ = control.release(0);
    control.close();
    let child = fixture
        .child
        .as_mut()
        .ok_or("missing EOF fixture child custody unavailable")?;
    let mut status = None;
    let ended = poll_private(Duration::from_secs(3), || {
        status = child.try_wait().ok().flatten();
        status.is_some()
    });
    if !ended {
        // Cleanup fallback uses only this actual retained Child, never a PGID.
        let _ = child.kill();
        poll_private(Duration::from_secs(2), || {
            status = child.try_wait().ok().flatten();
            status.is_some()
        });
    }
    if let Some(status) = status {
        fixture.reaped = true;
        Ok(status)
    } else {
        fixture.keep_unknown();
        if let Some(child) = fixture.child.take() {
            std::mem::forget(child);
        }
        Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: actual sibling cleanup not confirmed")
    }
}

#[cfg(unix)]
fn run_missing_captured_eof(root: &Path) -> Result<String, &'static str> {
    use std::io::Read;
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let base = root.join("base");
    let guard = acquired(&base)?;
    let (mut read_end, writer) =
        UnixStream::pair().map_err(|_| "private captured socket failed")?;
    let vendor_fd: OwnedFd = writer
        .try_clone()
        .map_err(|_| "private captured writer clone failed")?
        .into();
    let (mut vendor, mut vendor_control) =
        VendorFixture::spawn_with_stdout("hold", Some(Stdio::from(vendor_fd)))
            .map_err(|_| "private captured vendor spawn failed")?;
    let holder_fd: OwnedFd = writer.into(); // both parent writer ends transferred, no raw FD detach
    let (mut holder, mut holder_control) =
        match VendorFixture::spawn_with_stdout("hold", Some(Stdio::from(holder_fd))) {
            Ok(pair) => pair,
            Err(_) => {
                let _ = finish_missing_eof_fixture(&mut vendor, &mut vendor_control);
                return Err("private sibling writer spawn failed");
            }
        };
    if !vendor.started() || !holder.started() {
        let _ = finish_missing_eof_fixture(&mut vendor, &mut vendor_control);
        let _ = finish_missing_eof_fixture(&mut holder, &mut holder_control);
        return Err("private captured vendor/sibling exact entry unavailable");
    }
    // SAFETY: these actual retained children have not been reaped; no signals.
    let groups = unsafe {
        (
            libc::getpgid(vendor.spawned_pid as libc::pid_t),
            libc::getpgid(holder.spawned_pid as libc::pid_t),
        )
    };
    let separate_sibling = groups.0 == vendor.spawned_pid as libc::pid_t
        && groups.1 == holder.spawned_pid as libc::pid_t
        && groups.0 != groups.1;
    let eof = Arc::new(AtomicBool::new(false));
    let saw_eof = Arc::clone(&eof);
    let mut reader = Some(std::thread::spawn(move || -> std::io::Result<()> {
        let mut bytes = [0u8; 512];
        let mut total = 0usize;
        loop {
            let size = read_end.read(&mut bytes)?;
            if size == 0 {
                saw_eof.store(true, Ordering::Release);
                return Ok(());
            }
            total += size;
            if total > 1_048_576 {
                return Err(std::io::Error::other(
                    "private captured output exceeds bound",
                ));
            }
        }
    }));
    let cleanup_allowed = Arc::new(AtomicBool::new(false));
    let allowed = Arc::clone(&cleanup_allowed);
    let forced_release = Arc::new(AtomicBool::new(false));
    let forced = Arc::clone(&forced_release);
    let controller = std::thread::spawn(move || {
        // The barrier, rather than an exact timing assertion, proves production
        // returned while the sibling still retained its captured writer.
        if !poll_private(Duration::from_secs(6), || allowed.load(Ordering::Acquire)) {
            forced.store(true, Ordering::Release);
        }
        finish_missing_eof_fixture(&mut holder, &mut holder_control)
    });
    struct RetainedGrant {
        _lock: AccountLoginLock,
        dropped: Arc<AtomicBool>,
        marker: PathBuf,
    }
    impl Drop for RetainedGrant {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
            let _ = std::fs::write(&self.marker, b"modeled cleanup ran\n");
        }
    }
    let cleanup_dropped = Arc::new(AtomicBool::new(false));
    let cleanup_marker = root.join("modeled-cleanup");
    let watchdog = LoginWatchdog::new(Duration::from_secs(30), DeliveryPhase::Unknown);
    let group = vendor.take_group();
    let mut owner = OwnedLoginChild::adopt_group(
        vendor.take_child(),
        group.clone(),
        watchdog.clone(),
        RetainedGrant {
            _lock: guard,
            dropped: Arc::clone(&cleanup_dropped),
            marker: cleanup_marker.clone(),
        },
    );
    let original = owner.shared_child();
    let signal_ok = group.signal(group::GroupSignal::Kill).is_ok();
    let mut joined = false;
    let result = owner.wait_vendor_cancelled(
        || {
            if reader
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            {
                joined = matches!(
                    reader.take().expect("one captured reader").join(),
                    Ok(Ok(()))
                );
            }
            Ok(joined)
        },
        |_| {},
        || Ok(()),
        || true,
    );
    let refusal_text = result
        .as_ref()
        .err()
        .map(ToString::to_string)
        .unwrap_or_default();
    let publication = usize::from(result.is_ok());
    let returned_before_release = !forced_release.load(Ordering::Acquire);
    let eof_before_cleanup = eof.load(Ordering::Acquire);
    let falsely_joined = group.readers_joined();
    let uncertain = watchdog.custody_unresolved();
    drop(owner); // production must retain K itself; no outer Arc<K> exists
    let retained_actual_lock = held(&base);
    let cleanup_ran_early = cleanup_dropped.load(Ordering::Acquire) || cleanup_marker.exists();
    cleanup_allowed.store(true, Ordering::Release);
    let sibling_status = join_controller(controller).and_then(|status| status);
    let reader_completed = if let Some(reader) = reader.take() {
        if poll_private(Duration::from_secs(3), || reader.is_finished()) {
            matches!(reader.join(), Ok(Ok(())))
        } else {
            std::mem::forget(reader);
            false
        }
    } else {
        joined
    };
    vendor_control.close();
    let mut vendor_status = None;
    poll_private(Duration::from_secs(3), || {
        vendor_status = original
            .lock()
            .ok()
            .and_then(|mut child| child.try_wait().ok().flatten());
        vendor_status.is_some()
    });
    if vendor_status.is_none() {
        if let Ok(mut child) = original.lock() {
            let _ = child.kill();
        }
        poll_private(Duration::from_secs(2), || {
            vendor_status = original
                .lock()
                .ok()
                .and_then(|mut child| child.try_wait().ok().flatten());
            vendor_status.is_some()
        });
    }
    if vendor_status.is_some() {
        vendor.reaped = true;
    }
    // ALL semantic assertions follow actual child/reader/controller cleanup.
    if sibling_status.is_err()
        || vendor_status.is_none()
        || !reader_completed
        || !eof.load(Ordering::Acquire)
    {
        vendor.keep_unknown();
        return Err("LOGIN_FIXTURE_CUSTODY_UNKNOWN: captured fixture cleanup incomplete");
    }
    if !separate_sibling || !signal_ok {
        return Err("actual outside-group sibling / owned group signal prerequisite failed");
    }
    // These are externally observable ownership effects, not merely an
    // internal flag comparison: wrong early EOF/cleared UND must expose the
    // actual account lock or run the modeled cleanup before real captured EOF.
    if !retained_actual_lock || cleanup_ran_early {
        return Err("MISSING_EOF_LOCK: production dropped actual account lock or cleanup K before captured EOF");
    }
    if !returned_before_release || eof_before_cleanup || falsely_joined {
        return Err(
            "MISSING_EOF_REFUSAL: stop must terminate custody without fabricating captured EOF",
        );
    }
    if publication != 0 || !uncertain || !refusal_text.contains("login_custody_UNDETERMINED") {
        return Err("MISSING_EOF_REFUSAL: incomplete captured reader must refuse publication with custody PGID");
    }
    // The fixed production intentionally mem::forget's retained K: this isolated
    // driver proves retention until process exit, not a recovery engine.
    Ok(format!("actual_vendor_reaped=true\nactual_sibling_reaped=true\nactual_reader_eof_joined=true\npublication={publication}\nactual_lock_retained=true\ncleanup_probe=modeled_only\nretention_until=driver_process_exit\n"))
}

#[cfg(unix)]
#[test]
fn missing_captured_eof_after_explicit_stop_retains_actual_account_lock() {
    let _env_guard = csq_core::platform::test_env::lock();
    let (mut driver, mut control) =
        VendorFixture::spawn("driver-missing-eof").expect("isolated missing EOF driver");
    let started = driver.started();
    // Covers the nested Started/controller/reader/actual-child cleanup caps.
    let status = driver.observe_driver_budget(&mut control, Duration::from_secs(40));
    let failure = std::fs::read_to_string(driver.root().join("failure-marker")).ok();
    let proof =
        std::fs::read_to_string(driver.root().join("missing-eof-proof")).unwrap_or_default();
    assert!(started, "exact isolated driver entry must start");
    assert!(
        status.is_ok_and(|s| s.code() == Some(0)),
        "{}",
        failure.unwrap_or_else(|| "missing actual driver reap".into())
    );
    assert!(
        proof.contains("actual_vendor_reaped=true\n")
            && proof.contains("actual_sibling_reaped=true\n")
            && proof.contains("actual_reader_eof_joined=true\n")
    );
    assert!(proof.contains("publication=0\n") && proof.contains("actual_lock_retained=true\n"));
}

#[cfg(unix)]
fn actual_signal_pump_case(drop_owner: bool, requested: group::GroupSignal, expected_signal: i32) {
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let _env_guard = csq_core::platform::test_env::lock();
    let (mut fixture, control) =
        VendorFixture::spawn("signal-target").expect("actual signal-pump target");
    let started = fixture.started();
    let base = fixture.root().join("base");
    let guard = acquired(&base).expect("actual account custody for signal fixture");
    let watchdog = LoginWatchdog::new(Duration::from_secs(30), DeliveryPhase::Unknown);
    let mut owner = OwnedLoginChild::adopt_group(
        fixture.take_child(),
        fixture.take_group(),
        watchdog.clone(),
        guard,
    );
    let child = owner.shared_child();
    let group = owner.group_control();
    let group_matches_child = group.id() == fixture.spawned_pid;
    let valid_lease_before = group.check_wait_lease().is_ok();
    let finalized_before = owner.custody_finalized();
    let refused_before = watchdog.is_refused();
    let lock_held_before = held(&base);
    group.mark_readers_joined(); // stdout/stderr are files: no captured reader exists
    let delivered = Arc::new(AtomicBool::new(false));
    let callback_ran = Arc::clone(&delivered);
    let mut sent = false;
    group.set_signal_pump(move |group| {
        if !sent {
            // The same pump is called by production wait AND production Drop.
            group.check_wait_lease()?;
            group.signal(requested)?;
            callback_ran.store(true, Ordering::Release);
            sent = true;
        }
        Ok(())
    });
    // Cooperative lifeline bounds a missing-pump/forwarding semantic mutant.
    // It never kills on time; only this original Child reads its release pipe.
    let operation_finished = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&operation_finished);
    let controller = std::thread::spawn(move || {
        let mut control = control;
        let until = Instant::now() + Duration::from_secs(4);
        while !finished.load(Ordering::Acquire) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = control.release(0);
    });
    let cancelled = watchdog.refuse_cancelled();
    let (publication, finalized_after) = if drop_owner {
        drop(owner);
        (0, None)
    } else {
        let result = owner.wait_vendor_cancelled(|| Ok(true), |_| {}, || Ok(()), || true);
        let publication = usize::from(result.is_ok());
        let finalized = owner.custody_finalized();
        drop(owner);
        (publication, Some(finalized))
    };
    let production_status = watchdog.reaped_status();
    operation_finished.store(true, Ordering::Release);
    controller
        .join()
        .expect("actual signal fixture controller joined");
    let mut actual = None;
    poll_private(Duration::from_secs(3), || {
        actual = child
            .lock()
            .ok()
            .and_then(|mut child| child.try_wait().ok().flatten());
        actual.is_some()
    });
    if actual.is_none() {
        // Failure cleanup owns this exact Child handle; never signal a reused PGID.
        if let Ok(mut child) = child.lock() {
            let _ = child.kill();
        }
        poll_private(Duration::from_secs(2), || {
            actual = child
                .lock()
                .ok()
                .and_then(|mut child| child.try_wait().ok().flatten());
            actual.is_some()
        });
    }
    if actual.is_some() {
        fixture.reaped = true;
    } else {
        fixture.keep_unknown();
    }
    let lease_after = group.check_wait_lease().is_err();
    let refused_after = watchdog.is_refused();
    let lock_released = acquired(&base).is_ok();
    // Every behavioral assertion follows actual target cleanup and controller join.
    assert!(
        actual.is_some(),
        "SIGNAL_PUMP_CUSTODY_UNKNOWN: actual target not reaped"
    );
    assert!(
        started && group_matches_child && valid_lease_before,
        "SIGNAL_PUMP_OWNED_IDENTITY"
    );
    assert!(
        !finalized_before && !refused_before && lock_held_before,
        "SIGNAL_PUMP_PRE_FINALIZATION"
    );
    assert!(
        cancelled && delivered.load(Ordering::Acquire),
        "SIGNAL_PUMP_DISPATCH_REACHED"
    );
    assert_eq!(
        actual.and_then(|status| status.signal()),
        Some(expected_signal),
        "SIGNAL_PUMP_TYPED_SIGNAL_REAP"
    );
    assert_eq!(
        production_status, actual,
        "SIGNAL_PUMP_PRODUCTION_REAP_RECEIPT"
    );
    assert!(
        lease_after,
        "SIGNAL_PUMP_LEASE_ENDED_NO_REUSED_PGID_AUTHORITY"
    );
    assert!(
        refused_after && publication == 0 && lock_released,
        "SIGNAL_PUMP_REFUSED_AND_FINALIZED_CLEANUP"
    );
    if let Some(finalized) = finalized_after {
        assert!(finalized, "SIGNAL_PUMP_FINALIZED_ERROR_RECEIPT");
    }
}

#[cfg(unix)]
#[test]
fn production_wait_pump_forwards_owned_interrupt_term_hup_quit() {
    for (signal, native) in [
        (group::GroupSignal::Interrupt, libc::SIGINT),
        (group::GroupSignal::Terminate, libc::SIGTERM),
        (group::GroupSignal::Hangup, libc::SIGHUP),
        (group::GroupSignal::Quit, libc::SIGQUIT),
    ] {
        actual_signal_pump_case(false, signal, native);
    }
}
#[cfg(unix)]
#[test]
fn production_drop_pump_forwards_owned_interrupt_term_hup_quit() {
    for (signal, native) in [
        (group::GroupSignal::Interrupt, libc::SIGINT),
        (group::GroupSignal::Terminate, libc::SIGTERM),
        (group::GroupSignal::Hangup, libc::SIGHUP),
        (group::GroupSignal::Quit, libc::SIGQUIT),
    ] {
        actual_signal_pump_case(true, signal, native);
    }
}

// Empty-group gate: try_reap SIGKILLs the exited leader's group, then
// finalizes only when the census finds no live member besides the leader.
#[cfg(unix)]
struct CensusRun {
    refusal: Option<LoginChildRefusal>,
    finalized: bool,
    unresolved: bool,
    elapsed: Duration,
}

#[cfg(unix)]
fn census_gate_run(
    script: &str,
    args: &[&str],
    census: Option<group::GroupCensus>,
    cancel: bool,
    in_group: impl FnOnce(u32) -> Option<Child>,
) -> CensusRun {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", script, "census-leader"])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let (child, group) =
        group::spawn_controlled_fixture_for_test(&mut command).expect("spawn census leader");
    let pgid = group.id();
    let member = in_group(pgid);
    let watchdog = LoginWatchdog::new(Duration::from_secs(30), DeliveryPhase::Unknown);
    let mut owner = OwnedLoginChild::adopt_group(child, group, watchdog, ());
    let shared = owner.shared_child();
    group::inject_census_for_test(census);
    let started = Instant::now();
    let result = owner.wait_vendor_cancelled(|| Ok(true), |_| {}, || Ok(()), move || cancel);
    let elapsed = started.elapsed();
    group::inject_census_for_test(None);
    let run = CensusRun {
        refusal: result.err(),
        finalized: owner.custody_finalized(),
        unresolved: owner.watchdog.custody_unresolved(),
        elapsed,
    };
    if owner.reaped_status().is_none() {
        // Test-only cleanup: the unreaped leader still reserves this PGID.
        // SAFETY: plain group signal to our own retained group.
        unsafe { libc::kill(-(pgid as libc::pid_t), libc::SIGKILL) };
        let _ = shared.lock().expect("census child").wait();
    }
    drop(owner);
    if let Some(mut member) = member {
        let _ = member.wait();
    }
    run
}

// Dead = gone (ESRCH) or, on Linux, a zombie awaiting its reaper.
#[cfg(unix)]
fn pid_dead(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only probes existence.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
    }
    #[cfg(target_os = "linux")]
    if let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat")) {
        if let Some(close) = stat.iter().rposition(|byte| *byte == b')') {
            return matches!(stat.get(close + 2), Some(b'Z' | b'X'));
        }
    }
    false
}

// A same-uid helper the vendor left running in its group (pipes closed) is
// killed by the freeze, and sign-in finalizes; before the freeze it refused.
#[cfg(unix)]
#[test]
fn leftover_group_helper_is_killed_and_sign_in_finalizes() {
    let sandbox = tempfile::tempdir().expect("census helper sandbox");
    let pidfile = sandbox.path().join("helper.pid");
    let pidfile_arg = pidfile.to_str().expect("utf-8 sandbox path");
    let run = census_gate_run(
        "sleep 30 </dev/null >/dev/null 2>&1 & echo $! > \"$1\"; exit 0",
        &[pidfile_arg],
        None,
        false,
        |_| None,
    );
    let helper: libc::pid_t = std::fs::read_to_string(&pidfile)
        .expect("helper pid")
        .trim()
        .parse()
        .expect("numeric helper pid");
    let dead = poll_private(Duration::from_secs(5), || pid_dead(helper));
    if !dead {
        // SAFETY: test-only cleanup of the helper this test started.
        unsafe { libc::kill(helper, libc::SIGKILL) };
    }
    assert!(
        run.refusal.is_none() && run.finalized && !run.unresolved && dead,
        "FROZEN_HELPER_MUST_DIE_AND_FINALIZE: refusal={:?} finalized={} unresolved={} helper_dead={dead}",
        run.refusal.map(|r| r.reason),
        run.finalized,
        run.unresolved,
    );
}

// A non-leader ZOMBIE member (exited, unreaped by its parent — this test —
// still in the group) is not live: the cancel finalizes.
#[cfg(unix)]
#[test]
fn cancel_with_zombie_only_group_finalizes() {
    use std::os::unix::process::CommandExt;
    let mut zombie_in_group = false;
    let run = census_gate_run("sleep 0.5; exit 0", &[], None, true, |pgid| {
        let mut member = Command::new("/usr/bin/true");
        member
            .process_group(pgid as i32)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let member = member.spawn().expect("spawn group member");
        let exited = poll_private(Duration::from_secs(5), || {
            group::observe_owned_unreaped_for_test(&member).unwrap_or(false)
        });
        // SAFETY: getpgid on our own unreaped child.
        let member_pgid = unsafe { libc::getpgid(member.id() as libc::pid_t) };
        zombie_in_group =
            exited && (cfg!(target_os = "macos") || member_pgid == pgid as libc::pid_t);
        Some(member)
    });
    assert!(
        zombie_in_group && run.finalized && !run.unresolved,
        "CENSUS_ZOMBIE_ONLY_MUST_FINALIZE: zombie_in_group={zombie_in_group} finalized={} unresolved={}",
        run.finalized,
        run.unresolved,
    );
}

#[cfg(unix)]
#[test]
fn cancel_with_undetermined_census_does_not_finalize() {
    let run = census_gate_run(
        "exit 0",
        &[],
        Some(group::GroupCensus::Undetermined("injected")),
        true,
        |_| None,
    );
    assert!(
        run.refusal.is_some() && !run.finalized && run.unresolved,
        "CENSUS_UNDETERMINED_MUST_RETAIN_CUSTODY: refused={} finalized={} unresolved={}",
        run.refusal.is_some(),
        run.finalized,
        run.unresolved,
    );
}

// A survivor that outlives the freeze refuses after an ELAPSED budget equal to
// STOP_DRAIN_BUDGET (never a poll count), naming the census as the cause.
#[cfg(unix)]
#[test]
fn surviving_census_refuses_after_elapsed_budget_naming_census() {
    let run = census_gate_run(
        "exit 0",
        &[],
        Some(group::GroupCensus::Survivor(vec![1])),
        false,
        |_| None,
    );
    let reason = run.refusal.map(|r| r.reason);
    assert!(
        reason == Some(RefusalReason::GroupCensus)
            && !run.finalized
            && run.unresolved
            && run.elapsed >= group::STOP_DRAIN_BUDGET,
        "CENSUS_BUDGET_ELAPSED_AND_NAMED: reason={reason:?} finalized={} unresolved={} elapsed={:?}",
        run.finalized,
        run.unresolved,
        run.elapsed,
    );
}

// This lower-level production-group row retains the direct vendor unreaped
// until independent fixture cleanup. It does not claim descendant wait/reap.
// Match the actual API availability in main tests and source-including tests:
// Windows desktop-feature integration crates must exercise the same real API.
#[cfg(any(feature = "desktop", unix))]
mod finalized_stop_receipt_tests {
    use super::*;
    use std::io;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    // Reuse the existing env_clear, private-home, stdin-controlled inert actor.
    // This guard owns the ORIGINAL Child and real stdout reader on every path.
    struct FinalizedFixture {
        fixture: VendorFixture,
        control: VendorControl,
        reader: Option<std::thread::JoinHandle<io::Result<()>>>,
        eof: Arc<AtomicBool>,
        reader_joined: bool,
        status: Option<ExitStatus>,
    }

    impl FinalizedFixture {
        fn spawn() -> io::Result<Self> {
            Self::spawn_role("hold")
        }

        fn spawn_role(role: &str) -> io::Result<Self> {
            let (fixture, control) = VendorFixture::spawn_with_stdout(role, Some(Stdio::piped()))?;
            let mut owned = Self {
                fixture,
                control,
                reader: None,
                eof: Arc::new(AtomicBool::new(false)),
                reader_joined: false,
                status: None,
            };
            let mut stdout = owned
                .fixture
                .child
                .as_mut()
                .and_then(|child| child.stdout.take())
                .ok_or_else(|| io::Error::other("private captured stdout missing"))?;
            let eof = Arc::clone(&owned.eof);
            owned.reader = Some(
                std::thread::Builder::new()
                    .name("finalized-receipt-stdout".into())
                    .spawn(move || {
                        io::copy(&mut stdout, &mut io::sink())?;
                        eof.store(true, Ordering::Release);
                        Ok(())
                    })?,
            );
            if !owned.fixture.started() {
                return Err(io::Error::other("private exact vendor entry unavailable"));
            }
            Ok(owned)
        }

        fn group(&self) -> group::GroupControl {
            self.fixture.group.as_ref().expect("original group").clone()
        }

        fn join_reader(&mut self) -> io::Result<()> {
            if self.reader_joined {
                return Ok(());
            }
            let reader = self
                .reader
                .as_ref()
                .ok_or_else(|| io::Error::other("actual reader unavailable"))?;
            if !poll_private(Duration::from_secs(3), || reader.is_finished()) {
                return Err(io::Error::other("actual reader completion unconfirmed"));
            }
            self.reader
                .take()
                .expect("finished reader retained")
                .join()
                .map_err(|_| io::Error::other("actual reader panicked"))??;
            if !self.eof.load(Ordering::Acquire) {
                return Err(io::Error::other("actual reader EOF unconfirmed"));
            }
            self.reader_joined = true;
            Ok(())
        }

        fn reap_joined(&mut self, mark_before_reap: bool) -> io::Result<ExitStatus> {
            if !self.reader_joined {
                return Err(io::Error::other("cannot reap before actual reader join"));
            }
            let group = self.group();
            if mark_before_reap {
                group.mark_readers_joined();
            }
            if let Some(status) = self.status {
                return Ok(status);
            }
            let child = self
                .fixture
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("original Child unavailable"))?;
            if child.id() != self.fixture.spawned_pid {
                return Err(io::Error::other("original Child identity changed"));
            }
            let mut observed = None;
            let mut failure = None;
            poll_private(Duration::from_secs(3), || {
                match group.try_reap(child, true) {
                    Ok(Some(status)) => {
                        observed = Some(status);
                        true
                    }
                    Ok(None) => false,
                    Err(error) => {
                        failure = Some(error);
                        true
                    }
                }
            });
            if let Some(error) = failure {
                return Err(error);
            }
            let status =
                observed.ok_or_else(|| io::Error::other("original Child reap unconfirmed"))?;
            self.status = Some(status);
            self.fixture.reaped = true;
            Ok(status)
        }

        fn finish(&mut self) -> io::Result<ExitStatus> {
            self.control.close();
            self.join_reader()?;
            let status = self.reap_joined(true)?;
            eprintln!(
                "FINALIZED_API_CLEANUP: original_pid={}; actual_status={status:?}; actual_eof=true; actual_reader_joined=true; fallback=false",
                self.fixture.spawned_pid
            );
            Ok(status)
        }
    }

    impl Drop for FinalizedFixture {
        fn drop(&mut self) {
            if self.status.is_some() && self.reader_joined {
                return;
            }
            if self.finish().is_ok() {
                return;
            }
            self.control.close();
            // Descendant-free inert actor only; original retained handle,
            // never a numeric PID signal after reap or a vendor command.
            let needs_stop = self.status.is_none();
            if let Some(child) = self.fixture.child.as_mut().filter(|_| needs_stop) {
                let _ = child.kill();
            }
            let _ = self.join_reader();
            // If a reader is still live, preserve the unreaped original handle.
            // Otherwise account the original Child even if production refused.
            let needs_reap = self.reader.is_none() && self.status.is_none();
            if let Some(child) = self.fixture.child.as_mut().filter(|_| needs_reap) {
                poll_private(Duration::from_secs(3), || match child.try_wait() {
                    Ok(Some(status)) => {
                        self.status = Some(status);
                        self.fixture.reaped = true;
                        true
                    }
                    Ok(None) => false,
                    Err(_) => true,
                });
            }
            eprintln!(
                "FINALIZED_API_FALLBACK_CLEANUP: original_pid={}; actual_status={:?}; actual_eof={}; actual_reader_joined={}; reader_retained={}",
                self.fixture.spawned_pid,
                self.status,
                self.eof.load(Ordering::Acquire),
                self.reader_joined,
                self.reader.is_some()
            );
            if self.status.is_none() || self.reader.is_some() {
                self.fixture.keep_unknown();
                if let Some(child) = self.fixture.child.take() {
                    std::mem::forget(child);
                }
                if let Some(group) = self.fixture.group.take() {
                    std::mem::forget(group);
                }
                if let Some(reader) = self.reader.take() {
                    std::mem::forget(reader);
                }
                eprintln!("LOGIN_FIXTURE_CUSTODY_UNKNOWN: finalized API fallback incomplete; original owners retained");
            }
        }
    }

    #[test]
    fn live_stop_then_actual_reap_and_reader_join_issues_only_matching_receipt() {
        let _environment = csq_core::platform::test_env::lock();
        // The stopped actor ignores stdin EOF, so only the stop can end it.
        let mut stopped =
            FinalizedFixture::spawn_role("hold-until-signal").expect("private stopped actor");
        let mut other = FinalizedFixture::spawn().expect("private distinct actor");
        let stopped_group = stopped.group();
        let other_group = other.group();
        let original_pid = stopped.fixture.spawned_pid;
        let live_decision = stopped_group.request_stop_or_finalized(group::GroupSignal::Kill);
        // The stop must be OBSERVED (WNOWAIT: CLD_KILLED by SIGKILL) before any
        // stdin release or close, so EOF can never race the queued signal.
        #[cfg(unix)]
        {
            let mut seen = None;
            poll_private(Duration::from_secs(5), || {
                // SAFETY: plain C output struct, written by waitid below.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // SAFETY: WNOWAIT observation of our own unreaped direct Child.
                let rc = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        original_pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                #[cfg(target_os = "linux")]
                // SAFETY: waitid initialized the SIGCHLD arm.
                let (pid, status) = unsafe { (info.si_pid(), info.si_status()) };
                #[cfg(target_os = "macos")]
                let (pid, status) = (info.si_pid, info.si_status);
                if rc != 0 {
                    seen = Some(Err(io::Error::last_os_error().raw_os_error()));
                    return true;
                }
                if pid != 0 {
                    seen = Some(Ok((info.si_code, status)));
                }
                pid != 0
            });
            assert_eq!(
                seen,
                Some(Ok((libc::CLD_KILLED, libc::SIGKILL))),
                "FINALIZED_API_LIVE_STOP: kill not observed before release; decision_ok={}",
                live_decision.is_ok()
            );
        }
        let live_stop = matches!(live_decision, Ok(group::GroupStopDecision::StopRequested));
        let live_decision_error = live_decision.as_ref().err().map(ToString::to_string);
        other
            .control
            .release(0)
            .expect("cooperative distinct actor exit");
        // Every semantic check is deferred until BOTH real actors/readers end.
        let stopped_status = stopped.finish().expect("actual stopped actor completion");
        let other_status = other.finish().expect("actual distinct actor completion");
        let receipt_identity =
            match stopped_group.request_stop_or_finalized(group::GroupSignal::Kill) {
                Ok(group::GroupStopDecision::VendorFinalized(receipt)) => {
                    receipt.belongs_to(&stopped_group) && !receipt.belongs_to(&other_group)
                }
                _ => false,
            };
        let ended_native_authority_refused =
            stopped_group.signal(group::GroupSignal::Kill).is_err()
                && stopped_group.check_wait_lease().is_err();
        #[cfg(unix)]
        let killed = {
            use std::os::unix::process::ExitStatusExt;
            stopped_status.signal() == Some(libc::SIGKILL)
        };
        #[cfg(windows)]
        let killed = stopped_status.code() == Some(130);
        assert!(
            live_stop
                && killed
                && other_status.code() == Some(0)
                && original_pid == stopped_group.id()
                && stopped_group.id() != other_group.id(),
            "FINALIZED_API_LIVE_STOP_MUST_STOP_AND_REAP_ORIGINAL_CHILD: live_stop={live_stop}; live_error={live_decision_error:?}; stopped_status={stopped_status:?}; other_status={other_status:?}; original_pid={original_pid}; stopped_id={}; other_id={}",
            stopped_group.id(),
            other_group.id()
        );
        assert!(
            receipt_identity && ended_native_authority_refused,
            "FINALIZED_API_RECEIPT_MUST_BIND_EXACT_GROUP_AFTER_REAL_JOIN_AND_REAP"
        );
    }

    // Darwin: a stop requested after the leader exited (zombie-only group,
    // still unreaped) must be a no-op, not EPERM. Reds on darwin without the
    // signal_with_lease zombie-only branch; Linux kill accepts zombies anyway.
    #[cfg(unix)]
    #[test]
    fn stop_after_leader_exit_before_reap_is_not_an_error() {
        let _environment = csq_core::platform::test_env::lock();
        let mut command = std::process::Command::new("/usr/bin/true");
        let (mut child, control) =
            group::spawn(&mut command, group::StdinPolicy::Null).expect("spawn exiting leader");
        let pid = child.id();
        let exited = poll_private(Duration::from_secs(5), || {
            // SAFETY: plain C output struct, written by waitid below.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: WNOWAIT keeps our own direct Child unreaped.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            #[cfg(target_os = "linux")]
            // SAFETY: waitid initialized the SIGCHLD arm.
            let observed = unsafe { info.si_pid() };
            #[cfg(target_os = "macos")]
            let observed = info.si_pid;
            rc == 0 && observed != 0
        });
        let stop = control.signal(group::GroupSignal::Kill);
        let status = child.wait().expect("reap exited leader");
        assert!(exited, "leader exit not observed");
        assert!(stop.is_ok(), "zombie-only stop must be a no-op: {stop:?}");
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn actual_reap_before_reader_proof_cannot_issue_finalized_receipt() {
        let _environment = csq_core::platform::test_env::lock();
        let mut owned = FinalizedFixture::spawn().expect("private pending-reader-proof actor");
        let group = owned.group();
        owned
            .control
            .release(0)
            .expect("actual controlled zero exit");
        owned
            .join_reader()
            .expect("actual captured EOF and reader join");
        let no_reader_proof = matches!(
            group.try_reap(owned.fixture.child.as_mut().expect("original Child"), false),
            Ok(None)
        );
        // Actual EOF+join already happened. Delay only publication of its group
        // flag; the true try_reap argument never invents a live-reader success.
        let status = owned.reap_joined(false).expect("actual original zero reap");
        let pending_refused = group
            .request_stop_or_finalized(group::GroupSignal::Kill)
            .is_err()
            && !group.readers_joined()
            && group.kill_requested_at().is_none();
        group.mark_readers_joined();
        let final_identity = match group.request_stop_or_finalized(group::GroupSignal::Kill) {
            Ok(group::GroupStopDecision::VendorFinalized(receipt)) => receipt.belongs_to(&group),
            _ => false,
        };
        let final_no_native_stop = group.kill_requested_at().is_none()
            && group.signal(group::GroupSignal::Kill).is_err()
            && group.check_wait_lease().is_err();
        let actual_final = owned.finish().expect("final actual completion receipt");
        assert!(
            no_reader_proof
                && pending_refused
                && status.code() == Some(0)
                && actual_final == status,
            "FINALIZED_API_REAP_REQUIRES_READER_PROOF_BEFORE_RECEIPT"
        );
        assert!(
            final_identity && final_no_native_stop,
            "FINALIZED_API_LATE_JOIN_PROOF_MUST_FINALIZE_WITHOUT_NATIVE_SIGNAL"
        );
    }
}

#[cfg(unix)]
mod owned_group_causal {
    use super::*;
    use crate::login_child_custody::test_case_custody::CaseCustody;
    use std::io;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    const ENTRY: &str = "login_child_custody::tests::owned_group_causal::private_group_entry";
    const ROLE: &str = "CSQ_PRIVATE_GROUP_CAUSAL_ROLE";
    const ROOT: &str = "CSQ_PRIVATE_GROUP_CAUSAL_ROOT";
    const SEMANTIC: &str = "OWNED_GROUP_KILL_TRUE_DESCENDANT_BEFORE_CLEANUP";
    const UNKNOWN: &str = "OWNED_GROUP_CAUSAL_CUSTODY_UNKNOWN";
    const PANIC: &str = "OWNED_GROUP_CAUSAL_CONTROLLED_OBSERVER_PANIC";

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct Identity {
        pid: u32,
        parent: u32,
        group: i32,
        birth: String,
    }

    // Read only the exact test-owned native identities. A query failure is not
    // absence; numeric PID disappearance is termination evidence, never reap.
    #[cfg(target_os = "linux")]
    fn birth(pid: u32) -> io::Result<Option<String>> {
        let text = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let tail = text
            .rsplit_once(')')
            .ok_or_else(|| io::Error::other("invalid fixture stat"))?
            .1;
        let start = tail
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| io::Error::other("fixture birth missing"))?;
        Ok(Some(start.to_owned()))
    }
    #[cfg(target_os = "macos")]
    fn birth(pid: u32) -> io::Result<Option<String>> {
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID,
            i32::try_from(pid).map_err(|_| io::Error::other("fixture PID out of range"))?,
        ];
        let mut bytes = [0_u8; 2048];
        let mut len = bytes.len();
        // SAFETY: initialized query for this recorded fixture PID and writable
        // buffer. kinfo_proc begins with the process start timeval.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as _,
                bytes.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if len == 0 {
            return Ok(None);
        }
        if len < std::mem::size_of::<libc::timeval>() {
            return Err(io::Error::other("short fixture birth"));
        }
        // SAFETY: successful sysctl wrote at least one timeval; unaligned read.
        let start = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<libc::timeval>()) };
        if start.tv_sec == 0 {
            return Err(io::Error::other("zero fixture birth"));
        }
        Ok(Some(format!("{}:{}", start.tv_sec, start.tv_usec)))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn birth(_: u32) -> io::Result<Option<String>> {
        Err(io::Error::other("fixture native birth unsupported"))
    }
    fn gone(identity: &Identity) -> io::Result<bool> {
        Ok(birth(identity.pid)?.is_none_or(|current| current != identity.birth))
    }
    // The caller must first bind the queried identity's native birth and PGID.
    // A failed lookup never proves that identity gone: ESRCH is inconclusive
    // until a fresh successful query resolves it within the same deadline.
    fn observe_bound_termination(
        budget: Duration,
        mut query_gone: impl FnMut() -> io::Result<bool>,
        mut captured_eof: impl FnMut() -> bool,
    ) -> io::Result<(bool, bool)> {
        let mut error = None;
        let terminated = poll_private(budget, || match query_gone() {
            Ok(gone) => {
                error = None;
                gone && captured_eof()
            }
            Err(observation) => {
                let inconclusive = observation.raw_os_error() == Some(libc::ESRCH);
                error = Some(observation);
                !inconclusive
            }
        });
        match error {
            Some(error) => Err(error),
            None => Ok((terminated, captured_eof())),
        }
    }

    #[test]
    fn observer_requeries_esrch_before_crediting_definite_termination() {
        let mut queries = 0;
        let outcome = observe_bound_termination(
            Duration::from_secs(3),
            || {
                queries += 1;
                if queries == 1 {
                    Err(io::Error::from_raw_os_error(libc::ESRCH))
                } else {
                    Ok(true)
                }
            },
            || true,
        );
        assert!(
            outcome.is_ok_and(|value| value == (true, true)) && queries == 2,
            "BOUND_IDENTITY_OBSERVER_MUST_REQUERY_ESRCH"
        );
    }

    #[test]
    fn observer_does_not_credit_esrch_at_deadline() {
        let outcome = observe_bound_termination(
            Duration::ZERO,
            || Err(io::Error::from_raw_os_error(libc::ESRCH)),
            || true,
        );
        assert!(
            outcome.is_err_and(|error| error.raw_os_error() == Some(libc::ESRCH)),
            "BOUND_IDENTITY_OBSERVER_UNRESOLVED_ESRCH_IS_UNKNOWN"
        );
    }

    #[test]
    fn observer_does_not_credit_present_identity_even_with_eof() {
        let outcome = observe_bound_termination(Duration::ZERO, || Ok(false), || true);
        assert!(
            outcome.is_ok_and(|value| value == (false, true)),
            "BOUND_IDENTITY_OBSERVER_PRESENT_IDENTITY_IS_NOT_GONE"
        );
    }

    #[test]
    fn observer_requires_eof_after_definite_termination() {
        let outcome = observe_bound_termination(Duration::ZERO, || Ok(true), || false);
        assert!(
            outcome.is_ok_and(|value| value == (false, false)),
            "BOUND_IDENTITY_OBSERVER_DEFINITE_GONE_STILL_REQUIRES_EOF"
        );
    }

    #[test]
    fn observer_returns_other_query_errors_without_retry() {
        for code in [libc::EACCES, libc::EIO] {
            let mut queries = 0;
            let outcome = observe_bound_termination(
                Duration::from_secs(3),
                || {
                    queries += 1;
                    Err(io::Error::from_raw_os_error(code))
                },
                || true,
            );
            assert!(
                outcome.is_err_and(|error| error.raw_os_error() == Some(code)) && queries == 1,
                "BOUND_IDENTITY_OBSERVER_OTHER_ERRORS_ARE_IMMEDIATE_UNKNOWN"
            );
        }
    }

    fn atomic(root: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut pending = tempfile::NamedTempFile::new_in(root)?;
        pending.write_all(bytes)?;
        pending.flush()?;
        pending
            .persist(root.join(name))
            .map_err(|error| error.error)?;
        Ok(())
    }
    fn command(root: &Path, role: &str) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .args([
                ENTRY,
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(root)
            .env(ROLE, role)
            .env(ROOT, root)
            .env("HOME", root.join("home"))
            .env("CSQ_HOME", root.join("home"))
            .env("USERPROFILE", root.join("home"))
            .env("CSQ_BASE_DIR", root.join("base"))
            .env("CLAUDE_CONFIG_DIR", root.join("config"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("APPDATA", root.join("appdata"))
            .env("LOCALAPPDATA", root.join("local"))
            .env("PATH", root.join("bin"))
            .env("TMPDIR", root.join("tmp"))
            .env("TMP", root.join("tmp"))
            .env("TEMP", root.join("tmp"))
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("CSQ_SECRET_BACKEND", "in-memory")
            .stdin(Stdio::null());
        Ok(command)
    }
    struct DirectDescendant(Child);
    impl Drop for DirectDescendant {
        fn drop(&mut self) {
            // Only the vendor's actual original child on entry unwind. The
            // test's shared group guard independently accounts the whole PGID.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    #[test]
    #[ignore = "private inert native vendor/grandchild dispatcher"]
    fn private_group_entry() {
        let _environment = csq_core::platform::test_env::lock();
        // This inert process-group actor never opens a credential backend.
        assert_eq!(
            std::env::var("CSQ_SECRET_BACKEND").as_deref(),
            Ok("in-memory")
        );
        let root = PathBuf::from(std::env::var_os(ROOT).expect("owned group private root"));
        let role = std::env::var(ROLE).expect("owned group private role");
        assert!(matches!(
            role.as_str(),
            "vendor" | "descendant" | "leader-only"
        ));
        assert_eq!(
            std::env::var_os("HOME").as_deref(),
            Some(root.join("home").as_os_str())
        );
        let _descendant = if role == "vendor" {
            let mut descendant = command(&root, "descendant").expect("private descendant command");
            // No setsid or process_group: this native child inherits BOTH the
            // actual vendor PGID and the actual captured stdout write FD.
            descendant.stdout(Stdio::inherit()).stderr(Stdio::inherit());
            Some(DirectDescendant(
                descendant.spawn().expect("actual true descendant"),
            ))
        } else {
            None
        };
        let pid = std::process::id();
        // SAFETY: kernel queries for this live fixture itself.
        let identity = Identity {
            pid,
            parent: unsafe { libc::getppid() } as u32,
            group: unsafe { libc::getpgrp() },
            birth: birth(pid)
                .expect("actual fixture birth")
                .expect("live native fixture"),
        };
        atomic(
            &root,
            &format!("{role}-ready"),
            &serde_json::to_vec(&identity).unwrap(),
        )
        .expect("atomic actual identity");
        if role == "leader-only" {
            // No child is created in this role. Keep the leader live until its
            // owning guard and real reader are installed by the parent.
            while !root.join("leader-exit").is_file() {
                std::thread::yield_now();
            }
            eprintln!("OWNED_GROUP_ZOMBIE_FIXTURE: step=controlled_exit; errno=none; code=0; descendants_created=0");
            std::process::exit(0);
        }
        loop {
            std::thread::park();
        }
    }

    fn observe_and_cleanup(panic_after_setup: bool) -> (bool, bool) {
        let _environment = csq_core::platform::test_env::lock();
        let sandbox = tempfile::tempdir().expect("private production-group sandbox");
        for name in ["home", "base", "config", "appdata", "local", "bin", "tmp"] {
            std::fs::create_dir(sandbox.path().join(name)).expect("private fixture directory");
        }
        let root = sandbox.path();
        let mut vendor = command(root, "vendor").expect("actual vendor command");
        vendor
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(root.join("vendor.stderr")).unwrap());
        let (child, production_group) = group::spawn(&mut vendor, group::StdinPolicy::Caller)
            .expect("actual production group spawn");
        let pid = child.id();
        // Infallible guard adoption is immediate. It remains in scope across
        // setup failures, semantic RED, and the controlled panic below.
        let mut custody = CaseCustody::new(child);
        let original = custody.shared_child();
        let eof = Arc::new(AtomicBool::new(false));
        let reader_eof = Arc::clone(&eof);
        let mut descendant_identity = None;
        let mut vendor_identity = None;
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let stdout = original
                .lock()
                .unwrap()
                .stdout
                .take()
                .expect("actual captured vendor stdout");
            let reader = std::thread::Builder::new()
                .name("owned-group-causal-stdout".into())
                .spawn(move || {
                    let mut stdout = stdout;
                    io::copy(&mut stdout, &mut io::sink())?;
                    reader_eof.store(true, Ordering::Release);
                    Ok(())
                })
                .expect("actual captured reader thread");
            custody.add_reader(reader);
            assert!(
                poll_private(Duration::from_secs(5), || root
                    .join("vendor-ready")
                    .is_file()
                    && root.join("descendant-ready").is_file()),
                "OWNED_GROUP_CAUSAL_SETUP: actual entries missing"
            );
            let direct: Identity =
                serde_json::from_slice(&std::fs::read(root.join("vendor-ready")).unwrap()).unwrap();
            let descendant: Identity =
                serde_json::from_slice(&std::fs::read(root.join("descendant-ready")).unwrap())
                    .unwrap();
            let pgid = libc::pid_t::try_from(pid).unwrap();
            let descendant_pid = libc::pid_t::try_from(descendant.pid).unwrap();
            // SAFETY: both are current test-owned, birth-bound native entries;
            // direct Child has never been polled/reaped and reserves the PGID.
            let topology = direct.pid == pid
                && direct.group == pgid
                && production_group.id() == pid
                && descendant.parent == pid
                && descendant.group == pgid
                && unsafe { libc::getpgid(pgid) } == pgid
                && unsafe { libc::getpgid(descendant_pid) } == pgid
                && birth(pid).unwrap().as_deref() == Some(direct.birth.as_str())
                && birth(descendant.pid).unwrap().as_deref() == Some(descendant.birth.as_str());
            vendor_identity = Some(direct);
            descendant_identity = Some(descendant);
            assert!(
                topology && !eof.load(Ordering::Acquire),
                "OWNED_GROUP_CAUSAL_SETUP: actual PGID/birth/stdout prerequisites"
            );
            eprintln!("OWNED_GROUP_CAUSAL_TOPOLOGY: direct={vendor_identity:?}; descendant={descendant_identity:?}; native_pgid={pgid}; captured_eof=false");
            production_group
                .check_wait_lease()
                .expect("actual unreaped vendor lease before signal");
            if panic_after_setup {
                panic!("{PANIC}");
            }
            production_group
                .signal(group::GroupSignal::Kill)
                .expect("actual production whole-group kill");
            let observation = observe_bound_termination(
                Duration::from_secs(3),
                || gone(descendant_identity.as_ref().unwrap()),
                || eof.load(Ordering::Acquire),
            );
            // No try_wait/wait in the observation path: WNOWAIT still proves
            // that this same actual unreaped vendor reserves the owned PGID.
            production_group
                .check_wait_lease()
                .expect("actual unreaped vendor lease after observation");
            assert!(
                observation.is_ok(),
                "OWNED_GROUP_CAUSAL_OBSERVATION_UNKNOWN: {:?}",
                observation.as_ref().err()
            );
            let (terminated, captured_eof) =
                observation.expect("definite bound identity observation");
            eprintln!("OWNED_GROUP_CAUSAL_OBSERVATION: production_kill_sent=true; leader_unreaped=true; descendant_terminated_before_cleanup={terminated}; eof_before_cleanup={captured_eof}");
            (terminated, captured_eof)
        }));
        // Independent common killpg cleanup is intentionally unaffected by the
        // production direct-child-only mutant. It kills BEFORE original reap.
        let cleanup = custody.cleanup(Duration::from_secs(5));
        let descendant_gone = descendant_identity.as_ref().map(gone).transpose();
        let vendor_gone = vendor_identity.as_ref().map(gone).transpose();
        let actual_status = cleanup.status;
        let accounted = actual_status.is_some_and(|status| status.signal() == Some(libc::SIGKILL))
            && cleanup.readers_joined
            && eof.load(Ordering::Acquire)
            && cleanup.group_empty
            && descendant_gone
                .as_ref()
                .is_ok_and(|gone| *gone == Some(true))
            && vendor_gone.as_ref().is_ok_and(|gone| *gone == Some(true));
        eprintln!("OWNED_GROUP_CAUSAL_CLEANUP: original_pid={pid}; actual_status={actual_status:?}; reader_joined={}; actual_eof={}; owned_pgid_empty={}; descendant_gone={descendant_gone:?}; vendor_gone={vendor_gone:?}; detail={:?}", cleanup.readers_joined, eof.load(Ordering::Acquire), cleanup.group_empty, cleanup.detail);
        if !accounted {
            let evidence = sandbox.keep();
            panic!("{UNKNOWN}: actual original child/EOF/join/PGID/birth cleanup incomplete; private root={}", evidence.display());
        }
        // Actual descendant termination is observed; its native wait/reap is
        // intentionally not inferred from birth disappearance or pipe EOF.
        eprintln!("descendant reap: not observed (no subreaper on darwin)");
        drop(custody);
        match observed {
            Ok(saved) => saved,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
    #[test]
    fn production_group_kill_terminates_true_descendant_before_fixture_cleanup() {
        let (descendant_terminated, captured_eof) = observe_and_cleanup(false);
        assert!(descendant_terminated && captured_eof, "{SEMANTIC}");
    }
    #[test]
    fn controlled_observer_panic_still_reaps_vendor_joins_reader_and_empties_group() {
        let panic = std::panic::catch_unwind(|| observe_and_cleanup(true))
            .expect_err("controlled observer must panic");
        let text = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied());
        assert_eq!(text, Some(PANIC), "OWNED_GROUP_CAUSAL_PANIC_CLEANUP");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn already_exited_group_leader_with_no_descendants_is_joined_and_reaped() {
        let _environment = csq_core::platform::test_env::lock();
        let sandbox = tempfile::tempdir().expect("private exited-leader sandbox");
        for name in ["home", "base", "config", "appdata", "local", "bin", "tmp"] {
            std::fs::create_dir(sandbox.path().join(name)).expect("private fixture directory");
        }
        let root = sandbox.path();
        let mut command = command(root, "leader-only").expect("private no-descendant command");
        command
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(root.join("leader.stderr")).unwrap());
        let (child, production_group) = group::spawn(&mut command, group::StdinPolicy::Caller)
            .expect("actual production leader group");
        let pid = child.id();
        // The role cannot exit until leader-exit is atomically released below:
        // adoption therefore precedes intentional exit and captures live PGID.
        let mut custody = CaseCustody::new(child);
        let original = custody.shared_child();
        let eof = Arc::new(AtomicBool::new(false));
        let reader_eof = Arc::clone(&eof);
        let mut identity = None;
        let mut actual_native_exit = false;
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let stdout = original
                .lock()
                .unwrap()
                .stdout
                .take()
                .expect("actual leader stdout");
            let reader = std::thread::Builder::new()
                .name("owned-zombie-leader-stdout".into())
                .spawn(move || {
                    let mut stdout = stdout;
                    io::copy(&mut stdout, &mut io::sink())?;
                    reader_eof.store(true, Ordering::Release);
                    Ok(())
                })
                .expect("actual leader stdout reader");
            custody.add_reader(reader);
            assert!(
                poll_private(Duration::from_secs(5), || root
                    .join("leader-only-ready")
                    .is_file()),
                "OWNED_GROUP_ZOMBIE_SETUP: actual leader entry missing"
            );
            let record: Identity =
                serde_json::from_slice(&std::fs::read(root.join("leader-only-ready")).unwrap())
                    .unwrap();
            let pgid = libc::pid_t::try_from(pid).unwrap();
            // SAFETY: same still-owned direct Child, exit gate not yet released.
            let topology = record.pid == pid
                && record.group == pgid
                && production_group.id() == pid
                && unsafe { libc::getpgid(pgid) } == pgid
                && birth(pid).unwrap().as_deref() == Some(record.birth.as_str());
            identity = Some(record);
            assert!(
                topology,
                "OWNED_GROUP_ZOMBIE_SETUP: live native identity/PGID missing"
            );
            let live = group::observe_owned_unreaped_for_test(&original.lock().unwrap());
            eprintln!("OWNED_GROUP_ZOMBIE_STEP: step=live_wnowait; owned_pid={pid}; errno={:?}; exited={:?}",
                live.as_ref().err().and_then(io::Error::raw_os_error), live.as_ref().ok());
            assert!(
                !live.expect("actual native live WNOWAIT lease"),
                "leader must still await private release"
            );
            atomic(root, "leader-exit", b"controlled-exit-zero")
                .expect("atomic private exit release");
            let mut exit_error = None;
            let exited =
                poll_private(
                    Duration::from_secs(5),
                    || match group::observe_owned_unreaped_for_test(&original.lock().unwrap()) {
                        Ok(true) => {
                            actual_native_exit = true;
                            true
                        }
                        Ok(false) => false,
                        Err(error) => {
                            exit_error = Some(error);
                            true
                        }
                    },
                );
            eprintln!("OWNED_GROUP_ZOMBIE_STEP: step=exit_wnowait; owned_pid={pid}; errno={:?}; exited={actual_native_exit}",
                exit_error.as_ref().and_then(io::Error::raw_os_error));
            assert!(
                exited && actual_native_exit && exit_error.is_none(),
                "OWNED_GROUP_ZOMBIE_SETUP: native unreaped exit not proved"
            );
            let zombie_birth = birth(pid).expect("actual zombie native birth observation");
            assert!(
                zombie_birth.as_deref().is_none_or(|current| identity
                    .as_ref()
                    .is_some_and(|record| current == record.birth.as_str())),
                "actual unreaped Child must not change its bound native birth"
            );
            // Native zombie visibility may end before wait/reap; WNOWAIT above,
            // never birth disappearance, is the retained actual Child authority.
            // SAFETY: read-only lookup of the same owned unreaped direct Child.
            let exited_group = unsafe { libc::getpgid(pgid) };
            let lookup_errno = (exited_group < 0)
                .then(io::Error::last_os_error)
                .and_then(|error| error.raw_os_error());
            eprintln!("OWNED_GROUP_ZOMBIE_STEP: step=exited_getpgid; owned_pid={pid}; errno={lookup_errno:?}; group={exited_group}");
            assert!(
                poll_private(Duration::from_secs(3), || eof.load(Ordering::Acquire)),
                "OWNED_GROUP_ZOMBIE_SETUP: real captured stdout EOF missing"
            );
        }));
        let primary = custody.cleanup(Duration::from_secs(5));
        let primary_complete = primary
            .status
            .is_some_and(|status| status.code() == Some(0) && status.signal().is_none())
            && primary.readers_joined
            && primary.group_empty;
        // A source-ready OLD-helper run may refuse before joining/reaping this
        // positively exited leader. The independent no-signal common wait is
        // safety cleanup only and never earns primary-cleanup regression credit.
        let fallback = if !primary_complete && actual_native_exit && eof.load(Ordering::Acquire) {
            Some(custody.wait(Duration::from_secs(3)))
        } else {
            None
        };
        let actual_status = fallback
            .as_ref()
            .and_then(|receipt| receipt.status)
            .or(primary.status);
        let actual_joined = primary.readers_joined
            || fallback
                .as_ref()
                .is_some_and(|receipt| receipt.readers_joined);
        let mut absence_errno = None;
        let mut absent = false;
        let pgid = libc::pid_t::try_from(pid).unwrap();
        poll_private(Duration::from_secs(3), || {
            // SAFETY: read-only absence observation of the formerly owned PGID;
            // no signal authority is used after the actual typed Child reap.
            if unsafe { libc::killpg(pgid, 0) } < 0 {
                let error = io::Error::last_os_error();
                absence_errno = error.raw_os_error();
                absent = absence_errno == Some(libc::ESRCH);
                true
            } else {
                false
            }
        });
        let native_gone = identity.as_ref().map(gone).transpose();
        eprintln!("OWNED_GROUP_ZOMBIE_STEP: step=final_pgid_absence; owned_pid={pid}; errno={absence_errno:?}; absent={absent}");
        eprintln!("OWNED_GROUP_ZOMBIE_CLEANUP: original_pid={pid}; primary_complete={primary_complete}; fallback_used={}; actual_status={actual_status:?}; reader_joined={actual_joined}; actual_eof={}; owned_pgid_empty={absent}; vendor_gone={native_gone:?}; descendants_created=0", fallback.is_some(), eof.load(Ordering::Acquire));
        let accounted = actual_status.is_some()
            && actual_joined
            && eof.load(Ordering::Acquire)
            && absent
            && native_gone.as_ref().is_ok_and(|gone| *gone == Some(true));
        if let Ok(diagnostic) = std::fs::read_to_string(root.join("leader.stderr")) {
            for line in diagnostic
                .lines()
                .filter(|line| line.starts_with("OWNED_GROUP_ZOMBIE_FIXTURE:"))
            {
                eprintln!("{line}");
            }
        }
        if !accounted {
            let evidence = sandbox.keep();
            panic!("OWNED_GROUP_ZOMBIE_CUSTODY_UNKNOWN: original child/EOF/join/birth/PGID cleanup incomplete; private root={}", evidence.display());
        }
        drop(custody);
        if let Err(payload) = observed {
            std::panic::resume_unwind(payload);
        }
        assert!(
            actual_status
                .is_some_and(|status| status.code() == Some(0) && status.signal().is_none()),
            "OWNED_GROUP_ZOMBIE_EXPECTED_ACTUAL_EXIT_ZERO"
        );
        assert!(primary_complete, "OWNED_GROUP_ZOMBIE_CLEANUP_MUST_FINALIZE");
    }

    /// R2 item 6 LOW-2: a refusal recorded BEFORE the deadline (here a setup
    /// error) must not suppress the caller-authorized deadline kill. The first
    /// cause stays SetupFailed; the group still dies at the deadline.
    #[cfg(unix)]
    #[test]
    fn setup_refusal_does_not_suppress_the_deadline_group_kill() {
        let (mut fixture, mut control) =
            VendorFixture::spawn("hold").expect("deadline kill fixture");
        assert!(fixture.started(), "actual private writer must start");
        let watchdog = LoginWatchdog::new(Duration::from_millis(300), DeliveryPhase::Unknown);
        let group = fixture.take_group();
        let kill_group = group.clone();
        let mut owner = OwnedLoginChild::adopt_group(fixture.take_child(), group, watchdog, ());
        let mut ticks = 0_usize;
        let mut killed = false;
        let mut terminations = 0_usize;
        // IN-TEST TIMEOUT: without the deadline fix the hold fixture blocks the
        // wait forever. This observer turns that hang into a RED, never a stall.
        let finished =
            std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let timeout_group = kill_group.clone();
        let timeout_finished = std::sync::Arc::clone(&finished);
        let timeout_flag = std::sync::Arc::clone(&timed_out);
        let timeout_observer = std::thread::spawn(move || {
            let (lock, cond) = &*timeout_finished;
            let done = lock.lock().unwrap_or_else(|error| error.into_inner());
            let (done, wait) = cond
                .wait_timeout_while(done, Duration::from_secs(10), |done| !*done)
                .unwrap_or_else(|error| error.into_inner());
            if !*done && wait.timed_out() {
                timeout_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = timeout_group.signal(group::GroupSignal::Kill);
            }
        });
        let result = owner.wait_vendor_cancelled(
            || {
                ticks += 1;
                if ticks == 1 {
                    // A setup refusal wins FIRST; the deadline action is still due.
                    Err(std::io::Error::other("inert setup refusal"))
                } else {
                    Ok(true)
                }
            },
            |_| {},
            || {
                terminations += 1;
                killed = kill_group.signal(group::GroupSignal::Kill).is_ok();
                Ok(())
            },
            || false,
        );
        {
            let (lock, cond) = &*finished;
            *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
            cond.notify_all();
        }
        timeout_observer.join().expect("in-test timeout observer");
        assert!(
            !timed_out.load(std::sync::atomic::Ordering::SeqCst),
            "IN_TEST_TIMEOUT: the deadline stop never fired; the wait hung"
        );
        assert_eq!(terminations, 1, "the deadline stop must run exactly once");
        assert!(killed, "DEADLINE_KILL_SUPPRESSED_BY_EARLIER_REFUSAL");
        assert!(
            owner.deadline_stopped(),
            "DEADLINE_STOP_NOT_CARRIED_OUT_OF_THE_WAIT"
        );
        let refusal = result.expect_err("a refused login must not publish");
        assert_eq!(
            refusal.reason,
            RefusalReason::SetupFailed,
            "the first refusal cause must be retained"
        );
        control.close();
        drop(owner);
    }
}
