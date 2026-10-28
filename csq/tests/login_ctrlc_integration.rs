//! Inert current_exe fixtures exercise the shared default CLI spawn/wait body.
//! Typed receipts bind all four rows to the original Child and actual reap.
//! The first three rows deliberately preserve a harmless prior SIGINT handler:
//! a compiled handler-removal mutant must retain its real vendor reaper on macOS.
//! Their 130/publication assertions discriminate cancellation, not default-parent
//! death prevention. The fourth row proves actual SIG_DFL restoration separately.
#![cfg(unix)]

#[path = "../src/login_cancel_guard.rs"]
mod login_cancel_guard;
#[path = "../src/login_child_custody.rs"]
mod login_child_custody;

use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::types::AccountNum;
use std::io::Write;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const ENTRY: &str = "login_ctrlc_private_entry";
const ROLE: &str = "CSQ_PRIVATE_CTRLC_ROLE";
const ROOT: &str = "CSQ_PRIVATE_CTRLC_ROOT";
const NOTICE: &str = "Cancelling — waiting for Claude login to exit";
const DEFAULT_ASSERTION: &str = "LOGIN_CTRLC_DEFAULT_REAP_CANCEL130";
const RETAIN_ASSERTION: &str = "LOGIN_CTRLC_RETAIN_LOCK_PING";
const LATE_ASSERTION: &str = "LOGIN_CTRLC_LATE_ZERO_NO_POST";
const CONTROL_ASSERTION: &str = "LOGIN_CTRLC_NO_CANCEL_POSTS_ONCE";
const PRIOR_ASSERTION: &str = "LOGIN_CTRLC_PRIOR_RESTORED";
const RESTORE_ASSERTION: &str = "LOGIN_CTRLC_DEFAULT_RESTORED";
// These are failure/cleanup budgets, never scheduler-speed success assertions.
// Every successful transition requires its causal marker or fresh nonce.
const BUDGET: Duration = Duration::from_secs(8);
const PGID_ASSERTION: &str = "LOGIN_CTRLC_OWNED_VENDOR_PGID";
const REAP_ASSERTION: &str = "LOGIN_CTRLC_ACTUAL_CHILD_REAP";

static PRIOR_SIGNALS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn prior_sigint(_: libc::c_int) {
    PRIOR_SIGNALS.fetch_add(1, Ordering::SeqCst);
}

fn atomic_write(root: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(root)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.persist(root.join(name)).map_err(|error| error.error)?;
    Ok(())
}

fn poll(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + BUDGET;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::yield_now();
    }
}

fn selected_command(root: &Path, role: &str) -> std::io::Result<Command> {
    for relative in ["home", "base", "config", "bin", "tmp", "appdata", "local"] {
        std::fs::create_dir_all(root.join(relative))?;
    }
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
        .env("TMPDIR", root.join("tmp"))
        .env("TEMP", root.join("tmp"))
        .env("TMP", root.join("tmp"))
        .env("PATH", root.join("bin"))
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(root.join(format!("{role}.stdout")))?)
        .stderr(std::fs::File::create(root.join(format!("{role}.stderr")))?);
    Ok(command)
}

fn account() -> AccountNum {
    AccountNum::try_from(1_u16).expect("private fixture slot")
}

fn held(root: &Path) -> bool {
    matches!(
        AccountLoginLock::acquire(&root.join("base"), account()),
        Ok(AcquireOutcome::Held { .. })
    )
}

fn install_prior(default: bool) {
    // SAFETY: private fixture process only; initialized mask and a static
    // signal-safe atomic-only callback (or POSIX SIG_DFL) form the full action.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = if default {
        libc::SIG_DFL
    } else {
        prior_sigint as *const () as usize
    };
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: action owns the writable signal mask.
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    // SAFETY: the complete initialized action is installed in this fixture;
    // no signal state in the outer test runner is modified.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) },
        0
    );
}

fn run_vendor(root: &Path, ignore: bool) -> ! {
    // Explicit disposition before readiness: neither libtest nor a parent
    // disposition may choose which child behavior this row actually exercises.
    // SAFETY: private vendor fixture only; initialized below before libc reads it.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = if ignore { libc::SIG_IGN } else { libc::SIG_DFL };
    // SAFETY: action owns the writable signal mask.
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    // SAFETY: full initialized action; this is the owned vendor process itself.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut()) },
        0
    );
    atomic_write(
        root,
        "vendor-ready",
        std::process::id().to_string().as_bytes(),
    )
    .unwrap();
    let mut seen = Vec::new();
    loop {
        if let Ok(nonce) = std::fs::read(root.join("ping")) {
            if nonce != seen {
                atomic_write(root, "ping-ack", &nonce).unwrap();
                seen = nonce;
            }
        }
        if let Ok(release) = std::fs::read_to_string(root.join("release")) {
            // Atomic producer: malformed content is a loud fixture error,
            // never a retry that could hide a create-before-write race.
            let code = release.parse::<i32>().expect("atomic private release code");
            assert_eq!(code, 0);
            atomic_write(root, "vendor-completed", b"0").unwrap();
            std::process::exit(code);
        }
        std::thread::yield_now();
    }
}

fn run_driver(root: &Path, role: &str) -> ! {
    let default_prior = role == "driver-restore-default";
    install_prior(default_prior);
    // Private EOF lifeline: even abrupt outer-controller exit releases this
    // inert vendor cooperatively. The actual driver remains its sole reaper.
    // This thread is not reader-join or graceful-vendor evidence.
    let cleanup_root = root.to_path_buf();
    let _cleanup = std::thread::spawn(move || {
        let mut byte = [0_u8; 1];
        loop {
            match std::io::Read::read(&mut std::io::stdin(), &mut byte) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(0) | Err(_) => {
                    atomic_write(&cleanup_root, "release", b"0").unwrap();
                    atomic_write(&cleanup_root, "finish", b"outer EOF").unwrap();
                    break;
                }
                Ok(_) => {}
            }
        }
    });
    let lock = match AccountLoginLock::acquire(&root.join("base"), account()).unwrap() {
        AcquireOutcome::Acquired(lock) => lock,
        _ => panic!("private fixture account lock unexpectedly held"),
    };
    // Exercise the production bool wrapper as well as its shared-body receipt
    // entry, without starting any process for this small spawn-error control.
    let mut missing = Command::new(root.join("bin/private-missing-login-fixture"));
    missing
        .env_clear()
        .current_dir(root)
        .env("HOME", root.join("home"))
        .env("CSQ_BASE_DIR", root.join("base"))
        .env("CLAUDE_CONFIG_DIR", root.join("config"))
        .env("PATH", root.join("bin"))
        .env("TMPDIR", root.join("tmp"))
        .env("LANG", "C")
        .env("LC_ALL", "C");
    let spawn_error =
        login_cancel_guard::spawn_cli_login(&mut missing, Duration::from_secs(300), (), |_| {})
            .expect_err("missing inert executable must refuse before a child exists");
    assert!(spawn_error.chain().any(|cause| cause
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)));
    let vendor_role = if role == "driver-default" {
        "vendor-default"
    } else {
        "vendor-ignore"
    };
    let mut command = selected_command(root, vendor_role).unwrap();
    // This receipt entry and the production bool wrapper delegate the same
    // body: install, spawn, adopt, wait, actual reap, restore. No auth path runs.
    let result = login_cancel_guard::spawn_cli_login_receipt(
        &mut command,
        Duration::from_secs(300),
        lock,
        |_| {},
    );
    let vendor_pid: u32 = std::fs::read_to_string(root.join("vendor-ready"))
        .expect("selected actual vendor reached entry")
        .parse()
        .expect("actual vendor PID");
    let mut publications = 0_usize;
    let mut inert_post = || {
        publications += 1;
        atomic_write(root, "post-called", publications.to_string().as_bytes()).unwrap();
    };
    if result
        .as_ref()
        .is_ok_and(|receipt| receipt.reaped_status().success())
    {
        inert_post();
    }
    let (exit, reaped_pid, code, signal) = match &result {
        Ok(receipt) => {
            let status = receipt.reaped_status();
            (
                if status.success() { 0 } else { 1 },
                Some(receipt.child_id()),
                status.code(),
                status.signal(),
            )
        }
        Err(error) => {
            let cancellation = error.downcast_ref::<login_cancel_guard::CliLoginCancelled>();
            let status = cancellation.and_then(|cancel| cancel.reaped_status());
            (
                login_cancel_guard::cli_error_exit_code(error),
                cancellation.and_then(|cancel| cancel.child_id()),
                status.and_then(|status| status.code()),
                status.and_then(|status| status.signal()),
            )
        }
    };
    // Both branches carry typed actual Child receipts. The receipt is never
    // inferred from publication, process absence, or a fixture-assigned boolean.
    let prior_at_return = PRIOR_SIGNALS.load(Ordering::SeqCst);
    let receipt = serde_json::json!({
        "vendor_pid": vendor_pid,
        "reaped_pid": reaped_pid,
        "exit": exit,
        "publication": publications,
        "vendor_code": code,
        "vendor_signal": signal,
        "prior_signals_at_return": prior_at_return,
    });
    atomic_write(
        root,
        "reaped-receipt",
        serde_json::to_string(&receipt).unwrap().as_bytes(),
    )
    .unwrap();
    // Guard has already restored the prior OS disposition. Remain the owned
    // PGID leader until the controller finishes all descendant cleanup/signals.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if PRIOR_SIGNALS.load(Ordering::SeqCst) > prior_at_return
            && !root.join("prior-restored").exists()
        {
            atomic_write(root, "prior-restored", b"observed").unwrap();
        }
        if root.join("finish").exists() {
            std::process::exit(exit);
        }
        assert!(
            Instant::now() < deadline,
            "private fixture controller never finished"
        );
        std::thread::yield_now();
    }
}

#[test]
#[ignore = "fixture dispatcher; invoked only by an owned subprocess with explicit role"]
fn login_ctrlc_private_entry() {
    let _env_guard = csq_core::platform::test_env::lock();
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let role = role.to_str().expect("private fixture role");
    let root = PathBuf::from(std::env::var_os(ROOT).expect("private fixture root"));
    for (key, relative) in [
        ("HOME", "home"),
        ("CSQ_HOME", "home"),
        ("USERPROFILE", "home"),
        ("CSQ_BASE_DIR", "base"),
        ("CLAUDE_CONFIG_DIR", "config"),
        ("XDG_CONFIG_HOME", "config"),
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
    match role {
        "vendor-default" => run_vendor(&root, false),
        "vendor-ignore" => run_vendor(&root, true),
        "driver-default" | "driver-ignore" | "driver-control" | "driver-restore-default" => {
            run_driver(&root, role)
        }
        _ => panic!("unrecognized private fixture role"),
    }
}

struct Driver {
    child: Option<Child>,
    input: Option<ChildStdin>,
    sandbox: Option<tempfile::TempDir>,
    pid: libc::pid_t,
    pgid_custody: bool,
    role: &'static str,
    logs_forwarded: bool,
    vendor_pid: Option<u32>,
}

impl Driver {
    fn spawn(role: &'static str) -> Self {
        let sandbox = tempfile::tempdir().unwrap();
        let mut command = selected_command(sandbox.path(), role).unwrap();
        command.process_group(0).stdin(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let input = child.stdin.take();
        let pid = libc::pid_t::try_from(child.id()).unwrap();
        let fixture = Self {
            child: Some(child),
            input,
            sandbox: Some(sandbox),
            pid,
            pgid_custody: true,
            role,
            logs_forwarded: false,
            vendor_pid: None,
        };
        // A fresh actual Child remains UNREAPED until cleanup completes.
        // getpgid binds the only terminal-signal target to its owned group.
        // SAFETY: pid came from this still-owned, unreaped Child. Query only.
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        fixture
    }

    fn root(&self) -> &Path {
        self.sandbox.as_ref().unwrap().path()
    }
    fn ready(&mut self) -> bool {
        if !poll(|| self.root().join("vendor-ready").exists()) {
            return false;
        }
        let vendor_pid = std::fs::read_to_string(self.root().join("vendor-ready"))
            .expect("atomic selected vendor identity")
            .parse::<u32>()
            .expect("vendor PID");
        self.vendor_pid = Some(vendor_pid);
        self.assert_live_vendor_group();
        true
    }
    fn assert_live_vendor_group(&self) {
        assert!(self.pgid_custody, "{PGID_ASSERTION}");
        let vendor_pid =
            libc::pid_t::try_from(self.vendor_pid.expect("actual ready vendor PID")).unwrap();
        // SAFETY: before any signal/release, the selected inert vendor remains
        // live under this unreaped driver. The typed reap later binds the same
        // PID to the production owner's original Child handle.
        assert_eq!(
            unsafe { libc::getpgid(vendor_pid) },
            vendor_pid,
            "{PGID_ASSERTION}"
        );
    }
    fn actual_reap_matches_spawn(&self, receipt: &serde_json::Value) -> bool {
        let expected_pid = self.vendor_pid.or_else(|| {
            std::fs::read_to_string(self.root().join("vendor-ready"))
                .ok()?
                .parse::<u32>()
                .ok()
        });
        expected_pid.is_some_and(|pid| receipt["vendor_pid"] == pid && receipt["reaped_pid"] == pid)
            && (receipt["vendor_code"].as_i64().is_some()
                != receipt["vendor_signal"].as_i64().is_some())
    }
    fn signal_group(&self) {
        self.assert_live_vendor_group();
        assert!(self.pgid_custody);
        // SAFETY: actual Child group leader stays unreaped; process_group(0)
        // created this fresh group and only these two private fixtures join it.
        assert_eq!(unsafe { libc::getpgid(self.pid) }, self.pid);
        // SAFETY: the checked group remains in our custody until cleanup.
        assert_eq!(unsafe { libc::kill(-self.pid, libc::SIGINT) }, 0);
    }
    fn signal_driver(&self) {
        assert!(self.pgid_custody);
        // SAFETY: retained original Child identity; never signalled after reap.
        assert_eq!(unsafe { libc::getpgid(self.pid) }, self.pid);
        // SAFETY: only this unreaped private driver PID is targeted.
        assert_eq!(unsafe { libc::kill(self.pid, libc::SIGINT) }, 0);
    }
    fn notices(&self, role: &str) -> usize {
        std::fs::read_to_string(self.root().join(format!("{role}.stderr")))
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == NOTICE)
            .count()
    }
    fn ping(&self, nonce: &[u8]) -> bool {
        atomic_write(self.root(), "ping", nonce).unwrap();
        poll(|| std::fs::read(self.root().join("ping-ack")).ok().as_deref() == Some(nonce))
    }
    fn release(&self) {
        atomic_write(self.root(), "release", b"0").unwrap();
    }
    fn receipt(&self) -> Option<serde_json::Value> {
        if !poll(|| self.root().join("reaped-receipt").exists()) {
            return None;
        }
        Some(
            serde_json::from_slice(&std::fs::read(self.root().join("reaped-receipt")).unwrap())
                .unwrap(),
        )
    }
    fn finish_and_reap(&mut self) -> Option<ExitStatus> {
        // Do NOT poll/reap the group leader before the sole vendor reaper has
        // returned. Atomic cooperative release is bounded even in the mutant.
        self.release();
        let receipt = self.receipt()?;
        // Cleanup accepts any actual terminal status, including a behaviorally
        // wrong mutant. It never releases PGID custody on a made-up receipt.
        if !self.actual_reap_matches_spawn(&receipt) {
            return None;
        }
        // The only descendant was actually reaped by the exact production
        // helper; group cleanup is complete while its leader is still owned.
        self.pgid_custody = false;
        atomic_write(self.root(), "finish", b"done").unwrap();
        self.input.take();
        let child = self.child.as_mut().unwrap();
        let mut status = None;
        if !poll(|| match child.try_wait() {
            Ok(Some(actual)) => {
                status = Some(actual);
                true
            }
            Ok(None) => false,
            Err(_) => false,
        }) {
            return None;
        }
        self.child.take();
        if !self.logs_forwarded {
            // Preserve compiled-mutant reached markers in the outer complete
            // --nocapture log before this private tempdir is removed.
            eprint!(
                "{}",
                std::fs::read_to_string(self.root().join(format!("{}.stderr", self.role)))
                    .unwrap_or_default()
            );
            self.logs_forwarded = true;
        }
        status
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Close first so the independent private EOF lifeline also handles
        // unwinds; the fixture's production owner still performs the reap.
        self.input.take();
        if self.child.is_some() && self.finish_and_reap().is_none() {
            // Never turn PID absence into reap evidence or kill an unowned
            // orphan. Preserve private receipts on an unmeasurable cleanup.
            let root = self.sandbox.take().unwrap().keep();
            eprintln!(
                "LOGIN_CTRLC_CUSTODY_UNKNOWN: actual driver/vendor cleanup not proved: {}",
                root.display()
            );
        }
    }
}

fn actual_cancel_receipt(receipt: &serde_json::Value, signal: Option<i32>) -> bool {
    receipt["exit"] == 130
        && receipt["publication"] == 0
        && receipt["reaped_pid"] == receipt["vendor_pid"]
        && receipt["reaped_pid"].as_u64().is_some()
        && if let Some(signal) = signal {
            receipt["vendor_signal"] == signal && receipt["vendor_code"].is_null()
        } else {
            receipt["vendor_code"] == 0 && receipt["vendor_signal"].is_null()
        }
}

#[test]
fn login_ctrlc_default_sigint_child_reaped_cancel130_no_post() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-default");
    let ready = driver.ready();
    if ready {
        driver.signal_group();
    }
    let receipt = driver.receipt();
    let notices = driver.notices("driver-default");
    let post = std::fs::read(driver.root().join("post-called")).ok();
    // Prior callback is tested AFTER actual helper return, never as a claim
    // about the scoped guard's liveness behavior before child reap.
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    if reaped {
        driver.signal_driver();
    }
    let restored = reaped && poll(|| driver.root().join("prior-restored").exists());
    let status = driver.finish_and_reap();
    assert!(
        ready
            && reaped
            && receipt
                .as_ref()
                .is_some_and(|r| actual_cancel_receipt(r, Some(libc::SIGINT))
                    && r["prior_signals_at_return"] == 0)
            && status.is_some_and(|status| status.code() == Some(130))
            && notices == 1
            && post.is_none(),
        "{DEFAULT_ASSERTION}"
    );
    assert!(restored, "{PRIOR_ASSERTION}");
    assert!(reaped, "{REAP_ASSERTION}");
}

#[test]
fn login_ctrlc_ignored_sigint_retains_parent_lock_until_late_zero_reap() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-ignore");
    let ready = driver.ready();
    if ready {
        driver.signal_group();
    }
    let cancelled = ready && poll(|| driver.notices("driver-ignore") > 0);
    let retained = cancelled
        && held(driver.root())
        && driver.ping(b"after-cancel-1")
        && !driver.root().join("reaped-receipt").exists();
    let second_ping = if retained {
        driver.signal_group();
        let ping = driver.ping(b"after-repeat-2");
        driver.signal_group();
        ping
    } else {
        false
    };
    let repeated = retained
        && second_ping
        && driver.ping(b"after-repeat-3")
        && held(driver.root())
        && !driver.root().join("reaped-receipt").exists();
    // Cleanup precedes assertions even for a compiled missing-handler mutant.
    if ready {
        driver.assert_live_vendor_group();
    }
    driver.release();
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let completed = driver.root().join("vendor-completed").exists();
    let post = std::fs::read(driver.root().join("post-called")).ok();
    let notices = driver.notices("driver-ignore");
    let unlocked = matches!(
        AccountLoginLock::acquire(&driver.root().join("base"), account()),
        Ok(AcquireOutcome::Acquired(_))
    );
    let status = driver.finish_and_reap();
    assert!(retained && repeated, "{RETAIN_ASSERTION}");
    assert!(
        reaped
            && completed
            && unlocked
            && post.is_none()
            && notices == 1
            && receipt
                .as_ref()
                .is_some_and(|r| actual_cancel_receipt(r, None))
            && status.is_some_and(|status| status.code() == Some(130)),
        "{LATE_ASSERTION}"
    );
}

#[test]
fn login_ctrlc_no_cancel_actual_zero_posts_once() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-control");
    let ready = driver.ready();
    let live = ready && held(driver.root()) && driver.ping(b"before-release-control");
    if ready {
        driver.assert_live_vendor_group();
    }
    driver.release();
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let completed = driver.root().join("vendor-completed").exists();
    let post = std::fs::read(driver.root().join("post-called")).ok();
    let notices = driver.notices("driver-control");
    let status = driver.finish_and_reap();
    assert!(
        reaped
            && live
            && completed
            && post.as_deref() == Some(b"1")
            && notices == 0
            && receipt.is_some_and(|r| r["exit"] == 0
                && r["publication"] == 1
                && r["vendor_code"] == 0
                && r["vendor_signal"].is_null())
            && status.is_some_and(|status| status.code() == Some(0)),
        "{CONTROL_ASSERTION}"
    );
}

#[test]
fn login_ctrlc_restores_default_handler_after_actual_reap() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-restore-default");
    let ready = driver.ready();
    if ready {
        driver.assert_live_vendor_group();
    }
    driver.release();
    let receipt = driver.receipt();
    // No live vendor remains. A true default handler may now kill the owned
    // driver without stranding any grandchild or losing an actual reaper.
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    if reaped {
        driver.signal_driver();
    }
    let status = driver.finish_and_reap();
    assert!(
        ready
            && reaped
            && receipt.is_some_and(|r| r["exit"] == 0
                && r["publication"] == 1
                && r["vendor_code"] == 0
                && r["vendor_signal"].is_null())
            && status.is_some_and(|status| status.signal() == Some(libc::SIGINT)),
        "{RESTORE_ASSERTION}"
    );
}
