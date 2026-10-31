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
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const ENTRY: &str = "login_ctrlc_private_entry";
const ROLE: &str = "CSQ_PRIVATE_CTRLC_ROLE";
const ROOT: &str = "CSQ_PRIVATE_CTRLC_ROOT";
/// Fixture-only seam: the driver sleeps this many ms AFTER the guard returned
/// (its lock is already dropped with the owner) and BEFORE it writes the
/// receipt, so the "lock free, no receipt yet" window the fixture itself
/// creates can be made wide enough to hit on every run.
const RECEIPT_STALL: &str = "CSQ_PRIVATE_CTRLC_RECEIPT_STALL_MS";
const NOTICE: &str = "Cancelling — waiting for Claude login to exit";
const DEFAULT_ASSERTION: &str = "LOGIN_CTRLC_DEFAULT_REAP_CANCEL130";
const RETAIN_ASSERTION: &str = "LOGIN_CTRLC_RETAIN_LOCK_PING";
const LATE_ASSERTION: &str = "LOGIN_CTRLC_LATE_ZERO_NO_POST";
const CONTROL_ASSERTION: &str = "LOGIN_CTRLC_NO_CANCEL_POSTS_ONCE";
const PRIOR_ASSERTION: &str = "LOGIN_CTRLC_PRIOR_RESTORED";
const RESTORE_ASSERTION: &str = "LOGIN_CTRLC_DEFAULT_RESTORED";
// These are failure/cleanup budgets, never scheduler-speed success assertions.
// Every successful transition requires its causal marker or fresh nonce.
// HANG GUARD, not a pacing assumption: success always needs its causal marker;
// this only bounds a genuinely wedged run. Sized for a sustained host io stall (an internal ticket).
const BUDGET: Duration = Duration::from_secs(180);
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
        std::thread::sleep(Duration::from_millis(2));
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
    // Exit lifeline: the kernel closes this write end when the vendor exits.
    let _life = std::fs::OpenOptions::new()
        .write(true)
        .open(root.join("vendor-life"))
        .unwrap();
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
    if let Some(ms) = std::env::var(RECEIPT_STALL)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
    {
        std::thread::sleep(Duration::from_millis(ms));
    }
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
    let deadline = Instant::now() + BUDGET;
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

/// SIGCONT on drop, so a panic while the driver is stopped never strands it.
struct StoppedDriver(libc::pid_t);
impl Drop for StoppedDriver {
    fn drop(&mut self) {
        // SAFETY: the pid is this test's own still-owned, unreaped driver.
        unsafe { libc::kill(self.0, libc::SIGCONT) };
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
    life: Option<std::fs::File>,
}

impl Driver {
    fn spawn(role: &'static str) -> Self {
        Self::spawn_stalled(role, None)
    }

    /// [`Driver::spawn`] whose driver stalls `receipt_stall_ms` between the
    /// guard's return and the receipt write (see [`RECEIPT_STALL`]).
    fn spawn_stalled(role: &'static str, receipt_stall_ms: Option<u64>) -> Self {
        let sandbox = tempfile::tempdir().unwrap();
        let life_path = sandbox.path().join("vendor-life");
        let life_c = std::ffi::CString::new(life_path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: valid NUL-terminated path inside this test's private sandbox.
        assert_eq!(unsafe { libc::mkfifo(life_c.as_ptr(), 0o600) }, 0);
        let life = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&life_path)
            .unwrap();
        let mut command = selected_command(sandbox.path(), role).unwrap();
        command.process_group(0).stdin(Stdio::piped());
        if let Some(ms) = receipt_stall_ms {
            command.env(RECEIPT_STALL, ms.to_string());
        }
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
            life: Some(life),
        };
        // A fresh actual Child remains UNREAPED until cleanup completes.
        // getpgid binds the only terminal-signal target to its owned group.
        // SAFETY: pid came from this still-owned, unreaped Child. Query only.
        assert_eq!(unsafe { libc::getpgid(pid) }, pid);
        fixture
    }

    /// Freeze the driver (waitid(WSTOPPED|WNOWAIT) proves it stopped) so signals sent
    /// next are only pending: the 200ms production pump cannot act on them
    /// before the test has ordered the vendor's exit.
    fn stop(&self) -> StoppedDriver {
        assert!(self.pgid_custody);
        let guard = StoppedDriver(self.pid);
        // SAFETY: only this unreaped private driver PID is targeted.
        assert_eq!(unsafe { libc::kill(self.pid, libc::SIGSTOP) }, 0);
        // SAFETY: waitid with WNOWAIT only observes the state change and never
        // reaps: Child keeps sole ownership of the exit status, so a driver that
        // already died stays a zombie instead of being reaped before the guard's
        // SIGCONT (no PID-reuse window).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut info,
                libc::WSTOPPED | libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(
            info.si_code,
            libc::CLD_STOPPED,
            "driver exited instead of stopping"
        );
        guard
    }
    /// True once the kernel closed the vendor's FIFO write end: the vendor
    /// process exited. An event, not a duration; valid only after ready().
    fn vendor_exited(&self) -> bool {
        use std::io::Read;
        let mut byte = [0_u8; 1];
        let mut life = self.life.as_ref().unwrap();
        matches!(life.read(&mut byte), Ok(0))
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
    // The second interrupt is the product's explicit second-Ctrl-C kill
    // escalation, acted on by the 200ms pump. Deliver it while the driver is
    // stopped (a further SIGINT would coalesce into the same single pending
    // signal), release the vendor and wait for its ACTUAL exit before SIGCONT:
    // the late-zero outcome no longer depends on pump latency (an internal ticket). Lock
    // retention is asserted before the stop and again after the reap; nothing
    // is sampled while the driver is frozen, where no check could fail.
    let repeated = retained && {
        let stopped = driver.stop();
        driver.signal_group();
        driver.release();
        let exited = poll(|| driver.vendor_exited());
        drop(stopped);
        exited
    };
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

#[test]
fn login_ctrlc_second_interrupt_kills_vendor_130_no_post_lock_until_reap() {
    second_interrupt_kills_vendor(None);
}

/// The receipt is the fixture's OWN file, written after the guard returned, and
/// the guard drops the lock on return: "lock free, receipt not yet written" is
/// the normal state between those two points, never evidence of an early
/// release. Stalling the driver 1.5s there makes that window certain; the row
/// must still pass because the vendor was already reaped when the lock freed.
#[test]
fn login_ctrlc_lock_free_between_reap_and_receipt_is_not_an_early_release() {
    second_interrupt_kills_vendor(Some(1500));
}

fn second_interrupt_kills_vendor(receipt_stall_ms: Option<u64>) {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn_stalled("driver-ignore", receipt_stall_ms);
    let ready = driver.ready();
    if ready {
        driver.signal_group();
    }
    let cancelled = ready && poll(|| driver.notices("driver-ignore") > 0);
    // First interrupt handled; the SIGINT-ignoring vendor is still alive and
    // the vendor has NOT been released.
    let survived = cancelled
        && held(driver.root())
        && driver.ping(b"kill-after-cancel-1")
        && !driver.root().join("reaped-receipt").exists();
    // Second Ctrl-C: the pump escalates to SIGKILL. The vendor dies only by
    // that kill (never by release), proven by the kernel FIFO EOF.
    let killed = survived && {
        driver.signal_group();
        poll(|| driver.vendor_exited())
    };
    // The lock must stay held until the vendor is REAPED. The receipt cannot
    // witness that: the guard drops the lock when it returns and the fixture
    // writes the receipt after, so "lock free, no receipt yet" is the normal
    // state between the two. The reap itself is observable: the vendor is the
    // driver's child, a zombie answers kill(pid, 0) with success until the
    // driver reaps it, then ESRCH. Order is the proof: sample the lock FIRST,
    // then the reap. A lock seen free at t1 with the vendor still unreaped at
    // t2 > t1 means it was unreaped at t1 as well (a reap never un-happens), so
    // the lock was released before the reap. Free then reaped proves nothing,
    // and is not counted.
    let mut released_early = false;
    if killed {
        // `killed` implies `ready()` ran, which recorded the vendor PID.
        let vendor = libc::pid_t::try_from(driver.vendor_pid.expect("ready vendor PID")).unwrap();
        poll(|| {
            let free = !held(driver.root());
            let reaped = pid_gone(vendor);
            released_early |= free && !reaped;
            driver.root().join("reaped-receipt").exists() || released_early
        });
    }
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let completed = driver.root().join("vendor-completed").exists();
    let post = std::fs::read(driver.root().join("post-called")).ok();
    let unlocked = matches!(
        AccountLoginLock::acquire(&driver.root().join("base"), account()),
        Ok(AcquireOutcome::Acquired(_))
    );
    let status = driver.finish_and_reap();
    assert!(survived && killed, "{RETAIN_ASSERTION}");
    assert!(
        !released_early,
        "{LATE_ASSERTION}: lock released before reap"
    );
    assert!(
        reaped
            && !completed
            && unlocked
            && post.is_none()
            && receipt
                .as_ref()
                .is_some_and(|r| actual_cancel_receipt(r, Some(libc::SIGKILL)))
            && status.is_some_and(|status| status.code() == Some(130)),
        "{LATE_ASSERTION}"
    );
}

fn pid_gone(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only probes existence of a pid this test once owned.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

/// Stall-injection RED for the pgid case (an internal ticket acceptance 3): when an io stall
/// lets the vendor exit and be reaped BEFORE the test signals its group, the
/// owned-pgid read must refuse (`getpgid` == -1) instead of signalling a stale
/// group. The injected stall is the late `signal_group` after the full reap.
#[test]
#[should_panic(expected = "LOGIN_CTRLC_OWNED_VENDOR_PGID")]
fn login_ctrlc_pgid_assertion_refuses_a_vendor_gone_before_the_signal() {
    let _env_guard = csq_core::platform::test_env::lock();
    let mut driver = Driver::spawn("driver-ignore");
    assert!(driver.ready());
    driver.release();
    let receipt = driver.receipt();
    assert!(
        receipt.is_some(),
        "vendor must be reaped before the injected late signal"
    );
    driver.signal_group();
}

/// Last-resort cleanup for the exact driver and vendor pids a test spawned. It
/// SIGKILLs a pid only while that pid is still alive and only those two pids,
/// so a regression fails the row without leaking a frozen process onto a
/// fleet host.
struct LeakKiller(Vec<libc::pid_t>);
impl Drop for LeakKiller {
    fn drop(&mut self) {
        for pid in self.0.drain(..) {
            if !pid_gone(pid) {
                // SAFETY: a pid this test spawned and observed still alive.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }
}

/// Stall-injection RED for the cross-test-leak case (an internal ticket acceptance 3): a
/// failure while the driver is frozen (the worst stall) must still leave no
/// live driver or vendor behind, otherwise the next test's setup hits
/// `still running`.
#[test]
fn login_ctrlc_failure_while_driver_frozen_leaves_no_live_process() {
    let _env_guard = csq_core::platform::test_env::lock();
    // Declared before the driver, so on any unwind it drops AFTER the driver's
    // own cleanup has had its chance and only kills what is still alive.
    let mut leak_killer = LeakKiller(Vec::new());
    let mut driver = Driver::spawn("driver-ignore");
    assert!(driver.ready());
    let driver_pid = driver.pid;
    let vendor_pid = libc::pid_t::try_from(driver.vendor_pid.unwrap()).unwrap();
    leak_killer.0.extend([driver_pid, vendor_pid]);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _stopped = driver.stop();
        panic!("injected failure while the driver is frozen");
    }));
    assert!(unwound.is_err());
    drop(driver);
    assert!(pid_gone(vendor_pid), "vendor leaked past the failed test");
    assert!(pid_gone(driver_pid), "driver leaked past the failed test");
}
