//! Actual native CLI core seam plus scoped inherited child custody, inert inputs only.
//! Kimi and Grok each cover SIGINT exit, ignored SIGINT/late zero, and real binding.
//! All drivers deliberately retain an inert prior handler for safe mutant cleanup;
//! no prevention of raw SIG_DFL parent death or Windows runtime is claimed.
#![cfg(unix)]

#[path = "../src/login_cancel_guard.rs"]
mod login_cancel_guard;
#[path = "../src/login_child_custody.rs"]
mod login_child_custody;

use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::providers::{catalog::Surface, native, native_login};
use csq_core::types::AccountNum;
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const ENTRY: &str = "login_native_ctrlc_private_entry";
const ROLE: &str = "CSQ_PRIVATE_NATIVE_CTRLC_ROLE";
const ROOT: &str = "CSQ_PRIVATE_NATIVE_CTRLC_ROOT";
const SURFACE: &str = "CSQ_PRIVATE_NATIVE_CTRLC_SURFACE";
const CREDS: &[u8] = br#"{"fixture":"native-inert-credential"}"#;
const DEFAULT_ASSERTION: &str = "LOGIN_NATIVE_CTRLC_DEFAULT_REAP_CANCEL130";
const RETAIN_ASSERTION: &str = "LOGIN_NATIVE_CTRLC_RETAIN_LOCK_PING";
const LATE_ASSERTION: &str = "LOGIN_NATIVE_CTRLC_LATE_ZERO_NO_POST";
const CONTROL_ASSERTION: &str = "LOGIN_NATIVE_CTRLC_CONTROL_BINDING";
const PRIOR_ASSERTION: &str = "LOGIN_NATIVE_CTRLC_PRIOR_RESTORED";
// These are failure/cleanup budgets, never scheduler-speed success assertions.
// Every successful transition requires its causal marker or fresh nonce.
const BUDGET: Duration = Duration::from_secs(8);
const PGID_ASSERTION: &str = "LOGIN_NATIVE_CTRLC_OWNED_VENDOR_PGID";
const REAP_ASSERTION: &str = "LOGIN_NATIVE_CTRLC_ACTUAL_CHILD_REAP";

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

fn selected_command(root: &Path, role: &str, surface: Surface) -> std::io::Result<Command> {
    for relative in ["home", "base", "config", "bin", "tmp", "appdata", "local"] {
        std::fs::create_dir_all(root.join(relative))?;
    }
    let descriptor = native::descriptor(surface).expect("native fixture descriptor");
    // Static shell text: no path interpolated into shell source. It validates
    // real descriptor argv then execs only this exact test executable via quoted env.
    const STUB: &str = "#!/bin/sh\ncase \"$CSQ_PRIVATE_NATIVE_CTRLC_SURFACE\" in\n kimi-cli) [ \"$#\" -eq 1 ] && [ \"$1\" = login ] || exit 71 ;;\n grok) [ \"$#\" -eq 2 ] && [ \"$1\" = login ] && [ \"$2\" = --device-auth ] || exit 72 ;;\n *) exit 73 ;;\nesac\nexec \"$CSQ_PRIVATE_NATIVE_EXE\" \"$CSQ_PRIVATE_NATIVE_ENTRY\" --ignored --exact --nocapture --test-threads=1\n";
    for vendor in [native::KIMI.binary, native::GROK.binary] {
        let path = root.join("bin").join(vendor);
        std::fs::write(&path, STUB)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
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
        .env(SURFACE, descriptor.id)
        .env("CSQ_PRIVATE_NATIVE_EXE", std::env::current_exe()?)
        .env("CSQ_PRIVATE_NATIVE_ENTRY", ENTRY)
        .env("CSQ_SECRET_BACKEND", "in-memory")
        .env("KIMI_CODE_HOME", root.join("wrong-kimi"))
        .env("GROK_HOME", root.join("wrong-grok"))
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

fn run_vendor(root: &Path, ignore: bool, surface: Surface) -> ! {
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
    let descriptor = native::descriptor(surface).unwrap();
    let home = native::native_home_path(&root.join("base"), account(), surface);
    assert_eq!(
        std::env::var_os(descriptor.home_env).as_deref(),
        Some(home.as_os_str())
    );
    let sibling = if surface == Surface::Kimi {
        "GROK_HOME"
    } else {
        "KIMI_CODE_HOME"
    };
    assert!(
        std::env::var_os(sibling).is_none(),
        "native sibling home leaked"
    );
    let credential = home.join(descriptor.cred_relpath);
    std::fs::create_dir_all(credential.parent().unwrap()).unwrap();
    atomic_write(
        credential.parent().unwrap(),
        credential.file_name().unwrap().to_str().unwrap(),
        CREDS,
    )
    .unwrap();
    csq_core::platform::fs::secure_file(&credential).unwrap();
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

fn run_driver(root: &Path, role: &str, surface: Surface) -> ! {
    install_prior(false);
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
        _ => panic!("private native account lock unexpectedly held"),
    };
    let descriptor = native::descriptor(surface).unwrap();
    let vendor_role = if role == "driver-default" {
        "vendor-default"
    } else {
        "vendor-ignore"
    };
    let mut actual_reap = None;
    let mut run_calls = 0;
    let result = native_login::login_native_cli_with(
        &root.join("base"),
        account(),
        surface,
        |mut command| {
            run_calls += 1;
            // Assert the actual core-built program/argv/home overrides BEFORE fixture
            // tags or stdio are adapted. No real auth/finder fallback can be selected.
            assert_eq!(
                std::fs::canonicalize(command.get_program()).unwrap(),
                std::fs::canonicalize(root.join("bin").join(descriptor.binary)).unwrap()
            );
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                descriptor
                    .login_args
                    .iter()
                    .map(OsStr::new)
                    .collect::<Vec<_>>()
            );
            let home = native::native_home_path(&root.join("base"), account(), surface);
            let overrides = command
                .get_envs()
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(
                overrides.get(OsStr::new(descriptor.home_env)),
                Some(&Some(home.as_os_str()))
            );
            let sibling = if surface == Surface::Kimi {
                "GROK_HOME"
            } else {
                "KIMI_CODE_HOME"
            };
            assert_eq!(overrides.get(OsStr::new(sibling)), Some(&None));
            atomic_write(root, "command-plan-verified", descriptor.id.as_bytes()).unwrap();
            command
                .current_dir(root)
                .env(ROLE, vendor_role)
                .stdin(Stdio::null());
            let completed = login_cancel_guard::spawn_cli_inherited_login_receipt(
                &mut command,
                Duration::from_secs(300),
                &lock,
                descriptor.display_name,
                |_| {},
            );
            match completed {
                Ok(receipt) => {
                    let status = receipt.reaped_status();
                    actual_reap = Some((receipt.child_id(), status));
                    Ok(status)
                }
                Err(error) => {
                    if let Some(cancel) =
                        error.downcast_ref::<login_cancel_guard::CliLoginCancelled>()
                    {
                        actual_reap = cancel.child_id().zip(cancel.reaped_status());
                    }
                    Err(error)
                }
            }
        },
    );
    // The same enclosing lock spans the actual core finish/marker operation,
    // matching handle_native. It can release only after owned child completion.
    drop(lock);
    let vendor_pid: u32 = std::fs::read_to_string(root.join("vendor-ready"))
        .expect("selected native vendor reached entry")
        .parse()
        .unwrap();
    let (reaped_pid, code, signal) = actual_reap
        .map(|(pid, status)| (Some(pid), status.code(), status.signal()))
        .unwrap_or((None, None, None));
    let exit = result
        .as_ref()
        .map(|_| 0)
        .unwrap_or_else(login_cancel_guard::cli_error_exit_code);
    let marker = native::marker_exists(&root.join("base"), account(), surface);
    if result.is_ok() {
        atomic_write(root, "post-called", b"1").unwrap();
    }
    let prior_at_return = PRIOR_SIGNALS.load(Ordering::SeqCst);
    let receipt = serde_json::json!({
        "vendor_pid":vendor_pid,"reaped_pid":reaped_pid,"exit":exit,
        "publication":usize::from(marker),"vendor_code":code,"vendor_signal":signal,
        "prior_signals_at_return":prior_at_return,"run_calls":run_calls,
    });
    atomic_write(
        root,
        "reaped-receipt",
        serde_json::to_string(&receipt).unwrap().as_bytes(),
    )
    .unwrap();
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
            "private native controller never finished"
        );
        std::thread::yield_now();
    }
}

#[test]
#[ignore = "fixture dispatcher; invoked only by an owned subprocess with explicit role"]
fn login_native_ctrlc_private_entry() {
    let _env_guard = csq_core::platform::test_env::lock();
    let Some(role) = std::env::var_os(ROLE) else {
        return;
    };
    let role = role.to_str().expect("private fixture role");
    let root = PathBuf::from(std::env::var_os(ROOT).expect("private fixture root"));
    let provider = std::env::var(SURFACE).expect("private native surface");
    let surface = native::descriptor_by_id(&provider)
        .expect("private native descriptor")
        .surface;
    assert_eq!(std::env::var("CSQ_SECRET_BACKEND").unwrap(), "in-memory");
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
        "vendor-default" => run_vendor(&root, false, surface),
        "vendor-ignore" => run_vendor(&root, true, surface),
        "driver-default" | "driver-ignore" | "driver-control" => run_driver(&root, role, surface),
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
    surface: Surface,
    logs_forwarded: bool,
    vendor_pid: Option<u32>,
}

impl Driver {
    fn spawn(role: &'static str, surface: Surface) -> Self {
        let sandbox = tempfile::tempdir().unwrap();
        let mut command = selected_command(sandbox.path(), role, surface).unwrap();
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
            surface,
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
            .filter(|line| *line == notice_text(self.surface))
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
                "LOGIN_NATIVE_CTRLC_CUSTODY_UNKNOWN: actual driver/vendor cleanup not proved: {}",
                root.display()
            );
        }
    }
}

fn notice_text(surface: Surface) -> String {
    format!(
        "Cancelling — waiting for {} login to exit",
        native::descriptor(surface).unwrap().display_name
    )
}

fn credential_present(root: &Path, surface: Surface) -> bool {
    let descriptor = native::descriptor(surface).unwrap();
    std::fs::read(
        native::native_home_path(&root.join("base"), account(), surface)
            .join(descriptor.cred_relpath),
    )
    .ok()
    .as_deref()
        == Some(CREDS)
}

fn unbound(root: &Path, surface: Surface) -> bool {
    !native::marker_exists(&root.join("base"), account(), surface)
        && native::native_surface_for_slot(&root.join("base"), account()).is_none()
}

fn actual_cancel_receipt(receipt: &serde_json::Value, signal: Option<i32>) -> bool {
    receipt["exit"] == 130
        && receipt["publication"] == 0
        && receipt["run_calls"] == 1
        && receipt["reaped_pid"] == receipt["vendor_pid"]
        && receipt["reaped_pid"].as_u64().is_some()
        && if let Some(signal) = signal {
            receipt["vendor_signal"] == signal && receipt["vendor_code"].is_null()
        } else {
            receipt["vendor_code"] == 0 && receipt["vendor_signal"].is_null()
        }
}

fn assert_default(surface: Surface) {
    let mut driver = Driver::spawn("driver-default", surface);
    let ready = driver.ready();
    if ready {
        driver.signal_group();
    }
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let notices = driver.notices("driver-default");
    let preserved = credential_present(driver.root(), surface) && unbound(driver.root(), surface);
    let planned = driver.root().join("command-plan-verified").exists();
    if reaped {
        driver.signal_driver();
    }
    let restored = reaped && poll(|| driver.root().join("prior-restored").exists());
    let status = driver.finish_and_reap();
    assert!(
        ready
            && reaped
            && planned
            && preserved
            && notices == 1
            && receipt
                .as_ref()
                .is_some_and(|r| actual_cancel_receipt(r, Some(libc::SIGINT))
                    && r["prior_signals_at_return"] == 0)
            && status.is_some_and(|s| s.code() == Some(130)),
        "{DEFAULT_ASSERTION}"
    );
    assert!(restored, "{PRIOR_ASSERTION}");
    assert!(reaped, "{REAP_ASSERTION}");
}

fn assert_ignored(surface: Surface) {
    let mut driver = Driver::spawn("driver-ignore", surface);
    let ready = driver.ready();
    if ready {
        driver.signal_group();
    }
    let cancelled = ready && poll(|| driver.notices("driver-ignore") > 0);
    let retained = cancelled
        && held(driver.root())
        && driver.ping(b"native-after-cancel-1")
        && !driver.root().join("reaped-receipt").exists()
        && unbound(driver.root(), surface);
    let second = if retained {
        driver.signal_group();
        let ack = driver.ping(b"native-after-repeat-2");
        driver.signal_group();
        ack
    } else {
        false
    };
    let repeated = retained
        && second
        && driver.ping(b"native-after-repeat-3")
        && held(driver.root())
        && !driver.root().join("reaped-receipt").exists()
        && unbound(driver.root(), surface);
    if ready {
        driver.assert_live_vendor_group();
    }
    driver.release();
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let preserved = credential_present(driver.root(), surface) && unbound(driver.root(), surface);
    let completed = driver.root().join("vendor-completed").exists();
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
            && preserved
            && unlocked
            && notices == 1
            && receipt
                .as_ref()
                .is_some_and(|r| actual_cancel_receipt(r, None))
            && status.is_some_and(|s| s.code() == Some(130)),
        "{LATE_ASSERTION}"
    );
}

fn assert_control(surface: Surface) {
    let mut driver = Driver::spawn("driver-control", surface);
    let ready = driver.ready();
    let live = ready
        && held(driver.root())
        && driver.ping(b"native-control-before-release")
        && unbound(driver.root(), surface);
    if ready {
        driver.assert_live_vendor_group();
    }
    driver.release();
    let receipt = driver.receipt();
    let reaped = receipt
        .as_ref()
        .is_some_and(|r| driver.actual_reap_matches_spawn(r));
    let completed = driver.root().join("vendor-completed").exists();
    let binding = native::read_binding(&driver.root().join("base"), account(), surface).ok();
    let bound = credential_present(driver.root(), surface)
        && binding
            .as_ref()
            .is_some_and(|b| b.surface == surface.as_str())
        && native::native_surface_for_slot(&driver.root().join("base"), account()) == Some(surface);
    let notices = driver.notices("driver-control");
    let status = driver.finish_and_reap();
    assert!(
        ready
            && live
            && reaped
            && completed
            && bound
            && notices == 0
            && receipt.as_ref().is_some_and(|r| r["exit"] == 0
                && r["publication"] == 1
                && r["run_calls"] == 1
                && r["vendor_code"] == 0
                && r["vendor_signal"].is_null())
            && status.is_some_and(|s| s.code() == Some(0)),
        "{CONTROL_ASSERTION}"
    );
}

#[test]
fn login_native_kimi_ctrlc_default_reaps_cancel130_no_binding() {
    let _env_guard = csq_core::platform::test_env::lock();
    assert_default(Surface::Kimi);
}

#[test]
fn login_native_kimi_ctrlc_ignored_sigint_retains_lock_until_late_zero_no_binding() {
    let _env_guard = csq_core::platform::test_env::lock();
    assert_ignored(Surface::Kimi);
}

#[test]
fn login_native_kimi_no_cancel_actual_zero_writes_binding() {
    let _env_guard = csq_core::platform::test_env::lock();
    assert_control(Surface::Kimi);
}

#[test]
fn login_native_grok_ctrlc_default_reaps_cancel130_no_binding() {
    let _env_guard = csq_core::platform::test_env::lock();
    assert_default(Surface::Grok);
}

#[test]
fn login_native_grok_ctrlc_ignored_sigint_retains_lock_until_late_zero_no_binding() {
    let _env_guard = csq_core::platform::test_env::lock();
    assert_ignored(Surface::Grok);
}

#[test]
fn login_native_grok_no_cancel_actual_zero_writes_binding() {
    let _env_guard = csq_core::platform::test_env::lock();
    assert_control(Surface::Grok);
}
