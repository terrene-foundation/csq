//! Owned native identity/event fixtures; real Windows execution required.
//! No installer, real daemon, credentials or user-wide legacy event is run.
#![cfg(all(windows, feature = "test-utils"))]

use csq_core::update::upgrade_guard::{
    basename_may_match,
    quit_event::{desktop_quit_available, signal_desktop_quit, DesktopQuitEvent},
    windows::{validate_snapshot_for_test, OwnerFault, WindowsBackend},
    Backend, Candidate, QuitChannel, Role,
};
use std::{
    ffi::OsString,
    io::{BufRead, BufReader, Read, Write},
    os::windows::io::AsRawHandle,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_BROKEN_PIPE, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{Pipes::PeekNamedPipe, Threading::WaitForSingleObject},
};

struct Fixture {
    child: Option<Child>,
    reader: Option<JoinHandle<()>>,
    reader_done: mpsc::Receiver<()>,
    protocol: mpsc::Receiver<String>,
    endpoint_seen: Arc<AtomicBool>,
    executable: PathBuf,
    root: Option<tempfile::TempDir>,
}

impl Fixture {
    fn spawn(basename: &str) -> Self {
        let root = tempfile::TempDir::new().unwrap();
        let executable = root.path().join(basename);
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let mut command = Command::new(&executable);
        command.env_clear();
        for key in ["SYSTEMROOT", "SystemRoot", "WINDIR", "NUMBER_OF_PROCESSORS"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        for key in [
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "CSQ_BASE_DIR",
            "CLAUDE_CONFIG_DIR",
            "TMPDIR",
            "TEMP",
            "TMP",
        ] {
            let directory = root.path().join(key.to_ascii_lowercase());
            std::fs::create_dir_all(&directory).unwrap();
            command.env(key, directory);
        }
        command
            .current_dir(root.path())
            .env("CSQ_GUARD_OWNED_ENTRY", "1")
            .args(["daemon", "start", "--nocapture"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, protocol) = mpsc::channel();
        let (done, reader_done) = mpsc::channel();
        let endpoint_seen = Arc::new(AtomicBool::new(false));
        let endpoint_for_reader = Arc::clone(&endpoint_seen);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some((_, suffix)) = line.split_once("CSQ_GUARD_") {
                    let message = format!("CSQ_GUARD_{suffix}");
                    if message == "CSQ_GUARD_ENDPOINT_OBSERVED" {
                        endpoint_for_reader.store(true, Ordering::SeqCst);
                    }
                    let _ = tx.send(message);
                }
            }
            let _ = done.send(());
        });
        let fixture = Self {
            child: Some(child),
            reader: Some(reader),
            reader_done,
            protocol,
            endpoint_seen,
            executable,
            root: Some(root),
        };
        assert_eq!(
            fixture
                .protocol
                .recv_timeout(Duration::from_secs(3))
                .unwrap(),
            format!("CSQ_GUARD_READY {}", fixture.pid())
        );
        fixture
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }
    fn handle(&self) -> HANDLE {
        self.child.as_ref().unwrap().as_raw_handle() as HANDLE
    }
    fn candidate(&self) -> Candidate {
        Candidate {
            pid: self.pid(),
            basename: self.executable.file_name().map(|name| name.to_os_string()),
        }
    }
    fn assert_live(&self) {
        // SAFETY: this fixture retains the owned process handle.
        assert_eq!(
            unsafe { WaitForSingleObject(self.handle(), 0) },
            WAIT_TIMEOUT
        );
    }
    fn assert_probe_clear(&mut self) {
        self.child
            .as_mut()
            .unwrap()
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"?")
            .unwrap();
        self.child
            .as_mut()
            .unwrap()
            .stdin
            .as_mut()
            .unwrap()
            .flush()
            .unwrap();
        assert_eq!(
            self.protocol.recv_timeout(Duration::from_secs(2)).unwrap(),
            "CSQ_GUARD_PROBE_CLEAR",
            "child must observe its endpoint unsignaled AFTER the probe returned"
        );
    }
    fn wait_exit(&self) {
        // SAFETY: no PID lookup, the owned process handle stays valid during wait.
        assert_eq!(
            unsafe { WaitForSingleObject(self.handle(), 2_000) },
            WAIT_OBJECT_0
        );
    }
    fn preserve_unknown(&mut self, reason: &str) {
        let root = self.root.take().map(tempfile::TempDir::keep);
        eprintln!(
            "OWNED_FIXTURE_CLEANUP_UNDETERMINED reason={reason} pid={:?} root={root:?}",
            self.child.as_ref().map(Child::id)
        );
    }
    fn release_and_reap(&mut self) -> bool {
        if let Some(child) = self.child.as_mut() {
            // Private EOF is the only fallback: the child sees EOF and returns.
            drop(child.stdin.take());
            // SAFETY: Child owns this exact process handle, never a recycled PID.
            if unsafe { WaitForSingleObject(child.as_raw_handle() as HANDLE, 2_000) }
                != WAIT_OBJECT_0
            {
                self.preserve_unknown("NATURAL_EXIT_NOT_PROVEN");
                return false;
            }
            match child.wait() {
                Ok(status) if status.success() => self.child = None,
                _ => {
                    self.preserve_unknown("CHILD_REAP_OR_STATUS");
                    return false;
                }
            }
        }
        if self.reader.is_some() {
            if self
                .reader_done
                .recv_timeout(Duration::from_secs(2))
                .is_err()
            {
                self.preserve_unknown("READER_COMPLETION_NOT_PROVEN");
                return false;
            }
            if self.reader.take().unwrap().join().is_err() {
                self.preserve_unknown("READER_PANICKED");
                return false;
            }
        }
        true
    }
    fn finish(mut self, expect_endpoint: bool) {
        self.wait_exit();
        assert!(self.release_and_reap(), "owned fixture custody unresolved");
        if expect_endpoint {
            assert!(
                self.endpoint_seen.load(Ordering::SeqCst),
                "child did not observe bound endpoint"
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if !self.release_and_reap() && !std::thread::panicking() {
            panic!("owned fixture natural cleanup remains UNDETERMINED");
        }
    }
}

fn basename(tag: &str, suffix: &tempfile::TempDir) -> String {
    format!(
        "csq-{tag}-{}-{}.exe",
        std::process::id(),
        suffix.path().file_name().unwrap().to_string_lossy()
    )
}

#[test]
fn native_birth_bound_probe_is_nondestructive_and_quit_targets_owned_child() {
    let _env_guard = csq_core::platform::test_env::lock();
    let suffix = tempfile::TempDir::new().unwrap();
    let name = basename("upgrade", &suffix);
    let mut own = Fixture::spawn(&name);
    let foreign = Fixture::spawn(&name);
    let mut backend = WindowsBackend::new(None).unwrap();
    let installed = [own.executable.clone()];
    let inspected = backend
        .inspect(&own.candidate(), &installed)
        .unwrap()
        .unwrap();
    assert!(inspected.installed && inspected.role == Role::Daemon);
    assert_eq!(WindowsBackend::pid(&inspected.handle), own.pid());
    assert_ne!(WindowsBackend::birth(&inspected.handle), 0);
    assert_eq!(
        backend.quit_channel(&inspected.handle).unwrap(),
        QuitChannel::Bound
    );
    assert!(desktop_quit_available(own.pid(), own.handle()).unwrap());
    own.assert_probe_clear();
    backend
        .request_quit(&inspected.handle, QuitChannel::Bound)
        .unwrap();
    own.wait_exit();
    assert!(backend.exited(&inspected.handle).unwrap());
    foreign.assert_live();
    assert!(signal_desktop_quit(foreign.pid(), foreign.handle()).unwrap());
    own.finish(true);
    foreign.finish(true);
}

#[test]
fn native_mismatched_pid_and_retained_handle_refuse_before_signal() {
    let _env_guard = csq_core::platform::test_env::lock();
    let suffix = tempfile::TempDir::new().unwrap();
    let name = basename("mismatch", &suffix);
    let own = Fixture::spawn(&name);
    let other = Fixture::spawn(&name);
    assert!(desktop_quit_available(other.pid(), own.handle()).is_err());
    assert!(signal_desktop_quit(other.pid(), own.handle()).is_err());
    own.assert_live();
    other.assert_live();
    assert!(signal_desktop_quit(own.pid(), own.handle()).unwrap());
    assert!(signal_desktop_quit(other.pid(), other.handle()).unwrap());
    own.finish(true);
    other.finish(true);
}

#[test]
fn native_installed_image_with_different_or_unreadable_owner_refuses() {
    let _env_guard = csq_core::platform::test_env::lock();
    let suffix = tempfile::TempDir::new().unwrap();
    let own = Fixture::spawn(&basename("owner", &suffix));
    let installed = [own.executable.clone()];
    let mut refusals = Vec::new();
    for fault in [OwnerFault::Different, OwnerFault::Unreadable] {
        let mut backend = WindowsBackend::new(None)
            .unwrap()
            .with_owner_fault_for_test(fault);
        refusals.push(backend.inspect(&own.candidate(), &installed).is_err());
        own.assert_live();
    }
    // Actual owner/image positive control; faults can only remove authority.
    let mut actual = WindowsBackend::new(None).unwrap();
    assert!(
        actual
            .inspect(&own.candidate(), &installed)
            .unwrap()
            .unwrap()
            .installed
    );
    assert_eq!(
        refusals,
        [true, true],
        "installed Different and Unreadable owners must both refuse; baseline is [false, true]"
    );
    // Drop releases private EOF, then proves natural exit/reap.
}

#[test]
fn native_foreign_owner_noninstalled_image_is_skipped() {
    let _env_guard = csq_core::platform::test_env::lock();
    let suffix = tempfile::TempDir::new().unwrap();
    let name = basename("outside", &suffix);
    let own = Fixture::spawn(&name);
    let outside = Fixture::spawn(&name);
    let mut backend = WindowsBackend::new(None)
        .unwrap()
        .with_owner_fault_for_test(OwnerFault::Different);
    assert!(backend
        .inspect(&outside.candidate(), std::slice::from_ref(&own.executable))
        .unwrap()
        .is_none());
    own.assert_live();
    outside.assert_live();
}

#[test]
fn native_unrelated_unicode_basename_is_a_negative_filter() {
    let candidate = Candidate {
        pid: 1234,
        basename: Some("编辑器.exe".into()),
    };
    assert!(!basename_may_match(
        &candidate,
        &[PathBuf::from(r"C:\installed\csq.exe")]
    ));
}

#[test]
fn native_snapshot_requires_helper_pid_and_actual_census_contains_it() {
    let _env_guard = csq_core::platform::test_env::lock();
    let pid = std::process::id();
    let own = Candidate {
        pid,
        basename: Some("csq-upgrade-guard.exe".into()),
    };
    let empty_refused = validate_snapshot_for_test(&[], pid).is_err();
    let missing_refused = validate_snapshot_for_test(
        &[Candidate {
            pid: pid.wrapping_add(1),
            basename: None,
        }],
        pid,
    )
    .is_err();
    let valid = validate_snapshot_for_test(&[own], pid).is_ok();
    let mut backend = WindowsBackend::new(None).unwrap();
    let actual_contains_self = backend.scan().unwrap().iter().any(|row| row.pid == pid);
    assert_eq!(
        (empty_refused, missing_refused, valid, actual_contains_self),
        (true, true, true, true)
    );
}

#[test]
fn native_legacy_request_refuses_with_no_user_wide_signal_capability() {
    let _env_guard = csq_core::platform::test_env::lock();
    // SAFETY GATE: baseline must fail HERE, never invoke its legacy signal route.
    let source = include_str!("../src/update/upgrade_guard/quit_event.rs");
    assert!(!source.contains("fn signal_legacy_daemon_quit("),
        "legacy global signalling capability must be removed before this row can invoke request_quit");
    let suffix = tempfile::TempDir::new().unwrap();
    let own = Fixture::spawn(&basename("legacy-refusal", &suffix));
    let mut backend = WindowsBackend::new(None).unwrap();
    let inspected = backend
        .inspect(&own.candidate(), std::slice::from_ref(&own.executable))
        .unwrap()
        .unwrap();
    assert!(backend
        .request_quit(&inspected.handle, QuitChannel::Legacy)
        .is_err());
    own.assert_live();
}

#[test]
fn native_fixture_eof_drop_reaps_without_endpoint_or_force() {
    let _env_guard = csq_core::platform::test_env::lock();
    let suffix = tempfile::TempDir::new().unwrap();
    let mut own = Fixture::spawn(&basename("eof", &suffix));
    assert!(own.release_and_reap());
    assert!(own.child.is_none());
    assert!(!own.endpoint_seen.load(Ordering::SeqCst));
}

fn run_helper(arguments: &[OsString]) -> std::process::Output {
    let root = tempfile::TempDir::new().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_csq-upgrade-guard"));
    command.env_clear();
    for key in ["SYSTEMROOT", "SystemRoot", "WINDIR", "NUMBER_OF_PROCESSORS"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    for key in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "CSQ_BASE_DIR",
        "CLAUDE_CONFIG_DIR",
        "TMPDIR",
        "TEMP",
        "TMP",
    ] {
        let directory = root.path().join(key.to_ascii_lowercase());
        std::fs::create_dir_all(&directory).unwrap();
        command.env(key, directory);
    }
    let child = command
        .current_dir(root.path())
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // SAFETY: this test owns the exact child handle; no PID-based signal.
    if unsafe { WaitForSingleObject(child.as_raw_handle() as HANDLE, 2_000) } != WAIT_OBJECT_0 {
        let pid = child.id();
        let path = root.keep();
        panic!("OWNED_HELPER_EXIT_UNDETERMINED pid={pid} root={path:?}; preserve private clone");
    }
    child.wait_with_output().unwrap()
}

#[test]
fn native_helper_missing_image_refuses_with_existing_only_instruction() {
    let _env_guard = csq_core::platform::test_env::lock();
    let root = tempfile::TempDir::new().unwrap();
    let missing = root.path().join("not-installed.exe");
    assert!(!missing.exists());
    let output = run_helper(&[OsString::from("--image"), missing.into_os_string()]);
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("--image must name an existing installed binary"));
}

#[test]
fn native_helper_help_exposes_mandatory_installer_recheck_boundary() {
    let _env_guard = csq_core::platform::test_env::lock();
    let output = run_helper(&[OsString::from("--help")]);
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("installer MUST re-check and hold an admission lock across replace"));
}

#[test]
fn daemon_start_owned_fixture_entry() {
    let _env_guard = csq_core::platform::test_env::lock();
    if std::env::var_os("CSQ_GUARD_OWNED_ENTRY").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    // This is a native identity fixture, not an application/refresher host.
    let event = DesktopQuitEvent::create_current().unwrap();
    println!("CSQ_GUARD_READY {}", std::process::id());
    std::io::stdout().flush().unwrap();
    let start = Instant::now();
    let mut input = std::io::stdin();
    while start.elapsed() < Duration::from_secs(10) {
        if event.wait_for_quit(Duration::from_millis(50)).unwrap() {
            println!("CSQ_GUARD_ENDPOINT_OBSERVED");
            return;
        }
        let mut available = 0;
        // SAFETY: stdin is this child's private inherited pipe; no other reader.
        let queried = unsafe {
            PeekNamedPipe(
                input.as_raw_handle() as HANDLE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if queried == 0 {
            // SAFETY: read directly after the failed pipe probe.
            assert_eq!(unsafe { GetLastError() }, ERROR_BROKEN_PIPE);
            println!("CSQ_GUARD_PRIVATE_EOF_EXIT");
            return;
        }
        if available > 0 {
            let mut byte = [0];
            input.read_exact(&mut byte).unwrap();
            assert_eq!(byte, [b'?']);
            assert!(!event.wait_for_quit(Duration::ZERO).unwrap());
            println!("CSQ_GUARD_PROBE_CLEAR");
            std::io::stdout().flush().unwrap();
        }
    }
    panic!("owned fixture exceeded its private control deadline");
}
