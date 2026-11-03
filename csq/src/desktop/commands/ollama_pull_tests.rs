//! Real worker/subprocess regressions. All terminals, homes and actors belong to
//! this fixture. No vendor, daemon, keychain or live session is consulted.
use super::{cancel_ollama_pull_from, ollama_version_available, pull_ollama_model_blocking};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::Listener;

const ENTRY: &str = "desktop::commands::ollama_pull_tests::fixture_entry";
const READY_BUDGET: Duration = Duration::from_secs(8);
// The actor cannot finish normally until RELEASE. Thus the failing outcome is
// causally blocked, not a slower acceptable runtime. Two seconds allows the
// already-running cancel thread to be scheduled; it is not a performance SLO.
// The overlap case has the longest conservative actor-connect envelope:
// two actor readiness handshakes (accept + first-byte read: 2 * 16s), second
// registration (8s), first completion observation (8s), and cleanup (8s):
// 56s total. The 64s emergency watchdog adds one readiness bound (8s). Single
// actor cases fit within 34s. Watchdog exit is always a fixture failure, even
// if a host stall lets it unblock the production wait mutex.
const CANCEL_BUDGET: Duration = Duration::from_secs(2);
const ACTOR_WATCHDOG: Duration = Duration::from_secs(64);
const MODEL: &str = "FAKETEST model;literal";

fn until(budget: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn termios(fd: &impl AsRawFd) -> libc::termios {
    let mut value = std::mem::MaybeUninit::uninit();
    assert_eq!(
        unsafe { libc::tcgetattr(fd.as_raw_fd(), value.as_mut_ptr()) },
        0,
        "FAKETEST_pty_attributes_unavailable"
    );
    unsafe { value.assume_init() }
}

fn pty() -> (File, File) {
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0,
        "FAKETEST_pty_create_failed"
    );
    // Ownership transfers only after openpty succeeds; no numeric PID signals.
    let pair = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    for fd in [&pair.0, &pair.1] {
        assert_eq!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
            0,
            "FAKETEST_pty_cloexec_failed"
        );
    }
    let mut settings = termios(&pair.1);
    settings.c_lflag |= libc::ECHO | libc::ICANON;
    assert_eq!(
        unsafe { libc::tcsetattr(pair.1.as_raw_fd(), libc::TCSANOW, &settings) },
        0
    );
    pair
}

struct Fixture {
    home: tempfile::TempDir,
    listener: UnixListener,
    release: Option<UnixStream>,
    child: Option<Child>,
    master: File,
    slave: File,
}

impl Fixture {
    fn new() -> Self {
        // Short socket path stays below sockaddr_un's limit on macOS, including
        // when the host's TMPDIR is a long per-user path. Still a private TempDir.
        let home = tempfile::Builder::new()
            .prefix("csq-ollama-")
            .tempdir_in("/tmp")
            .expect("FAKETEST_home_create_failed");
        std::fs::create_dir(home.path().join("base")).unwrap();
        let listener = UnixListener::bind(home.path().join("release.sock"))
            .expect("FAKETEST_release_bind_failed");
        listener.set_nonblocking(true).unwrap();
        let (master, slave) = pty();
        Self {
            home,
            listener,
            release: None,
            child: None,
            master,
            slave,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.home.path().join(name)
    }

    fn spawn(&mut self, role: &str) {
        self.spawn_with_second_home(role, None);
    }

    fn spawn_with_second_home(&mut self, role: &str, second_home: Option<&Path>) {
        let exe = std::env::current_exe().expect("FAKETEST_test_exe_missing");
        let mut command = Command::new(&exe);
        command.env_clear()
            // Explicit Unix stdlib whitelist, with fixture-owned HOME/TMPDIR.
            .env("PATH", "/usr/bin:/bin").env("LANG", "C").env("LC_ALL", "C")
            .env("TERM", "dumb").env("HOME", self.home.path())
            .env("TMPDIR", self.home.path()).env("CSQ_BASE_DIR", self.path("base"))
            .env("FAKETEST_OLLAMA_ROLE", role)
            .env("FAKETEST_OLLAMA_TEST_EXE", exe)
            .args(["--exact", ENTRY, "--nocapture"])
            .stdin(Stdio::from(self.slave.try_clone().unwrap()))
            // The assertions use fixed files/events, never captured arbitrary
            // subprocess diagnostics. These null streams cannot fill and hang.
            .stdout(Stdio::null()).stderr(Stdio::null());
        if let Some(second_home) = second_home {
            command.env("FAKETEST_OLLAMA_SECOND_HOME", second_home);
        }
        // Queue input before the child starts; scheduler latency cannot decide
        // whether the explicit-stdin positive control sees its fixed marker.
        self.master.write_all(b"FAKETEST_INPUT\n").unwrap();
        self.child = Some(command.spawn().expect("FAKETEST_driver_spawn_failed"));
    }

    fn ready(&mut self) {
        let mut accepted = None;
        assert!(
            until(READY_BUDGET, || {
                match self.listener.accept() {
                    Ok((stream, _)) => {
                        accepted = Some(stream);
                        true
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
                    Err(_) => panic!("FAKETEST_release_accept_failed"),
                }
            }),
            "FAKETEST_vendor_not_ready"
        );
        let mut stream = accepted.unwrap();
        // Darwin may inherit O_NONBLOCK from the listening descriptor.
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(READY_BUDGET)).unwrap();
        let mut ready = [0u8; 1];
        stream
            .read_exact(&mut ready)
            .expect("FAKETEST_ready_read_failed");
        assert_eq!(ready, [b'R']);
        self.release = Some(stream);
    }

    fn release(&mut self) {
        if let Some(mut stream) = self.release.take() {
            let _ = stream.write_all(b"X");
        }
    }

    fn finish(&mut self) {
        self.release();
        let child = self.child.as_mut().unwrap();
        let mut status = None;
        assert!(
            until(READY_BUDGET, || {
                status = child.try_wait().expect("FAKETEST_driver_wait_failed");
                status.is_some()
            }),
            "FAKETEST_driver_cleanup_timeout"
        );
        assert!(
            !self.path("vendor-aborted").exists(),
            "FAKETEST_actor_watchdog_or_aborted_release"
        );
        assert!(status.unwrap().success(), "FAKETEST_driver_failed");
        self.child.take();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // This release does not touch the production child mutex. If readiness
        // failed before accept, try accepting once more to release that actor.
        if self.release.is_none() {
            if let Ok((stream, _)) = self.listener.accept() {
                self.release = Some(stream);
            }
        }
        self.release();
        if let Some(mut child) = self.child.take() {
            if !until(READY_BUDGET, || child.try_wait().ok().flatten().is_some()) {
                // This is the owned driver handle, never a saved PID/PGID.
                let _ = child.kill();
                let _ = until(READY_BUDGET, || child.try_wait().ok().flatten().is_some());
            }
        }
    }
}

#[test]
fn positive_control_vendor_reads_and_changes_only_disposable_pty() {
    let _env = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::new();
    fixture.spawn("vendor");
    fixture.ready();
    let observation = std::fs::read_to_string(fixture.path("stdin-observation")).unwrap();
    let echo_changed = termios(&fixture.slave).c_lflag & libc::ECHO == 0;
    fixture.finish();
    assert_eq!(observation, "FAKETEST_TTY_READ_CHANGED");
    assert!(echo_changed, "FAKETEST_positive_control_did_not_change_pty");
}

#[test]
fn worker_stdin_is_eof_and_does_not_change_disposable_pty() {
    let _env = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::new();
    fixture.spawn("pull");
    fixture.ready();
    let observation = std::fs::read_to_string(fixture.path("stdin-observation")).unwrap();
    let echo_preserved = termios(&fixture.slave).c_lflag & libc::ECHO != 0;
    fixture.finish();
    assert_eq!(
        observation, "FAKETEST_NONTTY_EOF",
        "FAKETEST_worker_inherited_terminal_stdin"
    );
    assert!(echo_preserved, "FAKETEST_worker_changed_terminal_flags");
}

#[test]
fn version_precheck_stdin_is_eof_and_preserves_disposable_pty() {
    let _env = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::new();
    fixture.spawn("version");
    fixture.ready();
    let observation = std::fs::read_to_string(fixture.path("stdin-observation")).unwrap();
    let echo_preserved = termios(&fixture.slave).c_lflag & libc::ECHO != 0;
    fixture.finish();
    assert_eq!(
        observation, "FAKETEST_NONTTY_EOF",
        "FAKETEST_version_precheck_inherited_terminal_stdin"
    );
    assert!(
        echo_preserved,
        "FAKETEST_version_precheck_changed_terminal_flags"
    );
}

#[test]
fn worker_streams_cr_and_lf_progress_before_vendor_exit() {
    let _env = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::new();
    fixture.spawn("pull");
    fixture.ready();
    let progress = fixture.path("progress");
    let live_progress = until(READY_BUDGET, || {
        let text = std::fs::read_to_string(&progress).unwrap_or_default();
        [
            "stdout:FAKETEST_OUT_CR\n",
            "stdout:FAKETEST_OUT_LF\n",
            "stderr:FAKETEST_ERR_CR\n",
            "stderr:FAKETEST_ERR_LF\n",
        ]
        .iter()
        .all(|marker| text.contains(marker))
    });
    // No RELEASE has been sent; all four events must arrive while actor lives.
    let actor_still_waiting = fixture.release.is_some()
        && fixture
            .child
            .as_mut()
            .unwrap()
            .try_wait()
            .unwrap()
            .is_none();
    fixture.finish();
    assert!(live_progress, "FAKETEST_progress_not_live");
    assert!(
        actor_still_waiting,
        "FAKETEST_actor_exited_before_progress_check"
    );
}

#[test]
fn cancel_returns_while_vendor_is_alive_before_cooperative_release() {
    let _env = csq_core::platform::test_env::lock();
    let mut fixture = Fixture::new();
    fixture.spawn("cancel");
    fixture.ready();
    std::fs::write(fixture.path("cancel-request"), b"FAKETEST_CANCEL").unwrap();
    assert!(
        until(READY_BUDGET, || fixture.path("cancel-started").exists()),
        "FAKETEST_cancel_not_started"
    );
    let canceled_before_release = until(CANCEL_BUDGET, || fixture.path("cancel-returned").exists());
    // Always unblock the actor independently BEFORE any assertion can unwind.
    fixture.finish();
    assert!(
        canceled_before_release,
        "FAKETEST_cancel_blocked_by_worker_wait_mutex"
    );
}

#[test]
fn finished_worker_preserves_second_live_workers_cancel_handle() {
    let _env = csq_core::platform::test_env::lock();
    let mut first = Fixture::new();
    let mut second = Fixture::new();
    first.spawn_with_second_home("overlap", Some(second.home.path()));
    first.ready();
    std::fs::write(first.path("second-start"), b"FAKETEST_SECOND_START").unwrap();
    second.ready();
    let second_registered = until(READY_BUDGET, || first.path("second-registered").exists());
    first.release();
    // The driver must observe first completion, retain the second *live* child
    // registration, then cancel and reap that second production worker.
    let first_preserved_second = until(READY_BUDGET, || {
        first.path("first-preserved-second").exists()
    });
    first.finish();
    assert!(second_registered, "FAKETEST_second_worker_not_registered");
    assert!(
        first_preserved_second,
        "FAKETEST_first_worker_erased_second_handle"
    );
    assert!(
        !second.path("vendor-aborted").exists(),
        "FAKETEST_second_actor_aborted"
    );
}

/// Re-entered only in env-cleared child processes. Ordinary collection is a no-op.
#[test]
fn fixture_entry() {
    let _env = csq_core::platform::test_env::lock();
    let Ok(role) = std::env::var("FAKETEST_OLLAMA_ROLE") else {
        return;
    };
    let home = PathBuf::from(std::env::var_os("HOME").expect("FAKETEST_home_missing"));
    match role.as_str() {
        "vendor" => vendor_actor(&home),
        "vendor-second" => vendor_actor(&second_home()),
        "overlap" => overlapping_workers_driver(&home),
        "version" => {
            let binary = vendor_binary(&home);
            assert!(
                ollama_version_available(&binary),
                "FAKETEST_version_precheck_failed"
            );
        }
        "pull" | "cancel" => worker_driver(&home, role == "cancel"),
        _ => panic!("FAKETEST_unknown_role"),
    }
}

fn vendor_actor(home: &Path) {
    let is_tty = unsafe { libc::isatty(0) } == 1;
    let stdin = std::io::stdin();
    if is_tty {
        let mut settings = termios(&stdin);
        settings.c_lflag &= !libc::ECHO;
        assert_eq!(unsafe { libc::tcsetattr(0, libc::TCSANOW, &settings) }, 0);
    }
    let mut ready_fd = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(
        unsafe { libc::poll(&mut ready_fd, 1, READY_BUDGET.as_millis() as i32) } > 0,
        "FAKETEST_stdin_neither_marker_nor_eof"
    );
    let mut bytes = [0u8; 64];
    let count = stdin
        .lock()
        .read(&mut bytes)
        .expect("FAKETEST_stdin_read_failed");
    let observation = match (is_tty, &bytes[..count]) {
        (true, b"FAKETEST_INPUT\n") => "FAKETEST_TTY_READ_CHANGED",
        (false, b"") => "FAKETEST_NONTTY_EOF",
        _ => panic!("FAKETEST_unexpected_stdin"),
    };
    std::fs::write(home.join("stdin-observation"), observation).unwrap();
    let mut release =
        UnixStream::connect(home.join("release.sock")).expect("FAKETEST_release_connect_failed");
    release.set_read_timeout(Some(ACTOR_WATCHDOG)).unwrap();
    release.write_all(b"R").unwrap();
    std::io::stdout()
        .write_all(b"FAKETEST_OUT_CR\rFAKETEST_OUT_LF\n")
        .unwrap();
    std::io::stdout().flush().unwrap();
    std::io::stderr()
        .write_all(b"FAKETEST_ERR_CR\rFAKETEST_ERR_LF\n")
        .unwrap();
    std::io::stderr().flush().unwrap();
    let mut command = [0u8; 1];
    // Only explicit RELEASE certifies an ordinary successful actor exit. A
    // killed vendor can produce EOF for its parent and a nonzero child status;
    // it never reaches this marker. Timeout, premature EOF and wrong commands
    // are instrumentation failures, checked independently by Fixture::finish.
    if release.read_exact(&mut command).is_err() || command != *b"X" {
        std::fs::write(home.join("vendor-aborted"), b"FAKETEST_RELEASE_ABORTED").unwrap();
        panic!("FAKETEST_release_not_explicit");
    }
}

fn vendor_binary(home: &Path) -> PathBuf {
    vendor_binary_with_role(home, false)
}

fn vendor_binary_with_role(home: &Path, second: bool) -> PathBuf {
    let binary = home.join("ollama-fixture");
    // argv is checked before re-entering the test actor. Quoted env expansion
    // passes the test executable as one literal path; no interpolated shell -c.
    let script = concat!(
        "#!/bin/sh\n",
        "if [ \"$#\" -eq 1 ] && [ \"$1\" = --version ]; then :\n",
        "elif [ \"$#\" -eq 2 ] && [ \"$1\" = pull ] && [ \"$2\" = 'FAKETEST model;literal' ]; then :\n",
        "else exit 71; fi\n",
        "FAKETEST_OLLAMA_ROLE=vendor exec \"$FAKETEST_OLLAMA_TEST_EXE\" --exact ",
        "desktop::commands::ollama_pull_tests::fixture_entry --nocapture\n",
    );
    // The role alternatives are fixed fixture vocabulary, never user input.
    assert_eq!(
        script.matches("FAKETEST_OLLAMA_ROLE=vendor exec").count(),
        1
    );
    let script = if second {
        script.replace(
            "FAKETEST_OLLAMA_ROLE=vendor exec",
            "FAKETEST_OLLAMA_ROLE=vendor-second exec",
        )
    } else {
        script.to_string()
    };
    std::fs::write(&binary, script).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    binary
}

fn worker_driver(home: &Path, cancel: bool) {
    let binary = vendor_binary(home);
    let app = tauri::test::mock_app();
    let progress = Arc::new(Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(home.join("progress"))
            .unwrap(),
    ));
    app.listen("ollama-pull-progress", move |event| {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(event.payload()) else {
            return;
        };
        let (Some(stream), Some(line)) = (value["stream"].as_str(), value["line"].as_str()) else {
            return;
        };
        if ["stdout", "stderr"].contains(&stream)
            && [
                "FAKETEST_OUT_CR",
                "FAKETEST_OUT_LF",
                "FAKETEST_ERR_CR",
                "FAKETEST_ERR_LF",
            ]
            .contains(&line)
        {
            let _ = writeln!(progress.lock().unwrap(), "{stream}:{line}");
        }
    });
    let slot = Arc::new(Mutex::new(None));
    let worker_slot = slot.clone();
    let handle = app.handle().clone();
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = pull_ollama_model_blocking(handle, worker_slot, binary, MODEL.to_string());
        let _ = done_tx.send(result);
    });
    if cancel {
        assert!(
            until(READY_BUDGET, || home.join("cancel-request").exists()),
            "FAKETEST_cancel_request_missing"
        );
        assert!(
            slot.lock().unwrap().is_some(),
            "FAKETEST_child_not_registered"
        );
        std::fs::write(home.join("cancel-started"), b"FAKETEST_CANCEL_STARTED").unwrap();
        cancel_ollama_pull_from(&slot).expect("FAKETEST_cancel_failed");
        std::fs::write(home.join("cancel-returned"), b"FAKETEST_CANCEL_RETURNED").unwrap();
    }
    let outcome = done_rx
        .recv_timeout(ACTOR_WATCHDOG + READY_BUDGET)
        .expect("FAKETEST_worker_timeout");
    worker.join().expect("FAKETEST_worker_panicked");
    if !cancel {
        assert!(outcome.is_ok(), "FAKETEST_pull_failed");
    }
    assert!(
        slot.lock().unwrap().is_none(),
        "FAKETEST_child_slot_not_cleared"
    );
}

fn second_home() -> PathBuf {
    PathBuf::from(
        std::env::var_os("FAKETEST_OLLAMA_SECOND_HOME").expect("FAKETEST_second_home_missing"),
    )
}

fn overlapping_workers_driver(home: &Path) {
    let app = tauri::test::mock_app();
    let slot = Arc::new(Mutex::new(None));
    let (first_tx, first_rx) = mpsc::channel();
    let first_handle = app.handle().clone();
    let first_slot = slot.clone();
    let first_binary = vendor_binary(home);
    let first = std::thread::spawn(move || {
        let result =
            pull_ollama_model_blocking(first_handle, first_slot, first_binary, MODEL.to_string());
        let _ = first_tx.send(result);
    });
    assert!(
        until(READY_BUDGET, || home.join("second-start").exists()),
        "FAKETEST_second_start_missing"
    );
    let original = slot
        .lock()
        .unwrap()
        .clone()
        .expect("FAKETEST_first_child_missing");
    let (second_tx, second_rx) = mpsc::channel();
    let second_handle = app.handle().clone();
    let second_slot = slot.clone();
    let second_binary = vendor_binary_with_role(&second_home(), true);
    let second = std::thread::spawn(move || {
        let result = pull_ollama_model_blocking(
            second_handle,
            second_slot,
            second_binary,
            MODEL.to_string(),
        );
        let _ = second_tx.send(result);
    });
    let mut replacement = None;
    assert!(
        until(READY_BUDGET, || {
            let registered = slot.lock().unwrap().clone();
            match registered {
                Some(child) if !Arc::ptr_eq(&child, &original) => {
                    replacement = Some(child);
                    true
                }
                _ => false,
            }
        }),
        "FAKETEST_second_child_missing"
    );
    let replacement = replacement.unwrap();
    std::fs::write(
        home.join("second-registered"),
        b"FAKETEST_SECOND_REGISTERED",
    )
    .unwrap();
    assert!(
        first_rx
            .recv_timeout(ACTOR_WATCHDOG)
            .expect("FAKETEST_first_worker_timeout")
            .is_ok(),
        "FAKETEST_first_worker_failed"
    );
    first.join().expect("FAKETEST_first_worker_panicked");
    let registered = slot
        .lock()
        .unwrap()
        .clone()
        .expect("FAKETEST_first_erased_second");
    assert!(
        Arc::ptr_eq(&registered, &replacement),
        "FAKETEST_second_registration_changed"
    );
    assert!(
        replacement.lock().unwrap().try_wait().unwrap().is_none(),
        "FAKETEST_second_child_not_live"
    );
    std::fs::write(
        home.join("first-preserved-second"),
        b"FAKETEST_FIRST_PRESERVED_SECOND",
    )
    .unwrap();
    cancel_ollama_pull_from(&slot).expect("FAKETEST_second_cancel_failed");
    assert!(
        second_rx
            .recv_timeout(READY_BUDGET)
            .expect("FAKETEST_second_worker_timeout")
            .is_err(),
        "FAKETEST_second_worker_not_canceled"
    );
    second.join().expect("FAKETEST_second_worker_panicked");
    assert!(
        slot.lock().unwrap().is_none(),
        "FAKETEST_second_slot_not_cleared"
    );
}
