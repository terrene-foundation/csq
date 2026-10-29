//! Shared recording-daemon fixture for desktop notify call-site tests.

//! A real, minimal daemon for the notify path: a listener bound at the
//! socket `notify::*` resolves for a fresh tempdir base, recording every
//! request and answering each with 200 after `response_delay`.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

/// Ceiling on every wait for a recorded request (see `recv`). Every wait it
/// bounds starts only once the fixture holds the shared env-test lock: the
/// queue for that lock is not a hang (it never gives up, and `test_env::lock`
/// reports a long holder after 60 s on its own), so a guard that started
/// before it would let a legitimately long sibling holder fail this fixture.
const HANG_GUARD: Duration = Duration::from_secs(60);

/// The startup schedule's first event: the constructor holds the env-test
/// lock. A scheduler starts its `HANG_GUARD` only after it sees this.
const ENV_ACQUIRED: &str = "env acquired";

/// The fixture's hold on the shared env-test mutex, for its whole life.
///
/// The fixture mutates NO process-global env. It used to point
/// `$XDG_RUNTIME_DIR` at its tempdir on Linux, so every concurrently running
/// test that resolved "the daemon" landed on it and the "nothing arrives"
/// row failed under load (an internal ticket). The socket is now injected per base through
/// `daemon::paths::test_socket`: only a caller passing the fixture's own
/// `base_dir()` resolves to it.
struct FixtureEnv {
    _guard: csq_core::platform::test_env::EnvTestGuard,
    _socket: csq_core::daemon::paths::test_socket::Registration,
}

impl FixtureEnv {
    fn acquire(base: &std::path::Path) -> (Self, std::path::PathBuf) {
        let _guard = csq_core::platform::test_env::lock();
        let (_socket, sock) = csq_core::daemon::paths::test_socket::register(base);
        (Self { _guard, _socket }, sock)
    }
}

pub(crate) struct RecordingDaemon {
    // Declaration order is drop order: the env hold (and the socket
    // registration) is released only after the serving thread has been stopped and
    // joined in `Drop` and every other field is gone.
    base: tempfile::TempDir,
    /// `Ok(request)` per recorded request; `Err(text)` when the fixture itself
    /// failed, so a broken fixture is a visible failure, never a missing request.
    requests: Receiver<Result<String, String>>,
    accepted: Arc<AtomicUsize>,
    accepts: Receiver<()>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    _env: FixtureEnv,
}

impl RecordingDaemon {
    pub(crate) fn new(response_delay: Duration) -> Self {
        Self::new_with_startup_schedule(response_delay, None)
    }

    fn new_with_startup_schedule(
        response_delay: Duration,
        schedule: Option<(Sender<&'static str>, Receiver<()>)>,
    ) -> Self {
        // Short path on purpose: a Unix socket pathname is length-bounded
        // (`UnixSocketPath`'s own doc). The shared short-root fixture also
        // pins the root's 0700 mode at creation.
        let base = csq_core::testing::socket_fixture::short_root("csq-lg-").unwrap();
        let (_env, sock) = FixtureEnv::acquire(base.path());
        // Outside the STARTUP_ORDERING block on purpose: the regression probe
        // that removes the rendezvous keeps this event, so the scheduler's
        // guarded wait still sees the baseline's "constructor returned" first.
        if let Some((events, _)) = &schedule {
            events.send(ENV_ACQUIRED).unwrap();
        }
        assert_eq!(
            csq_core::daemon::socket_path(base.path()),
            sock,
            "the fixture's base must resolve to the fixture socket"
        );
        let listener = UnixListener::bind(&sock).unwrap();
        let (tx, requests) = std::sync::mpsc::channel::<Result<String, String>>();
        let (accept_tx, accepts) = std::sync::mpsc::channel();
        let (ready_tx, ready) = std::sync::mpsc::sync_channel(0);
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (startup_events, start_gate) = match schedule {
            Some((events, gate)) => (Some(events), Some(gate)),
            None => (None, None),
        };
        let thread = {
            let stop = Arc::clone(&stop);
            let accepted = Arc::clone(&accepted);
            std::thread::spawn(move || {
                if let Some(gate) = start_gate {
                    gate.recv_timeout(HANG_GUARD).expect("startup scheduler");
                }
                // Hand ownership to the serving thread before a caller starts
                // a notify with its own bounded socket IO. Binding alone did
                // not establish that ordering under full-suite scheduling.
                ready_tx.send(()).unwrap();
                serve(listener, tx, stop, accepted, accept_tx, response_delay);
            })
        };
        // STARTUP_ORDERING_BEGIN: the regression probe removes this whole
        // rendezvous to reproduce the baseline constructor's ordering.
        if let Some(events) = startup_events {
            events.send("waiting for server").unwrap();
        }
        ready
            .recv_timeout(HANG_GUARD)
            .expect("fixture serve startup");
        // STARTUP_ORDERING_END
        Self {
            base,
            requests,
            accepted,
            accepts,
            stop,
            thread: Some(thread),
            _env,
        }
    }

    pub(crate) fn base_dir(&self) -> &std::path::Path {
        self.base.path()
    }

    /// The next recorded request, or a panic naming what was expected.
    /// The wait is on the EVENT: `HANG_GUARD` is only a ceiling that turns a
    /// request that will never come into a failure instead of a hung run, it
    /// is not a latency bound the code under test has to meet. A fixture
    /// failure panics with its own text.
    pub(crate) fn recv(&self, expected: &str) -> String {
        match self.requests.recv_timeout(HANG_GUARD) {
            Ok(Ok(request)) => request,
            Ok(Err(fixture)) => panic!("{fixture}"),
            Err(e) => panic!("expected the fixture daemon to receive {expected}: {e}"),
        }
    }

    /// Negative pole: true ONLY when the wait times out with the fixture still
    /// serving, i.e. no request arrived within `window`. A recorded request
    /// returns false; a fixture failure or a dead serve thread (the channel
    /// disconnected) panics, so it can never pass as "nothing arrived". Only
    /// meaningful when the caller has already driven everything that could
    /// have produced a request.
    pub(crate) fn nothing_within(&self, window: Duration) -> bool {
        match self.requests.recv_timeout(window) {
            Err(RecvTimeoutError::Timeout) => true,
            Ok(Ok(_)) => false,
            Ok(Err(fixture)) => panic!("{fixture}"),
            Err(RecvTimeoutError::Disconnected) => {
                panic!("the fixture daemon's serve thread is gone")
            }
        }
    }

    /// Connections the fixture has accepted so far (counted before it reads).
    pub(crate) fn accepted_connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn wait_for_accept(&self) {
        self.accepts
            .recv_timeout(HANG_GUARD)
            .expect("fixture must accept the connected client");
    }
}

impl Drop for RecordingDaemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake blocking accept; the stop check below keeps this control
        // connection out of the recorded request/accept streams.
        let _ = UnixStream::connect(csq_core::daemon::socket_path(self.base_dir()));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(
    listener: UnixListener,
    tx: Sender<Result<String, String>>,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    accept_tx: Sender<()>,
    response_delay: Duration,
) {
    // A send fails only once the receiver is gone (teardown): nothing to report to.
    let fail = |what: &str, e: std::io::Error| {
        let _ = tx.send(Err(format!("fixture daemon {what}: {e}")));
    };
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                accepted.fetch_add(1, Ordering::SeqCst);
                let _ = accept_tx.send(());
                // Keep the read explicitly blocking: accepted sockets inherit
                // O_NONBLOCK on macOS if the listener ever uses that flag.
                if let Err(e) = stream.set_nonblocking(false) {
                    fail("set_nonblocking", e);
                    continue;
                }
                if let Err(e) = stream.set_read_timeout(Some(HANG_GUARD)) {
                    fail("set_read_timeout", e);
                    continue;
                }
                let mut buf = [0u8; 1024];
                let n = match stream.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        fail("read", e);
                        continue;
                    }
                };
                if n == 0 {
                    // The client closed without writing: no request.
                    continue;
                }
                let _ = tx.send(Ok(String::from_utf8_lossy(&buf[..n]).to_string()));
                std::thread::sleep(response_delay);
                // The client may already have given up on the answer.
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                fail("accept", e);
                break;
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Runs the adversarial startup schedule with `guard` as the scheduler's
    /// ceiling and returns the first constructor event it observed.
    fn run_adversarial_schedule(guard: Duration) -> &'static str {
        let (events, observed) = std::sync::mpsc::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let scheduler = std::thread::spawn(move || {
            // Unguarded: the constructor may queue on the env-test lock for as
            // long as a sibling holds it. A constructor that panics before it
            // sends drops every sender, so this ends in `Disconnected`, never
            // a hang. `guard` starts only once the lock is held.
            let acquired = observed.recv().expect("constructor env acquisition");
            assert_eq!(acquired, ENV_ACQUIRED, "first startup event");
            let first = observed.recv_timeout(guard).expect("constructor event");
            release.send(()).unwrap();
            first
        });
        let daemon = RecordingDaemon::new_with_startup_schedule(
            Duration::ZERO,
            Some((events.clone(), gate)),
        );
        // In the baseline the first event is this return; the server was held
        // at the gate throughout construction. The fixed constructor instead
        // establishes the server-start rendezvous before it can return.
        let _ = events.send("constructor returned");
        let first = scheduler.join().unwrap();
        drop(daemon);
        first
    }

    /// Hold the serving thread until the constructor either waits for it or
    /// returns. The scheduler releases on either event, so the old constructor
    /// fails by event order rather than hanging or exceeding a timing bound.
    #[test]
    fn constructor_waits_for_the_server_under_an_adversarial_schedule() {
        let first = run_adversarial_schedule(HANG_GUARD);
        assert_eq!(first, "waiting for server", "constructor outran its server");
    }

    /// A sibling test holding the shared env-test lock for longer than the
    /// scheduler's guard must not fail the schedule: the guard bounds the
    /// server-start rendezvous, not the queue for the lock (which
    /// `test_env::lock` already reports on after 60 s). The hold is three
    /// times the guard, so a guard that starts before the constructor holds
    /// the lock expires while the constructor is still queued.
    #[test]
    fn a_long_env_lock_hold_before_construction_does_not_spend_the_guard() {
        const GUARD: Duration = Duration::from_secs(5);
        const HOLD: Duration = Duration::from_secs(15);
        let (held_tx, held) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _g = csq_core::platform::test_env::lock();
            held_tx.send(()).unwrap();
            std::thread::sleep(HOLD);
        });
        // No guard here either: the holder may itself queue behind a sibling,
        // and `test_env::lock` reports a long wait on its own. A holder that
        // panics drops `held_tx`, so this ends in `Disconnected`, never hangs.
        held.recv().expect("env-lock holder started");
        let first = run_adversarial_schedule(GUARD);
        holder.join().unwrap();
        assert_eq!(first, "waiting for server", "constructor outran its server");
    }

    /// A client that connects first and writes later must still be recorded.
    /// On macOS the old fixture dropped it (inherited O_NONBLOCK).
    #[test]
    fn a_request_written_after_the_connect_is_still_recorded() {
        let daemon = RecordingDaemon::new(Duration::ZERO);
        let sock = csq_core::daemon::socket_path(daemon.base_dir());
        let mut client = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        // Write only once the fixture has accepted (and so is about to read).
        daemon.wait_for_accept();
        assert_eq!(daemon.accepted_connections(), 1);
        // A fixture that failed has closed the stream, so this write may fail;
        // the verdict is `recv`, which surfaces the fixture's own error text.
        let _ = client.write_all(b"POST /api/probe HTTP/1.1\r\n\r\n");
        assert!(daemon
            .recv("the delayed probe")
            .starts_with("POST /api/probe HTTP/1.1"));
    }

    /// an internal ticket: the fixture must not leak into callers that did not pass its
    /// base. A daemon-reaching call for ANOTHER base (what a concurrently
    /// running test does) is resolved through the unchanged process env, so
    /// it never lands on the fixture; the fixture's own base still does.
    /// On Linux the old fixture pointed `$XDG_RUNTIME_DIR` at itself, so
    /// `socket_path(other)` equalled the fixture socket and the `assert_ne!`
    /// below reds.
    #[test]
    fn a_notify_for_another_base_never_reaches_the_fixture() {
        // Read under the shared env lock: sibling fixtures repoint this var
        // under it, so an unlocked read could observe their value. The lock
        // is released before `new`, which takes it for the fixture's life.
        let prior = {
            let _env = csq_core::platform::test_env::lock();
            std::env::var_os("XDG_RUNTIME_DIR")
        };
        let daemon = RecordingDaemon::new(Duration::ZERO);
        assert_eq!(
            std::env::var_os("XDG_RUNTIME_DIR"),
            prior,
            "the fixture must not mutate process-global env"
        );
        let other = tempfile::TempDir::new().unwrap();
        // No I/O: a notify for `other` would hit the REAL daemon socket on
        // Linux. Resolution is the whole property: `other` must not resolve
        // to the fixture's socket.
        assert_ne!(
            csq_core::daemon::socket_path(other.path()),
            csq_core::daemon::socket_path(daemon.base_dir()),
            "a different base resolved to the fixture socket"
        );
        // The fixture's own base still resolves to it.
        csq_core::daemon::notify::cache_invalidation(daemon.base_dir());
        assert!(daemon
            .recv("the own-base invalidation")
            .starts_with("POST /api/invalidate-cache HTTP/1.1"));
    }

    /// Negative pole: with nothing driven, nothing is recorded.
    #[test]
    fn no_request_is_recorded_when_nothing_is_sent() {
        let daemon = RecordingDaemon::new(Duration::ZERO);
        assert!(daemon.nothing_within(Duration::from_millis(300)));
    }
}
