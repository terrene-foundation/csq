//! In-process daemon supervisor.
//!
//! Runs the csq daemon (refresher + usage poller + auto-rotate + IPC
//! server) inside the Tauri app process itself, so tokens are
//! refreshed for as long as the desktop app is running — no separate
//! `csq daemon start` required.
//!
//! ### Why in-process
//!
//! an internal journal entry (this session): every OAuth account on the author's
//! machine had been expired for 6–80 hours because the user had to
//! remember to run `csq daemon start` manually. Shipping the daemon
//! as a separate CLI process was a solvable foot-gun — the desktop
//! app has a tokio runtime and a long-lived lifetime anyway (tray
//! icon keeps the process alive even when the main window closes),
//! so the daemon can just ride inside it.
//!
//! ### Cohabitation with an external daemon
//!
//! If the user still has `csq daemon start` running in a terminal
//! (e.g. they're debugging), the PID file guard in
//! `PidFile::acquire` rejects our attempt and we silently defer to
//! the external daemon. The supervisor loop then watches for that
//! daemon to go away and takes over when it does. No spin-locking,
//! no zombies: each iteration of the loop either owns the daemon or
//! sleeps 60s and re-polls.
//!
//! ### Shutdown
//!
//! On app exit, the supervisor's `CancellationToken` is fired. The
//! server, refresher, usage poller, and auto-rotator all observe the
//! same token and drain. `drain_subsystems` gives EACH handle its own
//! deadline (5 s) SEQUENTIALLY, so the total drain is NOT bounded by 5 s
//! — it can take 5 s per subsystem.
//!
//! The Exit handler therefore waits at most 6 s as a CAP ON APP EXIT,
//! never as a drain guarantee. What the wait is for: the supervisor
//! thread's return is what drops the `PidFile` guard (held last,
//! cleaning up the `.csq-daemon.pid` file). If the drain is still running
//! at the cap, the app leaves anyway — the OS then releases the lock when
//! this process ends (the flock fd closes; a Windows waiter takes the
//! named mutex as WAIT_ABANDONED) — and the cap is logged as
//! `daemon_supervisor_exit_cap_reached`. No exit path hangs on the daemon
//! (Q6 R1 L3 / R2 M-1).
//!
//! `csq daemon stop` reaches this same token from OUTSIDE the process,
//! via a platform-specific bridge owned once per supervisor generation:
//! a named shutdown event on Windows, a real `SIGTERM` handler on Unix
//! (an internal ticket — without it, the OS default disposition for an
//! unhandled `SIGTERM` would terminate the whole app). A stop-requested
//! sentinel (`csq_core::daemon::stop_sentinel`) additionally prevents the
//! supervisor loop from silently re-acquiring the daemon afterwards.

use csq_core::daemon;
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

// Imports for run_daemon (server, refresher subsystems). Cross-platform
// as of an internal ticket — the Windows supervisor now runs the same subsystems over a
// named pipe instead of a Unix socket.
use csq_core::accounts::AccountInfo;
use csq_core::daemon::{
    server as daemon_server, HttpGetFn, HttpGetWithRetryAfterFn, HttpPostFn, HttpPostFnCodex,
    HttpPostProbeFn, TtlCache,
};
use csq_core::http;
use csq_core::oauth::OAuthStateStore;
use std::sync::Arc;

/// Top-level handle returned to the Tauri setup() hook. Owns the
/// shutdown token; dropping it does **not** stop the daemon — call
/// [`shutdown`](Self::shutdown) explicitly at app exit.
pub struct SupervisorHandle {
    #[cfg(not(windows))]
    shutdown: CancellationToken,
    // Set (and notified) when the supervisor body finishes — by a DROP guard,
    // so it also fires if the body panics (Q6 R2 L-1). The Exit handler waits
    // on this instead of detaching the thread.
    #[cfg(not(windows))]
    finished: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    #[cfg(windows)]
    windows: Arc<WindowsSupervisor>,
}

#[cfg(windows)]
#[derive(Clone)]
struct WindowsGeneration {
    cancel: CancellationToken,
    completion: csq_core::update::upgrade_guard::drain::Completion,
    restart: Arc<std::sync::atomic::AtomicBool>,
    finished: Arc<std::sync::atomic::AtomicBool>,
    exit_finished: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    task: Arc<std::sync::Mutex<Option<tauri::async_runtime::JoinHandle<()>>>>,
    custody: Arc<std::sync::Mutex<Option<csq_core::update::upgrade_guard::drain::TaskCustody>>>,
}

#[cfg(windows)]
struct WindowsSupervisor {
    base: PathBuf,
    current: std::sync::Mutex<WindowsGeneration>,
}

#[cfg(windows)]
impl WindowsGeneration {
    fn new(completion: csq_core::update::upgrade_guard::drain::Completion) -> Self {
        Self {
            cancel: CancellationToken::new(),
            completion,
            restart: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            exit_finished: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
            task: Arc::new(std::sync::Mutex::new(None)),
            custody: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl SupervisorHandle {
    /// Fires the shared cancellation token. Any subsystem currently
    /// in-flight drains before the supervisor loop exits. Windows retains
    /// actual writer custody; other platforms use per-subsystem deadlines.
    pub fn shutdown(&self) {
        #[cfg(not(windows))]
        self.shutdown.cancel();
        #[cfg(windows)]
        match self.windows.current.lock() {
            Ok(current) => current.cancel.cancel(),
            Err(_) => tracing::error!(
                error_kind = "desktop_supervisor_state_poisoned",
                "desktop supervisor shutdown request failed"
            ),
        }
    }

    /// Waits up to `timeout` for the supervisor loop to return and release
    /// its PidFile lock. Returns `false` when observation expires. Windows Quit
    /// separately requires the generation completion and actual task joins;
    /// this bounded wait does not authorize process exit or release custody.
    pub fn wait_for_shutdown(&self, timeout: Duration) -> bool {
        #[cfg(not(windows))]
        let signal = Arc::clone(&self.finished);
        #[cfg(windows)]
        let signal = match self.windows.current.lock() {
            Ok(current) => Arc::clone(&current.exit_finished),
            Err(_) => {
                tracing::error!(
                    error_kind = "desktop_supervisor_state_poisoned",
                    "desktop supervisor shutdown wait failed"
                );
                return false;
            }
        };
        let (lock, finished) = &*signal;
        let done = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let done = finished
            .wait_timeout_while(done, timeout, |done| !*done)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0;
        *done
    }

    #[cfg(windows)]
    pub fn shutdown_for_upgrade(
        &self,
    ) -> Result<csq_core::update::upgrade_guard::drain::Completion, &'static str> {
        let current = self
            .windows
            .current
            .lock()
            .map_err(|_| "desktop_supervisor_state_poisoned")?;
        current.cancel.cancel();
        Ok(current.completion.clone())
    }

    #[cfg(windows)]
    pub fn resume_after_refused_upgrade(
        &self,
        expected: &csq_core::update::upgrade_guard::drain::Completion,
    ) -> Result<(), &'static str> {
        restart_windows_generation(&self.windows, expected)
    }
}

#[cfg(windows)]
fn restart_windows_generation(
    runtime: &Arc<WindowsSupervisor>,
    expected: &csq_core::update::upgrade_guard::drain::Completion,
) -> Result<(), &'static str> {
    // A retry may originate in an already-running desktop, so main's earlier
    // check is insufficient. Refuse before mutating generation/restart state.
    csq_core::update::installer_admission::windows::check()
        .map_err(|_| "installer_admission_refused")?;
    let next = {
        let mut current = runtime
            .current
            .lock()
            .map_err(|_| "desktop_supervisor_state_poisoned")?;
        if !current.completion.same_generation(expected) {
            return Ok(());
        }
        current
            .restart
            .store(true, std::sync::atomic::Ordering::Release);
        if !current.finished.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        let Some(completion) = csq_core::update::upgrade_guard::drain::Completion::retry_slot(
            &mut current.completion,
            expected,
        )
        .map_err(|_| "desktop_supervisor_retry_before_join")?
        else {
            return Ok(());
        };
        let next = WindowsGeneration::new(completion);
        *current = next.clone();
        next
    };
    spawn_windows_generation(Arc::clone(runtime), next);
    Ok(())
}

#[cfg(windows)]
fn spawn_windows_generation(runtime: Arc<WindowsSupervisor>, generation: WindowsGeneration) {
    let owner = Arc::clone(&generation.task);
    let task = tauri::async_runtime::spawn(async move {
        let bridge = match csq_core::update::upgrade_guard::drain::QuitBridge::start(
            generation.cancel.clone(),
            generation.completion.clone(),
            false,
        ) {
            Ok(bridge) => Some(bridge),
            Err(_) => {
                tracing::warn!(
                    error_kind = "daemon_upgrade_event_create_failed",
                    "desktop daemon shutdown listener unavailable; hosting continues"
                );
                None
            }
        };

        let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let child_base = runtime.base.clone();
        let child_cancel = generation.cancel.clone();
        let child_failed = Arc::clone(&failed);
        let child_custody = Arc::clone(&generation.custody);
        let finished_supervisor = Arc::clone(&generation.exit_finished);
        // PidFile's Windows mutex must be acquired and released on this one
        // OS thread. Drive the non-Send loop here; subsystem spawns still use
        // Tauri's runtime. The retained observer consumes the actual join.
        let child = tauri::async_runtime::spawn_blocking(move || {
            run_signaling_completion(finished_supervisor, || {
                tauri::async_runtime::block_on(supervisor_loop(
                    child_base,
                    child_cancel,
                    child_failed,
                    child_custody,
                ));
            });
        });
        let cause = supervisor_stop_cause(&child.await);
        log::log!(
            cause.level(),
            "event=daemon_supervisor_stopped cause={}",
            cause.token()
        );
        if cause != SupervisorStop::Returned {
            failed.store(true, std::sync::atomic::Ordering::Release);
        }
        if let Some(bridge) = bridge {
            if bridge.finish().await.is_err() {
                tracing::warn!(
                    error_kind = "daemon_upgrade_listener_join_failed",
                    "desktop daemon shutdown listener cleanup failed"
                );
                failed.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        // Generation owns the current session registry OUTSIDE the loop future.
        // A loop panic can drop run_daemon, but cannot detach its writer handles.
        let custody = generation
            .custody
            .lock()
            .unwrap_or_else(|error| {
                failed.store(true, std::sync::atomic::Ordering::Release);
                error.into_inner()
            })
            .take();
        if let Some(custody) = custody {
            if custody.drain().await.is_err() {
                failed.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        // The actual loop and every admitted task joined before this proof.
        generation.completion.record_joined();
        generation
            .finished
            .store(true, std::sync::atomic::Ordering::Release);
        if failed.load(std::sync::atomic::Ordering::Acquire) {
            generation.completion.fail();
        } else {
            generation.completion.finish();
        }
        if generation
            .restart
            .load(std::sync::atomic::Ordering::Acquire)
            && restart_windows_generation(&runtime, &generation.completion).is_err()
        {
            tracing::error!(
                error_kind = "desktop_supervisor_resume_failed",
                "desktop supervisor restart request failed"
            );
        }
    });
    *owner.lock().unwrap_or_else(|error| error.into_inner()) = Some(task);
}

/// Runs `body` with the supervisor's completion signal armed.
///
/// The signal is set by a DROP guard, so it fires on a normal return AND when
/// `body` unwinds with a panic — a panicking supervisor body must not leave the
/// Exit handler waiting out the whole exit cap on a thread that is already
/// gone (Q6 R2 L-1). The guard is created BEFORE the body runs.
fn run_signaling_completion(
    finished: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    body: impl FnOnce(),
) {
    struct SignalOnDrop(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for SignalOnDrop {
        fn drop(&mut self) {
            let (lock, done) = &*self.0;
            let mut finished = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *finished = true;
            done.notify_all();
        }
    }
    let _signal = SignalOnDrop(finished);
    body();
}

/// How the in-process supervisor task ended, as the fixed-vocabulary
/// `cause` token [`start`]'s observer logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupervisorStop {
    /// `supervisor_loop` unwound with a panic.
    Panic,
    /// The task was aborted (cancelled) before it could complete.
    Cancelled,
    /// The join failed in a shape that is neither panic nor cancellation, or
    /// the terminal `tauri::Error` was not a join error at all. A DISTINCT
    /// variant, never folded into `Cancelled`: deleting the cancellation arm
    /// must red the cancelled-path test rather than silently reclassifying.
    Unknown,
    /// `supervisor_loop` returned normally — the clean-shutdown path.
    Returned,
}

impl SupervisorStop {
    /// The `cause=<token>` value for this outcome. Fixed vocabulary, no
    /// error payload: the join error's Display is never logged
    /// (security.md MUST-2).
    fn token(self) -> &'static str {
        match self {
            SupervisorStop::Panic => "panic",
            SupervisorStop::Cancelled => "cancelled",
            SupervisorStop::Unknown => "unknown",
            SupervisorStop::Returned => "returned",
        }
    }

    /// Log level per outcome: a panic is an error the operator must see;
    /// a cancellation is unexpected but not a crash; a normal return is
    /// the clean shutdown path.
    fn level(self) -> log::Level {
        match self {
            SupervisorStop::Panic => log::Level::Error,
            SupervisorStop::Cancelled | SupervisorStop::Unknown => log::Level::Warn,
            SupervisorStop::Returned => log::Level::Info,
        }
    }
}

/// Classifies the terminal state of the supervisor task awaited from
/// [`start`]'s `spawn_blocking` handle.
///
/// Awaiting a `tauri::async_runtime::JoinHandle` yields `Ok(())` on a
/// normal return and `Err(tauri::Error::JoinError(..))` on a panic or an
/// abort. The cause token comes from the shared
/// [`csq_core::error::join_cause`] classifier — one implementation for every
/// join-error surface — and anything it cannot classify stays `Unknown`,
/// never folded into `Cancelled`.
fn supervisor_stop_cause(result: &Result<(), tauri::Error>) -> SupervisorStop {
    match result {
        Ok(()) => SupervisorStop::Returned,
        Err(tauri::Error::JoinError(e)) => match csq_core::error::join_cause(e) {
            "panic" => SupervisorStop::Panic,
            "cancelled" => SupervisorStop::Cancelled,
            _ => SupervisorStop::Unknown,
        },
        // `tauri::Error` is `#[non_exhaustive]`; a non-join terminal error is
        // not classifiable as either a panic or a cancellation.
        Err(_) => SupervisorStop::Unknown,
    }
}

/// Installs the daemon's redacting panic hook for the desktop process.
///
/// Called from the app's setup after the tracing subscriber is initialised
/// and before the supervisor thread starts: the Rust DEFAULT panic hook
/// prints the payload verbatim to stderr, and a supervisor panic is exactly
/// the class of failure whose message can embed upstream data. Idempotent —
/// `panic_hook::install` is `OnceLock`-guarded, so autostart and relaunch
/// paths are safe.
pub(crate) fn install_panic_hook() -> bool {
    csq_core::daemon::panic_hook::install("desktop_panic")
}

/// Starts the in-process daemon supervisor.
///
/// Runs a single supervisor loop on a DEDICATED OS THREAD (it owns the
/// thread-affine PidFile lock — Q6) until `shutdown` fires. Each iteration
/// tries to take ownership of the daemon (`PidFile::acquire` + `serve`),
/// and if another daemon already has it, waits 60s and retries.
///
/// The task's terminal state is observed: a panic or cancellation logs
/// `event=daemon_supervisor_stopped cause=<panic|cancelled|returned>`
/// instead of vanishing with the discarded JoinHandle. The supervisor is
/// NOT auto-restarted — restart semantics belong to the loop's own
/// `run_forever` retry path.
///
/// This function returns immediately — the work happens on that thread.
pub fn start(base_dir: PathBuf) -> SupervisorHandle {
    // an internal ticket: reopening the desktop app is itself an explicit "start"
    // intent — clear any stop-requested sentinel left by a prior `csq
    // daemon stop` (or a crash that left it set) so this launch is never
    // silently refused. Cheap and best-effort; see `stop_sentinel` doc.
    daemon::clear_stop_requested(&base_dir);

    #[cfg(windows)]
    {
        let generation =
            WindowsGeneration::new(csq_core::update::upgrade_guard::drain::Completion::default());
        let runtime = Arc::new(WindowsSupervisor {
            base: base_dir,
            current: std::sync::Mutex::new(generation.clone()),
        });
        spawn_windows_generation(Arc::clone(&runtime), generation);
        SupervisorHandle { windows: runtime }
    }
    #[cfg(not(windows))]
    {
        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();
        // The signal fires on return and unwind, after the loop drops its PidFile.
        let finished = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let finished_supervisor = Arc::clone(&finished);
        let supervisor = tauri::async_runtime::spawn_blocking(move || {
            run_signaling_completion(finished_supervisor, || {
                tauri::async_runtime::block_on(supervisor_loop(base_dir, shutdown_clone));
            });
        });
        let _observer = tauri::async_runtime::spawn(async move {
            let cause = supervisor_stop_cause(&supervisor.await);
            log::log!(
                cause.level(),
                "event=daemon_supervisor_stopped cause={}",
                cause.token()
            );
        });
        SupervisorHandle { shutdown, finished }
    }
}

/// Supervisor main loop. Delegates to the shared
/// [`csq_core::daemon::supervise::run_forever`] loop, passing the
/// desktop [`run_daemon`] as the per-session body. The detect/acquire/
/// backoff/cohabitation machinery lives in csq-core so the standalone
/// `csq daemon start --supervised` daemon and this in-process supervisor
/// share exactly one implementation (daemon-auth-resilience Wave B).
///
/// an internal ticket — the Windows named-pipe daemon is wired end to end
/// (`run_daemon` binds `daemon::serve_windows` + the same subsystems as
/// Unix), so the detect/acquire/run loop is identical across platforms;
/// only `run_daemon`'s transport bind differs.
async fn supervisor_loop(
    base_dir: PathBuf,
    cancel: CancellationToken,
    #[cfg(windows)] last_failed: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(windows)] generation_custody: Arc<
        std::sync::Mutex<Option<csq_core::update::upgrade_guard::drain::TaskCustody>>,
    >,
) {
    // Windows bridge ownership lives in spawn_windows_generation, outside
    // this loop future. A loop unwind cannot detach that bridge or the current
    // session's generation-owned credential task registry.

    // Unix (an internal ticket follow-up): install a SIGTERM handler ONCE, same
    // lifetime and same leaked-task rationale as the Windows arm above.
    // Cancels the SAME `cancel` token so both platforms share identical
    // semantics from here down. Never `.expect()`s — this runs inside an
    // already-live GUI app, unlike the CLI's `wait_for_shutdown` (which can
    // afford to panic at process startup); a registration failure is
    // logged and the app keeps running, just without a Unix `csq daemon
    // stop` bridge.
    //
    // Composition with the stop-requested sentinel (`stop_sentinel.rs`):
    // this bridge stops THIS app session's in-process daemon when SIGTERM
    // actually reaches it (i.e. this app's PID was the PidFile owner). The
    // sentinel, checked inside `run_forever` on every iteration, is the
    // OTHER half — it stops the loop from re-acquiring afterwards, and
    // also covers the case where SIGTERM went to some OTHER owner (e.g.
    // the standalone `--supervised` daemon) while this app's loop was
    // merely backing off. Both are needed; neither alone makes `csq
    // daemon stop` true for every cohabitation ordering.
    #[cfg(unix)]
    install_unix_sigterm_bridge(cancel.clone());

    daemon::supervise::run_forever(base_dir, cancel, |base, session_cancel| {
        #[cfg(windows)]
        let last_failed = Arc::clone(&last_failed);
        #[cfg(windows)]
        let generation_custody = Arc::clone(&generation_custody);
        async move {
            #[cfg(windows)]
            let result = run_daemon(&base, session_cancel, generation_custody).await;
            #[cfg(not(windows))]
            let result = run_daemon(&base, session_cancel).await;
            #[cfg(windows)]
            last_failed.store(result.is_err(), std::sync::atomic::Ordering::Release);
            result
        }
    })
    .await;
}

/// Installs a one-shot SIGTERM→cancel bridge for the process's lifetime.
///
/// Split out of [`supervisor_loop`] so it is independently testable: a
/// real signal cannot be raised against a `#[cfg(windows)]` shutdown
/// event, but it CAN be raised against this function directly — see the
/// `unix_sigterm_bridge_cancels_the_token` test below, which sends a
/// genuine `SIGTERM` in an owned subprocess and asserts `cancel` fires
/// without contaminating the parent test process's signal state.
///
/// Returns immediately after spawning the listener task; never blocks,
/// never panics. A registration failure (an exceptional kernel
/// condition — see [`tokio::signal::unix::signal`]'s own error docs) is
/// logged and swallowed: this runs inside an already-live GUI app, so
/// `.expect()`-ing here would crash a running app over a missing
/// SIGTERM bridge, which is strictly worse than the bridge just not
/// existing.
#[cfg(unix)]
fn install_unix_sigterm_bridge(cancel: CancellationToken) {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::spawn(async move {
                term.recv().await;
                log::info!("in-process daemon stopping (SIGTERM / csq daemon stop)");
                cancel.cancel();
            });
        }
        Err(e) => {
            // io::ErrorKind is a closed enum, so this stays fixed-vocabulary
            // while keeping the diagnostic class (security.md MUST-2).
            log::warn!(
                "could not install SIGTERM handler (kind={:?}); `csq daemon stop` will not \
                 signal the desktop daemon when this app's PID owns the PidFile",
                e.kind()
            );
        }
    }
}

#[cfg(all(test, unix))]
mod sigterm_bridge_tests {
    use super::install_unix_sigterm_bridge;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use tokio_util::sync::CancellationToken;

    const SIGNAL_CHILD_ENV: &str = "CSQ_TEST_SIGTERM_BRIDGE_CHILD";
    #[cfg(target_os = "linux")]
    const SIGNAL_PARENT_ENV: &str = "CSQ_TEST_SIGTERM_BRIDGE_PARENT";

    struct OwnedSignalChild(Option<Child>);

    impl OwnedSignalChild {
        fn kill_group_if_owned(&self) -> std::io::Result<()> {
            let child = self.0.as_ref().expect("wait-owned signal child");
            // SAFETY: initialized C output; WNOWAIT never consumes child ownership.
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            loop {
                // Refuse a recycled group ID if another reaper consumed our child.
                // SAFETY: the pointer is valid and only our child PID is queried.
                if unsafe {
                    libc::waitid(
                        libc::P_PID,
                        child.id() as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                } == 0
                {
                    // SAFETY: the fresh ownership probe reserves our group's leader.
                    if unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) } == 0 {
                        return Ok(());
                    }
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ESRCH) {
                        return Ok(());
                    }
                    // Darwin answers EPERM for a group of only zombies, but also
                    // for a live member we may not signal. Accept EPERM only when
                    // the leader exited unreaped AND no member besides it is
                    // live or unclassifiable; any other signal error returns.
                    #[cfg(target_os = "macos")]
                    if error.raw_os_error() == Some(libc::EPERM)
                        && info.si_pid == child.id() as libc::pid_t
                        && crate::login_child_custody::group::census_besides_leader(child.id())
                            == crate::login_child_custody::group::GroupCensus::Empty
                    {
                        return Ok(());
                    }
                    return Err(error);
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    impl Drop for OwnedSignalChild {
        fn drop(&mut self) {
            if self.0.is_some() {
                if let Err(error) = self.kill_group_if_owned() {
                    eprintln!("signal helper cleanup refused an unowned child: {error}");
                }
            }
            if let Some(child) = self.0.as_mut() {
                let _ = child.wait();
            }
        }
    }

    fn run_signal_child(
        exact_test: &str,
        witness: &str,
        deadline: std::time::Duration,
        expected_code: i32,
    ) {
        let sandbox = tempfile::TempDir::new_in("/tmp").expect("signal child sandbox");
        let home = sandbox.path().join("home");
        let base = sandbox.path().join("base");
        let tmp = sandbox.path().join("tmp");
        for path in [&home, &base, &tmp] {
            std::fs::create_dir(path).unwrap();
        }
        let stdout = sandbox.path().join("stdout");
        let stderr = sandbox.path().join("stderr");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.env_clear();
        for key in ["PATH", "LANG", "LC_ALL", "TERM", "USER"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        #[cfg(target_os = "linux")]
        {
            let parent = std::process::id() as libc::pid_t;
            command.env(SIGNAL_PARENT_ENV, parent.to_string());
            // SAFETY: only async-signal-safe syscalls run between fork and exec.
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent {
                        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                    }
                    Ok(())
                });
            }
        }
        let child = command
            .env("HOME", &home)
            .env("CSQ_BASE_DIR", &base)
            .env("CLAUDE_CONFIG_DIR", &home)
            .env("TMPDIR", &tmp)
            .env(SIGNAL_CHILD_ENV, exact_test)
            .current_dir(sandbox.path())
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .args(["--exact", exact_test, "--ignored", "--nocapture"])
            .process_group(0)
            .spawn()
            .expect("spawn owned signal helper");
        let mut child = OwnedSignalChild(Some(child));
        let pid = child.0.as_ref().unwrap().id();
        let (done, ready) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            // SAFETY: waitid initializes this plain C output structure before use.
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            let result = loop {
                // SAFETY: this is our child; WNOWAIT reserves its PID for cleanup.
                if unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid as libc::id_t,
                        &mut info,
                        libc::WEXITED | libc::WNOWAIT,
                    )
                } == 0
                {
                    break Ok(());
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    break Err(error.kind());
                }
            };
            let _ = done.send(result);
        });
        let observed = ready.recv_timeout(deadline);
        child
            .kill_group_if_owned()
            .expect("owned signal helper cleanup");
        let status = child
            .0
            .as_mut()
            .unwrap()
            .wait()
            .expect("reap signal helper");
        // The child is now reaped; disarm Drop so a recycled PID is never signalled.
        child.0.take();
        waiter.join().expect("signal helper waiter");
        let capture = |path: &std::path::Path| {
            assert!(std::fs::metadata(path).unwrap().len() <= 64 * 1024);
            std::fs::read_to_string(path).unwrap()
        };
        let log = format!("{}{}", capture(&stdout), capture(&stderr));
        assert!(
            matches!(observed, Ok(Ok(()))),
            "signal helper did not finish: {observed:?}; {log}"
        );
        assert_eq!(
            status.code(),
            Some(expected_code),
            "signal helper exited {status:?}; {log}"
        );
        if expected_code == 0 {
            assert!(
                log.contains("test result: ok. 1 passed; 0 failed; 0 ignored"),
                "wrong helper selection: {log}"
            );
            assert!(
                log.contains(witness),
                "missing body witness {witness}: {log}"
            );
        } else {
            assert_eq!(expected_code, 128 + libc::SIGTERM);
            assert!(
                log.contains("bridge-child:real-sigterm-cancelled-token"),
                "real bridge did not run: {log}"
            );
            assert!(
                log.contains("a termination signal arrived before the codex relaunch"),
                "real supervisor guard did not exit: {log}"
            );
            assert!(
                !log.contains(witness),
                "contaminated supervisor unexpectedly survived: {log}"
            );
        }
        println!(
            "signal-child-evidence: selector={exact_test} code={expected_code} survivor={} real-cancellation={}",
            log.contains("bridge-ordering:supervisor-pre-spawn-survived"),
            log.contains("bridge-child:real-sigterm-cancelled-token")
        );
    }

    fn assert_signal_child_context(exact_test: &str) {
        assert_eq!(std::env::var(SIGNAL_CHILD_ENV).as_deref(), Ok(exact_test));
        // SAFETY: read-only identity calls on this explicitly selected helper.
        assert_eq!(
            unsafe { libc::getpgrp() },
            std::process::id() as libc::pid_t
        );
        #[cfg(target_os = "linux")]
        {
            let parent: libc::pid_t = std::env::var(SIGNAL_PARENT_ENV).unwrap().parse().unwrap();
            assert!(parent > 1);
            // libtest runs the body on another thread. Arm that thread as well
            // as the exec thread already protected by pre_exec, then close the
            // parent-exited-before-registration race before doing any work.
            // SAFETY: these syscalls affect only this owned helper thread.
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) },
                0
            );
            assert_eq!(unsafe { libc::getppid() }, parent);
            let mut death_signal: libc::c_int = 0;
            // SAFETY: prctl writes one valid c_int; no process is signalled.
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut death_signal) },
                0
            );
            assert_eq!(death_signal, libc::SIGKILL);
        }
    }

    #[test]
    fn signal_child_cleanup_refuses_a_reaped_identity() {
        let mut command = Command::new("/bin/sh");
        command
            .env_clear()
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = OwnedSignalChild(Some(command.spawn().unwrap()));
        assert!(child.0.as_mut().unwrap().wait().unwrap().success());
        assert_eq!(
            child.kill_group_if_owned().unwrap_err().raw_os_error(),
            Some(libc::ECHILD),
            "a reaped PID cannot authorize a process-group signal"
        );
        child.0.take();
    }

    #[test]
    fn unix_sigterm_bridge_preserves_subsequent_supervisor_pre_spawn() {
        run_signal_child(
            "desktop::daemon_supervisor::sigterm_bridge_tests::supervisor_bridge_ordering_helper",
            "bridge-ordering:supervisor-pre-spawn-survived",
            // The nested bridge child has a 10s ceiling, leaving teardown margin.
            std::time::Duration::from_secs(30),
            0,
        );
    }

    #[test]
    #[ignore = "only run explicitly in the owned signal regression subprocess"]
    fn supervisor_bridge_ordering_helper() {
        // SAFETY: bound this explicitly selected helper even if its parent dies.
        unsafe { libc::alarm(20) };
        assert_signal_child_context(
            "desktop::daemon_supervisor::sigterm_bridge_tests::supervisor_bridge_ordering_helper",
        );
        crate::cli::commands::codex_supervise::bridge_signal_ordering_probe(
            unix_sigterm_bridge_cancels_the_token,
        );
    }

    #[test]
    fn in_process_bridge_signal_reaches_the_real_supervisor_exit_guard() {
        run_signal_child(
            "desktop::daemon_supervisor::sigterm_bridge_tests::in_process_bridge_ordering_helper",
            "bridge-ordering:supervisor-pre-spawn-survived",
            std::time::Duration::from_secs(10),
            128 + libc::SIGTERM,
        );
    }

    #[test]
    #[ignore = "only run explicitly by the owned positive-control subprocess"]
    fn in_process_bridge_ordering_helper() {
        // SAFETY: self-bound before registration, lock acquisition, or runtime startup.
        unsafe { libc::alarm(8) };
        assert_signal_child_context(
            "desktop::daemon_supervisor::sigterm_bridge_tests::in_process_bridge_ordering_helper",
        );
        crate::cli::commands::codex_supervise::bridge_signal_ordering_probe(
            assert_real_sigterm_bridge,
        );
    }

    /// A shared mutex cannot isolate persistent signal handlers or pending flags.
    /// Keep the real signal-to-token assertion in its own process instead.
    #[test]
    fn unix_sigterm_bridge_cancels_the_token() {
        run_signal_child(
            "desktop::daemon_supervisor::sigterm_bridge_tests::unix_sigterm_bridge_child",
            "bridge-child:real-sigterm-cancelled-token",
            // Above the real assertion's 5s bound, below the ordering parent's 30s.
            std::time::Duration::from_secs(10),
            0,
        );
    }

    #[ignore = "only run explicitly in the owned signal subprocess"]
    #[test]
    fn unix_sigterm_bridge_child() {
        // SAFETY: self-bound before registration, lock acquisition, or runtime startup.
        unsafe { libc::alarm(8) };
        assert_signal_child_context(
            "desktop::daemon_supervisor::sigterm_bridge_tests::unix_sigterm_bridge_child",
        );
        assert_real_sigterm_bridge();
    }

    fn assert_real_sigterm_bridge() {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let cancel = CancellationToken::new();
                install_unix_sigterm_bridge(cancel.clone());
                tokio::task::yield_now().await;
                // SAFETY: signal only this explicitly selected helper process.
                assert_eq!(
                    unsafe { libc::kill(std::process::id() as libc::pid_t, libc::SIGTERM) },
                    0
                );
                tokio::time::timeout(std::time::Duration::from_secs(5), cancel.cancelled())
                    .await
                    .expect("a real SIGTERM must cancel the bridged token within 5s");
                assert!(cancel.is_cancelled());
                println!("bridge-child:real-sigterm-cancelled-token");
            });
    }
}

/// One full run of the in-process daemon: bind socket, spawn
/// subsystems, await cancellation, drain cleanly.
///
/// Mirrors the CLI `csq daemon start` startup sequence in
/// `csq/src/cli/commands/daemon.rs` so the subsystem composition
/// stays in exactly one shape — refresher + usage poller +
/// auto-rotate + server, all sharing a single shutdown token.
///
/// Cross-platform as of an internal ticket: the whole body is shared; only the
/// transport bind (`daemon::serve` Unix socket vs `daemon::serve_windows`
/// named pipe) is `#[cfg]`-gated. `daemon::socket_path` already resolves
/// to the named-pipe path on Windows.
async fn run_daemon(
    base_dir: &std::path::Path,
    outer_cancel: CancellationToken,
    #[cfg(windows)] generation_custody: Arc<
        std::sync::Mutex<Option<csq_core::update::upgrade_guard::drain::TaskCustody>>,
    >,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        let custody = csq_core::update::upgrade_guard::drain::TaskCustody::default();
        {
            let mut current = generation_custody
                .lock()
                .map_err(|_| "desktop_session_custody_poisoned")?;
            *current = Some(custody.clone());
        }
        let result = custody
            .run(run_daemon_body(base_dir, outer_cancel, custody.clone()))
            .await;
        // Clear only after run joined every task. Outer unwind leaves the
        // registry available to the generation's retained completion owner.
        generation_custody
            .lock()
            .map_err(|_| "desktop_session_custody_poisoned")?
            .take();
        result
    }
    #[cfg(not(windows))]
    run_daemon_body(base_dir, outer_cancel).await
}

async fn run_daemon_body(
    base_dir: &std::path::Path,
    outer_cancel: CancellationToken,
    #[cfg(windows)] custody: csq_core::update::upgrade_guard::drain::TaskCustody,
) -> Result<(), String> {
    // Enterprise license gate for the desktop daemon-hosted enterprise stack (task #77
    // shard 3) — twin of the CLI `handle_start` gate. STARTUP variant (no liveness deny)
    // so a licensed-but-offline-beyond-grace customer can still bring the daemon up to
    // recover their CRL (the full per-op `enforce` would be a fail-closed deadlock).
    // Inert while the placeholder key is baked; community builds carry no gate.
    #[cfg(feature = "enterprise")]
    if let Err(e) = crate::cli::enforce_enterprise_license_startup(base_dir) {
        return Err(format!("enterprise license gate refused daemon start: {e}"));
    }

    let sock_path = daemon::socket_path(base_dir);

    // Local shutdown token — a CHILD of outer_cancel (not a clone). The
    // server gets its own internal token (created by `serve`). When
    // `outer_cancel` fires (app quit / supervisor stop), this child cancels
    // too and every subsystem drains. When a subsystem dies mid-session
    // (an internal ticket), the drain path cancels THIS child to wind the siblings down
    // WITHOUT firing `outer_cancel` — so `run_forever` restarts the session
    // rather than treating it as an intentional stop.
    let shutdown = outer_cancel.child_token();
    #[cfg(windows)]
    custody.register_stop(shutdown.clone());

    let refresh_cache: Arc<TtlCache<u16, daemon::RefreshStatus>> =
        Arc::new(TtlCache::with_default_age());
    let discovery_cache: Arc<TtlCache<(), Vec<AccountInfo>>> =
        Arc::new(TtlCache::new(daemon_server::DISCOVERY_CACHE_MAX_AGE));
    let oauth_store: Arc<OAuthStateStore> = Arc::new(OAuthStateStore::new());

    // Anthropic endpoints are behind Cloudflare which blocks
    // reqwest's rustls TLS fingerprint (JA3/JA4). Use Node.js
    // subprocess transport — its OpenSSL fingerprint passes
    // Cloudflare. Falls back to reqwest if no JS runtime found.
    let http_post: HttpPostFn = Arc::new(|url: &str, body: &str| http::post_json_node(url, body));
    // PR-C4: Codex refresh transport returns body + Date header so the
    // broker can emit `clock_skew_detected` per spec 07 §7.5 INV-P01.
    let http_post_codex: HttpPostFnCodex =
        Arc::new(|url: &str, body: &str| http::post_json_node_with_date(url, body));
    let http_get: HttpGetFn = Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
        http::get_bearer_node(url, token, headers)
    });
    // Anthropic-only sibling transport that additionally captures the
    // `retry-after` response header (see
    // `csq-core/src/daemon/usage_poller/mod.rs::HttpGetWithRetryAfterFn`).
    let http_get_retry_after: HttpGetWithRetryAfterFn =
        Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
            http::get_bearer_node_with_retry_after(url, token, headers)
        });
    let http_post_probe: HttpPostProbeFn =
        Arc::new(|url: &str, headers: &[(String, String)], body: &str| {
            http::post_json_with_headers(url, headers, body)
        });

    // Shared Gemini consumer state — same applied-set + quota mutex
    // as the NDJSON drainer (PR-G3, spec 05 §5.8.1).
    let gemini_consumer = csq_core::daemon::usage_poller::gemini::GeminiConsumerState::default();

    // FIX-2: mirror the CLI daemon's verify_chain block so the desktop
    // path has the same audit health signal and sentinel as the CLI path.
    // Run synchronous verify_chain in a spawn_blocking call to keep the
    // async runtime free during disk I/O.
    let (audit_health, audit_records_unverified): (csq_core::audit::AuditHealth, u64) = {
        let record_limit: usize = std::env::var("CSQ_AUDIT_VERIFY_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10_000);
        // FIX-5b: clamp timeout floor to 1s (same as CLI daemon). Absent an
        // explicit override, the default scales with the CONFIGURED
        // record_limit — see `derive_audit_verify_timeout_secs` (mirrored
        // from the CLI daemon path per this block's own FIX-2 comment).
        let timeout_secs: u64 = std::env::var("CSQ_AUDIT_VERIFY_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|v| v.max(1))
            .unwrap_or_else(|| crate::daemon_host::derive_audit_verify_timeout_secs(record_limit));
        let verify_cfg = csq_core::audit::VerifyConfig {
            record_limit,
            keychain_service: csq_core::audit::AUDIT_SIGNING_SERVICE_NAME.to_string(),
        };
        let base_for_verify = base_dir.to_path_buf();
        let verify_future = tokio::task::spawn_blocking(move || {
            // M3 §10.5 (W2a): reconcile the born-canonical EATP attestation chain's
            // own `.chain-broken` sentinel inside the SAME spawn_blocking so the
            // startup timeout covers both chains. Side pass — the EATP chain does
            // not gate daemon startup (the op-chain result below is the authority).
            // Inert until the EATP chain exists (`verify_chain_in` returns
            // Ok(default) for absent `eatp-runs/`).
            let eatp = csq_core::audit::verify_chain_in(
                &base_for_verify,
                &verify_cfg,
                None,
                csq_core::audit::ChainKind::Eatp,
            );
            csq_core::audit::reconcile_chain_sentinel(
                &base_for_verify,
                csq_core::audit::ChainKind::Eatp.runs_subdir(),
                &eatp,
            );
            csq_core::audit::verify_chain(&base_for_verify, &verify_cfg, None)
        });
        #[cfg(windows)]
        let verify_future = custody.adopt("audit_startup_verify", verify_future);
        // Set by the two Ok(Ok(Ok(summary))) arms below — mirrors the CLI
        // daemon path's `records_unverified` (FIX-2 parity).
        let mut records_unverified: u64 = 0;
        let health = match tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            verify_future,
        )
        .await
        {
            // SINGLE PRODUCER — twin parity with the CLI daemon's
            // `attempt_audit_verify`. `from_verify_result` owns the
            // summary→verdict mapping; hand-constructing `Verified` here is
            // what let this twin keep reporting a whole-chain verdict on a
            // truncated scan (`guard-reader-writer-parity.md` MUST NOT #2 —
            // an exhaustive match binds CONSUMERS, not PRODUCERS).
            Ok(Ok(Ok(summary))) => {
                records_unverified = summary.limit_exceeded_count;
                let health = csq_core::audit::AuditHealth::from_verify_result(&Ok(summary));
                match &health {
                    csq_core::audit::AuditHealth::Verified => {
                        log::info!(
                            "audit chain verified clean (desktop daemon startup); \
                             records_unverified={records_unverified}"
                        );
                    }
                    csq_core::audit::AuditHealth::TailVerified { skipped } => {
                        log::warn!(
                            "audit chain TAIL-VERIFIED (desktop daemon startup) — the \
                             {skipped} oldest record(s), INCLUDING the genesis, were NOT \
                             scanned, so the surviving window's first record is anchored \
                             to nothing. The audit subsystem stays operational; raise \
                             CSQ_AUDIT_VERIFY_LIMIT above the chain length for \
                             whole-chain coverage."
                        );
                    }
                    csq_core::audit::AuditHealth::Degraded { gaps } => {
                        log::warn!(
                            "audit chain DEGRADED ({} historical-key gap(s)) (desktop daemon startup)",
                            gaps.len()
                        );
                    }
                    // Unreachable by construction — see the CLI twin's note.
                    // Enumerated rather than wildcarded so a future variant
                    // forces a decision here too.
                    csq_core::audit::AuditHealth::Broken { .. }
                    | csq_core::audit::AuditHealth::Unknown { .. } => {
                        log::warn!(
                            "audit verify mapped a clean summary to an error verdict \
                             (desktop daemon startup)"
                        );
                    }
                }
                health
            }
            Ok(Ok(Err(ref e))) => {
                let h = csq_core::audit::AuditHealth::from_ledger_error(e);
                match &h {
                    // KeychainUnavailable (transient keychain access) → Unknown,
                    // NOT a chain-integrity failure. DEFERRED, not BROKEN.
                    csq_core::audit::AuditHealth::Unknown { reason } => {
                        log::error!(
                            "audit verify could not read the signing key (keychain locked / \
                             access-denied; {reason}) — audit subsystem fail-closed this run \
                             (desktop daemon startup); run `csq audit migrate-keys`"
                        );
                        // Parity with the panic/timeout Unknown arms (and the CLI
                        // daemon): emit an operator-visible stderr line too.
                        eprintln!(
                            "csq desktop daemon: AUDIT VERIFY DEFERRED — the signing key is \
present but the keychain could not be read (locked / access-denied). The chain is NOT \
broken. Audit anchoring/emit are disabled this run. Run `csq audit migrate-keys`."
                        );
                    }
                    _ => {
                        let ek = if let csq_core::audit::AuditHealth::Broken {
                            ref error_kind,
                            ..
                        } = h
                        {
                            error_kind.clone()
                        } else {
                            "audit_chain_integrity_failure".to_string()
                        };
                        log::error!(
                            "audit chain BROKEN ({ek}) — audit subsystem fail-closed (desktop daemon startup)"
                        );
                    }
                }
                h
            }
            // FIX-5a: raise to ERROR + eprintln! — Unknown is as serious as Broken.
            Ok(Err(join_err)) => {
                #[cfg(not(windows))]
                let cause = csq_core::error::join_cause(&join_err);
                #[cfg(windows)]
                let cause =
                    csq_core::update::upgrade_guard::drain::task_observation_join_cause(&join_err);
                log::error!(
                    "audit verify task panicked cause={} — audit subsystem fail-closed (desktop daemon startup)",
                    cause
                );
                eprintln!(
                    "csq desktop daemon: AUDIT VERIFY TASK PANICKED. \
Audit anchoring and new audit-record emits are disabled. \
Run `csq audit verify --full` for diagnosis."
                );
                csq_core::audit::AuditHealth::Unknown {
                    reason: "audit_verify_task_panicked".to_string(),
                }
            }
            Err(_timeout) => {
                log::error!(
                    "audit verify timed out after {timeout_secs}s — audit subsystem fail-closed (desktop daemon startup)"
                );
                eprintln!(
                    "csq desktop daemon: AUDIT VERIFY TIMED OUT after {timeout_secs}s. \
Audit anchoring and new audit-record emits are disabled. \
Run `csq audit verify --full` for diagnosis."
                );
                csq_core::audit::AuditHealth::Unknown {
                    reason: "audit_verify_timeout".to_string(),
                }
            }
        };

        // FIX-1/FIX-2: set/clear cross-process sentinel.
        // FIX-2: Unknown (timeout/panic) leaves sentinel UNCHANGED — a transient
        // condition must not produce a durable write-lockout that outlives it.
        match &health {
            // TailVerified clears alongside Verified/Degraded — outgrowing the
            // record limit is not brokenness. Coverage is reported separately.
            csq_core::audit::AuditHealth::Verified
            | csq_core::audit::AuditHealth::TailVerified { .. }
            | csq_core::audit::AuditHealth::Degraded { .. } => {
                csq_core::audit::clear_chain_broken(base_dir);
            }
            csq_core::audit::AuditHealth::Broken { error_kind, .. } => {
                csq_core::audit::set_chain_broken(base_dir, error_kind);
            }
            csq_core::audit::AuditHealth::Unknown { .. } => {
                // Transient condition — do not set a durable sentinel.
                // The in-RAM audit_health still gates daemon emit/anchor.
            }
        }

        (health, records_unverified)
    };

    // Clone before move into router_state so the anchor gate below can consult it.
    let audit_health_for_anchor = audit_health.clone();
    // an internal ticket — resolve the active transparency-log sink ONCE (twin of the CLI
    // daemon path) so both the anchor HTTP handler (RouterState.anchor_sink) and
    // the cadence drain task below share the same Arc + config. `None` in the
    // default local-only build → handler surfaces `inclusion_proof: null`.
    let anchor_sink_cfg_desktop =
        csq_core::audit::AuditSinkConfig::load(base_dir).unwrap_or_default();
    let anchor_sink_desktop: Option<std::sync::Arc<dyn csq_core::audit::LedgerSink>> =
        resolve_anchor_sink_desktop(&anchor_sink_cfg_desktop);
    // login-followup: ONE rebind wake channel, shared by the usage poller
    // (spawned below) and `POST /api/slot-rebind` (RouterState twin of the
    // CLI daemon). Created before the state so the route can never arrive
    // at a poller that is not waiting on the same Notify.
    let usage_poller_wake = Arc::new(csq_core::daemon::usage_poller::WakeChannel::new());
    let router_state = daemon_server::RouterState {
        cache: Arc::clone(&refresh_cache),
        discovery_cache: Arc::clone(&discovery_cache),
        base_dir: Arc::new(base_dir.to_path_buf()),
        oauth_store: Some(Arc::clone(&oauth_store)),
        gemini_consumer: gemini_consumer.clone(),
        // NOTE (scope): wrapped in the shared handle for type parity with the
        // standalone daemon's `RouterState`, but the in-process desktop
        // supervisor does NOT run the bounded verify-retry
        // (`csq/src/cli/commands/daemon.rs::spawn_audit_verify_retry`) — an
        // `Unknown` startup health here is never promoted without an app
        // restart. Extending the retry to this path is unverified scope, not
        // silently covered by this wrap.
        audit_health: csq_core::audit::new_shared(audit_health),
        audit_records_unverified,
        anchor_sink: anchor_sink_desktop.clone(),
        usage_poller_wake: Arc::clone(&usage_poller_wake),
        // an internal ticket — seed the interactive enforcement registry from the fail-closed
        // §10.5 activation gate (absent → empty/503).
        // an internal ticket follow-up — inject the cross-SDK kailash projector (the csq crate
        // owns the seam; csq-core cannot name it).
        // T-M4.3 — inject the PACT governor factory (twin of the CLI daemon path)
        // so a configured operating envelope wires the first production
        // ActionGovernor (fail-closed: an unloadable envelope refuses to open).
        #[cfg(feature = "enterprise")]
        interactive: Arc::new({
            let reg = csq_core::daemon::interactive_live::seed_registry(
                base_dir,
                Some(crate::kailash_projector::make_kailash_projector()),
                Some(crate::kailash_governor::make_governor_factory()),
                // T-M4.5 — inject the lifecycle-audit-sink factory (twin of the CLI
                // daemon path) so every session records a signed audit trail.
                Some(crate::kailash_audit_sink::make_audit_sink_factory(base_dir)),
            );
            // M3 §10.5 W2b — inject the EATP born-canonical genesis guard (twin
            // of the CLI daemon path). Classifies the genesis record on every
            // session open; non-BornCanonical refuses EATP chain appends but
            // the session still proceeds.
            // M3 §10.5 W3 — inject the EATP session-close attestation writer (twin
            // of the CLI daemon path). Appends a born-canonical session-close
            // attestation on every close (fail-closed-NON-FATAL).
            reg.with_eatp_genesis_guard(crate::kailash_eatp_genesis::make_eatp_genesis_guard(
                base_dir,
            ))
            .with_eatp_attestor(
                crate::kailash_eatp_attest::make_eatp_session_close_attestor(base_dir),
            )
        }),
    };

    // PR-C4: reconciler clamps Codex invariants (canonical 0o400 +
    // config.toml `cli_auth_credentials_store = "file"`) before any
    // subsystem touches them. Mutex-coordinated with the refresher.
    //
    // Blocking filesystem work (it walks the accounts tree), so it runs on the
    // blocking pool, never on a runtime worker (twin of the CLI daemon path). A
    // daemon stop also stops the label sweep's background continuation.
    // Held until this function returns by ANY path: the guard aborts the task on an
    // early return, and on a normal end the cancelled token has finished it.
    let _label_stop_watcher =
        csq_core::platform::label_upgrade::spawn_stop_watcher(shutdown.clone());
    {
        let reconcile_base = base_dir.to_path_buf();
        let reconcile =
            tokio::task::spawn_blocking(move || daemon::run_reconciler(&reconcile_base));
        #[cfg(windows)]
        let reconcile = custody.adopt("startup_reconciler", reconcile);
        if let Err(e) = reconcile.await {
            #[cfg(not(windows))]
            return Err(daemon::reconciler_join_failure(&e));
            #[cfg(windows)]
            {
                let _ = e;
                return Err("daemon_reconciler_join_failed".into());
            }
        }
    }

    // M3-7 + M4-5: Phase 4 fail-closed gate (an internal journal entry Delta F / OQ #7;
    // strengthened in M4-5). Refuse to start if the on-disk store predates
    // Phase 4 layout — the live-mirror retirement assumes identity
    // credentials + settings + (where Codex-bound) credentials-codex are
    // seeded for every UUID-keyed slot, and the gate enforces that. The
    // error's `Display` carries operator-actionable next steps per
    // `tauri-commands.md` MUST Rule 6.
    if let Err(e) = csq_core::daemon::startup_reconciler::phase4_gate_check(base_dir) {
        // Log before returning, mirroring the CLI twin: the desktop app has no
        // attached console, so the rolling daemon log is the ONLY place an
        // operator can see why the in-process daemon refused to start.
        //
        // `tracing::`, NOT `log::` — the rolling daemon log is fed by the
        // tracing subscriber's file layer, installed via `set_global_default`
        // with no `LogTracer` bridge, so `log::` records go to tauri-plugin-log
        // (stdout / app log dir / webview) and never reach the file this
        // comment is about. Same `error_kind` tag as the CLI twin.
        tracing::error!(
            error_kind = "phase4_gate_refused",
            "phase 4 gate refused start (desktop daemon): {e}"
        );
        return Err(format!("phase 4 gate refused start: {e}"));
    }

    // ── M19: Emit capture-matrix record (sidecar dedup) ──────────────────────
    // Emitted AFTER audit_health is finalised, BEFORE the transport binds —
    // same contract as the CLI twin, via the one shared orchestrator. Before
    // this call existed the desktop in-process daemon never emitted a matrix
    // record at all, so a desktop-only user's chain held ZERO
    // `ProvenanceCaptureMatrix` records forever.
    csq_core::audit::seam::emit_startup_capture_matrix(
        base_dir,
        audit_health_for_anchor.is_operational(),
    );

    // Bind the transport. Unix binds a domain socket; Windows binds a
    // named pipe. Both return a handle with `.shutdown()` + a
    // `JoinHandle<()>`, so the drain tail below is shared (an internal ticket).
    #[cfg(unix)]
    let (server, server_join) = daemon::serve(&sock_path, router_state)
        .await
        .map_err(|e| format!("socket bind failed: {e}"))?;
    #[cfg(windows)]
    let (server, server_join) = daemon::serve_windows(&sock_path.to_string_lossy(), router_state)
        .await
        .map_err(|e| format!("named-pipe bind failed: {e}"))?;
    #[cfg(windows)]
    drop(custody.adopt_subsystem("ipc_server", server_join));
    #[cfg(windows)]
    let server = std::sync::Arc::new(server);
    #[cfg(windows)]
    {
        custody.register_stop(server.shutdown_token());
        let proof = std::sync::Arc::clone(&server);
        custody.register_verdict(move || proof.completion_verified() && !proof.shutdown_error());
    }
    log::info!("in-process daemon IPC bound at {}", sock_path.display());

    // Subsystems share `shutdown` so a single cancel drains them
    // all. The server owns its own internal token fired via
    // `server.shutdown()` below.
    let refresher = daemon::spawn_refresher(
        base_dir.to_path_buf(),
        Arc::clone(&refresh_cache),
        http_post,
        http_post_codex,
        shutdown.clone(),
    );
    #[cfg(windows)]
    drop(custody.adopt_subsystem("refresher", refresher.join));
    // License CRL refresher (task #77 shard 2) — twin of the CLI daemon spawn. Keeps the
    // signed revocation list fresh for the enterprise license gate. Enterprise-only; inert
    // while the placeholder key is baked.
    #[cfg(feature = "enterprise")]
    let crl_refresher = daemon::spawn_crl_refresher(base_dir.to_path_buf(), shutdown.clone());
    #[cfg(all(windows, feature = "enterprise"))]
    drop(custody.adopt_subsystem("license_crl_refresher", crl_refresher.join));
    let usage_poller = daemon::spawn_usage_poller(
        base_dir.to_path_buf(),
        http_get,
        http_get_retry_after,
        http_post_probe,
        gemini_consumer.clone(),
        shutdown.clone(),
        // Same Arc as RouterState::usage_poller_wake (see above).
        Arc::clone(&usage_poller_wake),
    );
    #[cfg(windows)]
    drop(custody.adopt_subsystem("usage_poller", usage_poller.join));
    // Gemini midnight-LA reset task (PR-G3, ADR-G05).
    let gemini_midnight = tokio::spawn(csq_core::daemon::usage_poller::gemini::run_midnight_reset(
        base_dir.to_path_buf(),
        gemini_consumer.clone(),
        shutdown.clone(),
    ));
    #[cfg(windows)]
    drop(custody.adopt_subsystem("gemini_midnight", gemini_midnight));
    // PR-A1: pass claude_home so the rotator can re-materialize
    // settings.json after each handle dir repoint. Uses the SAME resolver as
    // the CLI twin (`$CLAUDE_HOME` override, else `~/.claude`) — a bare
    // `dirs::home_dir().join(".claude")` here silently ignored the operator's
    // `$CLAUDE_HOME` and pointed the rotator at the wrong tree. None → no-op.
    let claude_home_for_rotate = crate::daemon_host::claude_home().ok();
    let auto_rotator = daemon::spawn_auto_rotate(
        base_dir.to_path_buf(),
        claude_home_for_rotate,
        shutdown.clone(),
    );
    #[cfg(windows)]
    drop(custody.adopt_subsystem("auto_rotator", auto_rotator.join));
    // Sweep preserves each dead handle dir's image-cache into
    // ~/.claude/image-cache/ before removing the orphan. If we
    // cannot resolve ~/.claude (no $HOME in a sandboxed env), pass
    // `None` so the sweep still runs but skips preservation —
    // better to lose images than route them into a fallback path
    // like base_dir/image-cache/ that CC will never find. Same `$CLAUDE_HOME`-
    // aware resolver as the CLI twin.
    let claude_home_for_sweep = crate::daemon_host::claude_home().ok();
    let sweep = csq_core::session::spawn_sweep(
        base_dir.to_path_buf(),
        claude_home_for_sweep,
        shutdown.clone(),
    );

    #[cfg(windows)]
    drop(custody.adopt_subsystem("handle_dir_sweep", sweep.join));
    // Daemon-written usage-ledger writer (an internal ticket) — mirrors the CLI daemon
    // wiring. The desktop app IS the daemon (in-process supervisor), so this
    // task publishes each slot's usage ledger that `get_account_usage` reads
    // sub-ms instead of running the ~20s live transcript scan on the dashboard
    // render path. Daemon is the SOLE producer; terminals only read
    // (account-terminal-separation.md Rule 1, extended for billing telemetry).
    // Same `$CLAUDE_HOME`-aware resolver as the CLI twin; None → writer no-op.
    let claude_home_for_ledger = crate::daemon_host::claude_home().ok();
    let usage_ledger_writer = daemon::spawn_usage_ledger_writer(
        base_dir.to_path_buf(),
        claude_home_for_ledger,
        shutdown.clone(),
        chrono::Utc::now,
    );

    #[cfg(windows)]
    drop(custody.adopt_subsystem("usage_ledger_writer", usage_ledger_writer.join));
    // Parse-cache sweeper (PR-CA9b / T20) — twin of the CLI daemon's spawn.
    // Reads `<base_dir>/coc-roots-seen.jsonl` and GCs stale
    // `<root>/.cache/parsed-<lock_sha>.bin` files older than 30 days OR whose
    // lock_sha no longer matches the root's current COC.lock digest.
    //
    // The desktop in-process daemon previously omitted this entirely, so a
    // user whose ONLY daemon host is the desktop app never GC'd a single parse
    // cache and `csq doctor --json::cache_sweeper` reported `never_run`
    // forever. The two daemons are mutually exclusive (one PidFile), so the
    // omission meant no sweep at all — not a sweep performed elsewhere.
    // Roots path comes from the SHARED resolver that `csq run`'s
    // `record_root_seen` writer also uses; the state snapshot stays under
    // base_dir, where `csq doctor` reads it.
    let coc_cache_sweeper = daemon::spawn_coc_cache_sweeper(
        csq_core::daemon::coc_cache_sweeper::roots_seen_path_or_inert(base_dir),
        base_dir.to_path_buf(),
        shutdown.clone(),
    );

    #[cfg(windows)]
    drop(custody.adopt_subsystem("coc_cache_sweeper", coc_cache_sweeper.join));
    // Daemon rolling-log GC (#1a-2, daemon-auth-resilience Wave A2) — twin
    // of the CLI daemon's spawn. 14-day retention sweep over the persistent
    // rolling file log this in-process daemon writes via
    // `init_logging_subscriber`'s rolling-file layer (`crate::daemon_log`).
    let log_gc = csq_core::daemon::log_gc::spawn(base_dir.to_path_buf(), shutdown.clone());
    #[cfg(windows)]
    drop(custody.adopt_subsystem("daemon_log_gc", log_gc));

    // Background update check — same 24-hour-cached behavior as the
    // CLI. Fires a detached OS thread on daemon start so desktop
    // users see the "csq vX.Y.Z available" notice on app launch.
    // Without this, the CLI emits notices on every command but the
    // desktop app silently misses every release.
    //
    // Edition independence (rules/independence.md): COMMUNITY channel only —
    // an enterprise desktop must not query terrene-foundation/csq or surface a
    // community upgrade notice (mirrors the CLI + desktop update gates).
    if crate::BUILD_EDITION != "enterprise" {
        csq_core::update::auto_update_bg(base_dir.to_path_buf());
    }

    // M14 — external anchoring task (mirrors CLI daemon.rs wiring).
    // FIX-2: gate on audit_health.is_operational() so the anchor is not
    // spawned when the chain is Broken/Unknown (mirrors CLI daemon.rs).
    let anchor_handle = if audit_health_for_anchor.is_operational() {
        // an internal ticket — reuse the sink + config resolved once above for
        // RouterState.anchor_sink (no second config read / resolve).
        anchor_sink_desktop.and_then(|s| {
            daemon::spawn_anchor_task(
                base_dir.to_path_buf(),
                anchor_sink_cfg_desktop,
                s,
                shutdown.clone(),
            )
        })
    } else {
        log::info!(
            "audit chain not operational — anchor task not spawned (desktop daemon startup)"
        );
        None
    };

    #[cfg(windows)]
    if let Some(handle) = anchor_handle {
        drop(custody.adopt_subsystem("audit_anchor", handle.join));
    }
    // Collect every long-lived subsystem into a uniform set (label +
    // JoinHandle<()>) so the session can watch them for premature exit
    // (an internal ticket — the mass-expiry failure shape one level down) AND drain them
    // with one loop.
    //
    // CONTRACT (an internal ticket redteam LOW-1): every member here MUST run until
    // `shutdown` fires. `await_session_stop` treats ANY return from a member
    // — clean `Ok(())` or panic — as a fault that restarts the whole session.
    // A subsystem that returns early on a benign "nothing to do" condition
    // would trigger a restart storm; such a subsystem must instead idle-loop
    // on `shutdown` (see `auto_rotate::run_loop`), not return.
    //
    // `ipc_server` is the one member that exits on its OWN internal token
    // (fired by `server.shutdown()` during teardown below), NOT the shared
    // `shutdown` — but it still never returns during normal operation, so its
    // premature exit (a panicked accept loop) is a genuine fault worth a
    // restart (an internal ticket): a dead IPC server silently breaks login / status /
    // provision while the refresher keeps going.
    #[cfg(not(windows))]
    let mut subsystems: Vec<daemon::supervise::Subsystem> = vec![
        ("refresher", refresher.join),
        ("usage_poller", usage_poller.join),
        ("gemini_midnight", gemini_midnight),
        ("auto_rotator", auto_rotator.join),
        ("handle_dir_sweep", sweep.join),
        ("coc_cache_sweeper", coc_cache_sweeper.join),
        ("usage_ledger_writer", usage_ledger_writer.join),
        ("daemon_log_gc", log_gc),
        ("ipc_server", server_join),
    ];
    #[cfg(all(not(windows), feature = "enterprise"))]
    subsystems.push(("license_crl_refresher", crl_refresher.join));
    #[cfg(not(windows))]
    if let Some(handle) = anchor_handle {
        subsystems.push(("audit_anchor", handle.join));
    }

    // Block until a graceful stop (`outer_cancel` fires from the app
    // lifecycle / stop event) OR a subsystem dies mid-session (an internal ticket). On
    // Windows the `csq daemon stop` named event is bridged into the top-level
    // cancel token ONCE in `supervisor_loop` (a per-session bridge here would
    // leak a `wait_blocking` thread per restart — an internal ticket redteam MED-1), and
    // `outer_cancel` is a clone of that token (`run_forever` passes
    // `cancel.clone()` per session), so a stop event resolves this wait on
    // every platform. The
    // subsystems share `shutdown` (a child of `outer_cancel`), so on a
    // graceful stop they are already winding down.
    #[cfg(not(windows))]
    let stop = daemon::supervise::await_session_stop(&outer_cancel, &mut subsystems).await;
    #[cfg(windows)]
    let stop = custody.wait_stop(&outer_cancel).await;

    log::info!("in-process daemon stopping");
    server.shutdown();

    if let daemon::supervise::SessionStop::SubsystemExited(name) = &stop {
        // A subsystem died while the daemon was meant to be running. Fire the
        // CHILD `shutdown` token to drain the siblings WITHOUT cancelling
        // `outer_cancel` (so `run_forever` restarts rather than exits), then
        // return Err below.
        log::error!(
            "daemon subsystem '{name}' exited mid-session; draining siblings and restarting"
        );
        shutdown.cancel();
    }

    // Drain every remaining subsystem with a 5s per-handle deadline so one
    // stuck HTTP call can't wedge app shutdown (the dead one, if any, was
    // already removed by `await_session_stop`, so no handle is double-polled).
    // Includes `ipc_server` unless IT exited — `server.shutdown()` above fired
    // its accept loop's exit, so its handle completes here (no separate drain,
    // which would double-poll it — an internal ticket redteam hazard).
    #[cfg(not(windows))]
    daemon::supervise::drain_subsystems(subsystems, Duration::from_secs(5)).await;
    // Windows actual joins and IPC proof are owned by the outer custody boundary.

    if let daemon::supervise::SessionStop::SubsystemExited(name) = stop {
        return Err(format!("daemon subsystem exited mid-session: {name}"));
    }

    Ok(())
}

/// Resolves the active `LedgerSink` from `sink_cfg` for the desktop daemon.
/// Mirrors `resolve_anchor_sink` in `cli/commands/daemon.rs` — keep the two in sync.
///
/// REDACTION: every failure arm logs only `e.fixed_tag()` (the fixed
/// vocabulary `id_empty` / `id_length_out_of_range` /
/// `id_disallowed_charset` / `id_shape_mismatch`), never the error's
/// Display. `IdError`'s Display is documented non-echoing
/// (`csq_core::audit::types::IdError`). `fixed_tag()` is a SHARED
/// convention, not unique to that type — `AuditError::fixed_tag` and
/// `AuditV2Error::fixed_tag` expose the same signature — so the guarantee
/// is narrower and true: an error type with NO `fixed_tag` method fails to
/// compile at these arms, and every existing `fixed_tag` implementation
/// returns command-fixed `&'static str` literals rather than
/// input-derived text (security.md MUST-2).
fn resolve_anchor_sink_desktop(
    sink_cfg: &csq_core::audit::AuditSinkConfig,
) -> Option<std::sync::Arc<dyn csq_core::audit::LedgerSink>> {
    match sink_cfg.sink.as_str() {
        "none" => None,

        #[cfg(feature = "rekor-sink")]
        "rekor" => {
            match csq_core::audit::impls::sinks::rekor::RekorSink::with_defaults() {
                Ok(s) => {
                    // HONEST LABEL: M07 in-memory mock substrate — not a durable witness.
                    // See the CLI resolver's comment for the full rationale. The
                    // `event=anchor_sink_mock_backend` token is included so the
                    // same grep primitive that finds the CLI resolver's structured
                    // `tracing::warn!` event also finds this `log::warn!` (the
                    // `log` crate has no key=value fields, so the token is
                    // embedded in the message text instead).
                    log::warn!(
                        "event=anchor_sink_mock_backend sink=rekor rekor sink uses the \
                         in-memory M07 substrate (non-persistent); real Sigstore Rekor \
                         HTTP client is a pending follow-up"
                    );
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    log::warn!(
                        "rekor sink initialisation failed error_kind={} — anchor task not started",
                        e.fixed_tag()
                    );
                    None
                }
            }
        }

        #[cfg(feature = "csq-ledger-sink")]
        "csq-ledger" => {
            match csq_core::audit::impls::csq_ledger_sink::CsqLedgerSink::with_defaults() {
                Ok(s) => Some(std::sync::Arc::new(s)),
                Err(e) => {
                    log::warn!(
                        "csq-ledger sink initialisation failed error_kind={} — anchor task not started",
                        e.fixed_tag()
                    );
                    None
                }
            }
        }

        #[cfg(feature = "s3-sink")]
        "s3" => match csq_core::audit::impls::sinks::s3::S3ObjectLockSink::with_defaults() {
            Ok(s) => {
                // HONEST LABEL (mirrors rekor's above): in-memory mock substrate,
                // nothing leaves this process.
                log::warn!(
                    "event=anchor_sink_mock_backend sink=s3 s3 sink uses the in-memory \
                     M07 substrate (non-persistent); real AWS S3 Object Lock client is \
                     a pending follow-up"
                );
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                log::warn!(
                    "s3 sink initialisation failed error_kind={} — anchor task not started",
                    e.fixed_tag()
                );
                None
            }
        },

        #[cfg(feature = "azure-sink")]
        "azure" => {
            match csq_core::audit::impls::sinks::azure::AzureImmutableBlobSink::with_defaults() {
                Ok(s) => {
                    // HONEST LABEL (mirrors rekor's above): in-memory mock
                    // substrate, nothing leaves this process.
                    log::warn!(
                        "event=anchor_sink_mock_backend sink=azure azure sink uses the \
                         in-memory M07 substrate (non-persistent); real Azure Immutable \
                         Blob Storage client is a pending follow-up"
                    );
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    log::warn!(
                        "azure sink initialisation failed error_kind={} — anchor task not started",
                        e.fixed_tag()
                    );
                    None
                }
            }
        }

        #[cfg(feature = "gcp-sink")]
        "gcp" => match csq_core::audit::impls::sinks::gcp::GcpBucketLockSink::with_defaults() {
            Ok(s) => {
                // HONEST LABEL (mirrors rekor's above): in-memory mock substrate,
                // nothing leaves this process.
                log::warn!(
                    "event=anchor_sink_mock_backend sink=gcp gcp sink uses the in-memory \
                     M07 substrate (non-persistent); real GCP Cloud Storage Bucket Lock \
                     client is a pending follow-up"
                );
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                log::warn!(
                    "gcp sink initialisation failed error_kind={} — anchor task not started",
                    e.fixed_tag()
                );
                None
            }
        },

        #[cfg(feature = "azure-sql-sink")]
        "azure-sql" => {
            match csq_core::audit::impls::sinks::azure_sql::AzureSqlLedgerSink::with_defaults() {
                Ok(s) => {
                    // HONEST LABEL (mirrors rekor's above): in-memory mock
                    // substrate, nothing leaves this process.
                    log::warn!(
                        "event=anchor_sink_mock_backend sink=azure-sql azure-sql sink uses \
                         the in-memory M07 substrate (non-persistent); real Azure SQL \
                         ledger-table client is a pending follow-up"
                    );
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    log::warn!(
                        "azure-sql sink initialisation failed error_kind={} — anchor task not started",
                        e.fixed_tag()
                    );
                    None
                }
            }
        }

        #[cfg(feature = "customer-body-store-sink")]
        "customer-body-store" => {
            match csq_core::audit::impls::sinks::customer_body_store::CustomerBodyStoreSink::new(
                csq_core::audit::impls::sinks::customer_body_store::CustomerBodyStoreConfig::default(),
            ) {
                Ok(s) => Some(std::sync::Arc::new(s)),
                Err(e) => {
                    log::warn!(
                        "customer-body-store sink initialisation failed error_kind={} — anchor task not started",
                        e.fixed_tag()
                    );
                    None
                }
            }
        }

        other => {
            log::warn!(
                "sink '{}' configured but not compiled; rebuild with --features csq/{}-sink",
                other,
                other,
            );
            None
        }
    }
}

// The supervisor loop + backoff tests moved to
// `csq_core::daemon::supervise` alongside the extracted `run_forever`
// loop (daemon-auth-resilience Wave B). This module's remaining logic
// (`run_daemon`, `resolve_anchor_sink_desktop`) is exercised by the
// desktop self-test + live desktop verification (Wave C).

#[cfg(test)]
mod supervisor_signal_tests {
    use super::*;
    use std::sync::{Condvar, Mutex};

    fn new_signal() -> Arc<(Mutex<bool>, Condvar)> {
        Arc::new((Mutex::new(false), Condvar::new()))
    }

    fn handle_over(finished: Arc<(Mutex<bool>, Condvar)>) -> SupervisorHandle {
        SupervisorHandle {
            #[cfg(not(windows))]
            shutdown: CancellationToken::new(),
            #[cfg(not(windows))]
            finished,
            #[cfg(windows)]
            windows: Arc::new(WindowsSupervisor {
                base: PathBuf::new(),
                current: Mutex::new(WindowsGeneration {
                    exit_finished: finished,
                    ..WindowsGeneration::new(
                        csq_core::update::upgrade_guard::drain::Completion::default(),
                    )
                }),
            }),
        }
    }

    /// Q6 R2 L-1: a supervisor body that PANICS still signals completion — the
    /// guard fires on unwind, so the Exit handler is never left waiting out the
    /// whole exit cap on a thread that is already gone.
    #[test]
    fn a_panicking_supervisor_body_still_signals_completion() {
        let finished = new_signal();
        let body_signal = Arc::clone(&finished);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_signaling_completion(body_signal, || panic!("selftest: supervisor body panic"));
        }));
        assert!(caught.is_err(), "the body must have panicked");
        assert!(
            handle_over(finished).wait_for_shutdown(Duration::from_secs(2)),
            "completion was not signalled after a panicking body"
        );
    }

    /// The same guard on a normal return, and the wait is BOUNDED: an
    /// unsignalled handle returns false at its deadline instead of blocking
    /// forever (the exit path must never hang — Q6 R1 L3).
    #[test]
    fn a_normal_body_signals_completion_and_the_wait_is_bounded() {
        let finished = new_signal();
        run_signaling_completion(Arc::clone(&finished), || {});
        assert!(
            handle_over(Arc::clone(&finished)).wait_for_shutdown(Duration::from_millis(10)),
            "completion was not signalled after a normal return"
        );

        let pending = handle_over(new_signal());
        let started = std::time::Instant::now();
        assert!(
            !pending.wait_for_shutdown(Duration::from_millis(50)),
            "an unsignalled handle must report the cap, not an achieved drain"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the wait must return at its deadline"
        );
    }

    /// The supervisor's JoinHandle is no longer discarded, so a panicking
    /// supervisor task must be CLASSIFIED as a panic. A real
    /// `tauri::async_runtime::spawn_blocking` body really unwinds here —
    /// not a hand-built JoinError — so the test exercises the same await
    /// shape `start`'s observer uses.
    #[test]
    fn supervisor_stop_cause_reports_a_real_panic() {
        let result = tauri::async_runtime::block_on(async {
            tauri::async_runtime::spawn_blocking(|| panic!("selftest: supervisor task panic")).await
        });
        assert_eq!(
            supervisor_stop_cause(&result),
            SupervisorStop::Panic,
            "a panicking supervisor task must be classified panic"
        );
    }

    /// The mirror case: a body that returns normally classifies as
    /// `returned` (the clean-shutdown cause), never `panic`/`cancelled`.
    #[test]
    fn supervisor_stop_cause_reports_a_real_return() {
        let result = tauri::async_runtime::block_on(async {
            tauri::async_runtime::spawn_blocking(|| {}).await
        });
        assert_eq!(
            supervisor_stop_cause(&result),
            SupervisorStop::Returned,
            "a normally-returning supervisor task must be classified returned"
        );
    }

    /// Desktop startup installs the redacting panic hook with the DESKTOP
    /// label. Order-independent: the assertion uses the helper's own
    /// "did THIS call install" flag first, and the process-global read only
    /// as a fallback for a test binary where an earlier test already
    /// installed the hook. The prior hook is restored under the shared
    /// env-test lock so this test neither leaks the global hook into sibling
    /// tests nor races their hook swaps.
    #[test]
    fn startup_installs_the_redacting_panic_hook() {
        let _guard = csq_core::platform::test_env::lock();
        let prior = std::panic::take_hook();
        let _installed_by_this_call = install_panic_hook();
        let label = csq_core::daemon::panic_hook::active_label();
        std::panic::set_hook(prior);
        assert_eq!(
            label,
            Some("desktop_panic"),
            "desktop startup must install the redacting panic hook under the desktop label"
        );
    }

    /// The abort path: a task cancelled before it completes classifies as
    /// `cancelled`, distinct from both a panic and a clean return. A real
    /// task is spawned and aborted, so the test exercises the same
    /// `JoinError::is_cancelled` branch production reads.
    #[test]
    fn supervisor_stop_cause_reports_a_cancelled_task() {
        let result = tauri::async_runtime::block_on(async {
            let handle = tauri::async_runtime::spawn(async { std::future::pending::<()>().await });
            handle.abort();
            handle.await
        });
        assert_eq!(
            supervisor_stop_cause(&result),
            SupervisorStop::Cancelled,
            "an aborted supervisor task must be classified cancelled"
        );
    }
}
