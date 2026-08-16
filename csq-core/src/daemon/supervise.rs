//! Shared daemon supervisor loop.
//!
//! Owns the lifetime of a single daemon instance across crashes and
//! external-daemon contention, parameterized by the session body it
//! runs. Two callers share this one loop:
//!
//! - The desktop in-process supervisor
//!   (`csq::desktop::daemon_supervisor`) — runs the daemon inside the
//!   Tauri app process.
//! - The standalone `csq daemon start --supervised`
//!   (`csq::cli::commands::daemon::handle_start_supervised`) — the
//!   launchd-managed background daemon that survives app quit/crash.
//!
//! ### Why a shared loop
//!
//! an internal journal entry (daemon-auth-resilience): the refresher ran ONLY
//! in-process inside the desktop app. When the app died uncleanly and
//! nothing restarted it (its LaunchAgent had `RunAtLoad` but no
//! `KeepAlive`), every OAuth account aged past expiry together over a
//! ~3.5-day gap. The structural fix is a launchd-managed background
//! daemon (`KeepAlive` + `--supervised`) that keeps refreshing whether
//! or not the desktop app is open. Both restart sources run the SAME
//! detect/acquire/backoff loop — this module — so the cohabitation and
//! backoff semantics live in exactly one place.
//!
//! ### Cohabitation
//!
//! Exactly one process owns the daemon at a time, enforced by
//! [`PidFile`]. When another daemon already owns it, the loop observes
//! (backs off and re-polls); it takes over when the owner exits. No
//! spin-locking, no zombies.

use super::{
    detect_daemon, is_stop_requested, pid_file_path, version_drift_reason, DetectResult, PidFile,
};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Minimum wait between failed takeover attempts. Short enough that a
/// crashing external daemon doesn't starve csq for minutes before the
/// supervisor catches the gap.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);

/// Maximum wait between failed takeover attempts. 60s keeps the loop
/// from hot-spinning under pathological contention (e.g. two csq
/// processes racing to own the same PidFile) while staying well below
/// the 5-minute refresh interval.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Supervisor backoff state. Starts at [`BACKOFF_MIN`], doubles on each
/// failed attempt, caps at [`BACKOFF_MAX`], resets to `BACKOFF_MIN`
/// after a CLEAN daemon session exit (not merely on takeover — a
/// `run_session` that fails fast must keep backing off).
///
/// Rationale: a fixed poll burns a full interval of refresh downtime
/// every time an external daemon crashes, and hot-loops under
/// pathological contention. Exponential backoff gives instant recovery
/// in the common case (1s) while bounding the worst case (60s).
#[derive(Debug, Clone, Copy)]
struct Backoff {
    current: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            current: BACKOFF_MIN,
        }
    }

    fn current(&self) -> Duration {
        self.current
    }

    /// Doubles the wait up to [`BACKOFF_MAX`]. Call after a failed
    /// attempt before the next retry.
    fn bump(&mut self) {
        let next = self.current.saturating_mul(2);
        self.current = std::cmp::min(next, BACKOFF_MAX);
    }

    /// Resets to [`BACKOFF_MIN`]. Call after a daemon session exits
    /// CLEANLY (ran, then stopped) so the next cycle recovers instantly.
    /// NOT called on a fast `run_session` failure (e.g. a license-gate
    /// refusal) — those must keep backing off, not hot-loop.
    fn reset(&mut self) {
        self.current = BACKOFF_MIN;
    }
}

/// Runs the supervisor loop forever until `cancel` fires.
///
/// Each iteration: detect the current daemon state, and if no other
/// daemon owns it, acquire the [`PidFile`] and run one `run_session`
/// until it exits, then apply backoff. `run_session` receives a clone
/// of `base_dir` and a per-session [`CancellationToken`] derived from
/// `cancel` — it MUST run until that token fires, then drain and return.
///
/// Backoff semantics:
/// - Cold start: [`BACKOFF_MIN`] (1s).
/// - On each failed takeover attempt (external daemon owns the lock):
///   double the wait, cap at [`BACKOFF_MAX`] (60s).
/// - On a CLEAN session exit (`Ok(())` — the daemon owned the lock, ran
///   a session, and stopped because `cancel` was NOT fired): reset to
///   `BACKOFF_MIN` and retry almost immediately.
/// - On a fast `run_session` FAILURE (`Err` — socket-bind error, or a
///   license-gate refusal at the top of the session): do NOT reset; back
///   off exponentially so a durable refusal is a slow poll, not a 1s hot
///   loop.
///
/// `run_session` MUST NOT acquire the PidFile itself — this loop owns it
/// for the session's lifetime and drops it when the session returns.
///
/// an internal ticket — before EVERY detect/acquire attempt, the loop checks
/// [`super::is_stop_requested`]. While set, it never acquires the PidFile
/// or runs a session, polling at [`BACKOFF_MAX`] until either `cancel`
/// fires or the sentinel is cleared by a `csq daemon start`. This is what
/// makes `csq daemon stop` stick for a desktop-app in-process supervisor
/// that would otherwise observe the now-stopped standalone daemon's
/// `NotRunning` state and silently take over.
pub async fn run_forever<F, Fut>(base_dir: PathBuf, cancel: CancellationToken, run_session: F)
where
    F: Fn(PathBuf, CancellationToken) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    tracing::info!("daemon supervisor starting");
    let mut backoff = Backoff::new();
    loop {
        // Respect an already-fired cancel before starting a new session —
        // e.g. the desktop app quit during a backoff wait, or the loop was
        // entered pre-cancelled. Without this, a cancelled loop still pays a
        // full session startup (license gate, reconciler, audit verify, socket
        // bind, every subsystem spawn) + drain before observing cancellation
        // (redteam R2 finding 3). An in-flight session is unaffected — it
        // drains on its own `cancel.cancelled()`.
        if cancel.is_cancelled() {
            return;
        }

        // ── 0. Honor an explicit `csq daemon stop` (an internal ticket) ──
        //
        // Checked BEFORE detect/acquire so a stop-requested sentinel
        // defers this loop from ever taking over the daemon — not just
        // from a fresh `NotRunning`/`Stale` state, but even mid-backoff
        // against a `Healthy` external daemon that is itself in the
        // process of draining from the SAME `csq daemon stop` call.
        // Polls at a fixed `BACKOFF_MAX` cadence (not the exponential
        // backoff state, which this path never touches) — slow enough to
        // never busy-spin, independent of contention history.
        if is_stop_requested(&base_dir) {
            tracing::info!(
                "daemon stop requested via `csq daemon stop`; deferring re-acquire \
                 until a `csq daemon start` clears the request"
            );
            if wait_or_cancelled(&cancel, BACKOFF_MAX).await {
                return;
            }
            continue;
        }

        // ── 1. Detect current state ──────────────────────────────
        match detect_daemon(&base_dir) {
            DetectResult::Healthy {
                pid,
                daemon_version,
                ..
            } => {
                // Surface drift loudly so an operator inspecting logs can
                // see why the running daemon's data lags a freshly-installed
                // build. We do NOT unilaterally take over — that would kill
                // an in-flight flow — but a warn line points at the fix.
                if let Some(reason) = version_drift_reason(&daemon_version) {
                    tracing::warn!(
                        "external daemon (PID {pid}) reports drift: {reason}; deferring {:?}",
                        backoff.current()
                    );
                } else {
                    tracing::debug!(
                        "external daemon already running (PID {pid}); deferring {:?}",
                        backoff.current()
                    );
                }
                if wait_or_cancelled(&cancel, backoff.current()).await {
                    return;
                }
                backoff.bump();
                continue;
            }
            DetectResult::Unhealthy { reason } => {
                tracing::warn!(
                    "existing daemon is unhealthy ({reason}); deferring {:?}",
                    backoff.current()
                );
                if wait_or_cancelled(&cancel, backoff.current()).await {
                    return;
                }
                backoff.bump();
                continue;
            }
            DetectResult::Stale { reason } => {
                tracing::info!("stale daemon state detected ({reason}); taking over");
                // Fall through — PidFile::acquire cleans up the stale file
                // by virtue of being a fresh PidFile.
            }
            DetectResult::NotRunning => {
                tracing::info!("no daemon running; taking over");
            }
        }

        // ── 2. Try to acquire ownership ──────────────────────────
        let pid_path = pid_file_path(&base_dir);
        let pid_file = match PidFile::acquire(&pid_path) {
            Ok(f) => f,
            Err(e) => {
                // Race: another process grabbed the PidFile between our
                // detect and our acquire. Back off exponentially and let
                // the loop observe next iteration.
                tracing::debug!(
                    "PidFile::acquire failed ({e}); another daemon raced us; backing off {:?}",
                    backoff.current()
                );
                if wait_or_cancelled(&cancel, backoff.current()).await {
                    return;
                }
                backoff.bump();
                continue;
            }
        };

        // ── 3. Run one daemon session until it exits ─────────────
        //
        // `backoff.reset()` is applied ONLY after a CLEAN exit (Ok) — a
        // session that actually ran. A `run_session` that returns Err
        // (socket-bind failure, or a license-gate refusal at the top of
        // the session) must NOT reset, so repeated fast failures back off
        // exponentially instead of hot-looping at BACKOFF_MIN.
        let run_result = run_session(base_dir.clone(), cancel.clone()).await;
        drop(pid_file);

        // If the outer cancel fired during the session, exit the loop.
        if cancel.is_cancelled() {
            return;
        }

        let wait = match run_result {
            Ok(()) => {
                tracing::info!("daemon session exited cleanly");
                backoff.reset();
                BACKOFF_MIN
            }
            Err(e) => {
                let w = backoff.current();
                tracing::warn!("daemon session exited with error: {e} (retry in {w:?})");
                backoff.bump();
                w
            }
        };
        if wait_or_cancelled(&cancel, wait).await {
            return;
        }
    }
}

/// Sleeps for `duration` or until `cancel` fires. Returns `true` if
/// cancelled, `false` if the sleep completed. Lets the loop respect
/// shutdown promptly.
async fn wait_or_cancelled(cancel: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

/// A named long-lived daemon subsystem and its join handle.
///
/// Every daemon subsystem (refresher, usage poller, auto-rotator,
/// sweeps, ledger writer, log GC, anchor) is a `tokio::spawn`'d task
/// that loops until the shared shutdown token fires. The `&'static str`
/// is a stable label used in restart / drain log lines so an operator
/// can see WHICH subsystem died.
pub type Subsystem = (&'static str, JoinHandle<()>);

/// Why a daemon session's supervised wait returned.
///
/// A session body spawns every subsystem, then calls
/// [`await_session_stop`] to block until EITHER a graceful stop is
/// requested OR a subsystem exits on its own. The two outcomes drive
/// opposite dispositions:
///
/// - [`SessionStop::Cancelled`] — the caller's `cancel` token fired
///   (SIGTERM bridge, app quit, `csq daemon stop`). Drain and return
///   `Ok(())`; [`run_forever`] treats a clean exit as a normal stop.
/// - [`SessionStop::SubsystemExited`] — a subsystem task ended while
///   the session was still meant to be running (a panic, or a loop that
///   returned early). The session body cancels the SUBSYSTEM shutdown
///   token (a child of `cancel`, so siblings drain WITHOUT signalling
///   `run_forever` to stop), then returns `Err`. [`run_forever`] treats
///   the `Err` as a fast failure and restarts the session with backoff.
///
/// This closes the mass-token-expiry failure shape "one level down"
/// (an internal ticket): Wave B's launchd `KeepAlive` restarts the whole
/// PROCESS on a crash, but a subsystem task that dies inside a
/// still-alive process was previously invisible — the session blocked on
/// `cancel.cancelled()` and only awaited the join handles at shutdown, so
/// a dead refresher went unnoticed until the next full restart. The same
/// "tokens silently stopped refreshing" outcome the whole arc exists to
/// prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStop {
    /// The caller's cancellation token fired — a graceful stop.
    Cancelled,
    /// A subsystem (named) exited while the session was still running.
    SubsystemExited(&'static str),
}

/// Blocks until EITHER `cancel` fires OR the first subsystem in
/// `subsystems` exits, whichever comes first.
///
/// - On `cancel` first: returns [`SessionStop::Cancelled`]. `subsystems`
///   is left intact for the caller to drain.
/// - On a subsystem exiting first: `swap_remove`s that (already-finished)
///   handle from `subsystems` — so the caller's subsequent drain does NOT
///   re-await it (re-polling a completed `JoinHandle` panics) — and
///   returns [`SessionStop::SubsystemExited`] with its label. The
///   remaining live subsystems stay in `subsystems` for the caller to
///   drain.
///
/// The select is `biased` toward `cancel`: if a subsystem races a
/// graceful stop, the graceful path wins and the exit is handled as a
/// normal drain rather than a spurious restart.
pub async fn await_session_stop(
    cancel: &CancellationToken,
    subsystems: &mut Vec<Subsystem>,
) -> SessionStop {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => SessionStop::Cancelled,
        idx = first_finished(subsystems) => {
            let (name, _dead) = subsystems.swap_remove(idx);
            // `_dead` already resolved to `Ready` inside `first_finished`;
            // drop it WITHOUT awaiting again (a second poll of a completed
            // JoinHandle panics). The task is already gone.
            SessionStop::SubsystemExited(name)
        }
    }
}

/// Resolves to the index of the first subsystem whose task has ended.
///
/// Polls every handle on each wake; a `JoinHandle` becomes `Ready` when
/// its task completes — cleanly OR via panic (`Err(JoinError)`). Either
/// way the subsystem is no longer doing its job, so both are treated as
/// "exited". Uses `std::future::poll_fn` so no extra crate (`futures`)
/// is pulled in for a dynamic set of futures.
async fn first_finished(subsystems: &mut [Subsystem]) -> usize {
    std::future::poll_fn(|cx| {
        for (i, (_, handle)) in subsystems.iter_mut().enumerate() {
            // `JoinHandle` is `Unpin`, so `Pin::new` on the &mut is sound.
            if Pin::new(handle).poll(cx).is_ready() {
                return Poll::Ready(i);
            }
        }
        Poll::Pending
    })
    .await
}

/// Awaits every remaining subsystem with a per-handle deadline, logging
/// the outcome by name. Consumes `subsystems`.
///
/// Each handle gets its own `deadline`, so one stuck HTTP call in a
/// single subsystem cannot wedge the whole drain past `deadline`
/// (worst case is `deadline` × N, sequential — matching the pre-an internal ticket
/// hand-written drain). A handle already removed by [`await_session_stop`]
/// (the one that triggered the restart) is NOT in this set, so no handle
/// is ever double-polled.
pub async fn drain_subsystems(subsystems: Vec<Subsystem>, deadline: Duration) {
    for (name, handle) in subsystems {
        match tokio::time::timeout(deadline, handle).await {
            Ok(Ok(())) => tracing::info!(subsystem = name, "subsystem stopped cleanly"),
            Ok(Err(e)) => {
                // A `JoinError`'s Display carries the task's panic payload. This
                // drains OAuth-adjacent subsystems (the refresher / usage poller),
                // whose panic message could echo an upstream token (journals
                // 0007/0010 — Anthropic `invalid_grant` bodies have echoed a
                // refresh-token prefix). Route the payload through
                // `redact_tokens` before it reaches the persisted daemon log
                // (security.md §2/§8; the rolling file log is GC'd only every 14
                // days). Fixed `error_kind` tag per the §2 log-vocabulary guidance.
                tracing::warn!(
                    subsystem = name,
                    error_kind = "subsystem_panicked",
                    detail = %crate::error::redact_tokens(&e.to_string()),
                    "subsystem task panicked"
                )
            }
            Err(_) => tracing::warn!(
                subsystem = name,
                "subsystem did not stop within {:?} deadline",
                deadline
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn backoff_starts_at_min() {
        let b = Backoff::new();
        assert_eq!(b.current(), BACKOFF_MIN);
    }

    #[test]
    fn backoff_doubles_on_bump() {
        let mut b = Backoff::new();
        assert_eq!(b.current(), Duration::from_secs(1));
        b.bump();
        assert_eq!(b.current(), Duration::from_secs(2));
        b.bump();
        assert_eq!(b.current(), Duration::from_secs(4));
        b.bump();
        assert_eq!(b.current(), Duration::from_secs(8));
    }

    #[test]
    fn backoff_caps_at_max() {
        let mut b = Backoff::new();
        for _ in 0..20 {
            b.bump();
        }
        assert_eq!(b.current(), BACKOFF_MAX);
    }

    #[test]
    fn backoff_reset_drops_to_min() {
        let mut b = Backoff::new();
        b.bump();
        b.bump();
        b.bump();
        assert!(b.current() > BACKOFF_MIN);
        b.reset();
        assert_eq!(b.current(), BACKOFF_MIN);
    }

    #[test]
    fn backoff_saturates_on_overflow() {
        // Guard against u128 overflow in Duration multiplication. The cap
        // means we never get near overflow in practice — the saturating
        // mul is defense in depth.
        let mut b = Backoff::new();
        for _ in 0..100 {
            b.bump();
        }
        assert_eq!(b.current(), BACKOFF_MAX);
    }

    /// Drives `run_forever` to completion on a DEDICATED OS thread with its own
    /// 2-worker runtime, waiting for it via an OS-level `mpsc::recv_timeout`
    /// (a condvar wait, NOT a tokio timer). Panics if it does not return within
    /// `HANG_GUARD` — a genuine hang backstop, NOT a latency assertion.
    ///
    /// Why not `#[tokio::test] + tokio::time::timeout`: `run_forever` calls
    /// `PidFile::acquire` → a blocking `fsync` (`write_pid_atomic`). When the
    /// wrapping `timeout` timer shares the SAME runtime as that blocking fsync,
    /// extreme CI oversubscription (the enterprise suite runs 4000+ tests in
    /// parallel) starves the runtime and the wall-clock `timeout` Elapses
    /// spuriously — observed even at 60s on the ubuntu enterprise job
    /// (2026-07-25), and even after the earlier multi_thread fix (57a27925).
    /// Running `run_forever` on its own thread + waiting via `recv_timeout`
    /// decouples the completion signal from the starved runtime, so the guard
    /// fires only on a real hang.
    ///
    /// **Budget: 180s, raised from 60s.** This is a HANG backstop, not a
    /// latency assertion, and 60s was arbitrary. The instrumented runs settled
    /// what the failure is, by elimination rather than assumption:
    ///
    /// | run | backing | sessions | post-hoc probe |
    /// |-----|---------|----------|----------------|
    /// | 30153429238 | tmpfs(/dev/shm) | — | — |
    /// | 30155611297 | tmpfs(/dev/shm) | 0 | acquire SUCCEEDS |
    /// | 30156520139 | default-fs      | 0 | acquire SUCCEEDS |
    ///
    /// Identical on BOTH filesystems, so it is neither the ext4-fsync
    /// pathology (tmpfs has no journal) nor a `/dev/shm` capacity limit
    /// (default-fs has no shared cap). `unwound: true` every time means the
    /// loop was alive and answered cancel, so it is not a deadlock. And the
    /// same directory accepts a `PidFile::acquire` moments later, once the
    /// suite has drained.
    ///
    /// What remains is contention: the enterprise job runs 4243 tests in ~66s
    /// wall, and `run_forever` cannot complete one `detect → acquire` (which
    /// includes a blocking `fsync`) inside 60s of that. A real deadlock never
    /// resolves, so 180s still catches one; 60s was catching load.
    ///
    /// Do NOT read a failure here as a latency regression. The diagnostic in
    /// the panic message (backing / sessions / probe) is what distinguishes the
    /// modes — read it before changing this constant again.
    const HANG_GUARD: Duration = Duration::from_secs(180);

    /// Grace period for the loop to unwind after the harness fires `cancel`
    /// externally. Only used on the failure path, after `HANG_GUARD` expired.
    const UNWIND_GRACE: Duration = Duration::from_secs(30);

    /// Serializes the `run_forever` tests AND their `XDG_RUNTIME_DIR` override.
    /// Poison-tolerant: a panicking test must not wedge the rest.
    static SUPERVISE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Runs `f` with `XDG_RUNTIME_DIR` pointed at `dir`, serialized process-wide.
    ///
    /// **This is the actual isolation fix.** `pid_file_path` (paths.rs:33-39)
    /// IGNORES its `base_dir` argument on Linux whenever `XDG_RUNTIME_DIR` is
    /// set, returning `$XDG_RUNTIME_DIR/csq-daemon.pid` — one GLOBAL path. So
    /// giving each test its own tempdir never isolated anything: every
    /// `run_forever` test, and every concurrently-running job on the same
    /// self-hosted Linux runner (they share a `$XDG_RUNTIME_DIR`), contended on
    /// a single pid file. The loser's `PidFile::acquire` returned
    /// `AlreadyRunning` every iteration, so `run_forever` backed off forever and
    /// its session body never ran — `sessions run: 0`, loop alive, answers
    /// cancel. Exactly the observed signature, on every filesystem, at 60s and
    /// at 180s, and only on Linux (macOS has no `XDG_RUNTIME_DIR`, so it fell
    /// through to the per-test `base_dir` and passed).
    ///
    /// Pointing `XDG_RUNTIME_DIR` at the per-test tempdir makes
    /// `pid_file_path` resolve inside it, which is what the tests always
    /// assumed.
    fn with_isolated_runtime_dir<F: FnOnce() -> R, R>(dir: &std::path::Path, f: F) -> R {
        // Lock order per `test-hermeticity.md` MUST-1: the workspace-wide
        // `test_env::lock()` FIRST, then the in-module mutex.
        //
        // `SUPERVISE_ENV_LOCK` alone is insufficient and the comment that used
        // to sit below said so without meaning to: it asserted "no other thread
        // in this process reads XDG_RUNTIME_DIR concurrently", which is exactly
        // the assumption the shared lock exists because it fails. This is a
        // direct sibling of the an internal ticket incident — `daemon::detect` wrote a pid
        // file at `$XDG_RUNTIME_DIR/csq-daemon.pid` while `daemon::paths` flipped
        // that same variable under `test_env::lock()`, and the detect test
        // resolved to a different directory mid-flight. A module-local mutex
        // serialises this module only; the sibling holding the shared lock sails
        // straight through it.
        let _shared_env_guard = crate::platform::test_env::lock();
        let _g = SUPERVISE_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os("XDG_RUNTIME_DIR");
        // SAFETY: serialised by the shared lock above plus SUPERVISE_ENV_LOCK.
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", dir);
        }
        let out = f();
        unsafe {
            match prev {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }
        out
    }

    /// Confirms `PidFile::acquire` works at the path `run_forever` ACTUALLY
    /// uses — `pid_file_path(dir)`, not a name of our own choosing.
    ///
    /// The earlier version of this probe used `dir.join("probe.pid")`, which on
    /// Linux is a DIFFERENT file from the global `$XDG_RUNTIME_DIR/csq-daemon.pid`
    /// the loop contends on. It therefore reported `SUCCEEDS` across three CI
    /// rounds while the loop was losing a race on another path entirely, and
    /// sent me chasing filesystem theories. A probe must exercise the same path
    /// as the code under test.
    fn pid_lock_usable_in(dir: &std::path::Path) -> Result<(), String> {
        let probe = pid_file_path(dir);
        match PidFile::acquire(&probe) {
            Ok(f) => {
                drop(f);
                let _ = std::fs::remove_file(&probe);
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// A plain tempdir for the `run_forever` tests, plus a label reported in
    /// the failure message.
    ///
    /// **The tmpfs (`/dev/shm`) backing was REMOVED.** It was added for a root
    /// cause that this module's own diagnostics then refuted, and it became the
    /// best-supported explanation for the failure it was meant to fix:
    ///
    /// - Introduced (d9e3c91d) on the theory that `PidFile::acquire`'s `fsync`
    ///   stalled on a contended CI ext4 journal.
    /// - Run 30153429238 reported `backing: tmpfs(/dev/shm)` while the tests
    ///   still hung — the mitigation had ENGAGED and the hang persisted, so the
    ///   ext4-fsync explanation is refuted, not merely unconfirmed.
    /// - Run 30155611297 reported `sessions run: 0` with `post-hoc probe:
    ///   PidFile::acquire SUCCEEDS here now`: the loop never reached a session
    ///   because it could not acquire DURING the run, yet the same directory
    ///   accepted an acquire once the suite drained.
    ///
    /// `/dev/shm` is a size-capped tmpfs shared by the whole job, and
    /// `try_lock_file` surfaces any non-`EWOULDBLOCK` errno from `open`/`flock`
    /// as a failed acquire indistinguishable from contention. `run_forever`
    /// then backs off (1s, 2s, 4s … capped at 60s), consuming the hang guard —
    /// which fits every observation, including that only the enterprise job
    /// (4243 concurrent tests) ever hit it. A normal tempdir has no shared cap.
    fn test_tempdir() -> (tempfile::TempDir, &'static str) {
        (tempfile::tempdir().unwrap(), "default-fs")
    }

    /// Drives `run_forever` to completion on a DEDICATED OS thread with its own
    /// 2-worker runtime, waiting via an OS-level `mpsc::recv_timeout` (a condvar
    /// wait, NOT a tokio timer) so the completion signal is not affected by
    /// starvation inside the runtime under test.
    ///
    /// `run_forever` is an infinite loop whose ONLY exit is `cancel`. Its
    /// callers here fire `cancel` from INSIDE the session body, so any condition
    /// that prevents the session from being reached — a stalled `fsync` in
    /// `PidFile::acquire`, a transient `AlreadyRunning`, scheduler starvation —
    /// leaves the loop backing off forever with nothing able to stop it. The
    /// harness therefore fires `cancel` ITSELF once `HANG_GUARD` expires, so the
    /// loop always unwinds and the worker thread is never leaked, then fails
    /// with the diagnostic state (backing kind + how far the loop got) instead
    /// of a bare `Timeout`.
    /// `sessions` counts how many times the session body actually ran. It is the
    /// diagnostic that discriminates the two remaining explanations when the
    /// guard fires: `0` means the loop never got past detect/acquire (a backoff
    /// cycle — `PidFile::acquire` failing, or `detect_daemon` not returning
    /// NotRunning/Stale), whereas `>= 1` means sessions ran but the loop did not
    /// observe the cancel they fired. Run 30153429238 established `backing =
    /// tmpfs(/dev/shm)` and `unwound = true`, which refutes the ext4-fsync
    /// explanation (the mitigation engaged) and the deadlock explanation (the
    /// loop answered cancel immediately) — leaving exactly these two, which this
    /// counter separates.
    fn drive_run_forever_to_return<F, Fut>(
        base: PathBuf,
        cancel: CancellationToken,
        backing: &'static str,
        sessions: Arc<AtomicUsize>,
        body: F,
    ) where
        F: Fn(PathBuf, CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send,
    {
        let (tx, rx) = std::sync::mpsc::channel();
        let cancel_for_loop = cancel.clone();
        let base_for_probe = base.clone();
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("build test runtime");
            rt.block_on(run_forever(base, cancel_for_loop, body));
            let _ = tx.send(());
        });

        if rx.recv_timeout(HANG_GUARD).is_ok() {
            handle.join().expect("run_forever thread must not panic");
            return;
        }

        // The loop never reached its own cancel. Fire it from outside so the
        // thread unwinds and joins (otherwise it leaks for the rest of the
        // suite), then report what we know.
        cancel.cancel();
        let unwound = rx.recv_timeout(UNWIND_GRACE).is_ok();
        if unwound {
            handle.join().expect("run_forever thread must not panic");
        }
        let ran = sessions.load(Ordering::SeqCst);
        // The loop has stopped; a probe now names the acquire failure directly
        // instead of leaving "PidFile::acquire failing" as an inference.
        let probe = match pid_lock_usable_in(&base_for_probe) {
            Ok(()) => "PidFile::acquire SUCCEEDS here now".to_string(),
            Err(e) => format!("PidFile::acquire FAILS here: {e}"),
        };
        let verdict = if ran == 0 {
            "sessions=0 — the loop NEVER reached the session body: detect/acquire \
             backoff cycle (PidFile::acquire failing, or detect_daemon not \
             returning NotRunning/Stale)"
        } else {
            "sessions>=1 — the session body DID run; the loop failed to observe \
             the cancel it fired"
        };
        panic!(
            "run_forever did not return within {HANG_GUARD:?} on its own \
             (tempdir backing: {backing}; unwound after external cancel: {unwound}; \
             sessions run: {ran}; post-hoc probe: {probe}). {verdict}"
        );
    }

    /// The loop MUST exit promptly when the cancel token is already fired,
    /// without ever acquiring the PidFile or running a session.
    #[test]
    fn run_forever_exits_immediately_when_pre_cancelled() {
        let (tmp, backing) = test_tempdir();
        let base = tmp.path().to_path_buf();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);

        with_isolated_runtime_dir(&base.clone(), || {
            drive_run_forever_to_return(base, cancel, backing, Arc::clone(&calls), move |_b, _c| {
                let calls = Arc::clone(&calls_c);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
        });

        // The top-of-loop `is_cancelled()` guard returns BEFORE running any
        // session when the loop is entered already-cancelled — zero sessions.
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "pre-cancelled loop must run zero sessions, ran {}",
            calls.load(Ordering::SeqCst)
        );
    }

    /// A session that returns cleanly while cancel is NOT fired resets the
    /// backoff; the loop then observes cancel on the next wait and exits.
    #[test]
    fn run_forever_runs_session_then_honors_cancel() {
        let (tmp, backing) = test_tempdir();
        let base = tmp.path().to_path_buf();
        let cancel = CancellationToken::new();
        let cancel_for_session = cancel.clone();
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_c = Arc::clone(&ran);

        with_isolated_runtime_dir(&base.clone(), || {
            drive_run_forever_to_return(base, cancel, backing, Arc::clone(&ran), move |_b, _c| {
                let ran = Arc::clone(&ran_c);
                let cancel = cancel_for_session.clone();
                async move {
                    ran.fetch_add(1, Ordering::SeqCst);
                    // Simulate a clean session: fire cancel so the loop's
                    // post-session `is_cancelled()` check returns.
                    cancel.cancel();
                    Ok(())
                }
            })
        });

        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "session must run exactly once before cancel is observed"
        );
    }

    /// A subsystem-exit `Err` from `run_session` MUST restart the session
    /// (not exit the loop): this is the run_forever half of the an internal ticket fix.
    /// First session returns `Err` (subsystem died, cancel NOT fired) → the
    /// loop backs off and re-runs; the second session fires cancel + returns
    /// `Ok`, letting the loop exit. `ran == 2` proves the restart.
    #[test]
    fn run_forever_restarts_after_session_error() {
        let (tmp, backing) = test_tempdir();
        let base = tmp.path().to_path_buf();
        let cancel = CancellationToken::new();
        let cancel_for_session = cancel.clone();
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_c = Arc::clone(&ran);

        with_isolated_runtime_dir(&base.clone(), || {
            drive_run_forever_to_return(base, cancel, backing, Arc::clone(&ran), move |_b, _c| {
                let ran = Arc::clone(&ran_c);
                let cancel = cancel_for_session.clone();
                async move {
                    let n = ran.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        // First session: simulate a subsystem death — return Err
                        // WITHOUT firing cancel. run_forever must restart.
                        Err("subsystem exited mid-session: refresher".to_string())
                    } else {
                        // Second session: clean stop.
                        cancel.cancel();
                        Ok(())
                    }
                }
            })
        });

        assert_eq!(
            ran.load(Ordering::SeqCst),
            2,
            "an Err session must be restarted; expected 2 sessions, got {}",
            ran.load(Ordering::SeqCst)
        );
    }

    /// an internal ticket: while the stop-requested sentinel is set, `run_forever`
    /// MUST NOT acquire the PidFile or run a session — even though
    /// `detect_daemon` would otherwise report `NotRunning` and the loop
    /// would normally take over immediately. This is the non-vacuity proof
    /// for the § 0 sentinel check: an external thread fires `cancel` only
    /// AFTER a short delay, well short of `BACKOFF_MAX` (60s), so the loop
    /// returning promptly proves it was parked in the sentinel's
    /// `wait_or_cancelled(&cancel, BACKOFF_MAX)` branch (cancellation wins
    /// the `select!` immediately) rather than having raced through to a
    /// session before the delay elapsed.
    #[test]
    fn run_forever_never_acquires_while_stop_requested() {
        let (tmp, backing) = test_tempdir();
        let base = tmp.path().to_path_buf();
        crate::daemon::stop_sentinel::set_stop_requested(&base);

        let cancel = CancellationToken::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = Arc::clone(&calls);

        // Fire cancel from an independent thread after a short delay —
        // long enough for run_forever to have raced through detect/acquire
        // and started a session had the sentinel NOT been honored, short
        // enough that a 60s BACKOFF_MAX wait could not have elapsed.
        let cancel_for_delay = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            cancel_for_delay.cancel();
        });

        with_isolated_runtime_dir(&base.clone(), || {
            drive_run_forever_to_return(
                base.clone(),
                cancel,
                backing,
                Arc::clone(&calls),
                move |_b, _c| {
                    let calls = Arc::clone(&calls_c);
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
        });

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a stop-requested loop must never run a session, ran {}",
            calls.load(Ordering::SeqCst)
        );
        // NOTE: an earlier revision asserted `pid_lock_usable_in(&base).is_ok()`
        // here, meaning "the PidFile must remain unacquired". That assertion
        // could not discriminate the property it named, and it flaked in CI
        // (enterprise job, 4651 passed / 1 failed) while passing locally.
        //
        // By this point `run_forever` has RETURNED, so its `PidFile` guard is
        // dropped and the lock is released whether or not it was ever acquired
        // — "never acquired" and "acquired then released" are indistinguishable
        // from here. What the check actually measured was whether a fresh
        // `PidFile::acquire` succeeds RIGHT NOW, which under heavy parallel test
        // load is a property of the runner, not of the sentinel.
        //
        // The real property is `calls == 0` above: the loop never ran a session.
        // This second assertion adds a durable, non-racy fact instead — the loop
        // DEFERRED on the sentinel rather than consuming it, so a later
        // `daemon start` is still the thing that clears it.
        assert!(
            crate::daemon::stop_sentinel::is_stop_requested(&base),
            "the stop sentinel must survive the deferral — run_forever defers on \
             it, and only an explicit start path may clear it"
        );
    }

    /// Once the sentinel is cleared, the SAME loop resumes normal
    /// detect/acquire/run behavior — the deferral is not a permanent wedge.
    #[test]
    fn run_forever_resumes_after_stop_requested_cleared() {
        let (tmp, backing) = test_tempdir();
        let base = tmp.path().to_path_buf();
        // Never set — this test's control is `run_forever_runs_session_then_
        // honors_cancel` above; here we explicitly exercise clear() as a
        // no-op-on-absent path (mirrors clear_on_absent_sentinel_is_a_noop
        // in stop_sentinel's own unit tests) immediately before running the
        // loop, proving clear() never blocks a fresh start.
        crate::daemon::stop_sentinel::clear_stop_requested(&base);

        let cancel = CancellationToken::new();
        let cancel_for_session = cancel.clone();
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_c = Arc::clone(&ran);

        with_isolated_runtime_dir(&base.clone(), || {
            drive_run_forever_to_return(base, cancel, backing, Arc::clone(&ran), move |_b, _c| {
                let ran = Arc::clone(&ran_c);
                let cancel = cancel_for_session.clone();
                async move {
                    ran.fetch_add(1, Ordering::SeqCst);
                    cancel.cancel();
                    Ok(())
                }
            })
        });

        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "loop must run a session normally when no stop is requested"
        );
    }

    /// `await_session_stop` returns `Cancelled` when the token fires while
    /// every subsystem is still live, and leaves `subsystems` intact for the
    /// caller's drain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn await_session_stop_returns_cancelled_when_token_fires() {
        let cancel = CancellationToken::new();
        let sub_shutdown = cancel.child_token();
        // A live subsystem that only exits on the (child) shutdown token.
        let s = sub_shutdown.clone();
        let mut subsystems: Vec<Subsystem> = vec![(
            "refresher",
            tokio::spawn(async move { s.cancelled().await }),
        )];

        cancel.cancel();
        let stop = tokio::time::timeout(
            Duration::from_secs(5),
            await_session_stop(&cancel, &mut subsystems),
        )
        .await
        .expect("await_session_stop must return promptly on cancel");

        assert_eq!(stop, SessionStop::Cancelled);
        assert_eq!(subsystems.len(), 1, "live subsystem must remain for drain");
    }

    /// A subsystem that exits on its own (clean return) is detected, removed
    /// from `subsystems` (so the drain never re-polls the completed handle),
    /// and reported by name; live siblings remain.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn await_session_stop_detects_clean_subsystem_exit() {
        let cancel = CancellationToken::new();
        let live = cancel.child_token();
        let live_c = live.clone();
        let mut subsystems: Vec<Subsystem> = vec![
            // Dies immediately.
            ("refresher", tokio::spawn(async {})),
            // Stays alive until the token fires (never, in this test).
            (
                "usage_poller",
                tokio::spawn(async move { live_c.cancelled().await }),
            ),
        ];

        let stop = tokio::time::timeout(
            Duration::from_secs(5),
            await_session_stop(&cancel, &mut subsystems),
        )
        .await
        .expect("await_session_stop must detect the exited subsystem");

        assert_eq!(stop, SessionStop::SubsystemExited("refresher"));
        assert_eq!(subsystems.len(), 1, "dead handle must be removed");
        assert_eq!(
            subsystems[0].0, "usage_poller",
            "the live sibling must remain for drain"
        );
        // cancel is NOT fired — proves the return was subsystem-driven.
        assert!(!cancel.is_cancelled());
    }

    /// A subsystem that PANICS (JoinHandle resolves to `Err(JoinError)`) is
    /// treated identically to a clean exit — a panicked refresher is still a
    /// dead refresher.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn await_session_stop_detects_panicked_subsystem() {
        let cancel = CancellationToken::new();
        let mut subsystems: Vec<Subsystem> = vec![(
            "refresher",
            tokio::spawn(async { panic!("simulated subsystem panic") }),
        )];

        let stop = tokio::time::timeout(
            Duration::from_secs(5),
            await_session_stop(&cancel, &mut subsystems),
        )
        .await
        .expect("await_session_stop must detect the panicked subsystem");

        assert_eq!(stop, SessionStop::SubsystemExited("refresher"));
        assert!(subsystems.is_empty());
    }

    /// `drain_subsystems` awaits every live handle to completion once their
    /// shared token fires.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_subsystems_awaits_live_handles() {
        let shutdown = CancellationToken::new();
        let a = shutdown.clone();
        let b = shutdown.clone();
        let subsystems: Vec<Subsystem> = vec![
            (
                "refresher",
                tokio::spawn(async move { a.cancelled().await }),
            ),
            (
                "usage_poller",
                tokio::spawn(async move { b.cancelled().await }),
            ),
        ];

        shutdown.cancel();
        tokio::time::timeout(
            Duration::from_secs(5),
            drain_subsystems(subsystems, Duration::from_secs(5)),
        )
        .await
        .expect("drain must complete once the shared token fires");
    }

    /// A stuck subsystem does not wedge the drain past its per-handle
    /// deadline — the drain returns within a bounded window even though the
    /// task never exits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_subsystems_times_out_stuck_handle() {
        // A task that never observes any shutdown — it just sleeps far past
        // the drain deadline.
        let subsystems: Vec<Subsystem> = vec![(
            "stuck",
            tokio::spawn(async { tokio::time::sleep(Duration::from_secs(3600)).await }),
        )];

        // deadline = 100ms; the whole drain must return well under the 3600s
        // the task would otherwise take.
        tokio::time::timeout(
            Duration::from_secs(5),
            drain_subsystems(subsystems, Duration::from_millis(100)),
        )
        .await
        .expect("drain must return within the per-handle deadline for a stuck task");
    }
}
