//! In-process daemon supervisor.
//!
//! Runs the csq daemon (refresher + usage poller + auto-rotate + IPC
//! server) inside the Tauri app process itself, so tokens are
//! refreshed for as long as the desktop app is running — no separate
//! `csq daemon start` required.
//!
//! ### Why in-process
//!
//! Journal 0026 (this session): every OAuth account on the author's
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
//! same token and drain gracefully. The `PidFile` drops last,
//! cleaning up the `.csq-daemon.pid` file.

use csq_core::daemon::{self, detect_daemon, DetectResult, PidFile};
use std::path::PathBuf;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

// Unix-only imports for run_daemon (server, refresher subsystems).
// On Windows, the supervisor loop still detects external daemons and
// acquires the PidFile, but run_daemon is a no-op stub (M8.6).
#[cfg(unix)]
use csq_core::accounts::AccountInfo;
#[cfg(unix)]
use csq_core::daemon::{server as daemon_server, HttpGetFn, HttpPostFn, HttpPostProbeFn, TtlCache};
#[cfg(unix)]
use csq_core::http;
#[cfg(unix)]
use csq_core::oauth::OAuthStateStore;
#[cfg(unix)]
use std::sync::Arc;

/// Minimum wait between failed takeover attempts. Short enough
/// that a crashing external daemon doesn't starve csq for minutes
/// before our supervisor catches the gap.
const BACKOFF_MIN: Duration = Duration::from_secs(1);

/// Maximum wait between failed takeover attempts. 60s keeps the
/// loop from hot-spinning under pathological contention (e.g. two
/// csq apps racing each other to own the same PidFile) while also
/// being well below the 5-minute refresh interval.
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Supervisor backoff state. Starts at [`BACKOFF_MIN`], doubles on
/// each failed attempt, caps at [`BACKOFF_MAX`], resets to
/// `BACKOFF_MIN` whenever the supervisor successfully takes over.
///
/// Addresses journal 0026 design question 1: the fixed 60s poll
/// burns a full minute of refresh downtime every time an external
/// daemon crashes, and hot-loops under pathological contention.
/// Exponential backoff gives instant recovery in the common case
/// (1s) while bounding the worst case (60s).
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

    /// Resets to [`BACKOFF_MIN`]. Call whenever the supervisor
    /// successfully owns the daemon (so the next failure recovers
    /// instantly instead of inheriting the previous backoff).
    fn reset(&mut self) {
        self.current = BACKOFF_MIN;
    }
}

/// Top-level handle returned to the Tauri setup() hook. Owns the
/// shutdown token; dropping it does **not** stop the daemon — call
/// [`shutdown`](Self::shutdown) explicitly at app exit.
pub struct SupervisorHandle {
    shutdown: CancellationToken,
}

impl SupervisorHandle {
    /// Fires the shared cancellation token. Any subsystem currently
    /// in-flight drains on its own deadline; the supervisor loop
    /// exits on the next iteration.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// Starts the in-process daemon supervisor.
///
/// Spawns a single tokio task that loops forever until `shutdown`
/// fires. Each iteration tries to take ownership of the daemon
/// (`PidFile::acquire` + `serve`), and if another daemon already
/// has it, waits 60s and retries.
///
/// This function returns immediately — the work happens on the
/// returned tokio task.
pub fn start(base_dir: PathBuf) -> SupervisorHandle {
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tauri::async_runtime::spawn(async move {
        supervisor_loop(base_dir, shutdown_clone).await;
    });

    SupervisorHandle { shutdown }
}

/// Supervisor main loop. Owns the lifetime of the in-process daemon
/// across crashes and external-daemon contention.
///
/// Backoff semantics:
/// - Cold start: `BACKOFF_MIN` (1s)
/// - On each failed takeover attempt: double the wait, cap at
///   `BACKOFF_MAX` (60s)
/// - On each successful takeover (PidFile acquired, subsystems
///   spawned): reset to `BACKOFF_MIN` so the next failure recovers
///   instantly
/// - On clean daemon exit (we owned it, cancellation not fired):
///   stay at the reset value and retry after 5s
async fn supervisor_loop(base_dir: PathBuf, cancel: CancellationToken) {
    log::info!("daemon supervisor starting");
    let mut backoff = Backoff::new();
    loop {
        // ── 1. Detect current state ──────────────────────────────
        //
        // `detect_daemon` returns `NotRunning` (fresh state),
        // `Healthy` (someone else owns it — observe), `Stale`
        // (cleanup + take over), or `Unhealthy` (another daemon is
        // struggling; back off so we don't race it).
        match detect_daemon(&base_dir) {
            DetectResult::Healthy { pid, .. } => {
                log::debug!(
                    "external daemon already running (PID {pid}); deferring {:?}",
                    backoff.current()
                );
                // Wait and re-poll. If the external daemon dies, the
                // next detect returns NotRunning/Stale and we take over.
                if wait_or_cancelled(&cancel, backoff.current()).await {
                    return;
                }
                backoff.bump();
                continue;
            }
            DetectResult::Unhealthy { reason } => {
                log::warn!(
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
                log::info!("stale daemon state detected ({reason}); taking over");
                // Fall through — PidFile::acquire will clean up the
                // stale file by virtue of being a fresh PidFile.
            }
            DetectResult::NotRunning => {
                log::info!("no daemon running; taking over");
            }
        }

        // ── 2. Try to acquire ownership ──────────────────────────
        let pid_path = daemon::pid_file_path(&base_dir);
        let pid_file = match PidFile::acquire(&pid_path) {
            Ok(f) => f,
            Err(e) => {
                // Race: another process grabbed the PidFile between
                // our detect call and our acquire call. Back off
                // exponentially and let the loop observe next
                // iteration. Protects against hot-loops when two
                // csq apps fight over the same account dir.
                log::debug!(
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

        // ── 3. Successfully owning the daemon — reset backoff ────
        //
        // Any future failure (subsystem crash, next takeover
        // attempt) starts from BACKOFF_MIN again so we recover
        // instantly in the common case.
        backoff.reset();

        // ── 4. Run one daemon instance until it exits ────────────
        //
        // On Unix: binds the socket, spawns subsystems, waits for
        // either cancellation or a subsystem failure, then cleans up.
        // On Windows: M8.6 — no daemon subsystems yet; hold the
        // PidFile and wait for cancellation.
        if let Err(e) = run_daemon(&base_dir, cancel.clone()).await {
            log::warn!("in-process daemon exited with error: {e}");
        } else {
            log::info!("in-process daemon exited cleanly");
        }
        drop(pid_file);

        // If the outer cancel fired during run_daemon, exit the
        // supervisor loop. Otherwise, the daemon exited for some
        // internal reason and we should retry after a short wait.
        // `BACKOFF_MIN` is the right delay here — we just cleanly
        // released the lock, so the next iteration should try
        // again almost immediately rather than inherit a stale
        // exponential wait from before the takeover.
        if cancel.is_cancelled() {
            return;
        }
        if wait_or_cancelled(&cancel, BACKOFF_MIN).await {
            return;
        }
    }
}

/// Sleeps for `duration` or until the cancellation token fires.
/// Returns `true` if cancelled, `false` if the sleep completed
/// normally. Lets the supervisor loop respect shutdown promptly.
async fn wait_or_cancelled(cancel: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

/// One full run of the in-process daemon: bind socket, spawn
/// subsystems, await cancellation, drain cleanly.
///
/// Mirrors the CLI `csq daemon start` startup sequence in
/// `csq-cli/src/commands/daemon.rs` so the subsystem composition
/// stays in exactly one shape — refresher + usage poller +
/// auto-rotate + server, all sharing a single shutdown token.
#[cfg(unix)]
async fn run_daemon(
    base_dir: &std::path::Path,
    outer_cancel: CancellationToken,
) -> Result<(), String> {
    let sock_path = daemon::socket_path(base_dir);

    // Local shutdown token derived from outer_cancel. The server
    // gets its own internal token (created by `serve`); we cancel
    // our subsystems plus the server when the outer token fires.
    let shutdown = outer_cancel.clone();

    let refresh_cache: Arc<TtlCache<u16, daemon::RefreshStatus>> =
        Arc::new(TtlCache::with_default_age());
    let discovery_cache: Arc<TtlCache<(), Vec<AccountInfo>>> =
        Arc::new(TtlCache::new(daemon_server::DISCOVERY_CACHE_MAX_AGE));
    let oauth_store: Arc<OAuthStateStore> = Arc::new(OAuthStateStore::new());

    // The refresh endpoint requires JSON body (Anthropic switched to
    // JSON-only — see journal 0034). post_json sets Content-Type:
    // application/json; refresh::build_refresh_body produces the full
    // JSON payload with client_id and scope.
    let http_post: HttpPostFn = Arc::new(|url: &str, body: &str| http::post_json(url, body));
    let http_get: HttpGetFn = Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
        http::get_bearer(url, token, headers)
    });
    let http_post_probe: HttpPostProbeFn =
        Arc::new(|url: &str, headers: &[(String, String)], body: &str| {
            http::post_json_with_headers(url, headers, body)
        });

    let router_state = daemon_server::RouterState {
        cache: Arc::clone(&refresh_cache),
        discovery_cache: Arc::clone(&discovery_cache),
        base_dir: Arc::new(base_dir.to_path_buf()),
        oauth_store: Some(Arc::clone(&oauth_store)),
    };

    // Bind the Unix socket first. If bind fails (e.g. another
    // daemon owns it despite the PidFile acquire — shouldn't
    // happen but we guard against it), return so the supervisor
    // loop can back off and retry.
    let (server, server_join) = daemon::serve(&sock_path, router_state)
        .await
        .map_err(|e| format!("socket bind failed: {e}"))?;
    log::info!("in-process daemon socket bound at {}", sock_path.display());

    // Subsystems share `shutdown` so a single cancel drains them
    // all. The server owns its own internal token fired via
    // `server.shutdown()` below.
    let refresher = daemon::spawn_refresher(
        base_dir.to_path_buf(),
        Arc::clone(&refresh_cache),
        http_post,
        shutdown.clone(),
    );
    let usage_poller = daemon::spawn_usage_poller(
        base_dir.to_path_buf(),
        http_get,
        http_post_probe,
        shutdown.clone(),
    );
    let auto_rotator = daemon::spawn_auto_rotate(base_dir.to_path_buf(), shutdown.clone());
    let sweep = csq_core::session::spawn_sweep(base_dir.to_path_buf(), shutdown.clone());

    // Block until cancellation fires from the app lifecycle.
    outer_cancel.cancelled().await;

    log::info!("in-process daemon stopping");
    server.shutdown();

    // Drain with per-subsystem deadlines so one stuck HTTP call
    // can't wedge app shutdown. The same 5s budget the CLI uses.
    let _ = tokio::time::timeout(Duration::from_secs(5), refresher.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), usage_poller.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), auto_rotator.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), sweep.join).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), server_join).await;

    Ok(())
}

/// Windows stub — the csq daemon has no named-pipe backend yet
/// (M8-03). The supervisor loop will just sit on the backoff wait
/// until cancellation fires.
#[cfg(not(unix))]
async fn run_daemon(
    _base_dir: &std::path::Path,
    outer_cancel: CancellationToken,
) -> Result<(), String> {
    log::warn!("in-process daemon not supported on this platform (M8-03 Windows IPC pending)");
    outer_cancel.cancelled().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Hammer it 20 times — way past the cap.
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
        // Guard against u128 overflow in Duration multiplication.
        // Doubling a 60s Duration once is 120s; capping to 60s means
        // we never get near overflow in practice — the saturating
        // mul is defense in depth.
        let mut b = Backoff::new();
        for _ in 0..100 {
            b.bump();
        }
        assert_eq!(b.current(), BACKOFF_MAX);
    }
}
