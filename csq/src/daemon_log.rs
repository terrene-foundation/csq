//! csq daemon rolling-file log writer (#1a-2, daemon-auth-resilience Wave A2).
//!
//! Builds the writer half of the daemon's persistent history: a
//! daily-rolling file under
//! `csq_core::daemon::log_gc::daemon_log_dir(base_dir)`, GC'd on a 14-day
//! retention by `csq_core::daemon::log_gc::spawn`. Both the CLI (`csq daemon
//! start`) and the desktop in-process daemon supervisor wire this writer
//! into their `tracing` subscriber so the daemon's history survives process
//! death — the gap that let a 3.5-day silent token-refresh outage go
//! unnoticed (an internal journal entry).

use csq_core::daemon::log_gc::{self, LOG_FILE_PREFIX};
use std::path::Path;
use std::sync::OnceLock;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

/// Process-lifetime home for the `tracing-appender` worker guard.
///
/// The guard must stay alive for the life of the process — dropping it
/// stops the background flush thread and silently truncates buffered log
/// lines. A `OnceLock` gives it a `'static` home without threading it
/// through every caller; [`store_guard`] is called exactly once, right
/// after the subscriber that owns the writer is installed.
///
/// The guard is intentionally never dropped at process exit — there is no
/// shutdown-time flush wiring. On an abrupt kill (SIGKILL, crash, power
/// loss) the last small buffered chunk in the non-blocking channel may be
/// lost. That is acceptable for an observability log: continuous history
/// across the daemon's lifetime is the goal, not a guaranteed-flushed
/// dying breath.
static GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// Builds the daily-rolling file writer for the daemon log, plus its
/// `tracing-appender` worker guard.
///
/// Returns `None` (non-fatal) if the log directory cannot be created — the
/// daemon MUST still run without a file log rather than fail to start over
/// an observability-only feature.
pub fn make_writer(base_dir: &Path) -> Option<(NonBlocking, WorkerGuard)> {
    let dir = log_gc::daemon_log_dir(base_dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(
            error_kind = "daemon_log_dir_create",
            path = %dir.display(),
            "could not create daemon log directory: {e}"
        );
        return None;
    }
    let file_appender = tracing_appender::rolling::daily(&dir, LOG_FILE_PREFIX);
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    Some((non_blocking, guard))
}

/// Stashes `guard` in the process-lifetime [`GUARD`]. Idempotent — a second
/// call is a no-op (the first guard installed wins). Callers call this
/// exactly once, immediately after the subscriber owning the writer is
/// installed as the global default.
pub fn store_guard(guard: WorkerGuard) {
    let _ = GUARD.set(guard);
}
