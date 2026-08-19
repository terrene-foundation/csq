//! csq daemon: background token refresher, usage pollers, and IPC server.
//!
//! # Subsystems
//!
//! A running daemon hosts:
//!
//! - `lifecycle` + `pid` + `paths` — single-instance lifecycle, PID file,
//!   OS-specific socket / pipe paths.
//! - `server` (unix) + `server_windows` (named-pipe) — axum IPC/HTTP router
//!   sharing one `RouterState` across both transports.
//! - `refresher` — per-identity OAuth token refresher (Anthropic + Codex).
//! - `usage_poller` — per-surface quota pollers (Anthropic, Codex, Gemini,
//!   3P bearers) writing to `quota.json`.
//! - `auto_rotate` — auto-rotation loop.
//! - `cache` — in-memory TTL cache shared across pollers.
//! - `startup_reconciler` — multi-pass on-disk reconciliation at boot.
//! - `identity_mint` — UUID minting for identity-keyed storage (an internal ticket).
//! - `migrate_legacy_api_key_helper` — one-shot legacy migration.
//! - `coc_cache_sweeper` — CC image-cache GC.
//! - `detect` + `client` (unix) + `client_windows` — CLI-side detection
//!   and IPC client.
//!
//! All subsystems share one `CancellationToken`; on SIGTERM the daemon
//! cancels, every subsystem drains, and the PID file is removed via
//! `PidFile`'s `Drop` impl.
//!
//! Operator-facing run modes (foreground / detached / launchd-systemd
//! service) live in `csq::cli::commands::daemon`. The Tauri-tray
//! in-process daemon lives in `csq::desktop::daemon_supervisor`.

/// M14 — Daemon tokio task for periodic external anchoring.
///
/// Spawns a background loop that fires [`crate::audit::anchor::anchor_head`]
/// on the configured cadence (default `1d`). High-impact M11 ops request an
/// immediate anchor via [`anchor_task::AnchorTaskHandle::request_immediate_anchor`].
pub mod anchor_task;
pub mod auto_rotate;
pub mod cache;
#[cfg(unix)]
pub mod client;
#[cfg(windows)]
pub mod client_windows;
pub mod coc_cache_sweeper;
pub mod custodian;
pub mod detect;
pub mod identity_mint;
pub mod lifecycle;
/// Daemon rolling-log GC (#1a-2, daemon-auth-resilience Wave A2) — 14-day
/// retention sweep over the persistent rolling file log written by the
/// `csq` crate's `daemon_log` module. Mirrors `coc_cache_sweeper`'s
/// spawn/tick idiom.
pub mod log_gc;
pub mod migrate_legacy_api_key_helper;
/// Cross-platform daemon notify chokepoint (an internal ticket) — `POST
/// /api/invalidate-cache` + the targeted `/api/slot-swap` per-slot
/// invalidation, on both the Unix socket and the Windows named pipe. The
/// single production home for the "tell the daemon its on-disk cache is
/// stale" notification; CLI command handlers call `notify::cache_invalidation`
/// / `notify::slot_swap` instead of inlining a per-platform copy.
pub mod notify;
pub mod paths;
pub mod pid;
pub mod refresher;
pub mod startup_reconciler;
/// Explicit-stop sentinel (an internal ticket) — makes `csq daemon stop` honest
/// while a desktop-app in-process supervisor is cohabiting with the
/// daemon. Read by [`supervise::run_forever`] before every re-acquire;
/// set by `csq daemon stop`; cleared by every daemon-start entry point.
pub mod stop_sentinel;
pub mod supervise;
pub mod usage_ledger_writer;
pub mod usage_poller;

// `server` contains the cross-platform router, RouterState, request
// handlers, and JSON types. The Unix-socket bind/accept loop inside
// it is gated on `#[cfg(unix)]` per-function. The Windows named-pipe
// listener (`server_windows`) imports `router` and `RouterState` from
// here so both transports share the same axum router definition.
pub mod server;
#[cfg(windows)]
pub mod server_windows;
/// Windows graceful-stop channel (an internal ticket) — a named kernel event object the
/// daemon awaits and `csq daemon stop` fires. The Windows equivalent of the
/// Unix `SIGTERM` path; keeps the drain semantics identical across platforms.
#[cfg(windows)]
pub mod shutdown_windows;

pub use anchor_task::{spawn as spawn_anchor_task, AnchorTaskHandle};
pub use auto_rotate::{spawn as spawn_auto_rotate, AutoRotateHandle};
pub use cache::{TtlCache, DEFAULT_MAX_AGE};
pub use coc_cache_sweeper::{
    spawn as spawn_coc_cache_sweeper, SweeperHandle as CocCacheSweeperHandle, SweeperSnapshot,
};
pub use detect::{detect_daemon, version_drift_reason, DetectResult, CLI_VERSION};
pub use lifecycle::{status_of, stop_daemon, DaemonStatus};
#[cfg(windows)]
pub use paths::pipe_name;
pub use paths::{pid_file_path, socket_path};
pub use pid::PidFile;
pub use refresher::{
    spawn as spawn_refresher, HttpPostFn, HttpPostFnCodex, RefreshStatus, RefresherHandle,
};
pub use startup_reconciler::{run_reconciler, ReconcileSummary};
pub use stop_sentinel::{clear_stop_requested, is_stop_requested, set_stop_requested};
pub use usage_ledger_writer::{
    spawn as spawn_usage_ledger_writer, WriterHandle as UsageLedgerWriterHandle,
};
pub use usage_poller::{spawn as spawn_usage_poller, HttpGetFn, HttpPostProbeFn, PollerHandle};

#[cfg(unix)]
pub use client::{
    http_get_unix, http_get_unix_with_timeout, http_post_unix, http_post_unix_json,
    http_post_unix_json_with_headers, notify_slot_swap, DaemonClientError, DaemonResponse,
    DEFAULT_TIMEOUT,
};
// Cross-platform router types.
pub use server::{router, HealthResponse, ServerHandle};
// Unix-only listener entry point.
#[cfg(unix)]
pub use server::serve;

#[cfg(windows)]
pub use client_windows::{
    http_get_pipe, http_get_pipe_with_timeout, http_post_pipe,
    DaemonClientError as DaemonClientErrorWindows, DaemonResponse as DaemonResponseWindows,
    DEFAULT_TIMEOUT as DEFAULT_TIMEOUT_WINDOWS,
};
#[cfg(windows)]
pub use server_windows::{serve as serve_windows, WindowsServerHandle};
#[cfg(windows)]
pub use shutdown_windows::{
    create_shutdown_event, create_shutdown_event_scoped, signal_shutdown, signal_shutdown_scoped,
    ShutdownEvent,
};
