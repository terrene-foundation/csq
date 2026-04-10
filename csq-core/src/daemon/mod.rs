//! csq daemon: background token refresher, usage poller, and IPC server.
//!
//! # M8 scope
//!
//! This module is built incrementally across several PRs:
//!
//! - **M8.2 (this slice)** — lifecycle primitives: PID file, single-
//!   instance guard, platform paths per GAP-9, foreground-only
//!   `start/stop/status`. No IPC server yet.
//! - **M8.3** — Unix socket server, minimal HTTP health endpoint, and
//!   the 4-step client-side detection protocol.
//! - **M8.4** — in-memory TTL cache, per-account background refresher
//!   (using `crate::http::post_form`), Anthropic and 3P usage pollers.
//! - **M8.5** — full axum API routes, OAuth PKCE callback handler,
//!   graceful shutdown with in-flight deadline.
//! - **M8.6** — CLI delegation (status/statusline/swap), Windows
//!   named pipe, full integration test suite.
//!
//! Read `workspaces/csq-v2/todos/active/M8-daemon-core.md` for the
//! full task breakdown.

pub mod detect;
pub mod lifecycle;
pub mod paths;
pub mod pid;

#[cfg(unix)]
pub mod server;

pub use detect::{detect_daemon, DetectResult};
pub use lifecycle::{status_of, stop_daemon, DaemonStatus};
pub use paths::{pid_file_path, socket_path};
pub use pid::PidFile;

#[cfg(unix)]
pub use server::{router, serve, HealthResponse, ServerHandle};
