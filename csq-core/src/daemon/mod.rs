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

pub mod auto_rotate;
pub mod cache;
#[cfg(unix)]
pub mod client;
#[cfg(windows)]
pub mod client_windows;
pub mod detect;
pub mod lifecycle;
pub mod paths;
pub mod pid;
pub mod refresher;
pub mod usage_poller;

// `server` contains the cross-platform router, RouterState, request
// handlers, and JSON types. The Unix-socket bind/accept loop inside
// it is gated on `#[cfg(unix)]` per-function. The Windows named-pipe
// listener (`server_windows`) imports `router` and `RouterState` from
// here so both transports share the same axum router definition.
pub mod server;
#[cfg(windows)]
pub mod server_windows;

pub use auto_rotate::{spawn as spawn_auto_rotate, AutoRotateHandle};
pub use cache::{TtlCache, DEFAULT_MAX_AGE};
pub use detect::{detect_daemon, DetectResult};
pub use lifecycle::{status_of, stop_daemon, DaemonStatus};
#[cfg(windows)]
pub use paths::pipe_name;
pub use paths::{pid_file_path, socket_path};
pub use pid::PidFile;
pub use refresher::{spawn as spawn_refresher, HttpPostFn, RefreshStatus, RefresherHandle};
pub use usage_poller::{spawn as spawn_usage_poller, HttpGetFn, HttpPostProbeFn, PollerHandle};

#[cfg(unix)]
pub use client::{
    http_get_unix, http_get_unix_with_timeout, http_post_unix, DaemonClientError, DaemonResponse,
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
