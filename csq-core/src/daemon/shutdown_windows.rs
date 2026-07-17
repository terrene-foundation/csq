//! Windows graceful-stop channel: a named kernel event object.
//!
//! Unix daemons stop via `SIGTERM` — `stop_daemon` calls `libc::kill`,
//! the running daemon's `wait_for_shutdown()` selects on the signal, and
//! every subsystem drains on the shared `CancellationToken`. Windows has
//! no per-process `SIGTERM`: a detached, windowless daemon cannot receive
//! a console control event, and `TerminateProcess` is a hard kill that
//! skips the drain (leaving the named pipe, PID file, and in-flight token
//! refresh half-written).
//!
//! The graceful equivalent is a **named event object** (`CreateEventW` /
//! `SetEvent`). It is the canonical Windows IPC for "tell a windowless
//! process to shut down cleanly":
//!
//! 1. The daemon calls [`create_shutdown_event`] at startup, owning the
//!    manual-reset event, and blocks a thread on
//!    [`ShutdownEvent::wait_blocking`] (driven from async via
//!    `spawn_blocking`, so the run loop can `select!` it against Ctrl-C).
//! 2. `csq daemon stop` calls [`signal_shutdown`], which opens the same
//!    named event by name and calls `SetEvent`. The daemon's wait
//!    returns, its `CancellationToken` fires, and every subsystem drains
//!    exactly as it does on Unix.
//!
//! # Event name
//!
//! `Local\csq-daemon-shutdown-{username}` — the `{username}` suffix comes
//! from [`super::paths::windows_username`] (`GetUserNameW`, NOT
//! `%USERNAME%`) so the daemon and the `stop` side derive an identical
//! name AND a same-session process cannot poison the name by mutating the
//! `USERNAME` environment variable before the daemon starts (#786 redteam
//! H1 — parity with the named-pipe derivation in `paths.rs`).
//!
//! # Security model (parity with the Unix `0o600` socket — do NOT "harden" to `Global\`)
//!
//! The event's isolation matches the Unix graceful-stop threat model
//! ("only the same user may SIGTERM my daemon") on two independent axes,
//! and mirrors the named pipe's model (`server_windows.rs` §Security):
//!
//! - **`Local\` namespace** is per-**login-session**. A DIFFERENT user has
//!   a different logon session → a different `Local\` namespace → cannot
//!   open (let alone signal) this object at all. This is the correct
//!   default; `Global\` would be machine-wide and STRICTLY WIDER exposure —
//!   never switch to it.
//! - **Default DACL** (`CreateEventW` with NULL security attributes) grants
//!   the creating token's user SID (+SYSTEM) full access and nothing to
//!   other users — the object-level equivalent of the socket's `0o600`.
//!
//! A same-user (even lower-integrity) process CAN `SetEvent` this object,
//! but that triggers a GRACEFUL drain — strictly less dangerous than the
//! `TerminateProcess` it already could call, and exactly the Unix parity
//! (any same-uid process may `kill(SIGTERM)`; there is no integrity
//! sub-gate on either platform). This is accepted under csq's same-user
//! threat model (`security.md` Rule 7 posture, Rule 10 justification).
//!
//! # Why not a shutdown HTTP route
//!
//! Adding a `POST /api/shutdown` route would require threading a
//! `CancellationToken` through the cross-platform `RouterState` (13
//! construction sites, every one shared with Unix). The named event keeps
//! the graceful-stop mechanism entirely Windows-scoped and adds no field
//! to the shared IPC surface.

#![cfg(windows)]

use crate::error::DaemonError;
use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE, INFINITE,
};

/// `ERROR_FILE_NOT_FOUND` — `OpenEventW` against a name with no live object.
const ERROR_FILE_NOT_FOUND: i32 = 2;
/// `ERROR_ALREADY_EXISTS` — `CreateEventW` opened a pre-existing object.
const ERROR_ALREADY_EXISTS: i32 = 183;

/// Returns the shutdown event's fully-qualified name for the current user,
/// optionally namespaced by `scope` (empty in production; a per-process
/// suffix in tests so a test never fires a real daemon's event — #786
/// redteam MEDIUM test-isolation).
///
/// `Local\csq-daemon-shutdown-{username}{scope}` — `{username}` from
/// [`super::paths::windows_username`] (`GetUserNameW`), so the daemon and
/// the `stop` side derive an identical name and the value cannot be
/// poisoned via the `USERNAME` environment variable. Returned as a
/// NUL-terminated UTF-16 vector ready for `CreateEventW` / `OpenEventW`.
fn shutdown_event_name_wide(scope: &str) -> Vec<u16> {
    let username = super::paths::windows_username();
    let name = format!(r"Local\csq-daemon-shutdown-{username}{scope}");
    name.encode_utf16().chain(std::iter::once(0)).collect()
}

/// An owned, manual-reset shutdown event created by the running daemon.
///
/// Dropping the handle closes it (the kernel object is freed once the
/// daemon — the last holder — drops it). The daemon awaits it via
/// [`wait_blocking`](Self::wait_blocking).
///
/// windows-sys 0.52 declares `HANDLE` as `isize`, so `ShutdownEvent` is
/// automatically `Send + Sync` and can be moved into a `spawn_blocking`
/// closure without an explicit `unsafe impl`.
pub struct ShutdownEvent {
    handle: HANDLE,
}

impl ShutdownEvent {
    /// Blocks the calling thread until the event is signaled.
    ///
    /// Intended to run inside `tokio::task::spawn_blocking` so an async
    /// daemon loop can `select!` its completion against `ctrl_c()`.
    /// Returns once [`signal_shutdown`] (or any `SetEvent` on the same
    /// named object) fires, or immediately on a wait error (fail-open:
    /// a broken wait must not wedge shutdown forever).
    pub fn wait_blocking(&self) {
        // SAFETY: `self.handle` is a valid event handle owned by this
        // struct for the duration of the call. INFINITE waits until the
        // manual-reset event is signaled.
        let rc = unsafe { WaitForSingleObject(self.handle, INFINITE) };
        if rc != WAIT_OBJECT_0 {
            // WAIT_FAILED / abandoned — surface, but return so the caller
            // proceeds to drain rather than blocking forever.
            tracing::debug!(
                rc,
                "shutdown event wait returned non-signaled; proceeding to drain"
            );
        }
    }
}

impl Drop for ShutdownEvent {
    fn drop(&mut self) {
        // SAFETY: `self.handle` was returned by `CreateEventW` and is not
        // closed elsewhere — this is the sole owner.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Creates (or opens, if it already exists) the per-user shutdown event
/// and returns an owning handle.
///
/// Called once at daemon startup. The event is **manual-reset** and
/// initially non-signaled, so the daemon's `wait_blocking` blocks until
/// `stop` fires it. A manual-reset event stays signaled after the first
/// `SetEvent`, which is harmless here because the daemon exits on the
/// first wake.
pub fn create_shutdown_event() -> Result<ShutdownEvent, DaemonError> {
    create_shutdown_event_scoped("")
}

/// Scoped variant of [`create_shutdown_event`] for test isolation — see
/// [`shutdown_event_name_wide`]. Production always uses the empty scope via
/// [`create_shutdown_event`]; tests pass a per-process suffix so they never
/// create/fire the live daemon's event (#786 redteam MEDIUM).
#[doc(hidden)]
pub fn create_shutdown_event_scoped(scope: &str) -> Result<ShutdownEvent, DaemonError> {
    let name = shutdown_event_name_wide(scope);
    // SAFETY: `name` is a valid NUL-terminated wide string that outlives
    // the call. NULL security attributes → the process token's default
    // DACL (owning user only), matching the named pipe's DACL model.
    // manual_reset = 1 (TRUE), initial_state = 0 (non-signaled).
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) };
    // windows-sys `HANDLE` is `isize`; CreateEventW returns NULL (0) on
    // failure (not INVALID_HANDLE_VALUE), matching the OpenProcess/OpenEvent
    // convention used elsewhere in csq (accounts::login_lock).
    if handle == 0 {
        let err = io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0) as u32;
        tracing::debug!(error = %err, "CreateEventW for shutdown event failed");
        return Err(DaemonError::Win32 {
            code,
            context: "CreateEventW",
        });
    }
    // ERROR_ALREADY_EXISTS: the named object pre-existed and we got a handle
    // to it rather than a fresh one. `PidFile::acquire` already prevents a
    // second daemon, so in production this signals an anomaly (a same-user
    // process pre-created the object). Non-fatal — trace it (#786 redteam L1).
    if io::Error::last_os_error().raw_os_error() == Some(ERROR_ALREADY_EXISTS) {
        tracing::debug!(
            "shutdown event already existed at create — reusing (single-instance is PID-file-enforced)"
        );
    }
    Ok(ShutdownEvent { handle })
}

/// Signals the running daemon's shutdown event by name.
///
/// Opens the per-user event with `EVENT_MODIFY_STATE` and calls
/// `SetEvent`. Returns:
///
/// - `Ok(())` — the event was opened and set; the daemon's wait will
///   return and it will drain.
/// - `Err(DaemonError::StalePidFile { pid })` — the event does not exist
///   (`ERROR_FILE_NOT_FOUND`). The daemon PID is alive per the caller's
///   pre-check but has no shutdown event: treat like Unix `ESRCH` (the
///   process is not a csq daemon, or died between the liveness check and
///   here) so `stop_daemon` reports a stale/already-gone daemon rather
///   than hanging.
/// - `Err(DaemonError::Win32 { .. })` — the event exists but `OpenEventW` /
///   `SetEvent` failed (an exceptional kernel condition).
///
/// `pid` is threaded through only so the `StalePidFile` variant can carry
/// it; the signal itself is name-addressed, not PID-addressed (so it can
/// never mis-target a recycled PID, unlike the Unix `SIGTERM` path).
pub fn signal_shutdown(pid: u32) -> Result<(), DaemonError> {
    signal_shutdown_scoped("", pid)
}

/// Scoped variant of [`signal_shutdown`] for test isolation — see
/// [`shutdown_event_name_wide`]. Production always uses the empty scope via
/// [`signal_shutdown`] (#786 redteam MEDIUM).
#[doc(hidden)]
pub fn signal_shutdown_scoped(scope: &str, pid: u32) -> Result<(), DaemonError> {
    let name = shutdown_event_name_wide(scope);
    // SAFETY: `name` is a valid NUL-terminated wide string. `EVENT_MODIFY_STATE`
    // is the minimum access `SetEvent` needs.
    let handle = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    // NULL (0) return → the named event does not exist / access denied.
    if handle == 0 {
        let err = io::Error::last_os_error();
        // ERROR_FILE_NOT_FOUND (2): no such event — the daemon is not
        // listening (not a csq daemon, or already gone).
        if err.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) {
            return Err(DaemonError::StalePidFile { pid });
        }
        let code = err.raw_os_error().unwrap_or(0) as u32;
        tracing::debug!(error = %err, "OpenEventW for shutdown event failed");
        return Err(DaemonError::Win32 {
            code,
            context: "OpenEventW",
        });
    }

    // SAFETY: `handle` is a valid event handle we just opened; closed
    // below on every path.
    let set_ok = unsafe { SetEvent(handle) };
    // SAFETY: `handle` is valid and no longer used after this call.
    unsafe {
        CloseHandle(handle);
    }

    if set_ok == 0 {
        let err = io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0) as u32;
        tracing::debug!(error = %err, "SetEvent on shutdown event failed");
        return Err(DaemonError::Win32 {
            code,
            context: "SetEvent",
        });
    }
    Ok(())
}
