//! Windows graceful daemon stop, retaining process identity through completion.
//!
//! Production first signals the owner-checked PID/birth-bound event. If an old
//! daemon has no bound event, it verifies the PID-file target against the exact
//! current installed csq image, captures birth from its retained process handle,
//! checks same-user ownership, then signals the owner-checked per-user event.
//! Legacy fallback proves retained-handle exit within the shared drain policy
//! plus observation margin. An observer timeout refuses; it never kills a
//! process or cancels admitted credential work. Bound stop behavior is unchanged.
//!
//! Any same-user csq daemon may own the legacy user event,
//! because every same-user daemon is an upgrade stop target; a squatting non-csq
//! listener gains no authority from a graceful signal. Event presence alone is
//! never authority: image, owner, PID and birth verification precede the open.
//!
//! Events remain in the login-session Local namespace. Names derive usernames
//! from GetUserNameW, not environment variables; event opens verify object owner.
//! Native fixtures inject only isolated -test- scopes into the production path.
//! A non-csq PID is stale; unavailable identity fails closed before any signal.
//! CloseHandle failures are logged independently and cannot undo SetEvent.

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
/// suffix in tests so a test never fires a real daemon's event — an internal ticket
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
/// create/fire the live daemon's event (an internal ticket redteam MEDIUM).
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
    // process pre-created the object). Non-fatal — trace it (an internal ticket redteam L1).
    if io::Error::last_os_error().raw_os_error() == Some(ERROR_ALREADY_EXISTS) {
        tracing::debug!(
            "shutdown event already existed at create — reusing (single-instance is PID-file-enforced)"
        );
    }
    Ok(ShutdownEvent { handle })
}

/// Requests a bound stop or a verified legacy stop with retained exit proof.
///
/// Verified exit or a different executable returns `StalePidFile`. A live csq
/// image without a bound endpoint uses the owner-checked legacy event only
/// after same-user and exact selected-image verification. Legacy success also
/// requires exit of the retained process; unavailable or unverified channels
/// return typed refusal, and deadline expiry never authorizes force-stop.
pub fn signal_shutdown(pid: u32) -> Result<(), DaemonError> {
    let image = std::env::current_exe().map_err(|_| DaemonError::ShutdownUnverified { pid })?;
    let budget = crate::update::upgrade_guard::shutdown_observer_budget()
        .map_err(|_| DaemonError::ShutdownUnverified { pid })?;
    signal_shutdown_selected(pid, &[image], "", budget)
}

fn signal_shutdown_selected(
    pid: u32,
    installed: &[std::path::PathBuf],
    scope: &str,
    budget: std::time::Duration,
) -> Result<(), DaemonError> {
    signal_shutdown_selected_with_verifier(
        pid,
        installed,
        scope,
        budget,
        crate::update::upgrade_guard::windows::verify_sole_cli_legacy_daemon,
    )
}

// Transport/clock/wait are identical for native scoped fixtures. Only the
// census source is injected; production always chooses the whole-host verifier.
fn signal_shutdown_selected_with_verifier(
    pid: u32,
    installed: &[std::path::PathBuf],
    scope: &str,
    budget: std::time::Duration,
    verify_sole: impl FnOnce(HANDLE, u32, &[std::path::PathBuf]) -> anyhow::Result<bool>,
) -> Result<(), DaemonError> {
    let started = std::time::Instant::now();
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };
    // SAFETY: query/synchronize only; no signal or termination authority.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if process == 0 {
        let code = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return Err(if code == ERROR_INVALID_PARAMETER {
            DaemonError::StalePidFile { pid }
        } else {
            DaemonError::Win32 {
                code,
                context: "OpenProcess(daemon stop)",
            }
        });
    }
    struct Process(HANDLE);
    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: sole owner of the successfully opened process handle.
            if unsafe { CloseHandle(self.0) } == 0 {
                tracing::warn!(
                    error_kind = "daemon_stop_process_close_failed",
                    "daemon stop handle close failed"
                );
            }
        }
    }
    let process = Process(process);
    let live = || -> Result<(), DaemonError> {
        // SAFETY: retained query/synchronize handle; zero wait never blocks.
        match unsafe { WaitForSingleObject(process.0, 0) } {
            WAIT_OBJECT_0 => Err(DaemonError::StalePidFile { pid }),
            WAIT_TIMEOUT => Ok(()),
            _ => Err(DaemonError::Win32 {
                code: io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
                context: "WaitForSingleObject(daemon stop)",
            }),
        }
    };
    live()?;
    match crate::update::upgrade_guard::quit_event::signal_daemon_stop(pid, process.0) {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) => {
            live()?;
            return Err(
                match error
                    .downcast_ref::<io::Error>()
                    .and_then(io::Error::raw_os_error)
                {
                    Some(code) => DaemonError::Win32 {
                        code: code as u32,
                        context: "bound daemon stop event",
                    },
                    None => DaemonError::ShutdownUnverified { pid },
                },
            );
        }
    }
    live()?;
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    // SAFETY: writable image buffer covers the declared capacity; process retained.
    if unsafe { QueryFullProcessImageNameW(process.0, 0, image.as_mut_ptr(), &mut length) } == 0 {
        let code = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        live()?;
        return Err(DaemonError::Win32 {
            code,
            context: "QueryFullProcessImageNameW(daemon stop)",
        });
    }
    if length == 0 || length as usize >= image.len() {
        return Err(DaemonError::ShutdownUnverified { pid });
    }
    let image = String::from_utf16(&image[..length as usize])
        .map_err(|_| DaemonError::ShutdownUnverified { pid })?;
    let name = image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if !(name == "csq.exe" || name.starts_with("csq-") || name.starts_with("csq_")) {
        return Err(DaemonError::StalePidFile { pid });
    }
    live()?;
    // Ordinary stop names one daemon, unlike the installer's all-daemon
    // authority. A non-daemon PID is stale; collateral candidates refuse before
    // opening/signalling the legacy event. The retained target is rechecked.
    match verify_sole(process.0, pid, installed) {
        Ok(false) => return Err(DaemonError::StalePidFile { pid }),
        Ok(true) => {}
        Err(_) => {
            live()?;
            return Err(DaemonError::LegacyShutdownRefused { pid, reason: "sole live same-user daemon role/identity/session cannot be proved; zero legacy signals sent" });
        }
    }
    live()?;
    if started.elapsed() >= budget {
        return Err(DaemonError::LegacyShutdownTimeout {
            pid,
            timeout_ms: budget.as_millis().min(u128::from(u64::MAX)) as u64,
        });
    }
    signal_legacy_for_retained(pid, process.0, installed, scope)?;
    // Bound stops above retain their existing request-only behavior. Legacy
    // fallback additionally proves this exact process exited within the shared
    // observer policy; expiry never kills or cancels admitted credential work.
    let millis = budget
        .saturating_sub(started.elapsed())
        .as_millis()
        .min(u128::from(u32::MAX - 1)) as u32;
    // SAFETY: process retains SYNCHRONIZE access through this finite wait.
    match unsafe { WaitForSingleObject(process.0, millis) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(DaemonError::LegacyShutdownTimeout {
            pid,
            timeout_ms: budget.as_millis().min(u128::from(u64::MAX)) as u64,
        }),
        _ => Err(DaemonError::Win32 {
            code: io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
            context: "WaitForSingleObject(legacy daemon stop)",
        }),
    }
}

/// Request only: the caller retains the process and owns exit/deadline proof.
/// An owner-checked legacy user event is permitted after exact
/// selected-image, same-user, PID/birth verification. Its listener may be any
/// same-user csq daemon: all such daemons are upgrade stop targets. A squatting
/// non-csq listener gains no authority from this graceful signal. Never kill.
pub(crate) fn signal_legacy_for_retained(
    pid: u32,
    process: HANDLE,
    installed: &[std::path::PathBuf],
    scope: &str,
) -> Result<(), DaemonError> {
    crate::update::upgrade_guard::windows::verify_legacy_stop_target(process, pid, installed)
        .map_err(|_| DaemonError::LegacyShutdownRefused { pid, reason: "PID-file target owner, birth or exact installed csq image could not be verified; zero legacy signals sent" })?;
    let name = shutdown_event_name_wide(scope);
    const READ_CONTROL: u32 = 0x0002_0000;
    // SAFETY: NUL-terminated name; request only query-owner and event-set rights.
    let event = unsafe { OpenEventW(READ_CONTROL | EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    if event == 0 {
        let code = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return Err(if code == ERROR_FILE_NOT_FOUND as u32 {
            DaemonError::ShutdownUnavailable { pid }
        } else {
            DaemonError::Win32 {
                code,
                context: "OpenEventW(legacy daemon stop)",
            }
        });
    }
    struct Event(HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: sole owner of the opened event; close cannot undo SetEvent.
            if unsafe { CloseHandle(self.0) } == 0 {
                tracing::warn!(
                    error_kind = "legacy_stop_event_close_failed",
                    "legacy stop event close failed"
                );
            }
        }
    }
    let event = Event(event);
    if !crate::platform::fs_windows_acl::object_owned_by_current_user(event.0)
        .map_err(|_| DaemonError::ShutdownUnverified { pid })?
    {
        return Err(DaemonError::LegacyShutdownRefused {
            pid,
            reason: "legacy event is owned by another Windows account; zero signals sent",
        });
    }
    // SAFETY: owner-checked event; selected process identity was retained above.
    if unsafe { SetEvent(event.0) } == 0 {
        return Err(DaemonError::Win32 {
            code: io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32,
            context: "SetEvent(legacy daemon stop)",
        });
    }
    Ok(())
}

/// Native fixture DI: same identity/policy/signal/wait path, scoped event and
/// explicitly owned fixture census. Production never uses this entry point.
#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
pub fn signal_shutdown_scoped_for_test(
    pid: u32,
    installed: &[std::path::PathBuf],
    scope: &str,
    budget: std::time::Duration,
    owned_fixture_pids: &[u32],
) -> Result<(), DaemonError> {
    if !scope.starts_with("-test-") || !owned_fixture_pids.contains(&pid) {
        return Err(DaemonError::ShutdownUnverified { pid });
    }
    signal_shutdown_selected_with_verifier(
        pid,
        installed,
        scope,
        budget,
        |process, pid, installed| {
            crate::update::upgrade_guard::windows::verify_sole_cli_legacy_daemon_scoped(
                process,
                pid,
                installed,
                owned_fixture_pids,
            )
        },
    )
}

/// Legacy name-addressed signal utility for isolated compatibility tests.
/// Production `signal_shutdown` never calls this unbound path.
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
    let set_error = if set_ok == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    // SAFETY: `handle` is valid and no longer used after this call.
    unsafe {
        CloseHandle(handle);
    }

    if let Some(err) = set_error {
        let code = err.raw_os_error().unwrap_or(0) as u32;
        tracing::debug!(error = %err, "SetEvent on shutdown event failed");
        return Err(DaemonError::Win32 {
            code,
            context: "SetEvent",
        });
    }
    Ok(())
}
