//! Desktop quit endpoint bound to a PID and its process creation time.

use crate::platform::fs_windows_acl::{object_owned_by_current_user, OwnerOnlyObjectSecurity};
use anyhow::{bail, Context, Result};
use std::time::Duration;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, FILETIME, HANDLE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::Threading::{
        CreateEventW, GetCurrentProcess, GetCurrentProcessId, GetProcessId, GetProcessTimes,
        OpenEventW, SetEvent, WaitForSingleObject, EVENT_MODIFY_STATE,
    },
    System::WindowsProgramming::GetUserNameW,
};

/// Owns the endpoint created by the current desktop process.
pub struct DesktopQuitEvent {
    handle: HANDLE,
}

pub(super) fn process_birth(process: HANDLE) -> Result<u64> {
    // SAFETY: caller supplies a live process handle with query rights (or the
    // current process pseudo-handle); all C output slots are initialized.
    let (mut birth, mut exit, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        unsafe { std::mem::zeroed() };
    // SAFETY: outputs and the borrowed process handle remain live for the call.
    if unsafe { GetProcessTimes(process, &mut birth, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot bind desktop quit event to process birth");
    }
    let creation = (u64::from(birth.dwHighDateTime) << 32) | u64::from(birth.dwLowDateTime);
    if creation == 0 {
        bail!("process creation time is unavailable for desktop quit event");
    }
    Ok(creation)
}

fn event_name(pid: u32, process: HANDLE) -> Result<Vec<u16>> {
    event_name_for("csq-upgrade-quit", pid, process)
}

fn event_name_for(prefix: &str, pid: u32, process: HANDLE) -> Result<Vec<u16>> {
    let creation = process_birth(process)?;
    // SAFETY: the process handle is live and supports process-ID queries.
    if pid == 0 || unsafe { GetProcessId(process) } != pid {
        bail!("desktop quit event PID does not match retained process handle");
    }
    Ok(format!(r"Local\{prefix}-{pid}-{creation:016x}")
        .encode_utf16()
        .chain(Some(0))
        .collect())
}

impl DesktopQuitEvent {
    pub fn create_current() -> Result<Self> {
        Self::create_named("csq-upgrade-quit")
    }

    fn create_named(prefix: &str) -> Result<Self> {
        // SAFETY: these APIs return current process identity without ownership transfer.
        let name = event_name_for(prefix, unsafe { GetCurrentProcessId() }, unsafe {
            GetCurrentProcess()
        })?;
        let security = OwnerOnlyObjectSecurity::current_user()?;
        let attributes = security.attributes();
        // SAFETY: descriptor, attributes and NUL-terminated name remain live.
        let raw = unsafe { CreateEventW(&attributes, 1, 0, name.as_ptr()) };
        if raw == 0 {
            return Err(std::io::Error::last_os_error())
                .context("cannot create owner-only desktop quit event");
        }
        // SAFETY: read before any subsequent Win32 call changes the last error.
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let event = Self { handle: raw };
        // An existing object's descriptor was not applied by CreateEventW.
        // Refuse it rather than trusting a pre-created endpoint or stale signal.
        if existed {
            bail!("desktop quit event already exists; refusing pre-created endpoint");
        }
        Ok(event)
    }

    pub fn wait_for_quit(&self, timeout: Duration) -> Result<bool> {
        let millis = timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32;
        // SAFETY: this event is owned by self throughout the bounded wait.
        match unsafe { WaitForSingleObject(self.handle, millis) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(std::io::Error::last_os_error()).context("desktop quit event wait failed"),
        }
    }
}

impl Drop for DesktopQuitEvent {
    fn drop(&mut self) {
        // SAFETY: self exclusively owns one successfully created event handle.
        if unsafe { CloseHandle(self.handle) } == 0 {
            tracing::warn!(
                error_kind = "desktop_quit_handle_close_failed",
                "desktop quit event close failed"
            );
        }
    }
}

fn open_checked(name: &[u16], pid: u32, modify: bool) -> Result<Option<DesktopQuitEvent>> {
    const READ_CONTROL: u32 = 0x0002_0000;
    // SAFETY: name is NUL terminated and remains live; handle is not inherited.
    let access = READ_CONTROL | if modify { EVENT_MODIFY_STATE } else { 0 };
    let raw = unsafe { OpenEventW(access, 0, name.as_ptr()) };
    if raw == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            return Ok(None);
        }
        return Err(error).with_context(|| format!("cannot open desktop quit event for PID {pid}"));
    }
    let event = DesktopQuitEvent { handle: raw };
    if !object_owned_by_current_user(event.handle)? {
        bail!("desktop quit event for PID {pid} has a foreign owner");
    }
    Ok(Some(event))
}

/// Read-only preflight: absence is a legacy endpoint, never an exit proof.
pub fn desktop_quit_available(pid: u32, process_handle: HANDLE) -> Result<bool> {
    Ok(open_checked(&event_name(pid, process_handle)?, pid, false)?.is_some())
}

/// Signals only the endpoint for the retained process's exact birth identity.
/// `false` means the endpoint is absent (old version), never that it has exited.
pub fn signal_desktop_quit(pid: u32, process_handle: HANDLE) -> Result<bool> {
    let Some(event) = open_checked(&event_name(pid, process_handle)?, pid, true)? else {
        return Ok(false);
    };
    // SAFETY: this is the owner-checked event opened for the exact retained birth.
    if unsafe { SetEvent(event.handle) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot signal desktop quit event for PID {pid}"));
    }
    Ok(true)
}

fn legacy_daemon_event(pid: u32) -> Result<Option<DesktopQuitEvent>> {
    let mut user = vec![0u16; 257];
    let mut size = user.len() as u32;
    // SAFETY: output covers the supplied length. There is no environment fallback.
    if unsafe { GetUserNameW(user.as_mut_ptr(), &mut size) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("cannot identify legacy daemon event user");
    }
    if size < 2 || size as usize > user.len() || user[size as usize - 1] != 0 {
        bail!("invalid legacy daemon event username");
    }
    let user = String::from_utf16(&user[..size as usize - 1])
        .context("legacy daemon event username is not UTF-16")?;
    if user.contains('\0') {
        bail!("invalid legacy daemon event username terminator");
    }
    let name: Vec<u16> = format!(r"Local\csq-daemon-shutdown-{user}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    open_checked(&name, pid, false)
}

/// Presence probe only; never grants authority to stop an old host.
pub(super) fn legacy_event_exists() -> Result<bool> {
    Ok(legacy_daemon_event(0)?.is_some())
}

/// Bound normal daemon-stop endpoint, separate from the desktop app-quit event.
pub struct DaemonStopEvent(DesktopQuitEvent);
impl DaemonStopEvent {
    pub fn create_current() -> Result<Self> {
        DesktopQuitEvent::create_named("csq-daemon-stop").map(Self)
    }
    pub fn wait_for_quit(&self, timeout: Duration) -> Result<bool> {
        self.0.wait_for_quit(timeout)
    }
}

pub fn signal_daemon_stop(pid: u32, process: HANDLE) -> Result<bool> {
    let name = event_name_for("csq-daemon-stop", pid, process)?;
    let Some(event) = open_checked(&name, pid, true)? else {
        return Ok(false);
    };
    // SAFETY: owner-checked event is bound to the retained process's PID and birth.
    if unsafe { SetEvent(event.handle) } == 0 {
        return Err(std::io::Error::last_os_error()).context("bound daemon stop signal failed");
    }
    Ok(true)
}
