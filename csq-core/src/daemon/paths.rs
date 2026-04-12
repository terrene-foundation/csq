//! Platform-specific paths for the daemon PID file and IPC socket.
//!
//! Resolution rules per GAP-9 / ADR-005:
//!
//! | Platform | PID file                                    | Socket                                           |
//! | -------- | ------------------------------------------- | ------------------------------------------------ |
//! | macOS    | `{base_dir}/csq-daemon.pid`                 | `{base_dir}/csq.sock`                            |
//! | Linux    | `$XDG_RUNTIME_DIR/csq-daemon.pid` else base | `$XDG_RUNTIME_DIR/csq.sock` else `/tmp/csq-{uid}.sock` |
//! | Windows  | `%LOCALAPPDATA%\csq\csq-daemon.pid`         | `\\.\pipe\csq-{username}`                        |
//!
//! The `base_dir` fallback for Linux means a box without
//! `$XDG_RUNTIME_DIR` (non-systemd, non-desktop) still gets a working
//! daemon under `~/.claude/accounts/` — same place as macOS. The `/tmp`
//! socket fallback is for Linux only because macOS `tmp` paths collide
//! with 104-byte sun_path length limits.

use std::path::{Path, PathBuf};

/// Returns the PID file path for the daemon, given the csq base directory
/// (`~/.claude/accounts` on a default install).
///
/// On Linux, prefers `$XDG_RUNTIME_DIR` (typically `/run/user/{uid}`)
/// because that directory is tmpfs, single-user, and cleared on logout
/// — exactly what we want for a per-user daemon PID file. Falls back
/// to `base_dir` if the env var is unset or empty.
///
/// On macOS, always uses `base_dir` (macOS has no equivalent concept,
/// and `/var/run` requires root).
///
/// On Windows, uses `%LOCALAPPDATA%\csq\` (typically
/// `C:\Users\{user}\AppData\Local\csq\`). Falls back to `base_dir` if
/// `LOCALAPPDATA` is unset.
pub fn pid_file_path(base_dir: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = xdg_runtime_dir() {
            return dir.join("csq-daemon.pid");
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = local_app_data() {
            return dir.join("csq").join("csq-daemon.pid");
        }
    }
    base_dir.join("csq-daemon.pid")
}

/// Returns the IPC socket path (or Windows named-pipe path) for the
/// daemon.
///
/// Linux prefers `$XDG_RUNTIME_DIR/csq.sock`, falling back to
/// `/tmp/csq-{uid}.sock` — note the Linux fallback is `/tmp`, not
/// `base_dir`, because `base_dir` on a typical install is deep enough
/// (`/home/user/.claude/accounts/csq.sock`) to be near the
/// platform-dependent 108-byte `sun_path` limit on Linux. `/tmp`
/// keeps the path short and still per-user via the uid suffix.
///
/// macOS uses `{base_dir}/csq.sock`. sun_path on macOS is 104 bytes
/// but the default `base_dir` (`~/.claude/accounts`) fits comfortably
/// for typical home paths.
///
/// Windows returns a named-pipe path `\\.\pipe\csq-{username}`.
/// The username suffix ensures per-user isolation on multi-user boxes.
pub fn socket_path(base_dir: &Path) -> PathBuf {
    // base_dir is used on macOS and unknown-Unix only; suppress
    // unused-variable warnings on Linux and Windows.
    let _ = &base_dir;

    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = xdg_runtime_dir() {
            return dir.join("csq.sock");
        }
        // /tmp fallback with uid suffix.
        let uid = unsafe { libc::getuid() };
        PathBuf::from(format!("/tmp/csq-{uid}.sock"))
    }
    #[cfg(target_os = "macos")]
    {
        base_dir.join("csq.sock")
    }
    #[cfg(target_os = "windows")]
    {
        let username = windows_username();
        PathBuf::from(format!(r"\\.\pipe\csq-{username}"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // Unknown Unix: fall back to base_dir.
        base_dir.join("csq.sock")
    }
}

#[cfg(target_os = "linux")]
fn xdg_runtime_dir() -> Option<PathBuf> {
    match std::env::var("XDG_RUNTIME_DIR") {
        Ok(s) if !s.is_empty() => Some(PathBuf::from(s)),
        _ => None,
    }
}

/// Returns the Windows username via `GetUserNameW` — the authoritative
/// source. Falls back to `%USERNAME%` if the syscall fails (which would
/// mean the process token is broken, an exceptional condition).
///
/// Using `GetUserNameW` instead of `std::env::var("USERNAME")` prevents
/// a same-session process from poisoning the pipe name by mutating the
/// environment variable before the daemon starts.
#[cfg(target_os = "windows")]
fn windows_username() -> String {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // GetUserNameW fills a buffer with the username + NUL.
    // First call with size 0 to get the required buffer length.
    let mut size: u32 = 0;
    unsafe {
        windows_sys::Win32::System::WindowsProgramming::GetUserNameW(
            std::ptr::null_mut(),
            &mut size,
        );
    }
    if size == 0 {
        return std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    }
    let mut buf: Vec<u16> = vec![0u16; size as usize];
    let ok = unsafe {
        windows_sys::Win32::System::WindowsProgramming::GetUserNameW(buf.as_mut_ptr(), &mut size)
    };
    if ok == 0 {
        return std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    }
    // size now includes the NUL terminator; strip it.
    let len = (size as usize).saturating_sub(1);
    OsString::from_wide(&buf[..len])
        .to_string_lossy()
        .into_owned()
}

#[cfg(target_os = "windows")]
fn local_app_data() -> Option<PathBuf> {
    match std::env::var("LOCALAPPDATA") {
        Ok(s) if !s.is_empty() => Some(PathBuf::from(s)),
        _ => None,
    }
}

/// Returns the Windows named-pipe name for the daemon.
///
/// This is a typed alias for [`socket_path`] that makes Windows-specific
/// call sites self-documenting. On Windows, `socket_path` already returns
/// a named-pipe path; this function makes the intent explicit.
///
/// # Example
///
/// ```ignore
/// let name = pipe_name(base_dir).to_string_lossy().into_owned();
/// // name == r"\\.\pipe\csq-alice"
/// ```
#[cfg(target_os = "windows")]
pub fn pipe_name(base_dir: &Path) -> PathBuf {
    socket_path(base_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pid_file_path_includes_filename() {
        let base = Path::new("/tmp/test-base");
        let p = pid_file_path(base);
        assert!(p.ends_with("csq-daemon.pid"));
    }

    #[test]
    fn socket_path_is_non_empty() {
        let base = Path::new("/tmp/test-base");
        let s = socket_path(base);
        assert!(!s.as_os_str().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_paths_under_base_dir() {
        let base = Path::new("/tmp/test-base");
        assert_eq!(pid_file_path(base), base.join("csq-daemon.pid"));
        assert_eq!(socket_path(base), base.join("csq.sock"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_prefers_xdg_runtime_dir() {
        // Save + restore env to avoid poisoning other tests.
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        // SAFETY: tests are single-threaded for env var access; we
        // restore on the way out.
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");

        let base = Path::new("/tmp/test-base");
        assert_eq!(
            pid_file_path(base),
            PathBuf::from("/run/user/1000/csq-daemon.pid")
        );
        assert_eq!(socket_path(base), PathBuf::from("/run/user/1000/csq.sock"));

        match saved {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_pipe_name_format() {
        let base = Path::new(r"C:\Users\testuser\AppData\Local\csq");
        // Override USERNAME so the test is deterministic.
        std::env::set_var("USERNAME", "testuser");
        let p = pipe_name(base);
        let s = p.to_string_lossy();
        assert!(s.starts_with(r"\\.\pipe\csq-"), "unexpected pipe name: {s}");
        assert!(
            s.contains("testuser"),
            "pipe name should contain username: {s}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_socket_path_is_pipe() {
        let base = Path::new(r"C:\Users\testuser\AppData\Local\csq");
        std::env::set_var("USERNAME", "winuser");
        let p = socket_path(base);
        let s = p.to_string_lossy();
        assert!(
            s.starts_with(r"\\.\pipe\"),
            "Windows socket_path should be a named pipe: {s}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_falls_back_without_xdg_runtime_dir() {
        let saved = std::env::var("XDG_RUNTIME_DIR").ok();
        std::env::remove_var("XDG_RUNTIME_DIR");

        let base = Path::new("/tmp/test-base");
        assert_eq!(pid_file_path(base), base.join("csq-daemon.pid"));
        // Socket falls back to /tmp, not base.
        let sock = socket_path(base);
        assert!(sock.to_string_lossy().starts_with("/tmp/csq-"));
        assert!(sock.extension().unwrap_or_default() == "sock");

        if let Some(v) = saved {
            std::env::set_var("XDG_RUNTIME_DIR", v);
        }
    }
}
