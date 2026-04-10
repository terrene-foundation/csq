//! Process detection — check if a PID is alive, find the Claude Code
//! process in the parent chain, and identify CC by command name.

use crate::error::PlatformError;

/// Maximum depth when walking the parent process tree.
const MAX_PARENT_DEPTH: usize = 20;

/// Checks whether a process with the given PID is alive.
pub fn is_pid_alive(pid: u32) -> bool {
    imp::is_pid_alive(pid)
}

/// Walks the parent process tree from the current process up to
/// [`MAX_PARENT_DEPTH`] levels, looking for a Claude Code process.
///
/// Returns the PID of the first ancestor whose command matches
/// [`is_cc_command`], or `None` if no CC process is found.
pub fn find_cc_pid() -> Result<Option<u32>, PlatformError> {
    imp::find_cc_pid()
}

/// Returns `true` if `cmd` looks like a Claude Code binary invocation.
///
/// Matches the binary name (not arguments) against known CC patterns:
/// - `claude` (the binary itself)
/// - paths ending in `/claude` or `\claude`
/// - `node` running a path containing `claude` (the npm-installed form)
pub fn is_cc_command(cmd: &str) -> bool {
    let cmd_lower = cmd.to_lowercase();

    // Direct binary match
    if cmd_lower == "claude" {
        return true;
    }

    // Path ending in /claude or \claude (with optional .exe)
    let stripped = cmd_lower.trim_end_matches(".exe");
    if stripped.ends_with("/claude") || stripped.ends_with("\\claude") {
        return true;
    }

    // Node running claude (npm global install form):
    // "node /usr/local/bin/claude" or "node /path/to/@anthropic-ai/claude-code/..."
    if cmd_lower.starts_with("node ") || cmd_lower.starts_with("node.exe ") {
        let rest = cmd_lower.split_once(' ').map(|(_, r)| r).unwrap_or("");
        if rest.contains("claude") {
            return true;
        }
    }

    false
}

// ── Unix implementation ───────────────────────────────────────────────

#[cfg(unix)]
mod imp {
    use super::*;

    pub fn is_pid_alive(pid: u32) -> bool {
        // kill(pid, 0) checks existence without sending a signal.
        // Returns 0 if the process exists and we have permission to signal it.
        // Returns -1 with ESRCH if the process does not exist.
        // Returns -1 with EPERM if the process exists but we lack permission.
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc == 0 {
            return true;
        }
        // EPERM means the process exists but we can't signal it
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    pub fn find_cc_pid() -> Result<Option<u32>, PlatformError> {
        let mut pid = std::process::id();

        for _ in 0..MAX_PARENT_DEPTH {
            let (ppid, cmd) = match get_process_info(pid) {
                Some(info) => info,
                None => return Ok(None),
            };

            if is_cc_command(&cmd) {
                return Ok(Some(pid));
            }

            if ppid == 0 || ppid == 1 || ppid == pid {
                // Reached init or a cycle
                return Ok(None);
            }
            pid = ppid;
        }

        Ok(None)
    }

    /// Returns `(parent_pid, command_line)` for the given PID.
    fn get_process_info(pid: u32) -> Option<(u32, String)> {
        #[cfg(target_os = "linux")]
        {
            get_process_info_linux(pid)
        }
        #[cfg(target_os = "macos")]
        {
            get_process_info_macos(pid)
        }
    }

    #[cfg(target_os = "linux")]
    fn get_process_info_linux(pid: u32) -> Option<(u32, String)> {
        // Read /proc/{pid}/status for PPid
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let ppid = status
            .lines()
            .find(|l| l.starts_with("PPid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u32>().ok())?;

        // Read /proc/{pid}/cmdline for the command
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let cmd = String::from_utf8_lossy(&cmdline)
            .replace('\0', " ")
            .trim()
            .to_string();

        Some((ppid, cmd))
    }

    #[cfg(target_os = "macos")]
    fn get_process_info_macos(pid: u32) -> Option<(u32, String)> {
        // Use `ps` to get parent PID and command name. This is reliable
        // across all macOS versions and avoids unstable libc struct layouts.
        let output = std::process::Command::new("ps")
            .args(["-o", "ppid=,comm=", "-p", &pid.to_string()])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let line = String::from_utf8_lossy(&output.stdout);
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        // Output format: "  1234 /usr/local/bin/claude"
        let mut parts = line.splitn(2, char::is_whitespace);
        let ppid = parts.next()?.trim().parse::<u32>().ok()?;
        let cmd = parts.next()?.trim().to_string();

        Some((ppid, cmd))
    }
}

// ── Windows implementation ────────────────────────────────────────────

#[cfg(windows)]
mod imp {
    use super::*;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const STILL_ACTIVE: u32 = 259;
    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const INVALID_HANDLE_VALUE: *mut std::ffi::c_void = -1isize as *mut _;

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; 260],
    }

    extern "system" {
        fn OpenProcess(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            dwProcessId: u32,
        ) -> *mut std::ffi::c_void;
        fn GetExitCodeProcess(
            hProcess: *mut std::ffi::c_void,
            lpExitCode: *mut u32,
        ) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn CreateToolhelp32Snapshot(
            dwFlags: u32,
            th32ProcessID: u32,
        ) -> *mut std::ffi::c_void;
        fn Process32FirstW(
            hSnapshot: *mut std::ffi::c_void,
            lppe: *mut ProcessEntry32W,
        ) -> i32;
        fn Process32NextW(
            hSnapshot: *mut std::ffi::c_void,
            lppe: *mut ProcessEntry32W,
        ) -> i32;
    }

    pub fn is_pid_alive(pid: u32) -> bool {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        unsafe { CloseHandle(handle) };
        ok != 0 && exit_code == STILL_ACTIVE
    }

    pub fn find_cc_pid() -> Result<Option<u32>, PlatformError> {
        // Build PID → (parent_pid, exe_name) map from a process snapshot
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(PlatformError::Win32 {
                code: 0,
                message: "CreateToolhelp32Snapshot failed".into(),
            });
        }

        let mut entries = std::collections::HashMap::new();
        let mut entry: ProcessEntry32W = unsafe { std::mem::zeroed() };
        entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;

        if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
            loop {
                let exe = String::from_utf16_lossy(
                    &entry.sz_exe_file[..entry
                        .sz_exe_file
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(260)],
                );
                entries.insert(
                    entry.th32_process_id,
                    (entry.th32_parent_process_id, exe),
                );

                entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
                if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }
        unsafe { CloseHandle(snapshot) };

        // Walk parent chain from current PID
        let mut pid = std::process::id();
        for _ in 0..MAX_PARENT_DEPTH {
            let (ppid, exe) = match entries.get(&pid) {
                Some(e) => e.clone(),
                None => return Ok(None),
            };
            if is_cc_command(&exe) {
                return Ok(Some(pid));
            }
            if ppid == 0 || ppid == pid {
                return Ok(None);
            }
            pid = ppid;
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_pid_is_alive() {
        assert!(is_pid_alive(std::process::id()));
    }

    #[test]
    fn bogus_pid_is_dead() {
        // PID 99999999 is extremely unlikely to exist
        assert!(!is_pid_alive(99_999_999));
    }

    #[test]
    fn is_cc_command_matches_claude() {
        assert!(is_cc_command("claude"));
        assert!(is_cc_command("Claude"));
        assert!(is_cc_command("/usr/local/bin/claude"));
        assert!(is_cc_command("C:\\Program Files\\claude.exe"));
        assert!(is_cc_command("node /usr/local/bin/claude"));
        assert!(is_cc_command("node /home/user/.nvm/versions/node/v20/bin/claude"));
        assert!(is_cc_command("node /path/to/@anthropic-ai/claude-code/cli.js"));
    }

    #[test]
    fn is_cc_command_rejects_non_claude() {
        assert!(!is_cc_command("/bin/bash"));
        assert!(!is_cc_command("vim"));
        assert!(!is_cc_command("python3 script.py"));
        assert!(!is_cc_command(""));
    }

    #[test]
    fn find_cc_pid_does_not_error() {
        // find_cc_pid may return Some (if running under Claude Code)
        // or None (if running standalone). Either is valid — we just
        // verify it doesn't error.
        let result = find_cc_pid().unwrap();
        if let Some(pid) = result {
            assert!(is_pid_alive(pid), "returned CC PID should be alive");
        }
    }
}
