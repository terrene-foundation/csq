//! Windows backend for live CC session discovery.
//!
//! Enumerates running processes via the Toolhelp32 snapshot API,
//! filters to `claude.exe`, then walks each target's Process
//! Environment Block (PEB) to extract the environment variables
//! and current working directory. Returns one `SessionInfo` per
//! matching process.
//!
//! ### Why PEB walking is necessary
//!
//! Windows has no equivalent to `/proc/<pid>/environ` or `ps -E`.
//! The only documented way to read another process's environment
//! is:
//!
//! 1. `OpenProcess` with `PROCESS_QUERY_INFORMATION |
//!     PROCESS_VM_READ` rights.
//! 2. `NtQueryInformationProcess(ProcessBasicInformation)` to get
//!    the PEB address inside the target's virtual address space.
//! 3. `ReadProcessMemory` the `PEB` struct to find the
//!    `ProcessParameters` pointer.
//! 4. `ReadProcessMemory` the `RTL_USER_PROCESS_PARAMETERS` struct
//!    to find the `Environment` pointer and `EnvironmentSize`.
//! 5. `ReadProcessMemory` the full environment block — a
//!    `\0`-separated UTF-16 run of `KEY=VALUE` pairs terminated by
//!    a double `\0`.
//!
//! Alternatives considered and rejected:
//!
//! - **`sysinfo` crate `Process::environ()`** — returns an empty
//!   slice on Windows because the crate doesn't do PEB walking.
//! - **WMI `Win32_Process`** — exposes the command line but not
//!   the environment block.
//! - **PowerShell `Get-Process`** — same limitation as WMI; no env.
//!
//! PEB walking has two known fragility vectors:
//!
//! - **Wow64 processes**: a 32-bit process running on 64-bit
//!   Windows has a shadow PEB that the standard API does not
//!   reach. We ignore this because `claude.exe` is always 64-bit.
//! - **Protected processes**: `OpenProcess` with `PROCESS_VM_READ`
//!   fails for AV / anti-cheat processes. We also skip these
//!   silently — `claude.exe` is not protected.
//!
//! ### Testing
//!
//! This file has unit tests for the pure parser
//! (`parse_environment_block`), which is the only part that
//! doesn't touch syscalls. The syscall path is tested via the
//! integration smoke test in `sessions::tests::list_does_not_panic`
//! and by running `csq status` on a Windows machine.
//!
//! Compiles only on `target_os = "windows"`; the module file is
//! still present on other targets but `cfg`-gated to nothing.

#![allow(unsafe_code)]

use super::windows_parse::{exe_matches_claude, parse_environment_block};
use super::{parse_term_session_id, SessionInfo};
use std::ffi::OsString;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::ReadProcessMemory;
use windows_sys::Win32::System::Threading::{
    NtQueryInformationProcess, OpenProcess, ProcessBasicInformation, PROCESS_BASIC_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// Returns the list of live CC sessions for the current user.
pub fn list() -> Vec<SessionInfo> {
    let mut out = Vec::new();
    for pid in enumerate_claude_pids() {
        if let Some(info) = read_process(pid) {
            out.push(info);
        }
    }
    out
}

/// Walks the full process list and returns PIDs whose executable
/// basename is `claude.exe`. We filter here (not in `read_process`)
/// so the expensive PEB walk happens only for candidate processes.
fn enumerate_claude_pids() -> Vec<u32> {
    // SAFETY: CreateToolhelp32Snapshot is a well-defined syscall
    // that returns INVALID_HANDLE_VALUE on failure; we check and
    // bail. The returned handle is closed via CloseHandle in the
    // defer below.
    let snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot as isize == -1 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    // Process32FirstW / Process32NextW iterate the snapshot.
    // szExeFile is a fixed-size WCHAR array; find the NUL
    // terminator and compare against "claude.exe".
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            if exe_matches_claude(&entry.szExeFile) {
                out.push(entry.th32ProcessID);
            }
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }

    unsafe {
        CloseHandle(snapshot);
    }
    out
}

/// Opens a process, walks its PEB, extracts env and cwd.
fn read_process(pid: u32) -> Option<SessionInfo> {
    // SAFETY: OpenProcess returns NULL on failure. We check and
    // bail immediately. The returned handle is closed in the
    // cleanup path below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
    if handle.is_null() {
        return None;
    }

    // PEB walk. Wrapped in a closure so the CloseHandle below
    // always runs, even on early return.
    let result = (|| -> Option<SessionInfo> {
        let (env_block, cwd) = read_peb_env_and_cwd(handle)?;
        let environ = parse_environment_block(&env_block);

        let config_dir = environ.get("CLAUDE_CONFIG_DIR")?;
        if config_dir.is_empty() {
            return None;
        }
        let config_dir = PathBuf::from(config_dir);
        let account_id = SessionInfo::extract_account_id(&config_dir);

        let term_session_id = environ.get("TERM_SESSION_ID").cloned();
        let (term_window, term_tab, term_pane) = term_session_id
            .as_deref()
            .map(parse_term_session_id)
            .unwrap_or((None, None, None));
        let iterm_profile = environ.get("ITERM_PROFILE").cloned();

        Some(SessionInfo {
            pid,
            cwd: PathBuf::from(cwd),
            config_dir,
            account_id,
            started_at: None, // TODO: GetProcessTimes + FILETIME → unix seconds
            tty: None,        // Windows has no TTY concept for GUI apps
            term_window,
            term_tab,
            term_pane,
            iterm_profile,
            terminal_title: None, // no osascript equivalent on Windows
        })
    })();

    unsafe {
        CloseHandle(handle);
    }
    result
}

/// Walks the PEB to extract the environment block and cwd.
///
/// Returns `(environment_block_bytes, cwd_utf16_as_string)`.
fn read_peb_env_and_cwd(handle: HANDLE) -> Option<(Vec<u16>, String)> {
    // Step 1: NtQueryInformationProcess → PROCESS_BASIC_INFORMATION.
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { zeroed() };
    let mut return_length: u32 = 0;
    // SAFETY: NtQueryInformationProcess with ProcessBasicInformation
    // takes a &mut PBI. We pass a properly-sized buffer. A non-zero
    // return is an NTSTATUS failure code.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut _,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_length,
        )
    };
    if status != 0 {
        return None;
    }
    let peb_addr = pbi.PebBaseAddress as usize;
    if peb_addr == 0 {
        return None;
    }

    // Step 2: Read the PEB struct to get ProcessParameters pointer.
    //
    // The layout of PEB varies across Windows versions but the
    // `ProcessParameters` pointer is at offset 0x20 on 64-bit
    // Windows (stable since at least Vista; verified on Win10/11).
    // On 32-bit it's at 0x10 but we assume 64-bit claude.exe.
    const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x20;
    let params_addr = read_remote_ptr(handle, peb_addr + PEB_PROCESS_PARAMETERS_OFFSET)?;
    if params_addr == 0 {
        return None;
    }

    // Step 3: Read RTL_USER_PROCESS_PARAMETERS fields we need.
    //
    // Layout (64-bit):
    //   0x00  MaximumLength     u32
    //   0x04  Length            u32
    //   0x08  Flags             u32
    //   0x0C  DebugFlags        u32
    //   0x10  ConsoleHandle     *
    //   0x18  ConsoleFlags      u32
    //   0x20  StandardInput     HANDLE
    //   0x28  StandardOutput    HANDLE
    //   0x30  StandardError     HANDLE
    //   0x38  CurrentDirectory.DosPath (UNICODE_STRING = { u16 len, u16 max, *ptr })
    //   0x50  CurrentDirectory.Handle
    //   ...
    //   0x80  Environment       *  (pointer to env block in remote process)
    //   0x3F0 EnvironmentSize   usize
    //
    // These offsets are stable back through Vista but are
    // undocumented; we hardcode them and guard against bogus reads
    // with length sanity checks below.
    const CURRENT_DIRECTORY_OFFSET: usize = 0x38; // UNICODE_STRING
    const ENVIRONMENT_OFFSET: usize = 0x80;
    const ENVIRONMENT_SIZE_OFFSET: usize = 0x3F0;

    // Read CurrentDirectory UNICODE_STRING: { Length, MaximumLength, Buffer }
    let cwd_len_word = read_remote_u16(handle, params_addr + CURRENT_DIRECTORY_OFFSET)?;
    let cwd_ptr = read_remote_ptr(handle, params_addr + CURRENT_DIRECTORY_OFFSET + 0x8)?;
    let cwd_bytes = cwd_len_word as usize; // Length is in bytes
    let cwd = if cwd_ptr != 0 && cwd_bytes > 0 && cwd_bytes < 32_768 {
        read_remote_wide_string(handle, cwd_ptr, cwd_bytes / 2)
    } else {
        String::new()
    };

    // Read Environment pointer + size.
    let env_ptr = read_remote_ptr(handle, params_addr + ENVIRONMENT_OFFSET)?;
    let env_size = read_remote_usize(handle, params_addr + ENVIRONMENT_SIZE_OFFSET)?;
    if env_ptr == 0 || env_size == 0 || env_size > 1_048_576 {
        // Env block larger than 1 MB is suspicious; bail.
        return None;
    }
    // Read the env block (UTF-16 WCHAR array).
    let word_count = env_size / 2;
    let mut env_block: Vec<u16> = vec![0u16; word_count];
    let mut bytes_read: usize = 0;
    // SAFETY: ReadProcessMemory takes a raw buffer pointer. We pass
    // a Vec<u16> whose capacity matches env_size bytes. A non-zero
    // return indicates success; we still sanity-check bytes_read.
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            env_ptr as *const _,
            env_block.as_mut_ptr() as *mut _,
            env_size,
            &mut bytes_read,
        )
    };
    if ok == 0 || bytes_read != env_size {
        return None;
    }
    Some((env_block, cwd))
}

/// `ReadProcessMemory` wrapper that reads `T` from a remote address.
/// Returns `None` on read failure or short read.
///
/// SAFETY: caller must ensure `T` is `Copy` and has no invalid bit
/// patterns (i.e. `T` is plain-old-data). All callers pass `u16`,
/// `u32`, `u64`, or `usize` which satisfy this.
fn read_remote<T: Copy>(handle: HANDLE, addr: usize) -> Option<T> {
    let mut buf: T = unsafe { zeroed() };
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            addr as *const _,
            &mut buf as *mut _ as *mut _,
            size_of::<T>(),
            &mut read,
        )
    };
    if ok == 0 || read != size_of::<T>() {
        return None;
    }
    Some(buf)
}

fn read_remote_ptr(handle: HANDLE, addr: usize) -> Option<usize> {
    read_remote::<usize>(handle, addr)
}

fn read_remote_usize(handle: HANDLE, addr: usize) -> Option<usize> {
    read_remote::<usize>(handle, addr)
}

fn read_remote_u16(handle: HANDLE, addr: usize) -> Option<u16> {
    read_remote::<u16>(handle, addr)
}

/// Reads `word_count` UTF-16 code units from a remote address and
/// converts to a Rust String via OsString (lossy).
fn read_remote_wide_string(handle: HANDLE, addr: usize, word_count: usize) -> String {
    if word_count == 0 || word_count > 32_768 {
        return String::new();
    }
    let mut buf: Vec<u16> = vec![0u16; word_count];
    let mut bytes_read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            word_count * 2,
            &mut bytes_read,
        )
    };
    if ok == 0 {
        return String::new();
    }
    OsString::from_wide(&buf[..bytes_read / 2])
        .to_string_lossy()
        .into_owned()
}
