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

use super::windows_parse::{
    exe_matches_claude, hop_probe_from_image, open_failure_means_gone, owner_verdict,
    parse_environment_block,
};
use super::{parse_term_session_id, HopProbe, Listing, PidLookup, SessionInfo, Undetermined};
use std::ffi::OsString;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NO_MORE_FILES, FALSE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

// ---------------------------------------------------------------------------
// NtQueryInformationProcess FFI
//
// This ntdll.dll function is not exposed by the windows-sys crate.
// We declare the minimal surface needed for PEB walking. The struct
// layout and function signature are stable back through Vista and
// match the Windows SDK's winternl.h declaration.
// ---------------------------------------------------------------------------

/// `PROCESSINFOCLASS` value for `NtQueryInformationProcess` that
/// returns `ProcessBasicInfo`.
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

/// Minimal projection of `PROCESS_BASIC_INFORMATION` from winternl.h.
/// Layout on 64-bit Windows (48 bytes, verified against SDK):
///   offset  0: ExitStatus (i32, 4B + 4B padding)
///   offset  8: PebBaseAddress (usize, 8B)
///   offset 16: AffinityMask (usize, 8B)
///   offset 24: BasePriority (i32, 4B + 4B padding)
///   offset 32: UniqueProcessId (usize, 8B)
///   offset 40: InheritedFromUniqueProcessId (usize, 8B)
#[repr(C)]
struct ProcessBasicInfo {
    _exit_status: i32,
    peb_base_address: usize,
    _affinity_mask: usize,
    _base_priority: i32,
    _unique_process_id: usize,
    _inherited_from_unique_process_id: usize,
}

extern "system" {
    fn NtQueryInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: *mut core::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32; // NTSTATUS
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the list of live CC sessions for the current user.
pub fn list() -> Vec<SessionInfo> {
    try_list().unwrap_or_default()
}

/// [`list`], but `None` when the process snapshot itself could not be
/// taken, so a caller can tell "no live sessions" from "could not look".
pub fn try_list() -> Option<Vec<SessionInfo>> {
    try_list_detailed().map(|l| l.sessions)
}

/// [`try_list`] plus the count of `claude.exe` processes that could not be read. The
/// candidates are chosen by image name, so a candidate that fails to read (open refused,
/// token or PEB unreadable) is counted rather than skipped (INV-31-02). A process that is
/// gone, or positively owned by another user, is not.
pub fn try_list_detailed() -> Option<Listing> {
    let mut sessions = Vec::new();
    let mut unreadable_pids: Vec<u32> = Vec::new();
    for pid in enumerate_claude_pids(None)? {
        match read_process_checked(pid) {
            Ok(Some(info)) => sessions.push(info),
            Ok(None) => {}
            Err(Undetermined) => unreadable_pids.push(pid),
        }
    }
    Some(Listing {
        sessions,
        unreadable_claude: unreadable_pids.len(),
        unreadable_pids,
        incomplete: false,
        incomplete_cause: None,
        restricted: false,
    })
}

/// Walks the full process list and returns PIDs whose executable
/// basename is `claude.exe`. We filter here (not in `read_process`)
/// so the expensive PEB walk happens only for candidate processes.
///
/// `only` restricts the walk to one pid (the targeted lookup): the snapshot is the
/// cheap part on Windows; the PEB walk is what it avoids repeating per session.
fn enumerate_claude_pids(only: Option<u32>) -> Option<Vec<u32>> {
    // SAFETY: CreateToolhelp32Snapshot is a well-defined syscall
    // that returns INVALID_HANDLE_VALUE on failure; we check and
    // bail. The returned handle is closed via CloseHandle in the
    // defer below.
    let snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == 0 || snapshot == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut out = Vec::new();
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

    // Process32FirstW / Process32NextW iterate the snapshot.
    // szExeFile is a fixed-size WCHAR array; find the NUL
    // terminator and compare against "claude.exe".
    //
    // INV-31-02: a failed call is "could not read the table" (`None`) unless
    // GetLastError is ERROR_NO_MORE_FILES, which is how the API reports the
    // end of the table (or an empty one). A mid-walk failure also yields
    // `None`: a truncated table must not read as "enumerated".
    let mut complete = true;
    // SAFETY: `snapshot` is a valid handle and `entry.dwSize` is set.
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    loop {
        if !ok {
            // SAFETY: GetLastError only reads thread-local state.
            let code = unsafe { GetLastError() };
            if !is_end_of_table(code) {
                tracing::warn!(
                    reason = "process_walk_failed",
                    code,
                    "process table walk failed; listing undetermined"
                );
                complete = false;
            }
            break;
        }
        if exe_matches_claude(&entry.szExeFile)
            && (only.is_none() || only == Some(entry.th32ProcessID))
        {
            out.push(entry.th32ProcessID);
        }
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }

    unsafe {
        CloseHandle(snapshot);
    }
    complete.then_some(out)
}

/// `GetLastError` value the ToolHelp walk reports at the end of the table.
fn is_end_of_table(code: u32) -> bool {
    code == ERROR_NO_MORE_FILES
}

/// The session for one pid, three-outcome (see [`super::session_info_for_pid`]): the
/// snapshot confirms it is a `claude.exe`, then one PEB walk reads it. A failed snapshot
/// is `Err`; so is any open or PEB failure other than "no such process".
///
/// Same-user filter: the target's process-token user SID (`OpenProcessToken` +
/// `GetTokenInformation(TokenUser)`) is compared with this process's. A different SID is
/// `Ok(None)`; a token that cannot be read is `Err(Undetermined)`, never a determinate
/// answer (see [`read_process_checked`] and [`owner_verdict`]). Windows has no
/// controlling-terminal concept for `claude.exe`, so no terminal is required.
/// (Compile-checked only on `x86_64-pc-windows-gnu`; never run here.)
pub(crate) fn session_info_for_pid(pid: u32) -> PidLookup {
    let pids = enumerate_claude_pids(Some(pid)).ok_or(Undetermined)?;
    if pids.contains(&pid) {
        read_process_checked(pid)
    } else {
        Ok(None)
    }
}

/// The user SID of a process or token owner, as owned bytes (`TOKEN_USER` -> `Sid`, length
/// from `GetLengthSid`). `None` when any step fails.
fn token_user_sid(process: HANDLE) -> Option<Vec<u8>> {
    let mut token: HANDLE = 0;
    // SAFETY: `process` is a valid process handle or pseudo-handle; `token` is a live
    // out-pointer. OpenProcessToken returns 0 on failure, checked.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let sid = (|| {
        let mut needed = 0u32;
        // SAFETY: a null buffer with length 0 only asks for the required size.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return None;
        }
        // 8-byte alignment for the TOKEN_USER the kernel writes at the start.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        // SAFETY: `buf` is at least `needed` bytes and exclusively borrowed; the call
        // writes at most `needed` bytes and returns 0 on failure, checked.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast::<core::ffi::c_void>(),
                needed,
                &mut needed,
            )
        };
        if ok == 0 {
            return None;
        }
        // SAFETY: a successful TokenUser query wrote a TOKEN_USER at the start of `buf`
        // (aligned above), whose `User.Sid` points at the SID stored in the same buffer.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        if sid.is_null() {
            return None;
        }
        // The kernel-written `sid` pointer is not trusted to lie inside `buf`: bound its
        // offset from the buffer start before ANY read through it. A SID's fixed header
        // (revision, sub-authority count, 6-byte authority) is 8 bytes; GetLengthSid reads
        // only that header, so the header must fit within the `needed` bytes first.
        const SID_HEADER_LEN: usize = 8;
        let off = (sid as usize).checked_sub(buf.as_ptr() as usize)?;
        if off.checked_add(SID_HEADER_LEN)? > needed as usize {
            return None;
        }
        // SAFETY: `off + 8 <= needed <= buf.len() * 8` (checked above), so the SID header
        // GetLengthSid reads lies inside `buf`.
        let len = unsafe { GetLengthSid(sid) } as usize;
        if len == 0 || off.checked_add(len)? > needed as usize {
            return None;
        }
        // SAFETY: `off + len <= needed <= buf.len() * 8` (checked above), so the `len`
        // bytes starting `off` bytes into `buf` lie inside it; the slice is derived from
        // `buf`'s own pointer, never from the kernel-written one.
        Some(
            unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>().add(off), len) }.to_vec(),
        )
    })();
    // SAFETY: `token` was opened above and is closed exactly once.
    unsafe {
        CloseHandle(token);
    }
    sid
}

/// Whether `pid` is owned by the same user as this process, via the token user SIDs.
/// `Ok(false)` is returned for a vanished process and for a process whose token was read
/// and carries a different SID. A non-admin caller usually CANNOT query another user's
/// token, so such a process normally lands in `Err(Undetermined)` (the token could not be
/// read), not `Ok(false)`; on a shared Windows host that makes the per-pid lookups
/// answer undetermined, which is fail-closed.
fn same_owner(pid: u32) -> Result<bool, Undetermined> {
    // Limited-information access is typically enough to read a token when the caller may
    // open the process at all (the same user, or an admin). The exception is a protected
    // process, whose token can be refused even to an admin; that too lands in
    // `Err(Undetermined)`, as does another user's process, as the function doc says.
    // SAFETY: OpenProcess returns NULL (0) on failure, checked; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid) };
    if handle == 0 {
        // SAFETY: GetLastError only reads thread-local state.
        let code = unsafe { GetLastError() };
        return if open_failure_means_gone(code) {
            Ok(false)
        } else {
            Err(Undetermined)
        };
    }
    let target = token_user_sid(handle);
    // SAFETY: `handle` was opened above and is closed exactly once.
    unsafe {
        CloseHandle(handle);
    }
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no close.
    let own = token_user_sid(unsafe { GetCurrentProcess() });
    owner_verdict(target.as_deref(), own.as_deref()).ok_or(Undetermined)
}

/// Opens a process, walks its PEB, extracts env and cwd.
fn read_process_checked(pid: u32) -> PidLookup {
    // Same-user filter first: a process whose token was read and carries another SID is
    // positively not ours (`Ok(None)`); one whose owner cannot be read — usually another
    // user's process, for a non-admin caller — is undetermined (fail-closed).
    if !same_owner(pid)? {
        return Ok(None);
    }
    // SAFETY: OpenProcess returns NULL (0) on failure. We check and
    // bail immediately. The returned handle is closed in the
    // cleanup path below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid) };
    if handle == 0 {
        // SAFETY: GetLastError only reads thread-local state.
        let code = unsafe { GetLastError() };
        return if open_failure_means_gone(code) {
            Ok(None)
        } else {
            Err(Undetermined)
        };
    }

    // PEB walk. Wrapped in a closure so the CloseHandle below
    // always runs, even on early return.
    let result = (|| -> PidLookup {
        let (env_block, cwd) = read_peb_env_and_cwd(handle).ok_or(Undetermined)?;
        let environ = parse_environment_block(&env_block);

        let Some(config_dir) = environ.get("CLAUDE_CONFIG_DIR").filter(|d| !d.is_empty()) else {
            return Ok(None);
        };
        let config_dir = PathBuf::from(config_dir);
        let account_id = SessionInfo::extract_account_id(&config_dir);

        let term_session_id = environ.get("TERM_SESSION_ID").cloned();
        let (term_window, term_tab, term_pane) = term_session_id
            .as_deref()
            .map(parse_term_session_id)
            .unwrap_or((None, None, None));
        let iterm_profile = environ.get("ITERM_PROFILE").cloned();

        let started_at = get_process_start_time(handle);

        Ok(Some(SessionInfo {
            pid,
            cwd: PathBuf::from(cwd),
            config_dir,
            account_id,
            started_at,
            tty: None, // Windows has no TTY concept for GUI apps
            term_window,
            term_tab,
            term_pane,
            iterm_profile,
            terminal_title: None, // no osascript equivalent on Windows
        }))
    })();

    unsafe {
        CloseHandle(handle);
    }
    result
}

/// One process between a caller and a claimed owner, classified by IMAGE NAME from a
/// Toolhelp snapshot (a CLI image is a session whatever its owner; another readable image is
/// not; no env or terminal is needed). A failed snapshot is `Unreadable`; a pid absent from
/// the snapshot is `Gone`.
/// (Compile-checked only on `x86_64-pc-windows-gnu`; never run here.)
pub(crate) fn hop_probe(pid: u32) -> HopProbe {
    // SAFETY: CreateToolhelp32Snapshot returns INVALID_HANDLE_VALUE on failure; checked below.
    let snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == 0 || snapshot == INVALID_HANDLE_VALUE {
        return HopProbe::Unreadable;
    }
    // SAFETY: PROCESSENTRY32W is plain-old-data; all-zero is valid before dwSize is set.
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut image: Option<Vec<u16>> = None;
    // SAFETY: `snapshot` is a valid handle and `entry.dwSize` is set.
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while ok {
        if entry.th32ProcessID == pid {
            image = Some(entry.szExeFile.to_vec());
            break;
        }
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: GetLastError only reads thread-local state.
    let walk_failed = image.is_none() && !is_end_of_table(unsafe { GetLastError() });
    // SAFETY: `snapshot` is a valid handle returned above and is closed exactly once.
    unsafe {
        CloseHandle(snapshot);
    }
    match image {
        Some(image) => hop_probe_from_image(&image),
        None if walk_failed => HopProbe::Unreadable,
        None => HopProbe::Gone,
    }
}

/// The parent pid of `pid` from a Toolhelp snapshot (`th32ParentProcessID`), or `None`
/// when the snapshot cannot be taken, the walk fails, or `pid` is not in it.
pub(crate) fn parent_pid_of(pid: u32) -> Option<u32> {
    // SAFETY: CreateToolhelp32Snapshot returns INVALID_HANDLE_VALUE on failure; checked below.
    let snapshot: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == 0 || snapshot == INVALID_HANDLE_VALUE {
        return None;
    }
    // SAFETY: PROCESSENTRY32W is plain-old-data; all-zero is valid before dwSize is set.
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut found = None;
    // SAFETY: `snapshot` is a valid handle and `entry.dwSize` is set.
    let mut ok = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while ok {
        if entry.th32ProcessID == pid {
            found = Some(entry.th32ParentProcessID);
            break;
        }
        // SAFETY: as above.
        ok = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: `snapshot` is a valid handle returned above and is closed exactly once.
    unsafe {
        CloseHandle(snapshot);
    }
    found
}

/// The creation time of `pid` as unix seconds, or `None` when the process cannot be
/// opened or queried.
pub(crate) fn start_time_of(pid: u32) -> Option<u64> {
    // SAFETY: OpenProcess returns NULL (0) on failure; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid) };
    if handle == 0 {
        return None;
    }
    let started = get_process_start_time(handle);
    // SAFETY: `handle` is a valid handle returned by OpenProcess above.
    unsafe {
        CloseHandle(handle);
    }
    started
}

/// Returns the process creation time as a Unix timestamp (seconds since epoch),
/// or `None` if the call fails. Uses `GetProcessTimes` which returns
/// `FILETIME` structs (100-nanosecond intervals since 1601-01-01 UTC).
fn get_process_start_time(handle: HANDLE) -> Option<u64> {
    let creation = get_process_creation_filetime(handle)?;
    // Convert FILETIME (100ns since 1601-01-01) to Unix epoch (seconds since 1970-01-01).
    // Difference between 1601 and 1970 epochs in 100ns intervals:
    // 11644473600 seconds * 10_000_000 = 116444736000000000
    const FILETIME_UNIX_DIFF: u64 = 116_444_736_000_000_000;
    if creation < FILETIME_UNIX_DIFF {
        return None; // date before Unix epoch — shouldn't happen
    }
    Some((creation - FILETIME_UNIX_DIFF) / 10_000_000)
}

/// The creation FILETIME of `pid` in raw 100 ns units, the full-precision start the
/// ancestry walk compares ([`super::is_ancestor_of_current`]). `None` when the process
/// cannot be opened or queried.
pub(crate) fn creation_filetime_of(pid: u32) -> Option<u64> {
    // SAFETY: OpenProcess returns NULL (0) on failure; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid) };
    if handle == 0 {
        return None;
    }
    let t = get_process_creation_filetime(handle);
    // SAFETY: `handle` is a valid handle returned by OpenProcess above.
    unsafe {
        CloseHandle(handle);
    }
    // A zero creation time (kernel pseudo-processes) is not a real start: refusing it keeps
    // the walk fail-closed, matching macOS `micros` and the old `start_time_of` filter.
    t.filter(|&c| c != 0)
}

/// Raw creation FILETIME (100 ns since 1601-01-01 UTC) via `GetProcessTimes`.
fn get_process_creation_filetime(handle: HANDLE) -> Option<u64> {
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    // FILETIME = two u32s representing a 64-bit count of 100ns intervals
    // since 1601-01-01 00:00:00 UTC.
    let mut creation: u64 = 0;
    let mut exit: u64 = 0;
    let mut kernel: u64 = 0;
    let mut user: u64 = 0;

    // SAFETY: handle is a valid process handle opened with
    // PROCESS_QUERY_INFORMATION. The four out-pointers are stack locals.
    let ok = unsafe {
        GetProcessTimes(
            handle,
            std::ptr::addr_of_mut!(creation).cast(),
            std::ptr::addr_of_mut!(exit).cast(),
            std::ptr::addr_of_mut!(kernel).cast(),
            std::ptr::addr_of_mut!(user).cast(),
        )
    };
    if ok == 0 {
        return None;
    }
    Some(creation)
}

/// Walks the PEB to extract the environment block and cwd.
///
/// Returns `(environment_block_bytes, cwd_utf16_as_string)`.
fn read_peb_env_and_cwd(handle: HANDLE) -> Option<(Vec<u16>, String)> {
    // Step 1: NtQueryInformationProcess → ProcessBasicInfo.
    let mut pbi: ProcessBasicInfo = unsafe { zeroed() };
    let mut return_length: u32 = 0;
    // SAFETY: NtQueryInformationProcess with ProcessBasicInformation
    // takes a &mut PBI. We pass a properly-sized buffer. A non-zero
    // return is an NTSTATUS failure code.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut _,
            size_of::<ProcessBasicInfo>() as u32,
            &mut return_length,
        )
    };
    if status != 0 {
        return None;
    }
    let peb_addr = pbi.peb_base_address;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Only ERROR_NO_MORE_FILES (18) is a clean end of table; access-denied
    /// or any other code is "could not read" (INV-31-02).
    #[test]
    fn only_no_more_files_ends_the_table_cleanly() {
        assert!(is_end_of_table(18));
        assert!(!is_end_of_table(0));
        assert!(!is_end_of_table(5)); // ERROR_ACCESS_DENIED
        assert!(!is_end_of_table(24)); // ERROR_BAD_LENGTH
    }
}
