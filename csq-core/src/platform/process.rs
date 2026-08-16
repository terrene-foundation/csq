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

/// Returns `true` only when `pid` is **positively identified** as a
/// process that is NOT csq — i.e. the OS recycled a dead daemon's PID
/// and handed it to an unrelated program.
///
/// This is the guard against PID reuse on every path that reads a PID
/// out of csq's own PID file. `is_pid_alive` answers "does *something*
/// hold this PID"; it cannot answer "is that something *our daemon*".
/// On a host where the daemon died without running its `Drop` (SIGKILL,
/// panic-abort, OOM, a `/tmp` reap), the PID file outlives the process
/// and the kernel is free to reissue that PID minutes or hours later.
/// Every caller that trusted bare liveness then acted on a stranger's
/// PID — see [`crate::daemon::detect`], [`crate::daemon::lifecycle`],
/// and [`crate::daemon::pid`].
///
/// # Fails open, by design
///
/// Returns `false` ("assume it is ours") whenever the process's command
/// cannot be read — permission denied, the process exited between the
/// liveness check and this call, or an unsupported platform. Only a
/// positive foreign identification returns `true`. The asymmetry is
/// deliberate: a false *positive* would make csq disown a live daemon
/// (and, at `stop_daemon`, refuse to stop it), whereas a false
/// *negative* merely preserves the pre-existing behaviour.
pub fn is_pid_foreign(pid: u32) -> bool {
    match imp::process_command(pid) {
        Some(cmd) => !is_csq_command(&cmd),
        None => false,
    }
}

/// Returns `true` if `cmd` looks like a csq binary invocation.
///
/// The input is whatever the platform reports for a process: a bare
/// name (`csq`), an absolute executable path that may itself contain
/// spaces (`/Applications/Code Squad Q.app/Contents/MacOS/csq`), or a
/// full command line (`/home/u/.local/bin/csq daemon start`). Both the
/// whole string and its first whitespace-delimited token are tested so
/// all three shapes resolve, then the trailing path component is
/// matched against the csq family (`csq`, `csq-ee`, `csq.exe`, …).
pub fn is_csq_command(cmd: &str) -> bool {
    let whole = cmd.trim();
    if csq_program_matches(whole) {
        return true;
    }
    // Linux reports the full argv; the program is the first token.
    match whole.split_once(char::is_whitespace) {
        Some((first, _)) => csq_program_matches(first),
        None => false,
    }
}

/// True when `program`'s trailing path component names a csq binary.
///
/// Accepts `csq` exactly, plus `csq`-prefixed variants delimited by a
/// space (an argv tail), `-`, or `_` (`csq-ee`) so an edition-suffixed
/// or renamed install is not disowned. Deliberately rejects an
/// unbroken alphanumeric extension like `csquash`.
fn csq_program_matches(program: &str) -> bool {
    let base = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(program)
        .to_lowercase();
    let base = base.trim_end_matches(".exe");
    base == "csq"
        || base.starts_with("csq ")
        || base.starts_with("csq-")
        || base.starts_with("csq_")
}

/// Spawns a long-lived process that is definitely NOT csq, and does not
/// return until [`is_pid_foreign`] actually observes it as foreign.
///
/// Test-only helper, shared by every test that needs to stage a recycled
/// PID (`daemon::detect`, `daemon::lifecycle`, `daemon::pid`).
///
/// # The wait is load-bearing, not defensive
///
/// `Command::spawn` returns after `fork` but BEFORE `execve`. Until that
/// exec completes, Linux's `/proc/<pid>/cmdline` still reports the PARENT's
/// argv — and in a test binary the parent is `csq_core-<hash>`, which
/// matches the `csq_` arm of [`is_csq_command`]. So [`is_pid_foreign`]
/// fails OPEN and the caller gets a "csq process" where it staged a
/// stranger, silently testing nothing.
///
/// That is not hypothetical: it took down `detect_live_but_foreign_pid_is_
/// not_running` on the Linux CI lane with
/// `Stale { "PID … alive but socket … missing" }` while macOS passed —
/// there `ps -o comm=` reports the resolved executable, so the window is
/// invisible. Spawning without this wait is a race whose failure mode is
/// platform-dependent and reads as a flake.
///
/// Panics if the child never becomes observably foreign: a silent timeout
/// would reinstate exactly the fail-open the caller is testing against.
#[cfg(all(unix, any(test, feature = "test-utils")))]
pub fn spawn_foreign_test_process() -> std::process::Child {
    use std::time::{Duration, Instant};

    let mut child = std::process::Command::new("/bin/sleep")
        .arg("120")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn /bin/sleep");

    let deadline = Instant::now() + Duration::from_secs(10);
    while !is_pid_foreign(child.id()) {
        if Instant::now() >= deadline {
            let pid = child.id();
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "spawned /bin/sleep (pid {pid}) never became observable as non-csq \
                 within 10s. `is_pid_foreign` fails open, so continuing would stage \
                 a process the code under test reads as csq — the test would pass \
                 while asserting nothing."
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

/// Spawns a COPY of the current test binary — renamed to a `csq`-prefixed
/// path — and does not return until [`is_pid_foreign`]'s underlying
/// identification positively resolves the child's command as csq.
///
/// Windows counterpart to [`spawn_foreign_test_process`], with the polarity
/// reversed. `is_pid_foreign` identifies "ours" by the spawned process's
/// reported executable NAME (`csq_program_matches`, read via a
/// `CreateToolhelp32Snapshot` walk — see `imp::process_command`). An
/// INTEGRATION test binary's own name (e.g.
/// `daemon_windows_graceful_stop-<hash>.exe`) never matches that — unlike
/// csq-core's LIB test binary, which cargo names `csq_core-<hash>` and
/// which the `csq_` arm accepts (see this file's own
/// `own_pid_is_not_foreign` test). So an integration test that needs to
/// stage "a live daemon" PID cannot use its own `std::process::id()`:
/// `daemon::lifecycle::status_of`'s identity check (closing the PID-reuse
/// gap the recycled-Teams-helper incident surfaced) correctly disowns it,
/// reporting `PidReused` rather than `Running`.
///
/// This copies `std::env::current_exe()` (the running test binary) into a
/// fresh [`tempfile::TempDir`] under a `csq-`-prefixed file name, then
/// spawns THAT copy running ONLY the caller-named `#[ignore]`d test
/// (`--ignored --exact <target_test_name>`) — expected to block/sleep long
/// enough for the caller to finish its own assertions before the process
/// exits. `Command::spawn` on Windows goes through `CreateProcessW`, which
/// loads the target image synchronously as part of process creation — no
/// POSIX fork/exec split, so unlike `spawn_foreign_test_process`'s Linux
/// `/proc/<pid>/cmdline` concern there is no window where the child still
/// reads as the PARENT's image. The poll below guards a DIFFERENT gap: a
/// `CreateToolhelp32Snapshot` taken microseconds after `spawn()` returns may
/// not yet enumerate the new PID, and an unresolvable PID makes
/// `is_pid_foreign` fail OPEN to `false` (its documented fail-open
/// contract) — so this polls the POSITIVE signal directly
/// (`imp::process_command` returns `Some(cmd)` where [`is_csq_command`]
/// holds), never `is_pid_foreign`'s boolean, which a not-yet-visible child
/// would satisfy for the wrong reason (unresolved, not positively ours).
///
/// Panics (after killing the child) if it never becomes positively
/// observable as csq within the deadline: a silent timeout here would let
/// the caller proceed against a PID the identity check under test still
/// cannot resolve, silently asserting nothing.
#[cfg(all(windows, any(test, feature = "test-utils")))]
pub fn spawn_csq_named_test_process(
    target_test_name: &str,
) -> (std::process::Child, tempfile::TempDir) {
    use std::time::{Duration, Instant};

    let dir = tempfile::TempDir::new().expect("tempdir for renamed csq test binary");
    let src = std::env::current_exe().expect("current_exe for the running test binary");
    let dst = dir.path().join("csq-graceful-stop-test-host.exe");
    std::fs::copy(&src, &dst).expect("copy running test binary to a csq-prefixed path");

    let mut child = std::process::Command::new(&dst)
        .args(["--ignored", "--exact", target_test_name])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn renamed csq test binary");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if imp::process_command(child.id()).is_some_and(|cmd| is_csq_command(&cmd)) {
            break;
        }
        if Instant::now() >= deadline {
            let pid = child.id();
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "renamed csq-named test binary (pid {pid}) never became \
                 observable as csq within 10s. `is_pid_foreign` fails open on \
                 an unresolvable PID, so continuing on that alone would risk \
                 staging a PID the identity check under test still can't \
                 positively resolve — the test would pass while asserting \
                 nothing."
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    (child, dir)
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

    /// Returns the command reported for `pid`, or `None` when it cannot
    /// be read (process gone, permission denied). Backs
    /// [`super::is_pid_foreign`], whose fail-open contract depends on
    /// `None` being returned rather than an empty string.
    pub fn process_command(pid: u32) -> Option<String> {
        get_process_info(pid).map(|(_ppid, cmd)| cmd)
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
        fn GetExitCodeProcess(hProcess: *mut std::ffi::c_void, lpExitCode: *mut u32) -> i32;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut std::ffi::c_void;
        fn Process32FirstW(hSnapshot: *mut std::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(hSnapshot: *mut std::ffi::c_void, lppe: *mut ProcessEntry32W) -> i32;
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

    /// Returns the executable name reported for `pid`, or `None` when it
    /// cannot be read. Backs [`super::is_pid_foreign`], whose fail-open
    /// contract depends on `None` rather than an empty string.
    pub fn process_command(pid: u32) -> Option<String> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: ProcessEntry32W = unsafe { std::mem::zeroed() };
        entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;

        let mut found = None;
        if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
            loop {
                if entry.th32_process_id == pid {
                    found = Some(String::from_utf16_lossy(
                        &entry.sz_exe_file[..entry
                            .sz_exe_file
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(260)],
                    ));
                    break;
                }
                entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as u32;
                if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }
        unsafe { CloseHandle(snapshot) };
        found
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
                entries.insert(entry.th32_process_id, (entry.th32_parent_process_id, exe));

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
        assert!(is_cc_command(
            "node /home/user/.nvm/versions/node/v20/bin/claude"
        ));
        assert!(is_cc_command(
            "node /path/to/@anthropic-ai/claude-code/cli.js"
        ));
    }

    #[test]
    fn is_cc_command_rejects_non_claude() {
        assert!(!is_cc_command("/bin/bash"));
        assert!(!is_cc_command("vim"));
        assert!(!is_cc_command("python3 script.py"));
        assert!(!is_cc_command(""));
    }

    #[test]
    fn is_csq_command_matches_every_shape_the_platforms_report() {
        // macOS `ps -o comm=` for a bare CLI invocation.
        assert!(is_csq_command("csq"));
        // macOS `ps -o comm=` for the desktop bundle — note the SPACES
        // in the path, which is why the whole string is tested and not
        // just the first whitespace token.
        assert!(is_csq_command(
            "/Applications/Code Squad Q.app/Contents/MacOS/csq"
        ));
        // Linux `/proc/<pid>/cmdline`, NUL-joined into argv.
        assert!(is_csq_command("/home/u/.local/bin/csq daemon start"));
        assert!(is_csq_command("csq daemon start"));
        // Windows snapshot exe name.
        assert!(is_csq_command("csq.exe"));
        // Edition-suffixed / renamed installs must not be disowned.
        assert!(is_csq_command("/usr/local/bin/csq-ee"));
    }

    #[test]
    fn is_csq_command_rejects_unrelated_programs() {
        // The exact process that held the recycled PID in the originating
        // incident: csq's PID file said 1754, `kill(1754, 0)` succeeded,
        // and 1754 was a Microsoft Teams helper.
        assert!(!is_csq_command(
            "/Applications/Microsoft Teams.app/Contents/Helpers/\
             Microsoft Teams ModuleHost.app/Contents/MacOS/Microsoft Teams ModuleHost"
        ));
        assert!(!is_csq_command("/bin/zsh"));
        assert!(!is_csq_command("node /usr/local/bin/claude"));
        assert!(!is_csq_command(""));
        // Prefix match must not spill onto an unrelated name that merely
        // starts with the same three letters.
        assert!(!is_csq_command("csquash"));
        assert!(!is_csq_command("/usr/bin/csquash --flag"));
    }

    /// Load-bearing precondition for the own-PID tests in
    /// `daemon::detect`, `daemon::lifecycle`, and `daemon::pid`.
    ///
    /// Those tests write `std::process::id()` into a PID file and assert
    /// Running / Healthy / AlreadyRunning. They are only meaningful while
    /// this test binary reads as a csq process: cargo names it after the
    /// crate (`csq_core-<hash>`), which `csq_program_matches` accepts via
    /// its `csq_` arm. If the crate were renamed, `is_pid_foreign` would
    /// start reporting our own PID as foreign and every one of those
    /// sibling tests would flip to the not-running branch — still
    /// "passing" in the sense of not erroring, but no longer asserting
    /// what its name claims. This test fails loudly instead.
    #[test]
    fn own_pid_is_not_foreign() {
        let pid = std::process::id();
        let cmd = imp::process_command(pid)
            .expect("platform must be able to read our own process command");
        assert!(
            is_csq_command(&cmd),
            "this test binary must read as csq or the own-PID tests in \
             daemon::{{detect,lifecycle,pid}} become vacuous; got {cmd:?}"
        );
        assert!(!is_pid_foreign(pid));
    }

    /// The contract every caller of the helper depends on.
    ///
    /// `daemon::{detect,lifecycle,pid}` each stage a recycled PID by spawning
    /// this child and expecting the code under test to treat it as NOT csq.
    /// If the helper ever returns before the child is observably foreign,
    /// those tests do not fail — they pass while asserting nothing, because
    /// `is_pid_foreign` fails open. This pins the postcondition so that
    /// regression is a failure here rather than silent green over there.
    #[cfg(unix)]
    #[test]
    fn spawn_foreign_test_process_returns_an_observably_foreign_child() {
        let mut child = spawn_foreign_test_process();
        let pid = child.id();

        assert!(
            is_pid_foreign(pid),
            "helper returned before the child was observable as non-csq"
        );
        assert!(
            is_pid_alive(pid),
            "helper returned a child that already exited"
        );
        let cmd = imp::process_command(pid).expect("child command must be readable");
        assert!(
            !is_csq_command(&cmd),
            "child must not read as csq; got {cmd:?}"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn is_pid_foreign_fails_open_on_unreadable_pid() {
        // A PID that does not exist yields no command, and the fail-open
        // contract requires `false` — never claim "foreign" on absence.
        assert!(!is_pid_foreign(99_999_999));
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
