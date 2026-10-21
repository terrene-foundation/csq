//! Per-account exclusive file lock for the `csq login N` flow.
//!
//! # Why this exists
//!
//! Two concurrent `csq login 5` processes can both reach
//! `prepare_race`, both bind a loopback port, both mint PKCE
//! verifiers, and both complete OAuth races. The last one to
//! finish stomps `accounts/credentials/5.json`. The first user's
//! tokens are silently lost; the user has no idea which session
//! "won."
//!
//! Holding an exclusive POSIX flock (Unix) / `LockFileEx` (Windows)
//! for the duration of the login serializes them. The second
//! process gets a clear error pointing at the holder PID so the
//! user knows which terminal already has the flow open.
//!
//! UX-R1-H3.
//!
//! # Lock file naming
//!
//! `<base_dir>/.login-N.lock` — sibling to `accounts/credentials/`
//! and `profiles.json`. The holder's PID is written as decimal text
//! to the SIDECAR `<base_dir>/.login-N.lock.pid` (never inside the
//! lock file itself — Windows `LockFileEx` blocks reads from
//! non-holding handles even in the same process; the sidecar is
//! never locked, so any waiter can read it) so a concurrent attempt
//! can render a useful error ("PID 12345 is already running csq
//! login 5"). On lock release the lock file is *not* deleted:
//! keeping it around lets the next attempt re-use the same inode
//! and ensures the lock survives filesystem races between unlink
//! and re-open. The lock file is emptied and the sidecar removed on
//! release so a retained file never misattributes a fresh lock
//! attempt.

use crate::platform::fs::secure_file;
use crate::types::AccountNum;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Outcome of [`AccountLoginLock::acquire`].
pub enum AcquireOutcome {
    /// Caller now holds the lock; drop the returned guard to
    /// release.
    Acquired(AccountLoginLock),
    /// Another process holds the lock. The PID is the holder
    /// (read from the `.login-N.lock.pid` sidecar) when available,
    /// `None` if the sidecar is missing or unreadable.
    ///
    /// `pid_alive` is `Some(true)` when the holder PID is verifiably
    /// running, `Some(false)` when the PID is dead (stale lock from a
    /// prior crash), and `None` when no PID was readable or the
    /// liveness probe is unsupported on this platform.
    /// SEC-R2-08 / REV-R2-03 — distinguishes a real contention from a
    /// stale crash artefact so the caller can render a "the lock has
    /// been reclaimed" message instead of pointing at a dead PID.
    Held {
        pid: Option<u32>,
        pid_alive: Option<bool>,
    },
}

impl std::fmt::Debug for AcquireOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcquireOutcome::Acquired(g) => {
                f.debug_struct("Acquired").field("path", &g.path).finish()
            }
            AcquireOutcome::Held { pid, pid_alive } => f
                .debug_struct("Held")
                .field("pid", pid)
                .field("pid_alive", pid_alive)
                .finish(),
        }
    }
}

/// Who currently holds an `.login-N.lock`, for operator recovery
/// (`csq unlock N`). Returned by [`inspect_lock`].
#[derive(Debug, Clone)]
pub struct LockHolder {
    /// PID read from the `.login-N.lock.pid` sidecar, if present and
    /// parseable. `None` normally means the lock file is a RETAINED
    /// artefact of a prior login ATTEMPT (the file is created at
    /// `acquire` and kept on every release — success, failure, and abort
    /// alike; the sidecar is deleted on drop) — i.e. "no live holder",
    /// not "crashed". It can also mean a microsecond acquire race or a
    /// manual leftover.
    pub pid: Option<u32>,
    /// Whether that PID is currently alive. `None` when there is no PID.
    /// A live holder means the lock is genuinely in use (or hung); a dead
    /// holder means the lock files are stale residue.
    pub alive: Option<bool>,
    /// The holder's process command line (`ps -o command=`), for the
    /// operator to confirm it is a stuck `csq login` before terminating
    /// it. `None` on Windows or when the process cannot be inspected.
    pub command: Option<String>,
}

/// Outcome of a [`force_release`] operation.
#[derive(Debug, Clone)]
pub struct ForceReleaseReport {
    /// Whether a lock file (or sidecar) was present to begin with.
    pub had_lock: bool,
    /// The PID that was terminated, if `kill` was requested and a live,
    /// verified-as-login holder existed.
    pub killed_pid: Option<u32>,
    /// The lock files that were removed.
    pub removed_files: Vec<PathBuf>,
}

/// Exclusive per-account lock around the `csq login N` flow.
///
/// Acquired via [`AccountLoginLock::acquire`]; released on `Drop`.
/// The lock is process-scoped (POSIX flock on Unix, LockFileEx on
/// Windows) so a panic that unwinds past the guard still releases
/// it via the kernel's process-exit cleanup.
///
/// # Forking
///
/// Do NOT fork WITHOUT exec while holding this guard. The child inherits
/// the lock descriptor, and a child that drops its copy releases the lock
/// for the whole open file description — including the parent's, because
/// POSIX flock is per-description, not per-process (`flock(2)`). The
/// parent's own `Drop` releases explicitly for the mirror-image hazard: a
/// child that KEEPS its copy past the parent's close would otherwise hold
/// the lock until it execs (`FD_CLOEXEC`) or exits.
pub struct AccountLoginLock {
    file: File,
    path: PathBuf,
    pid_path: PathBuf,
}

impl AccountLoginLock {
    /// Lock file path for `account` under `base_dir`. Exposed so
    /// tests can assert on the location without re-deriving it.
    pub fn lock_path(base_dir: &Path, account: AccountNum) -> PathBuf {
        base_dir.join(format!(".login-{}.lock", account.get()))
    }

    /// Sidecar PID file path for `account`. Holds the holder PID as
    /// decimal text. Decoupled from the lock file because Windows
    /// `LockFileEx` blocks reads from non-holding handles even within
    /// the same process — making the in-lock-file PID unreadable to
    /// waiters. The sidecar is never locked, so any waiter can read
    /// it. On Unix, flock is advisory and reads always work, but the
    /// sidecar still applies (uniform cross-platform contract).
    fn pid_path(base_dir: &Path, account: AccountNum) -> PathBuf {
        base_dir.join(format!(".login-{}.lock.pid", account.get()))
    }

    /// Tries to acquire the exclusive lock for `account`. Returns
    /// immediately with [`AcquireOutcome::Held`] if another process
    /// is already holding the lock — this is non-blocking by design
    /// so the CLI can render a clear error rather than appearing to
    /// hang.
    ///
    /// On success, the lock file is rewritten with the current
    /// process's PID so a concurrent attempt can identify the
    /// holder.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on filesystem errors (cannot create lock
    /// file, cannot write PID). A held lock is reported via
    /// [`AcquireOutcome::Held`], not as an error.
    pub fn acquire(base_dir: &Path, account: AccountNum) -> std::io::Result<AcquireOutcome> {
        // SEC-2.15 (unified, R1 M1): the lock lives directly in the
        // accounts root. Create AND secure it through the shared
        // fail-closed helper unconditionally — a pre-existing 0o755 root
        // is tightened here rather than left world-enumerable. Failure
        // propagates; a root that cannot be secured never receives a lock
        // (and never falls through to the OpenOptions ENOENT below).
        crate::platform::fs::ensure_private_dir_root(base_dir)
            .map_err(|e| std::io::Error::other(format!("accounts_root_refused: {e}")))?;

        let path = Self::lock_path(base_dir, account);
        let pid_path = Self::pid_path(base_dir, account);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;

        // SEC-R2-07 / UX-R2-04: secure the lock file so a same-host
        // attacker cannot read the holder PID through a world-readable
        // file. The PID itself is low-impact, but a per-account stream
        // of "csq is logging in for slot N" timing data is exactly the
        // information a side-channel attack would seek. `secure_file`
        // is best-effort — on Windows it's a no-op (ACL defaults
        // already protect owner-only) and on Unix it sets 0o600. A
        // failure here is non-fatal: the lock still works correctly,
        // the file is just at default umask.
        let _ = secure_file(&path);

        match try_lock_exclusive(&file)? {
            LockResult::Acquired => {
                // We own it. Write our PID to the sidecar `.pid` file
                // so a concurrent waiter can identify us. The sidecar
                // is decoupled from the lock file: on Windows,
                // `LockFileEx` exclusively locks the byte range and
                // blocks reads from any other handle (even within the
                // same process), so a waiter cannot read the PID from
                // the lock file directly. The sidecar avoids that
                // entirely. (On Unix, flock is advisory — reads always
                // work — but using the same sidecar keeps the contract
                // uniform.)
                let mut pid_file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&pid_path)?;
                let _ = secure_file(&pid_path);
                writeln!(pid_file, "{}", std::process::id())?;
                pid_file.flush()?;
                Ok(AcquireOutcome::Acquired(AccountLoginLock {
                    file,
                    path,
                    pid_path,
                }))
            }
            LockResult::WouldBlock => {
                // Read the PID the holder wrote to the sidecar. The
                // sidecar is never locked so the read always succeeds
                // (modulo a microsecond race between holder lock
                // acquisition and PID write — handled below as "PID
                // None" → "stale lock file" UX).
                let pid = std::fs::read_to_string(&pid_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok());
                // SEC-R2-08 / REV-R2-03: confirm the PID is alive. A
                // crashed login holder leaves a `.login-N.lock` file
                // on disk with its (now-dead) PID inside, but the OS
                // released the flock when the process exited — so any
                // FRESH attempt would actually succeed on `flock` and
                // fall through this branch. Reaching `WouldBlock` with
                // a dead PID in the sidecar is the rarer race where
                // ANOTHER concurrent acquire holds the live flock but
                // hasn't yet rewritten the sidecar with its own PID.
                // Either way, the user sees a more accurate message:
                // "stale lock file" when the sidecar contents lie about
                // the holder, "PID N — wait or kill" when the holder
                // is verifiably alive.
                let pid_alive = pid.map(pid_is_alive);
                Ok(AcquireOutcome::Held { pid, pid_alive })
            }
        }
    }

    /// Returns the path to the lock file. Useful for tests and
    /// debugging output.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for AccountLoginLock {
    fn drop(&mut self) {
        // Delete the PID sidecar BEFORE releasing the lock, so a
        // racing waiter never sees a "lock free + stale PID readable"
        // window where it would mis-attribute the next acquire to a
        // dead holder. Best-effort.
        let _ = std::fs::remove_file(&self.pid_path);
        // Clear the lock file content (legacy belt-and-braces — the
        // PID is no longer stored here, but this keeps cleanup
        // explicit). Best-effort.
        let _ = self.file.set_len(0);
        let _ = self.file.flush();

        // RELEASE THE FLOCK EXPLICITLY — do not rely on the close below.
        //
        // POSIX flock is associated with the OPEN FILE DESCRIPTION, and the
        // kernel releases it only when EVERY descriptor referring to that
        // description is closed (`flock(2)`: "the lock is released either by
        // an explicit LOCK_UN operation on any of these duplicate file
        // descriptors, or when all such file descriptors have been closed").
        // A fork from ANY thread of this process duplicates every open
        // descriptor — a sibling test spawning a subprocess, a daemon-style
        // child — so the child's inherited copy keeps the description (and
        // the lock) alive past this guard's close: until exec for a spawned
        // command (FD_CLOEXEC), or until exit for a child that never execs.
        // In that window a re-acquire sees WouldBlock with the sidecar
        // already gone — the `acquire_login_lock_succeeds_once_prior_guard_drops`
        // full-suite flake (`drop_releases_even_while_a_forked_child_holds_the_inherited_descriptor`
        // freezes the window deterministically). LOCK_UN on ANY duplicate
        // releases the lock for the whole description, which makes THIS drop
        // the release point regardless of what any child inherited.
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // G2b item 3 (rule 6): the release result is CHECKED, not
            // ignored — a silently failed unlock leaves the lock held until
            // close (and longer, if a fork inherited the description). The
            // warning carries a fixed error_kind vocabulary; the io::Error
            // itself is never formatted (`security.md` MUST-2).
            // SAFETY: `self.file` is still open here (field drop runs after
            // this body); flock(LOCK_UN) touches no memory and only releases
            // an advisory lock this description holds.
            if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) } != 0 {
                tracing::warn!(
                    error_kind = "login_lock_unlock_failed",
                    errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                    "login lock could not be released"
                );
            }
        }
        // Windows needs no explicit unlock: there is no fork(), and std's
        // File handles are non-inheritable (CreateFileW without
        // bInheritHandle), so no child can hold a duplicate of this handle.
        // LockFileEx is released by CloseHandle, driven by File::drop.
        //
        // The lock FILE IS RETAINED — the module contract above: "On
        // lock release the file is not deleted: keeping it around lets
        // the next attempt re-use the same inode and ensures the lock
        // survives filesystem races between unlink and re-open."
        // REV-R2-02 removed the file here to avoid artefacts on disk;
        // that re-opened the very race the contract names: a contender
        // that pre-opened the old inode could lock it AFTER this drop,
        // while the next acquirer created and locked a NEW inode at the
        // same path — two processes each holding "the" lock
        // (`preopened_contender_cannot_lock_after_holder_drops`). The
        // cost of retention is one cleared file per account slot
        // (secured to 0600 by `secure_file` on acquire, best-effort;
        // bounded by the slot count, not accumulative), and it is what
        // makes re-acquisition inode-stable. Do NOT unlink here;
        // explicit cleanup belongs to `force_release`.
    }
}

#[derive(Debug, PartialEq, Eq)]
enum LockResult {
    Acquired,
    WouldBlock,
}

#[cfg(unix)]
fn try_lock_exclusive(file: &File) -> std::io::Result<LockResult> {
    use std::os::unix::io::AsRawFd;
    // LOCK_EX | LOCK_NB — exclusive, non-blocking.
    let fd = file.as_raw_fd();
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        Ok(LockResult::Acquired)
    } else {
        let err = std::io::Error::last_os_error();
        // EWOULDBLOCK / EAGAIN means another process holds the
        // lock. Anything else is a real error.
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
        {
            Ok(LockResult::WouldBlock)
        } else {
            Err(err)
        }
    }
}

/// Returns true when the given OS process ID corresponds to a process
/// that is currently alive (or for which we cannot tell — fail-open on
/// the "alive" side because reporting "stale lock — reclaimed" for a
/// live holder would mislead the user into killing nothing).
///
/// SEC-R2-08 / REV-R2-03: the lock file content is plain text that
/// outlives the holder process. A crash between flock acquire and
/// flock release leaves the PID inside but the kernel has reclaimed
/// the lock — so a fresh `acquire` would actually pass `flock`. Reaching
/// the contention path means a SECOND concurrent acquirer holds the live
/// flock; we use this probe to disambiguate "the file says PID 12345
/// but that PID is dead" (stale artefact) from "PID 12345 is the active
/// holder" (real contention).
///
/// Implementation notes:
///
/// - Unix: `kill(pid, 0)` returns 0 if the signal could be delivered
///   (process exists), `ESRCH` if no such process. `EPERM` (no
///   permission to signal — different UID) means the PID is alive but
///   we cannot signal it; treat as alive. The pidfile-on-csq always
///   contains same-UID PIDs, so EPERM is unlikely in practice.
/// - Windows: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
///   pid)` returns NULL when the PID does not correspond to any
///   process; on success we call `GetExitCodeProcess` and treat
///   `STILL_ACTIVE (259)` as alive. `ERROR_ACCESS_DENIED` (PID exists
///   but is owned by a higher-privilege account) is treated as ALIVE
///   so the message never tells the user the holder is stale when it
///   may not be — fail-open on the "alive" side, matching the Unix
///   `EPERM` branch above. R3-M1 / round-4 redteam.
#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Safe-guard against truncation on platforms where pid_t is
    // narrower than u32. macOS/Linux pid_t is i32; PIDs above i32::MAX
    // are unreachable in practice but we still refuse to misinterpret
    // them as a valid query.
    let pid_signed = match i32::try_from(pid) {
        Ok(p) => p,
        Err(_) => return false,
    };
    // SAFETY: `kill` with signal 0 performs no side-effect; it only
    // checks signal-delivery permission. The pid is a value the
    // kernel will validate.
    let rc = unsafe { libc::kill(pid_signed, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => false,
        // EPERM = process exists but we lack permission to signal it.
        // Treat as alive — the holder is real, we just can't probe it.
        Some(libc::EPERM) => true,
        _ => true,
    }
}

#[cfg(windows)]
fn pid_is_alive(pid: u32) -> bool {
    // R3-M1 / round-4 redteam: real Windows liveness probe via
    // `OpenProcess` + `GetExitCodeProcess`. Previously stubbed to
    // `true`, which made the stale-lock-detection UX message lie:
    // a Windows user with a `.login-N.lock` from a crashed prior
    // process saw "PID 12345 is in progress" even when the process
    // was dead, leading them to `taskkill /F /PID 12345` only to
    // get "process not found". The real probe disambiguates so the
    // user sees the accurate "stale lock — reclaiming" message
    // instead.
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if pid == 0 {
        // PID 0 is the system idle process on Windows; never a
        // user-mode login holder.
        return false;
    }

    // SAFETY: `OpenProcess` is a documented Win32 API. A zero/NULL
    // return indicates failure (no such PID, or access denied). We
    // check the handle before any further use, and always
    // `CloseHandle` on the success path.
    //
    // windows-sys 0.52 declares `HANDLE` as `isize` (not a raw
    // pointer), so the NULL check is against the integer value 0
    // — `is_null()` is unavailable on this newtype.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle == 0 {
        // Distinguish "no such process" from "no permission to
        // query". Permission denials on a same-user lock file
        // should be rare (csq writes 0o600 / ACL owner-only) but
        // could happen if an admin process or service account
        // holds the lock. Treat ERROR_ACCESS_DENIED as ALIVE so
        // we never tell the user "stale — reclaiming" for a real
        // holder we just couldn't query — matches the Unix EPERM
        // branch.
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return code == ERROR_ACCESS_DENIED;
    }

    // STILL_ACTIVE = 259 is the canonical "process has not yet
    // exited" sentinel returned by GetExitCodeProcess. There is a
    // 1-in-2^32 false-positive risk if a real process happens to
    // exit with code 259, but every csq subprocess we care about
    // (the prior login holder) exits with 0 on success or a small
    // signal-derived code on crash — so 259 in practice means the
    // process is still running.
    const STILL_ACTIVE: u32 = 259;
    let mut exit_code: u32 = 0;
    // SAFETY: handle is non-null (checked above). exit_code is a
    // valid out-pointer. GetExitCodeProcess does not retain the
    // handle.
    let ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    // SAFETY: handle is non-null and we own it. CloseHandle is
    // idempotent w.r.t. our local pointer; we never use it again
    // after this call.
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        // GetExitCodeProcess failed for a reason we couldn't
        // anticipate. Fail-open as alive so the user-facing message
        // never falsely claims the holder is dead.
        return true;
    }
    exit_code == STILL_ACTIVE
}

/// Read the holder PID from the sidecar, if present + parseable.
fn read_holder_pid(pid_path: &Path) -> Option<u32> {
    std::fs::read_to_string(pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// The holder process's command line, for operator confirmation.
/// Unix: `ps -o command= -p <pid>` (array args, no shell — `security.md`
/// MUST-NOT-1). Windows: not resolved (returns `None`); the kill still works.
#[cfg(unix)]
fn holder_command(pid: u32) -> Option<String> {
    let out = std::process::Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let cmd = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if cmd.is_empty() {
        None
    } else {
        Some(cmd)
    }
}

#[cfg(not(unix))]
fn holder_command(_pid: u32) -> Option<String> {
    None
}

/// TOCTOU / recycled-PID guard: the holder must still look like a `csq login`
/// process before we terminate it. Unix inspects the live command line; on
/// platforms without command inspection we conservatively require only that
/// the PID is still alive (the caller already re-read the sidecar PID).
#[cfg(unix)]
fn holder_looks_like_login(pid: u32) -> bool {
    match holder_command(pid) {
        // A csq login holder's argv contains the binary ("csq") and the
        // "login" subcommand. Match loosely (path prefixes vary) but require
        // both tokens so an unrelated recycled PID is not terminated.
        Some(cmd) => {
            let lc = cmd.to_ascii_lowercase();
            lc.contains("csq") && lc.contains("login")
        }
        // Could not read the command (process vanished, or ps unavailable) —
        // fail closed: do NOT kill a PID we cannot confirm.
        None => false,
    }
}

#[cfg(not(unix))]
fn holder_looks_like_login(pid: u32) -> bool {
    pid_is_alive(pid)
}

/// Terminate `pid`: SIGTERM, then SIGKILL after a short grace if still alive.
#[cfg(unix)]
fn terminate_pid(pid: u32) {
    let pid_signed = match i32::try_from(pid) {
        Ok(p) if p > 0 => p,
        _ => return,
    };
    // SAFETY: `kill` is a documented syscall; sending SIGTERM to a PID the
    // kernel validates. No memory is touched.
    unsafe {
        libc::kill(pid_signed, libc::SIGTERM);
    }
    // Grace: poll for exit up to ~2s, then escalate.
    for _ in 0..20 {
        if !pid_is_alive(pid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // SAFETY: as above; SIGKILL is unblockable.
    unsafe {
        libc::kill(pid_signed, libc::SIGKILL);
    }
}

#[cfg(windows)]
fn terminate_pid(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    if pid == 0 {
        return;
    }
    // SAFETY: OpenProcess is a documented Win32 API; a 0 handle means failure.
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle == 0 {
        return;
    }
    // SAFETY: handle is non-null and owned; TerminateProcess does not retain it.
    unsafe {
        TerminateProcess(handle, 1);
        CloseHandle(handle);
    }
}

/// Inspect the login lock for `account` without acquiring it.
///
/// Returns `Ok(None)` when no lock file (or sidecar) exists, and
/// `Ok(Some(holder))` describing the current holder otherwise — whether or not
/// a live process holds it. Read-only; safe to call while another process holds
/// the lock. Powers `csq unlock N`'s "here is what is holding it" display.
///
/// Operator-semantics note (retained-file contract): because the lock file is
/// RETAINED across `Drop`, a slot whose login flow ever reached `acquire`
/// keeps a cleared `.login-N.lock` on disk (retained on every release —
/// success, failure, and abort), so a later call normally returns
/// `Some(holder)` with `pid = None` and `alive = None` even though no process
/// holds the lock. `csq unlock N`'s current rendering for that state is the
/// "(stale)" arm — accurate for "no live holder", but it is the steady state,
/// not evidence of a crashed login. The wording is deliberately NOT changed in
/// this fix.
pub fn inspect_lock(base_dir: &Path, account: AccountNum) -> std::io::Result<Option<LockHolder>> {
    let lock_path = AccountLoginLock::lock_path(base_dir, account);
    let pid_path = AccountLoginLock::pid_path(base_dir, account);
    if !lock_path.exists() && !pid_path.exists() {
        return Ok(None);
    }
    let pid = read_holder_pid(&pid_path);
    let alive = pid.map(pid_is_alive);
    let command = pid.and_then(holder_command);
    Ok(Some(LockHolder {
        pid,
        alive,
        command,
    }))
}

/// Force-release the login lock for `account`.
///
/// When `kill` is true and a LIVE holder exists, terminates it (SIGTERM →
/// SIGKILL) then removes the lock files. TOCTOU-guarded: the sidecar PID is
/// re-read immediately before killing AND the holder is re-confirmed to look
/// like a `csq login` process (Unix), so a PID recycled between inspect and
/// kill is never terminated. Ordering is kill → wait-for-exit → unlink, so a
/// new acquirer cannot pin a fresh lock file behind a still-dying holder's
/// flock.
///
/// Callers (`csq unlock`, the desktop force-release command) MUST gate this
/// behind an operator confirmation showing [`inspect_lock`]'s holder — this
/// function does not prompt.
pub fn force_release(
    base_dir: &Path,
    account: AccountNum,
    kill: bool,
) -> std::io::Result<ForceReleaseReport> {
    let lock_path = AccountLoginLock::lock_path(base_dir, account);
    let pid_path = AccountLoginLock::pid_path(base_dir, account);
    let mut report = ForceReleaseReport {
        had_lock: false,
        killed_pid: None,
        removed_files: Vec::new(),
    };
    if !lock_path.exists() && !pid_path.exists() {
        return Ok(report);
    }
    report.had_lock = true;

    if kill {
        // Re-read the PID at the last moment (TOCTOU): the holder may have
        // exited between an earlier inspect_lock and now, and its PID may have
        // been recycled. Only terminate a PID that is (a) not us, (b) still
        // alive, AND (c) still looks like a csq login process.
        if let Some(pid) = read_holder_pid(&pid_path) {
            if pid != std::process::id() && pid_is_alive(pid) && holder_looks_like_login(pid) {
                terminate_pid(pid);
                report.killed_pid = Some(pid);
            }
        }
    }

    // Remove the lock files AFTER the holder is dead. Sidecar first, then the
    // lock file itself. NotFound is fine (concurrent Drop cleanup may race us).
    for p in [&pid_path, &lock_path] {
        match std::fs::remove_file(p) {
            Ok(()) => report.removed_files.push(p.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(report)
}

#[cfg(windows)]
fn try_lock_exclusive(file: &File) -> std::io::Result<LockResult> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, ERROR_LOCK_VIOLATION};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ok != 0 {
        Ok(LockResult::Acquired)
    } else {
        let err = std::io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0) as u32;
        if code == ERROR_LOCK_VIOLATION || code == ERROR_IO_PENDING {
            Ok(LockResult::WouldBlock)
        } else {
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    fn account(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    /// R2 H1 regression: the documented symlinked accounts root works
    /// through the login-lock path — the strict refusal would have broken
    /// every login on such a setup. RED on the pre-R3 bytes.
    #[cfg(unix)]
    #[test]
    fn acquire_accepts_symlinked_accounts_root() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("external");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("accounts");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let guard = reacquire_expect_acquired(&link, account(1), "symlinked-root acquire");
        drop(guard);

        assert_eq!(
            std::fs::symlink_metadata(&target)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the resolved accounts root must be secured by acquire"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the operator's symlink must be intact"
        );
    }

    /// Bounded retry wrapper for RE-acquisition after a drop.
    ///
    /// A sibling test's `Command::spawn` forks, duplicating this process's
    /// open file descriptors, and CLOEXEC closes them only at the child's
    /// exec. If a drop+re-acquire lands inside that fork→exec gap, the
    /// dropped guard's DESCRIPTION (not any fd we can see: measured on the
    /// flake — pid=None, no in-process fd, no /proc/locks entry by the time
    /// a probe runs) still holds the flock, so the fresh attempt transiently
    /// reports `Held`. The property under test is "a fresh acquire succeeds
    /// once no descriptor remains", so the transient `Held` is retried
    /// rather than misread. A deadline miss is still a FAILURE, and a real
    /// release regression never recovers, so it cannot hide here.
    fn reacquire_expect_acquired(dir: &Path, account: AccountNum, what: &str) -> AccountLoginLock {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match AccountLoginLock::acquire(dir, account).unwrap() {
                AcquireOutcome::Acquired(g) => return g,
                AcquireOutcome::Held { pid, pid_alive } => {
                    if std::time::Instant::now() >= deadline {
                        panic!(
                            "{what}: still Held (pid={pid:?}, alive={pid_alive:?}) 5s after drop"
                        );
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }

    // ── Cross-process contention (an internal ticket) ───────────────────────────────
    //
    // The property that matters is CROSS-PROCESS mutual exclusion: two
    // `csq login 7` invocations racing. A same-process second acquire is the
    // wrong instrument — it exercises handle semantics, not the user-facing
    // guarantee — and it is why the Windows path had no coverage at all: the
    // same-process test is `#[cfg(unix)]` because POSIX `flock` and Windows
    // `LockFileEx` differ on same-process reacquire, a difference that has no
    // bearing on whether two SEPARATE logins exclude each other.
    //
    // These two tests run on BOTH platforms from one code path, so the
    // guarantee is stated once and each CI target proves it. NOTE the
    // `windows-latest` job is NOT a required check in the `main — required CI
    // (no bypass)` ruleset, so a green merge does not imply this passed there —
    // read the run.

    /// Env var naming the lock directory the helper below should hold.
    const HOLD_DIR_ENV: &str = "CSQ_TEST_LOGIN_LOCK_HOLD_DIR";

    /// Env var naming the lock directory a PRE-OPENED-contender child should
    /// work in (the retained-inode regression below).
    const CONTENDER_DIR_ENV: &str = "CSQ_TEST_LOGIN_LOCK_CONTENDER_DIR";

    /// Child-process role: acquire the lock, announce readiness by writing our
    /// PID to `ready`, then hold it until `stop` appears.
    ///
    /// This is a `#[test]` so the parent can re-invoke this same test binary
    /// with `--exact` and reach it — the standard way to get a second PROCESS
    /// without shipping a helper binary. With `HOLD_DIR_ENV` unset it returns
    /// immediately, so it is a no-op in an ordinary suite run and cannot
    /// recurse (the child runs only this test, which never spawns).
    #[test]
    fn cross_process_lock_holder_helper() {
        let Ok(dir) = std::env::var(HOLD_DIR_ENV) else {
            return; // not the child — nothing to do
        };
        let dir = std::path::PathBuf::from(dir);
        let guard = match AccountLoginLock::acquire(&dir, account(7)) {
            Ok(AcquireOutcome::Acquired(g)) => g,
            other => panic!("helper must acquire the lock, got {other:?}"),
        };
        // Write-then-rename so `ready` appears COMPLETE in one step. A plain
        // `fs::write` creates the file before filling it, and the parent polls
        // for existence: on windows-latest it read the file in that window and
        // parsed an empty pid (`ParseIntError { kind: Empty }`).
        let tmp = dir.join("ready.tmp");
        std::fs::write(&tmp, format!("{}\n", std::process::id())).expect("helper writes ready.tmp");
        std::fs::rename(&tmp, dir.join("ready")).expect("helper publishes ready");

        // Bounded hold: if the parent dies without writing `stop`, exit rather
        // than wedge a CI job forever.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !dir.join("stop").exists() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        drop(guard);
    }

    #[test]
    fn cross_process_acquire_reports_the_live_holder_pid() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        let exe = std::env::current_exe().expect("test binary path");
        let mut cmd = std::process::Command::new(exe);
        // `env_clear` + whitelist per testing.md Rule 4a. The Windows-essential
        // vars are listed unconditionally — absent on Unix, so the `if let Ok`
        // simply skips them there, and REQUIRED on windows-latest for the child
        // to start at all.
        cmd.env_clear();
        for k in [
            "HOME",
            "PATH",
            "LANG",
            "LC_ALL",
            "TERM",
            "USER",
            "TMPDIR",
            "SYSTEMROOT",
            "SystemRoot",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        let mut child = cmd
            .env(HOLD_DIR_ENV, &dir)
            .args([
                "--exact",
                "accounts::login_lock::tests::cross_process_lock_holder_helper",
                "--nocapture",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the holder child");

        // Wait for the child to actually hold the lock. Bounded, and a timeout
        // is a FAILURE rather than a skip — a skip keyed on what the system
        // returned would turn a real regression green (test-skip-discipline).
        let ready = dir.join("ready");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !ready.exists() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        let holder_pid: u32 = if ready.exists() {
            std::fs::read_to_string(&ready)
                .expect("read ready")
                .trim()
                .parse()
                .expect("ready holds a pid")
        } else {
            let _ = child.kill();
            panic!("holder child never acquired the lock within 20s");
        };
        assert_eq!(
            holder_pid,
            child.id(),
            "the announced holder pid must be the child we spawned"
        );

        // THE ASSERTION. A second process must be refused, and must be told who
        // holds it and that the holder is alive.
        let outcome = AccountLoginLock::acquire(&dir, account(7)).expect("acquire returns");
        let result = match outcome {
            AcquireOutcome::Held { pid, pid_alive } => Ok((pid, pid_alive)),
            AcquireOutcome::Acquired(_) => Err("second PROCESS acquired a held lock"),
        };

        // Release the child before asserting, so a failure cannot leave it
        // holding the lock for its full 30s and slow the rest of the suite.
        std::fs::write(dir.join("stop"), b"1").ok();
        let _ = child.wait();

        let (pid, pid_alive) = result.expect("mutual exclusion across processes");
        assert_eq!(
            pid,
            Some(holder_pid),
            "the refusal must name the holding process"
        );
        assert_eq!(
            pid_alive,
            Some(true),
            "a live cross-process holder must be reported alive"
        );
    }

    /// Child-process role for the retained-inode regression: PRE-OPEN the
    /// lock file the parent currently holds, announce readiness, wait for the
    /// parent's `go`, then attempt a non-blocking exclusive lock on the
    /// still-open handle and record the outcome in `result`. With the file
    /// retained across the parent's release+re-acquire this stays WouldBlock
    /// (same file, new lock); if the old holder's Drop unlinked the file, the
    /// parent's re-acquire creates a NEW inode and this handle locks the
    /// orphaned OLD one — Acquired, i.e. two simultaneous holders.
    ///
    /// Cross-PROCESS by design (both platforms, one code path), mirroring the
    /// an internal ticket pair above: a same-process second handle exercises handle
    /// semantics, not the user-facing guarantee. With `CONTENDER_DIR_ENV`
    /// unset it returns immediately, so it is a no-op in an ordinary run.
    #[test]
    fn preopened_contender_helper() {
        let Ok(dir) = std::env::var(CONTENDER_DIR_ENV) else {
            return; // not the child — nothing to do
        };
        let dir = std::path::PathBuf::from(dir);
        let path = AccountLoginLock::lock_path(&dir, account(7));

        // Pre-open the live lock file the parent holds (no create — the
        // parent already made it; a miss means the spawn ordering broke).
        let handle = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("contender must pre-open the live lock file");
        std::fs::write(dir.join("ready"), std::process::id().to_string()).expect("write ready");

        let go = dir.join("go");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !go.exists() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        if !go.exists() {
            panic!("contender never saw 'go' within 20s");
        }

        let result = match try_lock_exclusive(&handle) {
            Ok(LockResult::Acquired) => "Acquired".to_string(),
            Ok(LockResult::WouldBlock) => "WouldBlock".to_string(),
            Err(e) => format!("Err:{e}"),
        };
        std::fs::write(dir.join("result"), result).expect("write result");
    }

    /// THE ASSERTION for the retained-inode contract, cross-process and
    /// cross-platform: a contender that pre-opened the lock file must remain
    /// blocked after the original holder releases and a fresh holder
    /// re-acquires. Falsifier: Drop unlinks the lock file; the fresh holder
    /// then locks a NEW inode while the pre-opened contender locks the
    /// orphaned old one (result file says "Acquired").
    #[test]
    fn preopened_cross_process_contender_stays_blocked_after_reacquire() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();

        let guard1 = match AccountLoginLock::acquire(&dir, account(7)).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!("first acquire must succeed"),
        };

        let exe = std::env::current_exe().expect("test binary path");
        let mut cmd = std::process::Command::new(exe);
        cmd.env_clear();
        for k in [
            "HOME",
            "PATH",
            "LANG",
            "LC_ALL",
            "TERM",
            "USER",
            "TMPDIR",
            "SYSTEMROOT",
            "SystemRoot",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "NUMBER_OF_PROCESSORS",
        ] {
            if let Ok(v) = std::env::var(k) {
                cmd.env(k, v);
            }
        }
        let mut child = cmd
            .env(CONTENDER_DIR_ENV, &dir)
            .args([
                "--exact",
                "accounts::login_lock::tests::preopened_contender_helper",
                "--nocapture",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the contender child");

        // Wait for the child's pre-open. Bounded; a timeout is a FAILURE
        // rather than a skip (test-skip-discipline).
        let ready = dir.join("ready");
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !ready.exists() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        if !ready.exists() {
            let _ = child.kill();
            panic!("contender child never pre-opened the lock file within 20s");
        }

        // The holder releases; a fresh holder re-acquires BY PATH.
        drop(guard1);
        let guard2 =
            reacquire_expect_acquired(&dir, account(7), "cross-process contender reacquire");

        // Release the child to make its attempt.
        std::fs::write(dir.join("go"), b"1").ok();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut status = None;
        while status.is_none() && std::time::Instant::now() < deadline {
            status = child.try_wait().expect("try_wait");
            if status.is_none() {
                thread::sleep(Duration::from_millis(25));
            }
        }
        let status = match status {
            Some(s) => s,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("contender child did not exit within 10s of 'go'");
            }
        };

        let result = std::fs::read_to_string(dir.join("result"))
            .expect("contender must write its lock result");
        assert_eq!(
            result.trim(),
            "WouldBlock",
            "pre-opened contender acquired the retired lock — Drop unlinked the file \
             (two simultaneous holders); child exit={status:?}"
        );
        drop(guard2);
    }

    #[test]
    fn handle_race_acquires_exclusive_lock_for_account() {
        // Successful acquire returns Acquired with a guard that
        // points at the right path.
        let dir = TempDir::new().unwrap();
        let result = AccountLoginLock::acquire(dir.path(), account(5)).unwrap();
        match result {
            AcquireOutcome::Acquired(guard) => {
                let expected = dir.path().join(".login-5.lock");
                assert_eq!(guard.path(), &expected);
                assert!(guard.path().exists());
            }
            AcquireOutcome::Held { .. } => {
                panic!("first acquire on a fresh dir must succeed")
            }
        }
    }

    #[test]
    fn inspect_lock_none_when_no_lock_file() {
        let dir = TempDir::new().unwrap();
        assert!(inspect_lock(dir.path(), account(3)).unwrap().is_none());
    }

    #[test]
    fn inspect_lock_reports_live_current_holder() {
        let dir = TempDir::new().unwrap();
        let _guard = match AccountLoginLock::acquire(dir.path(), account(3)).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("fresh acquire must succeed"),
        };
        let holder = inspect_lock(dir.path(), account(3))
            .unwrap()
            .expect("lock is held → Some");
        assert_eq!(holder.pid, Some(std::process::id()));
        assert_eq!(holder.alive, Some(true));
    }

    #[test]
    fn force_release_reports_no_lock_when_absent() {
        let dir = TempDir::new().unwrap();
        let report = force_release(dir.path(), account(3), true).unwrap();
        assert!(!report.had_lock);
        assert!(report.killed_pid.is_none());
        assert!(report.removed_files.is_empty());
    }

    #[test]
    fn force_release_removes_files_without_kill() {
        let dir = TempDir::new().unwrap();
        let guard = match AccountLoginLock::acquire(dir.path(), account(3)).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            AcquireOutcome::Held { .. } => panic!("fresh acquire must succeed"),
        };
        // Hold the guard (this process owns the flock); force_release(kill=false)
        // must still unlink the on-disk files without touching us.
        let report = force_release(dir.path(), account(3), false).unwrap();
        assert!(report.had_lock);
        assert!(report.killed_pid.is_none(), "kill=false must not terminate");
        assert_eq!(report.removed_files.len(), 2, "sidecar + lock file removed");
        assert!(!AccountLoginLock::lock_path(dir.path(), account(3)).exists());
        drop(guard);
    }

    #[test]
    #[cfg(unix)]
    fn force_release_kill_skips_dead_holder() {
        // A sidecar naming a guaranteed-dead PID must NOT be killed (the process
        // is gone / recycled-unknown); the stale files are still cleared.
        let dir = TempDir::new().unwrap();
        // A PID guaranteed never to name a live process: i32::MAX exceeds the
        // kernel PID ceiling (`/proc/sys/kernel/pid_max` ≤ 2^22 on Linux; macOS
        // similar), so `pid_is_alive` (kill(pid,0) → ESRCH) always reads it as
        // dead — the exact code path this test exercises. Deterministic and
        // hermetic: the prior `Command::new("true").spawn()` depended on $PATH
        // and hit `ENOENT` on a CI runner whose PATH lacked coreutils (a
        // non-hermetic bare-name spawn; see feedback_find_claude_binary +
        // test-hermeticity). No external binary, no fork, no reap-recycle race.
        let dead_pid: u32 = i32::MAX as u32;

        // Fabricate the on-disk lock state pointing at the dead PID.
        std::fs::write(AccountLoginLock::lock_path(dir.path(), account(7)), b"").unwrap();
        std::fs::write(
            AccountLoginLock::pid_path(dir.path(), account(7)),
            format!("{dead_pid}\n"),
        )
        .unwrap();

        let report = force_release(dir.path(), account(7), true).unwrap();
        assert!(report.had_lock);
        assert!(
            report.killed_pid.is_none(),
            "a dead holder PID must not be reported as killed"
        );
        assert_eq!(report.removed_files.len(), 2);
        assert!(!AccountLoginLock::pid_path(dir.path(), account(7)).exists());
    }

    #[test]
    #[cfg(unix)]
    fn handle_race_returns_clear_error_when_lock_held() {
        // Hold the lock in a separate thread; second acquire must
        // return Held with the holder's PID.
        //
        // POSIX-only: this test exercises BSD `flock` semantics where
        // two opens of the same file from the same process get
        // separate file descriptions and so respect each other's
        // advisory locks. Windows `LockFileEx` returns success for
        // both acquires from the same process — so the second
        // acquire reads back its OWN write rather than the first
        // holder's PID, and `pid` is None at line 454. The Windows
        // reacquire semantics differ, which is why this test is Unix-only.
        //
        // That difference does NOT matter to the user-facing guarantee, and
        // the coverage question it used to stand in for is now answered
        // properly by `cross_process_acquire_reports_the_live_holder_pid`
        // below, which runs on BOTH platforms and asserts what actually
        // matters: a second PROCESS is refused and told who holds the lock.
        //
        // History, because the previous note was wrong twice over (an internal ticket): it
        // claimed a Job-Object integration test covered this path, and cited
        // milestone id M8-03 as where that work lived. No such test existed
        // anywhere in the tree, and that id resolves only to a COMPLETED
        // an internal workspace todo. It also reasoned that on Windows both same-process
        // acquires succeed AND the second returns `Held` with `pid: None` —
        // which cannot both hold, since a successful `try_lock_exclusive`
        // takes the `Acquired` branch and never reaches a `Held` arm at all.
        // Do not restore either claim.
        //
        // The retracted sentence is PARAPHRASED above, deliberately not quoted.
        // `scripts/verify/milestone-refs.sh` fires when deferral vocabulary and
        // a milestone id co-occur on one line, so quoting the false claim
        // verbatim makes this retraction flag ITSELF. The fix is to paraphrase;
        // teaching the gate an exception would blind it to the real thing.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let first = AccountLoginLock::acquire(&dir_path, account(7)).unwrap();
        match first {
            AcquireOutcome::Acquired(_) => {}
            _ => panic!("first acquire must succeed"),
        }

        let second = AccountLoginLock::acquire(&dir_path, account(7)).unwrap();
        match second {
            AcquireOutcome::Held { pid, pid_alive } => {
                let pid = pid.expect("holder should have written a PID");
                assert_eq!(
                    pid,
                    std::process::id(),
                    "lock file should contain the holder's PID"
                );
                // SEC-R2-08 / R3-M1: the holder is THIS process, which
                // is by definition alive at this assertion. Both Unix
                // (`kill(pid, 0)`) and Windows (`OpenProcess` +
                // `GetExitCodeProcess` per round-4 redteam) return
                // Some(true) for a live holder.
                assert_eq!(pid_alive, Some(true), "live holder must be reported alive");
            }
            AcquireOutcome::Acquired(_) => {
                panic!("second acquire must report Held while first guard is alive")
            }
        }
    }

    #[test]
    fn lock_released_after_handle_race_returns() {
        // Drop the guard, then acquire again — must succeed.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let first = AccountLoginLock::acquire(&dir_path, account(3)).unwrap();
        match first {
            AcquireOutcome::Acquired(guard) => drop(guard),
            _ => panic!("first acquire must succeed"),
        }

        // After drop, a second acquire must succeed (bounded retry — a
        // sibling test's fork/exec spawn can briefly keep the dropped
        // guard's open file description, and thus the flock, alive in the
        // forked child; see `reacquire_expect_acquired`).
        let _second = reacquire_expect_acquired(&dir_path, account(3), "drop-then-reacquire");
    }

    #[test]
    fn lock_released_after_handle_race_panics() {
        // Even if the holder's thread panics, the OS releases the
        // lock when the process exits — but since we're testing
        // within ONE process here, we use a thread to simulate the
        // panic boundary. The thread's File handles get closed
        // when the thread unwinds and drops local owners, which
        // releases the flock.
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let (tx, rx) = mpsc::channel::<()>();
        let dir_for_thread = dir_path.clone();
        let handle = thread::spawn(move || {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                let acquired = AccountLoginLock::acquire(&dir_for_thread, account(9)).unwrap();
                match acquired {
                    AcquireOutcome::Acquired(_guard) => {
                        // Notify the main thread that we're holding the lock.
                        tx.send(()).unwrap();
                        // Panic while holding the lock.
                        panic!("simulated panic while holding lock");
                    }
                    _ => unreachable!(),
                }
            }));
        });

        // Wait for the thread to acquire.
        rx.recv_timeout(Duration::from_secs(2))
            .expect("thread should have acquired the lock");
        // Wait for the panic-and-unwind to complete so the File
        // (and thus the flock) is fully released.
        let _ = handle.join();

        // Now we should be able to acquire (bounded retry — see
        // `reacquire_expect_acquired` for the transient-fork-copy artifact).
        let _after = reacquire_expect_acquired(&dir_path, account(9), "panic-then-reacquire");
    }

    #[test]
    fn distinct_accounts_have_independent_locks() {
        // Holding the lock for account 1 must not block account 2.
        let dir = TempDir::new().unwrap();
        let dir_path = dir.path().to_path_buf();

        let g1 = AccountLoginLock::acquire(&dir_path, account(1)).unwrap();
        let g2 = AccountLoginLock::acquire(&dir_path, account(2)).unwrap();

        assert!(matches!(g1, AcquireOutcome::Acquired(_)));
        assert!(matches!(g2, AcquireOutcome::Acquired(_)));
    }

    #[test]
    fn lock_path_uses_account_number() {
        let dir = TempDir::new().unwrap();
        let path = AccountLoginLock::lock_path(dir.path(), account(42));
        assert_eq!(path, dir.path().join(".login-42.lock"));
    }

    // ── SEC-R2-07 / UX-R2-04: lock file is chmod 0600 on Unix ──────

    #[cfg(unix)]
    #[test]
    fn lock_file_is_chmod_0600_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let _guard = match AccountLoginLock::acquire(dir.path(), account(11)).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!("first acquire must succeed"),
        };

        let path = dir.path().join(".login-11.lock");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "lock file must be chmod 0600 to prevent same-host PID disclosure: got 0o{:o}",
            mode
        );
    }

    // ── Retained-file contract across Drop (REV-R2-02 retracted): the lock
    // file is NOT deleted on release. Retention keeps the inode stable so a
    // pre-opened contender cannot lock a dead inode while a fresh acquirer
    // locks a new one; explicit cleanup belongs to `force_release`.

    #[test]
    fn lock_file_persists_across_drop_and_reacquire() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".login-13.lock");
        let pid_path = dir.path().join(".login-13.lock.pid");

        let guard = match AccountLoginLock::acquire(dir.path(), account(13)).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!("first acquire must succeed"),
        };
        assert!(path.exists(), "lock file must exist while guard is alive");
        assert!(pid_path.exists(), "sidecar must exist while guard is alive");
        drop(guard);

        assert!(
            path.exists(),
            "lock file MUST be retained after guard drops (inode-identity contract): {:?}",
            path
        );
        assert!(
            !pid_path.exists(),
            "sidecar MUST be removed on drop so no stale PID is readable: {:?}",
            pid_path
        );

        // Re-acquiring takes the SAME retained path and works normally; a
        // second drop again retains the file.
        let guard2 = reacquire_expect_acquired(dir.path(), account(13), "retained-file reacquire");
        drop(guard2);
        assert!(
            path.exists(),
            "lock file retained across a second drop too: {:?}",
            path
        );
    }

    /// The deterministic two-holder race the retention contract prevents:
    /// a contender PRE-OPENS the lock file while holder 1 is live; holder 1
    /// drops; holder 2 acquires by path. If Drop unlinks the file, holder 2
    /// locks a NEW inode while the pre-opened contender can still lock the
    /// OLD one — two simultaneous "holders". With retention, both handles
    /// refer to the SAME inode, so the contender must stay WouldBlock.
    #[cfg(unix)]
    #[test]
    fn preopened_contender_cannot_lock_after_holder_drops() {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".login-21.lock");

        let guard1 = match AccountLoginLock::acquire(dir.path(), account(21)).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!("first acquire must succeed"),
        };
        // Contender pre-opens the lock file while guard1 holds the flock.
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("contender must open the live lock file");
        let ino_held = std::fs::metadata(&path).unwrap().ino();
        drop(guard1);

        // Fresh acquirer takes the lock BY PATH, as the CLI does.
        let guard2 = reacquire_expect_acquired(dir.path(), account(21), "inode-identity reacquire");
        let ino_now = std::fs::metadata(&path).unwrap().ino();
        assert_eq!(
            ino_held, ino_now,
            "acquire must reuse the RETAINED inode; an inode swap means Drop unlinked the file"
        );

        let res = try_lock_exclusive(&contender).unwrap();
        assert_eq!(
            res,
            LockResult::WouldBlock,
            "pre-opened contender acquired the retired inode — Drop unlinked the lock file \
             (two simultaneous holders)"
        );
        drop(guard2);
    }

    /// Dropping the holder MUST release the flock even while ANOTHER
    /// descriptor to the same open file description is still open.
    ///
    /// POSIX flock is associated with the open file description, and the
    /// kernel releases it only when EVERY descriptor referring to that
    /// description is closed — the holder's own `File::drop` is NOT the
    /// release point while a duplicate exists. A `fork` from ANY thread of
    /// this process (a sibling test spawning a subprocess; a daemon-style
    /// child) duplicates every open descriptor, including this lock fd,
    /// and keeps the description (and the lock) alive until the child
    /// closes it — at exec for a spawned command (`FD_CLOEXEC`), or at
    /// exit for a child that never execs. That window is the
    /// `acquire_login_lock_succeeds_once_prior_guard_drops` flake: the
    /// holder drops, but the immediate re-acquire still sees `WouldBlock`.
    ///
    /// This test freezes a forked child in place (a blocking pipe read, no
    /// exec) so the inheritance window is deterministic rather than
    /// scheduler-dependent, and asserts the guard's drop IS the release
    /// point. It is RED on a Drop that relies on close-alone (the child
    /// still holds the description) and GREEN once Drop releases the lock
    /// explicitly.
    #[cfg(unix)]
    #[test]
    fn drop_releases_even_while_a_forked_child_holds_the_inherited_descriptor() {
        let dir = TempDir::new().unwrap();
        let account = account(31);

        let guard = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            other => panic!("first acquire must succeed, got {other:?}"),
        };

        // The production exposure of an EXEC'd child is bounded by
        // FD_CLOEXEC: exec closes the inherited copy. Assert the flag so
        // the mechanism this test models stays documented and true (Rust's
        // OpenOptions sets it); the unbounded case is a child that never
        // execs, which the fork below models.
        {
            use std::os::unix::io::AsRawFd;
            // SAFETY: F_GETFD only reads descriptor flags; no memory access.
            let flags = unsafe { libc::fcntl(guard.file.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(flags, -1, "F_GETFD on the lock fd failed");
            assert_ne!(
                flags & libc::FD_CLOEXEC,
                0,
                "the lock fd must be close-on-exec; otherwise an exec'd child would hold the \
                 flock for its whole lifetime"
            );
        }

        // Fork a child that holds its inherited duplicate. The shared
        // harness is leak-proof: the child closes the pipe's write end
        // before blocking (a dead parent delivers EOF, never an orphan),
        // arms an alarm backstop, and the parent's wake+reap is RAII, so a
        // panic between here and the normal path still releases it.
        let child = crate::fork_harness::ForkedChild::spawn();

        // Release the guard while the child still holds its inherited copy.
        drop(guard);

        match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(second) => drop(second),
            AcquireOutcome::Held { .. } => panic!(
                "dropping the holder must release the lock even while a forked child \
                 holds the inherited descriptor — an inherited duplicate kept the flock \
                 alive past the holder's close (the full-suite login-lock flake)"
            ),
        }
        drop(child);
    }

    /// A panic between the fork and the normal release path MUST NOT leave
    /// the forked child alive holding the harness's descriptors — the
    /// fleet-offline leak class. The shared harness's RAII release runs
    /// during unwinding, so the child is woken and reaped; this test pins
    /// that contract against a future rewrite that drops the guard.
    #[cfg(unix)]
    #[test]
    fn a_panic_after_the_fork_still_reaps_the_child() {
        use std::sync::atomic::{AtomicI32, Ordering};
        use std::sync::Arc;

        let dir = TempDir::new().unwrap();
        let account = account(32);
        let guard = match AccountLoginLock::acquire(dir.path(), account).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            other => panic!("first acquire must succeed, got {other:?}"),
        };

        let recorded = Arc::new(AtomicI32::new(-1));
        let slot = Arc::clone(&recorded);
        // The default panic hook prints the injected panic to stderr. That
        // noise IS the mechanism; the hook is deliberately not swapped,
        // because the harness runs tests in parallel threads.
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let child = crate::fork_harness::ForkedChild::spawn();
            slot.store(child.pid(), Ordering::SeqCst);
            drop(guard);
            panic!("injected after the fork");
        }));
        assert!(panicked.is_err(), "the injected panic must unwind");

        let pid = recorded.load(Ordering::SeqCst);
        assert!(pid > 0, "the child pid must have been recorded");
        assert!(
            !pid_is_alive(pid as u32),
            "a panic between fork and release orphaned the forked child (pid {pid})"
        );
    }

    // ── SEC-R2-08 / REV-R2-03: dead PID in lock file → stale ───────

    #[cfg(unix)]
    #[test]
    fn dead_pid_in_lock_file_produces_stale_lock_message() {
        // Manually pre-populate a lock file with a known-dead PID,
        // then force a contention by holding the lock from a thread.
        // The Held-branch must report `pid_alive: Some(false)` for
        // the stale PID written into the file, even though the
        // ACTUAL holder is the live thread (the file content lies
        // about who's holding because we wrote it manually before
        // the thread acquired). The point: the caller's render path
        // sees the file content as the source of truth for the PID,
        // and SEC-R2-08 lets it disambiguate "stale" from "live".
        //
        // In production this case is reached when a prior crash left
        // the file with a dead PID and a NEW concurrent acquirer
        // holds the live flock but hasn't yet truncated the old PID
        // out. We simulate that ordering by writing the dead PID,
        // acquiring the live lock, then probing.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".login-29.lock");

        // Pick a PID that is guaranteed dead. PID 1 is init, almost
        // certainly alive, so we can't use it as a "dead PID". Use
        // a value well above any PID a sandbox would hand out: u32
        // wrap-around space is huge, and `kill(0xDEAD_BEEF, 0)`
        // will return ESRCH on every supported OS.
        let dead_pid: u32 = 0xDEAD_BEEF;
        // Sanity-check: must actually be reported dead by our probe
        // before we use it as the stale-PID fixture.
        assert!(
            !pid_is_alive(dead_pid),
            "test fixture PID {dead_pid} must be reported dead"
        );

        // Write the stale PID into a fresh lock file. Don't acquire
        // through the public API — just seed the bytes.
        std::fs::write(&path, format!("{dead_pid}\n")).unwrap();

        // Now hold the live lock from a thread so the next acquire
        // hits the contention path. We use a barrier-via-channel so
        // the thread has acquired BEFORE we attempt the second
        // acquire.
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let dir_for_thread = dir.path().to_path_buf();
        let handle = thread::spawn(move || {
            let g = AccountLoginLock::acquire(&dir_for_thread, account(29)).unwrap();
            // Clobber the SIDECAR `.lock.pid` file with the dead PID
            // so the contender reads "stale" content. Production hits
            // this when the live holder hasn't yet written its PID to
            // the sidecar (microsecond race after lock acquisition).
            // We simulate by overwriting the sidecar with a known-dead
            // PID value.
            std::fs::write(
                dir_for_thread.join(".login-29.lock.pid"),
                format!("{dead_pid}\n"),
            )
            .unwrap();
            ready_tx.send(()).unwrap();
            // Hold until the main thread says we can release.
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
            drop(g);
        });

        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("holder thread should have signalled ready");

        // Contend.
        let outcome = AccountLoginLock::acquire(dir.path(), account(29)).unwrap();
        match outcome {
            AcquireOutcome::Held { pid, pid_alive } => {
                assert_eq!(pid, Some(dead_pid), "should have read the stale PID");
                assert_eq!(
                    pid_alive,
                    Some(false),
                    "stale PID must be reported as dead so the caller can render \
                     a 'stale lock file' message instead of pointing at a dead PID"
                );
            }
            AcquireOutcome::Acquired(_) => panic!("expected contention, got acquired"),
        }

        // Release the holder so the test cleans up.
        let _ = release_tx.send(());
        let _ = handle.join();
    }

    // ── pid_is_alive sanity: this process is alive ────────────────

    #[cfg(unix)]
    #[test]
    fn pid_is_alive_returns_true_for_self() {
        assert!(
            pid_is_alive(std::process::id()),
            "pid_is_alive(self) MUST return true — defines the predicate"
        );
    }

    #[cfg(unix)]
    #[test]
    fn pid_is_alive_returns_false_for_zero_pid() {
        // PID 0 is the kernel scheduler placeholder; `kill(0, 0)`
        // semantics are "send signal 0 to every process in this
        // process group" which is meaningless as a liveness probe.
        // Treat as dead.
        assert!(!pid_is_alive(0));
    }

    // ── R3-M1 / round-4 redteam: Windows liveness probe ──────────

    #[cfg(windows)]
    #[test]
    fn pid_is_alive_returns_true_for_self_windows() {
        // The current process is by definition alive. The Windows
        // `OpenProcess` + `GetExitCodeProcess` path must agree.
        // Pre-R3-M1 this was a `true`-return stub; the assertion is
        // unchanged from the Unix sibling because the contract is
        // platform-uniform.
        assert!(
            pid_is_alive(std::process::id()),
            "pid_is_alive(self) MUST return true on Windows (R3-M1)"
        );
    }

    #[cfg(windows)]
    #[test]
    fn pid_is_alive_returns_false_for_non_existent_pid_windows() {
        // Pick a PID that is overwhelmingly unlikely to be assigned:
        // `OpenProcess` returns NULL with last-error
        // `ERROR_INVALID_PARAMETER` for a non-existent PID. We must
        // observe `false` (not the legacy `true` stub) so the
        // stale-lock UX message correctly reports "reclaimable" when
        // the prior holder crashed.
        //
        // Production-equivalent: a `.login-N.lock` left behind by a
        // crashed prior holder. The kernel released the flock at
        // process exit, but the file content still names the dead
        // PID — without R3-M1 the user would see "PID 0xDEAD_BEEF
        // is in progress" and run a futile `taskkill`.
        let dead_pid: u32 = 0xDEAD_BEEF;
        assert!(
            !pid_is_alive(dead_pid),
            "pid_is_alive must return false for a non-existent PID on Windows \
             (R3-M1 — pre-fix this was a true-stub)"
        );
    }

    #[cfg(windows)]
    #[test]
    fn pid_is_alive_returns_false_for_zero_pid_windows() {
        // PID 0 is the system idle process on Windows; the function
        // short-circuits to false so a malformed lock file containing
        // "0\n" cannot be misread as a live holder.
        assert!(!pid_is_alive(0));
    }
}
