//! PTY allocation, child spawn, signal plumbing and the byte pump of the
//! relay (spec 34 §34.2.1).
//!
//! [`Relay::run`] is the overlay-free baseline: it relays terminal input to
//! the child and child output to the terminal byte for byte, and owns the
//! process-level duties of §34.2.1 (a) restore, (c) resize, (d) signals,
//! (e) exit status, (f) job control, (g) termination and drain. The single
//! writer, the Enter rule and the chord filter are layered on top by later
//! shards; they reuse [`Pty`], [`SignalGuard`], [`RawGuard`] and the exit
//! helpers here.
//!
//! # Caller contract (S4a, S4c)
//!
//! [`RelayError`] says whether the CLI was started. `Declined`, `Busy` and
//! `NotStarted` mean nothing ran: launch unrelayed, but only for a launch that
//! asked for no other identity ([`RelayError::may_launch_unrelayed`] takes the
//! spec and answers false whenever it sets a uid or gid: an unrelayed launch
//! would start the CLI as the caller (or root), whatever the failure was,
//! including a truncated or unknown status from the shim). `PrivilegeDropFailed`
//! means the CLI never ran either, and never permits the fallback. `ChildStarted` means the
//! CLI ran or may still be running and has been signalled to end; the caller
//! MUST NOT launch it again (two instances on one handle dir would race the
//! account's refresh token).
//!
//! # Stated behaviour
//!
//! A `SIGKILL` of the relay cannot be caught. The master is then closed by
//! the kernel and the child, a session leader on that terminal, receives
//! `SIGHUP`. Restoring the outer terminal after that is the guardian and the
//! next-launch marker (shard S1d), not this module.
//!
//! Every other catchable signal whose default action terminates the relay
//! while the terminal is raw restores the terminal first (see
//! [`SignalGuard`]); fault signals (`SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE`,
//! `SIGABRT`) are left to the runtime. None of them dumps core: the relay's
//! memory holds the launch environment (which can carry a third-party API
//! token), so [`Relay::run`] zeroes `RLIMIT_CORE` and, on Linux, clears the
//! dumpable flag before anything else (`harden_process`); it refuses to
//! relay when that fails.
//!
//! Terminal restore on a panic relies on unwinding (see `relay::term`).
//!
//! Only one relay may run per process: the signal handlers write to one
//! process-wide wake channel. A second [`Relay::run`] is refused with
//! [`RelayError::Busy`].
//!
//! Logging carries counts and kinds only, never terminal bytes.

use std::cell::UnsafeCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::term::{self, Decline, RawGuard};

/// How long the relay keeps draining the master after the child exits
/// (spec 34 §34.2.1 (g), CHOSEN). The bound covers reading AND writing the
/// drained bytes to the terminal.
pub const DRAIN_MS: u64 = 200;

/// How long an abandoned child gets after `SIGHUP`+`SIGCONT` before `SIGKILL`.
pub const TERMINATE_GRACE_MS: u64 = 2000;

/// Upper bound on terminal input held while the child is not reading.
const IN_QUEUE_MAX: usize = 64 * 1024;

/// Upper bound on child output held while the terminal is not accepting it.
const OUT_QUEUE_MAX: usize = 64 * 1024;

/// A finite poll timeout, so child exit is noticed even if a wake byte is lost.
const POLL_BACKSTOP_MS: libc::c_int = 1000;
/// How long a relay resumed in the background waits for a terminating
/// signal's handler (which may run on another thread) before stopping again.
const RESUME_SIGNAL_GRACE_MS: libc::c_int = 250;
/// How long a resumed relay waits for a signal that arrived with the resume
/// before it looks (the poll returns at once when one is already there).
const RESUME_SIGNAL_SETTLE_MS: libc::c_int = 20;

const STDIN: RawFd = libc::STDIN_FILENO;
const STDOUT: RawFd = libc::STDOUT_FILENO;
const STDERR: RawFd = libc::STDERR_FILENO;

/// Signals meant for the session, forwarded to the child's process group
/// (spec 34 §34.2.1 (d)).
const FORWARDED: [libc::c_int; 6] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGALRM,
    libc::SIGUSR2,
];

/// Catchable signals outside [`FORWARDED`] whose default action terminates
/// the process. Each gets a handler that restores the terminal and re-raises.
#[cfg(target_os = "linux")]
const FATAL: &[libc::c_int] = &[
    libc::SIGVTALRM,
    libc::SIGPROF,
    libc::SIGXCPU,
    libc::SIGXFSZ,
    libc::SIGSYS,
    libc::SIGIO,
    libc::SIGPWR,
    libc::SIGSTKFLT,
];
#[cfg(not(target_os = "linux"))]
const FATAL: &[libc::c_int] = &[
    libc::SIGEMT,
    libc::SIGVTALRM,
    libc::SIGPROF,
    libc::SIGXCPU,
    libc::SIGXFSZ,
    libc::SIGSYS,
    libc::SIGIO,
];

/// Why [`Relay::run`] did not relay. See the module's caller contract.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayError {
    /// The start precondition failed; launch proceeds unrelayed.
    #[error("relay declined: {0:?}")]
    Declined(Decline),
    /// A relay is already running in this process; launch proceeds unrelayed.
    #[error("a relay is already running in this process")]
    Busy,
    /// A system call failed BEFORE the child was started; launch proceeds
    /// unrelayed. `op` is a fixed vocabulary tag.
    #[error("relay setup failed before the child started: {op} (errno {errno})")]
    NotStarted {
        /// Fixed-vocabulary operation tag.
        op: &'static str,
        /// The `errno` value.
        errno: i32,
    },
    /// The privilege drop to the requested uid/gid failed or did not take
    /// effect. The CLI never ran, but the caller MUST NOT launch it unrelayed
    /// either: that would run it with the caller's own identity instead of the
    /// requested one.
    #[error("relay refused: the privilege drop failed at {step} (errno {errno})")]
    PrivilegeDropFailed {
        /// Fixed-vocabulary step tag (`setgroups`, `capabilities`, `setgid`,
        /// `setuid`, `verify_drop`).
        step: &'static str,
        /// The `errno` value.
        errno: i32,
    },
    /// A system call failed AFTER the child was started. The child has been
    /// told to end; the caller MUST NOT launch the CLI again.
    #[error("relay failed after the child started: {op} (errno {errno})")]
    ChildStarted {
        /// Fixed-vocabulary operation tag.
        op: &'static str,
        /// The `errno` value.
        errno: i32,
    },
}

impl RelayError {
    /// Whether the CLI was started. When true the caller MUST NOT fall back
    /// to launching it unrelayed.
    pub fn child_started(&self) -> bool {
        matches!(self, RelayError::ChildStarted { .. })
    }

    /// Whether the caller may launch the CLI itself, without the relay: only
    /// where nothing ran and the launch's identity is unaffected. A refused
    /// privilege drop is not such a case.
    ///
    /// `spec` is the launch that failed: when it asks for another identity (a
    /// uid or gid), no error of any kind permits the fallback, because the
    /// unrelayed launch would run as the caller instead of the requested
    /// identity.
    pub fn may_launch_unrelayed(&self, spec: &LaunchSpec) -> bool {
        spec.uid.is_none()
            && spec.gid.is_none()
            && matches!(
                self,
                RelayError::Declined(_) | RelayError::Busy | RelayError::NotStarted { .. }
            )
    }
}

/// Why [`spawn_on_slave`] failed: the error, and the privilege-drop step it
/// happened in (`None` for any other failure).
#[derive(Debug)]
struct SpawnFailure {
    err: io::Error,
    drop_step: Option<&'static str>,
    /// The CLI had already been exec'ed (and has been told to end): the caller
    /// must treat the launch as started.
    started: bool,
}

impl SpawnFailure {
    fn raw_os_error(&self) -> Option<i32> {
        self.err.raw_os_error()
    }

    fn into_relay_error(self) -> RelayError {
        let errno = self.raw_os_error().unwrap_or(0);
        if self.started {
            return RelayError::ChildStarted { op: "fcntl", errno };
        }
        match self.drop_step {
            Some(step) => RelayError::PrivilegeDropFailed { step, errno },
            None => RelayError::NotStarted { op: "spawn", errno },
        }
    }
}

impl From<io::Error> for SpawnFailure {
    fn from(err: io::Error) -> Self {
        SpawnFailure {
            err,
            drop_step: None,
            started: false,
        }
    }
}

/// Decode a startup failure message: its `errno` and, for a privilege-drop
/// tag, the step. Anything else (a short or unknown message) is `EIO`.
fn decode_startup_failure(msg: &[u8; 5], got: usize) -> (i32, Option<&'static str>) {
    if got == msg.len() {
        let errno = i32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]);
        if msg[0] == TAG_GENERIC {
            return (errno, None);
        }
        if let Some(step) = drop_step_of(msg[0]) {
            return (errno, Some(step));
        }
    }
    (libc::EIO, None)
}

fn not_started(op: &'static str) -> impl FnOnce(io::Error) -> RelayError {
    move |e| RelayError::NotStarted {
        op,
        errno: e.raw_os_error().unwrap_or(0),
    }
}

fn started(op: &'static str, e: io::Error) -> RelayError {
    RelayError::ChildStarted {
        op,
        errno: e.raw_os_error().unwrap_or(0),
    }
}

/// How the child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayExit {
    /// The child exited with this code.
    Exited(i32),
    /// The child was killed by this signal.
    Signaled(i32),
}

impl RelayExit {
    /// End this process the way the child ended (spec 34 §34.2.1 (e)): exit
    /// with the child's code, or reset the signal to default and re-raise it
    /// so the parent shell sees `WIFSIGNALED` rather than `128+S`.
    pub fn conclude(self) -> ! {
        match self {
            RelayExit::Exited(code) => std::process::exit(code),
            RelayExit::Signaled(sig) => {
                reset_and_raise(sig);
                // The signal did not terminate us (it cannot be a default
                // terminating one); fall back to the shell convention.
                std::process::exit(128 + sig)
            }
        }
    }
}

/// Set `sig` to its default action, unblock it and raise it. Only raw
/// syscall wrappers (`disable_core_dumps`'s mechanism above plus
/// `sigaction`, `sigprocmask`, `raise`, `_exit`), so the fatal-signal handler
/// shares it.
fn reset_and_raise(sig: libc::c_int) {
    // SAFETY: plain signal-state syscalls on this process; `_exit` never
    // returns.
    unsafe {
        // No dump of this process (it holds the launch environment). Where
        // the dump cannot be ruled out, end WITHOUT raising a signal whose
        // default action may dump (fail closed).
        if disable_core_dumps().is_none() {
            libc::_exit(128 + sig);
        }
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(sig);
    }
}

/// Relay options.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Forward `SIGUSR1` to the child. True by default (spec 34 §34.2.1 (d));
    /// false only where the Codex supervisor owns `SIGUSR1` (§34.8).
    pub forward_usr1: bool,
    /// Drain window after the child exits.
    pub drain: Duration,
    /// Test fault: panic on the first terminal input byte.
    #[cfg(test)]
    pub(crate) panic_on_input: bool,
    /// Test only: never poll the master or the shim's report pipe, so the
    /// master hangup a session leader's exit causes and the report pipe's EOF
    /// cannot wake the relay and only `SIGCHLD` or the poll backstop can
    /// announce the child's exit.
    #[cfg(test)]
    pub(crate) deaf_master: bool,
    /// Test only, fires once: between the drain of the shim's reports and the
    /// `R` that resumes the CLI (the window a stale stop report slips through),
    /// continue the CLI whose pid is in this file and wait until the shim has
    /// reported its new stop. The report then sits in the up pipe stamped with
    /// the count from before this `R`.
    #[cfg(test)]
    pub(crate) stop_again_before_resume: Option<PathBuf>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            forward_usr1: true,
            drain: Duration::from_millis(DRAIN_MS),
            #[cfg(test)]
            panic_on_input: false,
            #[cfg(test)]
            deaf_master: false,
            #[cfg(test)]
            stop_again_before_resume: None,
        }
    }
}

fn set_nonblock(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags == -1 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A master/slave pseudo-terminal pair. Both ends are close-on-exec from the
/// moment they exist.
#[derive(Debug)]
pub struct Pty {
    /// The relay's end.
    pub master: OwnedFd,
    /// The child's end.
    pub slave: OwnedFd,
}

/// The name of the slave of `master`. `ptsname` is not thread-safe, so where
/// `ptsname_r` is missing a lock covers the call and the copy.
fn slave_name(master: RawFd) -> io::Result<std::ffi::CString> {
    #[cfg(target_os = "linux")]
    {
        let mut buf = [0 as libc::c_char; 128];
        // SAFETY: valid buffer and length.
        let rc = unsafe { libc::ptsname_r(master, buf.as_mut_ptr(), buf.len()) };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc));
        }
        // SAFETY: ptsname_r NUL-terminated the buffer.
        Ok(unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        static PTSNAME: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _held = PTSNAME.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: the result is copied before the lock is released.
        let p = unsafe { libc::ptsname(master) };
        if p.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: non-null, NUL-terminated.
        Ok(unsafe { std::ffi::CStr::from_ptr(p) }.to_owned())
    }
}

/// How many times in all a terminal call is attempted when it keeps failing
/// with an error [`retry_transient`]'s predicate accepts. A cap on ATTEMPTS,
/// not on time (each attempt is one immediate syscall, with a
/// `yield_now` between attempts), so the loop ends after at most this many
/// calls; the last error is returned. The bound is this enforced cap.
///
/// Measured typical: cap 4 was set in commit 00ccb2f81 (lane copy e92745dde)
/// from the then 16-thread x 200 form of
/// `pty_open_and_tty_reopen_survive_concurrent_pty_churn` on macOS: over 9
/// completed runs of 3200 open+reopen each, the longest run of consecutive
/// transient failures any one call absorbed before succeeding was 1. The cap
/// is 4x that observation. The test now runs 4 threads x 50 (a few concurrent
/// launches; the 16-thread form hit a kernel spin, see [`Pty::open`]), so the
/// 1 was measured on a heavier shape than the one asserted today. It is a
/// typical-case margin only; the enforced bound is the cap itself.
const PTY_TRANSIENT_ATTEMPTS: u32 = 4;

#[cfg(test)]
thread_local! {
    /// Test-only instrument behind the cap's measurement: when a test installs
    /// a counter on a thread, every [`retry_transient`] call on THAT thread
    /// that ends in success records the transient failures it absorbed first.
    /// Unset on every thread that did not install one, so tests that drive
    /// `retry_transient` directly never feed it.
    static TRANSIENT_RUN_PROBE: std::cell::RefCell<Option<std::sync::Arc<std::sync::atomic::AtomicU32>>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `op` until it succeeds, fails with an error `transient` rejects, or
/// has been attempted [`PTY_TRANSIENT_ATTEMPTS`] times. Any other error, and
/// the transient one after the cap, is returned unchanged: never swallowed.
fn retry_transient<T>(
    transient: impl Fn(&io::Error) -> bool,
    mut op: impl FnMut() -> io::Result<T>,
) -> io::Result<T> {
    let mut attempt = 1;
    loop {
        match op() {
            Err(e) if attempt < PTY_TRANSIENT_ATTEMPTS && transient(&e) => {
                attempt += 1;
                std::thread::yield_now();
            }
            done => {
                #[cfg(test)]
                if done.is_ok() {
                    TRANSIENT_RUN_PROBE.with(|p| {
                        if let Some(c) = p.borrow().as_ref() {
                            c.fetch_max(attempt - 1, std::sync::atomic::Ordering::Relaxed);
                        }
                    });
                }
                return done;
            }
        }
    }
}

/// `posix_openpt` failed with XNU's kernel-internal `EREDRIVEOPEN` (-6), which
/// macOS leaks to user space while other terminals are created and closed
/// (probed under concurrent churn: the next call succeeds). Not a value any
/// other platform's `errno` takes.
fn openpt_transient(e: &io::Error) -> bool {
    cfg!(target_os = "macos") && e.raw_os_error() == Some(-6)
}

/// `ttyname_r` reported `ERANGE` on macOS. The buffer it is given is far
/// longer than any terminal name, so this is its `/dev` name lookup racing
/// concurrent terminal churn (probed: the next call returns the right name),
/// never a buffer that is too small.
fn ttyname_transient(e: &io::Error) -> bool {
    cfg!(target_os = "macos") && e.raw_os_error() == Some(libc::ERANGE)
}

/// The marker error for a reopened terminal that is not the source terminal.
fn tty_mismatch(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::InvalidData && e.raw_os_error().is_none()
}

/// Reopen the terminal on `fd` by the name `ttyname_r` reports, for
/// non-blocking writes. The name is only a name; the caller verifies identity.
fn reopen_by_name(fd: RawFd) -> io::Result<OwnedFd> {
    let mut buf = [0 as libc::c_char; 128];
    // SAFETY: valid buffer and length.
    let rc = unsafe { libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    let flags = libc::O_WRONLY | libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC;
    // SAFETY: ttyname_r NUL-terminated the buffer.
    let raw = unsafe { libc::open(buf.as_ptr(), flags) };
    if raw == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a fresh descriptor we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `Ok` only when `a` and `b` are both character devices with an equal
/// `st_rdev`; a different device is the [`tty_mismatch`] error, and an
/// `fstat` failure is its own error (fail closed either way).
fn same_tty(a: RawFd, b: RawFd) -> io::Result<()> {
    fn stat(fd: RawFd) -> io::Result<libc::stat> {
        // SAFETY: a zeroed stat is a valid out-parameter for fstat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat writes into the stat we own.
        if unsafe { libc::fstat(fd, &mut st) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(st)
    }
    let (sa, sb) = (stat(a)?, stat(b)?);
    let chr = |st: &libc::stat| st.st_mode & libc::S_IFMT == libc::S_IFCHR;
    if chr(&sa) && chr(&sb) && sa.st_rdev == sb.st_rdev {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reopened terminal is not the source terminal",
        ))
    }
}

impl Pty {
    /// `posix_openpt` with `O_CLOEXEC` at creation (so no concurrent
    /// `fork`+`exec` can inherit either end), then the slave opened with
    /// `O_CLOEXEC` too. The slave's attributes and window size are copied
    /// from the outer terminal when given, so the child sees the terminal it
    /// would have had un-relayed.
    pub fn open(termios: Option<&libc::termios>, ws: Option<&libc::winsize>) -> io::Result<Pty> {
        let m = retry_transient(openpt_transient, || {
            // SAFETY: plain syscall; the flags are accepted atomically on
            // Linux and macOS (probed: FD_CLOEXEC is set on the result).
            let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
            if m == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(m)
            }
        })?;
        // SAFETY: posix_openpt returned a fresh descriptor we now own.
        let master = unsafe { OwnedFd::from_raw_fd(m) };
        // grantpt/unlockpt are NOT serialized. A macOS kernel spin in the
        // grantpt/unlockpt ioctl was reproduced IN-PROCESS at 16 concurrent
        // threads (scratchpad F-grantpt-repro.c; sampled at ~90% CPU in the
        // ioctl, hangs ~1 run in 4). The CROSS-PROCESS case (several relays
        // launching at once) is UNMEASURED. This MUST be resolved before the
        // relay is wired into any launch path (spec 34).
        // SAFETY: plain syscalls on the master we own.
        if unsafe { libc::grantpt(m) } == -1 || unsafe { libc::unlockpt(m) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let name = slave_name(m)?;
        // SAFETY: valid NUL-terminated path.
        let s = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if s == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: open returned a fresh descriptor we now own.
        let slave = unsafe { OwnedFd::from_raw_fd(s) };
        if let Some(t) = termios {
            // SAFETY: valid termios for the call.
            if unsafe { libc::tcsetattr(s, libc::TCSANOW, t) } == -1 {
                return Err(io::Error::last_os_error());
            }
        }
        if let Some(w) = ws {
            term::set_winsize(s, w)?;
        }
        Ok(Pty { master, slave })
    }
}

/// What the CLI is started with. The environment is COMPLETE and explicit: a
/// new spec starts empty, [`LaunchSpec::inherit_env`] copies the relay's own,
/// and nothing is read from the relay's environment behind the caller's back.
/// There is deliberately no conversion from [`std::process::Command`]: its `env_clear`,
/// `pre_exec` hooks, `uid`/`gid` and `process_group` are not readable back, so
/// a conversion would silently drop them (security-relevant: a caller that
/// strips credentials with `env_clear` would leak the whole environment).
#[derive(Clone)]
pub struct LaunchSpec {
    program: OsString,
    args: Vec<OsString>,
    arg0: Option<OsString>,
    env: BTreeMap<OsString, OsString>,
    /// Names the caller removed: `inherit_env` must never bring them back,
    /// whichever order the calls come in.
    removed: BTreeSet<OsString>,
    cwd: Option<PathBuf>,
    uid: Option<u32>,
    gid: Option<u32>,
}

impl fmt::Debug for LaunchSpec {
    /// Fixed text only: argv and environment can carry secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LaunchSpec").finish_non_exhaustive()
    }
}

impl LaunchSpec {
    /// A spec for `program` with no arguments and an EMPTY environment.
    pub fn new(program: impl Into<OsString>) -> Self {
        LaunchSpec {
            program: program.into(),
            args: Vec::new(),
            arg0: None,
            env: BTreeMap::new(),
            removed: BTreeSet::new(),
            cwd: None,
            uid: None,
            gid: None,
        }
    }

    /// Append one argument.
    pub fn arg(mut self, a: impl Into<OsString>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Append arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set `argv[0]` (defaults to the program as given).
    pub fn arg0(mut self, a: impl Into<OsString>) -> Self {
        self.arg0 = Some(a.into());
        self
    }

    /// Add the relay's own environment, in ANY call order: a name the caller
    /// set with `env` keeps the caller's value, and a name removed with
    /// `env_remove` stays absent (as with `Command`).
    pub fn inherit_env(mut self) -> Self {
        for (k, v) in std::env::vars_os() {
            if !self.removed.contains(&k) {
                self.env.entry(k).or_insert(v);
            }
        }
        self
    }

    /// Set one environment variable.
    pub fn env(mut self, k: impl Into<OsString>, v: impl Into<OsString>) -> Self {
        let k = k.into();
        self.removed.remove(&k);
        self.env.insert(k, v.into());
        self
    }

    /// Remove one environment variable.
    pub fn env_remove(mut self, k: impl AsRef<OsStr>) -> Self {
        self.env.remove(k.as_ref());
        self.removed.insert(k.as_ref().to_os_string());
        self
    }

    /// Run the CLI in this directory.
    pub fn current_dir(mut self, d: impl Into<PathBuf>) -> Self {
        self.cwd = Some(d.into());
        self
    }

    /// Run the CLI as this user id. Requires [`LaunchSpec::gid`] too (the
    /// supplementary groups are cleared and the group set before the user).
    /// The relay must be privileged (root) to do this: the shim clears the
    /// supplementary groups first, and where that is refused (`EPERM`) the
    /// launch fails with that error and the CLI never runs as the caller.
    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// Run the CLI as this group id. Like [`LaunchSpec::uid`] it needs a
    /// privileged relay (the supplementary groups are always cleared first).
    pub fn gid(mut self, gid: u32) -> Self {
        self.gid = Some(gid);
        self
    }

    /// Refuse a spec the shim cannot represent, with a fixed error: an empty
    /// program, or a NUL byte anywhere, or an environment name that is empty
    /// or contains `=`, or a user id without a group id, or a group id without a user id (the CLI
    /// would keep the relay's uid, possibly root, behind what reads as a drop).
    fn validate(&self) -> Result<(), RelayError> {
        let nul = |s: &OsStr| s.as_bytes().contains(&0);
        let bad = self.program.is_empty()
            || nul(&self.program)
            || self.args.iter().any(|a| nul(a))
            || self.arg0.as_deref().is_some_and(nul)
            || self.cwd.as_deref().is_some_and(|d| nul(d.as_os_str()))
            || self
                .env
                .iter()
                .any(|(k, v)| k.is_empty() || k.as_bytes().contains(&b'=') || nul(k) || nul(v));
        let bad = bad || (self.uid.is_some() != self.gid.is_some());
        if bad {
            return Err(RelayError::NotStarted {
                op: "launch_spec",
                errno: libc::EINVAL,
            });
        }
        Ok(())
    }
}

/// An executable file, by the spec's own `PATH` (absolute entries only; an
/// unset `PATH` means the system default), never the relay's directory.
fn resolve_program(spec: &LaunchSpec) -> io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let prog = Path::new(&spec.program);
    if spec.program.as_bytes().contains(&b'/') {
        return Ok(prog.to_path_buf());
    }
    let path: OsString = match spec.env.get(OsStr::new("PATH")) {
        Some(p) => p.clone(),
        None => default_path(),
    };
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(prog))
        .find(|c| {
            std::fs::metadata(c)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
}

/// The system default search path (`confstr(_CS_PATH)`).
fn default_path() -> OsString {
    let mut buf = [0u8; 1024];
    // SAFETY: valid buffer of the stated length.
    let n = unsafe { libc::confstr(libc::_CS_PATH, buf.as_mut_ptr().cast(), buf.len()) };
    if n == 0 || n > buf.len() {
        return OsString::from("/usr/bin:/bin");
    }
    OsString::from_vec(buf[..n - 1].to_vec())
}

/// Every signal disposition back to `SIG_DFL` (an inherited ignore would
/// break `yes | head` in every tool the CLI runs). Async-signal-safe.
unsafe fn reset_dispositions() {
    // SAFETY: caller is a freshly forked child; sigaction on its own state.
    unsafe {
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut dfl.sa_mask);
        for sig in 1..65 {
            if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                libc::sigaction(sig, &dfl, std::ptr::null_mut());
            }
        }
    }
}

/// The empty signal mask. Async-signal-safe.
unsafe fn clear_signal_mask() -> bool {
    // SAFETY: sigprocmask on the caller's own state.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) != -1
    }
}

/// Test harness only: the pre-exec of a session-leader helper (the `shell`
/// role) with the slave as controlling terminal, default dispositions and an
/// empty mask. The relayed CLI itself goes through the job-control shim.
#[cfg(test)]
fn child_prepare() -> io::Result<()> {
    // SAFETY: only async-signal-safe syscalls, on the child's own state.
    unsafe {
        if libc::setsid() == -1 {
            return Err(io::Error::last_os_error());
        }
        if libc::ioctl(STDIN, libc::TIOCSCTTY as _, 0) == -1 {
            return Err(io::Error::last_os_error());
        }
        reset_dispositions();
        if !clear_signal_mask() {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// The shim's descriptors after setup (everything else is closed).
const SHIM_ST: libc::c_int = 3;
const SHIM_UP: libc::c_int = 4;
const SHIM_CTL: libc::c_int = 5;
const SHIM_CHLD_R: libc::c_int = 6;
const SHIM_CHLD_W: libc::c_int = 7;

/// How long the shim gives the CLI after the relay is gone before `SIGKILL`
/// (the relay's own enforced abandon grace, [`TERMINATE_GRACE_MS`]).
const SHIM_ORPHAN_GRACE_MS: u64 = TERMINATE_GRACE_MS;

/// How long `spawn_on_slave` waits for a startup failure report before it
/// takes silence to mean the CLI started.
const SPAWN_STATUS_WAIT_MS: u64 = 5000;

/// How often the shim re-checks that its parent (the relay) is alive.
const SHIM_LIVENESS_POLL_MS: libc::c_int = 1000;

/// The relay's pid, as the relay itself knew it before the fork (its parent as
/// the shim sees it). The shim polls its parent against this to notice a relay
/// that is gone while a leaked copy of the control pipe keeps it open.
static SHIM_RELAY: AtomicI32 = AtomicI32::new(0);

/// Test only: the pid `shim_plan` records as the relay, in place of this
/// process's own (0 = unset).
#[cfg(test)]
static FORGED_RELAY: AtomicI32 = AtomicI32::new(0);

/// This process's pid as the plan's relay identity.
fn relay_pid() -> libc::pid_t {
    #[cfg(test)]
    {
        let forged = FORGED_RELAY.load(Ordering::Acquire);
        if forged != 0 {
            return forged;
        }
    }
    // SAFETY: getpid has no preconditions.
    unsafe { libc::getpid() }
}

/// The core-file soft limit this process had before [`harden_process`] zeroed
/// it, recorded once. The CLI gets it back (`ShimPlan::core_soft`).
static RELAY_CORE_SOFT: OnceLock<u64> = OnceLock::new();

/// Test only: [`disable_core_dumps`] reports failure while this is set. Never
/// set outside a forked judge, so no other test sees it.
#[cfg(test)]
static FAIL_DISABLE_CORE: AtomicBool = AtomicBool::new(false);

/// No core file or dump for this process: a dump of the relay or the shim
/// would contain the launch environment (credentials). `RLIMIT_CORE` soft
/// limit 0 and, on Linux, not dumpable. Returns the previous soft limit.
///
/// Callable from the fatal-signal handler because of its mechanism, not a
/// POSIX listing: `getrlimit`, `setrlimit` and `prctl` are not on POSIX's
/// async-signal-safe list, but on the libcs csq builds for (glibc, musl,
/// macOS libSystem) each is a thin wrapper that issues the system call
/// directly, with no allocation, no lock and no stdio. No other call is made.
fn disable_core_dumps() -> Option<u64> {
    // Test seam, compiled only into the unit-test build: make the hardening
    // fail so the callers' fail-closed branches can be exercised.
    #[cfg(test)]
    if FAIL_DISABLE_CORE.load(Ordering::Relaxed) {
        return None;
    }
    // SAFETY: plain syscalls on this process.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_CORE, &mut lim) != 0 {
            return None;
        }
        let old = lim.rlim_cur as u64;
        lim.rlim_cur = 0;
        if libc::setrlimit(libc::RLIMIT_CORE, &lim) != 0 {
            return None;
        }
        #[cfg(target_os = "linux")]
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return None;
        }
        Some(old)
    }
}

/// Make this process undumpable ([`disable_core_dumps`]) and remember the
/// limit it had. Called first thing in [`Relay::run`]: the relay's memory holds
/// the launch environment, and a stray `pkill -ABRT csq` would otherwise write
/// it into a core file. Fails closed: the caller does not relay when this
/// fails.
fn harden_process() -> io::Result<()> {
    match disable_core_dumps() {
        Some(old) => {
            // A second call sees the already-zeroed limit; the first value
            // stays.
            RELAY_CORE_SOFT.get_or_init(|| old);
            Ok(())
        }
        None => Err(io::Error::last_os_error()),
    }
}

/// The core-file soft limit the CLI is to get back: the one recorded by
/// [`harden_process`], or the current one where it never ran (a direct
/// [`spawn_on_slave`] caller).
fn original_core_soft() -> io::Result<u64> {
    if let Some(v) = RELAY_CORE_SOFT.get() {
        return Ok(*v);
    }
    // SAFETY: plain rlimit query into a valid out-pointer.
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_CORE, &mut lim) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(lim.rlim_cur as u64)
    }
}

/// The CLI's process group, for the shim's signal handlers (shim process
/// only; `0` while there is no live CLI).
static SHIM_CLI: AtomicI32 = AtomicI32::new(0);

/// The shim's `SIGCHLD` wake pipe (write end).
static SHIM_WAKE: AtomicI32 = AtomicI32::new(-1);

/// Shim handler: pass a session signal on to the CLI's process group. A
/// terminating one first hands the terminal to the CLI, then resumes it, so a
/// stopped CLI acts on the signal in the foreground (never the other order:
/// a background CLI would take `SIGTTIN`/`SIGTTOU` instead).
extern "C" fn shim_forward(sig: libc::c_int) {
    let cli = SHIM_CLI.load(Ordering::Acquire);
    if cli > 0 {
        // SAFETY: kill and tcsetpgrp are async-signal-safe; the shim blocks
        // every signal from reaping the CLI until SHIM_CLI is cleared, so
        // this never runs against a reaped (reusable) group. errno is saved
        // so the interrupted `poll` still sees its own EINTR.
        unsafe {
            let saved = *errno_location();
            libc::kill(-cli, sig);
            if (sig == libc::SIGHUP || sig == libc::SIGTERM) && !foreground_then_continue(cli) {
                // The terminal is gone (a hung-up PTY after the relay died) or
                // is not ours to hand over. The CLI still gets to act on the
                // signal it was sent: it is continued, never killed here; the
                // deadline `shim_watch` arms when the relay's pipe closes is
                // what ends one that does not.
                libc::kill(-cli, libc::SIGCONT);
            }
            *errno_location() = saved;
        }
    }
}

/// Hand the terminal to the CLI's group, THEN continue it: the one place
/// that order lives, used by the forwarding handler and by the shim's resume
/// (`R`). Reversed, the CLI would run in the background and take
/// `SIGTTIN`/`SIGTTOU` on its first terminal access. Returns whether the
/// hand-over worked; when it did not (nothing was continued) the caller
/// decides what that means. Async-signal-safe.
unsafe fn foreground_then_continue(cli: libc::pid_t) -> bool {
    // SAFETY: raw syscalls on the shim's own state.
    unsafe {
        if libc::tcsetpgrp(0, cli) == -1 {
            return false;
        }
        libc::kill(-cli, libc::SIGCONT);
        true
    }
}

/// Shim handler for `SIGCHLD`: wake the shim's poll.
extern "C" fn shim_chld(_sig: libc::c_int) {
    // SAFETY: errno save/restore and one write(2) are async-signal-safe.
    unsafe {
        let saved = *errno_location();
        let fd = SHIM_WAKE.load(Ordering::Acquire);
        if fd >= 0 {
            let _ = libc::write(fd, b"c".as_ptr().cast(), 1);
        }
        *errno_location() = saved;
    }
}

/// Whether the sender recorded in `info` is a process that really sent the
/// signal, not one that wrote the sender into a queued signal.
///
/// Linux lets any same-user process hand `rt_sigqueueinfo` a siginfo carrying
/// ANY `si_pid` as long as its `si_code` is negative, so there the code must be
/// `SI_USER` (`kill(2)`, code 0 by the kernel ABI). macOS has no such call: the
/// kernel fills `si_pid` for every sender, so there is nothing to check and
/// the `si_code` value it uses for `kill(2)` (0, or the header's 0x10001; the
/// two disagree) is deliberately not consulted.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn sender_is_genuine(info: *const libc::siginfo_t) -> bool {
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    unsafe { (*info).si_code == libc::SI_USER }
}

/// See the Linux variant.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
unsafe fn sender_is_genuine(_info: *const libc::siginfo_t) -> bool {
    true
}

/// The sender pid of a `siginfo_t`.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn si_sender(info: *const libc::siginfo_t) -> libc::pid_t {
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    unsafe { (*info).si_pid() }
}

/// The sender pid of a `siginfo_t`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
unsafe fn si_sender(info: *const libc::siginfo_t) -> libc::pid_t {
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    unsafe { (*info).si_pid }
}

/// Shim handler for the relay's "end the session" request, `SIGURG` (which
/// every other process ignores by default): `SIGKILL` the CLI's group. Only
/// the shim's own parent, the relay, may ask, by `kill(2)`: any other
/// same-user sender (a stray `kill -URG`, `kill(-1, SIGURG)`, `sigqueue`) is
/// ignored.
extern "C" fn shim_kill(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let cli = SHIM_CLI.load(Ordering::Acquire);
    // SAFETY: as in `shim_forward`; getppid is async-signal-safe. Only a
    // genuine sender (see `sender_is_genuine`) that is the parent counts.
    unsafe {
        let saved = *errno_location();
        if cli > 0
            && !info.is_null()
            && sender_is_genuine(info)
            && si_sender(info) == libc::getppid()
        {
            libc::kill(-cli, libc::SIGKILL);
        }
        *errno_location() = saved;
    }
}

/// Shim handler for `SIGSEGV`, `SIGBUS`, `SIGILL`, `SIGFPE` and `SIGTRAP`: the
/// CLI's group is `SIGKILL`ed, then the shim dies of the signal (default
/// action, no dump). Whether a process SENT it (a stray `kill -SEGV`, `pkill
/// -SEGV csq`) or the shim really faulted, it is never resumed and the CLI is
/// never left running without its session leader. Not told apart on purpose:
/// the `si_code` a `kill(2)`-sent fault signal carries is not the same on
/// every OS (macOS reports a hardware-fault code for it), so a classification
/// would be right on one platform and fail open on the other.
extern "C" fn shim_fault(sig: libc::c_int) {
    let cli = SHIM_CLI.load(Ordering::Acquire);
    // SAFETY: kill is async-signal-safe; the handler runs only while the CLI
    // is unreaped (see `shim_forward`).
    unsafe {
        if cli > 0 {
            libc::kill(-cli, libc::SIGKILL);
        }
        reset_and_raise(sig);
    }
}

/// What the scan closes up to when the open descriptors cannot be listed: far
/// above any descriptor a process realistically holds, at a bounded cost of one
/// failing `close` per number.
const FD_FALLBACK_CEILING: u64 = 1 << 20;

/// One more than the highest descriptor number open in this process now. Taken
/// by the relay BEFORE the fork (it allocates), so the shim's fallback close
/// loop reaches a descriptor that sits above a soft limit lowered after it was
/// opened, on a system whose limits do not say how high to look (macOS reports
/// an unlimited hard limit and a `sysconf` that stops at the soft one). A
/// descriptor opened after this point has a number below the limit in force
/// when it was opened, which the loop also covers. If the listing cannot be
/// read, the answer is [`FD_FALLBACK_CEILING`]: everything gets closed.
fn open_fd_ceiling() -> u64 {
    let listing = match std::fs::read_dir("/dev/fd") {
        Ok(l) => l,
        Err(_) => return fd_listing_failed(),
    };
    let mut top = 0u64;
    for entry in listing {
        let number = match entry {
            Ok(e) => e.file_name().to_str().and_then(|n| n.parse::<u64>().ok()),
            Err(_) => None,
        };
        match number {
            Some(n) => top = top.max(n.saturating_add(1)),
            None => return fd_listing_failed(),
        }
    }
    top
}

fn fd_listing_failed() -> u64 {
    tracing::warn!(
        error_kind = "fd_listing_failed",
        "open descriptors could not be listed; the shim closes up to a fixed ceiling"
    );
    FD_FALLBACK_CEILING
}

/// Close every descriptor from `low` up to `ceiling` (see
/// [`open_fd_ceiling`]) and to the process's limits. Async-signal-safe.
unsafe fn close_from(low: libc::c_int, ceiling: u64) {
    // SAFETY: closing descriptors this forked child owns copies of.
    unsafe {
        #[cfg(target_os = "linux")]
        if libc::syscall(libc::SYS_close_range, low as libc::c_uint, !0u32, 0) == 0 {
            return;
        }
        close_by_scan(low, ceiling);
    }
}

/// The portable close loop of [`close_from`].
unsafe fn close_by_scan(low: libc::c_int, ceiling: u64) {
    // SAFETY: closing descriptors this forked child owns copies of.
    unsafe {
        // Up to the HARD limit (a descriptor can sit above a soft limit that
        // was lowered after it was opened); an unlimited hard limit means the
        // system's own cap.
        let mut lim: libc::rlimit = std::mem::zeroed();
        let top = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0
            && lim.rlim_max != libc::RLIM_INFINITY
        {
            lim.rlim_max as u64
        } else {
            libc::sysconf(libc::_SC_OPEN_MAX).max(0) as u64
        };
        let by_limit = top.max(lim.rlim_cur as u64).clamp(low as u64, 1 << 20);
        // Past the limits, up to the highest descriptor that was open.
        let max = by_limit.max(ceiling.min(libc::c_int::MAX as u64)) as libc::c_int;
        for fd in low..max {
            libc::close(fd);
        }
    }
}

/// Monotonic milliseconds. Async-signal-safe.
unsafe fn now_ms() -> u64 {
    // SAFETY: valid out-pointer.
    unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
    }
}

/// Report a startup failure to the relay and end. `fd` is the status pipe.
/// Async-signal-safe.
unsafe fn shim_fail(fd: libc::c_int, code: libc::c_int, exit: libc::c_int) -> ! {
    // SAFETY: as `shim_fail_tagged`.
    unsafe { shim_fail_tagged(fd, TAG_GENERIC, code, exit) }
}

/// The first byte of a startup failure message. `TAG_GENERIC` is any failure
/// before the CLI ran; the others name a step of the privilege drop, whose
/// failure must never let the caller launch the CLI unrelayed (it would start
/// with the relay's own identity).
const TAG_GENERIC: u8 = b'E';
const TAG_SETGROUPS: u8 = b'G';
const TAG_CAPS: u8 = b'A';
const TAG_SETGID: u8 = b'g';
const TAG_SETUID: u8 = b'U';
const TAG_VERIFY: u8 = b'V';

/// The fixed-vocabulary step a privilege-drop tag names (`None` for a
/// generic failure or an unknown byte).
fn drop_step_of(tag: u8) -> Option<&'static str> {
    match tag {
        TAG_SETGROUPS => Some("setgroups"),
        TAG_CAPS => Some("capabilities"),
        TAG_SETGID => Some("setgid"),
        TAG_SETUID => Some("setuid"),
        TAG_VERIFY => Some("verify_drop"),
        _ => None,
    }
}

/// [`shim_fail`] with the failure's step tag as the message's first byte.
unsafe fn shim_fail_tagged(fd: libc::c_int, tag: u8, code: libc::c_int, exit: libc::c_int) -> ! {
    // SAFETY: write to a descriptor we hold; _exit never returns.
    unsafe {
        let mut msg = [tag, 0, 0, 0, 0];
        msg[1..].copy_from_slice(&code.to_le_bytes());
        let _ = libc::write(fd, msg.as_ptr().cast(), msg.len());
        libc::_exit(exit)
    }
}

/// What the credentials of the CLI process read as after the drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DropState {
    ruid: u32,
    euid: u32,
    suid: u32,
    rgid: u32,
    egid: u32,
    sgid: u32,
    /// `errno` of an attempt to become uid 0 again (`None`: not attempted).
    regain_uid: Option<i32>,
    /// `errno` of an attempt to become gid 0 again (`None`: not attempted).
    regain_gid: Option<i32>,
    /// Permitted, effective and inheritable capability sets (always 0 where
    /// not Linux).
    cap_permitted: u64,
    cap_effective: u64,
    cap_inheritable: u64,
    /// How many supplementary groups the process has (`-1`: unreadable).
    ngroups: i32,
    /// The only supplementary group when there is exactly one (`u32::MAX`
    /// otherwise).
    group0: u32,
}

/// What a drop that did not take effect got wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropMismatch {
    Uid,
    Gid,
    RegainUid,
    RegainGid,
    Capabilities,
    Groups,
}

/// Whether `state` is exactly the requested identity: every uid and gid slot
/// the target, no way back to uid 0 / gid 0 (where the target is not root
/// itself), and no capability left. Pure, so it is tested against injected
/// values on any host.
fn verify_dropped(uid: Option<u32>, gid: Option<u32>, s: &DropState) -> Result<(), DropMismatch> {
    verify_dropped_for(cfg!(target_os = "linux"), uid, gid, s)
}

/// [`verify_dropped`] for a stated OS family, so the injected-value tests
/// cover both on any host. Supplementary groups: none at all on Linux; on
/// macOS `getgroups` also lists the effective gid, so at most that one.
fn verify_dropped_for(
    linux: bool,
    uid: Option<u32>,
    gid: Option<u32>,
    s: &DropState,
) -> Result<(), DropMismatch> {
    let groups_ok = if linux {
        s.ngroups == 0
    } else {
        s.ngroups == 0 || (s.ngroups == 1 && s.group0 == s.egid)
    };
    if !groups_ok {
        return Err(DropMismatch::Groups);
    }
    if let Some(g) = gid {
        if s.rgid != g || s.egid != g || s.sgid != g {
            return Err(DropMismatch::Gid);
        }
    }
    if let Some(u) = uid {
        if s.ruid != u || s.euid != u || s.suid != u {
            return Err(DropMismatch::Uid);
        }
        if u != 0 {
            if s.regain_uid != Some(libc::EPERM) {
                return Err(DropMismatch::RegainUid);
            }
            if gid.is_some_and(|g| g != 0) && s.regain_gid != Some(libc::EPERM) {
                return Err(DropMismatch::RegainGid);
            }
            if s.cap_permitted != 0 || s.cap_effective != 0 || s.cap_inheritable != 0 {
                return Err(DropMismatch::Capabilities);
            }
        }
    }
    Ok(())
}

/// Read the credentials now. With `probe`, also try to become root again (a
/// failure is the expected answer; success means the drop did not hold, and
/// the caller ends the launch).
unsafe fn read_drop_state(probe: bool) -> DropState {
    // SAFETY: plain syscalls on the calling process; no allocation.
    unsafe {
        #[cfg(target_os = "linux")]
        let (ruid, euid, suid, rgid, egid, sgid) = {
            let (mut r, mut e, mut s) = (u32::MAX, u32::MAX, u32::MAX);
            let (mut rg, mut eg, mut sg) = (u32::MAX, u32::MAX, u32::MAX);
            // A failed read leaves u32::MAX: no target equals it by accident.
            libc::getresuid(&mut r, &mut e, &mut s);
            libc::getresgid(&mut rg, &mut eg, &mut sg);
            (r, e, s, rg, eg, sg)
        };
        // The saved ids cannot be read here; the `setuid(0)` probe covers them.
        #[cfg(not(target_os = "linux"))]
        let (ruid, euid, suid, rgid, egid, sgid) = {
            let (u, eu, g, eg) = (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            );
            (u, eu, eu, g, eg, eg)
        };
        let regain_uid = probe.then(|| {
            if libc::setuid(0) == -1 {
                *errno_location()
            } else {
                0
            }
        });
        let regain_gid = probe.then(|| {
            if libc::setgid(0) == -1 {
                *errno_location()
            } else {
                0
            }
        });
        let (cap_permitted, cap_effective, cap_inheritable) = read_capabilities();
        let ngroups = libc::getgroups(0, std::ptr::null_mut());
        let mut group0 = u32::MAX;
        if ngroups == 1 {
            let mut g = [0 as libc::gid_t; 1];
            if libc::getgroups(1, g.as_mut_ptr()) == 1 {
                group0 = g[0];
            }
        }
        DropState {
            ruid,
            euid,
            suid,
            rgid,
            egid,
            sgid,
            regain_uid,
            regain_gid,
            cap_permitted,
            cap_effective,
            cap_inheritable,
            ngroups,
            group0,
        }
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The capability sets of this process as the kernel reports them.
#[cfg(target_os = "linux")]
unsafe fn capget_raw() -> Option<(CapHeader, [CapData; 2])> {
    // _LINUX_CAPABILITY_VERSION_3: two data words, 64 capability bits.
    let mut head = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capget with a valid header and two data words.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &mut head, data.as_mut_ptr()) };
    (rc != -1).then_some((head, data))
}

/// Permitted, effective and inheritable capability sets of this process
/// (`u64::MAX` for all three when the read fails, which the verification then
/// refuses).
#[cfg(target_os = "linux")]
unsafe fn read_capabilities() -> (u64, u64, u64) {
    // SAFETY: plain syscall on this process.
    let Some((_, data)) = (unsafe { capget_raw() }) else {
        return (u64::MAX, u64::MAX, u64::MAX);
    };
    let word = |f: fn(&CapData) -> u32| u64::from(f(&data[0])) | u64::from(f(&data[1])) << 32;
    (
        word(|d| d.permitted),
        word(|d| d.effective),
        word(|d| d.inheritable),
    )
}

#[cfg(not(target_os = "linux"))]
unsafe fn read_capabilities() -> (u64, u64, u64) {
    (0, 0, 0)
}

/// Zero the inheritable capability set, while the process is still
/// privileged: an inheritable capability can come back through a file
/// capability on the CLI's `exec` target, and the uid change does not clear
/// it. Permitted and effective are left as they are (the uid change clears
/// them, and the read-back verifies it).
#[cfg(target_os = "linux")]
unsafe fn clear_inheritable_capabilities() -> Result<(), libc::c_int> {
    // SAFETY: plain syscalls on this process.
    unsafe {
        let Some((mut head, mut data)) = capget_raw() else {
            return Err(*errno_location());
        };
        data[0].inheritable = 0;
        data[1].inheritable = 0;
        if libc::syscall(libc::SYS_capset, &mut head, data.as_ptr()) == -1 {
            return Err(*errno_location());
        }
    }
    Ok(())
}

/// The privilege drop, in the forked CLI before `exec`: supplementary groups
/// cleared, then (Linux) ambient capabilities, then the group, then the user,
/// every id slot set at once; then the result is read back and any mismatch
/// refuses the launch. `Err` is the failing step's tag and an `errno`.
unsafe fn drop_privileges(uid: Option<u32>, gid: Option<u32>) -> Result<(), (u8, libc::c_int)> {
    if uid.is_none() && gid.is_none() {
        return Ok(());
    }
    // SAFETY: plain syscalls on the calling (freshly forked) process.
    unsafe {
        // Never keep the caller's supplementary groups.
        if libc::setgroups(0, std::ptr::null()) == -1 {
            return Err((TAG_SETGROUPS, *errno_location()));
        }
        // Inheritable capabilities go while the process can still change them.
        #[cfg(target_os = "linux")]
        if let Err(errno) = clear_inheritable_capabilities() {
            return Err((TAG_CAPS, errno));
        }
        // An ambient capability would survive the uid change: PR_CAP_AMBIENT
        // (47), PR_CAP_AMBIENT_CLEAR_ALL (4). A kernel without ambient
        // capabilities (EINVAL) has none to clear.
        #[cfg(target_os = "linux")]
        if libc::prctl(47, 4, 0, 0, 0) == -1 && *errno_location() != libc::EINVAL {
            return Err((TAG_CAPS, *errno_location()));
        }
        if let Some(g) = gid {
            #[cfg(target_os = "linux")]
            let rc = libc::setresgid(g, g, g);
            #[cfg(not(target_os = "linux"))]
            let rc = libc::setgid(g);
            if rc == -1 {
                return Err((TAG_SETGID, *errno_location()));
            }
        }
        if let Some(u) = uid {
            #[cfg(target_os = "linux")]
            let rc = libc::setresuid(u, u, u);
            #[cfg(not(target_os = "linux"))]
            let rc = libc::setuid(u);
            if rc == -1 {
                return Err((TAG_SETUID, *errno_location()));
            }
        }
        let probe = uid.is_some_and(|u| u != 0);
        let state = read_drop_state(probe);
        if verify_dropped(uid, gid, &state).is_err() {
            return Err((TAG_VERIFY, libc::EPERM));
        }
    }
    Ok(())
}

/// What the forked shim needs, all built before the fork so the child
/// allocates nothing. The pointer vectors borrow `_owned`.
struct ShimPlan {
    slave: RawFd,
    st_w: RawFd,
    up_w: RawFd,
    ctl_r: RawFd,
    program: CString,
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    cwd: Option<CString>,
    uid: Option<u32>,
    gid: Option<u32>,
    /// The core-file soft limit the CLI gets back (the relay's and the shim's
    /// own are zero).
    core_soft: u64,
    /// The relay's pid, taken BEFORE the fork. Read in the child it would be
    /// whatever the child was reparented to if the relay died in between, and
    /// the liveness poll would then never fire.
    relay: libc::pid_t,
    /// One past the highest descriptor open when the plan was built.
    fd_ceiling: u64,
    _owned: Vec<CString>,
}

/// Flatten a validated spec into a [`ShimPlan`].
fn shim_plan(
    spec: &LaunchSpec,
    slave: RawFd,
    st_w: RawFd,
    up_w: RawFd,
    ctl_r: RawFd,
) -> io::Result<ShimPlan> {
    let nul = |_| io::Error::from_raw_os_error(libc::EINVAL);
    let program = CString::new(resolve_program(spec)?.as_os_str().as_bytes()).map_err(nul)?;
    let mut owned = Vec::new();
    let argv0 = spec.arg0.as_ref().unwrap_or(&spec.program);
    owned.push(CString::new(argv0.as_bytes()).map_err(nul)?);
    for a in &spec.args {
        owned.push(CString::new(a.as_bytes()).map_err(nul)?);
    }
    let argc = owned.len();
    for (k, v) in &spec.env {
        let mut kv = k.as_bytes().to_vec();
        kv.push(b'=');
        kv.extend_from_slice(v.as_bytes());
        owned.push(CString::new(kv).map_err(nul)?);
    }
    let cwd = match &spec.cwd {
        Some(d) => Some(CString::new(d.as_os_str().as_bytes()).map_err(nul)?),
        None => None,
    };
    let mut argv: Vec<*const libc::c_char> = owned[..argc].iter().map(|c| c.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = owned[argc..].iter().map(|c| c.as_ptr()).collect();
    envp.push(std::ptr::null());
    Ok(ShimPlan {
        slave,
        st_w,
        up_w,
        ctl_r,
        program,
        argv,
        envp,
        cwd,
        uid: spec.uid,
        gid: spec.gid,
        core_soft: original_core_soft()?,
        relay: relay_pid(),
        fd_ceiling: open_fd_ceiling(),
        _owned: owned,
    })
}

/// The shim (spec 34 §34.2.1 (f), journal context-trim/0010 (on dev)): the
/// session leader of the CLI's terminal. It forks the CLI into its OWN
/// process group so that group is not orphaned (its parent, the shim, shares
/// its session), which is what lets a real `^Z` stop it. The shim itself
/// NEVER stops: when the CLI stops it takes the terminal back and tells the
/// relay (byte `S` on the up pipe); the relay stops itself for the outer
/// shell and, on resume, answers `R` on the control pipe, which hands the
/// terminal to the CLI and continues it. If the control pipe reaches EOF the
/// relay is gone (even `SIGKILL`): the shim ends the CLI's group
/// (`SIGCONT`, `SIGTERM`, then `SIGKILL` after [`SHIM_ORPHAN_GRACE_MS`]) so no
/// stopped or headless CLI outlives its relay. It forwards session signals,
/// mirrors the CLI's exit (code, or the same signal re-raised, with core
/// dumps off) and reports every setup failure on the status pipe. A fault
/// signal (`SIGSEGV` and kin), real or sent, ends the CLI's group first
/// (`shim_fault`). Async-signal-safe calls only; never returns.
unsafe fn shim_main(plan: &ShimPlan) -> ! {
    // SAFETY: a freshly forked child of a possibly multi-threaded process:
    // raw syscalls on its own state only, no allocation, no locks.
    unsafe {
        let st = plan.st_w;
        // Move the three pipe ends out of the way of the numbers they will
        // take, before anything is dup2'ed over them.
        let hi_st = libc::fcntl(plan.st_w, libc::F_DUPFD, 10);
        let hi_up = libc::fcntl(plan.up_w, libc::F_DUPFD, 10);
        let hi_ctl = libc::fcntl(plan.ctl_r, libc::F_DUPFD, 10);
        if hi_st == -1 || hi_up == -1 || hi_ctl == -1 {
            shim_fail(st, *errno_location(), 126);
        }
        let st = hi_st;
        reset_dispositions();
        // A relay that died since the fork has left this process reparented:
        // there is nothing to relay for, and the baseline below would be wrong.
        if libc::getppid() != plan.relay {
            shim_fail(st, libc::ESRCH, 126);
        }
        SHIM_RELAY.store(plan.relay, Ordering::Release);
        // The shim carries the launch environment: no dump of it, ever (the
        // relay did this too; this covers a caller that spawned directly). The
        // CLI gets `plan.core_soft` back just before its `exec`.
        if disable_core_dumps().is_none() {
            shim_fail(st, *errno_location(), 126);
        }
        if libc::setsid() == -1 {
            shim_fail(st, *errno_location(), 126);
        }
        for fd in 0..3 {
            if libc::dup2(plan.slave, fd) == -1 {
                shim_fail(st, *errno_location(), 126);
            }
        }
        if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
            shim_fail(st, *errno_location(), 126);
        }
        if libc::dup2(hi_st, SHIM_ST) == -1
            || libc::dup2(hi_up, SHIM_UP) == -1
            || libc::dup2(hi_ctl, SHIM_CTL) == -1
        {
            shim_fail(st, *errno_location(), 126);
        }
        let st = SHIM_ST;
        close_from(SHIM_CHLD_R, plan.fd_ceiling);
        // Our own wake pipe for SIGCHLD.
        let mut wake = [0 as libc::c_int; 2];
        if libc::pipe(wake.as_mut_ptr()) == -1
            || libc::dup2(wake[0], SHIM_CHLD_R) == -1
            || libc::dup2(wake[1], SHIM_CHLD_W) == -1
        {
            shim_fail(st, *errno_location(), 126);
        }
        for fd in [SHIM_CHLD_R, SHIM_CHLD_W, SHIM_CTL, SHIM_UP] {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl == -1 || libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) == -1 {
                shim_fail(st, *errno_location(), 126);
            }
        }
        for fd in [SHIM_ST, SHIM_UP, SHIM_CTL, SHIM_CHLD_R, SHIM_CHLD_W] {
            let fl = libc::fcntl(fd, libc::F_GETFD);
            if fl == -1 || libc::fcntl(fd, libc::F_SETFD, fl | libc::FD_CLOEXEC) == -1 {
                shim_fail(st, *errno_location(), 126);
            }
        }
        SHIM_WAKE.store(SHIM_CHLD_W, Ordering::Release);

        // Handlers, with every signal still blocked from before the fork.
        let fwd = sigaction_for(
            shim_forward as *const () as libc::sighandler_t,
            libc::SA_RESTART,
        );
        let sess = [
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGQUIT,
            libc::SIGALRM,
            libc::SIGUSR1,
            libc::SIGUSR2,
            // A stray `pkill -ABRT` is forwarded rather than killing the
            // shim (and, un-dumped, leaving the CLI unwatched).
            libc::SIGABRT,
        ];
        for sig in sess {
            if libc::sigaction(sig, &fwd, std::ptr::null_mut()) == -1 {
                shim_fail(st, *errno_location(), 126);
            }
        }
        // Every other default-terminating signal is forwarded too, so a stray
        // one cannot kill the shim and leave the CLI running unwatched.
        for &sig in FATAL {
            if libc::sigaction(sig, &fwd, std::ptr::null_mut()) == -1 {
                shim_fail(st, *errno_location(), 126);
            }
        }
        #[cfg(target_os = "linux")]
        for sig in libc::SIGRTMIN()..=libc::SIGRTMAX() {
            // A reserved real-time signal refuses a handler; nothing to guard.
            let _ = libc::sigaction(sig, &fwd, std::ptr::null_mut());
        }
        // The fault signals take the CLI with the shim (see `shim_fault`).
        let fault = sigaction_for(shim_fault as *const () as libc::sighandler_t, 0);
        for sig in [
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGILL,
            libc::SIGFPE,
            libc::SIGTRAP,
        ] {
            if libc::sigaction(sig, &fault, std::ptr::null_mut()) == -1 {
                shim_fail(st, *errno_location(), 126);
            }
        }
        let mut kill = sigaction_for(0, libc::SA_RESTART | libc::SA_SIGINFO);
        kill.sa_sigaction = shim_kill as *const () as libc::sighandler_t;
        let chld = sigaction_for(shim_chld as *const () as libc::sighandler_t, 0);
        let ign = sigaction_for(libc::SIG_IGN, 0);
        if libc::sigaction(libc::SIGURG, &kill, std::ptr::null_mut()) == -1
            || libc::sigaction(libc::SIGCHLD, &chld, std::ptr::null_mut()) == -1
            || libc::sigaction(libc::SIGPIPE, &ign, std::ptr::null_mut()) == -1
            || libc::sigaction(libc::SIGTTOU, &ign, std::ptr::null_mut()) == -1
        {
            shim_fail(st, *errno_location(), 126);
        }

        // The CLI waits on this pipe until it owns the terminal's foreground.
        let mut gate = [0 as libc::c_int; 2];
        if libc::pipe(gate.as_mut_ptr()) == -1 {
            shim_fail(st, *errno_location(), 126);
        }
        let cli = libc::fork();
        if cli == -1 {
            shim_fail(st, *errno_location(), 126);
        }
        if cli == 0 {
            shim_cli(plan, gate);
        }
        libc::close(gate[0]);
        // Only the shim moves the CLI into its own group, never the CLI as
        // well: the CLI cannot exec (or do anything else) before the gate
        // opens, so the shell's both-sides `setpgid` race does not exist
        // here, and calling it from both sides at once is not harmless — on
        // macOS the parent's call can fail with EPERM while the child is
        // inside its own `setpgid`, which failed the launch under load.
        if libc::setpgid(cli, cli) == -1 {
            let e = *errno_location();
            libc::kill(cli, libc::SIGKILL);
            shim_fail(st, e, 126);
        }
        if libc::tcsetpgrp(0, cli) == -1 {
            let e = *errno_location();
            libc::kill(cli, libc::SIGKILL);
            shim_fail(st, e, 126);
        }
        SHIM_CLI.store(cli, Ordering::Release);
        if libc::write(gate[1], b"g".as_ptr().cast(), 1) != 1 {
            let e = *errno_location();
            libc::kill(-cli, libc::SIGKILL);
            shim_fail(st, e, 126);
        }
        libc::close(gate[1]);
        // Only the CLI's copy of the status pipe may remain: its exec closes
        // it, which is how the relay learns the CLI started.
        libc::close(SHIM_ST);
        if !clear_signal_mask() {
            libc::kill(-cli, libc::SIGKILL);
            libc::_exit(126);
        }
        shim_watch(cli)
    }
}

/// The forked CLI: own group, wait for the terminal, shed the shim's state,
/// drop privileges if asked, `exec`. Failure is reported on fd 3.
unsafe fn shim_cli(plan: &ShimPlan, gate: [libc::c_int; 2]) -> ! {
    // SAFETY: freshly forked child; raw syscalls only.
    unsafe {
        libc::close(gate[1]);
        let mut b = 0u8;
        // EOF means the shim died before it handed over the terminal.
        if libc::read(gate[0], (&mut b as *mut u8).cast(), 1) != 1 {
            libc::_exit(126);
        }
        libc::close(gate[0]);
        // The shim put this process in a group of its own before opening the
        // gate (it never opens it otherwise); a CLI anywhere else is refused.
        if libc::getpgrp() != libc::getpid() {
            shim_fail(SHIM_ST, libc::EPERM, 127);
        }
        reset_dispositions();
        if !clear_signal_mask() {
            shim_fail(SHIM_ST, *errno_location(), 127);
        }
        libc::close(SHIM_UP);
        libc::close(SHIM_CTL);
        libc::close(SHIM_CHLD_R);
        libc::close(SHIM_CHLD_W);
        let mut core: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_CORE, &mut core) == -1 {
            shim_fail(SHIM_ST, *errno_location(), 127);
        }
        core.rlim_cur = plan.core_soft as libc::rlim_t;
        if libc::setrlimit(libc::RLIMIT_CORE, &core) == -1 {
            shim_fail(SHIM_ST, *errno_location(), 127);
        }
        if let Err((tag, e)) = drop_privileges(plan.uid, plan.gid) {
            shim_fail_tagged(SHIM_ST, tag, e, 127);
        }
        if let Some(cwd) = &plan.cwd {
            if libc::chdir(cwd.as_ptr()) == -1 {
                shim_fail(SHIM_ST, *errno_location(), 127);
            }
        }
        libc::execve(
            plan.program.as_ptr(),
            plan.argv.as_ptr(),
            plan.envp.as_ptr(),
        );
        shim_fail(SHIM_ST, *errno_location(), 127)
    }
}

/// The byte the shim reports a CLI stop with: the high bit marks a stop
/// report, the low seven bits are the number of `R` bytes the shim had read
/// when the CLI stopped (mod 128).
fn stop_report(resumes: u8) -> u8 {
    0x80 | (resumes & 0x7f)
}

/// Whether `bytes` (read from the shim's up pipe) hold a stop report that is
/// still true: one stamped with the number of resumes the relay has since
/// written. A report stamped with fewer describes a stop the shim saw before it
/// read the latest `R`; that `R` continued the CLI, so the stop is over and
/// acting on it would stop the relay for a CLI that is running.
fn holds_current_stop(bytes: &[u8], resumes_sent: u8) -> bool {
    bytes
        .iter()
        .any(|b| b & 0x80 != 0 && (b ^ resumes_sent) & 0x7f == 0)
}

/// The shim's main loop: reap and mirror the CLI, report its stops, honour
/// the relay's `R` and its disappearance.
unsafe fn shim_watch(cli: libc::pid_t) -> ! {
    // SAFETY: raw syscalls on the shim's own state.
    unsafe {
        let mut ctl_open = true;
        let mut deadline: Option<u64> = None;
        let mut killed = false;
        // Resume bytes read so far (mod 128): stamped on every stop report
        // so the relay can tell a stop that an `R` has since undone.
        let mut resumes: u8 = 0;
        loop {
            let mut fds = [
                libc::pollfd {
                    fd: SHIM_CHLD_R,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if ctl_open { SHIM_CTL } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // A bounded wait while the control pipe is open, so a relay that
            // died with a leaked copy of the pipe's write end (macOS has no
            // atomic close-on-exec pipe) is still noticed through its pid.
            let timeout = match deadline {
                Some(d) if !killed => d.saturating_sub(now_ms()).min(1 << 30) as libc::c_int,
                _ if ctl_open => SHIM_LIVENESS_POLL_MS,
                _ => -1,
            };
            if libc::poll(fds.as_mut_ptr(), 2, timeout) == -1 && *errno_location() != libc::EINTR {
                libc::kill(-cli, libc::SIGKILL);
                libc::_exit(125);
            }
            let mut sink = [0u8; 32];
            while libc::read(SHIM_CHLD_R, sink.as_mut_ptr().cast(), sink.len()) > 0 {}
            if ctl_open && libc::getppid() != SHIM_RELAY.load(Ordering::Acquire) {
                // Reparented: the relay is gone (same handling as EOF).
                ctl_open = false;
                libc::kill(-cli, libc::SIGCONT);
                libc::kill(-cli, libc::SIGTERM);
                deadline = Some(now_ms() + SHIM_ORPHAN_GRACE_MS);
            }
            if ctl_open {
                loop {
                    let n = libc::read(SHIM_CTL, sink.as_mut_ptr().cast(), sink.len());
                    if n > 0 {
                        resumes = resumes.wrapping_add(n as u8);
                        // `R`: the relay is foregrounded again. A CLI that
                        // cannot be given the terminal could never read it:
                        // it is ended, and the shim mirrors that.
                        if !foreground_then_continue(cli) {
                            libc::kill(-cli, libc::SIGKILL);
                        }
                    } else if n == 0 {
                        // The relay is gone, however it died.
                        ctl_open = false;
                        libc::kill(-cli, libc::SIGCONT);
                        libc::kill(-cli, libc::SIGTERM);
                        deadline = Some(now_ms() + SHIM_ORPHAN_GRACE_MS);
                        break;
                    } else {
                        break;
                    }
                }
            }
            if let Some(d) = deadline {
                if !killed && now_ms() >= d {
                    killed = true;
                    libc::kill(-cli, libc::SIGKILL);
                }
            }
            // Signals blocked from the reap until SHIM_CLI is cleared, so a
            // forwarding handler can never signal a reaped (reusable) group.
            let mut all: libc::sigset_t = std::mem::zeroed();
            libc::sigfillset(&mut all);
            libc::sigprocmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
            loop {
                let mut st: libc::c_int = 0;
                let r = libc::waitpid(cli, &mut st, libc::WNOHANG | libc::WUNTRACED);
                if r == 0 {
                    let _ = clear_signal_mask();
                    break;
                }
                if r == -1 {
                    if *errno_location() == libc::EINTR {
                        continue;
                    }
                    // Not ours any more or unreadable: never leave the CLI
                    // running unwatched.
                    libc::kill(-cli, libc::SIGKILL);
                    libc::_exit(125);
                }
                if libc::WIFSTOPPED(st) {
                    // Take the terminal back and tell the relay to stop for
                    // the outer shell. Without the hand-back the relay's
                    // shell could not own the terminal; without the report
                    // the relay would not stop: either failure ends the CLI.
                    // A full pipe (EAGAIN) already holds an unread `S`.
                    if libc::tcsetpgrp(0, libc::getpgrp()) == -1 {
                        libc::kill(-cli, libc::SIGKILL);
                        continue;
                    }
                    let report = stop_report(resumes);
                    let w = libc::write(SHIM_UP, (&report as *const u8).cast(), 1);
                    if w == -1
                        && !matches!(*errno_location(), libc::EAGAIN | libc::EINTR | libc::EPIPE)
                    {
                        libc::kill(-cli, libc::SIGKILL);
                    }
                    continue;
                }
                SHIM_CLI.store(0, Ordering::Release);
                if libc::WIFEXITED(st) {
                    libc::_exit(libc::WEXITSTATUS(st));
                }
                let sig = libc::WTERMSIG(st);
                reset_dispositions();
                // Core dumps were disabled at start (`disable_core_dumps`).
                let _ = clear_signal_mask();
                libc::raise(sig);
                libc::_exit(128 + sig);
            }
        }
    }
}

/// A pipe with both ends close-on-exec. Linux creates it atomically; macOS
/// has no `pipe2`, so the two `fcntl`s leave the window `std` itself has
/// there (a concurrent `fork` in another thread between the calls).
fn cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    #[cfg(target_os = "linux")]
    {
        // SAFETY: valid 2-element out array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: valid 2-element out array.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        for fd in fds {
            if let Err(e) = set_cloexec_always(fd) {
                // SAFETY: both descriptors are fresh and ours.
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                return Err(e);
            }
        }
    }
    // SAFETY: two fresh descriptors we now own.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

#[cfg(not(target_os = "linux"))]
fn set_cloexec_always(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags == -1 || libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A started shim: its pid (also its process group id), the control pipe the
/// relay writes (`R`; its closure means "the relay is gone") and the pipe the
/// shim reports CLI stops on.
pub struct Spawned {
    pid: libc::pid_t,
    ctl: OwnedFd,
    up: OwnedFd,
}

/// Spawn the spec behind the job-control shim, on the slave as stdin, stdout
/// and stderr and as the shim's controlling terminal. The CLI inherits no
/// other descriptor (the shim closes every one above 2, so the relay's master,
/// sockets and nonce files never reach it) and no signal state. Returns once the CLI
/// has `exec`ed (or failed to: that is an error, with the CLI never run). The
/// shim is the relay's direct child; it mirrors the CLI's exit. The parent's
/// slave copy is closed before return, so master EOF is reachable once the
/// child side closes.
fn spawn_on_slave(spec: &LaunchSpec, slave: OwnedFd) -> Result<Spawned, SpawnFailure> {
    let (st_r, st_w) = cloexec_pipe()?;
    let (up_r, up_w) = cloexec_pipe()?;
    let (ctl_r, ctl_w) = cloexec_pipe()?;
    let plan = shim_plan(
        spec,
        slave.as_raw_fd(),
        st_w.as_raw_fd(),
        up_w.as_raw_fd(),
        ctl_r.as_raw_fd(),
    )?;
    // Everything blocked across the fork: the relay's own handlers must never
    // run in the child (they would write to the relay's wake channel).
    // SAFETY: sigset manipulation on stack storage; `shim_main` never returns.
    let pid = unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut old);
        let pid = libc::fork();
        if pid == 0 {
            shim_main(&plan);
        }
        let err = io::Error::last_os_error();
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        if pid == -1 {
            return Err(err.into());
        }
        pid
    };
    drop((slave, st_w, up_w, ctl_r));
    // The status pipe stays open until the CLI execs; a message on it is a
    // failure before the CLI ran.
    let (msg, got) = match read_startup_status(
        st_r.as_raw_fd(),
        Duration::from_millis(SPAWN_STATUS_WAIT_MS),
    ) {
        Ok(r) => r,
        Err(e) => {
            terminate_child(pid, Duration::from_millis(TERMINATE_GRACE_MS));
            return Err(e.into());
        }
    };
    if got != 0 {
        terminate_child(pid, Duration::from_millis(TERMINATE_GRACE_MS));
        let (errno, drop_step) = decode_startup_failure(&msg, got);
        return Err(SpawnFailure {
            err: io::Error::from_raw_os_error(errno),
            drop_step,
            started: false,
        });
    }
    finish_spawn(pid, up_r, ctl_w, &set_nonblock)
}

/// The last step of a spawn, AFTER the CLI has exec'ed: both pipe ends become
/// non-blocking. A failure here is a started child (it ran, and is ended
/// here), never `NotStarted`: the caller must not launch the CLI again.
/// `nonblock` is a parameter so a test can make it fail.
fn finish_spawn(
    pid: libc::pid_t,
    up_r: OwnedFd,
    ctl_w: OwnedFd,
    nonblock: &dyn Fn(RawFd) -> io::Result<()>,
) -> Result<Spawned, SpawnFailure> {
    if let Err(err) = nonblock(up_r.as_raw_fd()).and_then(|()| nonblock(ctl_w.as_raw_fd())) {
        terminate_child(pid, Duration::from_millis(TERMINATE_GRACE_MS));
        return Err(SpawnFailure {
            err,
            drop_step: None,
            started: true,
        });
    }
    Ok(Spawned {
        pid,
        ctl: ctl_w,
        up: up_r,
    })
}

/// Read the startup status message (5 bytes: `E` and an errno) from `fd`,
/// waiting at most `bound`. Bounded because where a foreign fork can leak the
/// pipe's write end (macOS) EOF may never come: a failure is reported at once,
/// so silence after the bound means the CLI started. Returns the bytes and how
/// many arrived (0 on EOF or silence).
fn read_startup_status(fd: RawFd, bound: Duration) -> io::Result<([u8; 5], usize)> {
    let mut msg = [0u8; 5];
    let mut got = 0;
    let end = Instant::now() + bound;
    while got < msg.len() {
        let left = end.saturating_duration_since(Instant::now());
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let rc = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(1 << 30) as libc::c_int) };
        if rc == 0 {
            break;
        }
        if rc == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        match read_fd(fd, &mut msg[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok((msg, got))
}

/// [`end_child`] where the child's own exit is of no interest.
fn terminate_child(pid: libc::pid_t, grace: Duration) {
    end_child(pid, grace);
}

/// End a child nobody is going to relay for any more: `SIGHUP` then
/// `SIGCONT` (a stopped child acts on a pending `SIGHUP` only once it runs),
/// then `SIGKILL` after `grace`, and reap it. Never signals after the child
/// is reaped, and does nothing when `waitpid` reports it is not ours.
///
/// Returns the child's own exit when it had already ended by itself before a
/// single signal was sent (the status that reaping it here would otherwise
/// discard); `None` when this call had to end it, or it was not ours.
fn end_child(pid: libc::pid_t, grace: Duration) -> Option<RelayExit> {
    // Ownership first: signalling a pid that is not an unreaped child of
    // this process could hit a recycled process group.
    match wait_nohang(pid) {
        Waited::Gone => return None,
        Waited::Done(exit) => return Some(exit),
        Waited::Running | Waited::Stopped => {}
    }
    // SAFETY: wait_nohang just reported the pid as our unreaped child.
    unsafe {
        libc::kill(-pid, libc::SIGHUP);
        libc::kill(-pid, libc::SIGCONT);
    }
    let deadline = Instant::now() + grace;
    loop {
        match wait_nohang(pid) {
            Waited::Gone | Waited::Done(_) => return None,
            Waited::Running => {}
            // SAFETY: still our unreaped child; a stopped shim cannot act.
            Waited::Stopped => unsafe {
                libc::kill(-pid, libc::SIGCONT);
            },
        }
        if Instant::now() >= deadline {
            break;
        }
        // SAFETY: poll with no descriptors is a 20 ms timer.
        unsafe { libc::poll(std::ptr::null_mut(), 0, 20) };
    }
    // SAFETY: still unreaped (wait_nohang just said so). SIGURG asks a shim
    // to SIGKILL the CLI's group (it is a different group from the shim's,
    // and a plain child ignores SIGURG); then the shim itself goes.
    unsafe {
        libc::kill(-pid, libc::SIGURG);
        libc::kill(-pid, libc::SIGCONT);
    }
    let urg_deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < urg_deadline {
        match wait_nohang(pid) {
            Waited::Gone | Waited::Done(_) => return None,
            Waited::Running => {}
            // SAFETY: still our unreaped child.
            Waited::Stopped => unsafe {
                libc::kill(-pid, libc::SIGCONT);
            },
        }
        // SAFETY: poll with no descriptors is a 10 ms timer.
        unsafe { libc::poll(std::ptr::null_mut(), 0, 10) };
    }
    // SAFETY: still unreaped (the loop above reaps on exit). The pid itself
    // as well as its group: before the shim's `setsid` the group does not
    // exist yet and the group kill alone would leave the blocking wait below
    // waiting for a shim nobody ended.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::kill(-pid, libc::SIGKILL);
    };
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r != -1 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return None;
        }
    }
}

enum Waited {
    Running,
    Stopped,
    /// Reaped by this call, with how it ended.
    Done(RelayExit),
    /// `ECHILD`: someone else reaped it; the pid is no longer ours to signal.
    Gone,
}

fn wait_nohang(pid: libc::pid_t) -> Waited {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
        if r == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Waited::Gone;
        }
        if r == 0 {
            return Waited::Running;
        }
        if libc::WIFSTOPPED(status) {
            return Waited::Stopped;
        }
        if libc::WIFEXITED(status) {
            return Waited::Done(RelayExit::Exited(libc::WEXITSTATUS(status)));
        }
        if libc::WIFSIGNALED(status) {
            return Waited::Done(RelayExit::Signaled(libc::WTERMSIG(status)));
        }
    }
}

// ---------------------------------------------------------------------------
// Signals

/// The process-wide wake channel the handlers write to. It is created once
/// and never closed, so a handler that is mid-flight can never write into a
/// reused descriptor number.
struct WakeChannel {
    read: OwnedFd,
    _write: OwnedFd,
}

static WAKE: OnceLock<WakeChannel> = OnceLock::new();
/// Write end of [`WAKE`]; `-1` until the channel exists.
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);
static RELAY_ACTIVE: AtomicBool = AtomicBool::new(false);

/// A wake channel with both ends close-on-exec and non-blocking from the
/// moment they exist. Linux has `pipe2`; macOS has no atomic pipe, so a
/// raw-mode pseudo-terminal pair (whose creation is atomic, see
/// [`Pty::open`]) stands in.
fn make_wake_channel() -> io::Result<WakeChannel> {
    #[cfg(target_os = "linux")]
    {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: valid 2-element out array.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe2 returned two fresh descriptors we now own.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        Ok(WakeChannel {
            read,
            _write: write,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let Pty { master, slave } = Pty::open(None, None)?;
        let mut t = term::get_termios(slave.as_raw_fd())?;
        // SAFETY: valid termios; raw mode so bytes pass through unchanged.
        unsafe { libc::cfmakeraw(&mut t) };
        // SAFETY: valid termios for the call.
        if unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &t) } == -1 {
            return Err(io::Error::last_os_error());
        }
        set_nonblock(master.as_raw_fd())?;
        set_nonblock(slave.as_raw_fd())?;
        Ok(WakeChannel {
            read: master,
            _write: slave,
        })
    }
}

fn wake_channel() -> io::Result<&'static WakeChannel> {
    if let Some(w) = WAKE.get() {
        return Ok(w);
    }
    let fresh = make_wake_channel()?;
    // A concurrent initialiser may win; the loser's channel is dropped
    // before any handler could have been pointed at it.
    let _ = WAKE.set(fresh);
    let w = WAKE
        .get()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))?;
    WAKE_FD.store(w._write.as_raw_fd(), Ordering::Release);
    Ok(w)
}

extern "C" fn on_signal(sig: libc::c_int) {
    // SAFETY: errno save/restore and a single write(2) are async-signal-safe.
    unsafe {
        let saved = *errno_location();
        let fd = WAKE_FD.load(Ordering::Acquire);
        if fd >= 0 {
            let b = sig as u8;
            // A full channel means wakeups are already pending; EAGAIN is fine.
            let _ = libc::write(fd, &b as *const u8 as *const libc::c_void, 1);
        }
        *errno_location() = saved;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn errno_location() -> *mut libc::c_int {
    libc::__errno_location()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
unsafe fn errno_location() -> *mut libc::c_int {
    libc::__error()
}

/// The outer terminal's attributes before raw mode, readable from a signal
/// handler. Written once before [`ARMED`] is set, read only while it is.
struct SavedTermios(UnsafeCell<MaybeUninit<libc::termios>>);
// SAFETY: writes happen only while ARMED is false, reads only while true,
// ordered by Release/Acquire on ARMED.
unsafe impl Sync for SavedTermios {}
static SAVED: SavedTermios = SavedTermios(UnsafeCell::new(MaybeUninit::uninit()));
static ARMED: AtomicBool = AtomicBool::new(false);

/// Handler for a catchable signal that would terminate the relay with the
/// terminal raw: restore the terminal (only from the foreground, so it cannot
/// stop on `SIGTTOU`), then die of the same signal. `tcsetattr`, `tcgetpgrp`,
/// `getpgrp`, `sigaction`, `sigprocmask` and `raise` are all
/// async-signal-safe.
extern "C" fn on_fatal(sig: libc::c_int) {
    if ARMED.load(Ordering::Acquire) {
        // SAFETY: SAVED was initialised before ARMED was set.
        unsafe {
            if libc::tcgetpgrp(STDIN) == libc::getpgrp() {
                libc::tcsetattr(STDIN, libc::TCSANOW, (*SAVED.0.get()).as_ptr());
            }
        }
    }
    reset_and_raise(sig);
}

fn sigaction_for(handler: libc::sighandler_t, flags: libc::c_int) -> libc::sigaction {
    // SAFETY: an all-zero sigaction is a valid starting value.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = handler;
    sa.sa_flags = flags;
    // SAFETY: valid mask pointer.
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };
    sa
}

/// Installs the relay's signal handlers and puts every previous disposition
/// and the thread's signal mask back on drop.
///
/// - `SIGPIPE` is ignored (spec 34 §34.2.1 (d), §34.10: never forwarded).
/// - `SIGWINCH` and `SIGCHLD` wake the pump.
/// - `FORWARDED` (and `SIGUSR1` when asked) wake the pump, which forwards
///   them to the child's process group.
/// - Every other catchable terminating signal restores the terminal and
///   re-raises (`FATAL`, plus the Linux real-time range). A signal that
///   already has a non-default disposition is left alone.
///
/// The handled signals are unblocked for the guard's lifetime, so an
/// inherited mask cannot hide `SIGCHLD` from the pump.
pub struct SignalGuard {
    wake: &'static WakeChannel,
    saved: Vec<(libc::c_int, libc::sigaction)>,
    old_mask: libc::sigset_t,
}

impl fmt::Debug for SignalGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignalGuard")
            .field("handlers", &self.saved.len())
            .finish()
    }
}

impl SignalGuard {
    /// Install handlers. `outer` is the terminal's attributes before raw
    /// mode, kept for the fatal-signal handler. Fails with
    /// [`RelayError::Busy`] if another guard is live in this process.
    pub fn install(forward_usr1: bool, outer: &libc::termios) -> Result<SignalGuard, RelayError> {
        if RELAY_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(RelayError::Busy);
        }
        let wake = match wake_channel() {
            Ok(w) => w,
            Err(e) => {
                RELAY_ACTIVE.store(false, Ordering::Release);
                return Err(not_started("wake_channel")(e));
            }
        };
        // SAFETY: an all-zero sigset is overwritten by sigprocmask below.
        let old_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut guard = SignalGuard {
            wake,
            saved: Vec::new(),
            old_mask,
        };
        // Drop anything a previous relay left in the channel.
        let _ = guard.take();
        // SAFETY: SAVED is written while ARMED is false.
        unsafe { (*SAVED.0.get()).write(*outer) };
        ARMED.store(true, Ordering::Release);

        let relay = on_signal as *const () as libc::sighandler_t;
        let fatal = on_fatal as *const () as libc::sighandler_t;
        let mut plan: Vec<(libc::c_int, libc::sigaction, bool)> = vec![
            (libc::SIGPIPE, sigaction_for(libc::SIG_IGN, 0), false),
            (
                libc::SIGWINCH,
                sigaction_for(relay, libc::SA_RESTART),
                false,
            ),
            (libc::SIGCHLD, sigaction_for(relay, libc::SA_RESTART), false),
            (libc::SIGTSTP, sigaction_for(relay, libc::SA_RESTART), false),
            // NOT restarting: the kernel sends these when a terminal read or
            // write is refused to a background process. A restarted call is
            // refused again at once, the handler runs again, and the relay
            // spins inside one syscall without ever returning to its loop
            // (where the ending grace is checked). Unrestarted, the call
            // fails with EINTR and the loop runs.
            (libc::SIGTTIN, sigaction_for(relay, 0), false),
            (libc::SIGTTOU, sigaction_for(relay, 0), false),
        ];
        let mut forwarded: Vec<libc::c_int> = FORWARDED.to_vec();
        if forward_usr1 {
            forwarded.push(libc::SIGUSR1);
        }
        for sig in forwarded {
            plan.push((sig, sigaction_for(relay, libc::SA_RESTART), false));
        }
        let fatals = {
            #[allow(unused_mut)]
            let mut v: Vec<libc::c_int> = FATAL.to_vec();
            #[cfg(target_os = "linux")]
            v.extend(libc::SIGRTMIN()..=libc::SIGRTMAX());
            v
        };
        for sig in fatals {
            plan.push((
                sig,
                sigaction_for(fatal, libc::SA_NODEFER | libc::SA_RESETHAND),
                true,
            ));
        }

        let mut unblock: libc::sigset_t;
        // SAFETY: sigset manipulation on stack storage.
        unsafe {
            unblock = std::mem::zeroed();
            libc::sigemptyset(&mut unblock);
        }
        for (sig, sa, only_if_default) in plan {
            // SAFETY: valid sigaction pointers; `old` is written by the call.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            if only_if_default {
                // SAFETY: query only.
                let rc = unsafe { libc::sigaction(sig, std::ptr::null(), &mut old) };
                if rc == -1 || old.sa_sigaction != libc::SIG_DFL {
                    continue;
                }
            }
            // SAFETY: as above.
            if unsafe { libc::sigaction(sig, &sa, &mut old) } == -1 {
                let e = io::Error::last_os_error();
                if only_if_default {
                    // A reserved real-time signal; nothing to protect.
                    continue;
                }
                // Dropping `guard` restores whatever was installed so far.
                return Err(not_started("sigaction")(e));
            }
            guard.saved.push((sig, old));
            // SAFETY: valid sigset pointer.
            unsafe { libc::sigaddset(&mut unblock, sig) };
        }
        // SAFETY: valid sigset pointers; the previous mask is kept for drop.
        unsafe {
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblock, &mut guard.old_mask);
        }
        Ok(guard)
    }

    fn wake_fd(&self) -> RawFd {
        self.wake.read.as_raw_fd()
    }

    /// Drain the wake channel into signal numbers.
    fn take(&self) -> Vec<libc::c_int> {
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: valid buffer; the channel is non-blocking.
            let n = unsafe {
                libc::read(
                    self.wake_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            out.extend(buf[..n as usize].iter().map(|&b| b as libc::c_int));
        }
        out
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        ARMED.store(false, Ordering::Release);
        for (sig, old) in self.saved.iter().rev() {
            // SAFETY: restoring a sigaction previously returned by the kernel.
            unsafe { libc::sigaction(*sig, old, std::ptr::null_mut()) };
        }
        // SAFETY: restoring the mask captured at install.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old_mask, std::ptr::null_mut());
        }
        RELAY_ACTIVE.store(false, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Terminal output queue

/// Non-blocking, bounded output to the outer terminal. The terminal is
/// reopened through its device path, so `O_NONBLOCK` lands on this relay's
/// own open file description and never on the one the parent shell shares.
struct OutQueue {
    fd: OwnedFd,
    pending: Vec<u8>,
    dead: bool,
}

impl OutQueue {
    /// Reopen the terminal on `fd` for non-blocking writes. The name from
    /// `ttyname_r` is only a name: the reopened descriptor must be a character
    /// device with the same `st_rdev` as `fd`, or it is a different terminal
    /// (the name raced terminal churn) and is closed. A mismatch is retried
    /// within [`PTY_TRANSIENT_ATTEMPTS`]; after the cap it is an error.
    fn open_tty(fd: RawFd) -> io::Result<OutQueue> {
        Self::open_tty_via(fd, reopen_by_name)
    }

    /// [`OutQueue::open_tty`] with the by-name reopen injected, so a test can
    /// hand back a descriptor for a DIFFERENT terminal and prove the `st_rdev`
    /// check refuses and retries it.
    fn open_tty_via(
        fd: RawFd,
        mut reopen: impl FnMut(RawFd) -> io::Result<OwnedFd>,
    ) -> io::Result<OutQueue> {
        let reopened = retry_transient(
            |e| ttyname_transient(e) || tty_mismatch(e),
            || {
                let new = reopen(fd)?;
                same_tty(new.as_raw_fd(), fd)?;
                Ok(new)
            },
        )?;
        Ok(OutQueue::over(reopened))
    }

    fn over(fd: OwnedFd) -> OutQueue {
        OutQueue {
            fd,
            pending: Vec::new(),
            dead: false,
        }
    }

    fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    fn has_room(&self) -> bool {
        self.pending.len() < OUT_QUEUE_MAX
    }

    fn wants_write(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Hold `bytes` for the terminal without writing them. A terminal that
    /// stopped accepting output for good discards them.
    fn queue(&mut self, bytes: &[u8]) {
        if !self.dead {
            self.pending.extend_from_slice(bytes);
        }
    }

    /// Write queued bytes until the terminal takes no more. An interrupted
    /// write is NOT retried here: it is what a `SIGTTOU` (a background write
    /// under `tostop`) leaves behind, and a retry would be refused again,
    /// forever. The pump retries on its next pass, after it has handled the
    /// signal.
    fn flush(&mut self) {
        while !self.dead && !self.pending.is_empty() {
            match write_fd(self.raw(), &self.pending) {
                Ok(0) => self.fail(0),
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(e) => match e.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EINTR) => return,
                    errno => self.fail(errno.unwrap_or(0)),
                },
            }
        }
    }

    fn fail(&mut self, errno: i32) {
        self.dead = true;
        self.pending.clear();
        tracing::warn!(
            error_kind = "terminal_write_failed",
            errno,
            "terminal output stopped; discarding"
        );
    }
}

// ---------------------------------------------------------------------------
// The pump

/// Outcome of one read from the master.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum MasterRead {
    /// This many bytes were read.
    Data(usize),
    /// The slave side is gone: a zero read, or `EIO` (Linux's EOF).
    Eof,
    /// Nothing to read right now.
    Again,
    /// A real error, as `errno`.
    Failed(i32),
}

/// Classify the result of `read(2)` on the master (spec 34 §34.2.1 (g):
/// `EIO` is EOF).
pub(crate) fn classify_master_read(r: io::Result<usize>) -> MasterRead {
    match r {
        Ok(0) => MasterRead::Eof,
        Ok(n) => MasterRead::Data(n),
        Err(e) => match e.raw_os_error() {
            Some(libc::EIO) => MasterRead::Eof,
            Some(libc::EAGAIN) => MasterRead::Again,
            Some(libc::EINTR) => MasterRead::Again,
            other => MasterRead::Failed(other.unwrap_or(0)),
        },
    }
}

fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: valid buffer for the call's duration.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: valid buffer for the call's duration.
    let n = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

enum ChildState {
    Running,
    Stopped,
    Done(RelayExit),
}

/// `waitpid` for the child. `Err(errno)` is `ECHILD` or another failure; on
/// `ECHILD` the pid is no longer ours.
fn reap(pid: libc::pid_t) -> Result<ChildState, io::Error> {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::WUNTRACED) };
        if r == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if r == 0 {
            return Ok(ChildState::Running);
        }
        if libc::WIFSTOPPED(status) {
            return Ok(ChildState::Stopped);
        }
        if libc::WIFEXITED(status) {
            return Ok(ChildState::Done(RelayExit::Exited(libc::WEXITSTATUS(
                status,
            ))));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(ChildState::Done(RelayExit::Signaled(libc::WTERMSIG(
                status,
            ))));
        }
    }
}

/// The overlay-free relay.
pub struct Relay {
    spec: LaunchSpec,
    cfg: RelayConfig,
}

impl fmt::Debug for Relay {
    /// Fixed fields only: a spec's argv and environment can carry secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relay").field("cfg", &self.cfg).finish()
    }
}

impl Relay {
    /// A relay for `spec`. Its argv, environment and working directory are
    /// used as given and never altered (spec 34 §34.2.1). A spec the shim
    /// cannot represent is refused here with a fixed error, before anything
    /// runs.
    pub fn new(spec: LaunchSpec, cfg: RelayConfig) -> Result<Self, RelayError> {
        spec.validate()?;
        Ok(Relay { spec, cfg })
    }

    /// Run the child on a fresh PTY until it exits, then restore the
    /// terminal and report how it ended. The caller ends the process with
    /// [`RelayExit::conclude`]. See the module's caller contract for which
    /// errors allow an unrelayed fallback.
    pub fn run(self) -> Result<RelayExit, RelayError> {
        // The precondition first: a relay that declines hands back to an
        // unrelayed launch, which must not inherit the zeroed core limit.
        term::precondition(STDIN, STDOUT, STDERR).map_err(RelayError::Declined)?;
        harden_process().map_err(not_started("core_dumps"))?;
        let out = OutQueue::open_tty(STDOUT).map_err(not_started("open_tty"))?;
        let outer = term::get_termios(STDIN).map_err(not_started("tcgetattr"))?;
        let signals = SignalGuard::install(self.cfg.forward_usr1, &outer)?;
        let guard = RawGuard::enter(STDIN).map_err(not_started("tcsetattr"))?;
        let ws = term::get_winsize(STDIN).map_err(not_started("tiocgwinsz"))?;
        let pty = Pty::open(Some(guard.saved()), Some(&ws)).map_err(not_started("openpty"))?;
        set_nonblock(pty.master.as_raw_fd()).map_err(not_started("fcntl"))?;
        let Pty { master, slave } = pty;
        let Spawned { pid, ctl, up } =
            spawn_on_slave(&self.spec, slave).map_err(SpawnFailure::into_relay_error)?;
        let mut pump = Pump {
            master,
            pid,
            ctl,
            up,
            guard,
            signals,
            pending: Vec::new(),
            out,
            reaped: false,
            fault: None,
            ending: None,
            resumes: 0,
            cfg: self.cfg,
        };
        pump.run()
    }
}

struct Pump {
    master: OwnedFd,
    pid: libc::pid_t,
    /// Control pipe to the shim: `R` resumes the CLI; closing it (however
    /// the relay dies) makes the shim end the CLI's group.
    ctl: OwnedFd,
    /// The shim's reports (a byte with the high bit set: the CLI stopped;
    /// [`stop_report`]).
    up: OwnedFd,
    guard: RawGuard,
    signals: SignalGuard,
    /// Terminal input waiting for the master.
    pending: Vec<u8>,
    out: OutQueue,
    /// The child has been reaped (or is not ours): never signal its pid.
    reaped: bool,
    /// A failure inside a signal action, returned by the run loop.
    fault: Option<RelayError>,
    /// The session is ending: `SIGTERM`, `SIGHUP` or a lost terminal was seen,
    /// running or suspended. Persistent: an ending relay never stops again and,
    /// if the CLI is still there after `TERMINATE_GRACE_MS`, ends it.
    ending: Option<(libc::c_int, Instant)>,
    /// `R` bytes written to the shim so far (mod 128): a stop report counts
    /// only when stamped with this number ([`holds_current_stop`]).
    resumes: u8,
    cfg: RelayConfig,
}

impl Drop for Pump {
    fn drop(&mut self) {
        if !self.reaped {
            // Error or unwind path: end the child, escalating, so a relay
            // failure never leaves a headless agent running.
            terminate_child(self.pid, Duration::from_millis(TERMINATE_GRACE_MS));
            self.reaped = true;
        }
    }
}

impl Pump {
    fn run(&mut self) -> Result<RelayExit, RelayError> {
        let mut master_open = true;
        let mut stdin_open = true;
        let mut buf = vec![0u8; 8192];
        let exit = 'outer: loop {
            let mut fds = [
                libc::pollfd {
                    fd: self.signals.wake_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if master_open && self.out.has_room() && !self.master_deaf() {
                        self.master.as_raw_fd()
                    } else {
                        -1
                    },
                    events: libc::POLLIN
                        | if self.pending.is_empty() {
                            0
                        } else {
                            libc::POLLOUT
                        },
                    revents: 0,
                },
                libc::pollfd {
                    // A relay in the background never reads the terminal: the
                    // read would stop it with SIGTTIN, and the bytes belong to
                    // the foreground job (a shell, after `kill` or `bg`).
                    //
                    // An ending relay whose terminal is cooked (it restored
                    // it to stop, and never re-enters raw mode) forwards no
                    // input either: the outer line discipline would echo what
                    // is typed into a prompt that echoes nothing.
                    fd: if stdin_open
                        && self.pending.len() < IN_QUEUE_MAX
                        && (self.ending.is_none() || self.guard.is_raw())
                        && term::is_foreground(STDIN)
                    {
                        STDIN
                    } else {
                        -1
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    // A background relay never writes the terminal (it would
                    // take SIGTTOU under TOSTOP); output waits in the queue.
                    fd: if self.out.wants_write() && term::is_foreground(STDIN) {
                        self.out.raw()
                    } else {
                        -1
                    },
                    events: libc::POLLOUT,
                    revents: 0,
                },
                libc::pollfd {
                    // (Test mode `deaf_master` also mutes this pipe: its EOF
                    // at the shim's exit is a third way to learn of the exit.)
                    fd: if self.master_deaf() {
                        -1
                    } else {
                        self.up.as_raw_fd()
                    },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: valid pollfd array of the stated length.
            let rc = unsafe {
                libc::poll(
                    fds.as_mut_ptr(),
                    fds.len() as libc::nfds_t,
                    POLL_BACKSTOP_MS,
                )
            };
            if rc == -1 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(started("poll", e));
            }

            let woken: Vec<libc::c_int> = if fds[0].revents != 0 {
                self.signals.take()
            } else {
                Vec::new()
            };
            for sig in woken {
                self.on_signal(sig);
            }
            if let Some(e) = self.fault.take() {
                return Err(e);
            }
            // A lost terminal ends the session in EVERY state, not only while
            // suspended: the CLI may ignore the `SIGHUP` the kernel sends it,
            // and nothing else would ever end it. The backstop wake bounds the
            // time to notice.
            if !self.reaped && self.ending.is_none() && term::tty_lost(STDIN) {
                self.begin_ending(libc::SIGHUP);
            }
            if fds[4].revents != 0 {
                self.read_reports()?;
            }
            // Every wake, and the backstop timeout, checks the child, so a
            // lost wake byte cannot hide its exit. Before the ending check: a
            // CLI that ended by itself keeps its own exit status.
            if let Some(exit) = self.check_child()? {
                break 'outer exit;
            }
            if let Some((sig, since)) = self.ending {
                if !self.reaped && since.elapsed() >= Duration::from_millis(TERMINATE_GRACE_MS) {
                    // The session was told to end and the CLI is still here
                    // (it traps the signal, or keeps stopping): end it. One
                    // that ended in the instant since `check_child` keeps its
                    // own status.
                    let own = end_child(self.pid, Duration::from_millis(TERMINATE_GRACE_MS));
                    self.reaped = true;
                    break 'outer own.unwrap_or(RelayExit::Signaled(sig));
                }
            }
            if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                && self.pump_output(&mut buf)?
            {
                master_open = false;
            }
            if fds[1].revents & libc::POLLOUT != 0 {
                self.write_pending_input()?;
            }
            if fds[3].revents != 0 {
                self.out.flush();
            }
            if fds[2].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
                && !self.pump_input(&mut buf)?
            {
                stdin_open = false;
            }
        };
        // Spec 34 §34.2.1 (e): restore first, then drain.
        if let Err(e) = self.guard.restore() {
            tracing::warn!(
                error_kind = "termios_restore_failed",
                errno = e.raw_os_error().unwrap_or(0),
                "terminal restore failed"
            );
        }
        let fd = self.master.as_raw_fd();
        // A relay ending in the background must not write to the terminal at
        // all (spec 34 §34.2.1 (f)): the screen belongs to whichever job is in
        // the foreground. Blocking SIGTTOU does NOT refuse such a write (POSIX
        // and Linux let a background writer through when the signal is blocked
        // or ignored); it only keeps a foreground relay that is moved to the
        // background mid-drain from being stopped. The refusal is the
        // foreground check, made before every flush: from the background the
        // queued output is discarded.
        // SAFETY: sigset manipulation on stack storage.
        let old = unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTTOU);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
            old
        };
        drain_master(fd, &mut self.out, self.cfg.drain, &mut buf, &|| {
            term::is_foreground(STDIN)
        });
        // SAFETY: restoring the mask saved above.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut()) };
        Ok(exit)
    }

    #[cfg(test)]
    fn master_deaf(&self) -> bool {
        self.cfg.deaf_master
    }

    #[cfg(not(test))]
    fn master_deaf(&self) -> bool {
        false
    }

    /// The shim's reports: a current stop report means the CLI stopped. Reads everything
    /// queued; any failure but "nothing there" ends the session.
    fn read_reports(&mut self) -> Result<(), RelayError> {
        if self.drain_up()? {
            self.suspend(true)?;
        }
        Ok(())
    }

    /// Read the up pipe empty. `true` when a current stop report
    /// ([`holds_current_stop`]) was among the bytes.
    fn drain_up(&mut self) -> Result<bool, RelayError> {
        let mut b = [0u8; 64];
        let mut stop = false;
        loop {
            match read_fd(self.up.as_raw_fd(), &mut b) {
                // EOF: the shim is gone; `check_child` sees how.
                Ok(0) => return Ok(stop),
                Ok(n) => stop |= holds_current_stop(&b[..n], self.resumes),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(stop),
                Err(e) => return Err(started("read_up", e)),
            }
        }
    }

    /// Handle one wake-channel signal.
    fn on_signal(&mut self, sig: libc::c_int) {
        match sig {
            libc::SIGCHLD => {}
            libc::SIGWINCH => self.propagate_winsize(),
            libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => {
                // Stopped from outside (a `kill`, or a terminal-access
                // signal sent by hand): restore the terminal and stop like a
                // job; an error here ends the session via the run loop.
                if let Err(e) = self.suspend(false) {
                    self.fault = Some(e);
                }
            }
            other if !self.reaped => {
                if other == libc::SIGTERM || other == libc::SIGHUP {
                    // A request to end the session: passed on, and if the CLI
                    // is still here after the grace it is ended (a CLI that
                    // traps or ignores the signal must not park forever).
                    self.ending.get_or_insert((other, Instant::now()));
                }
                // SAFETY: the child is unreaped, so its pid (= its pgid) is
                // not reusable.
                unsafe { libc::kill(-self.pid, other) };
            }
            _ => {}
        }
    }

    /// The terminal is gone: end the session as a `SIGHUP` would, passing the
    /// `SIGHUP` on. Idempotent.
    fn begin_ending(&mut self, sig: libc::c_int) {
        self.ending.get_or_insert((sig, Instant::now()));
        // SAFETY: only called while the shim is unreaped.
        unsafe { libc::kill(-self.pid, sig) };
    }

    /// Reap or observe the shim (which mirrors the CLI's exit).
    fn check_child(&mut self) -> Result<Option<RelayExit>, RelayError> {
        match reap(self.pid) {
            Ok(ChildState::Running) => Ok(None),
            Ok(ChildState::Stopped) => {
                // The shim itself was stopped from outside; it cannot do its
                // job stopped, so it is continued.
                // SAFETY: the shim is unreaped.
                unsafe { libc::kill(-self.pid, libc::SIGCONT) };
                Ok(None)
            }
            Ok(ChildState::Done(exit)) => {
                self.reaped = true;
                Ok(Some(exit))
            }
            Err(e) => {
                if e.raw_os_error() == Some(libc::ECHILD) {
                    // Someone else took the status; the pid is not ours.
                    self.reaped = true;
                }
                Err(started("waitpid", e))
            }
        }
    }

    fn propagate_winsize(&self) {
        match term::get_winsize(STDIN) {
            Ok(ws) => {
                if let Err(e) = term::set_winsize(self.master.as_raw_fd(), &ws) {
                    tracing::warn!(
                        error_kind = "winsize_set_failed",
                        errno = e.raw_os_error().unwrap_or(0),
                        "window size propagation failed"
                    );
                }
            }
            Err(e) => tracing::warn!(
                error_kind = "winsize_get_failed",
                errno = e.raw_os_error().unwrap_or(0),
                "window size read failed"
            ),
        }
    }

    /// The CLI stopped (spec 34 §34.2.1 (f); the shim reported `S`): restore
    /// the terminal, stop this process for the outer shell, and on resume
    /// re-enter raw mode only when foregrounded, then tell the shim to
    /// continue the CLI. `resume_cli` is false when the relay itself was
    /// stopped from outside (`SIGTSTP`): the CLI was never stopped.
    fn suspend(&mut self, resume_cli: bool) -> Result<(), RelayError> {
        if self.ending.is_none() && term::tty_lost(STDIN) {
            self.begin_ending(libc::SIGHUP);
        }
        if self.ending.is_some() {
            // Ending: never stop again. A CLI that stopped itself again is
            // continued so it can act on the signal it was sent.
            if resume_cli {
                self.send_resume();
            }
            return Ok(());
        }
        self.guard.restore().map_err(|e| started("tcsetattr", e))?;
        loop {
            // `raise` is thread-directed, so the calling thread is stopped
            // before it returns; `kill(getpid(), ..)` is process-directed and
            // in a multi-threaded process the caller can run on before the
            // group stop reaches it.
            // SAFETY: stopping this process; resumes at SIGCONT.
            unsafe { libc::raise(libc::SIGSTOP) };
            // A signal that arrived with the resume may have its handler run
            // on another thread a moment after this one wakes.
            if self.end_if_signalled(RESUME_SIGNAL_SETTLE_MS) {
                return Ok(());
            }
            if term::is_foreground(STDIN) {
                break;
            }
            // Resumed by `bg`: stay cooked, leave the child stopped, stop
            // again until foregrounded. A terminating signal sent with the
            // resume may have its handler run on another thread a moment
            // after this one wakes, so look once more before stopping.
            if self.end_if_signalled(RESUME_SIGNAL_GRACE_MS) {
                return Ok(());
            }
        }
        self.guard.reenter().map_err(|e| started("tcsetattr", e))?;
        self.propagate_winsize();
        if resume_cli {
            // A report queued while we were stopped (an outside SIGCONT made
            // the CLI stop again) is stale: drop it, or it would stop the
            // relay again right after `fg`.
            self.drain_up()?;
            #[cfg(test)]
            self.fault_stop_again_before_resume();
            // The shim hands the terminal to the CLI and continues it. A
            // report written after the drain but before the shim reads this
            // `R` carries the old count and is dropped when read.
            self.send_resume();
        }
        Ok(())
    }

    /// The test seam of [`RelayConfig::stop_again_before_resume`]. Compiled
    /// only into the unit-test build.
    #[cfg(test)]
    fn fault_stop_again_before_resume(&mut self) {
        let Some(path) = self.cfg.stop_again_before_resume.take() else {
            return;
        };
        let pid: libc::pid_t = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .expect("the CLI wrote its pid");
        // SAFETY: the pid is the test's own CLI, stopped under the shim.
        unsafe { libc::kill(pid, libc::SIGCONT) };
        let mut pfd = libc::pollfd {
            fd: self.up.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd; bounded wait for the shim's new report.
        let n = unsafe { libc::poll(&mut pfd, 1, 10_000) };
        assert_eq!(n, 1, "the CLI never reported its second stop");
    }

    /// Tell the shim to continue the CLI (`R`). A full pipe or a gone shim
    /// needs no retry: `R` is idempotent and a gone shim is noticed by
    /// `check_child`. Only a byte the pipe took is counted, since only that
    /// one is read by the shim.
    fn send_resume(&mut self) {
        if write_fd(self.ctl.as_raw_fd(), b"R").is_ok() {
            self.resumes = self.resumes.wrapping_add(1);
        }
    }

    /// While suspended: a terminating signal (`SIGTERM`, `SIGHUP`) or a lost
    /// terminal ends the session instead of stopping again. It is passed on to
    /// the CLI's group (the shim continues a stopped CLI for it). Any other
    /// signal is passed on and the stop carries on, so `kill -INT` then `fg`
    /// resumes normally. Waits up to `grace_ms` for a handler that has not run
    /// yet. `true` when the session is ending.
    fn end_if_signalled(&mut self, grace_ms: libc::c_int) -> bool {
        if grace_ms > 0 {
            let mut pfd = libc::pollfd {
                fd: self.signals.wake_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(&mut pfd, 1, grace_ms) };
        }
        let mut ending = false;
        for sig in self.signals.take() {
            match sig {
                libc::SIGCHLD | libc::SIGWINCH | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU => {}
                libc::SIGTERM | libc::SIGHUP => {
                    ending = true;
                    self.ending.get_or_insert((sig, Instant::now()));
                    // SAFETY: the shim is unreaped (we are suspended, not it).
                    unsafe { libc::kill(-self.pid, sig) };
                }
                other => {
                    // SAFETY: as above.
                    unsafe { libc::kill(-self.pid, other) };
                }
            }
        }
        if !ending && term::tty_lost(STDIN) {
            ending = true;
            self.begin_ending(libc::SIGHUP);
        }
        ending
    }

    /// Master to terminal queue. `true` when the master reached EOF.
    fn pump_output(&mut self, buf: &mut [u8]) -> Result<bool, RelayError> {
        match classify_master_read(read_fd(self.master.as_raw_fd(), buf)) {
            MasterRead::Data(n) => {
                self.out.queue(&buf[..n]);
                // A relay in the background writes nothing: the write would
                // take `SIGTTOU` (a `tostop` terminal), and the bytes belong
                // on the screen of whoever holds it. They wait in the queue
                // until the relay is foregrounded again.
                if term::is_foreground(STDIN) {
                    self.out.flush();
                }
                Ok(false)
            }
            MasterRead::Eof => Ok(true),
            MasterRead::Again => Ok(false),
            MasterRead::Failed(errno) => Err(RelayError::ChildStarted {
                op: "read_master",
                errno,
            }),
        }
    }

    /// Terminal to master. `false` when terminal input ended.
    fn pump_input(&mut self, buf: &mut [u8]) -> Result<bool, RelayError> {
        let room = IN_QUEUE_MAX - self.pending.len();
        let take = room.min(buf.len());
        match read_fd(STDIN, &mut buf[..take]) {
            Ok(0) => Ok(false),
            Ok(n) => {
                #[cfg(test)]
                if self.cfg.panic_on_input {
                    panic!("relay test fault: input byte received");
                }
                self.pending.extend_from_slice(&buf[..n]);
                self.write_pending_input()?;
                Ok(true)
            }
            Err(e) if matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) => {
                Ok(true)
            }
            Err(e) => {
                tracing::warn!(
                    error_kind = "terminal_read_failed",
                    errno = e.raw_os_error().unwrap_or(0),
                    "terminal input ended"
                );
                Ok(false)
            }
        }
    }

    /// Write as much queued input to the master as it accepts.
    fn write_pending_input(&mut self) -> Result<(), RelayError> {
        while !self.pending.is_empty() {
            match write_fd(self.master.as_raw_fd(), &self.pending) {
                // A write that moves nothing and is not EAGAIN would spin.
                Ok(0) => {
                    return Err(RelayError::ChildStarted {
                        op: "write_master",
                        errno: 0,
                    })
                }
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(e) => match e.raw_os_error() {
                    Some(libc::EAGAIN) => return Ok(()),
                    Some(libc::EINTR) => {}
                    // The slave side is gone; the input has no reader.
                    Some(libc::EIO) => self.pending.clear(),
                    errno => {
                        return Err(RelayError::ChildStarted {
                            op: "write_master",
                            errno: errno.unwrap_or(0),
                        })
                    }
                },
            }
        }
        Ok(())
    }
}

/// Forward what is left in the master to the terminal queue, stopping at
/// master EOF with the queue empty, or when `window` has elapsed. The window
/// bounds reading AND writing: what the terminal has not taken by then is
/// discarded (counted, never logged). A holder of the slave that never closes
/// it never produces EOF, so the window is what ends the drain.
///
/// `may_write` is asked before every write: once it says no (the relay is no
/// longer the terminal's foreground job) the queue is discarded, counted and
/// never logged, and the drain ends.
fn drain_master(
    fd: RawFd,
    out: &mut OutQueue,
    window: Duration,
    buf: &mut [u8],
    may_write: &dyn Fn() -> bool,
) {
    let deadline = Instant::now() + window;
    let mut master_done = false;
    loop {
        if !may_write() {
            tracing::warn!(
                error_kind = "drain_background",
                discarded = out.pending.len(),
                "not the foreground job; discarding the drained output"
            );
            out.pending.clear();
            return;
        }
        out.flush();
        if master_done && !out.wants_write() {
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut fds = [
            libc::pollfd {
                fd: if master_done || !out.has_room() {
                    -1
                } else {
                    fd
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if out.wants_write() { out.raw() } else { -1 },
                events: libc::POLLOUT,
                revents: 0,
            },
        ];
        let ms = left.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: valid pollfd array of the stated length.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms.max(1)) };
        if r == 0 {
            break;
        }
        if r == -1 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if fds[0].revents != 0 {
            match classify_master_read(read_fd(fd, buf)) {
                MasterRead::Data(n) => out.queue(&buf[..n]),
                MasterRead::Again => {}
                MasterRead::Eof => master_done = true,
                MasterRead::Failed(errno) => {
                    tracing::warn!(error_kind = "drain_read_failed", errno, "drain read failed");
                    master_done = true;
                }
            }
        }
    }
    if out.wants_write() {
        tracing::warn!(
            error_kind = "drain_window_closed",
            discarded = out.pending.len(),
            "terminal did not take the drained output in time; discarding"
        );
    }
}

#[cfg(test)]
mod tests {
    //! The PTY harness. A test spawns a "shell" process (role `shell`) as the
    //! session leader of a fresh outer PTY; the shell starts the relay (role
    //! `relay`, this same test binary re-executed) in its own process group,
    //! hands it the foreground like an interactive shell would, and reports
    //! how it ended on the outer terminal. The test plays the user at the
    //! outer master and inspects the outer terminal's attributes.

    use super::*;
    use crate::relay::term::{get_termios, set_winsize};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    const ROLE: &str = "CSQ_S1A_ROLE";
    /// The pid of the process that started a helper role: the watchdog's
    /// reference, fixed BEFORE the role starts (see `spawn_parent_death_watchdog`).
    const PARENT: &str = "CSQ_S1A_PPID";
    const HELPER_ARGS: [&str; 4] = [
        "--exact",
        "relay::pty::tests::helper_main",
        "--nocapture",
        "--test-threads=1",
    ];
    /// The bound for the post-condition waits (`wait_gone`, a stalled
    /// terminal, a `ps` state flip): they have no ordering primitive, so a
    /// deadline is the only termination proof, and each names its own cause.
    const WAIT: Duration = Duration::from_secs(30);

    /// The backstop for a fixture that genuinely hangs — never a latency
    /// bound and never a readiness deadline. Startup readiness is the
    /// fixture's own write on its pid fifo ([`PidFifo`]): an ORDERING
    /// signal, so nothing about how long a start takes is measured and a
    /// slow start cannot read as a failed one. This expires only when the
    /// fixture is stuck, and the panic it raises is distinct from every
    /// forced-exit message. Mirrors the r9 runner's hang guard
    /// (`R9_RUNNER_HANG_GUARD`, d761a668e).
    const HANG_GUARD: Duration = Duration::from_secs(60);

    // -- helper roles (run in the re-executed test binary) -------------------

    fn env(key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    /// The test binary as the relayed CLI, with an explicit environment.
    fn helper_spec(role: &str) -> LaunchSpec {
        let mut spec =
            LaunchSpec::new(std::env::current_exe().expect("current_exe")).args(HELPER_ARGS);
        for (k, v) in std::env::vars() {
            // The watchdog reference (`PARENT`) belongs to the process that
            // started a role, never to the one it starts in turn; HOME is a
            // scratch directory, never the real one.
            if k == PARENT || k == "HOME" {
                continue;
            }
            if matches!(k.as_str(), "PATH" | "LANG" | "TERM" | "TMPDIR")
                || k.starts_with("CSQ_S1A_")
            {
                spec = spec.env(k, v);
            }
        }
        spec.env("HOME", scratch_home()).env(ROLE, role)
    }

    fn helper_command(role: &str) -> Command {
        let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
        cmd.args(HELPER_ARGS).env_clear();
        for (k, v) in std::env::vars() {
            if k == PARENT || k == "HOME" {
                continue;
            }
            if matches!(k.as_str(), "PATH" | "LANG" | "TERM" | "TMPDIR")
                || k.starts_with("CSQ_S1A_")
            {
                cmd.env(k, v);
            }
        }
        cmd.env("HOME", scratch_home())
            .env(ROLE, role)
            .env(PARENT, std::process::id().to_string());
        cmd
    }

    /// A scratch HOME for helper processes: never the real home directory.
    fn scratch_home() -> PathBuf {
        let dir = std::env::temp_dir().join("csq-s1a-home");
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    /// Entry point of every re-executed helper. A plain `cargo test` run has no
    /// role and passes immediately.
    #[test]
    fn helper_main() {
        match env(ROLE).as_deref() {
            None => {}
            Some("shell") => {
                spawn_parent_death_watchdog(shell_orphaned);
                role_shell()
            }
            Some("relay") => {
                spawn_parent_death_watchdog(relay_orphaned);
                role_relay()
            }
            Some("orphanprobe") => role_orphan_probe(),
            Some("sigprobe") => role_sigprobe(),
            Some("busy") => role_busy(),
            Some("spawner") => role_spawner(),
            Some("coreprobe") => role_coreprobe(),
            Some("forgedrelay") => role_forged_relay(),
            Some("outerhost") => role_outer_host(),
            Some("declined") => role_declined(),
            Some("ttyflags") => role_tty_flags(),
            Some("sentinel") => role_sentinel(),
            Some("reaper") => role_reaper(),
            Some("slowreaper") => role_slow_reaper(),
            Some("forker") => role_forker(),
            Some(other) => panic!("unknown helper role {other}"),
        }
    }

    /// Run `on_death` (it must not return) once this process's parent is gone.
    /// A test run killed from outside (`timeout`, a CI cancel, a crashed
    /// harness) never runs the harness's destructors, so without this the
    /// helper roles it started outlive it for good. The parent to watch is the
    /// spawner's pid handed over in `PARENT`: reading `getppid()` here instead
    /// would record the reaper's pid when the parent had already died during
    /// this process's start-up, and the watchdog would never fire. The check
    /// runs before the first sleep for the same reason.
    fn spawn_parent_death_watchdog(on_death: fn()) {
        // SAFETY: getppid has no preconditions.
        let parent = env(PARENT)
            .and_then(|v| v.parse::<libc::pid_t>().ok())
            .unwrap_or_else(|| unsafe { libc::getppid() });
        std::thread::spawn(move || {
            loop {
                // SAFETY: getppid has no preconditions.
                if unsafe { libc::getppid() } != parent {
                    on_death();
                }
                // No process listing here: the sentinel is the only tracker
                // (one `ps` stream per `Outer`, not one per role).
                std::thread::sleep(Duration::from_millis(200));
            }
        });
    }

    /// Append one line to the diagnostic log named by `CSQ_S1A_DEBUGLOG` (a
    /// test shows it when the cleanup of an externally killed run falls short).
    fn dbg(line: &str) {
        use std::io::Write;
        if let Some(f) = env("CSQ_S1A_DEBUGLOG") {
            if let Ok(mut h) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(f)
            {
                let _ = writeln!(
                    h,
                    "[{} {}] {line}",
                    env(ROLE).unwrap_or_default(),
                    std::process::id()
                );
            }
        }
    }

    /// How long a `ps` run may take before it is given up on.
    const PS_LIMIT: Duration = Duration::from_secs(5);

    /// A finished process listing and the pid of the `ps` that printed it (it
    /// is a child of the caller, so it is in its own listing, and must never
    /// count as a member of any tree).
    struct Listing {
        text: String,
        pid: libc::pid_t,
    }

    /// Run `cmd` (a process listing) with `/dev/null` for stdin and stderr, in a
    /// process group of its own, and read its output with a bounded
    /// non-blocking wait: a cleanup must never depend on the listing finishing.
    /// A run that does not finish is killed (it is this function's own, still
    /// unreaped child) and reported with what `/proc` says of it (Linux).
    fn run_bounded(cmd: Command, limit: Duration) -> Result<Listing, String> {
        run_bounded_with(cmd, limit, &[0], &set_nonblock)
    }

    /// [`run_bounded`] with the exit codes that count as success (a `ps -p` of
    /// a pid that does not exist exits 1) and the call that makes the pipe
    /// non-blocking (a parameter so a test can make it fail: a pipe left
    /// blocking would let the read outlive the deadline).
    fn run_bounded_with(
        mut cmd: Command,
        limit: Duration,
        ok_codes: &[i32],
        nonblock: &dyn Fn(RawFd) -> io::Result<()>,
    ) -> Result<Listing, String> {
        use std::io::Read;
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = cmd.spawn().map_err(|e| format!("ps did not start: {e}"))?;
        let pid = child.id() as libc::pid_t;
        let mut out = child.stdout.take().ok_or("ps had no stdout")?;
        if let Err(e) = nonblock(out.as_raw_fd()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("ps output could not be made non-blocking: {e}"));
        }
        let deadline = Instant::now() + limit;
        let mut bytes = Vec::new();
        let mut buf = [0u8; 8192];
        let timed_out = loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break true;
            }
            let mut pfd = libc::pollfd {
                fd: out.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(200) as libc::c_int) };
            match out.read(&mut buf) {
                Ok(0) => break false,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("ps output: {e}"));
                }
            }
        };
        let status = if timed_out {
            None
        } else {
            loop {
                match child.try_wait() {
                    Ok(Some(st)) => break Some(st),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    _ => break None,
                }
            }
        };
        match status {
            Some(st) if st.code().is_some_and(|c| ok_codes.contains(&c)) => Ok(Listing {
                text: String::from_utf8_lossy(&bytes).into_owned(),
                pid,
            }),
            Some(st) => Err(format!("ps exited {:?}", st.code())),
            None => {
                let state =
                    std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                let wchan =
                    std::fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
                let _ = child.kill();
                let _ = child.wait();
                Err(format!(
                    "ps did not finish in {limit:?}: stat={:?} wchan={wchan:?}",
                    state.trim()
                ))
            }
        }
    }

    /// One process of a full listing, with what identifies it again later: a
    /// pid alone could have been reused, the start time cannot match a later
    /// process of the same pid (the command line can change under `exec`).
    #[derive(Clone)]
    struct Proc {
        row: Row,
        stat: String,
        start: String,
        command: String,
    }

    impl Proc {
        fn is_zombie(&self) -> bool {
            self.stat.starts_with('Z')
        }
    }

    /// Parse `ps -A -o pid=,ppid=,pgid=,stat=,lstart=,command=` (`lstart` is
    /// five words), leaving out the listing process `skip` itself.
    fn parse_ps_full(text: &str, skip: libc::pid_t) -> Vec<Proc> {
        text.lines()
            .filter_map(|l| {
                let mut it = l.split_whitespace();
                let pid: libc::pid_t = it.next()?.parse().ok()?;
                let ppid: libc::pid_t = it.next()?.parse().ok()?;
                let pgid: libc::pid_t = it.next()?.parse().ok()?;
                let stat = it.next()?.to_string();
                let start = (0..5)
                    .map(|_| it.next())
                    .collect::<Option<Vec<_>>>()?
                    .join(" ");
                let command = it.collect::<Vec<_>>().join(" ");
                (pid != skip).then_some(Proc {
                    row: (pid, ppid, pgid),
                    stat,
                    start,
                    command,
                })
            })
            .collect()
    }

    /// Every process, from one `ps` run that ends by `deadline` (but is given
    /// at least 200 ms).
    fn ps_full_until(deadline: Instant) -> Option<Vec<Proc>> {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .clamp(Duration::from_millis(200), PS_LIMIT);
        // Absolute by default (no PATH race); `CSQ_S1A_PS` lets the sentinel
        // test point the helper at a counting wrapper without touching PATH.
        let ps = std::env::var_os("CSQ_S1A_PS").unwrap_or_else(|| "/bin/ps".into());
        let mut c = Command::new(ps);
        c.args(["-A", "-o", "pid=,ppid=,pgid=,stat=,lstart=,command="]);
        match run_bounded(c, left) {
            Ok(l) => Some(parse_ps_full(&l.text, l.pid)),
            Err(e) => {
                dbg(&format!("ps_full failed: {e}"));
                None
            }
        }
    }

    fn ps_full() -> Option<Vec<Proc>> {
        ps_full_until(Instant::now() + PS_LIMIT)
    }

    /// A process this role has seen below itself, with what identifies it
    /// again later (pid and start time).
    #[derive(Clone, PartialEq, Eq)]
    struct Seen {
        pid: libc::pid_t,
        pgid: libc::pid_t,
        start: String,
    }

    static SEEN: std::sync::Mutex<Vec<Seen>> = std::sync::Mutex::new(Vec::new());

    /// Whether `e` is still the live (not zombie) process it was.
    fn still_remembered(e: &Seen, procs: &[Proc]) -> bool {
        procs
            .iter()
            .any(|p| p.row.0 == e.pid && p.start == e.start && !p.is_zombie())
    }

    /// What identifies a root again before a live walk of its tree.
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Identity {
        start: String,
        command: String,
    }

    fn identity_of(procs: &[Proc], pid: libc::pid_t) -> Option<Identity> {
        procs
            .iter()
            .find(|p| p.row.0 == pid && !p.is_zombie())
            .map(|p| Identity {
                start: p.start.clone(),
                command: p.command.clone(),
            })
    }

    /// Whether `root` is still the process `ident` was taken from (same start
    /// time AND command, and not a zombie).
    fn root_still_is(ident: &Identity, procs: &[Proc], root: libc::pid_t) -> bool {
        identity_of(procs, root).as_ref() == Some(ident)
    }

    /// The sentinel's tick: at most four `ps` runs a second per `Outer`.
    const TRACK_TICK: Duration = Duration::from_millis(250);

    /// Remember what runs below `root` now (and, the first time, what `root`
    /// is). A tree walk made only when the parent has died finds nothing of a
    /// process that was reparented in the meantime (a `set -m` job whose shell
    /// the hangup already killed), so the sentinel remembers the tree while it
    /// is whole. Best effort: the walk at the time of death is the primary.
    fn track_pass(root: libc::pid_t, ident: &mut Option<Identity>) {
        let Some(procs) = ps_full() else { return };
        if ident.is_none() {
            *ident = identity_of(&procs, root);
        }
        let rows: Vec<Row> = procs.iter().map(|p| p.row).collect();
        let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
        for (pid, _, pgid) in descendants_of(&rows, root) {
            let Some(p) = procs.iter().find(|p| p.row.0 == pid) else {
                continue;
            };
            if !seen.iter().any(|e| e.pid == pid && e.start == p.start) {
                seen.retain(|e| e.pid != pid);
                seen.push(Seen {
                    pid,
                    pgid,
                    start: p.start.clone(),
                });
            }
        }
    }

    /// How long the remembered-tree reap may spend listing and signalling.
    const REMEMBER_BUDGET: Duration = Duration::from_secs(4);

    /// End every remembered process that is still the process it was (same
    /// pid and start time, not a zombie), whether or not it is still below
    /// anyone.
    fn reap_remembered() {
        let seen: Vec<Seen> = SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if seen.is_empty() {
            dbg("reap_remembered: nothing remembered");
            return;
        }
        dbg(&format!(
            "reap_remembered: {:?}",
            seen.iter().map(|e| (e.pid, e.pgid)).collect::<Vec<_>>()
        ));
        let deadline = Instant::now() + REMEMBER_BUDGET;
        // Several passes: a process that is still the one remembered after a
        // SIGKILL is signalled again, and what is left is logged.
        for pass in 0..5 {
            let Some(procs) = ps_full_until(deadline) else {
                dbg("no process listing");
                eprintln!("CLEANUP-SNAPSHOT-FAILED: no process listing for the remembered tree");
                return;
            };
            let mut killed = 0;
            for e in &seen {
                let same = still_remembered(e, &procs);
                dbg(&format!("  pass {pass}: {} same={same}", e.pid));
                if same {
                    kill_pid(e.pid, libc::SIGKILL);
                    killed += 1;
                }
            }
            if killed == 0 {
                return;
            }
            if Instant::now() >= deadline {
                eprintln!("CLEANUP-SNAPSHOT-FAILED: the remembered-tree budget was spent");
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The process group of the relay the `shell` role started (0 = none yet).
    static SHELL_RELAY_GROUP: AtomicI32 = AtomicI32::new(0);

    /// The `shell` role lost its harness: take everything it started with it
    /// (the whole tree, frozen first, then the relay's process group), then go.
    fn shell_orphaned() {
        dbg("shell_orphaned");
        arm_cleanup_alarm(CLEANUP_ALARM_SECS);
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        reap_remembered();
        let r = reap_tree_reported(me, false);
        dbg(&format!("reap_tree: {r:?}"));
        let group = SHELL_RELAY_GROUP.load(Ordering::Acquire);
        if group > 0 {
            // SAFETY: the group is the relay this role started and has not yet
            // reaped (the role reaps it only on its way out).
            unsafe { libc::kill(-group, libc::SIGKILL) };
        }
        // SAFETY: _exit never returns.
        unsafe { libc::_exit(137) }
    }

    /// The `relay` role lost its shell. Its forked waiter variant stands in
    /// for the relay at the announced pid and takes the real relay with it;
    /// the rest of what the relay started goes with the tree walk.
    ///
    /// Bound: commit de182d875 claimed a plain `alarm(15)` ended a wedged
    /// cleanup in this role. It did not: while the relay runs, `SignalGuard`
    /// has `SIGALRM` in its forwarded set ([`FORWARDED`]), so the alarm was
    /// forwarded to the child instead of ending the role. [`arm_cleanup_alarm`]
    /// now installs its own `SIGALRM` handler (replacing the forwarding one)
    /// and unblocks the signal, so the bound is real: the cleanup deadlines
    /// ([`REMEMBER_BUDGET`] plus [`FREEZE_DEADLINE`]) end well inside
    /// [`CLEANUP_ALARM_SECS`], and if they did not, the handler kills every
    /// frozen process before `_exit`.
    fn relay_orphaned() {
        dbg("relay_orphaned");
        arm_cleanup_alarm(CLEANUP_ALARM_SECS);
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        reap_remembered();
        let r = reap_tree_reported(me, false);
        dbg(&format!("reap_tree: {r:?}"));
        let forked = FORK_CHILD.load(Ordering::Acquire);
        if forked > 0 {
            // SAFETY: the waiter's own child.
            unsafe { libc::kill(forked, libc::SIGKILL) };
        }
        // SAFETY: _exit never returns.
        unsafe { libc::_exit(137) }
    }

    /// The `outerhost` role lost its parent (the test run).
    fn host_orphaned() {
        arm_cleanup_alarm(CLEANUP_ALARM_SECS);
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        reap_remembered();
        let r = reap_tree_reported(me, false);
        dbg(&format!("reap_tree: {r:?}"));
        // SAFETY: _exit never returns.
        unsafe { libc::_exit(137) }
    }

    /// Role `outerhost`: a stand-in for a test binary. It starts an [`Outer`]
    /// (a shell role, a relay, a shim, a CLI that starts a `set -m` job),
    /// reports the pids and then waits to be killed from outside, which runs no
    /// destructor.
    fn role_outer_host() -> ! {
        // SAFETY: alarm has no preconditions.
        unsafe { libc::alarm(120) };
        spawn_parent_death_watchdog(host_orphaned);
        let script = env("CSQ_S1A_HOST_SCRIPT").expect("host script");
        let pidfile = env("CSQ_S1A_PIDFILE").expect("pid file");
        let trackfile = env("CSQ_S1A_HOST_TRACKFILE").unwrap_or_default();
        let debuglog = env("CSQ_S1A_DEBUGLOG").unwrap_or_default();
        let hold = env("CSQ_S1A_HOST_HOLD_MASTER").is_some_and(|v| !v.is_empty());
        // The path names the fifo the job publishes its pid on, created and
        // opened here (before the job starts) rather than a file this role
        // samples under a deadline.
        let fifo = PidFifo::at(PathBuf::from(&pidfile));
        let mut o = Outer::start(
            &script,
            &[
                ("CSQ_S1A_PIDFILE", &pidfile),
                ("CSQ_S1A_TRACKFILE", &trackfile),
                ("CSQ_S1A_DEBUGLOG", &debuglog),
            ],
        );
        o.wait_for("READY");
        let job = fifo.read_pid("the job");
        // The sentinel remembers the tree on a tick: wait until a few passes ran
        // after the job existed, so an external kill finds it remembered.
        if let (Some(f), false) = (
            env("CSQ_S1A_HOST_TRACKFILE"),
            env("CSQ_S1A_NO_SENTINEL").is_some_and(|v| !v.is_empty()),
        ) {
            let count = || {
                std::fs::read_to_string(&f)
                    .ok()
                    .and_then(|t| t.trim().parse::<u64>().ok())
                    .unwrap_or(0)
            };
            let start = count();
            let deadline = Instant::now() + WAIT;
            while count() < start + 3 {
                assert!(Instant::now() < deadline, "the role never tracked the tree");
                tick();
            }
        }
        let shell = o.shell.as_ref().map(|c| c.id()).unwrap_or(0);
        let relay = o.announced("R-PID ").last().copied().unwrap_or(0);
        let cli = o.announced("CHILD=").last().copied().unwrap_or(0);
        // A forked copy that only waits keeps the terminal's master open
        // after the host is killed (bounded by an alarm).
        let holder = if hold {
            // SAFETY: the child only calls alarm and pause (async-signal-safe).
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe {
                    libc::alarm(60);
                    loop {
                        libc::pause();
                    }
                }
            }
            pid
        } else {
            0
        };
        println!("HOSTED shell={shell} relay={relay} cli={cli} job={job} holder={holder}");
        loop {
            // SAFETY: pause has no preconditions.
            unsafe { libc::pause() };
        }
    }

    /// Role `forker`: starts a `sleep <mark>` in a process group of its own
    /// every 20 ms, for as long as it runs (bounded by an alarm). With
    /// `CSQ_S1A_WRAP` it only runs the real forker below itself.
    fn role_forker() -> ! {
        // SAFETY: alarm has no preconditions.
        unsafe { libc::alarm(60) };
        spawn_parent_death_watchdog(relay_orphaned);
        let mark = env("CSQ_S1A_MARK").expect("mark");
        if env("CSQ_S1A_WRAP").is_some() {
            // The root the test reaps: it only waits for the real forker, so
            // the forker keeps forking while the root is being reaped.
            let mut inner = helper_command("forker");
            inner.env_remove("CSQ_S1A_WRAP");
            let _ = inner.stdout(Stdio::null()).status();
            // SAFETY: _exit never returns.
            unsafe { libc::_exit(0) }
        }
        loop {
            let _ = Command::new("/bin/sleep")
                .arg(&mark)
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Role `orphanprobe`: do nothing until the parent is gone, then end (the
    /// watchdog's effect, observable from outside). A bounded alarm keeps a
    /// broken watchdog from leaving it behind.
    fn role_orphan_probe() -> ! {
        // SAFETY: alarm has no preconditions.
        unsafe { libc::alarm(120) };
        spawn_parent_death_watchdog(relay_orphaned);
        loop {
            // SAFETY: pause has no preconditions.
            unsafe { libc::pause() };
        }
    }

    fn tcsetpgrp(pgrp: libc::pid_t) {
        // SAFETY: SIGTTOU is ignored by the shell role, so this cannot stop it.
        unsafe { libc::tcsetpgrp(STDIN, pgrp) };
    }

    /// Role `shell`: a minimal interactive-shell stand-in.
    fn role_shell() -> ! {
        use std::io::BufRead;
        // SAFETY: signal-state syscalls on this process.
        unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
        if env("CSQ_S1A_SHELL_IGN_CHLD").is_some() {
            // Children are reaped by the kernel: `waitpid` ends with ECHILD.
            // SAFETY: signal-state syscall on this process.
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
        }
        if env("CSQ_S1A_SHELL_IGNORE_HUP").is_some_and(|v| !v.is_empty()) {
            // A shell that survives its terminal closing: the relay then gets
            // no `SIGHUP` from the leader's exit and can only notice the
            // lost terminal itself.
            // SAFETY: as above.
            unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
        }
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: valid 2-element out array; both ends are ours.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // The read end must survive exec in the relay; the write end must not.
        // SAFETY: fcntl on descriptors we own.
        let (gate_r, gate_w) = unsafe {
            libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
            (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))
        };
        let mut cmd = helper_command("relay");
        cmd.env("CSQ_S1A_GATE", gate_r.as_raw_fd().to_string())
            .process_group(0);
        match env("CSQ_S1A_REDIR").as_deref() {
            Some("stdout") => {
                cmd.stdout(Stdio::null());
            }
            Some("stderr") => {
                cmd.stderr(Stdio::null());
            }
            _ => {}
        }
        let child = cmd.spawn().expect("spawn relay role");
        let pid = child.id() as libc::pid_t;
        SHELL_RELAY_GROUP.store(pid, Ordering::Release);
        drop(child);
        println!("R-PID {pid}");
        if env("CSQ_S1A_FG").as_deref() != Some("0") {
            tcsetpgrp(pid);
        }
        write_fd(gate_w.as_raw_fd(), b"g").expect("open gate");
        loop {
            let mut st: libc::c_int = 0;
            // SAFETY: valid out-pointer.
            let r = unsafe { libc::waitpid(pid, &mut st, libc::WUNTRACED) };
            if r == -1 {
                // Only an interrupted wait is retried: ECHILD (the child is
                // not ours) would spin forever.
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                println!("R-LOST");
                std::process::exit(1);
            }
            if libc::WIFSTOPPED(st) {
                // SAFETY: getpgrp has no preconditions.
                tcsetpgrp(unsafe { libc::getpgrp() });
                println!("R-STOPPED");
                let mut line = String::new();
                let _ = std::io::stdin().lock().read_line(&mut line);
                match line.trim() {
                    "fg" => {
                        tcsetpgrp(pid);
                        // SAFETY: signalling our own child.
                        unsafe { libc::kill(pid, libc::SIGCONT) };
                    }
                    "bg" => {
                        // SAFETY: signalling our own child.
                        unsafe { libc::kill(pid, libc::SIGCONT) };
                    }
                    _ => {}
                }
                continue;
            }
            // SAFETY: getpgrp has no preconditions.
            tcsetpgrp(unsafe { libc::getpgrp() });
            if libc::WIFEXITED(st) {
                println!("R-EXIT {}", libc::WEXITSTATUS(st));
            } else {
                println!("R-SIG {}", libc::WTERMSIG(st));
            }
            std::process::exit(0);
        }
    }

    static FORK_CHILD: AtomicI32 = AtomicI32::new(0);

    extern "C" fn relay_stand_in(sig: libc::c_int) {
        let pid = FORK_CHILD.load(Ordering::Acquire);
        if pid > 0 {
            // SAFETY: kill is async-signal-safe.
            unsafe { libc::kill(pid, sig) };
        }
    }

    /// Role `relay`: run [`Relay`] the way a launch arm would and exit with a
    /// code that names the outcome.
    fn role_relay() -> ! {
        // Wait for the shell to finish handing over the foreground.
        let gate: RawFd = env("CSQ_S1A_GATE")
            .and_then(|v| v.parse().ok())
            .expect("gate fd");
        let mut b = [0u8; 1];
        read_fd(gate, &mut b).expect("gate read");
        set_cloexec(gate).expect("gate cloexec");
        let blocked_at_start = match env("CSQ_S1A_PRESET").as_deref() {
            Some("2") => Some(libc::SIGCHLD),
            Some("3") => Some(libc::SIGTERM),
            _ => None,
        };
        if let Some(blocked) = blocked_at_start {
            // An inherited mask that hides `blocked` from the relay.
            // SAFETY: signal-mask syscall on this thread.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, blocked);
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            }
            // A process-directed SIGCHLD goes to ANY thread that does not
            // block it, and the harness has other threads that do not. Run
            // the relay in a fork, which keeps only this thread, so the
            // blocked mask is the only place SIGCHLD can be delivered (F11).
            // SAFETY: the other threads are idle in the harness; the child
            // goes straight on to the relay and exits through `exit`.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork");
            if pid > 0 {
                // The waiter stands in for the relay at its announced pid:
                // a SIGTERM aimed there reaches the real relay.
                FORK_CHILD.store(pid, Ordering::Release);
                // SAFETY: installing a handler that only calls kill(2).
                unsafe { libc::signal(libc::SIGTERM, relay_stand_in as *const () as usize) };
                let mut st: libc::c_int = 0;
                loop {
                    // SAFETY: valid out-pointer; `pid` is our child.
                    let r = unsafe { libc::waitpid(pid, &mut st, 0) };
                    if r == pid {
                        break;
                    }
                }
                std::process::exit(if libc::WIFEXITED(st) {
                    libc::WEXITSTATUS(st)
                } else {
                    101
                });
            }
        }
        if env("CSQ_S1A_PRESET").as_deref() == Some("1") {
            // An inherited ignore and a blocked mask the child must not see.
            // The ignore is on SIGVTALRM, which neither the relay (an ignored
            // fatal signal is left alone) nor the shim installs a handler
            // for: a handler would be reset by exec on its own and hide a
            // missing disposition reset (F9/F13). SIGURG is blocked, since
            // the guard unblocks every signal it handles and the relay never
            // handles SIGURG.
            // SAFETY: signal-state syscalls on this process.
            unsafe {
                libc::signal(libc::SIGVTALRM, libc::SIG_IGN);
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGURG);
                libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            }
        }
        if let Some(v) = env("CSQ_S1A_CORE").and_then(|v| v.parse::<libc::rlim_t>().ok()) {
            // SAFETY: plain rlimit syscalls on this process.
            unsafe {
                let mut lim: libc::rlimit = std::mem::zeroed();
                assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut lim), 0);
                lim.rlim_cur = v;
                assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &lim), 0);
            }
        }
        if env("CSQ_S1A_FD200").is_some() {
            // A descriptor the relay holds open (not close-on-exec) that the
            // relayed CLI must not inherit.
            // SAFETY: duplicating a descriptor we own to a high number.
            assert_ne!(unsafe { libc::fcntl(0, libc::F_DUPFD, 200) }, -1);
        }
        if env("CSQ_S1A_FDHIGH").is_some() {
            // A descriptor ABOVE a soft limit lowered after it was opened.
            // SAFETY: duplicating a descriptor we own, then a plain rlimit
            // call on this process.
            unsafe {
                raise_soft_nofile(1024);
                assert_ne!(libc::fcntl(0, libc::F_DUPFD, 300), -1);
                let mut lim: libc::rlimit = std::mem::zeroed();
                assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
                lim.rlim_cur = 64;
                assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
            }
        }
        let child = match env("CSQ_S1A_CHILD").as_deref() {
            Some("probe") => helper_spec("sigprobe"),
            // An explicit, stripped environment: only ONLY=1 may arrive.
            Some("env") => LaunchSpec::new("/usr/bin/env").env("ONLY", "1"),
            _ => LaunchSpec::new("/bin/sh")
                .arg("-c")
                .arg(env("CSQ_S1A_SCRIPT").expect("script"))
                .inherit_env(),
        };
        let mode = env("CSQ_S1A_MODE");
        let cfg = RelayConfig {
            panic_on_input: mode.as_deref() == Some("panic"),
            deaf_master: mode.as_deref() == Some("deaf"),
            stop_again_before_resume: env("CSQ_S1A_STALE_PIDFILE").map(PathBuf::from),
            ..RelayConfig::default()
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Relay::new(child, cfg).and_then(Relay::run)
        }));
        dbg(&format!("relay ended; tty_lost={}", term::tty_lost(STDIN)));
        if term::tty_lost(STDIN) {
            arm_cleanup_alarm(CLEANUP_ALARM_SECS);
            // The harness (the terminal's master) is gone, perhaps killed from
            // outside with nothing else to clean up: the shell role may have
            // died of the same hangup first. Take with this role what it
            // started, including a job in a group of its own whose shell the
            // hangup already ended (only the remembered tree still names it).
            // SAFETY: getpid has no preconditions.
            let me = unsafe { libc::getpid() };
            reap_remembered();
            let r = reap_tree_reported(me, false);
            dbg(&format!("reap_tree: {r:?}"));
        }
        match outcome {
            Err(_) => std::process::exit(101),
            Ok(Ok(exit)) => {
                // The relay itself, after it ran: still undumpable.
                println!("RELAY-CORE {}", core_state());
                exit.conclude()
            }
            Ok(Err(RelayError::Declined(Decline::Background))) => std::process::exit(42),
            Ok(Err(RelayError::Declined(Decline::NotTty(term::Stream::Stdout)))) => {
                std::process::exit(43)
            }
            Ok(Err(RelayError::Declined(Decline::NotTty(term::Stream::Stderr)))) => {
                std::process::exit(44)
            }
            Ok(Err(e)) => {
                // The error names a fixed-vocabulary op and an errno (never a
                // secret): without it an exit 50 leaves the failing step unknown.
                println!("R-ERR {e}");
                std::process::exit(50)
            }
        }
    }

    /// This process's core-file soft limit and (Linux) dumpable flag, as a
    /// report line (`-1` where there is no such flag).
    fn core_state() -> String {
        // SAFETY: plain rlimit query and prctl read.
        unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_CORE, &mut lim);
            #[cfg(target_os = "linux")]
            let dumpable = libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0);
            #[cfg(not(target_os = "linux"))]
            let dumpable = -1;
            format!("soft={} dumpable={dumpable}", lim.rlim_cur)
        }
    }

    /// Role `coreprobe`: start from a NON-ZERO core-file soft limit (an
    /// inherited zero would make the zeroing unobservable), then report the
    /// state before and after `disable_core_dumps`.
    fn role_coreprobe() -> ! {
        // SAFETY: plain rlimit syscalls on this process.
        unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut lim), 0);
            lim.rlim_cur = lim.rlim_max.min(4096);
            assert_eq!(libc::setrlimit(libc::RLIMIT_CORE, &lim), 0);
        }
        println!("CORE-BEFORE {}", core_state());
        let old = disable_core_dumps();
        println!(
            "CORE0 {} prev={}",
            core_state(),
            old.map_or(-1, |v| v as i64)
        );
        std::process::exit(0);
    }

    /// Role `forgedrelay`: spawn a shim whose plan names a relay pid that is
    /// not its parent (as if the relay had died since the fork). The shim must
    /// refuse to start the CLI.
    fn role_forged_relay() -> ! {
        // Pid 1 is never the shim's parent here.
        FORGED_RELAY.store(1, Ordering::Release);
        let spec = LaunchSpec::new("/bin/sh")
            .arg("-c")
            .arg("sleep 30")
            .inherit_env();
        let pty = Pty::open(None, None).expect("pty");
        match spawn_on_slave(&spec, pty.slave) {
            Err(e) => println!("SPAWN-ERR={}", e.raw_os_error().unwrap_or(-1)),
            Ok(sp) => {
                println!("SPAWN-OK");
                drop(sp);
            }
        }
        std::process::exit(0);
    }

    /// Role `spawner`: start a shim, leave a holder process that keeps the
    /// master and the control pipe's write end open (a leaked copy), and exit.
    /// The shim must still notice that its parent is gone (a pid check).
    fn role_spawner() -> ! {
        let pidfile = env("S1A_PIDFILE").expect("pidfile");
        let script = r#"P=$PPID; echo $$ > "$S1A_PIDFILE"; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;
        let spec = LaunchSpec::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .inherit_env()
            .env("S1A_PIDFILE", pidfile);
        let pty = Pty::open(None, None).expect("pty");
        let master = pty.master;
        let sp = spawn_on_slave(&spec, pty.slave).expect("spawn");
        // SAFETY: fork; the child only parks, then ends by SIGALRM.
        let holder = unsafe { libc::fork() };
        assert!(holder >= 0, "fork");
        if holder == 0 {
            let _keep = (&master, &sp);
            // SAFETY: alarm, close and pause are async-signal-safe. stdout
            // and stderr are closed so the caller's `output()` can return.
            unsafe {
                libc::close(1);
                libc::close(2);
                libc::alarm(120);
                loop {
                    libc::pause();
                }
            }
        }
        println!("HOLDER={holder}");
        // SAFETY: leave without running destructors (the holder has the fds).
        unsafe { libc::_exit(0) }
    }

    /// Role `busy`: a second [`SignalGuard`] in one process is refused. It runs
    /// in its own process because the guard installs process-wide handlers.
    fn role_busy() -> ! {
        // SAFETY: an all-zero termios is a valid value; it is only read by a
        // fatal-signal handler that this role never triggers.
        let outer: libc::termios = unsafe { std::mem::zeroed() };
        let first = SignalGuard::install(true, &outer).expect("first install");
        let second = SignalGuard::install(true, &outer).err();
        drop(first);
        let third = SignalGuard::install(true, &outer).map(drop);
        let ok = second == Some(RelayError::Busy) && third.is_ok();
        std::process::exit(if ok { 0 } else { 1 });
    }

    /// Role `sigprobe`: report the child's inherited signal state (F9).
    fn role_sigprobe() -> ! {
        // SAFETY: signal-state queries on this process.
        let (nondefault, blocked) = unsafe {
            let mut odd = Vec::new();
            for sig in 1..65 {
                // The Rust runtime owns SIGPIPE (ignored: the `yes | head`
                // test covers it) and the stack-overflow faults.
                if matches!(sig, libc::SIGKILL | libc::SIGSTOP | libc::SIGPIPE)
                    || matches!(sig, libc::SIGSEGV | libc::SIGBUS)
                {
                    continue;
                }
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &mut old) == 0
                    && old.sa_sigaction != libc::SIG_DFL
                {
                    odd.push(sig);
                }
            }
            let mut cur: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut cur);
            let n = (1..32).filter(|&s| libc::sigismember(&cur, s) == 1).count();
            (odd, n)
        };
        // SAFETY: plain rlimit query.
        let core = unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_CORE, &mut lim);
            lim.rlim_cur
        };
        println!("CORE={core}");
        println!("F9 nondefault={nondefault:?} blocked={blocked}");
        std::process::exit(0);
    }

    // -- the harness (runs in the real test process) -------------------------

    struct Outer {
        master: OwnedFd,
        orig: libc::termios,
        acc: Vec<u8>,
        pos: usize,
        shell: Option<std::process::Child>,
        /// A process of its own session that outlives a hangup and ends what
        /// the shell role started when this process dies (see `role_sentinel`).
        sentinel: Option<std::process::Child>,
        _home: tempfile::TempDir,
    }

    fn same_termios(a: &libc::termios, b: &libc::termios) -> bool {
        a.c_iflag == b.c_iflag
            && a.c_oflag == b.c_oflag
            && a.c_cflag == b.c_cflag
            // PENDIN is set by the kernel itself when the mode changes under
            // pending input; it is not a mode the relay chooses.
            && a.c_lflag & !libc::PENDIN == b.c_lflag & !libc::PENDIN
            && a.c_cc == b.c_cc
    }

    fn winsize(rows: u16, cols: u16) -> libc::winsize {
        libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }

    impl Outer {
        /// Start the shell role over a 33x101 outer PTY. `script` is the sh
        /// program the relayed child runs.
        fn start(script: &str, extra: &[(&str, &str)]) -> Outer {
            Outer::start_with(script, extra, false)
        }

        /// [`Outer::start`] on a terminal that may have `tostop` set (a
        /// background process writing to it is stopped by `SIGTTOU`).
        fn start_with(script: &str, extra: &[(&str, &str)], tostop: bool) -> Outer {
            let home = tempfile::tempdir().expect("tempdir");
            let ws = winsize(33, 101);
            let pty = Pty::open(None, Some(&ws)).expect("outer pty");
            if tostop {
                let mut t = get_termios(pty.master.as_raw_fd()).expect("outer termios");
                t.c_lflag |= libc::TOSTOP;
                // SAFETY: a valid termios for the call's duration.
                let rc = unsafe { libc::tcsetattr(pty.master.as_raw_fd(), libc::TCSANOW, &t) };
                assert_eq!(rc, 0, "set tostop");
            }
            let orig = get_termios(pty.master.as_raw_fd()).expect("outer termios");
            let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
            cmd.args(HELPER_ARGS)
                .env_clear()
                .env("PATH", std::env::var("PATH").unwrap_or_default())
                .env("LANG", "C")
                .env("TERM", "xterm")
                .env("TMPDIR", home.path())
                .env("HOME", home.path())
                .env(ROLE, "shell")
                .env(PARENT, std::process::id().to_string())
                .env("CSQ_S1A_SCRIPT", script);
            for (k, v) in extra {
                cmd.env(k, v);
            }
            let out = pty.slave.try_clone().expect("dup");
            let err = pty.slave.try_clone().expect("dup");
            cmd.stdin(Stdio::from(pty.slave))
                .stdout(Stdio::from(out))
                .stderr(Stdio::from(err));
            // SAFETY: `child_prepare` uses only async-signal-safe calls.
            unsafe { cmd.pre_exec(child_prepare) };
            let mut shell = cmd.spawn().expect("spawn shell role");
            let sentinel = if env("CSQ_S1A_NO_SENTINEL").is_some_and(|v| !v.is_empty()) {
                None
            } else {
                // Its stderr is a marker sink next to the scratch HOME, never
                // /dev/null: a failure the sentinel reports stays readable.
                let sink = std::fs::File::create(home.path().join("sentinel.err"))
                    .expect("sentinel marker sink");
                let mut sc = helper_command("sentinel");
                sc.env("CSQ_S1A_WATCH_ROOT", shell.id().to_string())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(sink));
                for (k, v) in extra {
                    sc.env(k, v);
                }
                // A session of its own: no controlling terminal, so the
                // hangup that ends the shell role never reaches it.
                // SAFETY: setsid is async-signal-safe.
                unsafe {
                    sc.pre_exec(|| {
                        libc::setsid();
                        Ok(())
                    })
                };
                match sc.spawn() {
                    Ok(c) => Some(c),
                    Err(e) => {
                        // A run without its safety net is not a run: end the
                        // shell role and fail hard.
                        let _ = shell.kill();
                        let _ = shell.wait();
                        panic!("CLEANUP-SENTINEL-NOT-STARTED: {e}");
                    }
                }
            };
            set_nonblock(pty.master.as_raw_fd()).expect("nonblock");
            Outer {
                master: pty.master,
                orig,
                acc: Vec::new(),
                pos: 0,
                shell: Some(shell),
                sentinel,
                _home: home,
            }
        }

        fn fill(&mut self, deadline: Instant) {
            assert!(
                Instant::now() < deadline,
                "timed out; output so far: {:?}",
                String::from_utf8_lossy(&self.acc)
            );
            let mut pfd = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(&mut pfd, 1, 100) };
            let mut buf = [0u8; 4096];
            if let MasterRead::Data(n) =
                classify_master_read(read_fd(self.master.as_raw_fd(), &mut buf))
            {
                self.acc.extend_from_slice(&buf[..n]);
            }
        }

        /// Wait until `marker` appears after the read cursor; consume through it.
        fn wait_for(&mut self, marker: &str) {
            let deadline = Instant::now() + WAIT;
            loop {
                if let Some(i) = find(&self.acc[self.pos..], marker.as_bytes()) {
                    self.pos += i + marker.len();
                    return;
                }
                self.fill(deadline);
            }
        }

        /// Wait for `prefix` and return the rest of that line.
        fn wait_value(&mut self, prefix: &str) -> String {
            self.wait_for(prefix);
            let deadline = Instant::now() + WAIT;
            loop {
                if let Some(i) = self.acc[self.pos..].iter().position(|&b| b == b'\n') {
                    let line =
                        String::from_utf8_lossy(&self.acc[self.pos..self.pos + i]).into_owned();
                    self.pos += i + 1;
                    return line.trim().to_string();
                }
                self.fill(deadline);
            }
        }

        /// Wait for exactly `n` bytes after the cursor and return them.
        fn take_bytes(&mut self, n: usize) -> Vec<u8> {
            let deadline = Instant::now() + WAIT;
            while self.acc.len() - self.pos < n {
                self.fill(deadline);
            }
            let out = self.acc[self.pos..self.pos + n].to_vec();
            self.pos += n;
            out
        }

        /// Close the outer master, as a closed terminal tab does.
        fn hang_up(&mut self) {
            let null = std::fs::File::open("/dev/null").expect("/dev/null");
            drop(std::mem::replace(&mut self.master, OwnedFd::from(null)));
        }

        fn send(&self, bytes: &[u8]) {
            write_all_blocking_nb(self.master.as_raw_fd(), bytes);
        }

        fn termios(&self) -> libc::termios {
            get_termios(self.master.as_raw_fd()).expect("outer termios")
        }

        fn is_raw_now(&self) -> bool {
            self.termios().c_lflag & libc::ICANON == 0
        }

        fn resize(&self, rows: u16, cols: u16) {
            set_winsize(self.master.as_raw_fd(), &winsize(rows, cols)).expect("resize outer");
        }

        fn relay_pid(&mut self) -> libc::pid_t {
            self.wait_value("R-PID ").parse().expect("relay pid")
        }

        fn assert_restored(&self, what: &str) {
            let now = self.termios();
            assert!(
                same_termios(&now, &self.orig),
                "outer terminal not restored after {what}: iflag {:x}/{:x} oflag {:x}/{:x} cflag {:x}/{:x} lflag {:x}/{:x} cc_equal {}",
                now.c_iflag, self.orig.c_iflag, now.c_oflag, self.orig.c_oflag,
                now.c_cflag, self.orig.c_cflag, now.c_lflag, self.orig.c_lflag,
                now.c_cc == self.orig.c_cc
            );
        }
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn write_all_blocking_nb(fd: RawFd, mut buf: &[u8]) {
        let deadline = Instant::now() + WAIT;
        while !buf.is_empty() {
            match write_fd(fd, buf) {
                Ok(n) => buf = &buf[n..],
                Err(e) if matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) => {
                    assert!(Instant::now() < deadline, "outer write stalled");
                    std::thread::yield_now();
                }
                Err(e) => panic!("outer write failed: {e}"),
            }
        }
    }

    fn kill_pid(pid: libc::pid_t, sig: libc::c_int) {
        // SAFETY: the test names a pid it learned from the process itself and
        // signals only that pid (never a pattern).
        unsafe { libc::kill(pid, sig) };
    }

    /// `ps -o <field>= -p <pid>`, trimmed, through the bounded runner:
    /// `Ok(None)` when the pid does not exist, `Err` when `ps` itself failed
    /// (an error is never a statement about the pid).
    fn ps_field_checked(pid: libc::pid_t, field: &str) -> Result<Option<String>, String> {
        let mut c = Command::new("/bin/ps");
        c.args(["-o", &format!("{field}="), "-p", &pid.to_string()]);
        let listing = run_bounded_with(c, PS_LIMIT, &[0, 1], &set_nonblock)?;
        let text = listing.text.trim().to_string();
        Ok((!text.is_empty()).then_some(text))
    }

    /// [`ps_field_checked`] for a test that polls: a failed `ps` fails the test
    /// loudly instead of reading as "the pid does not exist".
    fn ps_field(pid: libc::pid_t, field: &str) -> Option<String> {
        ps_field_checked(pid, field)
            .unwrap_or_else(|e| panic!("CLEANUP-PS-FAILED: ps {field} of {pid}: {e}"))
    }

    type Row = (libc::pid_t, libc::pid_t, libc::pid_t);

    /// How many `ps` runs are attempted before a snapshot counts as failed.
    const PS_ATTEMPTS: u64 = 5;
    /// How many freeze passes [`reap_tree_via`] makes before it gives up on the
    /// tree settling.
    const FREEZE_PASSES: usize = 50;
    /// How long the freeze phase may last in all (listings included). Well
    /// inside [`CLEANUP_ALARM_SECS`] together with [`REMEMBER_BUDGET`], so the
    /// kill phase is always reached.
    const FREEZE_DEADLINE: Duration = Duration::from_secs(5);
    /// The alarm a cleaning role arms: the backstop behind the deadlines.
    const CLEANUP_ALARM_SECS: u32 = 15;

    /// The system process listing: pid, parent and process group of every
    /// process.
    fn system_ps() -> Command {
        let mut c = Command::new("/bin/ps");
        c.args(["-A", "-o", "pid=,ppid=,pgid="]);
        c
    }

    /// Every process as `(pid, parent, process group)` from `ps` (a parameter
    /// so a test can make it fail), retried a bounded number of times: on a
    /// loaded host the fork can fail.
    fn ps_rows_via(ps: &dyn Fn() -> Command) -> Result<Vec<Row>, String> {
        ps_rows_until(ps, Instant::now() + PS_LIMIT * PS_ATTEMPTS as u32)
    }

    /// [`ps_rows_via`] that gives up at `deadline`. The listing process itself
    /// (a child of the caller, so it would otherwise be a descendant of the
    /// caller that is never gone from the next snapshot) is left out.
    fn ps_rows_until(ps: &dyn Fn() -> Command, deadline: Instant) -> Result<Vec<Row>, String> {
        let mut last = "the process listing deadline passed before a run".to_string();
        for attempt in 0..PS_ATTEMPTS {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match run_bounded(ps(), left.min(PS_LIMIT)) {
                Ok(listing) => {
                    let rows: Vec<Row> = listing
                        .text
                        .lines()
                        .filter_map(|l| {
                            let mut it = l.split_whitespace();
                            Some((
                                it.next()?.parse().ok()?,
                                it.next()?.parse().ok()?,
                                it.next()?.parse().ok()?,
                            ))
                        })
                        .filter(|r: &Row| r.0 != listing.pid)
                        .collect();
                    if rows.is_empty() {
                        last = "ps printed no process".to_string();
                    } else {
                        return Ok(rows);
                    }
                }
                Err(e) => last = e,
            }
            let pause = Duration::from_millis(50 * (attempt + 1));
            std::thread::sleep(pause.min(deadline.saturating_duration_since(Instant::now())));
        }
        Err(last)
    }

    /// Every descendant of `root` (not `root`), parents before children.
    fn descendants_of(rows: &[Row], root: libc::pid_t) -> Vec<Row> {
        let mut found: Vec<Row> = Vec::new();
        let mut frontier = vec![root];
        while let Some(parent) = frontier.pop() {
            for (pid, ppid, pgid) in rows {
                if *ppid == parent && !found.iter().any(|(p, _, _)| p == pid) {
                    found.push((*pid, *ppid, *pgid));
                    frontier.push(*pid);
                }
            }
        }
        found
    }

    /// Room for every process and group a cleanup freezes, readable from a
    /// signal handler. Written only by a cleaning role; never reset (the
    /// handler runs only in a role that is ending).
    const FROZEN_MAX: usize = 512;
    static FROZEN_PIDS: [AtomicI32; FROZEN_MAX] = [const { AtomicI32::new(0) }; FROZEN_MAX];
    static FROZEN_PIDS_N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    static FROZEN_GROUPS: [AtomicI32; FROZEN_MAX] = [const { AtomicI32::new(0) }; FROZEN_MAX];
    static FROZEN_GROUPS_N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    /// How many freeze passes the last reap made (test observation).
    static LAST_PASSES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn remember_frozen(pid: libc::pid_t, group: bool) {
        let (slots, n) = if group {
            (&FROZEN_GROUPS, &FROZEN_GROUPS_N)
        } else {
            (&FROZEN_PIDS, &FROZEN_PIDS_N)
        };
        let i = n.fetch_add(1, Ordering::SeqCst);
        if i < FROZEN_MAX {
            slots[i].store(pid, Ordering::SeqCst);
        }
    }

    /// `SIGALRM` of a cleaning role: SIGKILL everything the cleanup froze
    /// (nothing may stay `SIGSTOP`ped), then end. Async-signal-safe calls only.
    extern "C" fn cleanup_alarm(_sig: libc::c_int) {
        let groups = FROZEN_GROUPS_N.load(Ordering::SeqCst).min(FROZEN_MAX);
        for slot in &FROZEN_GROUPS[..groups] {
            let g = slot.load(Ordering::SeqCst);
            if g > 1 {
                // SAFETY: kill is async-signal-safe.
                unsafe { libc::kill(-g, libc::SIGKILL) };
            }
        }
        let pids = FROZEN_PIDS_N.load(Ordering::SeqCst).min(FROZEN_MAX);
        for slot in &FROZEN_PIDS[..pids] {
            let p = slot.load(Ordering::SeqCst);
            if p > 1 {
                // SAFETY: as above.
                unsafe { libc::kill(p, libc::SIGKILL) };
            }
        }
        // SAFETY: _exit never returns.
        unsafe { libc::_exit(137) }
    }

    /// Arm the backstop of a cleaning role: a `SIGALRM` handler of its own
    /// (replacing any other, such as the relay's forwarding handler), the
    /// signal unblocked, and an alarm in `secs`.
    fn arm_cleanup_alarm(secs: u32) {
        // SAFETY: plain signal-state syscalls on this process.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = cleanup_alarm as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(libc::SIGALRM, &sa, std::ptr::null_mut());
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGALRM);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            libc::alarm(secs);
        }
    }

    /// End everything below `root` however it got there: relay, shim, CLI and
    /// whatever the CLI started in groups of its own. Freeze first, then kill:
    /// every pass snapshots the tree (plus the members of the process groups
    /// the tree is in, which includes processes reparented out of it) and
    /// SIGSTOPs what is new, until a snapshot finds nothing new (a stopped
    /// process cannot fork, so what is frozen cannot escape into a new group
    /// while the rest is being killed); then the groups and the pids are
    /// SIGKILLed. `root` itself is stopped when `stop_root` (a watchdog is its
    /// own root and must keep running). Own group, group 1 and group 0 are
    /// never signalled, and `root <= 1` is refused.
    ///
    /// What holds, and what does not. A process this function has stopped
    /// cannot exit by itself, so its pid is not freed while its parent (which
    /// is in the tree and stopped too) keeps it unreaped; that is the only
    /// pid-reuse protection, and it does NOT cover a parent outside the tree
    /// that reaps a killed member, nor the window between a snapshot and the
    /// `SIGSTOP` of a pid it lists (a listed process can exit there and its
    /// number be reused). The freeze phase ends by [`FREEZE_DEADLINE`] (so the
    /// kill phase is always reached), and every frozen pid is recorded for
    /// [`cleanup_alarm`].
    ///
    /// `Err` when the process table could not be read, the tree did not settle
    /// or the deadline passed: whatever was frozen is still killed.
    fn reap_tree_via(
        ps: &dyn Fn() -> Command,
        root: libc::pid_t,
        stop_root: bool,
    ) -> Result<(), String> {
        reap_tree_bounded(ps, root, stop_root, FREEZE_DEADLINE)
    }

    fn reap_tree_bounded(
        ps: &dyn Fn() -> Command,
        root: libc::pid_t,
        stop_root: bool,
        freeze: Duration,
    ) -> Result<(), String> {
        if root <= 1 {
            return Err(format!("refusing to reap the tree of process {root}"));
        }
        // SAFETY: getpgrp and getpid have no preconditions.
        let (own, me) = unsafe { (libc::getpgrp(), libc::getpid()) };
        if stop_root {
            remember_frozen(root, false);
            kill_pid(root, libc::SIGSTOP);
        }
        let deadline = Instant::now() + freeze;
        let mut frozen: Vec<Row> = Vec::new();
        let mut groups: Vec<libc::pid_t> = Vec::new();
        let mut outcome = Err("the tree did not settle".to_string());
        let mut passes = 0usize;
        for _ in 0..FREEZE_PASSES {
            if Instant::now() >= deadline {
                outcome = Err("the freeze deadline passed before the tree settled".to_string());
                break;
            }
            passes += 1;
            let rows = match ps_rows_until(ps, deadline) {
                Ok(r) => r,
                Err(e) => {
                    outcome = Err(e);
                    break;
                }
            };
            let mut fresh: Vec<Row> = descendants_of(&rows, root)
                .into_iter()
                .filter(|r| !frozen.iter().any(|f| f.0 == r.0))
                .collect();
            for (_, _, pgid) in &fresh {
                if *pgid > 1 && *pgid != own && !groups.contains(pgid) {
                    remember_frozen(*pgid, true);
                    groups.push(*pgid);
                }
            }
            for r in &rows {
                if r.0 != me
                    && r.0 != root
                    && groups.contains(&r.2)
                    && !frozen.iter().any(|f| f.0 == r.0)
                    && !fresh.iter().any(|f| f.0 == r.0)
                {
                    fresh.push(*r);
                }
            }
            if fresh.is_empty() {
                outcome = Ok(());
                break;
            }
            for r in &fresh {
                remember_frozen(r.0, false);
                kill_pid(r.0, libc::SIGSTOP);
            }
            frozen.extend(fresh);
        }
        LAST_PASSES.store(passes, Ordering::Relaxed);
        for pgid in &groups {
            kill_pid(-*pgid, libc::SIGKILL);
        }
        for (pid, _, _) in frozen.iter().rev() {
            kill_pid(*pid, libc::SIGKILL);
        }
        outcome
    }

    /// [`reap_tree_via`] with the system `ps`, and a fixed marker on stderr
    /// when it could not do its job (never a silent fallback).
    fn reap_tree_reported(root: libc::pid_t, stop_root: bool) -> Result<(), String> {
        let r = reap_tree_via(&system_ps, root, stop_root);
        if let Err(e) = &r {
            eprintln!("CLEANUP-SNAPSHOT-FAILED: {e}");
        }
        r
    }

    /// Whether an announced relay pid is still ours to end: it is a helper
    /// role of this test binary and its parent is the shell role, or init once
    /// the shell role has died (a hangup kills the shell role first and
    /// reparents the relay).
    fn announced_relay_is_ours(
        shell: Option<libc::pid_t>,
        parent: Option<libc::pid_t>,
        command: Option<&str>,
    ) -> bool {
        let parent_ok = match (shell, parent) {
            (Some(s), Some(p)) => p == s || p == 1,
            _ => false,
        };
        parent_ok && command.is_some_and(|c| c.contains(HELPER_ARGS[1]))
    }

    impl Outer {
        /// Every pid announced after `tag` in the output, in order.
        fn announced(&self, tag: &str) -> Vec<libc::pid_t> {
            let mut out = Vec::new();
            let mut rest = &self.acc[..];
            while let Some(i) = find(rest, tag.as_bytes()) {
                rest = &rest[i + tag.len()..];
                let digits: String = rest
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .map(|&b| b as char)
                    .collect();
                if let Ok(pid) = digits.parse() {
                    out.push(pid);
                }
            }
            out
        }
    }

    /// Cleanup ends everything the shell role started (see [`reap_tree_via`]:
    /// freeze, then kill; a process table that cannot be read fails the test
    /// with `CLEANUP-SNAPSHOT-FAILED`). The shell role is a `Child` handle
    /// (killed and waited here). The announced-pid kills below are a second
    /// layer: each signals a pid only while `ps` shows it still hanging off
    /// its un-reaped parent, which keeps the number from being reused.
    impl Drop for Outer {
        fn drop(&mut self) {
            if std::thread::panicking() {
                eprintln!(
                    "outer terminal output: {:?}",
                    String::from_utf8_lossy(&self.acc)
                );
            }
            let shell_pid = self.shell.as_ref().map(|c| c.id() as libc::pid_t);
            // Everything the shell role started, relay, shim, CLI and what the
            // CLI started in groups of its own, whether or not the pty output
            // ever announced it: a test that ended before reading the
            // announcements (an early assertion, a timeout in `start`) must not
            // leave them behind. The sentinel keeps watching until the very
            // end: it is killed LAST, so an unfinished cleanup is still covered.
            let reaped = shell_pid.map_or(Ok(()), |root| reap_tree_reported(root, true));
            // The announced-pid layer runs whether the shell role is alive or
            // already dead (a hangup kills it and reparents the relay):
            // [`announced_relay_is_ours`] decides per pid.
            let relay = self.announced("R-PID ").last().copied();
            let child = self.announced("CHILD=").last().copied();
            let ppid = |p| {
                ps_field_checked(p, "ppid")
                    .ok()
                    .flatten()
                    .and_then(|v| v.parse::<libc::pid_t>().ok())
            };
            let command_of = |p| ps_field_checked(p, "command").ok().flatten();
            if let Some(r) = relay {
                if announced_relay_is_ours(shell_pid, ppid(r), command_of(r).as_deref()) {
                    if let Some(c) = child {
                        if ppid(c).and_then(ppid) == Some(r) {
                            kill_pid(c, libc::SIGKILL);
                        }
                    }
                    kill_pid(r, libc::SIGKILL);
                }
            }
            for sl in self.announced("SLEEP=") {
                let in_group = ps_field_checked(sl, "pgid")
                    .ok()
                    .flatten()
                    .and_then(|v| v.parse().ok())
                    == child;
                let is_sleep = command_of(sl).is_some_and(|c| c.contains("sleep"));
                if in_group && is_sleep {
                    kill_pid(sl, libc::SIGKILL);
                }
            }
            if let Some(mut shell) = self.shell.take() {
                let _ = shell.kill();
                let _ = shell.wait();
            }
            if let Some(mut sentinel) = self.sentinel.take() {
                let _ = sentinel.kill();
                let _ = sentinel.wait();
            }
            if let Err(e) = reaped {
                // Not a pass: the cleanup could not prove it found everything.
                if !std::thread::panicking() {
                    panic!("CLEANUP-SNAPSHOT-FAILED: {e}");
                }
            }
        }
    }

    // -- the criteria --------------------------------------------------------

    #[test]
    fn child_exit_code_is_the_relay_result() {
        let mut o = Outer::start("echo READY; exit 7", &[]);
        assert_eq!(o.wait_value("R-EXIT "), "7");
        o.assert_restored("a normal exit");
    }

    /// The relay's master is deaf (test mode), so the master hangup a session
    /// leader's exit causes cannot wake it: only SIGCHLD (unblocked by the
    /// guard) or the poll backstop can announce the shim's exit. Each alone
    /// is enough; removing both leaves the relay hung.
    #[test]
    fn child_exit_is_noticed_when_sigchld_was_blocked_at_start() {
        let mut o = Outer::start(
            // No output: a deaf master would leave it unread, and macOS holds
            // a closing tty until its output drains.
            "/bin/sleep 1; exit 5",
            &[("CSQ_S1A_PRESET", "2"), ("CSQ_S1A_MODE", "deaf")],
        );
        assert_eq!(o.wait_value("R-EXIT "), "5");
    }

    /// An inherited mask that blocks SIGTERM must not stop it being forwarded:
    /// the guard's unblock is the only thing that delivers it.
    #[test]
    fn sigterm_is_forwarded_when_the_relay_inherited_it_blocked() {
        let script = r#"P=$PPID; trap 'echo GOT-TERM; exit 3' TERM; echo READY; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;
        let mut o = Outer::start(script, &[("CSQ_S1A_PRESET", "3")]);
        let relay = o.relay_pid();
        o.wait_for("READY");
        kill_pid(relay, libc::SIGTERM);
        assert_eq!(o.wait_value("R-EXIT "), "3");
    }

    #[test]
    fn child_killed_by_signal_is_reraised_as_wifsignaled() {
        let mut o = Outer::start("echo READY; kill -TERM $$", &[]);
        assert_eq!(
            o.wait_value("R-SIG "),
            "15",
            "must be WIFSIGNALED, not exit 143"
        );
        o.assert_restored("a signalled exit");
    }

    #[test]
    fn resize_reaches_the_child_and_initial_size_is_copied() {
        let script = r#"P=$PPID; trap 'echo SIZE=$(/bin/stty size)' WINCH; echo "INIT=$(/bin/stty size)"; echo READY; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;
        let mut o = Outer::start(script, &[]);
        assert_eq!(o.wait_value("INIT="), "33 101");
        o.wait_for("READY");
        o.resize(40, 120);
        assert_eq!(o.wait_value("SIZE="), "40 120");
    }

    #[test]
    fn termios_is_raw_while_running_and_restored_after_child_kill() {
        let mut o = Outer::start(
            "P=$PPID; echo CHILD=$$; echo READY; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done",
            &[],
        );
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        assert!(o.is_raw_now(), "relay must hold the outer terminal raw");
        assert!(!same_termios(&o.termios(), &o.orig));
        kill_pid(child, libc::SIGKILL);
        assert_eq!(o.wait_value("R-SIG "), "9");
        o.assert_restored("a child kill");
    }

    #[test]
    fn termios_is_restored_after_a_relay_panic() {
        let mut o = Outer::start(
            "P=$PPID; echo READY; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done",
            &[("CSQ_S1A_MODE", "panic")],
        );
        o.wait_for("READY");
        assert!(o.is_raw_now());
        o.send(b"x");
        assert_eq!(o.wait_value("R-EXIT "), "101");
        o.assert_restored("a relay panic");
    }

    #[test]
    fn sigterm_to_the_relay_is_forwarded_and_termios_restored() {
        let mut o = Outer::start(
            "P=$PPID; echo READY; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done",
            &[],
        );
        let relay = o.relay_pid();
        o.wait_for("READY");
        kill_pid(relay, libc::SIGTERM);
        assert_eq!(o.wait_value("R-SIG "), "15");
        o.assert_restored("SIGTERM");
    }

    /// The child stops itself when it reads a line, the way an interactive
    /// CLI stops on `^Z`: the relay sees a plain child stop.
    const JOB_SCRIPT: &str = r#"P=$PPID; echo CHILD=$$; echo READY; read x; kill -STOP $$; echo "CONT-SIZE=$(/bin/stty size)"; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;

    #[test]
    fn child_stop_suspends_restoring_termios_and_resume_reenters_raw_with_size() {
        let mut o = Outer::start(JOB_SCRIPT, &[]);
        o.wait_for("READY");
        assert!(o.is_raw_now());
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        o.assert_restored("a child stop");
        o.resize(50, 130);
        o.send(b"fg\n");
        assert_eq!(
            o.wait_value("CONT-SIZE="),
            "50 130",
            "SIGCONT and size on resume"
        );
        assert!(o.is_raw_now(), "fg must re-enter raw mode");
    }

    /// The real `^Z` path: the CLI stops itself with SIGTSTP. Its process
    /// group is NOT orphaned (its parent, the shim, shares its session), so
    /// the kernel delivers the stop; run without the shim both kernels
    /// discarded it and nothing suspended.
    #[test]
    fn ctrl_z_tstp_suspends_a_relayed_child() {
        let script = r#"P=$PPID; echo CHILD=$$; echo READY; read x; kill -TSTP $$; echo "CONT-SIZE=$(/bin/stty size)"; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;
        let mut o = Outer::start(script, &[]);
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        o.assert_restored("a SIGTSTP stop");
        assert!(
            proc_state(child).starts_with('T'),
            "the CLI must be stopped, got {:?}",
            proc_state(child)
        );
        o.send(b"fg\n");
        o.wait_for("CONT-SIZE=");
        assert!(o.is_raw_now(), "fg must re-enter raw mode");
    }

    /// The `^Z` byte typed at the terminal: the inner line discipline turns
    /// it into SIGTSTP for the CLI's foreground group.
    #[test]
    fn a_typed_ctrl_z_suspends_and_fg_resumes_the_child() {
        let mut o = Outer::start("echo CHILD=$$; echo READY; read x; echo GOT-$x", &[]);
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(&[0x1a]);
        o.wait_for("R-STOPPED");
        o.assert_restored("a typed ^Z");
        assert!(
            proc_state(child).starts_with('T'),
            "got {:?}",
            proc_state(child)
        );
        o.send(b"fg\n");
        o.send(b"q\n");
        o.wait_for("GOT-q");
        assert_eq!(o.wait_value("R-EXIT "), "0");
    }

    #[test]
    fn sigterm_while_suspended_ends_the_session() {
        let mut o = Outer::start("echo CHILD=$$; echo READY; read x; echo GOT-$x", &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(&[0x1a]);
        o.wait_for("R-STOPPED");
        kill_pid(relay, libc::SIGTERM);
        kill_pid(relay, libc::SIGCONT);
        // The shell role is parked reading a command; any other line sends
        // it back to waiting on the relay.
        o.send(b"x\n");
        assert_eq!(o.wait_value("R-SIG "), "15");
        assert!(
            wait_gone(child),
            "the CLI must not outlive a terminated relay"
        );
    }

    #[test]
    fn a_closed_terminal_while_suspended_hangs_up_the_child() {
        let mut o = Outer::start("echo CHILD=$$; echo READY; read x; echo GOT-$x", &[]);
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(&[0x1a]);
        o.wait_for("R-STOPPED");
        o.hang_up();
        assert!(
            wait_gone(child),
            "the CLI must not outlive a closed terminal"
        );
    }

    /// The CLI's group is not orphaned: it leads its OWN group, and its parent
    /// (the shim) is in a different group of the same session. An orphaned
    /// group is exactly what made the kernel discard SIGTSTP (journal
    /// context-trim/0010).
    #[test]
    fn the_cli_leads_its_own_group_under_a_parent_in_another_group() {
        let script = r#"PP=$(/bin/ps -o ppid= -p $$ | /usr/bin/tr -d ' '); echo "PG=$(/bin/ps -o pgid= -p $$ | /usr/bin/tr -d ' ') ME=$$ PPG=$(/bin/ps -o pgid= -p $PP | /usr/bin/tr -d ' ') PP=$PP"; echo READY; read x"#;
        let mut o = Outer::start(script, &[]);
        let facts = o.wait_value("PG=");
        let field = |name: &str| {
            facts
                .split_whitespace()
                .find_map(|w| w.strip_prefix(name))
                .map(str::to_string)
                .unwrap_or_else(|| panic!("{name} in {facts:?}"))
        };
        // `wait_value("PG=")` strips the prefix: the first field is PG itself.
        let pg = facts.split_whitespace().next().unwrap().to_string();
        let (me, ppg, pp) = (field("ME="), field("PPG="), field("PP="));
        assert_eq!(pg, me, "the CLI must lead its own process group");
        assert_ne!(ppg, pg, "its parent must be in another group");
        assert_eq!(ppg, pp, "the parent is the session leader shim");
        o.send(b"\n");
    }

    /// Poll until `pid` no longer exists (or only as a zombie). A `ps` that
    /// fails says nothing about the pid: it is polled again, and at the end of
    /// `limit` the answer is "not gone".
    fn wait_gone_via(
        pid: libc::pid_t,
        state: &dyn Fn(libc::pid_t) -> Result<String, String>,
        limit: Duration,
    ) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if let Ok(st) = state(pid) {
                if st.is_empty() || st.starts_with('Z') {
                    return true;
                }
            }
            tick();
        }
        false
    }

    fn wait_gone(pid: libc::pid_t) -> bool {
        wait_gone_via(pid, &proc_state_checked, WAIT)
    }

    /// The `ps` state of `pid` (empty when it does not exist), `Err` when `ps`
    /// failed.
    fn proc_state_checked(pid: libc::pid_t) -> Result<String, String> {
        Ok(ps_field_checked(pid, "state")?.unwrap_or_default())
    }

    fn proc_state(pid: libc::pid_t) -> String {
        proc_state_checked(pid)
            .unwrap_or_else(|e| panic!("CLEANUP-PS-FAILED: ps state of {pid}: {e}"))
    }

    #[test]
    fn bg_resume_stays_cooked_and_stopped_and_fg_reenters_raw() {
        let mut o = Outer::start(JOB_SCRIPT, &[]);
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        o.send(b"bg\n");
        o.wait_for("R-STOPPED");
        o.assert_restored("a background resume");
        assert!(
            proc_state(child).starts_with('T'),
            "child must stay stopped after bg, got {:?}",
            proc_state(child)
        );
        o.send(b"fg\n");
        o.wait_for("CONT-SIZE=");
        assert!(o.is_raw_now(), "fg must re-enter raw mode");
        assert!(
            !proc_state(child).starts_with('T'),
            "child must run after fg"
        );
    }

    /// The retry: a transient error is retried until the call succeeds; it is
    /// returned after the cap; any other error is returned at once.
    #[test]
    fn retry_transient_retries_only_the_transient_error_up_to_the_cap() {
        let is_six = |e: &io::Error| e.raw_os_error() == Some(-6);
        let mut calls = 0;
        let r = retry_transient(is_six, || {
            calls += 1;
            if calls < 2 {
                Err(io::Error::from_raw_os_error(-6))
            } else {
                Ok(7)
            }
        });
        assert_eq!((r.expect("second attempt succeeds"), calls), (7, 2));
        let mut calls = 0;
        let r: io::Result<()> = retry_transient(is_six, || {
            calls += 1;
            Err(io::Error::from_raw_os_error(-6))
        });
        assert_eq!(r.expect_err("capped").raw_os_error(), Some(-6));
        assert_eq!(calls, PTY_TRANSIENT_ATTEMPTS);
        let mut calls = 0;
        let r: io::Result<()> = retry_transient(is_six, || {
            calls += 1;
            Err(io::Error::from_raw_os_error(libc::EIO))
        });
        assert_eq!(
            r.expect_err("not transient").raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn only_the_macos_transient_errors_are_retried() {
        let six = io::Error::from_raw_os_error(-6);
        let range = io::Error::from_raw_os_error(libc::ERANGE);
        let mac = cfg!(target_os = "macos");
        assert_eq!(openpt_transient(&six), mac);
        assert!(!openpt_transient(&range));
        assert_eq!(ttyname_transient(&range), mac);
        assert!(!ttyname_transient(&six));
    }

    /// Opening a terminal while many others are created and closed: macOS
    /// leaks XNU's internal `EREDRIVEOPEN` (-6) from `posix_openpt` and has
    /// `ttyname_r` report `ERANGE` while its `/dev` lookup races the churn
    /// (probed: each clears on the next attempt). Neither may fail a launch.
    #[test]
    fn pty_open_and_tty_reopen_survive_concurrent_pty_churn() {
        // A hard wall-time bound: a kernel call stuck under churn (observed on
        // macOS: a thread spinning in `grantpt`'s ioctl for an hour) must FAIL
        // this test, never hang it. Each thread also checks the deadline
        // between iterations; the join waits on a channel with a timeout so a
        // thread stuck INSIDE a syscall cannot hold the test either.
        const CHURN_DEADLINE: Duration = Duration::from_secs(120);
        let deadline = Instant::now() + CHURN_DEADLINE;
        let (tx, rx) = std::sync::mpsc::channel::<Result<(), String>>();
        // Sized to a real user: a few relays launching at once, not a stress
        // storm. 16 threads x 200 reproduces a macOS kernel spin in
        // grantpt/unlockpt (sampled at ~90% CPU in the ioctl; not csq code,
        // repro: scratchpad F-grantpt-repro.c) that hangs ~1 run in 4.
        let n_threads = 4;
        // Scoped to this test: each churn thread installs it, so only retries
        // absorbed before a SUCCESS inside this test's own calls are counted.
        let absorbed = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        for _ in 0..n_threads {
            let tx = tx.clone();
            let probe = absorbed.clone();
            std::thread::spawn(move || {
                TRANSIENT_RUN_PROBE.with(|p| *p.borrow_mut() = Some(probe));
                let r = (|| {
                    for _ in 0..50 {
                        if Instant::now() >= deadline {
                            return Err("churn deadline passed".to_string());
                        }
                        let pty = Pty::open(None, None).map_err(|e| format!("pty: {e}"))?;
                        let q = OutQueue::open_tty(pty.slave.as_raw_fd())
                            .map_err(|e| format!("tty reopen: {e}"))?;
                        if rdev_of(q.raw()) != rdev_of(pty.slave.as_raw_fd()) {
                            return Err("reopened fd is not the pty slave".to_string());
                        }
                    }
                    Ok(())
                })();
                let _ = tx.send(r);
            });
        }
        drop(tx);
        for _ in 0..n_threads {
            let left = deadline.saturating_duration_since(Instant::now()) + Duration::from_secs(10);
            match rx.recv_timeout(left) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => panic!("churn thread failed: {e}"),
                Err(e) => panic!("churn thread did not finish within {CHURN_DEADLINE:?}: {e}"),
            }
        }
        let run = absorbed.load(std::sync::atomic::Ordering::Relaxed);
        eprintln!("MEASURED max consecutive transient failures before a success: {run}");
        // Headroom the run can violate: a call that needed all but one attempt
        // is one transient failure from failing a launch.
        assert!(
            run <= PTY_TRANSIENT_ATTEMPTS - 2,
            "run {run} leaves less than one spare attempt under the cap {PTY_TRANSIENT_ATTEMPTS}"
        );
    }

    /// The oracle for the `st_rdev` check in `open_tty`: a reopen that hands
    /// back a DIFFERENT terminal is refused and retried, then succeeds on the
    /// right one; a reopen that never returns the right one fails with the
    /// mismatch error after exactly the cap.
    #[test]
    fn open_tty_refuses_a_reopen_that_is_a_different_terminal_and_retries() {
        let a = Pty::open(None, None).expect("pty a");
        let b = Pty::open(None, None).expect("pty b");
        let (sa, sb) = (a.slave.as_raw_fd(), b.slave.as_raw_fd());
        let dup = |fd: RawFd| -> io::Result<OwnedFd> {
            // SAFETY: dup of a descriptor this test holds open.
            let n = unsafe { libc::dup(fd) };
            if n == -1 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: dup returned a fresh descriptor we now own.
            Ok(unsafe { OwnedFd::from_raw_fd(n) })
        };
        let mut calls = 0;
        let q = OutQueue::open_tty_via(sa, |_| {
            calls += 1;
            dup(if calls == 1 { sb } else { sa })
        })
        .expect("the second reopen is the right terminal");
        assert_eq!(
            calls, 2,
            "the wrong terminal was refused once, then retried"
        );
        assert_eq!(rdev_of(q.raw()), rdev_of(sa));

        let mut calls = 0;
        let err = match OutQueue::open_tty_via(sa, |_| {
            calls += 1;
            dup(sb)
        }) {
            Ok(_) => panic!("a reopen that is always another terminal must fail"),
            Err(e) => e,
        };
        assert_eq!(calls, PTY_TRANSIENT_ATTEMPTS);
        assert!(tty_mismatch(&err), "{err}");
    }

    fn rdev_of(fd: RawFd) -> libc::dev_t {
        // SAFETY: zeroed stat is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat on a descriptor the caller holds.
        assert_eq!(unsafe { libc::fstat(fd, &mut st) }, 0);
        st.st_rdev
    }

    /// RED for the rdev check: two different ptys are NOT the same tty, and
    /// the check says so with the retryable mismatch error.
    #[test]
    fn same_tty_rejects_a_different_terminal_and_accepts_the_same_one() {
        let a = Pty::open(None, None).expect("pty a");
        let b = Pty::open(None, None).expect("pty b");
        let (sa, sb) = (a.slave.as_raw_fd(), b.slave.as_raw_fd());
        assert_ne!(rdev_of(sa), rdev_of(sb), "two ptys have distinct rdev");
        let err = same_tty(sa, sb).expect_err("different terminals must be refused");
        assert!(tty_mismatch(&err), "{err}");
        assert!(same_tty(sa, sa).is_ok());
        let q = OutQueue::open_tty(sa).expect("reopen");
        assert!(same_tty(q.raw(), sa).is_ok());
        assert!(same_tty(q.raw(), sb).is_err());
        // A non-terminal descriptor (a regular file) is refused too.
        let f = std::fs::File::open("/dev/null").expect("null");
        let f2 = tempfile::tempfile().expect("tmp");
        assert!(same_tty(f.as_raw_fd(), f2.as_raw_fd()).is_err());
    }

    /// A deadline-bounded tick used between polls of an external condition;
    /// it orders nothing, it only spaces the samples.
    fn tick() {
        // SAFETY: poll with no descriptors is a timer.
        unsafe { libc::poll(std::ptr::null_mut(), 0, 100) };
    }

    /// The fifo a fixture publishes its pid on, and the test's read end of
    /// it. The write IS the readiness signal — an ORDERING one: it happens
    /// after the fixture's pid exists, so nothing samples a clock to decide
    /// whether a start succeeded. A `WAIT` deadline on a pid file was the
    /// opposite: it elapsed under load, and the failure it raised was
    /// indistinguishable from a start that had genuinely failed.
    ///
    /// The read end is opened before the fixture starts, so the fixture's
    /// `>` never waits on when this test reads, and the test holds the write
    /// end too, so a read can never come back an empty EOF that would have
    /// to be told apart from a slow start. [`HANG_GUARD`] bounds a fixture
    /// that genuinely hangs.
    struct PidFifo {
        path: PathBuf,
        fd: RawFd,
    }

    impl PidFifo {
        fn new(dir: &Path, name: &str) -> PidFifo {
            PidFifo::at(dir.join(name))
        }

        /// For a role that is handed the path (a fixture started by a helper
        /// process), rather than a directory to name the fifo in.
        fn at(path: PathBuf) -> PidFifo {
            let c = CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
            // SAFETY: a fresh path; the mode is a literal.
            let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
            assert_eq!(
                rc,
                0,
                "mkfifo {}: {}",
                path.display(),
                io::Error::last_os_error()
            );
            // SAFETY: the same path, just created. O_RDWR holds a writer open
            // for the fifo's lifetime, which both platforms accept and which
            // is what makes the read end see data or nothing, never an EOF.
            let fd = unsafe {
                libc::open(
                    c.as_ptr(),
                    libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            assert!(
                fd >= 0,
                "open {}: {}",
                path.display(),
                io::Error::last_os_error()
            );
            PidFifo { path, fd }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        /// The pid, by a blocking read that ends on the fixture's write.
        /// `what` names the fixture in every message, and each failure is
        /// reported as itself: a hang-guard expiry, a bad payload, or a read
        /// error is never mistaken for a forced exit.
        fn read_pid(&self, what: &str) -> libc::pid_t {
            let deadline = Instant::now() + HANG_GUARD;
            let mut line: Vec<u8> = Vec::new();
            while !line.contains(&b'\n') && line.len() < 32 {
                let left = deadline.saturating_duration_since(Instant::now());
                assert!(
                    !left.is_zero(),
                    "{what} never started: no pid on {} within the {HANG_GUARD:?} hang guard",
                    self.path.display()
                );
                let mut pfd = libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd; `poll` only reads it.
                let n = unsafe { libc::poll(&mut pfd, 1, left.as_millis().max(1) as libc::c_int) };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    panic!("poll {}: {err}", self.path.display());
                }
                if n == 0 {
                    continue; // the guard check at the loop top is the bound
                }
                let mut buf = [0u8; 32];
                // SAFETY: an open fd and a buffer of its own length.
                let got = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
                if got < 0 {
                    let err = io::Error::last_os_error();
                    if matches!(err.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                        continue;
                    }
                    panic!("read {}: {err}", self.path.display());
                }
                assert!(
                    got > 0,
                    "read {} came back EOF with the test's own writer held: not a fifo",
                    self.path.display()
                );
                line.extend_from_slice(&buf[..got as usize]);
            }
            let text = String::from_utf8_lossy(&line);
            text.trim().parse().unwrap_or_else(|e| {
                panic!(
                    "{what} published {text:?} on {} instead of a pid: {e}",
                    self.path.display()
                )
            })
        }
    }

    impl Drop for PidFifo {
        fn drop(&mut self) {
            // SAFETY: the fd came from `open` and nothing else closes it.
            unsafe { libc::close(self.fd) };
        }
    }

    /// A `catch_unwind` around a forced early exit returns `Err` for any
    /// panic — the fixture's failed start included. Checking only `is_err()`
    /// passed such a failure for the forced exit, and the test then failed on
    /// a later line, reporting a cause it did not have. This asserts the
    /// payload IS the forced exit, so any other unwind reds as itself.
    fn forced_early_exit(payload: Box<dyn std::any::Any + Send>) {
        let text = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str));
        assert_eq!(
            text,
            Some("forced early exit"),
            "the unwind was not the forced exit"
        );
    }

    #[test]
    fn a_stalled_terminal_does_not_block_signal_forwarding() {
        // Each loop records its progress in a file, so "the child stopped
        // advancing" (it is blocked writing) is observable without reading
        // the outer terminal.
        let flood = r#"P=$PPID; echo CHILD=$$; echo READY; while kill -0 $P 2>/dev/null; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; echo y >> "$TMPDIR/progress"; done"#;
        let mut o = Outer::start(flood, &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        // Stop reading the outer terminal and wait until the child has
        // stopped advancing: the relay's writes now have nowhere to go.
        let progress = o._home.path().join("progress");
        let size = || std::fs::metadata(&progress).map(|m| m.len()).unwrap_or(0);
        let deadline = Instant::now() + WAIT;
        let (mut last, mut same) = (0u64, 0);
        while same < 3 {
            assert!(Instant::now() < deadline, "the terminal never stalled");
            tick();
            let now = size();
            same = if now > 0 && now == last { same + 1 } else { 0 };
            last = now;
        }
        kill_pid(relay, libc::SIGTERM);
        let deadline = Instant::now() + WAIT;
        loop {
            // Gone, a zombie, or exiting ('E' on macOS: its exit waits for the
            // stalled terminal to drain, which only happens after the signal
            // was delivered). A child that never got the signal is running.
            let gone =
                ps_field(child, "state").is_none_or(|s| s.starts_with('Z') || s.contains('E'));
            if gone {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "SIGTERM was not forwarded while the terminal was stalled (relay {:?} {:?}, child {:?})",
                ps_field(relay, "state"),
                ps_field(relay, "wchan"),
                ps_field(child, "state"),
            );
            tick();
        }
    }

    #[test]
    fn a_terminating_signal_the_relay_does_not_forward_still_restores_the_terminal() {
        let mut o = Outer::start(
            "P=$PPID; echo READY; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done",
            &[],
        );
        let relay = o.relay_pid();
        o.wait_for("READY");
        assert!(o.is_raw_now());
        kill_pid(relay, libc::SIGVTALRM);
        assert_eq!(o.wait_value("R-SIG "), libc::SIGVTALRM.to_string());
        o.assert_restored("an unforwarded terminating signal");
    }

    #[test]
    fn sigusr1_is_forwarded_to_the_child_by_default() {
        let script = "P=$PPID; trap 'echo GOT-USR1' USR1; echo READY; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done";
        let mut o = Outer::start(script, &[]);
        let relay = o.relay_pid();
        o.wait_for("READY");
        kill_pid(relay, libc::SIGUSR1);
        o.wait_for("GOT-USR1");
    }

    #[test]
    fn relay_in_a_background_process_group_declines() {
        let mut o = Outer::start("echo READY", &[("CSQ_S1A_FG", "0")]);
        assert_eq!(o.wait_value("R-EXIT "), "42");
        o.assert_restored("a declined start");
    }

    #[test]
    fn relay_declines_when_stdout_or_stderr_is_not_a_tty() {
        let mut o = Outer::start("echo READY", &[("CSQ_S1A_REDIR", "stdout")]);
        assert_eq!(o.wait_value("R-EXIT "), "43");
        let mut o = Outer::start("echo READY", &[("CSQ_S1A_REDIR", "stderr")]);
        assert_eq!(o.wait_value("R-EXIT "), "44");
    }

    #[test]
    fn grandchild_holding_the_slave_does_not_block_exit() {
        // The sleeper ignores the hangup the session leader's exit sends, so
        // it really holds the slave open for the whole test. The parent waits
        // for it to have armed that trap, or the exit could hang it up first.
        let script = r#"echo CHILD=$$; (trap '' HUP; : > "$TMPDIR/armed"; exec /bin/sleep 300) & echo SLEEP=$!; until [ -e "$TMPDIR/armed" ]; do :; done; echo READY; exit 3"#;
        let mut o = Outer::start(script, &[]);
        let sleeper: libc::pid_t = o.wait_value("SLEEP=").parse().unwrap();
        assert_eq!(o.wait_value("R-EXIT "), "3");
        o.assert_restored("a drained exit");
        assert!(
            ps_field(sleeper, "command").is_some_and(|c| c.contains("sleep")),
            "the grandchild must still be alive, holding the slave"
        );
    }

    #[test]
    fn output_written_just_before_exit_is_drained() {
        let mut o = Outer::start("echo READY; printf TAIL-OK; exit 0", &[]);
        o.wait_for("TAIL-OK");
        assert_eq!(o.wait_value("R-EXIT "), "0");
    }

    fn nonblocking_pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: valid 2-element out array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe returned two fresh descriptors we now own.
        let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        set_nonblock(w.as_raw_fd()).unwrap();
        (r, w)
    }

    /// Run `drain_master` in a thread so a drain that does not end fails the
    /// test by deadline instead of hanging it.
    fn drain_with_deadline(master: RawFd, out: OutQueue, window: Duration) -> OutQueue {
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut out = out;
            let mut buf = [0u8; 64];
            drain_master(master, &mut out, window, &mut buf, &|| true);
            tx.send(out).unwrap();
        });
        let out = rx
            .recv_timeout(WAIT)
            .expect("drain must end by its window, not by EOF or a writable terminal");
        worker.join().unwrap();
        out
    }

    #[test]
    fn drain_is_bounded_when_a_holder_keeps_the_slave_open_and_forwards_data() {
        let pty = Pty::open(None, None).expect("pty");
        set_nonblock(pty.master.as_raw_fd()).unwrap();
        // The slave stays open for the whole drain: no EOF ever.
        write_fd(pty.slave.as_raw_fd(), b"left-over").unwrap();
        let (r, w) = nonblocking_pipe();
        let out = drain_with_deadline(
            pty.master.as_raw_fd(),
            OutQueue::over(w),
            Duration::from_millis(100),
        );
        drop(out);
        let mut got = [0u8; 64];
        let n = read_fd(r.as_raw_fd(), &mut got).unwrap();
        assert_eq!(&got[..n], b"left-over");
    }

    #[test]
    fn drain_is_bounded_when_the_terminal_stops_accepting_output() {
        let pty = Pty::open(None, None).expect("pty");
        set_nonblock(pty.master.as_raw_fd()).unwrap();
        let (_r, w) = nonblocking_pipe();
        // Fill the "terminal" until it refuses more; nobody ever reads it.
        let chunk = [b'x'; 4096];
        while write_fd(w.as_raw_fd(), &chunk).is_ok() {}
        write_fd(pty.slave.as_raw_fd(), b"more").unwrap();
        let out = drain_with_deadline(
            pty.master.as_raw_fd(),
            OutQueue::over(w),
            Duration::from_millis(100),
        );
        assert!(
            out.wants_write(),
            "output the terminal never took is discarded, not forced"
        );
    }

    fn spawn_group_leader(script: &str) -> std::process::Child {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd.spawn().expect("spawn")
    }

    #[test]
    fn terminate_child_ends_a_stopped_child_that_ignores_hangup() {
        let child =
            spawn_group_leader("P=$PPID; trap '' HUP TERM; kill -STOP $$; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done");
        let pid = child.id() as libc::pid_t;
        // Consume the stop report so the child is known to be stopped.
        let mut st: libc::c_int = 0;
        // SAFETY: valid out-pointer; the child is ours.
        assert_eq!(unsafe { libc::waitpid(pid, &mut st, libc::WUNTRACED) }, pid);
        assert!(libc::WIFSTOPPED(st));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            terminate_child(pid, Duration::from_millis(100));
            tx.send(()).unwrap();
        });
        rx.recv_timeout(WAIT)
            .expect("a stopped, hangup-ignoring child must still be ended");
        // It was reaped by terminate_child: the pid is no longer our child.
        // SAFETY: valid out-pointer.
        let r = unsafe { libc::waitpid(pid, &mut st, libc::WNOHANG) };
        assert_eq!(r, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        std::mem::forget(child);
    }

    #[test]
    fn terminate_child_leaves_a_process_group_it_does_not_own_alone() {
        // The sleeper leads its own process group (a stray `kill(-pid, ..)`
        // would reach it) but is the shell's child, not ours: terminate_child
        // must see ECHILD and signal nothing.
        let tmp = tempfile::tempdir().expect("tempdir");
        let fifo = PidFifo::new(tmp.path(), "sleeper");
        // The sleeper publishes its own pid AFTER `setpgrp`, so the read is
        // ordered by the group leadership this test needs established — not
        // by a sampled `ps` field the parent shell's `echo $!` cannot wait
        // for.
        let script = format!(
            "perl -e 'setpgrp(0,0); open(F,\">\",\"{}\") or die \"fifo\"; print F \"$$\\n\"; close F; exec \"sleep\",\"300\"' & wait",
            fifo.path().display()
        );
        let mut shell = spawn_group_leader(&script);
        let sleeper = fifo.read_pid("the sleeper");
        // The precondition itself, read once (no poll): leadership is what
        // the fifo write above was ordered after.
        assert_eq!(ps_field(sleeper, "pgid"), Some(sleeper.to_string()));
        assert_eq!(ps_field(sleeper, "ppid"), Some(shell.id().to_string()));
        terminate_child(sleeper, Duration::from_millis(100));
        let state = ps_field(sleeper, "state");
        // Bound to the shell as its parent (checked above), so this pid is ours to clean up.
        kill_pid(sleeper, libc::SIGKILL);
        let _ = shell.kill();
        let _ = shell.wait();
        assert!(
            state.is_some_and(|s| !s.starts_with('Z')),
            "a process group that is not ours must not be signalled"
        );
    }

    #[test]
    fn relay_error_says_whether_the_child_started() {
        let started = RelayError::ChildStarted {
            op: "poll",
            errno: 4,
        };
        let before = RelayError::NotStarted {
            op: "openpty",
            errno: 24,
        };
        assert!(started.child_started());
        assert!(!before.child_started());
        assert!(!RelayError::Busy.child_started());
        assert!(!RelayError::Declined(Decline::Background).child_started());
    }

    #[test]
    fn relay_debug_never_prints_argv_or_environment() {
        let spec = LaunchSpec::new("sh")
            .arg("SECRET-ARGV")
            .env("SECRET_ENV_NAME", "SECRET-ENV-VALUE");
        let shown = format!(
            "{:?} {:?}",
            Relay::new(spec.clone(), RelayConfig::default()),
            spec
        );
        assert!(!shown.contains("SECRET"), "Debug leaked: {shown}");
    }

    #[test]
    fn master_read_classification_treats_eio_as_eof() {
        let eio = Err(io::Error::from_raw_os_error(libc::EIO));
        assert_eq!(classify_master_read(eio), MasterRead::Eof);
        assert_eq!(classify_master_read(Ok(0)), MasterRead::Eof);
        assert_eq!(classify_master_read(Ok(5)), MasterRead::Data(5));
        let again = Err(io::Error::from_raw_os_error(libc::EAGAIN));
        assert_eq!(classify_master_read(again), MasterRead::Again);
        let bad = Err(io::Error::from_raw_os_error(libc::EBADF));
        assert_eq!(classify_master_read(bad), MasterRead::Failed(libc::EBADF));
    }

    #[test]
    fn relay_is_byte_transparent_in_both_directions() {
        // Raw slave: no line-discipline rewriting, so any difference is the
        // relay's. 256 output bytes, then 9 input bytes echoed by `dd`.
        let script = r#"stty raw -echo; printf BEGIN; i=0; while [ $i -lt 256 ]; do printf "\\$(printf %03o $i)"; i=$((i+1)); done; printf FIN; dd bs=1 count=9 2>/dev/null; printf END"#;
        let mut o = Outer::start(script, &[]);
        o.wait_for("BEGIN");
        let got = o.take_bytes(256);
        let want: Vec<u8> = (0..=255u8).collect();
        assert_eq!(got, want, "child output must arrive unchanged");
        o.wait_for("FIN");
        let input = [0x03, 0x1a, 0x00, 0x7f, 0xff, 0x1b, b'[', b'A', 0x0d];
        o.send(&input);
        assert_eq!(
            o.take_bytes(9),
            input,
            "terminal input must reach the child unchanged"
        );
        o.wait_for("END");
    }

    #[test]
    fn sigpipe_to_the_relay_is_ignored_and_not_forwarded() {
        let script = "stty raw -echo; echo READY; dd bs=1 count=2 2>/dev/null; printf DONE";
        let mut o = Outer::start(script, &[]);
        let relay = o.relay_pid();
        o.wait_for("READY");
        kill_pid(relay, libc::SIGPIPE);
        o.send(b"ab");
        o.wait_for("abDONE");
        assert_eq!(
            o.wait_value("R-EXIT "),
            "0",
            "relay and child must survive SIGPIPE"
        );
    }

    #[test]
    fn child_starts_with_default_dispositions_and_an_empty_mask() {
        let mut o = Outer::start("", &[("CSQ_S1A_CHILD", "probe"), ("CSQ_S1A_PRESET", "1")]);
        o.wait_for("F9 nondefault=[] blocked=0");
        assert_eq!(o.wait_value("R-EXIT "), "0");
    }

    #[test]
    fn child_sees_default_sigpipe() {
        let script = r#"( yes 2>/dev/null; echo "YESRC=$?" > "$TMPDIR/yesrc" ) | head -n 1 >/dev/null; cat "$TMPDIR/yesrc""#;
        let mut o = Outer::start(script, &[]);
        assert_eq!(o.wait_value("YESRC="), "141");
    }

    #[test]
    fn master_and_slave_are_close_on_exec() {
        let pty = Pty::open(None, None).expect("pty");
        for fd in [pty.master.as_raw_fd(), pty.slave.as_raw_fd()] {
            // SAFETY: fcntl on a descriptor we own.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_ne!(flags & libc::FD_CLOEXEC, 0);
        }
    }

    #[test]
    fn a_second_relay_in_one_process_is_refused() {
        let home = tempfile::tempdir().expect("tempdir");
        let status = helper_command("busy")
            .env("HOME", home.path())
            .env("TMPDIR", home.path())
            .status()
            .expect("spawn busy role");
        assert!(status.success(), "second guard must be Busy, then reusable");
    }

    // -- R2 fixes: kill path, suspended signals, liveness, LaunchSpec -------

    const WAITING_CLI: &str = "echo CHILD=$$; echo READY; read x; echo GOT-$x";

    /// A relay that is SIGKILLed while the CLI is stopped leaves nothing
    /// behind: the shim sees its control pipe close and ends the CLI's group.
    #[test]
    fn a_killed_relay_while_suspended_leaves_no_stopped_cli() {
        let mut o = Outer::start(WAITING_CLI, &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(&[0x1a]);
        o.wait_for("R-STOPPED");
        kill_pid(relay, libc::SIGKILL);
        assert!(wait_gone(child), "a stopped CLI outlived its killed relay");
    }

    #[test]
    fn a_killed_relay_while_running_leaves_no_headless_cli() {
        let mut o = Outer::start(WAITING_CLI, &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        kill_pid(relay, libc::SIGKILL);
        assert!(wait_gone(child), "a CLI outlived its killed relay");
    }

    /// `kill -INT` on a suspended relay is passed on; it does not end the
    /// session, and `fg` re-enters raw mode.
    #[test]
    fn a_non_terminating_signal_while_suspended_does_not_end_the_session() {
        let script = r#"P=$PPID; trap 'echo GOT-INT' INT; echo CHILD=$$; echo READY; read x; kill -TSTP $$; echo "CONT-SIZE=$(/bin/stty size)"; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;
        let mut o = Outer::start(script, &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        kill_pid(relay, libc::SIGINT);
        o.send(b"fg\n");
        o.wait_for("CONT-SIZE=");
        assert!(o.is_raw_now(), "fg must re-enter raw mode after a signal");
        tick();
        tick();
        assert!(
            !proc_state(child).is_empty(),
            "the session must not have been ended"
        );
    }

    /// An outside `SIGTSTP` stops the relay like a job and `fg` carries on.
    #[test]
    fn an_external_sigtstp_stops_the_relay_like_a_job() {
        let mut o = Outer::start("echo READY; read x; echo GOT-$x", &[]);
        let relay = o.relay_pid();
        o.wait_for("READY");
        kill_pid(relay, libc::SIGTSTP);
        o.wait_for("R-STOPPED");
        o.assert_restored("an outside SIGTSTP");
        o.send(b"fg\n");
        o.send(b"q\n");
        o.wait_for("GOT-q");
        assert_eq!(o.wait_value("R-EXIT "), "0");
    }

    /// Only the relay may ask the shim to kill the CLI.
    #[test]
    fn a_stray_sigurg_does_not_kill_the_cli() {
        let script = "echo SHIM=$PPID; echo READY; while ! read x; do :; done; echo DONE-$x";
        let mut o = Outer::start(script, &[]);
        let shim: libc::pid_t = o.wait_value("SHIM=").parse().unwrap();
        o.wait_for("READY");
        kill_pid(shim, libc::SIGURG);
        tick();
        o.send(b"q\n");
        o.wait_for("DONE-q");
    }

    /// A stray default-terminating signal reaches the CLI; it does not kill
    /// the shim and leave the CLI running unwatched.
    #[test]
    fn a_stray_terminating_signal_to_the_shim_is_forwarded_to_the_cli() {
        let script = format!(
            "trap 'echo GOT-PROF' {}; echo SHIM=$PPID; echo READY; while ! read x; do :; done; echo DONE-$x",
            libc::SIGPROF
        );
        let mut o = Outer::start(&script, &[]);
        let shim: libc::pid_t = o.wait_value("SHIM=").parse().unwrap();
        o.wait_for("READY");
        kill_pid(shim, libc::SIGPROF);
        o.wait_for("GOT-PROF");
        o.send(b"q\n");
        o.wait_for("DONE-q");
        assert_eq!(o.wait_value("R-EXIT "), "0");
    }

    /// Descriptors other than the terminal never reach the CLI.
    #[test]
    fn the_cli_inherits_no_descriptor_but_the_terminal() {
        let mut o = Outer::start(
            "[ -e /dev/fd/200 ] && echo LEAK || echo CLEAN",
            &[("CSQ_S1A_FD200", "1")],
        );
        o.wait_for("CLEAN");
    }

    /// Raise this process's soft `RLIMIT_NOFILE` to `want` (within the hard
    /// limit): macOS starts a test process at 256, below the descriptor
    /// numbers these tests need to open first.
    ///
    /// # Safety
    /// Plain rlimit syscalls on this process.
    unsafe fn raise_soft_nofile(want: libc::rlim_t) {
        let mut lim: libc::rlimit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim), 0);
        if lim.rlim_cur < want {
            lim.rlim_cur = want.min(lim.rlim_max);
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &lim), 0);
        }
    }

    /// The same for a descriptor above a soft limit lowered after it was
    /// opened. On macOS this is the fallback close loop (there is no
    /// `close_range`), whose limits alone stop below it.
    #[test]
    fn the_cli_inherits_no_descriptor_above_a_lowered_soft_limit() {
        let mut o = Outer::start(
            "[ -e /dev/fd/300 ] && echo LEAK || echo CLEAN",
            &[("CSQ_S1A_FDHIGH", "1")],
        );
        o.wait_for("CLEAN");
    }

    /// The fallback close loop on every OS (Linux takes `close_range` first, so
    /// the relay-level test above cannot reach it there): with BOTH limits
    /// lowered under an open descriptor, only the ceiling taken before the
    /// fork reaches it.
    #[test]
    fn the_fallback_close_loop_reaches_a_descriptor_above_both_limits() {
        // SAFETY: a plain rlimit call, then duplicating a descriptor we own.
        let high = unsafe {
            raise_soft_nofile(1024);
            libc::fcntl(0, libc::F_DUPFD, 300)
        };
        assert_ne!(high, -1, "dup");
        // Not inherited by the other tests' children (the judge only forks).
        // SAFETY: fcntl on the descriptor just made.
        assert_ne!(
            unsafe { libc::fcntl(high, libc::F_SETFD, libc::FD_CLOEXEC) },
            -1
        );
        let ceiling = open_fd_ceiling();
        assert!(
            ceiling > 300,
            "the listing missed descriptor 300: {ceiling}"
        );
        // SAFETY: the forked judge uses only async-signal-safe calls and ends
        // with `_exit`; the limits it lowers are its own.
        let judge = unsafe { libc::fork() };
        assert!(judge >= 0, "fork");
        if judge == 0 {
            // SAFETY: as above.
            unsafe {
                let lim = libc::rlimit {
                    rlim_cur: 64,
                    rlim_max: 64,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                    libc::_exit(10);
                }
                close_by_scan(100, ceiling);
                let still_open = libc::fcntl(high, libc::F_GETFD) != -1;
                libc::_exit(if still_open { 1 } else { 0 });
            }
        }
        let mut st: libc::c_int = 0;
        // SAFETY: valid out-pointer; `judge` is our child.
        assert_eq!(unsafe { libc::waitpid(judge, &mut st, 0) }, judge);
        // SAFETY: closing the descriptor duplicated above.
        unsafe { libc::close(high) };
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "judge status {st:#x} (exit 1: descriptor 300 survived the loop)"
        );
    }

    /// The CLI gets exactly the environment the spec carries.
    #[test]
    fn a_caller_stripped_environment_variable_does_not_reach_the_cli() {
        let mut o = Outer::start(
            "",
            &[
                ("CSQ_S1A_CHILD", "env"),
                ("CSQ_S1A_SECRET_MARKER", "SECRET-IN-RELAY-ENV"),
            ],
        );
        o.wait_for("ONLY=1");
        assert_eq!(o.wait_value("R-EXIT "), "0");
        let seen = String::from_utf8_lossy(&o.acc).to_string();
        assert!(!seen.contains("SECRET-IN-RELAY-ENV"), "leaked: {seen:?}");
        assert!(!seen.contains("CSQ_S1A_SECRET_MARKER"), "leaked: {seen:?}");
    }

    #[test]
    fn the_plan_carries_exactly_the_spec() {
        let spec = LaunchSpec::new("env")
            .arg0("custom0")
            .arg("x")
            .env("A", "1");
        let plan = shim_plan(&spec, -1, -1, -1, -1).expect("plan");
        let strs = |v: &[*const libc::c_char]| -> Vec<String> {
            v.iter()
                .take_while(|p| !p.is_null())
                // SAFETY: the pointers borrow the plan's live CStrings.
                .map(|&p| unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into())
                .collect()
        };
        assert_eq!(strs(&plan.argv), ["custom0", "x"]);
        assert_eq!(strs(&plan.envp), ["A=1"]);
        assert!(plan.program.to_string_lossy().ends_with("/env"));
    }

    #[test]
    fn a_spec_the_shim_cannot_represent_is_refused_with_a_fixed_error() {
        let refused = |spec: LaunchSpec| {
            Relay::new(spec, RelayConfig::default()).expect_err("must be refused")
        };
        let want = RelayError::NotStarted {
            op: "launch_spec",
            errno: libc::EINVAL,
        };
        assert_eq!(refused(LaunchSpec::new("sh").arg("a\0b")), want);
        assert_eq!(refused(LaunchSpec::new("sh").env("A=B", "1")), want);
        assert_eq!(refused(LaunchSpec::new("sh").env("", "1")), want);
        assert_eq!(refused(LaunchSpec::new("")), want);
        assert!(Relay::new(LaunchSpec::new("sh"), RelayConfig::default()).is_ok());
    }

    /// `PATH` entries that are not absolute are never searched (they would
    /// resolve against the relay's directory, not the CLI's).
    #[test]
    fn a_relative_path_entry_is_never_searched() {
        use std::os::unix::fs::PermissionsExt;
        let name = format!(".s1a-path-probe-{}", std::process::id());
        std::fs::write(&name, b"#!/bin/sh\n").expect("write probe");
        std::fs::set_permissions(&name, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let spec = LaunchSpec::new(name.as_str()).env("PATH", ".:");
        let found = resolve_program(&spec);
        std::fs::remove_file(&name).expect("remove probe");
        assert_eq!(
            found.err().and_then(|e| e.raw_os_error()),
            Some(libc::ENOENT),
            "a relative PATH entry was searched"
        );
    }

    /// An `exec` that fails comes back as an error with the CLI never run.
    #[test]
    fn an_exec_failure_is_reported_and_the_cli_never_runs() {
        let pty = Pty::open(None, None).expect("pty");
        // Not executable: execve fails with EACCES inside the shim's child.
        let spec = LaunchSpec::new("/etc/passwd");
        let err = spawn_on_slave(&spec, pty.slave).err().expect("must fail");
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    /// Unprivileged branch of the privilege drop: a relay that cannot clear its
    /// supplementary groups (`setgroups` needs root) fails the launch with
    /// `EPERM` and the CLI never runs as the caller (a skipped `setgroups`, or
    /// an ignored failure, would start it with the caller's groups). Even a
    /// drop to the caller's own ids must clear the groups first.
    #[test]
    fn the_privilege_drop_refuses_the_launch_without_root() {
        // SAFETY: plain getters.
        let (euid, uid, gid) = unsafe { (libc::geteuid(), libc::getuid(), libc::getgid()) };
        if euid == 0 {
            println!("SKIPPED the unprivileged branch: euid is 0 (the root branch runs instead)");
            return;
        }
        println!("RAN the unprivileged privilege-drop branch (euid={euid}); the ROOT branch is SKIPPED here");
        let pty = Pty::open(None, None).expect("pty");
        let spec = LaunchSpec::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .uid(uid)
            .gid(gid);
        let err = spawn_on_slave(&spec, pty.slave).err().expect("must fail");
        assert_eq!(err.raw_os_error(), Some(libc::EPERM), "unprivileged drop");
        assert_eq!(err.drop_step, Some("setgroups"), "tagged as a drop step");
    }

    /// Root branch of the privilege drop: the CLI is exactly the requested uid
    /// and gid with no supplementary groups. It runs only as euid 0; anywhere
    /// else it prints a visible `SKIPPED` marker (the capability gate precedes
    /// the call, per the test-skip discipline) and the handback records the
    /// branch as UNMATCHED.
    #[test]
    fn the_privilege_drop_root_branch_sets_exact_ids_and_no_groups() {
        // SAFETY: plain getter.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            println!("SKIPPED the root branch of the privilege drop: euid={euid}, needs 0");
            return;
        }
        println!("RAN the root branch of the privilege drop (euid=0)");
        let pty = Pty::open(None, None).expect("pty");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(
            dir.path(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o777),
        )
        .expect("chmod");
        let out = dir.path().join("ids");
        // Every id slot and every capability set, not only the effective ids
        // `id` prints: a saved uid of 0 or a kept capability must show.
        #[cfg(target_os = "linux")]
        let body = "grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapAmb):' /proc/self/status";
        #[cfg(not(target_os = "linux"))]
        let body = "id -u; id -g; id -G; id -ru; id -rg";
        let script = format!(
            "{{ {body}; echo DONE; }} > {} 2>&1",
            out.to_str().expect("utf8")
        );
        let spec = LaunchSpec::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .uid(65534)
            .gid(65534);
        let _sp = spawn_on_slave(&spec, pty.slave).expect("privileged drop");
        let deadline = Instant::now() + WAIT;
        let text = loop {
            let t = std::fs::read_to_string(&out).unwrap_or_default();
            if t.lines().any(|l| l == "DONE") {
                break t;
            }
            assert!(Instant::now() < deadline, "the CLI wrote no ids: {t:?}");
            tick();
        };
        let lines: Vec<&str> = text.lines().filter(|l| *l != "DONE").collect();
        #[cfg(target_os = "linux")]
        {
            let squeeze = |l: &&str| l.split_whitespace().collect::<Vec<_>>().join(" ");
            let got: Vec<String> = lines.iter().map(squeeze).collect();
            assert_eq!(
                got,
                [
                    "Uid: 65534 65534 65534 65534",
                    "Gid: 65534 65534 65534 65534",
                    "Groups:",
                    "CapInh: 0000000000000000",
                    "CapPrm: 0000000000000000",
                    "CapEff: 0000000000000000",
                    "CapAmb: 0000000000000000",
                ]
            );
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(lines, ["65534", "65534", "65534", "65534", "65534"]);
    }

    /// The liveness pipe, with the terminal still open (so no hangup helps):
    /// when the relay's control pipe closes, the shim ends the CLI's group.
    #[test]
    fn the_shim_ends_a_running_cli_when_the_control_pipe_closes() {
        shim_ends_cli_after_control_close(false, false);
    }

    #[test]
    fn the_shim_ends_a_stopped_cli_when_the_control_pipe_closes() {
        shim_ends_cli_after_control_close(true, false);
    }

    /// The 2000 ms SIGKILL: a CLI that ignores HUP and TERM is still ended.
    #[test]
    fn the_shim_kills_a_cli_that_ignores_hup_and_term_after_the_grace() {
        shim_ends_cli_after_control_close(false, true);
    }

    fn shim_ends_cli_after_control_close(stopped: bool, trapping: bool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = PidFifo::new(dir.path(), "cli.pid");
        let script = match (stopped, trapping) {
            (true, _) => {
                r#"P=$PPID; echo $$ > "$S1A_PIDFILE"; kill -TSTP $$; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#
            }
            (false, false) => {
                r#"P=$PPID; echo $$ > "$S1A_PIDFILE"; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#
            }
            (false, true) => {
                r#"P=$PPID; trap '' HUP TERM; echo $$ > "$S1A_PIDFILE"; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#
            }
        };
        let spec = LaunchSpec::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .inherit_env()
            .env("S1A_PIDFILE", fifo.path().as_os_str());
        let pty = Pty::open(None, None).expect("pty");
        // The master stays open for the whole test: nothing hangs up.
        let _master = pty.master;
        let sp = spawn_on_slave(&spec, pty.slave).expect("spawn");
        let cli = fifo.read_pid("the CLI");
        if stopped {
            // Its own budget: readiness is no longer measured against it.
            let deadline = Instant::now() + WAIT;
            while !proc_state(cli).starts_with('T') {
                assert!(Instant::now() < deadline, "the CLI never stopped");
                tick();
            }
        }
        let Spawned { pid, ctl, up } = sp;
        // The relay "dies": its control pipe closes, nothing else changes.
        drop(ctl);
        let gone = wait_gone(cli);
        if !gone {
            // Still there, so the pid is still this CLI (never a reused one).
            kill_pid(cli, libc::SIGKILL);
        }
        terminate_child(pid, Duration::from_millis(100));
        drop(up);
        assert!(
            gone,
            "the CLI outlived its relay (stopped: {stopped}, trapping: {trapping})"
        );
    }

    /// The kill path: a CLI that traps HUP and TERM and stops itself again on
    /// every continue is ended by `terminate_child`, not only the shim.
    #[test]
    fn terminate_child_ends_a_trapping_cli_that_keeps_stopping() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = PidFifo::new(dir.path(), "cli.pid");
        let script = r#"P=$PPID; trap '' HUP TERM; echo $$ > "$S1A_PIDFILE"; while kill -0 $P 2>/dev/null; do kill -TSTP $$; done"#;
        let spec = LaunchSpec::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .inherit_env()
            .env("S1A_PIDFILE", fifo.path().as_os_str());
        let pty = Pty::open(None, None).expect("pty");
        let _master = pty.master;
        let sp = spawn_on_slave(&spec, pty.slave).expect("spawn");
        let cli = fifo.read_pid("the CLI");
        // Its own budget: readiness is no longer measured against it.
        let deadline = Instant::now() + WAIT;
        while !proc_state(cli).starts_with('T') {
            assert!(Instant::now() < deadline, "the CLI never stopped");
            tick();
        }
        // `sp` (its control pipe) stays open: only the signal path may end it.
        terminate_child(sp.pid, Duration::from_millis(100));
        let gone = wait_gone(cli);
        if !gone {
            kill_pid(cli, libc::SIGKILL);
        }
        drop(sp);
        assert!(gone, "the CLI outlived terminate_child");
    }

    // -- R3 fixes: persistent ending, TTIN/TTOU, stale S, core dumps -------

    /// A CLI that traps TERM: ^Z, `kill -TERM` the relay, `fg`. The session is
    /// ending, so the relay neither stops again nor re-enters raw mode; the CLI
    /// is ended after the grace, and the terminal is sane.
    #[test]
    fn a_trapped_term_while_suspended_ends_the_session_after_the_grace() {
        let script = r#"P=$PPID; trap 'echo GOT-TERM' TERM; echo CHILD=$$; echo READY; read x; kill -TSTP $$; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;
        let mut o = Outer::start(script, &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        kill_pid(relay, libc::SIGTERM);
        o.send(b"fg\n");
        assert_eq!(o.wait_value("R-SIG "), "15");
        assert!(wait_gone(child), "the CLI outlived the ended session");
        o.assert_restored("an ended session");
    }

    /// A CLI that ignores HUP and stops itself again on every continue, then
    /// the tab closes: nothing may stay parked.
    #[test]
    fn a_closed_terminal_with_a_hup_ignoring_cli_leaves_nothing_parked() {
        let script = r#"P=$PPID; trap '' HUP TERM; echo CHILD=$$; echo READY; read x || exit 0; while kill -0 $P 2>/dev/null; do kill -TSTP $$; done"#;
        let mut o = Outer::start(script, &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        o.hang_up();
        assert!(wait_gone(child), "the CLI stayed parked");
        assert!(wait_gone(relay), "the relay stayed parked");
    }

    // -- R5: the session ends in EVERY state ---------------------------

    /// A CLI that ignores HUP and TERM and runs for as long as its parent does.
    const IGNORING_CLI: &str = r#"P=$PPID; trap '' HUP TERM; echo CHILD=$$; echo READY; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;

    /// `sig` sent to a RUNNING relay (never suspended) whose CLI ignores it
    /// ends the CLI after the grace: the relay does not park behind it.
    fn a_running_relay_ends_an_ignoring_cli_on(sig: libc::c_int) {
        let mut o = Outer::start(IGNORING_CLI, &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        kill_pid(relay, sig);
        assert_eq!(o.wait_value("R-SIG "), sig.to_string());
        assert!(wait_gone(child), "the CLI outlived the ended session");
        o.assert_restored("a signal to a running relay");
    }

    #[test]
    fn sigterm_to_a_running_relay_ends_a_cli_that_ignores_it() {
        a_running_relay_ends_an_ignoring_cli_on(libc::SIGTERM);
    }

    #[test]
    fn sighup_to_a_running_relay_ends_a_cli_that_ignores_it() {
        a_running_relay_ends_an_ignoring_cli_on(libc::SIGHUP);
    }

    /// The terminal closes while the CLI runs and ignores HUP. The shell
    /// survives the hangup (no `SIGHUP` reaches the relay), so only the relay's
    /// own check of its terminal can end the session.
    #[test]
    fn a_lost_terminal_while_running_ends_a_cli_that_ignores_hup() {
        let mut o = Outer::start(IGNORING_CLI, &[("CSQ_S1A_SHELL_IGNORE_HUP", "1")]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.hang_up();
        assert!(wait_gone(child), "the CLI stayed parked");
        assert!(wait_gone(relay), "the relay stayed parked");
    }

    /// The same, with the leader dying of the hangup as a login shell does.
    #[test]
    fn a_closed_tab_while_running_ends_a_cli_that_ignores_hup() {
        let mut o = Outer::start(IGNORING_CLI, &[]);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.hang_up();
        assert!(wait_gone(child), "the CLI stayed parked");
        assert!(wait_gone(relay), "the relay stayed parked");
    }

    /// `stty tostop`, `^Z`, `bg`, `kill %1`: the relay ends up in the
    /// background, ending, while the CLI answers the TERM with output. The
    /// write to the terminal from the background raises `SIGTTOU`; it must not
    /// spin the relay inside the write (where the ending grace never runs).
    #[test]
    fn output_under_tostop_in_the_background_does_not_stall_the_ending_grace() {
        let script = r#"P=$PPID; trap 'echo GOT-TERM' TERM; echo CHILD=$$; echo READY; read x; kill -TSTP $$; while kill -0 $P 2>/dev/null; do /bin/sleep 1; done"#;
        let mut o = Outer::start_with(script, &[], true);
        let relay = o.relay_pid();
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        o.send(b"bg\n");
        o.wait_for("R-STOPPED");
        kill_pid(relay, libc::SIGTERM);
        kill_pid(relay, libc::SIGCONT);
        // The shell role is parked reading a command; any line sends it back
        // to waiting on the relay.
        o.send(b"x\n");
        assert_eq!(o.wait_value("R-SIG "), "15");
        assert!(wait_gone(child), "the CLI outlived the ended session");
    }

    /// An ending relay whose terminal is cooked (it stopped, and `kill -TERM`
    /// plus `fg` ended the session) forwards no typed input: the outer line
    /// discipline echoes it, and the CLI may be a prompt that echoes nothing.
    /// Judged at the end of the session: input forwarded at any point before
    /// it would have been echoed by the CLI by then.
    #[test]
    fn an_ending_relay_with_a_cooked_terminal_forwards_no_input() {
        let script = r#"P=$PPID; trap 'echo GOT-TERM' TERM; echo CHILD=$$; echo READY; read x; kill -TSTP $$; read y; echo GOT-$y; /bin/sleep 30"#;
        let mut o = Outer::start(script, &[]);
        let relay = o.relay_pid();
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        kill_pid(relay, libc::SIGTERM);
        o.send(b"fg\n");
        // The shell hands the terminal back before it continues the relay.
        let deadline = Instant::now() + WAIT;
        // SAFETY: tcgetpgrp only reads the outer terminal's state.
        while unsafe { libc::tcgetpgrp(o.master.as_raw_fd()) } != relay {
            assert!(
                Instant::now() < deadline,
                "the relay never got the terminal"
            );
            tick();
        }
        o.send(b"ZZZ\n");
        assert_eq!(o.wait_value("R-SIG "), "15");
        let seen = String::from_utf8_lossy(&o.acc).to_string();
        assert!(!seen.contains("GOT-ZZZ"), "input reached the CLI: {seen:?}");
    }

    /// `end_child` hands back the status of a child that had already ended by
    /// itself (reaping it here must not lose it), and nothing for one it had to
    /// end.
    #[test]
    fn end_child_keeps_the_status_of_a_child_that_ended_by_itself() {
        let reap_pending = |pid: libc::pid_t| {
            // SAFETY: waitid with WNOWAIT leaves the zombie for `end_child`.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            assert_eq!(rc, 0, "waitid");
        };
        let mut exited = Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", scratch_home())
            .spawn()
            .expect("sh");
        let pid = exited.id() as libc::pid_t;
        reap_pending(pid);
        assert_eq!(
            end_child(pid, Duration::from_millis(100)),
            Some(RelayExit::Exited(7))
        );
        assert!(exited.wait().is_err(), "end_child must have reaped it");
        let mut signalled = Command::new("/bin/sh")
            .args(["-c", "kill -TERM $$"])
            .spawn()
            .expect("sh");
        let pid = signalled.id() as libc::pid_t;
        reap_pending(pid);
        assert_eq!(
            end_child(pid, Duration::from_millis(100)),
            Some(RelayExit::Signaled(libc::SIGTERM))
        );
        assert!(signalled.wait().is_err(), "end_child must have reaped it");
        let mut running = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("sleep");
        assert_eq!(
            end_child(running.id() as libc::pid_t, Duration::from_millis(100)),
            None,
            "a child this call had to end has no status of its own"
        );
        assert!(running.wait().is_err(), "end_child must have reaped it");
    }

    fn external_stop_signal_restores_the_terminal(sig: libc::c_int) {
        let mut o = Outer::start("echo READY; read x; echo GOT-$x", &[]);
        let relay = o.relay_pid();
        o.wait_for("READY");
        kill_pid(relay, sig);
        o.wait_for("R-STOPPED");
        o.assert_restored("an outside terminal-access signal");
        o.send(b"fg\n");
        o.send(b"q\n");
        o.wait_for("GOT-q");
        assert_eq!(o.wait_value("R-EXIT "), "0");
    }

    #[test]
    fn an_external_sigttin_restores_the_terminal_and_stops_the_relay() {
        external_stop_signal_restores_the_terminal(libc::SIGTTIN);
    }

    #[test]
    fn an_external_sigttou_restores_the_terminal_and_stops_the_relay() {
        external_stop_signal_restores_the_terminal(libc::SIGTTOU);
    }

    /// An outside SIGCONT lets the stopped CLI run in the background, where it
    /// stops again at its first terminal read and the shim queues a second
    /// `S`. After `fg` that stale report must not stop the relay again.
    #[test]
    fn a_stale_stop_report_does_not_stop_the_relay_again_after_fg() {
        let script = "echo CHILD=$$; echo READY; read x; kill -TSTP $$; read y; echo GOT-$y";
        let mut o = Outer::start(script, &[]);
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        kill_pid(child, libc::SIGCONT);
        // The CLI is now stopped again by its background read: wait for it.
        let deadline = Instant::now() + WAIT;
        while !proc_state(child).starts_with('T') {
            assert!(Instant::now() < deadline, "the CLI never re-stopped");
            tick();
        }
        o.send(b"fg\n");
        tick();
        tick();
        o.send(b"q\n");
        o.wait_for("GOT-q");
        let stops = String::from_utf8_lossy(&o.acc).matches("R-STOPPED").count();
        assert_eq!(stops, 1, "a stale S stopped the relay a second time");
    }

    // -- LaunchSpec -----------------------------------------------------

    /// A report stamped before the latest `R` is stale; one stamped after it
    /// is current. This is the relay's side of the race where an outside
    /// `SIGCONT` lets the CLI stop again between the relay's drain and the
    /// shim's read of `R`.
    #[test]
    fn a_stop_report_older_than_the_latest_resume_is_dropped() {
        // Nothing resumed yet: the shim's first report is current.
        assert!(holds_current_stop(&[stop_report(0)], 0));
        // The relay has sent one `R` since the shim wrote this report.
        assert!(!holds_current_stop(&[stop_report(0)], 1));
        // The shim read that `R` and the CLI stopped again: current.
        assert!(holds_current_stop(&[stop_report(1)], 1));
        // A stale and a current report in one read: the current one counts.
        assert!(holds_current_stop(&[stop_report(0), stop_report(1)], 1));
        // The counter wraps at 128 on both sides.
        assert!(holds_current_stop(&[stop_report(130)], 2));
        assert!(!holds_current_stop(&[stop_report(129)], 2));
        // Bytes that are not stop reports never count.
        assert!(!holds_current_stop(b"S", 0));
        assert!(!holds_current_stop(&[], 0));
    }

    /// Every stop after an `R` is reported with the count the relay expects:
    /// a CLI that stops itself twice suspends the relay twice.
    /// The window `drain_up` does not close: the CLI stops again after the
    /// relay drained the shim's reports but before the shim reads the `R`.
    /// The seam continues the CLI at exactly that point and waits for its new
    /// report, so the stale report is in the up pipe when the relay goes on.
    /// The relay must NOT stop again for it (the CLI is running after the
    /// `R`); with the stop accepted, a second `R-STOPPED` appears and the
    /// typed line never reaches the CLI.
    #[test]
    fn a_stop_that_the_resume_undid_does_not_stop_the_relay_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("cli.pid");
        let script = "echo $$ > \"$CSQ_S1A_STALE_PIDFILE\"; echo READY; read x; kill -TSTP $$; read y; echo GOT-$y";
        let mut o = Outer::start(
            script,
            &[("CSQ_S1A_STALE_PIDFILE", pidfile.to_str().expect("utf8"))],
        );
        o.wait_for("READY");
        o.send(b"z\n");
        o.wait_for("R-STOPPED");
        o.send(b"fg\n");
        // Let the relay resume, run the seam and settle: a second stop would
        // have been printed by now.
        tick();
        tick();
        tick();
        o.send(b"q\n");
        o.wait_for("GOT-q");
        let stops = String::from_utf8_lossy(&o.acc).matches("R-STOPPED").count();
        assert_eq!(stops, 1, "a stale stop report stopped the relay again");
    }

    #[test]
    fn a_second_stop_after_fg_suspends_the_relay_again() {
        let script =
            "echo READY; read x; kill -TSTP $$; read y; kill -TSTP $$; read z; echo GOT-$z";
        let mut o = Outer::start(script, &[]);
        o.wait_for("READY");
        o.send(b"1\n");
        o.wait_for("R-STOPPED");
        o.send(b"fg\n");
        o.send(b"2\n");
        // The second genuine stop must reach the outer shell.
        o.wait_for("R-STOPPED");
        o.assert_restored("a second stop");
        o.send(b"fg\n");
        o.send(b"3\n");
        o.wait_for("GOT-3");
    }

    #[test]
    fn inherit_env_is_order_independent() {
        let has = |s: &LaunchSpec, k: &str| s.env.get(OsStr::new(k)).cloned();
        // PATH is set in every test process.
        let removed_first = LaunchSpec::new("x").env_remove("PATH").inherit_env();
        let removed_last = LaunchSpec::new("x").inherit_env().env_remove("PATH");
        assert_eq!(
            has(&removed_first, "PATH"),
            None,
            "a removed name came back"
        );
        assert_eq!(has(&removed_last, "PATH"), None);
        let set_first = LaunchSpec::new("x").env("PATH", "/explicit").inherit_env();
        let set_last = LaunchSpec::new("x").inherit_env().env("PATH", "/explicit");
        assert_eq!(has(&set_first, "PATH"), Some("/explicit".into()));
        assert_eq!(has(&set_last, "PATH"), Some("/explicit".into()));
        // A later `env` after a removal sets it again.
        let back = LaunchSpec::new("x")
            .env_remove("PATH")
            .env("PATH", "/p")
            .inherit_env();
        assert_eq!(has(&back, "PATH"), Some("/p".into()));
    }

    #[test]
    fn a_user_id_without_a_group_id_is_refused() {
        let cfg = RelayConfig::default;
        let want = RelayError::NotStarted {
            op: "launch_spec",
            errno: libc::EINVAL,
        };
        assert_eq!(
            Relay::new(LaunchSpec::new("sh").uid(1000), cfg()).expect_err("refused"),
            want
        );
        assert!(Relay::new(LaunchSpec::new("sh").uid(1000).gid(1000), cfg()).is_ok());
    }

    // -- shim handlers (called directly) ---------------------------------

    fn fake_info(code: libc::c_int, pid: libc::pid_t) -> libc::siginfo_t {
        // SAFETY: an all-zero siginfo_t is valid.
        let mut i: libc::siginfo_t = unsafe { std::mem::zeroed() };
        i.si_code = code;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        // SAFETY: si_pid sits after three ints, padded to the union's
        // alignment, inside the zeroed struct.
        unsafe {
            let a = std::mem::align_of::<usize>();
            let off = (3 * std::mem::size_of::<libc::c_int>()).div_ceil(a) * a;
            *((&mut i as *mut libc::siginfo_t as *mut u8).add(off) as *mut libc::pid_t) = pid;
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            i.si_pid = pid;
        }
        i
    }

    /// `si_code` of a plain `kill(2)` as the tests fake it. Linux's `SI_USER`
    /// is 0 by ABI; macOS's value is not consulted by `shim_kill`, so any value
    /// stands in there.
    const KILL_CODE: libc::c_int = 0;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const _: () = assert!(KILL_CODE == libc::SI_USER);

    /// The shim's handlers read process-wide statics (`SHIM_CLI`). Tests that
    /// store to them and then send real signals hold this lock for their whole
    /// body; under in-process parallel libtest, two of them otherwise signal
    /// each other's `sleep` or zero each other's group.
    static SHIM_STATICS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn shim_statics() -> std::sync::MutexGuard<'static, ()> {
        // A failed test poisons the lock; the next one must still run.
        SHIM_STATICS.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `shim_kill` honours only a genuine `kill(2)` from the parent.
    #[test]
    fn shim_kill_needs_a_genuine_kill_from_the_parent() {
        let _statics = shim_statics();
        let spawn = || {
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
                .expect("sleep")
        };
        let ppid = unsafe { libc::getppid() };
        let survives = |code: libc::c_int, pid: libc::pid_t| {
            let mut child = spawn();
            SHIM_CLI.store(child.id() as libc::pid_t, Ordering::Release);
            let mut info = fake_info(code, pid);
            shim_kill(libc::SIGURG, &mut info, std::ptr::null_mut());
            SHIM_CLI.store(0, Ordering::Release);
            tick();
            let alive = matches!(child.try_wait(), Ok(None));
            let _ = child.kill();
            let _ = child.wait();
            alive
        };
        assert!(survives(KILL_CODE, ppid + 1), "a stranger killed the CLI");
        // Only Linux can queue a signal that names another sender.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert!(
            survives(-1, ppid),
            "a queued signal (SI_QUEUE) killed the CLI"
        );
        assert!(
            !survives(KILL_CODE, ppid),
            "the parent's kill(2) was ignored"
        );
    }

    extern "C" fn exit_zero(_sig: libc::c_int) {
        // SAFETY: _exit is async-signal-safe.
        unsafe { libc::_exit(0) }
    }

    /// The shim's forwarded `SIGHUP`/`SIGTERM` hands the terminal to the CLI
    /// before continuing it; when that fails (the PTY hung up because the relay
    /// died) the CLI must still be continued so it can act on the signal, and
    /// must NOT be killed on the spot, which skipped the whole grace. A
    /// stopped CLI makes the outcome causal rather than a race: the pending
    /// `SIGHUP` runs its handler (exit 0) only if it is continued, and
    /// `SIGKILL` takes it whether or not it is stopped.
    #[test]
    fn a_failed_terminal_handover_still_lets_the_cli_act_on_the_signal() {
        // SAFETY: the forked judge uses only async-signal-safe calls and ends
        // with `_exit`; it works on its own copy of the statics.
        let judge = unsafe { libc::fork() };
        assert!(judge >= 0, "fork");
        if judge == 0 {
            // SAFETY: as above.
            unsafe {
                // A hung judge dies of SIGALRM; the parent reports it.
                libc::alarm(60);
                // Descriptor 0 is not a terminal: tcsetpgrp fails, as on a
                // hung-up one.
                let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
                if null == -1 || libc::dup2(null, 0) == -1 {
                    libc::_exit(10);
                }
                let cli = libc::fork();
                if cli == -1 {
                    libc::_exit(11);
                }
                if cli == 0 {
                    libc::setpgid(0, 0);
                    libc::signal(libc::SIGHUP, exit_zero as *const () as libc::sighandler_t);
                    libc::raise(libc::SIGSTOP);
                    loop {
                        libc::pause();
                    }
                }
                libc::setpgid(cli, cli);
                let mut st: libc::c_int = 0;
                if libc::waitpid(cli, &mut st, libc::WUNTRACED) != cli || !libc::WIFSTOPPED(st) {
                    libc::_exit(12);
                }
                SHIM_CLI.store(cli, Ordering::Release);
                shim_forward(libc::SIGHUP);
                SHIM_CLI.store(0, Ordering::Release);
                if libc::waitpid(cli, &mut st, 0) != cli {
                    libc::_exit(13);
                }
                libc::_exit(if libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0 {
                    0
                } else {
                    14
                });
            }
        }
        let mut st: libc::c_int = 0;
        // SAFETY: valid out-pointer; `judge` is our child.
        assert_eq!(unsafe { libc::waitpid(judge, &mut st, 0) }, judge);
        assert!(
            libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
            "judge status {st:#x} (exit 14: the CLI did not handle the HUP it was sent)"
        );
    }

    /// The forwarding and kill handlers leave errno as they found it (the
    /// interrupted `poll` must still see EINTR).
    #[test]
    fn shim_handlers_preserve_errno() {
        let _statics = shim_statics();
        SHIM_CLI.store(0x7fff_fffe, Ordering::Release); // no such group: kill fails
                                                        // SAFETY: errno slot of this thread.
        unsafe { *errno_location() = libc::ERANGE };
        shim_forward(libc::SIGUSR2);
        // SAFETY: as above.
        assert_eq!(unsafe { *errno_location() }, libc::ERANGE, "shim_forward");
        let mut info = fake_info(KILL_CODE, unsafe { libc::getppid() });
        shim_kill(libc::SIGURG, &mut info, std::ptr::null_mut());
        // SAFETY: as above.
        assert_eq!(unsafe { *errno_location() }, libc::ERANGE, "shim_kill");
        SHIM_CLI.store(0, Ordering::Release);
    }

    /// Every test that stores to the shim's process-wide statics and signals
    /// for real takes [`shim_statics`] (a forked judge works on its own copy
    /// and needs none). Read from this file's own text, so a test added later
    /// without the lock is caught here, not by a flake. The needles are
    /// assembled so this test does not match itself.
    #[test]
    fn tests_that_store_the_shim_statics_hold_the_lock() {
        let store = ["SHIM_CLI", ".store("].concat();
        let lock = ["shim_statics", "()"].concat();
        let fork = ["libc::", "fork()"].concat();
        let src = include_str!("pty.rs");
        let mut checked = 0;
        for chunk in src.split("#[test]").skip(1) {
            let name = chunk
                .split("fn ")
                .nth(1)
                .and_then(|t| t.split('(').next())
                .unwrap_or("?");
            if chunk.contains(&store) && !chunk.contains(&fork) {
                checked += 1;
                assert!(
                    chunk.contains(&lock),
                    "{name} stores the shim statics without holding the lock"
                );
            }
        }
        // Not vacuous: the two tests that need the lock were found.
        assert!(checked >= 2, "scan found {checked} tests");
    }

    // -- core dumps ------------------------------------------------------

    /// How a forked judge that hardens (or fails to harden) itself and then
    /// calls `reset_and_raise(SIGABRT)` ended: `Ok(code)` for a normal exit,
    /// `Err(sig)` for a signal. Core dumps are switched off for the judge by
    /// its own rlimit first, so a (mutated) raise cannot write a dump.
    fn raise_in_judge(fail_hardening: bool) -> Result<i32, i32> {
        // SAFETY: the judge uses only system calls and the code under test
        // (all raw syscall wrappers) and ends with `_exit` or a signal.
        let judge = unsafe { libc::fork() };
        assert!(judge >= 0, "fork");
        if judge == 0 {
            // SAFETY: as above.
            unsafe {
                libc::alarm(60);
                let lim = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::setrlimit(libc::RLIMIT_CORE, &lim);
                FAIL_DISABLE_CORE.store(fail_hardening, Ordering::Relaxed);
                reset_and_raise(libc::SIGABRT);
                // Never reached when the raise terminates the process.
                libc::_exit(99);
            }
        }
        let mut st: libc::c_int = 0;
        // SAFETY: valid out-pointer; `judge` is our child.
        assert_eq!(unsafe { libc::waitpid(judge, &mut st, 0) }, judge);
        if libc::WIFEXITED(st) {
            Ok(libc::WEXITSTATUS(st))
        } else {
            Err(libc::WTERMSIG(st))
        }
    }

    /// When the core-dump hardening fails, `reset_and_raise` must NOT raise a
    /// signal whose default action may dump (S4-7): it ends the process with
    /// the shell's `128 + sig` instead. The control run (hardening works)
    /// proves the judge does take the raise path otherwise.
    #[test]
    fn a_failed_core_hardening_ends_the_process_instead_of_raising() {
        assert_eq!(
            raise_in_judge(false),
            Err(libc::SIGABRT),
            "control: with the hardening working the signal is raised"
        );
        assert_eq!(
            raise_in_judge(true),
            Ok(128 + libc::SIGABRT),
            "a failed hardening must end the process without raising"
        );
    }

    /// The non-zero core-file soft limit a core-limit test stages, or `None`
    /// on a host whose `RLIMIT_CORE` HARD limit is 0 (a container or systemd
    /// default; CI's fleet runners). There no process can raise its soft limit
    /// above 0, so "zeroed" and "passed through unchanged" are the same
    /// observation and the test could not red: the test prints a visible
    /// `SKIPPED` marker and claims no coverage. The gate reads this process's
    /// limit (which every helper inherits) BEFORE the code under test runs,
    /// per the test-skip discipline; the property is asserted on every host
    /// with a non-zero hard limit, which prints `RAN`.
    ///
    /// `dumpable_branch` is true for a test that, on Linux, keeps real coverage
    /// of the dumpable half when the hard limit is 0 (its caller then prints
    /// `RAN ... dumpable only`); only there is `SKIPPED` withheld, so a test
    /// never prints both markers.
    fn core_limit_stage(test: &str, dumpable_branch: bool) -> Option<u64> {
        // SAFETY: plain rlimit query into a valid out-pointer.
        let lim = unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            assert_eq!(libc::getrlimit(libc::RLIMIT_CORE, &mut lim), 0);
            lim
        };
        if lim.rlim_max == 0 {
            if dumpable_branch && cfg!(target_os = "linux") {
                return None;
            }
            println!(
                "SKIPPED {test}: RLIMIT_CORE hard limit is 0 on this host, so a zeroed \
                 soft limit is indistinguishable from an inherited one (no coverage claimed)"
            );
            return None;
        }
        let stage = (lim.rlim_max as u64).min(4096);
        println!(
            "RAN {test}: staged core soft limit {stage} (hard {})",
            lim.rlim_max
        );
        Some(stage)
    }

    #[test]
    fn disable_core_dumps_zeroes_the_soft_limit() {
        let staged = core_limit_stage("disable_core_dumps_zeroes_the_soft_limit", true);
        // A zero HARD limit hides only the soft-limit half. On Linux the
        // dumpable flag still goes 1 -> 0, so that half keeps its coverage
        // there; elsewhere nothing observable is left.
        #[cfg(target_os = "linux")]
        if staged.is_none() {
            let out = helper_command("coreprobe").output().expect("coreprobe");
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            assert!(
                text.contains("CORE-BEFORE soft=0 dumpable=1"),
                "the probe did not start dumpable: {text:?}"
            );
            assert!(
                text.contains("CORE0 soft=0 dumpable=0"),
                "not made undumpable: {text:?}"
            );
            println!("RAN disable_core_dumps_zeroes_the_soft_limit: dumpable 1 -> 0 only");
            return;
        }
        let Some(stage) = staged else {
            return;
        };
        let out = helper_command("coreprobe").output().expect("coreprobe");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        #[cfg(target_os = "linux")]
        {
            assert!(
                text.contains(&format!("CORE-BEFORE soft={stage} dumpable=1")),
                "the probe did not start dumpable: {text:?}"
            );
            assert!(
                text.contains("CORE0 soft=0 dumpable=0"),
                "not zeroed and undumpable: {text:?}"
            );
        }
        // The probe starts from a non-zero limit: a zero start would let the
        // call be a no-op and still pass.
        let before = text
            .split("CORE-BEFORE soft=")
            .nth(1)
            .and_then(|r| r.split_whitespace().next())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_else(|| panic!("no CORE-BEFORE in {text:?}"));
        assert_eq!(
            before, stage,
            "the probe could not raise the limit: {text:?}"
        );
        assert!(text.contains("CORE0 soft=0"), "got {text:?}");
        assert!(text.contains(&format!("prev={before}")), "got {text:?}");
        #[cfg(target_os = "linux")]
        assert!(text.contains("dumpable=0"), "got {text:?}");
    }

    /// The relay process itself, not only the shim, holds the launch
    /// environment: it must be undumpable after a run. (`CSQ_S1A_CORE` gives it
    /// a non-zero limit to start from.)
    #[test]
    fn the_relay_process_itself_runs_with_no_core_limit() {
        let Some(stage) =
            core_limit_stage("the_relay_process_itself_runs_with_no_core_limit", true)
        else {
            #[cfg(target_os = "linux")]
            {
                let mut o = Outer::start("", &[]);
                let state = o.wait_value("RELAY-CORE ");
                assert_eq!(state, "soft=0 dumpable=0", "relay dumpable: {state:?}");
                assert_eq!(o.wait_value("R-EXIT "), "0");
                println!("RAN the_relay_process_itself_runs_with_no_core_limit: dumpable only");
            }
            return;
        };
        let mut o = Outer::start("", &[("CSQ_S1A_CORE", &stage.to_string())]);
        let state = o.wait_value("RELAY-CORE ");
        assert!(state.starts_with("soft=0"), "relay not hardened: {state:?}");
        #[cfg(target_os = "linux")]
        assert!(state.contains("dumpable=0"), "relay dumpable: {state:?}");
        assert_eq!(o.wait_value("R-EXIT "), "0");
    }

    /// The shim takes its relay's identity from before the fork: a relay that
    /// is already gone (the shim's parent is not the plan's relay) means no CLI
    /// is started, instead of a baseline the liveness poll can never trip on.
    #[test]
    fn a_shim_whose_relay_is_already_gone_starts_no_cli() {
        let out = helper_command("forgedrelay").output().expect("forgedrelay");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            text.contains(&format!("SPAWN-ERR={}", libc::ESRCH)),
            "got {text:?}"
        );
    }

    /// A `SIGSEGV` reaching the shim (a stray `kill -SEGV`, `pkill -SEGV csq`;
    /// a real fault takes the same path) ends the CLI with it: a CLI that
    /// ignores HUP and TERM and runs on its own must not outlive its shim.
    #[test]
    fn a_fault_signal_reaching_the_shim_takes_the_cli_with_it() {
        // The loop ends with the shell role (CSQ_S1A_PPID is its pid there): a
        // test run killed from outside never leaves this CLI spinning. The shim
        // is not the guard, since the test kills the shim and must see the
        // shim's own cleanup take the CLI.
        let script = r#"G=$CSQ_S1A_PPID; trap '' HUP TERM; echo CHILD=$$; echo SHIM=$PPID; echo READY; while kill -0 $G 2>/dev/null; do /bin/sleep 1; done"#;
        let mut o = Outer::start(script, &[]);
        let child: libc::pid_t = o.wait_value("CHILD=").parse().unwrap();
        let shim: libc::pid_t = o.wait_value("SHIM=").parse().unwrap();
        o.wait_for("READY");
        kill_pid(shim, libc::SIGSEGV);
        assert_eq!(o.wait_value("R-SIG "), "11");
        let gone = wait_gone(child);
        if !gone {
            // Still there, so the pid is still this CLI (never a reused one).
            kill_pid(child, libc::SIGKILL);
        }
        assert!(gone, "the CLI outlived the shim that a SEGV killed");
    }

    /// The CLI gets back the core-file limit the relay had; on Linux the shim
    /// itself runs with a zero limit.
    #[test]
    fn the_cli_gets_the_original_core_limit_and_the_shim_has_none() {
        let Some(stage) = core_limit_stage(
            "the_cli_gets_the_original_core_limit_and_the_shim_has_none",
            true,
        ) else {
            #[cfg(target_os = "linux")]
            shim_is_undumpable("the_cli_gets_the_original_core_limit_and_the_shim_has_none");
            return;
        };
        let staged = stage.to_string();
        let mut o = Outer::start("", &[("CSQ_S1A_CHILD", "probe"), ("CSQ_S1A_CORE", &staged)]);
        o.wait_for(&format!("CORE={stage}"));
        assert_eq!(o.wait_value("R-EXIT "), "0");
    }

    /// Hard core limit 0 (Linux): the shim's soft limit is 0 either way, but a
    /// hardened shim is also undumpable, and the kernel then makes its `/proc`
    /// FILES root-owned (not the `/proc/<pid>` directory, which it always
    /// shows with the process's euid). Read as a non-root user that ownership
    /// separates hardened from not; as root it cannot, so that case prints
    /// `SKIPPED`.
    #[cfg(target_os = "linux")]
    fn shim_is_undumpable(test: &str) {
        // SAFETY: plain getuid.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            println!("SKIPPED {test}: running as root, /proc ownership cannot show dumpable");
            return;
        }
        // `$PPID` is the shim: a hardened one is undumpable, so its `/proc`
        // FILES (`environ`) are root-owned. The CLI (`$$`) exec'ed, which reset
        // its own dumpable flag, so its `environ` still shows this process's
        // euid: an in-run control, without which the shim assertion could not
        // fail.
        let script = r#"echo SHIMOWN:$(/usr/bin/stat -c %u /proc/$PPID/environ); echo SELFOWN:$(/usr/bin/stat -c %u /proc/$$/environ); echo END"#;
        let mut o = Outer::start(script, &[]);
        o.wait_for("END");
        let seen = String::from_utf8_lossy(&o.acc).to_string();
        assert!(seen.contains("SHIMOWN:0"), "shim is dumpable: {seen:?}");
        assert!(
            seen.contains(&format!("SELFOWN:{euid}")),
            "control: the CLI's /proc/environ is not euid-owned, so the shim check cannot red: {seen:?}"
        );
        println!("RAN {test}: dumpable only");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_shim_runs_with_no_core_limit() {
        let Some(stage) = core_limit_stage("the_shim_runs_with_no_core_limit", true) else {
            shim_is_undumpable("the_shim_runs_with_no_core_limit");
            return;
        };
        let script =
            r#"grep 'core file' /proc/$PPID/limits | tr -s ' ' | sed 's/^/SHIMLIM:/'; echo END"#;
        let mut o = Outer::start(script, &[("CSQ_S1A_CORE", &stage.to_string())]);
        o.wait_for("END");
        let seen = String::from_utf8_lossy(&o.acc).to_string();
        assert!(
            seen.contains("SHIMLIM:Max core file size 0 "),
            "got {seen:?}"
        );
    }

    // -- startup status, parent liveness ---------------------------------

    #[test]
    fn the_startup_status_wait_is_bounded_and_reads_a_failure() {
        let (r, w) = cloexec_pipe().expect("pipe");
        let t0 = Instant::now();
        // A leaked write end: no EOF, no data. Silence after the bound.
        let (_, got) =
            read_startup_status(r.as_raw_fd(), Duration::from_millis(200)).expect("read");
        assert_eq!(got, 0);
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_millis(150),
            "returned early: {waited:?}"
        );
        assert!(waited < Duration::from_secs(5), "unbounded: {waited:?}");
        let mut msg = [b'E', 0, 0, 0, 0];
        msg[1..].copy_from_slice(&libc::EACCES.to_le_bytes());
        write_fd(w.as_raw_fd(), &msg).expect("write");
        let (back, got) = read_startup_status(r.as_raw_fd(), Duration::from_secs(5)).expect("read");
        assert_eq!((got, back), (5, msg));
    }

    /// The relay dies but a leaked copy of the control pipe keeps it open:
    /// the shim notices through its parent pid.
    #[test]
    fn the_shim_ends_the_cli_when_its_parent_dies_with_the_pipe_still_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        // The read end is open before the spawner runs: the CLI's write is
        // never gated on when this test reads, even though the spawner exits
        // (and the shim starts ending the CLI) first.
        let fifo = PidFifo::new(dir.path(), "cli.pid");
        let out = helper_command("spawner")
            .env("S1A_PIDFILE", fifo.path())
            .output()
            .expect("spawner");
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let holder: libc::pid_t = text
            .split("HOLDER=")
            .nth(1)
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("no HOLDER in {text:?}"));
        let cli = fifo.read_pid("the CLI");
        let gone = wait_gone(cli);
        // The holder sleeps 120 s, so it is still ours to end (never reused).
        kill_pid(holder, libc::SIGKILL);
        if !gone {
            kill_pid(cli, libc::SIGKILL);
        }
        assert!(gone, "the CLI outlived its relay's death");
    }

    /// A test that ends before it read any announcement (an early assertion,
    /// a timeout) must still leave nothing behind. The CLI starts a job in
    /// its own process group (`set -m`) that ignores HUP and TERM, which no
    /// group signal from the relay or the shim reaches; only a cleanup that
    /// walks the process tree finds it. The unwind is forced by `catch_unwind`
    /// right after the job published its pid (through its fifo, not the pty
    /// output the harness would read).
    #[test]
    fn a_test_that_ends_early_leaves_no_process_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = PidFifo::new(dir.path(), "job.pid");
        let script = r#"set -m; /bin/sh -c 'trap "" HUP TERM; echo $$ > "$CSQ_S1A_PIDFILE"; exec /bin/sleep 120' & echo READY; wait"#;
        let published = std::sync::Mutex::new(None::<libc::pid_t>);
        let early = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _outer = Outer::start(
                script,
                &[("CSQ_S1A_PIDFILE", fifo.path().to_str().expect("utf8"))],
            );
            let job = fifo.read_pid("the job");
            *published.lock().expect("published slot") = Some(job);
            // No wait_for / announced here: the harness knows no pid.
            panic!("forced early exit");
        }));
        forced_early_exit(early.expect_err("the forced early exit did not unwind"));
        let job = *published.lock().expect("published slot");
        let job = job.expect("the job's pid was never published: not the forced exit");
        let gone = wait_gone(job);
        if !gone {
            // Still there: the pid is still the fixture (the wait is bounded
            // well inside pid reuse).
            kill_pid(job, libc::SIGKILL);
        }
        assert!(gone, "the early-ended test left its job running");
    }

    /// The harness cleanup takes the whole process group of what it started,
    /// not only the processes still below the shell role: the CLI starts a
    /// helper that ignores HUP and TERM and whose own parent exits at once (a
    /// double fork), so it is reparented out of the tree but stays in the CLI's
    /// group.
    #[test]
    fn a_test_that_ends_early_leaves_no_reparented_group_member_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = PidFifo::new(dir.path(), "member.pid");
        // `wait` comes before `echo READY`: the shell reaps the subshell
        // first, and a process's children are reparented before its parent
        // can reap it, so READY is proof the member is already out of the
        // tree when the forced unwind runs — ordered by the harness's own
        // read instead of a sampled `ps` parent field.
        let script = r#"(/bin/sh -c 'trap "" HUP TERM; echo $$ > "$CSQ_S1A_PIDFILE"; exec /bin/sleep 120' &); wait; echo READY; /bin/sleep 60"#;
        let published = std::sync::Mutex::new(None::<libc::pid_t>);
        let early = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut outer = Outer::start(
                script,
                &[("CSQ_S1A_PIDFILE", fifo.path().to_str().expect("utf8"))],
            );
            let member = fifo.read_pid("the member");
            *published.lock().expect("published slot") = Some(member);
            // Its parent (the subshell) exits right after the member's pid is
            // written; READY is emitted after that exit is reaped.
            outer.wait_for("READY");
            panic!("forced early exit");
        }));
        forced_early_exit(early.expect_err("the forced early exit did not unwind"));
        let member = *published.lock().expect("published slot");
        let member = member.expect("the member's pid was never published: not the forced exit");
        let gone = wait_gone(member);
        if !gone {
            kill_pid(member, libc::SIGKILL);
        }
        assert!(gone, "the early-ended test left a group member running");
    }

    /// A helper role whose parent is gone ends by itself: the watchdog that the
    /// `shell` and `relay` roles also run. Without it the process outlives a
    /// test run that was killed from outside, since no destructor ran.
    #[test]
    fn a_helper_role_ends_when_its_parent_is_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("probe.pid");
        // The outer shell starts the probe in the background and exits at
        // once: the probe is orphaned. Its pid is the background job's.
        let exe = std::env::current_exe().expect("current_exe");
        let outer = format!(
            r#"{ROLE}=orphanprobe {PARENT}=$$ "$S1A_EXE" --exact relay::pty::tests::helper_main --nocapture --test-threads=1 >/dev/null 2>&1 & echo $! > "$S1A_PIDFILE""#
        );
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(outer)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", scratch_home())
            .env("S1A_PIDFILE", &pidfile)
            .env("S1A_EXE", &exe)
            .status()
            .expect("outer shell");
        assert!(status.success());
        let probe: libc::pid_t = std::fs::read_to_string(&pidfile)
            .expect("pid file")
            .trim()
            .parse()
            .expect("pid");
        let gone = wait_gone(probe);
        if !gone {
            kill_pid(probe, libc::SIGKILL);
        }
        assert!(gone, "an orphaned helper role kept running");
    }

    /// Fixtures that ignore HUP and TERM and spin must end once their parent
    /// is gone: a killed or timed-out test may never leave a CPU-burning
    /// orphan (they survive `timeout`, which signals only its direct child).
    #[test]
    fn a_spinning_fixture_ends_when_its_parent_dies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("spin.pid");
        // The outer shell starts the fixture, waits for its pid file, then
        // exits: the fixture is orphaned.
        let outer = r#"sh -c 'P=$PPID; trap "" HUP TERM; echo $$ > "$S1A_PIDFILE"; while kill -0 $P 2>/dev/null; do :; done' & while [ ! -s "$S1A_PIDFILE" ]; do :; done"#;
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(outer)
            .env("S1A_PIDFILE", &pidfile)
            .status()
            .expect("outer shell");
        assert!(status.success());
        let pid: libc::pid_t = std::fs::read_to_string(&pidfile)
            .expect("pid file")
            .trim()
            .parse()
            .expect("pid");
        let gone = wait_gone(pid);
        if !gone {
            // Still there, so the pid is still the fixture (never a reused one).
            kill_pid(pid, libc::SIGKILL);
        }
        assert!(gone, "a spinning fixture outlived its parent");
    }

    // -- R1 fixes: leak ------------------------------------------------------

    /// `ps -A -o pid=,command=` rows whose command line holds `needle`.
    fn processes_matching(needle: &str) -> Vec<libc::pid_t> {
        let mut c = Command::new("/bin/ps");
        c.args(["-A", "-o", "pid=,command="]);
        let listing = run_bounded(c, PS_LIMIT)
            .unwrap_or_else(|e| panic!("CLEANUP-PS-FAILED: process listing: {e}"));
        listing
            .text
            .lines()
            .filter(|l| l.contains(needle))
            .filter_map(|l| l.split_whitespace().next()?.parse().ok())
            .collect()
    }

    /// A test run killed from outside (`timeout`, a CI cancel) runs no
    /// destructor: the `shell` role's watchdog must take the whole tree with
    /// it, including a job in a group and session of its own that ignores HUP
    /// and TERM, which no group signal of the relay or the shim reaches. The
    /// host role stands in for the test binary; the test kills it with SIGKILL.
    #[test]
    fn a_test_run_killed_from_outside_leaves_nothing_behind() {
        externally_killed_run(false);
    }

    /// The same with the terminal's master kept open by another process, so no
    /// hangup reaches anything: the shell role is alive and its relay runs on,
    /// and only the shell role's own watchdog can end the `set -m` job. It is
    /// the only thing this variant can pass on.
    #[test]
    fn a_test_run_killed_with_its_terminal_still_open_leaves_nothing_behind() {
        externally_killed_run(true);
    }

    fn externally_killed_run(hold_master: bool) {
        let dir = tempfile::tempdir().expect("tempdir");
        let pidfile = dir.path().join("job.pid");
        let script = r#"echo CHILD=$$; set -m; /bin/sh -c 'trap "" HUP TERM; echo $$ > "$CSQ_S1A_PIDFILE"; exec /bin/sleep 120' & echo READY; wait"#;
        let errfile = dir.path().join("host.err");
        let mut host = helper_command("outerhost")
            .env("CSQ_S1A_HOST_SCRIPT", script)
            .env("CSQ_S1A_PIDFILE", &pidfile)
            .env("CSQ_S1A_HOST_TRACKFILE", dir.path().join("tracked"))
            .env("CSQ_S1A_DEBUGLOG", dir.path().join("debug.log"))
            .env(
                "CSQ_S1A_HOST_HOLD_MASTER",
                if hold_master { "1" } else { "" },
            )
            // Variant 2 isolates the shell role's own watchdog.
            .env(
                "CSQ_S1A_NO_SENTINEL",
                if hold_master { "1" } else { "" },
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(&errfile).expect("stderr file"))
            .spawn()
            .expect("spawn host");
        let host_pid = host.id() as libc::pid_t;
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(host.stdout.take().expect("stdout"));
        let hosted = loop {
            line.clear();
            use std::io::BufRead;
            if reader.read_line(&mut line).expect("host output") == 0 {
                kill_pid(host_pid, libc::SIGKILL);
                let _ = host.wait();
                panic!(
                    "the host ended before it reported: {:?}",
                    std::fs::read_to_string(&errfile).unwrap_or_default()
                );
            }
            // The harness prints its own "test ... " prefix on the same line.
            if let Some(i) = line.find("HOSTED ") {
                break line[i + "HOSTED ".len()..].trim().to_string();
            }
        };
        let field = |name: &str| -> libc::pid_t {
            hosted
                .split_whitespace()
                .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("no {name} in {hosted:?}"))
        };
        let pids = [
            ("shell", field("shell")),
            ("relay", field("relay")),
            ("cli", field("cli")),
            ("job", field("job")),
        ];
        // The external kill: no destructor of the host runs.
        kill_pid(host_pid, libc::SIGKILL);
        let _ = host.wait();
        let gone: Vec<(&str, bool)> = pids.iter().map(|(n, p)| (*n, wait_gone(*p))).collect();
        if hold_master {
            // The holder is this test's own fixture (alarm-bounded as well).
            kill_pid(field("holder"), libc::SIGKILL);
        }
        // What the survivors are doing, taken before they are ended.
        let list = pids
            .iter()
            .map(|(_, p)| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let states = Command::new("/bin/ps")
            .args(["-o", "pid=,ppid=,pgid=,stat=,wchan=,command=", "-p", &list])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        for (_, p) in &pids {
            // Still there means still the fixture (the waits are bounded well
            // inside pid reuse).
            if !wait_gone(*p) {
                kill_pid(*p, libc::SIGKILL);
            }
        }
        assert!(
            gone.iter().all(|(_, g)| *g),
            "survivors of an externally killed run: {gone:?}; states at the first check: {states:?}; diagnostic log: {:?}",
            std::fs::read_to_string(dir.path().join("debug.log")).unwrap_or_default()
        );
    }

    /// The freeze: a tree whose members keep forking (each child in a group of
    /// its own) is gone after one reap, with nothing escaping between the
    /// snapshot and the kill. The root only waits for the forker, so the forker
    /// keeps forking until it is frozen.
    #[test]
    fn reap_tree_ends_a_tree_that_keeps_forking() {
        let mark = format!("733.{}", std::process::id());
        let mut root = helper_command("forker")
            .env("CSQ_S1A_WRAP", "1")
            .env("CSQ_S1A_MARK", &mark)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn forker");
        let root_pid = root.id() as libc::pid_t;
        let deadline = Instant::now() + WAIT;
        loop {
            let rows = ps_rows_via(&system_ps).expect("ps");
            if descendants_of(&rows, root_pid).len() >= 4 && !processes_matching(&mark).is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                kill_pid(root_pid, libc::SIGKILL);
                let _ = root.wait();
                panic!("the forker never got going");
            }
            tick();
        }
        let reaped = reap_tree_via(&system_ps, root_pid, false);
        kill_pid(root_pid, libc::SIGKILL);
        let _ = root.wait();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut left = processes_matching(&mark);
        while !left.is_empty() && Instant::now() < deadline {
            tick();
            left = processes_matching(&mark);
        }
        for p in &left {
            // Carries this test's unique mark: still the fixture.
            kill_pid(*p, libc::SIGKILL);
        }
        assert_eq!(reaped, Ok(()), "the tree did not settle");
        assert!(left.is_empty(), "members escaped the reap: {left:?}");
    }

    /// A root (`sh`) that waits for one child, `sleep <mark>`, which stays in
    /// the caller's own process group (no job control), with the child's pid.
    // The handle is returned to the caller, which kills and waits it on every path.
    #[allow(clippy::zombie_processes)]
    fn root_with_one_child(mark: &str) -> (std::process::Child, libc::pid_t) {
        let mut root = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("sleep {mark} & wait"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn root");
        let root_pid = root.id() as libc::pid_t;
        let deadline = Instant::now() + WAIT;
        loop {
            let rows = ps_rows_via(&system_ps).expect("ps");
            if let Some(child) = descendants_of(&rows, root_pid).first() {
                return (root, child.0);
            }
            if Instant::now() >= deadline {
                kill_pid(root_pid, libc::SIGKILL);
                let _ = root.wait();
                panic!("the root never started its child");
            }
            tick();
        }
    }

    /// Poll (bounded) until `pid` is gone or only a zombie.
    fn gone_within(pid: libc::pid_t, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        loop {
            let st = proc_state(pid);
            if st.is_empty() || st.starts_with('Z') {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tick();
        }
    }

    /// The pid kill: a member in the caller's own group is reached by no group
    /// signal (the own group is never signalled), so only its pid ends it. A
    /// frozen but un-killed member would show as stopped, not gone.
    #[test]
    fn reap_tree_ends_a_member_that_shares_the_callers_group() {
        let mark = format!("734.{}", std::process::id());
        let (mut root, child) = root_with_one_child(&mark);
        let root_pid = root.id() as libc::pid_t;
        // SAFETY: getpgrp has no preconditions.
        let own = unsafe { libc::getpgrp() };
        let child_group = ps_field(child, "pgid").and_then(|v| v.parse::<libc::pid_t>().ok());
        let reaped = reap_tree_via(&system_ps, root_pid, false);
        let gone = gone_within(child, Duration::from_secs(10));
        kill_pid(root_pid, libc::SIGKILL);
        let _ = root.wait();
        if !gone {
            // Carries this test's unique mark: still the fixture.
            kill_pid(child, libc::SIGKILL);
        }
        assert_eq!(child_group, Some(own), "the fixture must share the group");
        assert_eq!(reaped, Ok(()), "the tree did not settle");
        assert!(gone, "a member of the caller's own group survived the reap");
    }

    /// The freeze, observed directly: the snapshot after the one that found a
    /// member sees it stopped. (The forking tree above races on some hosts;
    /// this does not, and it names the stop itself.)
    #[test]
    fn reap_tree_stops_a_member_before_it_takes_the_next_snapshot() {
        let mark = format!("735.{}", std::process::id());
        let (mut root, child) = root_with_one_child(&mark);
        let root_pid = root.id() as libc::pid_t;
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join("states");
        let log_path = log.display().to_string();
        let ps = move || {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(format!(
                r#"/bin/ps -A -o pid=,ppid=,pgid=; for i in 1 2 3 4 5 6 7 8 9 10; do s=$(/bin/ps -o state= -p {child}); case "$s" in T*) break;; esac; /bin/sleep 0.05; done; echo "$s" >> '{log_path}'"#
            ));
            c
        };
        let reaped = reap_tree_via(&ps, root_pid, false);
        let states = std::fs::read_to_string(&log).unwrap_or_default();
        let gone = gone_within(child, Duration::from_secs(10));
        kill_pid(root_pid, libc::SIGKILL);
        let _ = root.wait();
        if !gone {
            // Carries this test's unique mark: still the fixture.
            kill_pid(child, libc::SIGKILL);
        }
        assert_eq!(reaped, Ok(()), "the tree did not settle");
        assert!(
            states.lines().any(|l| l.trim().starts_with('T')),
            "the member was never seen stopped; states per snapshot: {states:?}"
        );
    }

    /// The sentinel alone: with the process that started it gone, it ends the
    /// tree it watches. Darwin cannot tell the sentinel from the other layers
    /// in the leak tests, which also clean up there; this reaches it directly.
    #[test]
    fn the_sentinel_ends_the_tree_it_watches_when_its_parent_dies() {
        let mark = format!("736.{}", std::process::id());
        let (mut root, child) = root_with_one_child(&mark);
        let root_pid = root.id() as libc::pid_t;
        // The launcher stands in for the harness: it is the sentinel's parent
        // (its pid is the watched `PARENT`) and the test kills it.
        let hc = helper_command("sentinel");
        let mut launcher = Command::new("/bin/sh");
        launcher.env_clear();
        for (k, v) in hc.get_envs() {
            if let Some(v) = v {
                launcher.env(k, v);
            }
        }
        launcher
            .env("CSQ_S1A_WATCH_ROOT", root_pid.to_string())
            .arg("-c")
            .arg(format!(r#"{PARENT}=$$ "$0" "$@" & wait"#))
            .arg(std::env::current_exe().expect("current_exe"))
            .args(HELPER_ARGS)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut parent = launcher.spawn().expect("spawn launcher");
        let parent_pid = parent.id() as libc::pid_t;
        let deadline = Instant::now() + WAIT;
        let mut watching = false;
        while Instant::now() < deadline {
            let rows = ps_rows_via(&system_ps).expect("ps");
            if !descendants_of(&rows, parent_pid).is_empty() {
                watching = true;
                break;
            }
            tick();
        }
        // A few ticks of the sentinel while the harness stand-in is alive.
        for _ in 0..8 {
            tick();
        }
        let alive_before = !gone_within(child, Duration::ZERO);
        kill_pid(parent_pid, libc::SIGKILL);
        let _ = parent.wait();
        let gone = gone_within(child, Duration::from_secs(15));
        kill_pid(root_pid, libc::SIGKILL);
        let _ = root.wait();
        if !gone {
            // Carries this test's unique mark: still the fixture.
            kill_pid(child, libc::SIGKILL);
        }
        assert!(watching, "the sentinel never started");
        assert!(alive_before, "the sentinel acted while its parent lived");
        assert!(gone, "the sentinel left the watched tree behind");
    }

    /// A process table that cannot be read is an error with the fixed marker,
    /// never an empty (silent) cleanup; a transient failure is retried.
    #[test]
    fn a_failing_process_snapshot_is_an_error_and_a_flaky_one_is_retried() {
        let t0 = Instant::now();
        let err = ps_rows_via(&|| Command::new("/nonexistent/ps-s1a")).expect_err("must fail");
        assert!(err.contains("did not start"), "got {err:?}");
        assert!(t0.elapsed() < Duration::from_secs(10), "unbounded retries");
        let dir = tempfile::tempdir().expect("tempdir");
        let counter = dir.path().join("n");
        let flaky = move || {
            let mut c = Command::new("/bin/sh");
            c.arg("-c").arg(format!(
                r#"n=$(cat '{0}' 2>/dev/null || echo 0); echo $((n+1)) > '{0}'; [ "$n" -lt 2 ] && exit 3; exec ps -A -o pid=,ppid=,pgid="#,
                counter.display()
            ));
            c
        };
        let rows = ps_rows_via(&flaky).expect("the third run succeeds");
        assert!(!rows.is_empty());
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        let failed = reap_tree_via(&|| Command::new("/nonexistent/ps-s1a"), me, false);
        assert!(
            failed.is_err(),
            "a failed snapshot must not read as success"
        );
    }

    // -- R1 fixes: privilege drop -------------------------------------------

    fn dropped_state(uid: u32, gid: u32) -> DropState {
        DropState {
            ruid: uid,
            euid: uid,
            suid: uid,
            rgid: gid,
            egid: gid,
            sgid: gid,
            regain_uid: Some(libc::EPERM),
            regain_gid: Some(libc::EPERM),
            cap_permitted: 0,
            cap_effective: 0,
            cap_inheritable: 0,
            ngroups: 0,
            group0: u32::MAX,
        }
    }

    /// The verification, against injected values: each way a drop can fail to
    /// take effect is refused, and only the exact identity passes.
    #[test]
    fn the_drop_verification_refuses_every_partial_drop() {
        let ok = dropped_state(1000, 1000);
        assert_eq!(verify_dropped(Some(1000), Some(1000), &ok), Ok(()));
        let bad = |f: &dyn Fn(&mut DropState)| {
            let mut s = ok;
            f(&mut s);
            verify_dropped(Some(1000), Some(1000), &s)
        };
        assert_eq!(bad(&|s| s.suid = 0), Err(DropMismatch::Uid));
        assert_eq!(bad(&|s| s.euid = 0), Err(DropMismatch::Uid));
        assert_eq!(bad(&|s| s.ruid = 0), Err(DropMismatch::Uid));
        assert_eq!(bad(&|s| s.sgid = 0), Err(DropMismatch::Gid));
        assert_eq!(bad(&|s| s.egid = 7), Err(DropMismatch::Gid));
        assert_eq!(bad(&|s| s.rgid = 0), Err(DropMismatch::Gid));
        assert_eq!(bad(&|s| s.regain_uid = None), Err(DropMismatch::RegainUid));
        assert_eq!(
            bad(&|s| s.regain_uid = Some(0)),
            Err(DropMismatch::RegainUid)
        );
        assert_eq!(bad(&|s| s.regain_gid = None), Err(DropMismatch::RegainGid));
        assert_eq!(
            bad(&|s| s.regain_gid = Some(0)),
            Err(DropMismatch::RegainGid)
        );
        assert_eq!(
            bad(&|s| s.cap_permitted = 1 << 6),
            Err(DropMismatch::Capabilities)
        );
        assert_eq!(
            bad(&|s| s.cap_effective = 1),
            Err(DropMismatch::Capabilities)
        );
        assert_eq!(
            bad(&|s| s.cap_permitted = u64::MAX),
            Err(DropMismatch::Capabilities)
        );
        // A drop TO root has no way back to refuse and keeps its capabilities.
        let root = DropState {
            regain_uid: None,
            regain_gid: None,
            cap_permitted: 1,
            cap_effective: 1,
            ..dropped_state(0, 0)
        };
        assert_eq!(verify_dropped(Some(0), Some(0), &root), Ok(()));
    }

    /// The tag a shim's failure message carries decides whether the caller may
    /// fall back; an unknown or short message is never a drop step.
    #[test]
    fn a_startup_failure_message_names_its_privilege_drop_step() {
        let msg = |tag: u8, errno: i32| {
            let mut m = [tag, 0, 0, 0, 0];
            m[1..].copy_from_slice(&errno.to_le_bytes());
            m
        };
        assert_eq!(
            decode_startup_failure(&msg(TAG_GENERIC, libc::EACCES), 5),
            (libc::EACCES, None)
        );
        for (tag, step) in [
            (TAG_SETGROUPS, "setgroups"),
            (TAG_CAPS, "capabilities"),
            (TAG_SETGID, "setgid"),
            (TAG_SETUID, "setuid"),
            (TAG_VERIFY, "verify_drop"),
        ] {
            assert_eq!(
                decode_startup_failure(&msg(tag, libc::EPERM), 5),
                (libc::EPERM, Some(step))
            );
        }
        assert_eq!(decode_startup_failure(&msg(b'?', 3), 5), (libc::EIO, None));
        assert_eq!(
            decode_startup_failure(&msg(TAG_SETUID, 3), 3),
            (libc::EIO, None)
        );
        let refused = SpawnFailure {
            err: io::Error::from_raw_os_error(libc::EPERM),
            drop_step: Some("setuid"),
            started: false,
        }
        .into_relay_error();
        assert_eq!(
            refused,
            RelayError::PrivilegeDropFailed {
                step: "setuid",
                errno: libc::EPERM
            }
        );
        assert!(
            !refused.may_launch_unrelayed(&LaunchSpec::new("/bin/true"))
                && !refused.child_started()
        );
        let plain = SpawnFailure::from(io::Error::from_raw_os_error(libc::EACCES));
        assert!(plain
            .into_relay_error()
            .may_launch_unrelayed(&LaunchSpec::new("/bin/true")));
        assert!(RelayError::Busy.may_launch_unrelayed(&LaunchSpec::new("/bin/true")));
        assert!(RelayError::Declined(Decline::Background)
            .may_launch_unrelayed(&LaunchSpec::new("/bin/true")));
        assert!(!RelayError::ChildStarted { op: "x", errno: 1 }
            .may_launch_unrelayed(&LaunchSpec::new("/bin/true")));
    }

    /// The real drop path as a non-root caller: the refusal is tagged as a drop
    /// step (so no unrelayed fallback), not a plain spawn failure.
    #[test]
    fn a_refused_privilege_drop_forbids_the_unrelayed_fallback() {
        // SAFETY: plain getters.
        let (euid, uid, gid) = unsafe { (libc::geteuid(), libc::getuid(), libc::getgid()) };
        if euid == 0 {
            println!("SKIPPED the unprivileged refusal: euid is 0");
            return;
        }
        let pty = Pty::open(None, None).expect("pty");
        let spec = LaunchSpec::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .uid(uid)
            .gid(gid);
        let failure = spawn_on_slave(&spec, pty.slave).err().expect("must fail");
        assert_eq!(failure.drop_step, Some("setgroups"));
        let err = failure.into_relay_error();
        assert_eq!(
            err,
            RelayError::PrivilegeDropFailed {
                step: "setgroups",
                errno: libc::EPERM
            }
        );
        assert!(!err.may_launch_unrelayed(&spec));
    }

    /// Root branch: an impossible gid is refused (either at the call or by the
    /// read-back), the CLI never runs, and the refusal is a drop step. Runs
    /// only as euid 0.
    #[test]
    fn the_privilege_drop_root_branch_refuses_an_impossible_gid() {
        // SAFETY: plain getter.
        if unsafe { libc::geteuid() } != 0 {
            println!("SKIPPED the root-branch refusal: euid is not 0");
            return;
        }
        println!("RAN the root-branch refusal (euid=0)");
        let pty = Pty::open(None, None).expect("pty");
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("ran");
        let spec = LaunchSpec::new("/bin/sh")
            .arg("-c")
            .arg(format!("echo ran > {}", marker.display()))
            .uid(65534)
            .gid(u32::MAX);
        let failure = spawn_on_slave(&spec, pty.slave).err().expect("must refuse");
        assert!(
            matches!(failure.drop_step, Some("setgid") | Some("verify_drop")),
            "got {:?}",
            failure.drop_step
        );
        assert!(!marker.exists(), "the CLI ran despite a refused drop");
    }

    #[test]
    fn a_group_id_without_a_user_id_is_refused() {
        let want = RelayError::NotStarted {
            op: "launch_spec",
            errno: libc::EINVAL,
        };
        assert_eq!(
            Relay::new(LaunchSpec::new("sh").gid(1000), RelayConfig::default())
                .expect_err("refused"),
            want
        );
    }

    // -- R1 fixes: other -----------------------------------------------------

    #[test]
    fn the_terminal_access_signal_handlers_do_not_restart_the_syscall() {
        let out = helper_command("ttyflags")
            .stdin(Stdio::null())
            .output()
            .expect("ttyflags role");
        let text = format!(
            "{} STDERR {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            text.contains("TTFLAGS installed=true restart=false"),
            "got {text:?}"
        );
    }

    /// A `waitpid` that fails for good (the child is not ours: here the kernel
    /// reaped it) ends the shell role instead of spinning on it.
    #[test]
    fn the_shell_role_stops_waiting_for_a_child_it_cannot_wait_for() {
        let mut o = Outer::start("exit 0", &[("CSQ_S1A_SHELL_IGN_CHLD", "1")]);
        o.wait_for("R-LOST");
    }

    /// A shim that has not yet made its own process group cannot be reached by
    /// a group signal: ending it must still end it (it did wait forever).
    #[test]
    fn end_child_ends_a_child_that_has_no_group_of_its_own_yet() {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"trap "" HUP TERM URG; exec sleep 120"#)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let pid = child.id() as libc::pid_t;
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            end_child(pid, Duration::from_millis(100));
            let _ = tx.send(());
        });
        let ended = rx.recv_timeout(Duration::from_secs(10)).is_ok();
        if !ended {
            // The wait is stuck on a child it never ended: end it so the
            // worker can return (the pid is ours and unreaped).
            kill_pid(pid, libc::SIGKILL);
        }
        let _ = worker.join();
        drop(child);
        assert!(
            ended,
            "end_child blocked on a child that no group signal reaches"
        );
    }

    /// A relay that is not the foreground job discards the drained output: it
    /// never writes to a terminal that belongs to another job.
    #[test]
    fn drain_writes_nothing_from_the_background() {
        let pty = Pty::open(None, None).expect("pty");
        set_nonblock(pty.master.as_raw_fd()).unwrap();
        write_fd(pty.slave.as_raw_fd(), b"left-over").unwrap();
        let (r, w) = nonblocking_pipe();
        set_nonblock(r.as_raw_fd()).unwrap();
        let mut out = OutQueue::over(w);
        out.queue(b"queued");
        let mut buf = [0u8; 64];
        drain_master(
            pty.master.as_raw_fd(),
            &mut out,
            Duration::from_millis(100),
            &mut buf,
            &|| false,
        );
        assert!(!out.wants_write(), "the queue was not discarded");
        let mut got = [0u8; 64];
        let err = read_fd(r.as_raw_fd(), &mut got).expect_err("nothing may be written");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    /// Role `sentinel`: watch the process that started an [`Outer`] and, once
    /// it is gone, end the whole tree of the shell role it started. The roles
    /// inside the terminal cannot be relied on for that: the hangup that
    /// follows the death of the harness kills the shell role, and the relay
    /// re-raises it from its own handler, so neither gets to clean up. The
    /// sentinel is in a session of its own and remembers the tree on a tick
    /// while it is whole. Its wedge alarm is re-armed on every tick, so it
    /// covers the harness for as long as the harness lives.
    fn role_sentinel() -> ! {
        let root: libc::pid_t = env("CSQ_S1A_WATCH_ROOT")
            .and_then(|v| v.parse().ok())
            .expect("watch root");
        let parent = env(PARENT)
            .and_then(|v| v.parse::<libc::pid_t>().ok())
            .expect("parent");
        let mut ident: Option<Identity> = None;
        let mut passes: u64 = 0;
        loop {
            // A wedged loop ends the role; re-armed on every tick, so the
            // cover lasts as long as the harness lives (no fixed lifetime).
            // SAFETY: alarm has no preconditions.
            unsafe { libc::alarm(120) };
            // SAFETY: getppid has no preconditions.
            if unsafe { libc::getppid() } != parent {
                arm_cleanup_alarm(CLEANUP_ALARM_SECS);
                dbg("sentinel: the harness is gone");
                reap_remembered();
                // The root may have died and its pid been reused: the live
                // walk happens only for the process the root was.
                match (&ident, ps_full()) {
                    (Some(id), Some(procs)) if root_still_is(id, &procs, root) => {
                        let r = reap_tree_reported(root, false);
                        dbg(&format!("sentinel reap_tree: {r:?}"));
                    }
                    (Some(_), Some(_)) => dbg("sentinel: the root is gone; remembered tree only"),
                    (None, _) => eprintln!(
                        "CLEANUP-ROOT-UNIDENTIFIED: the root was never seen; remembered tree only"
                    ),
                    (_, None) => eprintln!(
                        "CLEANUP-SNAPSHOT-FAILED: no process listing to re-identify the root"
                    ),
                }
                // SAFETY: _exit never returns.
                unsafe { libc::_exit(0) }
            }
            track_pass(root, &mut ident);
            passes += 1;
            // Test synchronisation only: how many tracking passes ran.
            if let Some(f) = env("CSQ_S1A_TRACKFILE") {
                let _ = std::fs::write(f, passes.to_string());
            }
            std::thread::sleep(TRACK_TICK);
        }
    }

    /// Role `ttyflags`: install the relay's signal handlers and report whether
    /// the terminal-access signals' handlers restart an interrupted syscall.
    /// A restarted write under `tostop` is refused again at once and would spin
    /// the relay inside the call (layer A of the TTIN/TTOU defence); reading the
    /// installed flags reaches it on every OS, where a behavioural test cannot.
    fn role_tty_flags() -> ! {
        // SAFETY: an all-zero termios is a valid value to keep.
        let outer: libc::termios = unsafe { std::mem::zeroed() };
        let _guard = SignalGuard::install(false, &outer).expect("install");
        let flags = |sig: libc::c_int| {
            // SAFETY: query only.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            unsafe { libc::sigaction(sig, std::ptr::null(), &mut old) };
            (
                old.sa_sigaction != libc::SIG_DFL,
                old.sa_flags & libc::SA_RESTART != 0,
            )
        };
        let (in_set, in_restart) = flags(libc::SIGTTIN);
        let (out_set, out_restart) = flags(libc::SIGTTOU);
        println!(
            "TTFLAGS installed={} restart={}",
            in_set && out_set,
            in_restart || out_restart
        );
        std::process::exit(0)
    }

    /// Role `declined`: run a relay that the start precondition declines
    /// (stdin is not a terminal), and report the core limit around it.
    fn role_declined() -> ! {
        let limit = || {
            // SAFETY: a valid out-pointer.
            let mut l: libc::rlimit = unsafe { std::mem::zeroed() };
            unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut l) };
            l.rlim_cur as u64
        };
        // A known, non-zero soft limit to compare against (a host whose
        // default is 0 would make "unchanged" true of a hardened process too).
        // SAFETY: a valid rlimit; raising the soft limit within the hard one.
        unsafe {
            let mut l: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_CORE, &mut l);
            l.rlim_cur = 4096.min(l.rlim_max);
            libc::setrlimit(libc::RLIMIT_CORE, &l);
        }
        let before = limit();
        let r = Relay::new(LaunchSpec::new("/bin/true"), RelayConfig::default())
            .expect("spec")
            .run();
        println!(
            "DECLINED before={before} after={} declined={}",
            limit(),
            matches!(r, Err(RelayError::Declined(_)))
        );
        std::process::exit(0)
    }

    /// A relay that declines hands back to an unrelayed launch, which must not
    /// inherit the zeroed core limit.
    #[test]
    fn a_declined_relay_leaves_the_core_limit_alone() {
        let Some(stage) = core_limit_stage("a_declined_relay_leaves_the_core_limit_alone", false)
        else {
            return;
        };
        let out = helper_command("declined")
            .stdin(Stdio::null())
            .output()
            .expect("declined role");
        let text = format!(
            "{} STDERR {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let line = text
            .lines()
            .find_map(|l| l.find("DECLINED ").map(|i| &l[i..]))
            .unwrap_or_else(|| panic!("no report in {text:?}"));
        let num = |k: &str| -> u64 {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("no {k} in {line:?}"))
        };
        assert!(line.contains("declined=true"), "got {line:?}");
        assert_eq!(
            num("before"),
            stage,
            "no non-zero limit to compare: {line:?}"
        );
        assert_eq!(num("before"), num("after"), "the core limit was changed");
    }

    // -- R2 fixes ------------------------------------------------------------

    /// Role `reaper`: reap the tree of this very process with the system `ps`
    /// and report the outcome and the number of freeze passes.
    fn role_reaper() -> ! {
        // SAFETY: alarm has no preconditions.
        unsafe { libc::alarm(60) };
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        let r = reap_tree_via(&system_ps, me, false);
        println!(
            "REAP {} passes={}",
            if r.is_ok() { "ok" } else { "err" },
            LAST_PASSES.load(Ordering::Relaxed)
        );
        std::process::exit(0)
    }

    /// The listing `ps` is a child of the caller and is in its own listing: it
    /// must never count as a member of the tree, or a caller that is its own
    /// root can never settle.
    #[test]
    fn a_caller_that_is_its_own_root_settles_in_a_few_passes() {
        let out = helper_command("reaper")
            .stdin(Stdio::null())
            .output()
            .expect("reaper role");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let line = text
            .lines()
            .find_map(|l| l.find("REAP ").map(|i| &l[i..]))
            .unwrap_or_else(|| panic!("no report in {text:?}"));
        let passes: usize = line
            .split("passes=")
            .nth(1)
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("no passes in {line:?}"));
        assert!(
            line.starts_with("REAP ok"),
            "the reap did not settle: {line:?}"
        );
        assert!(passes <= 3, "too many passes: {line:?}");
    }

    /// Role `slowreaper`: a tree member, then a reap whose `ps` is real for the
    /// first run and wedged for every later one. `CSQ_S1A_ALARM` is the
    /// backstop alarm, `CSQ_S1A_FREEZE_MS` the freeze deadline.
    fn role_slow_reaper() -> ! {
        let alarm: u32 = env("CSQ_S1A_ALARM")
            .and_then(|v| v.parse().ok())
            .expect("alarm");
        let freeze_ms: u64 = env("CSQ_S1A_FREEZE_MS")
            .and_then(|v| v.parse().ok())
            .expect("freeze ms");
        let mark = env("CSQ_S1A_MARK").expect("mark");
        arm_cleanup_alarm(alarm);
        // In the role's own group, not a group of its own: a stopped member of
        // a process group the role's exit orphans is ended by the kernel
        // (SIGHUP, SIGCONT), which would hide a handler that kills nothing.
        let member = Command::new("/bin/sleep")
            .arg(&mark)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("member");
        println!("MEMBER {}", member.id());
        // SAFETY: getpid has no preconditions.
        let me = unsafe { libc::getpid() };
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let ps = || {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                system_ps()
            } else {
                let mut c = Command::new("/bin/sh");
                c.args(["-c", "exec sleep 30"]);
                c
            }
        };
        let r = reap_tree_bounded(&ps, me, false, Duration::from_millis(freeze_ms));
        println!("REAP {}", if r.is_ok() { "ok" } else { "err" });
        std::process::exit(0)
    }

    /// Run the slow reaper; returns its output, its exit code and the pid of
    /// the member it froze. The member is ended here if it survived.
    fn run_slow_reaper(alarm: u32, freeze_ms: u64) -> (String, Option<i32>, libc::pid_t, bool) {
        // A valid `sleep` operand (one dot): an invalid one would end at once and
        // leave nothing to freeze.
        let mark = format!("733.{}{alarm}", std::process::id());
        let out = helper_command("slowreaper")
            .env("CSQ_S1A_ALARM", alarm.to_string())
            .env("CSQ_S1A_FREEZE_MS", freeze_ms.to_string())
            .env("CSQ_S1A_MARK", &mark)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("slowreaper role");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let member: libc::pid_t = text
            .lines()
            .find_map(|l| {
                l.find("MEMBER ")
                    .and_then(|i| l[i + 7..].trim().parse().ok())
            })
            .unwrap_or_else(|| panic!("no member pid in {text:?}"));
        let gone = wait_gone(member);
        if !gone {
            // Still there means still the fixture (the wait is bounded well
            // inside pid reuse); a stopped process needs the CONT to die.
            kill_pid(member, libc::SIGKILL);
            kill_pid(member, libc::SIGCONT);
        }
        (text, out.status.code(), member, gone)
    }

    /// A wedged `ps` must not keep the freeze from ending: the deadline is
    /// reached well inside the alarm, so the role itself kills what it froze
    /// and reports (exit 0, not the alarm's 137).
    #[test]
    fn a_wedged_listing_still_reaches_the_kill_phase_inside_the_alarm() {
        let (text, code, member, gone) = run_slow_reaper(8, 1000);
        assert!(gone, "member {member} stayed behind (stopped?): {text:?}");
        assert!(
            text.contains("REAP err") && code == Some(0),
            "the kill phase was not reached by the role itself: code {code:?} {text:?}"
        );
    }

    /// With a freeze deadline far beyond the alarm, the alarm's handler is the
    /// only thing between a stopped member and a stopped survivor: it kills
    /// every frozen pid before it ends the role.
    #[test]
    fn the_cleanup_alarm_kills_what_the_freeze_stopped() {
        let (text, code, member, gone) = run_slow_reaper(3, 60_000);
        assert!(
            gone,
            "member {member} survived the alarm (stopped?): {text:?}"
        );
        assert_eq!(
            code,
            Some(137),
            "the alarm handler did not end the role: {text:?}"
        );
    }

    /// Injected credentials: leftover supplementary groups and inheritable
    /// capabilities each refuse the drop, on both OS families.
    #[test]
    fn the_drop_verification_refuses_leftover_groups_and_inheritable_capabilities() {
        let ok = dropped_state(1000, 1000);
        for linux in [true, false] {
            assert_eq!(
                verify_dropped_for(linux, Some(1000), Some(1000), &ok),
                Ok(())
            );
        }
        let with = |f: &dyn Fn(&mut DropState)| {
            let mut s = ok;
            f(&mut s);
            s
        };
        let check =
            |linux: bool, s: &DropState| verify_dropped_for(linux, Some(1000), Some(1000), s);
        let one_other = with(&|s| {
            s.ngroups = 1;
            s.group0 = 4
        });
        let two = with(&|s| s.ngroups = 2);
        let unreadable = with(&|s| s.ngroups = -1);
        for linux in [true, false] {
            assert_eq!(check(linux, &one_other), Err(DropMismatch::Groups));
            assert_eq!(check(linux, &two), Err(DropMismatch::Groups));
            assert_eq!(check(linux, &unreadable), Err(DropMismatch::Groups));
            let inh = with(&|s| s.cap_inheritable = 1 << 6);
            assert_eq!(check(linux, &inh), Err(DropMismatch::Capabilities));
        }
        // macOS lists the effective gid; Linux lists nothing at all.
        let only_egid = with(&|s| {
            s.ngroups = 1;
            s.group0 = 1000
        });
        assert_eq!(check(true, &only_egid), Err(DropMismatch::Groups));
        assert_eq!(check(false, &only_egid), Ok(()));
    }

    /// The real read of the credentials reports groups and inheritable
    /// capabilities (neither unreadable).
    #[test]
    fn the_real_credential_read_reports_groups_and_inheritable_capabilities() {
        // SAFETY: plain syscalls on this process.
        let s = unsafe { read_drop_state(false) };
        assert!(s.ngroups >= 0, "getgroups unreadable: {}", s.ngroups);
        assert_ne!(s.cap_inheritable, u64::MAX, "capget unreadable");
    }

    /// An identity launch never falls back to an unrelayed launch, whatever
    /// the failure (including a truncated status from the shim); a plain one
    /// still may.
    #[test]
    fn an_identity_launch_never_permits_the_unrelayed_fallback() {
        let plain = LaunchSpec::new("/bin/true");
        let uid_only = LaunchSpec::new("/bin/true").uid(1000);
        let gid_only = LaunchSpec::new("/bin/true").gid(1000);
        let both = LaunchSpec::new("/bin/true").uid(1000).gid(1000);
        // A status cut short decodes to a plain failure (never a drop step).
        let truncated = SpawnFailure::from(io::Error::from_raw_os_error(
            decode_startup_failure(&[TAG_SETUID, 1, 0, 0, 0], 3).0,
        ))
        .into_relay_error();
        let errors = [
            truncated,
            RelayError::NotStarted {
                op: "spawn",
                errno: libc::EAGAIN,
            },
            RelayError::Busy,
            RelayError::Declined(Decline::Background),
        ];
        for e in &errors {
            assert!(
                e.may_launch_unrelayed(&plain),
                "{e:?} must allow a plain launch"
            );
            for spec in [&uid_only, &gid_only, &both] {
                assert!(
                    !e.may_launch_unrelayed(spec),
                    "{e:?} must never allow an identity launch to fall back"
                );
            }
        }
    }

    /// A failure after the CLI has exec'ed is a started child, and the child
    /// is ended.
    #[test]
    fn a_failed_nonblocking_after_the_exec_is_a_started_child() {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep");
        let pid = child.id() as libc::pid_t;
        // The pid is reaped by `finish_spawn`; the handle must not wait again.
        std::mem::forget(child);
        let (up, _w) = nonblocking_pipe();
        let (_r, ctl) = nonblocking_pipe();
        let failing = |_fd: RawFd| Err(io::Error::from_raw_os_error(libc::EMFILE));
        let failure = finish_spawn(pid, up, ctl, &failing)
            .err()
            .expect("must fail");
        let err = failure.into_relay_error();
        assert_eq!(
            err,
            RelayError::ChildStarted {
                op: "fcntl",
                errno: libc::EMFILE
            }
        );
        assert!(err.child_started());
        // SAFETY: signal 0 only probes.
        let rc = unsafe { libc::kill(pid, 0) };
        assert_eq!(rc, -1, "the child was not ended");
    }

    /// What the drain reads goes into the queue, and the foreground check runs
    /// before anything is written: a relay that lost the foreground between the
    /// read and the write writes nothing.
    #[test]
    fn drain_writes_nothing_after_it_loses_the_foreground() {
        let pty = Pty::open(None, None).expect("pty");
        set_nonblock(pty.master.as_raw_fd()).unwrap();
        write_fd(pty.slave.as_raw_fd(), b"left-over").unwrap();
        let (r, w) = nonblocking_pipe();
        set_nonblock(r.as_raw_fd()).unwrap();
        let mut out = OutQueue::over(w);
        let calls = std::cell::Cell::new(0);
        let may_write = || {
            calls.set(calls.get() + 1);
            calls.get() == 1
        };
        let mut buf = [0u8; 64];
        drain_master(
            pty.master.as_raw_fd(),
            &mut out,
            Duration::from_millis(300),
            &mut buf,
            &may_write,
        );
        assert!(calls.get() >= 2, "the foreground was checked once only");
        let mut got = [0u8; 64];
        let err = read_fd(r.as_raw_fd(), &mut got).expect_err("nothing may be written");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    fn proc_row(pid: libc::pid_t, stat: &str, start: &str, command: &str) -> Proc {
        Proc {
            row: (pid, 1, pid),
            stat: stat.to_string(),
            start: start.to_string(),
            command: command.to_string(),
        }
    }

    const T0: &str = "Thu Oct 15 15:37:53 2026";
    const T1: &str = "Thu Oct 15 15:38:01 2026";

    /// A remembered process is the same process by pid and start time: its
    /// command line may change under `exec`, a reused pid never has the same
    /// start.
    #[test]
    fn a_remembered_process_is_identified_by_its_start_time() {
        let seen = Seen {
            pid: 10,
            pgid: 10,
            start: T0.to_string(),
        };
        let execd = [proc_row(10, "S", T0, "/bin/other --after-exec")];
        assert!(
            still_remembered(&seen, &execd),
            "an exec changes the command only"
        );
        let reused = [proc_row(10, "S", T1, "sleep 733")];
        assert!(
            !still_remembered(&seen, &reused),
            "a reused pid is another process"
        );
        let zombie = [proc_row(10, "Z", T0, "")];
        assert!(
            !still_remembered(&seen, &zombie),
            "a zombie is not signalled again"
        );
        assert!(!still_remembered(&seen, &[]));
    }

    /// The sentinel's live walk happens only for the process its root was.
    #[test]
    fn the_sentinel_re_identifies_its_root_before_the_live_walk() {
        let id = Identity {
            start: T0.to_string(),
            command: "csq helper_main".to_string(),
        };
        assert!(root_still_is(
            &id,
            &[proc_row(7, "S", T0, "csq helper_main")],
            7
        ));
        assert!(
            !root_still_is(&id, &[proc_row(7, "S", T1, "csq helper_main")], 7),
            "same pid, later start: reused"
        );
        assert!(
            !root_still_is(&id, &[proc_row(7, "S", T0, "/bin/other")], 7),
            "same pid and start, other command"
        );
        assert!(!root_still_is(&id, &[proc_row(7, "Z", T0, "")], 7));
        assert!(!root_still_is(&id, &[], 7));
    }

    /// The full listing carries the start time (five words) and the command,
    /// and never the listing process itself.
    #[test]
    fn the_full_listing_parses_start_time_and_command_without_the_listing_process() {
        let text =
            format!("  12 1 12 Ss {T0} sh -c foo bar\n  99 12 12 R {T1} ps -A\n  bad line\n");
        let procs = parse_ps_full(&text, 99);
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].row, (12, 1, 12));
        assert_eq!(procs[0].start, T0);
        assert_eq!(procs[0].command, "sh -c foo bar");
    }

    /// A reap refuses a root it must never signal and lists nothing for it.
    #[test]
    fn a_reap_refuses_a_root_of_one_or_less() {
        let called = std::cell::Cell::new(false);
        let ps = || {
            called.set(true);
            Command::new("/nonexistent/ps-s1a")
        };
        for root in [1, 0, -5] {
            assert!(reap_tree_via(&ps, root, false).is_err(), "root {root}");
        }
        assert!(!called.get(), "a refused root was listed anyway");
    }

    /// A `ps` that fails is not "the process is gone".
    #[test]
    fn a_failing_ps_is_never_read_as_gone() {
        let failing = |_p: libc::pid_t| Err::<String, String>("ps failed".to_string());
        assert!(!wait_gone_via(1, &failing, Duration::from_millis(300)));
        assert!(wait_gone_via(
            1,
            &|_| Ok(String::new()),
            Duration::from_millis(300)
        ));
        assert!(wait_gone_via(
            1,
            &|_| Ok("Z+".into()),
            Duration::from_millis(300)
        ));
        assert!(!wait_gone_via(
            1,
            &|_| Ok("S".into()),
            Duration::from_millis(300)
        ));
    }

    /// A pipe that cannot be made non-blocking is an error at once, not a read
    /// that outlives the deadline.
    #[test]
    fn a_listing_pipe_that_stays_blocking_is_an_error() {
        let mut c = Command::new("/bin/sleep");
        c.arg("8");
        let began = Instant::now();
        let r = run_bounded_with(c, Duration::from_secs(2), &[0], &|_| {
            Err(io::Error::from_raw_os_error(libc::EIO))
        });
        assert!(r.is_err(), "a blocking pipe was accepted");
        assert!(
            began.elapsed() < Duration::from_secs(4),
            "the run was not cut short"
        );
    }

    /// The announced relay of a dead shell role (reparented to init) is still
    /// ours to end; another process, another parent or another command is not.
    #[test]
    fn an_announced_relay_is_ours_whether_or_not_its_shell_role_is_alive() {
        let cmd = Some("/x/csq relay::pty::tests::helper_main --nocapture");
        assert!(
            announced_relay_is_ours(Some(50), Some(50), cmd),
            "alive shell"
        );
        assert!(
            announced_relay_is_ours(Some(50), Some(1), cmd),
            "dead shell, reparented"
        );
        assert!(
            !announced_relay_is_ours(Some(50), Some(77), cmd),
            "someone else's child"
        );
        assert!(!announced_relay_is_ours(
            Some(50),
            Some(50),
            Some("/bin/sleep 1")
        ));
        assert!(!announced_relay_is_ours(Some(50), Some(1), None));
        assert!(!announced_relay_is_ours(None, Some(1), cmd));
    }

    /// A hung-up terminal leaves nothing the output announced behind.
    #[test]
    fn a_hung_up_terminal_leaves_no_announced_process_behind() {
        let (relay, child) = {
            let mut o = Outer::start(JOB_SCRIPT, &[]);
            o.wait_for("READY");
            let relay = o.announced("R-PID ").last().copied().expect("relay pid");
            let child = o.announced("CHILD=").last().copied().expect("child pid");
            o.hang_up();
            (relay, child)
        };
        assert!(
            wait_gone(relay),
            "the relay {relay} outlived the hung-up terminal"
        );
        assert!(
            wait_gone(child),
            "the child {child} outlived the hung-up terminal"
        );
    }

    /// The sentinel is the only tracker: at most four `ps` runs a second.
    #[test]
    fn the_sentinel_lists_processes_at_most_four_times_a_second() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = "/bin/ps";
        assert!(Path::new(real).exists(), "no {real}");
        let wrapper = dir.path().join("ps");
        let log = dir.path().join("ps.log");
        std::fs::write(
            &wrapper,
            format!("#!/bin/sh\necho x >> \"$CSQ_S1A_PSLOG\"\nexec {real} \"$@\"\n"),
        )
        .expect("wrapper");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
        }
        // A script just written can be refused with ETXTBSY while a fork
        // elsewhere in this process still holds the write end: retry.
        let mut runnable = false;
        for _ in 0..100 {
            if Command::new(&wrapper)
                .env("CSQ_S1A_PSLOG", &log)
                .args(["-p", "1"])
                .output()
                .is_ok()
            {
                runnable = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(runnable, "the ps wrapper never became runnable");
        let _ = std::fs::remove_file(&log);
        let mut sentinel = helper_command("sentinel")
            .env("CSQ_S1A_PS", &wrapper)
            .env("CSQ_S1A_PSLOG", &log)
            .env("CSQ_S1A_WATCH_ROOT", std::process::id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sentinel");
        std::thread::sleep(Duration::from_secs(4));
        let _ = sentinel.kill();
        let _ = sentinel.wait();
        let runs = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .count();
        assert!(runs >= 2, "the sentinel never listed processes: {runs}");
        assert!(runs <= 18, "{runs} ps runs in 4 s: more than four a second");
    }
}
