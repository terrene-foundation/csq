//! Terminal primitives for the PTY relay (spec 34 §34.2.1 (a), (c), (f)).
//!
//! Everything here is a thin, testable wrapper over one terminal fact:
//! whether the relay may run at all ([`precondition`]), the raw-mode guard
//! that puts the outer terminal back on every return path ([`RawGuard`]),
//! and window-size transfer ([`get_winsize`], [`set_winsize`]).
//!
//! Failure policy: a question the kernel cannot answer is answered
//! "no" (fail closed). `tcgetpgrp` returning `-1` means "not provably the
//! foreground group", so the relay declines rather than assuming.

// The terminal restore on a panic is `RawGuard`'s `Drop`, which only runs when
// the panic unwinds. An aborting profile would silently remove that restore.
#[cfg(panic = "abort")]
compile_error!(
    "the PTY relay restores the terminal on panic by unwinding; build with panic = \"unwind\""
);

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;

/// The outer terminal's three standard streams, in the order the relay
/// checks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// File descriptor 0.
    Stdin,
    /// File descriptor 1.
    Stdout,
    /// File descriptor 2.
    Stderr,
}

/// Why the relay declined to start (spec 34 §34.2.1: launch is then
/// unchanged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decline {
    /// The named stream is not a terminal.
    NotTty(Stream),
    /// The process is not provably in the foreground process group of its
    /// terminal (`tcgetpgrp(stdin) != getpgrp()`, or the call failed).
    Background,
}

/// Whether `fd` refers to a terminal.
pub fn is_tty(fd: RawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// Whether this process is in the foreground process group of the terminal
/// open on `fd`. `false` on any error (fail closed).
pub fn is_foreground(fd: RawFd) -> bool {
    // SAFETY: both calls only read kernel state.
    let fg = unsafe { libc::tcgetpgrp(fd) };
    fg != -1 && fg == unsafe { libc::getpgrp() }
}

/// Whether the terminal open on `fd` is gone (hung up or no longer a
/// terminal). Two signals, because the OSes differ: Linux fails `tcgetpgrp`
/// on a hung-up terminal (`ENOTTY`, `EIO`, `ENXIO`, `EBADF`), while macOS keeps
/// answering it and reports the hang-up only through `poll` (`POLLHUP`, or
/// `POLLNVAL` for a closed descriptor). Any other error, and a quiet `poll`,
/// is "not known to be lost".
pub fn tty_lost(fd: RawFd) -> bool {
    // SAFETY: reads kernel state; errno is read immediately after.
    let by_errno = unsafe {
        libc::tcgetpgrp(fd) == -1
            && matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOTTY) | Some(libc::EIO) | Some(libc::ENXIO) | Some(libc::EBADF)
            )
    };
    if by_errno {
        return true;
    }
    // POLLIN is requested on purpose: a hung-up macOS terminal was measured
    // reporting POLLIN|POLLHUP to a poll that asked for POLLIN. Only HUP and
    // NVAL are read, so queued input never reads as a lost terminal, and
    // nothing is consumed.
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd, zero timeout (never blocks).
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    n > 0 && p.revents & (libc::POLLHUP | libc::POLLNVAL) != 0
}

/// The relay start precondition (spec 34 §34.2.1): stdin, stdout and stderr
/// are all terminals AND this process is in the foreground process group.
pub fn precondition(stdin: RawFd, stdout: RawFd, stderr: RawFd) -> Result<(), Decline> {
    for (fd, stream) in [
        (stdin, Stream::Stdin),
        (stdout, Stream::Stdout),
        (stderr, Stream::Stderr),
    ] {
        if !is_tty(fd) {
            return Err(Decline::NotTty(stream));
        }
    }
    if is_foreground(stdin) {
        Ok(())
    } else {
        Err(Decline::Background)
    }
}

/// Read the terminal attributes of `fd`.
pub fn get_termios(fd: RawFd) -> io::Result<libc::termios> {
    let mut t = MaybeUninit::<libc::termios>::zeroed();
    // SAFETY: `t` is a valid out-pointer; tcgetattr fully initialises it on 0.
    if unsafe { libc::tcgetattr(fd, t.as_mut_ptr()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: tcgetattr returned success.
    Ok(unsafe { t.assume_init() })
}

fn apply_termios(fd: RawFd, t: &libc::termios) -> io::Result<()> {
    loop {
        // SAFETY: `t` is a valid termios for the call's duration.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, t) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// Run `f` with `SIGTTOU` blocked on this thread, then restore the mask.
fn with_sigttou_blocked<T>(f: impl FnOnce() -> T) -> T {
    // SAFETY: plain sigset manipulation on stack storage.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTTOU);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
        let out = f();
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        out
    }
}

/// Read the window size of the terminal open on `fd`.
pub fn get_winsize(fd: RawFd) -> io::Result<libc::winsize> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `ws` is a valid out-pointer for TIOCGWINSZ.
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ as _, &mut ws) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(ws)
}

/// Set the window size of the terminal open on `fd` (the master of a PTY
/// delivers `SIGWINCH` to the slave's foreground group).
pub fn set_winsize(fd: RawFd, ws: &libc::winsize) -> io::Result<()> {
    // SAFETY: `ws` is a valid in-pointer for TIOCSWINSZ.
    if unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, ws) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Raw-mode guard for the outer terminal (spec 34 §34.2.1 (a)).
///
/// [`RawGuard::enter`] saves the terminal's attributes and switches it to
/// raw mode; [`RawGuard::restore`] and `Drop` put the saved attributes back,
/// which covers the normal return, error returns and panic unwinding. A
/// `SIGKILL` of the process cannot run `Drop` (spec 34 §34.2.1 names the
/// guardian and the next-launch marker, shard S1d, for that case).
///
/// The guard does not own `fd`; the caller keeps it open for the guard's
/// lifetime.
#[derive(Debug)]
pub struct RawGuard {
    fd: RawFd,
    saved: libc::termios,
    raw: libc::termios,
    active: bool,
}

impl RawGuard {
    /// Save the attributes of `fd` and enter raw mode.
    pub fn enter(fd: RawFd) -> io::Result<Self> {
        let saved = get_termios(fd)?;
        let mut raw = saved;
        // SAFETY: `raw` is a valid termios.
        unsafe { libc::cfmakeraw(&mut raw) };
        let mut guard = RawGuard {
            fd,
            saved,
            raw,
            active: false,
        };
        // Raw only when something was applied (from the background nothing is).
        guard.active = guard.set(&guard.raw)?;
        Ok(guard)
    }

    /// The attributes in force before [`RawGuard::enter`].
    pub fn saved(&self) -> &libc::termios {
        &self.saved
    }

    /// Whether raw mode is currently applied by this guard.
    pub fn is_raw(&self) -> bool {
        self.active
    }

    /// Put the saved attributes back. Idempotent.
    pub fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        // Still raw when nothing was applied (called from the background):
        // the guard keeps the duty, so its drop tries again and `is_raw`
        // tells the truth.
        if self.set(&self.saved)? {
            self.active = false;
        }
        Ok(())
    }

    /// Re-apply raw mode after a [`RawGuard::restore`] (job-control resume).
    pub fn reenter(&mut self) -> io::Result<()> {
        if self.active {
            return Ok(());
        }
        if self.set(&self.raw)? {
            self.active = true;
        }
        Ok(())
    }

    /// `tcsetattr` with `SIGTTOU` blocked ONLY while this process is in the
    /// foreground (spec 34 §34.2.1 (f)). From the background nothing is
    /// changed at all. Returns whether the attributes were applied.
    fn set(&self, t: &libc::termios) -> io::Result<bool> {
        if is_foreground(self.fd) {
            with_sigttou_blocked(|| apply_termios(self.fd, t)).map(|()| true)
        } else {
            // A background process never changes the terminal: the relay
            // handles SIGTTOU itself (an outside one stops it like a job),
            // so the old "let the kernel stop the call" is not available, and
            // the terminal then belongs to whoever is in the foreground.
            Ok(false)
        }
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            tracing::warn!(
                error_kind = "termios_restore_failed",
                errno = e.raw_os_error().unwrap_or(0),
                "terminal restore failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// The calling thread's errno slot.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn errno_slot() -> *mut libc::c_int {
        // SAFETY: returns the thread's own errno slot.
        unsafe { libc::__errno_location() }
    }

    /// The calling thread's errno slot.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn errno_slot() -> *mut libc::c_int {
        // SAFETY: returns the thread's own errno slot.
        unsafe { libc::__error() }
    }

    fn pipe_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: valid 2-element out array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: pipe returned two fresh descriptors we now own.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    #[test]
    fn precondition_names_the_first_non_tty_stream() {
        let (r, w) = pipe_pair();
        let (r, w) = (r.as_raw_fd(), w.as_raw_fd());
        assert_eq!(precondition(r, w, w), Err(Decline::NotTty(Stream::Stdin)));
        assert_eq!(precondition(r, r, r), Err(Decline::NotTty(Stream::Stdin)));
    }

    #[test]
    fn precondition_declines_when_only_stdout_or_stderr_is_not_a_tty() {
        // One real terminal slave plus a pipe in each non-stdin position.
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: valid out-pointers; null name/termios/winsize are allowed.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: openpty returned two fresh descriptors we now own.
        let (_m, s) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let (_r, w) = pipe_pair();
        let (s, w) = (s.as_raw_fd(), w.as_raw_fd());
        assert_eq!(precondition(s, w, s), Err(Decline::NotTty(Stream::Stdout)));
        assert_eq!(precondition(s, s, w), Err(Decline::NotTty(Stream::Stderr)));
    }

    #[test]
    fn invalid_descriptor_is_not_foreground() {
        assert!(!is_foreground(-1));
        assert!(!is_tty(-1));
    }

    /// A terminal whose master end is closed is lost on every OS: Linux fails
    /// `tcgetpgrp`, macOS only reports `POLLHUP`. A live one is not lost.
    ///
    /// The whole check runs in a forked judge that opens its OWN pty, makes the
    /// slave its controlling terminal (as the relay's stdin is: `tcgetpgrp`
    /// answers `ENOTTY` for any other terminal, so a live slave would read as
    /// lost) and ignores the SIGHUP its own hang-up sends the session leader.
    /// The judge opens the pty after the fork because a master opened before
    /// it is copied into every other test's concurrent `fork`, and the slave
    /// is then never hung up while that copy lives (observed in the full
    /// suite, where this test passed alone and failed in parallel).
    #[test]
    fn a_terminal_is_lost_once_its_master_end_closes() {
        let mut rep = [0 as libc::c_int; 2];
        // SAFETY: valid 2-element out array.
        assert_eq!(unsafe { libc::pipe(rep.as_mut_ptr()) }, 0);
        let report = rep[1];
        // SAFETY: the judge uses only system calls and `tty_lost` (tcgetpgrp,
        // poll, an errno read) and ends with `_exit`.
        let judge = unsafe { libc::fork() };
        assert!(judge >= 0, "fork");
        if judge == 0 {
            // SAFETY: as above.
            unsafe {
                // A hung judge dies of SIGALRM; the parent reports it.
                libc::alarm(60);
                // The judge is the session leader of the terminal it is about
                // to hang up: the kernel would send it SIGHUP (wait status 0x1
                // is that signal, not exit code 1).
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                let mut master = -1;
                let mut slave = -1;
                if libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                ) != 0
                    || libc::setsid() == -1
                    || libc::ioctl(slave, libc::TIOCSCTTY as _, 0) == -1
                {
                    libc::_exit(10);
                }
                // Every result is reported; the parent judges them. A live
                // slave first (and what its two raw probes saw), then the
                // same slave once the last master is closed, then a pipe.
                let pgrp = libc::tcgetpgrp(slave);
                let errno = *errno_slot();
                let mut p = libc::pollfd {
                    fd: slave,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let n = libc::poll(&mut p, 1, 0);
                let live = tty_lost(slave) as libc::c_int;
                libc::close(master);
                let hung = tty_lost(slave) as libc::c_int;
                let mut pp = [0 as libc::c_int; 2];
                if libc::pipe(pp.as_mut_ptr()) != 0 {
                    libc::_exit(10);
                }
                let pipe = tty_lost(pp[0]) as libc::c_int;
                let detail = [pgrp, errno, n, p.revents as libc::c_int, live, hung, pipe];
                let put = libc::write(
                    report,
                    detail.as_ptr().cast(),
                    std::mem::size_of_val(&detail),
                );
                libc::_exit(if put == std::mem::size_of_val(&detail) as isize {
                    0
                } else {
                    11
                });
            }
        }
        let mut st: libc::c_int = 0;
        // SAFETY: valid out-pointer; `judge` is our child.
        assert_eq!(unsafe { libc::waitpid(judge, &mut st, 0) }, judge);
        let mut detail = [-1 as libc::c_int; 7];
        // SAFETY: closing our copy of the write end, then one read into a
        // buffer of the stated size (EOF with nothing written reads 0).
        let got = unsafe {
            libc::close(report);
            libc::read(
                rep[0],
                detail.as_mut_ptr().cast(),
                std::mem::size_of_val(&detail),
            )
        };
        // SAFETY: closing the read end opened above.
        unsafe { libc::close(rep[0]) };
        let [pgrp, errno, polled, revents, live, hung, pipe] = detail;
        let seen = format!(
            "judge status {st:#x} ({got} bytes); raw live probes: tcgetpgrp={pgrp} errno={errno} \
             poll={polled} revents={revents:#x}"
        );
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "{seen}");
        assert_eq!(live, 0, "a live terminal was lost; {seen}");
        assert_eq!(hung, 1, "a hung-up terminal was not lost; {seen}");
        assert_eq!(pipe, 1, "a non-terminal was not lost (ENOTTY); {seen}");
    }

    /// Entering from the background applies nothing, so the guard must not
    /// claim to be raw.
    #[test]
    fn entering_from_the_background_does_not_claim_raw() {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: valid out-pointers; null name/termios/winsize.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty");
        // SAFETY: openpty returned two fresh descriptors we now own.
        let (_master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let fd = slave.as_raw_fd();
        assert!(!is_foreground(fd));
        let guard = RawGuard::enter(fd).expect("enter");
        assert!(!guard.is_raw(), "nothing was applied, yet the guard is raw");
    }

    /// From the background nothing is applied, so the guard must stay raw: a
    /// restore that applied nothing must not clear the duty to restore.
    #[test]
    fn a_background_restore_applies_nothing_and_keeps_the_guard_raw() {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: valid out-pointers; null name/termios/winsize.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 0, "openpty");
        // SAFETY: openpty returned two fresh descriptors we now own.
        let (_master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let fd = slave.as_raw_fd();
        // This test process has no controlling terminal on the slave, so it is
        // never "the foreground job" of it.
        assert!(!is_foreground(fd));
        let saved = get_termios(fd).expect("termios");
        let mut raw = saved;
        // SAFETY: a valid termios.
        unsafe { libc::cfmakeraw(&mut raw) };
        let mut guard = RawGuard {
            fd,
            saved,
            raw,
            active: true,
        };
        guard.restore().expect("restore");
        assert!(
            guard.is_raw(),
            "a restore that applied nothing cleared the duty"
        );
        guard.active = false;
    }
}
