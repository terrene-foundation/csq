//! Test-only harness: a forked child that holds duplicates of every
//! descriptor open at fork time and blocks WITHOUT exec'ing.
//!
//! POSIX `flock` is bound to the open file description and is released only
//! by an explicit `LOCK_UN` on any duplicate or by closing EVERY descriptor
//! to it (`flock(2)`). A fork from any thread of a test binary therefore
//! keeps a lock alive past the holder's own close, until the child execs
//! (`FD_CLOEXEC`) or exits. This harness freezes that window deterministically
//! so a lock's `Drop` can be asserted to be the release point.
//!
//! Orphan bounds (the fleet-offline class):
//!
//! - The child closes the pipe's WRITE end before blocking, so a parent
//!   that dies without releasing it delivers EOF and the child exits
//!   instead of parking on its own descriptor.
//! - The child arms `SIGALRM` as a hard backstop (the same hung-child
//!   pattern as `relay::term`'s judge). The child first resets SIGALRM to
//!   `SIG_DFL` and UNBLOCKS it, so a handler or mask inherited from the
//!   test process (e.g. `relay::pty`'s `SA_RESTART` handler) cannot neuter
//!   the backstop; a child orphaned by a hard-killed test process is then
//!   bounded by the 60s alarm.
//! - The parent's release is RAII: a panic between the fork and the normal
//!   release path still wakes, closes, and reaps the child (EINTR-retried),
//!   so an assertion failure does not orphan a process holding the
//!   harness's descriptors.
//!
//! Only async-signal-safe calls run between `fork` and `_exit` in the child.

/// Backstop for a child whose parent never releases it (a hard-killed test
/// process, not a panicking one — a panic unwinds through `Drop`).
const CHILD_BACKSTOP_SECS: libc::c_uint = 60;

/// A forked child parked on a pipe read, holding its inherited descriptors.
/// Released and reaped by [`ForkedChild::release`] or `Drop`, idempotently.
pub(crate) struct ForkedChild {
    pid: libc::pid_t,
    write_fd: libc::c_int,
}

impl ForkedChild {
    /// Fork a child that inherits the caller's descriptors and then blocks
    /// on a pipe read until released (or until EOF from a dead parent, or
    /// the 60s alarm backstop).
    pub(crate) fn spawn() -> Self {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a valid two-element out-array for pipe(2).
        assert_eq!(
            unsafe { libc::pipe(fds.as_mut_ptr()) },
            0,
            "fork_harness: pipe failed"
        );
        let (read_fd, write_fd) = (fds[0], fds[1]);
        // Close-on-exec on BOTH ends: a parallel `Command::spawn` from another
        // test thread forks this process, and without FD_CLOEXEC the spawned
        // binary would inherit these descriptors (the read end would then keep
        // the pipe open past the harness's own calls).
        for fd in [read_fd, write_fd] {
            // SAFETY: `fd` is one of the pipe descriptors just created; F_SETFD
            // updates descriptor flags and touches no memory.
            let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
            if rc == -1 {
                // SAFETY: closing our own two descriptors once before failing.
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
                panic!("fork_harness: FD_CLOEXEC on the pipe failed");
            }
        }
        // SAFETY: the child executes ONLY async-signal-safe syscalls (close,
        // signal, sigemptyset, sigaddset, sigprocmask, alarm, read, _exit)
        // before _exit — no allocation, no locks, no Rust runtime state.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            // SAFETY: closing our own two descriptors once before failing.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            panic!("fork_harness: fork failed");
        }
        if pid == 0 {
            // SAFETY: as above. Closing the write end FIRST is the orphan
            // guard: a parent that dies without writing delivers EOF here.
            // SIGALRM is then restored to the default action and UNBLOCKED,
            // so an inherited handler/mask cannot swallow the backstop.
            unsafe {
                libc::close(write_fd);
                libc::signal(libc::SIGALRM, libc::SIG_DFL);
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGALRM);
                libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
                libc::alarm(CHILD_BACKSTOP_SECS);
                let mut byte = 0u8;
                libc::read(read_fd, &mut byte as *mut u8 as *mut libc::c_void, 1);
                libc::_exit(0);
            }
        }
        // SAFETY: the child has its own descriptor for the read end; the
        // parent never reads.
        unsafe {
            libc::close(read_fd);
        }
        Self { pid, write_fd }
    }

    /// The child's PID, for liveness assertions after a release.
    pub(crate) fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Wake the child (one byte, EINTR-retried), close the write end, and
    /// reap it (EINTR-retried). Idempotent; safe to call on the unwind path.
    pub(crate) fn release(&mut self) {
        if self.write_fd >= 0 {
            // Rust ignores SIGPIPE by default, so a child that already
            // exited yields EPIPE here instead of killing the test process.
            loop {
                // SAFETY: `write_fd` is an open pipe descriptor owned by
                // this struct; a one-byte write touches no Rust memory.
                let rc =
                    unsafe { libc::write(self.write_fd, b"x".as_ptr() as *const libc::c_void, 1) };
                if rc >= 0 {
                    break;
                }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            // SAFETY: closing our own descriptor once.
            unsafe {
                libc::close(self.write_fd);
            }
            self.write_fd = -1;
        }
        if self.pid > 0 {
            let mut status = 0 as libc::c_int;
            loop {
                // SAFETY: `pid` is the exact child forked above; `status`
                // is a valid out-pointer; waitpid touches no Rust memory.
                let rc = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if rc >= 0 {
                    break;
                }
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    break;
                }
            }
            self.pid = 0;
        }
    }
}

impl Drop for ForkedChild {
    fn drop(&mut self) {
        self.release();
    }
}
