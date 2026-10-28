//! Bounded ownership of test subprocesses. Unix groups are signalled only while
//! a fresh WNOWAIT probe shows their unreaped leader is still ours, and nothing
//! is spawned at all under a SIGCHLD disposition that would auto-reap children.
//! Windows has leader-only cleanup.
use std::io::{self, Read, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::time::{Duration, Instant};

pub const RUN_ENV_MARKERS: [&str; 2] = ["CSQ_TEST_RUN_ID", "TRESTLE_RUN_ID"];
pub const LIFELINE_FD_ENV: &str = "CSQ_TEST_LIFELINE_FD";
const GROUP_KILL_BOUND: Duration = Duration::from_secs(2);
const TICK: Duration = Duration::from_millis(20);
/// Enforced wait between a group's SIGTERM and the first SIGKILL.
#[cfg(unix)]
const TERM_GRACE: Duration = Duration::from_millis(200);
/// Maximum retained bytes per output stream; excess bytes are drained/discarded.
pub const OUTPUT_CAP: usize = 1024 * 1024;

/// Read the process disposition without changing it. SIG_IGN or SA_NOCLDWAIT --
/// both survive exec -- has the kernel reap this process's children
/// automatically, so a just-exited child's pid (its process-group id) can be
/// reassigned before any teardown proof runs. Nothing may be spawned then.
/// Same shape as the sibling copies in wake.rs, gate/legacy.rs and
/// session/shared_state.rs, each module keeping its own.
#[cfg(unix)]
fn child_wait_policy_safe() -> bool {
    // SAFETY: sigaction writes the initialized plain-data result; a null second
    // argument queries only and never installs a handler or changes signal policy.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) == 0
            && action.sa_sigaction != libc::SIG_IGN
            && action.sa_flags & libc::SA_NOCLDWAIT == 0
    }
}

/// What a fresh `waitid(WNOWAIT | WNOHANG)` says about an unreaped child.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitState {
    /// Alive and still our child: `waitid` succeeded with no pid in the result.
    Running,
    /// Exited and still our zombie: unreaped, so its pid (the group id) cannot
    /// be reassigned until [`Child::wait`].
    ExitedUnreaped,
    /// `waitid` failed: the pid is not our child any more (reaped elsewhere,
    /// possibly recycled). An EINTR or any other failure reads the same way, so
    /// every group signal is gated on a POSITIVE probe, never on an assumption.
    Gone,
}

/// Probe the child without blocking and without reaping it.
#[cfg(unix)]
fn child_wait_state(child: &Child) -> WaitState {
    let pid = libc::id_t::from(child.id());
    // SAFETY: `siginfo_t` is plain data for which all-zero is valid; `waitid`
    // writes only into it, and `WNOHANG | WNOWAIT` neither blocks nor reaps.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let result = libc::waitid(
            libc::P_PID,
            pid,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        );
        if result == -1 {
            return WaitState::Gone;
        }
        #[cfg(target_os = "macos")]
        let who = info.si_pid;
        #[cfg(not(target_os = "macos"))]
        let who = info.si_pid();
        if who != 0 {
            WaitState::ExitedUnreaped
        } else {
            WaitState::Running
        }
    }
}

/// Preserve only valid inherited markers. This never creates a run identity.
pub fn apply_run_env(cmd: &mut Command) {
    for key in RUN_ENV_MARKERS {
        cmd.env_remove(key);
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                cmd.env(key, value);
            }
        }
    }
}

#[derive(Debug)]
pub enum Finish {
    Exited(ExitStatus),
    TimedOut,
    Unconfirmed,
}

#[derive(Debug)]
pub struct GuardedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Owns the child, its newly created process group and the lifeline writer.
/// No raw child or ownership-disarming accessor is provided.
pub struct TestChild {
    child: Child,
    pgid: u32,
    #[cfg(unix)]
    lifeline: Option<std::io::PipeWriter>,
    done: bool,
}

impl TestChild {
    pub fn spawn(cmd: &mut Command) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let context = linux_spawn_record::Context::from_parent_env()?;
        let owned = Self::spawn_owned(cmd)?;
        #[cfg(target_os = "linux")]
        {
            owned.publish_record(context)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(owned)
        }
    }

    #[cfg(target_os = "linux")]
    fn publish_record(self, context: Option<linux_spawn_record::Context>) -> io::Result<Self> {
        // self already owns the unreaped child: publication errors invoke Drop.
        if let Some(context) = context {
            context.publish(self.id())?;
        }
        Ok(self)
    }

    fn spawn_owned(cmd: &mut Command) -> io::Result<Self> {
        #[cfg(unix)]
        if !child_wait_policy_safe() {
            // Without this refusal the teardown's ownership proofs are void: an
            // auto-reaped leader's pid, which is also the group id, can already
            // belong to another process by the time anything is signalled.
            return Err(io::Error::other(
                "test child wait policy unsafe: SIGCHLD ignored or auto-reaping",
            ));
        }
        #[cfg(unix)]
        let writer = {
            use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
            use std::os::unix::process::CommandExt;
            let (reader, writer) = std::io::pipe()?;
            // Keep the source clear of stdio's reserved descriptors, including fd 3.
            // SAFETY: reader is live; fcntl returns a new owned CLOEXEC descriptor.
            let fd = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 64) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is newly allocated above and has exactly one owner.
            let reader = unsafe { OwnedFd::from_raw_fd(fd) };
            cmd.process_group(0);
            cmd.env(LIFELINE_FD_ENV, "3");
            // SAFETY: the closure only invokes async-signal-safe dup2. reader is
            // owned by the closure and stays live through every spawn on cmd.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::dup2(reader.as_raw_fd(), 3) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            writer
        };
        apply_run_env(cmd);
        let child = cmd.spawn()?;
        Ok(Self {
            pgid: child.id(),
            child,
            #[cfg(unix)]
            lifeline: Some(writer),
            done: false,
        })
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }
    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        self.child.stdin.as_mut()
    }
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr.take()
    }

    /// On Unix this never reaps: the pid remains reserved for group teardown.
    pub fn has_exited(&mut self) -> io::Result<bool> {
        crate::cli_deps::cli_shim::child_exited_nowait(&mut self.child)
            .ok_or_else(io::Error::last_os_error)
    }

    pub fn finish(mut self, timeout: Duration) -> Finish {
        drop(self.child.stdin.take());
        let start = Instant::now();
        let timed_out = loop {
            match self.has_exited() {
                Ok(true) => break false,
                Ok(false) if start.elapsed() < timeout => std::thread::sleep(TICK),
                Ok(false) => break true,
                // The wait itself failed (typically ECHILD after somebody else
                // reaped the leader): the pid may no longer be ours, so this
                // goes straight to teardown, whose own fresh probe -- never this
                // error -- decides whether anything may still be signalled.
                Err(_) => {
                    let _ = self.teardown();
                    return Finish::Unconfirmed;
                }
            }
        };
        match self.teardown() {
            Some(_) if timed_out => Finish::TimedOut,
            Some(status) => Finish::Exited(status),
            None => Finish::Unconfirmed,
        }
    }

    /// Drains both streams concurrently, retaining at most OUTPUT_CAP each.
    /// No unbounded wait or reader-thread join is used, even if a descendant
    /// escaped the group and retained an output pipe.
    pub fn output(mut self, timeout: Duration) -> io::Result<GuardedOutput> {
        drop(self.child.stdin.take());
        let out = capture(self.take_stdout())?;
        let err = capture(self.take_stderr())?;
        let finish = self.finish(timeout);
        let start = Instant::now();
        let stdout = collect(out, &start)?;
        let stderr = collect(err, &start)?;
        match finish {
            Finish::Exited(status) => Ok(GuardedOutput {
                status,
                stdout,
                stderr,
            }),
            Finish::TimedOut => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test child timed out",
            )),
            Finish::Unconfirmed => Err(io::Error::other("test child cleanup unconfirmed")),
        }
    }

    fn teardown(&mut self) -> Option<ExitStatus> {
        if self.done {
            return None;
        }
        // Set before any reap: Drop must never signal a recycled group id.
        self.done = true;
        #[cfg(unix)]
        drop(self.lifeline.take());
        #[cfg(unix)]
        let escalated = self.escalate_unix();
        #[cfg(not(unix))]
        let escalated = {
            let _ = self.child.kill();
            true
        };
        let start = Instant::now();
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if start.elapsed() < GROUP_KILL_BOUND => std::thread::sleep(TICK),
                _ => break None,
            }
        };
        #[cfg(unix)]
        let group_gone = self.group_gone_after_reap();
        #[cfg(not(unix))]
        let group_gone = true;
        if !escalated || !group_gone || status.is_none() {
            // Unlike eprintln!, an unavailable stderr must not panic during unwind.
            let _ = writeln!(
                io::stderr().lock(),
                "csq-test-guard: UNCONFIRMED pgid={}",
                self.pgid
            );
            None
        } else {
            status
        }
    }

    /// Unix escalation: TERM, a bounded grace for the leader, then the
    /// probe-gated KILL loop. Returns false when a signal failed for a
    /// reason other than "no live member" or the leader was reaped by
    /// someone else (teardown UNCONFIRMED).
    #[cfg(unix)]
    fn escalate_unix(&self) -> bool {
        let mut clean = true;
        if child_wait_state(&self.child) == WaitState::Running {
            // Escalation: one TERM so the group may clean up, a bounded wait for
            // the leader, then the KILL loop below, which a TERM-ignoring member
            // cannot refuse. The probe just above gates this signal exactly as
            // each KILL tick is gated.
            // SAFETY: the probe proved the leader is still our unreaped child,
            // so pgid is still this child's process-group id.
            let sent = unsafe { libc::killpg(self.pgid as libc::pid_t, libc::SIGTERM) };
            if sent != 0
                && !matches!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH) | Some(libc::EPERM)
                )
            {
                clean = false;
            }
            let grace = Instant::now();
            while grace.elapsed() < TERM_GRACE
                && child_wait_state(&self.child) == WaitState::Running
            {
                std::thread::sleep(TICK);
            }
        }
        {
            let start = Instant::now();
            loop {
                // One fresh ownership probe gates the signal sent this tick. A
                // successful probe -- Running or an unreaped zombie -- proves the
                // pid still reserves this group id. Gone means somebody else
                // reaped the leader (an inherited auto-reaping disposition that
                // preceded the spawn gate, or a rogue waiter): the id may be
                // recycled, so nothing is signalled and the teardown is
                // UNCONFIRMED instead.
                let state = child_wait_state(&self.child);
                if state == WaitState::Gone {
                    clean = false;
                    break;
                }
                // SAFETY: the probe above proved the leader is unreaped by us,
                // so pgid is still this child's process-group id.
                let sent = unsafe { libc::killpg(self.pgid as libc::pid_t, libc::SIGKILL) };
                let code = if sent == 0 {
                    None
                } else {
                    io::Error::last_os_error().raw_os_error()
                };
                let no_live = matches!(code, Some(libc::ESRCH) | Some(libc::EPERM));
                if sent != 0 && !no_live {
                    clean = false;
                }
                // When the leader has exited, whether one more signal suffices
                // depends on the kernel:
                //
                // Linux: no_live can never become true while the unreaped zombie
                // leader is itself a group member (a zombie accepts the signal),
                // so the loop stops once the leader has exited. One SIGKILL is
                // enough there: kill_pgrp walks the group under tasklist_lock,
                // and copy_process re-checks signal_pending under the same lock
                // and fails the fork with ERESTARTNOINTR, so a member forking
                // concurrently either has its child in the group before the
                // walk (signalled) or never completes the fork (it dies of the
                // pending SIGKILL). The post-reap probe below is the proof.
                //
                // darwin: XNU's killpg walks the group without any such fork
                // re-check, so a member mid-fork can add a child after the walk
                // passed it. The loop therefore keeps signalling until the
                // kernel reports no signalable member left (EPERM: only the
                // zombie leader -- or reparented zombies -- remain; ESRCH: none)
                // or the bound expires. Every tick stays behind the fresh probe
                // above, and the reap waits for this loop.
                let leader_exit_ends = cfg!(not(target_os = "macos"));
                if no_live
                    || (leader_exit_ends && state == WaitState::ExitedUnreaped)
                    || start.elapsed() >= GROUP_KILL_BOUND
                {
                    break;
                }
                std::thread::sleep(TICK);
            }
        }
        clean
    }

    /// Unix post-reap proof: waits (bounded) until no member of the group
    /// remains. Returns false when the bound expires first.
    #[cfg(unix)]
    fn group_gone_after_reap(&self) -> bool {
        let start = Instant::now();
        loop {
            // SAFETY: signal zero only; the leader may already be reaped.
            let result = unsafe { libc::kill(-(self.pgid as libc::pid_t), 0) };
            if result < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return true;
            }
            if start.elapsed() >= GROUP_KILL_BOUND {
                return false;
            }
            std::thread::sleep(TICK);
        }
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.teardown();
        }
    }
}

struct Capture {
    recv: std::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
trait CaptureRead: Read + Send {
    fn configure(&self) -> io::Result<()>;
}
#[cfg(unix)]
impl<T: Read + Send + std::os::fd::AsRawFd> CaptureRead for T {
    fn configure(&self) -> io::Result<()> {
        // SAFETY: self owns a live pipe descriptor; only file-status flags change.
        let flags = unsafe { libc::fcntl(self.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: preserve existing flags and make reads cancellable/nonblocking.
        if unsafe { libc::fcntl(self.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
#[cfg(not(unix))]
impl<T: Read + Send> CaptureRead for T {
    fn configure(&self) -> io::Result<()> {
        Ok(())
    }
}
fn capture<R: CaptureRead + 'static>(reader: Option<R>) -> io::Result<Option<Capture>> {
    let Some(mut reader) = reader else {
        return Ok(None);
    };
    reader.configure()?;
    let (send, recv) = std::sync::mpsc::sync_channel(1);
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopped = cancel.clone();
    std::thread::Builder::new()
        .name("test-output".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let mut buf = [0; 8192];
            let result = loop {
                if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                match reader.read(&mut buf) {
                    Ok(0) => break Ok(bytes),
                    Ok(n) => {
                        let keep = n.min(OUTPUT_CAP.saturating_sub(bytes.len()));
                        bytes.extend_from_slice(&buf[..keep]);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(TICK),
                    Err(e) => break Err(e),
                }
            };
            let _ = send.send(result);
        })?;
    Ok(Some(Capture { recv, cancel }))
}
fn collect(capture: Option<Capture>, start: &Instant) -> io::Result<Vec<u8>> {
    match capture {
        None => Ok(Vec::new()),
        Some(capture) => capture
            .recv
            .recv_timeout(GROUP_KILL_BOUND.saturating_sub(start.elapsed()))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "test output pipe did not close")
            })?,
    }
}

/// Rust fixture startup hook: exit immediately on lifeline EOF or read error.
/// Call once at helper startup. Absent lifeline means an ordinary finite helper.
#[cfg(unix)]
pub fn watch_lifeline() -> io::Result<()> {
    use std::os::fd::FromRawFd;
    let Some(fd) = std::env::var_os(LIFELINE_FD_ENV) else {
        return Ok(());
    };
    if fd != "3" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid test lifeline fd",
        ));
    }
    // SAFETY: duplicate the inherited descriptor; File owns only the duplicate.
    let owned = unsafe { libc::fcntl(3, libc::F_DUPFD_CLOEXEC, 64) };
    if owned < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: owned is a fresh valid descriptor with no other Rust owner.
    let mut reader = unsafe { std::fs::File::from_raw_fd(owned) };
    std::thread::Builder::new()
        .name("test-lifeline".into())
        .spawn(move || {
            let mut buf = [0; 1];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        // SAFETY: helper termination is the lifeline's sole purpose;
                        // _exit avoids destructors/locks in the terminating process.
                        unsafe { libc::_exit(0) }
                    }
                    Ok(_) => {}
                }
            }
        })?;
    Ok(())
}

#[cfg(not(unix))]
pub fn watch_lifeline() -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn shell(script: &str) -> Command {
        let mut cmd = Command::new("/bin/bash");
        cmd.env_clear()
            .args(["-c", script])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }
    fn exited(child: &mut TestChild) {
        let start = Instant::now();
        while !child.has_exited().unwrap() {
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "child failed to exit"
            );
            std::thread::sleep(TICK);
        }
    }
    fn group_absent(pgid: u32) -> bool {
        // SAFETY: a zero signal observes existence without signalling a process.
        (unsafe { libc::kill(-(pgid as libc::pid_t), 0) }) < 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }

    #[test]
    fn has_exited_does_not_reap() {
        let _env = crate::platform::test_env::lock();
        let mut child = TestChild::spawn(&mut shell("exit 7")).unwrap();
        exited(&mut child);
        assert!(
            child.has_exited().unwrap(),
            "second WNOWAIT still sees zombie"
        );
        // The real reap, after group cleanup, retains the original status.
        assert!(matches!(child.finish(Duration::ZERO), Finish::Exited(s) if s.code() == Some(7)));
    }

    #[test]
    fn drop_kills_trapping_group() {
        let _env = crate::platform::test_env::lock();
        // Deliberately no lifeline here: this is the group-kill positive control.
        // Finite CPU loop bound prevents an unbounded fixture after a mutant.
        let child = TestChild::spawn(&mut shell(
            "trap '' HUP TERM; end=$((SECONDS+20)); while ((SECONDS<end)); do :; done",
        ))
        .unwrap();
        let pgid = child.id();
        drop(child);
        assert!(group_absent(pgid));
    }

    #[test]
    fn teardown_sends_term_before_kill() {
        // The group gets one TERM, and a bounded grace, before any KILL: a
        // member that handles TERM gets to run its handler. A KILL-only
        // teardown never lets this trap fire.
        let _env = crate::platform::test_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let mark = dir.path().join("term");
        let script = format!(
            "trap 'echo t > {}; exit 0' TERM; end=$((SECONDS+20)); \
             while ((SECONDS<end)); do sleep 0.05; done",
            mark.display(),
        );
        let child = TestChild::spawn(&mut shell(&script)).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(child);
        assert!(mark.exists(), "teardown must deliver TERM before KILL");
    }

    #[test]
    fn drop_during_unwind_does_not_panic() {
        let _env = crate::platform::test_env::lock();
        let mut pgid = 0;
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let child = TestChild::spawn(&mut shell("read -t 20 -u 3 _")).unwrap();
            pgid = child.id();
            let _child = child;
            panic!("intentional unwind");
        }));
        assert!(caught.is_err());
        assert!(group_absent(pgid));
    }

    #[test]
    fn finish_timeout_kills_group() {
        let _env = crate::platform::test_env::lock();
        let child = TestChild::spawn(&mut shell("read -t 20 -u 3 _")).unwrap();
        let pgid = child.id();
        assert!(matches!(
            child.finish(Duration::from_millis(40)),
            Finish::TimedOut
        ));
        assert!(group_absent(pgid));
    }

    #[test]
    fn teardown_after_leader_exit_kills_members_forked_during_the_kill() {
        // The leader exits while eight members fork without pause, so the
        // teardown starts from an exited, unreaped leader. A child forked while
        // the first group SIGKILL walks the group can land after the walk on
        // darwin; a teardown that sends one SIGKILL and reaps leaves that child
        // alive in the group (UNCONFIRMED). Each member keeps at most one live
        // sleep child, so the fixture stays bounded however fast it forks, and
        // every loop ends on its own after 20 s even under a broken teardown.
        let _env = crate::platform::test_env::lock();
        let script = "forker() { end=$((SECONDS+20)); while ((SECONDS<end)); do \
                      /bin/sleep 600 & p=$!; kill -9 $p 2>/dev/null; wait $p 2>/dev/null; \
                      done; }; \
                      for _ in 1 2 3 4 5 6 7 8; do forker & done; sleep 0.3; exit 0";
        let mut survivors = Vec::new();
        for round in 0..12 {
            let mut child = TestChild::spawn(&mut shell(script)).unwrap();
            let pgid = child.id();
            exited(&mut child);
            let finish = child.finish(Duration::ZERO);
            let absent = group_absent(pgid);
            if !absent {
                // Test-side cleanup of a RED round only: the surviving member
                // keeps the group id from being reused while it is non-empty.
                let start = Instant::now();
                while !group_absent(pgid) && start.elapsed() < Duration::from_secs(5) {
                    // SAFETY: plain kill(2) on the group this test created; a
                    // live member reserves the id (checked just above).
                    unsafe { libc::killpg(pgid as libc::pid_t, libc::SIGKILL) };
                    std::thread::sleep(TICK);
                }
            }
            if !absent || !matches!(finish, Finish::Exited(_)) {
                survivors.push((round, absent, format!("{finish:?}")));
            }
        }
        assert!(
            survivors.is_empty(),
            "members outlived teardown (round, group_absent, finish): {survivors:?}"
        );
    }

    #[test]
    fn wait_state_reports_gone_after_reap() {
        let _env = crate::platform::test_env::lock();
        let mut cmd = Command::new("/bin/sh");
        cmd.env_clear().args(["-c", "exit 0"]);
        let mut child = cmd.spawn().unwrap();
        child.wait().unwrap();
        // The pid is reaped: waitid answers ECHILD, and ECHILD must read as Gone
        // -- never Running -- or a teardown would signal an id it no longer owns.
        assert_eq!(child_wait_state(&child), WaitState::Gone);
    }

    #[test]
    fn inherited_auto_reaping_sigchld_refuses_spawn() {
        // SIGCHLD's disposition is per-process and survives exec, so the probe
        // runs in its own process (set before its exec) and the rest of this
        // test binary never observes SIG_IGN.
        let _env = crate::platform::test_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let witness = dir.path().join("probe-ran");
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.env_clear();
        cmd.env("CSQ_TEST_SIGCHLD_PROBE", "1");
        cmd.env("CSQ_TEST_SIGCHLD_WITNESS", &witness);
        cmd.args([
            "--exact",
            "testing::child_lifetime::tests::sigchld_ignore_probe",
            "--nocapture",
        ]);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: the closure runs between fork and exec and only calls
            // async-signal-safe signal(2); the disposition survives exec.
            unsafe {
                cmd.pre_exec(|| {
                    libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                    Ok(())
                });
            }
        }
        let mut child = TestChild::spawn(&mut cmd).unwrap();
        exited(&mut child);
        assert!(matches!(child.finish(Duration::from_secs(5)), Finish::Exited(s) if s.success()));
        // A probe that never matched its --exact name would exit 0 without
        // running, so the witness file, not the exit code, is the evidence.
        assert_eq!(std::fs::read_to_string(&witness).unwrap(), "ok\n");
    }

    #[test]
    fn sigchld_ignore_probe() {
        if std::env::var_os("CSQ_TEST_SIGCHLD_PROBE").is_none() {
            return;
        }
        let _env = crate::platform::test_env::lock();
        // Sanity: SIG_IGN really was inherited, or this probe would pass
        // vacuously over a disposition that makes the refusal untestable here.
        // SAFETY: a null second argument only queries the current disposition.
        let ignored = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) == 0
                && action.sa_sigaction == libc::SIG_IGN
        };
        assert!(ignored, "probe did not inherit SIGCHLD = SIG_IGN");
        // A supervisor context would refuse the spawn itself and mask the gate.
        std::env::remove_var("CSQ_TEST_RUN_CONTEXT");
        let mut cmd = Command::new("/bin/sh");
        cmd.env_clear().args(["-c", "exit 0"]);
        match TestChild::spawn(&mut cmd) {
            Err(error) => assert_eq!(
                error.kind(),
                io::ErrorKind::Other,
                "refusal came from the wrong check: {error}",
            ),
            Ok(_) => panic!("spawn must refuse an auto-reaping SIGCHLD disposition"),
        }
        std::fs::write(
            std::env::var_os("CSQ_TEST_SIGCHLD_WITNESS").unwrap(),
            b"ok\n",
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn teardown_never_signals_after_the_leader_is_auto_reaped() {
        // Same child-process shape as the spawn-gate test: the disposition must
        // be flipped only after the leader exists (the gate refuses it before),
        // so the probe process runs the whole scenario in isolation.
        let _env = crate::platform::test_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let witness = dir.path().join("probe-ran");
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.env_clear();
        cmd.env("CSQ_TEST_SIGCHLD_PROBE", "1");
        cmd.env("CSQ_TEST_SIGCHLD_WITNESS", &witness);
        cmd.args([
            "--exact",
            "testing::child_lifetime::tests::auto_reap_teardown_probe",
            "--nocapture",
        ]);
        let mut child = TestChild::spawn(&mut cmd).unwrap();
        exited(&mut child);
        assert!(matches!(child.finish(Duration::from_secs(20)), Finish::Exited(s) if s.success()));
        assert_eq!(std::fs::read_to_string(&witness).unwrap(), "ok\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn auto_reap_teardown_probe() {
        if std::env::var_os("CSQ_TEST_SIGCHLD_PROBE").is_none() {
            return;
        }
        let _env = crate::platform::test_env::lock();
        std::env::remove_var("CSQ_TEST_RUN_CONTEXT");
        let dir = tempfile::tempdir().unwrap();
        let flag = dir.path().join("go");
        let recorded = dir.path().join("grandchild");
        let script = format!(
            "while [ ! -e {flag} ]; do sleep 0.05; done; sleep 20 & echo $! > {out}; exit 0",
            flag = flag.display(),
            out = recorded.display(),
        );
        let mut cmd = Command::new("/bin/bash");
        cmd.env_clear().args(["-c", &script]);
        let child = TestChild::spawn(&mut cmd).unwrap();
        let leader = child.id();
        // Flip to auto-reaping BEFORE the leader exits; the kernel reaps it at
        // exit. Without the teardown probe, that leaves the group id -- the dead
        // leader's pid -- free to be signalled.
        // SAFETY: SIG_IGN for SIGCHLD is a process-local disposition, and this
        // probe process owns no other child.
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
        }
        std::fs::write(&flag, b"go").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let grandchild = loop {
            if let Ok(text) = std::fs::read_to_string(&recorded) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    break pid;
                }
            }
            assert!(Instant::now() < deadline, "grandchild pid never appeared");
            std::thread::sleep(TICK);
        };
        let start = linux_spawn_record::identity(grandchild)
            .unwrap()
            .start_ticks;
        while std::path::Path::new(&format!("/proc/{leader}")).exists() {
            assert!(Instant::now() < deadline, "leader was not auto-reaped");
            std::thread::sleep(TICK);
        }
        assert!(
            matches!(child.finish(Duration::from_secs(5)), Finish::Unconfirmed),
            "a leader reaped elsewhere must finish UNCONFIRMED",
        );
        // The gated teardown sent nothing: the group's surviving member lives.
        match linux_spawn_record::identity(grandchild) {
            Ok(now) => assert_eq!(now.start_ticks, start, "grandchild identity changed"),
            Err(error) => panic!("gated teardown still signalled the group: {error}"),
        }
        // Cleanup through a pidfd, never a bare pid: the grandchild is nobody's
        // child any more. The descriptor is opened FIRST and the identity is
        // re-read AFTER it, so the signal can only reach the process whose start
        // ticks were just verified -- a pid recycled before pidfd_open fails
        // that re-read instead of being signalled.
        // SAFETY: plain syscalls; pidfd_open returns a fresh descriptor on success.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, grandchild, 0) };
        assert!(fd >= 0, "pidfd_open failed: {}", io::Error::last_os_error());
        let pinned = linux_spawn_record::identity(grandchild);
        if !matches!(&pinned, Ok(now) if now.start_ticks == start) {
            // SAFETY: fd came from pidfd_open above and has no other owner.
            unsafe { libc::close(fd as i32) };
            panic!("grandchild identity changed before the pidfd pinned it");
        }
        // SAFETY: fd is a live pidfd whose identity was verified after it was
        // opened, and a null siginfo pointer is what pidfd_send_signal accepts
        // for a plain signal.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd as i32,
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        // SAFETY: fd came from pidfd_open above and has no other owner.
        unsafe { libc::close(fd as i32) };
        assert_eq!(
            sent,
            0,
            "pidfd_send_signal failed: {}",
            io::Error::last_os_error()
        );
        let killed = Instant::now() + Duration::from_secs(5);
        while std::path::Path::new(&format!("/proc/{grandchild}")).exists() {
            assert!(Instant::now() < killed, "grandchild survived cleanup");
            std::thread::sleep(TICK);
        }
        std::fs::write(
            std::env::var_os("CSQ_TEST_SIGCHLD_WITNESS").unwrap(),
            b"ok\n",
        )
        .unwrap();
    }

    #[test]
    fn shell_lifeline_eof_exits() {
        let _env = crate::platform::test_env::lock();
        let mut child = TestChild::spawn(&mut shell(
            "while :; do read -t 1 -u \"$CSQ_TEST_LIFELINE_FD\" _; [ $? -eq 1 ] && exit 0; done",
        ))
        .unwrap();
        drop(child.lifeline.take());
        exited(&mut child);
        assert!(matches!(child.finish(Duration::ZERO), Finish::Exited(s) if s.success()));
    }

    #[test]
    fn output_drains_both_streams_and_caps_retention() {
        let _env = crate::platform::test_env::lock();
        let script = "chunk=01234567890123456789012345678901; for ((i=0;i<40000;i++)); do printf %s \"$chunk\"; printf %s \"$chunk\" >&2; done";
        let output = TestChild::spawn(&mut shell(script))
            .unwrap()
            .output(Duration::from_secs(15))
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), OUTPUT_CAP);
        assert_eq!(output.stderr.len(), OUTPUT_CAP);
    }

    #[test]
    fn rust_lifeline_helper() {
        // The parent invokes only this exact test; the ordinary suite has no fd.
        if std::env::var_os(LIFELINE_FD_ENV).is_none() {
            return;
        }
        watch_lifeline().unwrap();
        std::thread::sleep(Duration::from_secs(20));
        panic!("lifeline did not terminate Rust helper");
    }

    #[test]
    fn rust_helper_lifeline_eof_exits() {
        let _env = crate::platform::test_env::lock();
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.env_clear().args([
            "--exact",
            "testing::child_lifetime::tests::rust_lifeline_helper",
            "--nocapture",
        ]);
        let mut child = TestChild::spawn(&mut cmd).unwrap();
        drop(child.lifeline.take());
        exited(&mut child);
        assert!(matches!(child.finish(Duration::ZERO), Finish::Exited(s) if s.success()));
    }

    #[test]
    fn drop_kills_grandchild_holding_stdout() {
        let _env = crate::platform::test_env::lock();
        // Grandchild inherits stdout and ignores the lifeline. Its own output
        // proves it ran before the leader exits; EOF is the death witness.
        let mut child =
            TestChild::spawn(&mut shell("(printf ready; exec /bin/sleep 20) & wait")).unwrap();
        let mut stdout = child.take_stdout().unwrap();
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut ready = [0; 5];
            let result = stdout.read_exact(&mut ready).map(|()| (ready, stdout));
            let _ = send.send(result);
        });
        let (ready, stdout) = recv.recv_timeout(Duration::from_secs(3)).unwrap().unwrap();
        assert_eq!(&ready, b"ready");
        let output = capture(Some(stdout)).unwrap();
        drop(child);
        assert!(collect(output, &Instant::now()).unwrap().is_empty());
    }

    struct RestoreMarkers([Option<std::ffi::OsString>; 2]);
    impl Drop for RestoreMarkers {
        fn drop(&mut self) {
            for (key, value) in RUN_ENV_MARKERS.into_iter().zip(&self.0) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
    fn env_output() -> String {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.env_clear().stdout(Stdio::piped());
        let out = TestChild::spawn(&mut cmd)
            .unwrap()
            .output(Duration::from_secs(3))
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    }
    #[cfg(target_os = "linux")]
    struct RestoreContext(Option<std::ffi::OsString>);
    #[cfg(target_os = "linux")]
    impl Drop for RestoreContext {
        fn drop(&mut self) {
            match &self.0 {
                Some(value) => std::env::set_var("CSQ_TEST_RUN_CONTEXT", value),
                None => std::env::remove_var("CSQ_TEST_RUN_CONTEXT"),
            }
        }
    }
    #[test]
    fn markers_survive_env_clear_invalid_dropped_and_never_minted() {
        let _env = crate::platform::test_env::lock();
        // This test deliberately changes run identity; an inherited supervisor
        // context binds the real identity and must be restored after the probe.
        #[cfg(target_os = "linux")]
        let _context = RestoreContext(std::env::var_os("CSQ_TEST_RUN_CONTEXT"));
        #[cfg(target_os = "linux")]
        std::env::remove_var("CSQ_TEST_RUN_CONTEXT");
        let _restore = RestoreMarkers(RUN_ENV_MARKERS.map(std::env::var_os));
        std::env::set_var(RUN_ENV_MARKERS[0], "csqt-test.valid_1");
        std::env::set_var(RUN_ENV_MARKERS[1], "trestle-test_2");
        let out = env_output();
        assert!(out
            .lines()
            .any(|s| s == "CSQ_TEST_RUN_ID=csqt-test.valid_1"));
        assert!(out.lines().any(|s| s == "TRESTLE_RUN_ID=trestle-test_2"));
        std::env::remove_var(RUN_ENV_MARKERS[1]);
        assert!(!env_output()
            .lines()
            .any(|s| s.starts_with("TRESTLE_RUN_ID=")));
        for invalid in ["", "bad value", "bad\nvalue", &"x".repeat(129)] {
            std::env::set_var(RUN_ENV_MARKERS[0], invalid);
            assert!(!env_output()
                .lines()
                .any(|s| s.starts_with("CSQ_TEST_RUN_ID=")));
        }
    }
}

/// Linux-only cooperation channel for the test supervisor. Records describe
/// ancestry; they never grant permission to signal a process.
#[cfg(target_os = "linux")]
mod linux_spawn_record {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Component, Path};
    use std::sync::atomic::{AtomicU64, Ordering};

    const CONTEXT_LIMIT: usize = 4096;
    const STAT_LIMIT: usize = 8192;
    const STATUS_LIMIT: usize = 16384;
    static NONCE: AtomicU64 = AtomicU64::new(0);

    fn invalid() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, "invalid test run context")
    }
    fn valid_run(run: &str) -> bool {
        !run.is_empty()
            && run.len() <= 128
            && run
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    }
    fn open_at(dir: &File, name: &OsStr, flags: i32, mode: u32) -> io::Result<File> {
        let name = CString::new(name.as_bytes()).map_err(|_| invalid())?;
        // SAFETY: dir and name stay live; a successful descriptor is uniquely owned.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd was freshly returned by openat and has no other Rust owner.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn private(file: &File, directory: bool) -> io::Result<()> {
        let meta = file.metadata()?;
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        if meta.uid() != uid
            || meta.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
            || if directory {
                !meta.is_dir()
            } else {
                !meta.is_file() || meta.nlink() != 1
            }
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn bounded(file: File, limit: usize) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        file.take((limit + 1) as u64).read_to_end(&mut data)?;
        if data.len() > limit {
            return Err(invalid());
        }
        Ok(data)
    }
    fn directory(path: &Path) -> io::Result<File> {
        if !path.is_absolute() || path.as_os_str().as_bytes().len() > 4096 {
            return Err(invalid());
        }
        let mut dir = File::open("/")?;
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    dir = open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                }
                _ => return Err(invalid()),
            }
        }
        private(&dir, true)?;
        Ok(dir)
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        v: u32,
        run_id: String,
        uid: u32,
        boot_id: String,
        start_ticks: u64,
        root: Root,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Root {
        pid: u32,
        start_ticks: u64,
    }
    pub(super) struct Identity {
        pub start_ticks: u64,
        pub sid: u32,
        live: bool,
    }
    /// The real uid from a `/proc/<pid>/status` body: exactly one `Uid:` line
    /// carrying four decimal ids (real, effective, saved, filesystem). Anything
    /// else -- missing, repeated, short, non-numeric -- is an error.
    pub(super) fn real_uid(status: &[u8]) -> io::Result<u32> {
        let text = std::str::from_utf8(status).map_err(|_| invalid())?;
        let mut lines = text.lines().filter_map(|line| line.strip_prefix("Uid:"));
        let (Some(line), None) = (lines.next(), lines.next()) else {
            return Err(invalid());
        };
        let ids = line
            .split_whitespace()
            .map(|id| id.parse::<u32>().map_err(|_| invalid()))
            .collect::<io::Result<Vec<_>>>()?;
        match ids.as_slice() {
            [real, _, _, _] => Ok(*real),
            _ => Err(invalid()),
        }
    }
    pub(super) fn identity(pid: u32) -> io::Result<Identity> {
        // SAFETY: geteuid has no preconditions.
        identity_in(Path::new("/proc"), pid, unsafe { libc::geteuid() })
    }
    /// [`identity`] against an explicit proc root and caller uid. Production
    /// passes `/proc` and the effective uid; tests inject a fixture tree.
    pub(super) fn identity_in(proc_root: &Path, pid: u32, uid: u32) -> io::Result<Identity> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(invalid());
        }
        // One directory descriptor pins the process: if the pid is reused after
        // this open, reads through it fail (ESRCH) instead of describing the
        // new process, so status and stat below describe the same task.
        let proc_dir = File::open(proc_root.join(pid.to_string()))?;
        // Ownership is the real uid in status, never an inode owner: the
        // kernel reports the files under /proc/<pid> as root-owned for any
        // non-dumpable task, and the directory's owner is the EFFECTIVE uid,
        // not the real one. An unreadable or malformed status fails closed.
        let status = bounded(
            open_at(&proc_dir, OsStr::new("status"), libc::O_RDONLY, 0)?,
            STATUS_LIMIT,
        )?;
        if real_uid(&status)? != uid {
            return Err(invalid());
        }
        let bytes = bounded(
            open_at(&proc_dir, OsStr::new("stat"), libc::O_RDONLY, 0)?,
            STAT_LIMIT,
        )?;
        let stat = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        let end = stat.rfind(')').ok_or_else(invalid)?;
        if stat
            .split_once(' ')
            .and_then(|(n, _)| n.parse::<u32>().ok())
            != Some(pid)
        {
            return Err(invalid());
        }
        let fields: Vec<_> = stat[end + 1..].split_whitespace().collect();
        if fields.len() < 20 {
            return Err(invalid());
        }
        if fields[0].len() != 1 {
            return Err(invalid());
        }
        for field in &fields[1..=3] {
            if field.parse::<u32>().map_err(|_| invalid())? > i32::MAX as u32 {
                return Err(invalid());
            }
        }
        let sid = fields[3].parse::<u32>().map_err(|_| invalid())?;
        let start_ticks = fields[19].parse::<u64>().map_err(|_| invalid())?;
        if sid == 0 {
            return Err(invalid());
        }
        Ok(Identity {
            start_ticks,
            sid,
            live: !matches!(fields[0], "Z" | "X" | "x"),
        })
    }
    pub(super) struct Context {
        // Hold both validated directories: no pathname is followed at publication.
        _dir: File,
        spawns: File,
        parent_pid: u32,
        parent: Identity,
    }
    impl Context {
        pub(super) fn from_parent_env() -> io::Result<Option<Self>> {
            let Some(path) = std::env::var_os("CSQ_TEST_RUN_CONTEXT") else {
                return Ok(None);
            };
            let run = std::env::var("CSQ_TEST_RUN_ID").map_err(|_| invalid())?;
            Self::load(Path::new(&path), &run).map(Some)
        }
        pub(super) fn load(path: &Path, run: &str) -> io::Result<Self> {
            if !valid_run(run) {
                return Err(invalid());
            }
            let dir = directory(path)?;
            let file = open_at(
                &dir,
                OsStr::new("context.json"),
                libc::O_RDONLY | libc::O_NONBLOCK,
                0,
            )?;
            private(&file, false)?;
            let wire: Wire =
                serde_json::from_slice(&bounded(file, CONTEXT_LIMIT)?).map_err(|_| invalid())?;
            let boot = bounded(File::open("/proc/sys/kernel/random/boot_id")?, 128)?;
            let boot = std::str::from_utf8(&boot).map_err(|_| invalid())?.trim();
            // SAFETY: geteuid has no preconditions.
            if wire.v != 1
                || wire.uid != unsafe { libc::geteuid() }
                || wire.run_id != run
                || wire.boot_id != boot
                || wire.start_ticks == 0
                || wire.root.start_ticks == 0
                || wire.root.start_ticks > wire.start_ticks
            {
                return Err(invalid());
            }
            let root = identity(wire.root.pid)?;
            if !root.live || root.start_ticks != wire.root.start_ticks {
                return Err(invalid());
            }
            let parent_pid = std::process::id();
            let parent = identity(parent_pid)?;
            if parent.start_ticks < wire.start_ticks {
                return Err(invalid());
            }
            let spawns = open_at(
                &dir,
                OsStr::new("spawns"),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            private(&spawns, true)?;
            Ok(Self {
                _dir: dir,
                spawns,
                parent_pid,
                parent,
            })
        }
        pub(super) fn publish(&self, pid: u32) -> io::Result<()> {
            let child = identity(pid)?; // The guard has not reaped, reserving pid.
            if child.start_ticks < self.parent.start_ticks {
                return Err(invalid());
            }
            // process_group(0) guarantees the INITIAL group, even if child code
            // has already changed groups/session by the time stat is read.
            let line = format!(
                "v1 {pid} {} {} {} {} {pid} {} 1 0\n",
                child.start_ticks,
                self.parent_pid,
                self.parent.start_ticks,
                self.parent.sid,
                self.parent.sid
            );
            if line.len() > 512 {
                return Err(invalid());
            }
            for _ in 0..16 {
                let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
                let stem = format!(
                    "{pid}-{}-{:08x}{nonce:016x}",
                    child.start_ticks, self.parent_pid
                );
                let temp = CString::new(format!(".{stem}.tmp")).map_err(|_| invalid())?;
                let target = CString::new(format!("{stem}.rec")).map_err(|_| invalid())?;
                let mut file = match open_at(
                    &self.spawns,
                    OsStr::from_bytes(temp.as_bytes()),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
                    0o600,
                ) {
                    Ok(file) => file,
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e),
                };
                let result = (|| {
                    private(&file, false)?;
                    file.write_all(line.as_bytes())?;
                    // linkat publishes a complete file atomically without ever
                    // overwriting another writer's identity record.
                    // SAFETY: live directory descriptors and valid C strings.
                    if unsafe {
                        libc::linkat(
                            self.spawns.as_raw_fd(),
                            temp.as_ptr(),
                            self.spawns.as_raw_fd(),
                            target.as_ptr(),
                            0,
                        )
                    } < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                })();
                // SAFETY: remove only this invocation's exclusively created temp.
                let unlinked = unsafe { libc::unlinkat(self.spawns.as_raw_fd(), temp.as_ptr(), 0) };
                result?;
                if unlinked < 0 {
                    return Err(io::Error::last_os_error());
                }
                return Ok(());
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "test spawn record collision",
            ))
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod spawn_record_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn context() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(dir.path().join("spawns")).unwrap();
        std::fs::set_permissions(
            dir.path().join("spawns"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let parent = linux_spawn_record::identity(std::process::id()).unwrap();
        // SAFETY: geteuid has no preconditions.
        let uid = unsafe { libc::geteuid() };
        let data = serde_json::json!({"v":1,"run_id":"csqt-record-test","uid":uid,
            "boot_id":std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),
            "start_ticks":parent.start_ticks,"root":{"pid":std::process::id(),"start_ticks":parent.start_ticks}});
        std::fs::write(
            dir.path().join("context.json"),
            serde_json::to_vec(&data).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(
            dir.path().join("context.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        dir
    }

    #[test]
    fn real_uid_reads_the_single_uid_line_and_refuses_anything_else() {
        let ok = b"Name:\tx\nUmask:\t0022\nUid:\t1000\t1001\t1002\t1003\nGid:\t5\t5\t5\t5\n";
        assert_eq!(linux_spawn_record::real_uid(ok).unwrap(), 1000);
        for bad in [
            &b"Name:\tx\nGid:\t5\t5\t5\t5\n"[..],
            b"Uid:\t1000\t1000\t1000\t1000\nUid:\t0\t0\t0\t0\n",
            b"Uid:\t1000\t1000\t1000\n",
            b"Uid:\t1000\t1000\t1000\t1000\t7\n",
            b"Uid:\t-1\t1000\t1000\t1000\n",
            b"Uid:\tabc\t1000\t1000\t1000\n",
            b"Uid:\n",
            b"Uid:\t\xff\t1\t1\t1\n",
        ] {
            assert!(
                linux_spawn_record::real_uid(bad).is_err(),
                "accepted {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn identity_attributes_a_non_dumpable_process_by_its_real_uid() {
        use std::os::unix::fs::MetadataExt;
        // A non-dumpable process's /proc/<pid> files are reported root-owned,
        // so an inode-owner check would refuse one of our own processes. The child below only
        // makes async-signal-safe calls (prctl, pause) and never returns into
        // Rust; the guard kills it by pid and reaps it on every exit path.
        struct Reap(libc::pid_t);
        impl Drop for Reap {
            fn drop(&mut self) {
                // SAFETY: the pid is our unreaped child, so it cannot be reused
                // before the waitpid below.
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    libc::waitpid(self.0, std::ptr::null_mut(), 0);
                }
            }
        }
        let _env = crate::platform::test_env::lock();
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: fds is a valid two-element array for pipe2(2) to fill; CLOEXEC
        // keeps the ends out of children other tests spawn meanwhile.
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "pipe failed"
        );
        // SAFETY: the child runs only prctl, write, close and pause, all
        // async-signal-safe, and loops forever without unwinding or touching
        // Rust state.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: see the fork above; this branch never returns.
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                // Report the dumpable flag the kernel now holds (0 expected).
                let flag = libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) as u8;
                libc::write(fds[1], (&flag as *const u8).cast(), 1);
                libc::close(fds[1]);
                loop {
                    libc::pause();
                }
            }
        }
        let _reap = Reap(pid);
        // SAFETY: the parent closes its write end and owns the read end, which
        // is read once into a one-byte buffer and then closed.
        let (read, flag) = unsafe {
            libc::close(fds[1]);
            let mut flag = 0xffu8;
            let read = libc::read(fds[0], (&mut flag as *mut u8).cast(), 1);
            libc::close(fds[0]);
            (read, flag)
        };
        assert_eq!((read, flag), (1, 0), "child did not become non-dumpable");
        // SAFETY: geteuid has no preconditions.
        let euid = unsafe { libc::geteuid() };
        // Discrimination premise: the per-process FILES of a non-dumpable task
        // are reported as owned by its namespace root, so a reader keyed on a
        // file owner (status, stat) would refuse this child. The /proc/<pid>
        // directory itself is not such a witness: task_dump_owner (fs/proc/
        // base.c) exempts a 0555 per-process directory and keeps the task's
        // effective uid (measured on
        // the fleet: owner == euid with PR_GET_DUMPABLE = 0).
        let file_owner = std::fs::metadata(format!("/proc/{pid}/status"))
            .unwrap()
            .uid();
        assert!(
            euid == 0 || file_owner != euid,
            "premise unmet: /proc/{pid}/status owner {file_owner} == euid {euid}"
        );
        let identity = linux_spawn_record::identity(pid as u32)
            .expect("our own non-dumpable process must be identified by real uid");
        assert!(identity.start_ticks > 0);
    }

    #[test]
    fn identity_attributes_a_setuid_shaped_process_by_its_real_uid_not_its_dir_owner() {
        use std::os::unix::fs::MetadataExt;
        // Injected /proc fixture for the setuid shape: the /proc/<pid>
        // directory is owned by the task's EFFECTIVE uid, which is foreign,
        // while the `Uid:` line's real uid is ours. The caller uid is injected
        // so the fixture directory (necessarily owned by the test user) plays
        // the foreign effective uid, and `ours` is a different uid.
        let root = tempfile::tempdir().unwrap();
        let pid = 4242u32;
        let task = root.path().join(pid.to_string());
        std::fs::create_dir(&task).unwrap();
        let dir_owner = std::fs::metadata(&task).unwrap().uid();
        let ours = dir_owner.wrapping_add(1);
        std::fs::write(
            task.join("status"),
            format!("Name:\tx\nUid:\t{ours}\t{dir_owner}\t{dir_owner}\t{dir_owner}\n"),
        )
        .unwrap();
        let tail = (4..=18)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        std::fs::write(
            task.join("stat"),
            format!("{pid} (x) S 1 {pid} {pid} {tail} 777 0\n"),
        )
        .unwrap();
        // Premise: the directory owner is foreign to the caller uid, so a
        // dir-owner reader would refuse this process.
        assert_ne!(
            dir_owner, ours,
            "premise unmet: dir owner equals caller uid"
        );
        let identity = linux_spawn_record::identity_in(root.path(), pid, ours)
            .expect("a process whose real uid is ours must be identified as ours");
        assert_eq!((identity.sid, identity.start_ticks), (pid, 777));
        // And the converse: a real uid that is not ours is refused even though
        // the directory is owned by the uid it is checked against.
        assert!(linux_spawn_record::identity_in(root.path(), pid, dir_owner).is_err());
    }

    #[test]
    fn malformed_private_contexts_are_refused() {
        let dir = context();
        assert!(linux_spawn_record::Context::load(dir.path(), "csqt-record-test").is_ok());
        assert!(linux_spawn_record::Context::load(dir.path(), "another-run").is_err());
        let file = dir.path().join("context.json");
        let original = std::fs::read(&file).unwrap();
        for (field, value) in [
            ("v", serde_json::json!(2)),
            ("uid", serde_json::json!(u32::MAX)),
            ("boot_id", serde_json::json!("wrong-boot")),
            ("extra", serde_json::json!(1)),
        ] {
            let mut data: serde_json::Value = serde_json::from_slice(&original).unwrap();
            data[field] = value;
            std::fs::write(&file, serde_json::to_vec(&data).unwrap()).unwrap();
            assert!(
                linux_spawn_record::Context::load(dir.path(), "csqt-record-test").is_err(),
                "{field}"
            );
        }
        std::fs::write(&file, vec![b' '; 4097]).unwrap();
        assert!(linux_spawn_record::Context::load(dir.path(), "csqt-record-test").is_err());
        std::fs::write(&file, original).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(linux_spawn_record::Context::load(dir.path(), "csqt-record-test").is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(
            dir.path().join("spawns"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(linux_spawn_record::Context::load(dir.path(), "csqt-record-test").is_err());
    }

    #[test]
    fn symlink_context_components_are_refused() {
        let dir = context();
        let link = dir.path().join("alias");
        symlink(dir.path().join("context.json"), &link).unwrap();
        std::fs::rename(&link, dir.path().join("context.json")).unwrap();
        assert!(linux_spawn_record::Context::load(dir.path(), "csqt-record-test").is_err());
        let other = tempfile::tempdir().unwrap();
        symlink(dir.path(), other.path().join("context")).unwrap();
        assert!(linux_spawn_record::Context::load(
            &other.path().join("context"),
            "csqt-record-test"
        )
        .is_err());
        let clean = context();
        std::fs::remove_dir(clean.path().join("spawns")).unwrap();
        symlink(dir.path().join("spawns"), clean.path().join("spawns")).unwrap();
        assert!(linux_spawn_record::Context::load(clean.path(), "csqt-record-test").is_err());
    }

    struct Restore(Vec<(&'static str, Option<std::ffi::OsString>)>);
    impl Drop for Restore {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
    fn enable(dir: &std::path::Path) -> Restore {
        let restore = Restore(
            ["CSQ_TEST_RUN_CONTEXT", "CSQ_TEST_RUN_ID"]
                .into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
        );
        std::env::set_var("CSQ_TEST_RUN_CONTEXT", dir);
        std::env::set_var("CSQ_TEST_RUN_ID", "csqt-record-test");
        restore
    }

    #[test]
    fn absent_context_preserves_guard_and_malformed_present_refuses_spawn() {
        let _env = crate::platform::test_env::lock();
        let dir = context();
        let _restore = enable(dir.path());
        std::env::remove_var("CSQ_TEST_RUN_CONTEXT");
        let mut cmd = Command::new("/bin/sh");
        cmd.env_clear().args(["-c", "exit 0"]);
        assert!(
            matches!(TestChild::spawn(&mut cmd).unwrap().finish(Duration::from_secs(3)), Finish::Exited(s) if s.success())
        );
        std::env::set_var("CSQ_TEST_RUN_CONTEXT", dir.path());
        std::env::set_var("CSQ_TEST_RUN_ID", "mismatched-run");
        let witness = dir.path().join("must-not-exist");
        let mut cmd = Command::new("/bin/sh");
        cmd.env_clear()
            .args(["-c", "printf started > \"$1\"", "fixture"])
            .arg(&witness);
        assert!(TestChild::spawn(&mut cmd).is_err());
        assert!(!witness.exists());
    }

    #[test]
    fn parent_context_records_env_cleared_child_before_reap() {
        let _env = crate::platform::test_env::lock();
        let dir = context();
        let _restore = enable(dir.path());
        let mut cmd = Command::new("/bin/sh");
        cmd.env_clear().args(["-c", "exit 0"]);
        let child = TestChild::spawn(&mut cmd).unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path().join("spawns"))
            .unwrap()
            .collect();
        assert_eq!(entries.len(), 1);
        let path = entries[0].as_ref().unwrap().path();
        assert_eq!(path.extension().unwrap(), "rec");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let record = std::fs::read_to_string(path).unwrap();
        let fields: Vec<_> = record.split_whitespace().collect();
        let own = linux_spawn_record::identity(std::process::id()).unwrap();
        assert_eq!(
            fields,
            vec![
                "v1".to_string(),
                child.id().to_string(),
                linux_spawn_record::identity(child.id())
                    .unwrap()
                    .start_ticks
                    .to_string(),
                std::process::id().to_string(),
                own.start_ticks.to_string(),
                own.sid.to_string(),
                child.id().to_string(),
                own.sid.to_string(),
                "1".into(),
                "0".into()
            ]
        );
        assert!(record.ends_with('\n'));
        drop(child);
    }

    #[test]
    fn publication_failure_drops_already_owned_child() {
        let _env = crate::platform::test_env::lock();
        let dir = context();
        let _restore = enable(dir.path());
        let context = linux_spawn_record::Context::load(dir.path(), "csqt-record-test").unwrap();
        // Keep the validated descriptor open but remove the directory: publication
        // must fail after spawn, and the owning guard must still reap its child.
        std::fs::remove_dir(dir.path().join("spawns")).unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.env_clear().args(["-c", "read -t 20 -u 3 _"]);
        let child = TestChild::spawn_owned(&mut cmd).unwrap();
        let pid = child.id();
        let result = child.publish_record(Some(context));
        assert!(result.is_err());
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "owned child was not reaped"
        );
    }
}
