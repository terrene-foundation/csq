//! Owned vendor process groups. Timeout is never a stop request.
use std::{
    io,
    process::{Child, Command, ExitStatus},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupSignal {
    Interrupt,
    Kill,
    #[cfg(unix)]
    Terminate,
    #[cfg(unix)]
    Hangup,
    #[cfg(unix)]
    Quit,
}
// Ten existing 200ms custody polls after an explicit stop intent. Expiration
// is a terminal retained-custody refusal, never proof of EOF or permission to
// clean credentials. This budget has no effect on ordinary login deadlines.
pub(crate) const STOP_DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
type Pump = Box<dyn FnMut(&GroupControl) -> io::Result<()> + Send>;
// Losing a wait lease is never positive completion authority.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WaitLease {
    Retained,
    ReapedPendingReaders,
    Finalized,
    #[cfg(unix)]
    Lost,
}
struct Inner {
    pid: u32,
    lease: Mutex<WaitLease>,
    pump: Mutex<Option<Pump>>,
    readers: AtomicBool,
    killed: Mutex<Option<Instant>>,
    // Terminal foreground held for an attended login; restored on reap or drop.
    #[cfg(unix)]
    foreground: Mutex<Option<TerminalCustody>>,
    #[cfg(windows)]
    job: win::Job,
}
#[derive(Clone)]
pub(crate) struct GroupControl(Arc<Inner>);

#[cfg(any(feature = "desktop", all(test, unix)))]
pub(crate) enum GroupStopDecision {
    StopRequested,
    VendorFinalized(VendorFinalizedReceipt),
}

// This token can only be issued after this exact group's original Child was
// reaped and every captured reader joined. It contains no numeric-PGID authority.
#[cfg(any(feature = "desktop", all(test, unix)))]
pub(crate) struct VendorFinalizedReceipt {
    identity: Arc<Inner>,
}
#[cfg(any(feature = "desktop", all(test, unix)))]
impl VendorFinalizedReceipt {
    pub(crate) fn belongs_to(&self, group: &GroupControl) -> bool {
        Arc::ptr_eq(&self.identity, &group.0)
    }
}

impl GroupControl {
    pub(crate) fn check_wait_lease(&self) -> io::Result<()> {
        let lease = self
            .0
            .lease
            .lock()
            .map_err(|_| io::Error::other("login group lease poisoned"))?;
        #[cfg(unix)]
        let mut lease = lease;
        if *lease != WaitLease::Retained {
            return Err(io::Error::other("login group wait lease unavailable"));
        }
        #[cfg(unix)]
        if let Err(error) = observe_unreaped(self.id()) {
            if error.raw_os_error() == Some(libc::ECHILD) {
                *lease = WaitLease::Lost;
            }
            return Err(error);
        }
        Ok(())
    }
    /// Give the terminal back to csq's own group (no-op when never handed off).
    #[cfg(unix)]
    pub(crate) fn release_foreground(&self) {
        let taken = self
            .0
            .foreground
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        drop(taken); // TerminalCustody::drop restores and logs a failure.
    }
    /// Move the terminal custody out to the sole custody owner, so leaking this
    /// handle (the deliberate unresolved-custody branch) can never leak the tty.
    #[cfg(unix)]
    pub(crate) fn take_terminal(&self) -> Option<TerminalCustody> {
        self.0
            .foreground
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
    /// Whether ANY member of the group is observed STOPPED (job control). The
    /// leader is read with WSTOPPED|WNOWAIT; other members from the process
    /// table (`scan_members`, heavier, so the caller rate-limits it). Read-only:
    /// never reaps. Requires csq still to hold the wait lease, so a numeric
    /// PGID is only ever read while our unreaped leader reserves it.
    #[cfg(unix)]
    pub(crate) fn stopped_member(&self, scan_members: bool) -> bool {
        let Ok(lease) = self.0.lease.lock() else {
            return false;
        };
        if *lease != WaitLease::Retained {
            return false;
        }
        // A leader that has already exited (unreaped) means the login is over:
        // its members are the freeze/census's to reap, never a suspension, so an
        // exit-0 login is not turned into a cancellation by a stopped helper.
        if leader_has_exited(self.id()) {
            return false;
        }
        // SAFETY: initialized C output; WSTOPPED|WNOWAIT only observe our child.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: query only our direct child.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.id() as libc::id_t,
                &mut info,
                libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc == 0 {
            #[cfg(target_os = "linux")]
            // SAFETY: waitid initialized the SIGCHLD arm.
            let observed = unsafe { info.si_pid() };
            #[cfg(target_os = "macos")]
            let observed = info.si_pid;
            if observed == self.id() as libc::pid_t && info.si_code == libc::CLD_STOPPED {
                return true;
            }
        }
        scan_members && group_has_stopped_member(self.id())
    }
    pub(crate) fn mark_readers_joined(&self) {
        // Serialize both completion orders with reaping and stop decisions.
        // A poisoned or lost lease can never become a finalized receipt.
        if let Ok(mut lease) = self.0.lease.lock() {
            if *lease == WaitLease::ReapedPendingReaders {
                *lease = WaitLease::Finalized;
            }
            self.0.readers.store(true, Ordering::Release);
        }
    }
    pub(crate) fn readers_joined(&self) -> bool {
        self.0.readers.load(Ordering::Acquire)
    }
    pub(crate) fn kill_requested_at(&self) -> Option<Instant> {
        *self.0.killed.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(crate) fn id(&self) -> u32 {
        self.0.pid
    }
    pub(crate) fn set_signal_pump(
        &self,
        pump: impl FnMut(&Self) -> io::Result<()> + Send + 'static,
    ) {
        *self.0.pump.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(pump));
    }
    pub(crate) fn clear_signal_pump(&self) {
        self.0.pump.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
    pub(crate) fn pump_signals(&self) -> io::Result<()> {
        let mut pump = self
            .0
            .pump
            .lock()
            .map_err(|_| io::Error::other("login signal pump poisoned"))?;
        if let Some(pump) = pump.as_mut() {
            pump(self)?;
        }
        Ok(())
    }
    #[cfg(unix)]
    pub(crate) fn invalidate_wait_lease(&self) {
        *self.0.lease.lock().unwrap_or_else(|e| e.into_inner()) = WaitLease::Lost;
    }
    #[cfg(any(feature = "desktop", all(test, unix)))]
    pub(crate) fn request_stop_or_finalized(
        &self,
        signal: GroupSignal,
    ) -> io::Result<GroupStopDecision> {
        let mut lease = self
            .0
            .lease
            .lock()
            .map_err(|_| io::Error::other("login group lease poisoned"))?;
        if *lease == WaitLease::Finalized && self.readers_joined() {
            // Do not signal or census a numeric group after the Child reap.
            return Ok(GroupStopDecision::VendorFinalized(VendorFinalizedReceipt {
                identity: Arc::clone(&self.0),
            }));
        }
        // Keep the retained lease locked across the decision and native signal.
        self.signal_with_lease(signal, &mut lease)?;
        Ok(GroupStopDecision::StopRequested)
    }
    pub(crate) fn signal(&self, signal: GroupSignal) -> io::Result<()> {
        let mut lease = self
            .0
            .lease
            .lock()
            .map_err(|_| io::Error::other("login group lease poisoned"))?;
        self.signal_with_lease(signal, &mut lease)
    }
    fn signal_with_lease(&self, signal: GroupSignal, lease: &mut WaitLease) -> io::Result<()> {
        if *lease != WaitLease::Retained {
            return Err(io::Error::other("login group wait lease unavailable"));
        }
        if matches!(signal, GroupSignal::Kill) {
            let mut killed = self
                .0
                .killed
                .lock()
                .map_err(|_| io::Error::other("login stop intent poisoned"))?;
            if killed.is_none() {
                *killed = Some(Instant::now());
            }
        }
        #[cfg(unix)]
        {
            let leader_exited = match observe_unreaped(self.id()) {
                Ok(exited) => exited,
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        *lease = WaitLease::Lost;
                    }
                    return Err(error);
                }
            };
            let signal = match signal {
                GroupSignal::Interrupt => libc::SIGINT,
                GroupSignal::Kill => libc::SIGKILL,
                GroupSignal::Terminate => libc::SIGTERM,
                GroupSignal::Hangup => libc::SIGHUP,
                GroupSignal::Quit => libc::SIGQUIT,
            };
            // SAFETY: waitid(WNOWAIT) just proved our unreaped leader reserves this PGID.
            if unsafe { libc::kill(-(self.id() as libc::pid_t), signal) } != 0 {
                let e = io::Error::last_os_error();
                // Darwin answers EPERM when the group's only members are
                // unreaped zombies (measured 2026-10-11, csq ede59944), but
                // EPERM equally means a live member we may not signal (another
                // uid). EPERM is a no-op ONLY when the leader is freshly
                // observed exited-unreaped under this lease (so it still
                // reserves the PGID) AND the census finds no member besides it
                // other than zombies. A live or unclassifiable member returns
                // the error. Completion stays gated on try_reap's census.
                #[cfg(target_os = "macos")]
                let no_signalable_member = leader_exited
                    && e.raw_os_error() == Some(libc::EPERM)
                    && census_besides_leader(self.id()) == GroupCensus::Empty;
                #[cfg(not(target_os = "macos"))]
                let no_signalable_member = {
                    let _ = leader_exited;
                    false
                };
                if e.raw_os_error() != Some(libc::ESRCH) && !no_signalable_member {
                    return Err(e);
                }
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            self.0.job.signal(self.id(), signal)
        }
    }
    pub(crate) fn try_reap(
        &self,
        child: &mut Child,
        readers_joined: bool,
    ) -> io::Result<Option<ExitStatus>> {
        if child.id() != self.id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "login group child identity mismatch",
            ));
        }
        #[cfg(unix)]
        {
            let mut lease = self
                .0
                .lease
                .lock()
                .map_err(|_| io::Error::other("login group lease poisoned"))?;
            if *lease != WaitLease::Retained {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            match observe_unreaped(self.id()) {
                Ok(false) => return Ok(None),
                Ok(true) => {}
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        *lease = WaitLease::Lost;
                    }
                    return Err(error);
                }
            }
        }
        if !readers_joined {
            return Ok(None);
        }
        let mut lease = self
            .0
            .lease
            .lock()
            .map_err(|_| io::Error::other("login group lease poisoned"))?;
        #[cfg(unix)]
        if *lease != WaitLease::Retained {
            return Err(io::Error::from_raw_os_error(libc::ECHILD));
        }
        // Freeze, then count. Run while the exited-unreaped leader still
        // reserves the numeric PGID (this lease is Retained and the leader was
        // observed exited above; only this Child handle can reap it). The
        // group is first sent SIGKILL (`freeze_group`): a SIGKILLed process
        // can no longer fork, so a member that forks a child and exits between
        // two census reads cannot hand the group to an uncounted process — the
        // fork-then-exit race of a bare walk. Leftover helpers the vendor CLI
        // left in its own group are custody's to kill on completion. Only an
        // Empty census after the freeze may reap as complete; a Survivor
        // (still dying) or an Undetermined census keeps the leader unreaped
        // and refuses this poll, and the caller's elapsed census budget ends
        // in a terminal retained-custody refusal. A member that left the group
        // (setpgid/setsid) is outside this gate; a fork-and-exit WITHIN the
        // group is covered by the freeze.
        #[cfg(unix)]
        {
            let census = match freeze_group(self.id()) {
                Ok(()) => census_besides_leader(self.id()),
                Err(_) => GroupCensus::Undetermined("freeze_signal_refused"),
            };
            if census != GroupCensus::Empty {
                eprintln!(
                    "login_group_census_refused pgid={} census={census:?}",
                    self.id()
                );
                return Err(io::Error::other(CensusRefusal));
            }
        }
        #[cfg(windows)]
        let remaining = if win::exited(child).ok() == Some(true) {
            // An exited leader is not active in the retained kernel Job. No
            // numeric PID query is needed to count the remaining active members.
            self.0.job.active_count().ok().map(|count| count as usize)
        } else {
            None
        };
        #[cfg(windows)]
        if let Some(count) = remaining.filter(|count| *count > 0) {
            eprintln!("login_group_members_remaining={count}");
        }
        let result = child.try_wait();
        if matches!(result, Ok(Some(_))) {
            #[cfg(unix)]
            self.release_foreground();
            // Only an actual reap of the original Child creates positive state.
            *lease = if self.readers_joined() {
                WaitLease::Finalized
            } else {
                WaitLease::ReapedPendingReaders
            };
        }
        result
    }
}

pub(crate) fn spawn(command: &mut Command) -> io::Result<(Child, GroupControl)> {
    spawn_with(command, false)
}

/// [`spawn`] for an ATTENDED login (csq's own stdin is its controlling
/// terminal, as in `csq login N`): the vendor's new process group is also made
/// the terminal's foreground group, so the vendor may use the tty without
/// being stopped by SIGTTOU/SIGTTIN. Foreground returns to csq when the leader
/// is reaped or the group handle drops. With no such terminal (desktop, pipes,
/// a backgrounded csq) this is exactly [`spawn`].
pub(crate) fn spawn_attended(command: &mut Command) -> io::Result<(Child, GroupControl)> {
    spawn_with(command, true)
}

fn spawn_with(command: &mut Command, attended: bool) -> io::Result<(Child, GroupControl)> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        let mut foreground = if attended {
            TerminalCustody::arm(command)?
        } else {
            None
        };
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                // Only the pre_exec handoff returns HANDOFF_ERRNO (every one of
                // its failures is mapped to it; execve never yields ENOTTY), so a
                // missing or unrunnable program is never labelled a handoff failure.
                if foreground.is_some() && error.raw_os_error() == Some(HANDOFF_ERRNO) {
                    eprintln!("login_tty_foreground_handoff_failed stage=pre_exec");
                }
                return Err(error);
            }
        };
        if let Some(custody) = foreground.as_mut() {
            custody.vendor = child.id() as libc::pid_t;
        }
        let group = GroupControl(Arc::new(Inner {
            pid: child.id(),
            lease: Mutex::new(WaitLease::Retained),
            pump: Mutex::new(None),
            readers: AtomicBool::new(false),
            killed: Mutex::new(None),
            foreground: Mutex::new(foreground),
        }));
        Ok((child, group))
    }
    #[cfg(windows)]
    {
        let _ = attended;
        win::spawn(command)
    }
}

/// The one errno the pre_exec handoff reports for every failure.
#[cfg(unix)]
const HANDOFF_ERRNO: libc::c_int = libc::ENOTTY;

/// At most one attended custody at a time: SIGTTOU save/restore pairs would
/// otherwise interleave out of order. A second concurrent arm is REFUSED
/// (fail closed) instead of corrupting the first one's restore.
#[cfg(unix)]
static CUSTODY_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
struct ActiveSlot;
#[cfg(unix)]
impl ActiveSlot {
    fn claim() -> Option<Self> {
        CUSTODY_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}
#[cfg(unix)]
impl Drop for ActiveSlot {
    fn drop(&mut self) {
        CUSTODY_ACTIVE.store(false, Ordering::Release);
    }
}

/// The terminal custody of an ATTENDED login, a separate owned object whose
/// Drop restores everything it took: the foreground group, the tty modes and
/// csq's SIGTTOU disposition. The custody owner holds it (not the group handle,
/// which the unresolved-custody branch deliberately leaks), so no custody end
/// can keep the operator's terminal.
///
/// csq ignores SIGTTOU for the whole window: with the vendor in the foreground
/// csq is a background group, and under `stty tostop` its own writes (notices,
/// the Codex stdout tee) would otherwise stop csq itself. The ignore is reset
/// to the default in the child before exec, so the vendor never inherits it.
#[cfg(unix)]
pub(crate) struct TerminalCustody {
    fd: std::os::fd::OwnedFd,
    own: libc::pid_t,
    pub(crate) vendor: libc::pid_t,
    termios: libc::termios,
    prior_ttou: libc::sigaction,
    // Declared last: released only after Drop::drop has restored everything.
    _slot: ActiveSlot,
}

#[cfg(unix)]
impl TerminalCustody {
    /// Arm the handoff when the process has a controlling terminal (opened as
    /// /dev/tty, so a redirected stdin does not defeat it) whose foreground
    /// group is csq's own; `Ok(None)` otherwise (not attended, or csq itself is
    /// a background job).
    ///
    /// The terminal is taken in the child's `pre_exec`, after std made the child
    /// its own group leader and before exec: the vendor never runs one
    /// instruction as a background group, so there is no window in which it can
    /// touch the tty and stop, and no SIGCONT is needed. A parent-side
    /// tcsetpgrp after spawn would race the vendor's first tty access.
    ///
    /// The registered closure is bound to this one handoff (a raw fd number and
    /// the parent's group): arm once per Command and never respawn that Command.
    fn arm(command: &mut Command) -> io::Result<Option<Self>> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::process::CommandExt;
        // Fail closed: degrading to an unattended spawn would put the vendor in a
        // background group, the very an internal ticket stop.
        let Some(slot) = ActiveSlot::claim() else {
            eprintln!("login_tty_custody_overlap_refused");
            return Err(io::Error::other("login terminal custody already active"));
        };
        // SAFETY: NUL-terminated literal path; the flags forbid acquiring a
        // controlling terminal and leaking the descriptor into the vendor.
        let tty = unsafe {
            libc::open(
                c"/dev/tty".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOCTTY,
            )
        };
        if tty < 0 {
            return Ok(None); // no controlling terminal: not attended
        }
        // SAFETY: tty is a fresh descriptor this function owns.
        let tty = unsafe { std::os::fd::OwnedFd::from_raw_fd(tty) };
        // SAFETY: read-only queries.
        let (foreground, own) = unsafe { (libc::tcgetpgrp(tty.as_raw_fd()), libc::getpgrp()) };
        if foreground < 0 || foreground != own {
            return Ok(None);
        }
        // SAFETY: F_DUPFD_CLOEXEC; >= 10 keeps clear of the child's stdio dup2
        // targets, CLOEXEC keeps it out of the vendor.
        let raw = unsafe { libc::fcntl(tty.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        if raw < 0 {
            eprintln!("login_tty_foreground_handoff_failed stage=dup");
            return Err(io::Error::other("login terminal handoff unavailable"));
        }
        // SAFETY: raw is a fresh descriptor this function exclusively owns.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        drop(tty);
        // SAFETY: zeroed termios filled by tcgetattr on the live tty.
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: valid fd and out-pointer.
        if unsafe { libc::tcgetattr(raw, &mut termios) } != 0 {
            eprintln!("login_tty_foreground_handoff_failed stage=termios");
            return Err(io::Error::other("login terminal handoff unavailable"));
        }
        // SAFETY: zeroed sigaction; SIG_IGN installed, the prior one saved.
        let mut prior_ttou: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: as above; only valid pointers are passed.
        unsafe {
            let mut ignore: libc::sigaction = std::mem::zeroed();
            ignore.sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&mut ignore.sa_mask);
            if libc::sigaction(libc::SIGTTOU, &ignore, &mut prior_ttou) != 0 {
                eprintln!("login_tty_foreground_handoff_failed stage=sigttou");
                return Err(io::Error::other("login terminal handoff unavailable"));
            }
        }
        // SAFETY: the closure only calls async-signal-safe functions.
        unsafe {
            command.pre_exec(move || {
                // Refuse if csq lost the foreground between arm and fork (a
                // ^Z-and-bg race): never take the terminal from the shell.
                if libc::tcgetpgrp(raw) != own {
                    return Err(io::Error::from_raw_os_error(HANDOFF_ERRNO));
                }
                // SIGTTOU is ignored (inherited from csq), so this is permitted
                // from the not-yet-foreground group.
                if libc::tcsetpgrp(raw, libc::getpid()) != 0 {
                    return Err(io::Error::from_raw_os_error(HANDOFF_ERRNO));
                }
                libc::signal(libc::SIGTTOU, libc::SIG_DFL);
                Ok(())
            });
        }
        Ok(Some(Self {
            fd,
            own,
            vendor: 0,
            termios,
            prior_ttou,
            _slot: slot,
        }))
    }
}

#[cfg(unix)]
impl Drop for TerminalCustody {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        let fd = self.fd.as_raw_fd();
        // SAFETY: plain queries/calls on our own duplicate of the tty and
        // groups; SIGTTOU is ignored for the whole window so none can stop us.
        unsafe {
            let foreground = libc::tcgetpgrp(fd);
            // Take the terminal back only from the vendor's group or from a
            // group that no longer exists; never from a live unrelated group.
            let vendor_gone = foreground > 0
                && foreground != self.own
                && libc::kill(-foreground, 0) != 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            if foreground == self.vendor || vendor_gone {
                if libc::tcsetpgrp(fd, self.own) != 0 {
                    eprintln!(
                        "login_tty_foreground_restore_failed errno={}",
                        io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                    );
                }
            } else if foreground != self.own {
                eprintln!("login_tty_foreground_restore_skipped");
            }
            if libc::tcgetpgrp(fd) == self.own
                && libc::tcsetattr(fd, libc::TCSANOW, &self.termios) != 0
            {
                eprintln!(
                    "login_tty_modes_restore_failed errno={}",
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                );
            }
            if libc::sigaction(libc::SIGTTOU, &self.prior_ttou, std::ptr::null_mut()) != 0 {
                eprintln!("login_tty_sigttou_restore_failed");
            }
        }
    }
}

// Test safety cleanup reuses the exact production WNOWAIT observation but
// cannot invoke the production signal policy (which semantic mutants change).
#[cfg(all(test, unix))]
pub(crate) fn observe_owned_unreaped_for_test(child: &Child) -> io::Result<bool> {
    observe_unreaped(child.id())
}

/// True only when the unreaped leader is observed EXITED (si_code names an
/// exit, kill or dump). Darwin fills the siginfo for a merely STOPPED child
/// even under WEXITED|WNOHANG, so `observe_unreaped`'s pid match alone is not
/// proof of exit; the si_code is.
#[cfg(unix)]
fn leader_has_exited(pid: u32) -> bool {
    // SAFETY: initialized C output; WNOWAIT never consumes the child's identity.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: query only our direct child.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: waitid initialized the SIGCHLD arm.
    let observed = unsafe { info.si_pid() };
    #[cfg(target_os = "macos")]
    let observed = info.si_pid;
    observed == pid as libc::pid_t
        && matches!(
            info.si_code,
            libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
        )
}

#[cfg(unix)]
fn observe_unreaped(pid: u32) -> io::Result<bool> {
    // SAFETY: initialized C output; WNOWAIT never consumes the owned child's identity.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: query only our direct child and retain it for future group signals.
    if unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    // SAFETY: waitid initialized the SIGCHLD arm.
    let observed = unsafe { info.si_pid() };
    #[cfg(target_os = "macos")]
    let observed = info.si_pid;
    Ok(observed == pid as libc::pid_t)
}

/// SIGKILL the whole group before its census. Caller contract: the leader is
/// observed exited-unreaped under a Retained lease, so it reserves the PGID and
/// the number cannot name another group. ESRCH: no member left to signal.
/// Darwin EPERM: no signalable member (a zombie-only group answers EPERM,
/// measured 2026-10-11, csq ede59944; another uid's member answers it too), so
/// the census that follows decides. Any other error refuses the census.
#[cfg(unix)]
fn freeze_group(pgid: u32) -> io::Result<()> {
    // SAFETY: plain signal to the PGID our unreaped leader reserves (see above).
    if unsafe { libc::kill(-(pgid as libc::pid_t), libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(()),
        #[cfg(target_os = "macos")]
        Some(libc::EPERM) => Ok(()),
        _ => Err(error),
    }
}

/// Members of a process group other than its (exited-unreaped) leader.
#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GroupCensus {
    /// No member besides the leader, other than dead (zombie) ones.
    Empty,
    /// Live members besides the leader (after the freeze: still dying).
    Survivor(Vec<u32>),
    /// The enumeration failed or a member could not be classified; the tag
    /// names the failed step (no paths, names or other process data).
    Undetermined(&'static str),
}

/// try_reap's refusal marker: the group was not proven empty.
#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct CensusRefusal;
#[cfg(unix)]
impl std::fmt::Display for CensusRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("login group not proven empty")
    }
}
#[cfg(unix)]
impl std::error::Error for CensusRefusal {}
#[cfg(unix)]
pub(crate) fn is_census_refusal(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<CensusRefusal>())
}

#[cfg(all(test, unix))]
thread_local! {
    static CENSUS_OVERRIDE: std::cell::RefCell<Option<GroupCensus>> =
        const { std::cell::RefCell::new(None) };
}
/// Test-only: replace this thread's census result (None restores the walk).
#[cfg(all(test, unix))]
pub(crate) fn inject_census_for_test(census: Option<GroupCensus>) {
    CENSUS_OVERRIDE.with(|cell| *cell.borrow_mut() = census);
}

/// Census of `pgid`'s members other than the leader `pgid`. Only meaningful
/// while the caller holds the unreaped leader (it reserves the PGID). The walk
/// is non-atomic; try_reap makes it sound by freezing the group first
/// (`freeze_group`), so no counted-then-exited member can leave a fork behind.
#[cfg(unix)]
pub(crate) fn census_besides_leader(pgid: u32) -> GroupCensus {
    #[cfg(test)]
    if let Some(census) = CENSUS_OVERRIDE.with(|cell| cell.borrow().clone()) {
        return census;
    }
    // A /proc that hides processes (hidepid, subset) would read as Empty.
    #[cfg(target_os = "linux")]
    // Bytes, decoded lossily: a mount point may hold non-UTF-8 bytes (e.g. a
    // user's FUSE mount), which must not deny every census; only "/proc" and
    // the ASCII option fields are matched.
    match std::fs::read("/proc/self/mountinfo") {
        Ok(info) => {
            if let Err(tag) = proc_mount_complete_bytes(&info) {
                return GroupCensus::Undetermined(tag);
            }
        }
        Err(_) => return GroupCensus::Undetermined("proc_mountinfo_unreadable"),
    }
    let pids = match members(pgid) {
        Ok(pids) => pids,
        Err(_) => return GroupCensus::Undetermined("group_enumeration_failed"),
    };
    let mut live = Vec::new();
    for pid in pids.into_iter().filter(|pid| *pid != pgid) {
        match member_state(pid) {
            // Fully reaped, or the pid now names a process outside this group.
            Ok(None) => {}
            Ok(Some((group, _))) if group != pgid => {}
            Ok(Some((_, false))) => {}
            Ok(Some((_, true))) => live.push(pid),
            Err(_) => return GroupCensus::Undetermined("member_unclassifiable"),
        }
    }
    if live.is_empty() {
        GroupCensus::Empty
    } else {
        GroupCensus::Survivor(live)
    }
}

/// [`proc_mount_complete`] over raw mountinfo bytes, decoded lossily.
#[cfg(target_os = "linux")]
fn proc_mount_complete_bytes(mountinfo: &[u8]) -> Result<(), &'static str> {
    proc_mount_complete(&String::from_utf8_lossy(mountinfo))
}

/// `Ok(())` only when the LAST procfs mount on /proc in this mount namespace
/// shows every process: no `hidepid` other than 0/off, no `subset`. Absent,
/// malformed or non-proc /proc is an error tag (fail closed).
#[cfg(target_os = "linux")]
fn proc_mount_complete(mountinfo: &str) -> Result<(), &'static str> {
    let mut verdict = Err("proc_mount_absent");
    for line in mountinfo.lines() {
        let Some((head, tail)) = line.split_once(" - ") else {
            continue;
        };
        let head: Vec<&str> = head.split(' ').collect();
        if head.get(4) != Some(&"/proc") {
            continue;
        }
        let mut tail = tail.split(' ');
        let (Some(mount_opts), Some(fstype), Some(_source), Some(super_opts)) =
            (head.get(5), tail.next(), tail.next(), tail.next())
        else {
            verdict = Err("proc_mountinfo_malformed");
            continue;
        };
        if fstype != "proc" {
            verdict = Err("proc_mount_not_procfs");
            continue;
        }
        verdict = mount_opts
            .split(',')
            .chain(super_opts.split(','))
            .try_for_each(|opt| match opt.split_once('=') {
                Some(("hidepid", "0" | "off")) => Ok(()),
                Some(("hidepid", _)) => Err("proc_hidepid"),
                Some(("subset", _)) => Err("proc_subset"),
                _ => Ok(()),
            });
    }
    verdict
}

/// `(state, pgrp)` from `/proc/<pid>/stat` bytes. comm (field 2) may hold any
/// byte, including ')', spaces, newlines and non-UTF-8: parse after the LAST
/// `)`. Only the numeric tail is decoded.
#[cfg(target_os = "linux")]
fn parse_stat(stat: &[u8]) -> Option<(u8, u32)> {
    let close = stat.iter().rposition(|byte| *byte == b')')?;
    let rest = std::str::from_utf8(&stat[close + 1..]).ok()?;
    let mut fields = rest.split_ascii_whitespace();
    let [state] = fields.next()?.as_bytes() else {
        return None; // field 3 is one byte
    };
    let pgrp = fields.nth(1)?.parse::<u32>().ok()?; // field 5
    Some((*state, pgrp))
}

/// Whether a member in `state` is live. A `Z` stat is only the thread-group
/// leader's state: more than one `/proc/<pid>/task` entry means other threads
/// still run. A Z member whose task dir was unreadable (`None`) is unknown.
#[cfg(target_os = "linux")]
fn member_liveness(state: u8, tasks: Option<usize>) -> Option<bool> {
    match state {
        b'Z' => tasks.map(|count| count > 1),
        b'X' | b'x' => Some(false),
        _ => Some(true),
    }
}

/// `(state, pgrp)` for `pid`; `None` when the pid is gone.
#[cfg(target_os = "linux")]
fn read_stat(pid: u32) -> io::Result<Option<(u8, u32)>> {
    let stat = match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(e) if e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH) => {
            return Ok(None)
        }
        Err(e) => return Err(e),
    };
    match parse_stat(&stat) {
        Some(parsed) => Ok(Some(parsed)),
        None => Err(io::Error::other("login group member stat unparsable")),
    }
}

/// `(pgrp, live)`; `None` when the pid is gone. EACCES or any read failure
/// (stat, or a Z member's task dir) is an error, i.e. Undetermined.
#[cfg(target_os = "linux")]
fn member_state(pid: u32) -> io::Result<Option<(u32, bool)>> {
    let Some((state, pgrp)) = read_stat(pid)? else {
        return Ok(None);
    };
    let tasks = if state == b'Z' {
        match std::fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(dir) => {
                let mut count = 0usize;
                for entry in dir {
                    entry?;
                    count += 1;
                }
                Some(count)
            }
            Err(_) => None,
        }
    } else {
        None
    };
    match member_liveness(state, tasks) {
        Some(live) => Ok(Some((pgrp, live))),
        None => Err(io::Error::other(
            "login group zombie member threads unreadable",
        )),
    }
}

/// Any live member of `pgid` in job-control stop (`T`/`t`). An unreadable
/// member reads as not stopped: this only ever ADDS a cancellation trigger.
#[cfg(target_os = "linux")]
fn group_has_stopped_member(pgid: u32) -> bool {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return false;
    };
    dir.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
            .and_then(|pid| read_stat(pid).ok().flatten())
            .is_some_and(|(state, group)| group == pgid && matches!(state, b'T' | b't'))
    })
}

#[cfg(target_os = "linux")]
fn members(pgid: u32) -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some((_, group)) = read_stat(pid)? {
            if group == pgid {
                pids.push(pid);
            }
        }
    }
    Ok(pids)
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    #[test]
    fn stat_parser_survives_hostile_comm_bytes() {
        // comm = "a) Z 1 1 (\n\xff" — a ')', spaces, a newline and non-UTF-8.
        let mut stat = b"4242 (a) Z 1 1 (\n\xff".to_vec();
        stat.extend_from_slice(b") S 1 777 777 0 -1 4194560 0 0 0 0\n");
        assert_eq!(
            parse_stat(&stat),
            Some((b'S', 777)),
            "STAT_PARSE_HOSTILE_COMM"
        );
        assert_eq!(parse_stat(b"1 (x) Z 0 9 9"), Some((b'Z', 9)));
        assert_eq!(parse_stat(b"1 (x) ZZ 0 9 9"), None);
        assert_eq!(parse_stat(b"1 (x) Z 0"), None);
        assert_eq!(parse_stat(b"1 x Z 0 9 9"), None);
    }

    #[test]
    fn mountinfo_with_non_utf8_mount_point_still_checks_proc() {
        let mut info = b"40 1 0:50 / /home/u/m\xff rw - fuse.x x rw\n".to_vec();
        info.extend_from_slice(b"22 1 0:21 / /proc rw - proc proc rw\n");
        assert_eq!(proc_mount_complete_bytes(&info), Ok(()));
        let mut hidden = b"40 1 0:50 / /home/u/m\xff rw - fuse.x x rw\n".to_vec();
        hidden.extend_from_slice(b"22 1 0:21 / /proc rw - proc proc rw,hidepid=2\n");
        assert_eq!(proc_mount_complete_bytes(&hidden), Err("proc_hidepid"));
    }

    #[test]
    fn mountinfo_hiding_proc_is_undetermined() {
        let line =
            |opts: &str| format!("22 1 0:21 / /proc rw,nosuid master:12 - proc proc {opts}\n");
        let root = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        assert_eq!(
            proc_mount_complete(&(root.to_owned() + &line("rw"))),
            Ok(())
        );
        assert_eq!(proc_mount_complete(&line("rw,hidepid=0")), Ok(()));
        assert_eq!(
            proc_mount_complete(&line("rw,hidepid=2")),
            Err("proc_hidepid")
        );
        assert_eq!(
            proc_mount_complete(&line("rw,hidepid=invisible")),
            Err("proc_hidepid")
        );
        assert_eq!(
            proc_mount_complete(&line("rw,subset=pid")),
            Err("proc_subset")
        );
        // The last /proc mount wins: an over-mount that hides is refused.
        let stacked = line("rw") + &line("rw,hidepid=noaccess");
        assert_eq!(proc_mount_complete(&stacked), Err("proc_hidepid"));
        assert_eq!(proc_mount_complete(root), Err("proc_mount_absent"));
        assert_eq!(
            proc_mount_complete("22 1 0:21 / /proc rw\n"),
            Err("proc_mount_absent")
        );
    }

    #[test]
    fn zombie_leader_with_live_threads_is_live() {
        assert_eq!(member_liveness(b'Z', Some(1)), Some(false));
        assert_eq!(member_liveness(b'Z', Some(0)), Some(false));
        assert_eq!(
            member_liveness(b'Z', Some(3)),
            Some(true),
            "Z_WITH_THREADS_IS_LIVE"
        );
        assert_eq!(
            member_liveness(b'Z', None),
            None,
            "Z_TASKS_UNREADABLE_IS_UNKNOWN"
        );
        assert_eq!(member_liveness(b'S', None), Some(true));
        assert_eq!(member_liveness(b'X', None), Some(false));
    }
}

/// `(pgid, live)` via PROC_PIDTBSDINFO; `None` when gone. A zombie answers
/// ESRCH here (measured darwin 2026-10-24: a listed zombie leader read as
/// gone), so zombies classify as not-live through `None`; SZOMB is kept for a
/// kernel that reports zombie info. EPERM or any other error is Undetermined.
#[cfg(target_os = "macos")]
fn member_state(pid: u32) -> io::Result<Option<(u32, bool)>> {
    const SZOMB: u32 = 5;
    // SAFETY: plain C output struct sized exactly for PROC_PIDTBSDINFO.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: valid output buffer of `size` bytes.
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if bytes <= 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(e);
    }
    if bytes != size {
        return Err(io::Error::other("login group member info incomplete"));
    }
    Ok(Some((info.pbi_pgid, info.pbi_status != SZOMB)))
}

/// Any live member of `pgid` in job-control stop (SSTOP). Unreadable reads as
/// not stopped: this only ever ADDS a cancellation trigger.
#[cfg(target_os = "macos")]
fn group_has_stopped_member(pgid: u32) -> bool {
    const SSTOP: u32 = 4;
    let Ok(pids) = members(pgid) else {
        return false;
    };
    pids.into_iter().any(|pid| {
        // SAFETY: plain C output struct sized exactly for PROC_PIDTBSDINFO.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: valid output buffer of `size` bytes.
        let bytes = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        bytes == size && info.pbi_pgid == pgid && info.pbi_status == SSTOP
    })
}

#[cfg(target_os = "macos")]
fn members(pgid: u32) -> io::Result<Vec<u32>> {
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_listpids(kind: u32, group: u32, buffer: *mut std::ffi::c_void, size: i32) -> i32;
    }
    let mut pids = vec![0u32; 32768];
    // SAFETY: PROC_PGRP_ONLY=2; output allocation covers supplied byte capacity.
    let bytes =
        unsafe { proc_listpids(2, pgid, pids.as_mut_ptr().cast(), (pids.len() * 4) as i32) };
    if bytes <= 0 || bytes as usize >= pids.len() * 4 || bytes % 4 != 0 {
        return Err(io::Error::other("login group census incomplete"));
    }
    pids.truncate(bytes as usize / 4);
    pids.retain(|pid| *pid != 0);
    Ok(pids)
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::{
        ffi::c_void,
        os::windows::{io::AsRawHandle, process::CommandExt},
        time::{Duration, Instant},
    };
    type Handle = *mut c_void;
    #[repr(C)]
    struct Accounting {
        user: i64,
        kernel: i64,
        period_user: i64,
        period_kernel: i64,
        faults: u32,
        total: u32,
        active: u32,
        terminated: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn TerminateJobObject(job: Handle, status: u32) -> i32;
        fn QueryInformationJobObject(
            job: Handle,
            class: i32,
            info: *mut c_void,
            size: u32,
            returned: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtResumeProcess(process: Handle) -> i32;
    }
    pub(super) struct Job(Handle);
    // SAFETY: the job is an owned kernel handle; operations are serialized by GroupControl.
    unsafe impl Send for Job {}
    // SAFETY: Win32 job query/termination support concurrent kernel-handle access.
    unsafe impl Sync for Job {}
    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: sole handle ownership; no KILL_ON_JOB_CLOSE flag is ever set.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    impl Job {
        pub(super) fn active_count(&self) -> io::Result<u32> {
            // SAFETY: initialized correctly aligned JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION.
            let mut info: Accounting = unsafe { std::mem::zeroed() };
            let mut returned = 0;
            // SAFETY: live owned job handle and exact output struct size, class=1.
            if unsafe {
                QueryInformationJobObject(
                    self.0,
                    1,
                    (&mut info as *mut Accounting).cast(),
                    std::mem::size_of::<Accounting>() as u32,
                    &mut returned,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if returned as usize != std::mem::size_of::<Accounting>() {
                return Err(io::Error::other("incomplete login job census"));
            }
            Ok(info.active)
        }
        pub(super) fn signal(&self, pid: u32, signal: GroupSignal) -> io::Result<()> {
            // SAFETY: retained job owns descendants; console event targets the own process group.
            let rc = unsafe {
                if signal == GroupSignal::Interrupt {
                    GenerateConsoleCtrlEvent(1, pid)
                } else {
                    TerminateJobObject(self.0, 130)
                }
            };
            if rc == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
    pub(super) fn exited(child: &Child) -> io::Result<bool> {
        // SAFETY: actual Child owns this process handle; zero timeout never
        // blocks or reaps it. Used only to qualify a best-effort Job snapshot.
        match unsafe { WaitForSingleObject(child.as_raw_handle(), 0) } {
            0 => Ok(true),
            258 => Ok(false),
            0xffff_ffff => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected login child wait probe")),
        }
    }
    pub(super) fn spawn(command: &mut Command) -> io::Result<(Child, GroupControl)> {
        // SAFETY: unnamed non-inherited job, initially empty, no kill-on-close policy.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Job(raw);
        command.creation_flags(0x0000_0004 | 0x0000_0200); // SUSPENDED | NEW_PROCESS_GROUP
        let mut child = command.spawn()?;
        // SAFETY: child's primary thread is still suspended, so no descendant can escape assignment.
        let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) } != 0;
        // SAFETY: retained process handle names the suspended assigned process.
        let resumed = assigned && unsafe { NtResumeProcess(child.as_raw_handle()) } >= 0;
        if !resumed {
            let failure = io::Error::other("login job assignment/resume refused");
            // The vendor never ran; stop only this owned suspended child on setup failure.
            let _ = child.kill();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return Err(failure),
                    Err(_) => break,
                    Ok(None) => {}
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            eprintln!(
                "login_custody_UNDETERMINED pgid={} suspended setup cleanup not confirmed",
                child.id()
            );
            std::mem::forget((child, job));
            return Err(failure);
        }
        let group = GroupControl(Arc::new(Inner {
            pid: child.id(),
            lease: Mutex::new(WaitLease::Retained),
            pump: Mutex::new(None),
            readers: AtomicBool::new(false),
            killed: Mutex::new(None),
            job,
        }));
        Ok((child, group))
    }
}

#[derive(Default)]
pub(super) struct ErrorBudget(u8);
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ErrorAction {
    Continue,
    #[cfg(unix)]
    LostLease,
    StopGroup,
}
impl ErrorBudget {
    pub(super) fn reset(&mut self) {
        self.0 = 0;
    }
    pub(super) fn record(
        &mut self,
        #[cfg(unix)] error: &io::Error,
        #[cfg(windows)] _: &io::Error,
    ) -> ErrorAction {
        #[cfg(unix)]
        if error.raw_os_error() == Some(libc::ECHILD) {
            return ErrorAction::LostLease;
        }
        self.0 = self.0.saturating_add(1);
        if self.0 >= 3 {
            ErrorAction::StopGroup
        } else {
            ErrorAction::Continue
        }
    }
}

#[cfg(all(test, unix))]
mod overlap_tests {
    use super::*;

    #[test]
    fn second_attended_arm_while_one_is_active_fails_closed() {
        // Hold the single custody slot as a live attended login would.
        let _held = ActiveSlot::claim().expect("slot free at test start");
        let mut command = Command::new("true");
        let error = match TerminalCustody::arm(&mut command) {
            Ok(_) => panic!("OVERLAP_NOT_REFUSED: a second arm must not degrade to unattended"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("already active"),
            "OVERLAP_WORDING: {error}"
        );
    }
}
