//! Owned vendor process groups. Timeout is never a stop request.
use super::process::{Child, Command, Stdio};
use std::{
    io,
    process::ExitStatus,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupSignal {
    #[cfg(any(feature = "cli", all(test, unix)))]
    Interrupt,
    Kill,
    #[cfg(all(unix, any(feature = "cli", test)))]
    Terminate,
    #[cfg(all(unix, any(feature = "cli", test)))]
    Hangup,
    #[cfg(all(unix, any(feature = "cli", test)))]
    Quit,
}
// Ten existing 200ms custody polls after an explicit stop intent. Expiration
// is a terminal retained-custody refusal, never proof of EOF or permission to
// clean credentials. This budget has no effect on ordinary login deadlines.
// Windows also grants this elapsed grace to observed leftover Job members
// after the original vendor/creator exited and captured readers joined.
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
#[derive(Clone, Copy)]
enum StopIntent {
    Explicit,
    #[cfg(windows)]
    Completion,
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
    // A successful native stop of THIS retained Job, not merely kill intent.
    // The wait lease serializes publication with creator/vendor observation.
    #[cfg(windows)]
    job_stop_requested: AtomicBool,
    // Only a positive census after original vendor/creator exit and reader
    // joins starts the cooperative-descendant completion grace period.
    #[cfg(windows)]
    job_nonempty_since: Mutex<Option<Instant>>,
}
#[derive(Clone)]
pub(crate) struct GroupControl(Arc<Inner>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StdinPolicy {
    #[cfg(any(unix, feature = "cli"))]
    Inherit,
    #[cfg(any(unix, feature = "desktop", test))]
    Null,
    #[cfg(test)]
    Caller,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupStop {
    Signal(i32),
    // The member census observes state, not the signal that stopped it.
    Unknown,
}

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
    #[cfg(any(feature = "cli", test))]
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
    /// A stop observed under the retained wait lease. The leader's signal
    /// comes from waitid(WSTOPPED|WNOWAIT); the optional member census observes
    /// only stopped state. A positive census refreshes the leader once before
    /// reporting an unknown signal. Read-only: never reaps. The unreaped leader
    /// reserves the numeric PGID.
    #[cfg(unix)]
    pub(crate) fn stop_observation(&self, scan_members: bool) -> Option<GroupStop> {
        let Ok(lease) = self.0.lease.lock() else {
            return None;
        };
        if *lease != WaitLease::Retained {
            return None;
        }
        // A leader that has already exited (unreaped) means the login is over:
        // its members are the freeze/census's to reap, never a suspension, so an
        // exit-0 login is not turned into a cancellation by a stopped helper.
        if leader_has_exited(self.id()) {
            return None;
        }
        if let Some(signal) = self.leader_stop_signal() {
            return Some(GroupStop::Signal(signal));
        }
        if scan_members && group_has_stopped_member(self.id()) {
            // The leader may have stopped after the first waitid but before
            // the census. Refresh once under this same retained lease before
            // classifying the stop as an unidentified nonleader observation.
            return Some(
                self.leader_stop_signal()
                    .map_or(GroupStop::Unknown, GroupStop::Signal),
            );
        }
        None
    }
    #[cfg(unix)]
    fn leader_stop_signal(&self) -> Option<i32> {
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
                #[cfg(target_os = "linux")]
                // SAFETY: waitid initialized the SIGCHLD arm.
                let signal = unsafe { info.si_status() };
                #[cfg(target_os = "macos")]
                let signal = info.si_status;
                return Some(signal);
            }
        }
        None
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
    #[cfg(all(windows, test, feature = "desktop"))]
    pub(crate) fn job_stop_requested_for_test(&self) -> bool {
        self.0.job_stop_requested.load(Ordering::Acquire)
    }
    #[cfg(any(feature = "cli", test))]
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
        self.signal_with_lease(signal, &mut lease, StopIntent::Explicit)?;
        Ok(GroupStopDecision::StopRequested)
    }
    pub(crate) fn signal(&self, signal: GroupSignal) -> io::Result<()> {
        let mut lease = self
            .0
            .lease
            .lock()
            .map_err(|_| io::Error::other("login group lease poisoned"))?;
        self.signal_with_lease(signal, &mut lease, StopIntent::Explicit)
    }
    fn signal_with_lease(
        &self,
        signal: GroupSignal,
        lease: &mut WaitLease,
        intent: StopIntent,
    ) -> io::Result<()> {
        if *lease != WaitLease::Retained {
            return Err(io::Error::other("login group wait lease unavailable"));
        }
        if matches!(signal, GroupSignal::Kill) && matches!(intent, StopIntent::Explicit) {
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
                #[cfg(any(feature = "cli", test))]
                GroupSignal::Interrupt => libc::SIGINT,
                GroupSignal::Kill => libc::SIGKILL,
                #[cfg(any(feature = "cli", test))]
                GroupSignal::Terminate => libc::SIGTERM,
                #[cfg(any(feature = "cli", test))]
                GroupSignal::Hangup => libc::SIGHUP,
                #[cfg(any(feature = "cli", test))]
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
            self.0.job.signal(self.id(), signal)?;
            if matches!(signal, GroupSignal::Kill) {
                // TerminateJobObject succeeded, but individual original process
                // handles may become signaled in either order. Keep all exit,
                // reader and empty-Job gates; record no success for failed calls.
                // https://learn.microsoft.com/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject
                self.0.job_stop_requested.store(true, Ordering::Release);
            }
            Ok(())
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
        #[cfg(windows)]
        {
            // signal_with_lease holds the same lock through the native call
            // and successful-stop publication. An in-flight explicit stop can
            // never look like an unexplained creator exit between these probes.
            let mut lease = self
                .0
                .lease
                .lock()
                .map_err(|_| io::Error::other("login group lease poisoned"))?;
            match child.poll_creator_lifecycle(self.0.job_stop_requested.load(Ordering::Acquire)) {
                Ok(true) => {}
                Ok(false) => return Ok(None),
                Err(error) => {
                    // Unexpected creator death remains an observation error.
                    // Stop this exact Job through the already-held lease (no
                    // recursive lock), consistently recording successful stop.
                    let _stop =
                        self.signal_with_lease(GroupSignal::Kill, &mut lease, StopIntent::Explicit);
                    return Err(error);
                }
            }
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
                Ok(true) => {
                    // Darwin can fill a stopped child's siginfo under WEXITED.
                    // Freeze only after its actual exit code is observed.
                    if !leader_has_exited(self.id()) {
                        return Ok(None);
                    }
                }
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
                return Err(io::Error::other(CensusRefusal::Unix));
            }
        }
        #[cfg(windows)]
        {
            let ready = job_completion_ready(win::exited(child), || self.0.job.active_count());
            let ready = match ready {
                Err(error) if is_nonempty_job_refusal(&error) => {
                    let now = Instant::now();
                    let mut since = self
                        .0
                        .job_nonempty_since
                        .lock()
                        .map_err(|_| io::Error::other("login Job census clock poisoned"))?;
                    let first = *since.get_or_insert(now);
                    if now.duration_since(first) < STOP_DRAIN_BUDGET {
                        return Err(error);
                    }
                    // The original vendor and creator have exited, and all
                    // captured readers joined. A leftover cooperative child is
                    // cleanup custody, just as on Unix; it cannot hold login
                    // completion forever. Do not turn this cleanup into an
                    // operator cancellation or replace the vendor's exit code.
                    self.signal_with_lease(GroupSignal::Kill, &mut lease, StopIntent::Completion)?;
                    match job_completion_ready(win::exited(child), || self.0.job.active_count()) {
                        // TerminateJobObject is asynchronous. A still-dying
                        // member is pending, never permission to finalize.
                        Err(error) if is_nonempty_job_refusal(&error) => return Ok(None),
                        result => result,
                    }
                }
                result => result,
            }?;
            if !ready {
                return Ok(None);
            }
        }
        #[cfg(unix)]
        let result = child.try_wait();
        // The retained process handle already proved exit and the Job census
        // proved empty. Waiting now cannot block on a live vendor; it also
        // closes any remaining parent stdin endpoint through the child owner.
        #[cfg(windows)]
        let result = child.wait().map(Some);
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

// In normal operation the creator waits for the original vendor before exit.
// Observe creator first, then freshly query vendor. A successful stop of this
// exact Job can instead terminate creator before vendor: retain pending custody
// until both original handles prove exit. Stop intent alone grants no exception.
#[cfg(any(windows, test))]
pub(super) fn creator_retirement_ready(
    job_stop_requested: bool,
    helper_exited: impl FnOnce() -> io::Result<bool>,
    vendor_exited: impl FnOnce() -> io::Result<bool>,
) -> io::Result<bool> {
    if !helper_exited()? {
        return Ok(false);
    }
    if !vendor_exited()? {
        if job_stop_requested {
            return Ok(false);
        }
        return Err(io::Error::other("login_creator_exited_before_vendor"));
    }
    Ok(true)
}

// An exited leader is no longer active in its retained kernel Job. Only a
// successful empty-Job census may permit the original Child reap. Typed
// refusals retain the wait lease and enter custody's elapsed census budget.
#[cfg(any(windows, test))]
fn job_completion_ready(
    exited: io::Result<bool>,
    active_count: impl FnOnce() -> io::Result<u32>,
) -> io::Result<bool> {
    match exited {
        Ok(false) => return Ok(false),
        Err(_) => return Err(io::Error::other(CensusRefusal::ExitUnavailable)),
        Ok(true) => {}
    }
    match active_count() {
        Ok(0) => Ok(true),
        Ok(count) => {
            eprintln!("login_group_members_remaining={count}");
            Err(io::Error::other(CensusRefusal::Nonempty))
        }
        Err(_) => Err(io::Error::other(CensusRefusal::Unavailable)),
    }
}

#[cfg(windows)]
fn is_nonempty_job_refusal(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<CensusRefusal>())
        .is_some_and(|refusal| matches!(refusal, CensusRefusal::Nonempty))
}

#[cfg(test)]
#[path = "group_windows_tests.rs"]
mod windows_tests;

// Only the desktop login commands (and this module's tests) spawn an
// unattended group; a `--no-default-features --features cli` build has no
// caller, so the function is compiled only where one exists.
#[cfg(any(feature = "desktop", test))]
pub(crate) fn spawn(
    command: &mut Command,
    stdin_policy: StdinPolicy,
) -> io::Result<(Child, GroupControl)> {
    spawn_with(command, false, true, stdin_policy)
}

/// Spawn an ATTENDED login (csq's own stdin is its controlling
/// terminal, as in `csq login N`): the vendor's new process group is also made
/// the terminal's foreground group, so the vendor may use the tty without
/// being stopped by SIGTTOU/SIGTTIN. Foreground returns to csq when the leader
/// is reaped or the group handle drops. When csq has no foreground terminal
/// custody (including a background job), the vendor instead starts a detached
/// session. Inherit policy then becomes Null; Caller preserves configured
/// input. Stdout/stderr configuration is preserved. Desktop callers use `spawn`.
#[cfg(any(feature = "cli", all(test, unix)))]
pub(crate) fn spawn_attended(
    command: &mut Command,
    stdin_policy: StdinPolicy,
) -> io::Result<(Child, GroupControl)> {
    spawn_with(command, true, false, stdin_policy)
}

// Synthetic custody fixtures control lifetime over an explicit stdin pipe and
// may join a sibling to the leader's group in the test process's own session.
// Production desktop callers continue to use the detached `spawn` above.
#[cfg(test)]
pub(crate) fn spawn_controlled_fixture_for_test(
    command: &mut Command,
) -> io::Result<(Child, GroupControl)> {
    spawn_with(command, false, false, StdinPolicy::Caller)
}

#[cfg(all(test, unix))]
pub(crate) fn spawn_legacy_unattended_for_tty_test(
    command: &mut Command,
) -> io::Result<(Child, GroupControl)> {
    spawn_with(command, false, false, StdinPolicy::Caller)
}

/// Stdin is an explicit caller policy (I-3), never inferred from Command.
/// Null replaces configured input; Caller preserves it. Inherit selects the
/// parent's input except when a Unix attended handoff is declined, when it
/// becomes Null. Desktop callers select Null; input-bearing fixtures select
/// Caller. Both detached routes preserve the caller's stdout/stderr settings.
///
/// A caller-supplied process_group is applied by std before pre_exec (I-4).
/// If it makes the detached child a group leader, setsid refuses with EPERM;
/// spawn returns the error. The foreground route sets process_group(0).
/// These one-shot Commands retain their registered handoff/detachment hooks.
fn spawn_with(
    command: &mut Command,
    attended: bool,
    detached: bool,
    stdin_policy: StdinPolicy,
) -> io::Result<(Child, GroupControl)> {
    // Arm before selecting the route: a declined handoff must not leave the
    // vendor in another background group of the controlling session.
    #[cfg(unix)]
    let mut foreground = if attended {
        TerminalCustody::arm(command)?
    } else {
        None
    };
    #[cfg(unix)]
    let attended_fallback = attended && foreground.is_none();
    #[cfg(unix)]
    let stdin_policy = if attended_fallback && stdin_policy == StdinPolicy::Inherit {
        StdinPolicy::Null
    } else {
        stdin_policy
    };
    match stdin_policy {
        #[cfg(any(unix, feature = "cli"))]
        StdinPolicy::Inherit => {
            command.stdin(Stdio::inherit());
        }
        #[cfg(any(unix, feature = "desktop", test))]
        StdinPolicy::Null => {
            command.stdin(Stdio::null());
        }
        #[cfg(test)]
        StdinPolicy::Caller => {}
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        if detached || attended_fallback {
            // SAFETY: setsid is async-signal-safe and touches only this new
            // child. It also makes pid == pgid, preserving owned group signals.
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        } else {
            command.process_group(0);
        }
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
        let _ = (attended, detached);
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

/// try_reap's typed refusal: no original-child reap or finalized receipt.
#[derive(Debug)]
pub(crate) enum CensusRefusal {
    #[cfg(unix)]
    Unix,
    #[cfg(any(windows, test))]
    Nonempty,
    #[cfg(any(windows, test))]
    Unavailable,
    #[cfg(any(windows, test))]
    ExitUnavailable,
}
impl std::fmt::Display for CensusRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            #[cfg(unix)]
            Self::Unix => "login group not proven empty",
            #[cfg(any(windows, test))]
            Self::Nonempty => "login_job_census_nonempty",
            #[cfg(any(windows, test))]
            Self::Unavailable => "login_job_census_unavailable",
            #[cfg(any(windows, test))]
            Self::ExitUnavailable => "login_job_exit_observation_unavailable",
        })
    }
}
impl std::error::Error for CensusRefusal {}
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
    use std::{ffi::c_void, os::windows::io::AsRawHandle};
    type Handle = *mut c_void;
    #[cfg(test)]
    type PostCreateHook = Box<dyn FnOnce(u32, Handle) -> io::Result<()>>;
    #[cfg(test)]
    std::thread_local! {
        static POST_CREATE_HOOK: std::cell::RefCell<Option<PostCreateHook>> = const {
            std::cell::RefCell::new(None)
        };
    }
    #[cfg(test)]
    pub(super) fn set_post_create_before_resume_hook_for_test(
        hook: impl FnOnce(u32, Handle) -> io::Result<()> + 'static,
    ) {
        POST_CREATE_HOOK.with(|slot| {
            assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
        });
    }
    #[cfg(test)]
    pub(super) fn post_create_before_resume_for_test(pid: u32, handle: Handle) -> io::Result<()> {
        let hook = POST_CREATE_HOOK.with(|slot| slot.borrow_mut().take());
        match hook {
            Some(hook) => hook(pid, handle),
            None => Ok(()),
        }
    }
    const EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const KILL_ON_JOB_CLOSE: u32 = 0x2000;
    // Win32 JOBOBJECT_BASIC_LIMIT_INFORMATION; usize matches SIZE_T/ULONG_PTR.
    #[repr(C)]
    #[derive(Default)]
    struct BasicLimits {
        process_time: i64,
        job_time: i64,
        flags: u32,
        min_working_set: usize,
        max_working_set: usize,
        active_limit: u32,
        affinity: usize,
        priority: u32,
        scheduling: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_ops: u64,
        write_ops: u64,
        other_ops: u64,
        read_bytes: u64,
        write_bytes: u64,
        other_bytes: u64,
    }
    // Win32 JOBOBJECT_EXTENDED_LIMIT_INFORMATION, including its reserved IO
    // counters and all four pointer-width memory fields (not a byte buffer).
    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimits {
        basic: BasicLimits,
        io: IoCounters,
        process_memory: usize,
        job_memory: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }
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
        fn TerminateJobObject(job: Handle, status: u32) -> i32;
        fn SetInformationJobObject(job: Handle, class: i32, info: *mut c_void, size: u32) -> i32;
        fn QueryInformationJobObject(
            job: Handle,
            class: i32,
            info: *mut c_void,
            size: u32,
            returned: *mut u32,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        #[cfg(feature = "cli")]
        fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
    }
    pub(super) struct Job(Handle);
    // SAFETY: the job is an owned kernel handle; operations are serialized by GroupControl.
    unsafe impl Send for Job {}
    // SAFETY: Win32 job query/termination support concurrent kernel-handle access.
    unsafe impl Sync for Job {}
    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: sole non-inherited handle, closed once. Its last close
            // terminates remaining members of a configured kill-on-close Job.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    impl Job {
        fn configure_kill_on_close(&self) -> io::Result<()> {
            let mut limits = ExtendedLimits::default();
            // No BREAKAWAY_OK (0x800) or SILENT_BREAKAWAY_OK (0x1000): contains
            // cooperative descendants; this is not a same-user isolation
            // boundary. An equally privileged process may duplicate our handle
            // or change the Job policy. Login does not exempt browser children:
            // a fresh child stays contained, while a shell's IPC handoff to an
            // already running process creates no member of this Job.
            limits.basic.flags = KILL_ON_JOB_CLOSE;
            // SAFETY: live owned empty Job, aligned class-9 input structure
            // and exact byte size. Only the kill-on-close policy is enabled.
            if unsafe {
                SetInformationJobObject(
                    self.0,
                    EXTENDED_LIMIT_INFORMATION,
                    std::ptr::addr_of_mut!(limits).cast(),
                    std::mem::size_of::<ExtendedLimits>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(test)]
        pub(super) fn limit_flags_for_test(&self) -> io::Result<u32> {
            let mut limits = ExtendedLimits::default();
            let mut returned = 0;
            // SAFETY: retained production Job and aligned class-9 output with
            // exact writable capacity. The kernel, not a configured constant,
            // supplies the flags read by the native qualification test.
            if unsafe {
                QueryInformationJobObject(
                    self.0,
                    EXTENDED_LIMIT_INFORMATION,
                    std::ptr::addr_of_mut!(limits).cast(),
                    std::mem::size_of::<ExtendedLimits>() as u32,
                    &mut returned,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if returned as usize != std::mem::size_of::<ExtendedLimits>() {
                return Err(io::Error::other("incomplete login Job limits"));
            }
            Ok(limits.basic.flags)
        }
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
            #[cfg(not(feature = "cli"))]
            let _ = pid;
            // SAFETY: retained job owns descendants; console event targets the own process group.
            let rc = unsafe {
                match signal {
                    #[cfg(feature = "cli")]
                    GroupSignal::Interrupt => GenerateConsoleCtrlEvent(1, pid),
                    GroupSignal::Kill => TerminateJobObject(self.0, 130),
                }
            };
            if rc == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
    #[cfg(all(test, target_pointer_width = "64"))]
    #[test]
    fn extended_limits_match_win64_layout() {
        assert_eq!(std::mem::size_of::<BasicLimits>(), 64);
        assert_eq!(std::mem::size_of::<IoCounters>(), 48);
        assert_eq!(std::mem::size_of::<ExtendedLimits>(), 144);
        assert_eq!(std::mem::align_of::<ExtendedLimits>(), 8);
        assert_eq!(std::mem::offset_of!(BasicLimits, flags), 16);
        assert_eq!(std::mem::offset_of!(ExtendedLimits, io), 64);
        assert_eq!(std::mem::offset_of!(ExtendedLimits, process_memory), 112);
    }
    pub(super) fn exited(child: &Child) -> io::Result<bool> {
        // SAFETY: actual Child owns this process handle; zero timeout never
        // blocks or reaps it. Qualifies the fail-closed retained-Job census.
        match unsafe { WaitForSingleObject(child.as_raw_handle(), 0) } {
            0 => Ok(true),
            258 => Ok(false),
            0xffff_ffff => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected login child wait probe")),
        }
    }
    pub(super) fn spawn(command: &mut Command) -> io::Result<(Child, GroupControl)> {
        // SAFETY: unnamed non-inherited Job, initially empty. Configuration
        // must succeed before any vendor process is created.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Job(raw);
        job.configure_kill_on_close()?;
        // Automatic stdio creates the vendor in this Job. Owned stdio creates
        // a private creator in it; that creator's child inherits membership in
        // the nonbreakaway Job. All Job handles stay in this main process. A
        // setup error can retain quarantined custody; preserve its payload.
        let child = super::super::windows_process::spawn(command, job.0, |pid, handle| {
            #[cfg(test)]
            {
                post_create_before_resume_for_test(pid, handle)
            }
            #[cfg(not(test))]
            {
                let _ = (pid, handle);
                Ok(())
            }
        })
        .map_err(super::super::windows_process::recover_setup_error)?;
        let group = GroupControl(Arc::new(Inner {
            pid: child.id(),
            lease: Mutex::new(WaitLease::Retained),
            pump: Mutex::new(None),
            readers: AtomicBool::new(false),
            killed: Mutex::new(None),
            job,
            job_stop_requested: AtomicBool::new(false),
            job_nonempty_since: Mutex::new(None),
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
