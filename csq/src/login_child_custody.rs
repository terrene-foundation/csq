//! Binary-private vendor ownership. A timeout refuses publication, not custody.

use std::fmt;
use std::io;
use std::process::{Child, ExitStatus};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[path = "login_child_custody/group.rs"]
pub(crate) mod group;
use group::{ErrorAction, ErrorBudget, GroupControl, GroupSignal};

const POLL_INTERVAL: Duration = Duration::from_millis(200);

pub(crate) fn parse_timeout(raw: Option<&str>) -> Duration {
    Duration::from_secs(
        raw.and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(300),
    )
}

#[cfg(any(feature = "desktop", test))]
pub(crate) fn login_timeout() -> Duration {
    parse_timeout(std::env::var("CSQ_LOGIN_TIMEOUT_SECS").ok().as_deref())
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DeliveryPhase {
    Unknown,
    #[cfg(test)]
    PostDelivery,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryKind {
    Unknown,
    PostDelivery,
}

#[cfg(test)]
impl DeliveryPhase {
    fn kind(self) -> DeliveryKind {
        match self {
            Self::Unknown => DeliveryKind::Unknown,
            Self::PostDelivery => DeliveryKind::PostDelivery,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefusalReason {
    Timeout,
    ObservationFailed,
    SetupFailed,
    DeadlineOverflow,
    Cancelled,
    /// The vendor's group was not proven empty within the census budget.
    #[cfg(unix)]
    GroupCensus,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LoginChildRefusal {
    pub(crate) reason: RefusalReason,
    pub(crate) custody_pgid: Option<u32>,
    /// Present only after actual Child::try_wait observed/reaped this child.
    #[cfg(test)]
    pub(crate) status: Option<ExitStatus>,
}

impl LoginChildRefusal {
    pub(crate) fn tag(self) -> &'static str {
        match self.reason {
            RefusalReason::Timeout => "login_timeout_refused",
            RefusalReason::Cancelled => "login_cancelled_refused",
            RefusalReason::ObservationFailed => "login_child_observation_refused",
            RefusalReason::SetupFailed => "login_child_setup_refused",
            RefusalReason::DeadlineOverflow => "login_deadline_overflow_refused",
            #[cfg(unix)]
            RefusalReason::GroupCensus => "login_group_census_refused",
        }
    }
}

impl fmt::Display for LoginChildRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(pgid) = self.custody_pgid {
            return write!(
                out,
                "login_custody_UNDETERMINED pgid={pgid}: canonical publication and cleanup refused"
            );
        }
        write!(out, "{}: canonical login publication refused", self.tag())
    }
}
impl std::error::Error for LoginChildRefusal {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimeoutDisposition {
    /// Custody retained past the deadline: no caller-authorized PRE stop.
    Retained,
    /// The caller authorized a stop and the process group was killed at the
    /// deadline; custody still lasts until the actual reap.
    Terminated,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TimeoutNotice {
    #[cfg(test)]
    pub(crate) phase: DeliveryKind,
    pub(crate) disposition: TimeoutDisposition,
    pub(crate) reason: RefusalReason,
}

impl TimeoutNotice {
    pub(crate) fn tag(self) -> &'static str {
        LoginChildRefusal {
            reason: self.reason,
            custody_pgid: None,
            #[cfg(test)]
            status: None,
        }
        .tag()
    }
}
impl fmt::Display for TimeoutNotice {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        let custody = match self.disposition {
            TimeoutDisposition::Retained => "sign-in program is still running; in this terminal press Ctrl-C once to interrupt its process group, then again to end the group explicitly; the deadline alone never kills it",
            TimeoutDisposition::Terminated => "sign-in program was terminated at the deadline",
        };
        write!(
            out,
            "{}: {custody}; canonical login publication refused",
            self.tag()
        )
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Running,
    Refused(RefusalReason),
    Sealed(ExitStatus),
}
struct State {
    outcome: Outcome,
    custody_pgid: Option<u32>,
    #[cfg(test)]
    reaped: Option<ExitStatus>,
}

/// Independent observer metadata; it never owns or drops a child handle.
#[derive(Clone)]
pub(crate) struct LoginWatchdog {
    state: Arc<Mutex<State>>,
    deadline: Option<Instant>,
    #[cfg(test)]
    phase: DeliveryPhase,
}

impl LoginWatchdog {
    pub(crate) fn new(timeout: Duration, _phase: DeliveryPhase) -> Self {
        let deadline = Instant::now().checked_add(timeout);
        let outcome = if deadline.is_some() {
            Outcome::Running
        } else {
            Outcome::Refused(RefusalReason::DeadlineOverflow)
        };
        Self {
            state: Arc::new(Mutex::new(State {
                outcome,
                custody_pgid: None,
                #[cfg(test)]
                reaped: None,
            })),
            deadline,
            #[cfg(test)]
            phase: _phase,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| {
            eprintln!("login_custody_state_poisoned: retaining actual vendor ownership");
            let mut state = error.into_inner();
            state.outcome = Outcome::Refused(RefusalReason::ObservationFailed);
            state
        })
    }

    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    #[cfg(all(test, feature = "desktop"))]
    // ROOT02c3e45c: path-included timeout/ctrlc/Codex/native/publication integration crates do not use this desktop-only fixture.
    #[allow(dead_code)]
    pub(crate) fn malformed_for_test() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                outcome: Outcome::Running,
                custody_pgid: None,
                reaped: None,
            })),
            deadline: None,
            phase: DeliveryPhase::Unknown,
        }
    }
    pub(crate) fn check_spawn_allowed(&self) -> Result<(), LoginChildRefusal> {
        match self.refusal() {
            Some(refusal) => Err(refusal),
            None => Ok(()),
        }
    }

    fn refuse(&self, reason: RefusalReason) -> bool {
        let mut state = self.state();
        if matches!(state.outcome, Outcome::Running) {
            state.outcome = Outcome::Refused(reason);
            return true;
        }
        false
    }

    /// Authorize only an explicit confirmed stop before publication is sealed.
    /// Existing refusal keeps its first cause and still permits user cancellation.
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn refuse_cancelled(&self) -> bool {
        let mut state = self.state();
        match state.outcome {
            Outcome::Running => {
                state.outcome = Outcome::Refused(RefusalReason::Cancelled);
                true
            }
            Outcome::Refused(_) => true,
            Outcome::Sealed(_) => false,
        }
    }

    pub(crate) fn refuse_setup(&self) {
        self.refuse(RefusalReason::SetupFailed);
    }
    pub(crate) fn observe_deadline(&self) -> bool {
        self.deadline_reached() && self.refuse(RefusalReason::Timeout)
    }
    /// Pure deadline read: the deadline ACTION is due whether or not an
    /// earlier refusal already won, so a setup failure cannot suppress it.
    pub(crate) fn deadline_reached(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
    #[cfg(test)]
    pub(crate) fn is_refused(&self) -> bool {
        self.refusal().is_some()
    }
    pub(crate) fn refusal(&self) -> Option<LoginChildRefusal> {
        let state = self.state();
        match state.outcome {
            Outcome::Refused(reason) => Some(LoginChildRefusal {
                reason,
                custody_pgid: state.custody_pgid,
                #[cfg(test)]
                status: state.reaped,
            }),
            _ => None,
        }
    }

    #[cfg(test)]
    fn record_reaped(&self, status: ExitStatus) {
        self.state().reaped = Some(status);
    }

    #[cfg(test)]
    pub(crate) fn reaped_status(&self) -> Option<ExitStatus> {
        self.state().reaped
    }

    /// Caller supplies actual child reap AND reader/forwarder join proof.
    /// This mutex is the only authorization transition, not a later flag check.
    #[cfg(test)]
    fn seal_vendor(&self, status: ExitStatus) -> Result<ExitStatus, LoginChildRefusal> {
        self.seal_vendor_cancelled(status, &mut || false)
    }

    fn seal_vendor_cancelled(
        &self,
        status: ExitStatus,
        cancelled: &mut impl FnMut() -> bool,
    ) -> Result<ExitStatus, LoginChildRefusal> {
        let mut state = self.state();
        // Observe the terminal latch under the same mutex as publication sealing.
        // Existing timeout/setup refusal retains its first cause.
        if cancelled() && matches!(state.outcome, Outcome::Running) {
            state.outcome = Outcome::Refused(RefusalReason::Cancelled);
        }
        #[cfg(test)]
        {
            state.reaped = Some(status);
        }
        // A late first poll cannot authorize publication merely because no
        // observer happened to wake exactly at the deadline.
        if matches!(state.outcome, Outcome::Running)
            && self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            state.outcome = Outcome::Refused(RefusalReason::Timeout);
        }
        match state.outcome {
            Outcome::Running => {
                state.outcome = Outcome::Sealed(status);
                Ok(status)
            }
            Outcome::Sealed(status) => Ok(status),
            Outcome::Refused(reason) => Err(LoginChildRefusal {
                reason,
                custody_pgid: state.custody_pgid,
                #[cfg(test)]
                status: Some(status),
            }),
        }
    }
}

type WaitObserver =
    dyn FnMut(&GroupControl, &mut Child, bool) -> io::Result<Option<ExitStatus>> + Send;

/// Sole owner retains the leader until actual exit and every captured reader joins.
pub(crate) struct OwnedLoginChild<K> {
    child: Arc<Mutex<Child>>,
    group: GroupControl,
    watchdog: LoginWatchdog,
    reaped: Option<ExitStatus>,
    errors: ErrorBudget,
    stop_deadline: Option<Instant>,
    /// First census refusal of this custody; the census budget runs from it.
    #[cfg(unix)]
    census_refused_since: Option<Instant>,
    terminal: bool,
    /// True once the caller's deadline stop actually SUCCEEDED. Carried out of
    /// the wait loop to the caller: the CLI's operator paragraph and the
    /// post-reap TERMINATED notice key on this, never on the refusal cause.
    deadline_stopped: bool,
    auxiliary_errors: ErrorBudget,
    observer: Option<Box<WaitObserver>>,
    keepalive: Option<K>,
}
impl<K> OwnedLoginChild<K> {
    pub(crate) fn adopt_group(
        child: Child,
        group: GroupControl,
        watchdog: LoginWatchdog,
        keepalive: K,
    ) -> Self {
        Self {
            child: Arc::new(Mutex::new(child)),
            group,
            watchdog,
            reaped: None,
            errors: ErrorBudget::default(),
            stop_deadline: None,
            #[cfg(unix)]
            census_refused_since: None,
            terminal: false,
            deadline_stopped: false,
            auxiliary_errors: ErrorBudget::default(),
            observer: None,
            keepalive: Some(keepalive),
        }
    }
    pub(crate) fn shared_child(&self) -> Arc<Mutex<Child>> {
        Arc::clone(&self.child)
    }
    #[cfg(any(test, feature = "desktop"))]
    pub(crate) fn group_control(&self) -> GroupControl {
        self.group.clone()
    }
    /// Actual child reap and every captured reader join authorize grant cleanup.
    pub(crate) fn custody_finalized(&self) -> bool {
        self.reaped.is_some() && self.group.readers_joined() && !self.watchdog.custody_unresolved()
    }
    #[cfg(test)]
    pub(crate) fn reaped_status(&self) -> Option<ExitStatus> {
        self.reaped
    }

    #[cfg(all(test, unix))]
    fn set_wait_observer(
        &mut self,
        observer: impl FnMut(&GroupControl, &mut Child, bool) -> io::Result<Option<ExitStatus>>
            + Send
            + 'static,
    ) {
        self.observer = Some(Box::new(observer));
    }
    fn terminal_refusal(&mut self) {
        self.terminal_refusal_for(RefusalReason::ObservationFailed);
    }
    /// An earlier refusal keeps its first cause; `reason` applies only if none.
    fn terminal_refusal_for(&mut self, reason: RefusalReason) {
        self.watchdog.refuse(reason);
        self.terminal = true;
        if self.reaped.is_none() || !self.group.readers_joined() {
            self.watchdog.mark_custody_unresolved(self.group.id());
            eprintln!(
                "login_custody_UNDETERMINED pgid={}: actual child/reader finalization incomplete",
                self.group.id()
            );
        }
    }
    fn observe_kill_intent(&mut self) {
        if self.stop_deadline.is_none() {
            if let Some(at) = self.group.kill_requested_at() {
                self.watchdog.refuse_cancelled_unconditional();
                self.stop_deadline = at.checked_add(group::STOP_DRAIN_BUDGET);
                if self.stop_deadline.is_none() {
                    self.terminal_refusal();
                }
            }
        }
    }
    fn observe_result(&mut self, result: io::Result<Option<ExitStatus>>) {
        match result {
            Ok(Some(status)) => {
                self.errors.reset();
                self.reaped = Some(status);
                #[cfg(test)]
                self.watchdog.record_reaped(status);
            }
            Ok(None) => self.errors.reset(),
            // The group was not proven empty before the reap (try_reap froze it
            // with SIGKILL first, so a Survivor is a member still dying). An
            // ELAPSED budget, STOP_DRAIN_BUDGET from the first refusal, bounds
            // the wait for it to die; never a poll count, whose wall time
            // depends on the poll interval. At the deadline: a terminal refusal
            // that retains custody (never a reap-as-complete), cause named.
            #[cfg(unix)]
            Err(error) if group::is_census_refusal(&error) => {
                let now = Instant::now();
                let since = *self.census_refused_since.get_or_insert(now);
                if now.duration_since(since) >= group::STOP_DRAIN_BUDGET {
                    self.terminal_refusal_for(RefusalReason::GroupCensus);
                }
            }
            Err(error) => {
                self.watchdog.refuse(RefusalReason::ObservationFailed);
                match self.errors.record(&error) {
                    ErrorAction::Continue => {}
                    #[cfg(unix)]
                    ErrorAction::LostLease => {
                        self.group.invalidate_wait_lease();
                        self.terminal_refusal();
                    }
                    ErrorAction::StopGroup => {
                        if self.stop_deadline.is_none() {
                            // Exceptional observation failure is ROOT-authorized; timeout never enters this path.
                            if self.group.signal(GroupSignal::Kill).is_err() {
                                self.terminal_refusal();
                            }
                            self.stop_deadline =
                                Instant::now().checked_add(group::STOP_DRAIN_BUDGET);
                            if self.stop_deadline.is_none() {
                                self.terminal_refusal();
                            }
                        }
                    }
                }
            }
        }
        if self.stop_deadline.is_some_and(|at| Instant::now() >= at)
            && (self.reaped.is_none() || !self.group.readers_joined())
        {
            self.terminal_refusal();
        }
    }
    fn poll_child(&mut self, joined: bool) {
        if self.reaped.is_some() || self.terminal {
            return;
        }
        let result = match self.child.lock() {
            Ok(mut child) => {
                if self.stop_deadline.is_some() {
                    self.group.try_reap(&mut child, joined)
                } else if let Some(observe) = self.observer.as_mut() {
                    observe(&self.group, &mut child, joined)
                } else {
                    self.group.try_reap(&mut child, joined)
                }
            }
            Err(_) => Err(io::Error::other("owned login child mutex poisoned")),
        };
        self.observe_result(result);
    }
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn wait_vendor(
        &mut self,
        tick: impl FnMut() -> io::Result<bool>,
        notice: impl FnMut(TimeoutNotice),
        graceful: impl FnMut() -> io::Result<()>,
    ) -> Result<ExitStatus, LoginChildRefusal> {
        self.wait_vendor_cancelled(tick, notice, graceful, || false)
    }
    pub(crate) fn wait_vendor_cancelled(
        &mut self,
        tick: impl FnMut() -> io::Result<bool>,
        mut notice: impl FnMut(TimeoutNotice),
        graceful: impl FnMut() -> io::Result<()>,
        cancelled: impl FnMut() -> bool,
    ) -> Result<ExitStatus, LoginChildRefusal> {
        let result = self.wait_vendor_loop(tick, &mut notice, graceful, cancelled);
        // A TERMINATED refusal is announced only AFTER the actual reap: it
        // reports what the stop did, never what it was asked to do. It fires
        // even when an EARLIER refusal (e.g. a setup error) was recorded first.
        if self.deadline_stopped {
            if let Some(refusal) = self.watchdog.refusal() {
                notice(TimeoutNotice {
                    #[cfg(test)]
                    phase: self.watchdog.phase.kind(),
                    disposition: TimeoutDisposition::Terminated,
                    reason: refusal.reason,
                });
            }
        }
        result
    }
    /// Whether the caller's deadline stop actually succeeded; callers carry
    /// this out of the wait (the CLI operator paragraph keys on it).
    pub(crate) fn deadline_stopped(&self) -> bool {
        self.deadline_stopped
    }
    // The observer is injected through the same production loop, never a cfg(test) alternative.
    fn wait_vendor_loop(
        &mut self,
        mut tick: impl FnMut() -> io::Result<bool>,
        mut notice: impl FnMut(TimeoutNotice),
        mut graceful: impl FnMut() -> io::Result<()>,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<ExitStatus, LoginChildRefusal> {
        let mut announced = false;
        // None until the deadline is first observed; Some(granted) records
        // whether the caller authorized the PRE stop at that moment.
        let mut deadline_stop: Option<bool> = None;
        // One bounded retry when the caller's stop errors (bounded = at most
        // two calls for the whole vendor wait).
        let mut deadline_stop_retried = false;
        loop {
            if cancelled() {
                self.watchdog.refuse_cancelled_unconditional();
            }
            let pump = self.group.pump_signals();
            let tick = tick();
            let joined = tick.as_ref().copied().unwrap_or(false);
            match pump.and(tick.map(|_| ())) {
                Ok(()) => self.auxiliary_errors.reset(),
                Err(error) => {
                    self.watchdog.refuse_setup();
                    if self.auxiliary_errors.record(&error) != ErrorAction::Continue {
                        self.terminal_refusal();
                    }
                }
            }
            if joined {
                self.group.mark_readers_joined();
            }
            self.observe_kill_intent();
            self.poll_child(joined);
            if self.terminal {
                return Err(self
                    .watchdog
                    .refusal()
                    .unwrap_or_else(|| self.observation_refusal()));
            }
            self.watchdog.observe_deadline();
            // The deadline action is due when the DEADLINE passes, whatever
            // refusal was recorded first: a setup failure must not suppress a
            // stop the caller's deadline authorizes. The stop runs once; if it
            // errors it is retried exactly once, then left refused.
            if self.watchdog.deadline_reached() {
                if deadline_stop.is_none() {
                    // A refusal (desktop: no proven PRE stop path) retains
                    // custody; a granted stop kills the process group, and the
                    // loop still waits for the ACTUAL reap below.
                    deadline_stop = Some(graceful().is_ok());
                } else if deadline_stop == Some(false) && !deadline_stop_retried {
                    deadline_stop_retried = true;
                    if graceful().is_ok() {
                        deadline_stop = Some(true);
                    }
                }
                if deadline_stop == Some(true) {
                    // Carry the SUCCEEDED stop out of the loop: the operator
                    // paragraph and the terminated notice key on this fact.
                    self.deadline_stopped = true;
                }
            }
            if let Some(refusal) = self.watchdog.refusal() {
                // A RETAINED refusal is announced now, while the operator can
                // still act. A TERMINATED one is announced by the caller after
                // the actual reap (wait_vendor_cancelled).
                if !announced && !self.deadline_stopped {
                    notice(TimeoutNotice {
                        #[cfg(test)]
                        phase: self.watchdog.phase.kind(),
                        disposition: TimeoutDisposition::Retained,
                        reason: refusal.reason,
                    });
                    announced = true;
                }
            }
            if let Some(status) = self.reaped {
                if joined {
                    return self.watchdog.seal_vendor_cancelled(status, &mut cancelled);
                }
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    fn observation_refusal(&self) -> LoginChildRefusal {
        LoginChildRefusal {
            reason: RefusalReason::ObservationFailed,
            custody_pgid: self.watchdog.state().custody_pgid,
            #[cfg(test)]
            status: self.reaped,
        }
    }
}
impl LoginWatchdog {
    pub(crate) fn mark_custody_unresolved(&self, pgid: u32) {
        self.state().custody_pgid = Some(pgid);
    }
    pub(crate) fn custody_unresolved(&self) -> bool {
        self.state().custody_pgid.is_some()
    }
    fn refuse_cancelled_unconditional(&self) {
        self.refuse(RefusalReason::Cancelled);
    }
}
impl<K> Drop for OwnedLoginChild<K> {
    fn drop(&mut self) {
        while self.reaped.is_none() && !self.terminal {
            match self.group.pump_signals() {
                Ok(()) => self.auxiliary_errors.reset(),
                Err(error) => {
                    self.watchdog.refuse_setup();
                    if self.auxiliary_errors.record(&error) != ErrorAction::Continue {
                        self.terminal_refusal();
                    }
                }
            }
            self.observe_kill_intent();
            if self.watchdog.custody_unresolved() {
                self.terminal = true;
            }
            self.poll_child(self.group.readers_joined());
            if !self.terminal && self.reaped.is_none() {
                std::thread::sleep(POLL_INTERVAL);
            }
        }
        if self.watchdog.custody_unresolved() {
            // Retain the actual Child, group handle and lock/permit. Never silently
            // drop a potentially live child or run cleanup before actual writer finalization.
            std::mem::forget((
                Arc::clone(&self.child),
                self.group.clone(),
                self.keepalive.take(),
            ));
        } else {
            self.group.clear_signal_pump();
        }
    }
}
#[cfg(all(test, unix))]
#[path = "test_case_custody.rs"]
pub(crate) mod test_case_custody;

#[cfg(test)]
#[path = "login_child_custody/tests.rs"]
mod tests;
