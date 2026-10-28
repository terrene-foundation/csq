//! Shared Unix test-fixture custody, extracted from the desktop case helper.
//! Safety cleanup is deliberately independent of the production signal policy.

use std::{
    io,
    process::{Child, ExitStatus},
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub(crate) struct CaseWait {
    pub(crate) group_empty: bool,
    pub(crate) status: Option<ExitStatus>,
    pub(crate) readers_joined: bool,
    pub(crate) timed_out: bool,
    pub(crate) detail: Option<String>,
}

pub(crate) struct CaseCustody {
    child: Arc<Mutex<Child>>,
    pid: u32,
    readers: Vec<JoinHandle<io::Result<()>>>,
    reader_error: Option<String>,
    reaped: Option<ExitStatus>,
    complete: bool,
    group_empty: bool,
    stop_requested: bool,
    owned_pgid_proven: bool,
}

impl CaseCustody {
    pub(crate) fn new(child: Child) -> Self {
        let pid = child.id();
        Self::from_shared(Arc::new(Mutex::new(child)), pid)
    }

    pub(crate) fn from_shared(child: Arc<Mutex<Child>>, pid: u32) -> Self {
        let owned_pgid_proven = Self::adoption_group(&child, pid);
        Self {
            child,
            pid,
            readers: Vec::new(),
            reader_error: None,
            reaped: None,
            complete: false,
            group_empty: false,
            stop_requested: false,
            owned_pgid_proven,
        }
    }

    pub(crate) fn shared_child(&self) -> Arc<Mutex<Child>> {
        Arc::clone(&self.child)
    }

    pub(crate) fn add_reader(&mut self, reader: JoinHandle<io::Result<()>>) {
        self.readers.push(reader);
    }

    fn probe_owned(child: &Child, phase: &'static str) -> io::Result<bool> {
        let result = super::group::observe_owned_unreaped_for_test(child);
        match &result {
            Ok(exited) if phase != "wait" || *exited => {
                let state = if *exited {
                    "exited-unreaped"
                } else {
                    "live-unreaped"
                };
                eprintln!("TEST_CASE_CUSTODY_STEP: phase={phase}; step=wnowait; owned_pid={}; errno=none; state={state}", child.id());
            }
            Ok(_) => {} // Repeated live wait polls have no state transition.
            Err(error) => {
                let errno = error
                    .raw_os_error()
                    .map_or_else(|| "none".to_owned(), |value| value.to_string());
                eprintln!("TEST_CASE_CUSTODY_STEP: phase={phase}; step=wnowait; owned_pid={}; errno={errno}; state=error", child.id());
            }
        }
        result
    }

    fn probe_group(pid: u32, phase: &'static str) -> io::Result<i32> {
        let target = i32::try_from(pid)
            .ok()
            .filter(|pid| *pid > 0)
            .ok_or_else(|| io::Error::other("original case PID outside signal range"))?;
        // SAFETY: callers hold the exact typed Child and a successful WNOWAIT
        // observation; this read-only query cannot signal an unrelated process.
        let group = unsafe { libc::getpgid(target) };
        if group < 0 {
            let error = io::Error::last_os_error();
            let errno = error
                .raw_os_error()
                .map_or_else(|| "none".to_owned(), |value| value.to_string());
            eprintln!("TEST_CASE_CUSTODY_STEP: phase={phase}; step=getpgid; owned_pid={pid}; errno={errno}; state=error");
            return Err(error);
        }
        let state = if group == target { "owned" } else { "mismatch" };
        eprintln!("TEST_CASE_CUSTODY_STEP: phase={phase}; step=getpgid; owned_pid={pid}; errno=none; state={state}");
        Ok(group)
    }

    fn adoption_group(child: &Arc<Mutex<Child>>, pid: u32) -> bool {
        let Ok(child) = child.try_lock() else {
            return false;
        };
        if child.id() != pid || Self::probe_owned(&child, "adopt").is_err() {
            return false;
        }
        Self::probe_group(pid, "adopt").is_ok_and(|group| u32::try_from(group).ok() == Some(pid))
    }

    fn observe(&self) -> io::Result<bool> {
        let child = self
            .child
            .try_lock()
            .map_err(|_| io::Error::other("original case lock unavailable"))?;
        if child.id() != self.pid {
            return Err(io::Error::other("original case identity changed"));
        }
        Self::probe_owned(&child, "wait")
    }

    fn stop_under_lease(&self) -> io::Result<()> {
        let child = self
            .child
            .try_lock()
            .map_err(|_| io::Error::other("original case lock unavailable"))?;
        if child.id() != self.pid {
            return Err(io::Error::other("original case identity changed"));
        }
        // WNOWAIT proves actual ownership whether the original leader is live or
        // already a zombie. Never call try_wait before this group safety signal.
        Self::probe_owned(&child, "stop")?;
        let pid = i32::try_from(self.pid)
            .ok()
            .filter(|pid| *pid > 0)
            .ok_or_else(|| io::Error::other("original case PID outside signal range"))?;
        match Self::probe_group(self.pid, "stop") {
            Ok(group) if group == pid => {}
            Ok(_) => return Err(io::Error::other("original case does not own its PGID")),
            Err(error) => {
                // A dead leader can disappear from getpgid before its retained
                // Child is reaped. Only this same still-valid WNOWAIT lease plus
                // positively captured adoption PGID permits the fallback.
                let unavailable = matches!(error.raw_os_error(), Some(libc::ESRCH | libc::EPERM));
                if !self.owned_pgid_proven || !unavailable {
                    return Err(error);
                }
            }
        }
        // SAFETY: successful current WNOWAIT retains the original Child's PID;
        // current or stored positive own-PGID proof identifies only its group.
        if unsafe { libc::killpg(pid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            let errno = error
                .raw_os_error()
                .map_or_else(|| "none".to_owned(), |value| value.to_string());
            eprintln!("TEST_CASE_CUSTODY_STEP: phase=stop; step=killpg; owned_pid={}; errno={errno}; state=error", self.pid);
            if !matches!(error.raw_os_error(), Some(libc::ESRCH | libc::EPERM)) {
                return Err(error);
            }
            // No live member was signalable. This is NOT an empty-group proof:
            // actual EOF/joins, original reap and final ESRCH are still required.
        } else {
            eprintln!("TEST_CASE_CUSTODY_STEP: phase=stop; step=killpg; owned_pid={}; errno=none; state=sent", self.pid);
        }
        Ok(())
    }

    fn join_readers(&mut self, deadline: Instant) -> bool {
        while !self.readers.is_empty() {
            if let Some(index) = self.readers.iter().position(JoinHandle::is_finished) {
                match self.readers.swap_remove(index).join() {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        self.reader_error = Some(format!("actual reader failed: {error}"));
                    }
                    Err(_) => {
                        self.reader_error = Some("actual reader panicked".into());
                    }
                }
            } else if Instant::now() >= deadline {
                return false;
            } else {
                std::thread::yield_now();
            }
        }
        self.reader_error.is_none()
    }

    fn reap(&mut self, deadline: Instant) -> io::Result<Option<ExitStatus>> {
        loop {
            if let Ok(mut child) = self.child.try_lock() {
                if child.id() != self.pid {
                    return Err(io::Error::other("original case identity changed"));
                }
                if let Some(status) = child.try_wait()? {
                    self.reaped = Some(status);
                    return Ok(Some(status));
                }
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::yield_now();
        }
    }

    pub(crate) fn cleanup(&mut self, budget: Duration) -> CaseWait {
        let mut result = CaseWait {
            group_empty: false,
            status: self.reaped,
            readers_joined: self.readers.is_empty() && self.reader_error.is_none(),
            timed_out: false,
            detail: None,
        };
        let Some(deadline) = Instant::now().checked_add(budget) else {
            result.detail = Some("case cleanup deadline overflow".into());
            return result;
        };
        // Once reaped, never signal its numeric PGID again. A prior incomplete
        // receipt remains incomplete rather than gaining stale-PID authority.
        if self.reaped.is_some() {
            result.group_empty = self.group_empty;
            result.detail =
                Some("original case already reaped; no further signal permitted".into());
            return result;
        }
        if let Err(error) = self.stop_under_lease() {
            result.detail = Some(format!("owned case group stop unconfirmed: {error}"));
            return result;
        }
        self.stop_requested = true;
        result = self.wait(deadline.saturating_duration_since(Instant::now()));
        if result.status.is_none() || !result.readers_joined {
            return result;
        }
        // Common wait proves actual EOF/joins and original reap. Forced cleanup
        // additionally requires the owned test PGID absence proof below.
        let proof = wait_case_group_empty(self.pid, deadline);
        result.group_empty = proof.is_ok();
        result.timed_out = proof.is_err() && Instant::now() >= deadline;
        result.detail = Some(format!("independent owned PGID stop; actual readers joined; original Child reaped; group absence={proof:?}"));
        self.group_empty = result.group_empty;
        self.complete = result.group_empty;
        result
    }

    // Observe and drain only. Callers choose whether to request an independent
    // stop; a deadline never recursively calls cleanup or sends any signal.
    pub(crate) fn wait(&mut self, budget: Duration) -> CaseWait {
        let mut result = CaseWait {
            group_empty: self.group_empty,
            status: self.reaped,
            readers_joined: self.readers.is_empty() && self.reader_error.is_none(),
            timed_out: false,
            detail: None,
        };
        if self.reaped.is_some() {
            return result;
        }
        let Some(deadline) = Instant::now().checked_add(budget) else {
            result.detail = Some("case wait deadline overflow".into());
            return result;
        };
        loop {
            match self.observe() {
                Ok(true) => {
                    result.readers_joined = self.join_readers(deadline);
                    if !result.readers_joined {
                        result.timed_out = Instant::now() >= deadline;
                        result.detail = Some(
                            self.reader_error
                                .clone()
                                .unwrap_or_else(|| "actual reader EOF/join unconfirmed".into()),
                        );
                        return result;
                    }
                    match self.reap(deadline) {
                        Ok(Some(status)) => {
                            self.complete = !self.stop_requested;
                            result.status = Some(status);
                        }
                        Ok(None) => {
                            result.timed_out = true;
                            result.detail =
                                Some("original case reap unconfirmed within wait budget".into());
                        }
                        Err(error) => {
                            result.detail = Some(format!("original case wait refused: {error}"));
                        }
                    }
                    return result;
                }
                Err(error) => {
                    result.detail = Some(format!("original case lease refused: {error}"));
                    return result;
                }
                Ok(false) => {}
            }
            if Instant::now() >= deadline {
                result.timed_out = true;
                result.detail = Some("original case exit unconfirmed within wait budget".into());
                return result;
            }
            std::thread::yield_now();
        }
    }
}

impl Drop for CaseCustody {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        let receipt = self.cleanup(Duration::from_secs(3));
        if receipt.status.is_some() && receipt.readers_joined && receipt.group_empty {
            return;
        }
        eprintln!("TEST_CASE_CUSTODY_UNKNOWN: original_pid={}; status={:?}; readers_joined={}; group_empty={}; timed_out={}; detail={:?}",
            self.pid, receipt.status, receipt.readers_joined, receipt.group_empty, receipt.timed_out, receipt.detail);
        // Retain actual owners on ECHILD/EPERM or missing EOF, never signal a
        // numeric identity after losing its wait lease or detach a live reader.
        std::mem::forget(Arc::clone(&self.child));
        for reader in self.readers.drain(..) {
            std::mem::forget(reader);
        }
    }
}

fn wait_case_group_empty(pgid: u32, deadline: Instant) -> Result<(), String> {
    let pgid = i32::try_from(pgid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or("case PGID outside observation range")?;
    loop {
        // SAFETY: read-only observation of the fixture's previously owned PGID.
        // After reap, reuse can only make absence fail closed. Never signal here.
        if unsafe { libc::killpg(pgid, 0) } < 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error() {
                // ESRCH is the ONLY absence proof, on every platform.
                Some(libc::ESRCH) => return Ok(()),
                // EPERM is never absence. Darwin answers EPERM while the group's
                // only members are unreaped zombies (measured 2026-10-11, csq
                // ede59944). After the leader's reap, killed descendants were
                // observed still existing (birth identity present) while the
                // probe answered EPERM, before launchd reaped them (measured
                // 2026-10-24 under load, csq 77ac33260). EPERM also answers for
                // a live member this uid cannot signal, or a reused PGID owned
                // by another uid. So EPERM keeps polling and fails closed at
                // the deadline, never certifying emptiness.
                Some(libc::EPERM) => {}
                _ => return Err(format!("case group absence unconfirmed: {error}")),
            }
        }
        if Instant::now() >= deadline {
            return Err("case group still observable after bounded original reap".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
