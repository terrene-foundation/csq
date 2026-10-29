//! Piped CLI login custody. Only this thread invokes the output callback.

use std::io::{self, BufRead, BufReader, Write};
use std::process::{ChildStdout, Command, ExitStatus};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Context;

use super::{cancelled_before_spawn, CliLoginCancelled, CliLoginReceipt, ScopedLoginCancellation};
use crate::login_child_custody::{
    DeliveryPhase, LoginWatchdog, OwnedLoginChild, RefusalReason, TimeoutNotice,
};

const LINE_QUEUE_CAPACITY: usize = 32;
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Test observations are snapshots of the actual owner and actual reader handle.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PipedLoginObservation {
    #[cfg(test)]
    pub(crate) child_id: u32,
    #[cfg(test)]
    pub(crate) reaped_status: Option<ExitStatus>,
    #[cfg(test)]
    pub(crate) reader_is_finished: bool,
    #[cfg(test)]
    pub(crate) reader_joined_thread_id: Option<thread::ThreadId>,
}

/// Initial phases are not terminal absence proof while the helper is live.
/// Fixtures may certify no vendor only after a known pre-spawn return/unwind.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PipedLoginSpawnOutcome {
    NoVendorBeforeSpawn,
    SpawnAttemptStarted,
    NotSpawned,
}

#[cfg(test)]
type AdoptedChildCallback = Box<dyn FnOnce(Arc<Mutex<std::process::Child>>)>;

#[cfg(test)]
#[derive(Default)]
struct PipedCustodyHooks {
    adopted_child: Option<AdoptedChildCallback>,
    spawn_outcome: Option<Box<dyn FnMut(PipedLoginSpawnOutcome)>>,
}

#[cfg(test)]
impl PipedCustodyHooks {
    fn spawn_outcome(&mut self, outcome: PipedLoginSpawnOutcome) {
        if let Some(callback) = self.spawn_outcome.as_mut() {
            callback(outcome);
        }
    }

    fn adopted_child(&mut self, child: Arc<Mutex<std::process::Child>>) {
        if let Some(callback) = self.adopted_child.take() {
            callback(child);
        }
    }
}

// The production representation still contains only the original gate/observer
// pair. Optional custody callbacks and every invocation compile only for tests.
struct PipedReaderHooks<'a, G, O> {
    scope: Option<&'a ScopedLoginCancellation>,
    callbacks: (G, O),
    #[cfg(test)]
    custody: PipedCustodyHooks,
}

impl<'a, G, O> PipedReaderHooks<'a, G, O> {
    fn new(callbacks: (G, O)) -> Self {
        Self {
            callbacks,
            scope: None,
            #[cfg(test)]
            custody: PipedCustodyHooks::default(),
        }
    }
}

#[cfg(test)]
pub(crate) struct PipedLoginTestHooks<G, O> {
    reader_finish_gate: G,
    observe: O,
    custody: PipedCustodyHooks,
}

#[cfg(test)]
impl<G, O> PipedLoginTestHooks<G, O>
where
    G: FnOnce() + Send + 'static,
    O: FnMut(PipedLoginObservation),
{
    pub(crate) fn new(reader_finish_gate: G, observe: O) -> Self {
        Self {
            reader_finish_gate,
            observe,
            custody: PipedCustodyHooks::default(),
        }
    }

    /// Store the actual adopted handle before fallible stdout extraction. The
    /// callback runs on the caller thread and must establish cleanup ownership
    /// before performing any fallible fixture logging or other work.
    pub(crate) fn with_adopted_child(
        mut self,
        callback: impl FnOnce(Arc<Mutex<std::process::Child>>) + 'static,
    ) -> Self {
        self.custody.adopted_child = Some(Box::new(callback));
        self
    }

    pub(crate) fn with_spawn_outcome(
        mut self,
        callback: impl FnMut(PipedLoginSpawnOutcome) + 'static,
    ) -> Self {
        self.custody.spawn_outcome = Some(Box::new(callback));
        self
    }
}

impl<'a, G, O> PipedReaderHooks<'a, G, O> {
    fn with_scope(mut self, scope: &'a ScopedLoginCancellation) -> Self {
        self.scope = Some(scope);
        self
    }
}

fn drain_bounded_stdout(
    mut reader: impl BufRead,
    watchdog: &LoginWatchdog,
    sender: &mpsc::SyncSender<String>,
) -> io::Result<()> {
    // Cap retained bytes per line, refuse malformed/oversized
    // output, and keep draining the actual pipe to EOF on refusal.
    let mut line = Vec::with_capacity(MAX_LINE_BYTES);
    let mut oversized = false;
    let mut refused = false;
    loop {
        let bytes = reader.fill_buf()?;
        if bytes.is_empty() {
            if !line.is_empty() && !oversized && !refused {
                match String::from_utf8(std::mem::take(&mut line)) {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            watchdog.refuse_setup();
                        }
                    }
                    Err(_) => watchdog.refuse_setup(),
                }
            }
            break;
        }
        let take = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |at| at + 1);
        let newline = bytes[take - 1] == b'\n';
        if !oversized && !refused {
            if line.len().saturating_add(take) > MAX_LINE_BYTES {
                oversized = true;
                line.clear();
                watchdog.refuse_setup();
            } else {
                line.extend_from_slice(&bytes[..take]);
            }
        }
        reader.consume(take);
        if newline {
            if !oversized && !refused {
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                match String::from_utf8(std::mem::take(&mut line)) {
                    Ok(line) => {
                        if sender.send(line).is_err() {
                            watchdog.refuse_setup();
                            refused = true;
                        }
                    }
                    Err(_) => {
                        watchdog.refuse_setup();
                        refused = true;
                    }
                }
            }
            line.clear();
            if oversized {
                refused = true;
            }
            oversized = false;
        }
    }
    Ok(())
}

/// Reads only on the prestarted worker. Callbacks stay on the waiting caller.
/// The wake channel carries no values: dropping its sole Sender lets the worker
/// take the stdout slot. An empty slot means vendor spawn never completed.
struct PipedReader {
    receiver: mpsc::Receiver<String>,
    thread: Option<JoinHandle<io::Result<()>>>,
    wake_sender: Option<mpsc::SyncSender<()>>,
    stdout_slot: Arc<Mutex<Option<ChildStdout>>>,
    watchdog: LoginWatchdog,
    has_stdout: bool,
    vendor: String,
    group: Option<crate::login_child_custody::group::GroupControl>,
    disconnected: bool,
    joined: bool,
    #[cfg(test)]
    joined_thread_id: Option<thread::ThreadId>,
}

impl PipedReader {
    /// Called BEFORE vendor spawn. Thread creation failure cannot leave a vendor
    /// child or stdout pipe pending, and requires no synchronous-read fallback.
    fn prepare(
        watchdog: LoginWatchdog,
        vendor: &str,
        reader_finish_gate: impl FnOnce() + Send + 'static,
    ) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(LINE_QUEUE_CAPACITY);
        let (wake_sender, wake_receiver) = mpsc::sync_channel::<()>(0);
        let stdout_slot = Arc::new(Mutex::new(None::<ChildStdout>));
        let worker_stdout = Arc::clone(&stdout_slot);
        let worker_watchdog = watchdog.clone();
        let handle = thread::Builder::new()
            .name("csq-login-stdout".into())
            .spawn(move || {
                // Sender-drop is the one-shot wake protocol, not an I/O error.
                // There is deliberately no fallible channel send after adoption.
                let _ = wake_receiver.recv();
                let stdout = worker_stdout
                    .lock()
                    .unwrap_or_else(|poisoned| {
                        worker_watchdog.refuse_setup();
                        poisoned.into_inner()
                    })
                    .take();
                let Some(stdout) = stdout else {
                    return Ok(()); // vendor spawn failed/cancelled before handoff.
                };
                drain_bounded_stdout(BufReader::new(stdout), &worker_watchdog, &sender)?;
                // This is actual EOF. The fixture gate does not simulate an open
                // pipe and does not run for an empty pre-spawn worker.
                reader_finish_gate();
                Ok(())
            })?;
        Ok(Self {
            receiver,
            thread: Some(handle),
            wake_sender: Some(wake_sender),
            stdout_slot,
            watchdog,
            has_stdout: false,
            vendor: vendor.to_owned(),
            group: None,
            disconnected: false,
            joined: false,
            #[cfg(test)]
            joined_thread_id: None,
        })
    }

    /// Infallible handoff to an existing worker. Release the slot mutex before
    /// waking it, so neither read nor caller callback runs under that mutex.
    fn handoff(&mut self, stdout: ChildStdout) {
        {
            let mut slot = self.stdout_slot.lock().unwrap_or_else(|poisoned| {
                self.watchdog.refuse_setup();
                poisoned.into_inner()
            });
            *slot = Some(stdout);
        }
        self.has_stdout = true;
        drop(self.wake_sender.take());
    }

    fn tick(&mut self, on_line: &mut impl FnMut(String)) -> bool {
        for _ in 0..LINE_QUEUE_CAPACITY {
            match self.receiver.try_recv() {
                Ok(line) => on_line(line),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.disconnected = true;
                    break;
                }
            }
        }
        if self.disconnected && self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
            self.join();
        }
        self.joined
    }

    fn join(&mut self) {
        if let Some(handle) = self.thread.take() {
            #[cfg(test)]
            let thread_id = handle.thread().id();
            match handle.join() {
                Ok(result) => {
                    #[cfg(test)]
                    {
                        self.joined_thread_id = Some(thread_id);
                    }
                    if result.is_err() {
                        self.watchdog.refuse_setup();
                    } else if let Some(group) = &self.group {
                        // Worker Ok is reached only after actual EOF and gate;
                        // this branch follows the actual JoinHandle::join.
                        group.mark_readers_joined();
                    }
                }
                Err(_) => self.watchdog.refuse_setup(),
            }
            self.joined = true;
        }
    }

    #[cfg(test)]
    fn is_finished(&self) -> bool {
        match self.thread.as_ref() {
            Some(handle) => handle.is_finished(),
            None => self.joined,
        }
    }

    #[cfg(test)]
    fn joined_thread_id(&self) -> Option<thread::ThreadId> {
        self.joined_thread_id
    }
}

/// If a fixture callback unwinds before normal stdout extraction, deliver the
/// still-owned fd to the existing worker before ordinary reader cleanup runs.
#[cfg(test)]
struct AdoptedHookUnwindHandoff<'a> {
    child: Arc<Mutex<std::process::Child>>,
    reader: &'a mut PipedReader,
    armed: bool,
}

#[cfg(test)]
impl Drop for AdoptedHookUnwindHandoff<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let stdout = {
            let watchdog = &self.reader.watchdog;
            let mut child = self.child.lock().unwrap_or_else(|poisoned| {
                watchdog.refuse_setup();
                poisoned.into_inner()
            });
            child.stdout.take()
        };
        if let Some(stdout) = stdout {
            self.reader.handoff(stdout);
        }
    }
}

impl Drop for PipedReader {
    fn drop(&mut self) {
        if self.joined {
            return;
        }
        // Wake an empty pre-spawn worker on failed/cancelled vendor spawn.
        drop(self.wake_sender.take());
        if self.has_stdout {
            let _ = writeln!(
                io::stderr(),
                "waiting for {} login to close its output before exit",
                self.vendor
            );
        }
        // Discard rather than invoke callbacks on an exceptional exit. This
        // guard is moved after OwnedLoginChild immediately after adoption, so
        // draining/joining happens before owner Drop waits or handler restores.
        loop {
            if let Some(group) = &self.group {
                let _ = group.pump_signals();
            }
            let observation_uncertain = self
                .group
                .as_ref()
                .is_some_and(|group| group.check_wait_lease().is_err());
            let killed_without_eof = self.group.as_ref().is_some_and(|group| {
                group.kill_requested_at().is_some_and(|at| {
                    at.elapsed() >= crate::login_child_custody::group::STOP_DRAIN_BUDGET
                })
            });
            if self.watchdog.custody_unresolved() || observation_uncertain || killed_without_eof {
                if let Some(group) = &self.group {
                    self.watchdog.mark_custody_unresolved(group.id());
                }
                // Reader Drop precedes Owned Drop. Retain the reader on an
                // uncertain group observation, then let the owner's canonical
                // ECHILD/repeated-error policy settle actual child custody.
                // No fake EOF/join receipt. Retain the real receiver/worker on
                // this terminal UND path alongside the owner's retained K.
                let (_sender, empty) = mpsc::sync_channel(1);
                std::mem::forget(std::mem::replace(&mut self.receiver, empty));
                if let Some(worker) = self.thread.take() {
                    std::mem::forget(worker);
                }
                eprintln!(
                    "login_custody_unresolved: actual stdout reader retained without join proof"
                );
                return;
            }
            match self.receiver.recv_timeout(Duration::from_millis(200)) {
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        self.join();
    }
}

/// Used verbatim by the Codex perform_with spawn closure. The caller retains
/// its outer account lock; K can independently carry that same real lock seam.
#[cfg(test)]
pub(crate) fn spawn_cli_piped_login<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    on_line: impl FnMut(String),
    notice: impl FnMut(TimeoutNotice),
) -> anyhow::Result<ExitStatus> {
    spawn_cli_piped_login_inner(
        command,
        timeout,
        keepalive,
        vendor,
        on_line,
        notice,
        PipedReaderHooks::new((|| {}, |_| {})),
    )
    .map(|receipt| receipt.status)
}

pub(crate) fn spawn_cli_piped_login_scoped<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    on_line: impl FnMut(String),
    notice: impl FnMut(TimeoutNotice),
    cancellation: &ScopedLoginCancellation,
) -> anyhow::Result<ExitStatus> {
    spawn_cli_piped_login_inner(
        command,
        timeout,
        keepalive,
        vendor,
        on_line,
        notice,
        PipedReaderHooks::new((|| {}, |_| {})).with_scope(cancellation),
    )
    .map(|receipt| receipt.status)
}

#[cfg(test)]
pub(crate) fn spawn_cli_piped_login_scoped_observed_receipt<G, O, K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    on_line: impl FnMut(String),
    notice: impl FnMut(TimeoutNotice),
    scoped_hooks: (PipedLoginTestHooks<G, O>, &ScopedLoginCancellation),
) -> anyhow::Result<CliLoginReceipt>
where
    G: FnOnce() + Send + 'static,
    O: FnMut(PipedLoginObservation),
{
    let (hooks, scope) = scoped_hooks;
    spawn_cli_piped_login_inner(
        command,
        timeout,
        keepalive,
        vendor,
        on_line,
        notice,
        PipedReaderHooks {
            scope: Some(scope),
            callbacks: (hooks.reader_finish_gate, hooks.observe),
            custody: hooks.custody,
        },
    )
}

/// Same body with an actual-reader EOF gate and successful reap/join receipt.
#[cfg(test)]
pub(crate) fn spawn_cli_piped_login_receipt<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    on_line: impl FnMut(String),
    notice: impl FnMut(TimeoutNotice),
    reader_finish_gate: impl FnOnce() + Send + 'static,
) -> anyhow::Result<CliLoginReceipt> {
    spawn_cli_piped_login_inner(
        command,
        timeout,
        keepalive,
        vendor,
        on_line,
        notice,
        PipedReaderHooks::new((reader_finish_gate, |_| {})),
    )
}

/// Actual poll/join observations remain available even when timeout refuses
/// the final result. They do not poll or reap any child independently.
#[cfg(test)]
pub(crate) fn spawn_cli_piped_login_observed_receipt<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    on_line: impl FnMut(String),
    notice: impl FnMut(TimeoutNotice),
    hooks: PipedLoginTestHooks<impl FnOnce() + Send + 'static, impl FnMut(PipedLoginObservation)>,
) -> anyhow::Result<CliLoginReceipt> {
    spawn_cli_piped_login_inner(
        command,
        timeout,
        keepalive,
        vendor,
        on_line,
        notice,
        PipedReaderHooks {
            scope: None,
            callbacks: (hooks.reader_finish_gate, hooks.observe),
            custody: hooks.custody,
        },
    )
}

fn spawn_cli_piped_login_inner<K>(
    command: &mut Command,
    timeout: Duration,
    keepalive: K,
    vendor: &str,
    mut on_line: impl FnMut(String),
    mut notice: impl FnMut(TimeoutNotice),
    reader_hooks: PipedReaderHooks<
        '_,
        impl FnOnce() + Send + 'static,
        impl FnMut(PipedLoginObservation),
    >,
) -> anyhow::Result<CliLoginReceipt> {
    let scope = reader_hooks.scope;
    let reader_finish_gate = reader_hooks.callbacks.0;
    #[cfg(test)]
    let mut observe = reader_hooks.callbacks.1;
    #[cfg(test)]
    let mut custody = reader_hooks.custody;
    #[cfg(test)]
    custody.spawn_outcome(PipedLoginSpawnOutcome::NoVendorBeforeSpawn);
    let watchdog = LoginWatchdog::new(timeout, DeliveryPhase::Unknown);
    watchdog
        .check_spawn_allowed()
        .context(super::CliLoginCustodyFinalized)?;
    // Declaration order is custody: reader Drop drains/joins, then owned Drop
    // reaps, and only then may cancellation Drop restore the terminal handler.
    let mut local_cancellation = if scope.is_none() {
        Some(
            ScopedLoginCancellation::install()
                .context("failed to install scoped terminal cancellation handler")
                .context(super::CliLoginCustodyFinalized)?,
        )
    } else {
        None
    };
    let cancellation = scope
        .or(local_cancellation.as_ref())
        .expect("caller or local cancellation guard");
    let pending_reader = PipedReader::prepare(watchdog.clone(), vendor, reader_finish_gate)
        .context("failed to start sign-in stdout reader before spawning sign-in program")
        .context(super::CliLoginCustodyFinalized)?;
    if cancellation.cancelled() {
        drop(pending_reader);
        eprintln!("Cancelling — waiting for {vendor} login to exit");
        return Err(cancelled_before_spawn().context(super::CliLoginCustodyFinalized));
    }
    #[cfg(test)]
    custody.spawn_outcome(PipedLoginSpawnOutcome::SpawnAttemptStarted);
    let (child, group) = match crate::login_child_custody::group::spawn_attended(command) {
        Ok(child) => child,
        Err(error) => {
            #[cfg(test)]
            custody.spawn_outcome(PipedLoginSpawnOutcome::NotSpawned);
            drop(pending_reader);
            if cancellation.cancelled() {
                eprintln!("Cancelling — waiting for {vendor} login to exit");
                return Err(cancelled_before_spawn());
            }
            return Err(error).context("failed to spawn sign-in program");
        }
    };
    #[cfg(test)]
    let child_id = child.id();
    let mut owned = OwnedLoginChild::adopt_group(child, group.clone(), watchdog.clone(), keepalive);
    // Moving this prestarted guard after the owner changes unwind drop order:
    // reader drain/join now precedes actual owner reap, while both retain scope.
    let mut reader = pending_reader;
    reader.group = Some(group.clone());
    super::attach_signal_pump(&group);
    #[cfg(test)]
    {
        let child = owned.shared_child();
        let mut handoff_on_unwind = AdoptedHookUnwindHandoff {
            child: Arc::clone(&child),
            reader: &mut reader,
            armed: true,
        };
        custody.adopted_child(child);
        handoff_on_unwind.armed = false;
    }
    let stdout = {
        let child = owned.shared_child();
        let mut child = child.lock().unwrap_or_else(|poisoned| {
            watchdog.refuse_setup();
            poisoned.into_inner()
        });
        child.stdout.take()
    }
    .context("sign-in program stdout pipe missing")?;
    #[cfg(test)]
    let observed_watchdog = watchdog.clone();
    reader.handoff(stdout);
    let mut announced_cancel = false;
    let result = owned.wait_vendor_cancelled(
        || {
            #[cfg(test)]
            observe(PipedLoginObservation {
                child_id,
                reaped_status: observed_watchdog.reaped_status(),
                reader_is_finished: reader.is_finished(),
                reader_joined_thread_id: reader.joined_thread_id(),
            });
            let joined = reader.tick(&mut on_line);
            #[cfg(test)]
            observe(PipedLoginObservation {
                child_id,
                reaped_status: observed_watchdog.reaped_status(),
                reader_is_finished: reader.is_finished(),
                reader_joined_thread_id: reader.joined_thread_id(),
            });
            Ok(joined)
        },
        |event| {
            if event.reason != RefusalReason::Cancelled {
                notice(event);
            }
        },
        || {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "opaque vendor login has no proven PRE-delivery stop path",
            ))
        },
        || {
            let cancelled = cancellation.cancelled();
            if cancelled && !announced_cancel {
                eprintln!("Cancelling — waiting for {vendor} login to exit");
                announced_cancel = true;
            }
            cancelled
        },
    );
    // The waiter returns only after actual reap plus reader join. Restore/read
    // cancellation before returning to the core canonical-publication path.
    if !owned.custody_finalized() {
        return Err(super::CliLoginCustodyUnresolved.into());
    }
    let mut was_cancelled = cancellation.cancelled();
    if let Some(local) = local_cancellation.as_mut() {
        was_cancelled |= local
            .close()
            .context("failed to restore terminal cancellation handler")
            .context(super::CliLoginCustodyFinalized)?;
    }
    // Final refusal/cancellation can follow the last tick's observation.
    // Success keeps its single terminal owner snapshot below.
    #[cfg(all(test, unix))]
    let terminal_refusal = result.is_err() || was_cancelled;
    #[cfg(all(test, unix))]
    if let Some(status) = owned.reaped_status().filter(|_| terminal_refusal) {
        observe(PipedLoginObservation {
            child_id,
            reaped_status: Some(status),
            reader_is_finished: reader.is_finished(),
            reader_joined_thread_id: reader.joined_thread_id(),
        });
    }
    let operator_stop = owned.operator_stop(result.as_ref().ok());
    was_cancelled |= operator_stop.is_some();
    if was_cancelled {
        match operator_stop {
            Some(message) => eprintln!("{message}"),
            None if !announced_cancel => {
                eprintln!("Cancelling — waiting for {vendor} login to exit");
            }
            None => {}
        }
        return Err(anyhow::Error::new(CliLoginCancelled {
            prior_refusal: result.err(),
            #[cfg(test)]
            child_id: Some(child_id),
            #[cfg(test)]
            reaped_status: owned.reaped_status(),
            #[cfg(test)]
            joined_reader_thread_id: reader.joined_thread_id(),
        }))
        .context(super::CliLoginCustodyFinalized);
    }
    let status = result.context(super::CliLoginCustodyFinalized)?;
    #[cfg(test)]
    let actual_reaped_status = owned
        .reaped_status()
        .context("login child completed without an actual owner reap receipt")?;
    #[cfg(test)]
    if actual_reaped_status != status {
        return Err(anyhow::anyhow!(
            "login child completion disagrees with actual owner reap receipt"
        ));
    }
    // The terminal snapshot follows the owner's final poll/reap. Earlier tick
    // observations can show the reader join before that poll stores its status.
    #[cfg(test)]
    observe(PipedLoginObservation {
        child_id,
        reaped_status: Some(actual_reaped_status),
        reader_is_finished: reader.is_finished(),
        reader_joined_thread_id: reader.joined_thread_id(),
    });
    Ok(CliLoginReceipt {
        #[cfg(not(test))]
        status,
        #[cfg(test)]
        status: actual_reaped_status,
        #[cfg(test)]
        child_id,
        #[cfg(test)]
        joined_reader_thread_id: reader.joined_thread_id(),
    })
}

#[cfg(test)]
mod bounded_line_tests {
    use super::*;

    #[test]
    fn cli_stdout_at_cap_is_forwarded_once() {
        let _environment = csq_core::platform::test_env::lock();
        let watchdog = LoginWatchdog::new(Duration::from_secs(30), DeliveryPhase::Unknown);
        let mut bytes = vec![b'x'; 64 * 1024 - 1];
        bytes.push(b'\n');
        let mut reader = std::io::Cursor::new(bytes);
        let (sender, receiver) = mpsc::sync_channel(32);
        drain_bounded_stdout(&mut reader, &watchdog, &sender).unwrap();
        drop(sender);
        let lines: Vec<_> = receiver.try_iter().collect();
        assert!(
            !watchdog.is_refused() && lines.len() == 1 && lines[0].len() == 64 * 1024 - 1,
            "LOGIN_CLI_STDOUT_64K_CONTROL"
        );
    }

    #[test]
    fn cli_stdout_over_cap_refuses_and_drains_through_following_line() {
        let _environment = csq_core::platform::test_env::lock();
        let watchdog = LoginWatchdog::new(Duration::from_secs(30), DeliveryPhase::Unknown);
        let mut bytes = vec![b'x'; 64 * 1024 + 1];
        bytes.extend_from_slice(b"\nnext line\n");
        let total = bytes.len() as u64;
        let mut reader = std::io::Cursor::new(bytes);
        let (sender, receiver) = mpsc::sync_channel(32);
        drain_bounded_stdout(&mut reader, &watchdog, &sender).unwrap();
        drop(sender);
        assert!(
            watchdog.is_refused() && reader.position() == total && receiver.try_iter().count() == 0,
            "LOGIN_CLI_STDOUT_OVERSIZE_DRAIN"
        );
    }

    #[test]
    fn cli_stdout_over_cap_without_newline_refuses_and_drains_to_eof() {
        let _environment = csq_core::platform::test_env::lock();
        let watchdog = LoginWatchdog::new(Duration::from_secs(30), DeliveryPhase::Unknown);
        let bytes = vec![b'x'; 64 * 1024 + 1];
        let total = bytes.len() as u64;
        let mut reader = std::io::Cursor::new(bytes);
        let (sender, receiver) = mpsc::sync_channel(32);
        drain_bounded_stdout(&mut reader, &watchdog, &sender).unwrap();
        drop(sender);
        assert!(
            watchdog.is_refused() && reader.position() == total && receiver.try_iter().count() == 0,
            "LOGIN_CLI_STDOUT_NO_NEWLINE_DRAIN"
        );
    }
}
