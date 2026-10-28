//! Upgrade completion requires joined work, never a drain deadline expiring.

#[cfg(test)]
mod panic_process_probe {
    use super::TaskCustody;
    use std::io::Read;
    use std::path::PathBuf;
    use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    const ROLE: &str = "CSQ_PRIVATE_CUSTODY_PROCESS_ROLE";
    const ROOT: &str = "CSQ_PRIVATE_CUSTODY_PROCESS_ROOT";
    const ENTRY: &str = "update::upgrade_guard::drain::panic_process_probe::owned_process_entry";

    struct OwnedProbe {
        child: Child,
        input: Option<ChildStdin>,
        sandbox: Option<tempfile::TempDir>,
        reaped: bool,
    }

    impl OwnedProbe {
        fn spawn(mode: &str) -> std::io::Result<Self> {
            let sandbox = tempfile::tempdir()?;
            let root = sandbox.path();
            for name in ["home", "base", "tmp", "bin", "config", "appdata", "local"] {
                std::fs::create_dir(root.join(name))?;
            }
            let mut command = Command::new(std::env::current_exe()?);
            command
                .env_clear()
                .args([ENTRY, "--exact", "--nocapture", "--test-threads=1"])
                .current_dir(root)
                .env(ROLE, mode)
                .env(ROOT, root)
                .env("HOME", root.join("home"))
                .env("USERPROFILE", root.join("home"))
                .env("CSQ_BASE_DIR", root.join("base"))
                .env("CLAUDE_CONFIG_DIR", root.join("config"))
                .env("XDG_CONFIG_HOME", root.join("config"))
                .env("APPDATA", root.join("appdata"))
                .env("LOCALAPPDATA", root.join("local"))
                .env("TMPDIR", root.join("tmp"))
                .env("TEMP", root.join("tmp"))
                .env("TMP", root.join("tmp"))
                .env("PATH", root.join("bin"))
                .env("LANG", "C")
                .env("LC_ALL", "C")
                .stdin(Stdio::piped())
                .stdout(std::fs::File::create(root.join("stdout.log"))?)
                .stderr(std::fs::File::create(root.join("stderr.log"))?);
            // Only loader essentials: no inherited HOME, PATH, auth or csq namespace.
            for key in ["SYSTEMROOT", "SystemRoot", "WINDIR"] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
            let mut child = command.spawn()?;
            let input = child.stdin.take();
            Ok(Self {
                child,
                input,
                sandbox: Some(sandbox),
                reaped: false,
            })
        }

        fn root(&self) -> &std::path::Path {
            self.sandbox.as_ref().expect("owned sandbox").path()
        }

        fn poll_until(&mut self, budget: Duration) -> std::io::Result<Option<ExitStatus>> {
            let deadline = Instant::now() + budget;
            loop {
                if let Some(status) = self.child.try_wait()? {
                    self.reaped = true;
                    return Ok(Some(status));
                }
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn preserve_unknown(&mut self) {
            if let Some(sandbox) = self.sandbox.take() {
                let path = sandbox.keep();
                eprintln!(
                    "CUSTODY_PROCESS_UNKNOWN retained private fixture at {}",
                    path.display()
                );
            }
        }

        fn observe(&mut self) -> std::io::Result<ExitStatus> {
            if let Some(status) = self.poll_until(Duration::from_secs(10))? {
                return Ok(status);
            }
            // Owned stdin EOF requests fixture self-exit 90. Never kill or signal a PID.
            self.input.take();
            if self.poll_until(Duration::from_secs(2))?.is_none() {
                self.preserve_unknown();
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "CUSTODY_PROCESS_UNKNOWN",
            ))
        }
    }

    impl Drop for OwnedProbe {
        fn drop(&mut self) {
            self.input.take();
            if !self.reaped {
                match self.poll_until(Duration::from_secs(2)) {
                    Ok(Some(_)) => {}
                    _ => self.preserve_unknown(),
                }
            }
        }
    }

    // Normal test discovery is inert. Only our exact, env-cleared child selects a role.
    #[test]
    fn owned_process_entry() {
        let _env_guard = crate::platform::test_env::lock();
        let Some(mode) = std::env::var_os(ROLE) else {
            return;
        };
        let mode = mode.to_str().expect("private ASCII role").to_owned();
        assert!(matches!(mode.as_str(), "panic" | "success"));
        let root = PathBuf::from(std::env::var_os(ROOT).expect("private fixture root"));
        assert!(root.is_dir());
        // A parent failure closes its private pipe. This is fixture cleanup only:
        // exit 90 is never accepted as joined/nonzero production evidence.
        std::thread::Builder::new()
            .name("custody-fixture-eof".into())
            .spawn(|| {
                let mut byte = [0_u8; 1];
                loop {
                    match std::io::stdin().read(&mut byte) {
                        Ok(0) => std::process::exit(90),
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => std::process::exit(91),
                    }
                }
            })
            .expect("private EOF cleanup thread");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("private current-thread runtime");
        let custody = TaskCustody::default();
        let body_custody = custody.clone();
        let body_root = root.clone();
        let panic_body = mode == "panic";
        let result = runtime.block_on(custody.run(async move {
            let marker = body_root.join("writer-completed");
            drop(body_custody.adopt_subsystem(
                "private_inert_writer",
                tokio::spawn(async move {
                    // Delayed private transaction, not a timing-based pass criterion.
                    // Current-thread runtime cannot poll this writer before body panic.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    std::fs::write(marker, b"inert writer completed\n")
                        .expect("inert marker write");
                }),
            ));
            std::fs::write(body_root.join("body-entered"), b"actual TaskCustody body\n")
                .expect("private reached marker");
            if panic_body {
                panic!("PRIVATE_CUSTODY_PROCESS_BODY_PANIC");
            }
            Ok(())
        }));
        let exit = if panic_body
            && result.as_ref().err().map(String::as_str) == Some("daemon_session_body_panicked")
        {
            7
        } else if !panic_body && result.is_ok() {
            0
        } else {
            8
        };
        // Deliberately no runtime Drop: the tested owner must already have joined.
        std::process::exit(exit);
    }

    fn assert_process(mode: &str, expected: i32) {
        let _env_guard = crate::platform::test_env::lock();
        let mut probe = OwnedProbe::spawn(mode).expect("spawn owned env-cleared fixture");
        let status = probe
            .observe()
            .expect("CUSTODY_PROCESS_UNKNOWN: child observation unavailable");
        assert_eq!(
            status.code(),
            Some(expected),
            "actual owned custody process exit mismatch"
        );
        assert!(
            probe.root().join("body-entered").is_file(),
            "actual custody body was not reached"
        );
        assert_eq!(
            std::fs::read(probe.root().join("writer-completed"))
                .ok()
                .as_deref(),
            Some(&b"inert writer completed\n"[..]),
            "actual process exited before registered writer joined"
        );
        if mode == "panic" {
            let error =
                std::fs::read_to_string(probe.root().join("stderr.log")).expect("child panic log");
            assert!(
                error.contains("PRIVATE_CUSTODY_PROCESS_BODY_PANIC"),
                "body panic was not reached"
            );
        }
    }

    #[test]
    fn body_panic_joins_registered_writer_before_actual_exit_seven() {
        assert_process("panic", 7);
    }

    #[test]
    fn successful_body_joins_registered_writer_before_actual_exit_zero() {
        assert_process("success", 0);
    }
}

use crate::daemon::supervise::Subsystem;
use anyhow::{bail, Result};
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use tokio_util::sync::CancellationToken;

/// Await every handle even after one fails, preserving ownership of siblings.
/// The observer deadline can refuse an upgrade, while this retained owner
/// continues joining actual work. No observer timeout aborts a rotating writer.
pub async fn strict_drain(subsystems: Vec<Subsystem>) -> Result<()> {
    let mut failed = false;
    for (name, handle) in subsystems {
        if handle.await.is_err() {
            failed = true;
            tracing::error!(
                subsystem = name,
                error_kind = "upgrade_subsystem_join_failed",
                "upgrade shutdown cannot certify subsystem completion"
            );
        }
    }
    if failed {
        bail!("upgrade_subsystem_join_failed");
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum Observation {
    Joined,
    Failed,
    Deadline,
}

/// One generation's verdict. Same-generation failure cannot finish green;
/// retry_slot accepts only a joined predecessor and rejects stale identities.
#[derive(Clone, Default)]
pub struct Completion {
    state: Arc<AtomicU8>,
    joined: Arc<std::sync::atomic::AtomicBool>,
    settled: CancellationToken,
}

impl Completion {
    pub fn retry_slot(current: &mut Self, expected: &Self) -> Result<Option<Self>> {
        if !current.same_generation(expected) {
            return Ok(None);
        }
        let next = current.next_verified_generation()?;
        *current = next.clone();
        Ok(Some(next))
    }

    pub async fn observe(&self, deadline: tokio::time::Instant) -> Observation {
        match tokio::time::timeout_at(deadline, self.wait()).await {
            Ok(Ok(())) => Observation::Joined,
            Ok(Err(_)) => Observation::Failed,
            Err(_) => Observation::Deadline,
        }
    }

    /// Call only after the owned supervisor and every admitted task joined.
    pub fn record_joined(&self) {
        self.joined.store(true, Ordering::Release);
    }

    pub fn same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    pub fn next_verified_generation(&self) -> Result<Self> {
        if !self.joined.load(Ordering::Acquire) {
            bail!("supervisor_retry_before_verified_join");
        }
        Ok(Self::default())
    }

    pub fn fail(&self) {
        self.state.store(2, Ordering::Release);
        self.settled.cancel();
    }

    pub fn finish(&self) {
        let _ = self
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
        self.settled.cancel();
    }

    pub async fn wait(&self) -> Result<()> {
        self.settled.cancelled().await;
        if self.state.load(Ordering::Acquire) != 1 {
            bail!("upgrade_shutdown_completion_failed");
        }
        Ok(())
    }
}

/// Shared policy duration for observing one admitted account transaction.
///
/// Policy window, derived from the rotating refresh/publication sequence:
/// pre-commit lock + Node child wait + post-commit canonical lock + local
/// publication allowance + post-lock durable-record acquisition. The local
/// allowance is `CREDENTIAL_COMMIT_IO_ALLOWANCE` for commit/rescue publication;
/// it is policy scheduling room, not an enforced filesystem timer. With the
/// current exports the window is 0.5 + 25 + 30 + 5 + 4 = 64.5 seconds.
/// Cooperative refresher cancellation stops admission of subsequent accounts,
/// so this is not multiplied by the number of configured accounts.
///
/// This is an availability policy, NOT a whole-transaction worst-case bound or
/// a completion guarantee. Optional custodian validation/adoption, pending
/// rescue adoption, Node's separate private pipe-drain budget, filesystem and
/// keychain operations, and scheduler delays can outlast it. Expiry only
/// refuses the observer's upgrade: retained owners still join all admitted
/// work, and admission cannot reopen on the strength of a deadline alone.
pub fn derived_shutdown_budget() -> Result<std::time::Duration> {
    use crate::credentials::rescue::{
        CREDENTIAL_COMMIT_IO_ALLOWANCE, CREDENTIAL_COMMIT_LOCK_BUDGET,
    };
    use crate::http::NODE_CHILD_WAIT_DEADLINE;
    use crate::platform::lock::{CREDENTIAL_LOCK_BUDGET, DURABLE_RECORD_LOCK_BUDGET};

    let budget = CREDENTIAL_LOCK_BUDGET
        .checked_add(NODE_CHILD_WAIT_DEADLINE)
        .and_then(|budget| budget.checked_add(CREDENTIAL_COMMIT_LOCK_BUDGET))
        .and_then(|budget| budget.checked_add(CREDENTIAL_COMMIT_IO_ALLOWANCE))
        .and_then(|budget| budget.checked_add(DURABLE_RECORD_LOCK_BUDGET))
        .ok_or_else(|| anyhow::anyhow!("upgrade_shutdown_budget_overflow"))?;
    Ok(budget)
}

/// Absolute observer deadline; expiry never cancels custodied work.
pub fn derived_shutdown_deadline() -> Result<tokio::time::Instant> {
    tokio::time::Instant::now()
        .checked_add(derived_shutdown_budget()?)
        .ok_or_else(|| anyhow::anyhow!("upgrade_shutdown_deadline_overflow"))
}

/// Observe only transport shutdown; handler work has independent custody.
pub async fn drain_connection_transport<F: std::future::Future>(
    connection: F,
) -> std::result::Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(std::time::Duration::from_secs(2), connection).await
}

/// Own router handlers separately from their transport connection. Dropping a
/// response receiver never cancels an admitted credential-writing handler.
#[derive(Default)]
pub struct HandlerWork {
    inner: std::sync::Mutex<(bool, tokio::task::JoinSet<()>)>,
    joined: std::sync::atomic::AtomicBool,
}

impl HandlerWork {
    pub fn spawn<T, F>(&self, work: F) -> Result<tokio::sync::oneshot::Receiver<T>>
    where
        T: Send + 'static,
        F: std::future::Future<Output = T> + Send + 'static,
    {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("ipc_handler_registry_poisoned"))?;
        if inner.0 {
            bail!("ipc_handler_admission_closed");
        }
        while let Some(result) = inner.1.try_join_next() {
            if result.is_err() {
                tracing::warn!(
                    error_kind = "ipc_completed_handler_panicked",
                    "completed IPC handler failed"
                );
            }
        }
        let (send, receive) = tokio::sync::oneshot::channel();
        inner.1.spawn(async move {
            let response = work.await;
            let _ = send.send(response);
        });
        Ok(receive)
    }

    pub fn all_joined(&self) -> bool {
        self.joined.load(Ordering::Acquire)
    }

    pub async fn close_and_join(&self) -> Result<()> {
        let poisoned = self.inner.is_poisoned();
        let mut handles = {
            let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
            inner.0 = true;
            std::mem::take(&mut inner.1)
        };
        let mut failed = poisoned;
        while let Some(result) = handles.join_next().await {
            if result.is_err() {
                failed = true;
                tracing::warn!(
                    error_kind = "ipc_shutdown_handler_join_failed",
                    "IPC shutdown handler failed"
                );
            }
        }
        self.joined.store(true, Ordering::Release);
        if failed {
            bail!("ipc_shutdown_handler_join_failed");
        }
        Ok(())
    }
}

/// One process-lifetime bridge, with finite waits and an owned thread join.
#[cfg(windows)]
pub struct QuitBridge {
    stop: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl QuitBridge {
    pub fn start(cancel: CancellationToken, _completion: Completion, bound: bool) -> Result<Self> {
        let daemon_stop = super::quit_event::DaemonStopEvent::create_current()?;
        let event = if bound {
            Some(super::quit_event::DesktopQuitEvent::create_current()?)
        } else {
            None
        };
        let stop = CancellationToken::new();
        let worker_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("csq-daemon-quit".into())
            .spawn(move || {
                let slice = std::time::Duration::from_millis(125);
                while !worker_stop.is_cancelled() && !cancel.is_cancelled() {
                    let signalled =
                        daemon_stop
                            .wait_for_quit(slice)
                            .and_then(|daemon_stop| match &event {
                                Some(event) => {
                                    event.wait_for_quit(slice).map(|bound| daemon_stop || bound)
                                }
                                None => Ok(daemon_stop),
                            });
                    match signalled {
                        Ok(true) => {
                            cancel.cancel();
                            break;
                        }
                        Ok(false) => {}
                        Err(_) => {
                            tracing::warn!(
                                error_kind = "daemon_upgrade_event_wait_failed",
                                "daemon upgrade shutdown listener failed"
                            );
                            break;
                        }
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    pub async fn finish(mut self) -> Result<()> {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            tokio::task::spawn_blocking(move || thread.join())
                .await?
                .map_err(|_| anyhow::anyhow!("daemon_upgrade_event_thread_panicked"))?;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for QuitBridge {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

// Registry ownership lives outside every protected body, including unwind.
type CustodyTasks = Arc<std::sync::Mutex<Vec<Arc<dyn CustodiedTask>>>>;
type CustodyVerdicts = Arc<std::sync::Mutex<Vec<Box<dyn Fn() -> bool + Send + Sync>>>>;

fn custody_lock<'a, T>(
    lock: &'a std::sync::Mutex<T>,
    failed: &std::sync::atomic::AtomicBool,
) -> std::sync::MutexGuard<'a, T> {
    lock.lock().unwrap_or_else(|error| {
        failed.store(true, Ordering::Release);
        tracing::error!(
            error_kind = "daemon_custody_lock_poisoned",
            "daemon task custody state poisoned"
        );
        error.into_inner()
    })
}

#[derive(Clone, Default)]
pub struct TaskCustody {
    tasks: CustodyTasks,
    stops: Arc<std::sync::Mutex<Vec<CancellationToken>>>,
    verdicts: CustodyVerdicts,
    failed: Arc<std::sync::atomic::AtomicBool>,
}

trait CustodiedTask: Send + Sync {
    fn poll_join(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<bool>;
    fn name(&self) -> &'static str;
    fn supervised(&self) -> bool;
    fn terminal(&self) -> Option<bool>;
}

struct TaskState<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
    result: Option<std::result::Result<T, tokio::task::JoinError>>,
    terminal: bool,
    failed: bool,
}

struct RetainedTask<T> {
    name: &'static str,
    supervised: bool,
    poison: Arc<std::sync::atomic::AtomicBool>,
    state: std::sync::Mutex<TaskState<T>>,
    wake: Arc<TaskWake>,
}

// JoinHandle retains one waker. All observers share this stable relay, so
// the last poller cannot replace the custody drain's wakeup with its own.
#[derive(Default)]
struct TaskWake(std::sync::Mutex<Vec<std::task::Waker>>);

impl TaskWake {
    fn register(&self, waker: &std::task::Waker) {
        let mut waiters = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if !waiters.iter().any(|prior| prior.will_wake(waker)) {
            waiters.push(waker.clone());
        }
    }
}

impl std::task::Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = {
            let mut waiters = self.0.lock().unwrap_or_else(|error| error.into_inner());
            std::mem::take(&mut *waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}

impl<T: Send + 'static> CustodiedTask for RetainedTask<T> {
    fn name(&self) -> &'static str {
        self.name
    }
    fn supervised(&self) -> bool {
        self.supervised
    }
    fn terminal(&self) -> Option<bool> {
        let state = custody_lock(&self.state, &self.poison);
        state.terminal.then_some(state.failed)
    }

    fn poll_join(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<bool> {
        use std::future::Future;
        use std::task::Poll;
        self.wake.register(cx.waker());
        let relay = std::task::Waker::from(Arc::clone(&self.wake));
        let mut relay_context = std::task::Context::from_waker(&relay);
        let mut state = custody_lock(&self.state, &self.poison);
        if state.terminal {
            return Poll::Ready(state.failed);
        }
        let Some(handle) = state.handle.as_mut() else {
            return Poll::Ready(true);
        };
        match std::pin::Pin::new(handle).poll(&mut relay_context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                state.failed = result.is_err();
                state.result = Some(result);
                state.terminal = true;
                state.handle = None;
                let failed = state.failed;
                drop(state);
                std::task::Wake::wake_by_ref(&self.wake);
                Poll::Ready(failed)
            }
        }
    }
}

/// Dropping an observer never drops or aborts the actual task handle.
pub struct TaskObservation<T>(Arc<RetainedTask<T>>);

// Retain only the shared classifier's literal, not the JoinError or its payload.
#[derive(Debug)]
struct TaskJoinFailure {
    cause: &'static str,
}

impl std::fmt::Display for TaskJoinFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("custodied_task_join_failed")
    }
}

impl std::error::Error for TaskJoinFailure {}

/// Fixed cause for an observed task failure, including through anyhow contexts.
/// Unrelated errors and already-observed results classify as `unknown`.
pub fn task_observation_join_cause(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<TaskJoinFailure>()
        .map_or("unknown", |failure| failure.cause)
}

impl<T: Send + 'static> std::future::Future for TaskObservation<T> {
    type Output = Result<T>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::task::Poll;
        if self.0.poll_join(cx).is_pending() {
            return Poll::Pending;
        }
        let mut state = custody_lock(&self.0.state, &self.0.poison);
        Poll::Ready(match state.result.take() {
            Some(Ok(result)) => Ok(result),
            Some(Err(error)) => Err(TaskJoinFailure {
                cause: crate::error::join_cause(&error),
            }
            .into()),
            None => Err(anyhow::anyhow!("custodied_task_result_already_observed")),
        })
    }
}

impl TaskCustody {
    pub fn adopt<T: Send + 'static>(
        &self,
        name: &'static str,
        handle: tokio::task::JoinHandle<T>,
    ) -> TaskObservation<T> {
        self.adopt_kind(name, handle, false)
    }

    pub fn adopt_subsystem<T: Send + 'static>(
        &self,
        name: &'static str,
        handle: tokio::task::JoinHandle<T>,
    ) -> TaskObservation<T> {
        self.adopt_kind(name, handle, true)
    }

    fn adopt_kind<T: Send + 'static>(
        &self,
        name: &'static str,
        handle: tokio::task::JoinHandle<T>,
        supervised: bool,
    ) -> TaskObservation<T> {
        let task = Arc::new(RetainedTask {
            name,
            supervised,
            poison: Arc::clone(&self.failed),
            wake: Arc::new(TaskWake::default()),
            state: std::sync::Mutex::new(TaskState {
                handle: Some(handle),
                result: None,
                terminal: false,
                failed: false,
            }),
        });
        let mut tasks = custody_lock(&self.tasks, &self.failed);
        tasks.retain(|prior| match (prior.supervised(), prior.terminal()) {
            (false, Some(failed)) => {
                self.failed.fetch_or(failed, Ordering::AcqRel);
                false
            }
            _ => true,
        });
        tasks.push(task.clone());
        TaskObservation(task)
    }

    pub fn register_stop(&self, stop: CancellationToken) {
        custody_lock(&self.stops, &self.failed).push(stop);
    }

    pub fn register_verdict(&self, verdict: impl Fn() -> bool + Send + Sync + 'static) {
        custody_lock(&self.verdicts, &self.failed).push(Box::new(verdict));
    }

    pub async fn wait_stop(
        &self,
        cancel: &CancellationToken,
    ) -> crate::daemon::supervise::SessionStop {
        use crate::daemon::supervise::SessionStop;
        tokio::select! {
            _ = cancel.cancelled() => SessionStop::Cancelled,
            name = std::future::poll_fn(|cx| {
                let tasks = custody_lock(&self.tasks, &self.failed);
                for task in tasks.iter().filter(|task| task.supervised()) {
                    if let std::task::Poll::Ready(failed) = task.poll_join(cx) {
                        self.failed.fetch_or(failed, Ordering::AcqRel);
                        return std::task::Poll::Ready(task.name());
                    }
                }
                std::task::Poll::Pending
            }) => SessionStop::SubsystemExited(name),
        }
    }

    pub async fn drain(&self) -> Result<()> {
        for stop in custody_lock(&self.stops, &self.failed).iter() {
            stop.cancel();
        }
        std::future::poll_fn(|cx| {
            let mut tasks = custody_lock(&self.tasks, &self.failed);
            tasks.retain(|task| match task.poll_join(cx) {
                std::task::Poll::Pending => true,
                std::task::Poll::Ready(failed) => {
                    self.failed.fetch_or(failed, Ordering::AcqRel);
                    false
                }
            });
            if tasks.is_empty() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        let proof_failed = custody_lock(&self.verdicts, &self.failed)
            .iter()
            .any(|proof| !proof());
        if self.failed.load(Ordering::Acquire) || proof_failed {
            bail!("custodied_session_join_failed");
        }
        Ok(())
    }

    /// Catch only body polling; registry lives outside and survives its unwind.
    /// No observer deadline may cancel this owned continuation.
    pub async fn run<F: std::future::Future<Output = std::result::Result<(), String>>>(
        &self,
        body: F,
    ) -> std::result::Result<(), String> {
        let outcome = {
            let mut body = std::pin::pin!(body);
            std::future::poll_fn(|cx| {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    std::future::Future::poll(body.as_mut(), cx)
                })) {
                    Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
                    Ok(std::task::Poll::Ready(result)) => std::task::Poll::Ready(result),
                    Err(_) => std::task::Poll::Ready(Err("daemon_session_body_panicked".into())),
                }
            })
            .await
        };
        let joined = self.drain().await;
        if joined.is_err() {
            return Err("custodied_session_join_failed".into());
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    #[tokio::test]
    async fn observed_task_panic_keeps_cause_without_exposing_payload() {
        const PAYLOAD: &str = "fake-credential-custody-test-only";
        let custody = TaskCustody::default();
        let panicked: tokio::task::JoinHandle<()> = tokio::spawn(async { panic!("{PAYLOAD}") });
        let error = custody.adopt("fixture_panic", panicked).await.unwrap_err();
        assert_eq!(task_observation_join_cause(&error), "panic");
        assert_eq!(error.to_string(), "custodied_task_join_failed");
        assert_eq!(
            error.chain().count(),
            1,
            "raw join error must not be a source"
        );
        for text in [
            format!("{error}"),
            format!("{error:?}"),
            format!("{error:#}"),
            format!("{error:#?}"),
        ] {
            assert!(
                !text.contains(PAYLOAD),
                "observed error exposed panic payload"
            );
        }
        let wrapped = error.context("fixture_join_context");
        assert_eq!(task_observation_join_cause(&wrapped), "panic");
        assert!(!format!("{wrapped:?}").contains(PAYLOAD));
        assert!(
            custody.drain().await.is_err(),
            "observing must retain failure state"
        );
    }

    #[tokio::test]
    async fn observed_task_cancellation_keeps_shared_cause_and_failed_drain() {
        let custody = TaskCustody::default();
        let cancelled = tokio::spawn(std::future::pending::<()>());
        cancelled.abort();
        let error = custody
            .adopt("fixture_cancelled", cancelled)
            .await
            .unwrap_err();
        assert_eq!(task_observation_join_cause(&error), "cancelled");
        assert_eq!(error.to_string(), "custodied_task_join_failed");
        assert!(custody.drain().await.is_err());
    }

    #[tokio::test]
    async fn already_observed_result_and_untyped_errors_have_unknown_cause() {
        let custody = TaskCustody::default();
        let mut observed = custody.adopt("fixture_success", tokio::spawn(async {}));
        (&mut observed).await.unwrap();
        let error = observed.await.unwrap_err();
        assert_eq!(error.to_string(), "custodied_task_result_already_observed");
        assert_eq!(task_observation_join_cause(&error), "unknown");
        assert_eq!(
            task_observation_join_cause(&anyhow::anyhow!("custodied_task_join_failed")),
            "unknown"
        );
        assert!(custody.drain().await.is_ok());
    }

    #[tokio::test]
    async fn rotating_write_outlives_old_five_second_drain() {
        let (release, blocked) = tokio::sync::oneshot::channel();
        let written = Arc::new(AtomicBool::new(false));
        let writer_flag = Arc::clone(&written);
        let writer = tokio::spawn(async move {
            blocked.await.expect("private write release");
            writer_flag.store(true, Ordering::Release);
        });
        let completion = Completion::default();
        let owner = completion.clone();
        let drain = tokio::spawn(async move {
            strict_drain(vec![("credential_write", writer)])
                .await
                .unwrap();
            owner.finish();
        });
        assert!(
            tokio::time::timeout(Duration::from_secs(5), completion.wait())
                .await
                .is_err()
        );
        assert!(!written.load(Ordering::Acquire));
        assert!(!drain.is_finished());
        release.send(()).unwrap();
        drain.await.unwrap();
        completion.wait().await.unwrap();
        assert!(written.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn panic_prevents_completion_and_siblings_are_still_joined() {
        use std::future::Future;
        use std::task::Poll;
        let (release, blocked) = tokio::sync::oneshot::channel();
        let written = Arc::new(AtomicBool::new(false));
        let sibling_written = Arc::clone(&written);
        let panicked: tokio::task::JoinHandle<()> =
            tokio::spawn(async { panic!("private fixture panic") });
        // Establish the first handle's completed error before polling the drain.
        while !panicked.is_finished() {
            tokio::task::yield_now().await;
        }
        let sibling = tokio::spawn(async move {
            blocked.await.unwrap();
            sibling_written.store(true, Ordering::Release);
        });
        let drain = strict_drain(vec![("panic", panicked), ("writer", sibling)]);
        tokio::pin!(drain);
        std::future::poll_fn(|cx| {
            assert!(
                drain.as_mut().poll(cx).is_pending(),
                "drain returned before the admitted sibling write completed"
            );
            Poll::Ready(())
        })
        .await;
        assert!(!written.load(Ordering::Acquire));
        release.send(()).unwrap();
        assert!(drain.await.is_err());
        assert!(
            written.load(Ordering::Acquire),
            "sibling write must finish before the drain reports its error"
        );
    }
    #[tokio::test]
    async fn same_unverified_generation_cannot_finish_green() {
        let completion = Completion::default();
        completion.fail();
        completion.finish();
        assert!(completion.wait().await.is_err());
    }

    #[tokio::test]
    async fn retry_requires_verified_join_and_fresh_generation() {
        let failed = Completion::default();
        failed.fail();
        assert!(
            failed.next_verified_generation().is_err(),
            "unjoined work cannot authorize a retry"
        );
        failed.record_joined();
        let next = failed.next_verified_generation().unwrap();
        assert!(
            !failed.same_generation(&next),
            "verified retry must replace failed generation identity"
        );
        next.finish();
        assert!(next.wait().await.is_ok());
        failed.finish();
        assert!(
            failed.wait().await.is_err(),
            "same failed generation stays failed"
        );
    }

    #[tokio::test]
    async fn stale_retry_proof_cannot_replace_newer_generation() {
        let old = Completion::default();
        old.record_joined();
        old.finish();
        let mut slot = old.clone();
        let current = Completion::retry_slot(&mut slot, &old).unwrap().unwrap();
        assert!(!current.same_generation(&old));
        assert!(Completion::retry_slot(&mut slot, &old).unwrap().is_none());
        assert!(slot.same_generation(&current));
    }

    #[tokio::test]
    async fn observer_refusal_never_certifies_or_cancels_owned_write() {
        use std::future::Future;
        use std::task::Poll;
        let completion = Completion::default();
        let owner = completion.clone();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let written = Arc::new(AtomicBool::new(false));
        let writer = Arc::clone(&written);
        let task = tokio::spawn(async move {
            blocked.await.unwrap();
            writer.store(true, Ordering::Release);
            owner.record_joined();
            owner.finish();
        });
        assert_eq!(
            completion.observe(tokio::time::Instant::now()).await,
            Observation::Deadline
        );
        assert!(!task.is_finished());
        assert!(!written.load(Ordering::Acquire));
        let result = completion.wait();
        tokio::pin!(result);
        std::future::poll_fn(|cx| {
            assert!(
                result.as_mut().poll(cx).is_pending(),
                "deadline cannot certify pending writer"
            );
            Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        task.await.unwrap();
        assert!(result.await.is_ok());
        assert!(written.load(Ordering::Acquire));
    }

    #[tokio::test(start_paused = true)]
    async fn derived_deadline_retains_owner_and_closed_handler_admission() {
        use std::future::Future;
        use std::task::Poll;

        let start = tokio::time::Instant::now();
        let deadline = derived_shutdown_deadline().unwrap();
        let work = Arc::new(HandlerWork::default());
        let written = Arc::new(AtomicBool::new(false));
        let writer = Arc::clone(&written);
        let (release, blocked) = tokio::sync::oneshot::channel();
        drop(
            work.spawn(async move {
                blocked.await.unwrap();
                writer.store(true, Ordering::Release);
            })
            .unwrap(),
        );
        let completion = Completion::default();
        let owner_completion = completion.clone();
        let owner_work = Arc::clone(&work);
        let (closed, admission_closed) = tokio::sync::oneshot::channel();
        let owner = tokio::spawn(async move {
            let joining = owner_work.close_and_join();
            tokio::pin!(joining);
            std::future::poll_fn(|cx| {
                assert!(joining.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            closed.send(()).unwrap();
            joining.await.unwrap();
            owner_completion.record_joined();
            owner_completion.finish();
        });
        admission_closed.await.unwrap();
        assert!(work.spawn(async {}).is_err());

        // Exercise the actual returned deadline on both sides without a
        // wall-clock sleep or an assertion mirroring its numeric composition.
        tokio::time::advance(deadline.duration_since(start) - Duration::from_millis(1)).await;
        let observation = completion.observe(deadline);
        tokio::pin!(observation);
        std::future::poll_fn(|cx| {
            assert!(observation.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Step one timer-wheel millisecond beyond the policy deadline.
        tokio::time::advance(Duration::from_millis(2)).await;
        std::future::poll_fn(|cx| {
            assert_eq!(
                observation.as_mut().poll(cx),
                Poll::Ready(Observation::Deadline)
            );
            Poll::Ready(())
        })
        .await;
        assert!(!owner.is_finished());
        assert!(!written.load(Ordering::Acquire));
        assert!(!work.all_joined());
        assert!(completion.next_verified_generation().is_err());
        assert!(work.spawn(async {}).is_err());

        release.send(()).unwrap();
        owner.await.unwrap();
        completion.wait().await.unwrap();
        assert!(written.load(Ordering::Acquire));
        assert!(work.all_joined());
        assert!(work.spawn(async {}).is_err());
    }

    #[tokio::test]
    async fn disconnected_response_does_not_release_handler_write_custody() {
        use std::future::Future;
        use std::task::Poll;
        let work = HandlerWork::default();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let written = Arc::new(AtomicBool::new(false));
        let writer = Arc::clone(&written);
        let response = work
            .spawn(async move {
                blocked.await.unwrap();
                writer.store(true, Ordering::Release);
            })
            .unwrap();
        drop(response); // Hyper/client lifetime ends before the actual write.
        let joined = work.close_and_join();
        tokio::pin!(joined);
        std::future::poll_fn(|cx| {
            assert!(
                joined.as_mut().poll(cx).is_pending(),
                "disconnect cannot certify an admitted write as complete"
            );
            Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        joined.await.unwrap();
        assert!(written.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn completed_error_response_does_not_poison_later_shutdown() {
        let work = HandlerWork::default();
        let response = work
            .spawn(async { Err::<(), &str>("fixture_response_error") })
            .unwrap();
        assert!(response.await.unwrap().is_err());
        assert!(work.close_and_join().await.is_ok());
    }

    #[tokio::test]
    async fn body_panic_joins_admitted_write_before_returning_nonzero() {
        use std::future::Future;
        use std::task::Poll;
        let custody = TaskCustody::default();
        let body_custody = custody.clone();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let written = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&written);
        let body = async move {
            drop(body_custody.adopt_subsystem(
                "fixture_writer",
                tokio::spawn(async move {
                    blocked.await.unwrap();
                    flag.store(true, Ordering::Release);
                }),
            ));
            panic!("private body panic after admission");
            #[allow(unreachable_code)]
            Ok(())
        };
        let joined = custody.run(body);
        tokio::pin!(joined);
        std::future::poll_fn(|cx| {
            assert!(
                joined.as_mut().poll(cx).is_pending(),
                "body panic returned before admitted writer joined"
            );
            Poll::Ready(())
        })
        .await;
        assert!(!written.load(Ordering::Acquire));
        release.send(()).unwrap();
        assert!(
            joined.await.is_err(),
            "body panic must return nonzero after verified drain"
        );
        assert!(written.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn task_panic_and_dropped_observer_still_join_sibling_write() {
        use std::future::Future;
        use std::task::Poll;
        let custody = TaskCustody::default();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let written = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&written);
        let panicked: tokio::task::JoinHandle<()> =
            tokio::spawn(async { panic!("private task panic") });
        while !panicked.is_finished() {
            tokio::task::yield_now().await;
        }
        drop(custody.adopt_subsystem("panic", panicked));
        drop(custody.adopt_subsystem(
            "writer",
            tokio::spawn(async move {
                blocked.await.unwrap();
                flag.store(true, Ordering::Release);
            }),
        ));
        let joined = custody.run(async { Ok(()) });
        tokio::pin!(joined);
        std::future::poll_fn(|cx| {
            assert!(
                joined.as_mut().poll(cx).is_pending(),
                "task panic returned before sibling writer joined"
            );
            Poll::Ready(())
        })
        .await;
        release.send(()).unwrap();
        assert!(joined.await.is_err());
        assert!(written.load(Ordering::Acquire));
    }

    // R1 M2: a peer that never finishes its transport cannot hold the daemon
    // alive; dropping that transport must not cancel its admitted writer.
    #[tokio::test(start_paused = true)]
    async fn r1_stalled_transport_deadline_keeps_handler_custody() {
        let work = HandlerWork::default();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let committed = Arc::new(AtomicBool::new(false));
        let published = Arc::clone(&committed);
        let response = work
            .spawn(async move {
                blocked.await.unwrap();
                published.store(true, Ordering::Release);
            })
            .unwrap();
        let observed = tokio::time::timeout(
            Duration::from_secs(3),
            drain_connection_transport(std::future::pending::<()>()),
        )
        .await;
        // Complete the writer even on the RED branch, retaining no leaked task.
        drop(response);
        assert!(!committed.load(Ordering::Acquire));
        assert!(!work.all_joined());
        release.send(()).unwrap();
        work.close_and_join().await.unwrap();
        assert!(committed.load(Ordering::Acquire));
        assert!(work.all_joined());
        assert!(observed.is_ok(), "R1_M2_STALLED_TRANSPORT_UNBOUNDED");
        assert!(observed.unwrap().is_err(), "stalled transport must expire");
    }

    // R1 L7: both independently owned pollers must receive completion wakeups.
    #[tokio::test]
    async fn r1_task_completion_wakes_observer_and_custody_drain() {
        use std::future::Future;
        use std::task::{Context, Poll, Wake, Waker};
        #[derive(Default)]
        struct Counter {
            count: std::sync::atomic::AtomicUsize,
            event: tokio::sync::Notify,
        }
        impl Wake for Counter {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.count.fetch_add(1, Ordering::AcqRel);
                self.event.notify_one();
            }
        }
        let custody = TaskCustody::default();
        let (release, blocked) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            blocked.await.unwrap();
        });
        let mut observation = std::pin::pin!(custody.adopt("r1_waiter_fixture", task));
        let mut drain = std::pin::pin!(custody.drain());
        let first = Arc::new(Counter::default());
        let second = Arc::new(Counter::default());
        let drain_waker = Waker::from(Arc::clone(&first));
        let observer_waker = Waker::from(Arc::clone(&second));
        assert!(matches!(
            drain.as_mut().poll(&mut Context::from_waker(&drain_waker)),
            Poll::Pending
        ));
        assert!(matches!(
            observation
                .as_mut()
                .poll(&mut Context::from_waker(&observer_waker)),
            Poll::Pending
        ));
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), second.event.notified())
            .await
            .unwrap();
        // Always consume both continuations before asserting the RED condition.
        observation.await.unwrap();
        drain.await.unwrap();
        assert!(
            first.count.load(Ordering::Acquire) > 0,
            "R1_L7_CUSTODY_WAKE_LOST"
        );
        assert!(second.count.load(Ordering::Acquire) > 0);
    }
}
