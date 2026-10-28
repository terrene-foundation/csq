//! Process-bound upgrade Quit endpoint; never a window-close request.

use anyhow::{Context, Result};
use csq_core::update::upgrade_guard::quit_event::DesktopQuitEvent;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::JoinHandle;
use std::time::Duration;
use tauri::{AppHandle, Manager};

const WAIT_SLICE: Duration = Duration::from_millis(250);
#[derive(Default)]
struct QuitState {
    verified: Arc<AtomicBool>,
    phase: std::sync::atomic::AtomicU8,
    task: Mutex<QuitTask>,
}

#[derive(Default)]
struct QuitTask {
    intent: ExitIntent,
    handle: Option<OwnedQuit>,
    recovery: Option<OwnedQuit>,
    install: Option<PendingInstall>,
    install_attempt: bool,
}

struct PendingInstall {
    operation: InstallCallback,
    result: Option<tokio::sync::oneshot::Sender<Result<(), &'static str>>>,
}
impl Drop for PendingInstall {
    fn drop(&mut self) {
        if let Some(result) = self.result.take() {
            let _ = result.send(Err("desktop_install_refused"));
        }
    }
}

fn reject_pending_install(app: &AppHandle) {
    let pending = app.try_state::<QuitState>().and_then(|state| {
        state
            .task
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .install
            .take()
    });
    if let Some(mut pending) = pending {
        pending.operation.reject();
    }
}

/// One canonical admission owner travels through drain, exact joins, install
/// and recovery. Installation never re-closes the updater's live identity.
enum Admission {
    Quit(super::credential_writes::Drain),
    Update {
        lease: Option<super::login_custody::UpdateLease>,
        unknown: bool,
    },
}
impl Admission {
    async fn wait(&self) -> Result<(), String> {
        match self {
            Self::Quit(drain) => drain.wait().await,
            Self::Update {
                lease: Some(lease), ..
            } => lease.wait().await,
            _ => Err("desktop_update_unverified".into()),
        }
    }
    fn reopen(self) -> Result<(), String> {
        match self {
            Self::Quit(drain) => drain.reopen(),
            Self::Update {
                lease: Some(lease),
                unknown: false,
            } => lease.release(),
            // An install return, panic or lost observer must retain sticky Drop.
            _ => Err("desktop_update_unverified".into()),
        }
    }
}

/// Rust-owned signed update only. The renderer cannot supply an approval,
/// resource identifier, URL or path. Cancellation drops this one-shot callback.
pub(super) fn request_install(
    app: &AppHandle,
    lease: super::login_custody::UpdateLease,
    continuation: impl FnOnce(ApprovedInstall) -> Result<(), ()> + Send + 'static,
) -> Result<tokio::sync::oneshot::Receiver<Result<(), &'static str>>, &'static str> {
    let state = match app.try_state::<QuitState>() {
        Some(state) => state,
        None => {
            let _ = lease.release();
            return Err("desktop_quit_state_unavailable");
        }
    };
    let mut owner = match state.task.lock() {
        Ok(owner) => owner,
        Err(_) => {
            let _ = lease.release();
            return Err("desktop_quit_task_state_poisoned");
        }
    };
    if owner.active_owner() {
        let _ = lease.release();
        return Err("desktop_quit_busy");
    }
    let Some(mode) = owner
        .intent
        .request_with_custody(QuitMode::Upgrade, 0, false, false)
    else {
        let _ = lease.release();
        return Err("desktop_quit_busy");
    };
    let (result, receiver) = tokio::sync::oneshot::channel();
    owner.install = Some(PendingInstall {
        operation: InstallCallback(Some(Box::new(continuation))),
        result: Some(result),
    });
    owner.install_attempt = true;
    state.phase.store(1, Ordering::Release);
    owner.handle = Some(OwnedQuit::spawn(quit_after_drain(
        app.clone(),
        mode,
        Some(Admission::Update {
            lease: Some(lease),
            unknown: false,
        }),
    )));
    Ok(receiver)
}

/// Track the future itself, including unwind/drop before its first poll. Each
/// continuation has its own flag, so an old owner cannot retire a newer one.
struct OwnedQuit {
    _handle: tauri::async_runtime::JoinHandle<()>,
    active: Arc<AtomicBool>,
}
impl OwnedQuit {
    fn spawn(future: impl std::future::Future<Output = ()> + Send + 'static) -> Self {
        struct Finished(Arc<AtomicBool>);
        impl Drop for Finished {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let active = Arc::new(AtomicBool::new(true));
        let finished = Finished(Arc::clone(&active));
        let handle = tauri::async_runtime::spawn(async move {
            let _finished = finished;
            future.await;
        });
        Self {
            _handle: handle,
            active,
        }
    }
}
impl QuitTask {
    fn active_owner(&self) -> bool {
        [&self.handle, &self.recovery].iter().any(|owner| {
            owner
                .as_ref()
                .is_some_and(|owner| owner.active.load(Ordering::Acquire))
        })
    }
}

struct Worker {
    cancelled: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

struct Listener(Mutex<Option<Worker>>, Arc<std::sync::atomic::AtomicU8>);

impl Drop for Listener {
    fn drop(&mut self) {
        // Also covers a rejected duplicate manage() registration or setup
        // teardown before RunEvent::Exit. Never keep waiting after state drops.
        let worker = self.0.get_mut().unwrap_or_else(|error| error.into_inner());
        if let Some(worker) = worker {
            worker.cancelled.store(true, Ordering::Release);
        }
    }
}

/// Listener failure disables the bound channel and warns; normal desktop
/// daemon hosting remains available. The listener owns its native handle.
pub(super) fn start(app: &AppHandle) {
    if !app.manage(QuitState::default()) {
        tracing::warn!(
            error_kind = "desktop_quit_state_already_registered",
            "desktop Quit state already registered"
        );
    }
    let signin_app = app.clone();
    if super::credential_writes::global()
        .set_signin_listener(Arc::new(move || {
            let ui_app = signin_app.clone();
            if signin_app
                .run_on_main_thread(move || signin_status_changed(&ui_app))
                .is_err()
            {
                tracing::warn!(
                    error_kind = "desktop_signin_status_dispatch_failed",
                    "desktop sign-in status update unavailable"
                );
            }
        }))
        .is_err()
    {
        tracing::warn!(
            error_kind = "desktop_signin_status_listener_failed",
            "desktop sign-in status listener unavailable"
        );
    }
    if start_listener(app).is_err() {
        tracing::warn!(
            error_kind = "desktop_upgrade_listener_unavailable",
            "desktop upgrade Quit channel unavailable; daemon hosting continues"
        );
    }
}

fn start_listener(app: &AppHandle) -> Result<()> {
    if app.try_state::<Listener>().is_none()
        && !app.manage(Listener(
            Mutex::new(None),
            Arc::new(std::sync::atomic::AtomicU8::new(0)),
        ))
    {
        anyhow::bail!("desktop_upgrade_listener_already_registered");
    }
    let listener = app
        .try_state::<Listener>()
        .ok_or_else(|| anyhow::anyhow!("desktop_upgrade_listener_state_unavailable"))?;
    if listener.1.load(Ordering::Acquire) != 0 {
        anyhow::bail!("desktop_upgrade_listener_join_unverified");
    }
    let mut slot = listener
        .0
        .lock()
        .map_err(|_| anyhow::anyhow!("desktop_upgrade_listener_state_poisoned"))?;
    if slot.is_some() {
        anyhow::bail!("desktop_upgrade_listener_already_running");
    }
    let event =
        DesktopQuitEvent::create_current().context("desktop_upgrade_event_create_failed")?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let handle = app.clone();
    let thread = std::thread::Builder::new()
        .name("csq-upgrade-quit".into())
        .spawn(move || {
            while !worker_cancelled.load(Ordering::Acquire) {
                match event.wait_for_quit(WAIT_SLICE) {
                    Ok(false) => {}
                    Ok(true) => {
                        if !worker_cancelled.load(Ordering::Acquire) {
                            // The old Exit callback only cancelled; its 5s
                            // drain could detach a rotating credential writer.
                            request_upgrade_quit(&handle);
                        }
                        break;
                    }
                    Err(_) => {
                        tracing::error!(
                            error_kind = "desktop_upgrade_event_wait_failed",
                            "desktop upgrade Quit listener stopped"
                        );
                        break;
                    }
                }
            }
            // Drop closes the event on signal, cancellation, or wait failure.
        })
        .context("desktop_upgrade_listener_spawn_failed")?;
    *slot = Some(Worker { cancelled, thread });
    Ok(())
}

pub(super) fn exit_verified(app: &AppHandle) -> bool {
    app.try_state::<QuitState>()
        .is_some_and(|state| state.verified.load(Ordering::Acquire))
}

pub(super) fn draining_status(app: &AppHandle) -> Option<&'static str> {
    app.try_state::<QuitState>()
        .and_then(|state| match state.phase.load(Ordering::Acquire) {
            1 => Some("csq: finishing credential writes before exit"),
            2 => Some("csq: joining credential refresher before exit"),
            3 => Some("csq: restoring supervisor after refused upgrade"),
            4 => Some("csq: running without daemon; credential admission closed; retry Quit"),
            5 if can_cancel_quit(app) => Some("csq: running without daemon while work joins; Cancel Quit keeps the dashboard open"),
            5 => Some("csq: exit refused; work remains owned; wait for recovery before retrying"),
            6 => Some("csq: Quit refused; finish or close sign-in browser, then retry Quit"),
            7 => Some("csq: Quit recovery; work remains owned; retry Quit when it finishes"),
            8 => Some("csq: Upgrade refused; finish or close sign-in browser, then retry the upgrade"),
            9 => Some("csq: Quit refused; credential writes remain owned; retry Quit when they finish"),
            10 => Some("csq: Upgrade refused; credential writes remain owned; retry the upgrade when they finish"),
            _ => None,
        })
}

fn phase(app: &AppHandle, value: u8) {
    if let Some(state) = app.try_state::<QuitState>() {
        state.phase.store(value, Ordering::Release);
    }
    if let (Some(tray), Some(status)) = (app.tray_by_id("main"), draining_status(app)) {
        if tray.set_tooltip(Some(status)).is_err() {
            tracing::warn!(
                error_kind = "desktop_draining_status_unavailable",
                "desktop tray status update failed"
            );
        }
    }
}

pub(super) fn request_quit(app: &AppHandle) {
    request(app, QuitMode::User, 0);
}
pub(super) fn request_exit(app: &AppHandle, code: i32) {
    request(app, QuitMode::User, code);
}
fn request_upgrade_quit(app: &AppHandle) {
    request(app, QuitMode::Upgrade, 0);
}

fn request(app: &AppHandle, mode: QuitMode, code: i32) {
    let Some(state) = app.try_state::<QuitState>() else {
        tracing::warn!(
            error_kind = "desktop_quit_state_unavailable",
            "desktop Quit refused"
        );
        return;
    };
    if state.task.is_poisoned() {
        reject_pending_install(app);
    }
    let (mut owner, poisoned) = match state.task.lock() {
        Ok(owner) => (owner, false),
        Err(error) => {
            tracing::error!(
                error_kind = "desktop_quit_task_state_poisoned",
                "desktop Quit state recovered; existing continuation retains custody"
            );
            (error.into_inner(), true)
        }
    };
    let active = owner.active_owner();
    let claimed = owner
        .intent
        .request_with_custody(mode, code, poisoned, active);
    if let Some(mode) = claimed {
        owner.install_attempt = false;
        state.phase.store(1, Ordering::Release);
        owner.handle = Some(OwnedQuit::spawn(quit_after_drain(app.clone(), mode, None)));
    }
    drop(owner);
    // Menu refresh may read exit intent: never call it under task custody.
    if claimed.is_none() && (poisoned || active) {
        phase(
            app,
            repeated_request_phase(state.phase.load(Ordering::Acquire)),
        );
        show_recovery(app);
    }
}

fn user_exit_code(app: &AppHandle) -> Option<i32> {
    let state = app.try_state::<QuitState>()?;
    let owner = state.task.lock().unwrap_or_else(|error| {
        tracing::error!(
            error_kind = "desktop_quit_task_state_poisoned",
            "desktop exit intent read from poisoned custody"
        );
        error.into_inner()
    });
    owner.intent.user_exit()
}

fn is_user_exit(app: &AppHandle) -> bool {
    user_exit_code(app).is_some()
}

async fn rearm_listener(app: &AppHandle) -> Result<()> {
    stop(app).await?;
    start_listener(app)
}

fn restore_running_ui(app: &AppHandle) {
    if !app
        .try_state::<QuitState>()
        .is_some_and(|state| state.phase.load(Ordering::Acquire) == 0)
    {
        return;
    }
    if let Some(window) = app.get_webview_window("main") {
        if window
            .set_title(app.config().product_name.as_deref().unwrap_or("csq"))
            .is_err()
        {
            tracing::warn!(
                error_kind = "desktop_title_restore_failed",
                "desktop window title restore failed"
            );
        }
    }
    if let Some(tray) = app.tray_by_id("main") {
        super::refresh_tray_menu(app, &tray);
    }
}

/// active_signins currently fails only when the credential gate mutex is poisoned.
/// Preserve that refusal and report its fixed cause without formatting the error.
fn inspect_signins<T, E>(observed: Result<T, E>) -> Result<T, E> {
    if observed.is_err() {
        tracing::warn!(
            error_kind = "credential_write_gate_poisoned",
            "desktop credential state unavailable"
        );
    }
    observed
}

fn signin_status_changed(app: &AppHandle) {
    let Some(state) = app.try_state::<QuitState>() else {
        return;
    };
    let current = state.phase.load(Ordering::Acquire);
    let decision = signin_decision(
        current,
        inspect_signins(super::credential_writes::global().active_signins())
            .map(|signins| !signins.is_empty()),
    );
    if decision.clear_refusal
        && state
            .phase
            .compare_exchange(current, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        // The callback is dispatched on the UI thread. Reopen/reset and the
        // last registration drop both use the same display restoration path.
        restore_running_ui(app);
    }
}

fn show_recovery(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        if app
            .try_state::<QuitState>()
            .is_some_and(|state| state.phase.load(Ordering::Acquire) == 7)
        {
            let _ = window
                .set_title("csq — Quit recovery: work remains owned; retry Quit when it finishes");
        } else if app
            .try_state::<QuitState>()
            .is_some_and(|state| state.phase.load(Ordering::Acquire) == 4)
        {
            let _ = window
                .set_title("csq — Running without daemon; credential admission closed; retry Quit");
        } else if app
            .try_state::<QuitState>()
            .is_some_and(|state| state.phase.load(Ordering::Acquire) == 5)
        {
            let title = if can_cancel_quit(app) {
                "csq — Shutdown work remains owned; Cancel Quit keeps the dashboard open"
            } else {
                "csq — Exit refused; shutdown work remains owned; wait for recovery before retrying"
            };
            let _ = window.set_title(title);
        }
        if window.show().and_then(|_| window.set_focus()).is_err() {
            tracing::warn!(
                error_kind = "desktop_recovery_window_show_failed",
                "desktop recovery window unavailable"
            );
        }
    }
    if let Some(tray) = app.tray_by_id("main") {
        super::refresh_tray_menu(app, &tray);
    }
}

/// Cancelling intent never cancels admitted credential work or reopens a
/// stopped generation. Its retained observer restores hosting after real join.
pub(super) fn can_cancel_quit(app: &AppHandle) -> bool {
    app.try_state::<QuitState>()
        .is_some_and(|state| state.phase.load(Ordering::Acquire) == 5)
        && is_user_exit(app)
}

pub(super) fn cancel_quit(app: &AppHandle) {
    if !can_cancel_quit(app) {
        return;
    }
    reject_pending_install(app);
    if let Some(state) = app.try_state::<QuitState>() {
        let mut owner = state.task.lock().unwrap_or_else(|error| {
            tracing::warn!(
                error_kind = "desktop_quit_cancel_state_poisoned",
                "Cancel Quit recovered intent; retained work continues"
            );
            error.into_inner()
        });
        owner.intent.user_exit = false;
    }
    show_recovery(app);
}

/// A consumed Upgrade listener has already returned long before a write-drain
/// deadline. Join only a finished native worker, synchronously under Quit task
/// ownership; never race a background rearm against a fresh explicit Quit.
fn rearm_finished_listener(app: &AppHandle) -> Result<()> {
    let worker = {
        let Some(listener) = app.try_state::<Listener>() else {
            return Ok(());
        };
        let mut slot = listener
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("desktop_upgrade_listener_state_poisoned"))?;
        if !slot
            .as_ref()
            .is_some_and(|worker| worker.thread.is_finished())
        {
            return Ok(());
        }
        slot.take()
    };
    if let Some(worker) = worker {
        if worker.thread.join().is_err() {
            if let Some(listener) = app.try_state::<Listener>() {
                listener.1.store(1, Ordering::Release);
            }
            anyhow::bail!("desktop_upgrade_listener_join_failed");
        }
    }
    start_listener(app)
}

/// Admission may reopen before supervisor cancellation, even with an existing
/// writer. Retire this attempt so a later explicit Quit gets a new deadline.
fn refuse_unstopped(
    app: &AppHandle,
    admission: Option<Admission>,
    mode: QuitMode,
    signins_refused: bool,
) {
    reject_pending_install(app);
    let reopened = if let Some(state) = app.try_state::<QuitState>() {
        match state.task.lock() {
            Ok(mut owner) => {
                if rearm_finished_listener(app).is_err() {
                    tracing::warn!(
                        error_kind = "desktop_upgrade_listener_rearm_failed",
                        "Quit refused; upgrade channel unavailable"
                    );
                }
                refuse_attempt(&mut owner.intent, || {
                    admission.is_none_or(|drain| drain.reopen().is_ok())
                })
            }
            Err(error) => {
                error.into_inner().intent.retire();
                false
            }
        }
    } else {
        false
    };
    if !reopened {
        phase(app, 7);
        show_recovery(app);
        return;
    }
    // Only a refusal caused by registered sign-ins may auto-clear when their
    // registrations finish. A writer deadline remains visible for explicit retry.
    phase(app, refusal_phase(mode, signins_refused));
    if let Some(window) = app.get_webview_window("main") {
        let signins = inspect_signins(super::credential_writes::global().active_signins());
        let title = match signins {
            Err(_) => format!(
                "csq — {} refused; credential state unavailable",
                if mode == QuitMode::User {
                    "Quit"
                } else {
                    "Upgrade"
                }
            ),
            Ok(signins) if !signins.is_empty() => {
                if signins_refused {
                    tracing::warn!(
                        error_kind = "desktop_signin_active",
                        "desktop exit attempt refused while sign-in remains active"
                    );
                }
                format!(
                    "csq — {} refused: {}; finish or close the sign-in browser and retry {}",
                    if mode == QuitMode::User {
                        "Quit"
                    } else {
                        "Upgrade"
                    },
                    signins
                        .iter()
                        .map(|signin| format!("{} slot {}", signin.provider, signin.account))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if mode == QuitMode::User {
                        "Quit"
                    } else {
                        "the upgrade"
                    }
                )
            }
            _ => format!(
                "csq — {} refused; finish credential writes and retry {}",
                if mode == QuitMode::User {
                    "Quit"
                } else {
                    "Upgrade"
                },
                if mode == QuitMode::User {
                    "Quit"
                } else {
                    "the upgrade"
                }
            ),
        };
        if window.set_title(&title).is_err() {
            tracing::warn!(
                error_kind = "desktop_quit_refusal_title_unavailable",
                "desktop Quit refusal title unavailable"
            );
        }
    }
    if !signins_refused {
        tracing::warn!(
            error_kind = "desktop_write_drain_deadline",
            "desktop exit attempt refused while credential work remains owned"
        );
    }
    show_recovery(app);
    signin_status_changed(app);
}

/// Retain recovery separately from the bounded Quit observer. No writer task
/// changes ownership when this observer reaches its deadline.
fn retain_recovery(
    app: &AppHandle,
    future: impl std::future::Future<Output = ()> + Send + 'static,
) {
    reject_pending_install(app);
    if let Some(state) = app.try_state::<QuitState>() {
        let mut owner = state.task.lock().unwrap_or_else(|error| error.into_inner());
        owner.recovery = Some(OwnedQuit::spawn(future));
        drop(owner);
        phase(app, 5);
        show_recovery(app);
        return;
    }
    phase(app, 7);
    show_recovery(app);
}

fn refused(app: &AppHandle, reason: &'static str, _mode: QuitMode) {
    reject_pending_install(app);
    tracing::warn!(
        error_kind = reason,
        "desktop Quit refused; application remains running"
    );
    let next_phase = if let Some(state) = app.try_state::<QuitState>() {
        match state.task.lock() {
            Ok(mut owner) => {
                // Refusal retires this attempt. A later explicit Quit claims a
                // fresh fully gated owner after this continuation has finished.
                owner.intent.retire();
                4
            }
            Err(error) => {
                let mut owner = error.into_inner();
                owner.intent.retire();
                tracing::error!(
                    error_kind = "desktop_quit_task_state_poisoned",
                    "desktop Quit refused; retry when retained continuation finishes"
                );
                7
            }
        }
    } else {
        7
    };
    phase(app, next_phase);
    show_recovery(app);
}

/// Before cancellation, refusal retires intent for a later explicit Quit;
/// refusal is never proof that current daemon writers have joined.
fn reopen_unstopped(app: &AppHandle, admission: Admission, mode: QuitMode, reason: &'static str) {
    reject_pending_install(app);
    let result = {
        let Some(state) = app.try_state::<QuitState>() else {
            tracing::error!(
                error_kind = "desktop_quit_state_unavailable",
                "desktop admission remains closed"
            );
            return;
        };
        let mut owner = match state.task.lock() {
            Ok(owner) => owner,
            Err(error) => {
                let mut owner = error.into_inner();
                owner.intent.retire();
                drop(owner);
                tracing::error!(
                    error_kind = "desktop_quit_task_state_poisoned",
                    "desktop admission remains closed; explicit Quit may retry after current work"
                );
                phase(app, 7);
                show_recovery(app);
                return;
            }
        };
        let result = owner.intent.commit_upgrade(|| admission.reopen().is_ok());
        if result == CommitDecision::Reopened {
            state.phase.store(0, Ordering::Release);
        }
        result
    };
    if result == CommitDecision::Reopened {
        tracing::warn!(
            error_kind = reason,
            "desktop Quit refused; admission restored"
        );
        restore_running_ui(app);
    } else {
        refused(app, reason, mode);
    }
}

fn request_supervisor_resume(
    app: &AppHandle,
    expected: &csq_core::update::upgrade_guard::drain::Completion,
) -> Result<()> {
    let state = app
        .try_state::<super::AppState>()
        .ok_or_else(|| anyhow::anyhow!("desktop_upgrade_state_unavailable"))?;
    let supervisor = state
        .daemon_supervisor
        .lock()
        .map_err(|_| anyhow::anyhow!("desktop_upgrade_supervisor_poisoned"))?;
    if let Some(supervisor) = supervisor.as_ref() {
        supervisor
            .resume_after_refused_upgrade(expected)
            .map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

// BEGIN PORTABLE_STICKY_INTENT
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuitMode {
    Upgrade,
    User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitDecision {
    Reopened,
    Exit(i32),
    Refused,
}

#[derive(Default)]
struct ExitIntent {
    requested: bool,
    user_exit: bool,
    exit_code: i32,
}

impl ExitIntent {
    fn request_with_custody(
        &mut self,
        mode: QuitMode,
        code: i32,
        poisoned: bool,
        active: bool,
    ) -> Option<QuitMode> {
        if active || (poisoned && mode == QuitMode::Upgrade) {
            return None;
        }
        // Poison recovery may retire an abandoned latch, never a live owner.
        // A new User attempt still traverses admission and exact-generation joins.
        if poisoned {
            self.requested = false;
        }
        self.request(mode, code)
    }

    /// Caller holds the existing task mutex through promotion and owner claim.
    fn request(&mut self, mode: QuitMode, code: i32) -> Option<QuitMode> {
        if mode == QuitMode::User {
            self.user_exit = true;
            self.exit_code = code;
        }
        if self.requested {
            return None;
        }
        self.requested = true;
        Some(if self.user_exit {
            QuitMode::User
        } else {
            QuitMode::Upgrade
        })
    }

    fn user_exit(&self) -> Option<i32> {
        self.user_exit.then_some(self.exit_code)
    }

    /// A refused attempt requires a later explicit request; no deferred exit.
    fn retire(&mut self) {
        self.requested = false;
        self.user_exit = false;
    }

    /// No await occurs between this latch check, reopen, and owner retirement.
    /// A later promotion acquires the same mutex and claims a fresh drain owner.
    fn commit_upgrade(&mut self, reopen: impl FnOnce() -> bool) -> CommitDecision {
        if let Some(code) = self.user_exit() {
            return CommitDecision::Exit(code);
        }
        if !reopen() {
            return CommitDecision::Refused;
        }
        self.requested = false;
        CommitDecision::Reopened
    }
}

#[derive(Clone, Copy)]
enum AdmissionObservation {
    Joined,
    Failed,
    Deadline,
}

/// The observation never owns or cancels a writer. Deadline refuses this attempt.
async fn observe_admission<O>(observed: O) -> bool
where
    O: std::future::Future<Output = AdmissionObservation>,
{
    matches!(observed.await, AdmissionObservation::Joined)
}

// END PORTABLE_STICKY_INTENT

// BEGIN PORTABLE_INSTALL_APPROVAL
/// Only this module constructs approval after actual writer/generation/listener joins.
pub(crate) struct ApprovedInstall {
    _private: (),
}
type InstallContinuation = Box<dyn FnOnce(ApprovedInstall) -> Result<(), ()> + Send>;
struct InstallCallback(Option<InstallContinuation>);
impl InstallCallback {
    fn reject(&mut self) {
        self.0.take();
    }
}

fn invoke_approved_install(
    verified: &std::sync::atomic::AtomicBool,
    joined: bool,
    operation: impl FnOnce(ApprovedInstall) -> Result<(), ()>,
) -> Result<(), ()> {
    use std::sync::atomic::Ordering;
    if !joined {
        return Err(());
    }
    struct Revoke<'a>(&'a std::sync::atomic::AtomicBool, bool);
    impl Drop for Revoke<'_> {
        fn drop(&mut self) {
            if !self.1 {
                self.0.store(false, Ordering::Release);
            }
        }
    }
    verified.store(true, Ordering::Release);
    let mut revoke = Revoke(verified, false);
    let result = operation(ApprovedInstall { _private: () });
    revoke.1 = result.is_ok();
    result
}

// END PORTABLE_INSTALL_APPROVAL

// BEGIN PORTABLE_REFUSAL_DECISION
fn refuse_attempt(intent: &mut ExitIntent, reopen: impl FnOnce() -> bool) -> bool {
    intent.retire();
    reopen()
}

/// An unreadable sign-in registry cannot authorize draining or clearing refusal.
/// Only a sign-in refusal may clear automatically; writer deadlines require retry.
#[derive(Debug, PartialEq, Eq)]
struct SigninDecision {
    refuse_quit: bool,
    clear_refusal: bool,
}

fn signin_decision<E>(current: u8, observed: Result<bool, E>) -> SigninDecision {
    let clear = matches!(observed, Ok(false));
    SigninDecision {
        refuse_quit: !clear,
        clear_refusal: clear && matches!(current, 6 | 8),
    }
}

fn refusal_phase(mode: QuitMode, signins_refused: bool) -> u8 {
    match (mode, signins_refused) {
        (QuitMode::User, true) => 6,
        (QuitMode::Upgrade, true) => 8,
        (QuitMode::User, false) => 9,
        (QuitMode::Upgrade, false) => 10,
    }
}

fn repeated_request_phase(current: u8) -> u8 {
    if current == 5 {
        5
    } else {
        7
    }
}

fn refuse_supervisor_deadline(intent: &mut ExitIntent) {
    intent.retire();
}
// END PORTABLE_REFUSAL_DECISION

// BEGIN PORTABLE_STICKY_RESOLVER
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ListenerJoin {
    Joined,
    JoinedFailure,
    Unverified,
}

async fn resolve_sticky_join<J, U, P, PF, C, L, LF, E, R>(
    joined: J,
    mut user_exit: U,
    prepare: P,
    commit: C,
    listener: L,
    exit: E,
    refuse: R,
) where
    J: std::future::Future<Output = bool>,
    U: FnMut() -> Option<i32>,
    P: FnOnce() -> PF,
    PF: std::future::Future<Output = bool>,
    C: FnOnce() -> CommitDecision,
    L: FnOnce() -> LF,
    LF: std::future::Future<Output = ListenerJoin>,
    E: FnOnce(i32),
    R: FnOnce(),
{
    let decision = if !joined.await {
        user_exit().map_or(CommitDecision::Refused, |_| CommitDecision::Exit(1))
    } else if let Some(code) = user_exit() {
        CommitDecision::Exit(code)
    } else {
        // Rearming is the last awaited preparation. No fresh writer generation
        // starts here; it can start only in the serialized commit callback.
        let prepared = prepare().await;
        if let Some(code) = user_exit() {
            CommitDecision::Exit(code)
        } else if !prepared {
            CommitDecision::Refused
        } else {
            commit()
        }
    };
    match decision {
        CommitDecision::Reopened => {}
        CommitDecision::Refused => refuse(),
        CommitDecision::Exit(code) => match listener().await {
            ListenerJoin::Joined => exit(code),
            ListenerJoin::JoinedFailure => exit(1),
            ListenerJoin::Unverified => refuse(), // Retire intent; keep admission closed.
        },
    }
}
// END PORTABLE_STICKY_RESOLVER

fn requested_exit_code(app: &AppHandle) -> i32 {
    user_exit_code(app).unwrap_or(0)
}

fn approve_exit(app: &AppHandle, code: i32) {
    if super::login_custody::global()
        .authorize_windows_exit()
        .is_err()
    {
        refused(app, "desktop_exit_custody_unverified", QuitMode::User);
        return;
    }
    if let Some(state) = app.try_state::<QuitState>() {
        state.verified.store(true, Ordering::Release);
    }
    app.exit(code);
}

async fn finish_install_or_exit(app: &AppHandle, code: i32, admission: &mut Admission) -> bool {
    let Some(state) = app.try_state::<QuitState>() else {
        return false;
    };
    let (install_attempt, pending) = match state.task.lock() {
        Ok(mut owner) => (owner.install_attempt, owner.install.take()),
        Err(error) => {
            let pending = error.into_inner().install.take();
            drop(pending);
            return false;
        }
    };
    if !install_attempt {
        approve_exit(app, code);
        return true;
    }
    let Some(mut pending) = pending else {
        return false;
    };
    let Some(operation) = pending.operation.0.take() else {
        return false;
    };
    let verified = Arc::clone(&state.verified);
    // Caller reaches here only after the actual admission, exact generation
    // and listener joins. Keep the installer task inside this OwnedQuit.
    let Admission::Update { lease, unknown } = admission else {
        return false;
    };
    let Some(install_lease) = lease.take() else {
        return false;
    };
    // From this boundary a return/unwind cannot prove installer completion.
    *unknown = true;
    let installed = tauri::async_runtime::spawn_blocking(move || {
        let result =
            install_lease.with_install_exit(|| invoke_approved_install(&verified, true, operation));
        (install_lease, result)
    })
    .await;
    if let Ok((returned_lease, _)) = installed {
        *lease = Some(returned_lease);
    }
    state.verified.store(false, Ordering::Release);
    // A successful Windows handoff exits inside install; EVERY return fails.
    let result: Result<(), &'static str> = Err("desktop_install_failed");
    if let Some(reply) = pending.result.take() {
        let _ = reply.send(result);
    }
    tracing::warn!(
        error_kind = "desktop_install_failed",
        "installation failed; restoring desktop hosting"
    );
    false
}

async fn recover_without_generation(
    app: &AppHandle,
    admission: Admission,
    mode: QuitMode,
    reason: &'static str,
) {
    if rearm_listener(app).await.is_err() {
        refused(app, "desktop_listener_join_unverified", mode);
        return;
    }
    reopen_unstopped(app, admission, mode, reason);
}

/// An owned observer retains closed command admission until the OLD generation
/// actually joins. Its timeout never cancels or drops the real writer task.
async fn reopen_after_join(
    app: AppHandle,
    completion: csq_core::update::upgrade_guard::drain::Completion,
    admission: Admission,
    _mode: QuitMode,
) {
    reject_pending_install(&app);
    phase(&app, 5);
    let read_app = app.clone();
    let prepare_app = app.clone();
    let commit_app = app.clone();
    let listener_app = app.clone();
    let exit_app = app.clone();
    let refused_app = app.clone();
    let wait_completion = completion.clone();
    resolve_sticky_join(
        async move { wait_completion.wait().await.is_ok() },
        move || user_exit_code(&read_app),
        move || async move {
            phase(&prepare_app, 3);
            if rearm_listener(&prepare_app).await.is_err() {
                tracing::error!(
                    error_kind = "desktop_supervisor_rearm_failed",
                    "desktop admission remains closed"
                );
                return false;
            }
            true
        },
        move || {
            let Some(state) = commit_app.try_state::<QuitState>() else {
                return CommitDecision::Refused;
            };
            let Ok(mut owner) = state.task.lock() else {
                phase(&commit_app, 4);
                tracing::error!(
                    error_kind = "desktop_quit_task_state_poisoned",
                    "desktop admission remains closed"
                );
                return CommitDecision::Refused;
            };
            // FINAL synchronous boundary: promotion uses THIS same mutex.
            let result = owner.intent.commit_upgrade(|| {
                // All awaits (including listener rearm) finished before fresh writers start.
                if request_supervisor_resume(&commit_app, &completion).is_err() {
                    tracing::error!(
                        error_kind = "desktop_supervisor_resume_failed",
                        "desktop admission remains closed"
                    );
                    return false;
                }
                if admission.reopen().is_err() {
                    tracing::error!(
                        error_kind = "desktop_write_gate_reopen_failed",
                        "desktop admission remains closed"
                    );
                    return false;
                }
                true
            });
            if result == CommitDecision::Reopened {
                state.phase.store(0, Ordering::Release);
            }
            result
        },
        move || async move { stop_joined(&listener_app).await },
        move |code| approve_exit(&exit_app, code),
        move || refused(&refused_app, "desktop_quit_drain_refused", QuitMode::User),
    )
    .await;
    if app
        .try_state::<QuitState>()
        .is_some_and(|state| state.phase.load(Ordering::Acquire) == 0)
    {
        restore_running_ui(&app);
    } else if let Some(tray) = app.tray_by_id("main") {
        super::refresh_tray_menu(&app, &tray);
    }
}

async fn quit_after_drain(app: AppHandle, mode: QuitMode, transferred: Option<Admission>) {
    let deadline = match csq_core::update::upgrade_guard::drain::derived_shutdown_deadline() {
        Ok(deadline) => deadline,
        Err(_) => {
            if let Some(admission) = transferred {
                let _ = admission.reopen();
            }
            refused(&app, "desktop_shutdown_budget_unavailable", mode);
            return;
        }
    };
    let mut admission = match transferred {
        Some(admission) => admission,
        None => {
            let signins = inspect_signins(super::credential_writes::global().active_signins())
                .map(|signins| !signins.is_empty());
            if signin_decision(0, signins).refuse_quit {
                refuse_unstopped(&app, None, mode, true);
                return;
            }
            match super::credential_writes::close_for_quit_tag(super::credential_writes::global()) {
                Ok(drain) => Admission::Quit(drain),
                Err(tag) => {
                    refused(&app, tag, mode);
                    return;
                }
            }
        }
    };
    let joined = observe_admission(async {
        match tokio::time::timeout_at(deadline, admission.wait()).await {
            Ok(Ok(())) => AdmissionObservation::Joined,
            Ok(Err(_)) => AdmissionObservation::Failed,
            Err(_) => AdmissionObservation::Deadline,
        }
    })
    .await;
    if !joined {
        // The daemon has not been cancelled: restore admission and retire this
        // attempt promptly. Existing permits still own their actual writers.
        refuse_unstopped(&app, Some(admission), mode, false);
        return;
    }
    phase(&app, 2);
    let completion = {
        let Some(state) = app.try_state::<super::AppState>() else {
            reopen_unstopped(&app, admission, mode, "desktop_upgrade_state_unavailable");
            return;
        };
        let Ok(supervisor) = state.daemon_supervisor.lock() else {
            reopen_unstopped(&app, admission, mode, "desktop_upgrade_supervisor_poisoned");
            return;
        };
        match supervisor
            .as_ref()
            .map(|supervisor| supervisor.shutdown_for_upgrade())
            .transpose()
        {
            Ok(completion) => completion,
            Err(_) => {
                reopen_unstopped(
                    &app,
                    admission,
                    mode,
                    "desktop_upgrade_supervisor_shutdown_refused",
                );
                return;
            }
        }
    };
    if let Some(completion) = &completion {
        use csq_core::update::upgrade_guard::drain::Observation;
        match completion.observe(deadline).await {
            Observation::Joined => {}
            observation @ (Observation::Deadline | Observation::Failed) => {
                if matches!(observation, Observation::Deadline) {
                    if let Some(state) = app.try_state::<QuitState>() {
                        let mut owner =
                            state.task.lock().unwrap_or_else(|error| error.into_inner());
                        refuse_supervisor_deadline(&mut owner.intent);
                    }
                }
                let recovery_app = app.clone();
                let completion = completion.clone();
                retain_recovery(&app, async move {
                    reopen_after_join(recovery_app, completion, admission, mode).await;
                });
                return;
            }
        }
    }
    let cleanup_app = app.clone();
    let mut cleanup = tauri::async_runtime::spawn(async move { stop(&cleanup_app).await });
    let cleanup_result = match tokio::time::timeout_at(deadline, &mut cleanup).await {
        Ok(result) => result
            .map_err(|_| anyhow::anyhow!("desktop_listener_cleanup_task_failed"))
            .and_then(|result| result),
        Err(_) => {
            if let Some(state) = app.try_state::<QuitState>() {
                let mut owner = state.task.lock().unwrap_or_else(|error| error.into_inner());
                refuse_supervisor_deadline(&mut owner.intent);
            }
            let recovery_app = app.clone();
            retain_recovery(&app, async move {
                // Keep and join the actual cleanup task after observer expiry.
                let _joined = cleanup.await;
                if let Some(completion) = completion {
                    reopen_after_join(recovery_app, completion, admission, mode).await;
                } else {
                    // No daemon generation exists; retry listener proof before exit.
                    match stop_joined(&recovery_app).await {
                        joined @ (ListenerJoin::Joined | ListenerJoin::JoinedFailure) => {
                            if is_user_exit(&recovery_app) {
                                let code = if joined == ListenerJoin::JoinedFailure {
                                    1
                                } else {
                                    requested_exit_code(&recovery_app)
                                };
                                approve_exit(&recovery_app, code);
                            } else {
                                recover_without_generation(
                                    &recovery_app,
                                    admission,
                                    mode,
                                    "desktop_quit_cancelled",
                                )
                                .await;
                            }
                        }
                        ListenerJoin::Unverified => {
                            refused(&recovery_app, "desktop_listener_join_unverified", mode)
                        }
                    }
                }
            });
            return;
        }
    };
    if cleanup_result.is_err() {
        if let Some(completion) = completion {
            reopen_after_join(app, completion, admission, mode).await;
        } else {
            recover_without_generation(&app, admission, mode, "desktop_listener_cleanup_failed")
                .await;
        }
        return;
    }
    // Admission stays closed through the install worker's real join or exit.
    if !finish_install_or_exit(&app, requested_exit_code(&app), &mut admission).await {
        if let Some(state) = app.try_state::<QuitState>() {
            let mut owner = state.task.lock().unwrap_or_else(|error| error.into_inner());
            refuse_supervisor_deadline(&mut owner.intent);
        }
        if let Some(completion) = completion {
            reopen_after_join(app, completion, admission, mode).await;
        } else {
            recover_without_generation(&app, admission, mode, "desktop_install_failed").await;
        }
    }
}

/// Join the native listener off the event loop before approving exit.
async fn stop(app: &AppHandle) -> Result<()> {
    match stop_joined(app).await {
        ListenerJoin::Joined => Ok(()),
        ListenerJoin::JoinedFailure => anyhow::bail!("desktop_upgrade_listener_join_failed"),
        ListenerJoin::Unverified => anyhow::bail!("desktop_upgrade_listener_join_unverified"),
    }
}

async fn stop_joined(app: &AppHandle) -> ListenerJoin {
    let worker = {
        let Some(listener) = app.try_state::<Listener>() else {
            return ListenerJoin::Joined;
        };
        if listener.1.load(Ordering::Acquire) == 2 {
            phase(app, 4);
            tracing::error!(
                error_kind = "desktop_upgrade_listener_join_unverified",
                "desktop admission remains closed; listener completion unverified"
            );
            return ListenerJoin::Unverified;
        }
        let mut state = match listener.0.lock() {
            Ok(state) => state,
            Err(error) => {
                listener.1.store(1, Ordering::Release);
                tracing::error!(
                    error_kind = "desktop_upgrade_listener_state_poisoned",
                    "desktop listener state poisoned; joining actual worker"
                );
                error.into_inner()
            }
        };
        state.take()
    };
    if let Some(worker) = worker {
        worker.cancelled.store(true, Ordering::Release);
        let proof = match app.try_state::<Listener>() {
            Some(listener) => Arc::clone(&listener.1),
            None => return ListenerJoin::Unverified,
        };
        let prior_failure = proof.load(Ordering::Acquire) == 1;
        proof.store(3, Ordering::Release);
        let joined = tauri::async_runtime::spawn_blocking(move || {
            let joined = worker.thread.join();
            proof.store(
                if joined.is_ok() && !prior_failure {
                    0
                } else {
                    1
                },
                Ordering::Release,
            );
            joined
        })
        .await;
        if let Some(listener) = app.try_state::<Listener>() {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    listener.1.store(1, Ordering::Release);
                    tracing::error!(
                        error_kind = "desktop_upgrade_listener_panicked",
                        "desktop listener joined with failure"
                    );
                }
                Err(_) => {
                    // The native join may already have completed independently
                    // of this observer. Preserve that proof for explicit retry.
                    let _ = listener
                        .1
                        .compare_exchange(3, 2, Ordering::AcqRel, Ordering::Acquire);
                    phase(app, 4);
                    tracing::error!(
                        error_kind = "desktop_upgrade_listener_join_unverified",
                        "desktop admission remains closed; listener completion unverified"
                    );
                    return ListenerJoin::Unverified;
                }
            }
        } else {
            phase(app, 4);
            tracing::error!(
                error_kind = "desktop_upgrade_listener_state_unavailable",
                "desktop admission remains closed; listener completion unverified"
            );
            return ListenerJoin::Unverified;
        }
    }
    match app
        .try_state::<Listener>()
        .map(|listener| listener.1.load(Ordering::Acquire))
    {
        Some(1) => ListenerJoin::JoinedFailure,
        Some(2 | 3) => ListenerJoin::Unverified,
        _ => ListenerJoin::Joined,
    }
}

// BEGIN PORTABLE_STICKY_TESTS
#[cfg(test)]
mod sticky_exit_tests {
    use super::{
        observe_admission, resolve_sticky_join, AdmissionObservation, ExitIntent, ListenerJoin,
        QuitMode,
    };
    use std::cell::{Cell, RefCell};
    use std::future::Future;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    struct Fixture {
        intent: Rc<Mutex<ExitIntent>>,
        joined: Rc<Cell<Option<bool>>>,
        rearm: Rc<Cell<Option<bool>>>,
        listener: Rc<Cell<Option<ListenerJoin>>>,
        promote_before_commit: Rc<Cell<bool>>,
        exit: Rc<Cell<Option<i32>>>,
        reopened: Rc<Cell<bool>>,
        generation: Rc<Cell<u32>>,
        joined_generation: Rc<Cell<Option<u32>>>,
        trace: Rc<RefCell<Vec<&'static str>>>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut intent = ExitIntent::default();
            assert_eq!(
                intent.request(QuitMode::Upgrade, 0),
                Some(QuitMode::Upgrade)
            );
            Self {
                intent: Rc::new(Mutex::new(intent)),
                joined: Rc::new(Cell::new(None)),
                rearm: Rc::new(Cell::new(Some(true))),
                listener: Rc::new(Cell::new(None)),
                promote_before_commit: Rc::new(Cell::new(false)),
                exit: Rc::new(Cell::new(None)),
                reopened: Rc::new(Cell::new(false)),
                generation: Rc::new(Cell::new(0)),
                joined_generation: Rc::new(Cell::new(None)),
                trace: Rc::new(RefCell::new(Vec::new())),
            }
        }

        fn promote(&self) -> Option<QuitMode> {
            self.intent.lock().unwrap().request(QuitMode::User, 7)
        }

        fn actor(&self) -> impl Future<Output = ()> {
            let joined = Rc::clone(&self.joined);
            let join_trace = Rc::clone(&self.trace);
            let joined_generation = Rc::clone(&self.joined_generation);
            let current_generation = self.generation.get();
            let read_intent = Rc::clone(&self.intent);
            let prepare = Rc::clone(&self.rearm);
            let prepare_trace = Rc::clone(&self.trace);
            let commit_intent = Rc::clone(&self.intent);
            let promote_before_commit = Rc::clone(&self.promote_before_commit);
            let generation = Rc::clone(&self.generation);
            let reopened = Rc::clone(&self.reopened);
            let commit_trace = Rc::clone(&self.trace);
            let listener = Rc::clone(&self.listener);
            let listener_trace = Rc::clone(&self.trace);
            let exit = Rc::clone(&self.exit);
            let exit_trace = Rc::clone(&self.trace);
            let refuse_trace = Rc::clone(&self.trace);
            resolve_sticky_join(
                std::future::poll_fn(move |_| match joined.get() {
                    Some(result) => {
                        joined_generation.set(Some(current_generation));
                        join_trace.borrow_mut().push("actual_join");
                        Poll::Ready(result)
                    }
                    None => Poll::Pending,
                }),
                move || read_intent.lock().unwrap().user_exit(),
                move || {
                    prepare_trace.borrow_mut().push("rearm_started");
                    std::future::poll_fn(move |_| match prepare.get() {
                        Some(result) => {
                            prepare_trace.borrow_mut().push("rearm_joined");
                            Poll::Ready(result)
                        }
                        None => Poll::Pending,
                    })
                },
                move || {
                    if promote_before_commit.get() {
                        assert_eq!(
                            commit_intent.lock().unwrap().request(QuitMode::User, 7),
                            None
                        );
                    }
                    commit_intent.lock().unwrap().commit_upgrade(|| {
                        generation.set(generation.get() + 1);
                        commit_trace.borrow_mut().push("restart");
                        reopened.set(true);
                        commit_trace.borrow_mut().push("reopen");
                        true
                    })
                },
                move || {
                    listener_trace.borrow_mut().push("listener_join_started");
                    std::future::poll_fn(move |_| match listener.get() {
                        Some(result) => {
                            listener_trace.borrow_mut().push("listener_joined");
                            Poll::Ready(result)
                        }
                        None => Poll::Pending,
                    })
                },
                move |code| {
                    exit_trace.borrow_mut().push("exit");
                    exit.set(Some(code));
                },
                move || refuse_trace.borrow_mut().push("refused"),
            )
        }
    }

    #[test]
    fn user_exit_while_rearm_waits_never_reopens_or_restarts() {
        let fixture = Fixture::new();
        fixture.joined.set(Some(true));
        fixture.rearm.set(None);
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_pending());
        assert_eq!(
            fixture.generation.get(),
            0,
            "fresh generation cannot start before listener rearm completes"
        );
        assert_eq!(fixture.promote(), None);
        fixture.rearm.set(Some(true));
        assert!(
            poll_once(actor.as_mut()).is_pending(),
            "user exit promoted during rearm must join listener before exit"
        );
        assert!(!fixture.reopened.get());
        assert_eq!(
            fixture.generation.get(),
            0,
            "promotion during rearm cannot start fresh writers"
        );
        fixture.listener.set(Some(ListenerJoin::Joined));
        assert!(poll_once(actor.as_mut()).is_ready());
        assert_eq!(fixture.exit.get(), Some(7));
        assert_eq!(
            &*fixture.trace.borrow(),
            &[
                "actual_join",
                "rearm_started",
                "rearm_joined",
                "listener_join_started",
                "listener_joined",
                "exit"
            ]
        );
    }

    #[test]
    fn refusal_retires_user_intent_without_handoff() {
        let mut intent = ExitIntent::default();
        assert_eq!(intent.request(QuitMode::User, 7), Some(QuitMode::User));
        assert!(super::refuse_attempt(&mut intent, || true));
        assert!(!intent.requested);
        assert_eq!(intent.user_exit(), None);
    }

    #[test]
    fn promotion_immediately_before_commit_prevents_reopen() {
        let fixture = Fixture::new();
        fixture.joined.set(Some(true));
        fixture.promote_before_commit.set(true);
        let mut actor = std::pin::pin!(fixture.actor());
        let result = poll_once(actor.as_mut());
        assert!(
            !fixture.reopened.get(),
            "latched exit immediately before reopen must refuse commit"
        );
        assert!(result.is_pending());
        assert_eq!(fixture.generation.get(), 0);
        fixture.listener.set(Some(ListenerJoin::Joined));
        assert!(poll_once(actor.as_mut()).is_ready());
        assert_eq!(fixture.exit.get(), Some(7));
    }

    #[test]
    fn late_after_commit_promotion_starts_current_generation_drain() {
        let fixture = Fixture::new();
        fixture.joined.set(Some(true));
        {
            let mut actor = std::pin::pin!(fixture.actor());
            assert!(poll_once(actor.as_mut()).is_ready());
        }
        assert!(fixture.reopened.get());
        assert_eq!(fixture.generation.get(), 1);
        assert_eq!(
            fixture.promote(),
            Some(QuitMode::User),
            "late promotion must claim a fresh drain owner"
        );
        fixture.joined.set(None);
        let mut current = std::pin::pin!(fixture.actor());
        assert!(poll_once(current.as_mut()).is_pending());
        assert_eq!(fixture.joined_generation.get(), Some(0));
        assert_eq!(
            fixture.exit.get(),
            None,
            "old generation proof cannot exit fresh writers"
        );
        fixture.joined.set(Some(true));
        assert!(poll_once(current.as_mut()).is_pending());
        assert_eq!(fixture.joined_generation.get(), Some(1));
        fixture.listener.set(Some(ListenerJoin::Joined));
        assert!(poll_once(current.as_mut()).is_ready());
        assert_eq!(fixture.exit.get(), Some(7));
    }

    #[test]
    fn failed_reopen_keeps_gate_closed_and_clears_refused_exit() {
        let mut intent = ExitIntent::default();
        assert_eq!(intent.request(QuitMode::User, 7), Some(QuitMode::User));
        let calls = Cell::new(0);
        assert!(!super::refuse_attempt(&mut intent, || {
            calls.set(calls.get() + 1);
            false
        }));
        assert_eq!(calls.get(), 1);
        assert!(!intent.requested);
        assert_eq!(
            intent.user_exit(),
            None,
            "refused Quit must never exit later"
        );
    }

    #[test]
    fn failed_completion_joins_listener_then_exits_nonzero_without_restart_or_reopen() {
        let fixture = Fixture::new();
        assert_eq!(fixture.promote(), None);
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_pending());
        fixture.joined.set(Some(false));
        assert!(
            poll_once(actor.as_mut()).is_pending(),
            "failed completion must join listener before exit notification"
        );
        assert!(!fixture.reopened.get());
        assert_eq!(fixture.exit.get(), None);
        fixture.listener.set(Some(ListenerJoin::Joined));
        assert!(poll_once(actor.as_mut()).is_ready());
        assert_eq!(fixture.exit.get(), Some(1));
        assert_eq!(fixture.generation.get(), 0);
    }

    #[test]
    fn promoted_user_exit_waits_for_actual_join_and_listener_without_restart() {
        let fixture = Fixture::new();
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_pending());
        assert_eq!(fixture.promote(), None);
        fixture.joined.set(Some(true));
        assert!(
            poll_once(actor.as_mut()).is_pending(),
            "promoted user exit must join listener before exiting"
        );
        fixture.listener.set(Some(ListenerJoin::Joined));
        assert!(poll_once(actor.as_mut()).is_ready());
        assert_eq!(fixture.exit.get(), Some(7));
        assert_eq!(fixture.generation.get(), 0);
        assert!(!fixture.reopened.get());
    }

    #[test]
    fn successful_upgrade_refusal_is_the_only_restart_and_reopen_path() {
        let fixture = Fixture::new();
        fixture.joined.set(Some(true));
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_ready());
        assert!(fixture.reopened.get());
        assert_eq!(fixture.generation.get(), 1);
        assert_eq!(fixture.exit.get(), None);
        assert_eq!(
            &*fixture.trace.borrow(),
            &[
                "actual_join",
                "rearm_started",
                "rearm_joined",
                "restart",
                "reopen"
            ]
        );
    }

    #[test]
    fn unavailable_listener_join_proof_keeps_admission_closed_without_exit() {
        let fixture = Fixture::new();
        fixture.joined.set(Some(false));
        fixture.listener.set(Some(ListenerJoin::Unverified));
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_ready());
        assert!(!fixture.reopened.get());
        assert_eq!(fixture.exit.get(), None);
    }

    #[test]
    fn verified_listener_failure_makes_promoted_user_exit_nonzero() {
        let fixture = Fixture::new();
        fixture.joined.set(Some(true));
        assert_eq!(fixture.promote(), None);
        fixture.listener.set(Some(ListenerJoin::JoinedFailure));
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_ready());
        assert_eq!(fixture.exit.get(), Some(1));
        assert!(!fixture.reopened.get());
    }
    #[test]
    fn unverified_listener_retires_exit_attempt_for_explicit_retry() {
        let fixture = Fixture::new();
        assert_eq!(fixture.promote(), None);
        fixture.joined.set(Some(true));
        fixture.listener.set(Some(ListenerJoin::Unverified));
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_ready());
        assert_eq!(fixture.exit.get(), None);
        assert!(!fixture.reopened.get());
        assert!(
            fixture.trace.borrow().contains(&"refused"),
            "missing refusal leaves the requested latch permanently set"
        );
    }

    #[test]
    fn upgrade_failure_refuses_after_actual_join_without_process_exit() {
        let fixture = Fixture::new();
        fixture.joined.set(Some(false));
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_ready());
        assert!(fixture.trace.borrow().contains(&"refused"));
        assert_eq!(fixture.exit.get(), None);
        assert!(!fixture.reopened.get());
        assert_eq!(fixture.generation.get(), 0);
    }

    #[test]
    fn refusal_executes_real_retire_reopen_clear_decision_once() {
        let mut intent = ExitIntent::default();
        assert_eq!(intent.request(QuitMode::User, 3), Some(QuitMode::User));
        let reopened = Cell::new(0);
        assert!(super::refuse_attempt(&mut intent, || {
            reopened.set(reopened.get() + 1);
            true
        }));
        assert_eq!(
            reopened.get(),
            1,
            "production decision must invoke actual reopen callback"
        );
        assert!(
            !intent.requested,
            "production decision must retire the attempt"
        );
        assert_eq!(
            intent.user_exit(),
            None,
            "production decision must clear deferred exit"
        );
        assert_eq!(
            intent.request_with_custody(QuitMode::User, 0, false, false),
            Some(QuitMode::User)
        );
    }

    #[test]
    fn supervisor_deadline_refuses_user_exit_then_exact_join_restores_hosting() {
        let fixture = Fixture::new();
        assert_eq!(fixture.promote(), None);
        super::refuse_supervisor_deadline(&mut fixture.intent.lock().unwrap());
        assert_eq!(fixture.intent.lock().unwrap().user_exit(), None);
        fixture.joined.set(Some(true));
        let mut actor = std::pin::pin!(fixture.actor());
        assert!(poll_once(actor.as_mut()).is_ready());
        assert_eq!(fixture.exit.get(), None);
        assert!(fixture.reopened.get());
        assert_eq!(fixture.generation.get(), 1);
        assert_eq!(fixture.joined_generation.get(), Some(0));
    }

    #[test]
    fn signin_decision_fails_closed_and_only_clears_signin_refusal() {
        for current in [0, 6, 8, 9, 10] {
            assert!(super::signin_decision(current, Ok::<_, ()>(true)).refuse_quit);
            let unreadable = super::signin_decision(current, Err::<bool, _>(()));
            assert!(unreadable.refuse_quit);
            assert!(!unreadable.clear_refusal);
            let clear = super::signin_decision(current, Ok::<_, ()>(false));
            assert!(!clear.refuse_quit);
            assert_eq!(clear.clear_refusal, matches!(current, 6 | 8));
        }
        assert_eq!(super::refusal_phase(QuitMode::User, true), 6);
        assert_eq!(super::refusal_phase(QuitMode::Upgrade, true), 8);
        assert_eq!(super::refusal_phase(QuitMode::User, false), 9);
        assert_eq!(super::refusal_phase(QuitMode::Upgrade, false), 10);
    }

    #[test]
    fn repeated_quit_preserves_cancel_quit_recovery_phase() {
        assert_eq!(super::repeated_request_phase(5), 5);
        assert_eq!(super::repeated_request_phase(1), 7);
    }

    #[test]
    fn failed_admission_refuses_promptly() {
        let mut observation = std::pin::pin!(observe_admission(std::future::ready(
            AdmissionObservation::Failed
        ),));
        assert_eq!(poll_once(observation.as_mut()), Poll::Ready(false));
    }

    #[test]
    fn poisoned_quit_without_live_owner_allows_fully_gated_user_retry() {
        let intent = Mutex::new(ExitIntent::default());
        let poisoned = std::panic::catch_unwind(|| {
            let mut guard = intent.lock().unwrap();
            assert_eq!(guard.request(QuitMode::Upgrade, 0), Some(QuitMode::Upgrade));
            panic!("fixture quit bookkeeping unwind");
        });
        assert!(poisoned.is_err());
        let mut guard = intent
            .lock()
            .err()
            .expect("fixture must poison custody")
            .into_inner();
        assert_eq!(
            guard.request_with_custody(QuitMode::User, 9, true, false),
            Some(QuitMode::User)
        );
        assert_eq!(guard.user_exit(), Some(9));
        assert!(
            guard.requested,
            "recovery claims an attempt, never exit or reopen proof"
        );
    }

    #[test]
    fn poisoned_quit_never_latches_exit_for_an_active_continuation() {
        let mut intent = ExitIntent::default();
        assert_eq!(
            intent.request(QuitMode::Upgrade, 0),
            Some(QuitMode::Upgrade)
        );
        assert_eq!(
            intent.request_with_custody(QuitMode::User, 9, true, true),
            None
        );
        assert_eq!(intent.user_exit(), None);
        assert_eq!(
            intent.request_with_custody(QuitMode::User, 9, true, true),
            None
        );
        assert_eq!(
            intent.request_with_custody(QuitMode::User, 9, true, false),
            Some(QuitMode::User)
        );
    }

    #[test]
    fn poisoned_quit_never_starts_an_automatic_upgrade_owner() {
        let mut intent = ExitIntent::default();
        assert_eq!(
            intent.request_with_custody(QuitMode::Upgrade, 0, true, false),
            None
        );
        assert!(!intent.requested);
        assert_eq!(intent.user_exit(), None);
    }
    #[test]
    fn approved_installer_runs_once_only_after_generation_and_listener_join() {
        let joined = Cell::new(false);
        let listener_joined = Cell::new(false);
        let calls = Cell::new(0);
        let verified = std::sync::atomic::AtomicBool::new(false);
        let mut actor = std::pin::pin!(resolve_sticky_join(
            std::future::poll_fn(|_| if joined.get() {
                Poll::Ready(true)
            } else {
                Poll::Pending
            }),
            || Some(0),
            || std::future::ready(true),
            || super::CommitDecision::Reopened,
            || std::future::poll_fn(|_| if listener_joined.get() {
                Poll::Ready(ListenerJoin::Joined)
            } else {
                Poll::Pending
            }),
            |_| {
                super::invoke_approved_install(&verified, true, |_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .unwrap();
            },
            || panic!("fixture unexpectedly refused"),
        ));
        assert!(poll_once(actor.as_mut()).is_pending());
        assert_eq!(calls.get(), 0);
        joined.set(true);
        assert!(poll_once(actor.as_mut()).is_pending());
        assert_eq!(calls.get(), 0);
        listener_joined.set(true);
        assert!(poll_once(actor.as_mut()).is_ready());
        assert_eq!(calls.get(), 1);
        assert!(verified.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn refused_install_callback_cannot_run_during_late_recovery() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let worker_calls = std::sync::Arc::clone(&calls);
        let mut pending = super::InstallCallback(Some(Box::new(move |_| {
            worker_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })));
        pending.reject(); // Production refusal/deadline/cancel custody operation.
        assert!(
            pending.0.take().is_none(),
            "late recovery cannot recover a refused callback"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn install_error_and_panic_revoke_verified_exit_before_recovery() {
        let verified = std::sync::atomic::AtomicBool::new(false);
        assert!(super::invoke_approved_install(&verified, true, |_| Err(())).is_err());
        assert!(!verified.load(std::sync::atomic::Ordering::Acquire));
        assert!(std::panic::catch_unwind(|| super::invoke_approved_install(
            &verified,
            true,
            |_| panic!("fixture install unwind")
        ))
        .is_err());
        assert!(!verified.load(std::sync::atomic::Ordering::Acquire));
        let called = Cell::new(false);
        assert!(super::invoke_approved_install(&verified, false, |_| {
            called.set(true);
            Ok(())
        })
        .is_err());
        assert!(!called.get());
    }
}
// END PORTABLE_STICKY_TESTS

/// R2 item 6(a): the refusal ROUTING `quit_after_drain` uses. The gate close
/// itself is proven on every platform; this module proves the Windows caller
/// routes each refusal to its own fixed tag without reopening admission.
#[cfg(test)]
mod quit_refusal_routing_tests {
    use super::super::credential_writes::{self, CredentialWrites};

    /// ROOT M1 correction: after an unverified update the Quit is ADMITTED
    /// (the gate is already closed and drains empty), while every route that
    /// could reopen admission keeps refusing.
    #[tokio::test]
    async fn quit_after_drain_admits_an_unverified_quit_and_never_reopens_admission() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        drop(lease); // KeepClosed-style unverified outcome
        let admission = credential_writes::close_for_quit_tag(&gate)
            .expect("an unverified update must still admit the Quit");
        admission
            .wait()
            .await
            .expect("the closed gate drains empty");
        assert_eq!(admission.reopen().unwrap_err(), "desktop_update_unverified");
        assert!(
            gate.admit().is_err(),
            "the routed Quit drain reopened admission"
        );
    }

    #[test]
    fn quit_after_drain_routes_a_live_lease_to_the_quiescence_tag() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update lease");
        assert_eq!(
            credential_writes::close_for_quit_tag(&gate).err(),
            Some("desktop_update_quiescence_held")
        );
        lease.release().expect("explicit verified release");
        assert!(gate.admit().is_ok(), "release did not reopen admission");
    }
}

#[cfg(test)]
mod transferred_admission_tests {
    use super::*;
    use crate::desktop::login_custody::CredentialWrites;
    #[tokio::test]
    async fn transferred_update_owner_never_recloses_and_safe_refusal_releases() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().unwrap();
        assert_eq!(
            gate.close_for_quit().err().as_deref(),
            Some("desktop_update_quiescence_held")
        );
        let owner = Admission::Update {
            lease: Some(lease),
            unknown: false,
        };
        owner.wait().await.unwrap();
        owner.reopen().unwrap();
        assert!(gate.admit().is_ok());
    }
    #[test]
    fn unknown_install_outcome_cannot_release_transferred_owner() {
        let gate = CredentialWrites::default();
        let owner = Admission::Update {
            lease: Some(gate.begin_update().unwrap()),
            unknown: true,
        };
        assert_eq!(owner.reopen().unwrap_err(), "desktop_update_unverified");
        assert!(gate.update_unverified_for_test());
        assert!(gate.admit().is_err());
        assert!(gate.close_for_quit().is_ok());
    }
}
