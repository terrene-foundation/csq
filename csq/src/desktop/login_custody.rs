//! One process-lifetime admission/drain and exact-child index for desktop work.
//! S1 credential_writes must re-export this module when the lanes reconcile.
use crate::login_child_custody::{
    group::{GroupControl, GroupSignal, GroupStopDecision},
    LoginWatchdog,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
};
use tauri::Manager;
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum LoginProvider {
    Claude,
    Codex,
    Kimi,
    Grok,
}
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct ChildKey {
    provider: LoginProvider,
    account: u16,
}
impl ChildKey {
    pub(crate) fn new(provider: LoginProvider, account: csq_core::types::AccountNum) -> Self {
        Self {
            provider,
            account: account.get(),
        }
    }
}
type RegisteredChildSlot = Arc<Mutex<Option<(Arc<Mutex<std::process::Child>>, GroupControl)>>>;
struct ChildEntry {
    operation_id: String,
    identity: Arc<()>,
    child: RegisteredChildSlot,
    watchdog: LoginWatchdog,
    publication: Arc<Mutex<Publication>>,
    quarantine: Arc<Mutex<Option<String>>>,
}
#[derive(Default)]
struct Publication {
    sealed: bool,
    cancelled: bool,
    committed: bool,
}
pub(crate) const COMMITTED_CANCELLED: &str =
    "login_committed_cancelled: account was signed in before cancellation";
/// The user-facing admission refusal after an unverified installer outcome.
/// This string reaches the renderer, so it NEVER carries the raw tag.
pub(crate) const RESTART_FOR_UPDATE_MESSAGE: &str =
    "Restart csq to finish the update before signing in.";
pub(crate) fn validate_operation_id(operation_id: &str) -> Result<(), String> {
    if operation_id.is_empty()
        || operation_id.len() > 128
        || !operation_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("login_operation_id_invalid".into());
    }
    Ok(())
}
#[derive(Default)]
struct State {
    active: usize,
    closed: Option<Arc<()>>,
    /// The identity a live `UpdateLease` owns. A drain built over it can never
    /// reopen admission; only the lease itself settles it (`release`).
    lease_identity: Option<Arc<()>>,
    /// S1's sign-in registry: advisory metadata the Windows Quit UI reads.
    signins: Vec<Weak<Signin>>,
    /// S1's cancellable browser waits; `close` flips every live flag.
    interactive: Vec<Weak<AtomicBool>>,
    children: HashMap<ChildKey, ChildEntry>,
    next_operation: u64,
    exit_pending: bool,
    /// Set with `exit_pending` by `UpdateProbe::authorize_restart`: the pending
    /// exit is the updater's OWN approved restart intent, so an ExitRequested
    /// that arrives before the lease drops rides it instead of deferring.
    restart_exit: bool,
    update_pending: bool,
    /// STICKY, process-lifetime: the installer ran but its completion is
    /// unverified (KeepClosed, an early error, or a panic). Every admission,
    /// Quit close and drain reopen refuses until the process exits.
    update_unverified: bool,
    exit_verified: bool,
    exit_code: i32,
}
#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    changed: Notify,
    #[cfg(any(windows, test))]
    signin_listener: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
#[derive(Clone, Default)]
pub(crate) struct CredentialWrites {
    inner: Arc<Inner>,
}
#[must_use = "move this permit into every actual writer"]
pub(crate) struct WritePermit {
    inner: Arc<Inner>,
}
#[must_use = "actual drain completion is required before exit"]
pub(crate) struct Drain {
    inner: Arc<Inner>,
    identity: Arc<()>,
}
/// S1's credential-write names live here now: one gate covers sign-in custody
/// and every other credential writer, so a Quit drain cannot miss a login
/// running on the other module's singleton.
#[derive(Clone, Copy)]
pub(crate) enum SigninProvider {
    Claude,
    Codex,
    Kimi,
    Grok,
    Gemini,
}
#[derive(Clone)]
#[cfg_attr(not(any(windows, test)), allow(dead_code))] // Read by the Windows Quit UI.
pub(crate) struct Signin {
    pub(crate) provider: &'static str,
    pub(crate) account: u16,
}
#[must_use = "move this registration into the actual login worker"]
pub(crate) struct SigninRegistration {
    signin: Option<Arc<Signin>>,
    #[cfg(any(windows, test))]
    inner: Weak<Inner>,
}
impl Drop for SigninRegistration {
    fn drop(&mut self) {
        // Remove the registration before notifying: callbacks see the real
        // post-drop set, and no credential/admission mutex is held here.
        self.signin.take();
        #[cfg(any(windows, test))]
        if let Some(inner) = self.inner.upgrade() {
            let listener = inner
                .signin_listener
                .lock()
                .ok()
                .and_then(|slot| slot.clone());
            if let Some(listener) = listener {
                listener();
            }
        }
    }
}

/// A browser wait is cancellable until admission is acquired atomically with
/// close. It still counts as outstanding cleanup, so Quit cannot exit before
/// its worker has released the account login lock and closed its listener.
#[must_use = "move this registration into the interactive worker"]
pub(crate) struct InteractiveLogin {
    cleanup: WritePermit,
    cancelled: Arc<AtomicBool>,
}
impl InteractiveLogin {
    pub(crate) fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
    /// This is the mint fence. No cancellation is honored after this succeeds.
    /// Keep this registration alive until worker cleanup (including lock release)
    /// finishes; its separate count also covers errors before admission.
    pub(crate) fn admit(&self) -> Result<WritePermit, String> {
        let inner = Arc::clone(&self.cleanup.inner);
        {
            let mut state = inner
                .state
                .lock()
                .map_err(|_| "credential_write_gate_poisoned".to_string())?;
            if state.update_unverified {
                return Err(RESTART_FOR_UPDATE_MESSAGE.to_string());
            }
            if state.closed.is_some() || self.cancelled.load(Ordering::Acquire) {
                return Err("credential_write_admission_closed".to_string());
            }
            state.active = state
                .active
                .checked_add(1)
                .ok_or_else(|| "credential_write_capacity_exhausted".to_string())?;
            state.interactive.retain(|entry| {
                entry
                    .upgrade()
                    .is_some_and(|flag| !Arc::ptr_eq(&flag, &self.cancelled))
            });
        }
        Ok(WritePermit { inner })
    }
}
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct PendingLogin {
    pub(crate) operation_id: String,
    pub(crate) provider: String,
    pub(crate) account: u16,
    pub(crate) native_id: Option<String>,
}
pub(crate) struct ChildRegistration {
    inner: Arc<Inner>,
    key: ChildKey,
    identity: Arc<()>,
    child: RegisteredChildSlot,
    publication: Arc<Mutex<Publication>>,
    quarantine: Arc<Mutex<Option<String>>>,
}
fn unresolved_cancel_message(binding: &Mutex<Option<String>>) -> String {
    let suffix = binding.lock().ok().and_then(|message| message.clone());
    match suffix {
        Some(message) => format!("login_group_custody_unresolved: {message}"),
        None => "login_group_custody_unresolved: quarantine path unavailable".into(),
    }
}
impl ChildRegistration {
    /// Bind once from this actual grant before spawn; never accept renderer paths.
    pub(crate) fn bind_quarantine(
        &self,
        grant: &csq_core::accounts::credential_transaction::VendorLoginGrant,
    ) -> Result<(), String> {
        let message = csq_core::cli_deps::sanitize::redact_display(grant.quarantine_message());
        let mut bound = self
            .quarantine
            .lock()
            .map_err(|_| "login_quarantine_binding_poisoned")?;
        if bound.is_some() {
            return Err("login_quarantine_already_bound".into());
        }
        *bound = Some(message);
        Ok(())
    }
    /// Infallible attachment: reserve every fallible registry field BEFORE spawn.
    pub(crate) fn attach(&self, child: Arc<Mutex<std::process::Child>>, group: GroupControl) {
        *self.child.lock().unwrap_or_else(|e| e.into_inner()) = Some((child, group));
        self.inner.changed.notify_waiters();
    }
    pub(crate) fn seal_publication(&self) -> anyhow::Result<()> {
        let mut state = self
            .publication
            .lock()
            .map_err(|_| anyhow::anyhow!("login_publication_state_poisoned"))?;
        if state.cancelled {
            anyhow::bail!("login_cancelled_refused: publication cancelled before commit");
        }
        state.sealed = true;
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn cancellation_received(&self) -> bool {
        self.publication.lock().is_ok_and(|state| state.cancelled)
    }
    pub(crate) fn mark_committed(&self) -> Result<(), String> {
        let mut state = self
            .publication
            .lock()
            .map_err(|_| "login_publication_state_poisoned")?;
        if !state.sealed {
            return Err("login_publication_unsealed".into());
        }
        state.committed = true;
        if state.cancelled {
            return Err(COMMITTED_CANCELLED.into());
        }
        Ok(())
    }
}
pub(crate) fn global() -> &'static CredentialWrites {
    static WRITES: OnceLock<CredentialWrites> = OnceLock::new();
    WRITES.get_or_init(CredentialWrites::default)
}
/// Verdict of `CredentialWrites::force_deadline_for_test`.
#[cfg(all(test, unix, feature = "test-utils"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadlineForce {
    /// No operation is registered under the key.
    Absent,
    /// The registry lock was poisoned; the operation could not be looked up.
    RegistryPoisoned,
    /// The operation was found; the inner value says whether the latch was taken.
    Forced(crate::login_child_custody::ForcedDeadline),
}

impl CredentialWrites {
    #[cfg(any(windows, test))]
    pub(crate) fn set_signin_listener(
        &self,
        listener: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        *self
            .inner
            .signin_listener
            .lock()
            .map_err(|_| "credential_signin_listener_poisoned".to_string())? = Some(listener);
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn authorize_windows_exit(&self) -> Result<(), String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned")?;
        if state.closed.is_none()
            || state.update_pending
            || state.active != 0
            || !state.children.is_empty()
        {
            return Err("desktop_exit_custody_unverified".into());
        }
        state.exit_verified = true;
        Ok(())
    }
    pub(crate) fn admit(&self) -> Result<WritePermit, String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned")?;
        if state.update_unverified {
            // USER-FACING: never the raw tag; this string reaches the renderer.
            tracing::warn!(
                error_kind = "desktop_update_unverified",
                "sign-in admission refused until restart"
            );
            return Err(RESTART_FOR_UPDATE_MESSAGE.into());
        }
        if state.closed.is_some() {
            return Err("credential_write_admission_closed".into());
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or("credential_write_capacity_exhausted")?;
        Ok(WritePermit {
            inner: Arc::clone(&self.inner),
        })
    }
    /// S1's sign-in marker: advisory metadata for the Windows Quit UI. It is
    /// not an admission; the worker's own permit is what Quit waits on.
    pub(crate) fn register_signin(
        &self,
        provider: SigninProvider,
        account: csq_core::types::AccountNum,
    ) -> Result<SigninRegistration, String> {
        let provider = match provider {
            SigninProvider::Claude => "Claude",
            SigninProvider::Codex => "Codex",
            SigninProvider::Kimi => "Kimi",
            SigninProvider::Grok => "Grok",
            SigninProvider::Gemini => "Gemini",
        };
        let signin = Arc::new(Signin {
            provider,
            account: account.get(),
        });
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned".to_string())?;
        state.signins.retain(|entry| entry.strong_count() != 0);
        state.signins.push(Arc::downgrade(&signin));
        Ok(SigninRegistration {
            signin: Some(signin),
            #[cfg(any(windows, test))]
            inner: Arc::downgrade(&self.inner),
        })
    }
    #[cfg(any(windows, test))]
    pub(crate) fn active_signins(&self) -> Result<Vec<Signin>, String> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned".to_string())?;
        Ok(state
            .signins
            .iter()
            .filter_map(Weak::upgrade)
            .map(|signin| (*signin).clone())
            .collect())
    }
    /// A cancellable browser wait still counts as outstanding cleanup, so Quit
    /// cannot exit before its worker has released the login lock.
    pub(crate) fn register_interactive(&self) -> Result<InteractiveLogin, String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned".to_string())?;
        if state.update_unverified {
            // USER-FACING: this string can reach the renderer; never the tag.
            return Err(RESTART_FOR_UPDATE_MESSAGE.to_string());
        }
        if state.closed.is_some() {
            return Err("credential_write_admission_closed".to_string());
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| "credential_write_capacity_exhausted".to_string())?;
        let cancelled = Arc::new(AtomicBool::new(false));
        state.interactive.retain(|entry| entry.strong_count() != 0);
        state.interactive.push(Arc::downgrade(&cancelled));
        Ok(InteractiveLogin {
            cleanup: WritePermit {
                inner: Arc::clone(&self.inner),
            },
            cancelled,
        })
    }
    pub(crate) fn spawn_with_ticket<F, Fut>(
        &self,
        operation: F,
    ) -> Result<tokio::task::JoinHandle<Fut::Output>, String>
    where
        F: FnOnce(Arc<WritePermit>) -> Fut + Send + 'static,
        Fut: std::future::Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let permit = Arc::new(self.admit()?);
        Ok(tokio::spawn(async move { operation(permit).await }))
    }
    fn spawn_blocking_with_ticket<F, T>(
        &self,
        body: F,
    ) -> Result<tokio::task::JoinHandle<T>, String>
    where
        F: FnOnce(Arc<WritePermit>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = Arc::new(self.admit()?);
        Ok(tokio::task::spawn_blocking(move || body(permit)))
    }
    #[cfg(test)]
    pub(crate) fn spawn<F>(
        &self,
        operation: F,
    ) -> Result<tokio::task::JoinHandle<F::Output>, String>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.spawn_with_ticket(|permit| async move {
            let _permit = permit;
            operation.await
        })
    }
    pub(crate) fn spawn_blocking<F, T>(&self, body: F) -> Result<tokio::task::JoinHandle<T>, String>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.spawn_blocking_with_ticket(move |permit| {
            let _permit = permit;
            body()
        })
    }
    /// Close admission and cancel every live browser wait. This is S1's
    /// production close: failure to join the returned drain is refusal, never
    /// permission, and `Drain::reopen` is the only way back. Windows Quit owns
    /// the production caller; unix exits through `request_exit`, which closes
    /// admission under its own exit-intent state.
    ///
    /// A live exit owner OR a live updater lease keeps its own identity: a
    /// second closer never supersedes the drain that owner is waiting on, and
    /// `Drain::reopen` refuses until the lease itself releases.
    /// Test-only since the Windows Quit uses `close_for_quit` (the one route
    /// that must refuse under an update): no production caller remains.
    #[cfg(test)]
    pub(crate) fn close(&self) -> Drain {
        let drain = {
            let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            self.close_locked(&mut state)
        };
        self.inner.changed.notify_waiters();
        drain
    }
    /// Close admission under an ALREADY-HELD gate lock. `close_for_quit` uses
    /// it so its update refusal and the close are ONE critical section: a
    /// `begin_update` cannot slip in between the check and the close.
    fn close_locked(&self, state: &mut State) -> Drain {
        let identity = if state.exit_pending || state.update_pending {
            state.closed.clone().unwrap_or_else(|| Arc::new(()))
        } else {
            let identity = Arc::new(());
            state.closed = Some(Arc::clone(&identity));
            identity
        };
        for flag in state.interactive.iter().filter_map(Weak::upgrade) {
            flag.store(true, Ordering::Release);
        }
        Drain {
            inner: Arc::clone(&self.inner),
            identity,
        }
    }
    /// Windows Quit's admission close. REFUSES while the updater owns sign-in
    /// quiescence — exactly like `request_exit` — so a Quit cannot abort a
    /// verified update in flight. On refusal nothing mutates.
    ///
    /// An UNVERIFIED installer outcome does NOT refuse the Quit: admission is
    /// already closed, so the Quit drains nothing and must reach exit (a user
    /// must never be left unable to quit). The safety lives in `Drain::reopen`,
    /// `admit`, `reserve_child` and `begin_update`, which keep refusing.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn close_for_quit(&self) -> Result<Drain, String> {
        let drain = {
            let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.update_pending {
                tracing::warn!(
                    error_kind = "desktop_update_quiescence_held",
                    "Quit refused while the updater owns sign-in quiescence"
                );
                return Err("desktop_update_quiescence_held".into());
            }
            self.close_locked(&mut state)
        };
        self.inner.changed.notify_waiters();
        Ok(drain)
    }
    /// Reservation owns identity and cancellation reachability before any child exists.
    pub(crate) fn reserve_child(
        &self,
        key: ChildKey,
        watchdog: LoginWatchdog,
    ) -> Result<Arc<ChildRegistration>, String> {
        let identity = Arc::new(());
        let child = Arc::new(Mutex::new(None));
        let publication = Arc::new(Mutex::new(Publication::default()));
        let quarantine = Arc::new(Mutex::new(None));
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned")?;
        if state.update_unverified {
            return Err("desktop_update_unverified".into());
        }
        if state.closed.is_some() {
            return Err("credential_write_admission_closed".into());
        }
        if state.children.contains_key(&key) {
            return Err("login_child_already_registered".into());
        }
        state.next_operation = state
            .next_operation
            .checked_add(1)
            .ok_or("login_operation_identity_exhausted")?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "login_operation_identity_unavailable")?
            .as_nanos();
        let operation_id = format!(
            "login-{}-{stamp:032x}-{:016x}",
            std::process::id(),
            state.next_operation
        );
        state.children.insert(
            key,
            ChildEntry {
                operation_id,
                identity: Arc::clone(&identity),
                child: Arc::clone(&child),
                watchdog,
                publication: Arc::clone(&publication),
                quarantine: Arc::clone(&quarantine),
            },
        );
        Ok(Arc::new(ChildRegistration {
            inner: Arc::clone(&self.inner),
            key,
            identity,
            child,
            publication,
            quarantine,
        }))
    }
    pub(crate) fn pending_logins(&self) -> Result<Vec<PendingLogin>, String> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned")?;
        Ok(state
            .children
            .iter()
            .map(|(key, entry)| {
                let (provider, native_id) = match key.provider {
                    LoginProvider::Claude => ("claude", None),
                    LoginProvider::Codex => ("codex", None),
                    LoginProvider::Kimi => ("native", Some("kimi-cli")),
                    LoginProvider::Grok => ("native", Some("grok")),
                };
                PendingLogin {
                    operation_id: entry.operation_id.clone(),
                    provider: provider.into(),
                    account: key.account,
                    native_id: native_id.map(str::to_owned),
                }
            })
            .collect())
    }
    pub(crate) async fn cancel_child_with_confirmation<F, Fut>(
        &self,
        key: ChildKey,
        operation_id: &str,
        confirmed: bool,
        confirm: F,
    ) -> Result<bool, String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<bool, String>>,
    {
        if !confirmed {
            return Err("login_cancel_confirmation_required".into());
        }
        validate_operation_id(operation_id)?;
        let target = {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| "credential_write_gate_poisoned")?;
            match state.children.get(&key) {
                Some(entry) if entry.operation_id == operation_id => Some((
                    Arc::clone(&entry.identity),
                    Arc::clone(&entry.child),
                    entry.watchdog.clone(),
                    Arc::clone(&entry.publication),
                    Arc::clone(&entry.quarantine),
                )),
                Some(_) => return Err("login_cancel_target_changed".into()),
                None => None,
            }
        };
        let Some((identity, child, watchdog, publication, quarantine)) = target else {
            return Ok(false);
        };
        // This callback is backend-owned native consent in production. The
        // renderer bool is request intent only. Tests inject explicit choice.
        if !confirm().await? {
            return Ok(false);
        }
        {
            let state = self
                .inner
                .state
                .lock()
                .map_err(|_| "credential_write_gate_poisoned")?;
            if !state
                .children
                .get(&key)
                .is_some_and(|entry| Arc::ptr_eq(&entry.identity, &identity))
            {
                return Err("login_cancel_target_changed".into());
            }
        }
        let before_publication = {
            let mut state = publication
                .lock()
                .map_err(|_| "login_publication_state_poisoned")?;
            state.cancelled = true;
            !state.sealed
        };
        if before_publication {
            let _ = watchdog.refuse_cancelled();
            if watchdog.custody_unresolved() {
                return Err(unresolved_cancel_message(&quarantine));
            }
        }
        let mut stopped = !before_publication;
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !stopped {
                let group = child
                    .lock()
                    .map_err(|_| "login_child_state_poisoned")?
                    .as_ref()
                    .map(|(_, group)| group.clone());
                if let Some(group) = group {
                    match group.request_stop_or_finalized(GroupSignal::Kill) {
                        Ok(GroupStopDecision::StopRequested) => {}
                        Ok(GroupStopDecision::VendorFinalized(receipt)) => {
                            if !receipt.belongs_to(&group) {
                                return Err(unresolved_cancel_message(&quarantine));
                            }
                        }
                        Err(_) => return Err(unresolved_cancel_message(&quarantine)),
                    }
                    // Neither decision retires the operation. Keep waiting for
                    // its exact registration and publication guard to finish.
                    stopped = true;
                }
            }
            {
                let state = self
                    .inner
                    .state
                    .lock()
                    .map_err(|_| "credential_write_gate_poisoned")?;
                if !state
                    .children
                    .get(&key)
                    .is_some_and(|entry| Arc::ptr_eq(&entry.identity, &identity))
                {
                    let publication = publication
                        .lock()
                        .map_err(|_| "login_publication_state_poisoned")?;
                    return if publication.committed {
                        Err(COMMITTED_CANCELLED.into())
                    } else {
                        Ok(true)
                    };
                }
            }
            // Actual unresolved custody may be recorded after the initial stop.
            // Refuse this observer promptly while the owner retains K and index.
            if watchdog.custody_unresolved() {
                return Err(unresolved_cancel_message(&quarantine));
            }
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {},
            }
        }
    }
    pub(crate) async fn cancel_provider_with_confirmation<F, Fut>(
        &self,
        provider: LoginProvider,
        operation_id: &str,
        confirmed: bool,
        confirm: F,
    ) -> Result<bool, String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<bool, String>>,
    {
        if !confirmed {
            return Err("login_cancel_confirmation_required".into());
        }
        validate_operation_id(operation_id)?;
        let keys: Vec<_> = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned")?
            .children
            .iter()
            .filter(|(key, entry)| key.provider == provider && entry.operation_id == operation_id)
            .map(|(key, _)| *key)
            .collect();
        match keys.as_slice() {
            [] => Err("login_cancel_target_changed".into()),
            [key] => {
                self.cancel_child_with_confirmation(*key, operation_id, true, confirm)
                    .await
            }
            _ => Err("login_cancel_target_ambiguous".into()),
        }
    }
    pub(crate) fn exit_verified(&self) -> bool {
        self.inner.state.lock().is_ok_and(|state| {
            state.exit_verified && state.active == 0 && state.children.is_empty()
        })
    }
    #[cfg(test)]
    pub(crate) fn update_pending_for_test(&self) -> bool {
        self.inner
            .state
            .lock()
            .is_ok_and(|state| state.update_pending)
    }
    #[cfg(test)]
    pub(crate) fn update_unverified_for_test(&self) -> bool {
        self.inner
            .state
            .lock()
            .is_ok_and(|state| state.update_unverified)
    }
    #[cfg(all(test, unix, feature = "test-utils"))]
    pub(crate) fn publication_cancelled_for_test(&self, key: &ChildKey) -> bool {
        self.inner
            .state
            .lock()
            .ok()
            .and_then(|state| {
                state.children.get(key).map(|entry| {
                    entry
                        .publication
                        .lock()
                        .is_ok_and(|publication| publication.cancelled)
                })
            })
            .unwrap_or(false)
    }
    /// Test-only: declare the registered operation's deadline reached now.
    /// Absent, a poisoned registry lock and an already-finished operation are
    /// three distinct verdicts, never folded into one.
    #[cfg(all(test, unix, feature = "test-utils"))]
    pub(crate) fn force_deadline_for_test(&self, key: &ChildKey) -> DeadlineForce {
        let watchdog = match self.inner.state.lock() {
            Ok(state) => state.children.get(key).map(|entry| entry.watchdog.clone()),
            Err(_) => return DeadlineForce::RegistryPoisoned,
        };
        match watchdog {
            Some(watchdog) => DeadlineForce::Forced(watchdog.force_deadline_for_test()),
            None => DeadlineForce::Absent,
        }
    }
    #[cfg(test)]
    pub(crate) fn registered_child_for_test(
        &self,
        key: &ChildKey,
    ) -> Option<Arc<Mutex<std::process::Child>>> {
        self.inner
            .state
            .lock()
            .ok()?
            .children
            .get(key)
            .and_then(|entry| {
                entry
                    .child
                    .lock()
                    .ok()?
                    .as_ref()
                    .map(|(child, _)| Arc::clone(child))
            })
    }
    #[cfg(all(test, unix))]
    pub(crate) fn registered_observation_for_test(
        &self,
        key: &ChildKey,
    ) -> Option<(GroupControl, LoginWatchdog)> {
        let state = self.inner.state.lock().ok()?;
        let entry = state.children.get(key)?;
        let child = entry.child.lock().ok()?;
        let (_, group) = child.as_ref()?;
        Some((group.clone(), entry.watchdog.clone()))
    }
}
pub(crate) struct ChildCustody<K> {
    _keepalive: K,
    registration: Arc<ChildRegistration>,
}
impl<K> ChildCustody<K> {
    pub(crate) fn new(keepalive: K, registration: Arc<ChildRegistration>) -> Self {
        Self {
            _keepalive: keepalive,
            registration,
        }
    }
    pub(crate) fn attach(&self, child: Arc<Mutex<std::process::Child>>, group: GroupControl) {
        self.registration.attach(child, group);
    }
}
/// A failed/superseded exit attempt ends its pending state and remains closed.
/// A later explicit Exit request can retry the actual drain without reopening writers.
fn refuse_exit(gate: &CredentialWrites) {
    let mut state = gate.inner.state.lock().unwrap_or_else(|e| e.into_inner());
    state.exit_pending = false;
    state.exit_verified = false;
    gate.inner.changed.notify_waiters();
}
/// Durable updater lease. Only a VERIFIED outcome settles the quiescence flag:
/// an explicit `release()` (the update did not restart) and the `Ok(true)`
/// restart handoff. EVERY other exit — KeepClosed, a `ready()`/`wait()` error
/// via `?`, or a panic — leaves the gate STICKY-closed (`update_unverified`)
/// until process exit, because the installer's completion is unverified.
/// Admission, reservation, a new update and `Drain::reopen` keep refusing; a
/// Quit is still ADMITTED (it only drains the already-closed gate), so a user
/// is never trapped in the app. Admission stays closed through a restart
/// (process replacement).
pub(crate) struct UpdateLease {
    drain: Drain,
    settled: bool,
}

/// Readiness probe handed to the production sequencing body. It re-checks
/// quiescence under the gate lock immediately before install and before
/// request_restart without moving the lease out of the drainer.
#[derive(Clone)]
pub(crate) struct UpdateProbe {
    inner: Arc<Inner>,
    identity: Arc<()>,
}

impl UpdateProbe {
    pub(crate) fn ready(&self) -> Result<bool, String> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned".to_string())?;
        if !state
            .closed
            .as_ref()
            .is_some_and(|id| Arc::ptr_eq(id, &self.identity))
        {
            return Err("desktop_update_lease_superseded".into());
        }
        if state.update_unverified {
            return Err("desktop_update_unverified".into());
        }
        Ok(state.active == 0 && state.children.is_empty())
    }
    /// Immediately before `request_restart`, under ONE gate lock: convert the
    /// lease into an approved EXIT INTENT — identity kept, `exit_pending`
    /// raised, `update_pending` cleared, admission still closed. An
    /// ExitRequested that arrives before the lease drops then rides this
    /// intent instead of being deferred.
    pub(crate) fn authorize_restart(&self) -> Result<(), String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned".to_string())?;
        if !state
            .closed
            .as_ref()
            .is_some_and(|id| Arc::ptr_eq(id, &self.identity))
        {
            return Err("desktop_update_lease_superseded".into());
        }
        if state.update_unverified {
            return Err("desktop_update_unverified".into());
        }
        if state.active != 0 || !state.children.is_empty() {
            return Err("update_quiescence_not_drained".into());
        }
        state.exit_pending = true;
        state.restart_exit = true;
        state.update_pending = false;
        self.inner.changed.notify_waiters();
        Ok(())
    }
}
pub(crate) fn begin_update() -> Result<UpdateLease, String> {
    global().begin_update()
}
/// Windows Quit routing over the gate's refusal: maps to the fixed tag
/// `refused` logs. An unverified installer outcome is NOT a refusal — the
/// Quit is admitted — so the only remaining refusal is a live update lease.
/// Exercised directly on every platform; Windows Quit calls it in production.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub(crate) fn close_for_quit_tag(gate: &CredentialWrites) -> Result<Drain, &'static str> {
    gate.close_for_quit()
        .map_err(|_| "desktop_update_quiescence_held")
}
impl CredentialWrites {
    pub(crate) fn begin_update(&self) -> Result<UpdateLease, String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned")?;
        if state.update_unverified {
            return Err("desktop_update_unverified".into());
        }
        if state.exit_pending || state.closed.is_some() {
            return Err("desktop_quiescence_conflict".into());
        }
        let identity = Arc::new(());
        state.closed = Some(Arc::clone(&identity));
        state.lease_identity = Some(Arc::clone(&identity));
        state.update_pending = true;
        self.inner.changed.notify_waiters();
        Ok(UpdateLease {
            drain: Drain {
                inner: Arc::clone(&self.inner),
                identity,
            },
            settled: false,
        })
    }
}

impl UpdateLease {
    pub(crate) fn ready(&self) -> Result<bool, String> {
        self.probe().ready()
    }
    pub(crate) fn probe(&self) -> UpdateProbe {
        UpdateProbe {
            inner: Arc::clone(&self.drain.inner),
            identity: Arc::clone(&self.drain.identity),
        }
    }
    pub(crate) async fn wait(&self) -> Result<(), String> {
        self.drain.wait().await
    }
    /// Only the actual Windows install worker may authorize this handoff. A
    /// return or unwind revokes exit proof without settling the live lease.
    #[cfg(any(windows, test))]
    pub(crate) fn with_install_exit<T>(&self, install: impl FnOnce() -> T) -> Result<T, String> {
        let probe = self.probe();
        {
            let mut state = probe
                .inner
                .state
                .lock()
                .map_err(|_| "credential_write_gate_poisoned")?;
            if !state
                .closed
                .as_ref()
                .is_some_and(|id| Arc::ptr_eq(id, &probe.identity))
                || state.update_unverified
                || !state.update_pending
                || state.active != 0
                || !state.children.is_empty()
            {
                return Err("desktop_exit_custody_unverified".into());
            }
            state.exit_verified = true;
        }
        struct Revoke(UpdateProbe);
        impl Drop for Revoke {
            fn drop(&mut self) {
                let mut state = self.0.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                if state
                    .closed
                    .as_ref()
                    .is_some_and(|id| Arc::ptr_eq(id, &self.0.identity))
                {
                    state.exit_verified = false;
                }
            }
        }
        let _revoke = Revoke(probe);
        Ok(install())
    }
    /// Explicit non-restart completion (VERIFIED): settle OUR flag and lease
    /// identity, then reopen admission.
    pub(crate) fn release(mut self) -> Result<(), String> {
        self.settle_verified(true);
        self.drain.reopen()
    }
    /// The `Ok(true)` restart handoff (VERIFIED): the flag is cleared as a
    /// verified outcome; admission stays closed and the lease identity is
    /// retained, because the process is being replaced.
    pub(crate) fn hand_off_restart(mut self) {
        self.settle_verified(false);
    }
    /// Clears only the state THIS lease owns. `reopenable` also drops the lease
    /// identity so `Drain::reopen` may proceed; `settled` makes Drop a no-op.
    fn settle_verified(&mut self, reopenable: bool) {
        {
            let mut state = self
                .drain
                .inner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if state
                .closed
                .as_ref()
                .is_some_and(|id| Arc::ptr_eq(id, &self.drain.identity))
            {
                state.update_pending = false;
                if reopenable {
                    state.lease_identity = None;
                }
            }
        }
        self.settled = true;
        self.drain.inner.changed.notify_waiters();
    }
}
impl Drop for UpdateLease {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        // UNVERIFIED outcome — KeepClosed, an early `?` error, or a panic. The
        // installer may have run with unknown completion, so admission stays
        // closed for the rest of the process: a STICKY refusal that only
        // process exit clears.
        {
            let mut state = self
                .drain
                .inner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if state
                .closed
                .as_ref()
                .is_some_and(|id| Arc::ptr_eq(id, &self.drain.identity))
            {
                state.update_pending = false;
                state.update_unverified = true;
            }
        }
        self.drain.inner.changed.notify_waiters();
    }
}
impl Drain {
    pub(crate) async fn wait(&self) -> Result<(), String> {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self
                    .inner
                    .state
                    .lock()
                    .map_err(|_| "credential_write_gate_poisoned")?;
                if !state
                    .closed
                    .as_ref()
                    .is_some_and(|id| Arc::ptr_eq(id, &self.identity))
                {
                    return Err("credential_write_drain_superseded".into());
                }
                if state.active == 0 && state.children.is_empty() {
                    return Ok(());
                }
            }
            changed.await;
        }
    }
    /// Refusal is the ONLY reopen path. It refuses while an exit intent is
    /// pending and while a live updater lease owns quiescence: only that lease
    /// releases its own flag, so a Quit drain's refused close can never reopen
    /// admission under an update.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn reopen(&self) -> Result<(), String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned")?;
        if state.exit_pending {
            return Err("desktop_exit_intent_pending".into());
        }
        if state.update_pending {
            return Err("desktop_update_quiescence_held".into());
        }
        if state.update_unverified {
            return Err("desktop_update_unverified".into());
        }
        if state
            .lease_identity
            .as_ref()
            .is_some_and(|id| Arc::ptr_eq(id, &self.identity))
        {
            // A non-lease drain can never reopen an identity the updater owns;
            // after the lease drops for an unverified reason the sticky state
            // above refuses first, and only `release()` clears this one.
            return Err("desktop_update_lease_retained".into());
        }
        if !state
            .closed
            .as_ref()
            .is_some_and(|id| Arc::ptr_eq(id, &self.identity))
        {
            return Err("credential_write_drain_superseded".into());
        }
        state.closed = None;
        self.inner.changed.notify_waiters();
        Ok(())
    }
    /// S1 can use this SAME final authorization after its supervisor join.
    pub(crate) fn authorize_exit(&self) -> Result<i32, String> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| "credential_write_gate_poisoned")?;
        if !state
            .closed
            .as_ref()
            .is_some_and(|id| Arc::ptr_eq(id, &self.identity))
            || state.active != 0
            || !state.children.is_empty()
        {
            return Err("desktop_exit_custody_unverified".into());
        }
        state.exit_verified = true;
        Ok(state.exit_code)
    }
}
impl Drop for WritePermit {
    fn drop(&mut self) {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active -= 1;
        self.inner.changed.notify_waiters();
    }
}
impl Drop for ChildRegistration {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state
            .children
            .get(&self.key)
            .is_some_and(|entry| Arc::ptr_eq(&entry.identity, &self.identity))
        {
            state.children.remove(&self.key);
        }
        self.inner.changed.notify_waiters();
    }
}
/// Keep the window hide reversible through the existing tray Show action.
/// Cancellation commands bypass admission and remain accessible while draining.
pub(super) fn request_exit<R: tauri::Runtime>(app: &tauri::AppHandle<R>, code: i32) {
    let final_app = app.clone();
    request_exit_with_finalizer(app, code, move |code| final_app.exit(code));
}
/// One gate lock decides an exit request. A fresh request claims a new intent;
/// the updater's pending RESTART intent is treated as approved and ridden to
/// completion; a different in-flight exit is neither duplicated nor deferred.
enum ExitBegin {
    Drain(Drain),
    Verified,
    Pending,
    Deferred,
    Poisoned,
}
fn begin_exit(gate: &CredentialWrites, code: i32) -> ExitBegin {
    let mut state = match gate.inner.state.lock() {
        Ok(state) => state,
        Err(_) => return ExitBegin::Poisoned,
    };
    if state.exit_verified {
        return ExitBegin::Verified;
    }
    if state.update_pending {
        tracing::warn!(
            error_kind = "desktop_update_quiescence_held",
            "Exit deferred while the updater owns sign-in quiescence"
        );
        return ExitBegin::Deferred;
    }
    state.exit_code = code;
    if state.exit_pending {
        if !state.restart_exit {
            return ExitBegin::Pending;
        }
        // The updater recorded its approved restart intent BEFORE calling
        // request_restart; this ExitRequested arrived first and rides that
        // same identity to a verified exit instead of deferring.
        state.restart_exit = false;
        return match state.closed.clone() {
            Some(identity) => ExitBegin::Drain(Drain {
                inner: Arc::clone(&gate.inner),
                identity,
            }),
            None => ExitBegin::Pending,
        };
    }
    state.exit_pending = true;
    let identity = Arc::new(());
    state.closed = Some(Arc::clone(&identity));
    ExitBegin::Drain(Drain {
        inner: Arc::clone(&gate.inner),
        identity,
    })
}
pub(crate) fn request_exit_with_finalizer<R: tauri::Runtime, F>(
    app: &tauri::AppHandle<R>,
    code: i32,
    finalizer: F,
) where
    F: FnOnce(i32) + Send + 'static,
{
    let gate = global();
    let drain = match begin_exit(gate, code) {
        ExitBegin::Drain(drain) => drain,
        ExitBegin::Verified | ExitBegin::Pending | ExitBegin::Deferred => return,
        ExitBegin::Poisoned => {
            tracing::error!(
                error_kind = "desktop_exit_state_poisoned",
                "desktop exit refused"
            );
            return;
        }
    };
    if let Some(window) = app.get_webview_window("main") {
        if window.hide().is_err() {
            tracing::warn!(
                error_kind = "desktop_exit_hide_failed",
                "desktop remains visible while finishing sign-in"
            );
        }
    }
    tauri::async_runtime::spawn(async move {
        match drain.wait().await.and_then(|()| drain.authorize_exit()) {
            Ok(code) => finalizer(code),
            Err(_) => {
                refuse_exit(global());
                tracing::error!(
                    error_kind = "desktop_exit_drain_refused",
                    "desktop stays running; retry Exit after resolving sign-in custody"
                );
            }
        }
    });
}

#[cfg(test)]
mod r2_gate_tests {
    use super::*;
    #[test]
    fn failed_exit_clears_pending_intent_without_reopening_writers() {
        let gate = CredentialWrites::default();
        let permit = gate.admit().unwrap();
        {
            let mut state = gate.inner.state.lock().unwrap();
            state.exit_pending = true;
            state.closed = Some(Arc::new(()));
        }
        refuse_exit(&gate);
        assert!(
            !gate.inner.state.lock().unwrap().exit_pending,
            "failed Exit drain must become retryable rather than stay pending"
        );
        assert!(
            gate.admit().is_err(),
            "Exit failure must not reopen writers with actual custody live"
        );
        drop(permit);
    }

    /// ROOT M1 correction (liveness): an unverified outcome (KeepClosed, an
    /// early error, a panic) keeps admission closed and un-reopenable, but a
    /// Quit is ADMITTED and reaches its drain so a user is never trapped. The
    /// admit refusal is the fixed user-facing message, never the raw tag.
    #[tokio::test]
    async fn unverified_lease_drop_admits_a_quit_but_never_reopens_admission() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("lease");
        drop(lease);
        assert!(gate.update_unverified_for_test());
        let admission = gate
            .close_for_quit()
            .expect("a Quit must be admitted after an unverified update");
        admission
            .wait()
            .await
            .expect("the closed gate drains empty");
        assert_eq!(admission.reopen().unwrap_err(), "desktop_update_unverified");
        assert_eq!(
            gate.admit().err().as_deref(),
            Some(RESTART_FOR_UPDATE_MESSAGE),
            "the admission refusal must be the actionable message, never the tag"
        );
    }

    /// R2 item 1 + 6(a): the Windows Quit routing refuses ONLY a live update
    /// lease; an unverified outcome admits the Quit.
    #[tokio::test]
    async fn quit_close_routes_only_a_live_lease_to_a_refusal() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("lease");
        assert_eq!(
            close_for_quit_tag(&gate).err(),
            Some("desktop_update_quiescence_held")
        );
        drop(lease);
        let admission = close_for_quit_tag(&gate).expect("unverified outcome admits the Quit");
        admission.wait().await.expect("drains empty");
        assert!(gate.admit().is_err(), "the Quit drain reopened admission");
    }

    /// R2 item 3: the update refusal and the close are one critical section, so
    /// begin_update cannot slip in between them in either order.
    #[test]
    fn close_for_quit_and_begin_update_are_mutually_exclusive() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("update first");
        assert_eq!(
            gate.close_for_quit().err().as_deref(),
            Some("desktop_update_quiescence_held")
        );
        lease.release().expect("explicit verified release");
        let drain = gate.close_for_quit().expect("close first");
        assert_eq!(
            gate.begin_update().err().as_deref(),
            Some("desktop_quiescence_conflict")
        );
        assert!(gate.admit().is_err(), "the close must own admission");
        drop(drain);
    }

    /// R2 item 4: a drain built over the updater's identity can never reopen
    /// it; only the lease itself settles its identity.
    #[test]
    fn a_non_lease_drain_can_never_reopen_a_lease_identity() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("lease");
        let drain = gate.close();
        {
            let mut state = gate.inner.state.lock().unwrap();
            state.update_pending = false; // a settled lease that still owns its identity
        }
        assert_eq!(drain.reopen().unwrap_err(), "desktop_update_lease_retained");
        assert!(
            gate.admit().is_err(),
            "a non-lease reopen cleared admission"
        );
        lease.release().expect("the lease settles its own identity");
        assert!(gate.admit().is_ok(), "release must reopen admission");
    }

    /// R2 item 2: ExitRequested arriving BEFORE the lease drops rides the
    /// updater's approved restart intent: not deferred, admission stays closed.
    #[tokio::test]
    async fn restart_intent_is_approved_before_the_lease_drops() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("lease");
        let probe = lease.probe();
        probe.authorize_restart().expect("drained restart intent");
        assert!(
            !gate.update_pending_for_test(),
            "UPDATE_RESTART_STRANDED_QUIESCENCE"
        );
        let drain = match begin_exit(&gate, 0) {
            ExitBegin::Drain(drain) => drain,
            _ => panic!("UPDATE_RESTART_EXIT_DEFERRED"),
        };
        assert!(gate.admit().is_err(), "restart intent reopened admission");
        drain.wait().await.expect("already drained");
        assert_eq!(drain.authorize_exit().expect("approved restart intent"), 0);
        assert!(gate.exit_verified());
        lease.hand_off_restart();
        assert!(gate.admit().is_err(), "handoff reopened admission");
        assert!(
            !gate.update_unverified_for_test(),
            "a verified handoff must not go sticky"
        );
    }

    /// R2 item 6: both probe checks abort once the outcome is unverified.
    #[test]
    fn probe_checks_abort_after_an_unverified_outcome() {
        let gate = CredentialWrites::default();
        let lease = gate.begin_update().expect("lease");
        let probe = lease.probe();
        assert!(probe.ready().expect("live probe"));
        drop(lease);
        assert_eq!(probe.ready().unwrap_err(), "desktop_update_unverified");
        assert_eq!(
            probe.authorize_restart().unwrap_err(),
            "desktop_update_unverified"
        );
    }
}

#[cfg(test)]
mod windows_install_custody_tests {
    use super::*;
    use std::future::Future;
    #[tokio::test]
    async fn install_authorization_waits_for_writer_and_registered_child() {
        let gate = CredentialWrites::default();
        let writer = gate.admit().unwrap();
        let account = csq_core::types::AccountNum::try_from(7u16).unwrap();
        let child = gate
            .reserve_child(
                ChildKey::new(LoginProvider::Claude, account),
                LoginWatchdog::new(
                    std::time::Duration::from_secs(60),
                    crate::login_child_custody::DeliveryPhase::Unknown,
                ),
            )
            .unwrap();
        let lease = gate.begin_update().unwrap();
        {
            let wait = lease.wait();
            tokio::pin!(wait);
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(
                    wait.as_mut().poll(cx).is_pending()
                ))
                .await
            );
            assert!(lease
                .with_install_exit(|| panic!("INSTALL_RAN_WITH_WRITER_AND_CHILD"))
                .is_err());
            drop(writer);
            assert!(!lease.ready().unwrap());
            assert!(lease
                .with_install_exit(|| panic!("INSTALL_RAN_WITH_CHILD"))
                .is_err());
            drop(child);
            wait.await.unwrap();
        }
        lease
            .with_install_exit(|| assert!(gate.exit_verified()))
            .unwrap();
        assert!(!gate.exit_verified());
        assert!(gate.update_pending_for_test());
        drop(lease);
        assert!(gate.update_unverified_for_test());
    }
    #[test]
    fn actual_install_error_and_unwind_revoke_canonical_exit_without_releasing() {
        for panic in [false, true] {
            let gate = CredentialWrites::default();
            let lease = gate.begin_update().unwrap();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                lease.with_install_exit(|| {
                    assert!(gate.exit_verified());
                    if panic {
                        panic!("inert installer panic");
                    }
                    Err::<(), ()>(())
                })
            }));
            assert_eq!(outcome.is_err(), panic);
            assert!(!gate.exit_verified());
            assert!(gate.update_pending_for_test());
            drop(lease);
            assert!(gate.update_unverified_for_test());
            assert!(gate.close_for_quit().is_ok());
            assert!(gate.admit().is_err());
        }
    }
}
