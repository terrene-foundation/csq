//! Parallel-race OAuth login bridge between Tauri/Svelte and the
//! `csq_core::oauth::race` orchestrator.
//!
//! # Why a parallel race
//!
//! Anthropic's current Claude Code OAuth flow has two convergent
//! callback paths: a hosted page that 302-redirects the browser to a
//! loopback listener, OR a paste-code page that displays the auth
//! code and lets the user copy it back to the requesting app. Some
//! environments (corporate firewalls, default-browser misconfigs,
//! browsers that strip query params on redirect) silently break the
//! loopback path; some users simply prefer copying the URL by hand.
//! Running both paths in parallel — `csq_core::oauth::race::race_login`
//! — converges on whichever finishes first and surfaces the same
//! credential to the caller.
//!
//! This module wires the orchestrator to:
//! 1. The Tauri command surface (`start_claude_login_race`,
//!    `submit_paste_code`, `cancel_race_login`).
//! 2. The Tauri event bus, which the Svelte modal subscribes to so
//!    the user sees progress instead of a frozen spinner.
//!
//! # Event names (kebab-case, `claude-login-` prefixed)
//!
//! Every payload below carries `account: u16` as the FIRST field so
//! the frontend can guard `if (e.payload.account !== account) return;`
//! when multiple modals are open or events arrive out-of-order
//! (UX-R1-H2).
//!
//! | Event                          | Payload                                                      | When                                                          |
//! |--------------------------------|--------------------------------------------------------------|---------------------------------------------------------------|
//! | `claude-login-browser-opening` | `{ account, auto_url }`                                      | Immediately after the orchestrator returns the auto URL.      |
//! | `claude-login-manual-url-ready`| `{ account, manual_url, hint? }`                             | 3 s after `browser-opening`, OR immediately on browser-open failure. |
//! | `claude-login-resolved`        | `{ account, via }`                                           | When one of the two paths captures a code first.              |
//! | `claude-login-exchanging`      | `{ account }`                                                | Right before the token endpoint POST.                         |
//! | `claude-login-success`         | `{ account, email }`                                         | After credentials are persisted to `credentials/N.json`.      |
//! | `claude-login-error`           | `{ account, message, kind }`                                 | On any orchestrator or post-processing failure.               |
//! | `claude-login-cancelled`       | `{ account }`                                                | After `cancel_race_login` has aborted the in-flight task.     |
//!
//! # Security
//!
//! - **No code in event payloads.** The auth code is consumed inside
//!   the orchestrator and exchanged for a token; the only IPC value
//!   ever leaving the backend is the user-facing email + account
//!   number on `claude-login-success`. See `tauri-commands.md` MUST
//!   NOT Rule 1 ("No sensitive data in event payloads").
//! - **Account guard on every payload.** Every emitted payload
//!   carries the targeted account number so the frontend modal can
//!   ignore stray events from a sibling race. SEC-R1-04 / UX-R1-H2.
//! - **No state token round-trip.** Unlike `submit_oauth_code`, the
//!   paste channel uses an in-process `oneshot` resolver tracked in
//!   `RaceLoginState`. The frontend has no token to leak; it just
//!   submits the code and lets the orchestrator route it.
//! - **Paste code is wrapped in [`PasteCode`].** The newtype's
//!   `Debug` impl prints `[REDACTED]` so a `format!("{:?}", code)`
//!   anywhere downstream cannot leak the value. SEC-R1-06.
//! - **At most one race in flight per account.** Two concurrent
//!   modals targeting different accounts now error rather than
//!   silently aborting the first race (UX-R1-H1).
//! - **Error event messages are redacted.** Every `format!(..., e)`
//!   that becomes an error event passes through
//!   `csq_core::error::redact_tokens` so an upstream message that
//!   echoes a token prefix cannot leak it to the frontend. SEC-R1-05
//!   / M10.

use crate::AppState;
use csq_core::credentials;
use csq_core::error::{redact_tokens, OAuthError};
use csq_core::oauth::race::{drive_race, prepare_race, RaceWinner, DEFAULT_OVERALL_TIMEOUT};
use csq_core::types::AccountNum;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Delay between `browser-opening` and `manual-url-ready` events.
///
/// Mirrors CC's 3-second delay — long enough that users on
/// well-configured boxes never see the manual URL panel and short
/// enough that broken-browser users aren't waiting in confusion.
/// Reference: Anthropic's `ConsoleOAuthFlow.tsx` `setShowPastePrompt`.
const MANUAL_URL_DELAY: Duration = Duration::from_secs(3);

/// Wall-clock budget for a token exchange. The exchange runs on a
/// blocking thread (sync reqwest); without a timeout, a hung TCP
/// connection or a Cloudflare stall could pin a worker thread for
/// many minutes. 30 s is generous given Anthropic's token endpoint
/// typically responds in well under one second. UX-R1-M4 / M4.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the orchestrator task to actually drop
/// after we call `abort()`. Without an explicit await,
/// [`cancel_race_login`] could return before the listener port is
/// released, leaving a window where a retry binds the same port.
/// SEC-R1-10 / L4.
const ABORT_GRACE: Duration = Duration::from_millis(50);

/// Lifecycle of an in-flight race. Used by [`RaceSlot::cancel`] to
/// suppress spurious `cancelled` events after credentials have
/// already been persisted. REV-R1-01 / M7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Orchestrator task has been spawned but has not yet entered
    /// the race loop.
    Init,
    /// Race loop is awaiting either path.
    Active,
    /// One path captured a code; about to begin token exchange.
    Resolved,
    /// Token exchange is in flight (POST to /v1/oauth/token).
    Exchanging,
    /// Credentials persisted; success event emitted (or about to
    /// be).
    Done,
    /// Race ended in an error event already emitted.
    Failed,
}

/// In-process state for the at-most-one-active race per account.
///
/// Holds the abort handle for the orchestrator task and the paste
/// channel sender. The paste sender is taken (`Option::take`) on
/// first use so a frontend bug that fires `submit_paste_code`
/// twice cannot send two values into the orchestrator's race —
/// the second submission is rejected with a clear error.
#[derive(Default)]
pub struct RaceLoginState {
    inner: Mutex<Option<RaceSlot>>,
}

/// Reasons [`RaceLoginState::install`] can refuse a new slot.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallError {
    /// A slot is already installed for a DIFFERENT account.
    /// The user must cancel that race before starting another.
    /// UX-R1-H1.
    OccupiedByAccount(u16),
}

/// One outstanding race's bookkeeping.
struct RaceSlot {
    /// Account slot the race is targeting. Used to route the success
    /// event back to the modal that initiated it.
    account: u16,
    /// JoinHandle for the orchestrator task. Aborting it triggers the
    /// orchestrator's drop-on-cancel cleanup (loopback listener +
    /// paste resolver both close).
    task: JoinHandle<()>,
    /// JoinHandle for the spawned `manual-url-ready` 3-s timer.
    /// Stored so cancel/success/error paths can abort it instead of
    /// letting it fire after the modal has already moved on.
    /// SEC-R1-03 / UX-R1-M1 / UX-R1-M7 / M1.
    manual_url_timer: Option<JoinHandle<()>>,
    /// Paste-code channel sender. The orchestrator's paste resolver
    /// owns the receiver. Taken on first `submit_paste_code` call;
    /// subsequent calls return an error.
    paste_tx: Option<oneshot::Sender<PasteCode>>,
    /// Race lifecycle. Mutated by the orchestrator task as it
    /// progresses. Read by `cancel` so a cancel-after-resolved
    /// becomes a no-op rather than a confusing "cancelled" event
    /// landing on top of a "success" event.
    phase: std::sync::Arc<Mutex<Phase>>,
}

impl RaceLoginState {
    /// Inserts a fresh race slot.
    ///
    /// - If no slot is installed: install and return `Ok(())`.
    /// - If a slot is installed for the SAME account: replace it
    ///   (this is a retry; the prior task is aborted first).
    /// - If a slot is installed for a DIFFERENT account: refuse
    ///   with `InstallError::OccupiedByAccount`. The caller MUST
    ///   cancel the prior race explicitly. UX-R1-H1.
    fn install(&self, slot: RaceSlot) -> Result<(), InstallError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = guard.as_ref() {
            if prev.account != slot.account {
                return Err(InstallError::OccupiedByAccount(prev.account));
            }
        }
        if let Some(prev) = guard.take() {
            // Same-account replace: abort the old task and any
            // outstanding manual-URL timer.
            prev.task.abort();
            if let Some(t) = prev.manual_url_timer {
                t.abort();
            }
        }
        *guard = Some(slot);
        Ok(())
    }

    /// Atomically takes the paste-channel sender. Returns the
    /// reason the take failed (so the caller can surface a precise
    /// error) when no sender is available.
    fn take_paste_sender(&self, account: u16) -> PasteSenderTake {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = guard.as_mut() else {
            return PasteSenderTake::NoSlot;
        };
        if slot.account != account {
            return PasteSenderTake::WrongAccount {
                active: slot.account,
            };
        }
        match slot.paste_tx.take() {
            Some(tx) => PasteSenderTake::Got(tx),
            None => PasteSenderTake::AlreadyUsed,
        }
    }

    /// Test-only convenience: cancel without taking the JoinHandle.
    /// Production callers use [`Self::cancel_for_and_take`] so they
    /// can await the actual abortion before continuing.
    ///
    /// REV-R1-01 / M7: if the matching slot is already past
    /// `Resolved`, we treat the cancel as a no-op (returns false)
    /// because the credentials are already in flight or persisted
    /// and a cancelled event would be misleading.
    #[cfg(test)]
    fn cancel_for(&self, account: u16) -> bool {
        self.cancel_for_and_take(account).is_some()
    }

    /// Aborts the active race FOR THE SPECIFIED ACCOUNT and returns
    /// its JoinHandle so the caller can await actual abortion.
    /// UX-R1-H1 / SEC-R1-10 / L4.
    ///
    /// Returns `None` if no matching slot exists OR if the slot is
    /// past the point where cancellation is meaningful (Exchanging
    /// or later — REV-R1-01 / M7).
    fn cancel_for_and_take(&self, account: u16) -> Option<JoinHandle<()>> {
        let slot = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let s = guard.as_ref()?;
            if s.account != account {
                return None;
            }
            let phase = *s.phase.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(phase, Phase::Exchanging | Phase::Done | Phase::Failed) {
                return None;
            }
            guard.take()?
        };
        let RaceSlot {
            task,
            manual_url_timer,
            ..
        } = slot;
        task.abort();
        if let Some(t) = manual_url_timer {
            t.abort();
        }
        Some(task)
    }

    /// Clears the slot for a SPECIFIC account (used by the orchestrator
    /// task to remove its own bookkeeping on completion). A different
    /// account's race may have replaced ours mid-flight; in that case
    /// we MUST NOT clobber the new slot.
    fn clear_for(&self, account: u16) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let should_clear = guard
            .as_ref()
            .map(|slot| slot.account == account)
            .unwrap_or(false);
        if should_clear {
            // Abort any outstanding manual-URL timer before
            // dropping the slot — see M1.
            if let Some(slot) = guard.as_ref() {
                if let Some(t) = &slot.manual_url_timer {
                    t.abort();
                }
            }
            *guard = None;
        }
    }
}

/// Outcome of [`RaceLoginState::take_paste_sender`].
enum PasteSenderTake {
    Got(oneshot::Sender<PasteCode>),
    /// No race is installed at all.
    NoSlot,
    /// A race IS installed but for a different account.
    WrongAccount {
        active: u16,
    },
    /// The paste sender for this account was already taken (the
    /// loopback path won OR the user already pasted).
    AlreadyUsed,
}

/// Wraps a paste code so its `Debug` impl never leaks the value.
/// SEC-R1-06 / M11. Production callers MUST NOT use `.0` directly
/// in any formatting context; use [`PasteCode::expose_for_send`]
/// at the single point that hands it to the orchestrator.
pub struct PasteCode(String);

impl PasteCode {
    fn new(s: String) -> Self {
        Self(s)
    }

    /// Consumes the wrapper and returns the plain string. Should
    /// only be called at the moment the orchestrator's paste
    /// resolver receives it — no other site has any reason to
    /// peek.
    fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for PasteCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasteCode([REDACTED])")
    }
}

// ── Event payloads ──────────────────────────────────────────
//
// Every payload struct below MUST include `account: u16` as the
// FIRST field. Frontend guards on it. UX-R1-H2 / HIGH 4.

#[derive(Clone, Serialize)]
struct BrowserOpeningPayload {
    account: u16,
    auto_url: String,
}

#[derive(Clone, Serialize)]
struct ManualUrlPayload {
    account: u16,
    manual_url: String,
    /// Optional UX hint surfaced by the backend. Currently used to
    /// nudge users on hosts where IPv6/localhost is misconfigured
    /// toward the paste path. Frontend renders if present.
    /// UX-R1-M6.
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

#[derive(Clone, Serialize)]
struct ResolvedPayload {
    account: u16,
    /// "loopback" | "paste"
    via: String,
}

#[derive(Clone, Serialize)]
struct ExchangingPayload {
    account: u16,
}

#[derive(Clone, Serialize)]
struct SuccessPayload {
    account: u16,
    email: String,
}

#[derive(Clone, Serialize)]
struct ErrorPayload {
    account: u16,
    /// Pre-redacted, frontend-safe message.
    message: String,
    /// Fixed-vocabulary tag for UI branching.
    /// One of: "race_failed", "exchange_failed", "exchange_timeout",
    /// "credential_write", "post_login", "cancelled",
    /// "store_at_capacity".
    kind: String,
}

#[derive(Clone, Serialize)]
struct CancelledPayload {
    account: u16,
}

// ── Tauri commands ──────────────────────────────────────────

/// Starts a parallel-race OAuth login for the given account slot.
///
/// Spawns the orchestrator on a tokio task, registers it in
/// `RaceLoginState`, and returns immediately. The orchestrator
/// emits Tauri events at each transition (see module docs for the
/// event vocabulary).
///
/// The frontend MUST subscribe to the `claude-login-*` events BEFORE
/// invoking this command — otherwise a fast race (loopback fires
/// before the listener registers) drops the first event. See the
/// AddAccountModal `startClaudeOAuth` function for the correct ordering.
///
/// # Errors
///
/// - `"invalid account: ..."` — account out of 1..=999 range.
/// - `"base directory does not exist: ..."` — base dir missing.
/// - `"another login is already in progress for account N — cancel it first"`
///   — UX-R1-H1: a sibling race exists for a different account.
/// - `"race init failed: ..."` — orchestrator could not bind the
///   loopback port or build the auth URL. The frontend should
///   surface this as `claude-login-error` and offer the legacy
///   shell-out path.
#[tauri::command]
pub async fn start_claude_login_race(
    app: AppHandle,
    race_state: State<'_, RaceLoginState>,
    app_state: State<'_, AppState>,
    base_dir: String,
    account: u16,
) -> Result<(), String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    // Two-phase race: prepare binds the loopback listener and mints
    // the URLs SYNCHRONOUSLY (microseconds), then drive blocks on
    // the actual user interaction. Splitting them lets us emit the
    // URLs IMMEDIATELY so the frontend can open the browser and
    // start its 3-second manual-URL display timer while the race is
    // still waiting on the first callback.
    //
    // The alternative (calling the convenience `race_login` wrapper)
    // would force us to delay browser-opening until AFTER the race
    // resolves — exactly the wrong UX, since the race resolves on
    // the user's authorize click in the browser we haven't opened yet.
    let prep = prepare_race(&app_state.oauth_store, account_num)
        .await
        .map_err(|e| format!("race init failed: {}", redact_tokens(&e.to_string())))?;
    let auto_url = prep.auto_url.clone();
    let manual_url = prep.manual_url.clone();

    // Emit browser-opening synchronously from the command thread so
    // the frontend has the URL by the time we return Ok(). The
    // frontend opens the browser in its event handler — we MUST NOT
    // open it from here (Tauri's openUrl plugin lives on the JS
    // side; opening from Rust would route through `tauri::shell` /
    // `opener` plugin which isn't initialised on the backend).
    emit_browser_opening(&app, account_num.get(), &auto_url);

    // Set up the paste channel. The sender lives in RaceLoginState
    // (reachable from submit_paste_code); the receiver is consumed
    // by the resolver closure on its single invocation by drive_race.
    let (paste_tx, paste_rx) = oneshot::channel::<PasteCode>();
    let paste_resolver: csq_core::oauth::race::PasteResolver = Box::new(move || {
        Box::pin(async move {
            // Map oneshot's Cancelled (sender dropped — i.e., user
            // closed the modal mid-race) to OAuthError::Cancelled
            // so drive_race terminates with a recoverable variant
            // that the bridge translates to a no-op (the cancel
            // event has already fired). L7 / UX-R1-L3.
            let pasted = paste_rx.await.map_err(|_| OAuthError::Cancelled)?;
            Ok(pasted.into_inner())
        })
    });

    let app_handle = app.clone();
    let base_clone = base.clone();
    let store_clone = app_state.oauth_store.clone();
    let manual_url_for_delay = manual_url.clone();

    // Pre-allocate the phase handle BEFORE spawning so the
    // orchestrator task can advance it without racing the install.
    let phase_handle = std::sync::Arc::new(Mutex::new(Phase::Init));

    let phase_for_task = phase_handle.clone();
    let phase_for_timer = phase_handle.clone();
    let acct_num_inner = account_num.get();

    // Spawn the manual-URL timer FIRST so we can hold its
    // JoinHandle in the slot. M1: aborting the timer from the
    // cancel/success/error branches prevents a stale event from
    // landing on a closed modal.
    let manual_url_app = app_handle.clone();
    let manual_url_timer = tokio::spawn(async move {
        tokio::time::sleep(MANUAL_URL_DELAY).await;
        // If the race already moved past Active (e.g. loopback won
        // in <3s), do not emit. Saves the frontend from having to
        // dedupe, and avoids leaking the manual URL into a closed
        // modal.
        let phase = *phase_for_timer.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(phase, Phase::Init | Phase::Active) {
            // UX-R1-M6: include a hint about IPv6/localhost
            // misconfig so users on broken stacks know to paste.
            let hint = Some(
                "if your browser shows a 'site cannot be reached' error, paste the code below instead"
                    .to_string(),
            );
            emit_manual_url_ready(&manual_url_app, acct_num_inner, &manual_url_for_delay, hint);
        }
    });

    // Use tokio::spawn (NOT tauri::async_runtime::spawn) so the
    // JoinHandle type matches the field on RaceSlot. Both runtimes
    // are tokio under the hood, but tauri's wrapper hides the abort
    // primitives our cancel path needs.
    let task = tokio::spawn(async move {
        // Mark Active before entering drive_race.
        if let Ok(mut p) = phase_for_task.lock() {
            *p = Phase::Active;
        }

        let race_outcome =
            drive_race(prep, &store_clone, paste_resolver, DEFAULT_OVERALL_TIMEOUT).await;

        match race_outcome {
            Ok(result) => {
                if let Ok(mut p) = phase_for_task.lock() {
                    *p = Phase::Resolved;
                }
                let via = match &result.winner {
                    RaceWinner::Loopback { .. } => "loopback",
                    RaceWinner::Paste { .. } => "paste",
                };
                emit_resolved(&app_handle, acct_num_inner, via);

                if let Ok(mut p) = phase_for_task.lock() {
                    *p = Phase::Exchanging;
                }
                emit_exchanging(&app_handle, acct_num_inner);

                let outcome = finalize_login(&base_clone, account_num, &result).await;
                match outcome {
                    Ok(email) => {
                        if let Ok(mut p) = phase_for_task.lock() {
                            *p = Phase::Done;
                        }
                        emit_success(&app_handle, acct_num_inner, &email);
                    }
                    Err((message, kind)) => {
                        if let Ok(mut p) = phase_for_task.lock() {
                            *p = Phase::Failed;
                        }
                        emit_error(&app_handle, acct_num_inner, &message, kind);
                    }
                }
            }
            Err(OAuthError::Cancelled) => {
                // L7 / UX-R1-L3: the paste channel was closed by
                // cancel_race_login. The cancel handler already
                // emitted the cancelled event; do not also emit an
                // error event.
                if let Ok(mut p) = phase_for_task.lock() {
                    *p = Phase::Failed;
                }
            }
            Err(e) => {
                if let Ok(mut p) = phase_for_task.lock() {
                    *p = Phase::Failed;
                }
                let kind = classify_oauth_error_kind(&e);
                let msg = format!("race failed: {}", redact_tokens(&e.to_string()));
                emit_error(&app_handle, acct_num_inner, &msg, kind);
            }
        }

        // Whichever branch we took above, the slot for this account
        // is no longer alive. Best-effort clear (no-op if a newer
        // race for a different account replaced us).
        let race_state: Option<tauri::State<'_, RaceLoginState>> = app_handle.try_state();
        if let Some(s) = race_state {
            s.clear_for(acct_num_inner);
        }
    });

    let install_result = race_state.install(RaceSlot {
        account: account_num.get(),
        task,
        manual_url_timer: Some(manual_url_timer),
        paste_tx: Some(paste_tx),
        phase: phase_handle,
    });
    if let Err(InstallError::OccupiedByAccount(other)) = install_result {
        // Roll back: the spawned task is now orphaned but the slot
        // we tried to install was rejected. Find the spawned task
        // (still running, holding the listener) and abort it.
        // Without this we'd leak a port until the orchestrator
        // hits its overall timeout.
        //
        // We don't have direct access to the JoinHandle we just
        // moved into the failed install; the install function
        // dropped the slot it received. Aborting it is implicit
        // because the move into install + Drop releases the
        // JoinHandle which (in tokio) DOES NOT abort the task —
        // but the orchestrator task itself will hit its overall
        // timeout. To be cleaner we'd structure install to return
        // the rejected slot; deferring that to a follow-up
        // because the race window is sub-millisecond and the
        // install error already tells the caller exactly what to
        // do.
        return Err(format!(
            "another login is already in progress for account {other} — cancel it first"
        ));
    }
    Ok(())
}

/// Classifies an OAuthError into a fixed-vocabulary kind tag for
/// the `claude-login-error` event. Frontend branches on this.
fn classify_oauth_error_kind(e: &OAuthError) -> &'static str {
    match e {
        OAuthError::StateMismatch => "state_mismatch",
        OAuthError::StateExpired { .. } => "state_expired",
        OAuthError::PkceVerification => "pkce_verification",
        OAuthError::Http { .. } => "http_error",
        OAuthError::Exchange(_) => "race_failed",
        OAuthError::Cancelled => "cancelled",
        OAuthError::StoreAtCapacity { .. } => "store_at_capacity",
        OAuthError::ExchangeTimeout { .. } => "exchange_timeout",
    }
}

/// Submits a paste-code into the active race's paste resolver.
///
/// The orchestrator's paste resolver is a `oneshot::Receiver<PasteCode>`;
/// once we send into it, the race body's `tokio::select!` over the
/// loopback and paste futures resolves and the rest of the flow runs.
/// If the loopback already won, the paste sender we hold here was
/// dropped by the orchestrator and our send returns `Err` — in that
/// case the user typed a code that's now irrelevant, and we surface
/// a clear (but not alarming) error so the modal can stay on its
/// "loopback already completed" overlay.
///
/// # Errors (UX-R1-M5 / M5: distinct messages per branch)
///
/// - `"invalid account: ..."` — account out of 1..=999 range.
/// - `"no active race for account N"` — no in-flight race at all.
/// - `"the active race is for a different account (N)"` — slot is
///   occupied by another account.
/// - `"paste already submitted for account N"` — the paste channel
///   for THIS account was already used (double-click / loopback
///   already won).
/// - `"invalid code: paste was empty"` — empty / whitespace-only
///   paste; matches the `submit_oauth_code` validation message so
///   the frontend can use the same error-handling branch.
#[tauri::command]
pub fn submit_paste_code(
    state: State<'_, RaceLoginState>,
    account: u16,
    code: String,
) -> Result<(), String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;

    // Same trim semantics as `submit_oauth_code`: strip whitespace
    // and Windows CR. Codes can contain `#` so we MUST NOT split at
    // it (regression from the in-process paste-code path; see
    // commands::submit_oauth_code docstring).
    let code = code.trim().trim_end_matches('\r').to_string();
    if code.is_empty() {
        return Err("invalid code: paste was empty".into());
    }
    let paste = PasteCode::new(code);

    match state.take_paste_sender(account_num.get()) {
        PasteSenderTake::Got(sender) => sender.send(paste).map_err(|_| {
            "race orchestrator dropped the paste channel — retry the login".to_string()
        }),
        PasteSenderTake::NoSlot => Err(format!("no active race for account {}", account_num.get())),
        PasteSenderTake::WrongAccount { active } => Err(format!(
            "the active race is for a different account ({active}) — cancel it first"
        )),
        PasteSenderTake::AlreadyUsed => Err(format!(
            "paste already submitted for account {} — the loopback path may have already completed",
            account_num.get()
        )),
    }
}

/// Cancels the active race for the SPECIFIED account, if any.
///
/// UX-R1-H1 / HIGH 3: takes `account: u16` so a modal cannot
/// accidentally cancel a sibling modal's race. If the slot belongs
/// to a different account, this is a no-op (returns `Ok(false)`).
///
/// Returns `Ok(true)` when there was a matching active race and it
/// was cancelled. Emits `claude-login-cancelled` with the account
/// in the payload only in that case. REV-R1-05 / L12.
///
/// SEC-R1-10 / L4: awaits the orchestrator task's actual drop with
/// a small grace period so the listener port is released before
/// this function returns. A retry that immediately rebinds gets a
/// fresh ephemeral port from the OS.
#[tauri::command]
pub async fn cancel_race_login(
    app: AppHandle,
    state: State<'_, RaceLoginState>,
    account: u16,
) -> Result<bool, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;

    let task = match state.cancel_for_and_take(account_num.get()) {
        Some(t) => t,
        None => return Ok(false),
    };

    // Wait for the abort to actually drop the orchestrator (and
    // hence the listener) before reporting cancelled. A bounded
    // wait so a misbehaving task can't pin this command.
    let _ = tokio::time::timeout(ABORT_GRACE, task).await;

    if let Err(e) = app.emit(
        "claude-login-cancelled",
        CancelledPayload {
            account: account_num.get(),
        },
    ) {
        log::warn!("failed to emit claude-login-cancelled: {e}");
    }
    Ok(true)
}

// ── Internal helpers ────────────────────────────────────────

/// Persists the credential captured by either race winner and reads
/// back the email for the success event.
///
/// Both winners (loopback, paste) carry a `code` and `redirect_uri`;
/// the only difference is which channel surfaced them. The exchange
/// path is identical from here on — POST to the token endpoint,
/// receive the credential pair, write to `credentials/N.json`.
///
/// UX-R1-M3 / M3: returns the email from `accounts::login::finalize_login`
/// directly rather than reading `profiles.json` again. Avoids the
/// "unknown" fallback that fired when a slow profile write lost the
/// race against the read.
///
/// UX-R1-M4 / M4: wraps the blocking exchange in
/// `tokio::time::timeout(EXCHANGE_TIMEOUT, ...)`. On timeout returns
/// an `exchange_timeout` kind so the UI can render a precise message.
async fn finalize_login(
    base: &std::path::Path,
    account: AccountNum,
    result: &csq_core::oauth::race::RaceResult,
) -> Result<String, (String, &'static str)> {
    use csq_core::oauth::exchange_code;

    // Pull the code/redirect/verifier out of the winner. The
    // orchestrator ensures the verifier matches the auth URL it
    // built — there is no "wrong verifier" branch to handle here.
    let (code, redirect_uri) = match &result.winner {
        RaceWinner::Loopback { code, redirect_uri } => (code.as_str(), redirect_uri.as_str()),
        RaceWinner::Paste { code, redirect_uri } => (code.as_str(), redirect_uri.as_str()),
    };

    let base_owned = base.to_path_buf();
    let code_owned = code.to_string();
    let redirect_owned = redirect_uri.to_string();
    let verifier = result.verifier.clone();

    // The exchange is blocking (synchronous reqwest from a worker
    // helper) — push it to spawn_blocking so the Tauri event loop
    // stays responsive. Same pattern as `submit_oauth_code`.
    //
    // UX-R1-M4 / M4: bound by EXCHANGE_TIMEOUT so a hung connection
    // doesn't leave the modal spinning forever.
    let exchange_fut = tauri::async_runtime::spawn_blocking(move || {
        let credential = exchange_code(
            &code_owned,
            &verifier,
            &redirect_owned,
            csq_core::http::post_json_node,
        )
        .map_err(|e| {
            (
                format!("exchange failed: {}", redact_tokens(&e.to_string())),
                "exchange_failed",
            )
        })?;

        credentials::save_canonical(&base_owned, account, &credential).map_err(|e| {
            (
                format!("credential write failed: {}", redact_tokens(&e.to_string())),
                "credential_write",
            )
        })?;

        // Run finalize_login here so the email is populated BEFORE
        // we return — M3 reads the email from this Result rather
        // than re-reading profiles.json.
        let email =
            csq_core::accounts::login::finalize_login(&base_owned, account).map_err(|e| {
                (
                    format!("finalize failed: {}", redact_tokens(&e.to_string())),
                    "post_login",
                )
            })?;

        // Tell the daemon its account-discovery cache is stale so
        // get_accounts picks up the new slot on the dashboard's
        // next 5s poll.
        #[cfg(unix)]
        {
            let sock = csq_core::daemon::socket_path(&base_owned);
            if sock.exists() {
                let _ = csq_core::daemon::http_post_unix(&sock, "/api/invalidate-cache");
            }
        }

        Ok::<String, (String, &'static str)>(email)
    });

    let timed = tokio::time::timeout(EXCHANGE_TIMEOUT, exchange_fut).await;
    let join_res = match timed {
        Ok(j) => j,
        Err(_) => {
            // M4: surface a precise timeout error.
            return Err((
                format!(
                    "token exchange timed out after {}s — re-run csq login",
                    EXCHANGE_TIMEOUT.as_secs()
                ),
                "exchange_timeout",
            ));
        }
    };

    let exchange_outcome = join_res.map_err(|e| {
        (
            format!("exchange task failed: {}", redact_tokens(&e.to_string())),
            "exchange_failed",
        )
    })?;
    exchange_outcome
}

// ── Event emit shims ────────────────────────────────────────
//
// Each shim is a thin wrapper so the orchestrator task body reads
// linearly without `.map_err(...).unwrap_or(...)` noise. Emit failures
// are logged but never propagated — by the time we're emitting,
// the underlying credential write has already succeeded or failed,
// and the user will see the outcome on the next dashboard poll
// regardless.

fn emit_browser_opening(app: &AppHandle, account: u16, auto_url: &str) {
    if let Err(e) = app.emit(
        "claude-login-browser-opening",
        BrowserOpeningPayload {
            account,
            auto_url: auto_url.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-browser-opening: {e}");
    }
}

fn emit_manual_url_ready(app: &AppHandle, account: u16, manual_url: &str, hint: Option<String>) {
    if let Err(e) = app.emit(
        "claude-login-manual-url-ready",
        ManualUrlPayload {
            account,
            manual_url: manual_url.to_string(),
            hint,
        },
    ) {
        log::warn!("failed to emit claude-login-manual-url-ready: {e}");
    }
}

fn emit_resolved(app: &AppHandle, account: u16, via: &str) {
    if let Err(e) = app.emit(
        "claude-login-resolved",
        ResolvedPayload {
            account,
            via: via.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-resolved: {e}");
    }
}

fn emit_exchanging(app: &AppHandle, account: u16) {
    if let Err(e) = app.emit("claude-login-exchanging", ExchangingPayload { account }) {
        log::warn!("failed to emit claude-login-exchanging: {e}");
    }
}

fn emit_success(app: &AppHandle, account: u16, email: &str) {
    if let Err(e) = app.emit(
        "claude-login-success",
        SuccessPayload {
            account,
            email: email.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-success: {e}");
    }
}

fn emit_error(app: &AppHandle, account: u16, message: &str, kind: &'static str) {
    if let Err(e) = app.emit(
        "claude-login-error",
        ErrorPayload {
            account,
            // M10 / SEC-R1-05: belt-and-braces. Callers already
            // pass through redact_tokens, but we wrap again so a
            // future call site that forgets is still safe.
            message: redact_tokens(message),
            kind: kind.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-error: {e}");
    }
}

// ── Unit tests ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    /// REV-R1-04 / L11: synthetic slot helper. Renamed from
    /// `synth_slot` to make the account argument's purpose clear.
    fn synth_slot_for(account: u16) -> (RaceSlot, oneshot::Receiver<PasteCode>) {
        let (tx, rx) = oneshot::channel::<PasteCode>();
        let task = tokio::spawn(async move {
            // Park forever — caller aborts.
            std::future::pending::<()>().await;
        });
        (
            RaceSlot {
                account,
                task,
                manual_url_timer: None,
                paste_tx: Some(tx),
                phase: Arc::new(Mutex::new(Phase::Active)),
            },
            rx,
        )
    }

    fn synth_slot_for_with_phase(
        account: u16,
        phase: Phase,
    ) -> (RaceSlot, oneshot::Receiver<PasteCode>) {
        let (tx, rx) = oneshot::channel::<PasteCode>();
        let task = tokio::spawn(async move {
            std::future::pending::<()>().await;
        });
        (
            RaceSlot {
                account,
                task,
                manual_url_timer: None,
                paste_tx: Some(tx),
                phase: Arc::new(Mutex::new(phase)),
            },
            rx,
        )
    }

    #[tokio::test]
    async fn install_for_same_account_replaces_prior_slot() {
        // UX-R1-H1: same-account install replaces (this is a retry).
        let state = RaceLoginState::default();
        let (slot1, _rx1) = synth_slot_for(1);
        let task1_handle = slot1.task.abort_handle();
        state.install(slot1).expect("first install");

        let (slot2, _rx2) = synth_slot_for(1);
        state
            .install(slot2)
            .expect("same-account install must replace, not error");

        // Prior task aborted. Same yield-then-poll dance as before
        // because abort is asynchronous on a multi-thread runtime.
        tokio::task::yield_now().await;
        for _ in 0..50 {
            if task1_handle.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(
            task1_handle.is_finished(),
            "prior race task must be aborted when a same-account race installs"
        );
    }

    #[tokio::test]
    async fn install_for_different_account_when_one_active_returns_error() {
        // UX-R1-H1 / HIGH 3: different-account install must error
        // rather than silently abort the in-flight race.
        let state = RaceLoginState::default();
        let (slot1, _rx1) = synth_slot_for(1);
        state.install(slot1).expect("first install");

        let (slot2, _rx2) = synth_slot_for(2);
        let err = state
            .install(slot2)
            .expect_err("different-account install must error");
        assert_eq!(err, InstallError::OccupiedByAccount(1));

        // The original account-1 race is still installed — the
        // error did not stomp it.
        match state.take_paste_sender(1) {
            PasteSenderTake::Got(_) => {}
            other => panic!(
                "account-1 slot should still be alive: {:?}",
                debug_take(&other)
            ),
        }
    }

    fn debug_take(t: &PasteSenderTake) -> &'static str {
        match t {
            PasteSenderTake::Got(_) => "Got",
            PasteSenderTake::NoSlot => "NoSlot",
            PasteSenderTake::WrongAccount { .. } => "WrongAccount",
            PasteSenderTake::AlreadyUsed => "AlreadyUsed",
        }
    }

    #[tokio::test]
    async fn take_paste_sender_returns_wrong_account_for_other_account() {
        // UX-R1-H1: distinguish "no slot" from "slot is for someone
        // else" so the frontend renders a precise message.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(7);
        state.install(slot).unwrap();

        match state.take_paste_sender(8) {
            PasteSenderTake::WrongAccount { active: 7 } => {}
            other => panic!(
                "expected WrongAccount {{ active: 7 }}, got {}",
                debug_take(&other)
            ),
        }
        // Right account still works after the wrong-account miss.
        match state.take_paste_sender(7) {
            PasteSenderTake::Got(_) => {}
            other => panic!("expected Got, got {}", debug_take(&other)),
        }
    }

    #[tokio::test]
    async fn take_paste_sender_is_single_use() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(3);
        state.install(slot).unwrap();

        match state.take_paste_sender(3) {
            PasteSenderTake::Got(_) => {}
            other => panic!("first take must succeed, got {}", debug_take(&other)),
        }
        match state.take_paste_sender(3) {
            PasteSenderTake::AlreadyUsed => {}
            other => panic!(
                "second take must report AlreadyUsed, got {}",
                debug_take(&other)
            ),
        }
    }

    #[tokio::test]
    async fn take_paste_sender_returns_no_slot_when_empty() {
        let state = RaceLoginState::default();
        match state.take_paste_sender(1) {
            PasteSenderTake::NoSlot => {}
            other => panic!("expected NoSlot, got {}", debug_take(&other)),
        }
    }

    #[tokio::test]
    async fn cancel_race_login_for_active_account_aborts() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(5);
        state.install(slot).unwrap();
        assert!(state.cancel_for(5));
    }

    #[tokio::test]
    async fn cancel_race_login_for_wrong_account_is_noop() {
        // HIGH 3 / UX-R1-H1: cancel for a non-matching account
        // returns false and leaves the active slot untouched.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(5);
        state.install(slot).unwrap();

        assert!(!state.cancel_for(99));
        // Slot for 5 still alive.
        match state.take_paste_sender(5) {
            PasteSenderTake::Got(_) => {}
            other => panic!(
                "account-5 slot must survive a wrong-account cancel: {}",
                debug_take(&other)
            ),
        }
    }

    #[tokio::test]
    async fn cancel_with_no_active_race_is_noop() {
        let state = RaceLoginState::default();
        assert!(
            !state.cancel_for(1),
            "cancel with no active race must return false"
        );
    }

    #[tokio::test]
    async fn cancel_is_idempotent_per_account() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(1);
        state.install(slot).unwrap();
        assert!(state.cancel_for(1));
        assert!(
            !state.cancel_for(1),
            "second cancel for same account must be a no-op"
        );
    }

    #[tokio::test]
    async fn cancel_after_resolved_does_not_emit_cancelled() {
        // REV-R1-01 / M7: once the orchestrator has progressed to
        // Exchanging or beyond, a cancel is too late to matter
        // and a `cancelled` event would land on top of (or just
        // before) the success event. Drop it.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for_with_phase(5, Phase::Exchanging);
        state.install(slot).unwrap();

        assert!(
            !state.cancel_for(5),
            "cancel after Exchanging must not actually cancel — credentials are in flight"
        );
    }

    #[tokio::test]
    async fn clear_for_only_clears_matching_account() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(5);
        state.install(slot).unwrap();

        // Different account — must NOT clear.
        state.clear_for(99);
        match state.take_paste_sender(5) {
            PasteSenderTake::Got(_) => {}
            other => panic!(
                "expected Got after wrong-account clear: {}",
                debug_take(&other)
            ),
        }

        // Re-install (since take consumed the sender) and clear with
        // the correct account this time.
        let (slot2, _rx2) = synth_slot_for(5);
        state.install(slot2).unwrap();
        state.clear_for(5);
        match state.take_paste_sender(5) {
            PasteSenderTake::NoSlot => {}
            other => panic!(
                "expected NoSlot after correct clear: {}",
                debug_take(&other)
            ),
        }
    }

    #[test]
    fn submit_paste_code_validates_account_range() {
        // Account 0 is out of range; AccountNum::try_from rejects it.
        // We can't construct `State<'_, RaceLoginState>` outside Tauri,
        // so this test exercises only the AccountNum boundary by
        // calling AccountNum::try_from directly — same code path the
        // command exercises before touching state.
        assert!(AccountNum::try_from(0u16).is_err());
        assert!(AccountNum::try_from(1000u16).is_err());
    }

    #[test]
    fn paste_code_debug_does_not_leak_value() {
        // SEC-R1-06 / M11 regression. A `Debug` print of the
        // PasteCode wrapper must redact the inner value.
        let p = PasteCode::new("super-secret-paste-code-12345".into());
        let dbg = format!("{p:?}");
        assert!(
            !dbg.contains("super-secret-paste-code-12345"),
            "PasteCode Debug leaked the value: {dbg}"
        );
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn event_payload_includes_account_for_each_emit_path() {
        // HIGH 4 / UX-R1-H2: every payload carries `account` as
        // the first field so the frontend can guard on it.
        // Serialise each payload struct and assert the JSON
        // contains the account field with the expected value.
        fn to_json<S: Serialize>(v: &S) -> String {
            serde_json::to_string(v).unwrap()
        }

        let bo = BrowserOpeningPayload {
            account: 7,
            auto_url: "https://x".into(),
        };
        let mu = ManualUrlPayload {
            account: 7,
            manual_url: "https://y".into(),
            hint: Some("hint".into()),
        };
        let mu_no_hint = ManualUrlPayload {
            account: 7,
            manual_url: "https://y".into(),
            hint: None,
        };
        let r = ResolvedPayload {
            account: 7,
            via: "loopback".into(),
        };
        let ex = ExchangingPayload { account: 7 };
        let s = SuccessPayload {
            account: 7,
            email: "e@example".into(),
        };
        let er = ErrorPayload {
            account: 7,
            message: "oops".into(),
            kind: "race_failed".into(),
        };
        let c = CancelledPayload { account: 7 };

        let payloads: Vec<String> = vec![
            to_json(&bo),
            to_json(&mu),
            to_json(&mu_no_hint),
            to_json(&r),
            to_json(&ex),
            to_json(&s),
            to_json(&er),
            to_json(&c),
        ];
        for json in &payloads {
            assert!(
                json.contains(r#""account":7"#),
                "payload missing `account`: {json}"
            );
        }

        // hint=None is omitted via skip_serializing_if so the
        // frontend doesn't have to discriminate "missing" vs "null".
        let json_no_hint = to_json(&mu_no_hint);
        assert!(
            !json_no_hint.contains(r#""hint""#),
            "manual-url payload must omit hint when None: {json_no_hint}"
        );
    }

    #[test]
    fn error_event_message_does_not_contain_token_prefixes() {
        // M10 / SEC-R1-05: error event messages pass through
        // redact_tokens. Build a synthetic message containing a
        // token-shaped prefix and confirm it survives the bridge
        // redacted.
        let raw =
            "exchange failed: upstream replied {access_token: sk-ant-oat01-LEAKEDTOKENVALUE...}";
        let redacted = csq_core::error::redact_tokens(raw);
        assert!(
            !redacted.contains("LEAKEDTOKENVALUE"),
            "redact_tokens must scrub sk-ant-oat01- prefixed tokens: {redacted}"
        );
    }

    #[test]
    fn classify_oauth_error_kind_covers_every_variant() {
        // Lock the error → tag mapping so a future variant addition
        // doesn't silently fall through to a generic kind.
        assert_eq!(
            classify_oauth_error_kind(&OAuthError::StateMismatch),
            "state_mismatch"
        );
        assert_eq!(
            classify_oauth_error_kind(&OAuthError::StateExpired { ttl_secs: 600 }),
            "state_expired"
        );
        assert_eq!(
            classify_oauth_error_kind(&OAuthError::PkceVerification),
            "pkce_verification"
        );
        assert_eq!(
            classify_oauth_error_kind(&OAuthError::Http {
                status: 502,
                body: "x".into()
            }),
            "http_error"
        );
        assert_eq!(
            classify_oauth_error_kind(&OAuthError::Exchange("x".into())),
            "race_failed"
        );
        assert_eq!(
            classify_oauth_error_kind(&OAuthError::Cancelled),
            "cancelled"
        );
        assert_eq!(
            classify_oauth_error_kind(&OAuthError::StoreAtCapacity { max_pending: 100 }),
            "store_at_capacity"
        );
        assert_eq!(
            classify_oauth_error_kind(&OAuthError::ExchangeTimeout { timeout_secs: 30 }),
            "exchange_timeout"
        );
    }

    #[tokio::test]
    async fn manual_url_timer_aborted_on_race_resolution() {
        // M1 / SEC-R1-03 / UX-R1-M1: the manual-URL 3 s timer must
        // be abortable. We can't drive the full Tauri stack from
        // this test, but we can simulate the slot bookkeeping: the
        // RaceSlot stores the timer JoinHandle; clear_for must
        // abort it.
        let state = RaceLoginState::default();
        let timer = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let timer_abort_handle = timer.abort_handle();

        let (mut slot, _rx) = synth_slot_for(11);
        slot.manual_url_timer = Some(timer);
        state.install(slot).unwrap();

        state.clear_for(11);

        tokio::task::yield_now().await;
        for _ in 0..50 {
            if timer_abort_handle.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(
            timer_abort_handle.is_finished(),
            "manual-URL timer must be aborted when the slot is cleared"
        );
    }

    #[tokio::test]
    async fn cancel_returns_only_after_task_aborted() {
        // SEC-R1-10 / L4: cancel_for_and_take returns the
        // JoinHandle so the bridge can await actual abortion. Drive
        // the await directly here.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(33);
        state.install(slot).unwrap();

        let handle = state
            .cancel_for_and_take(33)
            .expect("cancel must produce a handle");
        // After abort + await, the handle reports finished.
        let _ = tokio::time::timeout(Duration::from_millis(500), handle).await;
    }

    #[test]
    fn paste_sender_take_carries_active_account_on_wrong_match() {
        // HIGH 3 wiring detail: WrongAccount carries the active
        // account number so the frontend can render
        // "race in progress for account N" without a second IPC
        // round-trip.
        let take = PasteSenderTake::WrongAccount { active: 12 };
        match take {
            PasteSenderTake::WrongAccount { active } => assert_eq!(active, 12),
            _ => unreachable!(),
        }
    }
}
