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
//! | Event                         | Payload                              | When                                                          |
//! |-------------------------------|--------------------------------------|---------------------------------------------------------------|
//! | `claude-login-browser-opening`| `{ auto_url: string }`               | Immediately after the orchestrator returns the auto URL.      |
//! | `claude-login-manual-url-ready`| `{ manual_url: string }`            | 3 s after `browser-opening`, OR immediately on browser-open failure. |
//! | `claude-login-resolved`       | `{ via: "loopback" \| "paste" }`     | When one of the two paths captures a code first.              |
//! | `claude-login-exchanging`     | `{}`                                 | Right before the token endpoint POST.                         |
//! | `claude-login-success`        | `{ email: string, account: number }` | After credentials are persisted to `credentials/N.json`.      |
//! | `claude-login-error`          | `{ message: string, kind: string }`  | On any orchestrator or post-processing failure.               |
//! | `claude-login-cancelled`      | `{}`                                 | After `cancel_race_login` has aborted the in-flight task.     |
//!
//! # Security
//!
//! - **No code in event payloads.** The auth code is consumed inside
//!   the orchestrator and exchanged for a token; the only IPC value
//!   ever leaving the backend is the user-facing email + account
//!   number on `claude-login-success`. See `tauri-commands.md` MUST
//!   NOT Rule 1 ("No sensitive data in event payloads").
//! - **No state token round-trip.** Unlike `submit_oauth_code`, the
//!   paste channel uses an in-process `oneshot` resolver tracked in
//!   `RaceLoginState`. The frontend has no token to leak; it just
//!   submits the code and lets the orchestrator route it.
//! - **At most one race in flight.** The user has a single Add
//!   Account modal — concurrent logins make no UX sense and would
//!   compete for the loopback port.

use csq_core::credentials;
use csq_core::oauth::race::{race_login, RaceConfig, RaceWinner};
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

/// In-process state for the at-most-one-active race.
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

/// One outstanding race's bookkeeping.
struct RaceSlot {
    /// Account slot the race is targeting. Used to route the success
    /// event back to the modal that initiated it.
    account: u16,
    /// JoinHandle for the orchestrator task. Aborting it triggers the
    /// orchestrator's drop-on-cancel cleanup (loopback listener +
    /// paste resolver both close).
    task: JoinHandle<()>,
    /// Paste-code channel sender. The orchestrator's paste resolver
    /// owns the receiver. Taken on first `submit_paste_code` call;
    /// subsequent calls return an error.
    paste_tx: Option<oneshot::Sender<String>>,
}

impl RaceLoginState {
    /// Inserts a fresh race slot, replacing any prior one. The prior
    /// race (if any) is aborted first so a stale orchestrator can't
    /// keep a loopback port bound after the user retried.
    fn install(&self, slot: RaceSlot) {
        let mut guard = self.inner.lock().expect("race state mutex poisoned");
        if let Some(prev) = guard.take() {
            prev.task.abort();
        }
        *guard = Some(slot);
    }

    /// Atomically takes the paste-channel sender. Returns `None` if
    /// no race is active OR the paste channel has already been used.
    fn take_paste_sender(&self, account: u16) -> Option<oneshot::Sender<String>> {
        let mut guard = self.inner.lock().expect("race state mutex poisoned");
        let slot = guard.as_mut()?;
        if slot.account != account {
            return None;
        }
        slot.paste_tx.take()
    }

    /// Aborts the active race and clears the slot. Idempotent — calling
    /// twice in quick succession from a double-clicked Cancel button
    /// just no-ops the second call.
    fn cancel(&self) -> bool {
        let mut guard = self.inner.lock().expect("race state mutex poisoned");
        if let Some(slot) = guard.take() {
            slot.task.abort();
            true
        } else {
            false
        }
    }

    /// Clears the slot for a SPECIFIC account (used by the orchestrator
    /// task to remove its own bookkeeping on completion). A different
    /// account's race may have replaced ours mid-flight; in that case
    /// we MUST NOT clobber the new slot.
    fn clear_for(&self, account: u16) {
        let mut guard = self.inner.lock().expect("race state mutex poisoned");
        let should_clear = guard
            .as_ref()
            .map(|slot| slot.account == account)
            .unwrap_or(false);
        if should_clear {
            *guard = None;
        }
    }
}

// ── Event payloads ──────────────────────────────────────────

#[derive(Clone, Serialize)]
struct BrowserOpeningPayload {
    auto_url: String,
}

#[derive(Clone, Serialize)]
struct ManualUrlPayload {
    manual_url: String,
}

#[derive(Clone, Serialize)]
struct ResolvedPayload {
    /// "loopback" | "paste"
    via: String,
}

#[derive(Clone, Serialize)]
struct SuccessPayload {
    email: String,
    account: u16,
}

#[derive(Clone, Serialize)]
struct ErrorPayload {
    /// Pre-redacted, frontend-safe message.
    message: String,
    /// Fixed-vocabulary tag for UI branching.
    /// One of: "race_failed", "exchange_failed", "credential_write",
    /// "post_login", "cancelled".
    kind: String,
}

// ── Tauri commands ──────────────────────────────────────────

/// Starts a parallel-race OAuth login for the given account slot.
///
/// Spawns the orchestrator on a tokio task, registers it in
/// `RaceLoginState`, and returns immediately. The orchestrator drives
/// the browser-open + 3 s manual-URL delay + loopback-vs-paste race
/// internally and emits Tauri events at each transition (see module
/// docs for the event vocabulary).
///
/// The frontend MUST subscribe to the `claude-login-*` events BEFORE
/// invoking this command — otherwise a fast race (loopback fires
/// before the listener registers) drops the first event. See the
/// AddAccountModal `runRaceLogin` function for the correct ordering.
///
/// # Errors
///
/// - `"invalid account: ..."` — account out of 1..=999 range.
/// - `"base directory does not exist: ..."` — base dir missing.
/// - `"race init failed: ..."` — orchestrator could not bind the
///   loopback port or build the auth URL. The frontend should
///   surface this as `claude-login-error` and offer the legacy
///   shell-out path.
#[tauri::command]
pub async fn start_claude_login_race(
    app: AppHandle,
    state: State<'_, RaceLoginState>,
    base_dir: String,
    account: u16,
) -> Result<(), String> {
    let account_num =
        AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    // The race orchestrator owns:
    //   - loopback listener bound at race construction time
    //   - browser-open task (handled by Tauri opener plugin from the FE)
    //   - 3-second manual-URL delay timer
    //   - paste resolver (oneshot::Receiver passed in via RaceConfig)
    //
    // We pre-build the paste channel here so the sender lives in
    // RaceLoginState; the receiver moves into RaceConfig.
    let (paste_tx, paste_rx) = oneshot::channel::<String>();

    let cfg = RaceConfig {
        account: account_num,
        paste_resolver: paste_rx,
        manual_url_delay: MANUAL_URL_DELAY,
    };

    let app_handle = app.clone();
    let base_clone = base.clone();
    // Use tokio::spawn (NOT tauri::async_runtime::spawn) so the
    // JoinHandle type matches the field on RaceSlot. Both runtimes
    // are tokio under the hood, but tauri's wrapper hides the abort
    // primitives our cancel path needs.
    let task = tokio::spawn(async move {
        // Race init returns the immediate URLs (auto + manual) so the
        // frontend can open the browser. The race body then waits for
        // either path to converge.
        match race_login(cfg).await {
            Ok(result) => {
                // Emit the auto URL so the frontend can open it. The
                // manual URL is sent via a delayed emit handled inside
                // the orchestrator (see RaceConfig::manual_url_delay).
                emit_browser_opening(&app_handle, &result.auto_url);

                // Manual URL emission is the orchestrator's responsibility
                // when the delay elapses; we hold a copy here for the
                // resolved/success payload composition only.
                emit_manual_url_ready(&app_handle, &result.manual_url);

                let via = match &result.winner {
                    RaceWinner::Loopback { .. } => "loopback",
                    RaceWinner::Paste { .. } => "paste",
                };
                emit_resolved(&app_handle, via);

                emit_exchanging(&app_handle);

                // Orchestrator's RaceWinner already includes the code
                // and redirect_uri; finalize_login persists credentials
                // and reads back the email for the success event.
                let outcome = finalize_login(&base_clone, account_num, &result).await;
                match outcome {
                    Ok(email) => emit_success(&app_handle, &email, account_num.get()),
                    Err((message, kind)) => emit_error(&app_handle, &message, kind),
                }
            }
            Err(e) => {
                emit_error(&app_handle, &format!("race failed: {e}"), "race_failed");
            }
        }

        // Whichever branch we took above, the slot for this account
        // is no longer alive. Best-effort clear (no-op if a newer
        // race for a different account replaced us).
        let race_state: Option<tauri::State<'_, RaceLoginState>> = app_handle.try_state();
        if let Some(s) = race_state {
            s.clear_for(account_num.get());
        }
    });

    state.install(RaceSlot {
        account: account_num.get(),
        task,
        paste_tx: Some(paste_tx),
    });
    Ok(())
}

/// Submits a paste-code into the active race's paste resolver.
///
/// The orchestrator's paste resolver is a `oneshot::Receiver<String>`;
/// once we send into it, the race body's `tokio::select!` over the
/// loopback and paste futures resolves and the rest of the flow runs.
/// If the loopback already won, the paste sender we hold here was
/// dropped by the orchestrator and our send returns `Err` — in that
/// case the user typed a code that's now irrelevant, and we surface
/// a clear (but not alarming) error so the modal can stay on its
/// "loopback already completed" overlay.
///
/// # Errors
///
/// - `"invalid account: ..."` — account out of 1..=999 range.
/// - `"no active race for account ..."` — no in-flight race, or
///   the paste channel has already been used (double-click), or
///   the loopback path won the race (sender was dropped).
/// - `"invalid code: paste was empty"` — empty / whitespace-only
///   paste; matches the `submit_oauth_code` validation message so
///   the frontend can use the same error-handling branch.
#[tauri::command]
pub fn submit_paste_code(
    state: State<'_, RaceLoginState>,
    account: u16,
    code: String,
) -> Result<(), String> {
    let account_num =
        AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;

    // Same trim semantics as `submit_oauth_code`: strip whitespace
    // and Windows CR. Codes can contain `#` so we MUST NOT split at
    // it (regression from the in-process paste-code path; see
    // commands::submit_oauth_code docstring).
    let code = code.trim().trim_end_matches('\r').to_string();
    if code.is_empty() {
        return Err("invalid code: paste was empty".into());
    }

    let sender = state.take_paste_sender(account_num.get()).ok_or_else(|| {
        format!(
            "no active race for account {} — the loopback path may have already completed",
            account_num.get()
        )
    })?;

    sender
        .send(code)
        .map_err(|_| "race orchestrator dropped the paste channel — retry the login".to_string())
}

/// Cancels the active race, if any. Idempotent: returns `Ok(())`
/// even if no race was in flight, because the user-visible outcome
/// (no spinning Add Account modal) is the same.
///
/// Emits `claude-login-cancelled` so the modal can transition out
/// of any in-progress state.
#[tauri::command]
pub fn cancel_race_login(
    app: AppHandle,
    state: State<'_, RaceLoginState>,
) -> Result<(), String> {
    let cancelled = state.cancel();
    if cancelled {
        // Only emit the cancellation event if there actually was a
        // race to cancel. A no-op cancel (modal closed twice) should
        // not flood the bus with spurious events that other listeners
        // might react to.
        if let Err(e) = app.emit("claude-login-cancelled", &serde_json::json!({})) {
            log::warn!("failed to emit claude-login-cancelled: {e}");
        }
    }
    Ok(())
}

// ── Internal helpers ────────────────────────────────────────

/// Persists the credential captured by either race winner and reads
/// back the email for the success event.
///
/// Both winners (loopback, paste) carry a `code` and `redirect_uri`;
/// the only difference is which channel surfaced them. The exchange
/// path is identical from here on — POST to the token endpoint,
/// receive the credential pair, write to `credentials/N.json`.
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
    let exchange_outcome = tauri::async_runtime::spawn_blocking(move || {
        let credential = exchange_code(
            &code_owned,
            &verifier,
            &redirect_owned,
            csq_core::http::post_json_node,
        )
        .map_err(|e| (format!("exchange failed: {e}"), "exchange_failed"))?;

        credentials::save_canonical(&base_owned, account, &credential)
            .map_err(|e| (format!("credential write failed: {e}"), "credential_write"))?;

        // Best-effort post-login bookkeeping: profiles.json email,
        // marker, broker-failed clear. Mirrors `submit_oauth_code`.
        let _ = csq_core::accounts::login::finalize_login(&base_owned, account);

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

        Ok::<_, (String, &'static str)>(())
    })
    .await
    .map_err(|e| (format!("exchange task failed: {e}"), "exchange_failed"))?;

    exchange_outcome?;

    // Read the email back from profiles.json (populated by
    // finalize_login above). Falling back to "unknown" if the file
    // isn't readable — the user can rename later from the dashboard.
    let email = read_email_for(&base.to_path_buf(), account).unwrap_or_else(|| "unknown".into());
    Ok(email)
}

fn read_email_for(base: &std::path::Path, account: AccountNum) -> Option<String> {
    let profiles_path = base.join("profiles.json");
    let bytes = std::fs::read(&profiles_path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let key = account.get().to_string();
    value
        .get("accounts")
        .and_then(|a| a.get(&key))
        .and_then(|s| s.get("email"))
        .and_then(|e| e.as_str())
        .map(|s| s.to_string())
}

// ── Event emit shims ────────────────────────────────────────
//
// Each shim is a thin wrapper so the orchestrator task body reads
// linearly without `.map_err(...).unwrap_or(...)` noise. Emit failures
// are logged but never propagated — by the time we're emitting,
// the underlying credential write has already succeeded or failed,
// and the user will see the outcome on the next dashboard poll
// regardless.

fn emit_browser_opening(app: &AppHandle, auto_url: &str) {
    if let Err(e) = app.emit(
        "claude-login-browser-opening",
        BrowserOpeningPayload {
            auto_url: auto_url.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-browser-opening: {e}");
    }
}

fn emit_manual_url_ready(app: &AppHandle, manual_url: &str) {
    if let Err(e) = app.emit(
        "claude-login-manual-url-ready",
        ManualUrlPayload {
            manual_url: manual_url.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-manual-url-ready: {e}");
    }
}

fn emit_resolved(app: &AppHandle, via: &str) {
    if let Err(e) = app.emit(
        "claude-login-resolved",
        ResolvedPayload {
            via: via.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-resolved: {e}");
    }
}

fn emit_exchanging(app: &AppHandle) {
    if let Err(e) = app.emit("claude-login-exchanging", &serde_json::json!({})) {
        log::warn!("failed to emit claude-login-exchanging: {e}");
    }
}

fn emit_success(app: &AppHandle, email: &str, account: u16) {
    if let Err(e) = app.emit(
        "claude-login-success",
        SuccessPayload {
            email: email.to_string(),
            account,
        },
    ) {
        log::warn!("failed to emit claude-login-success: {e}");
    }
}

fn emit_error(app: &AppHandle, message: &str, kind: &'static str) {
    if let Err(e) = app.emit(
        "claude-login-error",
        ErrorPayload {
            message: message.to_string(),
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
    use tokio::sync::oneshot;

    /// Helper to install a synthetic race slot for state tests so we
    /// don't need to spin up the real orchestrator.
    fn synth_slot(account: u16) -> (RaceSlot, oneshot::Receiver<String>) {
        let (tx, rx) = oneshot::channel::<String>();
        let task = tokio::spawn(async move {
            // Park forever — caller aborts.
            std::future::pending::<()>().await;
        });
        (
            RaceSlot {
                account,
                task,
                paste_tx: Some(tx),
            },
            rx,
        )
    }

    #[tokio::test]
    async fn install_replaces_prior_slot_and_aborts_it() {
        let state = RaceLoginState::default();
        let (slot1, _rx1) = synth_slot(1);
        let task1_handle = slot1.task.abort_handle();
        state.install(slot1);

        let (slot2, _rx2) = synth_slot(2);
        state.install(slot2);

        // The first task must be aborted by install().
        assert!(
            task1_handle.is_finished(),
            "prior race task must be aborted when a new race installs"
        );
    }

    #[tokio::test]
    async fn take_paste_sender_returns_none_for_wrong_account() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot(7);
        state.install(slot);

        assert!(state.take_paste_sender(8).is_none());
        // Right account still works after the wrong-account miss.
        assert!(state.take_paste_sender(7).is_some());
    }

    #[tokio::test]
    async fn take_paste_sender_is_single_use() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot(3);
        state.install(slot);

        assert!(state.take_paste_sender(3).is_some());
        assert!(
            state.take_paste_sender(3).is_none(),
            "second take must return None — paste channel is single-use"
        );
    }

    #[tokio::test]
    async fn cancel_returns_true_when_race_was_active() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot(1);
        state.install(slot);
        assert!(state.cancel());
    }

    #[tokio::test]
    async fn cancel_returns_false_when_no_race() {
        let state = RaceLoginState::default();
        assert!(!state.cancel(), "cancel with no active race must return false");
    }

    #[tokio::test]
    async fn cancel_is_idempotent() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot(1);
        state.install(slot);
        assert!(state.cancel());
        assert!(!state.cancel(), "second cancel must be a no-op");
    }

    #[tokio::test]
    async fn clear_for_only_clears_matching_account() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot(5);
        state.install(slot);

        // Different account — must NOT clear.
        state.clear_for(99);
        assert!(state.take_paste_sender(5).is_some());

        // Re-install (since take consumed the sender) and clear with
        // the correct account this time.
        let (slot2, _rx2) = synth_slot(5);
        state.install(slot2);
        state.clear_for(5);
        assert!(state.take_paste_sender(5).is_none());
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
}
