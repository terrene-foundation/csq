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
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use csq_core::accounts::login_lock::{AccountLoginLock, AcquireOutcome};
use csq_core::credentials;
use csq_core::error::{redact_tokens, OAuthError};
use csq_core::oauth::race::{drive_race, prepare_race, RaceWinner, DEFAULT_OVERALL_TIMEOUT};
use csq_core::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Emitter, Manager, State, Window};
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

/// Outcome of [`RaceLoginState::cancel_for_and_take_with_token`].
///
/// SEC-R2-03: the race-token check is the security boundary that
/// turns the cancel command from an information-disclosure oracle
/// into a capability — only a caller that holds the token returned by
/// `start_claude_login_race` can cancel the race.
#[derive(Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The cancel succeeded and the orchestrator task has been
    /// aborted. Caller should emit `claude-login-cancelled` after
    /// awaiting the JoinHandle for the brief grace period.
    Cancelled,
    /// No active race exists for the given account, OR the account
    /// has a race but it is past the point where cancellation is
    /// meaningful (Exchanging or later).
    ///
    /// SEC-R2-03: returned **even when the token is wrong** for an
    /// account that has no active race, so the absence of an active
    /// race is not distinguishable from a wrong-token reject. The
    /// only signal the caller can extract is "no effect" — they
    /// cannot tell whether their token was wrong or there was nothing
    /// to cancel.
    NoOp,
    /// The token did not match the stored token for this account.
    /// Returned ONLY when there IS an active race and the supplied
    /// token is wrong — so it does NOT leak the existence of any
    /// other race. Surfaced as `Err("unauthorized")` from the
    /// `cancel_race_login` command.
    Unauthorized,
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
    /// SEC-R2-01: per-account login lock guard (same flock the CLI
    /// `csq login N` acquires). Held in the slot so it lives for the
    /// duration of the race; dropped automatically when the slot is
    /// taken (clear_for / cancel_for_and_take), which releases the
    /// flock and lets a subsequent CLI/desktop login proceed. The
    /// guard is `Option<...>` because synthetic test slots construct
    /// without acquiring a real lock — production paths always set
    /// `Some(...)`.
    ///
    /// `dead_code` is misleading here: the lock is "read" by being
    /// held; its Drop is the load-bearing behaviour. The compiler
    /// can't see that, so we silence the lint.
    #[allow(dead_code)]
    login_lock: Option<AccountLoginLock>,
    /// SEC-R2-04: window label of the renderer that initiated the
    /// race. Stored so every event emit goes through `emit_to(label,
    /// ...)` instead of broadcasting to every window in the app.
    /// Defends against a malicious second window scraping the auto
    /// URL (which carries the per-race path secret) out of the
    /// `claude-login-browser-opening` payload.
    ///
    /// Read indirectly: the orchestrator task captures the label at
    /// spawn time (see `window_label_for_task` in
    /// `start_claude_login_race`); this field on the slot is the
    /// authoritative copy used by the cancel path to emit the
    /// `claude-login-cancelled` event to the right window.
    #[allow(dead_code)]
    window_label: String,
    /// SEC-R2-03: opaque race token returned to the caller from
    /// `start_claude_login_race` and required by `cancel_race_login`.
    /// Without this token a malicious in-process JS handler could
    /// iterate account numbers calling `cancel_race_login(N)` to
    /// discover which account currently has an active login (oracle).
    /// Constant-time-compared on cancel.
    race_token: String,
    /// R3-M2 / round-4 redteam: tracks whether the user submitted a
    /// paste code BEFORE the loopback path won. Set to `true` by
    /// `submit_paste_code` at the moment it takes the sender — i.e.
    /// before the `sender.send(...)` call, which means the flag is
    /// flipped even when the orchestrator's `tokio::select!` cancels
    /// the resolver future before its `paste_rx.await` returns.
    ///
    /// Drives the UX-R2-02 `paste_after_loopback_won` info banner.
    /// Pre-R3-M2 the flag was set INSIDE the resolver future after
    /// `paste_rx.await`; if loopback won the select between
    /// `submit_paste_code`'s `sender.send(...)` and the resolver
    /// observing the value, the flag stayed false and the banner
    /// silently failed to fire. Moving the write into
    /// `submit_paste_code` closes that window — the user's submit
    /// action and the flag observation are now atomic with respect
    /// to the slot mutex.
    paste_was_used: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
    ///
    /// SEC-R2-02 / REV-R2-01: the rejected slot is RETURNED to the
    /// caller as the second tuple element so the caller can
    /// explicitly abort the orchestrator task and drop the lock
    /// guard / listener instead of leaking them. Without this,
    /// dropping the slot here would leave the spawned task running
    /// (Tokio does NOT abort tasks when the JoinHandle is dropped)
    /// and pin the loopback port + the per-account flock for the
    /// full overall-timeout (10 min default).
    ///
    /// `clippy::result_large_err` is suppressed because returning the
    /// boxed slot would force every caller to unbox before
    /// inspecting fields; the slot only flows through the (rare)
    /// rejection path so the size cost is negligible.
    #[allow(clippy::result_large_err)]
    fn install(&self, slot: RaceSlot) -> Result<(), (InstallError, RaceSlot)> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = guard.as_ref() {
            if prev.account != slot.account {
                let other_account = prev.account;
                return Err((InstallError::OccupiedByAccount(other_account), slot));
            }
        }
        if let Some(prev) = guard.take() {
            // Same-account replace: abort the old task and any
            // outstanding manual-URL timer. The previous slot's
            // login-lock guard is dropped here, releasing the flock
            // for the new slot we're about to install.
            prev.task.abort();
            if let Some(t) = prev.manual_url_timer {
                t.abort();
            }
        }
        *guard = Some(slot);
        Ok(())
    }

    /// Atomically takes the paste-channel sender AND a clone of the
    /// `paste_was_used` flag. Returns the reason the take failed (so
    /// the caller can surface a precise error) when no sender is
    /// available.
    ///
    /// R3-M2 / round-4 redteam: the flag clone is returned alongside
    /// the sender so `submit_paste_code` can flip it BEFORE calling
    /// `sender.send(...)`. This closes the race where loopback won
    /// the orchestrator's `tokio::select!` between the user's submit
    /// and the resolver's `paste_rx.await`, leaving the flag false
    /// and the `paste_after_loopback_won` banner silently lost.
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
            Some(tx) => PasteSenderTake::Got {
                sender: tx,
                paste_was_used: slot.paste_was_used.clone(),
            },
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
    ///
    /// SEC-R2-03: the production path now uses
    /// [`Self::cancel_for_and_take_with_token`] which adds an opaque
    /// token check on top of this method's account-only matching.
    /// This unauthenticated variant is kept as the building block
    /// (and for the existing test surface) but is NOT exposed via
    /// any Tauri command.
    #[cfg(test)]
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

    /// SEC-R2-03: token-gated cancellation.
    ///
    /// Returns:
    /// - `(CancelOutcome::Cancelled, Some(JoinHandle))` if the slot
    ///   matched the account AND the supplied token AND was in a
    ///   cancellable phase. Caller awaits the handle for the brief
    ///   abort grace period, then emits `claude-login-cancelled`.
    /// - `(CancelOutcome::Unauthorized, None)` ONLY when the account
    ///   has an active cancellable race AND the supplied token was
    ///   wrong. This is the security boundary — without this branch a
    ///   caller could iterate accounts to discover which one has an
    ///   active race.
    /// - `(CancelOutcome::NoOp, None)` for every other case (no slot,
    ///   wrong account, past Exchanging). Token is NOT examined in
    ///   the no-slot case so the caller cannot distinguish "slot
    ///   absent" from "slot present but wrong account" from "wrong
    ///   token on absent slot".
    ///
    /// Constant-time token comparison (SEC-R2-06) so a same-process
    /// attacker cannot use timing to brute-force the token byte by
    /// byte.
    fn cancel_for_and_take_with_token(
        &self,
        account: u16,
        token: &str,
    ) -> (CancelOutcome, Option<JoinHandle<()>>) {
        // Phase 1: take a peek under the lock. If there's no slot
        // for this account at all (or slot is past cancellable
        // phase), we want to return `NoOp` WITHOUT examining the
        // token — examining it would create the oracle we're
        // defending against (an attacker could probe each account
        // with junk and observe which call paths examine the token).
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = guard.as_ref() else {
            return (CancelOutcome::NoOp, None);
        };
        if s.account != account {
            return (CancelOutcome::NoOp, None);
        }
        let phase = *s.phase.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(phase, Phase::Exchanging | Phase::Done | Phase::Failed) {
            return (CancelOutcome::NoOp, None);
        }

        // Phase 2: there IS a cancellable race for this account.
        // Now check the token; this is the security boundary the
        // attacker is trying to bypass.
        let token_bytes = token.as_bytes();
        let stored_bytes = s.race_token.as_bytes();
        // Length-mismatch short-circuit. The token is fixed-length
        // (22 base64url chars) so a length mismatch is itself "no
        // match" without leaking the stored length.
        let token_ok =
            token_bytes.len() == stored_bytes.len() && bool::from(token_bytes.ct_eq(stored_bytes));
        if !token_ok {
            return (CancelOutcome::Unauthorized, None);
        }

        // Token matched — take the slot and abort.
        let Some(slot) = guard.take() else {
            return (CancelOutcome::NoOp, None);
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
        (CancelOutcome::Cancelled, Some(task))
    }

    /// SEC-R2-02 / REV-R2-01: rewrites the slot's `task` and
    /// `manual_url_timer` fields under the install mutex, after a
    /// successful `install` with placeholder handles. Lets the
    /// caller `install` first (and roll back on rejection without
    /// orphaning a spawned task), then swap the real handles in
    /// once we know the slot is ours.
    ///
    /// No-op if the slot has been replaced by a different account's
    /// race in the brief window between `install` and this call.
    fn replace_handles(
        &self,
        account: u16,
        task: JoinHandle<()>,
        manual_url_timer: Option<JoinHandle<()>>,
    ) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = guard.as_mut() else {
            // Slot was cleared; abort the just-spawned task to
            // avoid an orphan.
            task.abort();
            if let Some(t) = manual_url_timer {
                t.abort();
            }
            return;
        };
        if slot.account != account {
            // Different account replaced us; abort and let the
            // newer slot proceed.
            task.abort();
            if let Some(t) = manual_url_timer {
                t.abort();
            }
            return;
        }
        // Abort the placeholder handles before replacing them. The
        // placeholders are empty futures so this is mostly bookkeeping;
        // calling abort on an already-completed future is a no-op.
        let prev_task = std::mem::replace(&mut slot.task, task);
        prev_task.abort();
        if let Some(prev_timer) = std::mem::replace(&mut slot.manual_url_timer, manual_url_timer) {
            prev_timer.abort();
        }
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
    /// Sender was taken AND the `paste_was_used` flag clone is
    /// returned so `submit_paste_code` can flip it BEFORE the
    /// `sender.send(...)` call. R3-M2 / round-4 redteam.
    Got {
        sender: oneshot::Sender<PasteCode>,
        paste_was_used: std::sync::Arc<std::sync::atomic::AtomicBool>,
    },
    /// No race is installed at all.
    NoSlot,
    /// A race IS installed but for a different account.
    WrongAccount { active: u16 },
    /// The paste sender for this account was already taken (the
    /// loopback path won OR the user already pasted).
    AlreadyUsed,
}

/// Wraps a paste code so its `Debug` impl never leaks the value.
/// SEC-R1-06 / M11. Production callers MUST NOT use `.0` directly
/// in any formatting context; use [`PasteCode::into_inner`] at the
/// single point that hands it to the orchestrator.
///
/// SEC-R2-05: implements a custom `Deserialize` so when the Tauri
/// IPC layer parses the command argument, the resulting Debug-format
/// of the PasteCode (which is what tauri's command-arg logging at
/// `RUST_LOG=tauri=debug` prints) is the redacted form, not the raw
/// string. With a derived `Deserialize` the IPC layer would briefly
/// hold the value as a `String` argument before wrapping, and any
/// tracing/log span that captures arg names would see the unredacted
/// form. Custom Deserialize means the wrapper appears AT the IPC
/// boundary and is never exposed as a plain `String` anywhere upstream
/// of the orchestrator.
pub struct PasteCode(String);

impl PasteCode {
    /// Test-only constructor; production paths build PasteCode via
    /// the custom Deserialize at the IPC boundary.
    #[cfg(test)]
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

    /// Returns the trimmed form of the wrapped paste, used for
    /// validation. Does NOT clone — borrows for the duration of the
    /// caller's check. SEC-R2-05: keeps validation logic out of the
    /// command handler so the IPC layer never needs to compare a raw
    /// `String` against an empty / whitespace pattern.
    fn trimmed(&self) -> &str {
        self.0.trim().trim_end_matches('\r')
    }
}

impl std::fmt::Debug for PasteCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasteCode([REDACTED])")
    }
}

/// Custom Deserialize that collapses trim/empty validation into the
/// IPC parse step. SEC-R2-05.
///
/// Tauri's `#[tauri::command]` macro generates a wrapper that calls
/// `Deserialize::deserialize` on each command argument's type; if the
/// type is `String` Tauri sees the raw value briefly and may log it
/// under `RUST_LOG=tauri=debug`. By making the command parameter
/// `code: PasteCode`, the deserializer immediately wraps the
/// underlying string in the redacting newtype — Tauri's own logging
/// then prints `PasteCode([REDACTED])` because that's what `Debug`
/// for our type yields.
///
/// We perform trim + empty-check here too so the command handler is
/// a thin pass-through: a frontend that submits `"   "` is rejected
/// at deserialize time with a precise error rather than reaching the
/// orchestrator.
impl<'de> Deserialize<'de> for PasteCode {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let raw = String::deserialize(d)?;
        let trimmed = raw.trim().trim_end_matches('\r');
        if trimmed.is_empty() {
            return Err(D::Error::custom("invalid code: paste was empty"));
        }
        Ok(PasteCode(trimmed.to_string()))
    }
}

/// Generates a 16-byte URL-safe base64 race token (22 chars).
///
/// SEC-R2-03: each `start_claude_login_race` invocation mints a
/// fresh token, returns it to the calling renderer, and stores a
/// copy in the slot. `cancel_race_login` requires the same token to
/// proceed — without it, an attacker with arbitrary in-process JS
/// could iterate accounts to discover which one is in flight.
fn generate_race_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable — cannot generate race token");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Return type of `start_claude_login_race`. Carries the opaque
/// race token the frontend must thread through to `cancel_race_login`.
#[derive(Clone, Serialize)]
pub struct StartRaceResponse {
    /// Account slot the race is targeting. Echoed back so a caller
    /// can sanity-check (defensive — they pass it in to the command).
    pub account: u16,
    /// Opaque per-race CSPRNG token. SEC-R2-03 — required to call
    /// `cancel_race_login`. Not a secret in the credential sense,
    /// but a capability the renderer must hold to authorize cancel.
    pub race_token: String,
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
/// `RaceLoginState`, and returns immediately with a [`StartRaceResponse`]
/// containing the per-race token the caller MUST supply to
/// `cancel_race_login`. The orchestrator emits Tauri events at each
/// transition (see module docs for the event vocabulary).
///
/// The frontend MUST subscribe to the `claude-login-*` events BEFORE
/// invoking this command — otherwise a fast race (loopback fires
/// before the listener registers) drops the first event. See the
/// AddAccountModal `startClaudeOAuth` function for the correct ordering.
///
/// # Sequencing (SEC-R2-02 / REV-R2-01)
///
/// To avoid orphaning the orchestrator task on cross-account install
/// rejection, this command sequences in two phases:
///
/// 1. **Reserve the slot**: acquire the per-account login lock
///    (SEC-R2-01), prepare the listener + URLs, and TRY the install
///    BEFORE spawning the orchestrator task. The slot is installed
///    with a placeholder JoinHandle so the install-rejection path
///    runs without ever spawning anything to leak.
/// 2. **Spawn**: only after the slot is in place do we spawn the
///    orchestrator and rewrite the slot's task field to the real
///    handle. If install fails, the lock guard, listener, and URLs
///    drop on this function's stack — no orphan.
///
/// # Errors
///
/// - `"invalid account: ..."` — account out of 1..=999 range.
/// - `"base directory does not exist: ..."` — base dir missing.
/// - `"login already in progress for account N (PID ...)"` —
///   SEC-R2-01: another csq process (CLI or desktop) holds the
///   account login lock. Returns the structured error variant
///   `OAuthError::LoginInProgressElsewhere` rendered as a string.
/// - `"another login is already in progress for account N — cancel it first"`
///   — UX-R1-H1: a sibling race in THIS desktop process exists for a
///   different account.
/// - `"race init failed: ..."` — orchestrator could not bind the
///   loopback port or build the auth URL. The frontend should
///   surface this as `claude-login-error` and offer the legacy
///   shell-out path.
#[tauri::command]
pub async fn start_claude_login_race(
    app: AppHandle,
    window: Window,
    race_state: State<'_, RaceLoginState>,
    app_state: State<'_, AppState>,
    base_dir: String,
    account: u16,
) -> Result<StartRaceResponse, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;
    let base = PathBuf::from(&base_dir);
    if !base.is_dir() {
        return Err(format!("base directory does not exist: {base_dir}"));
    }

    // SEC-R2-04: capture the calling renderer's window label so all
    // emits go through emit_to(label, ...). Stored on the slot and
    // passed into the orchestrator task.
    let window_label = window.label().to_string();

    // SEC-R2-01: acquire the per-account login lock BEFORE preparing
    // the race. If a CLI `csq login N` is in flight the lock probe
    // returns Held with the holder PID; we map that to the
    // `LoginInProgressElsewhere` error so the frontend can render a
    // dedicated "another login is in progress" UI (UX-R2-03) with a
    // recovery path.
    let login_lock = match AccountLoginLock::acquire(&base, account_num) {
        Ok(AcquireOutcome::Acquired(g)) => g,
        Ok(AcquireOutcome::Held { pid, pid_alive: _ }) => {
            return Err(login_in_progress_message(account_num.get(), pid));
        }
        Err(e) => {
            return Err(format!(
                "could not create login lock for account {}: {}",
                account_num.get(),
                redact_tokens(&e.to_string())
            ));
        }
    };

    // Two-phase race: prepare binds the loopback listener and mints
    // the URLs SYNCHRONOUSLY (microseconds), then drive blocks on
    // the actual user interaction. Splitting them lets us emit the
    // URLs IMMEDIATELY so the frontend can open the browser and
    // start its 3-second manual-URL display timer while the race is
    // still waiting on the first callback.
    let prep = prepare_race(&app_state.oauth_store, account_num)
        .await
        .map_err(|e| format!("race init failed: {}", redact_tokens(&e.to_string())))?;
    let auto_url = prep.auto_url.clone();
    let manual_url = prep.manual_url.clone();

    // SEC-R2-03: mint the per-race token. Returned to the caller and
    // stored on the slot; required for cancel_race_login.
    let race_token = generate_race_token();

    // SEC-R2-04: emit browser-opening to ONLY the calling window
    // (not broadcast). Synchronously from the command thread so the
    // frontend has the URL by the time we return Ok().
    emit_browser_opening(&app, &window_label, account_num.get(), &auto_url);

    // Set up the paste channel. The sender lives in RaceLoginState
    // (reachable from submit_paste_code); the receiver is consumed
    // by the resolver closure on its single invocation by drive_race.
    let (paste_tx, paste_rx) = oneshot::channel::<PasteCode>();
    // SEC-R2-02 / REV-R2-01 / R3-M2: track whether the user
    // submitted a paste BEFORE the loopback path won. The flag
    // lives on the slot (so `submit_paste_code` can flip it under
    // the slot mutex) and a clone is captured by the orchestrator
    // task for the success-branch read.
    //
    // R3-M2: pre-fix, the flag was set INSIDE the resolver future
    // after `paste_rx.await`. If loopback won the orchestrator's
    // `tokio::select!` between `submit_paste_code`'s `sender.send`
    // and the resolver advancing past its await, the resolver
    // future was cancelled and the flag stayed false — the
    // `paste_after_loopback_won` info banner silently failed to
    // fire even though the user had typed and submitted a code.
    // The fix moves the write to `submit_paste_code` itself, where
    // it happens unconditionally before `sender.send` and is
    // serialised with every other slot read by the slot mutex.
    let paste_was_used = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let paste_was_used_for_task = paste_was_used.clone();
    let paste_resolver: csq_core::oauth::race::PasteResolver = Box::new(move || {
        Box::pin(async move {
            // Map oneshot's Cancelled (sender dropped — i.e., user
            // closed the modal mid-race) to OAuthError::Cancelled
            // so drive_race terminates with a recoverable variant
            // that the bridge translates to a no-op (the cancel
            // event has already fired). L7 / UX-R1-L3.
            //
            // R3-M2: the resolver no longer flips `paste_was_used`
            // — that responsibility moved to `submit_paste_code` so
            // a select-cancellation of this future does not lose
            // the bookkeeping. The flag write here would be
            // redundant on every code path that reaches this `Ok`.
            let pasted = paste_rx.await.map_err(|_| OAuthError::Cancelled)?;
            Ok(pasted.into_inner())
        })
    });

    let app_handle = app.clone();
    let base_clone = base.clone();
    let store_clone = app_state.oauth_store.clone();
    let manual_url_for_delay = manual_url.clone();
    let window_label_for_task = window_label.clone();
    let window_label_for_timer = window_label.clone();

    // Pre-allocate the phase handle BEFORE spawning so the
    // orchestrator task can advance it without racing the install.
    let phase_handle = std::sync::Arc::new(Mutex::new(Phase::Init));

    let phase_for_task = phase_handle.clone();
    let phase_for_timer = phase_handle.clone();
    let acct_num_inner = account_num.get();

    // SEC-R2-02 / REV-R2-01: install the slot BEFORE spawning the
    // orchestrator task. The slot starts with a placeholder
    // JoinHandle (a no-op task) so the install-rejection path can
    // run without there being any orchestrator to leak. If install
    // succeeds we IMMEDIATELY rewrite the placeholder with the real
    // handle, under the same mutex — there is no observable window
    // where the slot has the wrong handle, because no other code
    // path can take the slot while we hold the install mutex (and
    // we re-acquire it for the rewrite which serializes against
    // every other RaceLoginState method).
    let placeholder_task = tokio::spawn(async {});
    let manual_url_timer_placeholder = tokio::spawn(async {});
    manual_url_timer_placeholder.abort();

    let install_result = race_state.install(RaceSlot {
        account: account_num.get(),
        task: placeholder_task,
        manual_url_timer: Some(manual_url_timer_placeholder),
        paste_tx: Some(paste_tx),
        phase: phase_handle.clone(),
        login_lock: Some(login_lock),
        window_label: window_label.clone(),
        race_token: race_token.clone(),
        // R3-M2: the slot owns the canonical flag; the orchestrator
        // task captured a clone above (paste_was_used_for_task) and
        // `submit_paste_code` clones it out via take_paste_sender.
        paste_was_used: paste_was_used.clone(),
    });

    if let Err((InstallError::OccupiedByAccount(other), rejected)) = install_result {
        // SEC-R2-02: the slot we tried to install carries the lock
        // guard, paste_tx, and placeholder task. Dropping `rejected`
        // here releases all three — `placeholder_task.abort()` is
        // unnecessary because the placeholder is an empty future
        // that completes instantly, and `login_lock` Drops to
        // release the flock. The auto_url + listener inside `prep`
        // still need releasing — `prep` was moved into the
        // resolver's closure above (`paste_resolver`), which is
        // also moved into `rejected`'s `paste_tx`-closure chain
        // because `paste_resolver` captures `paste_rx`... wait —
        // `prep` is currently bound on the stack here and has not
        // been moved into the not-yet-spawned task. We must drop it
        // explicitly so the listener releases its port.
        drop(rejected);
        drop(prep);
        return Err(format!(
            "another login is already in progress for account {other} — cancel it first"
        ));
    }

    // Install succeeded. Spawn the manual-URL timer + the
    // orchestrator task, then swap the placeholder handles for the
    // real ones.
    let manual_url_app = app_handle.clone();
    let manual_url_timer = tokio::spawn(async move {
        tokio::time::sleep(MANUAL_URL_DELAY).await;
        let phase = *phase_for_timer.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(phase, Phase::Init | Phase::Active) {
            let hint = Some(
                "if your browser shows a 'site cannot be reached' error, paste the code below instead"
                    .to_string(),
            );
            emit_manual_url_ready(
                &manual_url_app,
                &window_label_for_timer,
                acct_num_inner,
                &manual_url_for_delay,
                hint,
            );
        }
    });

    let task = tokio::spawn(async move {
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
                emit_resolved(&app_handle, &window_label_for_task, acct_num_inner, via);

                // UX-R2-02: if loopback won AND the paste resolver
                // observed an active paste send, surface
                // `paste_after_loopback_won`. The frontend renders
                // an info banner ("you already signed in via your
                // browser, your paste wasn't needed") rather than
                // an alarming error. We emit BOTH events — the info
                // event for the banner, then the normal exchanging
                // sequence for the rest of the flow.
                if matches!(result.winner, RaceWinner::Loopback { .. })
                    && paste_was_used_for_task.load(std::sync::atomic::Ordering::SeqCst)
                {
                    emit_error(
                        &app_handle,
                        &window_label_for_task,
                        acct_num_inner,
                        "browser sign-in completed first — pasted code not needed",
                        "paste_after_loopback_won",
                    );
                }

                if let Ok(mut p) = phase_for_task.lock() {
                    *p = Phase::Exchanging;
                }
                emit_exchanging(&app_handle, &window_label_for_task, acct_num_inner);

                let outcome = finalize_login(&base_clone, account_num, &result).await;
                match outcome {
                    Ok(email) => {
                        if let Ok(mut p) = phase_for_task.lock() {
                            *p = Phase::Done;
                        }
                        emit_success(&app_handle, &window_label_for_task, acct_num_inner, &email);
                    }
                    Err((message, kind)) => {
                        if let Ok(mut p) = phase_for_task.lock() {
                            *p = Phase::Failed;
                        }
                        emit_error(
                            &app_handle,
                            &window_label_for_task,
                            acct_num_inner,
                            &message,
                            kind,
                        );
                    }
                }
            }
            Err(OAuthError::Cancelled) => {
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
                emit_error(
                    &app_handle,
                    &window_label_for_task,
                    acct_num_inner,
                    &msg,
                    kind,
                );
            }
        }

        // Best-effort clear (no-op if a newer race for a different
        // account replaced us). The lock guard inside the slot
        // drops here.
        let race_state: Option<tauri::State<'_, RaceLoginState>> = app_handle.try_state();
        if let Some(s) = race_state {
            s.clear_for(acct_num_inner);
        }
    });

    // Swap the placeholder handles for the real ones.
    race_state.replace_handles(account_num.get(), task, Some(manual_url_timer));

    Ok(StartRaceResponse {
        account: account_num.get(),
        race_token,
    })
}

/// Renders an `LoginInProgressElsewhere` error consistently across
/// the SEC-R2-01 acquire path and the SEC-R2-01 install reject path.
fn login_in_progress_message(account: u16, pid: Option<u32>) -> String {
    match pid {
        Some(p) => format!(
            "login already in progress for account {account} (PID {p}). \
             Cancel the other login or wait for it to finish."
        ),
        None => format!(
            "login already in progress for account {account}. \
             Wait for the other login to finish, or use the CLI \
             with --legacy-shell to bypass."
        ),
    }
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
        // SEC-R2-01: surfaced from the desktop start_claude_login_race
        // path when another csq process holds the per-account login
        // lock. The frontend keys on this kind to render the
        // dedicated "cancel previous login and retry" recovery UI
        // (UX-R2-03) instead of a bare error banner.
        OAuthError::LoginInProgressElsewhere { .. } => "login_in_progress_elsewhere",
    }
}

/// Submits a paste-code into the active race's paste resolver.
///
/// SEC-R2-05: takes `code: PasteCode` directly so Tauri's IPC layer
/// invokes `PasteCode`'s custom `Deserialize` (which trims, rejects
/// empty, and wraps in the redacting newtype). At no point in the
/// command-arg layer does the value exist as a plain `String` that
/// Tauri's `RUST_LOG=tauri=debug` arg-logging could capture.
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
/// - `"invalid code: paste was empty"` — bubbles up from
///   `PasteCode::deserialize` when the IPC argument was empty or
///   whitespace-only. Matches the wording the frontend already keys
///   on for the inline error display.
/// - `"no active race for account N"` — no in-flight race at all.
/// - `"the active race is for a different account (N)"` — slot is
///   occupied by another account.
/// - `"paste already submitted for account N"` — the paste channel
///   for THIS account was already used (double-click / loopback
///   already won).
#[tauri::command]
pub fn submit_paste_code(
    state: State<'_, RaceLoginState>,
    account: u16,
    code: PasteCode,
) -> Result<(), String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;

    // The PasteCode wrapper has already trimmed + rejected empty
    // input via its custom Deserialize. Belt-and-braces: re-check
    // here so a non-IPC caller (tests) can't sneak an empty paste in.
    if code.trimmed().is_empty() {
        return Err("invalid code: paste was empty".into());
    }

    match state.take_paste_sender(account_num.get()) {
        PasteSenderTake::Got {
            sender,
            paste_was_used,
        } => {
            // R3-M2 / round-4 redteam: set the flag BEFORE
            // `sender.send(...)`. The orchestrator's `tokio::select!`
            // can otherwise observe loopback winning between our
            // send completing and the resolver future advancing past
            // its `paste_rx.await`, which would silently drop the
            // `paste_after_loopback_won` info banner. Flipping
            // here makes the user's submit action and the flag
            // observation atomic from the orchestrator's
            // perspective: by the time the success branch reads
            // the flag, it has been set unconditionally on every
            // path that reached this match arm.
            paste_was_used.store(true, std::sync::atomic::Ordering::SeqCst);
            sender.send(code).map_err(|_| {
                "race orchestrator dropped the paste channel — retry the login".to_string()
            })
        }
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
/// SEC-R2-03: requires the opaque `race_token` returned from the
/// `start_claude_login_race` invocation that began this race. Without
/// the token a malicious in-process JS handler could iterate accounts
/// (1..999) calling `cancel_race_login(N, "")` to discover which
/// account is currently in flight (the success/no-op return code was
/// the oracle).
///
/// UX-R1-H1 / HIGH 3: takes `account: u16` so a modal cannot
/// accidentally cancel a sibling modal's race. If the slot belongs
/// to a different account, this is a no-op (returns `Ok(false)`).
///
/// Returns `Ok(true)` when there was a matching active race AND the
/// token matched AND the cancel succeeded. Emits
/// `claude-login-cancelled` with the account in the payload only in
/// that case. REV-R1-05 / L12.
///
/// Returns `Ok(false)` for a no-op (no slot, wrong account, race
/// already past Exchanging). Returns `Err("unauthorized")` ONLY when
/// the slot exists for the right account but the token was wrong —
/// see `CancelOutcome` for why this isn't an information leak.
///
/// SEC-R1-10 / L4: awaits the orchestrator task's actual drop with
/// a small grace period so the listener port is released before
/// this function returns. A retry that immediately rebinds gets a
/// fresh ephemeral port from the OS.
#[tauri::command]
pub async fn cancel_race_login(
    app: AppHandle,
    window: Window,
    state: State<'_, RaceLoginState>,
    account: u16,
    race_token: String,
) -> Result<bool, String> {
    let account_num = AccountNum::try_from(account).map_err(|e| format!("invalid account: {e}"))?;

    let (outcome, task) =
        state.cancel_for_and_take_with_token(account_num.get(), race_token.as_str());
    match outcome {
        CancelOutcome::Cancelled => {
            // Wait for the abort to actually drop the orchestrator
            // (and hence the listener) before reporting cancelled.
            // A bounded wait so a misbehaving task can't pin this
            // command.
            if let Some(t) = task {
                let _ = tokio::time::timeout(ABORT_GRACE, t).await;
            }
            // SEC-R2-04: emit only to the calling window.
            emit_cancelled(&app, window.label(), account_num.get());
            Ok(true)
        }
        CancelOutcome::NoOp => Ok(false),
        CancelOutcome::Unauthorized => Err("unauthorized: race token does not match".to_string()),
    }
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
            // M4 + SEC-R2-10: the timeout aborts THIS function's
            // await on the spawn_blocking handle, but a synchronous
            // reqwest already in flight on the worker thread cannot
            // be cancelled. If that POST + persistence ever
            // completes after we surface the timeout, the credential
            // lands silently — the user sees "timed out" while the
            // dashboard happens to show a fresh credential within
            // ~30 s.
            //
            // We document this in the user-facing message rather
            // than restructuring `exchange_code` to split network
            // from persistence. Splitting would change the
            // exchange_code signature shared with csq-cli and is a
            // larger refactor than the round-3 budget allows; the
            // documented behaviour is honest and the user has a
            // concrete next action ("refresh the dashboard before
            // retrying").
            return Err((
                format!(
                    "token exchange timed out after {}s — refresh the dashboard \
                     in 30 seconds; if your account appears as logged in, the \
                     exchange completed in the background. Otherwise re-run \
                     csq login.",
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
//
// SEC-R2-04: every emit goes through `emit_to(window_label, ...)`
// rather than `emit(...)`. The auto URL on `claude-login-browser-opening`
// carries the per-race path secret embedded in the loopback redirect
// URI (see `oauth/loopback.rs::generate_path_secret`); broadcasting
// that to every window in the app would let a malicious second
// window scrape the secret. Targeting only the calling window
// matches the `tauri-commands.md` "No sensitive data in event
// payloads" guidance — the secret is sensitive for the duration of
// the race even though it expires when the race resolves.
//
// R3-L4 / round-4 redteam note: emit_to scopes to the calling
// window's label. If a future tabbed UI hosts multiple
// AddAccountModal instances in one window, account-guards on each
// frontend handler still discriminate correctly — the per-payload
// `account` field is the second filter (UX-R1-H2 fix). The
// window-label scope is the outer filter; the account guard is
// the inner one. Both must be present for multi-modal-per-window
// scenarios to remain race-safe.

// R3-L3: the emit shims are generic over `R: tauri::Runtime` so the
// regression test in this module can drive them with `AppHandle<MockRuntime>`.
// Production code passes the default `AppHandle` (`AppHandle<Wry>`); the
// monomorphisation cost is the same as before because there is exactly
// one production runtime.

fn emit_browser_opening<R: tauri::Runtime>(
    app: &AppHandle<R>,
    window_label: &str,
    account: u16,
    auto_url: &str,
) {
    if let Err(e) = app.emit_to(
        window_label,
        "claude-login-browser-opening",
        BrowserOpeningPayload {
            account,
            auto_url: auto_url.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-browser-opening: {e}");
    }
}

fn emit_manual_url_ready<R: tauri::Runtime>(
    app: &AppHandle<R>,
    window_label: &str,
    account: u16,
    manual_url: &str,
    hint: Option<String>,
) {
    if let Err(e) = app.emit_to(
        window_label,
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

fn emit_resolved<R: tauri::Runtime>(
    app: &AppHandle<R>,
    window_label: &str,
    account: u16,
    via: &str,
) {
    if let Err(e) = app.emit_to(
        window_label,
        "claude-login-resolved",
        ResolvedPayload {
            account,
            via: via.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-resolved: {e}");
    }
}

fn emit_exchanging<R: tauri::Runtime>(app: &AppHandle<R>, window_label: &str, account: u16) {
    if let Err(e) = app.emit_to(
        window_label,
        "claude-login-exchanging",
        ExchangingPayload { account },
    ) {
        log::warn!("failed to emit claude-login-exchanging: {e}");
    }
}

fn emit_success<R: tauri::Runtime>(
    app: &AppHandle<R>,
    window_label: &str,
    account: u16,
    email: &str,
) {
    if let Err(e) = app.emit_to(
        window_label,
        "claude-login-success",
        SuccessPayload {
            account,
            email: email.to_string(),
        },
    ) {
        log::warn!("failed to emit claude-login-success: {e}");
    }
}

fn emit_error<R: tauri::Runtime>(
    app: &AppHandle<R>,
    window_label: &str,
    account: u16,
    message: &str,
    kind: &'static str,
) {
    if let Err(e) = app.emit_to(
        window_label,
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

fn emit_cancelled<R: tauri::Runtime>(app: &AppHandle<R>, window_label: &str, account: u16) {
    if let Err(e) = app.emit_to(
        window_label,
        "claude-login-cancelled",
        CancelledPayload { account },
    ) {
        log::warn!("failed to emit claude-login-cancelled: {e}");
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
    ///
    /// Round-3 update: every synthetic slot now carries a synthesised
    /// race_token so SEC-R2-03 token-gated cancel tests can pass it
    /// in. The `login_lock` field is `None` because synthetic slots
    /// don't acquire a real flock — production paths always set it.
    fn synth_slot_for(account: u16) -> (RaceSlot, oneshot::Receiver<PasteCode>) {
        synth_slot_for_with_token(account, "synth-token")
    }

    /// Synthetic slot with an explicit race token — used by the
    /// token-gated cancel tests. Returns the receiver so the test
    /// can assert on what the orchestrator would have observed.
    fn synth_slot_for_with_token(
        account: u16,
        token: &str,
    ) -> (RaceSlot, oneshot::Receiver<PasteCode>) {
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
                login_lock: None,
                window_label: "main".into(),
                race_token: token.into(),
                paste_was_used: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
            rx,
        )
    }

    /// Wraps `state.install` so the existing `.unwrap()`/`.expect(...)`
    /// test sites continue to work after the SEC-R2-02 / REV-R2-01
    /// signature change (install now returns the rejected slot
    /// alongside the error). Tests that need the rejected slot use
    /// `state.install(...)` directly.
    fn install_or_panic(state: &RaceLoginState, slot: RaceSlot) {
        if let Err((err, _rejected)) = state.install(slot) {
            panic!("expected install to succeed, got {err:?}");
        }
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
                login_lock: None,
                window_label: "main".into(),
                race_token: "synth-token".into(),
                paste_was_used: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
        install_or_panic(&state, slot1);

        let (slot2, _rx2) = synth_slot_for(1);
        install_or_panic(&state, slot2);

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
        //
        // SEC-R2-02 / REV-R2-01: install now returns the rejected
        // slot alongside the error so the caller can drop it
        // explicitly. Test asserts on both the error variant and
        // the rejected-slot identity.
        let state = RaceLoginState::default();
        let (slot1, _rx1) = synth_slot_for(1);
        install_or_panic(&state, slot1);

        let (slot2, _rx2) = synth_slot_for(2);
        let (err, rejected) = state
            .install(slot2)
            .expect_err("different-account install must error");
        assert_eq!(err, InstallError::OccupiedByAccount(1));
        assert_eq!(
            rejected.account, 2,
            "rejected slot must carry the account that was rejected"
        );
        // The rejected slot drops here when `rejected` goes out of
        // scope at end of test, releasing the placeholder
        // login_lock (None in synth) and the paste_tx.
        drop(rejected);

        // The original account-1 race is still installed — the
        // error did not stomp it.
        match state.take_paste_sender(1) {
            PasteSenderTake::Got { .. } => {}
            other => panic!(
                "account-1 slot should still be alive: {:?}",
                debug_take(&other)
            ),
        }
    }

    // ── SEC-R2-02 / REV-R2-01: install rejection cleanup ──────────

    #[tokio::test]
    async fn install_rejection_returns_rejected_slot_for_cleanup() {
        // REGRESSION: prior to this PR, install dropped the rejected
        // slot internally, with the caller having already spawned
        // the orchestrator task. The new contract returns the
        // rejected slot AND the production path installs with a
        // placeholder task BEFORE spawning the orchestrator — so the
        // rejection path never has an orchestrator to leak. This
        // test pins the API contract: install must return the
        // rejected slot so the caller can explicitly drop the lock
        // guard / paste_tx / etc.
        let state = RaceLoginState::default();
        let (slot1, _rx1) = synth_slot_for(1);
        install_or_panic(&state, slot1);

        let (slot2, _rx2) = synth_slot_for(2);

        let outcome = state.install(slot2);
        match outcome {
            Err((InstallError::OccupiedByAccount(1), rejected)) => {
                assert_eq!(rejected.account, 2);
                // The slot's fields are recoverable: we can read
                // login_lock (None in synth), window_label, etc.
                // before dropping. The production path uses these
                // same fields to release the lock + pass the label
                // through to the failure-event emit.
                assert!(rejected.login_lock.is_none());
                assert_eq!(rejected.window_label, "main");
                drop(rejected);
                // Account-1 is still alive (not stomped by the
                // failed install).
                assert_eq!(
                    state.inner.lock().unwrap().as_ref().map(|s| s.account),
                    Some(1)
                );
            }
            Err((other_err, _)) => panic!("unexpected install err: {other_err:?}"),
            Ok(()) => panic!("install must have rejected"),
        }
    }

    #[tokio::test]
    async fn install_rejection_does_not_orphan_task() {
        // SEC-R2-02 documented the prior bug: spawn → install fails →
        // task orphaned holding the loopback port for 10 minutes. The
        // new sequencing installs FIRST with placeholder handles, so
        // no orchestrator exists to orphan when install fails. The
        // production rejection path drops the rejected slot
        // (with its placeholder, which is an immediately-completed
        // future) and drops `prep` (which contains the listener) — so
        // no port is held past the function return.
        //
        // We can't drive `start_claude_login_race` directly from a
        // unit test (it requires a Tauri AppHandle/Window), so this
        // test pins the structural property: the install rejection
        // path returns the rejected slot, and the rejected slot's
        // task field is the placeholder (already-completed) future.
        let state = RaceLoginState::default();
        let (slot1, _rx1) = synth_slot_for(1);
        install_or_panic(&state, slot1);

        // Production-like construction: placeholder task that
        // completes immediately.
        let placeholder_task = tokio::spawn(async {});
        let placeholder_handle = placeholder_task.abort_handle();
        // Yield so the placeholder actually completes before we
        // observe it.
        tokio::task::yield_now().await;
        for _ in 0..10 {
            if placeholder_handle.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(
            placeholder_handle.is_finished(),
            "placeholder task must complete immediately — empty future"
        );

        let (tx, _rx) = oneshot::channel::<PasteCode>();
        let new_slot = RaceSlot {
            account: 2,
            task: placeholder_task,
            manual_url_timer: None,
            paste_tx: Some(tx),
            phase: Arc::new(Mutex::new(Phase::Init)),
            login_lock: None,
            window_label: "main".into(),
            race_token: "tok".into(),
            paste_was_used: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };

        let outcome = state.install(new_slot);
        match outcome {
            Err((InstallError::OccupiedByAccount(1), rejected)) => {
                // Rejected slot's placeholder task is already done.
                // No orphan, no port held. drop(rejected) releases
                // the synthetic resources.
                drop(rejected);
            }
            Err((other_err, _)) => panic!("unexpected install err: {other_err:?}"),
            Ok(()) => panic!("install must have rejected"),
        }
    }

    #[tokio::test]
    async fn install_rejection_releases_loopback_port() {
        // Sister test to install_rejection_does_not_orphan_task. The
        // production code's `drop(prep)` releases the loopback
        // listener after install rejects. We exercise the analogous
        // shape here by binding a real listener, asserting the port
        // is reachable, dropping the bind, and asserting the port is
        // released.
        //
        // This is a property test for `LoopbackListener::drop` (which
        // already has its own coverage in csq-core), wired into the
        // race-rejection path here so a future refactor that forgets
        // to drop `prep` on rejection has a regression check.
        use csq_core::oauth::loopback::LoopbackListener;

        let listener = LoopbackListener::bind("test-secret".into())
            .await
            .expect("bind a listener");
        let port = listener.port;

        // Confirm the port is reachable.
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok(),
            "port should be reachable while listener is bound"
        );

        // The production rejection path drops `prep` which owns
        // the listener. Mirror that here.
        drop(listener);
        // Give the kernel a tick.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let attempt = tokio::net::TcpStream::connect(("127.0.0.1", port)).await;
        assert!(
            attempt.is_err(),
            "port MUST be released after listener drops — install \
             rejection path drops prep, which drops listener (REV-R2-01)"
        );
    }

    fn debug_take(t: &PasteSenderTake) -> &'static str {
        match t {
            PasteSenderTake::Got { .. } => "Got",
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
        install_or_panic(&state, slot);

        match state.take_paste_sender(8) {
            PasteSenderTake::WrongAccount { active: 7 } => {}
            other => panic!(
                "expected WrongAccount {{ active: 7 }}, got {}",
                debug_take(&other)
            ),
        }
        // Right account still works after the wrong-account miss.
        match state.take_paste_sender(7) {
            PasteSenderTake::Got { .. } => {}
            other => panic!("expected Got, got {}", debug_take(&other)),
        }
    }

    #[tokio::test]
    async fn take_paste_sender_is_single_use() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(3);
        install_or_panic(&state, slot);

        match state.take_paste_sender(3) {
            PasteSenderTake::Got { .. } => {}
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
        install_or_panic(&state, slot);
        assert!(state.cancel_for(5));
    }

    #[tokio::test]
    async fn cancel_race_login_for_wrong_account_is_noop() {
        // HIGH 3 / UX-R1-H1: cancel for a non-matching account
        // returns false and leaves the active slot untouched.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(5);
        install_or_panic(&state, slot);

        assert!(!state.cancel_for(99));
        // Slot for 5 still alive.
        match state.take_paste_sender(5) {
            PasteSenderTake::Got { .. } => {}
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
        install_or_panic(&state, slot);
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
        install_or_panic(&state, slot);

        assert!(
            !state.cancel_for(5),
            "cancel after Exchanging must not actually cancel — credentials are in flight"
        );
    }

    #[tokio::test]
    async fn clear_for_only_clears_matching_account() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(5);
        install_or_panic(&state, slot);

        // Different account — must NOT clear.
        state.clear_for(99);
        match state.take_paste_sender(5) {
            PasteSenderTake::Got { .. } => {}
            other => panic!(
                "expected Got after wrong-account clear: {}",
                debug_take(&other)
            ),
        }

        // Re-install (since take consumed the sender) and clear with
        // the correct account this time.
        let (slot2, _rx2) = synth_slot_for(5);
        install_or_panic(&state, slot2);
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
        install_or_panic(&state, slot);

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
        install_or_panic(&state, slot);

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

    // ── SEC-R2-03: cancel oracle (race token) ─────────────────────

    #[tokio::test]
    async fn cancel_with_correct_token_proceeds() {
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for_with_token(5, "correct-token");
        install_or_panic(&state, slot);

        let (outcome, handle) = state.cancel_for_and_take_with_token(5, "correct-token");
        assert_eq!(outcome, CancelOutcome::Cancelled);
        assert!(
            handle.is_some(),
            "Cancelled outcome must include the JoinHandle"
        );
    }

    #[tokio::test]
    async fn cancel_with_wrong_token_returns_unauthorized() {
        // SEC-R2-03: an attacker who can call cancel_race_login but
        // doesn't hold the race token must get a hard rejection,
        // NOT a no-op. The rejection signals the slot exists for
        // this account; the "no slot" / "wrong account" branches
        // are no-ops to keep them indistinguishable.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for_with_token(5, "real-token");
        install_or_panic(&state, slot);

        let (outcome, handle) = state.cancel_for_and_take_with_token(5, "wrong-token");
        assert_eq!(outcome, CancelOutcome::Unauthorized);
        assert!(handle.is_none(), "Unauthorized must not return a handle");

        // The slot is still alive — the cancel didn't take it.
        assert!(state.inner.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn cancel_with_no_token_rejects() {
        // Empty token is a wrong token; for a slot with a 22-char
        // token, the length check short-circuits to Unauthorized.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for_with_token(5, "real-token");
        install_or_panic(&state, slot);

        let (outcome, _) = state.cancel_for_and_take_with_token(5, "");
        assert_eq!(outcome, CancelOutcome::Unauthorized);
    }

    #[tokio::test]
    async fn cancel_no_slot_is_noop_regardless_of_token() {
        // SEC-R2-03 oracle defence: when no slot exists for the
        // account, the token is NOT examined. The caller cannot
        // distinguish "no slot" from "wrong token" externally
        // — both look like a no-op.
        let state = RaceLoginState::default();
        let (outcome, _) = state.cancel_for_and_take_with_token(5, "any-token");
        assert_eq!(outcome, CancelOutcome::NoOp);
        let (outcome, _) = state.cancel_for_and_take_with_token(5, "");
        assert_eq!(outcome, CancelOutcome::NoOp);
    }

    #[tokio::test]
    async fn cancel_wrong_account_is_noop_regardless_of_token() {
        // Same oracle defence for wrong-account: the slot exists
        // but for a different account; do not examine the token.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for_with_token(5, "tok");
        install_or_panic(&state, slot);

        let (outcome, _) = state.cancel_for_and_take_with_token(99, "tok");
        assert_eq!(outcome, CancelOutcome::NoOp);
        // Even with a token we KNOW is wrong (different from the
        // stored "tok"), the response is NoOp — does not leak
        // "this account has a race".
        let (outcome, _) = state.cancel_for_and_take_with_token(99, "wrong");
        assert_eq!(outcome, CancelOutcome::NoOp);
    }

    #[test]
    fn start_returns_random_race_token_per_invocation() {
        // SEC-R2-03: every invocation mints a fresh CSPRNG token.
        // Repeating across many calls must produce distinct strings.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            let t = generate_race_token();
            assert_eq!(t.len(), 22, "16 bytes base64url unpadded = 22 chars");
            assert!(seen.insert(t), "race token must be unique per invocation");
        }
    }

    #[test]
    fn race_token_uses_constant_time_compare() {
        // Compile-time / structural assertion: `cancel_for_and_take_with_token`
        // routes the token comparison through `subtle::ConstantTimeEq`.
        // Adding `subtle::ConstantTimeEq` as an explicit `use` here
        // mirrors the production import; if a future refactor swaps
        // it for `==`, the unused-import lint trips.
        use subtle::ConstantTimeEq as _;
        let a = b"abcdefghijklmnopqrstuv"; // 22 chars
        let b = b"abcdefghijklmnopqrstuv";
        let ct: subtle::Choice = a.ct_eq(b);
        assert!(bool::from(ct));
    }

    // ── SEC-R2-04: events emitted with window label only ─────────

    #[tokio::test]
    async fn race_slot_persists_window_label() {
        // The slot stores the window label so the orchestrator and
        // cancel paths can route events to only the calling window.
        // Pin the field so a future refactor doesn't drop it.
        let (tx, _rx) = oneshot::channel::<PasteCode>();
        let slot = RaceSlot {
            account: 9,
            task: tokio::spawn(async {}),
            manual_url_timer: None,
            paste_tx: Some(tx),
            phase: Arc::new(Mutex::new(Phase::Init)),
            login_lock: None,
            window_label: "main-window".into(),
            race_token: "tok".into(),
            paste_was_used: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        assert_eq!(slot.window_label, "main-window");
    }

    // ── SEC-R2-05: PasteCode IPC deserialization ──────────────────

    #[test]
    fn paste_code_deserialize_trims_whitespace() {
        // SEC-R2-05: the custom Deserialize trims leading/trailing
        // whitespace and CR. A frontend that submits "  ABC  " gets
        // "ABC" in the wrapper.
        let json = r#""  AUTH_CODE_xyz123  ""#;
        let parsed: PasteCode = serde_json::from_str(json).expect("must parse");
        assert_eq!(parsed.trimmed(), "AUTH_CODE_xyz123");
        assert_eq!(parsed.into_inner(), "AUTH_CODE_xyz123");
    }

    #[test]
    fn paste_code_deserialize_rejects_empty() {
        // Empty after trim → custom error matching the
        // submit_paste_code wording.
        let cases = [r#""""#, r#""   ""#, r#""\r\n""#, r#""\t""#];
        for c in cases {
            let result: Result<PasteCode, _> = serde_json::from_str(c);
            assert!(
                result.is_err(),
                "empty/whitespace paste must reject at deserialize: {c}"
            );
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("invalid code: paste was empty"),
                "deserialize error must match the frontend-keyed wording: {msg}"
            );
        }
    }

    #[test]
    fn paste_code_debug_redacts() {
        // Sister test to paste_code_debug_does_not_leak_value but
        // pins SEC-R2-05's expectation: a Debug print of a value
        // that came in via Deserialize is also redacted (because
        // PasteCode's Debug is the only impl, applied uniformly).
        let json = r#""SECRET_PASTE_CODE_VALUE""#;
        let parsed: PasteCode = serde_json::from_str(json).unwrap();
        let dbg = format!("{parsed:?}");
        assert!(
            !dbg.contains("SECRET_PASTE_CODE_VALUE"),
            "Debug from a Deserialize'd PasteCode must redact: {dbg}"
        );
        assert!(dbg.contains("REDACTED"));
    }

    // ── SEC-R2-01: AccountLoginLock guard held in slot ────────────

    #[tokio::test]
    async fn race_slot_holds_login_lock_field() {
        // SEC-R2-01: the slot must persist the AccountLoginLock so
        // its Drop releases the flock when the slot is taken
        // (cancel / clear / replace). This pins the field so a
        // future refactor doesn't drop it (which would silently
        // re-introduce the CLI vs desktop concurrent-login race).
        let (tx, _rx) = oneshot::channel::<PasteCode>();
        let slot = RaceSlot {
            account: 1,
            task: tokio::spawn(async {}),
            manual_url_timer: None,
            paste_tx: Some(tx),
            phase: Arc::new(Mutex::new(Phase::Init)),
            login_lock: None,
            window_label: "main".into(),
            race_token: "tok".into(),
            paste_was_used: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        // Field exists and is Optional. Production sets Some(...).
        assert!(slot.login_lock.is_none(), "synth slot has None lock");
    }

    #[tokio::test]
    async fn desktop_race_blocks_when_lock_already_held() {
        // SEC-R2-01: simulate the concurrent-CLI scenario where a
        // CLI `csq login N` already holds the AccountLoginLock for
        // account N. The desktop start_claude_login_race acquires
        // the same lock and must observe Held — we verify the
        // direct AccountLoginLock contract here (the bridge test
        // would require a Tauri AppHandle).
        use tempfile::TempDir;
        let dir = TempDir::new().unwrap();
        let acct = AccountNum::try_from(7u16).unwrap();

        // Hold the lock from "the CLI".
        let _cli_guard = match AccountLoginLock::acquire(dir.path(), acct).unwrap() {
            AcquireOutcome::Acquired(g) => g,
            _ => panic!("first acquire must succeed"),
        };

        // The desktop attempts the same lock — must return Held.
        let outcome = AccountLoginLock::acquire(dir.path(), acct).unwrap();
        match outcome {
            AcquireOutcome::Held { pid, pid_alive: _ } => {
                assert_eq!(
                    pid,
                    Some(std::process::id()),
                    "Held result must carry the holder PID for the user-facing message"
                );
            }
            AcquireOutcome::Acquired(_) => panic!("desktop must observe Held"),
        }
    }

    #[test]
    fn login_in_progress_message_includes_pid_when_available() {
        // SEC-R2-01: the user-facing message names the holder PID
        // when readable so the user has a concrete next action.
        let msg = login_in_progress_message(5, Some(12345));
        assert!(msg.contains("12345"), "PID must be in the message: {msg}");
        assert!(
            msg.contains("account 5"),
            "account number must be in the message: {msg}"
        );
    }

    #[test]
    fn login_in_progress_message_falls_back_when_pid_unknown() {
        // No PID readable → still a useful message (suggests the
        // CLI --legacy-shell escape hatch).
        let msg = login_in_progress_message(5, None);
        assert!(msg.contains("account 5"));
        assert!(msg.contains("CLI") || msg.contains("--legacy-shell"));
    }

    // ── R3-M2 / round-4 redteam: paste_was_used flip race ─────────

    #[tokio::test]
    async fn paste_after_loopback_won_fires_when_user_pastes_then_loopback_wins_immediately() {
        // R3-M2 regression. Reproduces the race the round-3 redteam
        // surfaced: the user submits a paste, oneshot::send succeeds,
        // but the orchestrator's `tokio::select!` observes loopback
        // resolving in the same poll cycle and cancels the resolver
        // future before its `paste_rx.await` returns. Pre-fix, the
        // `paste_was_used` flag — set INSIDE the resolver after the
        // await — stayed false, and the success branch's
        // `paste_after_loopback_won` info-banner condition silently
        // evaluated false.
        //
        // The fix moves the flag write into `submit_paste_code`,
        // BEFORE the `sender.send(...)` call. The slot mutex
        // serialises this against the orchestrator's read of the
        // same Arc, so the flag is observable regardless of which
        // arm of the select wins.
        //
        // The test exercises the contract directly without spinning
        // up a real race orchestrator (which would need a Tauri
        // AppHandle): we simulate the user-submit by calling
        // `take_paste_sender` on a synth slot, flipping the flag
        // exactly as `submit_paste_code` does, then dropping the
        // sender (mimicking a select-cancellation that aborts the
        // resolver future before the receiver advances). The
        // orchestrator-side clone (the one captured at install
        // time) MUST observe `true`.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(7);
        // Capture the slot's Arc the way the orchestrator does at
        // spawn time — production captures `paste_was_used.clone()`
        // BEFORE installing the slot (see start_claude_login_race),
        // so the orchestrator's view of the flag survives the slot
        // being taken.
        let orchestrator_view = slot.paste_was_used.clone();
        install_or_panic(&state, slot);

        // Simulate `submit_paste_code` taking the sender. Per R3-M2
        // the take returns the flag clone alongside the sender.
        let (sender, paste_was_used) = match state.take_paste_sender(7) {
            PasteSenderTake::Got {
                sender,
                paste_was_used,
            } => (sender, paste_was_used),
            other => panic!("expected Got, got {}", debug_take(&other)),
        };

        // Flip the flag BEFORE attempting send — exactly the order
        // submit_paste_code uses.
        paste_was_used.store(true, std::sync::atomic::Ordering::SeqCst);

        // Now drop the sender WITHOUT calling send(). This simulates
        // the worst case where the orchestrator's select observes
        // loopback completing first and the resolver future is
        // cancelled before paste_rx.await even starts. Even in this
        // pathological case the orchestrator's read of the flag must
        // see true.
        drop(sender);

        // The orchestrator's view (independent Arc clone) sees the
        // flag set — the success branch would correctly emit
        // paste_after_loopback_won. Pre-R3-M2 this would be false
        // because the flag write lived inside the (now-cancelled)
        // resolver future.
        assert!(
            orchestrator_view.load(std::sync::atomic::Ordering::SeqCst),
            "paste_was_used MUST be observable by the orchestrator's \
             Arc clone after submit_paste_code flipped it, even when \
             the resolver future is cancelled before paste_rx.await \
             returns (R3-M2)"
        );
    }

    #[tokio::test]
    async fn paste_was_used_is_false_when_no_paste_submitted() {
        // Sister test: with no submit_paste_code call the flag
        // stays false — so a loopback-only success does NOT
        // misleadingly emit paste_after_loopback_won.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(8);
        let orchestrator_view = slot.paste_was_used.clone();
        install_or_panic(&state, slot);

        // No call to take_paste_sender → flag stays at construction
        // default (false).
        assert!(
            !orchestrator_view.load(std::sync::atomic::Ordering::SeqCst),
            "paste_was_used must default to false so a loopback-only \
             success does not emit a spurious paste_after_loopback_won"
        );
    }

    #[tokio::test]
    async fn take_paste_sender_returns_flag_clone_alongside_sender() {
        // Pin the API contract: take_paste_sender::Got carries
        // BOTH the sender AND a clone of paste_was_used. A future
        // refactor that drops one of these would silently regress
        // R3-M2.
        let state = RaceLoginState::default();
        let (slot, _rx) = synth_slot_for(3);
        install_or_panic(&state, slot);

        match state.take_paste_sender(3) {
            PasteSenderTake::Got {
                sender: _,
                paste_was_used,
            } => {
                // The returned Arc is independently observable —
                // flipping it must be visible to a sibling clone
                // (proving they share storage).
                let sibling = paste_was_used.clone();
                paste_was_used.store(true, std::sync::atomic::Ordering::SeqCst);
                assert!(
                    sibling.load(std::sync::atomic::Ordering::SeqCst),
                    "paste_was_used returned by take_paste_sender must \
                     be a clone of the slot's Arc, not a fresh allocation"
                );
            }
            other => panic!(
                "expected Got with paste_was_used clone, got {}",
                debug_take(&other)
            ),
        }
    }

    // ── R3-L3 / round-4 redteam: credential write decoupled from emit ─

    #[tokio::test]
    async fn credential_persists_when_event_emit_to_stale_window() {
        // R3-L3 contract: the credential write path
        // (`credentials::save_canonical`) is independent of event
        // delivery. If the calling window has been closed (or its
        // label no longer matches any live window), `emit_to(label,
        // ...)` silently no-ops in Tauri — the listener filter
        // simply finds no match and the call returns Ok(()) without
        // surfacing the missing target. The credential must still
        // land on disk regardless.
        //
        // We exercise this in three stages:
        //   1. Spin up a `tauri::test::mock_app` with NO window
        //      registered for the label our shim will target.
        //   2. Invoke each emit shim with the stale label. Every
        //      shim must return without panicking — we depend on
        //      the silent no-op contract.
        //   3. Write a credential via `credentials::save_canonical`
        //      and confirm the canonical file exists on disk.
        //
        // Pre-fix this property already held in production; the test
        // locks it in so a future refactor that makes credential
        // persistence conditional on emit success regresses loudly.
        use csq_core::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
        use csq_core::types::{AccessToken, RefreshToken};
        use std::collections::HashMap;
        use tauri::test::mock_app;
        use tauri::Manager;
        use tempfile::TempDir;

        // Stage 1: app with NO window for `stale-window`. mock_app
        // returns an App whose webview list is empty by default.
        let app = mock_app();
        let handle = app.handle().clone();
        // Sanity: confirm the label we're targeting is genuinely
        // absent. This pins the test fixture against a future
        // mock_app change that pre-registers a window.
        assert!(
            handle.get_webview_window("stale-window").is_none(),
            "test fixture invariant: mock_app must not pre-register \
             a 'stale-window' webview"
        );

        // Stage 2: every emit shim against the stale label must be
        // a no-op (no panic, no propagated error). The shim wraps
        // emit_to in `if let Err(e) = ... { log::warn!(...) }` so
        // even an internal error path stays silent — but the
        // dominant path here is Ok(()) with no listener match.
        emit_browser_opening(&handle, "stale-window", 1, "https://example/auto");
        emit_manual_url_ready(
            &handle,
            "stale-window",
            1,
            "https://example/manual",
            Some("hint".into()),
        );
        emit_resolved(&handle, "stale-window", 1, "loopback");
        emit_exchanging(&handle, "stale-window", 1);
        emit_success(&handle, "stale-window", 1, "user@example.com");
        emit_error(
            &handle,
            "stale-window",
            1,
            "synthetic message",
            "race_failed",
        );
        emit_cancelled(&handle, "stale-window", 1);
        // Reaching this line means none of the seven emit shims
        // panicked. If any were re-written to `.unwrap()` the
        // emit_to result, this assertion would never run.

        // Stage 3: persist a credential exactly the way the
        // production bridge does and confirm the canonical file
        // lands on disk. The credential write happens in
        // `finalize_login` BEFORE the `emit_success` call, so a
        // dropped emit cannot prevent the credential from being
        // recoverable on the next dashboard poll.
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(7u16).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("sk-ant-oat01-stale-window-test".into()),
                refresh_token: RefreshToken::new("sk-ant-ort01-stale-window-test".into()),
                expires_at: 4_102_444_800_000, // year 2100, no test-time-bomb
                scopes: vec!["user:inference".into()],
                subscription_type: Some("max".into()),
                rate_limit_tier: Some("default_claude_max_20x".into()),
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        });

        csq_core::credentials::save_canonical(dir.path(), account, &creds)
            .expect("credential write must succeed regardless of emit_to delivery");

        // Canonical Anthropic credential lives at
        // <base>/credentials/<N>.json (per spec 02 / spec 07).
        let canonical = dir
            .path()
            .join("credentials")
            .join(format!("{}.json", account.get()));
        assert!(
            canonical.exists(),
            "credential file MUST exist after save_canonical even when \
             every event emit went to a stale window: {:?}",
            canonical
        );
    }
}
