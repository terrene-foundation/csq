//! Owner alert when account slots newly become LOGIN-NEEDED.
//!
//! The refresher classifies OAuth refresh errors and writes the sticky per-slot
//! sentinel (`refresh::sentinel`). This module watches that classified state
//! and sends the owner ONE combined Telegram ping per pass, listing every slot
//! that newly needs `csq login N`, through the existing outbound core
//! ([`crate::bridge::notify::send_owner_ping_at`]). There is no second send
//! path: every refusal the notify core enforces (disabled, unpinned, kill
//! switch, budget, scrub, audit-or-refuse) applies unchanged.
//!
//! # What fires
//!
//! A slot is eligible when [`crate::refresh::sentinel::sentinel_scan`] classifies it
//! [`crate::refresh::sentinel::LoginNeededState::LoginNeeded`] and it has no entry in the persisted alert
//! state. A slot that is merely refresh-failing with an unrecorded cause
//! ([`crate::refresh::sentinel::LoginNeededState::Unknown`]) never fires by itself, and an Unknown marker
//! is not a clear either (only an ABSENT marker is), so a LoginNeeded → Unknown
//! → LoginNeeded flap cannot repeat the ping.
//!
//! All slots eligible in one pass share ONE message (`alert_text`); the first
//! pass of a build carrying this module therefore sends one ping for every slot
//! that is ALREADY login-needed, not one per slot. If the list would not fit the
//! notify text cap it is cut with "and N more"; the unlisted slots keep no entry
//! and are announced by the next pass.
//!
//! # Persisted state, re-arming and the 24 h cool-off
//!
//! `<base>/login-needed-alerts.json` (0600, written through the target-taking
//! private-temp factory `write_private_tmp_synced_retained` and published by
//! `replace`, `security.md` §5a: the writer is retained through publication and
//! the factory never unlinks a colliding path) holds one entry per slot that was
//! alerted or is being retried. A restart reads it back and does not resend.
//!
//! When a slot's marker is ABSENT in a readable scan (a successful login or
//! refresh clears it, [`crate::refresh::sentinel::clear_broker_failed`]) its entry records
//! `cleared_at` rather than disappearing. A slot that is re-marked is announced
//! again only once `COOLOFF_SECS` (24 h) have passed since the FIRST clear, so a
//! slot that flaps cannot ping more than once a day; the entry is dropped once the
//! cool-off has elapsed with the marker still absent. An entry whose alert was
//! never delivered (`done` false) is dropped the moment its marker clears, with no
//! cool-off: nothing was announced, so a re-death alerts normally. A scan that could not be
//! read in full ([`crate::refresh::sentinel::SentinelScan::readable`] false, which includes any
//! directory-entry error) changes nothing: no clear, no re-arm, no send.
//!
//! The state file is read through `load_state`, which separates two outcomes.
//!
//! - The read itself FAILS (an I/O error, or a path that cannot be inspected): the
//!   state is unknown, so the pass changes nothing, sends nothing and logs
//!   `login_alert_state_unreadable`, exactly as an unreadable sentinel scan does.
//!   `state_readable` exposes the same verdict to `csq doctor`.
//! - The file is read and REJECTED (corrupt, unknown version, over the size cap,
//!   not a regular file, a symlink, or not private-and-ours): it is NOT treated as
//!   empty. Every slot that is login-needed at that moment is recorded as ALREADY
//!   alerted (quietly) and one warning is logged (`login_alert_state_untrusted`),
//!   except a slot an other-version file that still parses showed as not yet
//!   delivered, which keeps its entry and its alert. The bound: a slot whose alert
//!   was lost with the file, or that went login-needed while the file was
//!   untrustworthy, is never announced for that episode; it is announced again
//!   after it clears and the cool-off passes. A MISSING file is the first-run
//!   case above, not corruption. A missing-file answer on Windows is confirmed
//!   through `platform::fs::confirm_absent` inside the reader.
//!
//! A stored `cleared_at` or `last_attempt` more than `FUTURE_SKEW_SECS` beyond
//! the pass clock is invalid (a backwards clock step or a forged value): the
//! cool-off ends and the entry re-arms (`login_alert_state_timestamp_future`), so
//! such a value can never silence a slot. A clock reading of zero or less (the
//! clock is unavailable) skips the pass before any write-ahead
//! (`login_alert_clock_unavailable`).
//!
//! # Retry policy (bounded, no spam)
//!
//! Before a send, every slot already at `MAX_ATTEMPTS` is abandoned
//! (`login_alert_gave_up`) without a send, so a panic or crash between the
//! write-ahead and the outcome can never allow more than `MAX_ATTEMPTS`
//! sends per slot. Then the attempt is written ahead of the send; if that write
//! fails nothing is sent (`login_alert_state_unwritable`). After the send:
//!
//! - delivered → the listed slots are DONE.
//! - a FINAL refusal (`Disposition::Final`: bridge not configured, disabled,
//!   unpinned, kill switch engaged, base dir overridden, home unavailable, or a
//!   text refusal) → DONE, no retry: enabling the bridge later does not replay.
//! - a TRANSIENT failure (`Disposition::Retry`) → not marked alerted; retried no
//!   sooner than `RETRY_INTERVAL_SECS` later, at most `MAX_ATTEMPTS`
//!   attempts, then DONE with `login_alert_gave_up`. A transport failure is
//!   ambiguous (the core never retries it because the message may have arrived),
//!   so a retry after one can duplicate, bounded by `MAX_ATTEMPTS`.
//!
//! # Concurrency, clock, shutdown
//!
//! A pass holds the advisory lock `<base>/login-needed-alerts.lock` for its whole
//! length, so two passes — in this process or another — cannot both read the
//! state and both send; a pass that cannot take it does nothing
//! (`login_alert_pass_busy`). The clock is a function read when the eligibility
//! decision is made and again immediately before each send, so a long state
//! write cannot hand the budget a stale time. The pass makes at most one send per
//! call; the shutdown token is checked before the state work and again before
//! the write-ahead and the send.
//!
//! A send already in flight has NO single bound owned by this module, and the
//! blocking task is not aborted, so runtime teardown may wait for the whole of
//! it. The steps of `notify::send_owner_ping_with` and what limits each:
//! config load and kill-switch read (size-capped file reads, no lock); the
//! budget reservation (`budget::reserve`, lock bounded by `LOCK_ATTEMPTS` 50 x
//! `LOCK_DELAY` 10 ms = 500 ms); the bot-token vault read (limited only by the
//! vault backend; this module sets no limit); the audit intent and outcome
//! writes (the `.chain-lock` plus the signing-key load in
//! `audit::op_emit::emit_record`, whose key budget is `PRE_CUTOFF_BUDGET` 200 ms
//! or `POST_CUTOFF_BUDGET` 5 s); and the HTTP request (`REQUEST_TIMEOUT_SECS`
//! 45 s in `bridge::telegram_api`, set on the client builder). No total is
//! claimed.
//!
//! The pass is spawned detached (`spawn_pass`) so a slow or failing ping never
//! delays a refresh. A panic inside it is contained by `catch_unwind` in
//! `spawn_pass` (the lock guard is released by the unwind) and logged as
//! `login_alert_pass_panicked`.
//!
//! # Message
//!
//! `alert_text` is fixed vocabulary: slot numbers and the action. No email,
//! token, error body, reason tag or path ever enters it.

use crate::bridge::notify::{self, NotifyError, MAX_TEXT_UTF16};
use crate::platform::{fs, lock};
use crate::refresh::sentinel::{self, LoginNeededState};
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// State file name inside `<base_dir>`.
pub(crate) const STATE_FILE: &str = "login-needed-alerts.json";

/// Advisory lock held for the whole pass.
pub(crate) const LOCK_FILE: &str = "login-needed-alerts.lock";

/// Largest state file parsed: [`crate::types::MAX_ACCOUNTS`] entries of ~100
/// bytes fit in 128 KiB with room to spare.
const STATE_MAX_BYTES: u64 = 128 * 1024;

/// Schema version this build writes and accepts.
const STATE_VERSION: u32 = 1;

/// Most send attempts for one transition, retries included.
pub(crate) const MAX_ATTEMPTS: u8 = 3;

/// Earliest a transient failure is retried. Three times the 5-minute refresher
/// cadence, so a retry never lands on the very next pass.
pub(crate) const RETRY_INTERVAL_SECS: i64 = 900;

/// Quiet period after a slot clears before it can be announced again.
pub(crate) const COOLOFF_SECS: i64 = 86_400;

/// Largest amount a stored timestamp may exceed `now` before it is treated as
/// invalid (a backwards clock step or a forged value) and the entry fails toward
/// alerting. Five minutes: wider than ordinary NTP slew, far below the cool-off.
pub(crate) const FUTURE_SKEW_SECS: i64 = 300;

/// UTF-16 budget for the message: the notify cap less headroom, so the notify
/// core's own pre- and post-scrub length checks cannot refuse a full list.
const TEXT_BUDGET_UTF16: usize = MAX_TEXT_UTF16 - 100;

/// The one outbound surface the alert uses. Production wiring is
/// [`ProductionPinger`] over the notify core's public API; tests inject a fake.
pub(crate) trait OwnerPinger {
    /// Sends `text` to the pinned owner at `now` (unix seconds).
    fn ping(&self, text: &str, now: i64) -> Result<(), NotifyError>;
}

/// [`notify::send_owner_ping_at`] — the existing outbound core, unchanged,
/// behind two INDEPENDENT guards that keep a non-production process away from
/// the real per-user bridge:
///
/// 1. Under `cfg(test)` or the `test-utils` feature the real send is refused
///    unless `CSQ_TEST_ALLOW_REAL_OWNER_PING` is set, so a test harness can never
///    reach the real home's config or token by accident.
/// 2. The daemon's base directory must be the canonical per-user directory. The
///    core takes no directory argument; a daemon whose base dir is elsewhere keeps
///    its own bridge state there, and pinging through the canonical one would
///    split the bridge exactly as the core's own `BaseDirOverridden` refusal
///    guards against.
///
/// Either guard refuses with [`NotifyError::BaseDirOverridden`], which is
/// [`Disposition::Final`], before any send.
pub(crate) struct ProductionPinger {
    pub base_dir: std::path::PathBuf,
}

/// Whether this build may reach the real bridge (guard 1).
fn real_send_permitted() -> bool {
    #[cfg(any(test, feature = "test-utils"))]
    {
        std::env::var_os("CSQ_TEST_ALLOW_REAL_OWNER_PING").is_some()
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        true
    }
}

/// Both guards, then `send`. Pure over its inputs so a test can prove each guard
/// alone stops the send without touching the real home.
fn guarded_ping(
    base_dir: &Path,
    real_send_permitted: bool,
    canonical: Result<std::path::PathBuf, NotifyError>,
    text: &str,
    now: i64,
    send: &dyn Fn(&str, i64) -> Result<(), NotifyError>,
) -> Result<(), NotifyError> {
    if !real_send_permitted {
        return Err(NotifyError::BaseDirOverridden);
    }
    let canonical = canonical?;
    let same = match (canonical.canonicalize(), base_dir.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => canonical == base_dir,
    };
    if !same {
        return Err(NotifyError::BaseDirOverridden);
    }
    send(text, now)
}

impl OwnerPinger for ProductionPinger {
    fn ping(&self, text: &str, now: i64) -> Result<(), NotifyError> {
        guarded_ping(
            &self.base_dir,
            real_send_permitted(),
            notify::canonical_owner_ping_dir(),
            text,
            now,
            &|text, now| notify::send_owner_ping_at(text, now).map(|_| ()),
        )
    }
}

/// Whether a refused or failed ping should be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// The owner's configuration says no, or the text cannot be sent: stop.
    Final,
    /// A condition that may clear: retry within the bound.
    Retry,
}

/// Classifies a notify refusal. Exhaustive on purpose: a new [`NotifyError`]
/// variant must be given a disposition here before the crate compiles.
pub(crate) fn disposition(error: &NotifyError) -> Disposition {
    match error {
        NotifyError::NotConfigured
        | NotifyError::HomeUnavailable
        | NotifyError::BaseDirOverridden
        | NotifyError::Disabled
        | NotifyError::Unpinned
        | NotifyError::Killed
        | NotifyError::TextEmpty
        | NotifyError::TextTooLong
        | NotifyError::TextControl => Disposition::Final,
        NotifyError::ConfigUnreadable
        | NotifyError::KillSwitchUnreadable
        | NotifyError::RateLimited
        | NotifyError::BudgetLocked
        | NotifyError::BudgetUnreadable
        | NotifyError::ClockInvalid
        | NotifyError::TokenUnavailable
        | NotifyError::AuditUnavailable
        | NotifyError::SendFailed => Disposition::Retry,
    }
}

/// The alert text for `slots` (ascending, non-empty) and how many of them it
/// lists. Fixed vocabulary: slot numbers and the action.
///
/// One slot: ``csq: account slot 3 needs login — run `csq login 3` ``. Several:
/// ``csq: account slots 3, 7 need login — run `csq login <N>` for each``. A list
/// that would exceed [`TEXT_BUDGET_UTF16`] is cut to the longest prefix that fits
/// and ends "and N more"; the caller leaves the N unlisted slots for the next pass.
pub(crate) fn alert_text(slots: &[AccountNum]) -> (String, usize) {
    if let [only] = slots {
        return (
            format!("csq: account slot {only} needs login — run `csq login {only}`"),
            1,
        );
    }
    let build = |listed: usize| {
        let numbers = slots[..listed]
            .iter()
            .map(|slot| slot.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let more = slots.len() - listed;
        let tail = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        format!("csq: account slots {numbers}{tail} need login — run `csq login <N>` for each")
    };
    for listed in (1..=slots.len()).rev() {
        let text = build(listed);
        if text.encode_utf16().count() <= TEXT_BUDGET_UTF16 {
            return (text, listed);
        }
    }
    (build(1), 1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    slot: u16,
    /// Attempts made for this transition, the write-ahead one included.
    attempts: u8,
    /// Unix seconds of the latest attempt.
    last_attempt: i64,
    /// Alerted, finally refused, or given up: never sent again until re-armed.
    done: bool,
    /// Unix seconds when the marker was first seen absent; `None` while marked.
    #[serde(default)]
    cleared_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertState {
    version: u32,
    slots: Vec<Entry>,
}

impl AlertState {
    fn empty() -> Self {
        Self {
            version: STATE_VERSION,
            slots: Vec::new(),
        }
    }

    fn entry_mut_if_present(&mut self, slot: u16) -> Option<&mut Entry> {
        self.slots.iter_mut().find(|e| e.slot == slot)
    }

    fn entry_mut(&mut self, slot: u16) -> &mut Entry {
        if let Some(idx) = self.slots.iter().position(|e| e.slot == slot) {
            return &mut self.slots[idx];
        }
        self.slots.push(Entry {
            slot,
            attempts: 0,
            last_attempt: 0,
            done: false,
            cleared_at: None,
        });
        let last = self.slots.len() - 1;
        &mut self.slots[last]
    }
}

/// What reading the state file found.
enum Loaded {
    /// No file: a first run.
    Fresh,
    /// A readable, current-version file.
    Trusted(AlertState),
    /// The file was read in full (or refused on its own metadata) and failed the
    /// parse, version, size, regular-file or private-and-ours check. `undelivered`
    /// are the entries a parseable other-version file showed as not yet delivered
    /// (empty when nothing was readable); they are carried over, never marked done.
    Untrusted { undelivered: Vec<Entry> },
    /// The read itself failed (an I/O error, not a verdict on the content): the
    /// state is UNKNOWN, so the pass changes nothing.
    Unreadable,
}

/// Whether a reader error is the reader's own verdict on the file (not a regular
/// file, over the size cap, foreign-owned or group/other-writable, a symlink)
/// rather than an I/O failure. The reader builds its verdicts with
/// `io::Error::new`, which carries no OS error code; every error from the
/// operating system carries one, except the symlink refusal (`ELOOP` from
/// `O_NOFOLLOW`), which is the same verdict and is named explicitly.
fn is_content_verdict(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    match error.raw_os_error() {
        None => matches!(
            error.kind(),
            ErrorKind::InvalidData | ErrorKind::PermissionDenied
        ),
        #[cfg(unix)]
        Some(code) => code == libc::ELOOP,
        #[cfg(not(unix))]
        Some(_) => false,
    }
}

fn load_state(base_dir: &Path) -> Loaded {
    let path = base_dir.join(STATE_FILE);
    match fs::read_private_regular_nofollow_bounded(&path, STATE_MAX_BYTES) {
        Ok(None) => Loaded::Fresh,
        Ok(Some(bytes)) => match serde_json::from_slice::<AlertState>(&bytes) {
            Ok(state) if state.version == STATE_VERSION => Loaded::Trusted(state),
            Ok(state) => Loaded::Untrusted {
                undelivered: state
                    .slots
                    .into_iter()
                    .filter(|e| !e.done && e.cleared_at.is_none())
                    .filter(|e| AccountNum::try_from(e.slot).is_ok())
                    .collect(),
            },
            Err(_) => Loaded::Untrusted {
                undelivered: Vec::new(),
            },
        },
        Err(error) if is_content_verdict(&error) => Loaded::Untrusted {
            undelivered: Vec::new(),
        },
        Err(_) => Loaded::Unreadable,
    }
}

/// Whether the daemon can read its alert state: `false` only when the read
/// itself fails, the one condition under which every pass changes nothing and no
/// alert can ever be sent. A missing file and a content the daemon rewrites on
/// its next pass both count as readable. `csq doctor` calls this so it uses the
/// daemon's own reader and classifier.
pub fn state_readable(base_dir: &Path) -> bool {
    !matches!(load_state(base_dir), Loaded::Unreadable)
}

fn persist_state(base_dir: &Path, state: &AlertState) -> Result<(), ()> {
    let path = base_dir.join(STATE_FILE);
    let bytes = serde_json::to_vec(state).map_err(|_| ())?;
    let writer = fs::write_private_tmp_synced_retained(&path, &bytes).map_err(|_| ())?;
    writer.replace(&path).map_err(|_| ())
}

/// What one pass did; also the fields of its summary log line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PassReport {
    /// Slots listed in the message this pass attempted.
    pub slots: usize,
    /// Pings attempted (0 or 1 per pass).
    pub attempted: usize,
    /// Pings the notify core delivered.
    pub delivered: usize,
}

fn log_summary(report: &PassReport) {
    if report.attempted > 0 {
        tracing::info!(
            error_kind = "login_alert_pass",
            slots = report.slots,
            attempted = report.attempted,
            delivered = report.delivered,
            "login-needed alert pass finished"
        );
    }
}

/// One pass over the classified slot state.
///
/// Logs every failure with a fixed tag and returns normally; a panic inside is
/// contained by [`spawn_pass`], not here. `clock` returns unix seconds and is read
/// per decision and per send.
pub(crate) fn run_pass(
    base_dir: &Path,
    pinger: &dyn OwnerPinger,
    clock: &dyn Fn() -> i64,
    shutdown: &CancellationToken,
) -> PassReport {
    run_pass_with_store(base_dir, pinger, clock, shutdown, &persist_state)
}

/// [`run_pass`] with the state writer injected, so a test can make the write
/// fail while the read still succeeds.
fn run_pass_with_store(
    base_dir: &Path,
    pinger: &dyn OwnerPinger,
    clock: &dyn Fn() -> i64,
    shutdown: &CancellationToken,
    persist: &dyn Fn(&Path, &AlertState) -> Result<(), ()>,
) -> PassReport {
    let mut report = PassReport::default();
    if shutdown.is_cancelled() {
        return report;
    }
    let _guard = match lock::try_lock_file_bounded_nofollow(
        &base_dir.join(LOCK_FILE),
        1,
        std::time::Duration::ZERO,
    ) {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            tracing::debug!(
                error_kind = "login_alert_pass_busy",
                "another login-needed alert pass holds the lock"
            );
            return report;
        }
        Err(_) => {
            tracing::warn!(
                error_kind = "login_alert_lock_unavailable",
                "login-needed alert pass skipped: lock could not be taken"
            );
            return report;
        }
    };

    let scan = sentinel::sentinel_scan(base_dir);
    if !scan.readable {
        // UNDETERMINED is neither "cleared" nor an alert source.
        tracing::warn!(
            error_kind = "login_alert_scan_undetermined",
            "login-needed alert pass skipped: credentials directory not fully readable"
        );
        return report;
    }
    let now = clock();
    if now <= 0 {
        // No usable clock: nothing below can be dated, and a spent attempt could
        // not be timed. Change nothing.
        tracing::warn!(
            error_kind = "login_alert_clock_unavailable",
            "login-needed alert pass skipped: clock unavailable"
        );
        return report;
    }
    let marker = |slot: u16| {
        scan.states
            .iter()
            .find(|(account, _)| account.get() == slot)
            .map(|(_, state)| *state)
    };

    let mut state = match load_state(base_dir) {
        Loaded::Fresh => AlertState::empty(),
        Loaded::Trusted(state) => state,
        Loaded::Unreadable => {
            // "Cannot read" means change nothing: no send, no write.
            tracing::warn!(
                error_kind = "login_alert_state_unreadable",
                "login-needed alert pass skipped: state file could not be read"
            );
            return report;
        }
        Loaded::Untrusted { undelivered } => {
            // Quiet: every slot that is login-needed now counts as already alerted,
            // EXCEPT a slot the old file showed as not yet delivered, which keeps
            // its entry and is still owed its alert.
            tracing::warn!(
                error_kind = "login_alert_state_untrusted",
                "login-needed alert state untrusted; current login-needed slots recorded as alerted"
            );
            let mut quiet = AlertState::empty();
            for entry in undelivered {
                if !quiet.slots.iter().any(|e| e.slot == entry.slot) {
                    quiet.slots.push(entry);
                }
            }
            for account in scan.login_needed_slots() {
                if quiet.entry_mut_if_present(account.get()).is_some() {
                    continue;
                }
                let entry = quiet.entry_mut(account.get());
                entry.done = true;
                entry.last_attempt = now;
            }
            if persist(base_dir, &quiet).is_err() {
                tracing::warn!(
                    error_kind = "login_alert_state_unwritable",
                    "login-needed alert state could not be rewritten"
                );
            }
            return report;
        }
    };

    // Reconcile with the scan: clear, cool-off, drop, re-arm.
    let mut changed = false;
    // A stored timestamp beyond `now` plus the skew is invalid (a backwards clock
    // step or a forged value). It is never trusted: fail toward alerting.
    let future = now.saturating_add(FUTURE_SKEW_SECS);
    let mut saw_future = false;
    state.slots.retain_mut(|entry| {
        if entry.cleared_at.is_some_and(|t| t > future) {
            saw_future = true;
            changed = true;
            if marker(entry.slot).is_none() {
                return false;
            }
            entry.attempts = 0;
            entry.last_attempt = 0;
            entry.done = false;
            entry.cleared_at = None;
        }
        if entry.last_attempt > future {
            saw_future = true;
            changed = true;
            entry.last_attempt = 0;
        }
        true
    });
    if saw_future {
        tracing::warn!(
            error_kind = "login_alert_state_timestamp_future",
            "login-needed alert state held a timestamp in the future; entry re-armed"
        );
    }
    state.slots.retain(|entry| {
        let drop_it = marker(entry.slot).is_none()
            && (!entry.done
                || entry
                    .cleared_at
                    .is_some_and(|t| now >= t.saturating_add(COOLOFF_SECS)));
        changed |= drop_it;
        !drop_it
    });
    for entry in &mut state.slots {
        match (marker(entry.slot), entry.cleared_at) {
            (None, None) => {
                entry.cleared_at = Some(now);
                changed = true;
            }
            (Some(LoginNeededState::LoginNeeded { .. }), Some(t))
                if now >= t.saturating_add(COOLOFF_SECS) =>
            {
                entry.attempts = 0;
                entry.last_attempt = 0;
                entry.done = false;
                entry.cleared_at = None;
                changed = true;
            }
            _ => {}
        }
    }

    // Eligibility. The attempt bound is enforced HERE, before any write-ahead.
    let mut eligible: Vec<AccountNum> = Vec::new();
    for account in scan.login_needed_slots() {
        if let Some(entry) = state.entry_mut_if_present(account.get()) {
            if entry.done || entry.cleared_at.is_some() {
                continue;
            }
            if entry.attempts >= MAX_ATTEMPTS {
                entry.done = true;
                changed = true;
                tracing::warn!(
                    error_kind = "login_alert_gave_up",
                    cause = "attempt_bound",
                    slot = account.get(),
                    "login-needed alert abandoned after the attempt bound"
                );
                continue;
            }
            if now < entry.last_attempt.saturating_add(RETRY_INTERVAL_SECS) {
                continue;
            }
        }
        eligible.push(account);
    }

    let finish = |state: &AlertState, changed: bool| {
        if changed && persist(base_dir, state).is_err() {
            tracing::warn!(
                error_kind = "login_alert_state_unwritable",
                "login-needed alert state could not be persisted"
            );
        }
    };
    if eligible.is_empty() || shutdown.is_cancelled() {
        finish(&state, changed);
        return report;
    }

    let (text, listed) = alert_text(&eligible);
    let batch = &eligible[..listed];

    // Write-ahead: the attempt is durable BEFORE the send, so a state file that
    // cannot be written never becomes a ping per tick.
    for account in batch {
        let entry = state.entry_mut(account.get());
        entry.attempts = entry.attempts.saturating_add(1);
        entry.last_attempt = now;
    }
    if persist(base_dir, &state).is_err() {
        tracing::warn!(
            error_kind = "login_alert_state_unwritable",
            slots = listed,
            "login-needed alert not sent: attempt could not be persisted"
        );
        return report;
    }

    // The clock is read again here, per send, not reused from the decision.
    let send_now = clock();
    if send_now <= 0 {
        // The write-ahead already spent the attempt; give it back so a missing
        // clock never burns the bounded retries, and send nothing.
        for account in batch {
            let entry = state.entry_mut(account.get());
            entry.attempts = entry.attempts.saturating_sub(1);
            entry.last_attempt = 0;
        }
        tracing::warn!(
            error_kind = "login_alert_clock_unavailable",
            slots = listed,
            "login-needed alert not sent: clock unavailable"
        );
        finish(&state, true);
        return report;
    }
    report.slots = listed;
    report.attempted = 1;
    let outcome = pinger.ping(&text, send_now);
    match outcome {
        Ok(()) => {
            report.delivered = 1;
            for account in batch {
                state.entry_mut(account.get()).done = true;
            }
            tracing::info!(
                error_kind = "login_alert_sent",
                slots = listed,
                "owner pinged: slots need login"
            );
        }
        Err(error) => {
            let tag = error.error_kind_tag();
            let final_refusal = disposition(&error) == Disposition::Final;
            for account in batch {
                let entry = state.entry_mut(account.get());
                if final_refusal {
                    entry.done = true;
                } else if entry.attempts >= MAX_ATTEMPTS {
                    entry.done = true;
                    tracing::warn!(
                        error_kind = "login_alert_gave_up",
                        cause = tag,
                        slot = account.get(),
                        "login-needed alert abandoned after the attempt bound"
                    );
                }
            }
            if final_refusal {
                tracing::info!(
                    error_kind = tag,
                    slots = listed,
                    "login-needed alert refused by the owner bridge; not retried"
                );
            } else {
                tracing::warn!(
                    error_kind = "login_alert_retry_pending",
                    cause = tag,
                    slots = listed,
                    "login-needed alert failed; unfinished slots will be retried"
                );
            }
        }
    }
    finish(&state, true);
    log_summary(&report);
    report
}

/// Runs [`run_pass`] on a blocking thread WITHOUT the caller awaiting it, so the
/// refresh loop never waits on a ping. The returned handle is for tests; the
/// refresher drops it. A panic in the pass is caught here, logged, and the lock
/// guard is released by the unwind, so the next pass runs normally.
pub(crate) fn spawn_pass(
    base_dir: std::path::PathBuf,
    pinger: Arc<dyn OwnerPinger + Send + Sync>,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_pass(&base_dir, pinger.as_ref(), clock.as_ref(), &shutdown)
        }));
        if outcome.is_err() {
            tracing::warn!(
                error_kind = "login_alert_pass_panicked",
                "login-needed alert pass panicked"
            );
        }
    })
}

/// Unix seconds now; `0` on a pre-epoch clock (the notify budget refuses `0`).
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

    const NOW: i64 = 1_700_000_000;
    const HOUR: i64 = 3_600;

    fn acct(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn no_shutdown() -> CancellationToken {
        CancellationToken::new()
    }

    /// Fixed-clock pass.
    fn pass(base: &Path, pinger: &dyn OwnerPinger, now: i64) -> PassReport {
        run_pass(base, pinger, &|| now, &no_shutdown())
    }

    /// Scripted pinger: pops answers; repeats `Ok` when the script is empty.
    struct FakePinger {
        answers: RefCell<Vec<Result<(), NotifyError>>>,
        sent: RefCell<Vec<(String, i64)>>,
    }

    impl FakePinger {
        fn ok() -> Self {
            Self::scripted(Vec::new())
        }
        fn scripted(answers: Vec<Result<(), NotifyError>>) -> Self {
            Self {
                answers: RefCell::new(answers),
                sent: RefCell::new(Vec::new()),
            }
        }
        fn count(&self) -> usize {
            self.sent.borrow().len()
        }
    }

    impl OwnerPinger for FakePinger {
        fn ping(&self, text: &str, now: i64) -> Result<(), NotifyError> {
            self.sent.borrow_mut().push((text.to_owned(), now));
            let mut answers = self.answers.borrow_mut();
            if answers.is_empty() {
                Ok(())
            } else {
                answers.remove(0)
            }
        }
    }

    fn mark(base: &Path, n: u16, reason: &str) {
        sentinel::set_broker_failed(base, acct(n), reason).unwrap();
    }

    fn read_state(base: &Path) -> AlertState {
        match load_state(base) {
            Loaded::Trusted(state) => state,
            _ => panic!("state file missing or untrusted"),
        }
    }

    #[test]
    fn transition_sends_once_with_fixed_text() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::ok();
        let report = pass(dir.path(), &pinger, NOW);
        assert_eq!(
            report,
            PassReport {
                slots: 1,
                attempted: 1,
                delivered: 1
            }
        );
        assert_eq!(
            pinger.sent.borrow().as_slice(),
            &[(
                "csq: account slot 3 needs login — run `csq login 3`".to_owned(),
                NOW
            )]
        );
    }

    #[test]
    fn first_run_burst_is_one_combined_message() {
        let dir = tempfile::tempdir().unwrap();
        for slot in [7, 3, 9] {
            mark(dir.path(), slot, "invalid_grant");
        }
        let pinger = FakePinger::ok();
        let report = pass(dir.path(), &pinger, NOW);
        assert_eq!(pinger.count(), 1, "one ping for three slots");
        assert_eq!(report.slots, 3);
        assert_eq!(
            pinger.sent.borrow()[0].0,
            "csq: account slots 3, 7, 9 need login — run `csq login <N>` for each"
        );
        // No slot is announced twice.
        pass(dir.path(), &pinger, NOW + 2 * COOLOFF_SECS);
        assert_eq!(pinger.count(), 1);
    }

    #[test]
    fn a_later_transition_gets_its_own_message_naming_only_the_new_slot() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        mark(dir.path(), 8, "invalid_grant");
        pass(dir.path(), &pinger, NOW + 300);
        assert_eq!(pinger.count(), 2);
        assert_eq!(
            pinger.sent.borrow()[1].0,
            "csq: account slot 8 needs login — run `csq login 8`"
        );
    }

    #[test]
    fn a_list_over_the_cap_is_cut_with_and_n_more_and_the_rest_follows() {
        let slots: Vec<AccountNum> = (1..=crate::types::MAX_ACCOUNTS).map(acct).collect();
        let (text, listed) = alert_text(&slots);
        assert!(listed < slots.len(), "999 slots do not fit one message");
        assert!(text.encode_utf16().count() <= TEXT_BUDGET_UTF16);
        assert!(
            text.contains(&format!(" and {} more ", slots.len() - listed)),
            "{text}"
        );
        assert!(notify::validate_text(&text).is_ok());

        // End to end: every slot is announced exactly once across passes.
        let dir = tempfile::tempdir().unwrap();
        for slot in 1..=crate::types::MAX_ACCOUNTS {
            mark(dir.path(), slot, "invalid_grant");
        }
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        pass(dir.path(), &pinger, NOW + 1);
        pass(dir.path(), &pinger, NOW + 2);
        let state = read_state(dir.path());
        assert_eq!(state.slots.len(), usize::from(crate::types::MAX_ACCOUNTS));
        assert!(state.slots.iter().all(|e| e.done && e.attempts == 1));
        assert!(pinger.count() >= 2 && pinger.count() <= 3);
    }

    #[test]
    fn repeated_ticks_do_not_resend() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::ok();
        for tick in 0..5 {
            pass(dir.path(), &pinger, NOW + tick * 300);
        }
        assert_eq!(pinger.count(), 1);
    }

    #[test]
    fn restart_does_not_resend() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let first = FakePinger::ok();
        pass(dir.path(), &first, NOW);
        // A restarted daemon has no in-memory state: only the file carries over.
        let second = FakePinger::ok();
        pass(dir.path(), &second, NOW + 86_400);
        assert_eq!(first.count(), 1);
        assert_eq!(second.count(), 0);
        let raw = std::fs::read(dir.path().join(STATE_FILE)).unwrap();
        assert!(String::from_utf8(raw).unwrap().contains("\"slot\":3"));
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        pass(dir.path(), &FakePinger::ok(), NOW);
        let mode = std::fs::metadata(dir.path().join(STATE_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn recovery_rearms_the_slot_after_the_cooloff() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        // Successful login/refresh clears the marker.
        sentinel::clear_broker_failed(dir.path(), acct(3));
        pass(dir.path(), &pinger, NOW + 300);
        assert_eq!(pinger.count(), 1);
        // The slot dies again a full cool-off after the clear: a fresh transition.
        mark(dir.path(), 3, "invalid_grant");
        pass(dir.path(), &pinger, NOW + 300 + COOLOFF_SECS);
        assert_eq!(pinger.count(), 2);
    }

    #[test]
    fn a_flapping_slot_is_quiet_for_the_cooloff_then_announced_once() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        let cleared = NOW + 300;
        sentinel::clear_broker_failed(dir.path(), acct(3));
        pass(dir.path(), &pinger, cleared);
        // Re-marked an hour later, then flaps again: still inside the cool-off.
        mark(dir.path(), 3, "invalid_grant");
        pass(dir.path(), &pinger, cleared + HOUR);
        sentinel::clear_broker_failed(dir.path(), acct(3));
        pass(dir.path(), &pinger, cleared + 2 * HOUR);
        mark(dir.path(), 3, "invalid_grant");
        pass(dir.path(), &pinger, cleared + 3 * HOUR);
        assert_eq!(pinger.count(), 1, "flaps inside the cool-off stay quiet");
        // Still dead once 24 h have passed since the FIRST clear: one ping.
        pass(dir.path(), &pinger, cleared + COOLOFF_SECS);
        pass(dir.path(), &pinger, cleared + COOLOFF_SECS + 300);
        assert_eq!(pinger.count(), 2);
    }

    #[test]
    fn a_cleared_entry_is_dropped_after_the_cooloff() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        pass(dir.path(), &FakePinger::ok(), NOW);
        sentinel::clear_broker_failed(dir.path(), acct(3));
        pass(dir.path(), &FakePinger::ok(), NOW + 300);
        assert_eq!(read_state(dir.path()).slots.len(), 1);
        pass(dir.path(), &FakePinger::ok(), NOW + 300 + COOLOFF_SECS);
        assert!(read_state(dir.path()).slots.is_empty());
    }

    #[test]
    fn unreadable_scan_does_not_clear_or_rearm() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        // `credentials` replaced by a regular file: the scan is UNDETERMINED.
        std::fs::remove_dir_all(dir.path().join("credentials")).unwrap();
        std::fs::write(dir.path().join("credentials"), b"x").unwrap();
        pass(dir.path(), &pinger, NOW + 300);
        let state = read_state(dir.path());
        assert_eq!(state.slots.len(), 1);
        assert_eq!(state.slots[0].cleared_at, None, "no clear was recorded");
    }

    #[test]
    fn unknown_marker_never_fires() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 4, "oauth"); // legacy generic tag => Unknown
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        assert_eq!(pinger.count(), 0);
    }

    #[test]
    fn unknown_to_login_needed_fires() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 4, "oauth");
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        mark(dir.path(), 4, "invalid_grant");
        pass(dir.path(), &pinger, NOW + 300);
        assert_eq!(pinger.count(), 1);
    }

    #[test]
    fn login_needed_alerted_unknown_login_needed_sends_no_second_ping() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 4, "invalid_grant");
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        // A legacy writer overwrites the marker with a generic tag: Unknown.
        mark(dir.path(), 4, "oauth");
        pass(dir.path(), &pinger, NOW + 300);
        // Back to login-needed, well past the cool-off so only the Unknown
        // step could have re-armed it.
        mark(dir.path(), 4, "invalid_grant");
        pass(dir.path(), &pinger, NOW + 300 + 2 * COOLOFF_SECS);
        assert_eq!(pinger.count(), 1);
    }

    #[test]
    fn transient_refusal_retries_after_interval_then_gives_up() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::scripted(vec![
            Err(NotifyError::RateLimited),
            Err(NotifyError::SendFailed),
            Err(NotifyError::BudgetLocked),
        ]);
        pass(dir.path(), &pinger, NOW);
        // Not yet due: no resend.
        pass(dir.path(), &pinger, NOW + RETRY_INTERVAL_SECS - 1);
        assert_eq!(pinger.count(), 1);
        pass(dir.path(), &pinger, NOW + RETRY_INTERVAL_SECS);
        pass(dir.path(), &pinger, NOW + 2 * RETRY_INTERVAL_SECS);
        assert_eq!(pinger.count(), usize::from(MAX_ATTEMPTS));
        // Bound reached: abandoned, even much later.
        pass(dir.path(), &pinger, NOW + 100 * RETRY_INTERVAL_SECS);
        assert_eq!(pinger.count(), usize::from(MAX_ATTEMPTS));
    }

    #[test]
    fn transient_refusal_then_success_stops() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::scripted(vec![Err(NotifyError::TokenUnavailable)]);
        pass(dir.path(), &pinger, NOW);
        pass(dir.path(), &pinger, NOW + RETRY_INTERVAL_SECS);
        pass(dir.path(), &pinger, NOW + 2 * RETRY_INTERVAL_SECS);
        assert_eq!(pinger.count(), 2);
    }

    #[test]
    fn final_refusal_is_not_retried() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::scripted(vec![Err(NotifyError::Killed)]);
        pass(dir.path(), &pinger, NOW);
        pass(dir.path(), &pinger, NOW + 10 * RETRY_INTERVAL_SECS);
        assert_eq!(pinger.count(), 1);
    }

    #[test]
    fn every_notify_error_has_the_intended_disposition() {
        assert_eq!(disposition(&NotifyError::SendFailed), Disposition::Retry);
        assert_eq!(disposition(&NotifyError::RateLimited), Disposition::Retry);
        assert_eq!(disposition(&NotifyError::Disabled), Disposition::Final);
        assert_eq!(disposition(&NotifyError::NotConfigured), Disposition::Final);
    }

    #[test]
    fn unwritable_state_sends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        // Fresh read (no file), failing write: the write-ahead cannot be made.
        let pinger = FakePinger::ok();
        let failing = |_: &Path, _: &AlertState| Err(());
        for i in 0..3 {
            run_pass_with_store(
                dir.path(),
                &pinger,
                &|| NOW + i * RETRY_INTERVAL_SECS,
                &no_shutdown(),
                &failing,
            );
        }
        assert_eq!(pinger.count(), 0);
    }

    #[test]
    fn a_squatted_state_path_is_untrusted_and_sends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        std::fs::create_dir(dir.path().join(STATE_FILE)).unwrap();
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        pass(dir.path(), &pinger, NOW + RETRY_INTERVAL_SECS);
        assert_eq!(pinger.count(), 0);
    }

    #[test]
    fn corrupt_state_records_current_slots_as_alerted_and_stays_quiet() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        std::fs::write(dir.path().join(STATE_FILE), b"{not json").unwrap();
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        pass(dir.path(), &pinger, NOW + 300);
        assert_eq!(pinger.count(), 0, "a corrupt file never causes a re-ping");
        let state = read_state(dir.path());
        assert_eq!(state.slots.len(), 1);
        assert!(state.slots[0].done);
        // A slot that dies AFTER the rewrite is announced normally.
        mark(dir.path(), 8, "invalid_grant");
        pass(dir.path(), &pinger, NOW + 600);
        assert_eq!(pinger.count(), 1);
    }

    #[test]
    fn unknown_version_state_is_treated_like_corruption() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        std::fs::write(dir.path().join(STATE_FILE), br#"{"version":99,"slots":[]}"#).unwrap();
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        assert_eq!(pinger.count(), 0);
    }

    #[test]
    fn message_has_no_email_token_or_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("credentials")).unwrap();
        std::fs::write(
            dir.path().join("credentials/3.json"),
            br#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-FAKETEST-SECRETSECRET","email":"owner@example.com"}}"#,
        )
        .unwrap();
        mark(dir.path(), 3, "invalid_grant");
        mark(dir.path(), 5, "unauthorized_client");
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        let text = pinger.sent.borrow()[0].0.clone();
        let base = dir.path().to_string_lossy().into_owned();
        for forbidden in [
            "@",
            "sk-ant",
            "SECRET",
            "invalid_grant",
            "unauthorized_client",
            base.as_str(),
            "/",
        ] {
            assert!(
                !text.contains(forbidden),
                "{forbidden:?} leaked into {text:?}"
            );
        }
        assert_eq!(text, alert_text(&[acct(3), acct(5)]).0);
    }

    #[test]
    fn alert_text_passes_the_notify_core_text_validation() {
        // The em dash and backticks must not trip the core's control/format filter.
        assert!(notify::validate_text(&alert_text(&[acct(999)]).0).is_ok());
        assert!(notify::validate_text(&alert_text(&[acct(1), acct(2)]).0).is_ok());
    }

    #[test]
    fn the_clock_is_read_again_for_the_send() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let ticks = Cell::new(NOW);
        let clock = || {
            let value = ticks.get();
            ticks.set(value + 1);
            value
        };
        let pinger = FakePinger::ok();
        run_pass(dir.path(), &pinger, &clock, &no_shutdown());
        let sent_at = pinger.sent.borrow()[0].1;
        let decided_at = read_state(dir.path()).slots[0].last_attempt;
        assert!(
            sent_at > decided_at,
            "send {sent_at} vs decision {decided_at}"
        );
    }

    #[test]
    fn a_cancelled_shutdown_token_stops_the_pass_before_any_send() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let token = CancellationToken::new();
        token.cancel();
        let pinger = FakePinger::ok();
        let clock_reads = Cell::new(0usize);
        let clock = || {
            clock_reads.set(clock_reads.get() + 1);
            NOW
        };
        let report = run_pass(dir.path(), &pinger, &clock, &token);
        assert_eq!(report, PassReport::default());
        assert_eq!(pinger.count(), 0);
        assert!(
            !dir.path().join(STATE_FILE).exists(),
            "no write-ahead either"
        );
        // Only the FIRST shutdown check prevents the decision clock read: with it
        // deleted the pass runs to the later check and reads the clock once.
        assert_eq!(clock_reads.get(), 0, "the pass returned before any work");
    }

    #[test]
    fn cancellation_between_decision_and_send_stops_before_the_write_ahead() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let token = CancellationToken::new();
        let inner = token.clone();
        // The first clock read (the decision) cancels, as a shutdown arriving
        // mid-pass would.
        let clock = move || {
            inner.cancel();
            NOW
        };
        let pinger = FakePinger::ok();
        run_pass(dir.path(), &pinger, &clock, &token);
        assert_eq!(pinger.count(), 0);
        assert!(
            read_state_if_any(dir.path())
                .slots
                .iter()
                .all(|e| e.attempts == 0),
            "no attempt was written ahead"
        );
    }

    fn read_state_if_any(base: &Path) -> AlertState {
        match load_state(base) {
            Loaded::Trusted(state) => state,
            _ => AlertState::empty(),
        }
    }

    #[test]
    fn a_held_lock_makes_the_pass_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        // The pass accepts only a private (0600) lock file; the holder creates its
        // file with the default mode, which the pass would refuse for the wrong
        // reason. Pre-create it private on unix (Windows creates no file).
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .mode(0o600)
                .open(dir.path().join(LOCK_FILE))
                .unwrap();
        }
        // Held from another thread: a same-thread re-acquire succeeds on Windows.
        let held = lock::HeldOnOtherThread::hold(&dir.path().join(LOCK_FILE));
        let pinger = FakePinger::ok();
        let report = pass(dir.path(), &pinger, NOW);
        assert_eq!(report, PassReport::default());
        assert_eq!(pinger.count(), 0);
        drop(held);
        pass(dir.path(), &pinger, NOW);
        assert_eq!(pinger.count(), 1, "the lock was the only obstacle");
    }

    fn write_state(base: &Path, entries: Vec<Entry>) {
        let state = AlertState {
            version: STATE_VERSION,
            slots: entries,
        };
        persist_state(base, &state).unwrap();
    }

    fn undelivered(slot: u16, attempts: u8, last_attempt: i64) -> Entry {
        Entry {
            slot,
            attempts,
            last_attempt,
            done: false,
            cleared_at: None,
        }
    }

    /// A read that FAILS (as opposed to a file that reads and is rejected) is
    /// UNKNOWN: the pass changes nothing, so an undelivered entry and its retry
    /// budget survive and the alert is still sent once the read works again.
    /// Mapping every read error to `Untrusted` REDs this: slot 3 is marked done.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_state_file_changes_nothing_and_sends_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        write_state(dir.path(), vec![undelivered(3, 1, NOW)]);
        let path = dir.path().join(STATE_FILE);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::File::open(&path).is_ok() {
            // Running with privileges that bypass file modes: nothing to prove.
            return;
        }
        let pinger = FakePinger::ok();
        let report = pass(dir.path(), &pinger, NOW + RETRY_INTERVAL_SECS);
        assert_eq!(report, PassReport::default());
        assert_eq!(pinger.count(), 0);
        assert!(!state_readable(dir.path()));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(state_readable(dir.path()));
        assert_eq!(
            read_state(dir.path()).slots,
            vec![undelivered(3, 1, NOW)],
            "the unreadable pass wrote nothing"
        );
        pass(dir.path(), &pinger, NOW + RETRY_INTERVAL_SECS);
        assert_eq!(pinger.count(), 1, "the owed alert is sent once readable");
    }

    /// The reader's own verdicts are content verdicts; an OS error is not.
    #[test]
    fn only_the_readers_own_verdicts_count_as_content() {
        use std::io::{Error, ErrorKind};
        assert!(is_content_verdict(&Error::new(ErrorKind::InvalidData, "x")));
        assert!(is_content_verdict(&Error::new(
            ErrorKind::PermissionDenied,
            "x"
        )));
        assert!(!is_content_verdict(&Error::from_raw_os_error(5)));
        assert!(!is_content_verdict(&Error::new(ErrorKind::TimedOut, "x")));
        #[cfg(unix)]
        {
            assert!(is_content_verdict(&Error::from_raw_os_error(libc::ELOOP)));
            assert!(!is_content_verdict(&Error::from_raw_os_error(libc::EACCES)));
        }
    }

    /// A quiet rewrite never marks done a slot the old (parseable, other-version)
    /// file showed undelivered. Marking every current slot done REDs this.
    #[test]
    fn a_quiet_rewrite_keeps_an_undelivered_entry_owed() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        mark(dir.path(), 8, "invalid_grant");
        std::fs::write(
            dir.path().join(STATE_FILE),
            format!(
                r#"{{"version":99,"slots":[{{"slot":3,"attempts":1,"last_attempt":{NOW},"done":false}}]}}"#
            ),
        )
        .unwrap();
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW + RETRY_INTERVAL_SECS);
        assert_eq!(pinger.count(), 0, "the rewrite pass itself is quiet");
        let state = read_state(dir.path());
        let by_slot = |n: u16| state.slots.iter().find(|e| e.slot == n).unwrap().clone();
        assert!(!by_slot(3).done, "the undelivered slot stays owed");
        assert!(by_slot(8).done, "an unknown slot is recorded quietly");
        pass(dir.path(), &pinger, NOW + 2 * RETRY_INTERVAL_SECS);
        assert_eq!(pinger.count(), 1);
        assert!(pinger.sent.borrow()[0].0.contains("slot 3"));
        assert!(!pinger.sent.borrow()[0].0.contains('8'));
    }

    /// A stored `last_attempt` far in the future must not silence the slot.
    #[test]
    fn a_future_last_attempt_does_not_silence_the_slot() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        write_state(dir.path(), vec![undelivered(3, 1, i64::MAX)]);
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        assert_eq!(pinger.count(), 1);
    }

    /// A stored `cleared_at` far in the future must not hold the cool-off forever.
    #[test]
    fn a_future_cleared_at_ends_the_cooloff() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        write_state(
            dir.path(),
            vec![Entry {
                slot: 3,
                attempts: 1,
                last_attempt: NOW,
                done: true,
                cleared_at: Some(i64::MAX),
            }],
        );
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        assert_eq!(pinger.count(), 1);
        // A timestamp inside the skew is still honoured.
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        write_state(
            dir.path(),
            vec![Entry {
                slot: 3,
                attempts: 1,
                last_attempt: NOW,
                done: true,
                cleared_at: Some(NOW + FUTURE_SKEW_SECS),
            }],
        );
        let pinger = FakePinger::ok();
        pass(dir.path(), &pinger, NOW);
        assert_eq!(pinger.count(), 0);
    }

    /// With no usable clock nothing is written ahead and nothing is sent.
    #[test]
    fn an_unavailable_clock_spends_no_attempt_and_sends_nothing() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::ok();
        let report = run_pass(dir.path(), &pinger, &|| 0, &no_shutdown());
        assert_eq!(report, PassReport::default());
        assert_eq!(pinger.count(), 0);
        assert!(!dir.path().join(STATE_FILE).exists(), "no write-ahead");

        // A clock that fails only at the send read gives the attempt back.
        let reads = Cell::new(0usize);
        let clock = || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                NOW
            } else {
                0
            }
        };
        let report = run_pass(dir.path(), &pinger, &clock, &no_shutdown());
        assert_eq!(report, PassReport::default());
        assert_eq!(pinger.count(), 0);
        assert_eq!(read_state(dir.path()).slots[0].attempts, 0);
    }

    /// A never-delivered entry is dropped when its marker clears, so a re-death
    /// inside 24 h alerts normally instead of starting a cool-off for an alert
    /// that was never sent.
    #[test]
    fn a_never_delivered_entry_is_dropped_on_clear_and_a_redeath_alerts() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = FakePinger::scripted(vec![Err(NotifyError::SendFailed)]);
        pass(dir.path(), &pinger, NOW);
        assert_eq!(pinger.count(), 1);
        sentinel::clear_broker_failed(dir.path(), acct(3));
        pass(dir.path(), &pinger, NOW + 300);
        assert!(read_state(dir.path()).slots.is_empty(), "entry dropped");
        mark(dir.path(), 3, "invalid_grant");
        pass(dir.path(), &pinger, NOW + 600);
        assert_eq!(pinger.count(), 2, "a re-death alerts normally");
    }

    // ── ProductionPinger guards ────────────────────────────────────────

    fn recording_send(calls: &Cell<usize>) -> impl Fn(&str, i64) -> Result<(), NotifyError> + '_ {
        move |_, _| {
            calls.set(calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn guard_one_alone_stops_the_send_even_for_the_canonical_base() {
        let dir = tempfile::tempdir().unwrap();
        let calls = Cell::new(0);
        let result = guarded_ping(
            dir.path(),
            false,
            Ok(dir.path().to_path_buf()), // guard 2 would pass
            "x",
            NOW,
            &recording_send(&calls),
        );
        assert_eq!(result, Err(NotifyError::BaseDirOverridden));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn guard_two_alone_stops_the_send_for_a_non_canonical_base() {
        let base = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let calls = Cell::new(0);
        let result = guarded_ping(
            base.path(),
            true, // guard 1 would pass
            Ok(other.path().to_path_buf()),
            "x",
            NOW,
            &recording_send(&calls),
        );
        assert_eq!(result, Err(NotifyError::BaseDirOverridden));
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn both_guards_open_reaches_the_send() {
        let dir = tempfile::tempdir().unwrap();
        let calls = Cell::new(0);
        let result = guarded_ping(
            dir.path(),
            true,
            Ok(dir.path().to_path_buf()),
            "x",
            NOW,
            &recording_send(&calls),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_test_build_refuses_the_real_send_without_the_explicit_opt_in() {
        if std::env::var_os("CSQ_TEST_ALLOW_REAL_OWNER_PING").is_some() {
            return; // an operator opted in on purpose
        }
        assert!(!real_send_permitted());
        let pinger = ProductionPinger {
            base_dir: tempfile::tempdir().unwrap().path().to_path_buf(),
        };
        assert_eq!(
            pinger.ping("csq: x", NOW),
            Err(NotifyError::BaseDirOverridden)
        );
    }

    // ── Detached execution ─────────────────────────────────────────────

    struct BlockingPinger {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl OwnerPinger for BlockingPinger {
        fn ping(&self, _text: &str, _now: i64) -> Result<(), NotifyError> {
            let _ = self.entered.send(());
            let _ = self.release.lock().unwrap().recv();
            Err(NotifyError::SendFailed)
        }
    }

    fn fixed_clock(now: i64) -> Arc<dyn Fn() -> i64 + Send + Sync> {
        Arc::new(move || now)
    }

    #[tokio::test]
    async fn a_stalled_ping_never_blocks_the_caller() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let pinger: Arc<dyn OwnerPinger + Send + Sync> = Arc::new(BlockingPinger {
            entered: entered_tx,
            release: std::sync::Mutex::new(release_rx),
        });

        // `spawn_pass` returns while the ping is still blocked. The call runs on
        // its own OS thread with a deadline so a synchronous implementation FAILS
        // here instead of hanging the test.
        let (spawned_tx, spawned_rx) = std::sync::mpsc::channel();
        let (call_base, call_pinger) = (dir.path().to_path_buf(), pinger.clone());
        let runtime = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            let _entered = runtime.enter();
            let handle = spawn_pass(call_base, call_pinger, fixed_clock(NOW), no_shutdown());
            let _ = spawned_tx.send(handle);
        });
        let handle = tokio::task::spawn_blocking(move || {
            spawned_rx.recv_timeout(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap()
        .expect("spawn_pass returned while the ping was still stalled");
        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        })
        .await
        .unwrap();
        release_tx.send(()).unwrap();
        handle.await.unwrap();
    }

    struct PanickingPinger {
        calls: AtomicUsize,
    }

    impl OwnerPinger for PanickingPinger {
        fn ping(&self, _text: &str, _now: i64) -> Result<(), NotifyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            panic!("pinger panicked after the write-ahead");
        }
    }

    #[tokio::test]
    async fn a_panicking_ping_reopens_the_lock_and_sends_stop_at_the_attempt_bound() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        let pinger = Arc::new(PanickingPinger {
            calls: AtomicUsize::new(0),
        });
        let now = Arc::new(AtomicI64::new(NOW));
        for _ in 0..(MAX_ATTEMPTS as usize + 4) {
            let clock_now = now.clone();
            let handle = spawn_pass(
                dir.path().to_path_buf(),
                pinger.clone(),
                Arc::new(move || clock_now.load(Ordering::SeqCst)),
                no_shutdown(),
            );
            handle.await.expect("the panic is contained by spawn_pass");
            now.fetch_add(RETRY_INTERVAL_SECS, Ordering::SeqCst);
        }
        // Every pass could take the lock again (the unwind released it), and
        // the sends stopped at the bound even though no outcome was ever written.
        assert_eq!(
            pinger.calls.load(Ordering::SeqCst),
            usize::from(MAX_ATTEMPTS)
        );
    }

    struct AlwaysFails;

    impl OwnerPinger for AlwaysFails {
        fn ping(&self, _text: &str, _now: i64) -> Result<(), NotifyError> {
            Err(NotifyError::SendFailed)
        }
    }

    #[tokio::test]
    async fn a_failing_ping_pass_leaves_the_sentinel_untouched() {
        let dir = tempfile::tempdir().unwrap();
        mark(dir.path(), 3, "invalid_grant");
        spawn_pass(
            dir.path().to_path_buf(),
            Arc::new(AlwaysFails),
            fixed_clock(NOW),
            no_shutdown(),
        )
        .await
        .unwrap();
        assert!(sentinel::login_needed_state(dir.path(), acct(3)).is_login_needed());
    }
}
