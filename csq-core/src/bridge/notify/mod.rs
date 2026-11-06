//! Outbound owner ping — `csq notify-owner`.
//!
//! One implementation owns the whole flow: config, enablement, the kill
//! switch, the persisted rate limit, the disclosure scrub, the signed-chain
//! audit pair, and the Telegram call. The CLI is the only public surface in
//! v1; the daemon's own alerts call [`send_owner_ping_at`] in-process, with no
//! IPC route.
//!
//! # Invariants
//!
//! - The destination is ALWAYS `BridgeConfig.owner_chat_id`. No caller input
//!   can name a chat, a token or a config path.
//! - The kill switch is checked BEFORE the vault is opened, and re-checked
//!   immediately before the send. A marker that lands while the request is in
//!   flight cannot recall it — that window is stated, not denied.
//! - The bot token never enters argv, a log line, an error, an audit record or
//!   the process output. Transport errors are typed and fixed-text.
//! - The audit intent must be EMITTED (`Ok(true)`); a chain-broken skip or an
//!   error refuses the send. Every exit after a written intent writes an
//!   outcome. A refusal that wrote no intent is logged, not chained.
//! - Text is scrubbed before the wire: the live bot token structurally, then
//!   the shared token-shape set. The audit records the scrubbed byte length,
//!   `redacted` and the marker count — never the text.
//!
//! See `internal-design-docs` for the design and
//! `specs/12-audit-trail.md` for the audit record.

mod budget;
mod scrub;

use crate::audit::op_emit;
use crate::audit::types::{EventKind, EventPayload, OpOutcome, RecordId, TelegramOwnerPingPayload};
use crate::bridge::config::{self, BridgeConfig, BridgeConfigError};
use crate::bridge::secrets::{self, SecretError};
use crate::bridge::telegram_api::{ReqwestTransport, TelegramApiError, TelegramTransport};
use secrecy::{ExposeSecret, SecretString};
use std::path::{Path, PathBuf};

pub(crate) use budget::BudgetError;

/// Maximum message length, in UTF-16 code units (Telegram's own ceiling is
/// 4096; 4000 leaves headroom and bounds abuse). Measured AFTER the scrub,
/// because `[REDACTED]` can be longer than what it replaces.
pub const MAX_TEXT_UTF16: usize = 4_000;

/// What a successful send did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingOutcome {
    /// Whether the scrub changed the caller's text.
    pub redacted: bool,
    /// How many `[REDACTED]` markers the scrub added.
    pub redaction_count: usize,
    /// Fixed outcome tag: `sent` or `sent_redacted`.
    pub outcome: &'static str,
}

/// Fixed-text refusals and failures. No variant carries a path, an upstream
/// body, a URL or a secret (`security.md` MUST-2).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NotifyError {
    /// The bridge has no config file at all.
    #[error("the owner bridge is not configured")]
    NotConfigured,
    /// The user home directory could not be resolved.
    #[error("the user home directory could not be resolved")]
    HomeUnavailable,
    /// `CSQ_BASE_DIR` names a directory other than the canonical one. Under an
    /// override the bridge's config, kill marker and budget live elsewhere, so
    /// reading the canonical pin here would split the bridge state.
    #[error("CSQ_BASE_DIR points at a different bridge state directory")]
    BaseDirOverridden,
    /// The config file exists but cannot be read or parsed.
    #[error("the owner bridge config is unreadable or invalid")]
    ConfigUnreadable,
    /// The bridge is switched off.
    #[error("the owner bridge is disabled")]
    Disabled,
    /// No owner is pinned yet.
    #[error("no owner is pinned")]
    Unpinned,
    /// The phone kill switch is engaged.
    #[error("the owner bridge is stopped by the kill switch")]
    Killed,
    /// The kill-switch marker's state cannot be read.
    #[error("the owner bridge kill switch state is unreadable")]
    KillSwitchUnreadable,
    /// The minute or hour budget is spent.
    #[error("the owner ping rate limit has been reached")]
    RateLimited,
    /// Another process holds the budget lock past its budget.
    #[error("the owner ping budget is busy; try again")]
    BudgetLocked,
    /// The budget file exists but cannot be trusted.
    #[error("the owner ping budget state is unreadable")]
    BudgetUnreadable,
    /// The system clock is before the epoch, zero, or earlier than a stored
    /// window start.
    #[error("the system clock is invalid")]
    ClockInvalid,
    /// The text is empty or only whitespace.
    #[error("the message text is empty")]
    TextEmpty,
    /// The text exceeds [`MAX_TEXT_UTF16`] after scrubbing.
    #[error("the message text is too long")]
    TextTooLong,
    /// The text contains a control character other than `\n`, or a Unicode
    /// format/bidi control.
    #[error("the message text contains a forbidden control character")]
    TextControl,
    /// The bot token is not stored or cannot be read.
    #[error("the bot token is unavailable")]
    TokenUnavailable,
    /// The signed-chain intent could not be emitted; nothing was sent.
    #[error("the audit chain is unavailable; nothing was sent")]
    AuditUnavailable,
    /// Telegram did not confirm the send. Delivery is ambiguous and the call
    /// is never retried automatically.
    #[error("telegram send failed; delivery is unknown and was not retried")]
    SendFailed,
}

impl NotifyError {
    /// Fixed-vocabulary tag for structured logging.
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            Self::NotConfigured => "owner_ping_not_configured",
            Self::HomeUnavailable => "owner_ping_home_unavailable",
            Self::BaseDirOverridden => "owner_ping_base_dir_overridden",
            Self::ConfigUnreadable => "owner_ping_config_unreadable",
            Self::Disabled => "owner_ping_disabled",
            Self::Unpinned => "owner_ping_unpinned",
            Self::Killed => "owner_ping_killed",
            Self::KillSwitchUnreadable => "owner_ping_kill_switch_unreadable",
            Self::RateLimited => "owner_ping_rate_limited",
            Self::BudgetLocked => "owner_ping_budget_locked",
            Self::BudgetUnreadable => "owner_ping_budget_unreadable",
            Self::ClockInvalid => "owner_ping_clock_invalid",
            Self::TextEmpty => "owner_ping_text_empty",
            Self::TextTooLong => "owner_ping_text_too_long",
            Self::TextControl => "owner_ping_text_control",
            Self::TokenUnavailable => "owner_ping_token_unavailable",
            Self::AuditUnavailable => "owner_ping_audit_unavailable",
            Self::SendFailed => "owner_ping_send_failed",
        }
    }

    fn from_budget(error: BudgetError) -> Self {
        match error {
            BudgetError::Locked => Self::BudgetLocked,
            BudgetError::Unreadable | BudgetError::Unwritable => Self::BudgetUnreadable,
            BudgetError::ClockInvalid => Self::ClockInvalid,
            BudgetError::RateLimited => Self::RateLimited,
        }
    }
}

/// Opaque intent/outcome correlation of one ping's audit pair.
pub(crate) struct PingAuditTicket {
    chain_id: String,
    correlation: RecordId,
}

/// Why the audit intent was refused.
pub(crate) struct PingAuditFailure {
    tag: &'static str,
}

impl PingAuditFailure {
    fn tag(&self) -> &'static str {
        self.tag
    }
}

/// The surfaces the flow needs, injected so every test is hermetic (no vault,
/// no network, no audit chain).
///
/// `pub(crate)` on purpose: a public injected trait would let a caller supply a
/// no-op audit sink, defeating the audit-or-refuse invariant. Outside callers
/// get [`send_owner_ping`] / [`send_owner_ping_at`], which hard-wire
/// [`ProductionNotifyIo`].
pub(crate) trait NotifyIo {
    fn load_config(&self, base_dir: &Path) -> Result<Option<BridgeConfig>, BridgeConfigError>;
    fn kill_switch_engaged(&self, base_dir: &Path) -> Result<bool, BridgeConfigError>;
    fn reserve_budget(&self, base_dir: &Path, now: i64) -> Result<(), BudgetError>;
    fn load_bot_token(&self) -> Result<SecretString, SecretError>;
    fn scrub(&self, text: &str, token: &str) -> (String, bool, usize);
    fn audit_intent(
        &self,
        base_dir: &Path,
        payload: &TelegramOwnerPingPayload,
    ) -> Result<PingAuditTicket, PingAuditFailure>;
    fn audit_outcome(
        &self,
        base_dir: &Path,
        ticket: &PingAuditTicket,
        payload: &TelegramOwnerPingPayload,
    );
    fn send(&self, token: &SecretString, chat_id: i64, text: &str) -> Result<(), TelegramApiError>;
}

/// Production wiring: the real config, kill marker, vault, budget, transport
/// and signed chain.
pub(crate) struct ProductionNotifyIo;

impl NotifyIo for ProductionNotifyIo {
    fn load_config(&self, base_dir: &Path) -> Result<Option<BridgeConfig>, BridgeConfigError> {
        config::load(base_dir)
    }

    fn kill_switch_engaged(&self, base_dir: &Path) -> Result<bool, BridgeConfigError> {
        config::kill_switch_engaged(base_dir)
    }

    fn reserve_budget(&self, base_dir: &Path, now: i64) -> Result<(), BudgetError> {
        budget::reserve(base_dir, now)
    }

    fn load_bot_token(&self) -> Result<SecretString, SecretError> {
        secrets::load_bot_token()
    }

    fn scrub(&self, text: &str, token: &str) -> (String, bool, usize) {
        scrub::scrub_for_delivery(text, token)
    }

    fn audit_intent(
        &self,
        base_dir: &Path,
        payload: &TelegramOwnerPingPayload,
    ) -> Result<PingAuditTicket, PingAuditFailure> {
        let chain_id = op_emit::load_chain_id(base_dir);
        let correlation = op_emit::gen_correlation_id().map_err(|_| PingAuditFailure {
            tag: "owner_ping_audit_correlation_failed",
        })?;
        let emitted = op_emit::emit_intent(
            base_dir,
            &chain_id,
            EventKind::TelegramOwnerPing,
            EventPayload::TelegramOwnerPing(payload.clone()),
            correlation.clone(),
        )
        .map_err(|_| PingAuditFailure {
            tag: "owner_ping_audit_intent_failed",
        })?;
        if !emitted {
            return Err(PingAuditFailure {
                tag: "owner_ping_audit_chain_broken",
            });
        }
        Ok(PingAuditTicket {
            chain_id,
            correlation,
        })
    }

    fn audit_outcome(
        &self,
        base_dir: &Path,
        ticket: &PingAuditTicket,
        payload: &TelegramOwnerPingPayload,
    ) {
        let result = if payload.outcome == "send_failed" || payload.outcome.starts_with("refused_")
        {
            OpOutcome::Failed {
                reason: op_emit::redact_reason(payload.outcome.clone()),
            }
        } else {
            OpOutcome::Ok
        };
        if op_emit::emit_outcome(
            base_dir,
            &ticket.chain_id,
            EventKind::TelegramOwnerPing,
            EventPayload::TelegramOwnerPing(payload.clone()),
            ticket.correlation.clone(),
            result,
        )
        .is_err()
        {
            tracing::warn!(
                error_kind = "owner_ping_audit_outcome_failed",
                "owner ping outcome could not be written; the delivery state is unchanged"
            );
        }
    }

    fn send(&self, token: &SecretString, chat_id: i64, text: &str) -> Result<(), TelegramApiError> {
        let transport = ReqwestTransport::new(token.clone())?;
        transport.send_message(chat_id, text)
    }
}

/// The canonical per-user bridge state directory for outbound pings.
///
/// The CLI takes no config path, and the daemon caller cannot substitute one:
/// this resolver is the only source, so the destination, the kill marker and
/// the audit chain cannot be redirected by a caller argument. A conflicting
/// `CSQ_BASE_DIR` is REFUSED rather than ignored — under an override the
/// bridge's state lives in that other directory, and reading the canonical pin
/// while the daemon watches the override would split the bridge (a phone
/// `/csq off` written there would be invisible to this send).
///
/// The home directory is the per-user home. A same-user process that controls
/// the environment (including `HOME`) or rewrites the config can still redirect
/// the send; it could equally read the vault. The pin guards MISROUTING and a
/// misled session, not a hostile process running as the same OS user.
pub fn canonical_owner_ping_dir() -> Result<PathBuf, NotifyError> {
    let home = crate::platform::home::home_dir().ok_or(NotifyError::HomeUnavailable)?;
    let canonical = home.join(".claude").join("accounts");
    if let Some(raw) = std::env::var_os("CSQ_BASE_DIR") {
        if Path::new(&raw) != canonical.as_path() {
            return Err(NotifyError::BaseDirOverridden);
        }
    }
    Ok(canonical)
}

/// Sends one ping to the pinned owner, using the system clock.
pub fn send_owner_ping(text: &str) -> Result<PingOutcome, NotifyError> {
    send_owner_ping_at(text, unix_now()?)
}

/// [`send_owner_ping`] with a caller-supplied clock, for the daemon's own
/// alerts (which already carry a clock).
///
/// A zero, negative, or backwards clock is refused by the budget, never
/// treated as a fresh window.
pub fn send_owner_ping_at(text: &str, now: i64) -> Result<PingOutcome, NotifyError> {
    let base_dir = canonical_owner_ping_dir()?;
    send_owner_ping_with(&ProductionNotifyIo, &base_dir, text, now)
}

/// The flow over injected surfaces.
pub(crate) fn send_owner_ping_with(
    io: &dyn NotifyIo,
    base_dir: &Path,
    text: &str,
    now: i64,
) -> Result<PingOutcome, NotifyError> {
    validate_text(text)?;

    let config = match io.load_config(base_dir) {
        Ok(Some(config)) => config,
        Ok(None) => return Err(NotifyError::NotConfigured),
        Err(_) => return Err(NotifyError::ConfigUnreadable),
    };
    if !config.enabled {
        return Err(NotifyError::Disabled);
    }
    if !config.is_pinned() {
        return Err(NotifyError::Unpinned);
    }

    // Before the vault: a stopped bridge must not even read the token.
    match io.kill_switch_engaged(base_dir) {
        Ok(true) => return Err(NotifyError::Killed),
        Ok(false) => {}
        Err(_) => return Err(NotifyError::KillSwitchUnreadable),
    }

    io.reserve_budget(base_dir, now)
        .map_err(NotifyError::from_budget)?;

    let token = io
        .load_bot_token()
        .map_err(|_| NotifyError::TokenUnavailable)?;
    let (scrubbed, redacted, redaction_count) = io.scrub(text, token.expose_secret());
    // The scrub can grow the text (`[REDACTED]` may be longer than what it
    // replaced), so the length is enforced again on the exact bytes sent.
    if scrubbed.encode_utf16().count() > MAX_TEXT_UTF16 {
        return Err(NotifyError::TextTooLong);
    }

    let intent = ping_payload(&scrubbed, redacted, redaction_count, "intent");
    let ticket = io.audit_intent(base_dir, &intent).map_err(|failure| {
        tracing::warn!(
            error_kind = failure.tag(),
            "owner ping audit intent refused; nothing was sent"
        );
        NotifyError::AuditUnavailable
    })?;

    // Re-check BOTH stops immediately before the wire: the local
    // `csq telegram off` (enabled = false) and the phone kill marker. A stop
    // that lands after this point cannot recall a request already in flight.
    match io.load_config(base_dir) {
        Ok(Some(config)) if config.enabled && config.is_pinned() => {}
        Ok(Some(config)) => {
            let (tag, error) = if config.enabled {
                ("refused_unpinned", NotifyError::Unpinned)
            } else {
                ("refused_disabled", NotifyError::Disabled)
            };
            let outcome = ping_payload(&scrubbed, redacted, redaction_count, tag);
            io.audit_outcome(base_dir, &ticket, &outcome);
            return Err(error);
        }
        Ok(None) => {
            let outcome = ping_payload(
                &scrubbed,
                redacted,
                redaction_count,
                "refused_not_configured",
            );
            io.audit_outcome(base_dir, &ticket, &outcome);
            return Err(NotifyError::NotConfigured);
        }
        Err(_) => {
            let outcome = ping_payload(
                &scrubbed,
                redacted,
                redaction_count,
                "refused_config_unreadable",
            );
            io.audit_outcome(base_dir, &ticket, &outcome);
            return Err(NotifyError::ConfigUnreadable);
        }
    }

    match io.kill_switch_engaged(base_dir) {
        Ok(false) => {}
        Ok(true) => {
            let outcome = ping_payload(&scrubbed, redacted, redaction_count, "refused_killed");
            io.audit_outcome(base_dir, &ticket, &outcome);
            return Err(NotifyError::Killed);
        }
        Err(_) => {
            let outcome = ping_payload(
                &scrubbed,
                redacted,
                redaction_count,
                "refused_kill_switch_unreadable",
            );
            io.audit_outcome(base_dir, &ticket, &outcome);
            return Err(NotifyError::KillSwitchUnreadable);
        }
    }

    match io.send(&token, config.owner_chat_id, &scrubbed) {
        Ok(()) => {
            let tag = if redacted { "sent_redacted" } else { "sent" };
            let outcome = ping_payload(&scrubbed, redacted, redaction_count, tag);
            io.audit_outcome(base_dir, &ticket, &outcome);
            Ok(PingOutcome {
                redacted,
                redaction_count,
                outcome: tag,
            })
        }
        Err(_) => {
            let outcome = ping_payload(&scrubbed, redacted, redaction_count, "send_failed");
            io.audit_outcome(base_dir, &ticket, &outcome);
            Err(NotifyError::SendFailed)
        }
    }
}

/// Builds the metadata-only audit payload for one phase.
fn ping_payload(
    scrubbed: &str,
    redacted: bool,
    redaction_count: usize,
    outcome: &str,
) -> TelegramOwnerPingPayload {
    TelegramOwnerPingPayload {
        byte_len: scrubbed.len() as u64,
        redacted,
        redaction_count: redaction_count as u64,
        outcome: outcome.to_owned(),
    }
}

/// Shape checks that need no state.
pub(crate) fn validate_text(text: &str) -> Result<(), NotifyError> {
    if text.trim().is_empty() {
        return Err(NotifyError::TextEmpty);
    }
    if text.encode_utf16().count() > MAX_TEXT_UTF16 {
        return Err(NotifyError::TextTooLong);
    }
    if text.chars().any(forbidden_char) {
        return Err(NotifyError::TextControl);
    }
    Ok(())
}

/// Control characters other than `\n`, plus the Unicode format and bidi
/// controls that can spoof the owner-visible rendering.
fn forbidden_char(c: char) -> bool {
    (c.is_control() && c != '\n') || is_format_control(c)
}

fn is_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

fn unix_now() -> Result<i64, NotifyError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| NotifyError::ClockInvalid)?;
    i64::try_from(elapsed.as_secs()).map_err(|_| NotifyError::ClockInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
    const SECRET_HALF: &str = "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";
    const NOW: i64 = 1_700_000_000;

    fn config() -> BridgeConfig {
        BridgeConfig {
            enabled: true,
            owner_user_id: 42,
            owner_chat_id: 4242,
            allow_classes: Vec::new(),
        }
    }

    #[derive(Clone)]
    enum ConfigAnswer {
        Present(BridgeConfig),
        Absent,
        Corrupt,
    }

    #[derive(Clone, Copy)]
    enum KillAnswer {
        Clear,
        Engaged,
        Unreadable,
    }

    struct FakeIo {
        config: ConfigAnswer,
        /// Answer used from the SECOND config read on (the pre-send re-check).
        config_after_intent: Option<ConfigAnswer>,
        config_reads: Cell<usize>,
        /// Successive kill-switch answers; the last one repeats.
        kill: Vec<KillAnswer>,
        budget: Result<(), BudgetError>,
        token: Option<SecretString>,
        token_loaded: Cell<bool>,
        kill_calls: Cell<usize>,
        sent: RefCell<Vec<(i64, String)>>,
        intents: RefCell<Vec<TelegramOwnerPingPayload>>,
        outcomes: RefCell<Vec<TelegramOwnerPingPayload>>,
        audit_intent: Result<(), &'static str>,
        send: Result<(), TelegramApiError>,
    }

    impl FakeIo {
        fn ready() -> Self {
            Self {
                config: ConfigAnswer::Present(config()),
                config_after_intent: None,
                config_reads: Cell::new(0),
                kill: vec![KillAnswer::Clear],
                budget: Ok(()),
                token: Some(SecretString::from(TOKEN.to_owned())),
                token_loaded: Cell::new(false),
                kill_calls: Cell::new(0),
                sent: RefCell::new(Vec::new()),
                intents: RefCell::new(Vec::new()),
                outcomes: RefCell::new(Vec::new()),
                audit_intent: Ok(()),
                send: Ok(()),
            }
        }
    }

    impl NotifyIo for FakeIo {
        fn load_config(&self, _base_dir: &Path) -> Result<Option<BridgeConfig>, BridgeConfigError> {
            let read = self.config_reads.get();
            self.config_reads.set(read + 1);
            let answer = if read > 0 {
                self.config_after_intent.as_ref().unwrap_or(&self.config)
            } else {
                &self.config
            };
            match answer {
                ConfigAnswer::Present(config) => Ok(Some(config.clone())),
                ConfigAnswer::Absent => Ok(None),
                ConfigAnswer::Corrupt => Err(BridgeConfigError::ConfigCorrupt),
            }
        }

        fn kill_switch_engaged(&self, _base_dir: &Path) -> Result<bool, BridgeConfigError> {
            let call = self.kill_calls.get();
            self.kill_calls.set(call + 1);
            match self
                .kill
                .get(call)
                .copied()
                .unwrap_or_else(|| *self.kill.last().expect("at least one answer"))
            {
                KillAnswer::Clear => Ok(false),
                KillAnswer::Engaged => Ok(true),
                KillAnswer::Unreadable => Err(BridgeConfigError::ConfigUnreadable),
            }
        }

        fn reserve_budget(&self, _base_dir: &Path, _now: i64) -> Result<(), BudgetError> {
            self.budget
        }

        fn load_bot_token(&self) -> Result<SecretString, SecretError> {
            self.token_loaded.set(true);
            self.token.clone().ok_or(SecretError::NamedNotFound)
        }

        fn scrub(&self, text: &str, token: &str) -> (String, bool, usize) {
            scrub::scrub_for_delivery(text, token)
        }

        fn audit_intent(
            &self,
            _base_dir: &Path,
            payload: &TelegramOwnerPingPayload,
        ) -> Result<PingAuditTicket, PingAuditFailure> {
            match self.audit_intent {
                Ok(()) => {
                    self.intents.borrow_mut().push(payload.clone());
                    Ok(PingAuditTicket {
                        chain_id: "chain".to_owned(),
                        correlation: RecordId::try_new("01JZ00000000000000000000XY")
                            .expect("correlation"),
                    })
                }
                Err(tag) => Err(PingAuditFailure { tag }),
            }
        }

        fn audit_outcome(
            &self,
            _base_dir: &Path,
            _ticket: &PingAuditTicket,
            payload: &TelegramOwnerPingPayload,
        ) {
            self.outcomes.borrow_mut().push(payload.clone());
        }

        fn send(
            &self,
            _token: &SecretString,
            chat_id: i64,
            text: &str,
        ) -> Result<(), TelegramApiError> {
            self.send?;
            self.sent.borrow_mut().push((chat_id, text.to_owned()));
            Ok(())
        }
    }

    fn run(io: &FakeIo, text: &str) -> Result<PingOutcome, NotifyError> {
        send_owner_ping_with(io, Path::new("/nonexistent"), text, NOW)
    }

    #[test]
    fn a_ready_bridge_sends_to_the_pinned_chat_only() {
        let io = FakeIo::ready();
        let outcome = run(&io, "build finished").expect("send");
        assert_eq!(outcome.outcome, "sent");
        assert_eq!(
            io.sent.borrow().as_slice(),
            &[(4242, "build finished".to_owned())]
        );
    }

    #[test]
    fn disabled_refuses_before_the_kill_switch_and_token() {
        let mut io = FakeIo::ready();
        io.config = ConfigAnswer::Present(BridgeConfig {
            enabled: false,
            ..config()
        });
        assert_eq!(run(&io, "hi"), Err(NotifyError::Disabled));
        assert_eq!(io.kill_calls.get(), 0);
        assert!(!io.token_loaded.get());
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    fn unpinned_refuses() {
        let mut io = FakeIo::ready();
        io.config = ConfigAnswer::Present(BridgeConfig {
            owner_chat_id: 0,
            ..config()
        });
        assert_eq!(run(&io, "hi"), Err(NotifyError::Unpinned));
        assert!(!io.token_loaded.get());
    }

    #[test]
    fn not_configured_refuses() {
        let mut io = FakeIo::ready();
        io.config = ConfigAnswer::Absent;
        assert_eq!(run(&io, "hi"), Err(NotifyError::NotConfigured));
    }

    #[test]
    fn a_corrupt_config_refuses() {
        let mut io = FakeIo::ready();
        io.config = ConfigAnswer::Corrupt;
        assert_eq!(run(&io, "hi"), Err(NotifyError::ConfigUnreadable));
    }

    #[test]
    fn the_kill_switch_refuses_before_the_token() {
        let mut io = FakeIo::ready();
        io.kill = vec![KillAnswer::Engaged];
        assert_eq!(run(&io, "hi"), Err(NotifyError::Killed));
        assert!(!io.token_loaded.get());
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    fn an_unreadable_kill_switch_refuses() {
        let mut io = FakeIo::ready();
        io.kill = vec![KillAnswer::Unreadable];
        assert_eq!(run(&io, "hi"), Err(NotifyError::KillSwitchUnreadable));
        assert!(!io.token_loaded.get());
    }

    #[test]
    fn budget_refusals_map_to_their_tags() {
        for (error, expected) in [
            (BudgetError::RateLimited, NotifyError::RateLimited),
            (BudgetError::Locked, NotifyError::BudgetLocked),
            (BudgetError::Unreadable, NotifyError::BudgetUnreadable),
            (BudgetError::Unwritable, NotifyError::BudgetUnreadable),
            (BudgetError::ClockInvalid, NotifyError::ClockInvalid),
        ] {
            let mut io = FakeIo::ready();
            io.budget = Err(error);
            assert_eq!(run(&io, "hi"), Err(expected));
            assert!(
                !io.token_loaded.get(),
                "{error:?} must refuse before the vault"
            );
            assert!(io.sent.borrow().is_empty());
        }
    }

    #[test]
    fn an_unavailable_token_refuses_without_sending() {
        let mut io = FakeIo::ready();
        io.token = None;
        assert_eq!(run(&io, "hi"), Err(NotifyError::TokenUnavailable));
        assert!(io.sent.borrow().is_empty());
        assert!(io.intents.borrow().is_empty());
    }

    #[test]
    fn empty_oversized_and_control_text_are_refused_before_any_state_read() {
        let io = FakeIo::ready();
        assert_eq!(run(&io, "   \n"), Err(NotifyError::TextEmpty));
        assert_eq!(run(&io, "a\u{0000}b"), Err(NotifyError::TextControl));
        assert_eq!(run(&io, "a\u{202E}b"), Err(NotifyError::TextControl));
        let long = "a".repeat(MAX_TEXT_UTF16 + 1);
        assert_eq!(run(&io, &long), Err(NotifyError::TextTooLong));
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    fn an_audit_intent_failure_refuses_the_send() {
        let mut io = FakeIo::ready();
        io.audit_intent = Err("owner_ping_audit_chain_broken");
        assert_eq!(run(&io, "hi"), Err(NotifyError::AuditUnavailable));
        assert!(io.sent.borrow().is_empty());
        assert!(io.outcomes.borrow().is_empty());
    }

    /// The OTHER half of the audit-or-refuse rule (acceptance item 8).
    ///
    /// The test above drives the INJECTED io to `Err`. It cannot reach
    /// `emit_intent == Ok(false)`, because the injectable surface returns a
    /// ticket or a failure and the `Ok(false)` decision lives inside the real
    /// wiring: a `.chain-broken` sentinel makes the write be SKIPPED rather
    /// than fail. That shape is exactly the dangerous one — a skipped intent
    /// is not an emitted intent, and treating it as success sends a message
    /// with no signed record of why.
    ///
    /// Found by a surviving mutant: deleting the `!emitted` refusal left the
    /// whole suite green. This test reddens on that deletion.
    #[test]
    fn an_intent_the_chain_refuses_to_write_is_not_treated_as_emitted() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::audit::health::set_chain_broken(dir.path(), "chain_corrupt");
        let payload = TelegramOwnerPingPayload {
            byte_len: 2,
            redacted: false,
            redaction_count: 0,
            outcome: "intent".to_owned(),
        };
        let failure = ProductionNotifyIo
            .audit_intent(dir.path(), &payload)
            .err()
            .expect("a skipped intent write must refuse the ping, not proceed");
        assert_eq!(failure.tag(), "owner_ping_audit_chain_broken");
    }

    #[test]
    fn a_token_shaped_secret_never_reaches_the_transport() {
        let io = FakeIo::ready();
        let text = format!("log line token={TOKEN} oauth=sk-ant-oat01-FAKETESTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA end");
        run(&io, &text).expect("send");
        let sent = &io.sent.borrow()[0].1;
        assert!(!sent.contains(TOKEN), "{sent}");
        assert!(!sent.contains(SECRET_HALF), "{sent}");
        assert!(!sent.contains("FAKETEST"), "{sent}");
        assert!(sent.contains("log line"), "{sent}");
    }

    #[test]
    fn the_secret_half_alone_is_scrubbed() {
        let io = FakeIo::ready();
        let outcome = run(&io, &format!("half {SECRET_HALF} end")).expect("send");
        let sent = &io.sent.borrow()[0].1;
        assert!(!sent.contains("AAHdqTcvCH1v"), "{sent}");
        assert!(outcome.redacted);
        assert!(outcome.redaction_count >= 1);
    }

    #[test]
    fn redaction_is_recorded_in_both_audit_phases() {
        let io = FakeIo::ready();
        let outcome = run(&io, &format!("token={TOKEN}")).expect("send");
        assert_eq!(outcome.outcome, "sent_redacted");
        let intents = io.intents.borrow();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].outcome, "intent");
        assert!(intents[0].redacted);
        assert!(intents[0].redaction_count >= 1);
        assert_eq!(intents[0].byte_len, io.sent.borrow()[0].1.len() as u64);
        let outcomes = io.outcomes.borrow();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].outcome, "sent_redacted");
    }

    #[test]
    fn clean_text_records_not_redacted() {
        let io = FakeIo::ready();
        let outcome = run(&io, "build finished").expect("send");
        assert!(!outcome.redacted);
        assert_eq!(outcome.redaction_count, 0);
        assert!(!io.intents.borrow()[0].redacted);
        assert_eq!(io.outcomes.borrow()[0].outcome, "sent");
    }

    #[test]
    fn a_send_failure_writes_a_failed_outcome() {
        let mut io = FakeIo::ready();
        io.send = Err(TelegramApiError::Transport);
        assert_eq!(run(&io, "hi"), Err(NotifyError::SendFailed));
        assert_eq!(io.outcomes.borrow().len(), 1);
        assert_eq!(io.outcomes.borrow()[0].outcome, "send_failed");
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    fn a_kill_switch_landing_after_the_intent_writes_an_outcome_and_does_not_send() {
        let mut io = FakeIo::ready();
        io.kill = vec![KillAnswer::Clear, KillAnswer::Engaged];
        assert_eq!(run(&io, "hi"), Err(NotifyError::Killed));
        assert_eq!(io.intents.borrow().len(), 1);
        assert_eq!(io.outcomes.borrow().len(), 1);
        assert_eq!(io.outcomes.borrow()[0].outcome, "refused_killed");
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    fn a_local_off_landing_after_the_intent_writes_an_outcome_and_does_not_send() {
        let mut io = FakeIo::ready();
        io.config_after_intent = Some(ConfigAnswer::Present(BridgeConfig {
            enabled: false,
            ..config()
        }));
        assert_eq!(run(&io, "hi"), Err(NotifyError::Disabled));
        assert_eq!(io.intents.borrow().len(), 1);
        assert_eq!(io.outcomes.borrow()[0].outcome, "refused_disabled");
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    fn a_config_disappearing_after_the_intent_writes_an_outcome_and_does_not_send() {
        let mut io = FakeIo::ready();
        io.config_after_intent = Some(ConfigAnswer::Absent);
        assert_eq!(run(&io, "hi"), Err(NotifyError::NotConfigured));
        assert_eq!(io.outcomes.borrow()[0].outcome, "refused_not_configured");
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    fn an_unreadable_kill_switch_after_the_intent_writes_an_outcome() {
        let mut io = FakeIo::ready();
        io.kill = vec![KillAnswer::Clear, KillAnswer::Unreadable];
        assert_eq!(run(&io, "hi"), Err(NotifyError::KillSwitchUnreadable));
        assert_eq!(
            io.outcomes.borrow()[0].outcome,
            "refused_kill_switch_unreadable"
        );
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    fn the_text_growing_past_the_cap_after_scrubbing_is_refused() {
        let io = FakeIo::ready();
        // Exactly at the cap before the scrub; the 6-char token prefix becomes
        // a 10-char marker, so the scrubbed text is 4 units over.
        let mut text = "x".repeat(MAX_TEXT_UTF16 - 6);
        text.push_str(&SECRET_HALF[..6]);
        assert_eq!(text.encode_utf16().count(), MAX_TEXT_UTF16);
        assert_eq!(run(&io, &text), Err(NotifyError::TextTooLong));
        assert!(io.sent.borrow().is_empty());
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn a_conflicting_csq_base_dir_is_refused() {
        let _env = crate::platform::test_env::lock();
        let home = tempfile::tempdir().expect("tempdir");
        let prior_home = std::env::var_os("CSQ_HOME");
        let prior_base = std::env::var_os("CSQ_BASE_DIR");
        // SAFETY: `test_env::lock` serialises environment mutation for this
        // crate's tests; both variables are restored before asserting.
        unsafe {
            std::env::set_var("CSQ_HOME", home.path());
            std::env::set_var("CSQ_BASE_DIR", home.path().join("elsewhere"));
        }
        let result = canonical_owner_ping_dir();
        // SAFETY: same lock; restore the prior state before asserting.
        unsafe {
            match prior_home {
                Some(value) => std::env::set_var("CSQ_HOME", value),
                None => std::env::remove_var("CSQ_HOME"),
            }
            match prior_base {
                Some(value) => std::env::set_var("CSQ_BASE_DIR", value),
                None => std::env::remove_var("CSQ_BASE_DIR"),
            }
        }
        assert_eq!(result, Err(NotifyError::BaseDirOverridden));
    }

    #[test]
    #[cfg(feature = "test-utils")]
    fn a_matching_csq_base_dir_is_accepted() {
        let _env = crate::platform::test_env::lock();
        let home = tempfile::tempdir().expect("tempdir");
        let canonical = home.path().join(".claude").join("accounts");
        let prior_home = std::env::var_os("CSQ_HOME");
        let prior_base = std::env::var_os("CSQ_BASE_DIR");
        // SAFETY: as above.
        unsafe {
            std::env::set_var("CSQ_HOME", home.path());
            std::env::set_var("CSQ_BASE_DIR", &canonical);
        }
        let result = canonical_owner_ping_dir();
        // SAFETY: as above.
        unsafe {
            match prior_home {
                Some(value) => std::env::set_var("CSQ_HOME", value),
                None => std::env::remove_var("CSQ_HOME"),
            }
            match prior_base {
                Some(value) => std::env::set_var("CSQ_BASE_DIR", value),
                None => std::env::remove_var("CSQ_BASE_DIR"),
            }
        }
        assert_eq!(result, Ok(canonical));
    }

    #[test]
    fn every_error_display_is_fixed_text_and_token_free() {
        let errors = [
            NotifyError::NotConfigured,
            NotifyError::HomeUnavailable,
            NotifyError::BaseDirOverridden,
            NotifyError::ConfigUnreadable,
            NotifyError::Disabled,
            NotifyError::Unpinned,
            NotifyError::Killed,
            NotifyError::KillSwitchUnreadable,
            NotifyError::RateLimited,
            NotifyError::BudgetLocked,
            NotifyError::BudgetUnreadable,
            NotifyError::ClockInvalid,
            NotifyError::TextEmpty,
            NotifyError::TextTooLong,
            NotifyError::TextControl,
            NotifyError::TokenUnavailable,
            NotifyError::AuditUnavailable,
            NotifyError::SendFailed,
        ];
        for error in errors {
            let text = error.to_string();
            assert!(!text.contains(TOKEN), "{text}");
            assert!(!text.contains(SECRET_HALF), "{text}");
            assert!(!text.contains("http"), "{text}");
            assert!(!text.is_empty());
            assert!(error.error_kind_tag().starts_with("owner_ping_"));
        }
    }
}
