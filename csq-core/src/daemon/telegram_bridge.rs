//! Daemon-side Telegram bridge ingest (S3).
//!
//! The bridge lets the machine's owner send a Telegram message to their own bot
//! and have it delivered to a csq session. This module is the daemon half:
//! it long-polls Telegram **outbound only** — it adds no listener, no webhook
//! and no inbound socket (`security.md` MUST-7) — validates every update with
//! the pure screen in [`crate::bridge::validator`], routes the accepted text to
//! exactly one live session, stores it with an
//! [`OwnerAttestation`](crate::bridge::attestation::OwnerAttestation), wakes the
//! target and acknowledges the phone.
//!
//! # Lifecycle
//!
//! [`run_telegram_bridge`](crate::daemon::telegram_bridge::run_telegram_bridge) is a background task shaped like the OAuth refresher:
//! a startup delay, one shared [`CancellationToken`](tokio_util::sync::CancellationToken), and a supervised loop
//! that backs off on failure. Absent or `enabled == false` config is the kill
//! switch: the task logs once at INFO and idles, touching neither the network
//! nor the vault. It keeps re-reading only the local config, so a later
//! `csq telegram on` (which does not notify the daemon) activates it without a
//! daemon restart.
//!
//! # Exactly-once delivery
//!
//! Telegram re-delivers an update until the `getUpdates` offset passes it. The
//! delivered-update ledger is persisted **before** the store write, so a crash
//! between the store write and the poll-cursor persist replays the update
//! against a ledger that already claims it: the message is stored exactly once.
//! The claim is rolled back only when the store returns an error, so a refused
//! store never strands a future retry.
//!
//! # Command surface
//!
//! Slash text is never delivered. The shared validator refuses it as
//! `NotMessage` after every identity screen, and this module answers it: the
//! ONE slash command that acts is [`OFF_COMMAND`](crate::daemon::telegram_bridge::OFF_COMMAND) (`/csq off`), the phone kill
//! switch, which works even while the inbound rate window is exhausted and is
//! EXEMPT from the command freshness window (replaying "off" can only leave
//! the bridge off; losing a stale off would be fail-open). Every other slash
//! text gets an explicit `not_under_relay` refusal, because commands ride the
//! spec-34 relay, which does not exist yet. Nothing here is ever stored for,
//! or typed into, a session.
//!
//! The kill switch writes ONLY the `telegram-bridge-killed` marker, never the
//! config; the poll gate refuses while the marker stands and an unreadable
//! marker fails closed. The daemon never removes the marker — the local
//! `csq telegram on` is the sole release path — so the daemon is not a config
//! writer at all and cannot resurrect a `csq telegram off` that races it.
//!
//! `swap <session> <N>` is the one allow-listed bridge command. It resolves the
//! session by name, re-verifies it against the live process table, runs the
//! gated production swap (owner-granted class + the daemon-known target-slot
//! login verdict, checked before any credential operation) and echoes the
//! outcome. A refusal is final: the cursor advances, nothing is retried and no
//! fallback slot is chosen.
//!
//! # Secrets
//!
//! The bot token is embedded in Telegram's request URL path
//! (`/bot<token>/getUpdates`), so **no** error from this module may format a
//! URL, a raw `reqwest` error or a response body. Every failure is a
//! fixed-vocabulary [`TelegramErrorKind`](crate::daemon::telegram_bridge::TelegramErrorKind) tag (`security.md` MUST-2).
//! The token itself is only ever passed to the poster as `&str` for URL
//! construction; it is never logged, never formatted into an error and never
//! placed in argv.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::bridge::attestation::OwnerAttestation;
use crate::bridge::config::{self as bridge_config, BridgeConfig, BridgeConfigError};
use crate::bridge::secrets as bridge_secrets;
use crate::bridge::validator::{validate_update, RawUpdate, Reject};
use crate::messaging::limits::Liveness;
use crate::messaging::model::{Recipient, Surface};
use crate::messaging::registry::{self, Candidate, Resolution};
use crate::messaging::wake::{self, Delivery};
use crate::platform::secret::SecretError;
use crate::session::swap_session::{SwapError, SwapOutcome};
use crate::types::AccountNum;

/// Telegram long-poll window requested from `getUpdates` (seconds).
pub const POLL_TIMEOUT_SECS: u64 = 50;

/// Delay before the first poll, so daemon startup work is not raced.
pub const STARTUP_DELAY: Duration = Duration::from_secs(3);

/// First backoff after a failed poll.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Cap on exponential poll backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Backoff after a `409 Conflict` (another poller or a webhook is active).
/// Long, because retrying harder cannot clear the condition.
const CONFLICT_BACKOFF: Duration = Duration::from_secs(300);

/// How often an inactive bridge re-reads its config.
///
/// The task must stay alive while disabled: `csq telegram on` writes the
/// config and does not notify the daemon, so exiting on the first `disabled`
/// read would make the bridge unreachable until a daemon restart. While idle
/// the task reads only the local config file — no network, no vault.
const INACTIVE_RECHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Inbound accepted-message allowance per [`INBOUND_WINDOW`].
pub const INBOUND_LIMIT: usize = 30;

/// Sliding window for [`INBOUND_LIMIT`].
pub const INBOUND_WINDOW: Duration = Duration::from_secs(600);

/// Rejected-update log coalescing interval (fixed tags only).
const REJECT_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Request timeout: the long-poll window plus headroom for the round trip.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(POLL_TIMEOUT_SECS + 15);

/// Telegram Bot API origin. Injectable so a test never reaches the network.
const DEFAULT_BASE_URL: &str = "https://api.telegram.org";

/// Ledger file name inside `<base_dir>`.
pub const DELIVERED_LEDGER_FILE: &str = "telegram-bridge-delivered.json";

/// Upper bound on the ledger file we are willing to parse.
const LEDGER_MAX_BYTES: u64 = 1024;

/// Fixed owner-facing texts. Never echo an update body.
const CONFLICT_NOTICE: &str =
    "csq bridge: another Telegram poller or webhook holds this bot; polling paused.";
const RATE_LIMIT_NOTICE: &str = "csq bridge: inbound rate limit reached; message dropped.";
const NO_SUCH_SESSION_PREFIX: &str = "csq bridge: no such session";
const LISTING_UNAVAILABLE_NOTICE: &str =
    "csq bridge: the live session list could not be read; message not delivered.";
const STATE_UNREADABLE_NOTICE: &str =
    "csq bridge: local bridge state is unreadable; message not delivered.";
const STORE_REFUSED_NOTICE: &str =
    "csq bridge: the message store refused this message (target ended or body unacceptable).";
const AUDIT_UNAVAILABLE_NOTICE: &str = "csq bridge: audit unavailable; message not delivered.";
/// The exact text that turns the bridge off from the owner's phone.
///
/// Re-enabling is machine-terminal-only (`csq telegram on`): a message can
/// stop the bridge but can never start it.
pub const OFF_COMMAND: &str = "/csq off";
/// Fixed refusal token for every other slash command.
pub const NOT_UNDER_RELAY: &str = "not_under_relay";
const OFF_CONFIRMATION: &str = "csq bridge: off. Re-enable at the machine with `csq telegram on`.";
const STALE_COMMAND_NOTICE: &str = "csq bridge: stale command refused; nothing changed.";
const SWAP_USAGE_NOTICE: &str = "csq bridge: usage `swap <session> <N>`; nothing changed.";
/// The one allow-listed bridge command word.
pub const SWAP_COMMAND: &str = "swap";

// ── Fixed-vocabulary transport errors ──────────────────────────────────────

/// Why a Telegram HTTP call failed.
///
/// Deliberately carries no `reqwest` error, no URL and no response body: the
/// token lives in the URL path, so formatting any of those would leak it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelegramErrorKind {
    /// HTTP 409 — a webhook is set or another process is polling.
    Conflict,
    /// HTTP 401/403 — the bot token is not accepted.
    Unauthorized,
    /// The request exceeded its deadline.
    Timeout,
    /// The connection could not be established.
    Connect,
    /// Any other transport failure.
    Transport,
    /// A 2xx response whose body was not the expected JSON.
    Decode,
    /// A non-2xx status that is not one of the classified ones.
    Status(u16),
    /// The HTTP client could not be constructed at all.
    Unavailable,
}

impl TelegramErrorKind {
    /// Fixed-vocabulary tag safe to log verbatim.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Conflict => "telegram_conflict",
            Self::Unauthorized => "telegram_unauthorized",
            Self::Timeout => "telegram_timeout",
            Self::Connect => "telegram_connect_failed",
            Self::Transport => "telegram_transport_failed",
            Self::Decode => "telegram_response_undecodable",
            Self::Status(_) => "telegram_http_status",
            Self::Unavailable => "telegram_client_unavailable",
        }
    }
}

/// A transport failure with a fixed vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelegramError {
    kind: TelegramErrorKind,
}

impl TelegramError {
    /// The fixed failure kind.
    #[must_use]
    pub fn kind(self) -> TelegramErrorKind {
        self.kind
    }

    fn new(kind: TelegramErrorKind) -> Self {
        Self { kind }
    }
}

impl std::fmt::Display for TelegramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind.tag())
    }
}

impl std::error::Error for TelegramError {}

/// Maps a `reqwest` failure to a fixed kind without formatting it.
///
/// `reqwest::Error`'s `Display` includes the request URL, which contains the
/// bot token; it is consulted only through the boolean classifiers below and
/// never stringified.
fn map_reqwest_error(error: &reqwest::Error) -> TelegramError {
    let kind = if error.is_timeout() {
        TelegramErrorKind::Timeout
    } else if error.is_connect() {
        TelegramErrorKind::Connect
    } else if error.is_decode() {
        TelegramErrorKind::Decode
    } else {
        TelegramErrorKind::Transport
    };
    TelegramError::new(kind)
}

// ── Injected HTTP surface ──────────────────────────────────────────────────

/// One inbound update: the validator's [`RawUpdate`] plus the Telegram
/// `message.message_id` it does not carry.
///
/// The id is required by [`crate::messaging::model::Origin::OwnerTelegram`] so an outbound phone reply
/// can be routed back to the exact session. It is metadata only — the
/// validator never trusts it.
#[derive(Clone, PartialEq, Eq)]
pub struct TelegramUpdate {
    /// The untrusted fields the validator screens.
    pub raw: RawUpdate,
    /// `message.message_id`; `0` when the update carries no message object.
    pub tg_message_id: i64,
}

impl std::fmt::Debug for TelegramUpdate {
    /// Deliberately omits the message text: the body must never reach a log,
    /// an error message or a panic payload (`security.md` MUST-2).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramUpdate")
            .field("update_id", &self.raw.update_id)
            .field("tg_message_id", &self.tg_message_id)
            .finish_non_exhaustive()
    }
}

/// The two Telegram Bot API calls the bridge needs.
///
/// Production uses [`ReqwestTelegramPost`]; every test injects a fake so no
/// test (and no local verification) reaches the network.
#[async_trait]
pub trait TelegramPost: Send + Sync {
    /// Long-polls for updates strictly above `offset`.
    async fn get_updates(
        &self,
        token: &str,
        offset: u64,
    ) -> Result<Vec<TelegramUpdate>, TelegramError>;

    /// Sends one plain-text message to `chat_id`, returning Telegram's
    /// `message_id` for it (`0` when the response carried none).
    ///
    /// The id is what an outbound reply is routed back to, so the caller that
    /// pings the owner keeps it; the ingest ack ignores it.
    async fn send_message(
        &self,
        token: &str,
        chat_id: i64,
        text: &str,
    ) -> Result<i64, TelegramError>;
}

/// The production poster over the workspace `reqwest` client.
pub struct ReqwestTelegramPost {
    /// `None` when the TLS backend could not be initialised; every call then
    /// reports [`TelegramErrorKind::Unavailable`] instead of panicking.
    client: Option<reqwest::Client>,
    base_url: String,
}

impl ReqwestTelegramPost {
    /// Builds the poster against Telegram's public API.
    #[must_use]
    pub fn new() -> Self {
        Self::with_base_url(DEFAULT_BASE_URL)
    }

    /// Builds the poster against `base_url` (tests only).
    #[must_use]
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(CLIENT_TIMEOUT)
            .build()
            .ok();
        Self {
            client,
            base_url: base_url.into(),
        }
    }
}

impl Default for ReqwestTelegramPost {
    fn default() -> Self {
        Self::new()
    }
}

impl ReqwestTelegramPost {
    fn client(&self) -> Result<&reqwest::Client, TelegramError> {
        self.client
            .as_ref()
            .ok_or_else(|| TelegramError::new(TelegramErrorKind::Unavailable))
    }
}

#[async_trait]
impl TelegramPost for ReqwestTelegramPost {
    async fn get_updates(
        &self,
        token: &str,
        offset: u64,
    ) -> Result<Vec<TelegramUpdate>, TelegramError> {
        let client = self.client()?;
        let url = format!("{}/bot{token}/getUpdates", self.base_url);
        let response = client
            .get(&url)
            .query(&[
                ("timeout", POLL_TIMEOUT_SECS.to_string()),
                ("offset", offset.to_string()),
                ("allowed_updates", "[\"message\"]".to_string()),
            ])
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        decode_updates(status.as_u16(), &body)
    }

    async fn send_message(
        &self,
        token: &str,
        chat_id: i64,
        text: &str,
    ) -> Result<i64, TelegramError> {
        let client = self.client()?;
        let url = format!("{}/bot{token}/sendMessage", self.base_url);
        let response = client
            .post(&url)
            .form(&[("chat_id", chat_id.to_string()), ("text", text.to_string())])
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        decode_send_result(status.as_u16(), &body)
    }
}

/// Classifies a `getUpdates` HTTP response and parses its updates.
///
/// Separate from the request so the status/body handling is exercised without
/// a socket at all.
pub(crate) fn decode_updates(
    status: u16,
    body: &[u8],
) -> Result<Vec<TelegramUpdate>, TelegramError> {
    if status == 409 {
        return Err(TelegramError::new(TelegramErrorKind::Conflict));
    }
    if status == 401 || status == 403 {
        return Err(TelegramError::new(TelegramErrorKind::Unauthorized));
    }
    if !(200..300).contains(&status) {
        return Err(TelegramError::new(TelegramErrorKind::Status(status)));
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| TelegramError::new(TelegramErrorKind::Decode))?;
    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        // Telegram can report the condition in a 200 body.
        return match value.get("error_code").and_then(serde_json::Value::as_u64) {
            Some(409) => Err(TelegramError::new(TelegramErrorKind::Conflict)),
            Some(401 | 403) => Err(TelegramError::new(TelegramErrorKind::Unauthorized)),
            Some(code) if code <= u64::from(u16::MAX) => {
                Err(TelegramError::new(TelegramErrorKind::Status(code as u16)))
            }
            _ => Err(TelegramError::new(TelegramErrorKind::Decode)),
        };
    }
    let Some(result) = value.get("result").and_then(serde_json::Value::as_array) else {
        return Err(TelegramError::new(TelegramErrorKind::Decode));
    };
    let mut updates = Vec::with_capacity(result.len());
    for item in result {
        let Some(update) = telegram_update_from_json(item) else {
            // An update with no numeric id is not something the offset can
            // advance past; refusing the whole batch keeps it out of the
            // delivery path and is surfaced by the poll-failure tag.
            return Err(TelegramError::new(TelegramErrorKind::Decode));
        };
        updates.push(update);
    }
    updates.sort_by_key(|u| u.raw.update_id);
    Ok(updates)
}

/// Classifies a `sendMessage` response and extracts Telegram's `message_id`.
///
/// The body is not interpreted beyond `ok` and the id; a refused
/// acknowledgement is logged, never retried in a loop.
pub(crate) fn decode_send_result(status: u16, body: &[u8]) -> Result<i64, TelegramError> {
    if status == 409 {
        return Err(TelegramError::new(TelegramErrorKind::Conflict));
    }
    if status == 401 || status == 403 {
        return Err(TelegramError::new(TelegramErrorKind::Unauthorized));
    }
    if !(200..300).contains(&status) {
        return Err(TelegramError::new(TelegramErrorKind::Status(status)));
    }
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| TelegramError::new(TelegramErrorKind::Decode))?;
    match value.get("ok").and_then(serde_json::Value::as_bool) {
        Some(true) => Ok(value
            .get("result")
            .and_then(|result| result.get("message_id"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0)),
        _ => Err(TelegramError::new(TelegramErrorKind::Decode)),
    }
}

/// Builds the daemon's [`RawUpdate`] from one Telegram update object.
///
/// Pure and total: any shape that lacks a numeric `update_id` returns `None`;
/// every other malformation is represented as a raw update the validator will
/// refuse (never silently corrected).
pub(crate) fn telegram_update_from_json(value: &serde_json::Value) -> Option<TelegramUpdate> {
    let update_id = value.get("update_id")?.as_u64()?;
    let edited = value.get("edited_message");
    let message = value.get("message").or(edited);
    let is_edited = edited.is_some();
    let Some(message) = message else {
        // callback_query, channel_post, poll, … — not a fresh text message.
        return Some(TelegramUpdate {
            raw: RawUpdate {
                update_id,
                from_id: 0,
                chat_id: 0,
                chat_type: String::new(),
                is_bot: false,
                date: 0,
                text: None,
                has_forward: false,
                via_bot: false,
                sender_chat: false,
                is_edited,
                is_command_kind: true,
            },
            tg_message_id: 0,
        });
    };
    let from = message.get("from");
    let chat = message.get("chat");
    let text = message
        .get("text")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    // `is_command_kind` MUST be truthful: a slash message is a command for the
    // spec-34 relay, never ordinary text. A false default here would let a
    // command be typed into a session, which is exactly what the spec-34
    // refusal exists to prevent.
    let is_command_kind = text.as_deref().is_some_and(|text| text.starts_with('/'));
    Some(TelegramUpdate {
        raw: RawUpdate {
            update_id,
            from_id: from
                .and_then(|f| f.get("id"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            chat_id: chat
                .and_then(|c| c.get("id"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            chat_type: chat
                .and_then(|c| c.get("type"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            is_bot: from
                .and_then(|f| f.get("is_bot"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            date: message
                .get("date")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
            text,
            // Every forward marker Telegram can emit, across both API
            // generations: modern `forward_origin`; legacy user forwards
            // (`forward_from`); channel forwards (`forward_from_chat`); and
            // hidden-account forwards (`forward_sender_name`, which carries no
            // id at all). A missing clause here would let a third-party
            // message arrive with the owner's provenance.
            has_forward: message.get("forward_origin").is_some()
                || message.get("forward_from").is_some()
                || message.get("forward_from_chat").is_some()
                || message.get("forward_sender_name").is_some()
                || message.get("forward_date").is_some(),
            via_bot: message.get("via_bot").is_some(),
            sender_chat: message.get("sender_chat").is_some(),
            is_edited,
            is_command_kind,
        },
        tg_message_id: message
            .get("message_id")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
    })
}

// ── Inbound rate limit ─────────────────────────────────────────────────────

/// Sliding-window admission for delivered inbound messages.
///
/// Only *stored* messages consume the allowance; a rejected update does not.
pub(crate) struct RateWindow {
    admitted: VecDeque<Instant>,
    limit: usize,
    window: Duration,
}

impl RateWindow {
    fn new(limit: usize, window: Duration) -> Self {
        Self {
            admitted: VecDeque::new(),
            limit,
            window,
        }
    }

    /// Whether one more message may be delivered at `now`.
    fn admit(&mut self, now: Instant) -> bool {
        while let Some(oldest) = self.admitted.front() {
            if now.duration_since(*oldest) >= self.window {
                self.admitted.pop_front();
            } else {
                break;
            }
        }
        if self.admitted.len() >= self.limit {
            false
        } else {
            self.admitted.push_back(now);
            true
        }
    }
}

// ── Coalesced reject logging ───────────────────────────────────────────────

/// Counts refusals and logs them at most once per [`REJECT_LOG_INTERVAL`] with
/// fixed tags only (never the body, never a username).
pub(crate) struct RejectCoalescer {
    counts: BTreeMap<&'static str, u64>,
    since: Instant,
}

impl RejectCoalescer {
    fn new(now: Instant) -> Self {
        Self {
            counts: BTreeMap::new(),
            since: now,
        }
    }

    fn record(&mut self, tag: &'static str) {
        *self.counts.entry(tag).or_insert(0) += 1;
    }

    fn flush_if_due(&mut self, now: Instant) {
        if now.duration_since(self.since) >= REJECT_LOG_INTERVAL {
            self.flush();
            self.since = now;
        }
    }

    fn flush(&mut self) {
        for (tag, count) in std::mem::take(&mut self.counts) {
            tracing::warn!(error_kind = tag, count, "bridge refused inbound update(s)");
        }
    }
}

// ── Target routing ─────────────────────────────────────────────────────────

/// The live-session listing could not be read completely.
///
/// Name resolution distinguishes "no such session" from "ambiguous" through
/// [`registry::Resolution`]; this type only marks the listing itself as
/// undetermined, which must never be reported as "no such session".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TargetError;

impl TargetError {
    fn tag(self) -> &'static str {
        "bridge_target_listing_unavailable"
    }
}

/// Splits `@name body` — the only accepted explicit addressing form.
///
/// Returns `None` when the message does not start with an `@name` token;
/// the caller then replies with the available names rather than broadcasting.
pub(crate) fn parse_targeted_text(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix('@')?;
    let split = rest.find(|c: char| c.is_ascii_whitespace())?;
    let (name, tail) = rest.split_at(split);
    let body = tail.trim_start_matches([' ', '\t']);
    if name.is_empty() || body.is_empty() {
        return None;
    }
    Some((name, body))
}

fn kind_of(surface: Surface) -> crate::sessions::CliKind {
    match surface {
        Surface::ClaudeCode => crate::sessions::CliKind::Claude,
        Surface::Codex => crate::sessions::CliKind::Codex,
    }
}

/// Builds the exact `(pid, started_at, surface)` address for one live session.
///
/// The registry name only SELECTS the candidate; the recipient carries the
/// process identity and, when the process table still binds it, the
/// full-precision start (`started_exact`) the wake paths require.
fn recipient_for(candidate: &Candidate) -> Recipient {
    let exact = match crate::sessions::session_info_exact_for_pid_kind(
        kind_of(candidate.surface),
        candidate.pid,
    ) {
        Ok(Some((info, exact)))
            if info
                .started_at
                .is_some_and(|s| crate::sessions::same_start(s, candidate.started_at)) =>
        {
            Some(exact)
        }
        _ => None,
    };
    Recipient {
        pid: candidate.pid,
        started_at: candidate.started_at,
        surface: candidate.surface,
        started_exact: exact,
    }
}

/// Whether `r` is still the incarnation it was resolved to (the store's
/// liveness check, mirroring `csq sessions send`).
fn recipient_liveness(r: &Recipient) -> Liveness {
    match crate::sessions::session_info_for_pid_kind(kind_of(r.surface), r.pid) {
        Ok(Some(info)) => match info.started_at {
            Some(s) if crate::sessions::same_start(s, r.started_at) => Liveness::Live,
            Some(_) => Liveness::Ended,
            None => Liveness::Unknown,
        },
        Ok(None) => Liveness::Ended,
        Err(_) => Liveness::Unknown,
    }
}

// ── Wake ───────────────────────────────────────────────────────────────────

/// Wakes `recipient` with the fixed pending-message notice.
///
/// This composes the EXISTING core wake path ([`crate::messaging::wake`]); it
/// opens no socket of its own. Claude Code gets the validated inbox-socket
/// post; Codex gets the validated `codex queue` wake. Any pre-condition that
/// cannot be proven yields `queued_only` (stored, not woken) — never a guess.
pub(crate) fn wake_recipient(base_dir: &Path, recipient: &Recipient, now: i64) -> Delivery {
    match recipient.surface {
        Surface::ClaudeCode => wake_claude(base_dir, recipient, now),
        Surface::Codex => wake_codex(base_dir, recipient),
    }
}

#[cfg(unix)]
fn wake_claude(base_dir: &Path, recipient: &Recipient, now: i64) -> Delivery {
    let Ok(now) = u64::try_from(now) else {
        return Delivery::QueuedOnly;
    };
    let notice = match crate::messaging::store::pending_notice(base_dir, now, recipient) {
        Ok(notice) if notice.count > 0 => notice,
        Ok(_) => return Delivery::QueuedOnly,
        Err(_) => {
            tracing::debug!(
                error_kind = "bridge_wake_notice_unreadable",
                "bridge wake uses a count-only notice; the store could not be read"
            );
            crate::messaging::store::PendingNotice::count_only(1)
        }
    };
    let Some(target) = wake::ClaudeWakeTarget::resolve(
        recipient.pid,
        recipient.started_at,
        recipient.started_exact,
        &|pid| {
            crate::sessions::session_info_exact_for_pid_kind(crate::sessions::CliKind::Claude, pid)
        },
        now,
    ) else {
        return Delivery::QueuedOnly;
    };
    wake::deliver_claude_coalesced_with_notice(
        &target,
        &wake::claude_socket_dirs(),
        &|| target.still_live_with(&crate::sessions::ancestor_start),
        &notice,
        wake::CLAUDE_SOCKET_TIMEOUT,
        now,
        &|| crate::messaging::store::pending_ids(base_dir, now, recipient).ok(),
    )
}

#[cfg(not(unix))]
fn wake_claude(_base_dir: &Path, _recipient: &Recipient, _now: i64) -> Delivery {
    // Claude Code's inbox socket is a Unix socket: nothing is attempted here.
    Delivery::QueuedOnly
}

/// Codex wake: validate the target's own launch and queue one fixed notice.
fn wake_codex(base_dir: &Path, recipient: &Recipient) -> Delivery {
    let Ok(Some((info, exact))) = crate::sessions::session_info_exact_for_pid_kind(
        crate::sessions::CliKind::Codex,
        recipient.pid,
    ) else {
        return Delivery::QueuedOnly;
    };
    if !info
        .started_at
        .is_some_and(|s| crate::sessions::same_start(s, recipient.started_at))
        || recipient.started_exact != Some(exact)
    {
        return Delivery::QueuedOnly;
    }
    let Some(launch) =
        crate::sessions::codex_launch_for_session(recipient.pid, recipient.started_at, exact)
    else {
        return Delivery::QueuedOnly;
    };
    let Some(target) =
        crate::sessions::wake_target_ok(base_dir, recipient.pid, &info.config_dir, &launch)
    else {
        return Delivery::QueuedOnly;
    };
    let spec = wake::WakeSpec::from_target(&target);
    let codex_home = spec.codex_home().to_path_buf();
    let thread = codex_thread_for(&target, &spec, &launch);
    if let Some(id) = thread.as_deref().filter(|_| target.still_live()) {
        // Correct an old subagent capture only after this incarnation's MAIN is proven.
        if crate::providers::codex::thread_id::write_captured_thread_id(&codex_home, id).is_err() {
            tracing::debug!(
                error_kind = "bridge_wake_capture_write_failed",
                "codex thread capture was not updated; the wake still proceeds"
            );
        }
    }
    let path = std::env::var_os("PATH");
    let home = std::env::var_os("HOME");
    wake::deliver(
        &spec,
        &|| target.still_live(),
        thread.as_deref(),
        1,
        wake::Launcher {
            program: std::ffi::OsStr::new("codex"),
            path: path.as_deref(),
            home: home.as_deref(),
        },
        wake::WAKE_TIMEOUT,
    )
}

/// Resolves the Codex main thread for `target`, or `None` when it cannot be
/// proven. Mirrors the `csq sessions send` discovery rule: only a thread whose
/// held-lock and top-level provenance is confirmed is returned.
fn codex_thread_for(
    target: &crate::sessions::WakeTarget,
    spec: &wake::WakeSpec,
    launch: &crate::sessions::CodexLaunch,
) -> Option<String> {
    use crate::providers::codex::thread_id as tid;
    let codex_home = spec.codex_home();
    let held = tid::held_lock_ids(
        target.pid(),
        &std::fs::canonicalize(codex_home.join("thread-writer-locks"))
            .unwrap_or_else(|_| codex_home.join("thread-writer-locks")),
    );
    let roles = held.as_ref().and_then(|h| {
        tid::read_thread_roles(
            &launch
                .sqlite_home
                .clone()
                .unwrap_or_else(|| codex_home.to_path_buf()),
            h,
        )
    });
    let selected =
        tid::select_main_thread(held.as_ref(), launch.thread_id.as_deref(), roles.as_ref());
    let holds = |id: &str| matches!(selected, tid::ThreadDiscovery::Found(ref main) if main == id);
    wake::resolve_thread_id(
        launch.thread_id.clone(),
        &|| match &selected {
            tid::ThreadDiscovery::Found(id) => tid::ThreadDiscovery::Found(id.clone()),
            other => other.clone(),
        },
        &|| tid::read_captured_thread_id(codex_home),
        &holds,
    )
}

// ── Injected daemon dependencies ───────────────────────────────────────────

/// A store refusal with a fixed-vocabulary tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoreFailure {
    tag: &'static str,
    /// A refusal that can never succeed on retry (the target ended, or the
    /// body is unacceptable). Such an update is dropped with an owner notice
    /// rather than blocking every later message behind an endless replay.
    permanent: bool,
}

impl StoreFailure {
    pub(crate) fn tag(self) -> &'static str {
        self.tag
    }

    pub(crate) fn is_permanent(self) -> bool {
        self.permanent
    }
}

/// An audit refusal with a fixed-vocabulary tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditFailure {
    tag: &'static str,
}

impl AuditFailure {
    pub(crate) fn tag(self) -> &'static str {
        self.tag
    }
}

/// The intent/outcome correlation of one delivery audit pair.
pub(crate) struct AuditTicket {
    chain_id: String,
    correlation: crate::audit::types::RecordId,
}

/// Metadata-only description of one inbound delivery (never a body or a hash).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeliveryAudit {
    pub update_id: u64,
    pub kind: &'static str,
    pub target_pid: u32,
    pub target_started_at: u64,
    pub target_surface: &'static str,
    pub byte_len: u64,
    pub outcome: &'static str,
}

/// Poll-loop durations (production constants; tests compress them).
#[derive(Debug, Clone, Copy)]
pub(crate) struct BridgeTiming {
    /// First backoff after a failed poll.
    pub initial_backoff: Duration,
    /// Cap on exponential poll backoff.
    pub max_backoff: Duration,
    /// Backoff after a `409 Conflict`.
    pub conflict_backoff: Duration,
}

impl BridgeTiming {
    fn production() -> Self {
        Self {
            initial_backoff: INITIAL_BACKOFF,
            max_backoff: MAX_BACKOFF,
            conflict_backoff: CONFLICT_BACKOFF,
        }
    }
}

/// The daemon surfaces the ingest loop needs, injected so every test is
/// hermetic (no vault, no process table, no real store, no audit chain).
pub(crate) trait BridgeIo: Send + Sync {
    /// Delay before the first poll (zero in tests).
    fn startup_delay(&self) -> Duration;
    /// How often an inactive bridge re-reads its config.
    fn inactive_recheck_interval(&self) -> Duration;
    /// Backoff durations for this run.
    fn timing(&self) -> BridgeTiming;
    /// Wall-clock UNIX seconds.
    fn now_secs(&self) -> i64;
    /// Reads the bridge config (`None` only when the file is absent).
    fn load_config(&self, base_dir: &Path) -> Result<Option<BridgeConfig>, BridgeConfigError>;
    /// Whether the phone kill switch is engaged. An unreadable marker state is
    /// an `Err` and the caller fails CLOSED.
    fn kill_switch_engaged(&self, base_dir: &Path) -> Result<bool, BridgeConfigError>;
    /// Engages the phone kill switch: writes the killed marker atomically at
    /// 0600. The daemon NEVER removes it; only the local `csq telegram on`
    /// does.
    fn engage_kill_switch(&self, base_dir: &Path) -> Result<(), BridgeConfigError>;
    /// Reads the poll cursor from its own state file (seeding it once from a
    /// pre-move config field when present).
    fn load_cursor(&self, base_dir: &Path) -> Result<u64, BridgeConfigError>;
    /// Writes the poll cursor to its own state file, atomically at 0600.
    fn save_cursor(&self, base_dir: &Path, update_id: u64) -> Result<(), BridgeConfigError>;
    /// Reads the bot token from the vault.
    fn load_bot_token(&self) -> Result<SecretString, SecretError>;
    /// Reads the 32-byte owner-attestation origin key.
    fn load_origin_key(&self) -> Result<[u8; 32], SecretError>;
    /// The live sessions with their registry names, and whether the listing was whole.
    fn live_candidates(&self, base_dir: &Path) -> Result<(Vec<Candidate>, bool), TargetError>;
    /// Stores one owner-attested message. The caller has already deduplicated
    /// by `update_id`; this write is the durable record a crash-replay relies on.
    #[allow(clippy::too_many_arguments)]
    fn store_owner(
        &self,
        base_dir: &Path,
        attestation: &OwnerAttestation,
        update_id: u64,
        tg_message_id: i64,
        target: &Recipient,
        body: &str,
        now: u64,
    ) -> Result<(), StoreFailure>;
    /// Wakes the target through the existing core wake path.
    fn wake(&self, base_dir: &Path, target: &Recipient, now: i64) -> Delivery;
    /// Runs the one allow-listed bridge command (`swap`) against `target`.
    ///
    /// Production applies the bridge gate (owner-granted class + the target
    /// slot's daemon-known login state) BEFORE any credential read or write,
    /// and re-verifies the session against the live process table. A refusal
    /// is final: the caller never retries and never picks a fallback slot.
    fn swap(
        &self,
        base_dir: &Path,
        target: &Recipient,
        slot: AccountNum,
        allow_classes: &[String],
    ) -> Result<SwapOutcome, SwapError>;
    /// Appends the delivery INTENT record. A refusal MUST abort delivery.
    fn audit_intent(
        &self,
        base_dir: &Path,
        record: &DeliveryAudit,
    ) -> Result<AuditTicket, AuditFailure>;
    /// Appends the delivery OUTCOME record (best effort; side effects committed).
    fn audit_outcome(&self, base_dir: &Path, ticket: &AuditTicket, record: &DeliveryAudit);
}

// ── Delivered-update ledger ────────────────────────────────────────────────

/// Why the delivered-update ledger could not be read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LedgerError {
    /// The state directory could not be created.
    DirectoryUnusable,
    /// The file exists but could not be read.
    Unreadable,
    /// The file is not the expected JSON.
    Corrupt,
    /// The file could not be published atomically.
    Unwritable,
}

impl LedgerError {
    fn tag(self) -> &'static str {
        match self {
            Self::DirectoryUnusable => "bridge_ledger_directory_unusable",
            Self::Unreadable => "bridge_ledger_unreadable",
            Self::Corrupt => "bridge_ledger_corrupt",
            Self::Unwritable => "bridge_ledger_unwritable",
        }
    }
}

/// The durable record of the highest Telegram update already claimed for
/// delivery. Persisted BEFORE the store write, so the crash window described
/// by the design ("store write done, high-water not yet persisted") replays
/// against a claim and stores exactly once.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveredLedger {
    delivered_update_id: u64,
}

/// Reads the claimed high-water. Absent means "nothing claimed".
///
/// An unreadable or corrupt ledger is an error, never `0`: treating it as
/// empty would re-deliver everything the ledger was protecting
/// (`guard-reader-writer-parity.md` MUST-2).
fn load_delivered(base_dir: &Path) -> Result<u64, LedgerError> {
    let path = base_dir.join(DELIVERED_LEDGER_FILE);
    // Private reader: a foreign-owned or group-writable ledger is refused, the
    // same containment class as the write side. A raised mark can only deny
    // delivery (DoS), never grant it, but path containment is rule 1's class.
    let bytes = crate::platform::fs::read_private_regular_nofollow_bounded(&path, LEDGER_MAX_BYTES)
        .map_err(|_| LedgerError::Unreadable)?;
    let Some(bytes) = bytes else {
        return Ok(0);
    };
    let ledger: DeliveredLedger =
        serde_json::from_slice(&bytes).map_err(|_| LedgerError::Corrupt)?;
    Ok(ledger.delivered_update_id)
}

/// Atomically claims `update_id` as delivered at 0600 (owner-local state).
fn save_delivered(base_dir: &Path, update_id: u64) -> Result<(), LedgerError> {
    std::fs::create_dir_all(base_dir).map_err(|_| LedgerError::DirectoryUnusable)?;
    let bytes = serde_json::to_vec(&DeliveredLedger {
        delivered_update_id: update_id,
    })
    .map_err(|_| LedgerError::Unwritable)?;
    let path = base_dir.join(DELIVERED_LEDGER_FILE);
    let writer = crate::platform::fs::write_private_tmp_synced_retained(&path, &bytes)
        .map_err(|_| LedgerError::Unwritable)?;
    writer.replace(&path).map_err(|_| LedgerError::Unwritable)
}

// ── Ingest state ───────────────────────────────────────────────────────────

struct BridgeState {
    rate: RateWindow,
    rejects: RejectCoalescer,
    conflict_alerted: bool,
    rate_notified: bool,
    /// One INFO/WARN per inactive stretch, not one per recheck.
    announced_inactive: bool,
    /// Set by [`handle_update`] when an update did NOT complete. The poll loop
    /// MUST then stop the batch: a later update that persists a higher
    /// high-water mark would move the Telegram offset past the failed one
    /// forever, so it would never be re-polled.
    halt_batch: bool,
    /// The poll cursor, mirrored from its own state file. The loop refreshes
    /// it before polling; `handle_update` advances it only after a successful
    /// durable write.
    cursor: u64,
}

impl BridgeState {
    fn new(now: Instant) -> Self {
        Self {
            rate: RateWindow::new(INBOUND_LIMIT, INBOUND_WINDOW),
            rejects: RejectCoalescer::new(now),
            conflict_alerted: false,
            rate_notified: false,
            announced_inactive: false,
            halt_batch: false,
            cursor: 0,
        }
    }
}

// ── Run loop ───────────────────────────────────────────────────────────────

/// A running bridge ingest task.
pub struct TelegramBridgeHandle {
    /// Join handle for the supervised loop.
    pub join: tokio::task::JoinHandle<()>,
}

/// Spawns the daemon's Telegram ingest loop on the caller's runtime.
///
/// Absent or disabled config is the kill switch: nothing is read from the
/// vault and no request is made. The task still re-reads the local config
/// every `INACTIVE_RECHECK_INTERVAL`, so `csq telegram on` takes effect
/// without a daemon restart; cancellation ends it at any point.
pub fn spawn(
    base_dir: PathBuf,
    cancel: CancellationToken,
    http: impl TelegramPost + 'static,
) -> TelegramBridgeHandle {
    TelegramBridgeHandle {
        join: tokio::spawn(run_telegram_bridge(base_dir, cancel, http)),
    }
}

/// Runs the Telegram ingest loop until cancelled.
///
/// A disabled or absent config does NOT return: the task idles and re-reads
/// the local config on `INACTIVE_RECHECK_INTERVAL`, because the supervised
/// daemon treats a subsystem return as a fault and because `csq telegram on`
/// writes only the config file. Cancellation ends it at any point.
///
/// The loop is OUTBOUND only: it never binds a socket or registers a webhook
/// (`security.md` MUST-7). The long poll and every backoff wait return
/// immediately on cancellation; acknowledgement and alert sends are bounded by
/// the HTTP client timeout (`CLIENT_TIMEOUT`) and are not separately
/// interruptible, so a drain can wait at most that timeout for one in-flight
/// send.
pub async fn run_telegram_bridge(
    base_dir: PathBuf,
    cancel: CancellationToken,
    http: impl TelegramPost,
) {
    run_telegram_bridge_with(base_dir, cancel, http, &ProductionIo).await;
}

async fn run_telegram_bridge_with<I, P>(
    base_dir: PathBuf,
    cancel: CancellationToken,
    http: P,
    io: &I,
) where
    I: BridgeIo,
    P: TelegramPost,
{
    if !sleep_or_cancel(&cancel, io.startup_delay()).await {
        return;
    }
    let timing = io.timing();
    let mut state = BridgeState::new(Instant::now());
    let mut token: Option<Arc<SecretString>> = None;
    let mut backoff = timing.initial_backoff;

    loop {
        if cancel.is_cancelled() {
            state.rejects.flush();
            return;
        }
        let loaded = match io.load_config(&base_dir) {
            Ok(config) => config,
            Err(error) => {
                if !state.announced_inactive {
                    state.announced_inactive = true;
                    tracing::warn!(
                        error_kind = error.error_kind_tag(),
                        reason = "config_unreadable",
                        "telegram bridge is inactive; ingest is idle"
                    );
                }
                if !sleep_or_cancel(&cancel, io.inactive_recheck_interval()).await {
                    return;
                }
                continue;
            }
        };
        let Some(mut config) = loaded else {
            if !state.announced_inactive {
                state.announced_inactive = true;
                tracing::info!(
                    event = "bridge_inactive",
                    reason = "not_configured",
                    "telegram bridge is not configured; ingest is idle"
                );
            }
            if !sleep_or_cancel(&cancel, io.inactive_recheck_interval()).await {
                return;
            }
            continue;
        };
        // The phone kill switch is a POLLING REFUSAL only. It does not touch
        // `config.enabled`, and the daemon never writes the config, so a local
        // `csq telegram on` racing a phone `/csq off` cannot be resurrected by
        // this process. NO branch other than this gate reads `enabled` — that
        // is why the marker cannot be forgotten by a future branch: a killed
        // bridge never polls, so no command or delivery branch is reachable
        // while the marker stands. An unreadable marker state fails CLOSED.
        let killed = match io.kill_switch_engaged(&base_dir) {
            Ok(killed) => killed,
            Err(error) => {
                tracing::warn!(
                    error_kind = error.error_kind_tag(),
                    "bridge kill-switch state unreadable; refusing to poll"
                );
                true
            }
        };
        if !config.enabled || !config.is_pinned() || killed {
            if !state.announced_inactive {
                state.announced_inactive = true;
                tracing::info!(
                    event = "bridge_inactive",
                    reason = if killed {
                        "killed"
                    } else if config.enabled {
                        "not_paired"
                    } else {
                        "disabled"
                    },
                    "telegram bridge is not active; ingest is idle"
                );
            }
            if !sleep_or_cancel(&cancel, io.inactive_recheck_interval()).await {
                return;
            }
            continue;
        }
        state.announced_inactive = false;

        if token.is_none() {
            match io.load_bot_token() {
                Ok(value) => token = Some(Arc::new(value)),
                Err(error) => {
                    tracing::warn!(
                        error_kind = error.error_kind_tag(),
                        "bridge bot token unavailable"
                    );
                    if !sleep_or_cancel(&cancel, backoff).await {
                        return;
                    }
                    backoff = next_backoff(backoff, timing.max_backoff);
                    continue;
                }
            }
        }
        // Clone the Arc so the response branches can clear the cache (an
        // `Unauthorized` reply means the vault value may have rotated) without
        // holding a borrow of it.
        let Some(cached) = token.clone() else {
            return;
        };
        let token_secret = cached.expose_secret();
        // The cursor lives in its own file so the bridge never writes the
        // config. A corrupt or unreadable cursor must NOT restart the poll at
        // 0 (that would replay up to 24 h of Telegram backlog), so back off
        // and retry the read instead.
        match io.load_cursor(&base_dir) {
            Ok(cursor) => state.cursor = cursor,
            Err(error) => {
                tracing::warn!(
                    error_kind = error.error_kind_tag(),
                    "bridge poll cursor unreadable; polling paused"
                );
                if !sleep_or_cancel(&cancel, backoff).await {
                    return;
                }
                backoff = next_backoff(backoff, timing.max_backoff);
                continue;
            }
        }
        let offset = state.cursor.saturating_add(1);
        let poll = tokio::select! {
            () = cancel.cancelled() => return,
            result = http.get_updates(token_secret, offset) => result,
        };
        match poll {
            Ok(updates) => {
                state.conflict_alerted = false;
                let mut halted = false;
                for update in &updates {
                    if cancel.is_cancelled() {
                        state.rejects.flush();
                        return;
                    }
                    // Re-read the config for every update: a local `csq telegram off`
                    // written while this batch is in flight must stop delivery at once.
                    config = match io.load_config(&base_dir) {
                        Ok(Some(current)) if current.enabled && current.is_pinned() => current,
                        _ => {
                            tracing::info!(
                                event = "bridge_inactive",
                                reason = "disabled_during_batch",
                                "telegram bridge stopped mid-batch"
                            );
                            // IDLE, never return: this task is in the
                            // supervised subsystem set, where any return is
                            // treated as a crash that restarts the whole
                            // session. Abandon the rest of the batch; the top
                            // of the loop sees the disabled config and sleeps
                            // its recheck interval.
                            break;
                        }
                    };
                    state.halt_batch = false;
                    handle_update(
                        io,
                        &http,
                        &base_dir,
                        &mut state,
                        token_secret,
                        &mut config,
                        update,
                    )
                    .await;
                    state.rejects.flush_if_due(Instant::now());
                    if state.halt_batch {
                        // Telegram's offset is the persisted high-water + 1.
                        // If a LATER update in this batch persisted a higher
                        // mark, the failed update would fall below the offset
                        // and never be re-polled. Stop here instead: the next
                        // poll re-fetches the failed update and everything
                        // after it.
                        tracing::warn!(
                            error_kind = "bridge_batch_halted",
                            update_id = update.raw.update_id,
                            "batch halted after an incomplete update; the failed update and \
                             every later one will be re-polled"
                        );
                        halted = true;
                        break;
                    }
                }
                if halted {
                    // The re-poll uses the SAME offset, so without pacing a
                    // persistently failing store would spin: a full poll plus
                    // an audit intent/outcome pair per attempt. Back off like
                    // any other failure, and keep backing off while halts
                    // repeat.
                    if !sleep_or_cancel(&cancel, backoff).await {
                        return;
                    }
                    backoff = next_backoff(backoff, timing.max_backoff);
                } else {
                    backoff = timing.initial_backoff;
                }
            }
            Err(error) if error.kind() == TelegramErrorKind::Conflict => {
                tracing::warn!(
                    error_kind = error.kind().tag(),
                    "telegram getUpdates conflict (webhook or second poller)"
                );
                if !state.conflict_alerted {
                    state.conflict_alerted = true;
                    if let Err(notice) = http
                        .send_message(token_secret, config.owner_chat_id, CONFLICT_NOTICE)
                        .await
                    {
                        tracing::warn!(
                            error_kind = notice.kind().tag(),
                            "bridge conflict notice could not be sent"
                        );
                    }
                }
                if !sleep_or_cancel(&cancel, timing.conflict_backoff).await {
                    return;
                }
            }
            Err(error) => {
                tracing::warn!(
                    error_kind = error.kind().tag(),
                    "telegram getUpdates failed; backing off"
                );
                if error.kind() == TelegramErrorKind::Unauthorized {
                    // `csq telegram rotate` may have replaced the vault value:
                    // drop the cached token so the next iteration re-reads it.
                    token = None;
                }
                if !sleep_or_cancel(&cancel, backoff).await {
                    return;
                }
                backoff = next_backoff(backoff, timing.max_backoff);
            }
        }
    }
}

fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

/// Sleeps for `delay`, returning `false` when cancellation arrived first.
async fn sleep_or_cancel(cancel: &CancellationToken, delay: Duration) -> bool {
    if delay.is_zero() {
        return !cancel.is_cancelled();
    }
    tokio::select! {
        () = cancel.cancelled() => false,
        () = tokio::time::sleep(delay) => true,
    }
}

/// Validates, routes, stores, persists the high-water mark, wakes and acks one
/// update. Failures are logged by fixed tag and never retried in a tight loop.
#[allow(clippy::too_many_arguments)]
async fn handle_update<I, P>(
    io: &I,
    http: &P,
    base_dir: &Path,
    state: &mut BridgeState,
    token: &str,
    config: &mut BridgeConfig,
    update: &TelegramUpdate,
) where
    I: BridgeIo,
    P: TelegramPost,
{
    let now = io.now_secs();
    let raw = &update.raw;
    let validated = match validate_update(
        raw,
        state.cursor,
        config.owner_user_id,
        config.owner_chat_id,
        now,
    ) {
        Ok(validated) => validated,
        Err(reject) => {
            // Slash text is refused by the shared validator as `NotMessage`
            // (commands ride the spec-34 relay, not this ingest), and that
            // refusal is emitted AFTER every identity screen — owner pin,
            // private chat, bot/forward/via-bot/sender-chat, edited. Reaching
            // it with slash text therefore means the message is authentically
            // the owner's. Such a message is NEVER stored for, or typed into,
            // a session: the one action the owner can take from the phone is
            // the kill switch, and every other slash command gets an explicit
            // refusal reply instead of a silent drop.
            if matches!(reject, Reject::NotMessage)
                && !raw.is_edited
                && raw
                    .text
                    .as_deref()
                    .is_some_and(|text| text.starts_with('/'))
            {
                handle_command(io, http, base_dir, state, token, config, raw, now).await;
                return;
            }
            state.rejects.record(reject.error_kind_tag());
            persist_high_water(
                io,
                base_dir,
                &mut state.cursor,
                raw.update_id,
                "refused_update",
            );
            return;
        }
    };

    if !state.rate.admit(Instant::now()) {
        if !state.rate_notified {
            state.rate_notified = true;
            send_notice(http, token, config.owner_chat_id, RATE_LIMIT_NOTICE).await;
        }
        state.rejects.record("bridge_rate_limited");
        persist_high_water(
            io,
            base_dir,
            &mut state.cursor,
            validated.update_id,
            "rate_limited",
        );
        return;
    }

    // The one allow-listed bridge command. It is NOT a slash command, so it
    // does not pass through `not_under_relay`; the daemon executes it under the
    // owner-granted class gate. Any text whose first word is exactly `swap`
    // belongs to this command surface: a malformed remainder is refused with
    // the usage line rather than typed into a session.
    match parse_swap_command(&validated.text) {
        SwapParse::NotSwap => {}
        SwapParse::Malformed => {
            state.rejects.record("swap_usage");
            send_notice(http, token, config.owner_chat_id, SWAP_USAGE_NOTICE).await;
            persist_high_water(
                io,
                base_dir,
                &mut state.cursor,
                validated.update_id,
                "swap_usage",
            );
            return;
        }
        SwapParse::Parsed(command) => {
            // `swap` is not `/`-prefixed, so the validator's command-kind
            // refusal does not cover it. A credential command recovered from a
            // day-old queue must not execute: apply the same freshness window
            // the slash commands get.
            if command_is_stale(validated.date, now) {
                state.rejects.record("bridge_reject_stale_command");
                send_notice(http, token, config.owner_chat_id, STALE_COMMAND_NOTICE).await;
                persist_high_water(
                    io,
                    base_dir,
                    &mut state.cursor,
                    validated.update_id,
                    "stale_command",
                );
                return;
            }
            handle_swap(
                io, http, base_dir, state, token, config, &validated, &command,
            )
            .await;
            return;
        }
    }

    let Some((name, body)) = parse_targeted_text(&validated.text) else {
        reply_no_target(io, http, token, config, base_dir).await;
        persist_high_water(
            io,
            base_dir,
            &mut state.cursor,
            validated.update_id,
            "no_target",
        );
        return;
    };

    let target = match io.live_candidates(base_dir) {
        Ok((live, complete)) => match registry::resolve_name(&live, name, None) {
            Resolution::One(candidate) => recipient_for(&candidate),
            Resolution::NotFound(names) if complete => {
                reply_no_such_session(http, token, config.owner_chat_id, name, &names).await;
                persist_high_water(
                    io,
                    base_dir,
                    &mut state.cursor,
                    validated.update_id,
                    "unknown_target",
                );
                return;
            }
            Resolution::NotFound(_) => {
                tracing::warn!(
                    error_kind = "bridge_target_listing_unavailable",
                    "bridge session listing is incomplete; refusing delivery"
                );
                send_notice(
                    http,
                    token,
                    config.owner_chat_id,
                    LISTING_UNAVAILABLE_NOTICE,
                )
                .await;
                persist_high_water(
                    io,
                    base_dir,
                    &mut state.cursor,
                    validated.update_id,
                    "listing_unavailable",
                );
                return;
            }
            Resolution::Ambiguous(candidates) => {
                let names: Vec<String> = candidates.into_iter().map(|c| c.name).collect();
                reply_no_such_session(http, token, config.owner_chat_id, name, &names).await;
                persist_high_water(
                    io,
                    base_dir,
                    &mut state.cursor,
                    validated.update_id,
                    "ambiguous_target",
                );
                return;
            }
        },
        Err(error) => {
            tracing::warn!(
                error_kind = error.tag(),
                "bridge could not read the live session listing"
            );
            send_notice(
                http,
                token,
                config.owner_chat_id,
                LISTING_UNAVAILABLE_NOTICE,
            )
            .await;
            persist_high_water(
                io,
                base_dir,
                &mut state.cursor,
                validated.update_id,
                "listing_unavailable",
            );
            return;
        }
    };

    let age_secs = now.saturating_sub(validated.date);
    let body = if age_secs > crate::bridge::validator::COMMAND_FRESHNESS_SECS {
        format!("[sent {age_secs}s ago] {body}")
    } else {
        body.to_owned()
    };
    let byte_len = body.len() as u64;
    let record = DeliveryAudit {
        update_id: validated.update_id,
        kind: "message",
        target_pid: target.pid,
        target_started_at: target.started_at,
        target_surface: target.surface.as_str(),
        byte_len,
        outcome: "intent",
    };

    let ticket = match io.audit_intent(base_dir, &record) {
        Ok(ticket) => ticket,
        Err(failure) => {
            tracing::warn!(
                error_kind = failure.tag(),
                update_id = validated.update_id,
                "bridge audit unavailable; refusing delivery"
            );
            send_notice(http, token, config.owner_chat_id, AUDIT_UNAVAILABLE_NOTICE).await;
            persist_high_water(
                io,
                base_dir,
                &mut state.cursor,
                validated.update_id,
                "audit_unavailable",
            );
            return;
        }
    };

    // ── Exactly-once claim ────────────────────────────────────────────────
    // The claim lands BEFORE the store write: a crash after the store but
    // before the poll-cursor persist replays this update against a ledger that
    // already claims it, so the message is stored ONCE. The claim is rolled
    // back only when the store returns an error, so a refused store never
    // strands a future retry. A crash between the claim and the store is the
    // at-most-once edge the design accepts (a duplicate owner command is the
    // injection this ordering prevents).
    let delivered = match load_delivered(base_dir) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                error_kind = error.tag(),
                update_id = validated.update_id,
                "bridge delivered-update ledger unreadable; refusing delivery"
            );
            send_notice(http, token, config.owner_chat_id, STATE_UNREADABLE_NOTICE).await;
            io.audit_outcome(
                base_dir,
                &ticket,
                &DeliveryAudit {
                    outcome: "refused_ledger",
                    ..record
                },
            );
            // Advance past it: a corrupt ledger would otherwise replay the same
            // update forever and block every later message.
            persist_high_water(
                io,
                base_dir,
                &mut state.cursor,
                validated.update_id,
                "ledger_unreadable",
            );
            return;
        }
    };
    let duplicate = validated.update_id <= delivered;
    if !duplicate {
        if let Err(error) = save_delivered(base_dir, validated.update_id) {
            tracing::warn!(
                error_kind = error.tag(),
                update_id = validated.update_id,
                "bridge delivered-update claim failed; refusing delivery"
            );
            send_notice(http, token, config.owner_chat_id, STATE_UNREADABLE_NOTICE).await;
            io.audit_outcome(
                base_dir,
                &ticket,
                &DeliveryAudit {
                    outcome: "refused_ledger",
                    ..record
                },
            );
            persist_high_water(
                io,
                base_dir,
                &mut state.cursor,
                validated.update_id,
                "ledger_unwritable",
            );
            return;
        }
    }

    if !duplicate {
        // A replay already has its durable record; only a first delivery mints
        // provenance and stores (so a replay cannot be refused by a vault blip).
        let key = match io.load_origin_key() {
            Ok(key) => key,
            Err(error) => {
                tracing::warn!(
                    error_kind = error.error_kind_tag(),
                    update_id = validated.update_id,
                    "bridge attestation key unavailable; refusing delivery"
                );
                roll_back_claim(base_dir, delivered, duplicate);
                io.audit_outcome(
                    base_dir,
                    &ticket,
                    &DeliveryAudit {
                        outcome: "refused_attestation_key",
                        ..record
                    },
                );
                send_notice(http, token, config.owner_chat_id, STATE_UNREADABLE_NOTICE).await;
                // The message was NOT delivered: tell the owner and do not
                // advance the cursor. Halt the batch so no LATER update can
                // advance it past this one; the next poll retries.
                state.halt_batch = true;
                return;
            }
        };
        let attestation = OwnerAttestation::mint(&validated, target.pid, target.started_at, &key);

        // Store FIRST: the durable record is what a crash-replay deduplicates on.
        if let Err(failure) = io.store_owner(
            base_dir,
            &attestation,
            validated.update_id,
            update.tg_message_id,
            &target,
            &body,
            u64::try_from(now).unwrap_or(0),
        ) {
            if failure.is_permanent() {
                tracing::warn!(
                    error_kind = failure.tag(),
                    update_id = validated.update_id,
                    "bridge store refused the update permanently; dropping it"
                );
                send_notice(http, token, config.owner_chat_id, STORE_REFUSED_NOTICE).await;
                roll_back_claim(base_dir, delivered, duplicate);
                io.audit_outcome(
                    base_dir,
                    &ticket,
                    &DeliveryAudit {
                        outcome: "refused_store_permanent",
                        ..record
                    },
                );
                // Advance past it: a permanent refusal would otherwise replay
                // forever and block every later message.
                persist_high_water(
                    io,
                    base_dir,
                    &mut state.cursor,
                    validated.update_id,
                    "store_refused",
                );
                return;
            }
            tracing::warn!(
                error_kind = failure.tag(),
                update_id = validated.update_id,
                "bridge store failed; batch halted so the update is re-polled"
            );
            // The message was not stored, so this update MUST be re-polled.
            // Any later update in this batch would advance the cursor past it.
            state.halt_batch = true;
            roll_back_claim(base_dir, delivered, duplicate);
            io.audit_outcome(
                base_dir,
                &ticket,
                &DeliveryAudit {
                    outcome: "refused_store",
                    ..record
                },
            );
            return;
        }
    }

    // Persist the high-water AFTER the durable write and BEFORE acting: a crash
    // in this window re-polls, and the delivered-update claim (above) makes the
    // replay a no-op (exactly one delivery).
    if !persist_high_water(
        io,
        base_dir,
        &mut state.cursor,
        validated.update_id,
        "delivered_update",
    ) {
        io.audit_outcome(
            base_dir,
            &ticket,
            &DeliveryAudit {
                outcome: "stored_not_acted",
                ..record
            },
        );
        // The durable write landed but the poll cursor did not, and the wake
        // has not run. Stop the batch so no later update advances the cursor
        // past this one; the replay is a silent no-op thanks to the ledger
        // claim, and it completes the action.
        state.halt_batch = true;
        return;
    }

    let delivery = io.wake(base_dir, &target, now);
    tracing::info!(
        event = "bridge_delivery",
        update_id = validated.update_id,
        surface = target.surface.as_str(),
        pid = target.pid,
        delivery = delivery.as_str(),
        duplicate,
        "owner message stored and dispatched"
    );
    io.audit_outcome(
        base_dir,
        &ticket,
        &DeliveryAudit {
            outcome: delivery_outcome_tag(delivery),
            ..record
        },
    );

    // The ack must say what THIS branch did. On `duplicate` the store was
    // SKIPPED — the ledger claimed the update before a crash — so "stored"
    // would be a false recovery claim to the owner.
    let ack = if duplicate {
        format!(
            "csq bridge: replay of update {}: store skipped (already claimed) for {} ({}) — {}",
            validated.update_id,
            target.surface.as_str(),
            target.pid,
            delivery.tagged()
        )
    } else {
        format!(
            "csq bridge: stored for {} ({}) — {}",
            target.surface.as_str(),
            target.pid,
            delivery.tagged()
        )
    };
    send_notice(http, token, config.owner_chat_id, &ack).await;
}

/// Handles a slash command that passed every identity screen.
///
/// Nothing here is stored for, or typed into, a session. `/csq off` works even
/// while the inbound rate window is exhausted: the kill switch must remain
/// reachable from the phone, and it costs one config write plus one reply.
#[allow(clippy::too_many_arguments)]
async fn handle_command<I, P>(
    io: &I,
    http: &P,
    base_dir: &Path,
    state: &mut BridgeState,
    token: &str,
    config: &mut BridgeConfig,
    raw: &RawUpdate,
    now: i64,
) where
    I: BridgeIo,
    P: TelegramPost,
{
    let text = raw.text.as_deref().unwrap_or_default();
    let is_off = text.trim_matches(' ') == OFF_COMMAND;
    // The kill switch is EXEMPT from the freshness window: replaying "off" can
    // only ever leave the bridge off, while losing the off because it aged out
    // would be fail-open. Every other command keeps the window. The exemption
    // does NOT exempt identity — the validator's owner pin, private-chat,
    // bot/forward/via-bot/sender-chat and edited screens all ran before this
    // function, and dedup is the high-water cursor.
    if !is_off && command_is_stale(raw.date, now) {
        state.rejects.record("bridge_reject_stale_command");
        send_notice(http, token, config.owner_chat_id, STALE_COMMAND_NOTICE).await;
        persist_high_water(
            io,
            base_dir,
            &mut state.cursor,
            raw.update_id,
            "stale_command",
        );
        return;
    }

    let record = DeliveryAudit {
        update_id: raw.update_id,
        kind: "command",
        target_pid: 0,
        target_started_at: 0,
        target_surface: "none",
        byte_len: text.len() as u64,
        outcome: "intent",
    };
    // A command moves neither a message nor a credential, so an unavailable
    // audit chain does not block it: the audit-unavailable rule refuses
    // DELIVERIES. The miss is logged with a fixed tag.
    let ticket = match io.audit_intent(base_dir, &record) {
        Ok(ticket) => Some(ticket),
        Err(failure) => {
            tracing::warn!(
                error_kind = failure.tag(),
                update_id = raw.update_id,
                "bridge command audit unavailable; continuing"
            );
            None
        }
    };

    if is_off {
        // The phone kill switch. The daemon writes ONLY the killed marker and
        // NEVER the config: `csq telegram on` / `off` remain the config's only
        // writers, so a local `on` racing this off cannot be resurrected here.
        // Only the local `on` removes the marker. The cursor is advanced so
        // the off is not replayed; the bridge is already killed, so a failed
        // cursor write cannot resurrect it. The batch still halts so no later
        // update in it is delivered after the kill.
        match io.engage_kill_switch(base_dir) {
            Ok(()) => {
                persist_high_water(io, base_dir, &mut state.cursor, raw.update_id, "off");
                state.halt_batch = true;
                tracing::info!(
                    event = "bridge_disabled_from_phone",
                    update_id = raw.update_id,
                    "kill switch engaged from the phone"
                );
                send_notice(http, token, config.owner_chat_id, OFF_CONFIRMATION).await;
                if let Some(ticket) = ticket {
                    io.audit_outcome(
                        base_dir,
                        &ticket,
                        &DeliveryAudit {
                            outcome: "off",
                            ..record
                        },
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    error_kind = error.error_kind_tag(),
                    update_id = raw.update_id,
                    "bridge kill-switch marker could not be written"
                );
                // Nothing acted and no cursor was written: halt the batch so
                // no later update can advance the poll cursor past the kill
                // switch before it is re-delivered.
                state.halt_batch = true;
                send_notice(http, token, config.owner_chat_id, STATE_UNREADABLE_NOTICE).await;
                if let Some(ticket) = ticket {
                    io.audit_outcome(
                        base_dir,
                        &ticket,
                        &DeliveryAudit {
                            outcome: "refused_state_unreadable",
                            ..record
                        },
                    );
                }
            }
        }
        return;
    }

    if !state.rate.admit(Instant::now()) {
        if !state.rate_notified {
            state.rate_notified = true;
            send_notice(http, token, config.owner_chat_id, RATE_LIMIT_NOTICE).await;
        }
        state.rejects.record("bridge_rate_limited");
        persist_high_water(
            io,
            base_dir,
            &mut state.cursor,
            raw.update_id,
            "rate_limited",
        );
        return;
    }

    let refusal = format!(
        "csq bridge: {NOT_UNDER_RELAY} — slash commands are not relayed yet; nothing was sent."
    );
    send_notice(http, token, config.owner_chat_id, &refusal).await;
    state.rejects.record(NOT_UNDER_RELAY);
    if let Some(ticket) = ticket {
        io.audit_outcome(
            base_dir,
            &ticket,
            &DeliveryAudit {
                outcome: NOT_UNDER_RELAY,
                ..record
            },
        );
    }
    persist_high_water(
        io,
        base_dir,
        &mut state.cursor,
        raw.update_id,
        "not_under_relay",
    );
}

/// The owner-facing reason for a refused swap.
///
/// The two variants that carry free-form text (`Failed`'s anyhow chain and
/// `LaunchBlocked`'s operator line) are replaced with fixed vocabulary: a
/// host path in a Telegram message is disclosure across a trust boundary.
/// Every other variant's `Display` is fixed by construction and is passed
/// through token redaction anyway, so a future free-form variant cannot
/// regress the guarantee.
fn swap_refusal_reason(error: &SwapError) -> String {
    match error {
        SwapError::Failed(_) => "the swap operation failed".to_owned(),
        SwapError::LaunchBlocked { .. } => "the target slot is blocked for launch".to_owned(),
        other => crate::error::redact_tokens(&other.to_string()),
    }
}

/// Whether a command-bearing message is too old (or too future-dated) to act
/// on.
///
/// Telegram retains undelivered updates for about a day, so a `swap` issued
/// yesterday would otherwise execute on recovery and rebind a live session to
/// another account. The same window gates slash commands.
fn command_is_stale(date: i64, now: i64) -> bool {
    date > now.saturating_add(crate::bridge::validator::FUTURE_SKEW_SECS)
        || now.saturating_sub(date) > crate::bridge::validator::COMMAND_FRESHNESS_SECS
}

/// One parsed [`SWAP_COMMAND`] message.
struct SwapCommand<'a> {
    session: &'a str,
    slot: u16,
}

/// What a message text is with respect to the bridge command surface.
enum SwapParse<'a> {
    /// Not the command word; ordinary routing applies.
    NotSwap,
    /// The command word, but not its exact shape.
    Malformed,
    /// A well-formed `swap <session> <N>`.
    Parsed(SwapCommand<'a>),
}

/// Parses the bridge command: the WHOLE message, trimmed of ASCII spaces, is
/// exactly `swap <session> <N>`, case-sensitive.
///
/// The session name may not contain a space and the slot must be a decimal
/// number. Any other text that starts with the command word is refused as
/// malformed rather than routed into a session named `swap`.
fn parse_swap_command(text: &str) -> SwapParse<'_> {
    let trimmed = text.trim_matches(' ');
    let mut parts = trimmed.split(' ');
    let Some(first) = parts.next() else {
        return SwapParse::NotSwap;
    };
    if first != SWAP_COMMAND {
        return SwapParse::NotSwap;
    }
    let (Some(session), Some(raw_slot), None) = (parts.next(), parts.next(), parts.next()) else {
        return SwapParse::Malformed;
    };
    if session.is_empty() {
        return SwapParse::Malformed;
    }
    let Ok(slot) = raw_slot.parse::<u16>() else {
        return SwapParse::Malformed;
    };
    SwapParse::Parsed(SwapCommand { session, slot })
}

/// Replies with a named swap refusal, records it, and advances the cursor.
///
/// A refusal is FINAL: the high-water mark advances, so the command is never
/// retried and no fallback slot or target is ever chosen.
#[allow(clippy::too_many_arguments)]
async fn refuse_swap<I, P>(
    io: &I,
    http: &P,
    base_dir: &Path,
    state: &mut BridgeState,
    token: &str,
    config: &mut BridgeConfig,
    update_id: u64,
    code: &'static str,
    detail: &str,
) where
    I: BridgeIo,
    P: TelegramPost,
{
    state.rejects.record(code);
    let text = if detail.is_empty() {
        format!("csq bridge: swap refused — {code}; nothing changed.")
    } else {
        format!("csq bridge: swap refused — {code}: {detail}; nothing changed.")
    };
    send_notice(http, token, config.owner_chat_id, &text).await;
    persist_high_water(io, base_dir, &mut state.cursor, update_id, code);
}

/// Executes `swap <session> <N>`: resolves the session, re-verifies it against
/// the live process table, runs the GATED bridge swap and echoes the outcome.
///
/// The production impl applies the owner-granted class gate and the
/// daemon-known target-slot login verdict before any credential operation; a
/// refusal is echoed with its named reason and is never retried.
#[allow(clippy::too_many_arguments)]
async fn handle_swap<I, P>(
    io: &I,
    http: &P,
    base_dir: &Path,
    state: &mut BridgeState,
    token: &str,
    config: &mut BridgeConfig,
    update: &crate::bridge::validator::ValidatedUpdate,
    command: &SwapCommand<'_>,
) where
    I: BridgeIo,
    P: TelegramPost,
{
    let slot = match AccountNum::try_from(command.slot) {
        Ok(slot) => slot,
        Err(_) => {
            refuse_swap(
                io,
                http,
                base_dir,
                state,
                token,
                config,
                update.update_id,
                "swap_slot_out_of_range",
                "",
            )
            .await;
            return;
        }
    };
    let target = match io.live_candidates(base_dir) {
        Ok((live, complete)) => match registry::resolve_name(&live, command.session, None) {
            Resolution::One(candidate) => recipient_for(&candidate),
            Resolution::NotFound(names) if complete => {
                let detail = format!(
                    "no session named {}; available: {}",
                    command.session,
                    names.join(", ")
                );
                refuse_swap(
                    io,
                    http,
                    base_dir,
                    state,
                    token,
                    config,
                    update.update_id,
                    "swap_target_not_found",
                    &detail,
                )
                .await;
                return;
            }
            Resolution::NotFound(_) => {
                refuse_swap(
                    io,
                    http,
                    base_dir,
                    state,
                    token,
                    config,
                    update.update_id,
                    "swap_listing_unavailable",
                    "",
                )
                .await;
                return;
            }
            Resolution::Ambiguous(candidates) => {
                let names: Vec<String> = candidates.into_iter().map(|c| c.name).collect();
                let detail = format!(
                    "session name {} is ambiguous: {}",
                    command.session,
                    names.join(", ")
                );
                refuse_swap(
                    io,
                    http,
                    base_dir,
                    state,
                    token,
                    config,
                    update.update_id,
                    "swap_target_ambiguous",
                    &detail,
                )
                .await;
                return;
            }
        },
        Err(_) => {
            refuse_swap(
                io,
                http,
                base_dir,
                state,
                token,
                config,
                update.update_id,
                "swap_listing_unavailable",
                "",
            )
            .await;
            return;
        }
    };

    let record = DeliveryAudit {
        update_id: update.update_id,
        kind: "swap",
        target_pid: target.pid,
        target_started_at: target.started_at,
        target_surface: target.surface.as_str(),
        byte_len: update.text.len() as u64,
        outcome: "intent",
    };
    let ticket = match io.audit_intent(base_dir, &record) {
        Ok(ticket) => ticket,
        Err(failure) => {
            tracing::warn!(
                error_kind = failure.tag(),
                update_id = update.update_id,
                "bridge audit unavailable; swap refused"
            );
            send_notice(http, token, config.owner_chat_id, AUDIT_UNAVAILABLE_NOTICE).await;
            persist_high_water(
                io,
                base_dir,
                &mut state.cursor,
                update.update_id,
                "audit_unavailable",
            );
            return;
        }
    };

    // ── Exactly-once claim (mirrors the message path) ─────────────────────
    // A swap moves credentials. Claim the update in the delivered ledger
    // BEFORE the operation: a crash in the ack round trip, in the audit write
    // or in a failed cursor save replays this update against a ledger that
    // already claims it, so the swap can never run twice.
    let delivered = match load_delivered(base_dir) {
        Ok(delivered) => delivered,
        Err(error) => {
            tracing::warn!(
                error_kind = error.tag(),
                update_id = update.update_id,
                "bridge delivered-update ledger unreadable; swap refused"
            );
            send_notice(http, token, config.owner_chat_id, STATE_UNREADABLE_NOTICE).await;
            io.audit_outcome(
                base_dir,
                &ticket,
                &DeliveryAudit {
                    outcome: "refused_ledger",
                    ..record
                },
            );
            persist_high_water(
                io,
                base_dir,
                &mut state.cursor,
                update.update_id,
                "ledger_unreadable",
            );
            return;
        }
    };
    if update.update_id <= delivered {
        // A replay after the swap already ran: never execute it again.
        tracing::info!(
            event = "bridge_swap_replay",
            update_id = update.update_id,
            "swap replay skipped; the ledger already claims this update"
        );
        // The claim is written BEFORE the swap, so a crash in between leaves a
        // claimed update that was never applied. Saying "already applied"
        // would be a false recovery claim; the honest answer is that the
        // outcome is unknown and the swap will not be re-run.
        send_notice(
            http,
            token,
            config.owner_chat_id,
            "csq bridge: replay of a swap the ledger already claimed; it was NOT re-run and its outcome is unconfirmed — check the slot at the machine.",
        )
        .await;
        io.audit_outcome(
            base_dir,
            &ticket,
            &DeliveryAudit {
                outcome: "swapped_replay",
                ..record
            },
        );
        persist_high_water(
            io,
            base_dir,
            &mut state.cursor,
            update.update_id,
            "swap_replay",
        );
        return;
    }
    if let Err(error) = save_delivered(base_dir, update.update_id) {
        tracing::warn!(
            error_kind = error.tag(),
            update_id = update.update_id,
            "bridge delivered-update claim failed; swap refused"
        );
        send_notice(http, token, config.owner_chat_id, STATE_UNREADABLE_NOTICE).await;
        io.audit_outcome(
            base_dir,
            &ticket,
            &DeliveryAudit {
                outcome: "refused_ledger",
                ..record
            },
        );
        persist_high_water(
            io,
            base_dir,
            &mut state.cursor,
            update.update_id,
            "ledger_unwritable",
        );
        return;
    }

    let executed = match io.swap(base_dir, &target, slot, &config.allow_classes) {
        Ok(outcome) => {
            let ack = format!(
                "csq bridge: swapped {} ({}) from slot {} to slot {}.",
                command.session,
                target.pid,
                outcome.from.get(),
                outcome.account.get()
            );
            send_notice(http, token, config.owner_chat_id, &ack).await;
            tracing::info!(
                event = "bridge_swap",
                update_id = update.update_id,
                pid = target.pid,
                from_slot = outcome.from.get(),
                to_slot = outcome.account.get(),
                "bridge swap succeeded"
            );
            io.audit_outcome(
                base_dir,
                &ticket,
                &DeliveryAudit {
                    outcome: "swapped",
                    ..record
                },
            );
            true
        }
        Err(error) => {
            let code = error.code();
            state.rejects.record(code);
            // The ledger claimed the update but the swap did not run: release
            // the claim so a re-poll (after a failed cursor save) re-refuses
            // instead of reporting a phantom success.
            roll_back_claim(base_dir, delivered, false);
            // Never forward a free-form error body to Telegram. `Failed`
            // carries an anyhow chain and `LaunchBlocked` an operator line;
            // either can name a host path (for example the raw CLAUDE_HOME),
            // and a Telegram message crosses a trust boundary. Fixed reasons
            // for those two variants, token redaction as a second layer for
            // every future variant that grows free-form text.
            let reason = swap_refusal_reason(&error);
            let ack = format!("csq bridge: swap refused — {code}: {reason}; nothing changed.");
            send_notice(http, token, config.owner_chat_id, &ack).await;
            io.audit_outcome(
                base_dir,
                &ticket,
                &DeliveryAudit {
                    outcome: code,
                    ..record
                },
            );
            false
        }
    };
    if !persist_high_water(io, base_dir, &mut state.cursor, update.update_id, "swap") && executed {
        // The swap ran but the cursor did not land. Halt the batch so no later
        // update advances the cursor past this one; the replay is caught by
        // the ledger claim above and never re-executes the swap.
        state.halt_batch = true;
        io.audit_outcome(
            base_dir,
            &ticket,
            &DeliveryAudit {
                outcome: "swapped_not_recorded",
                ..record
            },
        );
    }
}

/// Rolls a delivery claim back to `previous` after a refused store.
///
/// A failed rollback leaves the claim in place, which would turn the next
/// replay into a silent skip; it is logged as a WARN with a fixed tag so the
/// operator can see the at-most-once edge rather than discovering it as a
/// missing message.
fn roll_back_claim(base_dir: &Path, previous: u64, duplicate: bool) {
    if duplicate {
        return;
    }
    if let Err(error) = save_delivered(base_dir, previous) {
        tracing::warn!(
            error_kind = error.tag(),
            "bridge delivered-update claim could not be rolled back; a replay of this update \
             will be skipped"
        );
    }
}

/// Whether an audit outcome names a FAILED operation.
///
/// Delivery refusals already start with `refused`, but a refused `swap`
/// reports its [`SwapError::code`] (`class_not_allowed`, `swap_target_dead`,
/// `target_slot_login_needed`, `swap_failed`, …), which does not. Classifying
/// by prefix alone therefore audited every refused swap as `OpOutcome::Ok`,
/// so the audit chain claimed a credential operation succeeded when it did
/// not. Every `SwapError` code is listed here, and a test constructs all of
/// them so a new variant cannot silently fall through to `Ok`.
fn outcome_is_failure(outcome: &str) -> bool {
    outcome.starts_with("refused")
        || matches!(
            outcome,
            "class_not_allowed"
                | "swap_target_dead"
                | "swap_target_unverifiable"
                | "swap_handle_dir_invalid"
                | "swap_cross_surface"
                | "swap_third_party_slot"
                | "swap_surface_unsupported"
                | "swap_target_not_ready"
                | "swap_slot_out_of_range"
                | "swap_launch_blocked"
                | "target_slot_login_needed"
                | "swap_failed"
                | "swapped_not_recorded"
                // A replayed swap was CLAIMED but not confirmed applied (the
                // claim is written before the operation, so a crash in between
                // lands here). Auditing it as Ok would assert an execution the
                // daemon cannot prove, so it is classified Failed with the
                // reason tag — the same truthfulness the owner-facing ack now
                // states.
                | "swapped_replay"
        )
}

fn delivery_outcome_tag(delivery: Delivery) -> &'static str {
    match delivery {
        Delivery::ClaudeWoken => "claude_woken",
        Delivery::CodexWoken => "codex_woken",
        Delivery::QueuedOnly => "queued_only",
        Delivery::StoredNoWake => "stored_no_wake",
        Delivery::ClaudeWakeFailed | Delivery::ClaudeWakeContended => "claude_wake_failed",
        Delivery::ClaudeWakePending => "claude_wake_pending",
        Delivery::ClaudeWakeRateLimited => "claude_wake_rate_limited",
        Delivery::CodexWakeFailed => "codex_wake_failed",
        Delivery::CodexQueued | Delivery::CodexWakePending | Delivery::CodexWakeDeferred => {
            "codex_queued"
        }
        Delivery::CodexQueuedUnverified | Delivery::CodexRowNeverSeen => "codex_queued_unverified",
        Delivery::CodexNoTurnYet | Delivery::CodexWakeInFlight => "queued_only",
    }
}

/// Persists a new poll high-water mark. Returns whether it landed.
fn persist_high_water<I: BridgeIo>(
    io: &I,
    base_dir: &Path,
    cursor: &mut u64,
    update_id: u64,
    stage: &'static str,
) -> bool {
    if update_id <= *cursor {
        return true;
    }
    // The cursor lives in its OWN file (`telegram-bridge-state.json`). The
    // bridge never writes the owner config here, so it cannot resurrect a
    // concurrent `csq telegram off` — there is no read-modify-write of the
    // config to race, by construction rather than by timing.
    match io.save_cursor(base_dir, update_id) {
        Ok(()) => {
            *cursor = update_id;
            true
        }
        Err(error) => {
            tracing::warn!(
                error_kind = error.error_kind_tag(),
                stage,
                update_id,
                "bridge poll cursor persist failed"
            );
            false
        }
    }
}

/// Sends one fixed acknowledgement text; a failure is logged and not retried.
async fn send_notice<P: TelegramPost>(http: &P, token: &str, chat_id: i64, text: &str) {
    if let Err(error) = http.send_message(token, chat_id, text).await {
        tracing::warn!(
            error_kind = error.kind().tag(),
            "bridge notice could not be sent"
        );
    }
}

/// Replies to a message that names no session, listing what can be addressed.
async fn reply_no_target<I: BridgeIo, P: TelegramPost>(
    io: &I,
    http: &P,
    token: &str,
    config: &BridgeConfig,
    base_dir: &Path,
) {
    let names = match io.live_candidates(base_dir) {
        Ok((live, true)) => available_names(&live),
        _ => Vec::new(),
    };
    let text = if names.is_empty() {
        format!("{NO_SUCH_SESSION_PREFIX}; address one with `@name message`.")
    } else {
        format!(
            "{NO_SUCH_SESSION_PREFIX}; address one with `@name message`. Available: {}",
            names.join(", ")
        )
    };
    send_notice(http, token, config.owner_chat_id, &text).await;
}

async fn reply_no_such_session<P: TelegramPost>(
    http: &P,
    token: &str,
    chat_id: i64,
    name: &str,
    names: &[String],
) {
    let text = format!(
        "{NO_SUCH_SESSION_PREFIX}: {name}. Available: {}",
        names.join(", ")
    );
    send_notice(http, token, chat_id, &text).await;
}

fn available_names(live: &[Candidate]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for candidate in live {
        if !names
            .iter()
            .any(|n| registry::names_equal(n, &candidate.name))
        {
            names.push(candidate.name.clone());
        }
        if names.len() == 10 {
            break;
        }
    }
    names
}

// ── Production wiring ──────────────────────────────────────────────────────

/// The real daemon surfaces (vault, process table, message store, audit chain).
pub(crate) struct ProductionIo;

impl BridgeIo for ProductionIo {
    fn startup_delay(&self) -> Duration {
        STARTUP_DELAY
    }

    fn inactive_recheck_interval(&self) -> Duration {
        INACTIVE_RECHECK_INTERVAL
    }

    fn timing(&self) -> BridgeTiming {
        BridgeTiming::production()
    }

    fn now_secs(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
            Err(_) => 0,
        }
    }

    fn load_config(&self, base_dir: &Path) -> Result<Option<BridgeConfig>, BridgeConfigError> {
        bridge_config::load(base_dir)
    }

    fn kill_switch_engaged(&self, base_dir: &Path) -> Result<bool, BridgeConfigError> {
        bridge_config::kill_switch_engaged(base_dir)
    }

    fn engage_kill_switch(&self, base_dir: &Path) -> Result<(), BridgeConfigError> {
        std::fs::create_dir_all(base_dir).map_err(|_| BridgeConfigError::DirectoryUnusable)?;
        let path = base_dir.join(bridge_config::KILLED_FILE);
        // Presence is the whole protocol; the content is ignored. Same
        // target-taking private-temp factory as every other owner-local write
        // (`security.md` MUST-4/5, §5a).
        let writer = crate::platform::fs::write_private_tmp_synced_retained(&path, b"killed\n")
            .map_err(|_| BridgeConfigError::ConfigUnwritable)?;
        writer
            .replace(&path)
            .map_err(|_| BridgeConfigError::ConfigUnwritable)
    }

    fn load_cursor(&self, base_dir: &Path) -> Result<u64, BridgeConfigError> {
        bridge_config::load_cursor(base_dir).map(|cursor| cursor.high_water_update_id)
    }

    fn save_cursor(&self, base_dir: &Path, update_id: u64) -> Result<(), BridgeConfigError> {
        bridge_config::save_cursor(
            bridge_config::BridgeCursor {
                high_water_update_id: update_id,
            },
            base_dir,
        )
    }

    fn load_bot_token(&self) -> Result<SecretString, SecretError> {
        bridge_secrets::load_bot_token()
    }

    fn load_origin_key(&self) -> Result<[u8; 32], SecretError> {
        bridge_secrets::load_origin_key()
    }

    fn live_candidates(&self, base_dir: &Path) -> Result<(Vec<Candidate>, bool), TargetError> {
        let home = crate::platform::home::home_dir().ok_or(TargetError)?;
        let listing = crate::sessions::list_rows_for_names(base_dir, &home).ok_or(TargetError)?;
        if listing.restricted {
            return Err(TargetError);
        }
        Ok((
            registry::candidates_from_rows(&listing.rows),
            listing.is_complete(),
        ))
    }

    fn store_owner(
        &self,
        base_dir: &Path,
        attestation: &OwnerAttestation,
        update_id: u64,
        tg_message_id: i64,
        target: &Recipient,
        body: &str,
        now: u64,
    ) -> Result<(), StoreFailure> {
        let fs = crate::sessions::directives::real_fs();
        crate::messaging::store::send_owner(
            base_dir,
            now,
            &fs,
            &crate::messaging::limits::Limits::DEFAULT,
            &recipient_liveness,
            attestation,
            update_id,
            tg_message_id,
            *target,
            body,
        )
        .map(|_| ())
        .map_err(|error| {
            // `TargetMismatch` is the store's "recipient session is not
            // running"; `InvalidInput` covers an unacceptable body. Neither
            // can succeed on retry, so they are dropped with a notice rather
            // than blocking the queue. `RateLimited` / `Undetermined` retry.
            let (tag, permanent) = match error.code {
                crate::sdk::SdkErrorCode::TargetMismatch => ("bridge_store_target_ended", true),
                crate::sdk::SdkErrorCode::InvalidInput => ("bridge_store_invalid", true),
                crate::sdk::SdkErrorCode::RateLimited => ("bridge_store_rate_limited", false),
                crate::sdk::SdkErrorCode::Undetermined => ("bridge_store_undetermined", false),
                _ => ("bridge_store_failed", false),
            };
            StoreFailure { tag, permanent }
        })
    }

    fn wake(&self, base_dir: &Path, target: &Recipient, now: i64) -> Delivery {
        wake_recipient(base_dir, target, now)
    }

    fn swap(
        &self,
        base_dir: &Path,
        target: &Recipient,
        slot: AccountNum,
        allow_classes: &[String],
    ) -> Result<SwapOutcome, SwapError> {
        // Daemon-known verdict, never a probe: only a slot in the classified
        // LOGIN-NEEDED state is refused — it cannot authenticate, so binding a
        // live session to it is refused BEFORE any handle-dir, credential or
        // marker operation. An UNKNOWN marker (generic tag from the
        // pre-classification writer, unreadable file) is NOT evidence the
        // credential is dead: refusing on it would strand a healthy slot, so
        // the swap proceeds (guard-reader-writer-parity.md MUST-2 fail-open).
        let target_login_dead =
            crate::refresh::sentinel::login_needed_state(base_dir, slot).is_login_needed();
        crate::session::swap_session::swap_session_from_bridge_for_recipient(
            base_dir,
            target,
            slot,
            allow_classes,
            target_login_dead,
        )
    }

    fn audit_intent(
        &self,
        base_dir: &Path,
        record: &DeliveryAudit,
    ) -> Result<AuditTicket, AuditFailure> {
        use crate::audit::op_emit;
        let chain_id = op_emit::load_chain_id(base_dir);
        let correlation = op_emit::gen_correlation_id().map_err(|_| AuditFailure {
            tag: "bridge_audit_correlation_failed",
        })?;
        let emitted = op_emit::emit_intent(
            base_dir,
            &chain_id,
            crate::audit::types::EventKind::TelegramBridgeDelivery,
            bridge_audit_payload(record),
            correlation.clone(),
        )
        .map_err(|_| AuditFailure {
            tag: "bridge_audit_intent_failed",
        })?;
        if !emitted {
            return Err(AuditFailure {
                tag: "bridge_audit_chain_broken",
            });
        }
        Ok(AuditTicket {
            chain_id,
            correlation,
        })
    }

    fn audit_outcome(&self, base_dir: &Path, ticket: &AuditTicket, record: &DeliveryAudit) {
        use crate::audit::op_emit;
        use crate::audit::types::OpOutcome;
        let result = if outcome_is_failure(record.outcome) {
            OpOutcome::Failed {
                reason: op_emit::redact_reason(record.outcome),
            }
        } else {
            OpOutcome::Ok
        };
        if op_emit::emit_outcome(
            base_dir,
            &ticket.chain_id,
            crate::audit::types::EventKind::TelegramBridgeDelivery,
            bridge_audit_payload(record),
            ticket.correlation.clone(),
            result,
        )
        .is_err()
        {
            tracing::warn!(
                error_kind = "bridge_audit_outcome_failed",
                update_id = record.update_id,
                "bridge audit outcome could not be written"
            );
        }
    }
}

/// Builds the metadata-only audit payload for one delivery phase.
fn bridge_audit_payload(record: &DeliveryAudit) -> crate::audit::types::EventPayload {
    use crate::audit::types::{EventPayload, TelegramBridgeDeliveryPayload};
    EventPayload::TelegramBridgeDelivery(TelegramBridgeDeliveryPayload {
        update_id: record.update_id,
        kind: record.kind.to_string(),
        target_pid: record.target_pid,
        target_started_at: record.target_started_at,
        target_surface: record.target_surface.to_string(),
        byte_len: record.byte_len,
        outcome: record.outcome.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messaging::registry::NameSource;
    use async_trait::async_trait;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const OWNER: i64 = 42;
    const NOW: i64 = 1_000_000;
    const TOKEN: &str = "123:FAKETEST";

    fn candidate(name: &str) -> Candidate {
        Candidate {
            pid: 4_242,
            started_at: 1_000,
            surface: Surface::ClaudeCode,
            name: name.to_string(),
            name_source: NameSource::SelfSet,
            repo: None,
            branch: None,
            label_fallback: false,
        }
    }

    fn owner_config() -> BridgeConfig {
        BridgeConfig {
            enabled: true,
            owner_user_id: OWNER,
            owner_chat_id: OWNER,
            allow_classes: Vec::new(),
        }
    }

    fn update(update_id: u64, text: &str, from_id: i64) -> TelegramUpdate {
        TelegramUpdate {
            raw: RawUpdate {
                update_id,
                from_id,
                chat_id: from_id,
                chat_type: "private".to_string(),
                is_bot: false,
                date: NOW,
                text: Some(text.to_string()),
                has_forward: false,
                via_bot: false,
                sender_chat: false,
                is_edited: false,
                // Mirror the production adapter: slash text is command-kind.
                is_command_kind: text.starts_with('/'),
            },
            tg_message_id: i64::try_from(update_id).unwrap_or(0) * 10,
        }
    }

    // ── Fake HTTP poster ────────────────────────────────────────────────

    /// One scripted `getUpdates` reply.
    type ScriptedBatch = Result<Vec<TelegramUpdate>, TelegramErrorKind>;

    #[derive(Clone)]
    struct FakePost {
        batches: Arc<Mutex<VecDeque<ScriptedBatch>>>,
        sent: Arc<Mutex<Vec<(i64, String)>>>,
        polls: Arc<AtomicUsize>,
        /// Optional cap on `get_updates` calls, for a test that must fail
        /// rather than hang if the bridge starts polling without yielding.
        /// `tokio::time::timeout` cannot fire in that case: the runtime never
        /// regains control to poll the timer.
        poll_budget: Option<usize>,
        alert: Arc<tokio::sync::Notify>,
        /// Fired after every `getUpdates` call, so a test can wait for the
        /// loop to consume a scripted batch without sleeping.
        batch_ready: Arc<tokio::sync::Notify>,
    }

    impl FakePost {
        fn new() -> Self {
            Self {
                batches: Arc::new(Mutex::new(VecDeque::new())),
                sent: Arc::new(Mutex::new(Vec::new())),
                polls: Arc::new(AtomicUsize::new(0)),
                poll_budget: None,
                alert: Arc::new(tokio::sync::Notify::new()),
                batch_ready: Arc::new(tokio::sync::Notify::new()),
            }
        }

        /// Queues one `getUpdates` reply.
        fn push_batch(&self, updates: Vec<TelegramUpdate>) {
            self.batches.lock().unwrap().push_back(Ok(updates));
        }

        /// Bounds `get_updates` calls so a spinning loop panics RED instead of
        /// hanging the test (and its mutant run) indefinitely.
        fn with_poll_budget(mut self, budget: usize) -> Self {
            self.poll_budget = Some(budget);
            self
        }

        fn always_conflict() -> Self {
            let post = Self::new();
            post.batches
                .lock()
                .unwrap()
                .push_back(Err(TelegramErrorKind::Conflict));
            post
        }

        fn sent(&self) -> Vec<(i64, String)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TelegramPost for FakePost {
        async fn get_updates(
            &self,
            _token: &str,
            _offset: u64,
        ) -> Result<Vec<TelegramUpdate>, TelegramError> {
            let polls = self.polls.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some(budget) = self.poll_budget {
                assert!(
                    polls <= budget,
                    "get_updates ran {polls} times, over the {budget}-poll budget: \
                     the loop is spinning without yielding"
                );
            }
            let result = match self.batches.lock().unwrap().pop_front() {
                Some(result) => result.map_err(TelegramError::new),
                None => Err(TelegramError::new(TelegramErrorKind::Transport)),
            };
            self.batch_ready.notify_one();
            result
        }

        async fn send_message(
            &self,
            _token: &str,
            chat_id: i64,
            text: &str,
        ) -> Result<i64, TelegramError> {
            self.sent.lock().unwrap().push((chat_id, text.to_string()));
            if text == CONFLICT_NOTICE {
                // `notify_one` stores a permit if the test has not polled its
                // `Notified` yet; `notify_waiters` would drop the signal.
                self.alert.notify_one();
            }
            Ok(0)
        }
    }

    // ── Fake daemon surfaces ────────────────────────────────────────────

    /// One recorded `swap` call: `(pid, started_at, slot, allow_classes)`.
    type SwapCalls = Mutex<Vec<(u32, u64, u16, Vec<String>)>>;

    struct FakeIo {
        config: Mutex<Option<BridgeConfig>>,
        candidates: Vec<Candidate>,
        token: String,
        origin_key: [u8; 32],
        stored: Mutex<Vec<(u64, i64, u32, String)>>,
        audits: Mutex<Vec<String>>,
        /// The poll cursor, in the fake's own store (the bridge must never
        /// reach this through the config file).
        cursor: Mutex<u64>,
        /// Counts cursor writes.
        cursor_writes: AtomicUsize,
        /// Fails the NEXT cursor write (crash/failed-save injection).
        fail_next_cursor_save: AtomicBool,
        /// The phone kill switch (marker present).
        killed: AtomicBool,
        store_failure: Mutex<Option<StoreFailure>>,
        /// A failure consumed by the NEXT store call only (batch-retry tests).
        fail_next_store: Mutex<Option<StoreFailure>>,
        wake_calls: AtomicUsize,
        swap_result: Mutex<Option<Result<SwapOutcome, SwapError>>>,
        swap_calls: SwapCalls,
        /// How many `load_config` calls have happened (merge-on-write and
        /// mid-batch-disable tests need a deterministic interleaving).
        loads: AtomicUsize,
        /// From this `load_config` call onward the config reads as disabled
        /// (a phone kill switch landing mid-batch).
        disable_after_loads: AtomicUsize,
        /// On exactly this `load_config` call a CLI-style writer flips the
        /// STORED config to disabled (a kill switch racing the bridge's save).
        cli_off_after_loads: AtomicUsize,
        /// Makes the attestation origin key unreadable.
        origin_key_failure: AtomicBool,
        timing: BridgeTiming,
    }

    impl FakeIo {
        fn new(candidates: Vec<Candidate>) -> Self {
            Self {
                config: Mutex::new(Some(owner_config())),
                candidates,
                token: TOKEN.to_string(),
                origin_key: [0x5au8; 32],
                stored: Mutex::new(Vec::new()),
                audits: Mutex::new(Vec::new()),
                cursor: Mutex::new(0),
                cursor_writes: AtomicUsize::new(0),
                fail_next_cursor_save: AtomicBool::new(false),
                killed: AtomicBool::new(false),
                store_failure: Mutex::new(None),
                fail_next_store: Mutex::new(None),
                wake_calls: AtomicUsize::new(0),
                swap_result: Mutex::new(None),
                swap_calls: Mutex::new(Vec::new()),
                loads: AtomicUsize::new(0),
                disable_after_loads: AtomicUsize::new(0),
                cli_off_after_loads: AtomicUsize::new(0),
                origin_key_failure: AtomicBool::new(false),
                timing: BridgeTiming {
                    initial_backoff: Duration::from_millis(5),
                    max_backoff: Duration::from_millis(20),
                    conflict_backoff: Duration::from_millis(10),
                },
            }
        }

        fn config_now(&self) -> BridgeConfig {
            self.config.lock().unwrap().clone().expect("config present")
        }

        fn stored_ids(&self) -> Vec<u64> {
            self.stored.lock().unwrap().iter().map(|s| s.0).collect()
        }

        fn set_enabled(&self, enabled: bool) {
            if let Some(config) = self.config.lock().unwrap().as_mut() {
                config.enabled = enabled;
            }
        }

        fn cursor_now(&self) -> u64 {
            *self.cursor.lock().unwrap()
        }

        fn killed_now(&self) -> bool {
            self.killed.load(Ordering::SeqCst)
        }
    }

    impl BridgeIo for FakeIo {
        fn startup_delay(&self) -> Duration {
            Duration::ZERO
        }

        fn inactive_recheck_interval(&self) -> Duration {
            Duration::from_millis(5)
        }

        fn timing(&self) -> BridgeTiming {
            self.timing
        }

        fn now_secs(&self) -> i64 {
            NOW
        }

        fn load_config(&self, _base_dir: &Path) -> Result<Option<BridgeConfig>, BridgeConfigError> {
            let call = self.loads.fetch_add(1, Ordering::SeqCst) + 1;
            let cli_at = self.cli_off_after_loads.load(Ordering::SeqCst);
            if cli_at != 0 && call == cli_at {
                // A CLI-style writer lands `enabled: false` between the
                // bridge's read and its save.
                if let Some(stored) = self.config.lock().unwrap().as_mut() {
                    stored.enabled = false;
                }
            }
            let mut current = self.config.lock().unwrap().clone();
            let disable_at = self.disable_after_loads.load(Ordering::SeqCst);
            if disable_at != 0 && call >= disable_at {
                if let Some(config) = current.as_mut() {
                    config.enabled = false;
                }
            }
            Ok(current)
        }

        fn kill_switch_engaged(&self, _base_dir: &Path) -> Result<bool, BridgeConfigError> {
            Ok(self.killed.load(Ordering::SeqCst))
        }

        fn engage_kill_switch(&self, _base_dir: &Path) -> Result<(), BridgeConfigError> {
            self.killed.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn load_cursor(&self, _base_dir: &Path) -> Result<u64, BridgeConfigError> {
            Ok(*self.cursor.lock().unwrap())
        }

        fn save_cursor(&self, _base_dir: &Path, update_id: u64) -> Result<(), BridgeConfigError> {
            self.cursor_writes.fetch_add(1, Ordering::SeqCst);
            if self.fail_next_cursor_save.swap(false, Ordering::SeqCst) {
                return Err(BridgeConfigError::ConfigUnwritable);
            }
            *self.cursor.lock().unwrap() = update_id;
            Ok(())
        }

        fn load_bot_token(&self) -> Result<SecretString, SecretError> {
            Ok(SecretString::from(self.token.clone()))
        }

        fn load_origin_key(&self) -> Result<[u8; 32], SecretError> {
            if self.origin_key_failure.load(Ordering::SeqCst) {
                return Err(SecretError::NamedNotFound);
            }
            Ok(self.origin_key)
        }

        fn live_candidates(&self, _base_dir: &Path) -> Result<(Vec<Candidate>, bool), TargetError> {
            Ok((self.candidates.clone(), true))
        }

        fn store_owner(
            &self,
            _base_dir: &Path,
            _attestation: &OwnerAttestation,
            update_id: u64,
            tg_message_id: i64,
            target: &Recipient,
            body: &str,
            _now: u64,
        ) -> Result<(), StoreFailure> {
            if let Some(failure) = self.fail_next_store.lock().unwrap().take() {
                return Err(failure);
            }
            if let Some(failure) = *self.store_failure.lock().unwrap() {
                return Err(failure);
            }
            self.stored.lock().unwrap().push((
                update_id,
                tg_message_id,
                target.pid,
                body.to_string(),
            ));
            Ok(())
        }

        fn wake(&self, _base_dir: &Path, _target: &Recipient, _now: i64) -> Delivery {
            self.wake_calls.fetch_add(1, Ordering::SeqCst);
            Delivery::ClaudeWoken
        }

        fn swap(
            &self,
            _base_dir: &Path,
            target: &Recipient,
            slot: AccountNum,
            allow_classes: &[String],
        ) -> Result<SwapOutcome, SwapError> {
            self.swap_calls.lock().unwrap().push((
                target.pid,
                target.started_at,
                slot.get(),
                allow_classes.to_vec(),
            ));
            self.swap_result
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(SwapError::Failed(anyhow::anyhow!("no swap scripted"))))
        }

        fn audit_intent(
            &self,
            _base_dir: &Path,
            record: &DeliveryAudit,
        ) -> Result<AuditTicket, AuditFailure> {
            self.audits
                .lock()
                .unwrap()
                .push(format!("intent:{}:{}", record.update_id, record.byte_len));
            Ok(AuditTicket {
                chain_id: "test-chain".to_string(),
                correlation: crate::audit::types::RecordId::try_new("01ARZ3NDEKTSV4RRFFQ69G5FAV")
                    .expect("valid ULID"),
            })
        }

        fn audit_outcome(&self, _base_dir: &Path, _ticket: &AuditTicket, record: &DeliveryAudit) {
            self.audits
                .lock()
                .unwrap()
                .push(format!("outcome:{}:{}", record.update_id, record.outcome));
        }
    }

    // ── Tracing capture ─────────────────────────────────────────────────

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<String>>>);

    impl Capture {
        fn lines(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    struct Fields<'a>(&'a mut String);

    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={:?}", field.name(), value);
        }
    }

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut line = String::new();
            event.record(&mut Fields(&mut line));
            self.0.lock().unwrap().push(line);
        }
    }

    // ── Tests ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rejected_update_is_dropped_and_accepted_update_is_stored_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());

        let wrong_user = update(5, "@alpha hello", 999);
        let good = update(6, "@alpha hello", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &wrong_user,
        )
        .await;
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &good,
        )
        .await;

        assert_eq!(
            io.stored_ids(),
            vec![6],
            "only the accepted update is stored"
        );
        let stored = io.stored.lock().unwrap();
        assert_eq!(
            stored[0].3, "hello",
            "the @name routing token is not part of the stored body"
        );
        drop(stored);
        let sent = post.sent();
        assert_eq!(sent.len(), 1, "exactly one acknowledgement");
        assert!(
            sent[0].1.contains("stored for"),
            "ack names the delivery: {:?}",
            sent[0]
        );
        assert_eq!(
            sent[0].0, OWNER,
            "the acknowledgement goes to the pinned owner chat only"
        );
        assert!(io
            .audits
            .lock()
            .unwrap()
            .iter()
            .any(|a| a == "outcome:6:claude_woken"));
    }

    #[tokio::test]
    async fn crash_between_store_and_high_water_persist_delivers_exactly_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let good = update(6, "@alpha hello", OWNER);

        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());
        io.fail_next_cursor_save.store(true, Ordering::SeqCst);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &good,
        )
        .await;

        assert_eq!(
            io.stored_ids(),
            vec![6],
            "the store write landed before the crash"
        );
        assert_eq!(
            io.cursor_writes.load(Ordering::SeqCst),
            1,
            "the injected cursor-persist attempt fired"
        );
        assert_eq!(
            io.cursor_now(),
            0,
            "the failed cursor persist left the cursor behind"
        );
        assert!(
            post.sent().is_empty(),
            "no ack when the cursor persist failed"
        );
        assert_eq!(
            io.wake_calls.load(Ordering::SeqCst),
            0,
            "no wake after a failed persist"
        );

        // Restart: fresh in-memory state, cursor reloaded from disk (the failed
        // persist left it at the old value), exactly as the loop does.
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());
        state.cursor = io.cursor_now();
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &good,
        )
        .await;

        assert_eq!(
            io.stored_ids(),
            vec![6],
            "the replay must not store the update a second time"
        );
        assert_eq!(post.sent().len(), 1, "the replay completes the delivery");
        assert_eq!(io.wake_calls.load(Ordering::SeqCst), 1);
        assert_eq!(io.cursor_now(), 6);
    }

    #[tokio::test]
    async fn conflict_alerts_once_without_a_retry_storm() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![]);
        let post = FakePost::always_conflict();
        let cancel = CancellationToken::new();
        let scripted = post.clone();

        let alert = post.alert.notified();
        tokio::pin!(alert);
        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            scripted,
            &io,
        ));
        tokio::select! {
            () = &mut alert => {}
            () = &mut run => panic!("the loop exited before alerting the owner"),
        }
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("the loop stops on cancellation");

        let sent = post.sent();
        assert_eq!(sent.len(), 1, "exactly one conflict alert: {sent:?}");
        assert_eq!(sent[0].1, CONFLICT_NOTICE);
        assert!(post.polls.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn unknown_target_replies_with_the_available_names_and_never_broadcasts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha"), candidate("beta")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());

        let ghost = update(9, "@ghost hello", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &ghost,
        )
        .await;

        assert!(
            io.stored_ids().is_empty(),
            "an unknown target stores nothing"
        );
        let sent = post.sent();
        assert_eq!(sent.len(), 1, "exactly one refusal, never a broadcast");
        assert_eq!(sent[0].0, OWNER);
        assert!(sent[0].1.contains("no such session"), "{:?}", sent[0].1);
        assert!(sent[0].1.contains("alpha") && sent[0].1.contains("beta"));
        assert_eq!(
            io.cursor_now(),
            9,
            "the refused update still advances the poll cursor"
        );
    }

    #[tokio::test]
    async fn a_slash_command_other_than_off_is_refused_with_not_under_relay_and_never_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());

        let command = update(11, "/clear", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;

        assert!(
            io.stored_ids().is_empty(),
            "a slash command is never stored as a message"
        );
        assert_eq!(
            io.wake_calls.load(Ordering::SeqCst),
            0,
            "nothing is typed into a session"
        );
        let sent = post.sent();
        assert_eq!(sent.len(), 1, "the owner gets exactly one refusal");
        assert_eq!(sent[0].0, OWNER);
        assert!(
            sent[0].1.contains("not_under_relay"),
            "the refusal names the relay rule: {:?}",
            sent[0].1
        );
        assert_eq!(io.cursor_now(), 11);
        assert!(
            io.config_now().enabled,
            "only /csq off flips the kill switch"
        );
    }

    #[tokio::test]
    async fn csq_off_disables_the_bridge_even_while_rate_limited() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());
        // Exhaust the inbound window before the kill switch arrives: the kill
        // switch must stay reachable from the phone.
        for _ in 0..INBOUND_LIMIT {
            assert!(state.rate.admit(Instant::now()));
        }

        let off = update(12, OFF_COMMAND, OWNER);
        handle_update(&io, &post, dir.path(), &mut state, TOKEN, &mut config, &off).await;

        assert!(io.killed_now(), "the phone kill switch engages the marker");
        assert!(
            io.config_now().enabled,
            "the marker does NOT rewrite config.enabled (the daemon never writes it)"
        );
        assert_eq!(io.cursor_now(), 12, "the kill switch advances the cursor");
        assert!(io.stored_ids().is_empty());
        assert_eq!(io.wake_calls.load(Ordering::SeqCst), 0);
        let sent = post.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.contains("off"), "{:?}", sent[0].1);
    }

    #[tokio::test]
    async fn a_stale_kill_switch_still_kills_while_a_stale_action_command_is_refused() {
        // The freshness exemption for `/csq off` is BOUNDED, so both halves are
        // asserted: a stale kill switch must act (losing it would be
        // fail-open), and a stale action command must still be refused.
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        *io.swap_result.lock().unwrap() = Some(Ok(SwapOutcome {
            from: AccountNum::try_from(1).expect("slot 1"),
            account: AccountNum::try_from(2).expect("slot 2"),
        }));
        let post = FakePost::new();
        let mut config = io.config_now();
        config.allow_classes = vec!["swap".to_string()];
        let mut state = BridgeState::new(Instant::now());

        let stale_date = NOW - crate::bridge::validator::COMMAND_FRESHNESS_SECS - 1;
        let mut off = update(13, OFF_COMMAND, OWNER);
        off.raw.date = stale_date;
        handle_update(&io, &post, dir.path(), &mut state, TOKEN, &mut config, &off).await;

        assert!(
            io.killed_now(),
            "a STALE kill switch must still kill: losing it would be fail-open"
        );
        assert_eq!(io.cursor_now(), 13);
        assert_eq!(post.sent().len(), 1, "the owner is told the bridge is off");

        let mut stale_swap = update(14, "swap alpha 2", OWNER);
        stale_swap.raw.date = stale_date;
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &stale_swap,
        )
        .await;
        assert!(
            io.swap_calls.lock().unwrap().is_empty(),
            "a stale ACTION command is still refused"
        );
        assert!(
            post.sent()
                .last()
                .is_some_and(|(_, text)| text.contains("stale")),
            "the stale swap is refused with the stale notice"
        );

        // Identity is NOT exempted: an off from the wrong user never reaches
        // the command path, so it cannot kill the bridge.
        let io2 = FakeIo::new(vec![candidate("alpha")]);
        let post2 = FakePost::new();
        let mut config2 = io2.config_now();
        let mut state2 = BridgeState::new(Instant::now());
        let mut impostor = update(15, OFF_COMMAND, OWNER + 1);
        impostor.raw.date = stale_date;
        handle_update(
            &io2,
            &post2,
            dir.path(),
            &mut state2,
            TOKEN,
            &mut config2,
            &impostor,
        )
        .await;
        assert!(
            !io2.killed_now(),
            "an off from the wrong user must not kill the bridge"
        );
        assert!(io2.stored_ids().is_empty());
    }

    #[tokio::test]
    async fn swap_command_swaps_the_session_and_reports_the_new_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        *io.swap_result.lock().unwrap() = Some(Ok(SwapOutcome {
            from: AccountNum::try_from(1).expect("slot 1"),
            account: AccountNum::try_from(3).expect("slot 3"),
        }));
        let post = FakePost::new();
        let mut config = io.config_now();
        config.allow_classes = vec!["swap".to_string()];
        let mut state = BridgeState::new(Instant::now());

        let command = update(14, "swap alpha 3", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;

        let calls = io.swap_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "the command runs exactly once");
        assert_eq!(calls[0].0, 4_242);
        assert_eq!(calls[0].1, 1_000);
        assert_eq!(calls[0].2, 3);
        assert_eq!(calls[0].3, vec!["swap".to_string()]);
        assert!(
            io.stored_ids().is_empty(),
            "a command is never stored as a message"
        );
        let sent = post.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.contains("swapped alpha"), "{:?}", sent[0].1);
        assert!(sent[0].1.contains("slot 3"), "{:?}", sent[0].1);
        assert_eq!(io.cursor_now(), 14);
    }

    #[tokio::test]
    async fn a_swap_refusal_echoes_its_named_reason_and_is_never_retried() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        *io.swap_result.lock().unwrap() = Some(Err(SwapError::ClassNotAllowed { class: "swap" }));
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());

        let command = update(15, "swap alpha 2", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;

        assert_eq!(
            io.swap_calls.lock().unwrap().len(),
            1,
            "the gate is asked exactly once"
        );
        let sent = post.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.contains("class_not_allowed"), "{:?}", sent[0].1);
        assert_eq!(
            io.cursor_now(),
            15,
            "a refused swap still advances the cursor"
        );

        // A replay of the same update is refused by the validator: the command
        // is never retried and no fallback slot is chosen. The replay state
        // mirrors the loop, which reloads the cursor from disk before polling.
        let mut replay_state = BridgeState::new(Instant::now());
        replay_state.cursor = io.cursor_now();
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut replay_state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;
        assert_eq!(
            io.swap_calls.lock().unwrap().len(),
            1,
            "a refused swap is final"
        );
    }

    #[tokio::test]
    async fn a_replay_after_a_claim_without_a_store_says_the_store_was_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());
        // A crash between the ledger claim and the store write leaves the
        // claim without the message.
        save_delivered(dir.path(), 6).expect("claim");
        let replay = update(6, "@alpha hello", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &replay,
        )
        .await;

        assert!(
            io.stored_ids().is_empty(),
            "the replay does not store again"
        );
        let sent = post.sent();
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0].1.contains("store skipped"),
            "the ack names what this branch did: {:?}",
            sent[0].1
        );
        assert!(
            !sent[0].1.contains("stored for"),
            "the replay must not claim a store that was skipped: {:?}",
            sent[0].1
        );
        assert_eq!(io.wake_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_swap_replay_after_a_claim_without_execution_says_it_was_not_re_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        config.allow_classes = vec!["swap".to_string()];
        let mut state = BridgeState::new(Instant::now());
        // The claim is written BEFORE the swap, so this is the crash window:
        // claimed, never executed.
        save_delivered(dir.path(), 20).expect("claim");
        let command = update(20, "swap alpha 2", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;

        assert!(
            io.swap_calls.lock().unwrap().is_empty(),
            "a claimed swap is never re-run"
        );
        let sent = post.sent();
        assert_eq!(sent.len(), 1);
        assert!(
            sent[0].1.contains("NOT re-run") && sent[0].1.contains("unconfirmed"),
            "the ack states the unconfirmed outcome: {:?}",
            sent[0].1
        );
        assert!(
            !sent[0].1.contains("already applied"),
            "the replay must not claim an application it cannot prove: {:?}",
            sent[0].1
        );
        assert_eq!(io.cursor_now(), 20);
    }

    #[tokio::test]
    async fn a_malformed_swap_message_is_refused_rather_than_delivered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());

        let command = update(16, "swap alpha", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;

        assert!(io.stored_ids().is_empty());
        assert!(io.swap_calls.lock().unwrap().is_empty());
        let sent = post.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.contains("swap <session> <N>"), "{:?}", sent[0].1);
        assert_eq!(io.cursor_now(), 16);
    }

    #[test]
    fn swap_command_parsing_is_exact_after_trimming_ascii_spaces() {
        assert!(matches!(
            parse_swap_command("swap alpha 3"),
            SwapParse::Parsed(SwapCommand {
                session: "alpha",
                slot: 3
            })
        ));
        assert!(matches!(
            parse_swap_command("  swap alpha 3  "),
            SwapParse::Parsed(_)
        ));
        assert!(matches!(
            parse_swap_command("Swap alpha 3"),
            SwapParse::NotSwap
        ));
        assert!(matches!(
            parse_swap_command("@alpha swap beta 3"),
            SwapParse::NotSwap
        ));
        assert!(matches!(
            parse_swap_command("swap alpha 0"),
            SwapParse::Parsed(SwapCommand { slot: 0, .. })
        ));
        assert!(matches!(
            parse_swap_command("swap alpha 3 extra"),
            SwapParse::Malformed
        ));
        assert!(matches!(
            parse_swap_command("swap  alpha 3"),
            SwapParse::Malformed
        ));
        assert!(matches!(parse_swap_command("swap"), SwapParse::Malformed));
        assert!(matches!(
            parse_swap_command("swap alpha two"),
            SwapParse::Malformed
        ));
    }

    #[test]
    fn slash_text_is_command_kind_and_never_validates_as_a_message() {
        let value = serde_json::json!({
            "update_id": 21,
            "message": {
                "message_id": 210,
                "from": {"id": OWNER, "is_bot": false},
                "chat": {"id": OWNER, "type": "private"},
                "date": NOW,
                "text": "/clear"
            }
        });
        let parsed = telegram_update_from_json(&value).expect("parsed");
        assert!(
            parsed.raw.is_command_kind,
            "slash text must be marked command-kind by the adapter"
        );
        assert_eq!(
            validate_update(&parsed.raw, 0, OWNER, OWNER, NOW),
            Err(Reject::NotMessage),
            "a command is never a deliverable message"
        );
    }

    /// A well-formed owner message that additionally carries one forward
    /// marker, exactly as Telegram would send it.
    fn forwarded_json(update_id: u64, marker: &str, value: serde_json::Value) -> serde_json::Value {
        let mut message = serde_json::json!({
            "message_id": update_id * 10,
            "from": {"id": OWNER, "is_bot": false},
            "chat": {"id": OWNER, "type": "private"},
            "date": NOW,
            "text": "@alpha forwarded text"
        });
        message[marker] = value;
        serde_json::json!({"update_id": update_id, "message": message})
    }

    fn assert_forwarded(value: serde_json::Value) {
        let parsed = telegram_update_from_json(&value).expect("parsed");
        assert!(
            parsed.raw.has_forward,
            "the adapter must flag this forward marker"
        );
        assert_eq!(
            validate_update(&parsed.raw, 0, OWNER, OWNER, NOW),
            Err(Reject::Forwarded),
            "a forwarded message never carries owner provenance"
        );
    }

    #[test]
    fn a_modern_forward_origin_marker_is_refused() {
        assert_forwarded(forwarded_json(
            31,
            "forward_origin",
            serde_json::json!({"type": "user", "sender_user": {"id": 999}}),
        ));
    }

    #[test]
    fn a_legacy_forward_from_marker_is_refused() {
        assert_forwarded(forwarded_json(
            32,
            "forward_from",
            serde_json::json!({"id": 999}),
        ));
    }

    #[test]
    fn a_channel_forward_from_chat_marker_is_refused() {
        assert_forwarded(forwarded_json(
            33,
            "forward_from_chat",
            serde_json::json!({"id": -100_123, "type": "channel"}),
        ));
    }

    #[test]
    fn a_hidden_account_forward_sender_name_marker_is_refused() {
        assert_forwarded(forwarded_json(
            34,
            "forward_sender_name",
            serde_json::json!("Someone"),
        ));
    }

    #[test]
    fn a_forward_date_marker_is_refused() {
        assert_forwarded(forwarded_json(
            35,
            "forward_date",
            serde_json::json!(NOW - 60),
        ));
    }

    #[tokio::test]
    async fn a_transient_store_failure_halts_the_batch_and_the_update_is_re_polled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        *io.fail_next_store.lock().unwrap() = Some(StoreFailure {
            tag: "bridge_store_undetermined",
            permanent: false,
        });
        // Bound both loops. `tokio::time::timeout` alone cannot catch a
        // mutant that spins without yielding: the runtime never regains
        // control to poll the timer, so the test hangs instead of failing.
        // The poll budget trips inside `get_updates`; the turn cap below trips
        // in this test's own loop, which can also spin on stored permits.
        let post = FakePost::new().with_poll_budget(16);
        // Batch 1: update 1 fails to store and must halt the batch, so update 2
        // is NOT attempted. Telegram re-delivers from the persisted offset, so
        // batch 2 carries both updates again.
        post.push_batch(vec![
            update(1, "@alpha first", OWNER),
            update(2, "@alpha second", OWNER),
        ]);
        post.push_batch(vec![
            update(1, "@alpha first", OWNER),
            update(2, "@alpha second", OWNER),
        ]);
        let cancel = CancellationToken::new();
        let scripted = post.clone();
        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            scripted,
            &io,
        ));
        let stored = tokio::time::timeout(Duration::from_secs(2), async {
            let mut turns = 0usize;
            loop {
                turns += 1;
                assert!(
                    turns <= 64,
                    "the retry loop spun {turns} turns without both updates being stored"
                );
                let ids = io.stored_ids();
                if ids.len() >= 2 {
                    break ids;
                }
                // The loop must be DRIVEN here: awaiting only the notification
                // would never start it and the timeout would be guaranteed.
                // A FRESH `notified()` each turn: a Notified future panics if
                // polled after it has completed, and this loop wakes more than
                // once.
                tokio::select! {
                    () = &mut run => panic!("the loop exited before the batch was retried"),
                    () = post.batch_ready.notified() => {}
                }
            }
        })
        .await
        .expect("the failed update is re-polled and both updates are stored");
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), &mut run)
            .await
            .expect("the loop stops on cancellation");

        assert_eq!(
            stored,
            vec![1, 2],
            "update 1 is stored before update 2: the failed batch never ran update 2"
        );
        assert_eq!(
            io.stored_ids(),
            vec![1, 2],
            "each update is stored exactly once"
        );
    }

    #[tokio::test]
    async fn a_halted_batch_backs_off_before_re_polling() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut io = FakeIo::new(vec![candidate("alpha")]);
        // A store that fails on EVERY attempt, and a backoff long enough that
        // "slept before re-polling" and "re-polled immediately" cannot be
        // confused by scheduling jitter.
        *io.store_failure.lock().unwrap() = Some(StoreFailure {
            tag: "bridge_store_undetermined",
            permanent: false,
        });
        io.timing = BridgeTiming {
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_millis(200),
            conflict_backoff: Duration::from_millis(10),
        };
        let post = FakePost::new();
        post.push_batch(vec![update(1, "@alpha first", OWNER)]);
        post.push_batch(vec![update(1, "@alpha first", OWNER)]);
        let cancel = CancellationToken::new();
        let scripted = post.clone();
        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            scripted,
            &io,
        ));
        let notified = post.batch_ready.notified();
        tokio::pin!(notified);
        tokio::select! {
            () = notified.as_mut() => {}
            () = &mut run => panic!("the loop exited before the first poll"),
        }
        // The store failed and the batch halted. Unpaced, the loop would have
        // re-polled (and minted another audit pair) within microseconds.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            post.polls.load(Ordering::SeqCst),
            1,
            "a halted batch must sleep its backoff before re-polling"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), &mut run)
            .await
            .expect("the loop stops on cancellation");
    }

    #[tokio::test]
    async fn a_stale_swap_command_never_executes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        *io.swap_result.lock().unwrap() = Some(Ok(SwapOutcome {
            from: AccountNum::try_from(1).expect("slot 1"),
            account: AccountNum::try_from(2).expect("slot 2"),
        }));
        let post = FakePost::new();
        let mut config = io.config_now();
        config.allow_classes = vec!["swap".to_string()];
        let mut state = BridgeState::new(Instant::now());

        let mut command = update(17, "swap alpha 2", OWNER);
        command.raw.date = NOW - crate::bridge::validator::COMMAND_FRESHNESS_SECS - 1;
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;

        assert!(
            io.swap_calls.lock().unwrap().is_empty(),
            "a recovered day-old swap must never rebind a live session"
        );
        assert!(io.stored_ids().is_empty());
        let sent = post.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.contains("stale"), "{:?}", sent[0].1);
        assert_eq!(
            io.cursor_now(),
            17,
            "the stale command still advances the cursor"
        );
    }

    #[tokio::test]
    async fn a_swap_refusal_never_forwards_host_paths_to_telegram() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        *io.swap_result.lock().unwrap() = Some(Err(SwapError::Failed(anyhow::anyhow!(
            "failed to read /Users/example/secret-home/.claude.json"
        ))));
        let post = FakePost::new();
        let mut config = io.config_now();
        config.allow_classes = vec!["swap".to_string()];
        let mut state = BridgeState::new(Instant::now());

        let command = update(18, "swap alpha 2", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;

        let sent = post.sent();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.contains("swap_failed"), "{:?}", sent[0].1);
        assert!(
            !sent[0].1.contains("/Users/example"),
            "a host path must never cross to Telegram: {:?}",
            sent[0].1
        );
    }

    #[tokio::test]
    async fn a_disabled_config_mid_batch_idles_the_task_instead_of_exiting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        // The phone kill switch lands between the top-of-loop read and the
        // first per-update read of the batch.
        io.disable_after_loads.store(2, Ordering::SeqCst);
        let post = FakePost::new();
        post.push_batch(vec![
            update(1, "@alpha first", OWNER),
            update(2, "@alpha second", OWNER),
        ]);
        let cancel = CancellationToken::new();
        let scripted = post.clone();
        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            scripted,
            &io,
        ));
        // Give the loop ample time to reach the disabled branch and (wrongly)
        // return. A return here is a supervised-subsystem fault in production.
        let exited = tokio::time::timeout(Duration::from_millis(100), &mut run).await;
        assert!(
            exited.is_err(),
            "the bridge task MUST idle, never return, when the config is disabled mid-batch"
        );
        assert!(
            io.stored_ids().is_empty(),
            "nothing is delivered after the kill switch lands"
        );
        assert_eq!(
            post.polls.load(Ordering::SeqCst),
            1,
            "the task must not re-poll while disabled"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), &mut run)
            .await
            .expect("the loop stops on cancellation");
    }

    #[tokio::test]
    async fn the_poll_gate_refuses_while_the_phone_kill_switch_is_engaged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        // The phone off landed earlier: the marker stands, `enabled` is
        // untouched, and a batch is waiting to be fetched.
        io.killed.store(true, Ordering::SeqCst);
        let post = FakePost::new();
        post.push_batch(vec![update(1, "@alpha hello", OWNER)]);
        let cancel = CancellationToken::new();
        let scripted = post.clone();
        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            scripted,
            &io,
        ));
        // The loop must idle on the marker, never poll: the scripted batch is
        // never fetched, so nothing can be delivered while killed.
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
            () = &mut run => panic!("the loop exited while the kill switch was engaged"),
        }
        assert_eq!(
            post.polls.load(Ordering::SeqCst),
            0,
            "a killed bridge must not poll, even with updates waiting"
        );
        assert!(io.stored_ids().is_empty());
        assert!(
            io.config_now().enabled,
            "the marker is a polling refusal, not a rewrite of enabled"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), &mut run)
            .await
            .expect("the loop stops on cancellation");
    }

    #[tokio::test]
    async fn a_delivery_never_writes_the_config_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        // A phone kill switch lands BEFORE the delivery: whatever the bridge
        // does with the cursor, it must never touch the config again.
        io.set_enabled(false);
        let post = FakePost::new();
        let mut config = io.config_now();
        config.enabled = true;
        let mut state = BridgeState::new(Instant::now());

        let message = update(19, "@alpha hello", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &message,
        )
        .await;

        assert_eq!(io.stored_ids(), vec![19], "the message is still delivered");
        assert!(
            !io.config_now().enabled,
            "the stored kill switch is unchanged (the bridge never wrote it)"
        );
        assert!(
            io.cursor_writes.load(Ordering::SeqCst) > 0,
            "the cursor advances in its own file"
        );
        assert_eq!(io.cursor_now(), 19);
    }

    #[tokio::test]
    async fn a_replayed_swap_after_a_failed_cursor_save_never_executes_twice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        *io.swap_result.lock().unwrap() = Some(Ok(SwapOutcome {
            from: AccountNum::try_from(1).expect("slot 1"),
            account: AccountNum::try_from(2).expect("slot 2"),
        }));
        io.fail_next_cursor_save.store(true, Ordering::SeqCst);
        let post = FakePost::new();
        let mut config = io.config_now();
        config.allow_classes = vec!["swap".to_string()];
        let mut state = BridgeState::new(Instant::now());
        let command = update(20, "swap alpha 2", OWNER);

        // First attempt: the swap runs, then the cursor save fails, so the
        // update stays below the poll offset and MUST replay.
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;
        assert_eq!(io.swap_calls.lock().unwrap().len(), 1);
        assert_eq!(
            io.cursor_now(),
            0,
            "the failed save leaves the cursor behind"
        );
        assert!(state.halt_batch, "the batch halts so the update replays");

        // Telegram re-delivers the same update. The ledger claims it, so the
        // swap must NOT run a second time.
        *io.swap_result.lock().unwrap() = Some(Ok(SwapOutcome {
            from: AccountNum::try_from(1).expect("slot 1"),
            account: AccountNum::try_from(2).expect("slot 2"),
        }));
        let mut replay_state = BridgeState::new(Instant::now());
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut replay_state,
            TOKEN,
            &mut config,
            &command,
        )
        .await;

        assert_eq!(
            io.swap_calls.lock().unwrap().len(),
            1,
            "a replayed update must never execute the swap twice"
        );
        assert_eq!(io.cursor_now(), 20, "the replay completes the bookkeeping");
    }

    #[tokio::test]
    async fn an_unreadable_origin_key_notifies_and_does_not_advance_the_cursor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        io.origin_key_failure.store(true, Ordering::SeqCst);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());

        let message = update(21, "@alpha hello", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &message,
        )
        .await;

        assert!(io.stored_ids().is_empty(), "nothing is stored");
        let sent = post.sent();
        assert_eq!(sent.len(), 1, "the owner is told the message was dropped");
        assert_eq!(sent[0].1, STATE_UNREADABLE_NOTICE);
        assert_eq!(
            io.cursor_now(),
            0,
            "an undelivered message must not advance the cursor"
        );
        assert!(state.halt_batch, "the batch halts so the update replays");
    }

    /// The ingest has no config-write seam at all: its only owner-local writes
    /// are the cursor state file and the killed marker. Pinned at the SOURCE so
    /// a future edit cannot quietly reintroduce the config write (and with it
    /// the kill-switch race) that this change removed. The needles are built by
    /// concatenation so this test's own text cannot satisfy them.
    #[test]
    fn the_ingest_has_no_config_write_seam() {
        let source = include_str!("telegram_bridge.rs");
        let save_fn = concat!("bridge_config::", "save(");
        let io_method = concat!("fn ", "save_config", "(&self");
        assert!(
            !source.contains(save_fn),
            "the ingest must not write the owner config through bridge_config::save"
        );
        assert!(
            !source.contains(io_method),
            "the ingest must not expose a config-write seam on its IO trait"
        );
    }

    /// REAL instrumentation, not the fake: the production marker write against
    /// a real directory must leave the config FILE BYTES untouched and the
    /// config still enabled. This is what makes "the daemon never writes the
    /// config" a measured property rather than a claim about a test double.
    #[test]
    fn the_real_marker_write_leaves_the_config_file_untouched() {
        use crate::bridge::config as real_config;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = real_config::BridgeConfig {
            enabled: true,
            owner_user_id: OWNER,
            owner_chat_id: OWNER,
            allow_classes: Vec::new(),
        };
        real_config::save(&config, dir.path()).expect("save config");
        let before = std::fs::read(dir.path().join(real_config::CONFIG_FILE)).expect("read before");

        ProductionIo
            .engage_kill_switch(dir.path())
            .expect("engage marker");

        let after = std::fs::read(dir.path().join(real_config::CONFIG_FILE)).expect("read after");
        assert_eq!(
            before, after,
            "the real marker write must not touch the config file bytes"
        );
        assert!(
            ProductionIo
                .kill_switch_engaged(dir.path())
                .expect("marker state"),
            "the marker is present"
        );
        let loaded = real_config::load(dir.path())
            .expect("load config")
            .expect("config present");
        assert!(
            loaded.enabled,
            "the config still says enabled: the marker does not rewrite it"
        );
    }

    #[test]
    fn every_swap_error_code_is_audited_as_a_failure() {
        let slot = AccountNum::try_from(1).expect("slot 1");
        let errors = vec![
            SwapError::DeadTarget { pid: 1 },
            SwapError::UnverifiableTarget {
                pid: 1,
                reason: "unreadable",
            },
            SwapError::InvalidHandleDir { reason: "outside" },
            SwapError::CrossSurface {
                source: crate::providers::catalog::Surface::ClaudeCode,
                target: crate::providers::catalog::Surface::Codex,
            },
            SwapError::ThirdPartySlot {
                side: crate::session::swap_session::SwapSide::Source,
                slot,
            },
            SwapError::UnsupportedSurface {
                surface: crate::providers::catalog::Surface::ClaudeCode,
            },
            SwapError::TargetNotReady { slot },
            SwapError::SlotOutOfRange { slot: 0 },
            SwapError::LaunchBlocked {
                message: "blocked".to_owned(),
            },
            SwapError::ClassNotAllowed { class: "swap" },
            SwapError::TargetSlotLoginNeeded { slot },
            SwapError::Failed(anyhow::anyhow!("failed")),
        ];
        for error in errors {
            assert!(
                outcome_is_failure(error.code()),
                "{} must audit as Failed, not Ok",
                error.code()
            );
        }
        assert!(!outcome_is_failure("swapped"));
        assert!(
            outcome_is_failure("swapped_replay"),
            "a claimed-but-unconfirmed swap must not audit as Ok"
        );
        assert!(!outcome_is_failure("claude_woken"));
    }

    #[tokio::test]
    async fn a_permanent_store_refusal_is_dropped_with_a_notice_not_replayed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());
        *io.store_failure.lock().unwrap() = Some(StoreFailure {
            tag: "bridge_store_target_ended",
            permanent: true,
        });

        let ended = update(12, "@alpha hello", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &ended,
        )
        .await;

        assert!(io.stored_ids().is_empty());
        assert_eq!(io.wake_calls.load(Ordering::SeqCst), 0, "no wake");
        let sent = post.sent();
        assert_eq!(sent.len(), 1, "one refusal notice");
        assert!(
            sent[0].1.contains("refused this message"),
            "{:?}",
            sent[0].1
        );
        assert_eq!(
            io.cursor_now(),
            12,
            "a permanent refusal advances the cursor instead of blocking the queue"
        );
    }

    #[tokio::test]
    async fn a_transient_store_refusal_is_retried_not_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());
        *io.store_failure.lock().unwrap() = Some(StoreFailure {
            tag: "bridge_store_undetermined",
            permanent: false,
        });

        let pending = update(13, "@alpha hello", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &pending,
        )
        .await;

        assert!(io.stored_ids().is_empty());
        assert!(post.sent().is_empty(), "no ack for an undelivered message");
        assert_eq!(
            io.cursor_now(),
            0,
            "a transient refusal leaves the cursor for the re-poll"
        );

        // The same update succeeds on the replay once the store recovers.
        *io.store_failure.lock().unwrap() = None;
        let mut state = BridgeState::new(Instant::now());
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &pending,
        )
        .await;
        assert_eq!(io.stored_ids(), vec![13]);
        assert_eq!(post.sent().len(), 1, "the replay completes the delivery");
    }

    #[tokio::test]
    async fn rate_limit_refuses_the_thirty_first_message() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        let post = FakePost::new();
        let mut config = io.config_now();
        let mut state = BridgeState::new(Instant::now());

        for id in 1..=30u64 {
            let u = update(id, "@alpha hello", OWNER);
            handle_update(&io, &post, dir.path(), &mut state, TOKEN, &mut config, &u).await;
        }
        let over = update(31, "@alpha hello", OWNER);
        handle_update(
            &io,
            &post,
            dir.path(),
            &mut state,
            TOKEN,
            &mut config,
            &over,
        )
        .await;

        let stored = io.stored_ids();
        assert_eq!(stored.len(), 30, "thirty messages are admitted");
        assert!(!stored.contains(&31), "the 31st is refused");
        let notices = post
            .sent()
            .into_iter()
            .filter(|(_, text)| text == RATE_LIMIT_NOTICE)
            .count();
        assert_eq!(
            notices, 1,
            "the owner is told once, not once per refused message"
        );
    }

    #[tokio::test]
    async fn disabled_config_makes_no_http_call_and_stays_ready_to_activate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![]);
        io.set_enabled(false);
        let post = FakePost::new();
        let cancel = CancellationToken::new();
        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            post.clone(),
            &io,
        ));
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(40)) => {}
            () = &mut run => panic!("the inactive task must stay alive to observe `csq telegram on`"),
        }
        assert_eq!(
            post.polls.load(Ordering::SeqCst),
            0,
            "no poll when disabled"
        );
        assert!(post.sent().is_empty(), "no Telegram call when disabled");
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("the inactive loop stops on cancellation");
    }

    #[tokio::test]
    async fn absent_config_makes_no_http_call() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![]);
        *io.config.lock().unwrap() = None;
        let post = FakePost::new();
        let cancel = CancellationToken::new();
        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            post.clone(),
            &io,
        ));
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(40)) => {}
            () = &mut run => panic!("the unconfigured task must stay alive to observe setup"),
        }
        assert_eq!(post.polls.load(Ordering::SeqCst), 0);
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), run)
            .await
            .expect("the inactive loop stops on cancellation");
    }

    /// `csq telegram on` only writes the config; the daemon task must observe
    /// it without a restart.
    #[tokio::test]
    async fn enabling_after_being_disabled_activates_the_loop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![candidate("alpha")]);
        io.set_enabled(false);
        let post = FakePost::new();
        post.batches
            .lock()
            .unwrap()
            .push_back(Ok(vec![update(21, "@alpha hi", OWNER)]));
        let cancel = CancellationToken::new();
        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            post.clone(),
            &io,
        ));
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(30)) => {}
            () = &mut run => panic!("the inactive task must stay alive"),
        }
        assert_eq!(post.polls.load(Ordering::SeqCst), 0, "idle while disabled");

        io.set_enabled(true);
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(150)) => {}
            () = &mut run => panic!("the active task must keep polling"),
        }
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), run).await;

        assert!(
            post.polls.load(Ordering::SeqCst) >= 1,
            "the recheck picks up the enabled config"
        );
        assert_eq!(io.stored_ids(), vec![21]);
    }

    #[tokio::test]
    async fn a_reqwest_error_never_leaks_the_bot_token_into_logs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let io = FakeIo::new(vec![]);
        // A loopback port that ACCEPTS and immediately drops every connection.
        // A closed port looks equivalent but is not: on a Windows runner the
        // connect spends seconds in SYN retries before it gives up, so the
        // bounded control request below expires instead of exercising the
        // redaction path. Accepting and dropping fails immediately on every
        // platform, touches no external network, and still yields a real
        // `reqwest::Error` whose Display carries the URL — which contains the
        // token, and is exactly the leak vector this test exists to rule out.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stream.is_err() {
                    break;
                }
            }
        });
        let post = ReqwestTelegramPost::with_base_url(format!("http://127.0.0.1:{port}"));
        let capture = Capture::default();
        let guard = tracing::subscriber::set_default(capture.clone());
        let cancel = CancellationToken::new();

        let mut run = Box::pin(run_telegram_bridge_with(
            dir.path().to_path_buf(),
            cancel.clone(),
            post,
            &io,
        ));
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(250)) => {}
            () = &mut run => {}
        }
        cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), run).await;
        drop(guard);

        let lines = capture.lines();

        // Control: formatting the RAW `reqwest` error for the same URL DOES
        // reveal the token. That is the leak vector this module must not
        // expose, so the absence assertion below is discriminating rather than
        // vacuous (`instrument-discipline.md` MUST-1).
        let url = format!("http://127.0.0.1:{port}/bot{TOKEN}/getUpdates");
        let raw = tokio::time::timeout(
            Duration::from_secs(2),
            reqwest::Client::new().get(&url).send(),
        )
        .await
        .expect("the control request is bounded")
        .expect_err("the probe port is closed");
        let formatted = format!("{raw}");
        assert!(
            formatted.contains(TOKEN),
            "control failed: this reqwest version does not put the URL in its Display, so the \
             redaction test would be vacuous: {formatted}"
        );

        assert!(
            lines.iter().any(|l| l.contains("telegram_connect_failed")
                || l.contains("telegram_transport_failed")
                || l.contains("telegram_timeout")),
            "the failing request must have been logged: {lines:?}"
        );
        assert!(
            lines.iter().all(|l| !l.contains(TOKEN)),
            "the bot token leaked into a log line: {lines:?}"
        );
        assert!(
            lines.iter().all(|l| !l.contains("/bot")),
            "a request URL path leaked into a log line: {lines:?}"
        );
    }

    #[test]
    fn json_adapter_keeps_the_message_id_and_flags_non_messages() {
        let message = serde_json::json!({
            "update_id": 7u64,
            "message": {
                "message_id": 70i64,
                "from": {"id": 42i64, "is_bot": false},
                "chat": {"id": 42i64, "type": "private"},
                "date": NOW,
                "text": "@alpha hi"
            }
        });
        let parsed = telegram_update_from_json(&message).expect("parses");
        assert_eq!(parsed.raw.update_id, 7);
        assert_eq!(parsed.tg_message_id, 70);
        assert_eq!(parsed.raw.text.as_deref(), Some("@alpha hi"));
        assert!(!parsed.raw.is_command_kind);

        let callback = serde_json::json!({"update_id": 8u64, "callback_query": {"id": "x"}});
        let parsed = telegram_update_from_json(&callback).expect("parses");
        assert!(
            parsed.raw.is_command_kind,
            "non-message updates are refused later"
        );
        assert_eq!(parsed.tg_message_id, 0);
        assert!(telegram_update_from_json(&serde_json::json!({"message": {}})).is_none());
    }

    #[test]
    fn conflict_status_is_classified_at_the_http_layer() {
        assert_eq!(
            decode_updates(409, b"{}").unwrap_err().kind(),
            TelegramErrorKind::Conflict
        );
        assert_eq!(
            decode_updates(200, br#"{"ok":false,"error_code":409}"#)
                .unwrap_err()
                .kind(),
            TelegramErrorKind::Conflict
        );
        assert_eq!(
            decode_updates(401, b"{}").unwrap_err().kind(),
            TelegramErrorKind::Unauthorized
        );
        assert_eq!(
            decode_updates(200, br#"{"ok":true,"result":[]}"#)
                .expect("empty batch")
                .len(),
            0
        );
    }

    #[test]
    fn targeted_text_requires_an_at_name_and_a_body() {
        assert_eq!(
            parse_targeted_text("@alpha hello"),
            Some(("alpha", "hello"))
        );
        assert_eq!(
            parse_targeted_text("@alpha   hello"),
            Some(("alpha", "hello"))
        );
        assert_eq!(parse_targeted_text("@alpha"), None);
        assert_eq!(parse_targeted_text("@alpha "), None);
        assert_eq!(parse_targeted_text("hello"), None);
        assert_eq!(parse_targeted_text("@ hello"), None);
    }
}
