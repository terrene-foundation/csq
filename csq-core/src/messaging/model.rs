//! The `csq.message.v1` record (spec 32 §3).

use serde::{Deserialize, Serialize};

use super::frame;
use crate::sessions::same_start;

/// The record's `schema` value.
pub const SCHEMA: &str = "csq.message.v1";

/// Which CLI a session runs (spec 32 §2.1). Closed set; an unknown value in a stored
/// record fails deserialisation, which the store reports as `undetermined`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Surface {
    /// A Claude Code session.
    #[serde(rename = "claude-code")]
    ClaudeCode,
    /// A Codex session.
    #[serde(rename = "codex")]
    Codex,
}

impl Surface {
    /// The wire name, as in the frame header.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }
}

/// Which kind of identity sent a stored message (design an internal ticket §5).
///
/// This is the MESSAGING-local surface: it adds [`Self::Service`] to the two CLI surfaces.
/// [`Surface`] stays the app-wide "which CLI" concept (accounts, providers, desktop); a
/// service is not a CLI and never becomes one. The two session serde names are unchanged,
/// so every stored session record and the inbox wire stay byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SenderSurface {
    /// A Claude Code session.
    #[serde(rename = "claude-code")]
    ClaudeCode,
    /// A Codex session.
    #[serde(rename = "codex")]
    Codex,
    /// A registered service identity: not a session, no process, no inbox.
    #[serde(rename = "service")]
    Service,
}

impl SenderSurface {
    /// The wire name, as in the frame header and inbox row.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Service => "service",
        }
    }
}

impl From<Surface> for SenderSurface {
    fn from(surface: Surface) -> Self {
        match surface {
            Surface::ClaudeCode => Self::ClaudeCode,
            Surface::Codex => Self::Codex,
        }
    }
}

/// The registered service a [`Sender`] stands for (design an internal ticket §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRef {
    /// The registered name (grammar-checked at registration and re-checked on load).
    pub name: String,
    /// The registration this message was sent under. A re-registration mints a new one, so
    /// idempotency and rate accounting never carry across identities.
    pub registration_id: String,
}

/// The sending session. Built only from the identity the caller resolved (INV-32-01); the
/// store never takes a sender from message text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sender {
    /// Process id of the CLI process.
    pub pid: u32,
    /// OS process start time, unix seconds. For a service this is the registration's
    /// `created_at` (there is no process); the field exists so the record stays schema-valid.
    pub started_at: u64,
    /// Which kind of identity sent the message.
    pub surface: SenderSurface,
    /// Hash of the canonical handle dir (the only form of it that may reach a wire).
    /// Empty for a service (no handle dir).
    pub handle_dir_hash: String,
    /// The handle dir itself: stored, never on a wire. Empty for a service.
    pub handle_dir: String,
    /// Optional session name; excluded from every limit key so a rename frees nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The registered service this sender stands for, present exactly when `surface` is
    /// [`SenderSurface::Service`]. Absent from every session record, so their on-disk shape
    /// is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceRef>,
    /// Full-precision start ([`crate::sessions::ancestor_start`]; units differ per
    /// platform) read at the moment the session was identified. Stored, never on a wire:
    /// the Codex wake requires it to equal the listed value, which tells apart two
    /// processes that reused one pid within the same second. `None` (a record written
    /// before this field, or an unreadable start) means "cannot bind exactly": no wake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_exact: Option<u64>,
}

/// A session identity the §2.2 caller resolver proved. The store's `send`, `reply`, `inbox`
/// and `ack` take this instead of a plain [`Sender`] or [`Recipient`], so a surface cannot
/// build an identity from argv, env or message text: the only constructor is
/// `VerifiedSession::from_resolved`, `pub(crate)` and meant for the §2.2 resolver (and
/// in-crate tests). There is deliberately no public constructor and no `Deserialize`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSession {
    sender: Sender,
    recipient: Recipient,
}

impl VerifiedSession {
    /// Wrap the identity the §2.2 resolver proved. Its callers are the resolver
    /// (`sessions::ResolvedCaller::verified`) and in-crate tests, and nothing else: the
    /// test `from_resolved_has_no_production_caller_outside_the_resolver` greps the
    /// production source of both crates for it. Read-only paths take a plain [`Recipient`]
    /// (`store::pending_count`) and never build one of these.
    ///
    /// A `VerifiedSession` is a SESSION by construction: no production surface wraps a
    /// service sender (the service send path passes its [`Sender`] to `do_send_core`
    /// directly, never here). If a caller ever did, the stored address is the zero
    /// pid/start with the Claude surface — an address no live session can occupy — so
    /// nothing can be addressed to it. It is a fail-closed placeholder, never a guessed
    /// surface for a service.
    pub(crate) fn from_resolved(sender: Sender) -> Self {
        let recipient = sender.as_recipient().unwrap_or(Recipient {
            pid: 0,
            started_at: 0,
            surface: Surface::ClaudeCode,
            started_exact: None,
        });
        Self { sender, recipient }
    }

    /// The handle dir this session was proved to run in: where its own name is stored.
    /// Never on a wire.
    #[must_use]
    pub fn handle_dir(&self) -> &std::path::Path {
        std::path::Path::new(&self.sender.handle_dir)
    }

    /// Immutable canonical handle hash captured by the session resolver.
    #[must_use]
    pub fn handle_dir_hash(&self) -> &str {
        &self.sender.handle_dir_hash
    }

    /// The sender block csq writes on a stored record.
    pub(crate) fn sender(&self) -> &Sender {
        &self.sender
    }

    /// This session as an addressable `(pid, started_at, surface)`.
    #[must_use]
    pub fn as_recipient(&self) -> Recipient {
        self.recipient
    }
}

/// The addressed session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipient {
    /// Process id.
    pub pid: u32,
    /// Process start time, unix seconds.
    pub started_at: u64,
    /// Which CLI.
    pub surface: Surface,
    /// Full-precision start ([`crate::sessions::ancestor_start`]; units differ per
    /// platform) read at the moment the session was identified. Stored, never on a wire:
    /// the Codex wake requires it to equal the listed value, which tells apart two
    /// processes that reused one pid within the same second. `None` (a record written
    /// before this field, or an unreadable start) means "cannot bind exactly": no wake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_exact: Option<u64>,
}

impl Recipient {
    /// Whether `other` is this same session: equal pid and start within the
    /// `sessions::same_start` tolerance (a pid alone is reused by the OS).
    #[must_use]
    pub fn same_session(&self, other: &Recipient) -> bool {
        self.pid == other.pid && same_start(self.started_at, other.started_at)
    }
}

impl Sender {
    /// The sender as an addressable session. `None` for a service: it has no process
    /// identity and no inbox, so callers MUST refuse rather than fabricate an address
    /// (design an internal ticket §5).
    #[must_use]
    pub fn as_recipient(&self) -> Option<Recipient> {
        let surface = match self.surface {
            SenderSurface::ClaudeCode => Surface::ClaudeCode,
            SenderSurface::Codex => Surface::Codex,
            SenderSurface::Service => return None,
        };
        if self.service.is_some() {
            return None;
        }
        Some(Recipient {
            pid: self.pid,
            started_at: self.started_at,
            surface,
            started_exact: self.started_exact,
        })
    }

    /// Whether `other` is this same logical sender for rate/pending accounting.
    ///
    /// Sessions compare as `(pid, started_at)` within the `same_start` tolerance (a pid is
    /// reused). Services compare as `(name, registration_id)`: a re-registration is a NEW
    /// identity with its own quota and its own idempotency space, exactly as its new
    /// `registration_id` implies.
    #[must_use]
    pub fn same_identity(&self, other: &Sender) -> bool {
        match (&self.service, &other.service) {
            (Some(a), Some(b)) => a.name == b.name && a.registration_id == b.registration_id,
            (None, None) => match (self.as_recipient(), other.as_recipient()) {
                (Some(a), Some(b)) => a.same_session(&b),
                _ => false,
            },
            (Some(_), None) | (None, Some(_)) => false,
        }
    }
}

/// Provenance of a stored message (design §3).
///
/// Only [`Origin::Peer`] is reachable from a peer-facing surface: the CLI, the MCP
/// server, the hooks and [`super::store::send`]/[`super::store::reply`] have no
/// parameter that carries an origin. [`Origin::OwnerTelegram`] is written only by the
/// daemon's bridge ingress through `store::send_owner` (crate-internal), and its `mac`
/// is the HMAC the daemon holds the key for. A render MAY show the owner header only
/// after the daemon re-verified that mac for that exact body
/// ([`frame::OriginAuthority`]); the origin field alone never earns it.
///
/// [`Origin::Service`] is written only by the daemon's service-send route through
/// `store::send_service` (crate-internal) after the registry record was validated. A
/// render always shows it as `service:<name>` — never as a session, never as an approval,
/// and never with the owner header.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    /// An ordinary cross-CLI peer message. Also what every record written before this
    /// field existed deserialises as.
    #[default]
    Peer,
    /// A message the pinned Telegram owner sent, attested by the daemon.
    OwnerTelegram {
        /// Telegram update the message arrived in (replay key).
        update_id: u64,
        /// Telegram's id of the owner's message (the phone-reply routing key).
        tg_message_id: i64,
        /// HMAC-SHA256 over the attested fields, lowercase hex.
        mac: String,
    },
    /// A registered service identity sent the message (design an internal ticket). Written ONLY by the
    /// daemon's `/api/message/send-service` route from the registry record: no CLI or MCP
    /// parameter carries an origin, so a session-facing surface cannot produce this
    /// variant. A service is not a session and never an approval.
    Service {
        /// The registered name (grammar-checked).
        name: String,
        /// The registration this message was sent under.
        registration_id: String,
    },
}

impl Origin {
    /// Whether this record's provenance is an ordinary peer.
    #[must_use]
    pub fn is_peer(&self) -> bool {
        matches!(self, Self::Peer)
    }

    /// Whether the record claims owner provenance (verified or not: the claim itself
    /// is data, and only the daemon's verification may promote it).
    #[must_use]
    pub fn claims_owner(&self) -> bool {
        matches!(self, Self::OwnerTelegram { .. })
    }

    /// A stored record's origin must be structurally sane: the attestation mac is
    /// ASCII alphanumerics of bounded length, and a service origin names a grammar-valid
    /// service with a canonical UUIDv4 registration. Content is never checked against the
    /// key here (this runs on every load, including lock-free reads); the daemon verifies
    /// at render time.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match self {
            Self::Peer => true,
            Self::OwnerTelegram { mac, .. } => {
                !mac.is_empty()
                    && mac.chars().count() <= super::limits::MAX_HASH_CHARS
                    && mac.chars().all(|c| c.is_ascii_alphanumeric())
            }
            Self::Service {
                name,
                registration_id,
            } => {
                super::service::validate_service_name(name).is_ok()
                    && super::service::is_registration_id(registration_id)
            }
        }
    }
}

/// Lifecycle position of a message (spec 32 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Stored, not yet shown to the recipient.
    Queued,
    /// A notice was shown (hook or wake).
    Surfaced,
    /// The recipient fetched the body.
    Read,
    /// The recipient acknowledged it.
    Acked,
    /// The recipient session ended before reading it; kept for retention.
    Undeliverable,
}

impl Status {
    /// The wire spelling (`snake_case`, identical to the serde form). Exhaustive on purpose:
    /// a new variant fails to compile here instead of printing an empty string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Surfaced => "surfaced",
            Self::Read => "read",
            Self::Acked => "acked",
            Self::Undeliverable => "undeliverable",
        }
    }
}

/// The synthetic sender block every owner-origin record carries (design §3).
///
/// The owner is not a csq session, so the v1 record schema's required sender block has no
/// real value to hold: pid `0` cannot be a live session, the handle dir is empty, and the
/// hash is a fixed non-secret marker. Provenance lives in [`Message::origin`], and every
/// render of an owner record keys off that field — never off this block. It exists so the
/// record stays schema-valid and so nothing else in the store has to special-case a
/// missing sender.
#[must_use]
pub fn owner_sender() -> Sender {
    Sender {
        pid: 0,
        started_at: 0,
        surface: SenderSurface::ClaudeCode,
        handle_dir_hash: "owner".to_string(),
        handle_dir: String::new(),
        name: None,
        started_exact: None,
        service: None,
    }
}

/// The synthetic sender block a service-origin record carries (design an internal ticket §5).
///
/// A service is not a process: pid `0` can never be a live session, `started_at` is the
/// registration's `created_at`, the start is never "exact", and the handle fields are
/// empty. Provenance lives in [`Message::origin`]; every render keys off that field (and
/// cross-checks this block), never off the pid. `pub(crate)`: only the daemon's service
/// send path builds one, from a record [`super::service::load`] already validated.
#[cfg_attr(not(unix), allow(dead_code))] // the only production caller is the Unix-only service route
#[must_use]
pub(crate) fn service_sender(record: &super::service::ServiceRecord) -> Sender {
    Sender {
        pid: 0,
        started_at: record.created_at,
        surface: SenderSurface::Service,
        handle_dir_hash: String::new(),
        handle_dir: String::new(),
        name: None,
        started_exact: None,
        service: Some(ServiceRef {
            name: record.name.clone(),
            registration_id: record.registration_id.clone(),
        }),
    }
}

/// One stored message, one file `<id>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Always [`SCHEMA`].
    pub schema: String,
    /// Lowercase hyphenated UUID minted by csq at send.
    pub id: String,
    /// The resolved sender.
    pub from: Sender,
    /// The addressed session.
    pub to: Recipient,
    /// Provenance (design §3). Absent on every record written before this field: those
    /// deserialise as [`Origin::Peer`], and a peer record still serialises without the
    /// field, so the on-disk shape of ordinary mail is unchanged.
    #[serde(default, skip_serializing_if = "Origin::is_peer")]
    pub origin: Origin,
    /// Id of the message this answers; it was addressed to the sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// Id of the first message of the conversation.
    pub thread: String,
    /// The message text (untrusted; render only through `frame`).
    pub body: String,
    /// Unix seconds, csq's clock.
    pub created_at: u64,
    /// When an oversized hook pointer was recorded. Stored only: it does not mark the
    /// body surfaced/read and is never exposed in receipt or inbox wire views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noticed_at: Option<u64>,
    /// When the body was first surfaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surfaced_at: Option<u64>,
    /// When the body was fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<u64>,
    /// When it was acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_at: Option<u64>,
    /// When the recipient session was found ended with this still unread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undeliverable_at: Option<u64>,
    /// The acknowledgement note, if any (peer-written; render only through `frame`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_note: Option<String>,
    /// A random UUID minted when the acknowledgement was recorded; the note's frame header
    /// and terminator carry it. The note writer composes the note before it exists, so it
    /// cannot forge the terminator (`frame::render_note`). Present exactly when `ack_note` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_nonce: Option<String>,
}

impl Message {
    /// The furthest lifecycle state reached: derived from the timestamps, so a record
    /// cannot hold a status that disagrees with them.
    #[must_use]
    pub fn status(&self) -> Status {
        if self.acked_at.is_some() {
            Status::Acked
        } else if self.read_at.is_some() {
            Status::Read
        } else if self.undeliverable_at.is_some() {
            Status::Undeliverable
        } else if self.surfaced_at.is_some() {
            Status::Surfaced
        } else {
            Status::Queued
        }
    }

    /// Unread for inbox and wake: queued or surfaced. Caps count only queued records.
    #[must_use]
    pub fn pending(&self) -> bool {
        matches!(self.status(), Status::Queued | Status::Surfaced)
    }

    /// Whether this record consumes one of the sender/recipient pending caps.
    ///
    /// A queued body still needs to be delivered and therefore consumes a cap.
    /// A surfaced body has already been presented to the recipient's model; it
    /// remains unread for inbox and wake semantics, but does not block a new send.
    #[must_use]
    pub fn counts_toward_pending_caps(&self) -> bool {
        matches!(self.status(), Status::Queued)
    }

    /// The latest timestamp on the record; retention counts from here.
    #[must_use]
    pub fn last_transition(&self) -> u64 {
        [
            Some(self.created_at),
            self.surfaced_at,
            self.read_at,
            self.acked_at,
            self.undeliverable_at,
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or(self.created_at)
    }

    /// The receipt for this record.
    #[must_use]
    pub fn receipt(&self) -> Receipt {
        Receipt {
            id: self.id.clone(),
            thread: self.thread.clone(),
            status: self.status(),
            created_at: self.created_at,
            surfaced_at: self.surfaced_at,
            read_at: self.read_at,
            acked_at: self.acked_at,
            ack_note_framed: frame::render_note(self),
        }
    }

    /// The view of this record for its recipient: no handle dir, no raw body or note.
    ///
    /// Fail-closed and channel-conservative: owner provenance renders the tool-result
    /// string. The store's inbox/notice paths call [`Message::view_with`] after asking the
    /// daemon; only the hook-injection path passes [`frame::RenderChannel::Hook`].
    #[must_use]
    pub fn view(&self) -> MessageView {
        self.view_with(
            frame::OriginAuthority::unverified(&self.origin),
            frame::RenderChannel::ToolResult,
        )
    }

    /// [`Message::view`] with an explicit, store-proven origin authority and channel.
    #[must_use]
    pub fn view_with(
        &self,
        authority: frame::OriginAuthority,
        channel: frame::RenderChannel,
    ) -> MessageView {
        MessageView {
            id: self.id.clone(),
            thread: self.thread.clone(),
            in_reply_to: self.in_reply_to.clone(),
            from_surface: self.from.surface,
            from_pid: self.from.pid,
            service_origin: matches!(self.origin, Origin::Service { .. }),
            from_name: match &self.from.service {
                // The registered name is grammar-checked on load; `safe_name` is the
                // belt-and-braces sanitiser for a hand-edited record.
                Some(service) => frame::safe_name(&service.name),
                None => self.from.name.as_deref().and_then(frame::safe_name),
            },
            status: self.status(),
            created_at: self.created_at,
            surfaced_at: self.surfaced_at,
            read_at: self.read_at,
            acked_at: self.acked_at,
            framed_body: frame::render_with(self, authority, channel),
            already_shown: false,
            ack_note_framed: frame::render_note(self),
            notice: Some(super::store::PendingNotice::from_message_with(
                self, 1, authority, channel,
            )),
        }
    }
}

/// What `send` and `ack` return: no body, no sender block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Message id.
    pub id: String,
    /// Conversation id.
    pub thread: String,
    /// Lifecycle position.
    pub status: Status,
    /// Creation time.
    pub created_at: u64,
    /// First surfaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surfaced_at: Option<u64>,
    /// Body fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<u64>,
    /// Acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_at: Option<u64>,
    /// Acknowledgement note, framed (peer-written text never leaves the store raw).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_note_framed: Option<String>,
}

/// What `inbox` returns: a record without its handle dir and without its raw body. The only
/// form of the body is [`MessageView::framed_body`], which went through `frame::render`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageView {
    /// Internal notice derived directly from the record; never a wire field.
    #[serde(skip)]
    pub(crate) notice: Option<super::store::PendingNotice>,
    /// Message id.
    pub id: String,
    /// Conversation id.
    pub thread: String,
    /// The message this answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// The sender's identity kind (`claude-code`, `codex`, or `service`).
    pub from_surface: SenderSurface,
    /// The sender's pid.
    pub from_pid: u32,
    /// The record's ORIGIN says a registered service authored it. Readers that show or
    /// address the sender MUST consult this flag (via [`MessageView::is_service_sender`])
    /// as well as the surface: a malformed record can claim a session surface, and a
    /// service has no process identity to print. Never a wire field.
    #[serde(skip)]
    pub service_origin: bool,
    /// The sender's name, sanitised and capped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    /// Lifecycle position.
    pub status: Status,
    /// Creation time.
    pub created_at: u64,
    /// First surfaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surfaced_at: Option<u64>,
    /// Body fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_at: Option<u64>,
    /// Acknowledged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acked_at: Option<u64>,
    /// The body inside its untrusted-data frame, or a fixed csq-authored recovery stub.
    pub framed_body: String,
    /// The stored body is marked surfaced and this view carries a recovery stub. This is
    /// not proof that the model received it; request include_surfaced to recover the body.
    #[serde(default, skip_serializing_if = "is_false")]
    pub already_shown: bool,
    /// The acknowledgement note inside its frame.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_note_framed: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl MessageView {
    /// True when this record must never be presented with a session's process shape.
    ///
    /// The ORIGIN flag is the authority: a record a registered service authored is a
    /// service even when its sender block disagrees (the render path withholds such a
    /// record rather than printing it as a peer). The surface arm keeps a record that
    /// merely CLAIMS `service` from printing a session shape, matching the frame's
    /// `service:<invalid>` treatment. Every sender-showing reader uses this one predicate.
    #[must_use]
    pub fn is_service_sender(&self) -> bool {
        self.service_origin || self.from_surface == SenderSurface::Service
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// Whether `line` is a `#[cfg(…)]` whose predicate names `test` as a term —
    /// `#[cfg(test)]`, `#[cfg(all(test, unix, …))]`, `#[cfg(any(…, test))]` alike.
    ///
    /// ONLY cfg predicates count. A bare top-level `#[test]` fn is deliberately NOT a marker:
    /// the attribute removes that one item from a normal build, so a production item BELOW it
    /// still compiles — cutting there would hide it from the walk. What gates a whole region
    /// of source out of the normal build is the cfg predicate.
    ///
    /// String literals are stripped before the term scan, so a feature gate such as
    /// `#[cfg(feature = "test-utils")]` is NOT treated as a test marker: production code
    /// may legitimately sit behind a test-utils feature.
    fn is_test_only_marker(line: &str) -> bool {
        let l = line.trim_start();
        let Some(rest) = l.strip_prefix("#[cfg(") else {
            return false;
        };
        let mut predicate = String::with_capacity(rest.len());
        let mut in_string = false;
        for c in rest.chars() {
            match c {
                '"' => in_string = !in_string,
                _ if in_string => {}
                _ => predicate.push(c),
            }
        }
        predicate
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|term| term == "test")
    }

    /// The part of `text` that compiles in a normal (non-test) build: everything before the
    /// first test-only marker.
    ///
    /// Residual: a production item placed BELOW the first test-only marker would be invisible
    /// here. The caller's non-vacuity assert catches a walk that read the wrong tree, not this
    /// ordering assumption.
    fn production_source(text: &str) -> String {
        text.lines()
            .take_while(|line| !is_test_only_marker(line))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `from_resolved` is the only way to mint a `VerifiedSession`; its production callers
    /// must be the resolver alone. Production source = the text before a file's first
    /// test-only marker (see [`is_test_only_marker`]). A literal `#[cfg(test)]` split is NOT
    /// enough: `session/swap_session.rs` gates its whole test module
    /// `#[cfg(all(test, unix, feature = "secret-in-memory"))]`, so the literal form counted
    /// 14 test functions as production. Non-vacuity: the resolver file MUST be found calling
    /// it, else the walk read the wrong tree.
    #[test]
    fn from_resolved_has_no_production_caller_outside_the_resolver() {
        let core = crate::testing::manifest_dir(env!("CARGO_MANIFEST_DIR")).join("src");
        let cli = crate::testing::manifest_dir(env!("CARGO_MANIFEST_DIR")).join("../csq/src");
        let mut files = Vec::new();
        rs_files(&core, &mut files);
        if cli.is_dir() {
            rs_files(&cli, &mut files);
        }
        let mut callers = Vec::new();
        for f in &files {
            let text = std::fs::read_to_string(f).unwrap();
            let prod = production_source(&text);
            let hit = prod
                .lines()
                .any(|l| l.contains("from_resolved(") && !l.trim_start().starts_with("//"));
            if hit {
                callers.push(f.strip_prefix(&core).unwrap_or(f).to_path_buf());
            }
        }
        let resolver = std::path::PathBuf::from("sessions/mod.rs");
        let defn = std::path::PathBuf::from("messaging/model.rs");
        assert!(callers.contains(&resolver), "walk is vacuous: {callers:?}");
        let stray: Vec<_> = callers
            .iter()
            .filter(|c| **c != resolver && **c != defn)
            .collect();
        assert!(
            stray.is_empty(),
            "from_resolved outside the resolver: {stray:?}"
        );
    }

    /// Pins the classifier the resolver guard runs over every file, at its boundaries.
    ///
    /// Without this, loosening `is_test_only_marker` would silently widen what counts as
    /// production and the guard above would pass for the wrong reason. The last case is the
    /// positive control required by `instrument-discipline`: a REAL production call must still
    /// be kept, or the guard has been defanged rather than corrected.
    #[test]
    fn production_source_stops_at_every_test_only_marker_form() {
        // The shape that produced the false positive: a compound predicate.
        let compound = concat!(
            "fn prod() {}\n",
            "#[cfg(all(test, unix, feature = \"secret-in-memory\"))]\n",
            "mod tests {\n    fn t() { VerifiedSession::from_resolved(s); }\n}\n",
        );
        assert!(
            !production_source(compound).contains("from_resolved"),
            "a cfg(all(test, …)) module must be excluded from production source"
        );

        // A plain `#[cfg(test)]` module.
        let plain = "fn prod() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n";
        assert!(!production_source(plain).contains("mod tests"));

        // A bare top-level `#[test]` fn is deliberately NOT a cut. The attribute removes only
        // that item from a normal build, so production BELOW it still compiles and must still
        // be scanned — otherwise a real leak could hide behind a test.
        let bare = concat!(
            "fn prod() {}\n",
            "#[test]\nfn t() {}\n",
            "fn later() { let v = VerifiedSession::from_resolved(s); }\n",
        );
        assert!(
            production_source(bare).contains("from_resolved("),
            "a production call below a bare #[test] fn must still be caught"
        );

        // NOT a test marker: a feature gate whose NAME contains "test". Code behind it is
        // production and must be scanned.
        let feature = "#[cfg(feature = \"test-utils\")]\nfn prod() {}\n";
        assert!(
            production_source(feature).contains("fn prod"),
            "a test-utils FEATURE gate is not a test marker"
        );

        // Positive control: a real production call outside the resolver is KEPT.
        let real = "fn prod() { let v = VerifiedSession::from_resolved(s); }\n";
        assert!(
            production_source(real).contains("from_resolved("),
            "the walk must still see a real production call"
        );
    }

    /// Falsifiers: a service acquiring an address, a re-registration matching the old
    /// identity, or a service comparing equal to a session would each flip an assertion.
    #[test]
    fn a_service_sender_has_no_address_and_is_keyed_by_its_registration() {
        let record = crate::messaging::service::ServiceRecord {
            v: 1,
            name: "nightly".to_string(),
            uid: 7,
            registration_id: "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".to_string(),
            created_at: 9,
        };
        let sender = service_sender(&record);
        assert_eq!(sender.surface, SenderSurface::Service);
        assert!(sender.as_recipient().is_none(), "a service has no address");
        assert!(sender.same_identity(&sender));
        let mut reregistered = sender.clone();
        reregistered.service.as_mut().unwrap().registration_id =
            "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4e".to_string();
        assert!(
            !sender.same_identity(&reregistered),
            "a re-registration is a new identity"
        );
        assert!(!sender.same_identity(&owner_sender()));
        assert!(owner_sender().as_recipient().is_some());
    }

    #[test]
    fn a_service_origin_is_well_formed_only_with_the_registered_shapes() {
        let well_formed = Origin::Service {
            name: "nightly".to_string(),
            registration_id: "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".to_string(),
        };
        assert!(well_formed.is_well_formed());
        assert!(!well_formed.is_peer() && !well_formed.claims_owner());
        for bad in [
            // A reserved name can never have been registered.
            Origin::Service {
                name: "claude-code".to_string(),
                registration_id: "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d".to_string(),
            },
            Origin::Service {
                name: "nightly".to_string(),
                registration_id: "not-a-uuid".to_string(),
            },
        ] {
            assert!(!bad.is_well_formed(), "{bad:?}");
        }
    }

    #[test]
    fn status_as_str_matches_the_serde_spelling_for_every_variant() {
        for s in [
            Status::Queued,
            Status::Surfaced,
            Status::Read,
            Status::Acked,
            Status::Undeliverable,
        ] {
            assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
        }
    }
}
