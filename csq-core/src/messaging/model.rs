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

/// The sending session. Built only from the identity the caller resolved (INV-32-01); the
/// store never takes a sender from message text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sender {
    /// Process id of the CLI process.
    pub pid: u32,
    /// OS process start time, unix seconds.
    pub started_at: u64,
    /// Which CLI.
    pub surface: Surface,
    /// Hash of the canonical handle dir (the only form of it that may reach a wire).
    pub handle_dir_hash: String,
    /// The handle dir itself: stored, never on a wire.
    pub handle_dir: String,
    /// Optional session name; excluded from every limit key so a rename frees nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
}

impl VerifiedSession {
    /// Wrap the identity the §2.2 resolver proved. Its callers are the resolver
    /// (`sessions::ResolvedCaller::verified`) and in-crate tests, and nothing else: the
    /// test `from_resolved_has_no_production_caller_outside_the_resolver` greps the
    /// production source of both crates for it. Read-only paths take a plain [`Recipient`]
    /// (`store::pending_count`) and never build one of these.
    pub(crate) fn from_resolved(sender: Sender) -> Self {
        Self { sender }
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
        self.sender.as_recipient()
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
    /// The sender as an addressable session.
    #[must_use]
    pub fn as_recipient(&self) -> Recipient {
        Recipient {
            pid: self.pid,
            started_at: self.started_at,
            surface: self.surface,
            started_exact: self.started_exact,
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
    #[must_use]
    pub fn view(&self) -> MessageView {
        MessageView {
            id: self.id.clone(),
            thread: self.thread.clone(),
            in_reply_to: self.in_reply_to.clone(),
            from_surface: self.from.surface,
            from_pid: self.from.pid,
            from_name: self.from.name.as_deref().and_then(frame::safe_name),
            status: self.status(),
            created_at: self.created_at,
            surfaced_at: self.surfaced_at,
            read_at: self.read_at,
            acked_at: self.acked_at,
            framed_body: frame::render(self),
            already_shown: false,
            ack_note_framed: frame::render_note(self),
            notice: Some(super::store::PendingNotice::from_message(self, 1)),
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
    /// The sender's CLI.
    pub from_surface: Surface,
    /// The sender's pid.
    pub from_pid: u32,
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

    /// `from_resolved` is the only way to mint a `VerifiedSession`; its production callers
    /// must be the resolver alone. Production source = the text before a file's first
    /// `#[cfg(test)]`. Non-vacuity: the resolver file MUST be found calling it, else the walk
    /// read the wrong tree.
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
            let prod = text.split("#[cfg(test)]").next().unwrap_or("");
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
