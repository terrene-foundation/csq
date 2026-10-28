//! csq-authoritative limits and the pure checks over them (spec 32 §3, INV-32-03).
//! Nothing here touches the filesystem; `store` calls these under its lock.

use super::frame::contains_frame_phrase;
use super::model::{Message, Recipient, Sender};
use crate::sessions::directives::{is_forbidden_char, DirectiveError};

/// Longest body, in characters.
pub const MAX_BODY_CHARS: usize = 4_000;
/// Longest acknowledgement note, in characters.
pub const MAX_NOTE_CHARS: usize = 500;
/// Sends allowed per `(sender, recipient)` per [`RATE_WINDOW_SECS`].
pub const MAX_SEND_PER_PAIR: usize = 30;
/// The rolling rate window.
pub const RATE_WINDOW_SECS: u64 = 600;
/// Queued messages one recipient may hold across all senders.
pub const MAX_PENDING_PER_RECIPIENT: usize = 50;
/// Queued messages one sender may have outstanding across all recipients (spec 32 §3).
pub const MAX_PENDING_PER_SENDER: usize = 100;
/// Longest session name a sender may carry, in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Longest stored handle dir, in characters.
pub const MAX_HANDLE_DIR_CHARS: usize = 4096;
/// Longest handle-dir hash, in characters.
pub const MAX_HASH_CHARS: usize = 128;
/// Records the store may hold.
pub const MAX_MESSAGE_RECORDS: usize = 2_000;
/// A record is deleted this long after its last transition.
pub const RETENTION_SECS: u64 = 7 * 24 * 3600;
/// A stored record whose latest timestamp is more than this far ahead of csq's clock is bad
/// (quarantined under the lock): a future-dated record would sit in every rate window.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// The caps a store operation enforces. [`Limits::DEFAULT`] is production; tests lower
/// `max_records` so eviction is exercised without writing 2 000 files.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Per-pair sends per window.
    pub max_send_per_pair: usize,
    /// Per-recipient queued cap.
    pub max_pending: usize,
    /// Per-sender outstanding queued cap.
    pub max_pending_per_sender: usize,
    /// Store record cap.
    pub max_records: usize,
}

impl Limits {
    /// The spec 32 §3 values.
    pub const DEFAULT: Limits = Limits {
        max_send_per_pair: MAX_SEND_PER_PAIR,
        max_pending: MAX_PENDING_PER_RECIPIENT,
        max_pending_per_sender: MAX_PENDING_PER_SENDER,
        max_records: MAX_MESSAGE_RECORDS,
    };
}

/// Whether a recipient's session still exists. `Unknown` (a process table that could not
/// be read) is never treated as ended: eviction fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// The session is running.
    Live,
    /// The session is positively gone.
    Ended,
    /// Could not be determined.
    Unknown,
}

/// A character a body may not contain: everything the spec 31 set forbids except the
/// newline, plus the Unicode line and paragraph separators and NEL.
fn body_forbidden(c: char) -> bool {
    c != '\n' && (is_forbidden_char(c) || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}'))
}

/// `Ok` when `body` may be stored: 1..=[`MAX_BODY_CHARS`] characters, no forbidden
/// character except `\n`, no frame phrase ([`contains_frame_phrase`]). The refusal text is
/// fixed and never quotes the body.
pub fn check_body(body: &str) -> Result<(), DirectiveError> {
    let n = body.chars().count();
    if n == 0 || n > MAX_BODY_CHARS {
        return Err(DirectiveError::invalid("message body length out of range"));
    }
    if body.chars().any(body_forbidden) {
        return Err(DirectiveError::invalid(
            "message body contains a forbidden character",
        ));
    }
    if contains_frame_phrase(body) {
        return Err(DirectiveError::invalid("message body contains frame text"));
    }
    Ok(())
}

/// `Ok` when `note` may be stored as an acknowledgement note: at most [`MAX_NOTE_CHARS`],
/// no forbidden character (a note is one line), no frame phrase.
pub fn check_note(note: &str) -> Result<(), DirectiveError> {
    if note.chars().count() > MAX_NOTE_CHARS || note.chars().any(is_forbidden_char) {
        return Err(DirectiveError::invalid("acknowledgement note not allowed"));
    }
    if contains_frame_phrase(note) {
        return Err(DirectiveError::invalid(
            "acknowledgement note contains frame text",
        ));
    }
    Ok(())
}

/// `Ok` when the sender block's text fields may be stored: bounded length, no forbidden
/// character, no frame phrase; the hash is ASCII alphanumerics only.
pub fn check_sender(from: &Sender) -> Result<(), DirectiveError> {
    let text_ok = |s: &str, cap: usize| {
        s.chars().count() <= cap && !s.chars().any(is_forbidden_char) && !contains_frame_phrase(s)
    };
    let hash_ok = !from.handle_dir_hash.is_empty()
        && from.handle_dir_hash.chars().count() <= MAX_HASH_CHARS
        && from
            .handle_dir_hash
            .chars()
            .all(|c| c.is_ascii_alphanumeric());
    let ok = hash_ok
        && text_ok(&from.handle_dir, MAX_HANDLE_DIR_CHARS)
        && from
            .name
            .as_deref()
            .is_none_or(|n| text_ok(n, MAX_NAME_CHARS));
    if ok {
        Ok(())
    } else {
        Err(DirectiveError::invalid("sender fields not allowed"))
    }
}

/// Refuse the send when `from` already sent `limits.max_send_per_pair` messages to `to`
/// inside the window ending at `now`. The pair is keyed by pid and start time only, never
/// the sender's name, so a rename cannot reset it. `next_allowed_at` is when the oldest
/// counted message leaves the window.
pub fn check_rate(
    records: &[Message],
    from: &Sender,
    to: &Recipient,
    now: u64,
    limits: &Limits,
) -> Result<(), DirectiveError> {
    if limits.max_send_per_pair == 0 {
        // A zero cap refuses every send; it must not index an empty window below.
        return Err(DirectiveError::rate_limited(
            "send rate limit for this recipient",
            None,
        ));
    }
    let me = from.as_recipient();
    let mut in_window: Vec<u64> = records
        .iter()
        .filter(|m| m.from.as_recipient().same_session(&me) && m.to.same_session(to))
        .map(|m| m.created_at)
        .filter(|t| now.saturating_sub(*t) < RATE_WINDOW_SECS)
        .collect();
    if in_window.len() < limits.max_send_per_pair {
        return Ok(());
    }
    in_window.sort_unstable();
    let oldest = in_window[in_window.len() - limits.max_send_per_pair];
    Err(DirectiveError::rate_limited(
        "send rate limit for this recipient",
        Some(oldest.saturating_add(RATE_WINDOW_SECS)),
    ))
}

/// Refuse the send when `to` already holds `limits.max_pending` queued messages from all
/// senders together. Surfaced records remain unread for inbox/wake purposes but do not consume
/// this admission cap.
pub fn check_pending(
    records: &[Message],
    to: &Recipient,
    limits: &Limits,
) -> Result<(), DirectiveError> {
    let queued = records
        .iter()
        .filter(|m| m.counts_toward_pending_caps() && m.to.same_session(to))
        .count();
    if queued >= limits.max_pending {
        return Err(DirectiveError::rate_limited(
            "recipient has too many unread messages",
            None,
        ));
    }
    Ok(())
}

/// Refuse the send when `from` already has `limits.max_pending_per_sender` queued messages
/// outstanding across all recipients, so one session cannot fill the store with unread
/// mail for many peers. Surfaced records no longer consume this admission cap. Keyed by pid and
/// start time, never the name.
pub fn check_sender_pending(
    records: &[Message],
    from: &Recipient,
    limits: &Limits,
) -> Result<(), DirectiveError> {
    let n = records
        .iter()
        .filter(|m| m.counts_toward_pending_caps() && m.from.as_recipient().same_session(from))
        .count();
    if n >= limits.max_pending_per_sender {
        return Err(DirectiveError::rate_limited(
            "sender has too many unread messages outstanding",
            None,
        ));
    }
    Ok(())
}

/// Ids that may be evicted to make room, in the order they go: (1) acknowledged records,
/// oldest acknowledgement first; (2) expired records (`now - last_transition >=
/// RETENTION_SECS`), oldest first; (3) unread records marked undeliverable or
/// whose recipient is [`Liveness::Ended`], oldest first; (4) records that are read but not
/// acknowledged, recipient [`Liveness::Live`], oldest `read_at` first. An unread record
/// (queued or surfaced) whose recipient is `Live` or `Unknown` is in no class, so it is never
/// evicted. A record younger than [`RATE_WINDOW_SECS`] is in NO class: it still counts
/// toward a pair's rate window, and deleting it would reset that window. Ties break on id so
/// the order is total.
pub fn eviction_order(
    records: &[Message],
    now: u64,
    liveness: &dyn Fn(&Recipient) -> Liveness,
) -> Vec<String> {
    let expired = |m: &Message| now.saturating_sub(m.last_transition()) >= RETENTION_SECS;
    let in_window = |m: &Message| now.saturating_sub(m.created_at) < RATE_WINDOW_SECS;
    let mut acked: Vec<&Message> = records
        .iter()
        .filter(|m| m.acked_at.is_some() && !in_window(m))
        .collect();
    acked.sort_by(|a, b| (a.acked_at, &a.id).cmp(&(b.acked_at, &b.id)));
    let mut exp: Vec<&Message> = records
        .iter()
        .filter(|m| m.acked_at.is_none() && expired(m) && !in_window(m))
        .collect();
    exp.sort_by(|a, b| (a.last_transition(), &a.id).cmp(&(b.last_transition(), &b.id)));
    let mut ended: Vec<&Message> = records
        .iter()
        .filter(|m| {
            m.acked_at.is_none()
                && !expired(m)
                && !in_window(m)
                && (m.undeliverable_at.is_some() || liveness(&m.to) == Liveness::Ended)
        })
        .collect();
    ended.sort_by(|a, b| (a.last_transition(), &a.id).cmp(&(b.last_transition(), &b.id)));
    // Read, not acknowledged, and the recipient is running: the body was delivered, so
    // dropping the record loses no unread mail. Disjoint from `ended` by the liveness test.
    let mut read: Vec<&Message> = records
        .iter()
        .filter(|m| {
            m.acked_at.is_none()
                && m.read_at.is_some()
                && m.undeliverable_at.is_none()
                && !expired(m)
                && !in_window(m)
                && liveness(&m.to) == Liveness::Live
        })
        .collect();
    read.sort_by(|a, b| (a.read_at, &a.id).cmp(&(b.read_at, &b.id)));
    acked
        .into_iter()
        .chain(exp)
        .chain(ended)
        .chain(read)
        .map(|m| m.id.clone())
        .collect()
}
