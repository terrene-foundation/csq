//! Cross-CLI messaging wire types: the `csq.message_receipt.v1` and `csq.message_inbox.v1`
//! payloads (spec 32 §4.1).
//!
//! This module owns only the public serialized shape. The store, limits and lifecycle live in
//! the app (`csq-core::messaging`). Optional fields are ABSENT on the wire, never `null`
//! (spec 30 §5). Full `framed_body` and `ack_note_framed` values contain peer text inside
//! csq's sanitised untrusted-data frame (spec 32 §3); preserve that frame when giving it to
//! a model. `framed_body` may instead be a fixed csq-authored recovery stub when
//! `already_shown` is true. A stored surfaced marker is not proof a hook successfully
//! printed the body: request `include_surfaced:true` (CLI `--include-surfaced`) to recover
//! it. No handle dir and no raw body is ever here.
//!
//! UNTRUSTED: `MessageRow::from_name` is chosen by the PEER (the sender names itself) and is
//! NOT framed. A consumer must treat it as untrusted text and must never place it into a
//! model's context outside a frame of its own; the CLI hook never prints it.

//! # In-process wake embedding
//!
//! When embedding the application's wake API in the host process:
//! the host process must not ignore SIGCHLD or reap children it did not spawn while a wake is in flight.
//! These wire-only types perform no wake and configure no process signal policy.
//! A consumer only decoding subprocess JSON is not an in-process wake host.

use serde::{Deserialize, Serialize};

/// `csq.message_receipt.v1` payload: where a message is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MessageReceipt {
    /// The message id (a csq-minted UUID).
    pub id: String,
    /// Id of the first message of the conversation.
    pub thread: String,
    /// `queued`, `surfaced`, `read`, `acked` or `undeliverable`.
    pub status: String,
    /// Unix seconds the message was stored.
    pub created_at: u64,
    /// Unix seconds a notice of it was first shown; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surfaced_at: Option<u64>,
    /// Unix seconds the body was fetched; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<u64>,
    /// Unix seconds it was acknowledged; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_at: Option<u64>,
    /// The acknowledgement note inside its untrusted-data frame; absent when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_note_framed: Option<String>,
    /// How a send was delivered (`queued_only`, `codex_woken`, `codex_wake_failed`, `codex_queued`,
    /// `codex_queued_unverified`); present
    /// on a `send` receipt only. Claude values `claude_woken`, `claude_wake_failed` and
    /// `claude_wake_pending` and `claude_wake_rate_limited` are additive. `stored_no_wake` means
    /// the sender asked for no wake (`wake:false` / `--no-wake`) and none was attempted. Woken means a fixed notice reached the inbox
    /// socket, not that it was read. Pending means this attempt posted nothing because a
    /// recent successful notice for this incarnation still covers unread stored messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<String>,
    /// Why a delivery status is what it is, when the status alone is ambiguous
    /// (`wake_pending`, `codex_no_turn_yet`); additive, absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_reason: Option<String>,
    /// Present (`codex_no_turn_hook`) when the sender asked for `wake:false` / `--no-wake` but
    /// the recipient is a Codex session, which has no per-turn surfacing hook: the message was
    /// woken exactly as with `wake:true`. Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake_override: Option<String>,
    /// Process id of the session a `send` resolved to (so a send by name reports who it
    /// reached); present on a `send` receipt only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_pid: Option<u32>,
    /// Start time of the session a `send` resolved to, unix seconds; with `to_pid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_started_at: Option<u64>,
    /// Surface of the session a `send` reached (`claude-code` or `codex`); with `to_pid`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_surface: Option<String>,
    /// How the recipient's name resolved (`self`, `claude` or `default`); present only when
    /// the send was addressed by name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_label_source: Option<String>,
}

impl MessageReceipt {
    /// Build a receipt with the required fields; the optional fields start absent.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        thread: impl Into<String>,
        status: impl Into<String>,
        created_at: u64,
    ) -> Self {
        Self {
            id: id.into(),
            thread: thread.into(),
            status: status.into(),
            created_at,
            surfaced_at: None,
            read_at: None,
            acked_at: None,
            ack_note_framed: None,
            delivery: None,
            delivery_reason: None,
            wake_override: None,
            to_pid: None,
            to_started_at: None,
            to_surface: None,
            to_label_source: None,
        }
    }

    /// Set the surfaced time.
    #[must_use]
    pub fn with_surfaced_at(mut self, at: impl Into<Option<u64>>) -> Self {
        self.surfaced_at = at.into();
        self
    }

    /// Set the read time.
    #[must_use]
    pub fn with_read_at(mut self, at: impl Into<Option<u64>>) -> Self {
        self.read_at = at.into();
        self
    }

    /// Set the acknowledged time.
    #[must_use]
    pub fn with_acked_at(mut self, at: impl Into<Option<u64>>) -> Self {
        self.acked_at = at.into();
        self
    }

    /// Set the framed acknowledgement note.
    #[must_use]
    pub fn with_ack_note_framed(mut self, note: impl Into<Option<String>>) -> Self {
        self.ack_note_framed = note.into();
        self
    }

    /// Set the resolved recipient of a send.
    #[must_use]
    pub fn with_to(mut self, pid: u32, started_at: u64) -> Self {
        self.to_pid = Some(pid);
        self.to_started_at = Some(started_at);
        self
    }

    /// Set the surface of the session a send reached.
    #[must_use]
    pub fn with_to_surface(mut self, surface: impl Into<Option<String>>) -> Self {
        self.to_surface = surface.into();
        self
    }

    /// Set how the recipient's name resolved (a send addressed by name).
    #[must_use]
    pub fn with_to_label_source(mut self, source: impl Into<Option<String>>) -> Self {
        self.to_label_source = source.into();
        self
    }

    /// Set the reason tag of the delivery outcome.
    #[must_use]
    pub fn with_delivery_reason(mut self, reason: impl Into<Option<String>>) -> Self {
        self.delivery_reason = reason.into();
        self
    }

    /// Record that the sender's `wake:false` was overridden for this recipient.
    #[must_use]
    pub fn with_wake_override(mut self, over: impl Into<Option<String>>) -> Self {
        self.wake_override = over.into();
        self
    }

    /// Set the delivery outcome of a send.
    #[must_use]
    pub fn with_delivery(mut self, delivery: impl Into<Option<String>>) -> Self {
        self.delivery = delivery.into();
        self
    }
}

/// One received message: who sent it and the framed body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MessageRow {
    /// The message id.
    pub id: String,
    /// Conversation id.
    pub thread: String,
    /// The message this answers; absent for a conversation's first message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    /// The sender's CLI (`claude-code` or `codex`).
    pub from_surface: String,
    /// The sender's pid.
    pub from_pid: u32,
    /// The sender's name, sanitised and capped; absent when it has none. UNTRUSTED and
    /// UNFRAMED: the sender chose it, and unlike `framed_body` it is not inside csq's
    /// untrusted-data frame. Display it as data; never hand it to a model as an instruction
    /// or outside a frame of your own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_name: Option<String>,
    /// Unix seconds the message was stored.
    pub created_at: u64,
    /// The body inside its untrusted-data frame, or a fixed csq-authored recovery stub.
    pub framed_body: String,
    /// True when the required body field is a recovery stub for a stored surfaced marker.
    /// This is not proof the model received the body; `include_surfaced` restores it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub already_shown: bool,
}

impl MessageRow {
    /// Build a row with the required fields; `in_reply_to` and `from_name` start absent.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        thread: impl Into<String>,
        from_surface: impl Into<String>,
        from_pid: u32,
        created_at: u64,
        framed_body: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            thread: thread.into(),
            in_reply_to: None,
            from_surface: from_surface.into(),
            from_pid,
            from_name: None,
            created_at,
            framed_body: framed_body.into(),
            already_shown: false,
        }
    }

    /// Mark the row as carrying an already-shown stub.
    #[must_use]
    pub fn with_already_shown(mut self, already_shown: bool) -> Self {
        self.already_shown = already_shown;
        self
    }

    /// Set the message this answers.
    #[must_use]
    pub fn with_in_reply_to(mut self, id: impl Into<Option<String>>) -> Self {
        self.in_reply_to = id.into();
        self
    }

    /// Set the sender's name.
    #[must_use]
    pub fn with_from_name(mut self, name: impl Into<Option<String>>) -> Self {
        self.from_name = name.into();
        self
    }
}

/// One inbox row: the message plus its current receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MessageInboxEntry {
    /// The message, as untrusted data from a peer session.
    pub message: MessageRow,
    /// Its current lifecycle state.
    pub receipt: MessageReceipt,
}

impl MessageInboxEntry {
    /// Build an inbox row.
    #[must_use]
    pub fn new(message: MessageRow, receipt: MessageReceipt) -> Self {
        Self { message, receipt }
    }
}

/// `csq.message_inbox.v1` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct MessageInboxPayload {
    /// Messages addressed to the calling session, oldest first; present even when empty.
    pub messages: Vec<MessageInboxEntry>,
}

impl MessageInboxPayload {
    /// Build an inbox payload.
    #[must_use]
    pub fn new(messages: Vec<MessageInboxEntry>) -> Self {
        Self { messages }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn already_shown_is_optional_and_legacy_body_field_remains_required() {
        let legacy = json!({"id":"i", "thread":"t", "from_surface":"codex",
            "from_pid":1, "created_at":10, "framed_body":"full body"});
        let row: MessageRow = serde_json::from_value(legacy.clone()).unwrap();
        assert!(!row.already_shown);
        assert_eq!(serde_json::to_value(&row).unwrap(), legacy);
        let stub = MessageRow::new("i", "t", "codex", 1, 10, "[csq: already shown; recover full body with inbox include_surfaced:true (CLI --include-surfaced).]")
            .with_already_shown(true);
        let wire = serde_json::to_value(&stub).unwrap();
        assert_eq!(wire["framed_body"], "[csq: already shown; recover full body with inbox include_surfaced:true (CLI --include-surfaced).]");
        assert_eq!(wire["already_shown"], true);
        assert_eq!(
            serde_json::from_value::<MessageRow>(wire.clone()).unwrap(),
            stub
        );
        let mut missing = wire;
        missing.as_object_mut().unwrap().remove("framed_body");
        assert!(serde_json::from_value::<MessageRow>(missing).is_err());
    }

    #[test]
    fn receipt_minimal_shape_has_no_nulls() {
        let r = MessageReceipt::new("i", "t", "queued", 10);
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"id": "i", "thread": "t", "status": "queued", "created_at": 10})
        );
    }

    #[test]
    fn receipt_carries_the_claude_delivery_values_on_the_wire() {
        for d in [
            "claude_woken",
            "claude_wake_failed",
            "claude_wake_pending",
            "claude_wake_rate_limited",
            "stored_no_wake",
        ] {
            let r = MessageReceipt::new("i", "t", "queued", 10).with_delivery(Some(d.to_string()));
            let v = serde_json::to_value(&r).unwrap();
            assert_eq!(v["delivery"], json!(d));
            let back: MessageReceipt = serde_json::from_value(v).unwrap();
            assert_eq!(back.delivery.as_deref(), Some(d));
        }
    }

    #[test]
    fn receipt_maximal_round_trips_and_empty_inbox_keeps_its_key() {
        let r = MessageReceipt::new("i", "t", "acked", 10)
            .with_surfaced_at(11u64)
            .with_read_at(12u64)
            .with_acked_at(13u64)
            .with_ack_note_framed(Some("framed".to_string()))
            .with_delivery(Some("queued_only".to_string()))
            .with_to(77, 1_234)
            .with_to_surface(Some("codex".to_string()))
            .with_to_label_source(Some("self".to_string()));
        let back: MessageReceipt =
            serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        assert_eq!(
            serde_json::to_value(MessageInboxPayload::new(vec![])).unwrap(),
            json!({"messages": []})
        );
    }
}
