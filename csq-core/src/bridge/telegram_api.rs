//! The minimal Telegram Bot API surface the owner bridge needs: `getUpdates`
//! during enrolment and `sendMessage` for the enrolment acknowledgement.
//!
//! # Why this is a trait
//!
//! The enrolment state machine ([`super::enroll`]) must be testable without a
//! network, a bot token or a clock. [`TelegramTransport`] is the seam: the
//! production implementation talks to `api.telegram.org`, the tests drive a
//! scripted queue.
//!
//! # The token is in the URL path
//!
//! Telegram's API puts the bot token in the request path
//! (`/bot<TOKEN>/getUpdates`). Every reqwest error, status and response body is
//! therefore treated as credential-bearing: this module maps each failure to a
//! fixed [`TelegramApiError`] variant and never formats an error, a URL or a
//! response body. The only numbers that reach a caller are the HTTP status
//! code and the update ids Telegram sent.
//!
//! # Forwarded messages
//!
//! A forward is one of the ways a stranger can make the owner's own past
//! message appear in front of the bot. Telegram has changed this shape over
//! time, so any of the five markers it can emit sets
//! [`IncomingMessage::is_forwarded`]: `forward_origin`, `forward_from`,
//! `forward_from_chat`, `forward_sender_name`, `forward_date` (plus
//! `forward_from_message_id`, which only travels with a forward). The
//! enrolment screen refuses a forwarded message whatever else it carries.

use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value};

/// Telegram Bot API origin.
const API_BASE: &str = "https://api.telegram.org";

/// Upper bound on a single HTTP request, including a long poll. The long-poll
/// `timeout` the caller asks for is always smaller than this.
const REQUEST_TIMEOUT_SECS: u64 = 45;

/// Every forward marker Telegram has used. Presence of ANY means "forwarded".
const FORWARD_MARKERS: [&str; 6] = [
    "forward_origin",
    "forward_from",
    "forward_from_chat",
    "forward_sender_name",
    "forward_date",
    "forward_from_message_id",
];

/// One update as Telegram reported it, reduced to what the enrolment screen
/// needs. Everything here is untrusted.
///
/// `Debug` is implemented by hand: see [`IncomingMessage`].
#[derive(Clone, PartialEq, Eq)]
pub struct UpdateEnvelope {
    /// Telegram's monotone update id.
    pub update_id: u64,
    /// The update is an `edited_message`.
    pub is_edited: bool,
    /// The message, when the update is a message (original or edited).
    pub message: Option<IncomingMessage>,
}

/// The untrusted fields of one Telegram message.
///
/// `Debug` is implemented by hand and REDACTED: during pairing `text` is the
/// owner's code, and in general it is the content of a private message.
/// Neither belongs in a log line, a panic message or a `dbg!`.
#[derive(Clone, PartialEq, Eq)]
pub struct IncomingMessage {
    /// `message.from.id` (`0` when Telegram sent no `from`, e.g. a channel post).
    pub from_id: i64,
    /// `message.from.is_bot`.
    pub is_bot: bool,
    /// `message.chat.id`.
    pub chat_id: i64,
    /// `message.chat.type` (`"private"`, `"group"`, …).
    pub chat_type: String,
    /// `message.date` — UNIX seconds.
    pub date: i64,
    /// `message.text`, when the message carries text.
    pub text: Option<String>,
    /// Any forward marker is present.
    pub is_forwarded: bool,
    /// `message.via_bot` is present.
    pub via_bot: bool,
    /// `message.sender_chat` is present.
    pub sender_chat: bool,
}

impl std::fmt::Debug for UpdateEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateEnvelope")
            .field("update_id", &self.update_id)
            .field("is_edited", &self.is_edited)
            .field("message", &self.message)
            .finish()
    }
}

impl std::fmt::Debug for IncomingMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Presence is safe to show; the text itself is not.
        let text = self.text.as_ref().map(|_| "<redacted>");
        f.debug_struct("IncomingMessage")
            .field("from_id", &self.from_id)
            .field("is_bot", &self.is_bot)
            .field("chat_id", &self.chat_id)
            .field("chat_type", &self.chat_type)
            .field("date", &self.date)
            .field("text", &text)
            .field("is_forwarded", &self.is_forwarded)
            .field("via_bot", &self.via_bot)
            .field("sender_chat", &self.sender_chat)
            .finish()
    }
}

/// Why a Telegram API call failed.
///
/// Fixed text only: no URL, no upstream body, no token. The HTTP status code is
/// the one upstream number that is safe to keep.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum TelegramApiError {
    /// The request never produced a response (DNS, TLS, connection, timeout).
    #[error("telegram is unreachable")]
    Transport,
    /// The bot token was rejected (HTTP 401).
    #[error("telegram rejected the bot token")]
    Unauthorized,
    /// Another poller is already using this bot token (HTTP 409).
    #[error("another poller is already using this bot token")]
    Conflict,
    /// Telegram rate-limited the call (HTTP 429).
    #[error("telegram rate-limited the request")]
    RateLimited,
    /// Any other non-success status.
    #[error("telegram returned HTTP {0}")]
    HttpStatus(u16),
    /// The response was not the JSON shape this module expects.
    #[error("telegram returned an unreadable response")]
    Malformed,
}

impl TelegramApiError {
    /// Fixed-vocabulary tag for structured logging (`security.md` MUST-2).
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            TelegramApiError::Transport => "telegram_transport",
            TelegramApiError::Unauthorized => "telegram_unauthorized",
            TelegramApiError::Conflict => "telegram_conflict",
            TelegramApiError::RateLimited => "telegram_rate_limited",
            TelegramApiError::HttpStatus(_) => "telegram_http_status",
            TelegramApiError::Malformed => "telegram_malformed_response",
        }
    }
}

/// The two Bot API calls the bridge makes.
///
/// Implementations MUST NOT expose the token in an error, a `Debug` impl or a
/// log line.
pub trait TelegramTransport {
    /// `getUpdates` with `offset` and a long-poll `timeout_secs`.
    ///
    /// Returns the updates Telegram reported, oldest first.
    fn get_updates(
        &self,
        offset: u64,
        timeout_secs: u64,
    ) -> Result<Vec<UpdateEnvelope>, TelegramApiError>;

    /// `sendMessage` with plain text (no parse mode, no preview).
    fn send_message(&self, chat_id: i64, text: &str) -> Result<(), TelegramApiError>;
}

/// Parses a `getUpdates` response body.
///
/// `{"ok":true,"result":[…]}` is the only accepted shape. An `ok:false`
/// response is reported as [`TelegramApiError::Malformed`] without reading its
/// `description` — Telegram's error text can echo request context, and this
/// module never surfaces upstream text.
pub fn parse_updates(value: &Value) -> Result<Vec<UpdateEnvelope>, TelegramApiError> {
    let object = value.as_object().ok_or(TelegramApiError::Malformed)?;
    if object.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(TelegramApiError::Malformed);
    }
    let result = object
        .get("result")
        .and_then(Value::as_array)
        .ok_or(TelegramApiError::Malformed)?;
    result.iter().map(parse_update).collect()
}

fn parse_update(value: &Value) -> Result<UpdateEnvelope, TelegramApiError> {
    let object = value.as_object().ok_or(TelegramApiError::Malformed)?;
    let update_id = object
        .get("update_id")
        .and_then(Value::as_u64)
        .ok_or(TelegramApiError::Malformed)?;
    let edited = object.get("edited_message");
    let (message, is_edited) = match edited {
        Some(message) => (Some(message), true),
        None => (object.get("message"), false),
    };
    let message = message.map(parse_message).transpose()?;
    Ok(UpdateEnvelope {
        update_id,
        is_edited,
        message,
    })
}

fn parse_message(value: &Value) -> Result<IncomingMessage, TelegramApiError> {
    let object = value.as_object().ok_or(TelegramApiError::Malformed)?;
    let from = object.get("from").and_then(Value::as_object);
    let chat = object
        .get("chat")
        .and_then(Value::as_object)
        .ok_or(TelegramApiError::Malformed)?;
    Ok(IncomingMessage {
        from_id: from
            .and_then(|from| from.get("id"))
            .and_then(Value::as_i64)
            .unwrap_or(0),
        is_bot: from
            .and_then(|from| from.get("is_bot"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        chat_id: chat.get("id").and_then(Value::as_i64).unwrap_or(0),
        chat_type: chat
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        date: object.get("date").and_then(Value::as_i64).unwrap_or(0),
        text: object
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_owned),
        is_forwarded: has_any_key(object, &FORWARD_MARKERS),
        via_bot: object.contains_key("via_bot"),
        sender_chat: object.contains_key("sender_chat"),
    })
}

fn has_any_key(object: &Map<String, Value>, keys: &[&str]) -> bool {
    keys.iter().any(|key| object.contains_key(*key))
}

/// The production transport: `reqwest::blocking` over rustls.
///
/// Deliberately has no `Debug` derive — the client holds the token-bearing URL
/// prefix and must never be formatted.
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
    token: SecretString,
}

impl ReqwestTransport {
    /// Builds a client. A client-construction failure is reported as
    /// [`TelegramApiError::Transport`] with no upstream text.
    pub fn new(token: SecretString) -> Result<Self, TelegramApiError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .map_err(|_| TelegramApiError::Transport)?;
        Ok(Self { client, token })
    }

    fn url(&self, method: &str) -> String {
        format!("{API_BASE}/bot{}/{method}", self.token.expose_secret())
    }
}

fn status_error(status: reqwest::StatusCode) -> TelegramApiError {
    match status.as_u16() {
        401 => TelegramApiError::Unauthorized,
        409 => TelegramApiError::Conflict,
        429 => TelegramApiError::RateLimited,
        code => TelegramApiError::HttpStatus(code),
    }
}

impl TelegramTransport for ReqwestTransport {
    fn get_updates(
        &self,
        offset: u64,
        timeout_secs: u64,
    ) -> Result<Vec<UpdateEnvelope>, TelegramApiError> {
        let response = self
            .client
            .get(self.url("getUpdates"))
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", timeout_secs.to_string()),
            ])
            .send()
            .map_err(|_| TelegramApiError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error(status));
        }
        let bytes = response.bytes().map_err(|_| TelegramApiError::Transport)?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| TelegramApiError::Malformed)?;
        parse_updates(&value)
    }

    fn send_message(&self, chat_id: i64, text: &str) -> Result<(), TelegramApiError> {
        // The workspace's reqwest is compiled without the `json` feature, so
        // the body is serialized here and sent with an explicit content type.
        let body = serde_json::to_vec(&serde_json::json!({
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": true,
        }))
        .map_err(|_| TelegramApiError::Malformed)?;
        let response = self
            .client
            .post(self.url("sendMessage"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|_| TelegramApiError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error(status));
        }
        // The body is not read: the status is the whole contract for a send.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn message(extra: Value) -> Value {
        let mut base = json!({
            "message_id": 5,
            "from": {"id": 42, "is_bot": false},
            "chat": {"id": 42, "type": "private"},
            "date": 1_700_000_000,
            "text": "ABCD2345",
        });
        if let (Some(base), Value::Object(extra)) = (base.as_object_mut(), extra) {
            for (key, value) in extra {
                base.insert(key, value);
            }
        }
        base
    }

    fn update(message: Value) -> Value {
        json!({"update_id": 10, "message": message})
    }

    #[test]
    fn a_plain_private_message_parses() {
        let parsed = parse_updates(&json!({"ok": true, "result": [update(message(json!({})))]}))
            .expect("parse");
        assert_eq!(parsed.len(), 1);
        let message = parsed[0].message.as_ref().expect("message");
        assert_eq!(parsed[0].update_id, 10);
        assert!(!parsed[0].is_edited);
        assert_eq!(message.from_id, 42);
        assert_eq!(message.chat_id, 42);
        assert_eq!(message.chat_type, "private");
        assert_eq!(message.date, 1_700_000_000);
        assert_eq!(message.text.as_deref(), Some("ABCD2345"));
        assert!(!message.is_forwarded);
        assert!(!message.is_bot);
        assert!(!message.via_bot);
        assert!(!message.sender_chat);
    }

    /// Every forward marker Telegram can emit must set the flag; one missed
    /// marker is one way a stranger can make the owner's own message appear.
    #[test]
    fn every_forward_marker_sets_the_flag() {
        for marker in FORWARD_MARKERS {
            let mut forwarded = message(json!({}));
            forwarded
                .as_object_mut()
                .expect("object")
                .insert(marker.to_owned(), json!({"id": 9}));
            let parsed =
                parse_updates(&json!({"ok": true, "result": [update(forwarded)]})).expect("parse");
            let message = parsed[0].message.as_ref().expect("message");
            assert!(
                message.is_forwarded,
                "{marker} must mark the message forwarded"
            );
        }
    }

    #[test]
    fn edited_and_non_message_updates_are_shaped_not_dropped() {
        let edited = parse_updates(&json!({
            "ok": true,
            "result": [{"update_id": 11, "edited_message": message(json!({}))}]
        }))
        .expect("parse");
        assert!(edited[0].is_edited);
        assert!(edited[0].message.is_some());

        let callback = parse_updates(&json!({
            "ok": true,
            "result": [{"update_id": 12, "callback_query": {"id": "x"}}]
        }))
        .expect("parse");
        assert!(!callback[0].is_edited);
        assert!(callback[0].message.is_none());
    }

    #[test]
    fn via_bot_and_sender_chat_are_flagged() {
        let parsed = parse_updates(&json!({
            "ok": true,
            "result": [update(message(json!({"via_bot": {"id": 7}, "sender_chat": {"id": 8}})))]
        }))
        .expect("parse");
        let message = parsed[0].message.as_ref().expect("message");
        assert!(message.via_bot);
        assert!(message.sender_chat);
    }

    #[test]
    fn an_error_shaped_response_is_malformed_and_never_surfaced() {
        let error = parse_updates(&json!({
            "ok": false,
            "description": "Unauthorized bot123:SENTINEL"
        }))
        .expect_err("ok:false must not parse");
        assert_eq!(error, TelegramApiError::Malformed);
        assert!(!error.to_string().contains("SENTINEL"));
        assert_eq!(error.error_kind_tag(), "telegram_malformed_response");
    }

    #[test]
    fn debug_output_redacts_message_text() {
        let parsed = parse_updates(&json!({
            "ok": true,
            "result": [update(message(json!({"text": "SENTINEL-CODE"})))]
        }))
        .expect("parse");
        let rendered = format!("{parsed:?}");
        assert!(
            !rendered.contains("SENTINEL-CODE"),
            "message text must never appear in Debug: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "the redaction must be explicit, not an omission: {rendered}"
        );
    }

    #[test]
    fn a_missing_update_id_is_malformed() {
        assert_eq!(
            parse_updates(&json!({"ok": true, "result": [{"message": message(json!({}))}]}))
                .expect_err("missing update_id"),
            TelegramApiError::Malformed
        );
    }
}
