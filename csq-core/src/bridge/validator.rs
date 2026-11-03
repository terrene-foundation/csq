//! Pure inbound-update validation.
//!
//! The daemon hands every Telegram update through [`validate_update`] before
//! anything else looks at it. The function is deliberately I/O-free: no clock,
//! no network, no vault. `now` is injected so the table tests are
//! deterministic (`discovery_csq_core_chrono_no_clock_inject_now` — csq-core
//! never reads the wall clock directly).
//!
//! # What is checked, and in what order
//!
//! 1. Replay: `update_id` must be strictly greater than the stored high-water.
//! 2. The sender must not be a bot.
//! 3. The chat must be a private chat (a group has other members; an owner
//!    message there is not owner-exclusive).
//! 4. `from_id` must equal the pinned owner user id.
//! 5. `chat_id` must equal the pinned owner chat id.
//! 6. `chat_id` must equal `from_id` (a private chat's id IS the user's id).
//! 7. Forwarded / via-bot / sender-chat updates are refused outright.
//! 8. Non-message kinds and edited messages are refused: only a fresh
//!    `message` carries an owner intent we can trust.
//! 9. Text must be present, ≤ 4096 bytes, and free of control characters other
//!    than `\n`. Refused, never stripped — stripping would silently change
//!    what the owner asked for.
//! 10. A date in the future beyond the skew allowance is refused as
//!     [`Reject::Stale`]. An old date is NOT refused: the rule is "old is
//!     marked, not dropped", so the date is returned and the caller prefixes
//!     the message with its age.
//!
//! The order matters for diagnostics only — every refusal is a refusal — but a
//! specific reason is what lets the daemon log a fixed tag and the owner
//! understand why their message vanished.

/// Maximum accepted text length in bytes (Telegram's own message cap).
pub const MAX_TEXT_BYTES: usize = 4096;

/// An update at most this old is treated as a fresh command (seconds).
pub const COMMAND_FRESHNESS_SECS: i64 = 120;

/// An update at most this far in the future is tolerated (clock skew, seconds).
pub const FUTURE_SKEW_SECS: i64 = 120;

/// The raw, untrusted fields of one Telegram update that the screen needs.
///
/// Built by the daemon's JSON adapter. Nothing here is trusted: every field is
/// attacker-controlled until [`validate_update`] has returned an `Ok`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawUpdate {
    /// Telegram's monotone update id.
    pub update_id: u64,
    /// `message.from.id` — the sender's user id.
    pub from_id: i64,
    /// `message.chat.id` — the chat the message arrived in.
    pub chat_id: i64,
    /// `message.chat.type` (`"private"`, `"group"`, …).
    pub chat_type: String,
    /// `message.from.is_bot`.
    pub is_bot: bool,
    /// `message.date` — UNIX seconds.
    pub date: i64,
    /// `message.text`, when the update carries text.
    pub text: Option<String>,
    /// `message.forward_origin` / `forward_from` present.
    pub has_forward: bool,
    /// `message.via_bot` present (sent through an inline bot).
    pub via_bot: bool,
    /// `message.sender_chat` present (sent on behalf of a channel).
    pub sender_chat: bool,
    /// The update arrived as `edited_message`.
    pub is_edited: bool,
    /// The update is not a plain `message` (callback_query, channel_post, …).
    pub is_command_kind: bool,
}

/// An update that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUpdate {
    /// Telegram's update id (already checked to be above the high-water mark).
    pub update_id: u64,
    /// The message text. Not trimmed: the caller decides how to parse it.
    pub text: String,
    /// `message.date` in UNIX seconds. The caller compares it with `now` and
    /// marks the age; the validator never rejects on age.
    pub date: i64,
}

/// Why an update was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// `update_id` is at or below the stored high-water mark.
    Replay,
    /// `from_id` is not the pinned owner.
    WrongUser,
    /// `chat_id` is not the pinned owner chat (or differs from `from_id`).
    WrongChat,
    /// The chat is not a private chat.
    NotPrivate,
    /// The sender is a bot.
    FromBot,
    /// The message was forwarded.
    Forwarded,
    /// The message was sent via an inline bot.
    ViaBot,
    /// The message was sent on behalf of a channel.
    SenderChat,
    /// The update is not a fresh text message.
    NotMessage,
    /// The message date is in the future beyond the skew allowance.
    Stale(i64),
    /// The text is longer than [`MAX_TEXT_BYTES`]; carries the length in bytes.
    TooLong(usize),
    /// The text contains a control character other than `\n`.
    BadChars,
}

impl Reject {
    /// Fixed-vocabulary tag for structured logging (`security.md` MUST-2).
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            Reject::Replay => "bridge_reject_replay",
            Reject::WrongUser => "bridge_reject_wrong_user",
            Reject::WrongChat => "bridge_reject_wrong_chat",
            Reject::NotPrivate => "bridge_reject_not_private",
            Reject::FromBot => "bridge_reject_from_bot",
            Reject::Forwarded => "bridge_reject_forwarded",
            Reject::ViaBot => "bridge_reject_via_bot",
            Reject::SenderChat => "bridge_reject_sender_chat",
            Reject::NotMessage => "bridge_reject_not_message",
            Reject::Stale(_) => "bridge_reject_stale",
            Reject::TooLong(_) => "bridge_reject_too_long",
            Reject::BadChars => "bridge_reject_bad_chars",
        }
    }
}

/// Screens one raw update against the owner pin and the replay high-water mark.
///
/// Returns the validated update or the specific refusal reason. Pure: the same
/// inputs always produce the same result.
pub fn validate_update(
    raw: &RawUpdate,
    high_water: u64,
    pinned_user: i64,
    pinned_chat: i64,
    now: i64,
) -> Result<ValidatedUpdate, Reject> {
    if raw.update_id <= high_water {
        return Err(Reject::Replay);
    }
    if raw.is_bot {
        return Err(Reject::FromBot);
    }
    if raw.chat_type != "private" {
        return Err(Reject::NotPrivate);
    }
    if raw.from_id != pinned_user {
        return Err(Reject::WrongUser);
    }
    if raw.chat_id != pinned_chat {
        return Err(Reject::WrongChat);
    }
    if raw.chat_id != raw.from_id {
        return Err(Reject::WrongChat);
    }
    if raw.has_forward {
        return Err(Reject::Forwarded);
    }
    if raw.via_bot {
        return Err(Reject::ViaBot);
    }
    if raw.sender_chat {
        return Err(Reject::SenderChat);
    }
    if raw.is_command_kind || raw.is_edited {
        return Err(Reject::NotMessage);
    }
    let Some(text) = raw.text.as_deref() else {
        return Err(Reject::NotMessage);
    };
    if text.len() > MAX_TEXT_BYTES {
        return Err(Reject::TooLong(text.len()));
    }
    if text.chars().any(|c| c.is_control() && c != '\n') {
        return Err(Reject::BadChars);
    }
    // Future-dated beyond the skew allowance: a timestamp we did not observe
    // cannot be "old", so this is tampering or a badly skewed clock, not age.
    if raw.date > now.saturating_add(FUTURE_SKEW_SECS) {
        return Err(Reject::Stale(raw.date));
    }
    Ok(ValidatedUpdate {
        update_id: raw.update_id,
        text: text.to_owned(),
        date: raw.date,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: i64 = 42;
    const NOW: i64 = 1_000_000;

    fn valid() -> RawUpdate {
        RawUpdate {
            update_id: 10,
            from_id: OWNER,
            chat_id: OWNER,
            chat_type: "private".into(),
            is_bot: false,
            date: NOW,
            text: Some("/clear".into()),
            has_forward: false,
            via_bot: false,
            sender_chat: false,
            is_edited: false,
            is_command_kind: false,
        }
    }

    fn check(raw: &RawUpdate) -> Result<ValidatedUpdate, Reject> {
        validate_update(raw, 9, OWNER, OWNER, NOW)
    }

    #[test]
    fn accepts_the_pinned_owner() {
        let validated = check(&valid()).expect("owner is accepted");
        assert_eq!(validated.update_id, 10);
        assert_eq!(validated.text, "/clear");
        assert_eq!(validated.date, NOW);
    }

    /// The username is not a field the screen trusts, so a different `from_id`
    /// is refused even when the attacker copies the owner's username.
    #[test]
    fn wrong_from_id_carrying_the_owners_username_is_refused() {
        let mut raw = valid();
        raw.from_id = 43;
        assert_eq!(check(&raw), Err(Reject::WrongUser));
    }

    #[test]
    fn owner_post_in_a_group_is_refused() {
        let mut raw = valid();
        raw.chat_type = "group".into();
        raw.chat_id = -1001234567890;
        assert_eq!(check(&raw), Err(Reject::NotPrivate));
    }

    #[test]
    fn owner_in_a_private_chat_that_is_not_the_pinned_one() {
        let mut raw = valid();
        raw.chat_id = OWNER + 1;
        assert_eq!(check(&raw), Err(Reject::WrongChat));
    }

    #[test]
    fn chat_id_must_equal_from_id() {
        let mut raw = valid();
        raw.chat_id = OWNER + 1;
        // Both the pinned-chat and the chat==from checks refuse; the pinned
        // check runs first, so pin the chat id to the same wrong value to
        // isolate the chat==from rule.
        assert_eq!(check(&raw), Err(Reject::WrongChat));
        let result = validate_update(&raw, 9, OWNER, OWNER + 1, NOW);
        assert_eq!(result, Err(Reject::WrongChat));
    }

    #[test]
    fn edited_message_is_refused() {
        let mut raw = valid();
        raw.is_edited = true;
        assert_eq!(check(&raw), Err(Reject::NotMessage));
    }

    #[test]
    fn forwarded_message_is_refused() {
        let mut raw = valid();
        raw.has_forward = true;
        assert_eq!(check(&raw), Err(Reject::Forwarded));
    }

    #[test]
    fn via_bot_message_is_refused() {
        let mut raw = valid();
        raw.via_bot = true;
        assert_eq!(check(&raw), Err(Reject::ViaBot));
    }

    #[test]
    fn sender_chat_message_is_refused() {
        let mut raw = valid();
        raw.sender_chat = true;
        assert_eq!(check(&raw), Err(Reject::SenderChat));
    }

    #[test]
    fn bot_sender_is_refused() {
        let mut raw = valid();
        raw.is_bot = true;
        assert_eq!(check(&raw), Err(Reject::FromBot));
    }

    #[test]
    fn non_message_kind_is_refused() {
        let mut raw = valid();
        raw.is_command_kind = true;
        assert_eq!(check(&raw), Err(Reject::NotMessage));
    }

    #[test]
    fn absent_text_is_refused() {
        let mut raw = valid();
        raw.text = None;
        assert_eq!(check(&raw), Err(Reject::NotMessage));
    }

    /// Old messages are NOT dropped: the date is returned so the caller can
    /// prefix the command with its age.
    #[test]
    fn old_date_is_accepted_and_returned_for_age_marking() {
        let mut raw = valid();
        raw.date = NOW - 3_600;
        let validated = check(&raw).expect("old is marked, not dropped");
        assert_eq!(validated.date, NOW - 3_600);
        assert!(NOW - validated.date > COMMAND_FRESHNESS_SECS);
    }

    /// A date beyond the future-skew allowance is not "old" — it is a
    /// timestamp this process never observed, so it is refused.
    #[test]
    fn future_dated_update_is_stale() {
        let mut raw = valid();
        raw.date = NOW + FUTURE_SKEW_SECS + 1;
        assert_eq!(check(&raw), Err(Reject::Stale(NOW + FUTURE_SKEW_SECS + 1)));
        raw.date = NOW + FUTURE_SKEW_SECS;
        assert!(check(&raw).is_ok(), "skew allowance is inclusive");
    }

    #[test]
    fn replayed_update_id_is_refused() {
        let mut raw = valid();
        for update_id in [9, 8, 1] {
            raw.update_id = update_id;
            assert_eq!(check(&raw), Err(Reject::Replay));
        }
        raw.update_id = 10;
        assert!(
            check(&raw).is_ok(),
            "strictly above the high-water is fresh"
        );
    }

    #[test]
    fn oversized_text_is_refused_with_its_byte_length() {
        let mut raw = valid();
        raw.text = Some("a".repeat(MAX_TEXT_BYTES + 1));
        assert_eq!(check(&raw), Err(Reject::TooLong(MAX_TEXT_BYTES + 1)));
        raw.text = Some("a".repeat(MAX_TEXT_BYTES));
        assert!(check(&raw).is_ok(), "4096 bytes is the limit, inclusive");
    }

    #[test]
    fn control_characters_are_refused_but_newline_is_allowed() {
        for bad in ["bell\u{7}", "carriage\rreturn", "esc\u{1b}[31m", "nul\0"] {
            let mut raw = valid();
            raw.text = Some(bad.to_string());
            assert_eq!(check(&raw), Err(Reject::BadChars), "must refuse {bad:?}");
        }
        let mut raw = valid();
        raw.text = Some("line one\nline two".into());
        assert!(check(&raw).is_ok());
    }

    #[test]
    fn refusal_reasons_have_distinct_fixed_tags() {
        let tags = [
            Reject::Replay.error_kind_tag(),
            Reject::WrongUser.error_kind_tag(),
            Reject::WrongChat.error_kind_tag(),
            Reject::NotPrivate.error_kind_tag(),
            Reject::FromBot.error_kind_tag(),
            Reject::Forwarded.error_kind_tag(),
            Reject::ViaBot.error_kind_tag(),
            Reject::SenderChat.error_kind_tag(),
            Reject::NotMessage.error_kind_tag(),
            Reject::Stale(0).error_kind_tag(),
            Reject::TooLong(0).error_kind_tag(),
            Reject::BadChars.error_kind_tag(),
        ];
        let unique: std::collections::BTreeSet<&str> = tags.iter().copied().collect();
        assert_eq!(unique.len(), tags.len());
        assert!(tags.iter().all(|t| t.starts_with("bridge_reject_")));
    }
}
