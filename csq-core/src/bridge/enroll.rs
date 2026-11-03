//! Owner enrolment — the one place a stranger could try to claim the bridge.
//!
//! `csq telegram pair` mints a short one-time code, prints it on the owner's
//! terminal and then polls `getUpdates` itself for at most five minutes. The
//! first message that passes every check becomes the owner; everything else is
//! refused.
//!
//! # The challenge never touches disk
//!
//! The code and its SHA-256 live in zeroizing buffers for the length of the
//! handshake, and the CSPRNG bytes they are derived from are wiped once the
//! code exists; dropping the challenge wipes the rest. Nothing writes any of it
//! — not a log, not an audit record, not an error, not a file — so there is no
//! at-rest artifact to brute-force, and a process killed mid-handshake leaves
//! no live challenge behind. The five-minute window is enforced by the
//! in-memory `expires_at`, and the code is consumed exactly once, on the
//! accepted message.
//!
//! # What counts as the owner
//!
//! A message is accepted only when ALL of the following hold:
//!
//! * the chat is `private`;
//! * the text equals the code (constant-time comparison over SHA-256);
//! * the message is not forwarded (any Telegram forward marker), not from a
//!   bot, not sent via an inline bot, not sent on behalf of a channel, and not
//!   an edit;
//! * the sender and chat ids are usable and equal;
//! * the message date is inside the challenge window (bounded clock skew).
//!
//! Wrong codes are counted PER CHAT: three of them burn that chat's budget, and
//! a burned chat cannot come back even with the correct code. A stranger's
//! guesses therefore cannot abort the owner's pairing (a global counter would
//! have been an abort button any account could press); the run continues for
//! every other chat. At most [`MAX_TRACKED_CHATS`] distinct chats are tracked,
//! so a flood of throwaway accounts cannot grow the map. Refusals that must not
//! count against anyone (a group message, a forward, a bot) are ignored.
//!
//! # The cursor hand-off
//!
//! Every update the poller sees advances the shared cursor BEFORE the owner is
//! pinned, so a daemon restart can never route the pairing traffic into a
//! session, and a crash between the two durable writes leaves an unpinned
//! bridge rather than a pinned one with a stale cursor.

use crate::bridge::config::{self, BridgeConfig, BridgeConfigError, BridgeCursor};
use crate::bridge::telegram_api::{TelegramApiError, TelegramTransport, UpdateEnvelope};
use crate::bridge::validator::FUTURE_SKEW_SECS;
use sha2::{Digest, Sha256};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Wrong code attempts allowed per chat before that chat is burned.
pub const MAX_CODE_MISMATCHES: u32 = 3;

/// Most distinct chats whose wrong guesses are tracked.
///
/// This is a MEMORY bound, not a security bound: N accounts × 3 guesses against
/// a 40-bit code is negligible for any N (the guess chance stays ~3·2⁻⁴⁰ per
/// chat), so the cap only stops a flood of thousands of throwaway accounts from
/// growing the map inside the five-minute window. A chat past the cap simply
/// cannot enrol in this run — the owner's chat is among the first few.
pub const MAX_TRACKED_CHATS: usize = 64;

/// Bytes of a generated pairing code (8 symbols × 5 bits = 40 bits).
pub const PAIRING_CODE_LEN: usize = 8;

/// Lifetime of the in-memory handshake, in seconds (5 minutes). The loop's own
/// deadline is the only place this is enforced; nothing durable stores it.
pub const PAIRING_TTL_SECS: i64 = 300;

/// Unambiguous alphabet: no `I`, `O`, `0` or `1`, so a code read off a terminal
/// cannot be mistyped into a different valid code. 32 symbols, and 256 is an
/// exact multiple of 32, so `byte & 0x1f` is uniform.
const PAIRING_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Long-poll window requested from `getUpdates` (seconds). Always smaller than
/// the HTTP client timeout.
pub const POLL_LONG_TIMEOUT_SECS: u64 = 25;

/// Pause after an empty poll so a misbehaving server cannot make the CLI spin.
const IDLE_SLEEP: std::time::Duration = std::time::Duration::from_secs(1);

/// Text sent to the owner's chat after a successful enrolment. Fixed: it
/// carries no code and no token.
pub const ACK_TEXT: &str =
    "csq: owner enrolled. Run `csq telegram on` on the host to enable the bridge.";

/// A one-time pairing challenge held only in process memory.
///
/// Both the code and its digest are `Zeroizing`, so dropping the challenge
/// wipes them; the CSPRNG bytes are wiped in `generate_pairing_code`.
pub struct PairingChallenge {
    code: Zeroizing<String>,
    code_sha256: Zeroizing<[u8; 32]>,
    created_at: i64,
    expires_at: i64,
}

impl PairingChallenge {
    /// Mints a code and its hash. Both are held in zeroizing buffers.
    pub fn generate(now: i64) -> Result<Self, EnrolError> {
        let code = generate_pairing_code()?;
        let digest = Sha256::digest(code.as_bytes());
        let mut code_sha256 = Zeroizing::new([0u8; 32]);
        code_sha256
            .as_mut_slice()
            .copy_from_slice(digest.as_slice());
        Ok(Self {
            code: Zeroizing::new(code),
            code_sha256,
            created_at: now,
            expires_at: now.saturating_add(PAIRING_TTL_SECS),
        })
    }

    /// The plaintext code, for the owner's terminal only. Callers MUST NOT log
    /// it, write it to a file or include it in an error.
    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    /// Constant-time comparison of `candidate` against the stored hash.
    pub fn matches(&self, candidate: &str) -> bool {
        let digest = Sha256::digest(candidate.as_bytes());
        bool::from(self.code_sha256.as_slice().ct_eq(digest.as_slice()))
    }

    /// Whether the challenge has expired at `now` (UNIX seconds).
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// UNIX seconds when the challenge was minted.
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// UNIX seconds after which the challenge MUST be refused.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Mints a code from the OS CSPRNG. Never written anywhere.
///
/// The CSPRNG bytes fully determine the code, so they are wiped after the code
/// is derived (`zeroize`), leaving no stack copy behind.
fn generate_pairing_code() -> Result<String, EnrolError> {
    let mut bytes = [0u8; PAIRING_CODE_LEN];
    getrandom::getrandom(&mut bytes).map_err(|_| EnrolError::EntropyUnavailable)?;
    let code: String = bytes
        .iter()
        .map(|b| PAIRING_ALPHABET[usize::from(b & 0x1f)] as char)
        .collect();
    bytes.zeroize();
    Ok(code)
}

/// Why enrolment did not complete.
///
/// Fixed text only: no token, no code, no URL, no upstream body.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum EnrolError {
    /// The bridge is already enabled; re-pairing would race the daemon's poll.
    #[error("the bridge is enabled; run `csq telegram off` before pairing a new owner")]
    AlreadyEnabled,
    /// Another terminal enabled the bridge while this one was pairing.
    #[error("the bridge was enabled from another terminal while pairing")]
    EnabledMidPairing,
    /// The five-minute window closed before the owner's code arrived.
    #[error("the pairing window expired before the owner's code arrived")]
    Expired,
    /// The OS CSPRNG refused to mint a code.
    #[error("the secure random source is unavailable")]
    EntropyUnavailable,
    /// Telegram is unreachable.
    #[error("telegram is unreachable")]
    Transport,
    /// The bot token was rejected.
    #[error("telegram rejected the bot token")]
    Unauthorized,
    /// Another poller holds this bot token.
    #[error("another poller is already using this bot token")]
    Conflict,
    /// Telegram rate-limited the poll.
    #[error("telegram rate-limited the pairing poll")]
    RateLimited,
    /// Any other non-success HTTP status.
    #[error("telegram returned HTTP {0}")]
    HttpStatus(u16),
    /// The response was not the expected JSON shape.
    #[error("telegram returned an unreadable response")]
    Malformed,
    /// Bridge state could not be read or written.
    #[error("bridge state could not be read or written")]
    State,
}

impl EnrolError {
    /// Fixed-vocabulary tag for structured logging.
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            EnrolError::AlreadyEnabled => "bridge_enrol_already_enabled",
            EnrolError::EnabledMidPairing => "bridge_enrol_enabled_mid_pairing",
            EnrolError::Expired => "bridge_enrol_expired",
            EnrolError::EntropyUnavailable => "bridge_enrol_entropy_unavailable",
            EnrolError::Transport => "bridge_enrol_transport",
            EnrolError::Unauthorized => "bridge_enrol_unauthorized",
            EnrolError::Conflict => "bridge_enrol_conflict",
            EnrolError::RateLimited => "bridge_enrol_rate_limited",
            EnrolError::HttpStatus(_) => "bridge_enrol_http_status",
            EnrolError::Malformed => "bridge_enrol_malformed",
            EnrolError::State => "bridge_enrol_state",
        }
    }
}

impl From<TelegramApiError> for EnrolError {
    fn from(error: TelegramApiError) -> Self {
        match error {
            TelegramApiError::Transport => EnrolError::Transport,
            TelegramApiError::Unauthorized => EnrolError::Unauthorized,
            TelegramApiError::Conflict => EnrolError::Conflict,
            TelegramApiError::RateLimited => EnrolError::RateLimited,
            TelegramApiError::HttpStatus(code) => EnrolError::HttpStatus(code),
            TelegramApiError::Malformed => EnrolError::Malformed,
        }
    }
}

impl From<BridgeConfigError> for EnrolError {
    fn from(_: BridgeConfigError) -> Self {
        EnrolError::State
    }
}

/// Durable bridge state the enrolment touches.
///
/// A trait so the crash tests can fail a specific durable step and prove the
/// order (cursor before pin) rather than a timing window.
pub trait EnrolStore {
    /// The owner config, or `None` when it does not exist yet.
    fn load_config(&self, base_dir: &Path) -> Result<Option<BridgeConfig>, EnrolError>;
    /// Writes the owner config atomically.
    fn save_config(&self, config: &BridgeConfig, base_dir: &Path) -> Result<(), EnrolError>;
    /// The shared poll cursor.
    fn load_cursor(&self, base_dir: &Path) -> Result<u64, EnrolError>;
    /// Writes the shared poll cursor atomically.
    fn save_cursor(&self, cursor: u64, base_dir: &Path) -> Result<(), EnrolError>;
}

/// The production store: the config module's atomic 0600 writers.
pub struct FsStore;

impl EnrolStore for FsStore {
    fn load_config(&self, base_dir: &Path) -> Result<Option<BridgeConfig>, EnrolError> {
        Ok(config::load(base_dir)?)
    }

    fn save_config(&self, config: &BridgeConfig, base_dir: &Path) -> Result<(), EnrolError> {
        Ok(config::save(config, base_dir)?)
    }

    fn load_cursor(&self, base_dir: &Path) -> Result<u64, EnrolError> {
        Ok(config::load_cursor(base_dir)?.high_water_update_id)
    }

    fn save_cursor(&self, cursor: u64, base_dir: &Path) -> Result<(), EnrolError> {
        Ok(config::save_cursor(
            BridgeCursor {
                high_water_update_id: cursor,
            },
            base_dir,
        )?)
    }
}

/// The outcome of one enrolment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enrolled {
    /// Pinned Telegram user id.
    pub owner_user_id: i64,
    /// Pinned private-chat id.
    pub owner_chat_id: i64,
    /// Highest update id seen, persisted before the pin.
    pub cursor: u64,
    /// Whether the acknowledgement message reached Telegram.
    pub ack_delivered: bool,
}

enum Verdict {
    Accept { from_id: i64, chat_id: i64 },
    Mismatch,
    Ignore,
}

/// Judges one update against the challenge.
///
/// `Ignore` covers refusals that must NOT burn the owner's attempts (group
/// chats, forwards, bots). `Mismatch` covers a private human text that does not
/// carry the code — including a correct code outside the freshness window,
/// which is a replay and is treated as a wrong attempt.
fn judge(update: &UpdateEnvelope, challenge: &PairingChallenge, now: i64) -> Verdict {
    if update.is_edited {
        return Verdict::Ignore;
    }
    let Some(message) = update.message.as_ref() else {
        return Verdict::Ignore;
    };
    if message.is_forwarded
        || message.is_bot
        || message.via_bot
        || message.sender_chat
        || message.chat_type != "private"
    {
        return Verdict::Ignore;
    }
    // The daemon's validator requires `chat_id == from_id` for a private chat.
    // Pinning a pair it will refuse would leave an "enrolled" bridge that never
    // accepts a message, so refuse it here too.
    if message.chat_id != message.from_id {
        return Verdict::Ignore;
    }
    // A malformed update can omit `from`/`chat` entirely. An `Enrolled` with a
    // non-positive id would fail `is_pinned()`, leaving a bridge that can never
    // run, so refuse unusable ids here (the equality check above makes one test
    // sufficient for both).
    if message.from_id <= 0 {
        return Verdict::Ignore;
    }
    let Some(text) = message.text.as_deref() else {
        return Verdict::Ignore;
    };
    if !challenge.matches(text) {
        return Verdict::Mismatch;
    }
    // A correct code outside the window is a replay: never accepted, and
    // counted so it burns an attempt.
    if message.date < challenge.created_at().saturating_sub(FUTURE_SKEW_SECS)
        || message.date > now.saturating_add(FUTURE_SKEW_SECS)
    {
        return Verdict::Mismatch;
    }
    Verdict::Accept {
        from_id: message.from_id,
        chat_id: message.chat_id,
    }
}

/// Runs the pairing handshake until the owner is pinned or the window closes.
///
/// Blocks for at most the challenge lifetime. `now` is injected so the tests
/// are deterministic and the loop never reads the wall clock directly.
pub fn enrol_owner(
    base_dir: &Path,
    challenge: &PairingChallenge,
    transport: &dyn TelegramTransport,
    store: &dyn EnrolStore,
    now: &dyn Fn() -> i64,
) -> Result<Enrolled, EnrolError> {
    let mut config = store.load_config(base_dir)?.unwrap_or_else(unpinned_config);
    if config.enabled {
        return Err(EnrolError::AlreadyEnabled);
    }
    let mut cursor = store.load_cursor(base_dir)?;
    // Wrong guesses are counted PER CHAT so a stranger's DMs cannot abort the
    // owner's pairing; the map is capped so a flood of throwaway accounts
    // cannot grow it (MAX_TRACKED_CHATS is a memory bound, not a security one).
    let mut mismatches: std::collections::BTreeMap<i64, u32> = std::collections::BTreeMap::new();

    loop {
        let current = now();
        if challenge.is_expired(current) {
            return Err(EnrolError::Expired);
        }
        let remaining = challenge.expires_at().saturating_sub(current).max(1) as u64;
        let updates = transport.get_updates(
            cursor.saturating_add(1),
            remaining.min(POLL_LONG_TIMEOUT_SECS),
        )?;
        if updates.is_empty() {
            std::thread::sleep(IDLE_SLEEP);
            continue;
        }

        let mut max_seen = cursor;
        let mut accepted: Option<(i64, i64)> = None;
        for update in &updates {
            // The offset should have excluded anything at or below the cursor;
            // do not rely on the server for a security boundary.
            if update.update_id <= cursor {
                continue;
            }
            max_seen = max_seen.max(update.update_id);
            if accepted.is_some() {
                continue;
            }
            match judge(update, challenge, now()) {
                Verdict::Accept { from_id, chat_id } => {
                    // A burned chat cannot come back, even with the code.
                    if mismatches.get(&chat_id).copied().unwrap_or(0) >= MAX_CODE_MISMATCHES {
                        continue;
                    }
                    // A chat past the tracking cap cannot enrol in this run.
                    if !mismatches.contains_key(&chat_id) && mismatches.len() >= MAX_TRACKED_CHATS {
                        continue;
                    }
                    accepted = Some((from_id, chat_id));
                }
                Verdict::Mismatch => {
                    if let Some(chat_id) = update.message.as_ref().map(|message| message.chat_id) {
                        if mismatches.contains_key(&chat_id) || mismatches.len() < MAX_TRACKED_CHATS
                        {
                            let entry = mismatches.entry(chat_id).or_insert(0);
                            *entry = entry.saturating_add(1);
                        }
                    }
                }
                Verdict::Ignore => {}
            }
        }

        // The cursor is durable BEFORE the pin: a crash between the two leaves
        // an unpinned bridge, never a pinned one that would route the pairing
        // traffic into a session.
        store.save_cursor(max_seen, base_dir)?;
        cursor = max_seen;

        if let Some((owner_user_id, owner_chat_id)) = accepted {
            // Another terminal may have enabled the bridge while we waited;
            // pinning now would start the daemon's poll mid-handshake.
            let latest = store.load_config(base_dir)?.unwrap_or_else(unpinned_config);
            if latest.enabled {
                return Err(EnrolError::EnabledMidPairing);
            }
            config.owner_user_id = owner_user_id;
            config.owner_chat_id = owner_chat_id;
            store.save_config(&config, base_dir)?;
            let ack_delivered = transport.send_message(owner_chat_id, ACK_TEXT).is_ok();
            return Ok(Enrolled {
                owner_user_id,
                owner_chat_id,
                cursor,
                ack_delivered,
            });
        }
    }
}

fn unpinned_config() -> BridgeConfig {
    BridgeConfig {
        enabled: false,
        owner_user_id: 0,
        owner_chat_id: 0,
        allow_classes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::telegram_api::{IncomingMessage, TelegramTransport};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    const START: i64 = 1_700_000_000;

    struct Clock(Cell<i64>);
    impl Clock {
        fn new(now: i64) -> Self {
            Self(Cell::new(now))
        }
        fn now(&self) -> i64 {
            self.0.get()
        }
    }

    struct ScriptedTransport {
        batches: RefCell<VecDeque<Vec<UpdateEnvelope>>>,
        sent: RefCell<Vec<(i64, String)>>,
    }
    impl ScriptedTransport {
        fn new(batches: Vec<Vec<UpdateEnvelope>>) -> Self {
            Self {
                batches: RefCell::new(batches.into()),
                sent: RefCell::new(Vec::new()),
            }
        }
    }
    impl TelegramTransport for ScriptedTransport {
        fn get_updates(
            &self,
            _offset: u64,
            _timeout_secs: u64,
        ) -> Result<Vec<UpdateEnvelope>, TelegramApiError> {
            // Exhaustion is an error, not an empty batch: a guard removal that
            // lets the loop run past its script fails the test instead of
            // spinning until the wall-clock deadline.
            self.batches
                .borrow_mut()
                .pop_front()
                .ok_or(TelegramApiError::Transport)
        }
        fn send_message(&self, chat_id: i64, text: &str) -> Result<(), TelegramApiError> {
            self.sent.borrow_mut().push((chat_id, text.to_owned()));
            Ok(())
        }
    }

    fn message(from: i64, chat_id: i64, chat_type: &str, text: &str, date: i64) -> IncomingMessage {
        IncomingMessage {
            from_id: from,
            is_bot: false,
            chat_id,
            chat_type: chat_type.to_owned(),
            date,
            text: Some(text.to_owned()),
            is_forwarded: false,
            via_bot: false,
            sender_chat: false,
        }
    }

    fn update(update_id: u64, message: IncomingMessage) -> UpdateEnvelope {
        UpdateEnvelope {
            update_id,
            is_edited: false,
            message: Some(message),
        }
    }

    struct Fixture {
        dir: tempfile::TempDir,
        clock: Clock,
        challenge: PairingChallenge,
    }

    fn fixture() -> Fixture {
        Fixture {
            dir: tempfile::tempdir().expect("tempdir"),
            clock: Clock::new(START),
            challenge: PairingChallenge::generate(START).expect("challenge"),
        }
    }

    fn run(fixture: &Fixture, transport: &dyn TelegramTransport) -> Result<Enrolled, EnrolError> {
        let now = || fixture.clock.now();
        enrol_owner(
            fixture.dir.path(),
            &fixture.challenge,
            transport,
            &FsStore,
            &now,
        )
    }

    // (i) A stranger who does not know the code cannot pin the bridge, and the
    // owner's later message still wins.
    #[test]
    fn a_stranger_racing_the_code_is_refused() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![update(10, message(99, 99, "private", "HELLO", START))],
            vec![update(11, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("owner enrols");
        assert_eq!(enrolled.owner_user_id, 42);
        assert_eq!(enrolled.owner_chat_id, 42);
        assert_eq!(transport.sent.borrow().len(), 1, "one acknowledgement");
    }

    // Wrong guesses burn PER CHAT, so a stranger cannot abort the owner's
    // pairing: three wrong texts from chat 99, then the owner's OWN two wrong
    // guesses, then the CORRECT code from chat 42 still succeeds. The owner's
    // budget is its own — the stranger's three do not consume any of it.
    #[test]
    fn a_stranger_cannot_burn_the_owners_chat() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![
                update(10, message(99, 99, "private", "AAAA", START)),
                update(11, message(99, 99, "private", "BBBB", START)),
                update(12, message(99, 99, "private", "CCCC", START)),
            ],
            vec![
                update(13, message(42, 42, "private", "DDDD", START)),
                update(14, message(42, 42, "private", "EEEE", START)),
            ],
            vec![update(15, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("the owner still enrols");
        assert_eq!(enrolled.owner_user_id, 42);
        assert_eq!(enrolled.owner_chat_id, 42);
        assert_eq!(transport.sent.borrow().len(), 1, "one acknowledgement");
    }

    // A chat that spent its three attempts is burned for the rest of the run:
    // its later message carrying the CORRECT code must not pin it. The
    // handshake keeps running for the owner, so this also proves the burn no
    // longer aborts the whole pairing.
    #[test]
    fn a_burned_chat_cannot_come_back_with_the_code() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![
                update(10, message(99, 99, "private", "AAAA", START)),
                update(11, message(99, 99, "private", "BBBB", START)),
                update(12, message(99, 99, "private", "CCCC", START)),
            ],
            vec![update(13, message(99, 99, "private", &code, START))],
            vec![update(14, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("the owner enrols");
        assert_eq!(
            enrolled.owner_user_id, 42,
            "the burned chat must not pin, even with the code"
        );
        assert_eq!(enrolled.owner_chat_id, 42);
    }

    // The tracking map is capped: once MAX_TRACKED_CHATS distinct chats are
    // tracked, a NEW chat cannot enrol in this run, even with the code. The
    // transport is exhausted because nothing was accepted — a guard removal
    // would accept chat 42 and return Enrolled instead.
    #[test]
    fn a_chat_past_the_tracking_cap_cannot_enrol() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let mut flood = Vec::new();
        for index in 0..MAX_TRACKED_CHATS {
            let id = 1_000 + index as i64;
            flood.push(update(
                10 + index as u64,
                message(id, id, "private", "AAAA", START),
            ));
        }
        let transport = ScriptedTransport::new(vec![
            flood,
            vec![update(500, message(42, 42, "private", &code, START))],
        ]);
        assert_eq!(
            run(&fixture, &transport).expect_err("the map is full"),
            EnrolError::Transport,
            "a chat past the tracking cap must not enrol"
        );
        assert!(config::load(fixture.dir.path()).expect("load").is_none());
        assert!(transport.sent.borrow().is_empty());
    }

    // Non-positive ids are malformed or group-chat shaped; pinning 0 would
    // leave an "enrolled" bridge that can never pass `is_pinned()`.
    #[test]
    fn a_non_positive_sender_id_is_refused() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![update(10, message(0, 0, "private", &code, START))],
            vec![update(11, message(-5, -5, "private", &code, START))],
            vec![update(12, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("the real owner enrols");
        assert_eq!(enrolled.owner_user_id, 42);
        assert_eq!(enrolled.owner_chat_id, 42);
    }

    // (ii) An old message carrying the code is a replay, not an enrolment.
    #[test]
    fn an_old_dated_code_is_refused() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![update(10, message(99, 99, "private", &code, START - 600))],
            vec![update(11, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("owner enrols");
        assert_eq!(
            enrolled.owner_user_id, 42,
            "the stale message must not pin its sender"
        );
    }

    // (ii) A code minted by a PREVIOUS pairing run has no standing: the
    // challenge is per-process memory, so no stored value can be replayed. This
    // test pins the property so nobody reintroduces a durable challenge.
    #[test]
    fn a_code_from_a_previous_run_cannot_enrol() {
        let first = PairingChallenge::generate(START).expect("first challenge");
        let old_code = first.code().to_owned();
        let second = PairingChallenge::generate(START).expect("second challenge");
        assert_ne!(first.code(), second.code(), "each run mints a fresh code");
        assert!(
            !second.matches(&old_code),
            "a previous run's code must not match a new challenge"
        );

        let fixture = fixture();
        let current = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![update(10, message(99, 99, "private", &old_code, START))],
            vec![update(11, message(42, 42, "private", &current, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("owner enrols with the current code");
        assert_eq!(enrolled.owner_user_id, 42);
    }

    /// The handshake must leave nothing on disk: an enrolment that expires
    /// before a message creates no file at all, so there is no stored code or
    /// expiry for anyone to read later.
    #[test]
    fn the_challenge_never_touches_disk() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        fixture.clock.0.set(START + PAIRING_TTL_SECS + 1);
        let transport = ScriptedTransport::new(vec![]);
        assert_eq!(
            run(&fixture, &transport).expect_err("expired"),
            EnrolError::Expired
        );
        let entries: Vec<_> = std::fs::read_dir(fixture.dir.path())
            .expect("read dir")
            .collect();
        assert!(
            entries.is_empty(),
            "the handshake must leave no artifact on disk"
        );
        assert!(
            !fixture
                .dir
                .path()
                .join("telegram-bridge-pairing.json")
                .exists(),
            "no legacy pairing file may be created"
        );
        // The code never reached any file this process could have written.
        let mut found = Vec::new();
        collect_files(fixture.dir.path(), &mut found);
        for path in found {
            let bytes = std::fs::read(&path).expect("read file");
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&code),
                "the pairing code must never be stored: {path:?}"
            );
        }
    }

    fn collect_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                collect_files(&path, out);
            } else {
                out.push(path);
            }
        }
    }

    // (ii) An update at or below the shared cursor is a replay even if the
    // server sends it again.
    #[test]
    fn a_replayed_update_below_the_cursor_is_refused() {
        let fixture = fixture();
        config::save_cursor(
            BridgeCursor {
                high_water_update_id: 20,
            },
            fixture.dir.path(),
        )
        .expect("seed cursor");
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![update(15, message(99, 99, "private", &code, START))],
            vec![update(21, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("owner enrols");
        assert_eq!(enrolled.owner_user_id, 42);
        assert_eq!(enrolled.cursor, 21);
    }

    // (iii) A group message carrying the code is not the owner's DM.
    //
    // The fixture deliberately uses `chat_id == from_id`: a real group id is
    // negative, and that would make the separate chat/sender check refuse the
    // message too, hiding whether the chat-TYPE guard is what refuses it.
    #[test]
    fn a_group_message_with_the_code_is_refused() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![update(10, message(99, 99, "group", &code, START))],
            vec![update(11, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("owner enrols");
        assert_eq!(enrolled.owner_user_id, 42);
        assert_eq!(enrolled.owner_chat_id, 42);
    }

    // (iv) A forward carrying the code is not the owner speaking.
    #[test]
    fn a_forwarded_message_with_the_code_is_refused() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let mut forwarded = message(99, 99, "private", &code, START);
        forwarded.is_forwarded = true;
        let transport = ScriptedTransport::new(vec![
            vec![update(10, forwarded)],
            vec![update(11, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("owner enrols");
        assert_eq!(enrolled.owner_user_id, 42);
    }

    // A private chat whose id differs from the sender's is not a pair the
    // daemon's validator will ever accept; pinning it would be a dead bridge.
    #[test]
    fn a_private_chat_whose_id_differs_from_the_sender_is_refused() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![
            vec![update(10, message(99, 77, "private", &code, START))],
            vec![update(11, message(42, 42, "private", &code, START))],
        ]);
        let enrolled = run(&fixture, &transport).expect("owner enrols");
        assert_eq!(enrolled.owner_user_id, 42);
        assert_eq!(enrolled.owner_chat_id, 42);
    }

    // (v) The cursor hand-off leaves the daemon nothing to route: every update
    // the pairing poller saw is at or below the persisted cursor, which the
    // validator treats as a replay.
    #[test]
    fn the_cursor_handoff_leaves_the_daemon_nothing_to_route() {
        let fixture = fixture();
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![vec![
            update(10, message(99, 99, "private", "before", START)),
            update(11, message(42, 42, "private", &code, START)),
            update(12, message(99, 99, "private", "after", START)),
        ]]);
        let enrolled = run(&fixture, &transport).expect("owner enrols");
        assert_eq!(enrolled.cursor, 12);
        let persisted = config::load_cursor(fixture.dir.path()).expect("cursor");
        assert_eq!(persisted.high_water_update_id, 12);
        for seen in 10..=12 {
            assert!(
                seen <= persisted.high_water_update_id,
                "update {seen} would be routable: {persisted:?}"
            );
        }
    }

    // (vi) A crash at the cursor step (the durable step before the pin) leaves
    // the previous config intact and the bridge unpinned.
    #[test]
    fn a_crash_mid_pin_leaves_the_previous_config_valid() {
        let fixture = fixture();
        let old = unpinned_config();
        config::save(&old, fixture.dir.path()).expect("seed old config");
        let code = fixture.challenge.code().to_owned();
        let transport = ScriptedTransport::new(vec![vec![update(
            10,
            message(42, 42, "private", &code, START),
        )]]);
        struct CursorFails;
        impl EnrolStore for CursorFails {
            fn load_config(&self, base_dir: &Path) -> Result<Option<BridgeConfig>, EnrolError> {
                FsStore.load_config(base_dir)
            }
            fn save_config(
                &self,
                config: &BridgeConfig,
                base_dir: &Path,
            ) -> Result<(), EnrolError> {
                FsStore.save_config(config, base_dir)
            }
            fn load_cursor(&self, base_dir: &Path) -> Result<u64, EnrolError> {
                FsStore.load_cursor(base_dir)
            }
            fn save_cursor(&self, _cursor: u64, _base_dir: &Path) -> Result<(), EnrolError> {
                Err(EnrolError::State)
            }
        }
        let now = || fixture.clock.now();
        let error = enrol_owner(
            fixture.dir.path(),
            &fixture.challenge,
            &transport,
            &CursorFails,
            &now,
        )
        .expect_err("the failing durable step aborts the pin");
        assert_eq!(error, EnrolError::State);
        let loaded = config::load(fixture.dir.path())
            .expect("the config must still parse")
            .expect("the config must still exist");
        assert_eq!(loaded, old, "no half-pinned state may survive a crash");
        assert!(!loaded.is_pinned());
    }

    #[test]
    fn an_enabled_bridge_refuses_to_pair() {
        let fixture = fixture();
        let transport = ScriptedTransport::new(vec![]);
        config::save(
            &BridgeConfig {
                enabled: true,
                ..unpinned_config()
            },
            fixture.dir.path(),
        )
        .expect("seed enabled config");
        assert_eq!(
            run(&fixture, &transport).expect_err("enabled refuses"),
            EnrolError::AlreadyEnabled
        );
    }

    #[test]
    fn an_expired_challenge_pairs_nothing() {
        let fixture = fixture();
        fixture.clock.0.set(START + PAIRING_TTL_SECS + 1);
        let transport = ScriptedTransport::new(vec![]);
        assert_eq!(
            run(&fixture, &transport).expect_err("expired"),
            EnrolError::Expired
        );
        assert!(config::load(fixture.dir.path()).expect("load").is_none());
    }

    #[test]
    fn the_challenge_bounds_and_comparison_are_wired() {
        let challenge = PairingChallenge::generate(START).expect("challenge");
        let code = challenge.code().to_owned();
        assert!(challenge.matches(&code));
        assert!(!challenge.matches(&code.to_lowercase()));
        assert!(!challenge.matches(""));
        assert!(!challenge.is_expired(START));
        assert!(challenge.is_expired(START + PAIRING_TTL_SECS));
        assert_eq!(
            challenge.expires_at(),
            START + PAIRING_TTL_SECS,
            "the TTL is wired, not decorative"
        );
    }
}
