//! Shared relay types and traits (spec 34 §34.2.5, §34.5.1; spec 34a §34a.1).
//!
//! # Fail-closed by construction
//!
//! Three shards (S1b the loop and classifier, S2b the chord filter, S3b the
//! state machine) are built against this contract by different authors, so the
//! contract makes the unsafe shapes unrepresentable instead of documenting them:
//!
//! - A `\r` needs a `Transaction` (`state.rs`), the single-use value that owns
//!   one inject from the moment its queue entry leaves the queue to its single
//!   terminal outcome. Its fields, the queue, the gate flags and the writer lock
//!   are private to that one module, so nothing else in the crate can build a
//!   transaction, reach a payload or write a `\r`: the compiler refuses it. The
//!   transaction owns the payload bytes and writes the bracketed-paste framing
//!   itself (a payload may never carry ESC or a control byte), re-checks the
//!   Enter rule (spec 34a §34a.1) at every step, records the `\r` with the gate
//!   BEFORE writing exactly one, and records exactly one outcome even when it is
//!   dropped. The `\r` kind is derived from the request's entry kind, never
//!   chosen by the writer. `EnterGate` is relay-private and sealed, and a
//!   conformance scan allows one production implementation, so no stub can
//!   stand in for the machine.
//! - A [`ClassifiedKey`] is constructed only by `route` in this file (from a
//!   [`Run`] the classifier built). A `Run` is built only by the classifier
//!   (`inparse.rs`), the writer lock's constructor is called only by the writer
//!   (`writer.rs`) and the state machine's only by the loop (`loop.rs`).
//!   `pub(in crate::relay)`
//!   admits the other `relay` modules too (authz, hooks), so those three rest on
//!   a conformance test (`construction_sites_are_limited_to_their_owners`) that
//!   fails when any other `relay` file names the constructors, in any call,
//!   path, alias or function-pointer form it can see. The part that needs no
//!   test is the transaction itself, whose private fields make it unbuildable
//!   outside `state.rs`.
//! - Every transition of the §34a.1 table is its own method. No method serves
//!   two events, so a `turn_start` hook cannot clear `perm_pending` by being
//!   expressed as an Enter key (spec 34 §34.10).
//! - [`ChordFilter`] returns a typed [`ChordEvent`] plus a per-run forward
//!   mask, never raw bytes, so no component re-parses dropped input.
//!
//! # What is safe to log
//!
//! Flags, counters, identity pairs and closed codes derive `Debug`. [`Run`] and
//! [`ChallengeAttempt`] hold user keystrokes and the operator challenge code,
//! so their `Debug` is hand-written and prints lengths only (spec 34 §34.3.1:
//! payload bytes appear in no log).
//!
//! # Error codes
//!
//! Refusal codes are `SdkErrorCode` values (spec 34 §34.5.1), added additively
//! in `csq-sdk` (`SdkErrorCode` is `#[non_exhaustive]`). `RateLimited` is the
//! pre-existing code reused for `rate_limited`; a lapsed control request is the
//! new `RequestExpired`, distinct from the directive/lease `Expired`.

use crate::all_enum::declare_all_enum;
use crate::sdk::SdkErrorCode;
use std::fmt;

/// Result of an inject attempt (spec 34 §34.5.1, schema `csq.session_inject.v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum InjectOutcome {
    /// The kernel accepted all bytes; NOT that the CLI read or acted on them.
    DeliveredToPty,
    /// Accepted for later delivery; the entry carries an id and an expiry.
    QueuedDeferred,
    /// The target already has a pending request, or the overlay is shown.
    RequestPending,
    /// The target session is not running under a relay.
    NotUnderRelay,
    /// Refused with an `error.code`.
    Refused(SdkErrorCode),
    /// A write began and errored, or the chain or clock could not be read.
    Undetermined,
}

impl InjectOutcome {
    /// The `outcome` string on the wire (spec 34 §34.5.1).
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::DeliveredToPty => "delivered_to_pty",
            Self::QueuedDeferred => "queued_deferred",
            Self::RequestPending => "request_pending",
            Self::NotUnderRelay => "not_under_relay",
            Self::Refused(_) => "refused",
            Self::Undetermined => "undetermined",
        }
    }

    /// The refusal code, present only for [`Self::Refused`].
    #[must_use]
    pub const fn code(self) -> Option<SdkErrorCode> {
        match self {
            Self::Refused(c) => Some(c),
            _ => None,
        }
    }
}

/// Turn phase of a relayed session (spec 34a §34a.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Busy,
    TurnEnded,
    Idle,
}

impl Phase {
    /// The phase at launch: Busy (spec 34a §34a.1 row "(launch) start"). There is
    /// no separate launching phase; Idle is reached only through `turn_end`, a
    /// redraw and the quiet window, never by the CLI merely being ready.
    #[must_use]
    pub const fn at_launch() -> Self {
        Self::Busy
    }
}

/// How a csq-written slash command signals the session is back at its prompt
/// (spec 34a §34a.1 "Slash completion"). A cell measured `none` is refused at
/// enqueue and never reaches the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleReturn {
    /// The CLI fires `turn_end`/`turn_start` hooks.
    Hook,
    /// A redraw plus `QUIET_MS` of silence.
    Quiet,
}

/// What a csq-written `\r` ended (spec 34a §34a.1 rows "csq-written `\r`").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsqEnter {
    /// A text submit or wake notice: a turn starts.
    Text,
    /// A slash command with its measured `idle_return`.
    Slash(IdleReturn),
}

impl CsqEnter {
    /// The phase the gate enters. A `Quiet` slash enters TurnEnded with
    /// `redraw_seen = false`, so the ordinary redraw-plus-quiet tick returns it
    /// to Idle; without this a `/clear` that fires no hook would stay Busy
    /// forever. Every other case is Busy until its hook fires.
    #[must_use]
    pub const fn phase_after(self) -> Phase {
        match self {
            Self::Slash(IdleReturn::Quiet) => Phase::TurnEnded,
            Self::Text | Self::Slash(IdleReturn::Hook) => Phase::Busy,
        }
    }
}

declare_all_enum! {
/// Ground-state key events (spec 34 §34.2.5). The key's value is never kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable byte.
    Printable,
    /// `\r` not preceded by ESC or `\`: the one clearing, submitting Enter.
    Enter,
    /// `ESC` + `\r` (Meta-Enter): inserts a newline, clears nothing.
    MetaEnter,
    /// `\r` directly after a `\` key (newline continuation): clears nothing.
    ContinuationEnter,
    Backspace,
    /// `^C`.
    CtrlC,
    /// `^U`.
    CtrlU,
    /// A lone ESC after `ESC_TIMEOUT_MS`.
    Escape,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    /// Any other ground-state key (Tab, Shift-Tab, `^D`/`^W`/`^K`/`^Y`, Home,
    /// End, Delete, F-keys, Alt-x). It edits the draft, so it sets
    /// `line_dirty`, but it is not in the dialog-answering set.
    Other,
}
}

impl Key {
    /// Whether this Key can answer a modal dialog and so clear `perm_pending`
    /// (spec 34 §34.2.5; spec 34a §34a.1: printable, `\r`, lone ESC, `^C`,
    /// arrows). Meta-Enter and continuation-Enter insert a newline and answer
    /// nothing.
    #[must_use]
    pub const fn answers_dialog(self) -> bool {
        matches!(
            self,
            Self::Printable
                | Self::Enter
                | Self::Escape
                | Self::CtrlC
                | Self::ArrowUp
                | Self::ArrowDown
                | Self::ArrowLeft
                | Self::ArrowRight
        )
    }

    /// Whether this Key clears `line_dirty` (spec 34a §34a.1: a clearing `\r`,
    /// `^C`, `^U`).
    #[must_use]
    pub const fn clears_line_dirty(self) -> bool {
        matches!(self, Self::Enter | Self::CtrlC | Self::CtrlU)
    }

    /// Whether this Key sets `line_dirty` (spec 34a §34a.1: "any Key other than
    /// a clearing `\r`, `^C`, `^U`").
    #[must_use]
    pub const fn sets_line_dirty(self) -> bool {
        !self.clears_line_dirty()
    }

    /// Whether this Key enters Busy (spec 34a §34a.1: only the clearing `\r`).
    #[must_use]
    pub const fn is_clearing_enter(self) -> bool {
        matches!(self, Self::Enter)
    }
}

/// A [`Key`] produced by the outer-input classifier (spec 34 §34.2.5).
///
/// The constructor is visible only inside `relay`, so the state machine cannot
/// be fed a key by a hook handler or a control thread (F1, D12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedKey(Key);

impl ClassifiedKey {
    /// Called by `route` in this file only (the classifier hands it a `Run`).
    #[cfg_attr(
        all(not(unix), not(test)),
        expect(dead_code, reason = "callers are cfg(unix); stays dead on Windows")
    )]
    #[cfg_attr(
        all(unix, not(test)),
        allow(
            dead_code,
            reason = "S1b deletes this line when it lands (01-plan.md S0 rules)"
        )
    )]
    pub(in crate::relay) const fn new(key: Key) -> Self {
        Self(key)
    }

    /// The classified key.
    #[must_use]
    pub const fn key(self) -> Key {
        self.0
    }
}

/// Class of one run of outer-input bytes (spec 34 §34.2.5); every byte is
/// classified exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputClass {
    /// Terminal-generated: forwarded, updates no state.
    Report,
    /// Inside a bracketed paste: forwarded, non-human. A `0x1D` here is paste
    /// text, never a chord (spec 34 §34.3.3).
    PasteContent,
    /// Inside an unbracketed burst the relay cannot distinguish from typing
    /// (spec 34 §34.2.5): non-human, but a DRAFT like a paste, so `route` sends
    /// it to `EnterGate::on_paste_content` and `line_dirty` is set. A read
    /// containing a `0x1D` here is dropped whole (`burst_guard`, spec 34
    /// §34.3.3).
    BurstContent,
    /// A ground-state key event: the only class that reaches the state machine.
    Key(Key),
    /// A ground-state `0x1D` (`Ctrl-]`): the chord lead (spec 34 §34.3.3),
    /// routed to the [`ChordFilter`], never to the `EnterGate`.
    ChordLead,
}

/// Process identity of a session CLI or controller: `(pid, start time)`. A pid
/// alone is recyclable, so every identity comparison uses both (spec 34 §34.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionIdentity {
    pub pid: u32,
    /// The process start time as read from the OS (same unit as
    /// `sessions::SessionInfo::started_at`).
    pub started_at: u64,
}

/// The CLI a relay hosts (spec 34 §34.4.3). Gemini, Kimi and Grok have no relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CliKind {
    Claude,
    Codex,
    /// A CLI the per-CLI table does not list: slash refused (`cli_unmeasured`).
    Unknown,
}

impl From<crate::sessions::CliKind> for CliKind {
    fn from(k: crate::sessions::CliKind) -> Self {
        match k {
            crate::sessions::CliKind::Claude => Self::Claude,
            crate::sessions::CliKind::Codex => Self::Codex,
        }
    }
}

/// Deliver one classified run to the gate (spec 34 §34.2.5, spec 34a §34a.1).
/// The match is exhaustive: a Report and a chord lead change no state; paste
/// content AND burst content are drafts (`line_dirty`); a Key is the only input
/// that reaches `on_key`. S1b calls this and never the gate's input methods
/// directly, so a class cannot be routed by omission.
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "callers are cfg(unix); stays dead on Windows")
)]
#[cfg_attr(
    all(unix, not(test)),
    allow(
        dead_code,
        reason = "S1b deletes this line when it lands (01-plan.md S0 rules)"
    )
)]
pub(in crate::relay) fn route<G: EnterGate + ?Sized>(run: &Run<'_>, gate: &mut G, now_ms: u64) {
    match run.class {
        InputClass::Report | InputClass::ChordLead => {}
        InputClass::PasteContent | InputClass::BurstContent => gate.on_paste_content(now_ms),
        InputClass::Key(k) => gate.on_key(ClassifiedKey::new(k), now_ms),
    }
}

/// `MASK_MS` (CHOSEN, 500): output this soon after a relay redraw trigger is
/// the relay's own and never the completion redraw (spec 34a §34a.1 rule 3).
pub const MASK_MS: u64 = 500;
/// `QUIET_MS` (CHOSEN, 1000): silence after a redraw before TurnEnded is Idle.
pub const QUIET_MS: u64 = 1000;

/// The TurnEnded/Idle half of the §34a.1 table: `redraw_seen`, `t_out` and the
/// redraw mask. S3b embeds it, so the quiet and masked-output rows and the quiet
/// slash reset are fixed here rather than re-derived.
#[derive(Debug)]
pub struct QuietTracker {
    phase: Phase,
    redraw_seen: bool,
    t_out: u64,
    mask_until: u64,
}

impl QuietTracker {
    #[cfg_attr(
        all(not(unix), not(test)),
        expect(dead_code, reason = "callers are cfg(unix); stays dead on Windows")
    )]
    pub(in crate::relay) const fn new(now_ms: u64) -> Self {
        Self {
            phase: Phase::at_launch(),
            redraw_seen: false,
            t_out: now_ms,
            mask_until: 0,
        }
    }

    /// Current phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Time of the last child output, masked or not (spec 34a §34a.1 quiet
    /// clause): the quiet window an Enter needs is measured from here. At
    /// launch it is the launch time.
    #[must_use]
    pub const fn last_output_ms(&self) -> u64 {
        self.t_out
    }

    /// Whether an unmasked redraw was seen since the last reset.
    #[must_use]
    pub const fn redraw_seen(&self) -> bool {
        self.redraw_seen
    }

    /// Busy by an event other than the `turn_end` path (spec 34a §34a.1:
    /// `turn_start`, a human `\r`, a child identity change): the phase is Busy
    /// and `redraw_seen` is false, so the next completion needs a fresh redraw.
    /// The redraw mask and `t_out` are untouched, so a relay echo still in flight
    /// stays masked.
    pub fn on_busy(&mut self) {
        self.phase = Phase::Busy;
        self.redraw_seen = false;
    }

    /// A draft-editing Key (spec 34a §34a.1 row "any Key"): Idle becomes
    /// TurnEnded and the quiet timer restarts at `now_ms`; `redraw_seen` is kept.
    /// Any other phase is unchanged.
    pub fn on_draft_key(&mut self, now_ms: u64) {
        if self.phase == Phase::Idle {
            self.phase = Phase::TurnEnded;
            self.t_out = now_ms;
        }
    }

    /// A relay redraw trigger (resize nudge, overlay draw or close, csq's own
    /// paste echo): output for the next `MASK_MS` is the relay's own.
    pub fn open_mask(&mut self, now_ms: u64) {
        self.mask_until = now_ms.saturating_add(MASK_MS);
    }

    /// `turn_end` hook: Busy becomes TurnEnded with `redraw_seen = false`.
    pub fn on_turn_end(&mut self) {
        if self.phase == Phase::Busy {
            self.phase = Phase::TurnEnded;
            self.redraw_seen = false;
        }
    }

    /// A csq-written `\r`: the phase `kind` names, and the `\r`'s own echo is
    /// masked so it can never be the completion redraw. A `Quiet` slash also
    /// clears `redraw_seen`: the redraw that completes it must come AFTER the
    /// command, not from before it.
    pub fn on_csq_enter(&mut self, kind: CsqEnter, now_ms: u64) {
        self.phase = kind.phase_after();
        if kind == CsqEnter::Slash(IdleReturn::Quiet) {
            self.redraw_seen = false;
        }
        self.open_mask(now_ms);
        self.t_out = now_ms;
    }

    /// Child output (spec 34a §34a.1). Busy: nothing. TurnEnded unmasked:
    /// `redraw_seen`, `t_out`. Idle unmasked: TurnEnded, `t_out`. Masked, in
    /// either: `t_out` only, the phase is unchanged.
    pub fn on_child_output(&mut self, now_ms: u64) {
        let masked = now_ms < self.mask_until;
        match (self.phase, masked) {
            (Phase::Busy, _) => {}
            (_, true) => self.t_out = now_ms,
            (Phase::TurnEnded, false) => {
                self.redraw_seen = true;
                self.t_out = now_ms;
            }
            (Phase::Idle, false) => {
                self.phase = Phase::TurnEnded;
                self.t_out = now_ms;
            }
        }
    }

    /// Quiet tick: TurnEnded becomes Idle after `QUIET_MS` of silence with a
    /// redraw seen.
    pub fn on_tick(&mut self, now_ms: u64) {
        if self.phase == Phase::TurnEnded
            && self.redraw_seen
            && now_ms.saturating_sub(self.t_out) >= QUIET_MS
        {
            self.phase = Phase::Idle;
        }
    }
}

pub(in crate::relay) mod sealed {
    /// Implemented only inside `crate::relay`; keeps the gate traits closed.
    pub trait Sealed {}
}

/// The input half of the §34a.1 state machine, as implemented by S3b
/// (`RelayState`) and driven by S1b's classifier through `route`.
///
/// Relay-private and sealed: only `crate::relay` can name it, and the
/// construction scan allows one production implementation (`state.rs`). The rest
/// of the machine (hooks, ticks, the Enter transaction) are inherent methods of
/// `RelayState`, so nothing outside the owning module can reach them through a
/// trait object either.
#[cfg_attr(
    not(unix),
    allow(dead_code, reason = "implemented and driven only on unix")
)]
#[cfg_attr(
    all(unix, not(test)),
    allow(
        dead_code,
        reason = "S1b drives these when it lands (01-plan.md S0 rules)"
    )
)]
pub(in crate::relay) trait EnterGate: sealed::Sealed {
    /// A classified Key (spec 34a §34a.1 rows "any Key", "`^C`/`^U`",
    /// "clearing `\r`", "answering Key"). Also counts as "a Key since the
    /// transaction began" for every open transaction.
    fn on_key(&mut self, key: ClassifiedKey, now_ms: u64);

    /// Bracketed-paste OR burst content arrived (`route` sends both): a
    /// draft, so `line_dirty = true`; not a Key, so `perm_pending` is untouched
    /// (spec 34a §34a.1 rule 2).
    fn on_paste_content(&mut self, now_ms: u64);
}

/// One run of outer-input bytes with the class the single classifier gave it
/// (spec 34 §34.2.5).
///
/// `Debug` prints the class and length only: the bytes are user keystrokes.
#[derive(Clone, Copy)]
pub struct Run<'a> {
    class: InputClass,
    bytes: &'a [u8],
}

impl<'a> Run<'a> {
    /// Called by the classifier (S1b) only.
    #[cfg_attr(
        all(not(unix), not(test)),
        expect(dead_code, reason = "callers are cfg(unix); stays dead on Windows")
    )]
    #[cfg_attr(
        all(unix, not(test)),
        allow(
            dead_code,
            reason = "S1b deletes this line when it lands (01-plan.md S0 rules)"
        )
    )]
    pub(in crate::relay) const fn new(class: InputClass, bytes: &'a [u8]) -> Self {
        Self { class, bytes }
    }

    #[must_use]
    pub const fn class(&self) -> InputClass {
        self.class
    }

    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

impl fmt::Debug for Run<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Run")
            .field("class", &self.class)
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Four operator-typed challenge characters (spec 34 §34.3.3). Compared by the
/// request owner; `Debug` never prints them.
#[derive(Clone, PartialEq, Eq)]
pub struct ChallengeAttempt([u8; 4]);

impl ChallengeAttempt {
    /// Called by the [`ChordFilter`] implementation (S2b) only.
    #[cfg_attr(
        all(not(unix), not(test)),
        expect(dead_code, reason = "callers are cfg(unix); stays dead on Windows")
    )]
    #[cfg_attr(
        all(unix, not(test)),
        allow(
            dead_code,
            reason = "S2b deletes this line when it lands (01-plan.md S0 rules)"
        )
    )]
    pub(in crate::relay) const fn new(chars: [u8; 4]) -> Self {
        Self(chars)
    }

    /// The typed characters, for a constant-time comparison.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

impl fmt::Debug for ChallengeAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChallengeAttempt(<redacted>)")
    }
}

/// A grant slot, `1..=8` (spec 34 §34.3.3 `Ctrl-] r`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantSlot(u8);

impl GrantSlot {
    /// `None` outside `1..=8`.
    #[must_use]
    pub const fn new(n: u8) -> Option<Self> {
        if n >= 1 && n <= 8 {
            Some(Self(n))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// What the operator did with the chord this read (spec 34 §34.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChordEvent {
    /// No chord activity.
    None,
    /// `Ctrl-]` + four characters: approve (or clear the kill switch) if the
    /// characters match the pending challenge.
    Approve(ChallengeAttempt),
    /// `Ctrl-] d`.
    Deny,
    /// `Ctrl-] x`: toggle the kill switch (clearing needs a fresh code).
    Kill,
    /// `Ctrl-] r`: draw the controller list.
    RevokeList,
    /// The Key `1`-`8` after `Ctrl-] r`: revoke that grant.
    Revoke(GrantSlot),
    /// `Ctrl-] Ctrl-]`: the caller writes ONE literal `0x1D` to the child.
    Literal,
    /// Any other key after `Ctrl-]`, or a follower read that is not exactly one
    /// key byte (`follower_byte`): the chord is cancelled and its bytes
    /// consumed. A WRONG challenge code is not this: the filter cannot tell, so
    /// it yields `Approve` and the request owner compares and counts attempts.
    Cancelled,
    /// A read carrying `0x1D` and other input together was dropped whole; it
    /// changes nothing (F6).
    DroppedBurst,
}

/// A [`ChordFilter`]'s verdict for one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChordResult {
    /// The chord event, if any.
    pub event: ChordEvent,
    /// One flag per run of the read, in order: forward that run to the child.
    /// A `0x1D` run is never forwarded except via [`ChordEvent::Literal`].
    /// Read it through [`Self::forwarded`], never directly.
    forward: Vec<bool>,
}

impl ChordResult {
    /// A filter's verdict: `event` plus one forward flag per run.
    #[cfg_attr(
        all(not(unix), not(test)),
        expect(dead_code, reason = "callers are cfg(unix); stays dead on Windows")
    )]
    #[cfg_attr(
        all(unix, not(test)),
        allow(
            dead_code,
            reason = "S2b deletes this line when it lands (01-plan.md S0 rules)"
        )
    )]
    pub(in crate::relay) const fn new(event: ChordEvent, forward: Vec<bool>) -> Self {
        Self { event, forward }
    }

    /// No chord activity: forward every one of `runs` runs.
    #[must_use]
    pub fn forward_all(runs: usize) -> Self {
        Self {
            event: ChordEvent::None,
            forward: vec![true; runs],
        }
    }

    /// The per-run forward flags for a read of `runs` runs. A length that does
    /// not match forwards NOTHING (fail closed): a filter bug may drop input,
    /// never forward a chord.
    #[must_use]
    pub fn forwarded(&self, runs: usize) -> Vec<bool> {
        if self.forward.len() == runs {
            self.forward.clone()
        } else {
            vec![false; runs]
        }
    }

    /// A burst carrying `0x1D` plus other input: forward nothing.
    #[must_use]
    pub fn dropped_burst(runs: usize) -> Self {
        Self {
            event: ChordEvent::DroppedBurst,
            forward: vec![false; runs],
        }
    }
}

/// Implemented by S2b: finds operator chords in the classifier's output
/// (spec 34 §34.3.3). One parser only (spec 34 §34.2.5): the filter never sees
/// raw bytes without their class.
///
/// Contract:
/// - `read` is ONE `read(2)` result as classified runs.
/// - Call `burst_guard` first on every read; a `Some` result is the answer.
///   It drops whole a read whose `ChordLead` shares it with other runs, and a
///   read whose unbracketed-burst content holds a `0x1D` (spec 34 §34.3.3).
/// - A lead starts a chord only as the sole run of its read. Each follower must
///   arrive in a LATER read and be exactly one key byte (`follower`);
///   anything else is [`ChordEvent::Cancelled`]. A `Report` run never cancels
///   or advances a chord and is forwarded (spec 34 §34.2.5). The classifier carries burst
///   state across reads, so a read that continues a burst is `BurstContent`.
/// - `PasteContent` (bracketed) runs are never chord input and are forwarded.
pub trait ChordFilter {
    /// Classify one read; see the trait contract.
    fn filter(&mut self, read: &[Run<'_>]) -> ChordResult;
}

/// A read that carries a chord lead together with other input, or a `0x1D`
/// inside an unbracketed burst, is dropped whole: no chord event results and
/// nothing is forwarded except terminal Reports, which never change state
/// (spec 34 §34.2.5, §34.3.3, F6). `None` means the read is not a burst and the
/// filter proceeds.
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "callers are cfg(unix); stays dead on Windows")
)]
#[cfg_attr(
    all(unix, not(test)),
    allow(
        dead_code,
        reason = "S2b deletes this line when it lands (01-plan.md S0 rules)"
    )
)]
pub(in crate::relay) fn burst_guard(read: &[Run<'_>]) -> Option<ChordResult> {
    let others = read
        .iter()
        .filter(|r| r.class != InputClass::Report)
        .count();
    let lead_with_others = others > 1 && read.iter().any(|r| r.class == InputClass::ChordLead);
    let burst_0x1d = read
        .iter()
        .any(|r| r.class == InputClass::BurstContent && r.bytes.contains(&0x1D));
    (lead_with_others || burst_0x1d).then(|| {
        let keep = read.iter().map(|r| r.class == InputClass::Report).collect();
        ChordResult::new(ChordEvent::DroppedBurst, keep)
    })
}

/// A chord follower read, with terminal Reports set aside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::relay) enum Follower {
    /// Exactly one key byte (a `Key` or a second `ChordLead`).
    Byte(u8),
    /// Only Reports: the chord waits and the Reports are forwarded.
    Pending,
    /// Longer, split across runs, or another class: the chord is cancelled
    /// (spec 34 §34.3.3, "separate reads").
    Invalid,
}

/// Classify a follower read. A lead followed by a multi-byte read cannot yield
/// `Kill`, `Deny` or `Revoke`; a Report in between neither cancels nor
/// advances the chord.
#[cfg_attr(
    all(not(unix), not(test)),
    expect(dead_code, reason = "callers are cfg(unix); stays dead on Windows")
)]
#[cfg_attr(
    all(unix, not(test)),
    allow(
        dead_code,
        reason = "S2b deletes this line when it lands (01-plan.md S0 rules)"
    )
)]
pub(in crate::relay) fn follower(read: &[Run<'_>]) -> Follower {
    let mut runs = read.iter().filter(|r| r.class != InputClass::Report);
    match (runs.next(), runs.next()) {
        (None, _) => Follower::Pending,
        (Some(r), None) if matches!(r.class, InputClass::Key(_) | InputClass::ChordLead) => {
            match r.bytes {
                [b] => Follower::Byte(*b),
                _ => Follower::Invalid,
            }
        }
        _ => Follower::Invalid,
    }
}

/// Test-only constructors for the guarded types. The construction scan
/// (`construction_sites_are_limited_to_their_owners`) exempts this file, so tests
/// in other relay modules build keys, runs and writer locks through these
/// instead of repeating the guarded call (never compiled into production; unix
/// only, since every relay test module is).
#[cfg(all(test, unix))]
pub(in crate::relay) mod test_support {
    use super::*;

    /// A classified key, as the classifier would produce it.
    pub fn classified_key(k: Key) -> ClassifiedKey {
        ClassifiedKey::new(k)
    }

    /// A classified run, as the classifier would produce it.
    pub fn run(class: InputClass, bytes: &[u8]) -> Run<'_> {
        Run::new(class, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_wire_and_code() {
        for (o, w) in [
            (InjectOutcome::DeliveredToPty, "delivered_to_pty"),
            (InjectOutcome::QueuedDeferred, "queued_deferred"),
            (InjectOutcome::RequestPending, "request_pending"),
            (InjectOutcome::NotUnderRelay, "not_under_relay"),
            (InjectOutcome::Refused(SdkErrorCode::NotIdle), "refused"),
            (InjectOutcome::Undetermined, "undetermined"),
        ] {
            assert_eq!(o.wire(), w);
        }
        let r = InjectOutcome::Refused(SdkErrorCode::NotIdle);
        assert_eq!(r.code(), Some(SdkErrorCode::NotIdle));
        assert_eq!(InjectOutcome::Undetermined.code(), None);
    }

    /// `(answers_dialog, clears_line_dirty, is_clearing_enter)`. The match is
    /// exhaustive, so a new `Key` variant fails to compile here, and `Key::ALL`
    /// is generated from the enum, so the loop below cannot skip it.
    fn expected(k: Key) -> (bool, bool, bool) {
        match k {
            Key::Printable | Key::Escape => (true, false, false),
            Key::ArrowUp | Key::ArrowDown | Key::ArrowLeft | Key::ArrowRight => {
                (true, false, false)
            }
            Key::Enter => (true, true, true),
            Key::CtrlC => (true, true, false),
            Key::CtrlU => (false, true, false),
            Key::MetaEnter | Key::ContinuationEnter | Key::Backspace | Key::Other => {
                (false, false, false)
            }
        }
    }

    #[test]
    fn key_table_is_exhaustive() {
        let mut seen = 0;
        for &k in Key::ALL {
            let (answers, clears, enter) = expected(k);
            assert_eq!(k.answers_dialog(), answers, "{k:?} answers_dialog");
            assert_eq!(k.clears_line_dirty(), clears, "{k:?} clears_line_dirty");
            assert_eq!(k.sets_line_dirty(), !clears, "{k:?} sets_line_dirty");
            assert_eq!(k.is_clearing_enter(), enter, "{k:?} is_clearing_enter");
            seen += 1;
        }
        assert_eq!(seen, Key::ALL.len());
    }

    #[test]
    fn grant_slot_bounds() {
        assert!(GrantSlot::new(0).is_none() && GrantSlot::new(9).is_none());
        assert_eq!(GrantSlot::new(1).map(GrantSlot::get), Some(1));
        assert_eq!(GrantSlot::new(8).map(GrantSlot::get), Some(8));
    }

    #[test]
    fn classified_key_round_trips() {
        for &k in Key::ALL {
            assert_eq!(ClassifiedKey::new(k).key(), k);
        }
    }

    #[test]
    fn launch_is_busy_and_slash_quiet_returns_through_turn_ended() {
        assert_eq!(Phase::at_launch(), Phase::Busy);
        for (k, want) in [
            (CsqEnter::Text, Phase::Busy),
            (CsqEnter::Slash(IdleReturn::Hook), Phase::Busy),
            (CsqEnter::Slash(IdleReturn::Quiet), Phase::TurnEnded),
        ] {
            assert_eq!(k.phase_after(), want, "{k:?}");
        }
    }

    /// A gate double: counts Keys and records whether a draft was seen.
    struct Probe {
        keys: u64,
        dirty: bool,
    }

    impl sealed::Sealed for Probe {}

    impl EnterGate for Probe {
        fn on_key(&mut self, _: ClassifiedKey, _: u64) {
            self.keys += 1;
        }
        fn on_paste_content(&mut self, _: u64) {
            self.dirty = true;
        }
    }

    /// Burst content is a draft exactly like a paste; only a Key is a Key.
    #[test]
    fn route_marks_paste_and_burst_as_drafts_and_reports_as_nothing() {
        for (class, dirty) in [
            (InputClass::PasteContent, true),
            (InputClass::BurstContent, true),
            (InputClass::Report, false),
            (InputClass::ChordLead, false),
        ] {
            let mut g = Probe {
                keys: 0,
                dirty: false,
            };
            route(&Run::new(class, b"x"), &mut g, 0);
            assert_eq!((g.dirty, g.keys), (dirty, 0), "{class:?}");
        }
        let mut g = Probe {
            keys: 0,
            dirty: false,
        };
        route(&Run::new(InputClass::Key(Key::Printable), b"x"), &mut g, 0);
        assert_eq!((g.keys, g.dirty), (1, false));
    }

    fn at_idle(t: &mut QuietTracker) {
        t.on_turn_end();
        t.on_child_output(5_000);
        t.on_tick(6_000);
        assert_eq!(t.phase(), Phase::Idle);
    }

    /// A quiet slash must not be completed by its own echo, nor by the redraw
    /// seen before it.
    #[test]
    fn quiet_slash_returns_to_idle_only_after_its_own_unmasked_redraw() {
        let mut t = QuietTracker::new(0);
        at_idle(&mut t);
        t.on_csq_enter(CsqEnter::Slash(IdleReturn::Quiet), 7_000);
        assert_eq!((t.phase(), t.redraw_seen()), (Phase::TurnEnded, false));
        t.on_child_output(7_100); // the `\r` echo, inside the mask
        t.on_tick(9_000);
        assert_eq!(
            t.phase(),
            Phase::TurnEnded,
            "echo must not complete the slash"
        );
        t.on_child_output(7_600); // the command's own redraw, after the mask
        t.on_tick(8_500);
        assert_eq!(t.phase(), Phase::TurnEnded, "QUIET_MS not elapsed");
        t.on_tick(8_600);
        assert_eq!(t.phase(), Phase::Idle);
    }

    #[test]
    fn masked_output_in_idle_keeps_idle_and_unmasked_leaves_it() {
        let mut t = QuietTracker::new(0);
        at_idle(&mut t);
        t.open_mask(7_000);
        t.on_child_output(7_100);
        assert_eq!(t.phase(), Phase::Idle, "masked output must not leave Idle");
        t.on_child_output(7_600);
        assert_eq!(t.phase(), Phase::TurnEnded);
    }

    #[test]
    fn on_busy_resets_phase_and_redraw_seen_but_keeps_the_mask() {
        for start in [Phase::Busy, Phase::TurnEnded, Phase::Idle] {
            let mut t = QuietTracker::new(0);
            at_idle(&mut t);
            t.open_mask(7_000);
            match start {
                Phase::Busy => {}
                Phase::TurnEnded => t.on_draft_key(7_010),
                Phase::Idle => {}
            }
            t.on_busy();
            assert_eq!(
                (t.phase(), t.redraw_seen()),
                (Phase::Busy, false),
                "{start:?}"
            );
            t.on_turn_end();
            t.on_child_output(7_100); // inside the mask kept across on_busy
            assert!(!t.redraw_seen(), "{start:?}: mask was forgotten");
        }
    }

    #[test]
    fn on_draft_key_moves_only_idle_and_restarts_quiet() {
        let mut t = QuietTracker::new(0);
        t.on_draft_key(10);
        assert_eq!(t.phase(), Phase::Busy);
        t.on_turn_end();
        t.on_draft_key(10);
        assert_eq!(t.phase(), Phase::TurnEnded);
        let mut t = QuietTracker::new(0);
        at_idle(&mut t);
        t.on_draft_key(9_000);
        assert_eq!((t.phase(), t.redraw_seen()), (Phase::TurnEnded, true));
        t.on_tick(9_000 + QUIET_MS - 1);
        assert_eq!(t.phase(), Phase::TurnEnded);
        t.on_tick(9_000 + QUIET_MS);
        assert_eq!(t.phase(), Phase::Idle);
    }

    #[test]
    fn text_enter_enters_busy_and_keeps_redraw_seen() {
        let mut t = QuietTracker::new(0);
        at_idle(&mut t);
        t.on_csq_enter(CsqEnter::Text, 7_000);
        assert_eq!((t.phase(), t.redraw_seen()), (Phase::Busy, true));
    }

    fn run(class: InputClass, bytes: &[u8]) -> Run<'_> {
        Run::new(class, bytes)
    }

    #[test]
    fn burst_guard_drops_lead_with_company_and_burst_0x1d_only() {
        let lead = InputClass::ChordLead;
        let key = InputClass::Key(Key::Printable);
        // Sole lead: a chord may start.
        assert_eq!(burst_guard(&[run(lead, &[0x1D])]), None);
        // Lead plus anything else: dropped whole, nothing forwarded.
        let r = burst_guard(&[run(lead, &[0x1D]), run(key, b"x")]).unwrap();
        assert_eq!(
            (r.event, r.forward),
            (ChordEvent::DroppedBurst, vec![false; 2])
        );
        // Unbracketed burst holding 0x1D: dropped whole.
        let r = burst_guard(&[run(key, b"a"), run(InputClass::BurstContent, b"b\x1dc")]).unwrap();
        assert_eq!(r.forward, vec![false; 2]);
        // Burst without 0x1D, and bracketed paste with 0x1D, are forwarded as text.
        assert_eq!(burst_guard(&[run(InputClass::BurstContent, b"abc")]), None);
        assert_eq!(
            burst_guard(&[run(InputClass::PasteContent, b"a\x1d")]),
            None
        );
    }

    /// Reports never change state: a Report beside the lead neither drops the
    /// read nor is dropped itself.
    #[test]
    fn reports_are_forwarded_and_never_make_a_burst() {
        let lead = InputClass::ChordLead;
        let rep = InputClass::Report;
        assert_eq!(
            burst_guard(&[run(lead, &[0x1D]), run(rep, b"\x1b[I")]),
            None
        );
        let r = burst_guard(&[
            run(lead, &[0x1D]),
            run(rep, b"\x1b[I"),
            run(InputClass::Key(Key::Printable), b"x"),
        ])
        .unwrap();
        assert_eq!(r.forward, vec![false, true, false]);
    }

    #[test]
    fn follower_is_exactly_one_key_byte_and_reports_neither_cancel_nor_advance() {
        let key = InputClass::Key(Key::Printable);
        let rep = InputClass::Report;
        assert_eq!(follower(&[run(key, b"x")]), Follower::Byte(b'x'));
        assert_eq!(
            follower(&[run(rep, b"\x1b[I"), run(key, b"x")]),
            Follower::Byte(b'x')
        );
        assert_eq!(
            follower(&[run(InputClass::ChordLead, &[0x1D])]),
            Follower::Byte(0x1D)
        );
        assert_eq!(follower(&[run(rep, b"\x1b[I")]), Follower::Pending);
        assert_eq!(follower(&[]), Follower::Pending);
        assert_eq!(follower(&[run(key, b"xy")]), Follower::Invalid);
        assert_eq!(
            follower(&[run(key, b"x"), run(key, b"y")]),
            Follower::Invalid
        );
        assert_eq!(
            follower(&[run(InputClass::BurstContent, b"x")]),
            Follower::Invalid
        );
    }

    #[test]
    fn forwarded_fails_closed_on_length_mismatch() {
        let ok = ChordResult::forward_all(2);
        assert_eq!(ok.forwarded(2), vec![true; 2]);
        assert_eq!(ok.forwarded(3), vec![false; 3]);
        assert_eq!(ok.forwarded(1), vec![false; 1]);
    }

    #[test]
    fn debug_never_prints_keystrokes_or_challenge() {
        let secret = b"hunter2!";
        let r = Run::new(InputClass::Key(Key::Printable), secret);
        let rendered = format!("{r:?}");
        assert!(rendered.contains("len: 8"));
        assert!(!rendered.contains("hunter") && !rendered.contains("104"));
        let ev = ChordEvent::Approve(ChallengeAttempt::new(*b"k7p2"));
        let rendered = format!("{ev:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("k7p2") && !rendered.contains("107"));
    }

    #[test]
    fn chord_result_helpers() {
        let f = ChordResult::forward_all(3);
        assert_eq!((f.event, f.forward), (ChordEvent::None, vec![true; 3]));
        let d = ChordResult::dropped_burst(2);
        assert_eq!(
            (d.event, d.forward),
            (ChordEvent::DroppedBurst, vec![false; 2])
        );
    }

    // (pattern, the only relay-relative files allowed to contain it). Patterns
    // meet the source after `normalized`, which removes whitespace around
    // punctuation, so a split line, `T ::new` and `<T>::new` read the same; a
    // pattern ending in an identifier character must end a token. `X::new` with
    // no `(` also catches `map(X::new)` and `let f = X::new;`. A bare method
    // name (no leading `.`) matches the method form, the path form
    // `RelayState::name(&mut g)` and the fn-pointer form alike. The first four
    // are also present in this file; the rest only name callers.
    const OWNED: [(&str, &[&str]); 15] = [
        ("ClassifiedKey::new", &["types.rs"]),
        ("Run::new", &["inparse.rs"]),
        ("EnterGate for ", &["state.rs"]),
        ("Sealed for ", &["state.rs"]),
        ("WriterLock::new", &["state.rs"]),
        ("RelayState::new", &["loop.rs", "state.rs"]),
        ("on_identity_change", &["state.rs", "loop.rs"]),
        ("set_inputs", &["state.rs", "loop.rs"]),
        ("relaunched", &["state.rs", "loop.rs"]),
        ("from_scan", &["state.rs", "loop.rs"]),
        ("InputFlushed::new", &["state.rs"]),
        ("flush_input", &["state.rs", "loop.rs"]),
        ("writer_lock", &["state.rs", "loop.rs", "writer.rs"]),
        ("Text::new", &["state.rs", "input.rs"]),
        ("for_cli", &["state.rs", "input.rs"]),
    ];
    /// How many leading `OWNED` patterns this file's own source must contain.
    const SELF_VISIBLE: usize = 4;
    /// The guarded types, for the alias and `Self::new` checks.
    const GUARDED: [&str; 8] = [
        "ClassifiedKey",
        "Run",
        "WriterLock",
        "RelayState",
        "InputFlushed",
        "EnterCapableInputs",
        "Text",
        "SlashTable",
    ];
    /// Where the production half of `types.rs` ends.
    const TYPES_TEST_MARKER: &str =
        "\n#[cfg(all(test, unix))]\npub(in crate::relay) mod test_support";

    fn ident(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    /// `src` without comments (line and nested block) and without the `r#` of
    /// raw identifiers, so `T::/* c */new`, `T::r#new` and a `//` line break
    /// between path segments read as `T::new`. String and char literals are
    /// skipped whole, so a `"//"` or `'"'` earlier on a line cannot hide code.
    /// The number of `#` of a raw string literal opening at `c[i]` (`r"`,
    /// `r#"`, and the `b`/`c` prefixed forms), or `None` when `c[i]` opens none.
    fn raw_string_hashes(c: &[char], i: usize) -> Option<usize> {
        if c[i] != 'r' {
            return None;
        }
        let prefixed = i > 0 && matches!(c[i - 1], 'b' | 'c');
        let before = if prefixed {
            i.checked_sub(2)
        } else {
            i.checked_sub(1)
        };
        if before.is_some_and(|k| ident(c[k])) {
            return None;
        }
        let n = c[i + 1..].iter().take_while(|&&x| x == '#').count();
        (c.get(i + 1 + n) == Some(&'"')).then_some(n)
    }

    fn strip_comments_and_raw_idents(src: &str) -> String {
        let c: Vec<char> = src.chars().collect();
        let mut out = String::with_capacity(src.len());
        let mut i = 0;
        while i < c.len() {
            let at = |k: usize| c.get(k).copied().unwrap_or('\0');
            match c[i] {
                '/' if at(i + 1) == '/' => {
                    while i < c.len() && c[i] != '\n' {
                        i += 1;
                    }
                }
                '/' if at(i + 1) == '*' => {
                    let mut depth = 1;
                    i += 2;
                    while i < c.len() && depth > 0 {
                        if c[i] == '/' && at(i + 1) == '*' {
                            depth += 1;
                            i += 2;
                        } else if c[i] == '*' && at(i + 1) == '/' {
                            depth -= 1;
                            i += 2;
                        } else {
                            i += 1;
                        }
                    }
                    out.push(' ');
                }
                '"' => {
                    out.push('"');
                    i += 1;
                    while i < c.len() && c[i] != '"' {
                        if c[i] == '\\' {
                            out.push(c[i]);
                            i += 1;
                        }
                        if i < c.len() {
                            out.push(c[i]);
                            i += 1;
                        }
                    }
                    if i < c.len() {
                        out.push('"');
                        i += 1;
                    }
                }
                '\'' if at(i + 2) == '\'' && at(i + 1) != '\\' => {
                    out.extend(&c[i..i + 3]);
                    i += 3;
                }
                '\'' if at(i + 1) == '\\' => {
                    let mut j = i + 2;
                    while j < c.len() && c[j] != '\'' {
                        j += 1;
                    }
                    let end = (j + 1).min(c.len());
                    out.extend(&c[i..end]);
                    i = end;
                }
                'r' if raw_string_hashes(&c, i).is_some() => {
                    // A raw string (`r"..."`, `r#"..."#`, `br#"..."#`): skipped
                    // whole, so a `//` or `/*` inside it hides nothing after it.
                    let n = raw_string_hashes(&c, i).unwrap_or(0);
                    let body = i + 1 + n + 1;
                    let mut j = body;
                    while j < c.len() && !(c[j] == '"' && (1..=n).all(|k| at(j + k) == '#')) {
                        j += 1;
                    }
                    let end = (j + 1 + n).min(c.len());
                    out.extend(&c[i..end]);
                    i = end;
                }
                'r' if at(i + 1) == '#'
                    && (at(i + 2).is_alphabetic() || at(i + 2) == '_')
                    && !(i > 0 && ident(c[i - 1])) =>
                {
                    i += 2;
                }
                ch => {
                    out.push(ch);
                    i += 1;
                }
            }
        }
        out
    }

    /// `src` with comments and raw-ident markers removed, whitespace collapsed,
    /// then dropped next to punctuation.
    fn normalized(src: &str) -> String {
        let src = strip_comments_and_raw_idents(src);
        let collapsed = src.split_whitespace().collect::<Vec<_>>().join(" ");
        let chars: Vec<char> = collapsed.chars().collect();
        let punct = |c: char| "<>(),:;={}&".contains(c);
        let mut out = String::with_capacity(chars.len());
        for (i, &c) in chars.iter().enumerate() {
            let edge = i == 0 || i + 1 == chars.len();
            if c == ' ' && (edge || punct(chars[i - 1]) || punct(chars[i + 1])) {
                continue;
            }
            out.push(c);
        }
        out
    }

    /// Whether `pat` occurs in `src` as a token: an identifier character at
    /// either end of `pat` must not touch another identifier character.
    fn has_token(src: &str, pat: &str) -> bool {
        let pat = &normalized(pat);
        let first = pat.chars().next().is_some_and(ident);
        let last = pat.chars().last().is_some_and(ident);
        src.match_indices(pat).any(|(i, _)| {
            let before = src[..i].chars().last();
            let after = src[i + pat.len()..].chars().next();
            !(first && before.is_some_and(ident)) && !(last && after.is_some_and(ident))
        })
    }

    /// The first construction-surface violation `src` (at `rel` under `relay/`)
    /// commits, if any. `types.rs` is the exempt home of `ClassifiedKey::new`;
    /// its production half (before `test_support`) is scanned too, and may call
    /// that constructor exactly once, in `route`.
    fn scan_violation(rel: &str, src: &str) -> Option<String> {
        let prod;
        let src = if rel == "types.rs" {
            let Some(end) = src.find(TYPES_TEST_MARKER) else {
                return Some("types.rs lost its test_support marker: the scan is blind".to_owned());
            };
            prod = src[..end].to_owned();
            prod.as_str()
        } else {
            src
        };
        let mut n = normalized(src);
        for t in GUARDED {
            // `<T>::new` is `T::new`.
            n = n.replace(&format!("<{t}>::"), &format!("{t}::"));
        }
        for (pat, owner) in OWNED {
            if !owner.contains(&rel) && has_token(&n, pat) {
                return Some(format!("{rel} contains {pat}"));
            }
        }
        if rel == "types.rs" && n.matches("ClassifiedKey::new(").count() != 1 {
            return Some("types.rs must call ClassifiedKey::new once, in route".to_owned());
        }
        for t in GUARDED {
            let aliases = [format!("{t} as "), format!("={t};"), format!("={t}<")];
            if let Some(a) = aliases.iter().find(|a| has_token(&n, a)) {
                return Some(format!("{rel} renames or aliases a guarded type ({a})"));
            }
            let impls = [
                format!("impl {t}"),
                format!("impl<W> {t}<W>"),
                format!("impl<'a> {t}<'a>"),
            ];
            if impls.iter().any(|i| has_token(&n, i)) && has_token(&n, "Self::new") {
                return Some(format!("{rel} builds a guarded type via Self::new"));
            }
        }
        None
    }

    /// The constructors are `pub(in crate::relay)`, which admits the authz and
    /// hook modules too. This scan is the tripwire: each construction pattern has
    /// an allowed file, matched by its path under `relay/`. It is LEXICAL: it
    /// reads path, UFCS (`<T>::new`), alias (`as`, `type =`) and fn-pointer forms
    /// and `Self::new` inside the type's own `impl`, whitespace-insensitively; it
    /// cannot see a call built by a macro defined elsewhere or from concatenated
    /// tokens. It is a BACKSTOP: the transaction and the queue are private to
    /// `state.rs`, which the compiler enforces.
    #[test]
    fn construction_sites_are_limited_to_their_owners() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = crate::testing::manifest_dir(env!("CARGO_MANIFEST_DIR")).join("src/relay");
        let mut files = Vec::new();
        walk(&root, &mut files);
        let mut types_hits = false;
        for f in &files {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            let src = std::fs::read_to_string(f).unwrap();
            if rel == "types.rs" {
                let n = normalized(&src);
                types_hits = OWNED[..SELF_VISIBLE]
                    .iter()
                    .all(|(pat, _)| has_token(&n, pat));
            }
            assert_eq!(scan_violation(&rel, &src), None, "{rel}");
        }
        assert!(
            types_hits,
            "scan is blind: it must see this file's own constructions"
        );
    }

    /// The scan REDs on a production literal in a non-owner file, and the
    /// `test_support` helpers do not widen that surface: a file that builds its
    /// values through them is clean, a file that calls the constructor is not.
    #[test]
    fn scan_rejects_a_non_owner_literal_and_accepts_test_support_use() {
        for (pat, owner) in OWNED {
            let literal = format!("f({pat}(a));");
            assert!(scan_violation("authz.rs", &literal).is_some(), "{pat}");
            for o in owner {
                // `types.rs` is scanned only up to its test marker.
                let src = if *o == "types.rs" {
                    format!("{literal}{TYPES_TEST_MARKER}")
                } else {
                    literal.clone()
                };
                assert_eq!(scan_violation(o, &src), None, "{pat} owner {o}");
            }
        }
        let via_helpers = "use test_support::{run, classified_key}; let r = run(c, b);";
        assert_eq!(scan_violation("state.rs", via_helpers), None);
        // Literal production forms (not derived from the table, so a pattern
        // that silently stopped matching REDs here).
        for src in [
            "impl EnterGate for Stub {}",
            "impl<T: Zeroize> EnterGate for Stub<T> {}",
            "impl sealed::Sealed for Stub {}",
            "let g = RelayState::new(0, true, true, i, w, f, c);",
            "gate.on_identity_change();",
            "gate.set_inputs(i);",
            "gate.relaunched(true, true, i, f);",
            "let i = EnterCapableInputs::from_scan(&[], &[], true);",
            "let f = InputFlushed::new();",
            "let f = flush_input(fd);",
            "let l = gate.writer_lock(w);",
        ] {
            assert!(scan_violation("authz.rs", src).is_some(), "{src}");
            assert_eq!(scan_violation("state.rs", src), None, "{src} owner");
        }
    }

    /// Comments and raw identifiers cannot hide a construction: the forms the
    /// scan used to miss are caught, a pattern that only appears in a comment is
    /// not a construction, and a `//` or a quote inside a string or char literal
    /// does not make the scan skip the code after it.
    #[test]
    fn scan_sees_through_comments_and_raw_idents() {
        for src in [
            "let f = InputFlushed::r#new();",
            "let t = Text::/**/new(Role::Operator, b);",
            "let g = RelayState::/* a /* nested */ b */new(0, true, true, i, w, f, c);",
            "let g = RelayState:: // why\n    new(0, true, true, i, w, f, c);",
            "let k = ClassifiedKey::r#new(x);",
            "let k = r#ClassifiedKey::new(x);",
            "let u = \"http://x\"; let g = RelayState::new(0, true, true, i, w, f, c);",
            "let q = '\"'; let g = RelayState::new(0, true, true, i, w, f, c);",
            "let q = '\\''; let g = RelayState::new(0, true, true, i, w, f, c);",
            "let s = \"a \\\" b\"; let t = Text::new(Role::Operator, b);",
            "let a = r#\"a\"//\"#; let g = RelayState::new(0, true, true, i, w, f, c);",
            "let a = r\"//\"; let g = RelayState::new(0, true, true, i, w, f, c);",
            "let a = br##\"x\"#//\"##; let g = RelayState::new(0, true, true, i, w, f, c);",
            "let a = r#\"/*\"#; let t = Text::new(Role::Operator, b);",
        ] {
            assert!(scan_violation("authz.rs", src).is_some(), "{src}");
        }
        for src in [
            "// RelayState::new(0, true, true, i, w, f, c)\nlet x = 1;",
            "/* Text::new(Role::Operator, b) */ let x = 1;",
            "/// docs name InputFlushed::new() and from_scan\nfn f() {}",
            "let lifetime: &'a str = s; let x = 1;",
        ] {
            assert_eq!(scan_violation("authz.rs", src), None, "{src}");
        }
    }

    /// Every spelling of a guarded call the scan promises to see: UFCS, path,
    /// split across lines, spaced, as a function pointer and through an alias.
    #[test]
    fn scan_sees_ufcs_alias_fn_pointer_and_split_forms() {
        for src in [
            "let k = <ClassifiedKey>::new(x);",
            "let k = crate::relay::types::ClassifiedKey\n    ::new(x);",
            "let k = ClassifiedKey :: new (x);",
            "let f = ClassifiedKey::new;",
            "let v: Vec<_> = ks.into_iter().map(ClassifiedKey::new).collect();",
            "let r = Run::new(c, b);",
            "let f = Run::new;",
            "let l = WriterLock::new(w);",
            "let f: fn(u64, bool, bool, I) -> RelayState = RelayState::new;",
            "let g = <RelayState>::new(0, true, true, i);",
            "RelayState::on_identity_change(&mut g);",
            "RelayState::set_inputs(&mut g, i);",
            "RelayState::relaunched(&mut g, true, true, i, f);",
            "RelayState::writer_lock(&g, w);",
            "<RelayState>::on_identity_change(&mut g);",
            "RelayState\n    ::relaunched(&mut g, true, true, i, f);",
            "let f = RelayState::on_identity_change;",
            "let f = RelayState::set_inputs;",
            "let f = EnterCapableInputs::from_scan;",
            "let m = RelayState::writer_lock;",
            "let f = InputFlushed :: new ;",
            "let f = <InputFlushed>::new();",
            "let t = Text::new(Role::Operator, b);",
            "let t = <Text>::new(Role::Operator, b);",
            "let f = Text::new;",
            "let t = SlashTable::for_cli(c);",
            "let t = <SlashTable>::for_cli(c);",
            "let f = SlashTable::for_cli;",
            "type T = Text;",
            "type S = SlashTable;",
            "let i = <EnterCapableInputs>::from_scan(&[], &[], true);",
            "type I = EnterCapableInputs;",
            "type F = InputFlushed;",
            "let i = EnterCapableInputs\n    ::from_scan(&[], &[], true);",
            "let g = RelayState\n    ::new(0, true, true, i);",
            "type K = ClassifiedKey;",
            "type R<'a> = Run<'a>;",
            "type G = RelayState;",
            "use super::types::ClassifiedKey as K;",
            "use super::state::RelayState as S;",
            "impl RelayState { fn f() -> Self { Self::new(0, true, true, i) } }",
            "impl<W> WriterLock<W> { fn f(w: W) -> Self { Self::new(w) } }",
        ] {
            assert!(scan_violation("authz.rs", src).is_some(), "{src}");
        }
        // A name that merely contains a guarded one is not a construction.
        for src in [
            "let r = Runner::new(c);",
            "let r = MyRun::new(c);",
            "let l = WriterLockGuard::new(w);",
            "let was_relaunched = true;",
            "let x = relaunched_count;",
            "let f = MyInputFlushed::new();",
            "let s = from_scanner(b);",
            "let w = my_writer_lock(g);",
        ] {
            assert_eq!(scan_violation("authz.rs", src), None, "{src}");
        }
    }

    /// `types.rs` is exempt for the constructors it owns, but its PRODUCTION half
    /// is still scanned: a second `ClassifiedKey::new` call or another type's
    /// constructor there is a violation; the same text after the marker is not.
    #[test]
    fn scan_covers_the_production_half_of_types_rs() {
        let tail = format!(
            "{TYPES_TEST_MARKER} {{ fn t() {{ RelayState::new(0, true, true, i, w, f, c); }} }}"
        );
        let ok = format!("fn route() {{ ClassifiedKey::new(k); }}{tail}");
        assert_eq!(scan_violation("types.rs", &ok), None);
        let two = format!("fn route() {{ ClassifiedKey::new(k); ClassifiedKey::new(j); }}{tail}");
        assert!(scan_violation("types.rs", &two).is_some());
        let other = format!(
            "fn route() {{ ClassifiedKey::new(k); RelayState::new(0, true, true, i, w, f, c); }}{tail}"
        );
        assert!(scan_violation("types.rs", &other).is_some());
        // Without the marker the production half cannot be bounded: blind, so red.
        assert!(scan_violation("types.rs", "fn route() { ClassifiedKey::new(k); }").is_some());
    }
}
