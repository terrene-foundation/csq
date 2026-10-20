//! Session-directive store: `deliver`, `receipts`, `ack`, `inbox` and the statusline
//! summary (contract `internal-design-docs` §3-§5).
//!
//! csq NEVER executes a directive. It validates one, queues it for exactly one live
//! session identified by `(pid, started_at)` (pids are reused), records its lifecycle
//! `queued -> surfaced -> acknowledged` (or `expired`), and lets the issuer pull the
//! receipt.
//!
//! # Store
//!
//! `<base_dir>/directives/` (dir 0700, created atomically with that mode, never a
//! symlink; files 0600), one `<id>.json` per directive holding the directive and its
//! receipt, plus one `pid-<pid>-<start>.idx` per target SESSION (pid and the stored live
//! start) listing the ids that were PENDING (queued or surfaced, not expired) at its last
//! sync, so the statusline reads a handful of files instead of the whole store. Every mutation runs under `directives/.lock`
//! (bounded wait, opened without following a symlink); every write is tmp ->
//! `secure_file` -> `atomic_replace` with the tmp removed on every failure branch
//! (`security.md` §4 / §5a). After EVERY locked operation the indexes are reconciled
//! with the records, so a failed index write is repaired by the next mutating call.
//! Directives carry no credentials; nothing here logs directive text or paths.
//!
//! # Bounds
//!
//! At most [`MAX_PENDING_PER_TARGET`] pending directives per `(pid, started_at)` across
//! ALL issuers (refused as `rate_limited`); at most [`MAX_RECORDS`] records, where a full
//! store saves the new record and then EVICTS its oldest evictable records (target no
//! longer a live listed session, or expired; never an unexpired acknowledgement, never a
//! pending record of a live session), refusing only when none is evictable; a directive
//! must live at least [`MIN_LIFETIME_SECS`]. So rotating the `issuer` string can neither
//! flood one session nor lock the store. Sessions are compared BETWEEN records by the
//! exact live start stored at delivery (the 1 s tolerance is not transitive) and against
//! a CURRENT reading with [`same_start`].
//!
//! # Bad records
//!
//! A record is read only through an `O_NOFOLLOW | O_NONBLOCK` handle that is `fstat`ed to
//! be a regular file of at most [`MAX_RECORD_BYTES`]; an entry that cannot be opened
//! because of what it is (mode 000, socket) is bad too. Lock-free reads report a bad record
//! as [`SdkErrorCode::Undetermined`]; the next mutating call, which holds the lock, MOVES
//! it (and any index path that is not a regular file) to `directives/rejected/` (newest
//! [`MAX_REJECTED`] csq-named entries kept; deleted only with `remove_file`, never a
//! directory) so one bad file cannot block the store forever.
//!
//! # Outcomes
//!
//! Every operation has three outcomes: success, a typed refusal, and
//! [`SdkErrorCode::Undetermined`] (could not read/lock/write the store). A store read
//! failure is never an empty list and never a refusal.
//!
//! # Injection
//!
//! Time, liveness, start time, the host name and the filesystem primitives are parameters
//! of the `*_inner` functions ([`Env`], [`Live`], [`FsOps`]); the public wrappers supply
//! the real clock, [`super::try_list`] and the real `platform::fs` primitives.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use csq_sdk::directives::{Directive, DirectiveAck, DirectiveInboxEntry, DirectiveReceipt};
use csq_sdk::SdkErrorCode;
use serde::{Deserialize, Serialize};
use unicode_general_category::{get_general_category, GeneralCategory};

use super::{same_start, START_TOLERANCE_SECS};
use crate::error::PlatformError;
use crate::platform::fs::{
    atomic_replace, secure_dir, secure_file, unique_tmp_path, write_new_private,
};

/// A directive is deleted this long after its last transition.
pub const RETENTION_SECS: u64 = 7 * 24 * 3600;
/// Rolling window of the per-`(issuer, pid, started_at)` rate limit.
pub const RATE_WINDOW_SECS: u64 = 3600;
/// Longest permitted `expires_at - issued_at`, and longest `expires_at - now`.
pub const MAX_LIFETIME_SECS: u64 = 24 * 3600;
/// Shortest permitted `expires_at - issued_at`: a 1-second directive would let one issuer
/// fill the pending set cheaply and churn the store.
pub const MIN_LIFETIME_SECS: u64 = 300;
/// Furthest into the future `issued_at` may lie (clock skew allowance).
pub const MAX_ISSUED_SKEW_SECS: u64 = 300;
/// Cap on `summary`, each `suggested` entry, `why.source`, `why.metric`, `scope` and `ack.note`.
pub const MAX_TEXT_CHARS: usize = 500;
/// Cap on the number of `suggested` entries.
pub const MAX_SUGGESTED: usize = 10;
/// Most pending (`queued`/`surfaced`) directives one `(pid, started_at)` may hold, all issuers.
pub const MAX_PENDING_PER_TARGET: usize = 10;
/// Most records the store holds; at the cap a delivery evicts the oldest settled record.
pub const MAX_RECORDS: usize = 500;
/// Largest record file that is read; a bigger one makes the read `undetermined`.
pub const MAX_RECORD_BYTES: u64 = 512 * 1024;
/// A `*.tmp.*` leftover at least this old is removed by the sweep.
pub const STALE_TMP_SECS: u64 = 3600;
/// Entries `directives/rejected/` keeps (the newest); older quarantined records are deleted.
pub const MAX_REJECTED: usize = 20;
/// The exact `scope` the deleting kinds must carry (and the only `scope` any kind may carry).
pub const DELETE_SCOPE: &str = "only paths this session created";

/// Directory entries beyond this many make the store unreadable instead of being scanned
/// (the store is capped at [`MAX_RECORDS`] records plus their indexes; this is the hard
/// stop for a directory something else filled). Counted while iterating.
const MAX_SCANNED_RECORDS: usize = 4 * MAX_RECORDS;
const MAX_INDEX_BYTES: u64 = 64 * 1024;
const REJECTED_DIR: &str = "rejected";
const TOMBSTONE_FILE: &str = "tombstones.json";
/// The replay horizon: one decimal `u64`, its own file so that losing `tombstones.json`
/// can never take the horizon with it.
const HORIZON_FILE: &str = "replay-horizon";
/// A `u64` in decimal is at most 20 bytes; anything past this is not csq's.
const MAX_HORIZON_BYTES: u64 = 32;
/// Most duplicate-id tombstones the store keeps; the oldest by `expires_at` go first.
pub const MAX_TOMBSTONES: usize = 5000;
/// A tombstone file is `MAX_TOMBSTONES` entries of about 150 bytes; anything past this
/// is not one of csq's.
const MAX_TOMBSTONE_BYTES: u64 = 2 * 1024 * 1024;
#[cfg(not(test))]
const LOCK_ATTEMPTS: u32 = 50;
#[cfg(not(test))]
const LOCK_DELAY: Duration = Duration::from_millis(100);
// Tests wait milliseconds, not seconds: the timeout path is exercised without sleeping long.
// Test-only budget: 100 x 5 ms = 500 ms bounds genuine contention, not a guarantee about
// another process's hold time. StoreLock explicitly unlocks before closing its file so an
// unrelated fork's copied description cannot extend this guard's hold after drop. The wait
// is bounded (`LOCK_ATTEMPTS` tries), so the outcome is a test FAILURE, never a hang;
// `held_lock_times_out_as_undetermined` holds the lock for good and ends after this budget.
#[cfg(test)]
const LOCK_ATTEMPTS: u32 = 100;
#[cfg(test)]
const LOCK_DELAY: Duration = Duration::from_millis(5);

// Messaging load fixtures exercise the installed Unix admission policy, rather than
// the accelerated generic directive timeout fixtures above. These values are identical
// in production and tests: two contention rounds share a cooperative ten-second budget.
const MESSAGE_LOCK_ATTEMPTS: u32 = 50;
const MESSAGE_LOCK_ROUNDS: u32 = 2;
const MESSAGE_LOCK_DELAY: Duration = Duration::from_millis(100);

// Gate ledger admission uses the same policy in production and tests. Two bounded
// contention rounds share one second; no durable write has begun during either round.
#[cfg(unix)]
const GATE_LEDGER_LOCK_ATTEMPTS: u32 = 5;
#[cfg(unix)]
const GATE_LEDGER_LOCK_ROUNDS: u32 = 2;
#[cfg(unix)]
const GATE_LEDGER_LOCK_DELAY: Duration = Duration::from_millis(100);

const KINDS: [&str; 4] = ["offload", "land_and_drain", "delete_scratch", "free_disk"];
const OUTCOMES: [&str; 3] = ["done", "declined", "deferred"];

/// Closed diagnostic causes; never derived from arbitrary error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndeterminedCause {
    /// No more precise stage was established.
    Unknown,
    /// Bounded lock admission exhausted its attempts or elapsed deadline.
    LockTimeout,
    /// Lock authority or I/O was unavailable.
    LockUnavailable,
    /// Request authority could not be read or validated.
    LedgerRead,
    /// Request authority could not be durably published.
    LedgerWrite,
    /// Clock or temporal eligibility could not be established.
    Clock,
    /// Sender identity could not be pinned.
    SenderIdentity,
    /// Registry enumeration or name resolution was incomplete.
    RegistryRead,
    /// A prepared public record could not be established.
    RecordUncertain,
}
impl UndeterminedCause {
    /// Fixed nonsecret token for a trusted diagnostic.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::LockTimeout => "lock_timeout",
            Self::LockUnavailable => "lock_unavailable",
            Self::LedgerRead => "ledger_read",
            Self::LedgerWrite => "ledger_write",
            Self::Clock => "clock",
            Self::SenderIdentity => "sender_identity",
            Self::RegistryRead => "registry_read",
            Self::RecordUncertain => "record_uncertain",
        }
    }
}

/// A typed refusal (or could-not-determine) from a directive operation.
#[derive(Debug, Clone)]
pub struct DirectiveError {
    /// Actual protected operation attempts; not a new SDK envelope field.
    pub attempts: Option<u8>,
    /// Typed internal diagnostic; not a new SDK envelope field.
    pub cause: Option<UndeterminedCause>,
    /// The closed-vocabulary code the envelope carries.
    pub code: SdkErrorCode,
    /// A fixed, csq-authored message (no directive text, no paths).
    pub message: String,
    /// Set only for [`SdkErrorCode::RateLimited`]: the earliest moment a slot frees.
    pub next_allowed_at: Option<u64>,
}

impl DirectiveError {
    /// Attach stage context without replacing a more precise originating cause.
    pub fn with_cause(mut self, cause: UndeterminedCause) -> Self {
        if self.code == SdkErrorCode::Undetermined && self.cause.is_none() {
            self.cause = Some(cause);
        }
        self
    }
    pub(crate) fn new(code: SdkErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            attempts: None,
            next_allowed_at: None,
            cause: None,
        }
    }
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(SdkErrorCode::InvalidInput, message)
    }
    pub(crate) fn undet(message: impl Into<String>) -> Self {
        Self::new(SdkErrorCode::Undetermined, message)
    }
    pub(crate) fn undetermined(what: &str, kind: impl std::fmt::Display) -> Self {
        Self::new(SdkErrorCode::Undetermined, format!("{what}: {kind}"))
    }
    pub(crate) fn rate_limited(message: &str, next_allowed_at: Option<u64>) -> Self {
        let mut e = Self::new(SdkErrorCode::RateLimited, message);
        e.next_allowed_at = next_allowed_at;
        e
    }
}

impl std::fmt::Display for DirectiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for DirectiveError {}

type WriteFn<'a> = &'a dyn Fn(&Path, &[u8]) -> Result<(), PlatformError>;

/// Injected filesystem primitives for the write pipeline.
pub struct FsOps<'a> {
    /// Create the tmp file with the payload, mode 0600 at creation.
    pub write_tmp: WriteFn<'a>,
    /// Narrow the tmp file's mode.
    pub secure: &'a dyn Fn(&Path) -> Result<(), PlatformError>,
    /// Rename the tmp over the target.
    pub replace: &'a dyn Fn(&Path, &Path) -> Result<(), PlatformError>,
}

/// The real `platform::fs` primitives.
#[must_use]
pub fn real_fs() -> FsOps<'static> {
    FsOps {
        write_tmp: &write_new_private,
        secure: &secure_file,
        replace: &atomic_replace,
    }
}

/// Injected clock and filesystem.
pub struct Env<'a> {
    /// Unix seconds "now".
    pub now: u64,
    /// Write primitives.
    pub fs: &'a FsOps<'a>,
}

/// Injected host and liveness, used only by [`deliver_inner`].
pub struct Live<'a> {
    /// This host's name.
    pub host: &'a str,
    /// Start time (unix seconds) of a live pid, `None` when no such process.
    pub proc_start: &'a dyn Fn(u32) -> Option<u64>,
    /// Whether the pid's liveness could not be READ (a live process whose info was
    /// unreadable, as opposed to one that is gone). `true` makes a delivery to it
    /// `undetermined`, never `target_mismatch`, and keeps its records out of eviction.
    pub unreadable: &'a dyn Fn(u32) -> bool,
    /// Whether `(pid, started_at)` is a listed Claude Code session.
    pub is_listed: &'a dyn Fn(u32, u64) -> bool,
    /// The listed session's canonical handle dir (its `CLAUDE_CONFIG_DIR`); recorded at
    /// delivery so the statusline can tie a pid marker back to the session.
    pub handle_dir_of: &'a dyn Fn(u32, u64) -> Option<PathBuf>,
}

/// What the statusline and the session listing need about one session's inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingInfo {
    /// Directives currently `queued` or `surfaced` (not expired, not acknowledged).
    pub pending: usize,
    /// `queued_at` of the newest directive addressed to the session, any status.
    pub last_directive_at: Option<u64>,
    /// `summary` of the oldest pending directive.
    pub first_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    directive: Directive,
    queued_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    surfaced_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acknowledged_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ack: Option<DirectiveAck>,
    /// Canonical handle dir of the target session at delivery. Internal: never on a wire DTO.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handle_dir: Option<String>,
    /// The target's start time as the LIVE session listing read it at delivery. Internal:
    /// never on a wire DTO. The wire `target.started_at` may be off by the tolerance, and
    /// two different wire values for one session do not match each other (the tolerance is
    /// not transitive), so every comparison BETWEEN records uses this exact value; only a
    /// comparison with a CURRENT reading uses [`same_start`]. `None` in a record written
    /// before this field existed, which falls back to the wire value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    live_start: Option<u64>,
}

impl Record {
    fn status(&self, now: u64) -> &'static str {
        if self.acknowledged_at.is_some() {
            "acknowledged"
        } else if now >= self.directive.expires_at {
            "expired"
        } else if self.surfaced_at.is_some() {
            "surfaced"
        } else {
            "queued"
        }
    }

    fn last_transition(&self, now: u64) -> u64 {
        let mut t = self.queued_at;
        for v in [self.surfaced_at, self.acknowledged_at]
            .into_iter()
            .flatten()
        {
            t = t.max(v);
        }
        if self.status(now) == "expired" {
            t = t.max(self.directive.expires_at);
        }
        t
    }

    fn receipt(&self, now: u64) -> DirectiveReceipt {
        DirectiveReceipt::new(
            self.directive.id.clone(),
            self.status(now),
            self.queued_at,
            self.directive.expires_at,
        )
        .with_surfaced_at(self.surfaced_at)
        .with_acknowledged_at(self.acknowledged_at)
        .with_ack(self.ack.clone())
    }

    /// The start time every comparison uses: the live reading stored at delivery, else the
    /// wire value (a record from before `live_start` existed).
    fn start(&self) -> u64 {
        self.live_start.unwrap_or(self.directive.target.started_at)
    }

    /// Whether this record is addressed to the session whose CURRENT reading is
    /// `(pid, started_at)`: the stored live start is compared with [`same_start`], since
    /// Linux derives a start time from `btime`, which can move a second between reads.
    fn targets(&self, pid: u32, started_at: u64) -> bool {
        self.directive.target.pid == pid && same_start(self.start(), started_at)
    }

    /// Whether two RECORDS address the same session: exact equality on the stored live
    /// start, because [`same_start`] is not transitive between two records.
    fn same_session(&self, pid: u32, live_start: u64) -> bool {
        self.directive.target.pid == pid && self.start() == live_start
    }

    fn pending(&self, now: u64) -> bool {
        matches!(self.status(now), "queued" | "surfaced")
    }
}

/// What remains of an acknowledged record once it is evicted before it expires: enough to
/// refuse a re-submission of the same id (`doc_sha256` tells "the same document" from "a
/// different one"), but no receipt, so nothing the issuer could read back is invented.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Tombstone {
    id: String,
    doc_sha256: String,
    expires_at: u64,
    /// The directive's `issued_at`; 0 on an entry written before this field existed.
    #[serde(default)]
    issued_at: u64,
}

/// The in-memory view of the tombstones and the replay horizon. `tombstones.json` is a bare
/// array of [`Tombstone`]; the horizon lives in its own file ([`HORIZON_FILE`]). A tombstone
/// that is lost (quarantined file, or dropped at the cap) can no longer refuse its id, so the
/// horizon is raised first: a directive issued before it is refused whatever its id.
#[derive(Debug, Clone, Default)]
struct TombstoneFile {
    refuse_issued_before: Option<u64>,
    tombstones: Vec<Tombstone>,
}

/// SHA-256 (hex) of the directive's canonical serialization: one struct, one byte string.
fn doc_hash(d: &Directive) -> Result<String, DirectiveError> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(d)
        .map_err(|_| DirectiveError::undet("directive store: serialize failed"))?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn store_dir(base_dir: &Path) -> PathBuf {
    base_dir.join("directives")
}

pub(crate) fn canonical_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s)
        .map(|u| u.hyphenated().to_string() == s)
        .unwrap_or(false)
}

/// The Unicode `Default_Ignorable_Code_Point` property (Unicode 15.1,
/// `DerivedCoreProperties.txt`) as explicit inclusive ranges: code points a renderer may
/// draw as nothing, so text containing them reads differently from what it holds (variation
/// selectors, the combining grapheme joiner, Hangul fillers, Mongolian free variation
/// selectors, zero-width and bidi controls, tag characters, ...). It includes unassigned
/// code points inside those blocks, which is intended.
const DEFAULT_IGNORABLE: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

/// U+2800 BRAILLE PATTERN BLANK: assigned (So) and not default-ignorable, but it draws as
/// blank space, so it hides text exactly like a default-ignorable character.
const BRAILLE_BLANK: char = '\u{2800}';

fn default_ignorable(c: char) -> bool {
    let u = c as u32;
    DEFAULT_IGNORABLE
        .iter()
        .any(|&(lo, hi)| (lo..=hi).contains(&u))
}

/// Hidden or control characters that are forbidden whatever the Unicode version: controls
/// (Cc), format (Cf), line/paragraph separators (Zl/Zp), private use (Co), surrogates (Cs),
/// every `Default_Ignorable_Code_Point` and U+2800. Excludes Cn (unassigned).
fn hidden_char(c: char) -> bool {
    if c.is_ascii() {
        return c.is_control();
    }
    c.is_control()
        || c == BRAILLE_BLANK
        || default_ignorable(c)
        || matches!(
            get_general_category({
                #[cfg(all(test, unix))]
                crate::ascii_probe::hit("op_unicode_category");
                c
            }),
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
                | GeneralCategory::PrivateUse
                | GeneralCategory::Surrogate
        )
}

/// The one shared predicate for characters that are never legitimate in a directive text
/// field and are never shown raw: the private `hidden_char` set plus Cn (unassigned code points). Used at
/// `deliver`, at render, and by the human session table.
#[must_use]
pub fn is_forbidden_char(c: char) -> bool {
    if c.is_ascii() {
        return c.is_control();
    }
    hidden_char(c)
        || get_general_category({
            #[cfg(all(test, unix))]
            crate::ascii_probe::hit("op_unicode_category");
            c
        }) == GeneralCategory::Unassigned
}

/// [`is_forbidden_char`] plus combining marks (Mn, Me): what the human session table
/// escapes, since a mark can alter or stack over the character before it.
#[must_use]
pub fn is_display_unsafe(c: char) -> bool {
    is_forbidden_char(c)
        || matches!(
            get_general_category(c),
            GeneralCategory::NonspacingMark | GeneralCategory::EnclosingMark
        )
}

/// Whether `s` contains a character [`is_forbidden_char`] refuses.
#[must_use]
pub fn has_forbidden_char(s: &str) -> bool {
    s.chars().any(is_forbidden_char)
}

/// `s` with every display-unsafe character dropped (every forbidden character plus the
/// combining marks Mn and Me, [`is_display_unsafe`]); the render-time re-sanitise for text
/// read back from the store (defence in depth behind the check at `deliver`). A combining
/// mark is accepted in directive text but would stack over the character before it on the
/// statusline, so it is dropped here rather than refused at `deliver`.
#[must_use]
pub fn sanitize_display(s: &str) -> String {
    s.chars().filter(|c| !is_display_unsafe(*c)).collect()
}

fn check_text(
    label: &str,
    s: &str,
    allow_empty: bool,
    forbidden: fn(char) -> bool,
) -> Result<(), DirectiveError> {
    if !allow_empty && s.is_empty() {
        return Err(DirectiveError::invalid(format!(
            "{label} must not be empty"
        )));
    }
    if s.chars().count() > MAX_TEXT_CHARS {
        return Err(DirectiveError::invalid(format!(
            "{label} exceeds {MAX_TEXT_CHARS} characters"
        )));
    }
    if s.chars().any(forbidden) {
        return Err(DirectiveError::invalid(format!(
            "{label} contains control or hidden characters"
        )));
    }
    Ok(())
}

fn valid_issuer(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Every text field of a directive (`summary`, `suggested`, `why.metric`, `why.source`,
/// `scope`): length, emptiness, forbidden characters. `forbidden` is
/// [`is_forbidden_char`] at `deliver` and [`hidden_char`] when re-checking a record loaded
/// from disk: a newer csq may have accepted a character an older csq still sees as
/// unassigned (Cn), and that must not make the record unreadable.
fn check_directive_text(d: &Directive, forbidden: fn(char) -> bool) -> Result<(), DirectiveError> {
    check_text("summary", &d.summary, false, forbidden)?;
    if d.suggested.len() > MAX_SUGGESTED {
        return Err(DirectiveError::invalid(format!(
            "suggested has more than {MAX_SUGGESTED} entries"
        )));
    }
    for s in &d.suggested {
        check_text("suggested entry", s, false, forbidden)?;
    }
    check_text("why.metric", &d.why.metric, false, forbidden)?;
    check_text("why.source", &d.why.source, false, forbidden)?;
    if let Some(scope) = &d.scope {
        check_text("scope", scope, true, forbidden)?;
    }
    Ok(())
}

/// Contract §3 rows 1-2: shape, vocabulary, limits, scope.
fn validate_shape(raw: &str) -> Result<Directive, DirectiveError> {
    let d: Directive = serde_json::from_str(raw).map_err(|_| {
        DirectiveError::invalid("directive is not a valid csq.directive.v1 document")
    })?;
    if d.schema != "csq.directive.v1" {
        return Err(DirectiveError::invalid("schema must be csq.directive.v1"));
    }
    if !canonical_uuid(&d.id) {
        return Err(DirectiveError::invalid(
            "id must be a lowercase hyphenated UUID",
        ));
    }
    if !valid_issuer(&d.issuer) {
        return Err(DirectiveError::invalid("issuer must match [a-z0-9-]{1,64}"));
    }
    if !KINDS.contains(&d.kind.as_str()) {
        return Err(DirectiveError::invalid(
            "kind is not a known directive kind",
        ));
    }
    check_directive_text(&d, is_forbidden_char)?;
    let deleting = matches!(d.kind.as_str(), "delete_scratch" | "free_disk");
    match d.scope.as_deref() {
        Some(DELETE_SCOPE) => {}
        None if !deleting => {}
        None => {
            return Err(DirectiveError::invalid(format!(
                "kind {} requires scope \"{DELETE_SCOPE}\"",
                d.kind
            )))
        }
        Some(_) => {
            return Err(DirectiveError::invalid(format!(
                "scope must be absent or exactly \"{DELETE_SCOPE}\""
            )))
        }
    }
    Ok(d)
}

// ── store primitives ────────────────────────────────────────────────

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// `Ok(true)` when `dir` exists as a real directory, `Ok(false)` when absent; a symlink, a
/// non-directory or an unreadable path is `Undetermined`. Uses `symlink_metadata`: a
/// symlink is never followed, and `try_exists` (which follows) is not used for presence.
pub(crate) fn check_store_dir_as(label: &str, dir: &Path) -> Result<bool, DirectiveError> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => {
            Err(DirectiveError::undet(format!("{label}: dir is a symlink")))
        }
        Ok(m) if !m.is_dir() => Err(DirectiveError::undet(format!("{label}: not a directory"))),
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(DirectiveError::undetermined(
            &format!("{label}: stat dir"),
            e.kind(),
        )),
    }
}

pub(crate) fn ensure_dir_as(label: &str, dir: &Path) -> Result<(), DirectiveError> {
    if !check_store_dir_as(label, dir)? {
        create_private_dir(dir)
            .map_err(|e| DirectiveError::undetermined(&format!("{label}: create dir"), e.kind()))?;
        // Re-check: a racing creator may have put a symlink in the gap.
        check_store_dir_as(label, dir)?;
    }
    secure_dir(dir).map_err(|_| DirectiveError::undet(format!("{label}: secure dir")))
}

/// The label the directive store passes to the shared helpers; its error text is unchanged.
pub(crate) const DIRECTIVE_LABEL: &str = "directive store";

pub(crate) fn check_store_dir(dir: &Path) -> Result<bool, DirectiveError> {
    check_store_dir_as(DIRECTIVE_LABEL, dir)
}

pub(crate) fn ensure_dir(dir: &Path) -> Result<(), DirectiveError> {
    ensure_dir_as(DIRECTIVE_LABEL, dir)
}

pub(crate) fn write_atomic(
    path: &Path,
    bytes: &[u8],
    fs: &FsOps<'_>,
) -> Result<(), DirectiveError> {
    write_atomic_as(DIRECTIVE_LABEL, path, bytes, fs)
}

pub(crate) fn read_regular_bounded(path: &Path, max: u64) -> Result<Option<String>, LoadFail> {
    read_regular_bounded_as(DIRECTIVE_LABEL, path, max)
}

pub(crate) fn remove_file_only(path: &Path) -> Result<(), DirectiveError> {
    remove_file_only_as(DIRECTIVE_LABEL, path)
}

pub(crate) fn acquire_store_lock(path: &Path) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_as(DIRECTIVE_LABEL, path)
}

fn record_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// The index of one SESSION: keyed by pid AND the stored live start, because a pid is
/// reused and the pending cap is per session, not per pid.
fn index_path(dir: &Path, pid: u32, start: u64) -> PathBuf {
    dir.join(format!("pid-{pid}-{start}.idx"))
}

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A decimal csq itself writes: digits, no leading zero (`0` alone is fine).
fn canonical_decimal(s: &str) -> bool {
    all_digits(s) && (s == "0" || !s.starts_with('0'))
}

/// `(pid, Some(start))` for `pid-<pid>-<start>.idx`, `(pid, None)` for the retired
/// `pid-<pid>.idx`; `None` for any other name. Only a name this accepts is ever touched.
fn parse_index_name(name: &str) -> Option<(u32, Option<u64>)> {
    let body = name.strip_prefix("pid-")?.strip_suffix(".idx")?;
    match body.split_once('-') {
        Some((p, st)) if canonical_decimal(p) && canonical_decimal(st) => {
            Some((p.parse().ok()?, Some(st.parse().ok()?)))
        }
        None if canonical_decimal(body) => Some((body.parse().ok()?, None)),
        _ => None,
    }
}

/// `pid-007-099.idx`: EXACTLY a name whose fields are all digits, at least one of them with a
/// leading zero, and which would otherwise parse (the pid fits `u32`, the start `u64`). csq
/// never writes it; it would parse to the same numbers as `pid-7-99.idx`, so a lenient
/// parser made it an alias that the sync kept forever. A regular file of this shape is
/// removed. An all-digit name that does NOT parse (a pid over 32 bits) is not an alias and
/// is left alone, like any other name that is not csq's.
fn is_leading_zero_index_alias(name: &str) -> bool {
    let Some(body) = name
        .strip_prefix("pid-")
        .and_then(|b| b.strip_suffix(".idx"))
    else {
        return false;
    };
    let leading_zero = |f: &str| f.len() > 1 && f.starts_with('0');
    match body.split_once('-') {
        Some((p, st)) => {
            all_digits(p)
                && all_digits(st)
                && (leading_zero(p) || leading_zero(st))
                && p.parse::<u32>().is_ok()
                && st.parse::<u64>().is_ok()
        }
        None => all_digits(body) && leading_zero(body) && body.parse::<u32>().is_ok(),
    }
}

/// Write `bytes` to `path` via tmp -> secure -> replace. The tmp is removed on every
/// failure branch (`security.md` §5a) EXCEPT when `write_tmp` itself reported
/// `AlreadyExists`: the file at that name was then not created by this call and is not ours
/// to delete.
pub(crate) fn write_atomic_as(
    label: &str,
    path: &Path,
    bytes: &[u8],
    fs: &FsOps<'_>,
) -> Result<(), DirectiveError> {
    let tmp = stage_atomic_as(label, path, bytes, fs)?;
    commit_atomic_as(label, &tmp, path, fs)
}

/// The first two steps of [`write_atomic`]: a secured tmp file next to `path` holding
/// `bytes`, removed on every failure branch.
fn stage_atomic_as(
    label: &str,
    path: &Path,
    bytes: &[u8],
    fs: &FsOps<'_>,
) -> Result<PathBuf, DirectiveError> {
    let tmp = unique_tmp_path(path);
    if let Err(e) = (fs.write_tmp)(&tmp, bytes) {
        let not_ours =
            matches!(&e, PlatformError::Io(io_e) if io_e.kind() == io::ErrorKind::AlreadyExists);
        if !not_ours {
            let _ = std::fs::remove_file(&tmp);
        }
        return Err(DirectiveError::undet(format!("{label}: write failed")));
    }
    if (fs.secure)(&tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(DirectiveError::undet(format!("{label}: secure failed")));
    }
    Ok(tmp)
}

/// The last step of [`write_atomic`]: rename the staged `tmp` over `path`, removing it on failure.
fn commit_atomic_as(
    label: &str,
    tmp: &Path,
    path: &Path,
    fs: &FsOps<'_>,
) -> Result<(), DirectiveError> {
    if (fs.replace)(tmp, path).is_err() {
        let _ = std::fs::remove_file(tmp);
        return Err(DirectiveError::undet(format!("{label}: replace failed")));
    }
    Ok(())
}

fn save(dir: &Path, rec: &Record, fs: &FsOps<'_>) -> Result<(), DirectiveError> {
    let bytes = serde_json::to_vec(rec)
        .map_err(|_| DirectiveError::undet("directive store: serialize failed"))?;
    write_atomic(&record_path(dir, &rec.directive.id), bytes.as_slice(), fs)
}

/// Why a store file could not be loaded: its CONTENT is bad (the lock holder quarantines
/// it) or the filesystem could not be read (never quarantined, never guessed at).
pub(crate) enum LoadFail {
    Bad(&'static str),
    Io(DirectiveError),
}

impl LoadFail {
    pub(crate) fn into_err(self) -> DirectiveError {
        match self {
            Self::Bad(m) => DirectiveError::undet(format!("directive store: {m}")),
            Self::Io(e) => e,
        }
    }

    /// [`Self::into_err`] for a store other than the directive store: `label` names it.
    pub(crate) fn into_err_as(self, label: &str) -> DirectiveError {
        match self {
            Self::Bad(m) => DirectiveError::undet(format!("{label}: {m}")),
            Self::Io(e) => e,
        }
    }
}

/// `FILE_FLAG_OPEN_REPARSE_POINT` from the Win32 API (`winbase.h`).
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Open for reading without following a symlink and without blocking on a FIFO swapped in
/// for a regular file.
fn open_nofollow(path: &Path) -> io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open a reparse point (symlink, junction) AS ITSELF rather than its target; the
        // `is_file()` check on the handle then rejects it.
        o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    o.open(path)
}

fn is_symlink_refusal(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ELOOP)
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

/// Whether an `open` failure is a property of the ENTRY (permissions, file type) rather
/// than of the system: `EACCES`/`EPERM`, `ENXIO` (a socket or an orphaned FIFO end),
/// `EISDIR`, `ENODEV`, `EOPNOTSUPP`.
fn open_failure_is_the_entrys_fault(e: &io::Error) -> bool {
    #[cfg(unix)]
    {
        e.kind() == io::ErrorKind::PermissionDenied
            || matches!(
                e.raw_os_error(),
                Some(libc::ENXIO | libc::EISDIR | libc::ENODEV | libc::EOPNOTSUPP)
            )
    }
    #[cfg(not(unix))]
    {
        e.kind() == io::ErrorKind::PermissionDenied
    }
}

/// Read a regular file of at most `max` bytes. The decision is made on the OPEN handle
/// (`fstat`), so a swap between a directory scan and the open cannot make this read a
/// FIFO, a device or a symlink target. `Ok(None)` when it does not exist (a record that
/// vanished between readdir and open).
pub(crate) fn read_regular_bounded_as(
    label: &str,
    path: &Path,
    max: u64,
) -> Result<Option<String>, LoadFail> {
    #[cfg(not(unix))]
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(LoadFail::Bad("entry is not a regular file"))
        }
        _ => {}
    }
    let file = match open_nofollow(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if is_symlink_refusal(&e) => {
            return Err(LoadFail::Bad("entry is not a regular file"))
        }
        // An entry that cannot be OPENED because of what it is (mode 000, a socket, a
        // device) will never become readable by waiting: quarantine it so it cannot block
        // the store forever. A resource failure (EMFILE, EIO) says nothing about the
        // entry, so it stays an `Io` error and is never quarantined.
        Err(e) if open_failure_is_the_entrys_fault(&e) => {
            return Err(LoadFail::Bad("entry cannot be opened"))
        }
        Err(e) => {
            return Err(LoadFail::Io(DirectiveError::undetermined(
                &format!("{label}: open file"),
                e.kind(),
            )))
        }
    };
    let meta = file.metadata().map_err(|e| {
        LoadFail::Io(DirectiveError::undetermined(
            &format!("{label}: stat file"),
            e.kind(),
        ))
    })?;
    if !meta.is_file() {
        return Err(LoadFail::Bad("entry is not a regular file"));
    }
    if meta.len() > max {
        return Err(LoadFail::Bad("file too large"));
    }
    let mut buf = Vec::new();
    file.take(max + 1).read_to_end(&mut buf).map_err(|e| {
        LoadFail::Io(DirectiveError::undetermined(
            &format!("{label}: read file"),
            e.kind(),
        ))
    })?;
    if buf.len() as u64 > max {
        return Err(LoadFail::Bad("file too large"));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| LoadFail::Bad("file is not UTF-8"))
}

/// One record by id; `Ok(None)` when its file is gone. A record with forbidden characters
/// (Cn excepted: Unicode-version skew), a bad shape or a mismatched id is `Bad`.
fn load_record_x(path: &Path, id: &str) -> Result<Option<Record>, LoadFail> {
    let Some(text) = read_regular_bounded(path, MAX_RECORD_BYTES)? else {
        return Ok(None);
    };
    let corrupt = || LoadFail::Bad("corrupt record");
    let rec: Record = serde_json::from_str(&text).map_err(|_| corrupt())?;
    if rec.directive.id != id {
        return Err(LoadFail::Bad("record id does not match its file"));
    }
    check_directive_text(&rec.directive, hidden_char).map_err(|_| corrupt())?;
    // An `ack.outcome` this csq does not know (a newer csq wrote it) is KEPT: the record is
    // still acknowledged and receipts return the outcome unchanged. `DirectiveAck.outcome`
    // is an open `String`, so it can carry the value.
    if let Some(ack) = &rec.ack {
        if let Some(n) = &ack.note {
            check_text("note", n, true, hidden_char).map_err(|_| corrupt())?;
        }
    }
    Ok(Some(rec))
}

/// [`load_record_x`] with every failure as an `Undetermined` error (the lock-free paths).
fn load_record(path: &Path, id: &str) -> Result<Option<Record>, DirectiveError> {
    load_record_x(path, id).map_err(LoadFail::into_err)
}

/// The ids of the record files in `dir`. Stops with `Undetermined` the moment the
/// iteration passes [`MAX_SCANNED_RECORDS`] entries, rather than collecting them all.
fn list_record_ids(dir: &Path) -> Result<Vec<String>, DirectiveError> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| DirectiveError::undetermined("directive store: read dir", e.kind()))?;
    let mut ids = Vec::new();
    let mut seen = 0usize;
    for entry in rd {
        let entry = entry
            .map_err(|e| DirectiveError::undetermined("directive store: read dir", e.kind()))?;
        seen += 1;
        if seen > MAX_SCANNED_RECORDS {
            return Err(DirectiveError::undet(
                "directive store: too many records to read",
            ));
        }
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        if canonical_uuid(stem) {
            ids.push(stem.to_string());
        }
    }
    Ok(ids)
}

/// Every record in the store, lock-free. A missing directory is an empty store; any other
/// read failure or an unreadable record is `Undetermined` — never silently skipped. A
/// record that vanishes between readdir and open is skipped (it was deleted, not hidden).
fn load_all(dir: &Path) -> Result<Vec<Record>, DirectiveError> {
    if !check_store_dir(dir)? {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for id in list_record_ids(dir)? {
        if let Some(rec) = load_record(&record_path(dir, &id), &id)? {
            out.push(rec);
        }
    }
    Ok(out)
}

fn ensure_rejected_dir_as(label: &str, rej: &Path) -> Result<(), DirectiveError> {
    if !check_store_dir_as(label, rej)? {
        create_private_dir(rej).map_err(|e| {
            DirectiveError::undetermined(&format!("{label}: create rejected"), e.kind())
        })?;
        check_store_dir_as(label, rej)?;
    }
    secure_dir(rej).map_err(|_| DirectiveError::undet(format!("{label}: secure rejected")))
}

/// `rejected/` must be a real directory RIGHT NOW (`symlink_metadata`, never followed).
/// Called immediately before every `read_dir`, rename and delete that goes through it, so
/// a swap to a symlink after an earlier check cannot redirect csq into another directory.
#[cfg(not(unix))]
fn require_real_rejected_as(label: &str, rej: &Path) -> Result<(), DirectiveError> {
    if check_store_dir_as(label, rej)? {
        Ok(())
    } else {
        Err(DirectiveError::undet(format!(
            "{label}: rejected is missing"
        )))
    }
}

/// Delete one regular entry. NEVER a directory: csq deletes only with `remove_file`, so a
/// directory (or a symlink's target) can never be removed through this.
pub(crate) fn remove_file_only_as(label: &str, path: &Path) -> Result<(), DirectiveError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DirectiveError::undetermined(
            &format!("{label}: remove entry"),
            e.kind(),
        )),
    }
}

/// Process-wide quarantine counter: with the process id it makes every quarantine name
/// unique across calls and processes, so a second quarantine of the same id in the same
/// second cannot replace the first.
static QUARANTINE_SEQ: AtomicU64 = AtomicU64::new(0);
const QUARANTINE_NAME_TRIES: u32 = 64;

/// Whether `name` is one csq's quarantine produced:
/// `<20-digit time>-<pid>-<counter>-<stem>.(json|idx)` with `stem` of `[0-9a-z-]{1,64}`.
/// Only such a name is ever deleted from `rejected/`.
fn is_rejected_name(name: &str) -> bool {
    let mut parts = name.splitn(4, '-');
    let (Some(t), Some(p), Some(q), Some(rest)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some((stem, ext)) = rest.rsplit_once('.') else {
        return false;
    };
    t.len() == 20
        && all_digits(t)
        && all_digits(p)
        && all_digits(q)
        && matches!(ext, "json" | "idx")
        && (1..=64).contains(&stem.len())
        && stem
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || b == b'-')
}

/// A handle on `directives/rejected/` for the operations that rename into it, list it and
/// delete from it.
///
/// On unix, `directives/` and `rejected/` are opened ONCE with `O_DIRECTORY | O_NOFOLLOW`
/// and every later rename, listing and delete is relative to those descriptors
/// (`renameat`, `fstatat`, `unlinkat`), so no path is resolved again: a `rejected/`
/// swapped for a symlink after the open cannot redirect anything, because the descriptor
/// still names the directory that was checked. On other platforms the directory is
/// re-checked with `symlink_metadata` immediately before each operation, which narrows
/// that window but cannot close it (check-then-act).
struct RejectedHandle {
    #[cfg(unix)]
    store_fd: dirfd::DirFd,
    #[cfg(unix)]
    rej_fd: dirfd::DirFd,
    #[cfg(not(unix))]
    store: PathBuf,
    #[cfg(not(unix))]
    rej: PathBuf,
    /// Names the store in error text (`directive store`, `message store`).
    label: String,
}

#[cfg(unix)]
pub(crate) mod dirfd {
    //! Descriptor-relative directory operations. Every `unsafe` block passes a descriptor
    //! this module owns (or a NUL-terminated name that outlives the call) and has no other
    //! precondition.
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// An open directory descriptor, closed on drop.
    pub struct DirFd(libc::c_int);

    impl Drop for DirFd {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a descriptor this value opened and has not closed.
            unsafe {
                libc::close(self.0);
            }
        }
    }

    const FLAGS: libc::c_int =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    /// A single path component: `unlinkat`, `renameat` and `openat` resolve a name with a
    /// `/` (or `..`) outside the directory the descriptor names, so those are refused here,
    /// along with the empty name and `.`. A NUL cannot be passed to the kernel either.
    fn cname(name: &str) -> io::Result<CString> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }

    /// The thread's `errno` slot, where this platform's libc exposes it.
    fn errno_slot() -> Option<*mut libc::c_int> {
        // SAFETY: each of these libc functions returns a pointer to the calling thread's
        // `errno`, valid for the thread's lifetime and with no other precondition.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        return Some(unsafe { libc::__errno_location() });
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        return Some(unsafe { libc::__error() });
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd"
        )))]
        None
    }

    /// What [`DirFd::names`] read. `complete` is false when the listing stopped before the
    /// end of the directory: the cap was passed, a `readdir` error ended it, or this
    /// platform gives no way to tell a `readdir` error from the end. Only a complete
    /// listing may be used to decide what is NOT in the directory or what is newest in it.
    pub struct Listing {
        pub names: Vec<String>,
        pub complete: bool,
    }

    impl DirFd {
        /// Open `path` (its final component is not followed).
        pub fn open(path: &Path) -> io::Result<Self> {
            let c = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
            let fd = unsafe { libc::open(c.as_ptr(), FLAGS) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(fd))
            }
        }

        /// Open the child directory `name` relative to this descriptor, not following a
        /// symlink.
        pub fn open_child(&self, name: &str) -> io::Result<Self> {
            let c = cname(name)?;
            // SAFETY: `self.0` is open; `c` is a valid NUL-terminated name.
            let fd = unsafe { libc::openat(self.0, c.as_ptr(), FLAGS) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(fd))
            }
        }

        /// `fstatat(AT_SYMLINK_NOFOLLOW)`: `Ok(None)` when absent, else whether it is a directory.
        pub fn entry_is_dir(&self, name: &str) -> io::Result<Option<bool>> {
            let c = cname(name)?;
            // SAFETY: an all-zero `stat` is a valid value for the kernel to overwrite.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `self.0` is open, `c` is NUL-terminated, `st` is a valid out-pointer.
            let rc =
                unsafe { libc::fstatat(self.0, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
            if rc == 0 {
                return Ok(Some((st.st_mode & libc::S_IFMT) == libc::S_IFDIR));
            }
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            }
        }

        /// `renameat(self/from -> to_dir/to)`.
        pub fn rename_to(&self, from: &str, to_dir: &Self, to: &str) -> io::Result<()> {
            let (f, t) = (cname(from)?, cname(to)?);
            // SAFETY: both descriptors are open; both names are NUL-terminated.
            let rc = unsafe { libc::renameat(self.0, f.as_ptr(), to_dir.0, t.as_ptr()) };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        /// `unlinkat(self/name, 0)`: removes a file or symlink, NEVER a directory.
        pub fn unlink(&self, name: &str) -> io::Result<()> {
            let c = cname(name)?;
            // SAFETY: `self.0` is open; `c` is NUL-terminated; flags 0 refuses a directory.
            let rc = unsafe { libc::unlinkat(self.0, c.as_ptr(), 0) };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        pub(crate) fn raw_fd(&self) -> libc::c_int {
            self.0
        }
        pub(crate) fn metadata(&self) -> io::Result<std::fs::Metadata> {
            use std::os::fd::{BorrowedFd, OwnedFd};
            // SAFETY: self owns this still-open descriptor; the borrow does not close it.
            let borrowed = unsafe { BorrowedFd::borrow_raw(self.0) };
            let owned: OwnedFd = borrowed.try_clone_to_owned()?;
            std::fs::File::from(owned).metadata()
        }
        pub(crate) fn regular(&self, name: &str, flags: libc::c_int) -> io::Result<std::fs::File> {
            use std::os::fd::FromRawFd;
            let name = cname(name)?;
            // SAFETY: live directory fd and bounded NUL-terminated component; fixed file mode.
            let fd = unsafe {
                libc::openat(
                    self.0,
                    name.as_ptr(),
                    flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is a new owned descriptor returned by openat.
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }
        pub(crate) fn mkdir_child(&self, name: &str) -> io::Result<()> {
            let name = cname(name)?;
            // SAFETY: live directory fd and NUL-terminated single component.
            let rc = unsafe { libc::mkdirat(self.0, name.as_ptr(), 0o700) };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        /// Count raw non-dot entries before decoding; cap+1 is the overflow sentinel.
        pub(crate) fn names_strict(&self, cap: usize) -> io::Result<Listing> {
            // SAFETY: self owns the live fd; the duplicate is owned by DIR on success.
            let dup = unsafe { libc::fcntl(self.0, libc::F_DUPFD_CLOEXEC, 0) };
            if dup < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: dup is a freshly owned directory descriptor.
            let dp = unsafe { libc::fdopendir(dup) };
            if dp.is_null() {
                let error = io::Error::last_os_error();
                // SAFETY: fdopendir failed without taking ownership.
                unsafe {
                    libc::close(dup);
                }
                return Err(error);
            }
            // SAFETY: dp is a live DIR; reset the shared directory offset.
            unsafe {
                libc::rewinddir(dp);
            }
            let (mut names, mut seen) = (Vec::new(), 0usize);
            let complete = loop {
                if let Some(slot) = errno_slot() {
                    // SAFETY: slot is this thread's errno storage.
                    unsafe {
                        *slot = 0;
                    }
                }
                // SAFETY: dp remains owned and live until closedir below.
                let entry = unsafe { libc::readdir(dp) };
                if entry.is_null() {
                    // SAFETY: valid thread errno; read immediately after readdir.
                    break errno_slot().is_some_and(|slot| unsafe { *slot } == 0);
                }
                // SAFETY: readdir returned a live dirent with NUL-terminated d_name.
                let raw = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
                if matches!(raw.to_bytes(), b"." | b"..") {
                    continue;
                }
                seen += 1;
                if seen > cap {
                    break false;
                }
                let name = match raw.to_str() {
                    Ok(name) => name,
                    Err(_) => break false,
                };
                names.push(name.to_owned());
            };
            // SAFETY: dp is closed exactly once; this also closes dup.
            unsafe {
                libc::closedir(dp);
            }
            Ok(Listing { names, complete })
        }

        /// Entry names of this directory, at most `cap + 1` of them. Read through a
        /// duplicate of the descriptor, so the path is not resolved again. A listing that
        /// stops early (cap passed, or a `readdir` error) is reported with
        /// `complete == false`: it is a PREFIX of the directory in an arbitrary order, so a
        /// caller deleting "the oldest" from it can delete a newer entry it never saw.
        /// That is why such a listing must not be acted on, not the "safe direction".
        pub fn names(&self, cap: usize) -> io::Result<Listing> {
            // SAFETY: `self.0` is open. `F_DUPFD_CLOEXEC` returns a new descriptor (>= 0)
            // that is close-on-exec, so a child spawned meanwhile does not inherit it.
            let dup = unsafe { libc::fcntl(self.0, libc::F_DUPFD_CLOEXEC, 0) };
            if dup < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `dup` is a fresh descriptor; on success `fdopendir` owns it.
            let dp = unsafe { libc::fdopendir(dup) };
            if dp.is_null() {
                let e = io::Error::last_os_error();
                // SAFETY: `fdopendir` failed, so `dup` is still ours to close.
                unsafe {
                    libc::close(dup);
                }
                return Err(e);
            }
            // The duplicate shares its open file description, and so its offset, with `self.0`:
            // a second listing would otherwise start where the first stopped.
            // SAFETY: `dp` is a live DIR*.
            unsafe { libc::rewinddir(dp) };
            let mut out = Vec::new();
            let complete = loop {
                if let Some(slot) = errno_slot() {
                    // SAFETY: `slot` points at this thread's errno; `readdir` leaves it
                    // untouched at the end of the directory and sets it on error.
                    unsafe { *slot = 0 };
                }
                // SAFETY: `dp` is a live DIR* until `closedir` below.
                let ent = unsafe { libc::readdir(dp) };
                if ent.is_null() {
                    // SAFETY: as above; read straight after the `readdir` that returned NULL.
                    break errno_slot().is_some_and(|slot| unsafe { *slot } == 0);
                }
                // SAFETY: `ent` points to a valid dirent whose `d_name` is NUL-terminated.
                let raw = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
                if let Ok(n) = raw.to_str() {
                    if n != "." && n != ".." {
                        out.push(n.to_string());
                    }
                }
                if out.len() > cap {
                    break false;
                }
            };
            // SAFETY: `dp` is live and closed exactly once (closing it closes `dup`).
            unsafe {
                libc::closedir(dp);
            }
            Ok(Listing {
                names: out,
                complete,
            })
        }
    }
}

/// Run between "`rejected/` was verified" and the first operation on it; production passes
/// a no-op, a test swaps the directory there to prove the swap changes nothing.
type Window<'a> = &'a dyn Fn();

impl RejectedHandle {
    #[cfg(unix)]
    fn open(label: &str, dir: &Path, window: Window<'_>) -> Result<Self, DirectiveError> {
        let refused = |e: io::Error| match e.raw_os_error() {
            Some(libc::ELOOP | libc::ENOTDIR) => {
                DirectiveError::undet(format!("{label}: rejected is not a real directory"))
            }
            _ if e.kind() == io::ErrorKind::NotFound => {
                DirectiveError::undet(format!("{label}: rejected is missing"))
            }
            _ => DirectiveError::undetermined(&format!("{label}: open rejected"), e.kind()),
        };
        let store_fd = dirfd::DirFd::open(dir).map_err(refused)?;
        let rej_fd = store_fd.open_child(REJECTED_DIR).map_err(refused)?;
        window();
        Ok(Self {
            store_fd,
            rej_fd,
            label: label.to_string(),
        })
    }

    #[cfg(not(unix))]
    fn open(label: &str, dir: &Path, window: Window<'_>) -> Result<Self, DirectiveError> {
        let rej = dir.join(REJECTED_DIR);
        require_real_rejected_as(label, &rej)?;
        window();
        Ok(Self {
            store: dir.to_path_buf(),
            rej,
            label: label.to_string(),
        })
    }

    /// Whether `name` already exists in `rejected/` (of any type, a symlink not followed).
    fn taken(&self, name: &str) -> Result<bool, DirectiveError> {
        let label = self.label.as_str();
        #[cfg(unix)]
        let r = self.rej_fd.entry_is_dir(name).map(|e| e.is_some());
        #[cfg(not(unix))]
        let r = match std::fs::symlink_metadata(self.rej.join(name)) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        };
        r.map_err(|e| DirectiveError::undetermined(&format!("{label}: quarantine"), e.kind()))
    }

    /// Move `src_name` (an entry of the store directory) to `dest_name` in `rejected/`.
    fn move_in(&self, src_name: &str, dest_name: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.store_fd.rename_to(src_name, &self.rej_fd, dest_name)
        }
        #[cfg(not(unix))]
        {
            require_real_rejected_as(&self.label, &self.rej)
                .map_err(|_| io::Error::other("rejected"))?;
            std::fs::rename(self.store.join(src_name), self.rej.join(dest_name))
        }
    }

    /// Names in `rejected/` with whether each is a directory; at most `cap + 1` names. The
    /// flag is whether the listing reached the end of the directory.
    fn entries(&self, cap: usize) -> Result<(Vec<(String, bool)>, bool), DirectiveError> {
        let label = self.label.as_str();
        let err = |e: io::Error| {
            DirectiveError::undetermined(&format!("{label}: read rejected"), e.kind())
        };
        #[cfg(unix)]
        {
            let mut out = Vec::new();
            let listing = self.rej_fd.names(cap).map_err(err)?;
            for n in listing.names {
                // Gone between the listing and the stat: skip it.
                if let Some(is_dir) = self.rej_fd.entry_is_dir(&n).map_err(err)? {
                    out.push((n, is_dir));
                }
            }
            Ok((out, listing.complete))
        }
        #[cfg(not(unix))]
        {
            require_real_rejected_as(&self.label, &self.rej)?;
            let mut out = Vec::new();
            let mut complete = true;
            for entry in std::fs::read_dir(&self.rej).map_err(err)? {
                let entry = entry.map_err(err)?;
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                out.push((name, entry.file_type().is_ok_and(|t| t.is_dir())));
                if out.len() > cap {
                    complete = false;
                    break;
                }
            }
            Ok((out, complete))
        }
    }

    /// Delete one non-directory entry of `rejected/`; already gone is success.
    fn unlink(&self, name: &str) -> Result<(), DirectiveError> {
        let label = self.label.as_str();
        #[cfg(unix)]
        let r = self.rej_fd.unlink(name);
        #[cfg(not(unix))]
        let r = {
            require_real_rejected_as(&self.label, &self.rej)?;
            std::fs::remove_file(self.rej.join(name))
        };
        match r {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(DirectiveError::undetermined(
                &format!("{label}: remove entry"),
                e.kind(),
            )),
        }
    }
}

/// The three fixed-vocabulary events the shared quarantine/prune helpers log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreLog {
    /// A bad entry was moved to `rejected/`.
    Quarantined,
    /// `rejected/` was not listed to the end; nothing was pruned.
    ScanIncomplete,
    /// A directory inside `rejected/` was left alone.
    DirSkipped,
}

/// The `(error_kind, message)` a shared helper logs for `event` in the store named by
/// `label`. The directive store keeps its original tags and text exactly; any other store
/// logs `message_*` so a log line names the store it came from. Fixed text only.
pub(crate) fn store_log_text(label: &str, event: StoreLog) -> (&'static str, &'static str) {
    let directive = label == DIRECTIVE_LABEL;
    match (event, directive) {
        (StoreLog::Quarantined, true) => (
            "directive_record_quarantined",
            "a bad directive store entry was moved to rejected/",
        ),
        (StoreLog::Quarantined, false) => (
            "message_record_quarantined",
            "a bad message store entry was moved to rejected/",
        ),
        (StoreLog::ScanIncomplete, true) => (
            "directive_rejected_scan_incomplete",
            "rejected/ was not listed to the end; nothing was pruned",
        ),
        (StoreLog::ScanIncomplete, false) => (
            "message_rejected_scan_incomplete",
            "rejected/ was not listed to the end; nothing was pruned",
        ),
        (StoreLog::DirSkipped, true) => (
            "directive_rejected_dir_skipped",
            "a directory inside rejected/ was left alone",
        ),
        (StoreLog::DirSkipped, false) => (
            "message_rejected_dir_skipped",
            "a directory inside rejected/ was left alone",
        ),
    }
}

/// Move one bad store entry (a record or an index, of ANY file type) into `rejected/`
/// under a name no earlier entry has; never overwrites. A name already taken is skipped
/// to the next counter value.
fn quarantine_entry(
    dir: &Path,
    src: &Path,
    stem: &str,
    ext: &str,
    now: u64,
) -> Result<(), DirectiveError> {
    quarantine_entry_in(dir, src, stem, ext, now, &|| {})
}

fn quarantine_entry_in_as(
    label: &str,
    dir: &Path,
    src: &Path,
    stem: &str,
    ext: &str,
    now: u64,
    window: Window<'_>,
) -> Result<(), DirectiveError> {
    let rej = dir.join(REJECTED_DIR);
    ensure_rejected_dir_as(label, &rej)?;
    let src_name = match (src.parent(), src.file_name().and_then(|n| n.to_str())) {
        (Some(p), Some(n)) if p == dir => n,
        _ => {
            return Err(DirectiveError::undet(format!(
                "{label}: quarantine source is not in the store"
            )))
        }
    };
    let handle = RejectedHandle::open(label, dir, window)?;
    for _ in 0..QUARANTINE_NAME_TRIES {
        let seq = QUARANTINE_SEQ.fetch_add(1, Ordering::Relaxed);
        let dest = format!(
            "{now:020}-{:010}-{seq:010}-{stem}.{ext}",
            std::process::id()
        );
        if handle.taken(&dest)? {
            continue;
        }
        match handle.move_in(src_name, &dest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(DirectiveError::undetermined(
                    &format!("{label}: quarantine"),
                    e.kind(),
                ))
            }
        }
        // Fixed tag only: never the id, the path or any record text.
        let (kind, what) = store_log_text(label, StoreLog::Quarantined);
        tracing::warn!(error_kind = kind, "{what}");
        return Ok(());
    }
    Err(DirectiveError::undet(format!(
        "{label}: no free quarantine name"
    )))
}

fn quarantine_entry_in(
    dir: &Path,
    src: &Path,
    stem: &str,
    ext: &str,
    now: u64,
    window: Window<'_>,
) -> Result<(), DirectiveError> {
    quarantine_entry_in_as(DIRECTIVE_LABEL, dir, src, stem, ext, now, window)
}

/// [`quarantine_entry`] for a store other than the directive store: `label` names it in
/// every error.
pub(crate) fn quarantine_entry_as(
    label: &str,
    dir: &Path,
    src: &Path,
    stem: &str,
    ext: &str,
    now: u64,
) -> Result<(), DirectiveError> {
    quarantine_entry_in_as(label, dir, src, stem, ext, now, &|| {})
}

/// Keep only the newest [`MAX_REJECTED`] csq-named entries of `rejected/`. Deletes with
/// `unlinkat` / `remove_file` only: a directory inside `rejected/` is logged, skipped and
/// not counted, and an entry whose name is not csq's own is never touched. A listing that
/// stops early (after [`MAX_SCANNED_RECORDS`] entries, or on a `readdir` error) prunes nothing.
fn prune_rejected(dir: &Path) -> Result<(), DirectiveError> {
    prune_rejected_in(dir, &|| {})
}

fn prune_rejected_in_as(label: &str, dir: &Path, window: Window<'_>) -> Result<(), DirectiveError> {
    let handle = RejectedHandle::open(label, dir, window)?;
    let (listed, complete) = handle.entries(MAX_SCANNED_RECORDS)?;
    for name in rejected_to_prune(label, listed, complete) {
        handle.unlink(&name)?;
    }
    Ok(())
}

fn prune_rejected_in(dir: &Path, window: Window<'_>) -> Result<(), DirectiveError> {
    prune_rejected_in_as(DIRECTIVE_LABEL, dir, window)
}

/// [`prune_rejected`] for a store other than the directive store.
pub(crate) fn prune_rejected_as(label: &str, dir: &Path) -> Result<(), DirectiveError> {
    prune_rejected_in_as(label, dir, &|| {})
}

/// The csq-named entries of a `rejected/` listing to delete: all but the newest
/// [`MAX_REJECTED`]. A listing that did not reach the end of the directory (the scan cap, or
/// a `readdir` error) is a prefix in directory order, so "the oldest of what was seen" can be
/// newer than entries never seen: it deletes NOTHING this time and logs a fixed tag.
fn rejected_to_prune(label: &str, listed: Vec<(String, bool)>, complete: bool) -> Vec<String> {
    if !complete || listed.len() > MAX_SCANNED_RECORDS {
        let (kind, what) = store_log_text(label, StoreLog::ScanIncomplete);
        tracing::warn!(error_kind = kind, "{what}");
        return Vec::new();
    }
    let mut names = Vec::new();
    for (name, is_dir) in listed {
        if is_dir {
            let (kind, what) = store_log_text(label, StoreLog::DirSkipped);
            tracing::warn!(error_kind = kind, "{what}");
            continue;
        }
        if is_rejected_name(&name) {
            names.push(name);
        }
    }
    names.sort();
    let excess = names.len().saturating_sub(MAX_REJECTED);
    names.truncate(excess);
    names
}

/// Every record in the store, under the lock: a record whose CONTENT is bad, or that cannot
/// be opened because of what it is, is moved to `rejected/` and skipped, so one bad file
/// cannot block the store. A resource failure (could not stat/read) is still `Undetermined`.
fn load_all_quarantining(dir: &Path, now: u64) -> Result<Vec<Record>, DirectiveError> {
    let mut out = Vec::new();
    let mut moved = 0usize;
    for id in list_record_ids(dir)? {
        match load_record_x(&record_path(dir, &id), &id) {
            Ok(Some(rec)) => out.push(rec),
            Ok(None) => {}
            Err(LoadFail::Bad(_)) => {
                quarantine_entry(dir, &record_path(dir, &id), &id, "json", now)?;
                moved += 1;
            }
            Err(LoadFail::Io(e)) => return Err(e),
        }
    }
    if moved > 0 {
        prune_rejected(dir)?;
    }
    Ok(out)
}

/// The ids listed in the index of session `(pid, start)`; a missing index is an empty list.
fn read_index(dir: &Path, pid: u32, start: u64) -> Result<Vec<String>, DirectiveError> {
    let Some(text) = read_regular_bounded(&index_path(dir, pid, start), MAX_INDEX_BYTES)
        .map_err(LoadFail::into_err)?
    else {
        return Ok(Vec::new());
    };
    let ids: Vec<String> = serde_json::from_str(&text)
        .map_err(|_| DirectiveError::undet("directive store: corrupt index"))?;
    if ids.len() > MAX_SCANNED_RECORDS || !ids.iter().all(|i| canonical_uuid(i)) {
        return Err(DirectiveError::undet("directive store: corrupt index"));
    }
    Ok(ids)
}

/// Make the per-session indexes list exactly the PENDING ids of `records`: move aside any
/// index path that is not a regular file (so it can be rewritten), write the ones that
/// differ (an unchanged index is not rewritten), remove regular index files whose session
/// has nothing pending (including the retired `pid-<pid>.idx` form). Never deletes a
/// directory. Runs under the store lock after every locked operation.
fn sync_index(
    dir: &Path,
    records: &[Record],
    now: u64,
    fs: &FsOps<'_>,
) -> Result<(), DirectiveError> {
    let mut by_session: BTreeMap<(u32, u64), Vec<String>> = BTreeMap::new();
    for r in records.iter().filter(|r| r.pending(now)) {
        by_session
            .entry((r.directive.target.pid, r.start()))
            .or_default()
            .push(r.directive.id.clone());
    }
    // One bounded scan of the store directory, counted while iterating.
    let rd = std::fs::read_dir(dir)
        .map_err(|e| DirectiveError::undetermined("directive store: read dir", e.kind()))?;
    let mut present: Vec<(String, bool)> = Vec::new();
    let mut seen = 0usize;
    for entry in rd {
        let entry = entry
            .map_err(|e| DirectiveError::undetermined("directive store: read dir", e.kind()))?;
        seen += 1;
        if seen > MAX_SCANNED_RECORDS {
            return Err(DirectiveError::undet(
                "directive store: too many records to read",
            ));
        }
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if parse_index_name(&name).is_none() && !is_leading_zero_index_alias(&name) {
            continue;
        }
        // `DirEntry::file_type` does not follow a symlink: a link is NOT a regular file.
        let regular = entry.file_type().is_ok_and(|t| t.is_file());
        present.push((name, regular));
    }
    // One bad index entry must not stop every other index from being written: each step
    // that fails is logged with a fixed tag, the entry it concerns is skipped, and the FIRST
    // failure is returned at the end so the caller still sees the sync was incomplete.
    let mut first_err: Option<DirectiveError> = None;
    let mut note = |e: DirectiveError, tag_logged: &mut bool| {
        if !*tag_logged {
            tracing::warn!(
                error_kind = "directive_index_entry_skipped",
                "a directive index entry could not be repaired and was skipped"
            );
            *tag_logged = true;
        }
        first_err.get_or_insert(e);
    };
    let mut logged = false;
    let mut stuck = BTreeSet::new();
    let mut moved_aside = BTreeSet::new();
    for (name, regular) in &present {
        if !regular {
            let stem = name.strip_suffix(".idx").unwrap_or(name);
            match quarantine_entry(dir, &dir.join(name), stem, "idx", now) {
                Ok(()) => {
                    moved_aside.insert(name.clone());
                }
                Err(e) => {
                    stuck.insert(name.clone());
                    note(e, &mut logged);
                }
            }
        }
    }
    if !moved_aside.is_empty() {
        if let Err(e) = prune_rejected(dir) {
            note(e, &mut logged);
        }
    }
    for (&(pid, start), ids) in &mut by_session {
        ids.sort();
        let name = format!("pid-{pid}-{start}.idx");
        if stuck.contains(&name) {
            continue;
        }
        if read_index(dir, pid, start).ok().as_ref() != Some(ids) {
            let written = serde_json::to_vec(ids)
                .map_err(|_| DirectiveError::undet("directive store: serialize failed"))
                .and_then(|bytes| write_atomic(&index_path(dir, pid, start), bytes.as_slice(), fs));
            if let Err(e) = written {
                note(e, &mut logged);
            }
        }
    }
    for (name, regular) in &present {
        if !regular || moved_aside.contains(name) || stuck.contains(name) {
            continue;
        }
        let wanted = matches!(
            parse_index_name(name),
            Some((pid, Some(start))) if by_session.contains_key(&(pid, start))
        );
        if !wanted {
            if let Err(e) = remove_file_only(&dir.join(name)) {
                note(e, &mut logged);
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// Remove `*.tmp.*` leftovers (a crash between write and rename) at least
/// [`STALE_TMP_SECS`] old. A fresh one may belong to a live writer and is left alone.
fn sweep_stale_tmp(dir: &Path, now: u64) -> Result<(), DirectiveError> {
    sweep_stale_tmp_as(DIRECTIVE_LABEL, dir, now, MAX_SCANNED_RECORDS)
}

/// [`sweep_stale_tmp`] for a store other than the directive store: `label` names it in every
/// error. Same policy: only a regular `*.tmp.*` file at least [`STALE_TMP_SECS`] old goes.
/// `scan_cap` is the entry count past which the sweep gives up as undetermined; a store
/// passes the cap its own loader uses, so a store that is legitimately full is still swept.
pub(crate) fn sweep_stale_tmp_as(
    label: &str,
    dir: &Path,
    now: u64,
    scan_cap: usize,
) -> Result<(), DirectiveError> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| DirectiveError::undetermined(&format!("{label}: read dir"), e.kind()))?;
    let mut seen = 0usize;
    for entry in rd {
        let entry = entry
            .map_err(|e| DirectiveError::undetermined(&format!("{label}: read dir"), e.kind()))?;
        seen += 1;
        if seen > scan_cap {
            return Err(DirectiveError::undet(format!(
                "{label}: too many records to read"
            )));
        }
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.contains(".tmp."))
        {
            continue;
        }
        let meta = match std::fs::symlink_metadata(entry.path()) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(DirectiveError::undetermined(
                    &format!("{label}: stat tmp"),
                    e.kind(),
                ))
            }
        };
        if !meta.file_type().is_file() {
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let Some(modified) = modified else { continue };
        if now.saturating_sub(modified) >= STALE_TMP_SECS {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(DirectiveError::undetermined(
                        &format!("{label}: tmp remove"),
                        e.kind(),
                    ))
                }
            }
        }
    }
    Ok(())
}

/// Delete records whose last transition is at least [`RETENTION_SECS`] old; return the rest.
fn sweep(dir: &Path, now: u64, records: Vec<Record>) -> Result<Vec<Record>, DirectiveError> {
    let mut keep = Vec::with_capacity(records.len());
    for rec in records {
        if rec.last_transition(now).saturating_add(RETENTION_SECS) <= now {
            match std::fs::remove_file(record_path(dir, &rec.directive.id)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(DirectiveError::undetermined(
                        "directive store: gc remove",
                        e.kind(),
                    ))
                }
            }
        } else {
            keep.push(rec);
        }
    }
    Ok(keep)
}

/// Holds the store lock; released on drop.
pub(crate) struct StoreLock {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(not(unix))]
    _guard: crate::platform::lock::FileLockGuard,
}

#[cfg(unix)]
impl StoreLock {
    /// True when `path` still names the exact inode (dev+ino, not a symlink) this guard holds.
    fn names_path(&self, path: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let (Ok(held), Ok(named)) = (self._file.metadata(), std::fs::symlink_metadata(path)) else {
            return false;
        };
        (held.dev(), held.ino()) == (named.dev(), named.ino())
    }

    /// Cooperatively confirm the named lock is the private same-UID inode we hold.
    pub(crate) fn matches_path(&self, path: &Path) -> Result<(), DirectiveError> {
        use std::os::unix::fs::MetadataExt;
        let refused =
            || DirectiveError::undet("message storage: original lock identity unavailable");
        let held = self._file.metadata().map_err(|_| refused())?;
        let named = std::fs::symlink_metadata(path).map_err(|_| refused())?;
        // SAFETY: geteuid has no arguments and no Rust memory preconditions.
        let uid = unsafe { libc::geteuid() };
        for meta in [&held, &named] {
            if !meta.is_file()
                || meta.uid() != uid
                || meta.mode() & 0o7777 != 0o600
                || meta.nlink() != 1
            {
                return Err(refused());
            }
        }
        if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
            return Err(refused());
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for StoreLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // Closing our file alone leaves flock held while an unrelated fork child still
        // holds the shared open description. Unlock it explicitly at the guard boundary.
        // SAFETY: the guard owns this valid open descriptor; flock touches no Rust memory.
        unsafe {
            libc::flock(self._file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Held existing lock and directory for positive-only request recovery.
#[cfg(unix)]
pub(crate) struct ExistingMessageStoreLock {
    lock: StoreLock,
    directory: std::fs::File,
    path: PathBuf,
}

#[cfg(unix)]
impl ExistingMessageStoreLock {
    pub(crate) fn matches_path(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        let same = |held: &std::fs::File, path: &Path, directory: bool| {
            let Ok(a) = held.metadata() else { return false };
            let Ok(b) = std::fs::symlink_metadata(path) else {
                return false;
            };
            a.dev() == b.dev()
                && a.ino() == b.ino()
                && !b.file_type().is_symlink()
                && (if directory {
                    b.is_dir()
                } else {
                    b.is_file() && b.nlink() == 1
                })
                && b.uid() == unsafe { libc::geteuid() }
                && b.mode() & 0o077 == 0
        };
        same(&self.lock._file, &self.path, false)
            && self
                .path
                .parent()
                .is_some_and(|parent| same(&self.directory, parent, true))
    }
}

/// Existing inode only: no create, chmod, authority initialization, or publication.
#[cfg(unix)]
pub(crate) fn acquire_existing_message_store_lock_as(
    label: &str,
    path: &Path,
) -> Result<ExistingMessageStoreLock, DirectiveError> {
    let started = std::time::Instant::now();
    tracing::debug!(
        event = "store_lock",
        stage = "lock_wait",
        outcome = "start",
        elapsed_ms = 0u64
    );
    let result = acquire_existing_message_store_lock_as_inner(label, path, started);
    result.inspect_err(|e| {
        tracing::debug!(
            event = "store_lock",
            stage = "lock_wait",
            outcome = "error",
            cause = e.cause.unwrap_or(UndeterminedCause::Unknown).as_str(),
            elapsed_ms = started.elapsed().as_millis() as u64
        );
    })
}

#[cfg(unix)]
fn acquire_existing_message_store_lock_as_inner(
    label: &str,
    path: &Path,
    started: std::time::Instant,
) -> Result<ExistingMessageStoreLock, DirectiveError> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let bad = || {
        DirectiveError::undet(format!("{label}: existing lock unavailable"))
            .with_cause(UndeterminedCause::LockUnavailable)
    };
    let timeout = || {
        tracing::debug!(
            event = "store_lock",
            stage = "lock_wait",
            outcome = "admission_timeout",
            cause = "lock_timeout",
            elapsed_ms = started.elapsed().as_millis() as u64
        );
        DirectiveError::undet(format!("{label}: existing lock unavailable"))
            .with_cause(UndeterminedCause::LockTimeout)
    };
    let parent = path.parent().ok_or_else(bad)?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| bad())?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| bad())?;
    let metadata = file.metadata().map_err(|_| bad())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(bad());
    }
    let deadline = std::time::Instant::now()
        + MESSAGE_LOCK_DELAY.saturating_mul(MESSAGE_LOCK_ATTEMPTS * MESSAGE_LOCK_ROUNDS);
    for _ in 0..MESSAGE_LOCK_ATTEMPTS * MESSAGE_LOCK_ROUNDS {
        if std::time::Instant::now() >= deadline {
            return Err(timeout());
        }
        // SAFETY: file owns a valid fd and flock does not access Rust memory.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            let guard = ExistingMessageStoreLock {
                lock: StoreLock { _file: file },
                directory,
                path: path.to_path_buf(),
            };
            if !guard.matches_path() {
                return Err(bad());
            }
            if std::time::Instant::now() >= deadline {
                return Err(timeout());
            }
            tracing::debug!(
                event = "store_lock",
                stage = "lock_wait",
                outcome = "acquired",
                elapsed_ms = started.elapsed().as_millis() as u64
            );
            return Ok(guard);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
            return Err(bad());
        }
        std::thread::sleep(
            MESSAGE_LOCK_DELAY.min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
    Err(timeout())
}

/// Take the store lock with up to `LOCK_ATTEMPTS` attempts and `LOCK_DELAY` between
/// attempts within a cooperative elapsed admission budget. Filesystem calls cannot be
/// interrupted; elapsed time is checked before an attempt and before returning a guard.
/// A try-once policy (`attempts * rounds <= 1`, see [`acquire_store_lock_attempts_as`]) has
/// NO elapsed deadline: it makes its one attempt and can succeed late; zero attempts make
/// none and time out. After a successful `flock` the held fd and the named path must still
/// share dev+ino, otherwise the lock is released and admission is refused as `Undetermined`.
/// The lock file is
/// opened WITHOUT following a symlink (`O_NOFOLLOW`; a swap after a separate stat would
/// otherwise win the race), `fstat`ed to be a regular file, and narrowed to 0600 through
/// the open handle.
#[cfg(unix)]
pub(crate) fn acquire_store_lock_as(label: &str, path: &Path) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_attempts_as(label, path, LOCK_ATTEMPTS)
}

/// [`acquire_store_lock_as`] with the number of `flock` attempts chosen by the caller; `1`
/// is "try once, never wait" (the message hook: a busy store means print nothing). Try-once
/// has no elapsed deadline: a host stall before the single non-blocking `flock` cannot turn
/// a free lock into `LockTimeout`, and a late success is admitted. Busy still refuses.
#[cfg(unix)]
pub(crate) fn acquire_store_lock_attempts_as(
    label: &str,
    path: &Path,
    attempts: u32,
) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_policy_as(label, path, attempts, 1, &mut |_| {})
}

/// Messaging gets exactly one internal retry after a contention-only exhausted round.
/// Open/stat/security/I/O failures return immediately; no mutation has begun here.
/// Production and tests both use the installed ten-second cooperative admission budget;
/// the indexed hook's separate try-once path remains nonblocking.
#[cfg(unix)]
pub(crate) fn acquire_message_store_lock_as(
    label: &str,
    path: &Path,
) -> Result<StoreLock, DirectiveError> {
    acquire_message_store_lock_with_round_hook_as(label, path, &mut |_| {})
}

#[cfg(unix)]
fn acquire_message_store_lock_with_round_hook_as(
    label: &str,
    path: &Path,
    round_exhausted: &mut dyn FnMut(u32),
) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_policy_with_delay_as(
        label,
        path,
        MESSAGE_LOCK_ATTEMPTS,
        MESSAGE_LOCK_ROUNDS,
        MESSAGE_LOCK_DELAY,
        round_exhausted,
    )
}

#[cfg(unix)]
fn acquire_store_lock_policy_as(
    label: &str,
    path: &Path,
    attempts: u32,
    rounds: u32,
    round_exhausted: &mut dyn FnMut(u32),
) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_policy_with_delay_as(
        label,
        path,
        attempts,
        rounds,
        LOCK_DELAY,
        round_exhausted,
    )
}

/// Gate gets one internal contention retry within a shared one-second admission
/// budget. Production and tests use the same policy; security/I/O errors are not retried.
/// This is cooperative: synchronous filesystem calls can overrun, but late success is
/// refused. Ledger mutation starts only after a guard is returned.
#[cfg(unix)]
pub(crate) fn acquire_gate_ledger_lock_as(
    label: &str,
    path: &Path,
) -> Result<StoreLock, DirectiveError> {
    acquire_gate_ledger_lock_with_round_hook_as(label, path, &mut |_| {})
}

#[cfg(unix)]
fn acquire_gate_ledger_lock_with_round_hook_as(
    label: &str,
    path: &Path,
    round_exhausted: &mut dyn FnMut(u32),
) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_policy_with_delay_as(
        label,
        path,
        GATE_LEDGER_LOCK_ATTEMPTS,
        GATE_LEDGER_LOCK_ROUNDS,
        GATE_LEDGER_LOCK_DELAY,
        round_exhausted,
    )
}

#[cfg(not(unix))]
pub(crate) fn acquire_gate_ledger_lock_as(
    label: &str,
    path: &Path,
) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_attempts_as(label, path, 1)
}

#[cfg(unix)]
fn acquire_store_lock_policy_with_delay_as(
    label: &str,
    path: &Path,
    attempts: u32,
    rounds: u32,
    delay: Duration,
    round_exhausted: &mut dyn FnMut(u32),
) -> Result<StoreLock, DirectiveError> {
    let started = std::time::Instant::now();
    tracing::debug!(
        event = "store_lock",
        stage = "lock_wait",
        outcome = "start",
        elapsed_ms = 0u64
    );
    let mut now = std::time::Instant::now;
    let result = acquire_store_lock_policy_with_delay_as_inner(
        label,
        path,
        attempts,
        rounds,
        delay,
        round_exhausted,
        started,
        &mut now,
    );
    result.map_err(|e: DirectiveError| {
        let e = e.with_cause(UndeterminedCause::LockUnavailable);
        tracing::debug!(
            event = "store_lock",
            stage = "lock_wait",
            outcome = "error",
            cause = e.cause.unwrap_or(UndeterminedCause::Unknown).as_str(),
            elapsed_ms = started.elapsed().as_millis() as u64
        );
        e
    })
}

/// Test-only entry point that supplies the clock the admission deadline is read from.
/// Fixtures that must observe a retry use a fixed clock so a loaded runner's wall time
/// cannot expire admission before the round under test. The error mapping matches
/// production's wrapper; `started` is `now()` like production's own first read.
#[cfg(all(test, unix))]
fn acquire_store_lock_policy_with_clock_as(
    label: &str,
    path: &Path,
    attempts: u32,
    rounds: u32,
    delay: Duration,
    round_exhausted: &mut dyn FnMut(u32),
    now: &mut dyn FnMut() -> std::time::Instant,
) -> Result<StoreLock, DirectiveError> {
    let started = now();
    acquire_store_lock_policy_with_delay_as_inner(
        label,
        path,
        attempts,
        rounds,
        delay,
        round_exhausted,
        started,
        now,
    )
    .map_err(|e: DirectiveError| e.with_cause(UndeterminedCause::LockUnavailable))
}

/// A try-once policy is exactly one attempt in one round. It has no wait to bound, so it
/// carries no elapsed deadline: open/stat/chmod time and scheduling stalls are not contention.
#[cfg(unix)]
fn is_try_once(attempts: u32, rounds: u32) -> bool {
    attempts.saturating_mul(rounds) <= 1
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)] // the policy's four knobs plus the two callbacks and clock it is driven through
fn acquire_store_lock_policy_with_delay_as_inner(
    label: &str,
    path: &Path,
    attempts: u32,
    rounds: u32,
    delay: Duration,
    round_exhausted: &mut dyn FnMut(u32),
    started: std::time::Instant,
    now: &mut dyn FnMut() -> std::time::Instant,
) -> Result<StoreLock, DirectiveError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;
    // One elapsed admission budget across both contention rounds. Production messaging
    // permits 2 * 50 * 100ms = 10s; callbacks, syscalls and scheduling consume it too.
    // Synchronous filesystem calls cannot be interrupted: every return is checked before
    // another attempt or successful admission, so this is a cooperative elapsed bound.
    // EXCEPTION: a try-once policy has NO elapsed deadline (see `is_try_once`).
    let budget = delay.saturating_mul(attempts.saturating_mul(rounds));
    let deadline = started + budget;
    let try_once = is_try_once(attempts, rounds);
    let timeout = || {
        tracing::debug!(
            event = "store_lock",
            stage = "lock_wait",
            cause = "lock_timeout",
            outcome = "admission_timeout",
            elapsed_ms = started.elapsed().as_millis() as u64
        );
        DirectiveError::undet(format!("{label}: lock timed out"))
            .with_cause(UndeterminedCause::LockTimeout)
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if is_symlink_refusal(&e) {
                DirectiveError::undet(format!("{label}: lock is a symlink"))
            } else {
                DirectiveError::undetermined(&format!("{label}: open lock"), e.kind())
            }
        })?;
    let meta = file
        .metadata()
        .map_err(|e| DirectiveError::undetermined(&format!("{label}: stat lock"), e.kind()))?;
    if !meta.is_file() {
        return Err(DirectiveError::undet(format!(
            "{label}: lock is not a regular file"
        )));
    }
    // `set_permissions` below acts on the inode: a hard link to a file elsewhere would
    // narrow THAT file's mode too, and the lock would not be ours alone. Refuse, and do not
    // touch the inode.
    if meta.nlink() > 1 {
        return Err(DirectiveError::undet(format!(
            "{label}: lock has more than one link"
        )));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| DirectiveError::undet(format!("{label}: secure lock failed")))?;
    for round in 0..rounds {
        for attempt in 0..attempts {
            if !try_once && now() >= deadline {
                return Err(timeout());
            }
            // SAFETY: `flock` on a file descriptor this function owns and keeps open for the
            // lifetime of the returned guard; it has no memory-safety preconditions.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                let guard = StoreLock { _file: file };
                // A swap of the named path before this check is refused: the flock is on the
                // inode opened above, and a same-UID rename since then would leave two
                // holders on different inodes. Fail closed; dropping the guard releases the
                // flock. This is cooperative, as in `legacy_guard.rs` (revalidation does not
                // exclude a hostile concurrent path writer): it claims nothing about a swap
                // after this check.
                if !guard.names_path(path) {
                    drop(guard);
                    return Err(DirectiveError::undet(format!(
                        "{label}: lock identity changed"
                    )));
                }
                if !try_once && now() >= deadline {
                    drop(guard);
                    return Err(timeout());
                }
                tracing::debug!(
                    event = "store_lock",
                    stage = "lock_wait",
                    outcome = "acquired",
                    elapsed_ms = started.elapsed().as_millis() as u64
                );
                return Ok(guard);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::WouldBlock {
                return Err(DirectiveError::undetermined(
                    &format!("{label}: lock failed"),
                    err.kind(),
                ));
            }
            if attempt + 1 < attempts {
                std::thread::sleep(delay.min(deadline.saturating_duration_since(now())));
            }
        }
        round_exhausted(round);
    }
    Err(timeout())
}

#[cfg(not(unix))]
pub(crate) fn acquire_store_lock_as(label: &str, path: &Path) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_attempts_as(label, path, LOCK_ATTEMPTS)
}

/// See the unix definition: `attempts` bounded tries, `1` meaning try once.
#[cfg(not(unix))]
pub(crate) fn acquire_store_lock_attempts_as(
    label: &str,
    path: &Path,
    attempts: u32,
) -> Result<StoreLock, DirectiveError> {
    acquire_store_lock_attempts_delay_as(label, path, attempts, LOCK_DELAY)
}

#[cfg(not(unix))]
fn acquire_store_lock_attempts_delay_as(
    label: &str,
    path: &Path,
    attempts: u32,
    delay: Duration,
) -> Result<StoreLock, DirectiveError> {
    // Windows locks a named mutex derived from the path; the lock file itself is not opened.
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(DirectiveError::undet(format!("{label}: lock is a symlink")))
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(DirectiveError::undetermined(
                &format!("{label}: stat lock"),
                e.kind(),
            ))
        }
    }
    let guard = crate::platform::lock::try_lock_file_bounded(path, attempts, delay)
        .map_err(|_| DirectiveError::undet(format!("{label}: lock failed")))?
        .ok_or_else(|| {
            DirectiveError::undet(format!("{label}: lock timed out"))
                .with_cause(UndeterminedCause::LockTimeout)
        })?;
    secure_file(path).map_err(|_| DirectiveError::undet(format!("{label}: secure lock failed")))?;
    Ok(StoreLock { _guard: guard })
}

#[cfg(not(unix))]
pub(crate) fn acquire_message_store_lock_as(
    label: &str,
    path: &Path,
) -> Result<StoreLock, DirectiveError> {
    // Windows needs a typed timeout distinction before a safe retry is possible;
    // preserve its current fail-closed acquisition rather than retry generic I/O. The wait
    // is one flat 100 x 100 ms round, the unix total, without the per-round retry.
    acquire_store_lock_attempts_delay_as(
        label,
        path,
        MESSAGE_LOCK_ATTEMPTS * MESSAGE_LOCK_ROUNDS,
        MESSAGE_LOCK_DELAY,
    )
}

/// Run `f` under the store lock with the swept record set (bad records quarantined). `f`
/// mutates `records` to match what it wrote. EVERY locked operation ends by reconciling
/// the indexes with the records — an idempotent duplicate delivery and a no-op gc
/// included — so an index write that failed earlier is repaired by the next mutating call.
fn locked<T>(
    base_dir: &Path,
    now: u64,
    fs: &FsOps<'_>,
    f: impl FnOnce(&Path, &mut Vec<Record>) -> Result<T, DirectiveError>,
) -> Result<T, DirectiveError> {
    let dir = store_dir(base_dir);
    ensure_dir(&dir)?;
    let _guard = acquire_store_lock(&dir.join(".lock"))?;
    sweep_stale_tmp(&dir, now)?;
    let loaded = load_all_quarantining(&dir, now)?;
    let mut records = sweep(&dir, now, loaded)?;
    let out = f(&dir, &mut records);
    let synced = sync_index(&dir, &records, now, fs);
    if synced.is_err() {
        tracing::warn!(
            error_kind = "directive_index_sync_failed",
            "directive index could not be reconciled"
        );
    }
    // `f`'s result is the outcome: when `f` succeeded its change is already durable, and a
    // failed index sync only leaves the statusline's index stale until the next locked
    // call repairs it. Reporting that as a failure would invite a retry of a delivered
    // directive.
    out
}

// ── operations ──────────────────────────────────────────────────────

/// The ids that may be evicted to make room, in the order they go.
///
/// 1. Expired records, and records whose pid is held by no live process (`pid_held`,
///    called with `proc_start(p).is_some() || unreadable(p)`: a live process that cannot
///    be read still holds its pid, so its record is kept), oldest last transition first.
///    The test is "does a live listed `claude` session, or one that cannot be read, hold
///    this pid", NOT "is the pid in use": a pid since reused by a process that is
///    positively not a claude session reads `Ok(None)`, holds nothing, and its record IS
///    evictable. A pid reused by another claude session keeps the record (the safe
///    direction; the record's own start is not compared here).
/// 2. Acknowledged records that are still unexpired and whose pid is held, oldest
///    acknowledgement first. The caller leaves a tombstone for each.
///
/// A pending record of a live session is in neither class, so it is never evicted.
fn eviction_order(records: &[Record], now: u64, pid_held: &dyn Fn(u32) -> bool) -> Vec<String> {
    let gone = |r: &&Record| now >= r.directive.expires_at || !pid_held(r.directive.target.pid);
    let mut first: Vec<&Record> = records.iter().filter(gone).collect();
    first.sort_by(|a, b| {
        a.last_transition(now)
            .cmp(&b.last_transition(now))
            .then_with(|| a.directive.id.cmp(&b.directive.id))
    });
    let mut second: Vec<&Record> = records
        .iter()
        .filter(|r| !gone(r) && r.acknowledged_at.is_some())
        .collect();
    second.sort_by(|a, b| {
        a.acknowledged_at
            .cmp(&b.acknowledged_at)
            .then_with(|| a.directive.id.cmp(&b.directive.id))
    });
    first
        .into_iter()
        .chain(second)
        .map(|r| r.directive.id.clone())
        .collect()
}

fn valid_tombstones(v: &[Tombstone]) -> bool {
    v.len() <= MAX_TOMBSTONES
        && v.iter().all(|t| {
            canonical_uuid(&t.id)
                && t.doc_sha256.len() == 64
                && t.doc_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// The replay horizon, under the lock. Absent is `None`. A file that is unreadable, of the
/// wrong type, oversized or not a canonical decimal `u64` is `Undetermined`, NEVER `None`:
/// reading it as "no horizon" would re-open every replay the horizon exists to refuse.
fn read_horizon(dir: &Path) -> Result<Option<u64>, DirectiveError> {
    let bad = || DirectiveError::undet("directive store: replay horizon is unreadable");
    match read_regular_bounded(&dir.join(HORIZON_FILE), MAX_HORIZON_BYTES) {
        Ok(None) => Ok(None),
        Ok(Some(text)) if canonical_decimal(&text) => text.parse().map(Some).map_err(|_| bad()),
        Ok(Some(_)) | Err(LoadFail::Bad(_)) => Err(bad()),
        Err(LoadFail::Io(e)) => Err(e),
    }
}

/// Raise the horizon to at least `to` (never lower it) and make it durable. Returns the
/// horizon now in force; writes nothing when it already covers `to`.
fn raise_horizon(
    dir: &Path,
    current: Option<u64>,
    to: u64,
    fs: &FsOps<'_>,
) -> Result<Option<u64>, DirectiveError> {
    if current.is_some_and(|c| c >= to) {
        return Ok(current);
    }
    write_atomic(&dir.join(HORIZON_FILE), to.to_string().as_bytes(), fs)?;
    Ok(Some(to))
}

/// The tombstones and the horizon, under the lock. Absent is empty. Expired entries are
/// absent HERE, so the answer for an id never depends on whether unrelated activity has
/// pruned the file yet.
///
/// A tombstone file that cannot be opened because of what it is, or whose content is bad,
/// is moved to `rejected/` like a record. Its tombstones are lost, so the horizon is raised
/// to `now` and written FIRST; only then is the file moved. If the horizon cannot be
/// written the bad file stays where it was. A resource failure, including a quarantine that
/// fails (a broken `rejected/`) or an unreadable horizon, is `Undetermined`, as for a
/// corrupt record.
fn load_tombstones(dir: &Path, now: u64, fs: &FsOps<'_>) -> Result<TombstoneFile, DirectiveError> {
    let horizon = read_horizon(dir)?;
    let path = dir.join(TOMBSTONE_FILE);
    match read_regular_bounded(&path, MAX_TOMBSTONE_BYTES) {
        Ok(None) => {
            return Ok(TombstoneFile {
                refuse_issued_before: horizon,
                tombstones: Vec::new(),
            })
        }
        Ok(Some(text)) => {
            if let Some(mut v) = serde_json::from_str::<Vec<Tombstone>>(&text)
                .ok()
                .filter(|v| valid_tombstones(v))
            {
                v.retain(|t| now < t.expires_at);
                return Ok(TombstoneFile {
                    refuse_issued_before: horizon,
                    tombstones: v,
                });
            }
        }
        Err(LoadFail::Bad(_)) => {}
        Err(LoadFail::Io(e)) => return Err(e),
    }
    // A lost tombstone may carry an `issued_at` up to `MAX_ISSUED_SKEW_SECS` in the future
    // (validation accepts that skew), so the horizon must clear `now + skew`, not `now`.
    let raised = raise_horizon(
        dir,
        horizon,
        now.saturating_add(MAX_ISSUED_SKEW_SECS + 1),
        fs,
    )?;
    quarantine_entry(dir, &path, "tombstones", "json", now)?;
    prune_rejected(dir)?;
    Ok(TombstoneFile {
        refuse_issued_before: raised,
        tombstones: Vec::new(),
    })
}

/// Write the tombstones atomically: expired entries are dropped, then, past
/// [`MAX_TOMBSTONES`], the ones with the oldest effective `issued_at` (so the horizon
/// moves as little as possible). The horizon is raised past every dropped
/// tombstone's `issued_at` BEFORE the file is written, so a tombstone is never gone while
/// the horizon that stands in for it is not yet durable.
fn save_tombstones(
    dir: &Path,
    mut file: TombstoneFile,
    now: u64,
    fs: &FsOps<'_>,
) -> Result<(), DirectiveError> {
    let all = &mut file.tombstones;
    all.retain(|t| now < t.expires_at);
    if all.len() > MAX_TOMBSTONES {
        all.sort_by(|a, b| {
            effective_issued_at(a)
                .cmp(&effective_issued_at(b))
                .then_with(|| a.id.cmp(&b.id))
        });
        let drop_n = all.len() - MAX_TOMBSTONES;
        let floor = all
            .drain(..drop_n)
            .map(|t| effective_issued_at(&t).saturating_add(1))
            .max();
        if let Some(floor) = floor {
            raise_horizon(dir, file.refuse_issued_before, floor, fs)?;
        }
    }
    let bytes = serde_json::to_vec(&file.tombstones)
        .map_err(|_| DirectiveError::undet("directive store: serialize failed"))?;
    write_atomic(&dir.join(TOMBSTONE_FILE), bytes.as_slice(), fs)
}

/// The `issued_at` a tombstone stands for. A tombstone written before the field existed
/// reads as 0; validation guarantees `issued_at <= expires_at - MIN_LIFETIME_SECS`, so that
/// bound is used instead, and a horizon raised past it still covers the original document.
fn effective_issued_at(t: &Tombstone) -> u64 {
    if t.issued_at == 0 {
        t.expires_at.saturating_sub(MIN_LIFETIME_SECS)
    } else {
        t.issued_at
    }
}

/// Validate and queue one directive (contract §3). `raw` is the stdin document.
///
/// # Errors
/// The first failing check in contract order, as a typed [`DirectiveError`].
pub fn deliver_inner(
    base_dir: &Path,
    env: &Env<'_>,
    live: &Live<'_>,
    raw: &str,
) -> Result<DirectiveReceipt, DirectiveError> {
    let d = validate_shape(raw)?;
    if d.target.host != live.host {
        return Err(DirectiveError::new(
            SdkErrorCode::TargetMismatch,
            "target.host is not this host",
        ));
    }
    let now = env.now;
    if now >= d.expires_at {
        return Err(DirectiveError::new(
            SdkErrorCode::Expired,
            "directive has expired",
        ));
    }
    if d.issued_at > now.saturating_add(MAX_ISSUED_SKEW_SECS) {
        return Err(DirectiveError::invalid("issued_at is in the future"));
    }
    match d.expires_at.checked_sub(d.issued_at) {
        Some(life) if (MIN_LIFETIME_SECS..=MAX_LIFETIME_SECS).contains(&life) => {}
        _ => {
            return Err(DirectiveError::invalid(
                "expires_at must be 5 minutes to 24 hours after issued_at",
            ))
        }
    }
    if d.expires_at - now > MAX_LIFETIME_SECS {
        return Err(DirectiveError::invalid(
            "expires_at is more than 24 hours from now",
        ));
    }
    let (pid, started_at) = (d.target.pid, d.target.started_at);
    // The LIVE start time, as the listing reads it now. It is what the record stores and
    // what every record-to-record comparison uses; the wire value only has to be within
    // the tolerance of it.
    // Could-not-read is not "not a session" (INV-31-01/02): refuse as undetermined.
    if (live.unreadable)(pid) {
        return Err(DirectiveError::undet(format!(
            "the target process (pid {pid}) could not be read; retry, and if it persists check that process"
        )));
    }
    let live_start = (live.proc_start)(pid).filter(|s| same_start(*s, started_at));
    let Some(live_start) = live_start.filter(|_| (live.is_listed)(pid, started_at)) else {
        return Err(DirectiveError::new(
            SdkErrorCode::TargetMismatch,
            "target is not a live listed session on this host",
        ));
    };
    let handle_dir =
        (live.handle_dir_of)(pid, started_at).map(|p| p.to_string_lossy().into_owned());
    locked(base_dir, now, env.fs, |dir, records| {
        // One session, one stored start. On Linux two readings of the same process can
        // differ by a second (`START_TOLERANCE_SECS`), so a session that already has
        // records keeps the start they stored; without this, a later delivery could store
        // `S+1` beside an earlier `S` and the exact record-to-record comparisons below
        // would count one session as two (rate limit, pending cap, index).
        let live_start = records
            .iter()
            .filter(|r| {
                // Only a record that carries a live reading, and was queued no earlier than
                // this process could have started: a record queued BEFORE the process
                // started belongs to an earlier holder of the pid, whatever its stored
                // start is within.
                r.directive.target.pid == pid
                    && r.live_start.is_some_and(|ls| {
                        same_start(ls, live_start)
                            && r.queued_at.saturating_add(START_TOLERANCE_SECS) >= live_start
                    })
            })
            .map(Record::start)
            .min()
            .unwrap_or(live_start);
        if let Some(existing) = records.iter().find(|r| r.directive.id == d.id) {
            // The same document again is idempotent; the same id with anything different is
            // a collision, never silently answered with the other document's receipt.
            if existing.directive == d {
                return Ok(existing.receipt(now));
            }
            return Err(DirectiveError::invalid(
                "id already used for a different directive",
            ));
        }
        // An acknowledged record evicted before it expired leaves a tombstone, so its id
        // stays used. There is no receipt left to return for the same document.
        let hash = doc_hash(&d)?;
        let mut tombs = load_tombstones(dir, now, env.fs)?;
        if let Some(t) = tombs.tombstones.iter().find(|t| t.id == d.id) {
            return Err(DirectiveError::invalid(if t.doc_sha256 == hash {
                "directive already delivered and acknowledged; its receipt is no longer held"
            } else {
                "id already used for a different directive"
            }));
        }
        // A lost tombstone cannot refuse its id; the horizon refuses what it covered.
        if tombs.refuse_issued_before.is_some_and(|h| d.issued_at < h) {
            return Err(DirectiveError::invalid(
                "directive was issued before the store's replay horizon",
            ));
        }
        let newest = records
            .iter()
            .filter(|r| r.directive.issuer == d.issuer && r.same_session(pid, live_start))
            .map(|r| r.queued_at)
            .max();
        if let Some(q) = newest {
            let next = q.saturating_add(RATE_WINDOW_SECS);
            if next > now {
                return Err(DirectiveError::rate_limited(
                    "one directive per session per hour from this issuer",
                    Some(next),
                ));
            }
        }
        // All issuers together: rotating the issuer string must not lift the cap.
        let frees_at = records
            .iter()
            .filter(|r| r.same_session(pid, live_start) && r.pending(now))
            .map(|r| r.directive.expires_at)
            .collect::<Vec<_>>();
        if frees_at.len() >= MAX_PENDING_PER_TARGET {
            return Err(DirectiveError::rate_limited(
                "this session already holds the maximum number of pending directives",
                frees_at.into_iter().min(),
            ));
        }
        // Room for the new record: how many existing records must go for the store to end
        // at MAX_RECORDS, and which ones may. Refused only when too many records are
        // pending for live sessions.
        let overflow = (records.len() + 1).saturating_sub(MAX_RECORDS);
        let victims = if overflow == 0 {
            Vec::new()
        } else {
            let order = eviction_order(records, now, &|p| {
                (live.proc_start)(p).is_some() || (live.unreadable)(p)
            });
            if order.len() < overflow {
                let keep = records.iter().filter(|r| !order.contains(&r.directive.id));
                return Err(DirectiveError::rate_limited(
                    "the directive store is full of pending directives for live sessions",
                    keep.map(|r| r.directive.expires_at).min(),
                ));
            }
            order.into_iter().take(overflow).collect::<Vec<_>>()
        };
        // Computed BEFORE anything is written, so a failure here refuses cleanly.
        let mut new_tombs = Vec::new();
        for id in &victims {
            if let Some(r) = records.iter().find(|r| &r.directive.id == id) {
                if r.acknowledged_at.is_some() && now < r.directive.expires_at {
                    new_tombs.push(Tombstone {
                        id: id.clone(),
                        doc_sha256: doc_hash(&r.directive)?,
                        expires_at: r.directive.expires_at,
                        issued_at: r.directive.issued_at,
                    });
                }
            }
        }
        let rec = Record {
            directive: d,
            queued_at: now,
            surfaced_at: None,
            acknowledged_at: None,
            ack: None,
            handle_dir,
            live_start: Some(live_start),
        };
        // Save the NEW record first: a failed save then evicts nothing, and a refused
        // delivery changes nothing.
        save(dir, &rec, env.fs)?;
        let receipt = rec.receipt(now);
        // Tombstones first, so an acknowledged record is never deleted without the mark
        // that keeps its id used; if they cannot be written those records stay (the store
        // is briefly over its cap) and the delivery, already durable, still succeeds.
        let mut keep_acked = BTreeSet::new();
        if !new_tombs.is_empty() {
            let ids: Vec<String> = new_tombs.iter().map(|t| t.id.clone()).collect();
            tombs.tombstones.extend(new_tombs);
            if save_tombstones(dir, tombs, now, env.fs).is_err() {
                tracing::warn!(
                    error_kind = "directive_tombstone_write_failed",
                    "directive tombstones could not be written; acknowledged records kept"
                );
                keep_acked.extend(ids);
            }
        }
        let mut gone = BTreeSet::new();
        for id in victims.iter().filter(|id| !keep_acked.contains(*id)) {
            match std::fs::remove_file(record_path(dir, id)) {
                Ok(()) => {
                    gone.insert(id.clone());
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    gone.insert(id.clone());
                }
                // The new record is durable: report success, leave the store over its
                // cap, and let the next delivery evict again.
                Err(_) => tracing::warn!(
                    error_kind = "directive_evict_failed",
                    "an evictable directive record could not be removed"
                ),
            }
        }
        records.retain(|r| !gone.contains(&r.directive.id));
        records.push(rec);
        Ok(receipt)
    })
}

/// Receipts whose last transition is at or after `since`, oldest first; optionally one `id`.
///
/// # Errors
/// `invalid_input` for a malformed `id`; `undetermined` when the store cannot be read.
pub fn receipts_inner(
    base_dir: &Path,
    env: &Env<'_>,
    since: Option<u64>,
    id: Option<&str>,
) -> Result<Vec<DirectiveReceipt>, DirectiveError> {
    if let Some(id) = id {
        if !canonical_uuid(id) {
            return Err(DirectiveError::invalid(
                "id must be a lowercase hyphenated UUID",
            ));
        }
    }
    let records = load_all(&store_dir(base_dir))?;
    let mut rows: Vec<(u64, DirectiveReceipt)> = records
        .iter()
        .filter(|r| id.is_none_or(|i| r.directive.id == i))
        .map(|r| (r.last_transition(env.now), r.receipt(env.now)))
        .filter(|(t, _)| since.is_none_or(|s| *t >= s))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.id.cmp(&b.1.id)));
    Ok(rows.into_iter().map(|(_, r)| r).collect())
}

/// The calling session `(pid, started_at)`, resolved lazily by [`ack_inner`] once the
/// request itself is known to be well-formed.
pub type CallerFn<'a> = &'a dyn Fn() -> Result<(u32, u64), DirectiveError>;

/// Acknowledge a directive; transitions are monotone, so a second ack is refused. Only the
/// session the directive is addressed to may acknowledge it.
///
/// # Errors
/// `invalid_input` (unknown id, bad outcome/note, already acknowledged), `target_mismatch`
/// (the directive is addressed to another session), `expired`, `undetermined` (including
/// an unresolvable caller or an unreadable store).
pub fn ack_inner(
    base_dir: &Path,
    env: &Env<'_>,
    id: &str,
    outcome: &str,
    note: Option<&str>,
    caller: CallerFn<'_>,
) -> Result<DirectiveReceipt, DirectiveError> {
    if !canonical_uuid(id) {
        return Err(DirectiveError::invalid(
            "id must be a lowercase hyphenated UUID",
        ));
    }
    if !OUTCOMES.contains(&outcome) {
        return Err(DirectiveError::invalid(
            "outcome must be done, declined or deferred",
        ));
    }
    if let Some(n) = note {
        check_text("note", n, true, is_forbidden_char)?;
    }
    let (cpid, cstart) = caller()?;
    let now = env.now;
    if !check_store_dir(&store_dir(base_dir))? {
        return Err(DirectiveError::invalid("unknown directive id"));
    }
    locked(base_dir, now, env.fs, |dir, records| {
        let idx = records
            .iter()
            .position(|r| r.directive.id == id)
            .ok_or_else(|| DirectiveError::invalid("unknown directive id"))?;
        let mut rec = records[idx].clone();
        if !rec.targets(cpid, cstart) {
            return Err(DirectiveError::new(
                SdkErrorCode::TargetMismatch,
                "directive is not addressed to this session",
            ));
        }
        match rec.status(now) {
            "acknowledged" => {
                // The same outcome and note again is a retry of a call that already
                // succeeded: answer with the original receipt. Anything different is
                // refused, so an acknowledgement is never rewritten.
                let same = rec
                    .ack
                    .as_ref()
                    .is_some_and(|a| a.outcome == outcome && a.note.as_deref() == note);
                if same {
                    return Ok(rec.receipt(now));
                }
                return Err(DirectiveError::invalid("directive already acknowledged"));
            }
            "expired" => {
                return Err(DirectiveError::new(
                    SdkErrorCode::Expired,
                    "directive has expired",
                ))
            }
            _ => {}
        }
        rec.acknowledged_at = Some(now);
        rec.ack = Some(DirectiveAck::new(outcome, note.map(str::to_string)));
        save(dir, &rec, env.fs)?;
        let receipt = rec.receipt(now);
        records[idx] = rec;
        Ok(receipt)
    })
}

/// Directives addressed to `(pid, started_at)`, oldest first. `mark_surfaced` moves each
/// returned `queued` directive to `surfaced` (under the lock); without it the call is
/// read-only. Only records addressed to `(pid, started_at)` are ever TRANSITIONED
/// (`surfaced`); the locked sweep that `mark_surfaced` runs also removes retained records
/// past [`RETENTION_SECS`] and stale tmp files, moves bad entries to `rejected/`, and
/// reconciles every session's index, whoever they are addressed to.
///
/// # Errors
/// `undetermined` when the store cannot be read, locked or written.
pub fn inbox_for_inner(
    base_dir: &Path,
    env: &Env<'_>,
    pid: u32,
    started_at: u64,
    pending_only: bool,
    mark_surfaced: bool,
) -> Result<Vec<DirectiveInboxEntry>, DirectiveError> {
    let now = env.now;
    let build = |dir: &Path,
                 records: &mut Vec<Record>|
     -> Result<Vec<DirectiveInboxEntry>, DirectiveError> {
        let mut mine: Vec<usize> = records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.targets(pid, started_at))
            .map(|(i, _)| i)
            .collect();
        mine.sort_by(|&a, &b| {
            records[a]
                .queued_at
                .cmp(&records[b].queued_at)
                .then_with(|| records[a].directive.id.cmp(&records[b].directive.id))
        });
        let mut out = Vec::new();
        for i in mine {
            if pending_only && !records[i].pending(now) {
                continue;
            }
            if mark_surfaced && records[i].status(now) == "queued" {
                let mut rec = records[i].clone();
                rec.surfaced_at = Some(now);
                save(dir, &rec, env.fs)?;
                records[i] = rec;
            }
            let rec = &records[i];
            out.push(DirectiveInboxEntry::new(
                rec.directive.clone(),
                rec.receipt(now),
            ));
        }
        Ok(out)
    };
    if mark_surfaced {
        locked(base_dir, now, env.fs, build)
    } else {
        let dir = store_dir(base_dir);
        let mut records = load_all(&dir)?;
        build(&dir, &mut records)
    }
}

fn pending_info(mut mine: Vec<Record>, now: u64) -> PendingInfo {
    mine.sort_by(|a, b| {
        a.queued_at
            .cmp(&b.queued_at)
            .then_with(|| a.directive.id.cmp(&b.directive.id))
    });
    let pending: Vec<&Record> = mine.iter().filter(|r| r.pending(now)).collect();
    PendingInfo {
        pending: pending.len(),
        last_directive_at: mine.iter().map(|r| r.queued_at).max(),
        first_summary: pending.first().map(|r| r.directive.summary.clone()),
    }
}

/// Read-only pending summary for one session (listing).
///
/// # Errors
/// `undetermined` when the store cannot be read.
pub fn pending_count_and_last_inner(
    base_dir: &Path,
    now: u64,
    pid: u32,
    started_at: u64,
) -> Result<PendingInfo, DirectiveError> {
    let mine: Vec<Record> = load_all(&store_dir(base_dir))?
        .into_iter()
        .filter(|r| r.targets(pid, started_at))
        .collect();
    Ok(pending_info(mine, now))
}

/// [`pending_count_and_last_inner`] for many sessions at once: the store is loaded ONCE and
/// the result is one [`PendingInfo`] per entry of `targets`, in order (the listing calls
/// this instead of re-reading the store per row).
///
/// # Errors
/// `undetermined` when the store cannot be read.
pub fn pending_for_targets_inner(
    base_dir: &Path,
    now: u64,
    targets: &[(u32, u64)],
) -> Result<Vec<PendingInfo>, DirectiveError> {
    let records = load_all(&store_dir(base_dir))?;
    Ok(targets
        .iter()
        .map(|&(pid, started_at)| {
            let mine = records
                .iter()
                .filter(|r| r.targets(pid, started_at))
                .cloned()
                .collect();
            pending_info(mine, now)
        })
        .collect())
}

fn canonical_string(p: &Path) -> String {
    std::fs::canonicalize(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

/// Pending directives for the session living in `handle_dir`, without enumerating
/// processes. The pid comes from the handle dir's `.live-cc-pid` marker (or `.live-pid`
/// when csq exec-replaced itself with `claude`); the session is then identified by that
/// pid's START TIME (`start_of`), not by when the marker was written. A record counts only
/// when it is addressed to that pid, its recorded start time matches within
/// [`super::START_TOLERANCE_SECS`], AND it was recorded for this same handle dir. Only the
/// pid's index (at most [`MAX_PENDING_PER_TARGET`] ids) and the records it lists are read.
///
/// `Ok(None)`: nothing to show (no marker, or no store yet). `Err`: the store exists and
/// could not be read, a pid marker exists but could not be read, the pid's start time could not be read, or the index lists more
/// than the per-target cap; the statusline then shows `[directives: ?]`.
///
/// # Errors
/// `undetermined` as above.
pub fn pending_for_handle_dir_at(
    base_dir: &Path,
    handle_dir: &Path,
    now: u64,
    start_of: &dyn Fn(u32) -> Option<u64>,
) -> Result<Option<PendingInfo>, DirectiveError> {
    use crate::accounts::markers;
    // The CHECKED readers: a marker that exists but cannot be read is its own outcome
    // ("undetermined"), never "no marker". `.live-cc-pid` is preferred; an unreadable one
    // is not papered over by `.live-pid`, since the unreadable file may be the one that
    // names the session.
    let pid: Result<Option<u32>, ()> = match markers::read_live_cc_pid_checked(handle_dir) {
        Ok(Some(pid)) => Ok(Some(pid)),
        Ok(None) => markers::read_live_pid_checked(handle_dir).map_err(|_| ()),
        Err(_) => Err(()),
    };
    let dir = store_dir(base_dir);
    let pid = match pid {
        Ok(Some(pid)) => pid,
        Ok(None) => return Ok(None),
        Err(()) => {
            // Nothing to show when there is no store; with a store, an unreadable marker
            // must not look like "no directives".
            return if check_store_dir(&dir)? {
                Err(DirectiveError::undet(
                    "session pid marker could not be read",
                ))
            } else {
                Ok(None)
            };
        }
    };
    if !check_store_dir(&dir)? {
        return Ok(None);
    }
    let start = start_of(pid)
        .ok_or_else(|| DirectiveError::undet("session start time could not be read"))?;
    // The index is keyed by the stored live start, which can differ from this reading by
    // the tolerance: look at start-1, start and start+1. The cap applies per FILE (one
    // session), never across the three.
    let mut ids = BTreeSet::new();
    for st in [start.checked_sub(1), Some(start), start.checked_add(1)]
        .into_iter()
        .flatten()
    {
        let one = read_index(&dir, pid, st)?;
        if one.len() > MAX_PENDING_PER_TARGET {
            return Err(DirectiveError::undet(
                "directive store: index lists too many directives",
            ));
        }
        ids.extend(one);
    }
    let want = canonical_string(handle_dir);
    let mut mine = Vec::new();
    for id in ids {
        if let Some(rec) = load_record(&record_path(&dir, &id), &id)? {
            if rec.targets(pid, start) && rec.handle_dir.as_deref() == Some(want.as_str()) {
                mine.push(rec);
            }
        }
    }
    Ok(Some(pending_info(mine, now)))
}

/// [`pending_for_handle_dir_at`] against the real clock and [`super::process_start_time`].
///
/// # Errors
/// As [`pending_for_handle_dir_at`].
pub fn pending_for_handle_dir(
    base_dir: &Path,
    handle_dir: &Path,
) -> Result<Option<PendingInfo>, DirectiveError> {
    pending_for_handle_dir_at(
        base_dir,
        handle_dir,
        now_secs()?,
        &super::process_start_time,
    )
}

/// Delete directives 7 days past their last transition. Also runs inside every mutating call.
///
/// # Errors
/// `undetermined` when the store cannot be read, locked or pruned.
pub fn gc_inner(base_dir: &Path, now: u64) -> Result<(), DirectiveError> {
    if !check_store_dir(&store_dir(base_dir))? {
        return Ok(());
    }
    locked(base_dir, now, &real_fs(), |_, _| Ok(()))
}

// ── real-environment wrappers ───────────────────────────────────────

fn now_secs() -> Result<u64, DirectiveError> {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| DirectiveError::undet("system clock is before the unix epoch"))
}

/// This host's name (`hostname`), `None` when it cannot be read. Directive `target.host`
/// and the session listing's `host` MUST both come from here so they compare equal.
#[must_use]
pub fn host_name() -> Option<String> {
    let out = std::process::Command::new("hostname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let name = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!name.is_empty()).then_some(name)
}

/// [`deliver_inner`] with the host, clock and session list supplied lazily. The
/// directive's shape is validated FIRST, so a malformed one is `invalid_input` even when
/// `hostname` or the process table cannot be read, and none of the three is touched.
/// Test seam over a pre-enumerated list; production goes through `deliver_with_lookup`.
#[cfg(test)]
fn deliver_via(
    base_dir: &Path,
    raw: &str,
    host: &dyn Fn() -> Option<String>,
    clock: &dyn Fn() -> Result<u64, DirectiveError>,
    list: &dyn Fn() -> Option<Vec<super::SessionInfo>>,
    fs: &FsOps<'_>,
) -> Result<DirectiveReceipt, DirectiveError> {
    validate_shape(raw)?;
    // Host, clock, then the list: the order the refusals have always taken.
    let host = host().ok_or_else(|| DirectiveError::undet("host name could not be read"))?;
    let now = clock()?;
    let sessions =
        list().ok_or_else(|| DirectiveError::undet("live sessions could not be enumerated"))?;
    let info_of = |pid: u32| Ok(sessions.iter().find(|s| s.pid == pid).cloned());
    deliver_with_lookup(
        base_dir,
        raw,
        &|| Some(host.clone()),
        &|| Ok(now),
        &info_of,
        fs,
    )
}

/// [`deliver_inner`] with the live facts read per pid. `info_of(pid)` is the live
/// session for that one pid (`Ok(None)`: positively not a listed session; `Err`: could
/// not be read, which is `undetermined`, never a mismatch). Everything `deliver_inner`
/// asks of the live set is a question about specific pids — the target's start time and
/// handle dir, and (only when the store is full) whether each stored pid is still
/// listed — so no process-table enumeration is needed, and a delivery on a loaded host
/// costs a few syscalls instead of a full pass. Shape validation still runs FIRST.
fn deliver_with_lookup(
    base_dir: &Path,
    raw: &str,
    host: &dyn Fn() -> Option<String>,
    clock: &dyn Fn() -> Result<u64, DirectiveError>,
    info_of: &dyn Fn(u32) -> super::PidLookup,
    fs: &FsOps<'_>,
) -> Result<DirectiveReceipt, DirectiveError> {
    validate_shape(raw)?;
    let host = host().ok_or_else(|| DirectiveError::undet("host name could not be read"))?;
    let now = clock()?;
    // Each pid is read ONCE per delivery and every question below is answered from that
    // one read. Separate reads could disagree (a process that is readable, then not, or
    // listed, then gone), which is how an `Ok` followed by an `Err` could have produced a
    // `target_mismatch` for a process that was never positively "not a session".
    let memo: std::cell::RefCell<std::collections::HashMap<u32, super::PidLookup>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
    let read = |pid: u32| -> super::PidLookup {
        if let Some(hit) = memo.borrow().get(&pid) {
            return hit.clone();
        }
        // A session whose start time the platform did not report cannot be compared with
        // the directive's `started_at`: it was found but not fully read, which is
        // `undetermined`, never "a different process" (INV-31-01).
        let r = match info_of(pid) {
            Ok(Some(s)) if s.started_at.is_none() => Err(super::Undetermined),
            other => other,
        };
        memo.borrow_mut().insert(pid, r.clone());
        r
    };
    // `unreadable` is how `deliver_inner` tells "could not read" from "positively not one".
    let unreadable = |pid: u32| read(pid).is_err();
    let proc_start = |pid: u32| read(pid).ok().flatten().and_then(|s| s.started_at);
    let listed = |s: &super::SessionInfo, pid: u32, started_at: u64| {
        s.pid == pid && s.started_at.is_some_and(|t| same_start(t, started_at))
    };
    let is_listed = |pid: u32, started_at: u64| {
        read(pid)
            .ok()
            .flatten()
            .is_some_and(|s| listed(&s, pid, started_at))
    };
    let handle_dir_of = |pid: u32, started_at: u64| {
        read(pid)
            .ok()
            .flatten()
            .filter(|s| listed(s, pid, started_at))
            .map(|s| PathBuf::from(canonical_string(&s.config_dir)))
    };
    deliver_inner(
        base_dir,
        &Env { now, fs },
        &Live {
            host: &host,
            proc_start: &proc_start,
            unreadable: &unreadable,
            is_listed: &is_listed,
            handle_dir_of: &handle_dir_of,
        },
        raw,
    )
}

/// `deliver_with_lookup` against the real clock, host and
/// [`super::session_info_for_pid`]: only the target's own pid is read.
///
/// # Errors
/// As [`deliver_inner`]; an unreadable host name or clock is `undetermined`.
pub fn deliver(base_dir: &Path, raw: &str) -> Result<DirectiveReceipt, DirectiveError> {
    deliver_with_lookup(
        base_dir,
        raw,
        &host_name,
        &now_secs,
        &super::session_info_for_pid,
        &real_fs(),
    )
}

/// [`receipts_inner`] against the real clock.
///
/// # Errors
/// As [`receipts_inner`].
pub fn receipts(
    base_dir: &Path,
    since: Option<u64>,
    id: Option<&str>,
) -> Result<Vec<DirectiveReceipt>, DirectiveError> {
    let fs = real_fs();
    receipts_inner(
        base_dir,
        &Env {
            now: now_secs()?,
            fs: &fs,
        },
        since,
        id,
    )
}

/// [`ack_inner`] against the real clock. `caller` resolves the calling session.
///
/// # Errors
/// As [`ack_inner`].
pub fn ack(
    base_dir: &Path,
    id: &str,
    outcome: &str,
    note: Option<&str>,
    caller: CallerFn<'_>,
) -> Result<DirectiveReceipt, DirectiveError> {
    let fs = real_fs();
    ack_inner(
        base_dir,
        &Env {
            now: now_secs()?,
            fs: &fs,
        },
        id,
        outcome,
        note,
        caller,
    )
}

/// [`inbox_for_inner`] against the real clock.
///
/// # Errors
/// As [`inbox_for_inner`].
pub fn inbox_for(
    base_dir: &Path,
    pid: u32,
    started_at: u64,
    pending_only: bool,
    mark_surfaced: bool,
) -> Result<Vec<DirectiveInboxEntry>, DirectiveError> {
    let fs = real_fs();
    inbox_for_inner(
        base_dir,
        &Env {
            now: now_secs()?,
            fs: &fs,
        },
        pid,
        started_at,
        pending_only,
        mark_surfaced,
    )
}

/// [`pending_count_and_last_inner`] against the real clock.
///
/// # Errors
/// As [`pending_count_and_last_inner`].
pub fn pending_count_and_last(
    base_dir: &Path,
    pid: u32,
    started_at: u64,
) -> Result<PendingInfo, DirectiveError> {
    pending_count_and_last_inner(base_dir, now_secs()?, pid, started_at)
}

/// [`pending_for_targets_inner`] against the real clock.
///
/// # Errors
/// As [`pending_for_targets_inner`].
pub fn pending_for_targets(
    base_dir: &Path,
    targets: &[(u32, u64)],
) -> Result<Vec<PendingInfo>, DirectiveError> {
    pending_for_targets_inner(base_dir, now_secs()?, targets)
}

/// [`gc_inner`] against the real clock.
///
/// # Errors
/// As [`gc_inner`].
pub fn gc(base_dir: &Path) -> Result<(), DirectiveError> {
    gc_inner(base_dir, now_secs()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use csq_sdk::directives::{DirectiveTarget, DirectiveWhy};
    use std::cell::Cell;
    use tempfile::TempDir;

    const HOST: &str = "test-host";
    const PID: u32 = 4242;
    const START: u64 = 1_000;
    const NOW: u64 = 10_000;
    const ID1: &str = "0b6c3c1e-7d0e-4b0a-9d3e-2f8f1a2b3c4d";
    const ID2: &str = "1b6c3c1e-7d0e-4b0a-9d3e-2f8f1a2b3c4d";
    const ID3: &str = "2b6c3c1e-7d0e-4b0a-9d3e-2f8f1a2b3c4d";

    fn dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn dv(id: &str, issuer: &str) -> Directive {
        Directive::new(
            id,
            issuer,
            NOW - 10,
            NOW + 3_600,
            DirectiveTarget::new(PID, START, HOST),
            "offload",
            "Move the build to another host.",
            DirectiveWhy::new("session_cpu_cores", 3.87, 2.0, NOW - 20, "ps -o %cpu"),
        )
    }

    fn json(d: &Directive) -> String {
        serde_json::to_string(d).unwrap()
    }

    fn deliver_at(base: &Path, now: u64, raw: &str) -> Result<DirectiveReceipt, DirectiveError> {
        let fs = real_fs();
        let start = |p: u32| (p == PID).then_some(START);
        let listed = |p: u32, s: u64| p == PID && same_start(s, START);
        deliver_inner(
            base,
            &Env { now, fs: &fs },
            &Live {
                host: HOST,
                proc_start: &start,
                unreadable: &|_| false,
                is_listed: &listed,
                handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
            },
            raw,
        )
    }

    #[test]
    fn an_unreadable_target_names_its_pid_and_says_to_retry() {
        let t = dir();
        let fs = real_fs();
        let e = deliver_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            &Live {
                host: HOST,
                proc_start: &|p| (p == PID).then_some(START),
                unreadable: &|p| p == PID,
                is_listed: &|p, s| p == PID && same_start(s, START),
                handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
            },
            &json(&dv(ID1, "a")),
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(e.message.contains(&format!("pid {PID}")), "{}", e.message);
        assert!(e.message.contains("retry"), "{}", e.message);
    }

    #[allow(clippy::unnecessary_wraps)]
    fn me() -> Result<(u32, u64), DirectiveError> {
        Ok((PID, START))
    }

    fn code(r: Result<DirectiveReceipt, DirectiveError>) -> SdkErrorCode {
        r.expect_err("expected a refusal").code
    }

    fn json_files(base: &Path) -> Vec<String> {
        match std::fs::read_dir(store_dir(base)) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".json") && n != TOMBSTONE_FILE)
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn ack_at(
        base: &Path,
        now: u64,
        id: &str,
        outcome: &str,
    ) -> Result<DirectiveReceipt, DirectiveError> {
        let fs = real_fs();
        ack_inner(base, &Env { now, fs: &fs }, id, outcome, None, &me)
    }

    fn recs_at(
        base: &Path,
        now: u64,
        since: Option<u64>,
        id: Option<&str>,
    ) -> Vec<DirectiveReceipt> {
        let fs = real_fs();
        receipts_inner(base, &Env { now, fs: &fs }, since, id).unwrap()
    }

    // ── §3 validation rows ──

    #[test]
    fn valid_directive_is_queued_with_receipt() {
        let t = dir();
        let r = deliver_at(t.path(), NOW, &json(&dv(ID1, "trestle-steward"))).unwrap();
        assert_eq!(
            (r.id.as_str(), r.status.as_str(), r.queued_at),
            (ID1, "queued", NOW)
        );
        assert_eq!(json_files(t.path()), vec![format!("{ID1}.json")]);
    }

    #[test]
    fn refusals_write_nothing() {
        let t = dir();
        let mut d = dv(ID1, "trestle-steward");
        d.summary = "bad\u{7}".into();
        assert!(deliver_at(t.path(), NOW, &json(&d)).is_err());
        assert!(
            !store_dir(t.path()).exists(),
            "no store may be created by a refusal"
        );
    }

    #[test]
    fn rejects_unparseable_and_missing_required_fields() {
        let t = dir();
        assert_eq!(
            code(deliver_at(t.path(), NOW, "not json")),
            SdkErrorCode::InvalidInput
        );
        let mut v = serde_json::to_value(dv(ID1, "a")).unwrap();
        v.as_object_mut().unwrap().remove("why");
        assert_eq!(
            code(deliver_at(t.path(), NOW, &v.to_string())),
            SdkErrorCode::InvalidInput
        );
    }

    #[test]
    fn rejects_wrong_schema_bad_uuid_and_unknown_kind() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.schema = "csq.directive.v2".into();
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
        for bad in [
            "not-a-uuid",
            "0B6C3C1E-7D0E-4B0A-9D3E-2F8F1A2B3C4D",
            "../../etc/passwd",
        ] {
            let d = dv(bad, "a");
            assert_eq!(
                code(deliver_at(t.path(), NOW, &json(&d))),
                SdkErrorCode::InvalidInput,
                "{bad}"
            );
        }
        let mut d = dv(ID1, "a");
        d.kind = "reboot".into();
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
    }

    #[test]
    fn rejects_bad_issuer() {
        let t = dir();
        for bad in ["", "Upper", "has space", &"a".repeat(65)] {
            let d = dv(ID1, bad);
            assert_eq!(
                code(deliver_at(t.path(), NOW, &json(&d))),
                SdkErrorCode::InvalidInput,
                "{bad:?}"
            );
        }
        assert!(deliver_at(t.path(), NOW, &json(&dv(ID1, &"a".repeat(64)))).is_ok());
    }

    #[test]
    fn summary_cap_is_500_characters_not_bytes() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.summary = "é".repeat(500);
        assert!(
            deliver_at(t.path(), NOW, &json(&d)).is_ok(),
            "500 chars (1000 bytes) is within the cap"
        );
        let mut d = dv(ID2, "b");
        d.summary = "x".repeat(501);
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
    }

    #[test]
    fn suggested_limits_apply() {
        let t = dir();
        let d = dv(ID1, "a").with_suggested(vec!["s".into(); 10]);
        assert!(deliver_at(t.path(), NOW, &json(&d)).is_ok());
        let d = dv(ID2, "b").with_suggested(vec!["s".into(); 11]);
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
        let d = dv(ID2, "b").with_suggested(vec!["x".repeat(501)]);
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
    }

    #[test]
    fn control_characters_rejected_in_summary_suggested_source_and_note() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.summary = "line\nbreak".into();
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
        let d = dv(ID1, "a").with_suggested(vec!["esc\u{1b}[31m".into()]);
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
        let mut d = dv(ID1, "a");
        d.why.source = "cmd\r".into();
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
        // note
        deliver_at(t.path(), NOW, &json(&dv(ID2, "a"))).unwrap();
        let fs = real_fs();
        let e = ack_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            ID2,
            "done",
            Some("bad\u{0}"),
            &me,
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        let e = ack_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            ID2,
            "done",
            Some(&"n".repeat(501)),
            &me,
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
    }

    #[test]
    fn deleting_kinds_require_the_exact_scope() {
        let t = dir();
        for kind in ["delete_scratch", "free_disk"] {
            let mut d = dv(ID1, "a");
            d.kind = kind.into();
            assert_eq!(
                code(deliver_at(t.path(), NOW, &json(&d))),
                SdkErrorCode::InvalidInput,
                "{kind} no scope"
            );
            let wrong = d.clone().with_scope(Some("everything".to_string()));
            assert_eq!(
                code(deliver_at(t.path(), NOW, &json(&wrong))),
                SdkErrorCode::InvalidInput,
                "{kind} wrong scope"
            );
        }
        let mut d = dv(ID2, "a");
        d.kind = "free_disk".into();
        let ok = d.with_scope(Some(DELETE_SCOPE.to_string()));
        assert!(deliver_at(t.path(), NOW, &json(&ok)).is_ok());
    }

    #[test]
    fn host_mismatch_is_target_mismatch() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.target.host = "other-host".into();
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::TargetMismatch
        );
    }

    #[test]
    fn expiry_and_lifetime_rows() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.expires_at = NOW; // now < expires_at is false at equality
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::Expired
        );
        let mut d = dv(ID1, "a");
        d.issued_at = NOW - 10;
        d.expires_at = d.issued_at + MAX_LIFETIME_SECS + 1;
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
        let mut d = dv(ID1, "a");
        d.expires_at = d.issued_at + MAX_LIFETIME_SECS;
        assert!(
            deliver_at(t.path(), NOW, &json(&d)).is_ok(),
            "exactly 24 h is allowed"
        );
        let mut d = dv(ID2, "b");
        d.issued_at = NOW + 50;
        d.expires_at = NOW + 40;
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput,
            "expires before issued"
        );
    }

    #[test]
    fn dead_pid_reused_pid_and_unlisted_pid_are_target_mismatch() {
        let t = dir();
        let fs = real_fs();
        let run = |start: &dyn Fn(u32) -> Option<u64>, listed: &dyn Fn(u32, u64) -> bool| {
            deliver_inner(
                t.path(),
                &Env { now: NOW, fs: &fs },
                &Live {
                    host: HOST,
                    proc_start: start,
                    unreadable: &|_| false,
                    is_listed: listed,
                    handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
                },
                &json(&dv(ID1, "a")),
            )
        };
        let dead = run(&|_| None, &|_, _| true);
        assert_eq!(code(dead), SdkErrorCode::TargetMismatch);
        let reused = run(&|_| Some(START + 99), &|_, _| true);
        assert_eq!(
            code(reused),
            SdkErrorCode::TargetMismatch,
            "same pid, different started_at"
        );
        let unlisted = run(&|_| Some(START), &|_, _| false);
        assert_eq!(code(unlisted), SdkErrorCode::TargetMismatch);
        assert!(!store_dir(t.path()).exists());
    }

    #[test]
    fn unwritable_store_is_undetermined_not_a_refusal() {
        let t = dir();
        let blocker = t.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        assert_eq!(
            code(deliver_at(&blocker, NOW, &json(&dv(ID1, "a")))),
            SdkErrorCode::Undetermined
        );
    }

    #[test]
    fn corrupt_record_makes_reads_undetermined_never_empty() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        std::fs::write(store_dir(t.path()).join(format!("{ID2}.json")), b"{ torn").unwrap();
        let fs = real_fs();
        let e = receipts_inner(t.path(), &Env { now: NOW, fs: &fs }, None, None).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        let e = inbox_for_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            PID,
            START,
            false,
            false,
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        // a mutating call holds the lock, so it moves the bad record aside and succeeds
        let mut d = dv(ID3, "a");
        d.issued_at = NOW + 4_990;
        d.expires_at = NOW + 9_000;
        assert!(deliver_at(t.path(), NOW + 5_000, &json(&d)).is_ok());
    }

    // ── rate limit and idempotency ──

    #[test]
    fn rate_limit_window_issuer_and_pid_reuse() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        // second inside the window: refused, with next_allowed_at
        let e = deliver_at(t.path(), NOW + 3_599, &json(&dv(ID2, "a"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::RateLimited);
        assert_eq!(e.next_allowed_at, Some(NOW + 3_600));
        // a refusal does not consume the limit and writes nothing
        assert_eq!(json_files(t.path()).len(), 1);
        // at the boundary: accepted
        let mut d = dv(ID2, "a");
        d.expires_at = NOW + 3_600 + 100;
        assert!(deliver_at(t.path(), NOW + 3_600, &json(&d)).is_ok());
        // a different issuer, same session, same instant: accepted
        let mut d = dv(ID3, "b");
        d.expires_at = NOW + 3_600 + 100;
        assert!(deliver_at(t.path(), NOW + 3_600, &json(&d)).is_ok());
    }

    #[test]
    fn rate_limit_is_per_started_at_so_pid_reuse_is_accepted() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let fs = real_fs();
        let mut d = dv(ID2, "a");
        d.target.started_at = START + 500;
        let r = deliver_inner(
            t.path(),
            &Env {
                now: NOW + 1,
                fs: &fs,
            },
            &Live {
                host: HOST,
                proc_start: &|_| Some(START + 500),
                unreadable: &|_| false,
                is_listed: &|_, _| true,
                handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
            },
            &json(&d),
        );
        assert!(
            r.is_ok(),
            "same pid with a new started_at is a different session: {r:?}"
        );
    }

    #[test]
    fn duplicate_id_returns_original_receipt_and_consumes_nothing() {
        let t = dir();
        let first = deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let again = deliver_at(t.path(), NOW + 60, &json(&dv(ID1, "a"))).unwrap();
        assert_eq!(
            first, again,
            "the original receipt, unchanged (queued_at stays NOW)"
        );
        assert_eq!(json_files(t.path()).len(), 1);
        // the duplicate did not extend the rate-limit window
        let mut d = dv(ID2, "a");
        d.expires_at = NOW + 3_700;
        assert!(deliver_at(t.path(), NOW + 3_600, &json(&d)).is_ok());
    }

    // ── lifecycle ──

    #[test]
    fn lifecycle_queued_surfaced_acknowledged_and_double_ack_refused() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let fs = real_fs();
        let env = |now| Env { now, fs: &fs };
        // read-only inbox does not transition
        let rows = inbox_for_inner(t.path(), &env(NOW + 1), PID, START, true, false).unwrap();
        assert_eq!(rows[0].receipt.status, "queued");
        assert_eq!(recs_at(t.path(), NOW + 1, None, None)[0].status, "queued");
        // mark_surfaced transitions
        let rows = inbox_for_inner(t.path(), &env(NOW + 2), PID, START, true, true).unwrap();
        assert_eq!(rows[0].receipt.status, "surfaced");
        assert_eq!(rows[0].receipt.surfaced_at, Some(NOW + 2));
        // surfacing again keeps the first surfaced_at
        let rows = inbox_for_inner(t.path(), &env(NOW + 9), PID, START, true, true).unwrap();
        assert_eq!(rows[0].receipt.surfaced_at, Some(NOW + 2));
        // ack
        let r = ack_at(t.path(), NOW + 20, ID1, "done").unwrap();
        assert_eq!(r.status, "acknowledged");
        assert_eq!(r.acknowledged_at, Some(NOW + 20));
        assert_eq!(r.ack.as_ref().unwrap().outcome, "done");
        // double ack refused, state unchanged
        let e = ack_at(t.path(), NOW + 30, ID1, "declined").unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        assert_eq!(
            recs_at(t.path(), NOW + 31, None, Some(ID1))[0]
                .ack
                .as_ref()
                .unwrap()
                .outcome,
            "done"
        );
        // pending_only now excludes it; the full inbox keeps it
        assert!(
            inbox_for_inner(t.path(), &env(NOW + 40), PID, START, true, false)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            inbox_for_inner(t.path(), &env(NOW + 40), PID, START, false, false)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn inbox_is_addressed_by_pid_and_started_at() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let fs = real_fs();
        let env = Env {
            now: NOW + 1,
            fs: &fs,
        };
        assert!(
            inbox_for_inner(t.path(), &env, PID + 1, START, false, false)
                .unwrap()
                .is_empty()
        );
        assert!(
            inbox_for_inner(t.path(), &env, PID, START + 2, false, false)
                .unwrap()
                .is_empty(),
            "pid reuse (two seconds apart is a different process)"
        );
    }

    #[test]
    fn expiry_is_read_as_expired_and_blocks_ack() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let after = NOW + 3_600; // == expires_at
        assert_eq!(recs_at(t.path(), after, None, None)[0].status, "expired");
        let e = ack_at(t.path(), after, ID1, "done").unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Expired);
        let fs = real_fs();
        let rows = inbox_for_inner(
            t.path(),
            &Env {
                now: after,
                fs: &fs,
            },
            PID,
            START,
            true,
            true,
        )
        .unwrap();
        assert!(
            rows.is_empty(),
            "expired directives are not pending and are never surfaced"
        );
        let p = pending_count_and_last_inner(t.path(), after, PID, START).unwrap();
        assert_eq!(p.pending, 0);
        assert_eq!(p.last_directive_at, Some(NOW));
    }

    #[test]
    fn ack_validates_outcome_id_and_existence() {
        let t = dir();
        assert_eq!(
            ack_at(t.path(), NOW, ID1, "done").unwrap_err().code,
            SdkErrorCode::InvalidInput,
            "no store"
        );
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        assert_eq!(
            ack_at(t.path(), NOW, ID1, "maybe").unwrap_err().code,
            SdkErrorCode::InvalidInput
        );
        assert_eq!(
            ack_at(t.path(), NOW, "../x", "done").unwrap_err().code,
            SdkErrorCode::InvalidInput
        );
        assert_eq!(
            ack_at(t.path(), NOW, ID2, "done").unwrap_err().code,
            SdkErrorCode::InvalidInput,
            "unknown id"
        );
    }

    #[test]
    fn pending_count_and_last_reports_count_first_summary_and_newest() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let mut d = dv(ID2, "b");
        d.summary = "second".into();
        d.expires_at = NOW + 4_000;
        deliver_at(t.path(), NOW + 100, &json(&d)).unwrap();
        let p = pending_count_and_last_inner(t.path(), NOW + 200, PID, START).unwrap();
        assert_eq!(p.pending, 2);
        assert_eq!(p.last_directive_at, Some(NOW + 100));
        assert_eq!(
            p.first_summary.as_deref(),
            Some("Move the build to another host.")
        );
        let none = pending_count_and_last_inner(t.path(), NOW + 200, PID + 1, START).unwrap();
        assert_eq!(
            (none.pending, none.last_directive_at, none.first_summary),
            (0, None, None)
        );
    }

    // ── review fixes: helpers ──

    fn uid(i: u32) -> String {
        format!("{i:08x}-7d0e-4b0a-9d3e-2f8f1a2b3c4d")
    }

    fn set_mtime(path: &Path, secs: u64) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    }

    fn deliver_hd(
        base: &Path,
        now: u64,
        raw: &str,
        hd: &Path,
    ) -> Result<DirectiveReceipt, DirectiveError> {
        let fs = real_fs();
        let start = |p: u32| (p == PID).then_some(START);
        let listed = |p: u32, s: u64| p == PID && same_start(s, START);
        let hdf = |_: u32, _: u64| Some(hd.to_path_buf());
        deliver_inner(
            base,
            &Env { now, fs: &fs },
            &Live {
                host: HOST,
                proc_start: &start,
                unreadable: &|_| false,
                is_listed: &listed,
                handle_dir_of: &hdf,
            },
            raw,
        )
    }

    /// Write a record straight into the store (bypassing `deliver`).
    fn seed(base: &Path, id: &str, pid: u32, queued_at: u64, acked: bool) {
        seed_full(base, id, pid, START, queued_at, acked, NOW + 3_600);
    }

    /// [`seed`] with the live start and the expiry chosen.
    fn seed_full(
        base: &Path,
        id: &str,
        pid: u32,
        start: u64,
        queued_at: u64,
        acked: bool,
        expires_at: u64,
    ) {
        let mut d = dv(id, "seed");
        d.target.pid = pid;
        d.target.started_at = start;
        d.expires_at = expires_at;
        let rec = Record {
            directive: d,
            queued_at,
            surfaced_at: None,
            acknowledged_at: acked.then_some(queued_at),
            ack: acked.then(|| DirectiveAck::new("done", None)),
            handle_dir: None,
            live_start: Some(start),
        };
        ensure_dir(&store_dir(base)).unwrap();
        save(&store_dir(base), &rec, &real_fs()).unwrap();
    }

    fn marker(handle: &Path, name: &str, pid: u32, mtime: u64) {
        std::fs::create_dir_all(handle).unwrap();
        let p = handle.join(name);
        std::fs::write(&p, pid.to_string()).unwrap();
        set_mtime(&p, mtime);
    }

    // ── M1: hidden Unicode, one test per class ──

    fn hidden_class_refused_everywhere(ch: char) {
        let t = dir();
        let bad = format!("a{ch}b");
        let fields: Vec<(&str, Directive)> = vec![
            ("summary", {
                let mut d = dv(ID1, "a");
                d.summary = bad.clone();
                d
            }),
            ("suggested", dv(ID1, "a").with_suggested(vec![bad.clone()])),
            ("metric", {
                let mut d = dv(ID1, "a");
                d.why.metric = bad.clone();
                d
            }),
            ("source", {
                let mut d = dv(ID1, "a");
                d.why.source = bad.clone();
                d
            }),
            ("scope", dv(ID1, "a").with_scope(Some(bad.clone()))),
        ];
        for (name, d) in fields {
            assert_eq!(
                code(deliver_at(t.path(), NOW, &json(&d))),
                SdkErrorCode::InvalidInput,
                "{name} U+{:04X}",
                ch as u32
            );
        }
        assert!(!store_dir(t.path()).exists(), "refusals write nothing");
        deliver_at(t.path(), NOW, &json(&dv(ID2, "a"))).unwrap();
        let fs = real_fs();
        let e = ack_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            ID2,
            "done",
            Some(&bad),
            &me,
        )
        .unwrap_err();
        assert_eq!(
            e.code,
            SdkErrorCode::InvalidInput,
            "note U+{:04X}",
            ch as u32
        );
        assert!(
            sanitize_display(&bad) == "ab",
            "render drops U+{:04X}",
            ch as u32
        );
    }

    macro_rules! hidden_class {
        ($name:ident, $ch:expr) => {
            #[test]
            fn $name() {
                hidden_class_refused_everywhere($ch);
            }
        };
    }
    hidden_class!(hidden_cc_control_refused, '\u{7}');
    hidden_class!(hidden_bidi_override_refused, '\u{202E}');
    hidden_class!(hidden_bidi_embedding_refused, '\u{202A}');
    hidden_class!(hidden_bidi_isolate_refused, '\u{2066}');
    hidden_class!(hidden_bidi_isolate_pop_refused, '\u{2069}');
    hidden_class!(hidden_zero_width_space_refused, '\u{200B}');
    hidden_class!(hidden_zero_width_joiner_refused, '\u{200D}');
    hidden_class!(hidden_word_joiner_refused, '\u{2060}');
    hidden_class!(hidden_bom_refused, '\u{FEFF}');
    hidden_class!(hidden_tag_character_refused, '\u{E0041}');
    hidden_class!(hidden_line_separator_refused, '\u{2028}');
    hidden_class!(hidden_paragraph_separator_refused, '\u{2029}');
    hidden_class!(hidden_private_use_refused, '\u{E000}');
    hidden_class!(hidden_unassigned_refused, '\u{0378}');

    #[test]
    fn ordinary_non_ascii_text_is_accepted() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.summary = "Déplacer le build — 日本語 ok\u{a0}!".into();
        assert!(deliver_at(t.path(), NOW, &json(&d)).is_ok());
    }

    #[test]
    fn loaded_record_with_hidden_characters_is_undetermined() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let p = record_path(&store_dir(t.path()), ID1);
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replace("Move the build", "Move\u{202E} the build")).unwrap();
        let fs = real_fs();
        let e = receipts_inner(t.path(), &Env { now: NOW, fs: &fs }, None, None).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
    }

    // ── M2: bounds ──

    #[test]
    fn pending_cap_holds_across_issuers_and_a_slot_frees_on_ack() {
        let t = dir();
        for i in 0..MAX_PENDING_PER_TARGET as u32 {
            let mut d = dv(&uid(i), &format!("issuer-{i}"));
            d.expires_at = NOW + 1_000 + u64::from(i);
            deliver_at(t.path(), NOW, &json(&d)).unwrap();
        }
        let e = deliver_at(t.path(), NOW, &json(&dv(&uid(99), "issuer-new"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::RateLimited);
        assert_eq!(e.next_allowed_at, Some(NOW + 1_000), "earliest expiry");
        // acknowledging one frees a slot
        ack_at(t.path(), NOW + 1, &uid(3), "done").unwrap();
        assert!(deliver_at(t.path(), NOW + 2, &json(&dv(&uid(99), "issuer-new"))).is_ok());
    }

    #[test]
    fn full_store_of_pending_records_refuses_with_the_earliest_expiry() {
        let t = dir();
        // every record pends on a LIVE session, expiries all different; the earliest
        // (NOW + 2_000) is neither the first nor the last seeded, and is not the new
        // record's own NOW + 3_600
        for i in 0..MAX_RECORDS as u32 {
            let expires = if i == 137 {
                NOW + 2_000
            } else {
                NOW + 5_000 + u64::from(i)
            };
            seed_full(
                t.path(),
                &uid(i),
                10_000 + i,
                START,
                NOW - 100,
                false,
                expires,
            );
        }
        let before = json_files(t.path());
        let e = deliver_all_live(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::RateLimited);
        assert_eq!(e.next_allowed_at, Some(NOW + 2_000), "earliest expires_at");
        let mut after = json_files(t.path());
        let mut before = before;
        before.sort();
        after.sort();
        assert_eq!(after, before, "a refused delivery changes nothing");
    }

    /// Deliver with a listing in which EVERY pid is a live session started at `START`.
    fn deliver_all_live(
        base: &Path,
        now: u64,
        raw: &str,
    ) -> Result<DirectiveReceipt, DirectiveError> {
        let fs = real_fs();
        deliver_inner(
            base,
            &Env { now, fs: &fs },
            &Live {
                host: HOST,
                proc_start: &|_| Some(START),
                unreadable: &|_| false,
                is_listed: &|_, s| same_start(s, START),
                handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
            },
            raw,
        )
    }

    #[test]
    fn scope_is_absent_or_exactly_the_delete_scope_for_every_kind() {
        let t = dir();
        let d = dv(ID1, "a").with_scope(Some("anything at all".to_string()));
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
        let long = dv(ID1, "a").with_scope(Some("s".repeat(MAX_TEXT_CHARS + 1)));
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&long))),
            SdkErrorCode::InvalidInput
        );
        let ok = dv(ID1, "a").with_scope(Some(DELETE_SCOPE.to_string()));
        assert!(deliver_at(t.path(), NOW, &json(&ok)).is_ok());
    }

    #[test]
    fn statusline_path_never_reads_unrelated_records() {
        let t = dir();
        let handle = t.path().join("term-1");
        deliver_hd(t.path(), NOW, &json(&dv(ID1, "a")), &handle_canon(&handle)).unwrap();
        marker(&handle, ".live-cc-pid", PID, NOW);
        // a corrupt record for another pid: a whole-store scan would fail on it
        std::fs::write(record_path(&store_dir(t.path()), ID2), b"{ torn").unwrap();
        let p = pend_at(t.path(), &handle, NOW + 1).unwrap().unwrap();
        assert_eq!(p.pending, 1);
        let fs = real_fs();
        assert!(receipts_inner(t.path(), &Env { now: NOW, fs: &fs }, None, None).is_err());
    }

    /// Statusline read with an injected start-time reader that knows every pid as `START`.
    fn pend_at(
        base: &Path,
        handle: &Path,
        now: u64,
    ) -> Result<Option<PendingInfo>, DirectiveError> {
        pending_for_handle_dir_at(base, handle, now, &|_| Some(START))
    }

    fn handle_canon(h: &Path) -> PathBuf {
        std::fs::create_dir_all(h).unwrap();
        std::fs::canonicalize(h).unwrap()
    }

    #[test]
    fn index_is_rebuilt_on_delivery_and_pruned_by_gc() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let idx = index_path(&store_dir(t.path()), PID, START);
        std::fs::remove_file(&idx).unwrap();
        deliver_at(t.path(), NOW, &json(&dv(ID2, "b"))).unwrap();
        assert_eq!(
            read_index(&store_dir(t.path()), PID, START).unwrap().len(),
            2
        );
        gc_inner(t.path(), NOW + RETENTION_SECS + 4_000).unwrap();
        assert!(json_files(t.path()).is_empty());
        assert!(!idx.exists(), "index of a pid with no records is removed");
    }

    // ── M3: caller binding ──

    #[test]
    fn ack_by_another_session_is_target_mismatch_and_changes_nothing() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let fs = real_fs();
        for (p, s) in [(PID + 1, START), (PID, START + 2)] {
            let e = ack_inner(
                t.path(),
                &Env {
                    now: NOW + 1,
                    fs: &fs,
                },
                ID1,
                "done",
                None,
                &move || Ok((p, s)),
            )
            .unwrap_err();
            assert_eq!(e.code, SdkErrorCode::TargetMismatch, "{p} {s}");
        }
        assert_eq!(
            recs_at(t.path(), NOW + 2, None, Some(ID1))[0].status,
            "queued"
        );
        assert!(ack_at(t.path(), NOW + 3, ID1, "done").is_ok());
    }

    #[test]
    fn ack_resolves_the_caller_only_after_the_request_is_well_formed() {
        let t = dir();
        let fs = real_fs();
        let boom = || -> Result<(u32, u64), DirectiveError> { panic!("caller resolved early") };
        let e = ack_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            ID1,
            "maybe",
            None,
            &boom,
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        let e = ack_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            ID1,
            "done",
            None,
            &|| Err(DirectiveError::undet("no caller")),
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
    }

    #[test]
    fn mark_surfaced_touches_only_the_callers_records() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        seed(t.path(), ID2, PID + 1, NOW, false);
        let fs = real_fs();
        let env = Env {
            now: NOW + 5,
            fs: &fs,
        };
        let mine = inbox_for_inner(t.path(), &env, PID, START, false, true).unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].receipt.status, "surfaced");
        let other = recs_at(t.path(), NOW + 6, None, Some(ID2));
        assert_eq!(
            other[0].status, "queued",
            "another session's record untouched"
        );
        assert!(other[0].surfaced_at.is_none());
    }

    // ── H2/M4: issued_at and remaining lifetime ──

    #[test]
    fn future_issued_at_and_long_remaining_lifetime_are_invalid_input() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.issued_at = NOW + MAX_ISSUED_SKEW_SECS + 1;
        d.expires_at = d.issued_at + 3_600;
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput,
            "issued_at beyond skew"
        );
        // issued within skew but life == max: expires_at - now > max
        let mut d = dv(ID1, "a");
        d.issued_at = NOW + MAX_ISSUED_SKEW_SECS;
        d.expires_at = d.issued_at + MAX_LIFETIME_SECS;
        assert_eq!(
            code(deliver_at(t.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput,
            "remaining lifetime beyond max"
        );
        // boundary: exactly the skew and a normal life is accepted
        let mut d = dv(ID1, "a");
        d.issued_at = NOW + MAX_ISSUED_SKEW_SECS;
        d.expires_at = d.issued_at + 3_600;
        assert!(deliver_at(t.path(), NOW, &json(&d)).is_ok());
    }

    // ── L1: record read safety ──

    /// A complete, valid record for `id` written outside the store under test.
    fn valid_record_text(id: &str) -> String {
        let other = dir();
        seed(other.path(), id, PID + 9, NOW, false);
        std::fs::read_to_string(record_path(&store_dir(other.path()), id)).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_record_is_undetermined() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        // the link target is a VALID record for ID2, so only the symlink refusal can fail it
        let real = t.path().join("elsewhere.json");
        std::fs::write(&real, valid_record_text(ID2)).unwrap();
        let link = record_path(&store_dir(t.path()), ID2);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let fs = real_fs();
        let e = receipts_inner(t.path(), &Env { now: NOW, fs: &fs }, None, None).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(e.message.contains("not a regular file"), "{}", e.message);
    }

    #[test]
    fn oversized_record_is_undetermined() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        // a VALID record padded with JSON whitespace past the cap: only the size bound refuses it
        let mut text = valid_record_text(ID2);
        text.push_str(&" ".repeat(MAX_RECORD_BYTES as usize));
        std::fs::write(record_path(&store_dir(t.path()), ID2), text).unwrap();
        let fs = real_fs();
        let e = receipts_inner(t.path(), &Env { now: NOW, fs: &fs }, None, None).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(e.message.contains("too large"), "{}", e.message);
    }

    #[test]
    fn record_that_vanished_is_skipped_not_an_error() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let gone = record_path(&store_dir(t.path()), ID2);
        assert!(load_record(&gone, ID2).unwrap().is_none());
        assert!(load_record(&record_path(&store_dir(t.path()), ID1), ID1)
            .unwrap()
            .is_some());
    }

    #[test]
    fn too_many_record_files_is_undetermined() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        // VALID records, so only the scan bound can refuse the directory
        let text = valid_record_text(ID2);
        for i in 0..=(4 * MAX_RECORDS) as u32 {
            let id = uid(i);
            std::fs::write(
                record_path(&store_dir(t.path()), &id),
                text.replace(ID2, &id),
            )
            .unwrap();
        }
        let e = load_all(&store_dir(t.path())).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
    }

    #[test]
    fn sweep_removes_stale_tmp_files_only() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let d = store_dir(t.path());
        let old = d.join(format!("{ID2}.tmp.1.1"));
        let fresh = d.join(format!("{ID3}.tmp.1.2"));
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&fresh, b"x").unwrap();
        set_mtime(&old, NOW - STALE_TMP_SECS - 5);
        set_mtime(&fresh, NOW - 5);
        gc_inner(t.path(), NOW).unwrap();
        assert!(!old.exists(), "stale tmp removed");
        assert!(fresh.exists(), "fresh tmp kept");
    }

    // ── L2: errors are not absence ──

    #[cfg(unix)]
    #[test]
    fn unstattable_store_is_undetermined_in_ack_gc_and_statusline() {
        let t = dir();
        let blocker = t.path().join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        assert_eq!(
            ack_at(&blocker, NOW, ID1, "done").unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        assert_eq!(
            gc_inner(&blocker, NOW).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        let handle = t.path().join("term-1");
        marker(&handle, ".live-cc-pid", PID, NOW);
        let e = pend_at(&blocker, &handle, NOW).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
    }

    #[test]
    fn absent_store_and_absent_marker_show_nothing() {
        let t = dir();
        let handle = t.path().join("term-1");
        marker(&handle, ".live-cc-pid", PID, NOW);
        assert_eq!(pend_at(t.path(), &handle, NOW).unwrap(), None);
        assert_eq!(gc_inner(t.path(), NOW).ok(), Some(()));
    }

    // ── L3: symlinked store dir / lock, lock timeout ──

    #[cfg(unix)]
    #[test]
    fn symlinked_store_dir_and_lock_are_undetermined() {
        let t = dir();
        let real = t.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        let base = t.path().join("base");
        std::fs::create_dir_all(&base).unwrap();
        std::os::unix::fs::symlink(&real, store_dir(&base)).unwrap();
        assert_eq!(
            code(deliver_at(&base, NOW, &json(&dv(ID1, "a")))),
            SdkErrorCode::Undetermined
        );
        let fs = real_fs();
        let e = receipts_inner(&base, &Env { now: NOW, fs: &fs }, None, None).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(
            std::fs::read_dir(&real).unwrap().next().is_none(),
            "nothing written through it"
        );

        let base2 = t.path().join("base2");
        ensure_dir(&store_dir(&base2)).unwrap();
        let target = t.path().join("lock-target");
        std::fs::write(&target, b"").unwrap();
        let mode_of = |p: &Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        };
        std::fs::set_permissions(&target, {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o644)
        })
        .unwrap();
        std::os::unix::fs::symlink(&target, store_dir(&base2).join(".lock")).unwrap();
        assert_eq!(
            code(deliver_at(&base2, NOW, &json(&dv(ID1, "a")))),
            SdkErrorCode::Undetermined
        );
        assert_eq!(
            mode_of(&target),
            0o644,
            "the symlink target must be neither locked nor chmod-ed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dropped_store_lock_releases_even_while_a_fork_child_holds_its_description() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::time::Instant;

        struct ForkChild {
            pid: Option<libc::pid_t>,
            control: UnixStream,
        }
        impl ForkChild {
            fn finish(&mut self) -> io::Result<i32> {
                let _ = self.control.write_all(b"x");
                let Some(pid) = self.pid else {
                    return Ok(0);
                };
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    let mut status = 0;
                    // SAFETY: this fixture owns this unreaped child; status is writable.
                    let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                    if result == pid {
                        self.pid = None;
                        return Ok(status);
                    }
                    if result == -1 {
                        let error = io::Error::last_os_error();
                        if error.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        self.pid = None;
                        return Err(error);
                    }
                    if Instant::now() >= deadline {
                        // Fresh waitpid returned 0: our child is still alive and unreaped.
                        // SAFETY: kill/waitpid target only that owned child, not a group.
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                        // Reap after timeout cleanup; no competing waiter exists here.
                        while unsafe { libc::waitpid(pid, &mut status, 0) } == -1 {
                            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                                break;
                            }
                        }
                        self.pid = None;
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "owned fork child did not exit",
                        ));
                    }
                    // Bounded reaping poll, not a readiness delay: readiness uses the socket.
                    std::thread::park_timeout(Duration::from_millis(10));
                }
            }
        }
        impl Drop for ForkChild {
            fn drop(&mut self) {
                if self.pid.is_some() {
                    let _ = self.finish();
                }
            }
        }

        let t = dir();
        let path = t.path().join(".lock");
        let held = acquire_store_lock_attempts_as("fixture", &path, 1).unwrap();
        let lock_fd = held._file.as_raw_fd();
        let (parent, child) = UnixStream::pair().unwrap();
        for endpoint in [&parent, &child] {
            endpoint
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            endpoint
                .set_write_timeout(Some(Duration::from_secs(30)))
                .unwrap();
        }
        let parent_fd = parent.as_raw_fd();
        let child_fd = child.as_raw_fd();
        // SAFETY: the child branch uses only async-signal-safe integer/descriptor syscalls,
        // stack bytes, and _exit. It never allocates, locks a Rust mutex, or drops inherited
        // Rust values in this multi-threaded test process.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::close(parent_fd);
                let mut byte = 1u8;
                if libc::fcntl(lock_fd, libc::F_GETFD) == -1
                    || libc::write(child_fd, (&byte as *const u8).cast(), 1) != 1
                    || libc::read(child_fd, (&mut byte as *mut u8).cast(), 1) != 1
                    || byte != b'a'
                {
                    libc::_exit(1);
                }
                // Parent has dropped its guard; the copied description is still open here.
                byte = 2;
                if libc::fcntl(lock_fd, libc::F_GETFD) == -1
                    || libc::write(child_fd, (&byte as *const u8).cast(), 1) != 1
                    || libc::read(child_fd, (&mut byte as *mut u8).cast(), 1) != 1
                    || byte != b'x'
                {
                    libc::_exit(2);
                }
                libc::_exit(0);
            }
        }
        drop(child);
        let mut child = ForkChild {
            pid: Some(pid),
            control: parent,
        };
        let mut byte = [0u8];
        child.control.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [1], "child must hold the inherited lock descriptor");
        assert!(
            acquire_store_lock_attempts_as("fixture", &path, 1).is_err(),
            "guard still holds the lock"
        );
        drop(held);
        child.control.write_all(b"a").unwrap();
        child.control.read_exact(&mut byte).unwrap();
        assert_eq!(
            byte,
            [2],
            "child descriptor must remain open after guard drop"
        );
        let acquired = acquire_store_lock_attempts_as("fixture", &path, 1);
        // Join our child BEFORE asserting, so the RED path cannot leak it or copied locks.
        let status = child.finish().unwrap();
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert!(
            acquired.is_ok(),
            "dropped guard must explicitly unlock despite the inherited open description"
        );
    }

    #[cfg(unix)]
    #[test]
    fn message_lock_production_profile_admits_release_after_one_second() {
        let d = dir();
        let path = d.path().join(".lock");
        let mut held = Some(acquire_message_store_lock_as("fixture", &path).unwrap());
        let mut rounds = Vec::new();
        let started = std::time::Instant::now();
        let result =
            acquire_message_store_lock_with_round_hook_as("fixture", &path, &mut |round| {
                rounds.push(round);
                // Hold a real conflicting lock for more than the old accelerated
                // profile's entire one-second budget, then release before retry.
                std::thread::sleep(Duration::from_millis(1100));
                drop(held.take());
            });
        assert!(held.is_none(), "release point must execute under RED too");
        assert!(started.elapsed() > Duration::from_secs(1));
        assert_eq!(rounds, vec![0]);
        assert!(
            result.is_ok(),
            "message admission must use the production profile"
        );
    }

    /// Windows named mutexes are re-entrant per thread, so the holder MUST be another
    /// thread. Falsifier: drop `.with_cause(LockTimeout)` on the Windows timeout arm and
    /// `cause` is `None`.
    #[cfg(windows)]
    #[test]
    fn windows_lock_timeout_carries_the_typed_cause_against_a_holder_on_another_thread() {
        let d = dir();
        let path = d.path().join(".lock");
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder_path = path.clone();
        let holder = std::thread::spawn(move || {
            let guard = acquire_store_lock_as("holder", &holder_path).unwrap();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
            drop(guard);
        });
        held_rx.recv().unwrap();
        let error =
            acquire_store_lock_attempts_delay_as("fixture", &path, 2, Duration::from_millis(5))
                .err()
                .expect("a lock held by another thread must time out");
        assert_eq!(error.message, "fixture: lock timed out");
        assert_eq!(error.cause, Some(UndeterminedCause::LockTimeout));
        release_tx.send(()).unwrap();
        holder.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn message_lock_production_profile_refuses_release_after_shared_deadline() {
        let d = dir();
        let path = d.path().join(".lock");
        let mut held = Some(acquire_message_store_lock_as("fixture", &path).unwrap());
        let mut rounds = Vec::new();
        let started = std::time::Instant::now();
        let budget = MESSAGE_LOCK_DELAY.saturating_mul(MESSAGE_LOCK_ATTEMPTS * MESSAGE_LOCK_ROUNDS);
        let result =
            acquire_message_store_lock_with_round_hook_as("fixture", &path, &mut |round| {
                rounds.push(round);
                // Consume the entire shared budget after a genuine exhausted round.
                // A new per-round deadline would wrongly admit after this release.
                std::thread::sleep(budget);
                drop(held.take());
            });
        assert!(held.is_none());
        assert!(started.elapsed() >= budget);
        assert_eq!(
            rounds,
            vec![0],
            "expired admission must never start another round"
        );
        assert_eq!(result.err().unwrap().message, "fixture: lock timed out");
        assert!(
            acquire_message_store_lock_as("fixture", &path).is_ok(),
            "late refusal must retain no lock"
        );
    }

    #[cfg(unix)]
    #[test]
    fn message_lock_production_profile_refuses_unsafe_files_without_retry() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let target = d.path().join("foreign");
        std::fs::write(&target, b"foreign bytes").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = d.path().join("unsafe.lock");
        for hard_link in [false, true] {
            if hard_link {
                std::fs::hard_link(&target, &path).unwrap();
            } else {
                std::os::unix::fs::symlink(&target, &path).unwrap();
            }
            let mut rounds = Vec::new();
            let result =
                acquire_message_store_lock_with_round_hook_as("fixture", &path, &mut |round| {
                    rounds.push(round)
                });
            assert!(result.is_err());
            assert!(
                rounds.is_empty(),
                "unsafe files must refuse before any retry"
            );
            assert_eq!(std::fs::read(&target).unwrap(), b"foreign bytes");
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o644
            );
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::create_dir(&path).unwrap();
        let mut rounds = Vec::new();
        assert!(
            acquire_message_store_lock_with_round_hook_as("fixture", &path, &mut |round| rounds
                .push(round),)
            .is_err()
        );
        assert!(rounds.is_empty(), "open/type failures must never retry");
    }

    #[cfg(unix)]
    #[test]
    fn gate_ledger_lock_retries_once_after_transient_contention() {
        let d = dir();
        let path = d.path().join(".demotion-lock");
        let mut held = Some(acquire_gate_ledger_lock_as("fixture", &path).unwrap());
        let mut rounds = Vec::new();
        // A FIXED clock (D237 R2 corr L2): a loaded runner must not expire the
        // one-second admission budget before the retry the row exists to observe.
        let base = std::time::Instant::now();
        let mut clock = move || base;
        let acquired = acquire_store_lock_policy_with_clock_as(
            "fixture",
            &path,
            GATE_LEDGER_LOCK_ATTEMPTS,
            GATE_LEDGER_LOCK_ROUNDS,
            GATE_LEDGER_LOCK_DELAY,
            &mut |round| {
                rounds.push(round);
                // A genuine exhausted contention round precedes release. The callback
                // only coordinates this fixture; production uses the same lock policy.
                drop(held.take());
            },
            &mut clock,
        );
        assert!(held.is_none(), "release point must execute even under RED");
        assert_eq!(rounds, vec![0]);
        assert!(
            acquired.is_ok(),
            "Gate must admit the single contention retry"
        );
    }

    #[cfg(unix)]
    #[test]
    fn gate_ledger_lock_refuses_late_retry_and_releases_ownership() {
        let d = dir();
        let path = d.path().join(".demotion-lock");
        let mut held = Some(acquire_gate_ledger_lock_as("fixture", &path).unwrap());
        let mut rounds = Vec::new();
        let started = std::time::Instant::now();
        let budget = GATE_LEDGER_LOCK_DELAY
            .saturating_mul(GATE_LEDGER_LOCK_ATTEMPTS * GATE_LEDGER_LOCK_ROUNDS);
        let result = acquire_gate_ledger_lock_with_round_hook_as("fixture", &path, &mut |round| {
            rounds.push(round);
            // Deliberately consume the shared admission budget before release.
            // Counting fresh attempts per round would incorrectly admit this retry.
            std::thread::sleep(
                (started + budget).saturating_duration_since(std::time::Instant::now())
                    + Duration::from_millis(20),
            );
            drop(held.take());
        });
        assert!(held.is_none());
        assert_eq!(
            rounds,
            vec![0],
            "late admission must never start a new round"
        );
        let error = result.err().expect("late Gate admission must refuse");
        assert_eq!(error.message, "fixture: lock timed out");
        assert!(acquire_gate_ledger_lock_as("fixture", &path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn gate_ledger_lock_preserves_exhaustion_and_refuses_unsafe_files_without_retry() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        let path = d.path().join(".demotion-lock");
        let held = acquire_gate_ledger_lock_as("fixture", &path).unwrap();
        let mut rounds = Vec::new();
        // A fixed clock: a loaded runner's wall time must not expire the shared budget
        // before round 1, which is what this row asserts is entered.
        let base = std::time::Instant::now();
        let mut clock = move || base;
        let result = acquire_store_lock_policy_with_clock_as(
            "fixture",
            &path,
            GATE_LEDGER_LOCK_ATTEMPTS,
            GATE_LEDGER_LOCK_ROUNDS,
            GATE_LEDGER_LOCK_DELAY,
            &mut |round| rounds.push(round),
            &mut clock,
        );
        assert_eq!(rounds, vec![0, 1], "only one internal retry is permitted");
        assert_eq!(result.err().unwrap().message, "fixture: lock timed out");
        drop(held);

        let target = d.path().join("foreign");
        std::fs::write(&target, b"foreign bytes").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let unsafe_lock = d.path().join("unsafe.lock");
        for hard_link in [false, true] {
            if hard_link {
                std::fs::hard_link(&target, &unsafe_lock).unwrap();
            } else {
                std::os::unix::fs::symlink(&target, &unsafe_lock).unwrap();
            }
            rounds.clear();
            let result = acquire_gate_ledger_lock_with_round_hook_as(
                "fixture",
                &unsafe_lock,
                &mut |round| rounds.push(round),
            );
            assert!(result.is_err());
            assert!(rounds.is_empty(), "security failures must never retry");
            assert_eq!(std::fs::read(&target).unwrap(), b"foreign bytes");
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o644
            );
            std::fs::remove_file(&unsafe_lock).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn store_retention_lock_retry_shares_elapsed_budget() {
        let d = dir();
        let path = d.path().join(".lock");
        let mut held = Some(acquire_store_lock_attempts_as("fixture", &path, 1).unwrap());
        let mut rounds = Vec::new();
        let started = std::time::Instant::now();
        let admission_budget = LOCK_DELAY.saturating_mul(4);
        let result = acquire_store_lock_policy_as("fixture", &path, 2, 2, &mut |round| {
            rounds.push(round);
            // The first round really exhausted contention. Release the lock only after
            // the shared elapsed budget; old attempt-count-only code admits on retry.
            std::thread::sleep(admission_budget.saturating_mul(2));
            drop(held.take());
        });
        assert!(held.is_none(), "falsifying release point must execute");
        assert!(started.elapsed() >= admission_budget);
        assert_eq!(
            rounds,
            vec![0],
            "expired admission never starts a second round"
        );
        let error = result
            .err()
            .expect("shared elapsed budget must refuse late admission");
        assert_eq!(error.code, SdkErrorCode::Undetermined);
        assert_eq!(error.message, "fixture: lock timed out");
        assert!(
            acquire_store_lock_attempts_as("fixture", &path, 1).is_ok(),
            "timeout never retains ownership of a released lock"
        );
        eprintln!(
            "store lock admission budget_ms={} observed_ms={}",
            admission_budget.as_millis(),
            started.elapsed().as_millis()
        );
    }

    #[cfg(unix)]
    #[test]
    fn code_red2_lock_retries_only_contention_once_and_preserves_exhaustion() {
        use std::sync::mpsc;
        let d = dir();
        let path = d.path().join(".lock");
        let held = acquire_store_lock_attempts_as("fixture", &path, 1).unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            release_rx.recv().unwrap();
            drop(held);
            done_tx.send(()).unwrap();
        });
        let mut rounds = Vec::new();
        // The injected clock never advances, so a loaded runner's wall time cannot expire
        // the shared admission budget before the retry round under test is entered.
        let base = std::time::Instant::now();
        let mut clock = move || base;
        let acquired = acquire_store_lock_policy_with_clock_as(
            "fixture",
            &path,
            2,
            2,
            LOCK_DELAY,
            &mut |round| {
                rounds.push(round);
                release_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            },
            &mut clock,
        );
        worker.join().unwrap();
        assert!(acquired.is_ok(), "lock must acquire in the single retry");
        assert_eq!(rounds, vec![0]);
        drop(acquired);
        let _held = acquire_store_lock_attempts_as("fixture", &path, 1).unwrap();
        let mut rounds = Vec::new();
        // Exhaustion comes from the bounded rounds below, never from the wall clock.
        let e = acquire_store_lock_policy_with_clock_as(
            "fixture",
            &path,
            2,
            2,
            LOCK_DELAY,
            &mut |r| rounds.push(r),
            &mut clock,
        )
        .err()
        .unwrap();
        assert_eq!(rounds, vec![0, 1]);
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert_eq!(e.message, "fixture: lock timed out");
        let bad = d.path().join("bad.lock");
        std::fs::create_dir(&bad).unwrap();
        let mut rounds = Vec::new();
        assert!(
            acquire_store_lock_policy_as("fixture", &bad, 2, 2, &mut |r| rounds.push(r)).is_err()
        );
        assert!(
            rounds.is_empty(),
            "open/security failures are never retried"
        );
    }

    #[cfg(unix)]
    #[test]
    fn held_lock_times_out_as_undetermined() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let lock = store_dir(t.path()).join(".lock");
        let _held = crate::platform::lock::lock_file(&lock).unwrap();
        let e = deliver_at(t.path(), NOW, &json(&dv(ID2, "b"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(e.message.contains("timed out"), "{}", e.message);
    }

    // ── L4: statusline pid tied to the session ──

    #[test]
    fn statusline_requires_the_recorded_handle_dir() {
        let t = dir();
        let (a, b) = (t.path().join("term-a"), t.path().join("term-b"));
        deliver_hd(t.path(), NOW, &json(&dv(ID1, "a")), &handle_canon(&a)).unwrap();
        handle_canon(&b);
        marker(&a, ".live-cc-pid", PID, NOW);
        marker(&b, ".live-cc-pid", PID, NOW);
        let pa = pend_at(t.path(), &a, NOW + 1).unwrap().unwrap();
        let pb = pend_at(t.path(), &b, NOW + 1).unwrap().unwrap();
        assert_eq!(
            (pa.pending, pb.pending),
            (1, 0),
            "same pid, other handle dir"
        );
    }

    #[test]
    fn live_pid_marker_is_the_fallback_and_cc_marker_wins() {
        let t = dir();
        let h = t.path().join("term-1");
        deliver_hd(t.path(), NOW, &json(&dv(ID1, "a")), &handle_canon(&h)).unwrap();
        marker(&h, ".live-pid", PID, NOW);
        let p = pend_at(t.path(), &h, NOW + 1).unwrap().unwrap();
        assert_eq!(p.pending, 1, ".live-pid fallback");
        marker(&h, ".live-cc-pid", PID + 7, NOW);
        let p = pend_at(t.path(), &h, NOW + 1).unwrap().unwrap();
        assert_eq!(p.pending, 0, ".live-cc-pid takes precedence over .live-pid");
    }

    #[test]
    fn pending_is_none_without_a_pid_marker() {
        let t = dir();
        let handle = t.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        assert_eq!(pend_at(t.path(), &handle, NOW).unwrap(), None);
    }

    // ── M1 (order): shape before host / process table ──

    fn panicking<T>(what: &'static str) -> impl Fn() -> T {
        move || panic!("{what} consulted before the directive was validated")
    }

    #[test]
    fn malformed_directive_is_invalid_input_before_host_clock_or_process_table() {
        let t = dir();
        let fs = real_fs();
        let mut d = dv(ID1, "a");
        d.summary = "bad\u{202E}".into();
        let r = deliver_via(
            t.path(),
            &json(&d),
            &panicking::<Option<String>>("host"),
            &panicking::<Result<u64, DirectiveError>>("clock"),
            &panicking::<Option<Vec<super::super::SessionInfo>>>("process table"),
            &fs,
        );
        assert_eq!(code(r), SdkErrorCode::InvalidInput);
        // a VALID directive does need them: unreadable host is undetermined
        let r = deliver_via(
            t.path(),
            &json(&dv(ID1, "a")),
            &|| None,
            &|| Ok(NOW),
            &|| Some(Vec::new()),
            &fs,
        );
        assert_eq!(code(r), SdkErrorCode::Undetermined);
    }

    #[test]
    fn delivery_records_the_listed_sessions_canonical_handle_dir() {
        let t = dir();
        let h = t.path().join("term-1");
        let hc = handle_canon(&h);
        let session = super::super::SessionInfo {
            pid: PID,
            cwd: PathBuf::from("/"),
            config_dir: h.clone(),
            account_id: None,
            started_at: Some(START),
            tty: None,
            term_window: None,
            term_tab: None,
            term_pane: None,
            iterm_profile: None,
            terminal_title: None,
        };
        deliver_via(
            t.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &|| Some(vec![session.clone()]),
            &real_fs(),
        )
        .unwrap();
        let rec = load_record(&record_path(&store_dir(t.path()), ID1), ID1)
            .unwrap()
            .unwrap();
        assert_eq!(rec.handle_dir.as_deref(), Some(hc.to_str().unwrap()));
    }

    // ── receipts --since ──

    #[test]
    fn receipts_filter_since_and_sort_by_last_transition() {
        let t = dir();
        let fs = real_fs();
        // three directives to three different issuers so none is rate limited
        for (i, (id, issuer)) in [(ID1, "a"), (ID2, "b"), (ID3, "c")].into_iter().enumerate() {
            deliver_at(t.path(), NOW + (i as u64) * 10, &json(&dv(id, issuer))).unwrap();
        }
        let all = recs_at(t.path(), NOW + 50, None, None);
        assert_eq!(
            all.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec![ID1, ID2, ID3]
        );
        // ack the FIRST at a later time: its last transition now sorts last
        ack_inner(
            t.path(),
            &Env {
                now: NOW + 100,
                fs: &fs,
            },
            ID1,
            "done",
            Some("ok"),
            &me,
        )
        .unwrap();
        let all = recs_at(t.path(), NOW + 101, None, None);
        assert_eq!(
            all.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec![ID2, ID3, ID1]
        );
        // since is inclusive and filters by last transition, not queued_at
        let since = recs_at(t.path(), NOW + 101, Some(NOW + 20), None);
        assert_eq!(
            since.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec![ID3, ID1]
        );
        let since = recs_at(t.path(), NOW + 101, Some(NOW + 101), None);
        assert!(since.is_empty());
        let one = recs_at(t.path(), NOW + 101, None, Some(ID2));
        assert_eq!(one.len(), 1);
        assert_eq!(
            recs_at(
                t.path(),
                NOW + 101,
                None,
                Some("2b6c3c1e-0000-4000-8000-000000000000")
            )
            .len(),
            0
        );
        assert_eq!(
            receipts_inner(t.path(), &Env { now: NOW, fs: &fs }, None, Some("bad"))
                .unwrap_err()
                .code,
            SdkErrorCode::InvalidInput
        );
    }

    #[test]
    fn receipts_on_missing_store_is_empty_not_error() {
        let t = dir();
        assert!(recs_at(t.path(), NOW, None, None).is_empty());
    }

    // ── retention GC ──

    #[test]
    fn gc_deletes_seven_days_after_last_transition() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap(); // expires NOW+3600
        let mut d = dv(ID2, "b");
        d.expires_at = NOW + 5_000;
        deliver_at(t.path(), NOW, &json(&d)).unwrap();
        ack_at(t.path(), NOW + 1_000, ID2, "done").unwrap();
        // ID1: last transition = expires_at (NOW+3600); ID2: acknowledged NOW+1000.
        gc_inner(t.path(), NOW + 1_000 + RETENTION_SECS - 1).unwrap();
        assert_eq!(json_files(t.path()).len(), 2, "one second early: both kept");
        gc_inner(t.path(), NOW + 1_000 + RETENTION_SECS).unwrap();
        assert_eq!(
            json_files(t.path()),
            vec![format!("{ID1}.json")],
            "ack'd one gone, expired one still young"
        );
        gc_inner(t.path(), NOW + 3_600 + RETENTION_SECS).unwrap();
        assert!(json_files(t.path()).is_empty());
    }

    #[test]
    fn mutating_calls_run_gc_opportunistically() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let later = NOW + 3_600 + RETENTION_SECS + 5;
        let mut d = dv(ID2, "a");
        d.issued_at = later - 10;
        d.expires_at = later + MIN_LIFETIME_SECS;
        deliver_at(t.path(), later, &json(&d)).unwrap();
        assert_eq!(json_files(t.path()), vec![format!("{ID2}.json")]);
    }

    // ── modes ──

    #[cfg(unix)]
    #[test]
    fn store_dir_is_0700_and_files_0600() {
        use std::os::unix::fs::PermissionsExt;
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(store_dir(t.path())), 0o700);
        assert_eq!(mode(store_dir(t.path()).join(format!("{ID1}.json"))), 0o600);
        assert_eq!(mode(store_dir(t.path()).join(".lock")), 0o600);
        // an ack rewrite keeps the mode
        ack_at(t.path(), NOW + 1, ID1, "done").unwrap();
        assert_eq!(mode(store_dir(t.path()).join(format!("{ID1}.json"))), 0o600);
    }

    // ── tmp cleanup on every failure branch ──

    fn tmp_leftovers(base: &Path) -> Vec<String> {
        std::fs::read_dir(store_dir(base))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.contains(".tmp."))
            .collect()
    }

    fn fail() -> PlatformError {
        PlatformError::Io(io::Error::other("injected"))
    }

    fn deliver_with_fs(base: &Path, fs: &FsOps<'_>) -> Result<DirectiveReceipt, DirectiveError> {
        deliver_inner(
            base,
            &Env { now: NOW, fs },
            &Live {
                host: HOST,
                proc_start: &|_| Some(START),
                unreadable: &|_| false,
                is_listed: &|_, _| true,
                handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
            },
            &json(&dv(ID1, "a")),
        )
    }

    #[test]
    fn tmp_is_removed_when_replace_fails() {
        let t = dir();
        let replaced = Cell::new(0);
        let replace = |_: &Path, _: &Path| {
            replaced.set(replaced.get() + 1);
            Err(fail())
        };
        let fs = FsOps {
            write_tmp: &write_new_private,
            secure: &secure_file,
            replace: &replace,
        };
        let e = deliver_with_fs(t.path(), &fs).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert_eq!(replaced.get(), 1, "the failing replace was reached");
        assert!(
            tmp_leftovers(t.path()).is_empty(),
            "tmp must be removed: {:?}",
            tmp_leftovers(t.path())
        );
        assert!(json_files(t.path()).is_empty(), "no partial record");
    }

    #[test]
    fn tmp_is_removed_when_secure_fails() {
        let t = dir();
        let secure = |_: &Path| Err(fail());
        let fs = FsOps {
            write_tmp: &write_new_private,
            secure: &secure,
            replace: &atomic_replace,
        };
        assert_eq!(
            deliver_with_fs(t.path(), &fs).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        assert!(tmp_leftovers(t.path()).is_empty());
        assert!(json_files(t.path()).is_empty());
    }

    #[test]
    fn tmp_is_removed_when_write_fails_after_creating_it() {
        let t = dir();
        // a writer that created the file and then failed (the shape §5a guards against)
        let write = |p: &Path, b: &[u8]| {
            std::fs::write(p, b).unwrap();
            Err(fail())
        };
        let fs = FsOps {
            write_tmp: &write,
            secure: &secure_file,
            replace: &atomic_replace,
        };
        assert_eq!(
            deliver_with_fs(t.path(), &fs).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        assert!(tmp_leftovers(t.path()).is_empty());
    }

    #[test]
    fn failed_ack_write_leaves_the_record_unchanged() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let replace = |_: &Path, _: &Path| Err(fail());
        let fs = FsOps {
            write_tmp: &write_new_private,
            secure: &secure_file,
            replace: &replace,
        };
        let e = ack_inner(
            t.path(),
            &Env {
                now: NOW + 1,
                fs: &fs,
            },
            ID1,
            "done",
            None,
            &me,
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(tmp_leftovers(t.path()).is_empty());
        assert_eq!(
            recs_at(t.path(), NOW + 2, None, Some(ID1))[0].status,
            "queued"
        );
    }

    // ── round 2: hidden text, the full Default_Ignorable set ──

    hidden_class!(hidden_variation_selector_refused, '\u{FE0F}');
    hidden_class!(hidden_variation_selector_supplement_refused, '\u{E0100}');
    hidden_class!(hidden_combining_grapheme_joiner_refused, '\u{034F}');
    hidden_class!(hidden_mongolian_selector_refused, '\u{180B}');
    hidden_class!(hidden_khmer_inherent_vowel_refused, '\u{17B4}');
    hidden_class!(hidden_hangul_choseong_filler_refused, '\u{115F}');
    hidden_class!(hidden_hangul_jungseong_filler_refused, '\u{1160}');
    hidden_class!(hidden_hangul_filler_refused, '\u{3164}');
    hidden_class!(hidden_halfwidth_hangul_filler_refused, '\u{FFA0}');
    hidden_class!(hidden_braille_blank_refused, '\u{2800}');
    hidden_class!(hidden_soft_hyphen_refused, '\u{00AD}');
    hidden_class!(hidden_arabic_letter_mark_refused, '\u{061C}');

    #[test]
    fn every_default_ignorable_code_point_is_forbidden_and_is_display_unsafe() {
        let mut n = 0u32;
        for &(lo, hi) in DEFAULT_IGNORABLE {
            for u in lo..=hi {
                let Some(c) = char::from_u32(u) else { continue };
                assert!(is_forbidden_char(c), "U+{u:04X}");
                assert!(is_display_unsafe(c), "U+{u:04X}");
                assert!(hidden_char(c), "U+{u:04X} must hold on load too");
                n += 1;
            }
        }
        assert!(n > 4_000, "the E0000 block alone is 4096 points: {n}");
        for c in ['a', 'é', '日', ' ', '-', '\u{a0}', '\u{2014}'] {
            assert!(!is_display_unsafe(c), "{c:?}");
        }
        // combining marks (Mn / Me) are display-unsafe but NOT refused in directive text
        assert!(is_display_unsafe('\u{0301}') && is_display_unsafe('\u{20DD}'));
        assert!(!is_forbidden_char('\u{0301}'));
    }

    // ── round 2: Unicode-version skew on load, quarantine of bad records ──

    #[test]
    fn unassigned_character_is_refused_at_deliver_dropped_at_render_but_loadable() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.summary = "a\u{0378}b".into();
        // a newer csq accepted it (it is assigned there); this csq sees Cn
        let rec = Record {
            directive: d.clone(),
            queued_at: NOW,
            surfaced_at: None,
            acknowledged_at: None,
            ack: None,
            handle_dir: None,
            live_start: None,
        };
        ensure_dir(&store_dir(t.path())).unwrap();
        save(&store_dir(t.path()), &rec, &real_fs()).unwrap();
        let r = recs_at(t.path(), NOW + 1, None, Some(ID1));
        assert_eq!(
            r.len(),
            1,
            "a Cn character must not make the record unreadable"
        );
        assert!(
            rejected_names(t.path()).is_empty(),
            "and must not quarantine it"
        );
        assert_eq!(sanitize_display(&d.summary), "ab");
        let t2 = dir();
        assert_eq!(
            code(deliver_at(t2.path(), NOW, &json(&d))),
            SdkErrorCode::InvalidInput
        );
    }

    fn rejected_names(base: &Path) -> Vec<String> {
        let mut v: Vec<String> = match std::fs::read_dir(store_dir(base).join(REJECTED_DIR)) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect(),
            Err(_) => Vec::new(),
        };
        v.sort();
        v
    }

    /// Plant a bad `<ID2>.json` of the named kind in an existing store.
    fn plant_bad(base: &Path, kind: &str) {
        let p = record_path(&store_dir(base), ID2);
        match kind {
            "oversize" => {
                let mut text = valid_record_text(ID2);
                text.push_str(&" ".repeat(MAX_RECORD_BYTES as usize));
                std::fs::write(&p, text).unwrap();
            }
            "not_regular" => std::fs::create_dir(&p).unwrap(),
            "not_utf8" => std::fs::write(&p, [0xffu8, 0xfe, 0x00]).unwrap(),
            "unparseable" => std::fs::write(&p, b"{ torn").unwrap(),
            "id_mismatch" => std::fs::write(&p, valid_record_text(ID3)).unwrap(),
            "forbidden_text" => std::fs::write(
                &p,
                valid_record_text(ID2).replace("Move the build", "Move\u{202E} the build"),
            )
            .unwrap(),
            #[cfg(unix)]
            "symlink" => {
                let real = base.join("elsewhere.json");
                std::fs::write(&real, valid_record_text(ID2)).unwrap();
                std::os::unix::fs::symlink(&real, &p).unwrap();
            }
            other => panic!("unknown kind {other}"),
        }
    }

    #[test]
    fn a_bad_record_is_quarantined_by_the_next_mutating_call_and_never_blocks_the_store() {
        let kinds: &[&str] = &[
            "oversize",
            "not_regular",
            "not_utf8",
            "unparseable",
            "id_mismatch",
            "forbidden_text",
            #[cfg(unix)]
            "symlink",
        ];
        for kind in kinds {
            let t = dir();
            deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
            plant_bad(t.path(), kind);
            let fs = real_fs();
            let env = Env { now: NOW, fs: &fs };
            // lock-free reads still report could-not-determine
            assert_eq!(
                receipts_inner(t.path(), &env, None, None).unwrap_err().code,
                SdkErrorCode::Undetermined,
                "{kind}"
            );
            // a mutating call repairs it and succeeds
            let r = deliver_at(t.path(), NOW, &json(&dv(ID3, "b")));
            assert!(r.is_ok(), "{kind}: {r:?}");
            assert!(
                std::fs::symlink_metadata(record_path(&store_dir(t.path()), ID2)).is_err(),
                "{kind}: the bad entry left the store"
            );
            assert_eq!(rejected_names(t.path()).len(), 1, "{kind}");
            let ids: Vec<String> = recs_at(t.path(), NOW, None, None)
                .into_iter()
                .map(|r| r.id)
                .collect();
            assert_eq!(ids.len(), 2, "{kind}: receipts work afterwards: {ids:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejected_dir_is_0700_and_a_symlinked_rejected_dir_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        plant_bad(t.path(), "unparseable");
        deliver_at(t.path(), NOW, &json(&dv(ID3, "b"))).unwrap();
        let rej = store_dir(t.path()).join(REJECTED_DIR);
        assert_eq!(
            std::fs::metadata(&rej).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let t2 = dir();
        deliver_at(t2.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let elsewhere = t2.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, store_dir(t2.path()).join(REJECTED_DIR)).unwrap();
        plant_bad(t2.path(), "unparseable");
        let e = deliver_at(t2.path(), NOW, &json(&dv(ID3, "b"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(
            std::fs::read_dir(&elsewhere).unwrap().next().is_none(),
            "nothing moved through the symlink"
        );
        assert!(
            record_path(&store_dir(t2.path()), ID2).exists(),
            "bad record left in place"
        );
    }

    #[test]
    fn rejected_keeps_only_the_newest_twenty() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        for i in 0..(MAX_REJECTED as u64 + 5) {
            plant_bad(t.path(), "unparseable");
            gc_inner(t.path(), NOW + i).unwrap();
        }
        let names = rejected_names(t.path());
        assert_eq!(names.len(), MAX_REJECTED);
        // the quarantine time leads the name: the first five (NOW..NOW+4) are the ones gone
        assert!(
            names[0].starts_with(&format!("{:020}", NOW + 5)),
            "oldest kept: {}",
            names[0]
        );
    }

    // ── round 2: index reconciliation ──

    fn idx_exists(base: &Path) -> bool {
        index_path(&store_dir(base), PID, START).exists()
    }

    #[test]
    fn deleted_index_is_repaired_by_a_duplicate_delivery_and_by_a_noop_gc() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        assert!(idx_exists(t.path()));
        std::fs::remove_file(index_path(&store_dir(t.path()), PID, START)).unwrap();
        deliver_at(t.path(), NOW + 1, &json(&dv(ID1, "a"))).unwrap();
        assert!(
            idx_exists(t.path()),
            "idempotent duplicate delivery repairs the index"
        );
        std::fs::remove_file(index_path(&store_dir(t.path()), PID, START)).unwrap();
        gc_inner(t.path(), NOW + 2).unwrap();
        assert!(
            idx_exists(t.path()),
            "a gc that deletes nothing repairs the index"
        );
    }

    #[test]
    fn an_index_write_that_failed_is_repaired_by_the_next_mutating_call() {
        let t = dir();
        let replace = |tmp: &Path, target: &Path| {
            if target.extension().is_some_and(|e| e == "idx") {
                Err(fail())
            } else {
                atomic_replace(tmp, target)
            }
        };
        let fs = FsOps {
            write_tmp: &write_new_private,
            secure: &secure_file,
            replace: &replace,
        };
        // the record is durable, so the delivery succeeds; only the index is stale
        let r = deliver_with_fs(t.path(), &fs).unwrap();
        assert_eq!(r.status, "queued");
        assert!(json_files(t.path()).contains(&format!("{ID1}.json")));
        assert!(!idx_exists(t.path()), "the index write failed");
        assert!(tmp_leftovers(t.path()).is_empty());
        gc_inner(t.path(), NOW).unwrap();
        assert!(idx_exists(t.path()), "repaired");
        assert_eq!(
            read_index(&store_dir(t.path()), PID, START).unwrap(),
            vec![ID1.to_string()]
        );
    }

    #[test]
    fn an_unchanged_index_is_not_rewritten() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let writes = Cell::new(0);
        let write = |p: &Path, b: &[u8]| {
            writes.set(writes.get() + 1);
            write_new_private(p, b)
        };
        let fs = FsOps {
            write_tmp: &write,
            secure: &secure_file,
            replace: &atomic_replace,
        };
        let r = deliver_with_fs(t.path(), &fs).unwrap();
        assert_eq!(r.status, "queued");
        assert_eq!(
            writes.get(),
            0,
            "duplicate delivery with an intact index writes nothing"
        );
    }

    #[test]
    fn index_lists_only_pending_ids() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        deliver_at(t.path(), NOW, &json(&dv(ID2, "b"))).unwrap();
        assert_eq!(
            read_index(&store_dir(t.path()), PID, START).unwrap().len(),
            2
        );
        ack_at(t.path(), NOW + 1, ID1, "done").unwrap();
        assert_eq!(
            read_index(&store_dir(t.path()), PID, START).unwrap(),
            vec![ID2.to_string()],
            "an acknowledged record leaves the index"
        );
        ack_at(t.path(), NOW + 2, ID2, "done").unwrap();
        assert!(!idx_exists(t.path()), "no pending id: no index file");
    }

    #[test]
    fn an_index_listing_more_than_the_pending_cap_is_undetermined_on_the_statusline() {
        let t = dir();
        let h = t.path().join("term-1");
        deliver_hd(t.path(), NOW, &json(&dv(ID1, "a")), &handle_canon(&h)).unwrap();
        marker(&h, ".live-cc-pid", PID, NOW);
        let ids: Vec<String> = (0..=MAX_PENDING_PER_TARGET as u32).map(uid).collect();
        std::fs::write(
            index_path(&store_dir(t.path()), PID, START),
            serde_json::to_vec(&ids).unwrap(),
        )
        .unwrap();
        let e = pend_at(t.path(), &h, NOW + 1).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(e.message.contains("too many"), "{}", e.message);
    }

    // ── round 2: lifetime floor and store eviction ──

    #[test]
    fn lifetime_below_the_floor_is_invalid_input() {
        let t = dir();
        for life in [1, MIN_LIFETIME_SECS - 1] {
            let mut d = dv(ID1, "a");
            d.issued_at = NOW;
            d.expires_at = NOW + life;
            assert_eq!(
                code(deliver_at(t.path(), NOW - 1, &json(&d))),
                SdkErrorCode::InvalidInput,
                "life {life}"
            );
        }
        let mut d = dv(ID1, "a");
        d.issued_at = NOW;
        d.expires_at = NOW + MIN_LIFETIME_SECS;
        assert!(
            deliver_at(t.path(), NOW, &json(&d)).is_ok(),
            "exactly the floor is allowed"
        );
    }

    #[test]
    fn full_store_evicts_the_oldest_expired_record_by_last_transition() {
        let t = dir();
        // all EXPIRED at NOW, all on live sessions. uid(0) is the NEWEST by last
        // transition and uid(499) the OLDEST: order by time, not by id.
        for i in 0..MAX_RECORDS as u32 {
            let q = NOW - 3_000 - u64::from(i);
            seed_full(t.path(), &uid(i), 10_000 + i, START, q, false, q + 400);
        }
        let r = deliver_all_live(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        assert_eq!(r.status, "queued");
        let files = json_files(t.path());
        assert_eq!(files.len(), MAX_RECORDS);
        let oldest = format!("{}.json", uid(MAX_RECORDS as u32 - 1));
        assert!(!files.contains(&oldest), "the oldest expired was evicted");
        assert!(files.contains(&format!("{}.json", uid(0))));
        assert!(files.contains(&format!("{ID1}.json")));
    }

    #[test]
    fn full_store_of_pending_records_for_dead_sessions_evicts_the_oldest_dead_one() {
        let t = dir();
        // pending, unexpired, but the sessions are NOT in the listing (only PID is live)
        for i in 0..MAX_RECORDS as u32 {
            let q = NOW - 100 - u64::from(i);
            seed_full(t.path(), &uid(i), 10_000 + i, START, q, false, NOW + 3_600);
        }
        let r = deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        assert_eq!(r.status, "queued");
        let files = json_files(t.path());
        assert_eq!(files.len(), MAX_RECORDS);
        assert!(
            !files.contains(&format!("{}.json", uid(MAX_RECORDS as u32 - 1))),
            "the oldest dead-session record was evicted"
        );
        assert!(files.contains(&format!("{}.json", uid(0))));
        assert!(files.contains(&format!("{ID1}.json")));
    }

    #[test]
    fn a_failed_save_evicts_nothing() {
        let t = dir();
        for i in 0..MAX_RECORDS as u32 {
            let q = NOW - 3_000 - u64::from(i);
            seed_full(t.path(), &uid(i), 10_000 + i, START, q, false, q + 400);
        }
        let before = {
            let mut f = json_files(t.path());
            f.sort();
            f
        };
        let replace = |_: &Path, _: &Path| Err(fail());
        let fs = FsOps {
            write_tmp: &write_new_private,
            secure: &secure_file,
            replace: &replace,
        };
        let e = deliver_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            &Live {
                host: HOST,
                proc_start: &|_| Some(START),
                unreadable: &|_| false,
                is_listed: &|_, _| true,
                handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
            },
            &json(&dv(ID1, "a")),
        )
        .unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        let mut after = json_files(t.path());
        after.sort();
        assert_eq!(after, before, "nothing was evicted and nothing was added");
    }

    // ── round 2: hostile file types ──

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    /// Run `f` on a thread and fail (instead of hanging the suite) if it does not return.
    #[cfg(unix)]
    fn bounded<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(Duration::from_secs(20))
            .expect("the read hung on a FIFO")
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_in_place_of_a_record_or_an_index_is_undetermined_without_hanging() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        mkfifo(&record_path(&store_dir(t.path()), ID2));
        let base = t.path().to_path_buf();
        let e = bounded(move || {
            let fs = real_fs();
            receipts_inner(&base, &Env { now: NOW, fs: &fs }, None, None).unwrap_err()
        });
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        // the lock holder quarantines it
        let base = t.path().to_path_buf();
        let r = bounded(move || deliver_at(&base, NOW, &json(&dv(ID3, "b"))));
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(rejected_names(t.path()).len(), 1);
        // an index that is a FIFO
        let h = t.path().join("term-1");
        marker(&h, ".live-cc-pid", PID, NOW);
        let idx = index_path(&store_dir(t.path()), PID, START);
        std::fs::remove_file(&idx).unwrap();
        mkfifo(&idx);
        let (base, h2) = (t.path().to_path_buf(), h.clone());
        let e = bounded(move || pend_at(&base, &h2, NOW).unwrap_err());
        assert_eq!(e.code, SdkErrorCode::Undetermined);
    }

    #[cfg(unix)]
    #[test]
    fn dangling_store_symlink_is_undetermined_never_absent() {
        let t = dir();
        std::os::unix::fs::symlink(t.path().join("nowhere"), store_dir(t.path())).unwrap();
        assert_eq!(
            ack_at(t.path(), NOW, ID1, "done").unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        assert_eq!(
            gc_inner(t.path(), NOW).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        let h = t.path().join("term-1");
        marker(&h, ".live-cc-pid", PID, NOW);
        assert_eq!(
            pend_at(t.path(), &h, NOW).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        let fs = real_fs();
        let env = Env { now: NOW, fs: &fs };
        assert_eq!(
            receipts_inner(t.path(), &env, None, None).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        assert_eq!(
            inbox_for_inner(t.path(), &env, PID, START, false, false)
                .unwrap_err()
                .code,
            SdkErrorCode::Undetermined
        );
    }

    #[test]
    fn scan_bound_counts_entries_while_iterating_not_only_record_files() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        for i in 0..=(4 * MAX_RECORDS) {
            std::fs::write(store_dir(t.path()).join(format!("junk-{i}.txt")), b"").unwrap();
        }
        let e = load_all(&store_dir(t.path())).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(e.message.contains("too many"), "{}", e.message);
    }

    // ── round 2: start-time tolerance and statusline binding ──

    #[test]
    fn start_time_within_one_second_matches_two_does_not() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let fs = real_fs();
        let env = Env {
            now: NOW + 1,
            fs: &fs,
        };
        for (delta, hit) in [(0i64, true), (1, true), (-1, true), (2, false), (-2, false)] {
            let s = START.checked_add_signed(delta).unwrap();
            let n = inbox_for_inner(t.path(), &env, PID, s, false, false)
                .unwrap()
                .len();
            assert_eq!(n == 1, hit, "inbox delta {delta}");
            let p = pending_count_and_last_inner(t.path(), NOW + 1, PID, s).unwrap();
            assert_eq!(p.pending == 1, hit, "pending delta {delta}");
            let e = ack_inner(t.path(), &env, ID1, "done", None, &move || Ok((PID, s)));
            assert_eq!(
                e.as_ref().err().map(|e| e.code) != Some(SdkErrorCode::TargetMismatch),
                hit,
                "ack delta {delta}"
            );
            if hit {
                // restore a pending record for the next probe
                let _ = std::fs::remove_file(record_path(&store_dir(t.path()), ID1));
                deliver_at(t.path(), NOW + 1, &json(&dv(ID1, "a")))
                    .unwrap_or_else(|_| panic!("redeliver for delta {delta}"));
            }
        }
    }

    #[test]
    fn delivery_accepts_a_start_time_one_second_off_and_refuses_two() {
        // the wire value is START; the LIVE session started at `live_start`. The stubs
        // honour the start time, so a match that reverts to `==` (or ignores it) goes RED.
        for (live_start, ok) in [
            (START, true),
            (START + 1, true),
            (START - 1, true),
            (START + 2, false),
            (START - 2, false),
        ] {
            let t = dir();
            let fs = real_fs();
            let r = deliver_inner(
                t.path(),
                &Env { now: NOW, fs: &fs },
                &Live {
                    host: HOST,
                    proc_start: &|p| (p == PID).then_some(live_start),
                    unreadable: &|_| false,
                    is_listed: &|p, s| p == PID && same_start(s, live_start),
                    handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
                },
                &json(&dv(ID1, "a")),
            );
            assert_eq!(r.is_ok(), ok, "live start {live_start}: {r:?}");
        }
        // the wire value is S - 1 and S + 1 for ONE session started at S: both are accepted
        // and both rate-limit against each other (see the transitivity test below)
    }

    /// `deliver_via` with an injected listing: the session started at `listed_start`.
    fn via(
        base: &Path,
        now: u64,
        raw: &str,
        listed_start: Option<u64>,
    ) -> Result<DirectiveReceipt, DirectiveError> {
        let session = |st: u64| super::super::SessionInfo {
            pid: PID,
            cwd: PathBuf::from("/"),
            config_dir: base.join("term-1"),
            account_id: None,
            started_at: Some(st),
            tty: None,
            term_window: None,
            term_tab: None,
            term_pane: None,
            iterm_profile: None,
            terminal_title: None,
        };
        let list: Vec<_> = listed_start.map(session).into_iter().collect();
        deliver_via(
            base,
            raw,
            &|| Some(HOST.to_string()),
            &|| Ok(now),
            &|| Some(list.clone()),
            &real_fs(),
        )
    }

    #[test]
    fn deliver_via_matches_the_listed_session_within_the_tolerance_only() {
        for (listed, ok) in [
            (START, true),
            (START + 1, true),
            (START - 1, true),
            (START + 2, false),
            (START - 2, false),
        ] {
            let t = dir();
            let r = via(t.path(), NOW, &json(&dv(ID1, "a")), Some(listed));
            assert_eq!(r.is_ok(), ok, "listed start {listed}: {r:?}");
        }
        let t = dir();
        assert_eq!(
            code(via(t.path(), NOW, &json(&dv(ID1, "a")), None)),
            SdkErrorCode::TargetMismatch,
            "an empty listing"
        );
        // the LIVE start (not the wire value) is what the record stores
        let t = dir();
        via(t.path(), NOW, &json(&dv(ID1, "a")), Some(START + 1)).unwrap();
        let rec = load_record(&record_path(&store_dir(t.path()), ID1), ID1)
            .unwrap()
            .unwrap();
        assert_eq!(rec.live_start, Some(START + 1));
        assert_eq!(rec.directive.target.started_at, START);
    }

    #[test]
    fn deliver_with_lookup_asks_only_about_the_target_pid() {
        let t = dir();
        let asked = std::cell::RefCell::new(Vec::<u32>::new());
        let info = |pid: u32| {
            asked.borrow_mut().push(pid);
            Ok((pid == PID).then(|| super::super::SessionInfo {
                pid,
                cwd: PathBuf::from("/"),
                config_dir: t.path().join("term-1"),
                account_id: None,
                started_at: Some(START),
                tty: None,
                term_window: None,
                term_tab: None,
                term_pane: None,
                iterm_profile: None,
                terminal_title: None,
            }))
        };
        let r = deliver_with_lookup(
            t.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &info,
            &real_fs(),
        );
        assert!(r.is_ok(), "{r:?}");
        let asked = asked.borrow();
        assert!(!asked.is_empty(), "the lookup was consulted");
        assert!(
            asked.iter().all(|p| *p == PID),
            "only the target pid is read, got {asked:?}"
        );
        // A pid the lookup does not know is not a listed session; a lookup answering
        // with a DIFFERENT pid's session never satisfies the target.
        let t2 = dir();
        let none = |_: u32| Ok(None);
        let r = deliver_with_lookup(
            t2.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &none,
            &real_fs(),
        );
        assert_eq!(code(r), SdkErrorCode::TargetMismatch);
    }

    /// INV-31-01/02: a target whose process info could not be READ is `undetermined`, never
    /// `target_mismatch` ("not a session"). Control: a lookup answering `Ok(None)` is.
    #[test]
    fn an_unreadable_target_is_undetermined_not_a_mismatch() {
        let t = dir();
        let unreadable = |_: u32| Err(super::super::Undetermined);
        let r = deliver_with_lookup(
            t.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &unreadable,
            &real_fs(),
        );
        assert_eq!(code(r), SdkErrorCode::Undetermined);
        let absent = |_: u32| Ok(None);
        let r = deliver_with_lookup(
            t.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &absent,
            &real_fs(),
        );
        assert_eq!(code(r), SdkErrorCode::TargetMismatch);
    }

    fn session_of(pid: u32, dir: &Path, started_at: Option<u64>) -> super::super::SessionInfo {
        super::super::SessionInfo {
            pid,
            cwd: PathBuf::from("/"),
            config_dir: dir.join("term-1"),
            account_id: None,
            started_at,
            tty: None,
            term_window: None,
            term_tab: None,
            term_pane: None,
            iterm_profile: None,
            terminal_title: None,
        }
    }

    /// One read per pid: a lookup answering `Ok` then `Err` on successive calls must not
    /// be able to produce `target_mismatch` (the first answer is the one every question
    /// uses), and each pid is asked exactly once.
    #[test]
    fn deliver_reads_each_pid_once_so_ok_then_err_cannot_mismatch() {
        let t = dir();
        let calls = std::cell::RefCell::new(Vec::<u32>::new());
        let info = |pid: u32| {
            let n = {
                let mut c = calls.borrow_mut();
                c.push(pid);
                c.iter().filter(|p| **p == pid).count()
            };
            if n == 1 {
                Ok(Some(session_of(pid, t.path(), Some(START))))
            } else {
                Err(super::super::Undetermined)
            }
        };
        let r = deliver_with_lookup(
            t.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &info,
            &real_fs(),
        );
        assert!(r.is_ok(), "{r:?}");
        let calls = calls.borrow();
        let mut uniq = calls.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(calls.len(), uniq.len(), "a pid was read twice: {calls:?}");
        // the reverse order (Err first) is undetermined, never a mismatch
        let t2 = dir();
        let n = std::cell::Cell::new(0u32);
        let info = |pid: u32| {
            n.set(n.get() + 1);
            if n.get() == 1 {
                Err(super::super::Undetermined)
            } else {
                Ok(Some(session_of(pid, t2.path(), Some(START))))
            }
        };
        let r = deliver_with_lookup(
            t2.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &info,
            &real_fs(),
        );
        assert_eq!(code(r), SdkErrorCode::Undetermined);
    }

    /// A found session whose start time was not reported is unreadable, not a mismatch.
    #[test]
    fn a_target_without_a_start_time_is_undetermined_not_a_mismatch() {
        let t = dir();
        let info = |pid: u32| Ok(Some(session_of(pid, t.path(), None)));
        let r = deliver_with_lookup(
            t.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &info,
            &real_fs(),
        );
        assert_eq!(code(r), SdkErrorCode::Undetermined);
    }

    /// `eviction_order`'s hold test: a stored pid now owned by a process that is positively
    /// not a claude session (`Ok(None)`) holds nothing, so a full store makes room.
    #[test]
    fn eviction_frees_a_record_whose_pid_was_reused_by_a_non_session() {
        let t = dir();
        for i in 0..MAX_RECORDS as u32 {
            seed_full(
                t.path(),
                &uid(i),
                10_000 + i,
                START,
                NOW - 100,
                false,
                NOW + 5_000 + u64::from(i),
            );
        }
        let info = |pid: u32| Ok((pid == PID).then(|| session_of(pid, t.path(), Some(START))));
        let r = deliver_with_lookup(
            t.path(),
            &json(&dv(ID1, "a")),
            &|| Some(HOST.to_string()),
            &|| Ok(NOW),
            &info,
            &real_fs(),
        );
        assert!(r.is_ok(), "{r:?}");
    }

    /// Eviction treats a pid it cannot read as HELD (the safe direction): a full store of
    /// pending records for unreadable pids refuses, and the same store with those pids
    /// positively gone makes room by evicting them.
    #[test]
    fn eviction_keeps_a_record_whose_pid_is_unreadable() {
        let seed = |t: &TempDir| {
            for i in 0..MAX_RECORDS as u32 {
                seed_full(
                    t.path(),
                    &uid(i),
                    10_000 + i,
                    START,
                    NOW - 100,
                    false,
                    NOW + 5_000 + u64::from(i),
                );
            }
        };
        let deliver = |t: &TempDir, unreadable: bool| {
            let fs = real_fs();
            deliver_inner(
                t.path(),
                &Env { now: NOW, fs: &fs },
                &Live {
                    host: HOST,
                    proc_start: &|p| (p == PID).then_some(START),
                    unreadable: &|p| unreadable && p != PID,
                    is_listed: &|p, s| p == PID && same_start(s, START),
                    handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
                },
                &json(&dv(ID1, "a")),
            )
        };
        let held = dir();
        seed(&held);
        let before = json_files(held.path());
        let e = deliver(&held, true).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::RateLimited);
        let (mut a, mut b) = (json_files(held.path()), before);
        a.sort();
        b.sort();
        assert_eq!(a, b, "nothing evicted for an unreadable pid");
        let gone = dir();
        seed(&gone);
        assert!(deliver(&gone, false).is_ok(), "gone pids are evictable");
    }

    /// One session started at `START`, delivered to with wire values START-1 / START+1.
    fn deliver_wire(
        base: &Path,
        now: u64,
        id: &str,
        issuer: &str,
        wire: u64,
    ) -> Result<DirectiveReceipt, DirectiveError> {
        let mut d = dv(id, issuer);
        d.target.started_at = wire;
        deliver_at(base, now, &json(&d))
    }

    #[test]
    fn wire_values_one_second_either_side_of_one_session_share_its_rate_limit() {
        // S-1 and S+1 are 2 apart, so they do NOT match each other under `same_start`;
        // both name the session started at S, so the limit must still bind.
        let t = dir();
        deliver_wire(t.path(), NOW, ID1, "a", START - 1).unwrap();
        let e = deliver_wire(t.path(), NOW + 5, ID2, "a", START + 1).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::RateLimited);
        assert_eq!(e.next_allowed_at, Some(NOW + RATE_WINDOW_SECS));
    }

    #[test]
    fn alternating_wire_values_stop_at_the_pending_cap() {
        let t = dir();
        let mut ok = 0;
        for i in 0..20u32 {
            let wire = if i % 2 == 0 { START - 1 } else { START + 1 };
            let r = deliver_wire(t.path(), NOW, &uid(i), &format!("issuer-{i}"), wire);
            match r {
                Ok(_) => ok += 1,
                Err(e) => assert_eq!(e.code, SdkErrorCode::RateLimited, "delivery {i}"),
            }
        }
        assert_eq!(ok, MAX_PENDING_PER_TARGET);
        assert_eq!(json_files(t.path()).len(), MAX_PENDING_PER_TARGET);
    }

    #[test]
    fn a_record_without_a_stored_live_start_falls_back_to_the_wire_value() {
        let t = dir();
        let mut d = dv(ID1, "a");
        d.target.started_at = START + 1;
        let rec = Record {
            directive: d,
            queued_at: NOW,
            surfaced_at: None,
            acknowledged_at: None,
            ack: None,
            handle_dir: None,
            live_start: None,
        };
        assert_eq!(rec.start(), START + 1);
        assert!(rec.targets(PID, START + 1) && rec.targets(PID, START + 2));
        assert!(!rec.targets(PID, START + 3));
        assert!(rec.same_session(PID, START + 1) && !rec.same_session(PID, START));
        ensure_dir(&store_dir(t.path())).unwrap();
        save(&store_dir(t.path()), &rec, &real_fs()).unwrap();
        let text = std::fs::read_to_string(record_path(&store_dir(t.path()), ID1)).unwrap();
        assert!(!text.contains("live_start"), "None is not written");
    }

    #[test]
    fn statusline_binds_by_start_time_so_a_late_marker_still_shows_directives() {
        let t = dir();
        let h = t.path().join("term-1");
        let hc = handle_canon(&h);
        deliver_hd(t.path(), NOW, &json(&dv(ID1, "a")), &hc).unwrap();
        // the marker is written LONG after the directive was queued (a late marker)
        marker(&h, ".live-cc-pid", PID, NOW + 5_000);
        let at = |start: Option<u64>| {
            pending_for_handle_dir_at(t.path(), &h, NOW + 1, &move |_| start)
                .map(|o| o.map(|p| p.pending))
        };
        assert_eq!(
            at(Some(START)).unwrap(),
            Some(1),
            "late marker: still shown"
        );
        assert_eq!(
            at(Some(START + 1)).unwrap(),
            Some(1),
            "one second off still matches"
        );
        assert_eq!(at(Some(START - 1)).unwrap(), Some(1));
        assert_eq!(
            at(Some(START + 2)).unwrap(),
            Some(0),
            "two seconds off: another holder of the pid"
        );
        assert_eq!(at(Some(START + 9_999)).unwrap(), Some(0), "a recycled pid");
        let e = at(None).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined, "start time unreadable");
    }

    #[test]
    fn statusline_reads_the_start_time_only_when_a_store_exists() {
        let t = dir();
        let h = t.path().join("term-1");
        marker(&h, ".live-cc-pid", PID, NOW);
        let r = pending_for_handle_dir_at(t.path(), &h, NOW, &|_| panic!("read start time early"));
        assert_eq!(r.unwrap(), None);
    }

    // ── round 2: atomic-write ownership, duplicate ids, listing ──

    #[test]
    fn write_atomic_never_removes_a_tmp_it_did_not_create() {
        let t = dir();
        let theirs = Cell::new(None::<PathBuf>);
        let write = |p: &Path, _: &[u8]| {
            std::fs::write(p, b"someone else's").unwrap();
            theirs.set(Some(p.to_path_buf()));
            Err(PlatformError::Io(io::Error::from(
                io::ErrorKind::AlreadyExists,
            )))
        };
        let fs = FsOps {
            write_tmp: &write,
            secure: &secure_file,
            replace: &atomic_replace,
        };
        let target = t.path().join("x.json");
        let e = write_atomic(&target, b"{}", &fs).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        let p = theirs.take().unwrap();
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"someone else's",
            "their file survives"
        );
    }

    #[test]
    fn same_id_with_a_different_document_is_refused_and_an_identical_one_is_idempotent() {
        let t = dir();
        let first = deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let again = deliver_at(t.path(), NOW + 1, &json(&dv(ID1, "a"))).unwrap();
        assert_eq!(first, again);
        let mut other = dv(ID1, "a");
        other.summary = "A different sentence.".into();
        let e = deliver_at(t.path(), NOW + 1, &json(&other)).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        assert_eq!(e.message, "id already used for a different directive");
        let mut other = dv(ID1, "a");
        other.expires_at += 1;
        assert_eq!(
            code(deliver_at(t.path(), NOW + 1, &json(&other))),
            SdkErrorCode::InvalidInput
        );
        let mut other = dv(ID1, "other-issuer");
        other.summary = dv(ID1, "a").summary;
        assert_eq!(
            code(deliver_at(t.path(), NOW + 1, &json(&other))),
            SdkErrorCode::InvalidInput,
            "issuer differs"
        );
    }

    #[test]
    fn pending_for_targets_loads_once_and_matches_the_per_session_answer() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        seed(t.path(), ID2, PID + 1, NOW + 5, false);
        let targets = [
            (PID, START),
            (PID + 1, START),
            (PID + 2, START),
            (PID, START + 2),
        ];
        let all = pending_for_targets_inner(t.path(), NOW + 10, &targets).unwrap();
        assert_eq!(all.len(), targets.len());
        for (info, &(pid, s)) in all.iter().zip(&targets) {
            assert_eq!(
                *info,
                pending_count_and_last_inner(t.path(), NOW + 10, pid, s).unwrap(),
                "({pid}, {s})"
            );
        }
        assert_eq!(all[0].pending, 1);
        assert_eq!(all[2].pending, 0);
        // a bad record makes the whole answer undetermined, never a row of zeros
        std::fs::write(record_path(&store_dir(t.path()), ID3), b"{ torn").unwrap();
        assert_eq!(
            pending_for_targets_inner(t.path(), NOW + 10, &targets)
                .unwrap_err()
                .code,
            SdkErrorCode::Undetermined
        );
    }

    // ── round 3 ──

    /// Deliver to the session `PID` whose LIVE start is `live_start`, in handle dir `hd`.
    fn deliver_session(
        base: &Path,
        now: u64,
        d: &Directive,
        live_start: u64,
        hd: &Path,
    ) -> Result<DirectiveReceipt, DirectiveError> {
        let fs = real_fs();
        let hdf = |_: u32, _: u64| Some(hd.to_path_buf());
        deliver_inner(
            base,
            &Env { now, fs: &fs },
            &Live {
                host: HOST,
                proc_start: &|_| Some(live_start),
                unreadable: &|_| false,
                is_listed: &|_, s| same_start(s, live_start),
                handle_dir_of: &hdf,
            },
            &json(d),
        )
    }

    #[test]
    fn a_session_keeps_its_first_stored_start_when_a_later_reading_is_a_second_off() {
        let t = dir();
        let hc = handle_canon(&t.path().join("term-1"));
        // first delivery reads the session at START; a later one (Linux btime moved) at
        // START + 1. The second must be the SAME session: same issuer → rate limited,
        // another issuer → stored with START, not START + 1.
        deliver_session(t.path(), NOW, &dv(ID1, "a"), START, &hc).unwrap();
        let mut again = dv(ID2, "a");
        again.target.started_at = START + 1;
        assert_eq!(
            deliver_session(t.path(), NOW + 10, &again, START + 1, &hc)
                .unwrap_err()
                .code,
            SdkErrorCode::RateLimited
        );
        again.issuer = "b".to_string();
        deliver_session(t.path(), NOW + 10, &again, START + 1, &hc).unwrap();
        let recs = load_all(&store_dir(t.path())).unwrap();
        assert_eq!(recs.len(), 2);
        assert!(
            recs.iter().all(|r| r.start() == START),
            "one stored start per session"
        );
    }

    #[test]
    fn two_sessions_that_reused_one_pid_keep_separate_indexes_and_caps() {
        let t = dir();
        let h = t.path().join("term-1");
        let hc = handle_canon(&h);
        // session A (start START) holds 10 pending; session B (start START + 500, the pid
        // was recycled) holds 1. Both are recorded against the same handle dir.
        for i in 0..MAX_PENDING_PER_TARGET as u32 {
            let d = dv(&uid(i), &format!("issuer-{i}"));
            deliver_session(t.path(), NOW, &d, START, &hc).unwrap();
        }
        let mut b = dv(ID1, "issuer-b");
        b.target.started_at = START + 500;
        deliver_session(t.path(), NOW, &b, START + 500, &hc).unwrap();
        assert!(index_path(&store_dir(t.path()), PID, START).exists());
        assert!(index_path(&store_dir(t.path()), PID, START + 500).exists());
        marker(&h, ".live-cc-pid", PID, NOW);
        let at = |start: u64| {
            pending_for_handle_dir_at(t.path(), &h, NOW + 1, &move |_| Some(start))
                .map(|o| o.map(|p| p.pending))
        };
        assert_eq!(at(START + 500).unwrap(), Some(1), "B shows 1, not `?`");
        assert_eq!(at(START).unwrap(), Some(MAX_PENDING_PER_TARGET));
        // the retired per-pid index is removed by the next sync
        std::fs::write(store_dir(t.path()).join(format!("pid-{PID}.idx")), b"[]").unwrap();
        gc_inner(t.path(), NOW + 2).unwrap();
        assert!(!store_dir(t.path()).join(format!("pid-{PID}.idx")).exists());
    }

    #[test]
    fn statusline_finds_an_index_keyed_one_second_off_its_own_reading() {
        let t = dir();
        let h = t.path().join("term-1");
        let hc = handle_canon(&h);
        deliver_session(t.path(), NOW, &dv(ID1, "a"), START + 1, &hc).unwrap();
        marker(&h, ".live-cc-pid", PID, NOW);
        for read in [START, START + 1, START + 2] {
            let r = pending_for_handle_dir_at(t.path(), &h, NOW + 1, &move |_| Some(read))
                .unwrap()
                .unwrap();
            assert_eq!(r.pending, 1, "reading {read}");
        }
        let r = pending_for_handle_dir_at(t.path(), &h, NOW + 1, &|_| Some(START + 3))
            .unwrap()
            .unwrap();
        assert_eq!(r.pending, 0, "two seconds off the stored start");
    }

    #[test]
    fn parse_index_name_and_rejected_name_accept_only_csqs_own_shapes() {
        assert_eq!(parse_index_name("pid-7-99.idx"), Some((7, Some(99))));
        assert_eq!(parse_index_name("pid-7.idx"), Some((7, None)));
        for bad in [
            "pid-.idx",
            "pid-7-.idx",
            "pid--9.idx",
            "pid-+7.idx",
            "pid-7-9-1.idx",
            "pid-7.idx.bak",
            "xpid-7.idx",
            "pid-a.idx",
            "pid-007-099.idx",
            "pid-7-099.idx",
            "pid-07.idx",
        ] {
            assert_eq!(parse_index_name(bad), None, "{bad}");
        }
        let ok = format!("{:020}-{:010}-{:010}-{ID1}.json", NOW, 1, 2);
        assert!(is_rejected_name(&ok));
        assert!(is_rejected_name(&format!("{:020}-1-2-pid-7-99.idx", NOW)));
        for bad in [
            "notes.txt",
            "123-1-2-x.json",
            &format!("{:020}-1-2-{ID1}.txt", NOW),
            &format!("{:020}-x-2-{ID1}.json", NOW),
            &format!("{:020}-1-2-.json", NOW),
            &format!("{:020}-1-2-UP.json", NOW),
        ] {
            assert!(!is_rejected_name(bad), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_mode_000_record_is_quarantined_and_delivery_then_succeeds() {
        use std::os::unix::fs::PermissionsExt;
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let bad = record_path(&store_dir(t.path()), ID2);
        std::fs::write(&bad, valid_record_text(ID2)).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o000)).unwrap();
        // a process that bypasses file modes (root) cannot reproduce the condition
        if std::fs::File::open(&bad).is_ok() {
            return;
        }
        let fs = real_fs();
        assert_eq!(
            receipts_inner(t.path(), &Env { now: NOW, fs: &fs }, None, None)
                .unwrap_err()
                .code,
            SdkErrorCode::Undetermined
        );
        let r = deliver_at(t.path(), NOW + 1, &json(&dv(ID3, "b")));
        assert!(r.is_ok(), "{r:?}");
        assert!(std::fs::symlink_metadata(&bad).is_err());
        assert_eq!(rejected_names(t.path()).len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_named_like_a_record_is_quarantined() {
        // Keep the store and the socket on one short, private root: the socket
        // path must fit sun_path even when the runner's TMPDIR is deep.
        let t = crate::testing::socket_fixture::short_root("dsk-").unwrap();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let bad = record_path(&store_dir(t.path()), ID2);
        // The store and the socket share one short `/tmp` root created by the
        // shared fixture, so the socket path fits sun_path regardless of the
        // runner's TMPDIR, and the rename below stays inside that one
        // directory tree (same filesystem, no mount crossing).
        let sock = t.path().join("s");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::fs::rename(&sock, &bad).unwrap();
        let r = deliver_at(t.path(), NOW + 1, &json(&dv(ID3, "b")));
        assert!(r.is_ok(), "{r:?}");
        assert!(std::fs::symlink_metadata(&bad).is_err());
        assert_eq!(rejected_names(t.path()).len(), 1);
    }

    #[test]
    fn a_directory_named_like_a_record_is_quarantined_with_its_contents() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let bad = record_path(&store_dir(t.path()), ID2);
        std::fs::create_dir(&bad).unwrap();
        std::fs::write(bad.join("keep"), b"x").unwrap();
        deliver_at(t.path(), NOW + 1, &json(&dv(ID3, "b"))).unwrap();
        assert!(std::fs::symlink_metadata(&bad).is_err());
        let names = rejected_names(t.path());
        assert_eq!(names.len(), 1);
        assert!(store_dir(t.path())
            .join(REJECTED_DIR)
            .join(&names[0])
            .join("keep")
            .exists());
    }

    #[test]
    fn a_directory_at_an_index_path_is_moved_aside_and_the_index_rewritten() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let idx = index_path(&store_dir(t.path()), PID, START);
        std::fs::remove_file(&idx).unwrap();
        std::fs::create_dir(&idx).unwrap();
        std::fs::write(idx.join("keep"), b"x").unwrap();
        deliver_at(t.path(), NOW + 1, &json(&dv(ID1, "a"))).unwrap();
        assert!(std::fs::symlink_metadata(&idx).unwrap().is_file());
        assert_eq!(
            read_index(&store_dir(t.path()), PID, START).unwrap(),
            vec![ID1]
        );
        let names = rejected_names(t.path());
        assert_eq!(names.len(), 1);
        assert!(names[0].ends_with(".idx"), "{names:?}");
        assert!(store_dir(t.path())
            .join(REJECTED_DIR)
            .join(&names[0])
            .join("keep")
            .exists());
    }

    #[test]
    fn sync_never_deletes_a_directory_even_one_named_like_a_stale_index() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        // a retired-form name, with nothing pending for it: the old sync deleted it
        let stale = store_dir(t.path()).join("pid-99999.idx");
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("keep"), b"x").unwrap();
        gc_inner(t.path(), NOW + 1).unwrap();
        assert!(!stale.exists(), "moved out of the store");
        let names = rejected_names(t.path());
        assert!(store_dir(t.path())
            .join(REJECTED_DIR)
            .join(&names[0])
            .join("keep")
            .exists());
    }

    fn scratch_with_files(root: &Path) -> PathBuf {
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        for i in 0..(MAX_REJECTED as u64 + 5) {
            let n = format!("{:020}-{:010}-{:010}-{ID1}.json", 100 + i, 1, i);
            std::fs::write(elsewhere.join(n), b"x").unwrap();
        }
        std::fs::write(elsewhere.join("ordinary.txt"), b"x").unwrap();
        let sub = elsewhere.join(format!("{:020}-{:010}-{:010}-{ID2}.json", 1, 1, 1));
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("inner"), b"x").unwrap();
        elsewhere
    }

    #[cfg(unix)]
    #[test]
    fn a_rejected_dir_replaced_by_a_symlink_loses_nothing_to_any_mutating_call() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let elsewhere = scratch_with_files(t.path());
        let snapshot = |d: &Path| {
            let mut v: Vec<String> = walk(d);
            v.sort();
            v
        };
        let before = snapshot(&elsewhere);
        std::os::unix::fs::symlink(&elsewhere, store_dir(t.path()).join(REJECTED_DIR)).unwrap();
        // the prune itself refuses
        assert_eq!(
            prune_rejected(&store_dir(t.path())).unwrap_err().code,
            SdkErrorCode::Undetermined
        );
        assert_eq!(snapshot(&elsewhere), before, "prune_rejected");
        // a call that finds nothing bad does not touch it
        gc_inner(t.path(), NOW + 1).unwrap();
        assert_eq!(snapshot(&elsewhere), before, "gc");
        // a call that finds a bad record fails closed
        plant_bad(t.path(), "unparseable");
        assert!(deliver_at(t.path(), NOW + 2, &json(&dv(ID3, "b"))).is_err());
        assert_eq!(snapshot(&elsewhere), before, "deliver with a bad record");
    }

    fn walk(d: &Path) -> Vec<String> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            out.push(n.clone());
            if e.file_type().unwrap().is_dir() {
                out.extend(walk(&e.path()).into_iter().map(|c| format!("{n}/{c}")));
            }
        }
        out
    }

    #[test]
    fn prune_leaves_directories_and_foreign_names_alone_and_counts_neither() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        let rej = store_dir(t.path()).join(REJECTED_DIR);
        let src = scratch_with_files(t.path());
        std::fs::rename(&src, &rej).unwrap();
        prune_rejected(&store_dir(t.path())).unwrap();
        let all = walk(&rej);
        assert!(all.iter().any(|n| n == "ordinary.txt"), "foreign name kept");
        assert!(
            all.iter().any(|n| n.ends_with("/inner")),
            "a directory (the oldest by name) and its contents kept: {all:?}"
        );
        let csq_files = rejected_names(t.path())
            .into_iter()
            .filter(|n| is_rejected_name(n) && rej.join(n).is_file())
            .count();
        assert_eq!(
            csq_files, MAX_REJECTED,
            "the directory did not count toward 20"
        );
    }

    #[test]
    fn two_quarantines_of_one_id_in_one_second_keep_both_copies() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        for _ in 0..2 {
            plant_bad(t.path(), "unparseable");
            gc_inner(t.path(), NOW).unwrap();
        }
        let names = rejected_names(t.path());
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.iter().all(|n| is_rejected_name(n)));
    }

    #[test]
    fn quarantine_never_overwrites_an_existing_entry() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        let dir_ = store_dir(t.path());
        for i in 0..3 {
            std::fs::write(dir_.join("victim.json"), format!("{i}")).unwrap();
            quarantine_entry(&dir_, &dir_.join("victim.json"), "victim", "json", NOW).unwrap();
        }
        let rej = dir_.join(REJECTED_DIR);
        let mut bodies: Vec<String> = rejected_names(t.path())
            .iter()
            .map(|n| std::fs::read_to_string(rej.join(n)).unwrap())
            .collect();
        bodies.sort();
        assert_eq!(bodies, ["0", "1", "2"]);
    }

    #[test]
    fn directory_scans_stop_at_the_scan_cap() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        let d = store_dir(t.path());
        for i in 0..=MAX_SCANNED_RECORDS {
            std::fs::write(d.join(format!("junk-{i}.txt")), b"").unwrap();
        }
        for r in [
            sweep_stale_tmp(&d, NOW),
            sync_index(&d, &[], NOW, &real_fs()),
        ] {
            let e = r.unwrap_err();
            assert_eq!(e.code, SdkErrorCode::Undetermined);
            assert!(e.message.contains("too many"), "{}", e.message);
        }
        // `rejected/` is capped too, but a flooded one must not block the store
        let rej = d.join(REJECTED_DIR);
        std::fs::create_dir(&rej).unwrap();
        for i in 0..=MAX_SCANNED_RECORDS {
            std::fs::write(rej.join(format!("junk-{i}.txt")), b"").unwrap();
        }
        prune_rejected(&d).unwrap();
        assert!(
            rej.join("junk-0.txt").exists(),
            "foreign names are never deleted"
        );
    }

    #[test]
    fn acknowledging_again_with_the_same_outcome_and_note_returns_the_original_receipt() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let fs = real_fs();
        let ack = |now: u64, outcome: &str, note: Option<&str>| {
            ack_inner(t.path(), &Env { now, fs: &fs }, ID1, outcome, note, &me)
        };
        let first = ack(NOW + 1, "done", Some("shipped")).unwrap();
        let again = ack(NOW + 9, "done", Some("shipped")).unwrap();
        assert_eq!(first, again);
        assert_eq!(again.acknowledged_at, Some(NOW + 1), "not re-stamped");
        for (outcome, note) in [
            ("declined", Some("shipped")),
            ("done", Some("other")),
            ("done", None),
        ] {
            let e = ack(NOW + 10, outcome, note).unwrap_err();
            assert_eq!(e.code, SdkErrorCode::InvalidInput, "{outcome} {note:?}");
        }
        assert_eq!(recs_at(t.path(), NOW + 11, None, Some(ID1))[0], first);
    }

    #[cfg(unix)]
    #[test]
    fn a_lock_with_a_second_hard_link_is_undetermined_and_the_other_name_is_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let other = t.path().join("other-name");
        std::fs::hard_link(store_dir(t.path()).join(".lock"), &other).unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = deliver_at(t.path(), NOW + 1, &json(&dv(ID2, "b"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(e.message.contains("link"), "{}", e.message);
        assert_eq!(
            std::fs::metadata(&other).unwrap().permissions().mode() & 0o777,
            0o644,
            "the refusal came before any chmod of the shared inode"
        );
    }

    #[test]
    fn an_outcome_this_csq_does_not_know_is_kept_acknowledged_and_returned_unchanged() {
        let t = dir();
        let mut rec = Record {
            directive: dv(ID1, "a"),
            queued_at: NOW,
            surfaced_at: None,
            acknowledged_at: Some(NOW + 1),
            ack: Some(DirectiveAck::new("snoozed", Some("later".to_string()))),
            handle_dir: None,
            live_start: Some(START),
        };
        rec.directive.target.pid = PID;
        ensure_dir(&store_dir(t.path())).unwrap();
        save(&store_dir(t.path()), &rec, &real_fs()).unwrap();
        // lock-free read: the record is readable, not undetermined
        let r = recs_at(t.path(), NOW + 2, None, Some(ID1));
        assert_eq!(r[0].status, "acknowledged");
        assert_eq!(r[0].ack.as_ref().unwrap().outcome, "snoozed");
        // a mutating call keeps it in place
        deliver_at(t.path(), NOW + 2, &json(&dv(ID2, "b"))).unwrap();
        assert!(rejected_names(t.path()).is_empty(), "not quarantined");
        assert!(record_path(&store_dir(t.path()), ID1).exists());
        // a re-ack with a KNOWN outcome cannot equal it, so it is refused, not rewritten
        let e = ack_at(t.path(), NOW + 3, ID1, "done").unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        assert_eq!(
            recs_at(t.path(), NOW + 3, None, Some(ID1))[0]
                .ack
                .as_ref()
                .unwrap()
                .outcome,
            "snoozed"
        );
    }

    #[test]
    fn the_display_sanitiser_also_drops_combining_marks() {
        assert_eq!(sanitize_display("e\u{0301}x\u{20DD}y"), "exy");
        assert_eq!(sanitize_display("日本 é"), "日本 é");
    }

    // ── round 4 ──

    /// The directive `seed_full` stores for these arguments (for a re-submission).
    fn seeded_directive(id: &str, pid: u32, start: u64, expires_at: u64) -> Directive {
        let mut d = dv(id, "seed");
        d.target.pid = pid;
        d.target.started_at = start;
        d.expires_at = expires_at;
        d
    }

    /// A full store of unexpired ACKNOWLEDGED records on live sessions. `uid(MAX-1)` is the
    /// oldest acknowledgement.
    fn full_of_acknowledged(base: &Path) {
        for i in 0..MAX_RECORDS as u32 {
            let q = NOW - 3_000 - u64::from(i);
            seed_full(base, &uid(i), 10_000 + i, START, q, true, NOW + 3_600);
        }
    }

    fn tombstones_of(base: &Path) -> Vec<Tombstone> {
        let t = std::fs::read_to_string(store_dir(base).join(TOMBSTONE_FILE)).unwrap();
        serde_json::from_str(&t).unwrap()
    }

    fn horizon_of(base: &Path) -> Option<u64> {
        read_horizon(&store_dir(base)).unwrap()
    }

    #[test]
    fn a_store_full_of_unexpired_acknowledgements_accepts_a_delivery_and_remembers_the_evicted_id()
    {
        let t = dir();
        full_of_acknowledged(t.path());
        let r = deliver_all_live(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        assert_eq!(r.status, "queued");
        let files = json_files(t.path());
        let oldest = uid(MAX_RECORDS as u32 - 1);
        assert_eq!(files.len(), MAX_RECORDS);
        assert!(
            !files.contains(&format!("{oldest}.json")),
            "oldest ack evicted"
        );
        assert!(files.contains(&format!("{}.json", uid(0))));
        assert!(files.contains(&format!("{ID1}.json")));
        let tombs = tombstones_of(t.path());
        assert_eq!(tombs.len(), 1);
        assert_eq!(
            (tombs[0].id.as_str(), tombs[0].expires_at),
            (oldest.as_str(), NOW + 3_600)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(store_dir(t.path()).join(TOMBSTONE_FILE)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
        // the same document again: already delivered, no receipt to return
        let same = seeded_directive(&oldest, 10_000 + MAX_RECORDS as u32 - 1, START, NOW + 3_600);
        let e = deliver_all_live(t.path(), NOW + 1, &json(&same)).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        assert!(
            e.message.contains("receipt is no longer held"),
            "{}",
            e.message
        );
        // the same id with a different document
        let mut other = same.clone();
        other.summary = "Something else entirely.".into();
        let e = deliver_all_live(t.path(), NOW + 1, &json(&other)).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        assert!(e.message.contains("different directive"), "{}", e.message);
    }

    #[test]
    fn expired_and_dead_session_records_go_before_any_acknowledgement() {
        let t = dir();
        for i in 0..(MAX_RECORDS as u32 - 1) {
            let q = NOW - 3_000 - u64::from(i);
            seed_full(t.path(), &uid(i), 10_000 + i, START, q, true, NOW + 3_600);
        }
        // the NEWEST record, but expired: still first to go
        seed_full(t.path(), &uid(900), 20_000, START, NOW - 5, false, NOW - 1);
        deliver_all_live(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let files = json_files(t.path());
        assert!(!files.contains(&format!("{}.json", uid(900))));
        assert!(files.contains(&format!("{}.json", uid(MAX_RECORDS as u32 - 2))));
        assert!(
            !store_dir(t.path()).join(TOMBSTONE_FILE).exists(),
            "no ack evicted"
        );
    }

    #[test]
    fn an_acknowledged_record_on_a_dead_pid_is_evicted_by_pid_alone() {
        let t = dir();
        for i in 0..MAX_RECORDS as u32 {
            let q = NOW - 3_000 - u64::from(i);
            seed_full(t.path(), &uid(i), 10_000 + i, START, q, true, NOW + 3_600);
        }
        // only PID is listed, so every seeded record's pid is dead; a REUSED pid with a
        // different start would still count as held
        let r = deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        assert_eq!(r.status, "queued");
        assert_eq!(json_files(t.path()).len(), MAX_RECORDS);
        // the evicted records were acknowledged and unexpired: each left a tombstone
        let tombs = tombstones_of(t.path());
        assert_eq!(tombs.len(), 1, "one eviction, one tombstone");
        assert_eq!(tombs[0].expires_at, NOW + 3_600);
        assert!(
            !json_files(t.path()).contains(&format!("{}.json", tombs[0].id)),
            "the tombstoned record is the one evicted"
        );
    }

    #[test]
    fn a_corrupt_tombstone_file_is_quarantined_and_delivery_continues() {
        let t = dir();
        full_of_acknowledged(t.path());
        std::fs::write(store_dir(t.path()).join(TOMBSTONE_FILE), b"{ torn").unwrap();
        // the delivery that finds the corrupt file quarantines it and sets the horizon to
        // NOW + skew + 1, past any `issued_at` that delivery could carry, so it is itself refused
        // (a lost tombstone might have been for it); the quarantine still persists
        let e = deliver_all_live(t.path(), NOW, &json(&dv_issued(ID2, "b", NOW))).unwrap_err();
        assert!(e.message.contains("replay horizon"), "{}", e.message);
        // a directive issued at the horizon, delivered a second later, is accepted
        let r = deliver_all_live(
            t.path(),
            NOW + 1,
            &json(&dv_issued(ID1, "a", NOW + MAX_ISSUED_SKEW_SECS + 1)),
        );
        assert!(r.is_ok(), "{r:?}");
        let names = rejected_names(t.path());
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(names[0].ends_with("-tombstones.json"), "{names:?}");
        // replaced by a valid file that already holds the new eviction
        assert_eq!(tombstones_of(t.path()).len(), 1);
    }

    #[test]
    fn tombstones_are_capped_dropping_expired_then_the_oldest() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        let mk = |i: usize, exp: u64| Tombstone {
            id: uid(i as u32),
            doc_sha256: "0".repeat(64),
            expires_at: exp,
            issued_at: 0,
        };
        let mut all: Vec<Tombstone> = (0..MAX_TOMBSTONES + 10)
            .map(|i| mk(i, NOW + 1 + i as u64))
            .collect();
        all.extend((0..5).map(|i| mk(MAX_TOMBSTONES + 10 + i, NOW - 1)));
        save_tombstones(
            &store_dir(t.path()),
            TombstoneFile {
                refuse_issued_before: None,
                tombstones: all,
            },
            NOW,
            &real_fs(),
        )
        .unwrap();
        let kept = tombstones_of(t.path());
        assert_eq!(kept.len(), MAX_TOMBSTONES);
        assert_eq!(kept.iter().map(|k| k.expires_at).min(), Some(NOW + 11));
        assert!(kept.iter().all(|k| k.expires_at > NOW));
    }

    #[test]
    fn a_full_store_of_pending_live_records_is_still_refused() {
        let t = dir();
        for i in 0..MAX_RECORDS as u32 {
            seed_full(
                t.path(),
                &uid(i),
                10_000 + i,
                START,
                NOW - 100,
                false,
                NOW + 5_000 + u64::from(i),
            );
        }
        let e = deliver_all_live(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::RateLimited);
        assert!(!store_dir(t.path()).join(TOMBSTONE_FILE).exists());
    }

    // fix 2: checked marker readers

    #[test]
    fn an_unreadable_pid_marker_is_undetermined_when_a_store_exists_and_absent_shows_nothing() {
        let t = dir();
        let hd = t.path().join("term-1");
        std::fs::create_dir_all(&hd).unwrap();
        let start_of = |_: u32| Some(START);
        // no store: nothing to show whatever the marker holds
        std::fs::write(hd.join(".live-cc-pid"), "not a pid").unwrap();
        assert_eq!(
            pending_for_handle_dir_at(t.path(), &hd, NOW, &start_of).unwrap(),
            None
        );
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        // store exists, marker unreadable: undetermined, in BOTH marker positions
        let e = pending_for_handle_dir_at(t.path(), &hd, NOW, &start_of).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        std::fs::remove_file(hd.join(".live-cc-pid")).unwrap();
        std::fs::write(hd.join(".live-pid"), "").unwrap();
        let e = pending_for_handle_dir_at(t.path(), &hd, NOW, &start_of).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        // an unreadable cc marker is not papered over by a readable `.live-pid`
        std::fs::write(hd.join(".live-pid"), PID.to_string()).unwrap();
        std::fs::write(hd.join(".live-cc-pid"), "x").unwrap();
        assert!(pending_for_handle_dir_at(t.path(), &hd, NOW, &start_of).is_err());
        // absent markers: nothing
        std::fs::remove_file(hd.join(".live-cc-pid")).unwrap();
        std::fs::remove_file(hd.join(".live-pid")).unwrap();
        assert_eq!(
            pending_for_handle_dir_at(t.path(), &hd, NOW, &start_of).unwrap(),
            None
        );
    }

    // fix 3: one bad index entry must not stop the others

    #[cfg(unix)]
    #[test]
    fn a_bad_index_entry_that_cannot_be_quarantined_does_not_stop_other_indexes() {
        let t = dir();
        seed_full(t.path(), ID1, PID, START, NOW - 10, false, NOW + 3_600);
        seed_full(t.path(), ID2, 5_001, START, NOW - 10, false, NOW + 3_600);
        let d = store_dir(t.path());
        // PID's index path is a directory; `rejected/` is a regular file, so moving the
        // directory aside fails
        std::fs::create_dir(index_path(&d, PID, START)).unwrap();
        std::fs::write(d.join(REJECTED_DIR), b"not a dir").unwrap();
        let _ = gc_inner(t.path(), NOW);
        assert_eq!(
            read_index(&d, 5_001, START).unwrap(),
            vec![ID2],
            "the other session's index was written"
        );
        assert!(
            index_path(&d, PID, START).is_dir(),
            "the bad entry was left alone"
        );
    }

    // fix 4: no path is resolved again after `rejected/` was verified

    #[cfg(unix)]
    fn swap_rejected_for_symlink(dir: &Path, elsewhere: &Path) -> impl Fn() {
        let dir = dir.to_path_buf();
        let elsewhere = elsewhere.to_path_buf();
        move || {
            let rej = dir.join(REJECTED_DIR);
            std::fs::rename(&rej, dir.join("rejected.orig")).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &rej).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_rejected_dir_swapped_after_the_check_redirects_neither_a_quarantine_nor_a_prune() {
        let snap = |d: &Path| {
            let mut v = walk(d);
            v.sort();
            v
        };
        // quarantine
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let d = store_dir(t.path());
        let elsewhere = scratch_with_files(t.path());
        let before = snap(&elsewhere);
        let bad = record_path(&d, ID2);
        std::fs::write(&bad, b"{ torn").unwrap();
        let swap = swap_rejected_for_symlink(&d, &elsewhere);
        quarantine_entry_in(&d, &bad, ID2, "json", NOW, &swap).unwrap();
        assert_eq!(
            snap(&elsewhere),
            before,
            "nothing landed in the symlink target"
        );
        assert!(!bad.exists());
        let orig: Vec<_> = std::fs::read_dir(d.join("rejected.orig"))
            .unwrap()
            .collect();
        assert_eq!(orig.len(), 1, "it went into the directory that was checked");

        // prune
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        let d = store_dir(t.path());
        let elsewhere = scratch_with_files(t.path());
        std::fs::create_dir(d.join(REJECTED_DIR)).unwrap();
        for i in 0..(MAX_REJECTED as u64 + 3) {
            let n = format!("{:020}-{:010}-{:010}-{ID1}.json", 100 + i, 1, i);
            std::fs::write(d.join(REJECTED_DIR).join(n), b"x").unwrap();
        }
        let before = snap(&elsewhere);
        let swap = swap_rejected_for_symlink(&d, &elsewhere);
        prune_rejected_in(&d, &swap).unwrap();
        assert_eq!(
            snap(&elsewhere),
            before,
            "no file in the symlink target was deleted"
        );
        let left = std::fs::read_dir(d.join("rejected.orig")).unwrap().count();
        assert_eq!(left, MAX_REJECTED, "the checked directory was pruned");
    }

    // fix 6: a record queued before the process started cannot name its start

    #[test]
    fn a_stale_record_for_a_reused_pid_does_not_capture_the_new_sessions_start() {
        let t = dir();
        const NEW_START: u64 = 5_000;
        // an earlier holder of PID: queued 10 s before the new process started, stored
        // start 1 s from the new one
        seed_full(
            t.path(),
            ID1,
            PID,
            NEW_START - 1,
            NEW_START - 10,
            false,
            NOW + 3_600,
        );
        let mut d = dv(ID2, "other-issuer");
        d.target.started_at = NEW_START;
        let fs = real_fs();
        deliver_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            &Live {
                host: HOST,
                proc_start: &|p| (p == PID).then_some(NEW_START),
                unreadable: &|_| false,
                is_listed: &|p, s| p == PID && same_start(s, NEW_START),
                handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
            },
            &json(&d),
        )
        .unwrap();
        let rec = load_record(&record_path(&store_dir(t.path()), ID2), ID2)
            .unwrap()
            .unwrap();
        assert_eq!(rec.live_start, Some(NEW_START), "kept its own reading");
    }

    // fix 7: leading zeros

    #[test]
    fn a_leading_zero_index_name_is_removed_and_never_read_as_an_alias() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let d = store_dir(t.path());
        let alias = d.join(format!("pid-00{PID}-00{START}.idx"));
        std::fs::write(&alias, b"[]").unwrap();
        assert!(is_leading_zero_index_alias(&format!(
            "pid-00{PID}-00{START}.idx"
        )));
        assert!(!is_leading_zero_index_alias(&format!(
            "pid-{PID}-{START}.idx"
        )));
        gc_inner(t.path(), NOW + 1).unwrap();
        assert!(!alias.exists(), "removed");
        assert!(index_path(&d, PID, START).exists(), "the real index stays");
    }

    // round 5

    #[cfg(unix)]
    #[test]
    fn two_listings_of_one_handle_return_the_same_names() {
        let t = dir();
        for n in ["a", "b", "c"] {
            std::fs::write(t.path().join(n), b"").unwrap();
        }
        let fd = dirfd::DirFd::open(t.path()).unwrap();
        let sorted = |mut l: dirfd::Listing| {
            assert!(l.complete);
            l.names.sort();
            l.names
        };
        let first = sorted(fd.names(100).unwrap());
        let second = sorted(fd.names(100).unwrap());
        assert_eq!(first, ["a", "b", "c"]);
        assert_eq!(
            second, first,
            "the second listing starts from the beginning"
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_relative_operations_refuse_a_name_that_leaves_the_directory() {
        let t = dir();
        let sub = t.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(t.path().join("victim"), b"v").unwrap();
        std::fs::create_dir(t.path().join("other")).unwrap();
        let fd = dirfd::DirFd::open(&sub).unwrap();
        let other = dirfd::DirFd::open(&t.path().join("other")).unwrap();
        for bad in ["../victim", "..", ".", "", "a/b", "/abs"] {
            let kinds = [
                fd.unlink(bad).unwrap_err().kind(),
                fd.rename_to(bad, &other, "x").unwrap_err().kind(),
                fd.rename_to("victim", &other, bad).unwrap_err().kind(),
                fd.entry_is_dir(bad).unwrap_err().kind(),
                fd.open_child(bad).err().unwrap().kind(),
            ];
            assert!(
                kinds.iter().all(|k| *k == io::ErrorKind::InvalidInput),
                "{bad:?}: {kinds:?}"
            );
        }
        assert!(
            t.path().join("victim").exists(),
            "nothing left the directory"
        );
        std::fs::write(sub.join("real"), b"").unwrap();
        fd.unlink("real").unwrap();
    }

    #[test]
    fn only_a_parsing_leading_zero_name_is_an_alias() {
        for yes in [
            "pid-007-099.idx",
            "pid-7-099.idx",
            "pid-007-99.idx",
            "pid-007.idx",
        ] {
            assert!(is_leading_zero_index_alias(yes), "{yes}");
        }
        for no in [
            "pid-7-99.idx",
            "pid-0-0.idx",
            "pid-7.idx",
            "pid-99999999999-5.idx", // pid over 32 bits: does not parse
            "pid-007-99999999999999999999999.idx", // start over 64 bits
            "pid-0099999999999.idx",
            "pid-x07-099.idx",
            "pid-007-099.json",
        ] {
            assert!(!is_leading_zero_index_alias(no), "{no}");
        }
    }

    #[test]
    fn an_overflow_index_name_is_not_deleted_by_the_sync() {
        let t = dir();
        deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap();
        let d = store_dir(t.path());
        let overflow = d.join("pid-99999999999-5.idx");
        std::fs::write(&overflow, b"[]").unwrap();
        gc_inner(t.path(), NOW + 1).unwrap();
        assert!(overflow.exists(), "not csq's name, so not touched");
    }

    fn rejected_entry(i: usize) -> String {
        format!("{i:020}-{:010}-{i:010}-x.json", 1)
    }

    #[test]
    fn a_listing_that_stops_early_prunes_nothing() {
        let list = |n: usize| -> Vec<(String, bool)> {
            (0..n).map(|i| (rejected_entry(i), false)).collect()
        };
        assert_eq!(
            rejected_to_prune(DIRECTIVE_LABEL, list(MAX_REJECTED + 5), true).len(),
            5
        );
        assert!(
            rejected_to_prune(DIRECTIVE_LABEL, list(MAX_REJECTED + 5), false).is_empty(),
            "a readdir error ended the listing"
        );
        assert!(
            rejected_to_prune(DIRECTIVE_LABEL, list(MAX_SCANNED_RECORDS + 1), true).is_empty(),
            "past the scan cap"
        );
    }

    #[test]
    fn a_rejected_dir_past_the_scan_cap_deletes_none_of_its_entries() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        let d = store_dir(t.path());
        let rej = d.join(REJECTED_DIR);
        std::fs::create_dir(&rej).unwrap();
        for i in 0..=MAX_SCANNED_RECORDS {
            std::fs::write(rej.join(rejected_entry(i)), b"").unwrap();
        }
        prune_rejected(&d).unwrap();
        assert_eq!(rejected_names(t.path()).len(), MAX_SCANNED_RECORDS + 1);
    }

    fn write_tombstone_file(base: &Path, body: &str) {
        ensure_dir(&store_dir(base)).unwrap();
        std::fs::write(store_dir(base).join(TOMBSTONE_FILE), body).unwrap();
    }

    fn dv_issued(id: &str, issuer: &str, issued_at: u64) -> Directive {
        let mut d = dv(id, issuer);
        d.issued_at = issued_at;
        d
    }

    #[test]
    fn a_quarantined_tombstone_file_refuses_an_earlier_issued_replay_and_admits_a_later_one() {
        let t = dir();
        write_tombstone_file(t.path(), "{ torn");
        let e = deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        assert!(e.message.contains("replay horizon"), "{}", e.message);
        assert!(json_files(t.path()).is_empty(), "no record written");
        assert_eq!(rejected_names(t.path()).len(), 1);
        // the horizon is durable in its own file, so it survives the next call; it clears
        // `now + MAX_ISSUED_SKEW_SECS` because a lost tombstone may carry a future-skewed
        // `issued_at`
        let horizon = NOW + MAX_ISSUED_SKEW_SECS + 1;
        assert_eq!(horizon_of(t.path()), Some(horizon));
        let e = deliver_at(t.path(), NOW + 1, &json(&dv(ID1, "a"))).unwrap_err();
        assert!(e.message.contains("replay horizon"), "{}", e.message);
        // a future-skewed replay (issued 250 s ahead, inside the accepted skew) is refused too
        let e = deliver_at(t.path(), NOW + 1, &json(&dv_issued(ID3, "c", NOW + 250))).unwrap_err();
        assert!(e.message.contains("replay horizon"), "{}", e.message);
        let ok = deliver_at(t.path(), NOW + 1, &json(&dv_issued(ID2, "b", horizon)));
        assert!(ok.is_ok(), "{ok:?}");
    }

    #[test]
    fn a_dropped_legacy_tombstone_raises_the_horizon_past_its_possible_issue_time() {
        let t = dir();
        write_tombstone_file(t.path(), "[]");
        let tomb = |i: u32, issued_at: u64, expires_at: u64| Tombstone {
            id: uid(i),
            doc_sha256: String::new(),
            expires_at,
            issued_at,
        };
        // a legacy entry (issued_at 0) expiring at NOW + 400 was issued at most at NOW + 100;
        // every other entry was issued later, so the legacy one is the one dropped
        let mut tombstones = vec![tomb(0, 0, NOW + 400)];
        for i in 1..=MAX_TOMBSTONES as u32 {
            tombstones.push(tomb(i, NOW + 200, NOW + 3_600));
        }
        let file = TombstoneFile {
            refuse_issued_before: None,
            tombstones,
        };
        save_tombstones(&store_dir(t.path()), file, NOW, &real_fs()).unwrap();
        assert_eq!(tombstones_of(t.path()).len(), MAX_TOMBSTONES);
        assert!(
            tombstones_of(t.path()).iter().all(|x| x.issued_at != 0),
            "the legacy entry is the one dropped"
        );
        assert_eq!(
            horizon_of(t.path()),
            Some(NOW + 400 - MIN_LIFETIME_SECS + 1),
            "past the legacy entry's latest possible issued_at, never 1"
        );
    }

    #[test]
    fn a_failed_horizon_write_leaves_the_corrupt_file_in_place() {
        let t = dir();
        write_tombstone_file(t.path(), "{ torn");
        let fs = FsOps {
            write_tmp: &|_: &Path, _: &[u8]| Err(fail()),
            secure: &secure_file,
            replace: &atomic_replace,
        };
        let e = deliver_with_fs(t.path(), &fs).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
        assert!(rejected_names(t.path()).is_empty(), "nothing moved yet");
        let body = std::fs::read_to_string(store_dir(t.path()).join(TOMBSTONE_FILE)).unwrap();
        assert_eq!(body, "{ torn");
        assert_eq!(horizon_of(t.path()), None, "no horizon without a write");
    }

    #[test]
    fn a_quarantine_that_cannot_finish_still_refuses_the_earlier_issued_replay() {
        let t = dir();
        write_tombstone_file(t.path(), "{ torn");
        let e = deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap_err();
        assert!(e.message.contains("replay horizon"), "{}", e.message);
        // From here no tombstone file exists and every rename onto it fails: the horizon
        // alone must carry the refusal.
        let replaced = Cell::new(0);
        let replace = |from: &Path, to: &Path| {
            if to.file_name().is_some_and(|n| n == TOMBSTONE_FILE) {
                replaced.set(replaced.get() + 1);
                return Err(fail());
            }
            atomic_replace(from, to)
        };
        let fs = FsOps {
            write_tmp: &write_new_private,
            secure: &secure_file,
            replace: &replace,
        };
        let e = deliver_with_fs(t.path(), &fs).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::InvalidInput);
        assert!(e.message.contains("replay horizon"), "{}", e.message);
        assert!(json_files(t.path()).is_empty());
        assert!(!store_dir(t.path()).join(TOMBSTONE_FILE).exists());
    }

    #[test]
    fn an_unreadable_replay_horizon_is_undetermined_never_no_horizon() {
        for body in ["garbage", "007", "-1", "99999999999999999999999", ""] {
            let t = dir();
            ensure_dir(&store_dir(t.path())).unwrap();
            std::fs::write(store_dir(t.path()).join(HORIZON_FILE), body).unwrap();
            let e = deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap_err();
            assert_eq!(e.code, SdkErrorCode::Undetermined, "{body:?}: {e}");
            assert!(json_files(t.path()).is_empty(), "{body:?}");
        }
        // a directory where the file should be is unreadable too
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        std::fs::create_dir(store_dir(t.path()).join(HORIZON_FILE)).unwrap();
        let e = deliver_at(t.path(), NOW, &json(&dv(ID1, "a"))).unwrap_err();
        assert_eq!(e.code, SdkErrorCode::Undetermined);
    }

    #[test]
    fn the_replay_horizon_only_rises() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        let d = store_dir(t.path());
        let fs = real_fs();
        assert_eq!(raise_horizon(&d, None, 100, &fs).unwrap(), Some(100));
        assert_eq!(raise_horizon(&d, Some(100), 50, &fs).unwrap(), Some(100));
        assert_eq!(
            horizon_of(t.path()),
            Some(100),
            "a lower value writes nothing"
        );
        assert_eq!(raise_horizon(&d, Some(100), 200, &fs).unwrap(), Some(200));
        assert_eq!(horizon_of(t.path()), Some(200));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(d.join(HORIZON_FILE)).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_cap_dropped_tombstone_raises_the_replay_horizon() {
        let t = dir();
        ensure_dir(&store_dir(t.path())).unwrap();
        let mk = |i: usize| Tombstone {
            id: uid(i as u32),
            doc_sha256: "0".repeat(64),
            expires_at: NOW + 1 + i as u64,
            issued_at: 100 + i as u64,
        };
        let all: Vec<Tombstone> = (0..MAX_TOMBSTONES + 3).map(mk).collect();
        let file = TombstoneFile {
            refuse_issued_before: None,
            tombstones: all,
        };
        save_tombstones(&store_dir(t.path()), file, NOW, &real_fs()).unwrap();
        assert_eq!(tombstones_of(t.path()).len(), MAX_TOMBSTONES);
        // the three oldest by expires_at (i = 0..3) went; the newest of them issued at 102
        assert_eq!(horizon_of(t.path()), Some(103));
        // a later drop covering only an older directive never lowers it
        let file = TombstoneFile {
            refuse_issued_before: horizon_of(t.path()),
            tombstones: (0..MAX_TOMBSTONES + 1).map(mk).collect(),
        };
        save_tombstones(&store_dir(t.path()), file, NOW, &real_fs()).unwrap();
        assert_eq!(horizon_of(t.path()), Some(103));
    }

    #[test]
    fn an_expired_tombstone_does_not_refuse_and_a_legacy_array_is_still_read() {
        let t = dir();
        let tomb = |id: &str, exp: u64| {
            format!(
                r#"{{"id":"{id}","doc_sha256":"{}","expires_at":{exp}}}"#,
                "0".repeat(64)
            )
        };
        // legacy bare array: one live tombstone (ID2), one expired (ID1)
        write_tombstone_file(
            t.path(),
            &format!("[{},{}]", tomb(ID1, NOW - 1), tomb(ID2, NOW + 3_600)),
        );
        let ok = deliver_at(t.path(), NOW, &json(&dv(ID1, "a")));
        assert!(ok.is_ok(), "expired tombstone is absent on read: {ok:?}");
        let e = deliver_at(t.path(), NOW, &json(&dv(ID2, "b"))).unwrap_err();
        assert!(e.message.contains("different directive"), "{}", e.message);
        // `issued_at` defaults to 0 and no horizon is invented for a legacy file
        let loaded = load_tombstones(&store_dir(t.path()), NOW, &real_fs()).unwrap();
        assert!(loaded.refuse_issued_before.is_none());
        assert!(!store_dir(t.path()).join(HORIZON_FILE).exists());
        assert_eq!(loaded.tombstones.len(), 1);
        assert_eq!(loaded.tombstones[0].issued_at, 0);
    }

    #[test]
    fn a_failed_tombstone_write_keeps_the_acknowledged_victims_and_still_delivers() {
        let t = dir();
        full_of_acknowledged(t.path());
        let reached = Cell::new(0);
        let write = |p: &Path, b: &[u8]| {
            let tomb_tmp = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("tombstones.tmp"));
            if tomb_tmp {
                reached.set(reached.get() + 1);
                return Err(fail());
            }
            write_new_private(p, b)
        };
        let fs = FsOps {
            write_tmp: &write,
            secure: &secure_file,
            replace: &atomic_replace,
        };
        let r = deliver_inner(
            t.path(),
            &Env { now: NOW, fs: &fs },
            &Live {
                host: HOST,
                proc_start: &|_| Some(START),
                unreadable: &|_| false,
                is_listed: &|_, s| same_start(s, START),
                handle_dir_of: &|_, _| Some(PathBuf::from("/h")),
            },
            &json(&dv(ID1, "a")),
        );
        assert_eq!(
            reached.get(),
            1,
            "the tombstone write was attempted and failed"
        );
        assert_eq!(r.unwrap().status, "queued");
        let files = json_files(t.path());
        assert_eq!(
            files.len(),
            MAX_RECORDS + 1,
            "over the cap: the victim was kept"
        );
        let oldest = uid(MAX_RECORDS as u32 - 1);
        assert!(
            files.contains(&format!("{oldest}.json")),
            "acknowledged victim kept"
        );
        assert!(files.contains(&format!("{ID1}.json")));
        assert!(
            !store_dir(t.path()).join(TOMBSTONE_FILE).exists(),
            "no tombstone file"
        );
    }
}

#[cfg(all(test, unix))]
#[path = "ascii_directives_tests.rs"]
mod ascii_fastpath_tests;

/// Store-lock admission budget: a try-once policy has no elapsed deadline, wait
/// policies keep theirs, and a lock renamed between open and flock is refused.
/// `started` is backdated through the existing parameter, so no timing is relied on.
#[cfg(all(test, unix))]
mod store_lock_budget_tests {
    use super::*;

    const DELAY: Duration = Duration::from_millis(5);
    const STALL: Duration = Duration::from_millis(50);

    fn run(p: &Path, attempts: u32, rounds: u32) -> Result<StoreLock, DirectiveError> {
        let started = std::time::Instant::now()
            .checked_sub(STALL)
            .expect("monotonic clock is older than the 50ms stall");
        acquire_store_lock_policy_with_delay_as_inner(
            "fixture",
            p,
            attempts,
            rounds,
            DELAY,
            &mut |_| {},
            started,
            &mut std::time::Instant::now,
        )
    }

    /// Holder acquired with a budget far above any stall, so acquiring it never flakes.
    fn hold(p: &Path) -> StoreLock {
        acquire_store_lock_policy_with_delay_as_inner(
            "holder",
            p,
            1,
            1,
            Duration::from_secs(30),
            &mut |_| {},
            std::time::Instant::now(),
            &mut std::time::Instant::now,
        )
        .unwrap()
    }

    fn is_timeout(r: Result<StoreLock, DirectiveError>) -> bool {
        matches!(r, Err(e) if e.cause == Some(UndeterminedCause::LockTimeout))
    }

    #[test]
    fn try_once_on_a_free_lock_succeeds_after_a_stall_past_the_budget() {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join(".lock");
        assert!(
            run(&p, 1, 1).is_ok(),
            "free lock must be admitted: try-once has no elapsed deadline"
        );
    }

    #[test]
    fn try_once_on_a_held_lock_times_out() {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join(".lock");
        let _held = hold(&p);
        assert!(is_timeout(run(&p, 1, 1)));
    }

    #[test]
    fn wait_policies_keep_their_elapsed_deadline_on_a_free_lock() {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join(".lock");
        for (attempts, rounds) in [(2, 1), (1, 2), (2, 2)] {
            assert!(
                is_timeout(run(&p, attempts, rounds)),
                "{attempts}x{rounds} must stay deadline-bound"
            );
        }
    }

    #[test]
    fn lock_deleted_between_open_and_flock_is_refused() {
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join(".lock");
        let mut holder = Some(hold(&p));
        // Round 0 is busy; the swap then DELETES the named path and releases the holder, so
        // round 1's flock succeeds while `lstat` of the path fails (the error branch of
        // `names_path`, distinct from the dev+ino-mismatch branch).
        let mut swap = |_round: u32| {
            std::fs::remove_file(&p).unwrap();
            drop(holder.take());
        };
        let r = acquire_store_lock_policy_with_delay_as_inner(
            "fixture",
            &p,
            1,
            2,
            Duration::from_secs(30),
            &mut swap,
            std::time::Instant::now(),
            &mut std::time::Instant::now,
        );
        match r {
            Ok(_) => panic!("a lock on an inode the path no longer names was admitted"),
            Err(e) => assert!(e.message.contains("lock identity changed"), "{e:?}"),
        }
    }

    #[test]
    fn lock_renamed_between_open_and_flock_is_refused() {
        use std::os::unix::fs::OpenOptionsExt;
        let d = tempfile::TempDir::new().unwrap();
        let p = d.path().join(".lock");
        let mut holder = Some(hold(&p));
        let moved = d.path().join("moved-lock");
        // Round 0 is busy (the holder owns the original inode). Between that and round 1,
        // the named path is replaced by a new inode and the original is released: round 1's
        // flock then succeeds on an inode the path no longer names.
        let mut swap = |_round: u32| {
            std::fs::rename(&p, &moved).unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&p)
                .unwrap();
            drop(holder.take());
        };
        let r = acquire_store_lock_policy_with_delay_as_inner(
            "fixture",
            &p,
            1,
            2,
            Duration::from_secs(30),
            &mut swap,
            std::time::Instant::now(),
            &mut std::time::Instant::now,
        );
        match r {
            Ok(_) => panic!("a lock on an inode the path no longer names was admitted"),
            Err(e) => assert!(e.message.contains("lock identity changed"), "{e:?}"),
        }
    }
}
