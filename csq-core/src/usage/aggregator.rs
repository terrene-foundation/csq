//! Phase B' aggregator — scans CC's per-session transcripts, attributes them
//! to slots via the launch log, converts to [`UsageEvent`]s, and is consumed
//! by the daemon to append to per-account ledgers.
//!
//! Per an internal journal entry D2 (post-hoc time correlation attribution).
//!
//! ## Data source (an internal ticket)
//!
//! The v1 aggregator read `~/.claude/usage-data/session-meta/*.json` on the
//! assumption that CC writes one metadata file per session. **CC never wrote
//! there** — that directory does not exist on any real install, so the ledger
//! was empty for every slot since it shipped. The real per-session usage lives
//! in CC's transcripts:
//!
//! ```text
//! ~/.claude/projects/<encoded-cwd>/<session-id>.jsonl
//! ```
//!
//! Each line carries `cwd` (== the launch-log `project_path` exactly, so the
//! existing [`attribute_session`] correlation is unchanged), `timestamp`,
//! `sessionId`, and — on assistant lines — `message.usage` token counts.
//!
//! ## Request granularity and nested transcripts (an internal ticket)
//!
//! Two corrections to the pre-an internal ticket scan, both of which moved real money:
//!
//! 1. **A usage-bearing line is a SNAPSHOT, not a request.** CC appends a fresh
//!    `message.usage` object as a response streams, so one API call leaves
//!    several records carrying the same `requestId` and a growing
//!    `output_tokens`. Summing every record therefore counted each request's
//!    input and cache tokens once per snapshot. [`super::request`] collapses a
//!    file's records to one billable request each; this module then prices and
//!    buckets every request at ITS OWN model and ITS OWN timestamp instead of
//!    attributing a whole session to its first model and start time.
//! 2. **Subagent transcripts were never opened.** CC writes them to
//!    `<encoded-cwd>/<session-id>/subagents/*.jsonl`, one directory level below
//!    the files this scanner read. On the host that surfaced an internal ticket those files
//!    outnumbered the parent-level ones by roughly eight to one over a 31-day
//!    window, so their usage was missing from the ledger entirely.
//!    `scan_project_transcripts` now descends to reach them, opening `subagents/`
//!    and nothing else — so a session's `memory/` and `tool-results/` siblings
//!    are never read.
//!
//! ## Privacy invariant (D6)
//!
//! `TranscriptLine` below is the SOLE deserialization shape used here. It
//! includes ONLY metadata fields — `cwd`, `timestamp`, `sessionId`, and the
//! numeric `message.usage` token counts + `message.model` name. It CANNOT see
//! `message.content`, `first_prompt`, tool payloads, or any conversational
//! text: those fields are simply absent from the struct, so serde discards
//! them. Transcripts are read via a line-streaming [`BufReader`] so no
//! transcript is ever held whole in memory. The relaxed D6 contract (vs the
//! v1 "transcript is NEVER read"): transcript CONTENT is never retained or
//! persisted; only token/cwd/timestamp/model metadata is extracted in-memory.
//! If a future change adds a content field to `TranscriptLine` or
//! `TranscriptMessage`, the privacy contract is violated.

use crate::types::AccountNum;
use crate::usage::ledger::{UsageEvent, UsageSource};
use crate::usage::request::{NormalizedRequest, RequestCollector, SnapshotUsage, UsageSnapshot};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::launch_log::LaunchEvent;

/// Directory name CC uses for a session's nested subagent transcripts. The ONLY
/// child directory this scanner descends into.
const SUBAGENTS_DIR: &str = "subagents";

/// Skip transcript files whose mtime is older than this many days. The widest
/// ledger window is 30 days ([`super::ledger::summarize`]); the extra day is
/// slack for timezone/rounding. On a host with thousands of historical
/// transcripts this bounds the per-render scan to recently-active sessions.
const SCAN_MAX_AGE_DAYS: i64 = 31;

/// One transcript line, projected to METADATA ONLY. PRIVACY (D6): this struct
/// and [`TranscriptMessage`] / [`TranscriptUsage`] are the privacy gate — they
/// contain NO content fields (`content`, `text`, `first_prompt`, tool payloads
/// are absent, so serde drops them). Never add a content field here.
#[derive(Debug, Deserialize)]
struct TranscriptLine {
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(rename = "sessionId", default)]
    session_id: Option<String>,
    /// The vendor's request identifier (an internal ticket). Opaque id, no content.
    #[serde(rename = "requestId", default)]
    request_id: Option<String>,
    /// The record's own identifier. Used ONLY as the last-resort request
    /// identity when neither `requestId` nor `message.id` is present.
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    message: Option<TranscriptMessage>,
}

/// The `message` object on assistant/user lines. METADATA ONLY — carries the
/// model name, the message id and usage counts; `content` is deliberately
/// absent.
#[derive(Debug, Deserialize)]
struct TranscriptMessage {
    /// The assistant message id. Observed 1:1 with `requestId` on every record
    /// carrying both (see [`super::request`]); used as the identity when
    /// `requestId` is absent.
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    usage: Option<TranscriptUsage>,
}

/// The per-turn token counts inside `message.usage`. All numeric.
#[derive(Debug, Default, Deserialize)]
struct TranscriptUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

/// Returns the canonical CC projects directory under `claude_home`, where CC
/// writes per-session transcripts as `<encoded-cwd>/<session-id>.jsonl`.
fn projects_dir(claude_home: &Path) -> PathBuf {
    claude_home.join("projects")
}

/// Why an entry the scan reached was not scanned.
///
/// The variants are deliberately DISJOINT. A reader who sees [`SkipReason::Symlink`]
/// must be able to conclude that containment refused a link — a different finding
/// from an entry that is simply not there, from one whose type is wrong, and from
/// one that could not be read. Collapsing any two of these into one word would
/// make the summary report a refusal that never happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipReason {
    /// A symlink stood where a real entry was required (containment refusal).
    Symlink,
    /// The entry exists but is the wrong kind — a file where a directory is
    /// required, or a directory where a file is required.
    WrongKind,
    /// Nothing is there (`ErrorKind::NotFound`).
    Absent,
    /// Present, but the read failed for another reason (permissions, I/O).
    Unreadable,
}

impl SkipReason {
    const fn as_str(self) -> &'static str {
        match self {
            SkipReason::Symlink => "symlink",
            SkipReason::WrongKind => "wrong-kind",
            SkipReason::Absent => "absent",
            SkipReason::Unreadable => "unreadable",
        }
    }

    /// True for the reasons that mean "something was there and the scan declined
    /// it". `Absent` is the ORDINARY case — most session directories have no
    /// `subagents/` — so it is counted but never alerted: warning on it would
    /// fire on every scan of a healthy tree and drown the two reasons that are
    /// actually findings.
    const fn is_alertable(self) -> bool {
        matches!(self, SkipReason::Symlink | SkipReason::Unreadable)
    }
}

/// Classifies a failed `symlink_metadata` / `read_dir` into [`SkipReason`].
fn reason_for_error(e: &std::io::Error) -> SkipReason {
    if e.kind() == std::io::ErrorKind::NotFound {
        SkipReason::Absent
    } else {
        SkipReason::Unreadable
    }
}

/// Classifies a failed OPEN into [`SkipReason`].
///
/// Separate from [`reason_for_error`] because `ELOOP` is meaningful only here:
/// the opens in this module pass `O_NOFOLLOW` (see [`open_readonly`]), so a link
/// that appeared between the admission check and the open is reported as a
/// containment refusal rather than as a generic I/O failure.
fn reason_for_open_error(e: &std::io::Error) -> SkipReason {
    if e.kind() == std::io::ErrorKind::NotFound {
        return SkipReason::Absent;
    }
    #[cfg(unix)]
    if e.raw_os_error() == Some(libc::ELOOP) {
        return SkipReason::Symlink;
    }
    SkipReason::Unreadable
}

/// Admits `path` as a real directory, or names why it is refused.
///
/// [`std::path::Path::is_dir`] follows symlinks, so it answers `true` for a link
/// pointing at any directory anywhere on the filesystem. Using it to decide
/// which directories to descend into would let a link planted in the
/// vendor-written `projects/` tree redirect the scan outside it — the same
/// containment [`admits_transcript`] gives the file half.
/// [`std::fs::symlink_metadata`] does not traverse the link, which is the
/// property that distinguishes them.
///
/// Returns the refusal REASON rather than a bare `false` so the scan can account
/// for what it passed over (see [`ScanSkips`]). The verdict and the reason come
/// from ONE `symlink_metadata`, so the two cannot disagree — a second stat to
/// classify a refusal could report `symlink` for an entry that was merely
/// missing by the time it ran.
fn admit_dir(path: &Path) -> Result<(), SkipReason> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(SkipReason::Symlink),
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(SkipReason::WrongKind),
        Err(e) => Err(reason_for_error(&e)),
    }
}

/// Admits `path` as a regular file and NOT a symlink to one, or names why it is
/// refused. The mtime-FREE half of the file check, used by
/// [`read_attribution_header`].
///
/// Deliberately NOT [`admits_transcript`], which differs in exactly TWO respects
/// and matters here in both. `admits_transcript` also gates on the `.jsonl`
/// EXTENSION, and it also bounds mtime by [`SCAN_MAX_AGE_DAYS`]. The bound is
/// dropped because a parent may sit outside the window while its children are
/// inside it, so the parent's attribution has to be readable without the parent
/// being scanned for usage; re-imposing it would silently drop the attribution
/// of every subagent beneath a long-running session. The extension gate is
/// dropped because the caller derives this path from the session id
/// (`with_extension`) rather than from a directory entry's own name.
fn admit_file(path: &Path) -> Result<(), SkipReason> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(SkipReason::Symlink),
        Ok(m) if m.is_file() => Ok(()),
        Ok(_) => Err(SkipReason::WrongKind),
        Err(e) => Err(reason_for_error(&e)),
    }
}

/// Opens `path` for reading WITHOUT following a symlink in the final component.
///
/// ## Why the flag, and what it does NOT close
///
/// Every admission in this module is a check-then-use on a PATH NAME: [`admit_dir`],
/// [`admit_file`] and [`admits_transcript`] stat the name, and the open then
/// re-resolves it. A link swapped in between the stat and the open is therefore
/// followed — the file half of a time-of-check/time-of-use window. `O_NOFOLLOW`
/// closes that half at the syscall: the open itself refuses the link (`ELOOP`)
/// instead of trusting a check that has already happened.
///
/// The DIRECTORY half is NOT closed. [`std::fs::read_dir`] takes a path and
/// re-resolves it, and offers no equivalent flag, so a link swapped into a
/// directory's place between its admission and its enumeration is still
/// followed. Closing it needs `openat`-style directory descriptors threaded
/// through the whole traversal, which `std` does not expose. This is a bounded,
/// documented gap rather than a silent one — the window is between two syscalls
/// of the same scan, and its precondition is write access to the tree, which is
/// already sufficient to plant the transcripts directly.
///
/// Non-unix has no `O_NOFOLLOW`, so the plain open is used and the callers'
/// `admit_*` checks remain the only refusal, exactly as before.
#[cfg(unix)]
fn open_readonly(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_readonly(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// Skip counts for one tier, in the [`SkipReason`] vocabulary.
///
/// The shape mirrors [`crate::usage::ledger::ReadResult`]: a read returns its
/// data AND what it passed over, so a skip is REPORTABLE rather than silent.
/// That struct's `skipped_malformed` is the same discipline for malformed ledger
/// lines; this is its filesystem-side counterpart.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SkipCounts {
    symlink: usize,
    wrong_kind: usize,
    absent: usize,
    unreadable: usize,
}

impl SkipCounts {
    fn record(&mut self, reason: SkipReason) {
        match reason {
            SkipReason::Symlink => self.symlink += 1,
            SkipReason::WrongKind => self.wrong_kind += 1,
            SkipReason::Absent => self.absent += 1,
            SkipReason::Unreadable => self.unreadable += 1,
        }
    }

    fn total(&self) -> usize {
        self.symlink + self.wrong_kind + self.absent + self.unreadable
    }
}

impl std::fmt::Display for SkipCounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "symlink={} wrong-kind={} absent={} unreadable={}",
            self.symlink, self.wrong_kind, self.absent, self.unreadable
        )
    }
}

/// What one traversal of `projects/` passed over, by containment tier.
///
/// One counter group per tier of the four enumerated in
/// [`scan_project_transcripts`]'s docs, so that enumeration has a visible
/// counterpart: a tier whose check was dropped would show up here as the
/// refusals it stopped making.
///
/// Which reasons are counted is per-tier, because what is ORDINARY differs per
/// tier — counting everything everywhere would report noise as skips.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ScanSkips {
    /// Tier 1 — entries directly in `projects/`. Every entry is expected to be a
    /// project directory, so all four reasons are counted.
    project_dir: SkipCounts,
    /// Tier 2 — the session directory `<encoded-cwd>/<session-id>/`. Only
    /// REFUSALS are counted here: most entries at this level are plain files
    /// (`<session-id>.jsonl` among them), so `wrong-kind` and `absent` are the
    /// ordinary shape of "this entry is not a session directory". Those two
    /// fields stay zero by construction.
    session_dir: SkipCounts,
    /// Tier 3 — `<session-id>/subagents/`, probed speculatively for every
    /// session directory. `absent` is the ordinary case and IS counted, because
    /// distinguishing it from `unreadable` is the point: a permissions failure
    /// and a session with no subagents are otherwise indistinguishable.
    subagents_dir: SkipCounts,
    /// Tier 4 — transcript files, at both open sites (the attribution read and
    /// the usage scan). A file is only reached here after [`admits_transcript`]
    /// admitted it, so `symlink` is the TOCTOU residue and `unreadable` is the
    /// permissions case.
    transcript_file: SkipCounts,
}

impl ScanSkips {
    fn total(&self) -> usize {
        self.project_dir.total()
            + self.session_dir.total()
            + self.subagents_dir.total()
            + self.transcript_file.total()
    }

    /// Emits the per-scan summary: ONE line per traversal, never one line per
    /// entry.
    ///
    /// The scan runs on a periodic daemon tick, so per-entry logging would emit
    /// a line per file per tick — for a project directory holding many
    /// symlinked transcripts, that is the difference between a constant and a
    /// flood. Counters carry the same information at constant cost. Silenced
    /// entirely when nothing was skipped, so a healthy tree logs nothing.
    fn report(&self) {
        if self.total() == 0 {
            return;
        }
        tracing::debug!(
            project_dir = %self.project_dir,
            session_dir = %self.session_dir,
            subagents_dir = %self.subagents_dir,
            transcript_file = %self.transcript_file,
            "transcript scan skipped entries"
        );
    }
}

/// Paths already alerted on, so a PERSISTENT refusal warns on the first scan
/// rather than on every tick.
///
/// Bounded deliberately: the scan runs on a schedule against a tree that can
/// grow, so an unbounded set would be a leak only a long-lived daemon would
/// find. Past the cap the set is cleared, which RE-ARMS every alert — the
/// failure mode of the cap is a repeated warning, never a suppressed one.
fn alerted_paths() -> &'static Mutex<HashSet<PathBuf>> {
    static ALERTED: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    ALERTED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Above this many remembered paths, the dedupe set is cleared rather than grown.
const ALERT_DEDUPE_CAP: usize = 256;

/// Reports a refused entry ONCE per path, for the reasons that represent a
/// finding ([`SkipReason::is_alertable`]).
///
/// Without the dedupe, a link planted in the tree would warn on every tick
/// forever. Without the alert at all, the refusal is visible only at `debug` —
/// which is why a legitimately symlinked project directory, one this scan read
/// before containment landed and refuses now, produced no signal whatsoever.
fn alert_once(path: &Path, reason: SkipReason) {
    if !reason.is_alertable() {
        return;
    }
    {
        // A poisoned lock means another thread panicked while holding it.
        // Recovering the guard keeps the alert working instead of silently
        // dropping it.
        let mut seen = alerted_paths()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if seen.len() >= ALERT_DEDUPE_CAP {
            seen.clear();
        }
        if !seen.insert(path.to_path_buf()) {
            return;
        }
    }
    tracing::warn!(
        reason = reason.as_str(),
        path = %path.display(),
        "transcript scan refused an entry"
    );
}

/// True when `path` is a regular `.jsonl` file (not a symlink) whose mtime is
/// at or after `cutoff`.
///
/// Symlinks are refused rather than followed: `projects/` is a vendor-written
/// tree, and following a link out of it would let an entry placed there decide
/// which files this scanner reads. `symlink_metadata` does not traverse the
/// link, so this is the check that distinguishes them — `Path::is_file` does
/// traverse and would answer `true` for a link to a regular file.
///
/// The two failure branches do NOT agree, deliberately. A failed
/// `symlink_metadata` REFUSES: without it there is no evidence the entry is a
/// real regular file, so admitting would defeat the containment above. A failed
/// `modified()` on a metadata value that WAS read ADMITS, preserving the
/// pre-an internal ticket behaviour — the mtime bound is a scan-cost optimisation, so failing
/// to read an mtime must not silently drop a slot's billing data. Naming the
/// second as "a file whose metadata cannot be read" would describe the first,
/// which does the opposite.
fn admits_transcript(path: &Path, cutoff: DateTime<Utc>) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
        return false;
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    match meta.modified() {
        Ok(modified) => DateTime::<Utc>::from(modified) >= cutoff,
        Err(_) => true,
    }
}

/// Scans the CC projects directory (`~/.claude/projects`) and returns one
/// [`ScannedSession`] per transcript that carries at least one usage-bearing
/// record.
///
/// ## Traversal shape (an internal ticket)
///
/// Two levels, and no more. For each `<encoded-cwd>/` project directory:
///
/// - every `*.jsonl` directly inside it — the parent-level session transcripts,
///   which is all the pre-an internal ticket scanner read;
/// - every `*.jsonl` inside `<session-id>/subagents/` — the nested subagent
///   transcripts, whose usage was previously missing outright.
///
/// Nothing else is descended into, and the mechanism is an ALLOWLIST OF ONE
/// NAME, not a denylist: every child directory of a project is collected, and
/// the only path then opened under each is `<child>/subagents/`
/// ([`SUBAGENTS_DIR`]). A session's `memory/` and `tool-results/` siblings are
/// therefore excluded by never being opened — there is no skip-list naming
/// them anywhere in this file, and adding a directory name to one would exclude
/// nothing. To exclude a NEW directory, nothing need be done; to INCLUDE one,
/// it must be opened explicitly like `subagents/` is.
///
/// The depth is a fixed constant of the code rather than a recursion bound —
/// two nested loops, no self-call — so a deep or cyclic tree cannot be walked
/// past the second level.
///
/// ## Containment (four tiers, all load-bearing)
///
/// `projects/` is a vendor-written tree, so every path this scanner opens is
/// admitted by a check that refuses a symlink. There are FOUR such tiers,
/// because a link can be planted at four levels and each level is reached by a
/// different call:
///
/// 1. the PROJECT directory `projects/<encoded-cwd>/` — [`admit_dir`];
/// 2. the SESSION directory `<encoded-cwd>/<session-id>/` — [`admit_dir`];
/// 3. the `<session-id>/subagents/` directory — [`admit_dir`];
/// 4. every transcript FILE, parent-level and subagent — [`admits_transcript`],
///    and the parent-only ATTRIBUTION read — [`admit_file`].
///
/// **Tier 2 is not derivable from tier 1, and none of the four substitutes for
/// another.** `lstat` examines only the FINAL path component; the kernel
/// resolves every intermediate symlink in the prefix first. So if the
/// session-directory admission (tier 2) did not exist, a link planted at
/// `<session-id>` would be resolved BEFORE tier 4 is reached: an attacker points
/// it at a directory of their own holding a real `subagents/` and a real
/// `leak.jsonl` with a fresh mtime, tier 3 lstats the final component of a path
/// the kernel has already redirected, sees a genuine `subagents/` directory,
/// admits it — and tier 4 then sees a genuine regular file and admits that too.
/// The escape is the missing tier, not a weak one. Containment is a chain, and it
/// holds only as strongly as its weakest link, which is why all four tiers are
/// checked rather than the deepest one.
///
/// All four share one primitive: [`std::fs::symlink_metadata`], which reports on
/// the link itself. `Path::is_dir` and `Path::is_file` FOLLOW symlinks and would
/// admit a link pointing anywhere on the filesystem.
///
/// Two boundaries this does NOT cover, named so neither is mistaken for an
/// oversight. **Hardlinks**: `symlink_metadata` reports a hardlink as an
/// ordinary regular file, so a hardlink planted in the tree and pointing at a
/// file outside it IS admitted. No `lstat` can distinguish it, and refusing on
/// `st_nlink == 1` would refuse legitimate files, which carry their own link
/// count. Creating the hardlink requires write access to this tree, which is
/// already sufficient to plant the transcript's contents directly — so this is a
/// boundary, not a hole. **The directory half of TOCTOU**: a link swapped into a
/// directory's place AFTER its admission but BEFORE `read_dir` re-resolves it is
/// followed, because `std`'s `read_dir` takes a path and exposes no
/// `O_NOFOLLOW` equivalent. The FILE half of that window is closed at the
/// syscall by [`open_readonly`].
///
/// [`projects_dir`] itself is deliberately NOT checked, and adding a check there
/// would be a mistake rather than a hardening. Containment is defined RELATIVE TO
/// this root — a path is admitted because it is inside the tree the scanner was
/// handed, and the root cannot be outside itself. The directory is opened where
/// `claude_home` says it is, including when that path traverses a symlink,
/// because CC writes there through that same path. A future auditor should not
/// "fix" this line.
///
/// Bounded by mtime ([`SCAN_MAX_AGE_DAYS`]) so a host with thousands of
/// historical transcripts does not pay a full scan on every dashboard render.
/// Files that fail to open, contain no usage, or cannot be attributed to a cwd
/// are skipped — the aggregator's job is best-effort billing telemetry — and
/// every skip the filesystem CAUSED is counted per tier into [`ScanSkips`], so a
/// refusal is reportable rather than silent. (A file that opens and simply
/// carries no usage is not counted: that is the predicate working, not a skip.)
///
/// A subagent transcript is scanned AFTER its parent, which is what lets a
/// request appearing in both keep the parent's provenance
/// ([`super::request::RequestCollector::push`]).
fn scan_project_transcripts(projects_dir: &Path, now: DateTime<Utc>) -> Vec<ScannedSession> {
    let (sessions, skips) = scan_project_transcripts_counting(projects_dir, now);
    skips.report();
    sessions
}

/// [`scan_project_transcripts`], returning what it passed over alongside what it
/// read.
///
/// Split out so the counters are ASSERTABLE without capturing logs: the wrapper
/// above reports them, this one computes them. A test asserts here.
fn scan_project_transcripts_counting(
    projects_dir: &Path,
    now: DateTime<Utc>,
) -> (Vec<ScannedSession>, ScanSkips) {
    let cutoff = now - Duration::days(SCAN_MAX_AGE_DAYS);
    let mut skips = ScanSkips::default();
    let project_entries = match std::fs::read_dir(projects_dir) {
        Ok(e) => e,
        // The root itself: accounted, then the scan returns nothing. A missing
        // `projects/` is ordinary on a host that has never run CC; an
        // UNREADABLE one is a finding, and only the counters tell them apart.
        Err(e) => {
            let reason = reason_for_error(&e);
            skips.project_dir.record(reason);
            alert_once(projects_dir, reason);
            return (Vec::new(), skips);
        }
    };
    let mut out = Vec::new();
    for project in project_entries.flatten() {
        let project_path = project.path();
        // Containment tier 1. `is_dir` FOLLOWS symlinks, so a link planted here
        // would redirect every read below it — and the file-level checks cannot
        // see it, because lstat examines only the final component (module docs).
        if let Err(reason) = admit_dir(&project_path) {
            skips.project_dir.record(reason);
            alert_once(&project_path, reason);
            continue;
        }
        let entries = match std::fs::read_dir(&project_path) {
            Ok(e) => e,
            Err(e) => {
                let reason = reason_for_error(&e);
                skips.project_dir.record(reason);
                alert_once(&project_path, reason);
                continue;
            }
        };
        let mut session_dirs: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if admits_transcript(&path, cutoff) {
                if let Some(session) = scan_one_transcript(&path, false, None, &mut skips) {
                    out.push(session);
                }
            } else if let Err(reason) = admit_dir(&path) {
                // Containment tier 2. Refusals ONLY are counted here: most
                // entries at this level are plain files (`<session-id>.jsonl`
                // among them), so `wrong-kind`/`absent` are the ordinary shape
                // of "not a session directory" rather than skips — counting them
                // would report noise, and `is_alertable` is exactly the line
                // between the two.
                if reason.is_alertable() {
                    skips.session_dir.record(reason);
                    alert_once(&path, reason);
                }
            } else {
                session_dirs.push(path);
            }
        }
        // Second level: `<session-id>/subagents/*.jsonl` only.
        for session_dir in session_dirs {
            let subagents = session_dir.join(SUBAGENTS_DIR);
            // Containment tier 3. `session_dir` was itself admitted by the tier-2
            // check above, so the whole prefix is already known real and lstat on
            // this final component is sufficient — that tier is what makes this
            // one sufficient, and removing it would not be compensated for here.
            if let Err(reason) = admit_dir(&subagents) {
                skips.subagents_dir.record(reason);
                alert_once(&subagents, reason);
                continue; // no subagents/ here, or it is a symlink
            }
            let children = match std::fs::read_dir(&subagents) {
                Ok(c) => c,
                Err(e) => {
                    let reason = reason_for_error(&e);
                    skips.subagents_dir.record(reason);
                    alert_once(&subagents, reason);
                    continue; // unreadable
                }
            };
            // The parent transcript sits beside the session directory and
            // shares its name. It supplies a cwd ONLY for a child that carries
            // none of its own; resolved lazily so the common case pays nothing.
            let parent_transcript = session_dir.with_extension("jsonl");
            let mut parent: Option<Option<ParentAttribution>> = None;
            for child in children.flatten() {
                let path = child.path();
                if !admits_transcript(&path, cutoff) {
                    continue;
                }
                let parent_attr = parent
                    .get_or_insert_with(|| read_attribution_header(&parent_transcript, &mut skips))
                    .as_ref();
                if let Some(session) = scan_one_transcript(&path, true, parent_attr, &mut skips) {
                    // A child attributes as its PARENT did (an internal ticket finding 4).
                    // Only when the parent's instant is unavailable does the
                    // child fall back to its own, which is no worse than the
                    // pre-fix behaviour.
                    let session = match parent_attr.and_then(|p| p.start_time.clone()) {
                        Some(parent_start) => session.with_attribution_time(parent_start),
                        None => session,
                    };
                    out.push(session);
                }
            }
        }
    }
    (out, skips)
}

/// The parent transcript's attribution keys, used only to rescue a subagent
/// transcript that carries no `cwd` of its own.
#[derive(Debug, Clone, PartialEq)]
struct ParentAttribution {
    project_path: String,
    session_id: Option<String>,
    /// The parent session's own earliest observed timestamp, used as the
    /// ATTRIBUTION instant for every child beneath it (see
    /// [`ScannedSession::attribution_time`]). `None` when the parent transcript
    /// is unreadable or carries no parseable timestamp.
    start_time: Option<String>,
}

/// Streams a transcript only far enough to read its `cwd` and `sessionId`,
/// stopping at the first line that supplies the `cwd`.
///
/// Deliberately separate from [`scan_one_transcript`]: a parent may be outside
/// the mtime window while its children are inside it, so the parent's
/// attribution has to be readable without the parent being scanned for usage.
/// Returns `None` when the file is absent or carries no `cwd`.
///
/// Containment tier 4, attribution half. This is the ONE file the scanner opens
/// that [`admits_transcript`] does not gate, so it carries its own symlink
/// refusal — [`admit_file`], the mtime-FREE form. Reusing the mtime-bounded
/// predicate instead would re-impose the very bound this function exists to
/// avoid, silently dropping the attribution of every subagent under a parent
/// older than [`SCAN_MAX_AGE_DAYS`].
///
/// Both the refusal and an open failure are recorded into `skips`: a caller
/// cannot otherwise tell "this session has no parent transcript" from "there is
/// one and we were not allowed to read it", and those two mean different things
/// for the child's attribution.
fn read_attribution_header(path: &Path, skips: &mut ScanSkips) -> Option<ParentAttribution> {
    if let Err(reason) = admit_file(path) {
        skips.transcript_file.record(reason);
        alert_once(path, reason);
        return None;
    }
    let reader = match open_readonly(path) {
        Ok(f) => BufReader::new(f),
        Err(e) => {
            let reason = reason_for_open_error(&e);
            skips.transcript_file.record(reason);
            alert_once(path, reason);
            return None;
        }
    };
    let mut session_id: Option<String> = None;
    let mut project_path: Option<String> = None;
    let mut start_time: Option<String> = None;
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.is_empty() {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<TranscriptLine>(&line) else {
            continue;
        };
        if session_id.is_none() {
            session_id = rec.session_id;
        }
        if project_path.is_none() {
            project_path = rec.cwd;
        }
        if start_time.is_none() {
            // The FIRST parseable timestamp, not a scan for the minimum. CC
            // appends transcripts, and in every transcript examined for an internal ticket
            // timestamps were non-decreasing down the file, so the first is
            // typically the earliest. That is an observation about this
            // vendor's writer, NOT a guarantee about the format, and the cost
            // of it being wrong is bounded: a late parent instant can only
            // admit a launch event the parent itself would not have matched,
            // which is the same failure mode as reading no parent at all.
            // Scanning the whole parent file for a true minimum would cost a
            // full read per session directory on every tick.
            if let Some(ts) = rec.timestamp {
                if DateTime::parse_from_rfc3339(&ts).is_ok() {
                    start_time = Some(ts);
                }
            }
        }
        if project_path.is_some() && start_time.is_some() {
            break;
        }
    }
    Some(ParentAttribution {
        project_path: project_path?,
        session_id,
        start_time,
    })
}

/// Streams one transcript file line-by-line (never holding it whole), collapses
/// its usage snapshots into normalized requests, and folds the metadata into a
/// [`ScannedSession`]. Returns `None` when the file has no usage-bearing record
/// or cannot be attributed to a `cwd`/`timestamp`.
///
/// `from_subagent` marks every request this file produces, so the summary can
/// report how much usage came from nested transcripts.
///
/// `parent` is consulted ONLY when this file carries no `cwd` of its own, and
/// only then under the agreement condition in [`ScannedSession`]'s docs:
/// nesting alone never authorizes attribution, so a child that names a
/// DIFFERENT session than the directory it sits in is dropped rather than
/// billed to the parent's slot.
fn scan_one_transcript(
    path: &Path,
    from_subagent: bool,
    parent: Option<&ParentAttribution>,
    skips: &mut ScanSkips,
) -> Option<ScannedSession> {
    // The call site admitted this file via `admits_transcript`, so an open
    // failure here is either the permissions case or a link that appeared in
    // between — `O_NOFOLLOW` refuses the latter outright rather than following
    // it. Either way it is RECORDED rather than dropped: a transcript that
    // exists but cannot be read is a billing gap, and it is indistinguishable
    // from an empty file unless the failure is counted.
    let file = match open_readonly(path) {
        Ok(f) => f,
        Err(e) => {
            let reason = reason_for_open_error(&e);
            skips.transcript_file.record(reason);
            alert_once(path, reason);
            return None;
        }
    };
    let reader = BufReader::new(file);
    // Identity namespace for the last-resort per-record key. The full path is
    // unique per file within one scan, so two files' uuid-less records can
    // never merge.
    let file_key = path.to_string_lossy().into_owned();

    let mut project_path: Option<String> = None;
    let mut start_time: Option<String> = None;
    let mut start_ts: Option<DateTime<chrono::FixedOffset>> = None;
    let mut session_id: Option<String> = None;
    let mut model: Option<String> = None;
    let mut requests = RequestCollector::new();
    let mut line_ordinal: u64 = 0;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break, // truncated/binary — stop, keep what we have
        };
        line_ordinal += 1;
        if line.is_empty() {
            continue;
        }
        // Perf prefilter (an internal ticket): a transcript is mostly content/user/
        // attachment lines that carry no token counts. Once the attribution
        // header (cwd + sessionId + first timestamp) is captured — which CC
        // writes on the earliest lines — only lines bearing a `usage` object
        // can still contribute, so skip the serde parse on everything else.
        // This turns an O(all lines) parse into O(header + usage lines) and is
        // the difference between a multi-second and a sub-second per-file scan
        // on transcripts with hundreds of large content lines. CC appends in
        // timestamp order, so the earliest timestamp is on an early line and
        // is never on a skipped tail line.
        let header_complete =
            project_path.is_some() && session_id.is_some() && start_time.is_some();
        if header_complete && !line.contains("\"usage\"") {
            continue;
        }
        let rec: TranscriptLine = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue, // tolerate non-conforming lines
        };
        if project_path.is_none() {
            if let Some(cwd) = rec.cwd {
                project_path = Some(cwd);
            }
        }
        if session_id.is_none() {
            session_id = rec.session_id;
        }
        // Earliest timestamp seen. The perf prefilter above skips non-`usage`
        // tail lines once the header is complete, so this is the minimum across
        // header lines and usage lines rather than across every line in the
        // file. CC writes transcripts by appending, and in the transcripts
        // observed for an internal ticket timestamps were non-decreasing down the file, so
        // the earliest one is typically on an early line that the prefilter
        // does not skip. That is an observation, NOT a guarantee about the
        // format: a genuinely earlier timestamp on a skipped non-usage tail
        // line would leave `start_time` late.
        //
        // What that costs, precisely: `start_time` is used for attribution (a
        // launch event must be at or before it) and — before an internal ticket — for
        // pricing the entire session. Pricing no longer depends on it at all,
        // because each request is priced at its own timestamp
        // (`attributed_session_to_events_with_manifest`), so a late
        // `start_time` can now only shift which launch event wins attribution,
        // never what a token costs and never which rolling window it lands in.
        if let Some(ts) = rec.timestamp.as_deref() {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
                match start_ts {
                    Some(prev) if parsed >= prev => {}
                    _ => {
                        start_ts = Some(parsed);
                        start_time = Some(ts.to_string());
                    }
                }
            }
        }
        if let Some(msg) = rec.message {
            // Treat an empty model string as absent so the caller's slot
            // fallback applies instead of passing "" to the rate table.
            let line_model = msg.model.filter(|m| !m.is_empty());
            if model.is_none() {
                model.clone_from(&line_model);
            }
            if let Some(u) = msg.usage {
                requests.push(
                    UsageSnapshot {
                        request_id: rec.request_id,
                        message_id: msg.id,
                        record_uuid: rec.uuid,
                        timestamp: rec.timestamp.clone(),
                        model: line_model,
                        usage: SnapshotUsage {
                            input_tokens: u.input_tokens,
                            output_tokens: u.output_tokens,
                            cache_creation_tokens: u.cache_creation_input_tokens,
                            cache_read_tokens: u.cache_read_input_tokens,
                        },
                    },
                    &file_key,
                    line_ordinal,
                    from_subagent,
                );
            }
        }
    }

    // Require usage; otherwise there is nothing to bill.
    if requests.is_empty() {
        return None;
    }
    // Fall back to the file stem for session_id (CC names files by session id).
    let session_id = session_id.clone().or_else(|| {
        path.file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
    })?;

    // Attribution. A file with its own `cwd` stands alone and is attributed by
    // the same cwd + time + provider gate as any parent transcript — nesting
    // grants it nothing. Only a file with NO `cwd` may borrow its parent's, and
    // only when it does not name a different session: a subagent transcript
    // claiming another session id is evidence against, not for, the parent's
    // ownership of its usage.
    let project_path = match project_path {
        Some(own) => own,
        None => {
            let parent = parent?;
            let names_other_session = session_id != *parent.session_id.as_ref()?;
            if names_other_session {
                return None;
            }
            parent.project_path.clone()
        }
    };
    let requests = requests.finish();
    // Every request's own timestamp is a candidate start; the earliest wins so
    // a file whose header line carried no timestamp still attributes.
    let start_time = start_time.or_else(|| earliest_request_timestamp(&requests))?;

    Some(ScannedSession::from_parts(
        session_id,
        project_path,
        start_time,
        model,
        requests,
    ))
}

/// The earliest parseable request timestamp, used as a session start only when
/// no transcript line supplied one. Requests whose timestamp does not parse are
/// skipped here; they still bill, they just cannot anchor the session start.
fn earliest_request_timestamp(requests: &[NormalizedRequest]) -> Option<String> {
    requests
        .iter()
        .filter_map(|r| {
            let raw = r.timestamp.as_ref()?;
            let parsed = DateTime::parse_from_rfc3339(raw).ok()?;
            Some((parsed, raw.clone()))
        })
        .min_by_key(|(parsed, _)| *parsed)
        .map(|(_, raw)| raw)
}

/// One scanned transcript — the metadata projection used for attribution.
///
/// One of these covers ONE FILE. A parent-level transcript and each of its
/// `subagents/*.jsonl` children produce separate `ScannedSession`s, each
/// attributed on its own merits: a child with its own `cwd` is matched against
/// the launch log exactly like a parent, and a child with no `cwd` borrows its
/// parent's only when it does not name a different `sessionId`. Nesting is how
/// the file is FOUND; it is never by itself a reason to bill a slot.
#[derive(Debug, Clone, PartialEq)]
pub struct ScannedSession {
    pub session_id: String,
    pub project_path: String,
    pub start_time: String,
    /// The first non-empty model name seen in the transcript. Used by the
    /// attribution provider-consistency gate ([`attribute_session`]), which
    /// needs one family per file, and as a display default.
    ///
    /// This is NOT what prices the session. Since an internal ticket each entry in
    /// [`ScannedSession::requests`] carries its own model and is priced at it,
    /// so a session that switched models mid-run bills each model it used.
    pub model: Option<String>,
    /// Sum of `input_tokens` over [`ScannedSession::requests`]. Derived by
    /// [`ScannedSession::from_parts`], so it cannot drift from the requests it
    /// summarizes.
    pub input_tokens: u64,
    /// Sum of `output_tokens` over [`ScannedSession::requests`].
    pub output_tokens: u64,
    /// Sum of cache-write tokens (`cache_creation_input_tokens`) over
    /// [`ScannedSession::requests`].
    pub cache_creation_tokens: u64,
    /// Sum of cache-read tokens (`cache_read_input_tokens`) over
    /// [`ScannedSession::requests`].
    pub cache_read_tokens: u64,
    /// The billable requests this transcript contributes, after snapshot
    /// collapse. Each is priced and bucketed individually.
    pub requests: Vec<NormalizedRequest>,
    /// The instant [`attribute_session`] matches against the launch log —
    /// SEPARATE from [`ScannedSession::start_time`], which is a display and
    /// bucketing value.
    ///
    /// For a parent transcript the two are equal. For a SUBAGENT transcript
    /// this is the PARENT session's start, because a child's usage belongs to
    /// whichever slot's credentials the parent session was launched under, and
    /// the child's own start time is not evidence of that. A `csq run` into the
    /// same cwd between the parent's start and the child's would otherwise route
    /// the child to a different slot than its parent — one `sessionId` billed
    /// across two accounts. The provider-consistency gate cannot separate them
    /// when both slots are the same family.
    ///
    /// Falls back to the child's own start only when the parent transcript is
    /// unreadable or carries no parseable timestamp; that case is strictly no
    /// worse than the pre-fix behaviour, and it is the only case in which a
    /// child can still diverge from its parent.
    pub attribution_time: String,
}

impl ScannedSession {
    /// Builds a session from its normalized requests, DERIVING the four
    /// aggregate token totals by summation.
    ///
    /// The aggregates are derived rather than passed in so that no caller —
    /// production or test — can construct a session whose totals disagree with
    /// the requests they claim to summarize.
    pub fn from_parts(
        session_id: String,
        project_path: String,
        start_time: String,
        model: Option<String>,
        requests: Vec<NormalizedRequest>,
    ) -> Self {
        let mut input_tokens = 0u64;
        let mut output_tokens = 0u64;
        let mut cache_creation_tokens = 0u64;
        let mut cache_read_tokens = 0u64;
        for r in &requests {
            input_tokens = input_tokens.saturating_add(r.usage.input_tokens);
            output_tokens = output_tokens.saturating_add(r.usage.output_tokens);
            cache_creation_tokens =
                cache_creation_tokens.saturating_add(r.usage.cache_creation_tokens);
            cache_read_tokens = cache_read_tokens.saturating_add(r.usage.cache_read_tokens);
        }
        ScannedSession {
            session_id,
            project_path,
            // Defaults to the session's own start; the scanner overrides it for
            // a subagent transcript via `with_attribution_time`.
            attribution_time: start_time.clone(),
            start_time,
            model,
            input_tokens,
            output_tokens,
            cache_creation_tokens,
            cache_read_tokens,
            requests,
        }
    }

    /// Overrides the launch-log matching instant — used by the scanner to make a
    /// subagent transcript attribute as its PARENT did. See
    /// [`ScannedSession::attribution_time`].
    pub fn with_attribution_time(mut self, attribution_time: String) -> Self {
        self.attribution_time = attribution_time;
        self
    }
}

/// Result of attributing a session to a slot.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributedSession {
    pub slot: AccountNum,
    pub session: ScannedSession,
}

/// Classifies a TRANSCRIPT model NAME into its provider-family id in the
/// `providers::catalog` id namespace (`claude`/`codex`/`gemini`/`deepseek`/
/// `mm`/`zai`/`ollama`), so it can be compared against a slot's family
/// resolved from its [`crate::accounts::AccountSource`] via
/// [`provider_family_for_source`]. Used ONLY by [`attribute_session`]'s
/// provider-consistency gate.
///
/// Case-insensitive substring match. Returns `None` for names it cannot
/// classify (Ollama-hosted open models like `qwen`/`llama`, future providers)
/// — the gate treats `None` as "don't know, don't gate", preserving cwd+time
/// attribution for unclassifiable models rather than over-rejecting.
///
/// The MiniMax and OpenAI arms are ANCHORED (`starts_with` / dotted prefixes)
/// rather than bare `contains` so a stray `m2.`/`o3` substring inside another
/// provider's model name cannot misclassify it (`deepseek`/`glm`/`gemini`/
/// `claude` are provider-unique tokens and stay `contains`).
fn model_provider_family(model: &str) -> Option<&'static str> {
    let lc = model.to_lowercase();
    if lc.contains("claude") {
        Some("claude")
    } else if lc.contains("deepseek") {
        Some("deepseek")
    } else if lc.contains("kimi") {
        Some("kimi")
    } else if lc.contains("glm") {
        Some("zai")
    } else if lc.contains("minimax")
        || lc.contains("abab")
        || lc.starts_with("m2.")
        || lc.starts_with("m3.")
        || lc.starts_with("m4.")
        || lc == "m2"
        || lc == "m3"
        || lc == "m4"
    {
        Some("mm")
    } else if lc.contains("gemini") {
        Some("gemini")
    } else if lc.contains("gpt")
        || lc.contains("codex")
        || lc == "o1"
        || lc == "o3"
        || lc == "o4"
        || lc.starts_with("o1-")
        || lc.starts_with("o3-")
        || lc.starts_with("o4-")
    {
        Some("codex")
    } else {
        None
    }
}

/// Resolves a slot's provider-family id (same namespace as
/// [`model_provider_family`]) from its authoritative
/// [`crate::accounts::AccountSource`]. This is the slot side of the
/// provider-consistency gate — using the account source (not the slot's
/// configured `ANTHROPIC_MODEL`) is what makes the gate correct for EVERY
/// surface: Codex slots store their model in `config.toml` and Gemini slots in
/// `~/.gemini`, so a model-string lookup would resolve `None` and mis-default
/// them to the Anthropic family, letting a `claude` session bleed onto a
/// Codex/Gemini card. `Manual` sources classify to `None` (unknown → gate does
/// not fire).
fn provider_family_for_source(source: &crate::accounts::AccountSource) -> Option<&'static str> {
    use crate::accounts::AccountSource as S;
    match source {
        S::Anthropic => Some("claude"),
        S::Codex => Some("codex"),
        S::Gemini => Some("gemini"),
        // Display name (`"DeepSeek"`/`"MiniMax"`/`"Z.AI"`/`"Ollama"`) → catalog id.
        S::ThirdParty { provider } => crate::providers::catalog::id_from_display_name(provider),
        S::Manual => None,
        // Native-CLI session surfaces (Wave 3, an internal journal entry) — `kimi` / `grok`.
        // In practice this arm is inert for attribution: `kimi`/`grok` are
        // vendor binaries, NOT `claude`, so they write no CC-shaped JSONL
        // transcript for `attribute_session` to scan in the first place. The
        // mapping is filled for exhaustiveness + symmetry with the 3P Kimi
        // bearer id ("kimi", matched by `model_provider_family`'s
        // `contains("kimi")` arm above).
        S::Native { surface } => Some(surface.as_str()),
    }
}

/// Attributes a session to a slot using the launch log. Returns `None` if no
/// matching launch event is found — those sessions remain unattributed and
/// are excluded from per-slot ledgers (visible in a future "unattributed"
/// total in the UI per an internal journal entry §FD #1).
///
/// Match heuristic: pick the most recent launch event whose `project_path`
/// equals the session's `project_path` AND whose timestamp is ≤ the session's
/// `start_time` AND whose slot's provider family is consistent with the
/// transcript's model family. The launch event closest in time before the
/// session start wins. If no project_path match exists, we return None (do NOT
/// cross-match across cwds — that would smear telemetry across unrelated work).
///
/// ## Provider-consistency gate (cross-provider attribution bleed)
///
/// cwd+time alone mis-attributes: a plain `claude` (Anthropic subscription)
/// session run in a directory where a DeepSeek/Codex/Gemini slot was last
/// `csq run` gets billed onto that slot, because CC's transcript carries a
/// matching `cwd` and that slot's launch event is the closest prior. But CC's
/// transcript reports the ACTUAL model — `claude-*` for a genuine Anthropic
/// session, `deepseek-*` for a DeepSeek slot — so the transcript's model
/// family must agree with the slot's provider family. `slot_family` resolves a
/// candidate slot's provider family (the caller derives it from the slot's
/// [`crate::accounts::AccountSource`] — authoritative for Anthropic, Codex,
/// Gemini, and 3P alike); a candidate whose family is KNOWN and disagrees with
/// the transcript model's KNOWN family is skipped. When either side is unknown
/// (model-less transcript, unclassifiable model, unresolvable slot) the gate
/// does not fire and cwd+time attribution stands — no over-rejection.
///
/// KNOWN LIMITATION (inherent to cwd+time correlation, not the gate): two
/// slots of the SAME provider family run in the same cwd are indistinguishable
/// — the gate is provider-family-granular, so both pass and the closest-prior
/// launch wins. Resolving that needs a per-session→slot signal CC does not
/// emit (e.g. the config dir written into the transcript). The gate closes the
/// CROSS-family bleed (claude-onto-DeepSeek), not same-family ambiguity.
pub fn attribute_session<G>(
    session: &ScannedSession,
    launch_events: &[LaunchEvent],
    mut slot_family: G,
) -> Option<AttributedSession>
where
    G: FnMut(AccountNum) -> Option<&'static str>,
{
    use chrono::DateTime;

    let session_ts = DateTime::parse_from_rfc3339(&session.attribution_time).ok()?;
    let session_family = session.model.as_deref().and_then(model_provider_family);

    let mut best: Option<&LaunchEvent> = None;
    for ev in launch_events {
        if ev.project_path != session.project_path {
            continue;
        }
        let ev_ts = match DateTime::parse_from_rfc3339(&ev.ts) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ev_ts > session_ts {
            continue;
        }
        // Provider-consistency gate: reject a candidate slot whose provider
        // family is known and disagrees with the transcript model's known
        // family (see the doc comment). Only gates when BOTH families are
        // known, so model-less/unclassifiable sessions fall through to
        // cwd+time.
        if let Some(sf) = session_family {
            if let Ok(cand_slot) = AccountNum::try_from(ev.slot) {
                if let Some(cf) = slot_family(cand_slot) {
                    if sf != cf {
                        continue;
                    }
                }
            }
        }
        // Pick the latest launch event ≤ session_ts.
        match best {
            None => best = Some(ev),
            Some(prev) => {
                let prev_ts = DateTime::parse_from_rfc3339(&prev.ts).ok()?;
                if ev_ts > prev_ts {
                    best = Some(ev);
                }
            }
        }
    }

    let matched = best?;
    let slot = AccountNum::try_from(matched.slot).ok()?;
    Some(AttributedSession {
        slot,
        session: session.clone(),
    })
}

/// Converts an attributed session to one [`UsageEvent`] PER NORMALIZED REQUEST
/// using bundled rates. This pure compatibility helper does not read local
/// overrides; runtime aggregation uses its explicitly loaded snapshot instead.
///
/// The model is sourced from the TRANSCRIPT (the real model CC used) when
/// present — an internal ticket's v2 model source, realizing the `UsageEvent::model`
/// doc's "v2: per-turn model from projects/jsonl", which an internal ticket completes by
/// resolving it per request rather than once per session. Only a request whose
/// own records carried no model falls back to `fallback_model` (the slot's
/// configured model, resolved by the caller).
///
/// If a request's resolved model is unknown to the rate table, that request's
/// `cost_usd_estimate` is `None` and the UI shows "n/a" for the cost column —
/// its tokens still count, and its siblings on a known model still price.
///
/// COST NOTE (an internal ticket): the estimate bills cache tokens — cache-write
/// (`cache_creation_tokens`) and cache-read (`cache_read_tokens`) — in addition
/// to `input_tokens` + `output_tokens`, via
/// [`super::cost_rates::CostRate::estimate_usd_with_cache`], at each rate row's
/// OWN stored cache prices. A row with no verified price for a dimension bills
/// that dimension at $0, so csq never applies one vendor's cache economics to
/// another's row.
///
/// Today that means: Anthropic Claude rows bill both cache dimensions;
/// DeepSeek rows bill cache-READ at DeepSeek's published per-tier price and
/// cache-WRITE at $0 (DeepSeek publishes no write price in the bundled
/// evidence); every other bundled provider bills both at $0.
///
/// Sessions with zero cache tokens bill identically on every provider, so no
/// cost regresses. DeepSeek sessions WITH cache reads become more expensive
/// than they previously reported — that is the an internal ticket under-report being
/// corrected, not a rate change.
pub fn attributed_session_to_events(
    attributed: &AttributedSession,
    fallback_model: &str,
) -> Vec<UsageEvent> {
    attributed_session_to_events_with_manifest(
        attributed,
        fallback_model,
        &crate::providers::model_manifest::ModelManifest::bundled(),
    )
}

/// Converts one session's requests with the coherent manifest snapshot selected
/// by its caller. Returns one event per request, in transcript order.
pub fn attributed_session_to_events_with_manifest(
    attributed: &AttributedSession,
    fallback_model: &str,
    manifest: &crate::providers::model_manifest::ModelManifest,
) -> Vec<UsageEvent> {
    let session = &attributed.session;
    session
        .requests
        .iter()
        .map(|request| {
            // Each request is priced at ITS OWN model. Before an internal ticket the whole
            // session was priced at its FIRST model, so a session that started
            // on one model and continued on a more expensive one billed every
            // token at the cheaper rate (or the reverse).
            let model = request
                .model
                .as_deref()
                .or(session.model.as_deref())
                .unwrap_or(fallback_model);
            // Price at the instant the REQUEST ran, not the session start and
            // not wall-clock now (an internal ticket, narrowed by an internal ticket): a DeepSeek
            // request's rate depends on whether it predates the 2026-08-16
            // peak/off-peak cutover and, after it, which UTC window it fell in
            // — and a long session crosses those windows. An unparseable or
            // absent timestamp yields `None`, which the rate table treats as
            // "cannot select a tier": flat rows still resolve, time-varying
            // rows render `n/a` rather than guessing (fail-loud contract).
            let at = request
                .timestamp
                .as_deref()
                .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                .map(|t| t.with_timezone(&chrono::Utc));
            // Unconditional since an internal ticket: each rate row carries its OWN cache
            // prices, and a row with no verified price contributes exactly $0
            // for that dimension, so `estimate_usd_with_cache` reduces to
            // `estimate_usd` on such a row for any token counts. The former
            // `if r.cache_eligible` branch existed only to keep Anthropic's
            // multipliers off non-Anthropic rows; with prices stored per row
            // there is no longer a wrong multiplier to guard against.
            let cost = manifest.rate_for_model_at(model, at).map(|r| {
                r.estimate_usd_with_cache(
                    request.usage.input_tokens,
                    request.usage.output_tokens,
                    request.usage.cache_creation_tokens,
                    request.usage.cache_read_tokens,
                )
            });
            UsageEvent {
                // BUCKETING and PRICING diverge here deliberately, and the two
                // are not interchangeable.
                //
                // `ts` must be PARSEABLE or the event silently leaves every
                // rolling window: `summarize` bucket-skips on a parse failure
                // (`Err(_) => continue`), so an unparseable `ts` lands the
                // request's tokens in `total_*` alone — and the billing card
                // renders only 7d and 30d, which makes them invisible rather
                // than merely mis-bucketed. The fallback therefore fires when
                // the request's own timestamp is ABSENT **or UNPARSEABLE**, not
                // only when absent: `Some("garbage")` is `Some`, so a plain
                // `unwrap_or_else` would pass the garbage straight through.
                //
                // Falling back to `session.start_time` is safe because it is
                // parseable BY CONSTRUCTION: `scan_one_transcript` assigns it
                // only inside a `parse_from_rfc3339` Ok branch or from
                // `earliest_request_timestamp` (which filters to parseable),
                // and `attribute_session` returns `None` when it does not
                // parse — so no `AttributedSession` can carry an unparseable
                // one. It places the request inside its session's window, which
                // is where it happened.
                //
                // `at` (above) deliberately stays `None` in the same case. A
                // window bucket derived from the session is a sound
                // approximation; a RATE derived from it is a guess that a
                // pricing-window boundary can make wrong, so the fail-loud
                // contract holds and a time-varying row renders `n/a`.
                ts: match request.timestamp.as_deref() {
                    Some(raw) if at.is_some() => raw.to_string(),
                    _ => session.start_time.clone(),
                },
                session_id: session.session_id.clone(),
                model: model.to_string(),
                input_tokens: request.usage.input_tokens,
                output_tokens: request.usage.output_tokens,
                cache_creation_tokens: request.usage.cache_creation_tokens,
                cache_read_tokens: request.usage.cache_read_tokens,
                cost_usd_estimate: cost,
                source: UsageSource::ProjectsJsonl,
                project_path: Some(session.project_path.clone()),
                snapshots_collapsed: request.snapshots_collapsed,
                finalization_divergent: request.finalization_divergent,
                from_subagent: request.from_subagent,
                unidentified: request.identity.is_unidentified(),
            }
        })
        .collect()
}

/// Top-level aggregator entry — scans CC's projects transcripts, reads the
/// launch log, attributes each session, returns the (slot, event) pairs ready
/// to be appended to per-account ledgers.
///
/// `now` bounds the transcript scan by mtime (`SCAN_MAX_AGE_DAYS`); pass
/// `chrono::Utc::now()` in production (a parameter so tests are deterministic).
///
/// `model_for_slot` is a FALLBACK callback returning the slot's configured
/// model — used only for sessions whose transcript carried no model line. The
/// real per-turn model from the transcript takes precedence (an internal ticket).
///
/// The attribution provider-consistency gate ([`attribute_session`]) resolves
/// each slot's provider family internally from [`crate::accounts::discovery`]
/// (`AccountSource`), so no extra provider callback is needed.
///
/// Loads one runtime model/rate manifest before scanning. A malformed present
/// manifest returns an error; callers must not interpret failure as zero usage.
pub fn aggregate<F>(
    claude_home: &Path,
    base_dir: &Path,
    now: DateTime<Utc>,
    model_for_slot: F,
) -> anyhow::Result<Vec<(AccountNum, UsageEvent)>>
where
    F: FnMut(AccountNum) -> String,
{
    // Load before any scan or publish: an invalid present file is an error,
    // never an empty successful aggregation that could erase existing ledgers.
    let manifest = crate::providers::model_manifest::ModelManifest::load(base_dir)?;
    Ok(aggregate_with_manifest(
        claude_home,
        base_dir,
        now,
        model_for_slot,
        &manifest,
    ))
}

fn aggregate_with_manifest<F>(
    claude_home: &Path,
    base_dir: &Path,
    now: DateTime<Utc>,
    mut model_for_slot: F,
    manifest: &crate::providers::model_manifest::ModelManifest,
) -> Vec<(AccountNum, UsageEvent)>
where
    F: FnMut(AccountNum) -> String,
{
    let sessions = scan_project_transcripts(&projects_dir(claude_home), now);
    let launch = match super::launch_log::read_all(base_dir) {
        Ok(r) => r.events,
        Err(_) => Vec::new(),
    };
    // Resolve each slot's provider family ONCE from its authoritative
    // `AccountSource` (Anthropic / Codex / Gemini / 3P), for the attribution
    // provider-consistency gate. Built once per aggregation; a slot absent from
    // the map (or `Manual`) resolves to `None`, which disables the gate for
    // that candidate (falls through to cwd+time — no over-rejection).
    let mut source_family_by_slot: std::collections::HashMap<AccountNum, &'static str> =
        crate::accounts::discovery::discover_all(base_dir)
            .into_iter()
            .filter_map(|a| {
                let slot = AccountNum::try_from(a.id).ok()?;
                let family = provider_family_for_source(&a.source)?;
                Some((slot, family))
            })
            .collect();
    // 3P-dominance overlay: a slot actively routing through a 3P endpoint (its
    // `settings.json` `ANTHROPIC_BASE_URL` is what CC uses at runtime) IS that
    // 3P provider for billing — even if a stale Anthropic `by_slot` mapping
    // from a pre-rebind `csq login` still shadows it (discover_all lists
    // Anthropic before per-slot 3P, so the stale map would otherwise win). Left
    // un-overlaid, a rebind-without-`csq logout` slot classifies Anthropic and
    // the gate REJECTS its own `deepseek-*` sessions — a blank card, strictly
    // worse than the bleed this gate fixes. The live base-URL binding is the
    // authoritative runtime signal, so it dominates the OAuth map here.
    for a in crate::accounts::discovery::discover_per_slot_third_party(base_dir) {
        if let (Ok(slot), Some(family)) = (
            AccountNum::try_from(a.id),
            provider_family_for_source(&a.source),
        ) {
            source_family_by_slot.insert(slot, family);
        }
    }
    let mut out = Vec::with_capacity(sessions.len());
    for session in sessions {
        let attributed = attribute_session(&session, &launch, |slot| {
            source_family_by_slot.get(&slot).copied()
        });
        if let Some(attributed) = attributed {
            let fallback = model_for_slot(attributed.slot);
            for event in
                attributed_session_to_events_with_manifest(&attributed, &fallback, manifest)
            {
                out.push((attributed.slot, event));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn launch_ev(ts: &str, slot: u16, project: &str) -> LaunchEvent {
        LaunchEvent {
            ts: ts.into(),
            event: "run".into(),
            slot,
            pid: 1,
            project_path: project.into(),
        }
    }

    /// A single-request session. Aggregates are DERIVED from the request by
    /// [`ScannedSession::from_parts`], so a fixture cannot claim totals its
    /// requests do not add up to.
    fn scanned(ts: &str, project: &str, in_tok: u64, out_tok: u64) -> ScannedSession {
        scanned_with_cache(ts, project, in_tok, out_tok, 0, 0)
    }

    /// A single-request session carrying cache tokens.
    fn scanned_with_cache(
        ts: &str,
        project: &str,
        in_tok: u64,
        out_tok: u64,
        cache_create: u64,
        cache_read: u64,
    ) -> ScannedSession {
        ScannedSession::from_parts(
            format!("sess-{ts}"),
            project.into(),
            ts.into(),
            None,
            vec![request_at(
                ts,
                None,
                in_tok,
                out_tok,
                cache_create,
                cache_read,
            )],
        )
    }

    /// One normalized request, as the collector would emit it.
    fn request_at(
        ts: &str,
        model: Option<&str>,
        in_tok: u64,
        out_tok: u64,
        cache_create: u64,
        cache_read: u64,
    ) -> NormalizedRequest {
        NormalizedRequest {
            timestamp: Some(ts.to_string()),
            model: model.map(str::to_string),
            usage: SnapshotUsage {
                input_tokens: in_tok,
                output_tokens: out_tok,
                cache_creation_tokens: cache_create,
                cache_read_tokens: cache_read,
            },
            snapshots_collapsed: 0,
            finalization_divergent: false,
            identity: crate::usage::request::IdentitySource::RequestId,
            from_subagent: false,
        }
    }

    /// The single event a one-request session produces.
    fn only_event(attr: &AttributedSession, fallback: &str) -> UsageEvent {
        let events = attributed_session_to_events(attr, fallback);
        assert_eq!(events.len(), 1, "fixture is single-request: {events:?}");
        events.into_iter().next().unwrap()
    }

    /// A fixed "now" far enough after the fixture timestamps that a
    /// just-written file's real mtime is always within the scan window.
    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    /// Writes `<projects>/<project_dir>/<filename>` with the given jsonl lines.
    fn write_transcript(
        projects: &Path,
        project_dir: &str,
        filename: &str,
        lines: &[&str],
    ) -> PathBuf {
        let dir = projects.join(project_dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(filename);
        std::fs::write(&path, lines.join("\n")).unwrap();
        path
    }

    /// A "don't know the slot's family" resolver — bypasses the provider gate
    /// (the gate only fires when BOTH families are known). Used by tests whose
    /// session carries no model, where the gate is irrelevant.
    fn no_family(_: AccountNum) -> Option<&'static str> {
        None
    }

    /// D6: the field sets of the three TRANSCRIPT carriers are LOCKED.
    ///
    /// These are the structs that deserialize vendor JSON, so they are the
    /// privacy gate itself — every other carrier downstream is built from what
    /// these drop. A content field declared here is the only way conversational
    /// text can enter the pipeline at all, and it is named below as `added`.
    ///
    /// The scan mechanism, the failure message and the update procedure live in
    /// ONE place — `assert_field_set_locked` in `super::request` — so this guard
    /// and the request-side one cannot drift apart.
    ///
    /// Falsifying result: add a field to `TranscriptLine`, `TranscriptMessage`
    /// or `TranscriptUsage` and it is named here as `added`.
    #[test]
    fn transcript_carrier_field_sets_are_locked() {
        use crate::usage::request::tests::assert_field_set_locked;

        // A REAL transcript line — including a filed `content` key. Tolerating
        // and dropping it is the CORRECT design: the vendor adds fields freely,
        // and a strict struct would start rejecting whole lines. What must never
        // happen is a content field being DECLARED on these structs, which is
        // exactly what the field sets below pin.
        let line: TranscriptLine = serde_json::from_str(
            r#"{"cwd":"/w","timestamp":"2026-09-01T00:00:00Z","sessionId":"s",
                "requestId":"req_a","uuid":"u","content":["NOT READ"],
                "message":{"id":"msg_a","model":"claude-opus-4-8",
                           "usage":{"input_tokens":11,"output_tokens":22,
                                    "cache_creation_input_tokens":33,
                                    "cache_read_input_tokens":44}}}"#,
        )
        .expect("a transcript line deserializes");

        assert_field_set_locked(
            "TranscriptLine",
            &format!("{line:#?}"),
            &[
                "cwd",
                "timestamp",
                "session_id",
                "request_id",
                "uuid",
                "message",
            ],
        );

        let message = line.message.expect("fixture carries a message");
        assert_field_set_locked(
            "TranscriptMessage",
            &format!("{message:#?}"),
            &["id", "model", "usage"],
        );

        let usage = message.usage.expect("fixture carries usage");
        assert_field_set_locked(
            "TranscriptUsage",
            &format!("{usage:#?}"),
            &[
                "input_tokens",
                "output_tokens",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
            ],
        );
    }

    #[test]
    fn attribute_session_picks_closest_prior_launch() {
        let session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        let launches = vec![
            // Earlier same project — wrong (outdated)
            launch_ev("2026-05-06T09:00:00Z", 1, "/repo/a"),
            // Closer prior same project — correct
            launch_ev("2026-05-06T11:00:00Z", 4, "/repo/a"),
            // After session start — must be ignored
            launch_ev("2026-05-06T12:00:00Z", 7, "/repo/a"),
            // Different project — must be ignored
            launch_ev("2026-05-06T11:15:00Z", 2, "/repo/b"),
        ];
        let result = attribute_session(&session, &launches, no_family).unwrap();
        assert_eq!(result.slot, slot(4));
    }

    #[test]
    fn attribute_session_returns_none_when_no_project_match() {
        let session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/different")];
        assert!(attribute_session(&session, &launches, no_family).is_none());
    }

    #[test]
    fn attribute_session_returns_none_for_session_before_any_launch() {
        let session = scanned("2026-05-06T08:00:00Z", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/a")];
        assert!(attribute_session(&session, &launches, no_family).is_none());
    }

    #[test]
    fn attribute_session_skips_malformed_timestamp() {
        let session = scanned("not-a-ts", "/repo/a", 100, 50);
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 1, "/repo/a")];
        assert!(attribute_session(&session, &launches, no_family).is_none());
    }

    /// Bug-2 regression: a `claude-*` (Anthropic) transcript run in a cwd whose
    /// only launch event is a DeepSeek (3P) slot MUST NOT attribute to that
    /// slot — the provider gate rejects the sole candidate, leaving it
    /// unattributed. This is the $246.50-opus-on-the-DeepSeek-card bleed.
    #[test]
    fn attribute_session_rejects_cross_provider_slot() {
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        session.model = Some("claude-opus-4-8".into());
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 11, "/repo/a")];
        // Slot 11 is DeepSeek; the opus transcript is claude-family → rejected.
        let result = attribute_session(&session, &launches, |s| {
            if s == slot(11) {
                Some("deepseek")
            } else {
                Some("claude")
            }
        });
        assert!(result.is_none());
    }

    /// The gate FILTERS candidates rather than only rejecting post-hoc: when a
    /// cwd hosted BOTH an Anthropic-slot launch and a (closer-in-time) DeepSeek
    /// launch, a claude transcript attributes to the Anthropic slot even though
    /// the DeepSeek launch is nearer the session start.
    #[test]
    fn attribute_session_prefers_provider_consistent_launch() {
        let mut session = scanned("2026-05-06T12:00:00Z", "/repo/a", 100, 50);
        session.model = Some("claude-opus-4-8".into());
        let launches = vec![
            // Anthropic slot, earlier.
            launch_ev("2026-05-06T10:00:00Z", 1, "/repo/a"),
            // DeepSeek slot, CLOSER to session start — but provider-inconsistent.
            launch_ev("2026-05-06T11:30:00Z", 11, "/repo/a"),
        ];
        let result = attribute_session(&session, &launches, |s| {
            if s == slot(11) {
                Some("deepseek")
            } else {
                Some("claude")
            }
        })
        .unwrap();
        assert_eq!(result.slot, slot(1));
    }

    /// A DeepSeek transcript still attributes to its DeepSeek slot (the gate
    /// must not reject provider-CONSISTENT matches).
    #[test]
    fn attribute_session_keeps_provider_consistent_3p_slot() {
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        session.model = Some("deepseek-v4-pro".into());
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 11, "/repo/a")];
        let result = attribute_session(&session, &launches, |_| Some("deepseek")).unwrap();
        assert_eq!(result.slot, slot(11));
    }

    /// When the transcript model is unclassifiable (unknown family), the gate
    /// does not fire and cwd+time attribution stands — no over-rejection.
    #[test]
    fn attribute_session_unknown_model_family_falls_through() {
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 100, 50);
        session.model = Some("some-local-ollama-model".into());
        let launches = vec![launch_ev("2026-05-06T11:00:00Z", 11, "/repo/a")];
        // Even though the slot family is "deepseek", the unknown transcript
        // family means the gate cannot fire → attributed by cwd+time.
        let result = attribute_session(&session, &launches, |_| Some("deepseek")).unwrap();
        assert_eq!(result.slot, slot(11));
    }

    #[test]
    fn model_provider_family_classifies_known_families() {
        // Namespace matches the catalog provider ids so it compares against
        // `provider_family_for_source`.
        assert_eq!(model_provider_family("claude-opus-4-8"), Some("claude"));
        assert_eq!(model_provider_family("claude-sonnet-4-6"), Some("claude"));
        assert_eq!(model_provider_family("deepseek-v4-pro"), Some("deepseek"));
        assert_eq!(model_provider_family("deepseek-v4-flash"), Some("deepseek"));
        assert_eq!(model_provider_family("glm-4.6"), Some("zai"));
        assert_eq!(model_provider_family("m2.7-coder"), Some("mm"));
        assert_eq!(model_provider_family("MiniMax-M3"), Some("mm"));
        assert_eq!(model_provider_family("m3.1-coder"), Some("mm"));
        assert_eq!(model_provider_family("M3"), Some("mm")); // bare short form
        assert_eq!(model_provider_family("gemini-2.5-pro"), Some("gemini"));
        assert_eq!(model_provider_family("gpt-5-codex"), Some("codex"));
        assert_eq!(model_provider_family("o3-mini"), Some("codex"));
        // Unclassifiable → None (Ollama-hosted open models; no false OpenAI
        // match on a stray `o3`/`m2.` substring inside another name).
        assert_eq!(model_provider_family("qwen2.5-coder"), None);
        assert_eq!(model_provider_family("llama-3-o3-tune"), None);
        assert_eq!(model_provider_family(""), None);
    }

    #[test]
    fn provider_family_for_source_maps_every_variant() {
        use crate::accounts::AccountSource as S;
        assert_eq!(provider_family_for_source(&S::Anthropic), Some("claude"));
        assert_eq!(provider_family_for_source(&S::Codex), Some("codex"));
        assert_eq!(provider_family_for_source(&S::Gemini), Some("gemini"));
        assert_eq!(
            provider_family_for_source(&S::ThirdParty {
                provider: "DeepSeek".into()
            }),
            Some("deepseek")
        );
        assert_eq!(
            provider_family_for_source(&S::ThirdParty {
                provider: "MiniMax".into()
            }),
            Some("mm")
        );
        assert_eq!(provider_family_for_source(&S::Manual), None);
        // The transcript-side and source-side namespaces MUST agree, else a
        // DeepSeek transcript would never match its DeepSeek-source slot.
        assert_eq!(
            provider_family_for_source(&S::ThirdParty {
                provider: "DeepSeek".into()
            }),
            model_provider_family("deepseek-v4-pro")
        );
    }

    #[test]
    fn attributed_session_to_event_estimates_cost() {
        let attr = AttributedSession {
            slot: slot(4),
            session: scanned("2026-05-06T11:30:00Z", "/repo/a", 1_000_000, 1_000_000),
        };
        // Transcript has no model → falls back to the supplied model.
        let event = only_event(&attr, "deepseek-chat");
        assert_eq!(event.input_tokens, 1_000_000);
        assert_eq!(event.output_tokens, 1_000_000);
        // 1M input + 1M output @ deepseek-chat (V4-flash rate) = $0.14 + $0.28 = $0.42
        let cost = event.cost_usd_estimate.unwrap();
        assert!((cost - 0.42).abs() < 0.001, "expected ~0.42, got {cost}");
        assert_eq!(event.source, UsageSource::ProjectsJsonl);
        assert_eq!(event.project_path, Some("/repo/a".to_string()));
        assert_eq!(event.model, "deepseek-chat");
    }

    #[test]
    fn attributed_session_to_event_prefers_transcript_model_over_fallback() {
        // The transcript's real model must win over the caller's slot-configured
        // fallback — an internal ticket's second bug (caller hardcoded sonnet for all).
        let mut session = scanned("2026-05-06T11:30:00Z", "/repo/a", 1_000_000, 1_000_000);
        session.model = Some("deepseek-chat".into());
        let attr = AttributedSession {
            slot: slot(11),
            session,
        };
        let event = only_event(&attr, "claude-sonnet-4-6");
        assert_eq!(event.model, "deepseek-chat");
        // Cost is deepseek's $0.42, NOT sonnet's ($3 + $15 = $18.00).
        let cost = event.cost_usd_estimate.unwrap();
        assert!(
            (cost - 0.42).abs() < 0.001,
            "expected deepseek 0.42, got {cost}"
        );
    }

    /// an internal ticket end-to-end: the DeepSeek rate is selected by the SESSION's own
    /// timestamp, so three otherwise-identical sessions differing only in when
    /// they ran get three different bills — and a July session keeps pricing at
    /// July's rate no matter when the aggregator runs.
    #[test]
    fn attributed_session_to_event_prices_deepseek_by_session_time() {
        // 1M in + 1M out @ deepseek-v4-pro, at three fixed instants.
        for (ts, expected, label) in [
            (
                "2026-07-04T02:30:00Z",
                1.305,
                "pre-cutover flat (0.435 + 0.87)",
            ),
            (
                "2026-08-20T02:30:00Z",
                5.28,
                "post-cutover PEAK (1.32 + 3.96)",
            ),
            (
                "2026-08-20T12:30:00Z",
                2.64,
                "post-cutover OFF-PEAK (0.66 + 1.98)",
            ),
        ] {
            let mut session = scanned(ts, "/repo/a", 1_000_000, 1_000_000);
            session.model = Some("deepseek-v4-pro".into());
            let attr = AttributedSession {
                slot: slot(7),
                session,
            };
            let event = only_event(&attr, "deepseek-v4-pro");
            let cost = event.cost_usd_estimate.expect("v4-pro is a rated model");
            assert!(
                (cost - expected).abs() < 0.001,
                "{ts} ({label}): expected ~${expected}, got ${cost}"
            );
        }
    }

    /// an internal ticket fail-loud: a session whose timestamp will not parse cannot select
    /// a DeepSeek tier, so the cost renders `n/a` rather than guessing one of
    /// two rates that differ by 2×. A time-invariant model is unaffected.
    #[test]
    fn attributed_session_to_event_unparseable_ts_yields_na_for_deepseek_only() {
        let mut session = scanned("not-a-timestamp", "/repo/a", 1_000_000, 1_000_000);
        session.model = Some("deepseek-v4-pro".into());
        let attr = AttributedSession {
            slot: slot(7),
            session,
        };
        assert!(
            only_event(&attr, "deepseek-v4-pro")
                .cost_usd_estimate
                .is_none(),
            "unparseable timestamp must render n/a, never a guessed tier"
        );

        // Claude's rate does not depend on when → still priced.
        let mut session = scanned("not-a-timestamp", "/repo/a", 100_000, 50_000);
        session.model = Some("claude-sonnet-4-6".into());
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let cost = only_event(&attr, "claude-sonnet-4-6")
            .cost_usd_estimate
            .expect("time-invariant rows must not regress to n/a");
        assert!((cost - 1.05).abs() < 0.001, "expected ~$1.05, got ${cost}");
    }

    #[test]
    fn attributed_session_to_event_unknown_model_returns_none_cost() {
        let attr = AttributedSession {
            slot: slot(4),
            session: scanned("2026-05-06T11:30:00Z", "/repo/a", 1000, 500),
        };
        let event = only_event(&attr, "future-model-not-in-table");
        assert!(event.cost_usd_estimate.is_none());
        // Tokens still record correctly.
        assert_eq!(event.input_tokens, 1000);
    }

    #[test]
    fn attributed_session_to_event_captures_cache_tokens() {
        let session = scanned_with_cache(
            "2026-05-06T11:30:00Z",
            "/repo/a",
            100,
            50,
            930_906,
            8_839_479,
        );
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let event = only_event(&attr, "claude-opus-4-8");
        // Cache tokens are captured on the event.
        assert_eq!(event.cache_creation_tokens, 930_906);
        assert_eq!(event.cache_read_tokens, 8_839_479);
        // an internal ticket: cost now bills input + output + cache-write(1.25×) + cache-read(0.10×)
        // at claude-opus-4-8 input rate ($5/1M).
        let cost = event.cost_usd_estimate.unwrap();
        let expected = 100.0 * 5.0 / 1e6             // input
            + 50.0 * 25.0 / 1e6                       // output
            + 930_906.0 * 5.0 * 1.25 / 1e6            // cache write
            + 8_839_479.0 * 5.0 * 0.10 / 1e6; // cache read
        assert!(
            (cost - expected).abs() < 1e-9,
            "expected cache-inclusive ${expected}, got ${cost}"
        );
    }

    #[test]
    fn attributed_session_to_event_bills_deepseek_cache_read_but_not_write() {
        // an internal ticket: DeepSeek publishes a cache-HIT price, so cache reads now bill
        // at that row's own per-tier price — this is the under-report being
        // corrected. Cache WRITES stay at $0 because DeepSeek publishes no
        // write price and csq does not guess one (guessing would OVER-bill).
        //
        // This assertion previously read "non-Anthropic cache must be $0" and
        // was correct only while csq had no DeepSeek cache price at all.
        let mut session = scanned_with_cache(
            "2026-05-06T11:30:00Z",
            "/repo/a",
            1_000,
            500,
            5_000_000,
            20_000_000,
        );
        session.model = Some("deepseek-v4-pro".into());
        let attr = AttributedSession {
            slot: slot(7),
            session,
        };
        let event = only_event(&attr, "claude-sonnet-4-6");
        assert_eq!(event.cache_creation_tokens, 5_000_000);
        assert_eq!(event.cache_read_tokens, 20_000_000);
        // Pre-cutover v4-pro: $0.435/1M in, $0.87/1M out, $0.003625/1M cache-hit.
        // Cache WRITE contributes exactly nothing despite 5M write tokens.
        let cost = event.cost_usd_estimate.unwrap();
        let expected = 1_000.0 * 0.435 / 1e6          // input
            + 500.0 * 0.87 / 1e6                       // output
            + 20_000_000.0 * 0.003625 / 1e6; // cache read (write = $0)
        assert!(
            (cost - expected).abs() < 1e-12,
            "deepseek cache-read must bill, cache-write must not: expected ${expected}, got ${cost}"
        );
    }

    #[test]
    fn scan_one_transcript_sums_usage_and_extracts_metadata() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        // Real CC shape: a non-usage first line (no cwd), then assistant lines
        // each carrying message.usage; cwd/timestamp appear on later lines.
        let path = write_transcript(
            &projects,
            "-Users-me-repos-foo",
            "00d5e35f-affc-42cf-8c22-87e0ff54c260.jsonl",
            &[
                r#"{"type":"mode","sessionId":"00d5e35f-affc-42cf-8c22-87e0ff54c260","mode":"default"}"#,
                r#"{"type":"assistant","cwd":"/Users/me/repos/foo","timestamp":"2026-05-06T09:38:21.837Z","sessionId":"00d5e35f-affc-42cf-8c22-87e0ff54c260","message":{"model":"claude-opus-4-8","content":"SECRET CONTENT MUST NOT BE READ","usage":{"input_tokens":10000,"output_tokens":174,"cache_creation_input_tokens":36777,"cache_read_input_tokens":18562}}}"#,
                r#"{"type":"user","cwd":"/Users/me/repos/foo","timestamp":"2026-05-06T09:40:00.000Z","sessionId":"00d5e35f-affc-42cf-8c22-87e0ff54c260","message":{"content":"more secret"}}"#,
                r#"{"type":"assistant","cwd":"/Users/me/repos/foo","timestamp":"2026-05-06T09:41:00.000Z","sessionId":"00d5e35f-affc-42cf-8c22-87e0ff54c260","message":{"model":"claude-opus-4-8","usage":{"input_tokens":6673,"output_tokens":13782,"cache_creation_input_tokens":100,"cache_read_input_tokens":200}}}"#,
            ],
        );

        let s = scan_one_transcript(&path, false, None, &mut ScanSkips::default()).unwrap();
        assert_eq!(s.session_id, "00d5e35f-affc-42cf-8c22-87e0ff54c260");
        assert_eq!(s.project_path, "/Users/me/repos/foo");
        // Earliest timestamp wins.
        assert_eq!(s.start_time, "2026-05-06T09:38:21.837Z");
        assert_eq!(s.model.as_deref(), Some("claude-opus-4-8"));
        // Summed across BOTH usage lines.
        assert_eq!(s.input_tokens, 16673);
        assert_eq!(s.output_tokens, 13956);
        assert_eq!(s.cache_creation_tokens, 36877);
        assert_eq!(s.cache_read_tokens, 18762);
        // Privacy (D6): ScannedSession has no content field — message.content
        // above is never captured (compile-time guarantee).
    }

    #[test]
    fn scan_one_transcript_none_without_usage() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "no-usage.jsonl",
            &[
                r#"{"type":"user","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","sessionId":"no-usage","message":{"content":"hi"}}"#,
            ],
        );
        assert!(scan_one_transcript(&path, false, None, &mut ScanSkips::default()).is_none());
    }

    #[test]
    fn scan_one_transcript_none_without_cwd() {
        // Usage present but NO cwd on any line → unattributable → dropped
        // (the largest silent-drop path; lock it with a test).
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "no-cwd.jsonl",
            &[
                r#"{"type":"assistant","timestamp":"2026-05-06T09:00:00Z","sessionId":"no-cwd","message":{"model":"gpt-5","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        assert!(scan_one_transcript(&path, false, None, &mut ScanSkips::default()).is_none());
    }

    #[test]
    fn scan_one_transcript_empty_file_is_none() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(&projects, "-p", "empty.jsonl", &[""]);
        assert!(scan_one_transcript(&path, false, None, &mut ScanSkips::default()).is_none());
    }

    #[test]
    fn scan_one_transcript_tolerates_malformed_lines_midfile() {
        // A broken line between two good usage lines must not abort the scan;
        // both good lines still sum.
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "mixed.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","sessionId":"mixed","message":{"model":"gpt-5","usage":{"input_tokens":10,"output_tokens":1}}}"#,
                r#"{ this is not valid json"#,
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:01:00Z","message":{"model":"gpt-5","usage":{"input_tokens":20,"output_tokens":2}}}"#,
            ],
        );
        let s = scan_one_transcript(&path, false, None, &mut ScanSkips::default()).unwrap();
        assert_eq!(s.input_tokens, 30);
        assert_eq!(s.output_tokens, 3);
    }

    #[test]
    fn scan_one_transcript_empty_model_falls_through_to_none() {
        // `"model":""` must be treated as absent so the slot fallback applies.
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "empty-model.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","sessionId":"em","message":{"model":"","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        let s = scan_one_transcript(&path, false, None, &mut ScanSkips::default()).unwrap();
        assert_eq!(s.model, None);
    }

    #[test]
    fn scan_one_transcript_falls_back_to_filename_for_session_id() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        // No sessionId field anywhere → derive from the file stem.
        let path = write_transcript(
            &projects,
            "-p",
            "abc-123.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","message":{"model":"gpt-5","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        let s = scan_one_transcript(&path, false, None, &mut ScanSkips::default()).unwrap();
        assert_eq!(s.session_id, "abc-123");
    }

    /// Writes a `<projects>/<project_dir>/<session>/subagents/<filename>`
    /// nested transcript.
    fn write_subagent_transcript(
        projects: &Path,
        project_dir: &str,
        session: &str,
        filename: &str,
        lines: &[&str],
    ) -> PathBuf {
        let dir = projects.join(project_dir).join(session).join(SUBAGENTS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(filename);
        std::fs::write(&path, lines.join("\n")).unwrap();
        path
    }

    /// Builds one usage-bearing transcript record with an explicit `requestId`.
    fn usage_line(
        cwd: &str,
        session: &str,
        request_id: &str,
        ts: &str,
        model: &str,
        input: u64,
        output: u64,
    ) -> String {
        serde_json::json!({
            "type": "assistant",
            "cwd": cwd,
            "sessionId": session,
            "requestId": request_id,
            "timestamp": ts,
            "message": {
                "id": format!("msg_{request_id}"),
                "model": model,
                "content": "FIXTURE CONTENT MUST NOT BE CAPTURED",
                "usage": { "input_tokens": input, "output_tokens": output }
            }
        })
        .to_string()
    }

    /// THE an internal ticket double-count defect, end to end at the file level. Three
    /// streaming snapshots of ONE request must bill that request's input once.
    /// Falsifying result: `input_tokens == 30_000`, which is exactly what the
    /// pre-an internal ticket blind sum produced.
    #[test]
    fn scan_one_transcript_collapses_streaming_snapshots_to_one_request() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let path = write_transcript(
            &projects,
            "-p",
            "stream.jsonl",
            &[
                &usage_line(
                    "/p",
                    "s1",
                    "req_1",
                    "2026-05-06T09:00:00Z",
                    "claude-opus-4-8",
                    10_000,
                    5,
                ),
                &usage_line(
                    "/p",
                    "s1",
                    "req_1",
                    "2026-05-06T09:00:01Z",
                    "claude-opus-4-8",
                    10_000,
                    250,
                ),
                &usage_line(
                    "/p",
                    "s1",
                    "req_1",
                    "2026-05-06T09:00:02Z",
                    "claude-opus-4-8",
                    10_000,
                    900,
                ),
            ],
        );
        let s = scan_one_transcript(&path, false, None, &mut ScanSkips::default()).unwrap();
        assert_eq!(s.requests.len(), 1, "three snapshots are ONE request");
        assert_eq!(s.input_tokens, 10_000, "input billed once, not 30_000");
        assert_eq!(s.output_tokens, 900, "the final output snapshot");
        assert_eq!(s.requests[0].snapshots_collapsed, 2);
    }

    /// Nested subagent transcripts are found and their usage is included, with
    /// each file's requests billed exactly once. Falsifying result: one scanned
    /// session (the parent only) — the pre-an internal ticket behaviour, which lost the
    /// subagent's tokens entirely.
    #[test]
    fn scan_project_transcripts_includes_subagents_without_double_counting() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        write_transcript(
            &projects,
            "-p",
            "sess-a.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_parent",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                100,
                10,
            )],
        );
        write_subagent_transcript(
            &projects,
            "-p",
            "sess-a",
            "child-1.jsonl",
            &[
                &usage_line(
                    "/p",
                    "sess-a",
                    "req_child",
                    "2026-05-06T09:05:00Z",
                    "claude-opus-4-8",
                    700,
                    70,
                ),
                // A second snapshot of the SAME child request.
                &usage_line(
                    "/p",
                    "sess-a",
                    "req_child",
                    "2026-05-06T09:05:02Z",
                    "claude-opus-4-8",
                    700,
                    90,
                ),
            ],
        );

        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert_eq!(sessions.len(), 2, "parent + subagent: {sessions:?}");

        // THE REQUEST AXIS, asserted independently of any token sum. This is
        // the assertion the shipped code's own blind spot would have passed:
        // measured against the provider export, the pre-an internal ticket pipeline landed
        // at 0.895x on TOKENS — plausible — while sitting at 0.429x on
        // REQUESTS, because missing ~87% of requests and multiplying the rest
        // by ~2.87 are two large errors of opposite sign that nearly cancel on
        // the token axis alone. A fixture carrying BOTH defects (a duplicated
        // snapshot and a nested child) and asserting only tokens can therefore
        // pass with both still present. Falsifying results: 1 request (the
        // traversal regressed and the subagent was not read) or 3 (the dedup
        // regressed and the child's two snapshots both billed).
        let requests: Vec<_> = sessions.iter().flat_map(|s| &s.requests).collect();
        assert_eq!(
            requests.len(),
            2,
            "one parent request + one child request, each counted once: {requests:?}"
        );
        assert_eq!(
            requests.iter().filter(|r| r.from_subagent).count(),
            1,
            "exactly one request came from the nested transcript"
        );
        assert_eq!(
            requests.iter().map(|r| r.snapshots_collapsed).sum::<u64>(),
            1,
            "the child's duplicate snapshot was collapsed, not billed"
        );

        // The token axis, which alone would not have caught either defect.
        let total: u64 = sessions.iter().map(|s| s.input_tokens).sum();
        assert_eq!(total, 800, "each request billed once (100 + 700)");
    }

    /// The literal directory name `subagents` is PINNED, not merely shared.
    ///
    /// Every other subagent fixture builds its path with [`SUBAGENTS_DIR`], so
    /// the fixture's producer and the scanner's consumer move together. That
    /// makes them jointly insensitive to what the constant CONTAINS: mutating
    /// `SUBAGENTS_DIR` to `"subagents-DISABLED"` leaves the whole `usage::`
    /// suite green (measured 2026-09-19 — 128 passed, 0 failed), because the
    /// fixture then writes into the same wrong directory the scanner reads.
    /// The traversal's agreement with CC's real on-disk layout therefore rested
    /// on no Rust test at all.
    ///
    /// This fixture hardcodes the literal path CC writes. Falsifying result:
    /// one scanned session (the parent only) and 100 input tokens — what the
    /// scanner produces once the constant stops naming that directory.
    #[test]
    fn subagents_literal_directory_name_is_pinned() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        write_transcript(
            &projects,
            "-p",
            "sess-lit.jsonl",
            &[&usage_line(
                "/p",
                "sess-lit",
                "req_parent",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                100,
                10,
            )],
        );
        // Deliberately NOT `SUBAGENTS_DIR` — this is the literal CC writes.
        let nested = projects.join("-p").join("sess-lit").join("subagents");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            nested.join("child.jsonl"),
            usage_line(
                "/p",
                "sess-lit",
                "req_child",
                "2026-05-06T09:05:00Z",
                "claude-opus-4-8",
                700,
                70,
            ),
        )
        .unwrap();

        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert_eq!(
            sessions.len(),
            2,
            "the literal `subagents` directory must be traversed: {sessions:?}"
        );
        let total: u64 = sessions.iter().map(|s| s.input_tokens).sum();
        assert_eq!(total, 800, "parent 100 + nested child 700");
    }

    /// The token axis and the request axis fail INDEPENDENTLY, so a suite that
    /// watches only one of them is blind to half the class. This pins the pair
    /// explicitly: a fixture built to carry both defects must report exactly
    /// two requests AND exactly 800 input tokens, and the ratio between them is
    /// not a substitute for either.
    ///
    /// Grounded in the four-variant measurement recorded at `d6eb9321` (lane
    /// ledger): parents-only-deduped lands at 0.303x the provider export and
    /// subagents-without-dedup at 3.333x, while the corrected pipeline lands at
    /// 1.174x tokens / 1.071x requests. Each half alone is further from the
    /// truth than the bug — which is why both halves shipped in one commit.
    #[test]
    fn request_axis_and_token_axis_are_asserted_separately() {
        let session = ScannedSession::from_parts(
            "axes".into(),
            "/p".into(),
            "2026-05-06T09:00:00Z".into(),
            None,
            vec![
                request_at(
                    "2026-05-06T09:00:00Z",
                    Some("claude-opus-4-8"),
                    400,
                    0,
                    0,
                    0,
                ),
                request_at(
                    "2026-05-06T09:01:00Z",
                    Some("claude-opus-4-8"),
                    400,
                    0,
                    0,
                    0,
                ),
            ],
        );
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let events = attributed_session_to_events(&attr, "claude-opus-4-8");
        let now = DateTime::parse_from_rfc3339("2026-05-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let s = crate::usage::ledger::summarize(&events, now);
        assert_eq!(s.request_count, 2, "request axis");
        assert_eq!(s.total_input_tokens, 800, "token axis");
        // Two requests of 400 and one request of 800 are the SAME token total
        // and a different request count — the discrimination this pair exists
        // for. Falsifying result: equality here, meaning the request axis is
        // derived from tokens rather than counted.
        let merged = ScannedSession::from_parts(
            "merged".into(),
            "/p".into(),
            "2026-05-06T09:00:00Z".into(),
            None,
            vec![request_at(
                "2026-05-06T09:00:00Z",
                Some("claude-opus-4-8"),
                800,
                0,
                0,
                0,
            )],
        );
        let merged_events = attributed_session_to_events(
            &AttributedSession {
                slot: slot(1),
                session: merged,
            },
            "claude-opus-4-8",
        );
        let m = crate::usage::ledger::summarize(&merged_events, now);
        assert_eq!(m.total_input_tokens, s.total_input_tokens, "same tokens");
        assert_ne!(m.request_count, s.request_count, "different request count");
    }

    /// The traversal admits ONLY `subagents/`. Falsifying result: the
    /// `memory/` or `tool-results/` transcript appearing as a scanned session,
    /// which would bill vendor bookkeeping as user usage.
    #[test]
    fn scan_project_transcripts_excludes_memory_and_tool_results_dirs() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        for excluded in ["memory", "tool-results"] {
            let d = projects.join("-p").join("sess-a").join(excluded);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("x.jsonl"),
                usage_line(
                    "/p",
                    "sess-a",
                    "req_x",
                    "2026-05-06T09:00:00Z",
                    "claude-opus-4-8",
                    5_000,
                    1,
                ),
            )
            .unwrap();
        }
        write_subagent_transcript(
            &projects,
            "-p",
            "sess-a",
            "child.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_c",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                7,
                1,
            )],
        );

        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert_eq!(
            sessions.len(),
            1,
            "only subagents/ is admitted: {sessions:?}"
        );
        assert_eq!(sessions[0].input_tokens, 7);
    }

    /// A subagent with no `cwd` of its own borrows its PARENT's — and only its
    /// parent's. A subagent that names a DIFFERENT session is dropped rather
    /// than billed to the parent's slot: nesting alone never authorizes
    /// attribution. Falsifying result: the stranger appearing in the output
    /// with the parent's `project_path`.
    #[test]
    fn subagent_without_cwd_borrows_parent_but_never_across_sessions() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        write_transcript(
            &projects,
            "-p",
            "sess-a.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_parent",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                1,
                1,
            )],
        );
        let cwdless = |session: &str, req: &str| {
            serde_json::json!({
                "type": "assistant",
                "sessionId": session,
                "requestId": req,
                "timestamp": "2026-05-06T09:10:00Z",
                "message": {"model": "claude-opus-4-8", "usage": {"input_tokens": 42, "output_tokens": 4}}
            })
            .to_string()
        };
        write_subagent_transcript(
            &projects,
            "-p",
            "sess-a",
            "own.jsonl",
            &[&cwdless("sess-a", "req_ok")],
        );
        write_subagent_transcript(
            &projects,
            "-p",
            "sess-a",
            "stranger.jsonl",
            &[&cwdless("sess-OTHER", "req_bad")],
        );

        let sessions = scan_project_transcripts(&projects, fixed_now());
        let borrowed: Vec<_> = sessions.iter().filter(|s| s.input_tokens == 42).collect();
        assert_eq!(
            borrowed.len(),
            1,
            "only the same-session child borrows the parent cwd: {sessions:?}"
        );
        assert_eq!(borrowed[0].project_path, "/p");
        assert!(
            !sessions.iter().any(|s| s.session_id == "sess-OTHER"),
            "a child naming another session must NOT inherit the parent's cwd"
        );
    }

    /// A malformed/truncated tail must not discard the requests already read.
    #[test]
    fn scan_one_transcript_tolerates_a_truncated_tail() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let good = usage_line(
            "/p",
            "s",
            "req_1",
            "2026-05-06T09:00:00Z",
            "claude-opus-4-8",
            500,
            20,
        );
        let truncated = &good[..good.len() / 2];
        let path = write_transcript(&projects, "-p", "trunc.jsonl", &[&good, truncated]);
        let s = scan_one_transcript(&path, false, None, &mut ScanSkips::default()).unwrap();
        assert_eq!(s.requests.len(), 1);
        assert_eq!(s.input_tokens, 500);
    }

    /// A symlinked transcript is refused rather than followed, so an entry
    /// planted in the vendor-written tree cannot redirect the scan. Falsifying
    /// result: two sessions, i.e. the link was read as a transcript.
    #[cfg(unix)]
    #[test]
    fn scan_project_transcripts_refuses_symlinked_transcripts() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let real = write_transcript(
            &projects,
            "-p",
            "real.jsonl",
            &[&usage_line(
                "/p",
                "s",
                "req_1",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                11,
                1,
            )],
        );
        std::os::unix::fs::symlink(&real, projects.join("-p").join("link.jsonl")).unwrap();
        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert_eq!(
            sessions.len(),
            1,
            "the symlink must not be scanned: {sessions:?}"
        );
    }

    /// A subagent's usage belongs to whichever slot its PARENT session ran
    /// under. A `csq run` into the same cwd between the parent's start and the
    /// child's must NOT reroute the child: one `sessionId` billed across two
    /// accounts is the defect, and the provider-consistency gate cannot catch it
    /// because both slots are the same family.
    ///
    /// The scenario is the reviewer's, and it is reachable on this host rather
    /// than theoretical — the launch log carries 899 events across 20 slots in
    /// 31 days, with slots rotating through overlapping directories.
    ///
    /// Falsifying result: the child attributed to slot 2, which is what its OWN
    /// 09:40 start time selects. Both events must be slot 1.
    #[test]
    fn subagent_attributes_to_its_parents_slot_not_a_later_launch() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();

        write_transcript(
            &claude_home.join("projects"),
            "-p",
            "sess-a.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_parent",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                100,
                10,
            )],
        );
        write_subagent_transcript(
            &claude_home.join("projects"),
            "-p",
            "sess-a",
            "child.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_child",
                // AFTER slot 2's launch — this is the whole scenario.
                "2026-05-06T09:40:00Z",
                "claude-opus-4-8",
                700,
                70,
            )],
        );

        // Slot 1 launched at 09:00; slot 2 launched into the SAME cwd at 09:30.
        super::super::launch_log::append(base, &launch_ev("2026-05-06T09:00:00Z", 1, "/p"))
            .unwrap();
        super::super::launch_log::append(base, &launch_ev("2026-05-06T09:30:00Z", 2, "/p"))
            .unwrap();

        let result = aggregate(claude_home, base, fixed_now(), |_| {
            "claude-opus-4-8".to_string()
        })
        .unwrap();
        assert_eq!(result.len(), 2, "parent + child: {result:?}");
        let slots: Vec<u16> = result.iter().map(|(s, _)| s.get()).collect();
        assert_eq!(
            slots,
            vec![1, 1],
            "the child must follow its parent's slot, not the 09:30 launch"
        );
        // And the child's own timestamp still drives its BUCKET — attribution
        // and bucketing are separate axes, so inheriting one must not move the
        // other.
        let child = result
            .iter()
            .find(|(_, e)| e.input_tokens == 700)
            .expect("child event present");
        assert_eq!(child.1.ts, "2026-05-06T09:40:00Z");
    }

    /// A symlinked DIRECTORY must not be descended into. `Path::is_dir` follows
    /// symlinks, so the obvious spelling of this check admits a link pointing
    /// anywhere on the filesystem and lets it redirect the scan outside
    /// `projects/`. The transcript here sits OUTSIDE the projects tree and is
    /// reachable only through the planted link, so it can be attributed to the
    /// scan only if containment failed.
    ///
    /// Falsifying result: one scanned session — the outside transcript was read
    /// through the link. `scan_project_transcripts_refuses_symlinked_transcripts`
    /// covers the FILE half; this is the directory half, which that test cannot
    /// reach because it never plants a directory link.
    #[cfg(unix)]
    #[test]
    fn scan_project_transcripts_refuses_symlinked_session_directories() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        std::fs::create_dir_all(projects.join("-p")).unwrap();

        // A real session tree OUTSIDE `projects/`, holding a usage-bearing
        // subagent transcript.
        let outside = dir.path().join("outside-the-projects-tree");
        let outside_subagents = outside.join(SUBAGENTS_DIR);
        std::fs::create_dir_all(&outside_subagents).unwrap();
        std::fs::write(
            outside_subagents.join("leaked.jsonl"),
            usage_line(
                "/p",
                "sess-a",
                "req_leak",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                123_456,
                1,
            ),
        )
        .unwrap();

        // Plant a directory symlink inside the project dir pointing at it.
        std::os::unix::fs::symlink(&outside, projects.join("-p").join("sess-a")).unwrap();

        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert!(
            sessions.is_empty(),
            "a symlinked session directory must not be descended into; \
             scan escaped `projects/` and returned {sessions:?}"
        );
    }

    /// The scan ACCOUNTS for what it passed over, and its vocabulary keeps a
    /// REFUSAL apart from an ABSENCE.
    ///
    /// Both are silent drops, and they are different findings: a refusal means
    /// containment declined an entry that is there (a legitimately symlinked
    /// project directory — a user's own volume, a dotfile manager — was read
    /// before containment landed and is not read now), while an absence means
    /// there was nothing to read. Naming them with one word is the failure this
    /// pins against: the counters are read by someone deciding whether their
    /// transcripts are missing or merely gone.
    ///
    /// Falsifying result: either counter reading zero, or both reading non-zero
    /// — i.e. the two reasons collapsed onto one counter. This test REDS under
    /// exactly that collapse.
    #[cfg(unix)]
    #[test]
    fn scan_skips_distinguish_a_refused_symlink_from_an_absent_path() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        std::fs::create_dir_all(&projects).unwrap();

        // (a) A REFUSAL: a link planted at containment tier 1.
        let outside = dir.path().join("outside-the-projects-tree");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, projects.join("-linked-project")).unwrap();

        // (b) An ABSENCE: a real session holding a subagent transcript, whose
        // parent transcript `<session-id>.jsonl` does not exist. Nothing is
        // refused here — the attribution read simply has nothing to open.
        write_subagent_transcript(
            &projects,
            "-p",
            "sess-a",
            "child.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_child",
                "2026-05-06T09:40:00Z",
                "claude-opus-4-8",
                700,
                70,
            )],
        );

        let (sessions, skips) = scan_project_transcripts_counting(&projects, fixed_now());

        assert_eq!(sessions.len(), 1, "the real subagent transcript is scanned");
        assert_eq!(
            skips.project_dir.symlink, 1,
            "the planted project-directory link must be counted as a REFUSAL: {skips:?}"
        );
        assert_eq!(
            skips.project_dir.absent, 0,
            "a symlink is not an absence; collapsing the two is the defect: {skips:?}"
        );
        assert_eq!(
            skips.transcript_file.absent, 1,
            "the missing parent transcript must be counted as ABSENT: {skips:?}"
        );
        assert_eq!(
            skips.transcript_file.symlink, 0,
            "an absent path is not a symlink refusal: {skips:?}"
        );
    }

    /// Containment tier 1. A link planted at `projects/<encoded-cwd>` is
    /// invisible to every check BELOW it — `lstat` examines only the final
    /// component, so the transcripts reachable through the link are ordinary
    /// regular files that `admits_transcript` admits without complaint. This
    /// tier is the only thing between the link and the scan.
    ///
    /// Falsifying result: one scanned session — the outside transcript was read
    /// through the link.
    #[cfg(unix)]
    #[test]
    fn scan_project_transcripts_refuses_symlinked_project_directories() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        std::fs::create_dir_all(&projects).unwrap();

        // A real project tree OUTSIDE `projects/`.
        let outside = dir.path().join("outside-the-projects-tree");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join("leaked.jsonl"),
            usage_line(
                "/p",
                "sess-a",
                "req_leak",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                123_456,
                1,
            ),
        )
        .unwrap();

        std::os::unix::fs::symlink(&outside, projects.join("-linked-project")).unwrap();

        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert!(
            sessions.is_empty(),
            "a symlinked project directory must not be descended into; \
             scan escaped `projects/` and returned {sessions:?}"
        );
    }

    /// Containment tier 3. The session directory here is REAL, so the tiers above
    /// admit it and the tier below (`admits_transcript`) sees ordinary regular
    /// files — the link has to be refused at its OWN tier or not at all.
    ///
    /// Falsifying result: one scanned session — the outside subagent transcript
    /// was read through the link.
    #[cfg(unix)]
    #[test]
    fn scan_project_transcripts_refuses_symlinked_subagent_directories() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        std::fs::create_dir_all(projects.join("-p").join("sess-a")).unwrap();

        let outside = dir.path().join("outside-the-projects-tree");
        let outside_subagents = outside.join(SUBAGENTS_DIR);
        std::fs::create_dir_all(&outside_subagents).unwrap();
        std::fs::write(
            outside_subagents.join("leaked.jsonl"),
            usage_line(
                "/p",
                "sess-a",
                "req_leak",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                123_456,
                1,
            ),
        )
        .unwrap();

        std::os::unix::fs::symlink(
            &outside_subagents,
            projects.join("-p").join("sess-a").join(SUBAGENTS_DIR),
        )
        .unwrap();

        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert!(
            sessions.is_empty(),
            "a symlinked subagents directory must not be descended into; \
             scan escaped `projects/` and returned {sessions:?}"
        );
    }

    /// Containment tier 4, attribution half. The parent transcript is the ONE
    /// file this scanner opens that `admits_transcript` does not gate — it is
    /// read for attribution only. A symlinked parent must still be refused.
    ///
    /// The child carries its own `cwd`, so it is scanned either way; that is what
    /// makes the ATTRIBUTION instant the observable here rather than the session
    /// count. This test pins the REFUSAL; that the refusal is mtime-FREE is
    /// pinned separately by
    /// [`subagent_reads_a_parent_transcript_older_than_the_scan_window`], since
    /// both `admit_file` and `admits_transcript` refuse a symlink and only an
    /// out-of-window parent tells them apart.
    ///
    /// Falsifying result: a `09:00:00Z` instant — the outside parent was read
    /// and decided the child's slot.
    #[cfg(unix)]
    #[test]
    fn scan_project_transcripts_refuses_symlinked_parent_transcript() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");

        write_subagent_transcript(
            &projects,
            "-p",
            "sess-a",
            "child.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_child",
                "2026-05-06T09:40:00Z",
                "claude-opus-4-8",
                700,
                70,
            )],
        );

        // The parent transcript, `<session-id>.jsonl` beside the session dir, is
        // a symlink to a REAL transcript outside `projects/`.
        let outside = dir.path().join("outside-the-projects-tree");
        std::fs::create_dir_all(&outside).unwrap();
        let outside_parent = outside.join("parent.jsonl");
        std::fs::write(
            &outside_parent,
            usage_line(
                "/p",
                "sess-a",
                "req_parent",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                100,
                10,
            ),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside_parent, projects.join("-p").join("sess-a.jsonl"))
            .unwrap();

        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert_eq!(sessions.len(), 1, "exactly the child: {sessions:?}");
        assert_eq!(
            sessions[0].attribution_time, "2026-05-06T09:40:00Z",
            "a symlinked parent must not be read: a child attributes as its \
             parent did, so following the link moves the instant to the outside \
             parent's 09:00:00Z"
        );
    }

    /// The attribution read is mtime-FREE, and that is load-bearing: a parent may
    /// sit outside `SCAN_MAX_AGE_DAYS` while its children are inside it, so
    /// gating the parent read on the mtime bound would silently drop the
    /// attribution of every subagent beneath a long-running session — the exact
    /// failure [`read_attribution_header`] exists to avoid.
    ///
    /// This is the test that pins [`admit_file`] against
    /// [`admits_transcript`]; only an out-of-window parent can tell them apart.
    ///
    /// Falsifying result: the child carrying its OWN `09:40:00Z` instant instead
    /// of the 90-day-old parent's `09:00:00Z` — i.e. the bound was re-imposed and
    /// the parent went unread.
    #[cfg(unix)]
    #[test]
    fn subagent_reads_a_parent_transcript_older_than_the_scan_window() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");

        let parent = write_transcript(
            &projects,
            "-p",
            "sess-a.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_parent",
                "2026-05-06T09:00:00Z",
                "claude-opus-4-8",
                100,
                10,
            )],
        );
        // Push the parent 90 days back — far outside the 31-day window — while
        // the child below is written NOW and is therefore inside it.
        std::fs::File::options()
            .write(true)
            .open(&parent)
            .unwrap()
            .set_modified(std::time::SystemTime::from(
                fixed_now() - Duration::days(90),
            ))
            .unwrap();

        write_subagent_transcript(
            &projects,
            "-p",
            "sess-a",
            "child.jsonl",
            &[&usage_line(
                "/p",
                "sess-a",
                "req_child",
                "2026-05-06T09:40:00Z",
                "claude-opus-4-8",
                700,
                70,
            )],
        );

        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert_eq!(sessions.len(), 1, "exactly the child: {sessions:?}");
        assert_eq!(
            sessions[0].attribution_time, "2026-05-06T09:00:00Z",
            "the out-of-window parent must still be read for attribution"
        );
    }

    /// Per-request pricing: one session, two models. Each request must bill at
    /// ITS OWN model. Falsifying result: both events carrying the FIRST model —
    /// the pre-an internal ticket session-first-model attribution.
    #[test]
    fn events_price_each_request_at_its_own_model() {
        let session = ScannedSession::from_parts(
            "multi".into(),
            "/repo/a".into(),
            "2026-05-06T11:00:00Z".into(),
            Some("claude-sonnet-4-6".into()),
            vec![
                request_at(
                    "2026-05-06T11:00:00Z",
                    Some("claude-sonnet-4-6"),
                    1_000_000,
                    0,
                    0,
                    0,
                ),
                request_at(
                    "2026-05-06T11:30:00Z",
                    Some("claude-opus-4-8"),
                    1_000_000,
                    0,
                    0,
                    0,
                ),
            ],
        );
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let events = attributed_session_to_events(&attr, "claude-sonnet-4-6");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].model, "claude-sonnet-4-6");
        assert_eq!(events[1].model, "claude-opus-4-8");
        // 1M input at sonnet ($3/1M) and at opus ($5/1M) — the whole point is
        // that these differ; pre-an internal ticket both billed $3.
        let sonnet = events[0].cost_usd_estimate.unwrap();
        let opus = events[1].cost_usd_estimate.unwrap();
        assert!((sonnet - 3.0).abs() < 1e-9, "sonnet: {sonnet}");
        assert!((opus - 5.0).abs() < 1e-9, "opus: {opus}");
    }

    /// A UTC pricing-window edge INSIDE one session. DeepSeek's post-cutover
    /// peak window is half-open, so the request at the window end is off-peak
    /// while its sibling inside the window is peak. Falsifying result: both
    /// requests at the same rate, which is what session-start pricing gave.
    #[test]
    fn events_price_across_a_utc_pricing_window_edge_within_one_session() {
        let session = ScannedSession::from_parts(
            "edge".into(),
            "/repo/a".into(),
            "2026-08-17T03:30:00Z".into(),
            Some("deepseek-v4-pro".into()),
            vec![
                // Inside the peak window.
                request_at(
                    "2026-08-17T03:30:00Z",
                    Some("deepseek-v4-pro"),
                    1_000_000,
                    1_000_000,
                    0,
                    0,
                ),
                // Exactly the window END — half-open, so OFF-peak.
                request_at(
                    "2026-08-17T04:00:00Z",
                    Some("deepseek-v4-pro"),
                    1_000_000,
                    1_000_000,
                    0,
                    0,
                ),
            ],
        );
        let attr = AttributedSession {
            slot: slot(7),
            session,
        };
        let events = attributed_session_to_events(&attr, "deepseek-v4-pro");
        let peak = events[0].cost_usd_estimate.unwrap();
        let off_peak = events[1].cost_usd_estimate.unwrap();
        assert!((peak - 5.28).abs() < 1e-9, "peak: {peak}");
        assert!((off_peak - 2.64).abs() < 1e-9, "off-peak: {off_peak}");
        assert!(
            peak > off_peak,
            "the two sides of the window edge must differ within one session"
        );
    }

    /// A rolling-window cutoff falling INSIDE a session now splits it, because
    /// each request is bucketed at its own timestamp. Falsifying result: all
    /// 3,000 input tokens in `last_7d`, which is what session-start bucketing
    /// produced for a session that began before the cutoff.
    #[test]
    fn requests_bucket_across_a_rolling_window_cutoff_within_one_session() {
        let now = DateTime::parse_from_rfc3339("2026-05-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let session = ScannedSession::from_parts(
            "straddle".into(),
            "/repo/a".into(),
            // Session STARTS 8 days back — wholly outside the 7d window.
            "2026-04-28T12:00:00Z".into(),
            None,
            vec![
                request_at(
                    "2026-04-28T12:00:00Z",
                    Some("claude-opus-4-8"),
                    1_000,
                    0,
                    0,
                    0,
                ),
                // One hour BEFORE the 7d cutoff (2026-04-29T12:00:00Z).
                request_at(
                    "2026-04-29T11:00:00Z",
                    Some("claude-opus-4-8"),
                    1_000,
                    0,
                    0,
                    0,
                ),
                // One hour AFTER it.
                request_at(
                    "2026-04-29T13:00:00Z",
                    Some("claude-opus-4-8"),
                    1_000,
                    0,
                    0,
                    0,
                ),
            ],
        );
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let events = attributed_session_to_events(&attr, "claude-opus-4-8");
        let s = crate::usage::ledger::summarize(&events, now);
        assert_eq!(s.total_input_tokens, 3_000);
        assert_eq!(
            s.last_7d_input_tokens, 1_000,
            "only the request AFTER the cutoff is inside the 7d window"
        );
        assert_eq!(s.last_30d_input_tokens, 3_000);
        assert_eq!(s.request_count, 3);
    }

    /// A request whose OWN timestamp will not parse must still land in a
    /// rolling window, because `summarize` bucket-skips an unparseable `ts` and
    /// the billing card renders only 7d and 30d — so the tokens would reach
    /// `total_*` alone and be invisible, not merely mis-bucketed.
    ///
    /// This is the falsifier the suite lacked: `request.rs`'s retention test
    /// asserts only that the raw string survives normalization and never
    /// reaches the bucketing path, so no mutation there could red it.
    ///
    /// Falsifying result: `last_7d_input_tokens == 0`, which is exactly what
    /// `unwrap_or_else(|| session.start_time)` produced — `Some("garbage")` is
    /// `Some`, so the fallback never fired and the garbage reached `ts`.
    #[test]
    fn unparseable_request_timestamp_still_lands_in_a_rolling_window() {
        let now = DateTime::parse_from_rfc3339("2026-05-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut bad = request_at(
            "2026-05-06T09:00:00Z",
            Some("claude-opus-4-8"),
            4_242,
            7,
            0,
            0,
        );
        bad.timestamp = Some("not-a-timestamp".into());
        let session = ScannedSession::from_parts(
            "unparseable".into(),
            "/repo/a".into(),
            // Parseable BY CONSTRUCTION — no AttributedSession can carry an
            // unparseable start_time (attribute_session returns None).
            "2026-05-06T09:00:00Z".into(),
            None,
            vec![bad],
        );
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let events = attributed_session_to_events(&attr, "claude-opus-4-8");
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].ts, "2026-05-06T09:00:00Z",
            "an unparseable request timestamp must be replaced by the session start"
        );

        let s = crate::usage::ledger::summarize(&events, now);
        assert_eq!(s.total_input_tokens, 4_242);
        assert_eq!(
            s.last_7d_input_tokens, 4_242,
            "the request must reach the 7d window, not total_* alone"
        );
        assert_eq!(s.last_30d_input_tokens, 4_242);
        assert_eq!(s.today_input_tokens, 4_242);

        // Pricing stays FAIL-LOUD in the same case: a window bucket derived
        // from the session is a sound approximation, a RATE derived from it is
        // a guess a pricing-window boundary can make wrong. A time-invariant
        // row still prices; the DeepSeek assertion for the time-varying side
        // lives in attributed_session_to_event_unparseable_ts_yields_na_for_deepseek_only.
        assert!(
            events[0].cost_usd_estimate.is_some(),
            "claude is time-invariant, so it prices even with no usable instant"
        );
    }

    /// A request on an unknown model still contributes tokens and increments
    /// the unestimated counter, and does NOT suppress its priced siblings.
    #[test]
    fn unknown_model_request_still_counts_tokens_and_does_not_block_siblings() {
        let session = ScannedSession::from_parts(
            "mixed".into(),
            "/repo/a".into(),
            "2026-05-06T11:00:00Z".into(),
            None,
            vec![
                request_at(
                    "2026-05-06T11:00:00Z",
                    Some("claude-opus-4-8"),
                    1_000_000,
                    0,
                    0,
                    0,
                ),
                request_at(
                    "2026-05-06T11:05:00Z",
                    Some("future-model-not-in-table"),
                    777,
                    0,
                    0,
                    0,
                ),
            ],
        );
        let attr = AttributedSession {
            slot: slot(1),
            session,
        };
        let events = attributed_session_to_events(&attr, "claude-opus-4-8");
        let now = DateTime::parse_from_rfc3339("2026-05-06T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let s = crate::usage::ledger::summarize(&events, now);
        assert_eq!(
            s.unestimated_cost_count, 1,
            "only the unknown-model request"
        );
        assert_eq!(s.total_input_tokens, 1_000_777, "its tokens still count");
        assert!(
            (s.total_cost_usd - 5.0).abs() < 1e-9,
            "the priced sibling still prices: {}",
            s.total_cost_usd
        );
    }

    #[test]
    fn scan_project_transcripts_skips_files_older_than_window() {
        use std::time::SystemTime;
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        let now = fixed_now();

        let recent = write_transcript(
            &projects,
            "-p",
            "recent.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","message":{"model":"gpt-5","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        let old = write_transcript(
            &projects,
            "-p",
            "old.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","message":{"model":"gpt-5","usage":{"input_tokens":5,"output_tokens":7}}}"#,
            ],
        );
        // Age the "old" file well beyond the 31-day window. NOTE: Windows
        // requires the file be opened for WRITE to set its mtime (Unix allows
        // it on a read handle), so use OpenOptions::write, not File::open.
        let set_mtime = |path: &Path, mtime: SystemTime| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        };
        set_mtime(&old, (now - Duration::days(40)).into());
        // Keep the recent file inside the window.
        set_mtime(&recent, (now - Duration::days(1)).into());

        let sessions = scan_project_transcripts(&projects, now);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, "recent");
    }

    #[test]
    fn scan_project_transcripts_skips_non_jsonl_and_missing_dir() {
        let dir = TempDir::new().unwrap();
        let projects = dir.path().join("projects");
        // Missing dir → empty.
        assert!(scan_project_transcripts(&projects, fixed_now()).is_empty());

        std::fs::create_dir_all(projects.join("-p")).unwrap();
        std::fs::write(projects.join("-p").join("notes.txt"), "ignored").unwrap();
        write_transcript(
            &projects,
            "-p",
            "good.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/p","timestamp":"2026-05-06T09:00:00Z","message":{"model":"gpt-5","usage":{"input_tokens":1,"output_tokens":2}}}"#,
            ],
        );
        let sessions = scan_project_transcripts(&projects, fixed_now());
        assert_eq!(sessions.len(), 1);
    }

    /// Plants a `config-<slot>/settings.json` with a DeepSeek
    /// `ANTHROPIC_BASE_URL` so `accounts::discovery::discover_all` classifies
    /// the slot as `ThirdParty { provider: "DeepSeek" }` — the on-disk state a
    /// real 3P DeepSeek slot carries, which the provider-consistency gate reads.
    fn plant_deepseek_slot(base: &Path, slot: u16) {
        let config = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("settings.json"),
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://api.deepseek.com/anthropic","ANTHROPIC_MODEL":"deepseek-v4-pro","ANTHROPIC_AUTH_TOKEN":"sk-test"}}"#,
        )
        .unwrap();
    }

    #[test]
    fn deepseek_v41_writer_rebuilds_unpriced_ledger_from_private_transcript() {
        use crate::daemon::usage_ledger_writer;
        use crate::usage::ledger;

        let _env_guard = crate::platform::test_env::lock();
        let dir = TempDir::new().unwrap();
        let claude_home = dir.path().join("claude");
        let base = claude_home.join("accounts");
        let project = dir.path().join("workspace");
        let project = project.to_str().unwrap();
        let account = slot(4);
        plant_deepseek_slot(&base, account.get());
        // Pin BOTH now and mtime: these historical pricing fixtures must not
        // become dependent on the date the test happens to execute.
        let now = DateTime::parse_from_rfc3339("2026-09-14T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let ts = "2026-09-14T11:30:00Z";
        let transcript = serde_json::json!({
            "type": "assistant",
            "cwd": project,
            "timestamp": ts,
            "sessionId": "fixture-v41-session",
            "message": {
                "model": "deepseek-flash",
                "content": "PRIVATE FIXTURE CONTENT MUST NOT ENTER LEDGER",
                "usage": {
                    "input_tokens": 1_000_000,
                    "output_tokens": 1_000_000,
                    "cache_creation_input_tokens": 1_000_000,
                    "cache_read_input_tokens": 1_000_000
                }
            }
        })
        .to_string();
        let path = write_transcript(
            &claude_home.join("projects"),
            "fixture-project",
            "fixture-v41-session.jsonl",
            &[&transcript],
        );
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(now.into())
            .unwrap();
        let original_transcript = std::fs::read(&path).unwrap();
        super::super::launch_log::append(
            &base,
            &launch_ev("2026-09-14T11:00:00Z", account.get(), project),
        )
        .unwrap();

        // Model a ledger published by a binary that did not recognize the new
        // canonical ID. No live user ledger or transcript is read or changed.
        let old = UsageEvent {
            ts: ts.into(),
            session_id: "fixture-v41-session".into(),
            model: "deepseek-flash".into(),
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_creation_tokens: 1_000_000,
            cache_read_tokens: 1_000_000,
            cost_usd_estimate: None,
            source: UsageSource::ProjectsJsonl,
            project_path: Some(project.into()),
            snapshots_collapsed: 0,
            finalization_divergent: false,
            from_subagent: false,
            // The fixture transcript carries no `requestId`, no `message.id`
            // and no record `uuid`, so its single record normalizes to one
            // unidentified request (an internal ticket) — billed on its own, exactly as the
            // pre-an internal ticket scanner billed it.
            unidentified: true,
        };
        ledger::write_all(&base, account, std::slice::from_ref(&old)).unwrap();
        let before = ledger::read_all(&base, account).unwrap();
        assert_eq!(before.events.as_slice(), std::slice::from_ref(&old));
        assert_eq!(
            ledger::summarize(&before.events, now).unestimated_cost_count,
            1
        );

        // Exercise the real synchronous core of the daemon tick, not a test
        // reconstruction of aggregate + write_all. The configured V4 fallback
        // intentionally differs: the transcript's V4.1 canonical ID must win.
        let report = usage_ledger_writer::run_once(&claude_home, &base, now);
        assert_eq!(report.slots_written, 1);
        assert_eq!(report.events_written, 1);
        assert_eq!(report.slots_rolled_off, 0);
        assert_eq!(report.write_failures, 0);
        let published = ledger::read_all(&base, account).unwrap();
        assert_eq!(published.skipped_malformed, 0);
        assert_eq!(published.events.len(), 1);
        let event = &published.events[0];
        let cost = event
            .cost_usd_estimate
            .expect("V4.1 must no longer be unpriced");
        // Monday 11:30 UTC is off-peak: 1M input ($0.15), output ($0.60),
        // cache-hit ($0.003); no invented charge for cache creation.
        assert!((cost - 0.753).abs() < 1e-12, "expected $0.753, got ${cost}");
        let mut expected = old;
        expected.cost_usd_estimate = Some(cost);
        assert_eq!(
            *event, expected,
            "rebuild changes cost, not source metadata"
        );
        let summary = ledger::summarize(&published.events, now);
        assert_eq!(summary.event_count, 1);
        assert_eq!(summary.unestimated_cost_count, 0);
        assert_eq!(summary.total_input_tokens, 1_000_000);
        assert_eq!(summary.total_output_tokens, 1_000_000);
        assert_eq!(summary.total_cost_usd, cost);
        assert_eq!(summary.last_7d_cost_usd, cost);
        assert_eq!(summary.last_30d_cost_usd, cost);

        let ledger_path = ledger::ledger_path(&base, account);
        let first_bytes = std::fs::read(&ledger_path).unwrap();
        assert!(!String::from_utf8_lossy(&first_bytes).contains("PRIVATE FIXTURE CONTENT"));
        assert_eq!(
            usage_ledger_writer::run_once(&claude_home, &base, now),
            report
        );
        assert_eq!(std::fs::read(&ledger_path).unwrap(), first_bytes);
        assert_eq!(std::fs::read(&path).unwrap(), original_transcript);
    }

    #[test]
    fn aggregate_end_to_end() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();

        // Plant a real-shape transcript for slot 4's project.
        write_transcript(
            &claude_home.join("projects"),
            "-repo-a",
            "sess1.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/repo/a","timestamp":"2026-05-06T11:30:00Z","sessionId":"sess1","message":{"model":"deepseek-chat","usage":{"input_tokens":10000,"output_tokens":5000}}}"#,
            ],
        );

        // Plant a launch event that attributes /repo/a to slot 4.
        super::super::launch_log::append(base, &launch_ev("2026-05-06T11:00:00Z", 4, "/repo/a"))
            .unwrap();

        // Slot 4 is a DeepSeek slot (discovered via its 3P base-URL binding), so
        // the provider gate keeps the deepseek transcript.
        plant_deepseek_slot(base, 4);
        let result = aggregate(claude_home, base, fixed_now(), |_slot| {
            "deepseek-v4-pro".to_string()
        })
        .unwrap();
        assert_eq!(result.len(), 1);
        let (s, ev) = &result[0];
        assert_eq!(*s, slot(4));
        assert_eq!(ev.input_tokens, 10000);
        assert_eq!(ev.session_id, "sess1");
        // Real transcript model (deepseek) wins over the fallback.
        assert_eq!(ev.model, "deepseek-chat");
        assert_eq!(ev.source, UsageSource::ProjectsJsonl);
        assert!(ev.cost_usd_estimate.is_some());
    }

    /// Bug-2 end-to-end: a `claude-*` transcript in a cwd whose only launch is a
    /// DeepSeek slot is NOT attributed to that slot (the $246.50 opus-on-the-
    /// DeepSeek-card bleed), because slot 11's authoritative `AccountSource`
    /// (ThirdParty DeepSeek) classifies to a different provider family than the
    /// claude transcript. Exercises the real `discover_all` wiring in `aggregate`.
    #[test]
    fn aggregate_does_not_bleed_claude_onto_3p_slot() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();

        // A real Anthropic (opus) session run in slot 11's cwd.
        write_transcript(
            &claude_home.join("projects"),
            "-repo-astro",
            "opus.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/repo/astro","timestamp":"2026-05-06T11:30:00Z","sessionId":"opus","message":{"model":"claude-opus-4-8","usage":{"input_tokens":10000,"output_tokens":5000}}}"#,
            ],
        );

        // The only launch event for that cwd is DeepSeek slot 11.
        super::super::launch_log::append(
            base,
            &launch_ev("2026-05-06T11:00:00Z", 11, "/repo/astro"),
        )
        .unwrap();

        // Slot 11 is a DeepSeek 3P slot (discovered via its base-URL binding) →
        // provider gate rejects the opus transcript → zero attributed events.
        plant_deepseek_slot(base, 11);
        let result = aggregate(claude_home, base, fixed_now(), |_slot| {
            "deepseek-v4-pro".to_string()
        })
        .unwrap();
        assert!(
            result.is_empty(),
            "claude transcript must not attribute to the DeepSeek slot, got {result:?}"
        );
    }

    /// Guards the fall-through: when a slot is NOT discoverable (no 3P binding,
    /// no anthropic credential → `AccountSource` unresolved), the gate is
    /// disabled for it and cwd+time attribution stands — a claude session in an
    /// undiscovered slot's cwd still attributes (no over-rejection).
    #[test]
    fn aggregate_undiscovered_slot_falls_through_to_cwd_time() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();

        write_transcript(
            &claude_home.join("projects"),
            "-repo-b",
            "sess.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/repo/b","timestamp":"2026-05-06T11:30:00Z","sessionId":"sess","message":{"model":"claude-opus-4-8","usage":{"input_tokens":100,"output_tokens":50}}}"#,
            ],
        );
        // Slot 2 has NO on-disk discovery state → source unresolved → gate off.
        super::super::launch_log::append(base, &launch_ev("2026-05-06T11:00:00Z", 2, "/repo/b"))
            .unwrap();

        let result = aggregate(claude_home, base, fixed_now(), |_slot| {
            "claude-sonnet-4-6".to_string()
        })
        .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, slot(2));
    }

    /// Regression (redteam R2 F1): a slot that was Anthropic-logged (a stale
    /// `by_slot` mapping survives) THEN rebound to DeepSeek without `csq logout`
    /// (a live 3P `settings.json` base-URL binding) must classify as DeepSeek —
    /// the live 3P binding dominates the stale Anthropic map. Otherwise the gate
    /// would reject the slot's own `deepseek-*` sessions and blank its card
    /// (worse than the bleed). `discover_all` lists Anthropic (by_slot) before
    /// per-slot 3P, so WITHOUT the 3P-dominance overlay slot 3 resolves
    /// `claude` and this session is rejected.
    #[test]
    fn aggregate_3p_binding_dominates_stale_anthropic_by_slot() {
        let claude_home_dir = TempDir::new().unwrap();
        let base_dir = TempDir::new().unwrap();
        let claude_home = claude_home_dir.path();
        let base = base_dir.path();
        std::fs::create_dir_all(base).unwrap();

        // Stale Anthropic `by_slot` for slot 3 (pre-rebind login) — no identity
        // credentials planted, but the by_slot branch still emits Anthropic.
        std::fs::write(
            base.join("profiles.json"),
            r#"{"accounts":{},"by_slot":{"3":"550e8400-e29b-41d4-a716-446655440003"}}"#,
        )
        .unwrap();
        // Live DeepSeek 3P binding on the same slot (rebind without logout).
        plant_deepseek_slot(base, 3);

        write_transcript(
            &claude_home.join("projects"),
            "-repo-ds",
            "ds.jsonl",
            &[
                r#"{"type":"assistant","cwd":"/repo/ds","timestamp":"2026-05-06T11:30:00Z","sessionId":"ds","message":{"model":"deepseek-v4-pro","usage":{"input_tokens":1000,"output_tokens":500}}}"#,
            ],
        );
        super::super::launch_log::append(base, &launch_ev("2026-05-06T11:00:00Z", 3, "/repo/ds"))
            .unwrap();

        let result = aggregate(claude_home, base, fixed_now(), |_slot| {
            "deepseek-v4-pro".to_string()
        })
        .unwrap();
        assert_eq!(
            result.len(),
            1,
            "the deepseek session must attribute to its rebound 3P slot (3P binding \
             dominates the stale Anthropic by_slot), got {result:?}"
        );
        assert_eq!(result[0].0, slot(3));
    }

    // ---------------------------------------------------------------------
    // D6 privacy gate — executable guards
    //
    // The module header states the D6 contract: the deserialization structs
    // ARE the privacy gate, carrying metadata only, and content fields are
    // absent so serde drops them. Absence is not self-enforcing — adding
    // `content` to `TranscriptMessage` would silently begin capturing prompt
    // text and no fixture built from metadata-only lines would notice. The
    // three tests below make the contract fail LOUDLY instead.
    //
    // They are deliberately two different instruments, because each is blind
    // where the other sees:
    //
    // - the SENTINEL tests are a DENYLIST of field names we thought of. They
    //   prove serde really discards those fields today, end to end, but say
    //   nothing about a content field named something we did not anticipate.
    // - the FIELD-SET LOCK is an ALLOWLIST. It reds on ANY field added to a
    //   gated struct, including one whose name nobody predicted, which is the
    //   half that actually defends the contract.
    //
    // None of them changes production behaviour, and none adds
    // `#[serde(deny_unknown_fields)]`: tolerating unknown fields is the
    // correct design, since the vendor adds fields freely and a strict struct
    // would start dropping whole billable lines.
    // ---------------------------------------------------------------------

    /// Distinctive values planted in the content-bearing fields of the D6
    /// fixture. None can appear in a metadata-only projection, so any one of
    /// them surfacing in a parsed value names the leak.
    const D6_SENTINELS: [&str; 6] = [
        "CSQ-D6-LEAK-CONTENT",
        "CSQ-D6-LEAK-TEXT",
        "CSQ-D6-LEAK-FIRST-PROMPT",
        "CSQ-D6-LEAK-THINKING",
        "CSQ-D6-LEAK-TOOL-RESULT",
        "CSQ-D6-LEAK-NESTED-INPUT",
    ];

    /// A realistic CC assistant line carrying BOTH the metadata the scanner
    /// needs and every content shape it must refuse: a top-level `content`,
    /// `first_prompt` and `toolUseResult`, plus a `message.content` array with
    /// text, thinking and a nested tool-use `input` payload.
    ///
    /// The metadata is real so the line is genuinely billable — that is what
    /// makes the end-to-end guard non-vacuous (see
    /// [`scan_of_content_bearing_transcript_extracts_tokens_and_no_content`]).
    fn d6_sentinel_line() -> &'static str {
        concat!(
            r#"{"type":"assistant","cwd":"/repo/d6","timestamp":"2026-05-06T11:30:00Z","#,
            r#""sessionId":"sess-d6","requestId":"req_d6","uuid":"uuid-d6","#,
            r#""content":"CSQ-D6-LEAK-CONTENT","first_prompt":"CSQ-D6-LEAK-FIRST-PROMPT","#,
            r#""toolUseResult":{"stdout":"CSQ-D6-LEAK-TOOL-RESULT"},"#,
            r#""message":{"id":"msg_d6","model":"claude-opus-4-8","content":["#,
            r#"{"type":"text","text":"CSQ-D6-LEAK-TEXT"},"#,
            r#"{"type":"thinking","thinking":"CSQ-D6-LEAK-THINKING"},"#,
            r#"{"type":"tool_use","input":{"command":"CSQ-D6-LEAK-NESTED-INPUT"}}],"#,
            r#""usage":{"input_tokens":11,"output_tokens":22,"#,
            r#""cache_creation_input_tokens":33,"cache_read_input_tokens":44}}}"#,
        )
    }

    /// Top-level field names of a `{:#?}` rendering, in declaration order.
    ///
    /// Mechanism: pretty `Debug` puts a struct's OWN fields at exactly four
    /// spaces of indent and every nested field deeper, and it ESCAPES string
    /// contents — a `\n` inside a value is rendered as the two characters
    /// `\` `n`, never as a real newline. So no field VALUE can forge a line
    /// that looks like a top-level field, which is the property that makes a
    /// line-indent scan a sound field-set reader. Non-pretty `{:?}` has no such
    /// property and would need brace/quote tracking instead.
    ///
    /// Falsifying result: a struct with a field this misses would show up as a
    /// SHORTER list than the expected one in the callers below, which they
    /// assert on — so a reader that under-reports cannot make a lock pass.
    fn top_level_debug_fields(pretty: &str) -> Vec<String> {
        pretty
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("    ")?;
                if rest.starts_with(' ') {
                    return None; // nested field, not this struct's own
                }
                let name = rest.split(':').next()?;
                let is_ident = !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
                // Require the colon to actually follow the identifier, so a
                // `Vec` element or enum variant rendered at this indent is not
                // mistaken for a field.
                if is_ident && rest[name.len()..].starts_with(':') {
                    Some(name.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Asserts a D6-gated struct's field set is EXACTLY `expected`, naming any
    /// field that appeared or vanished.
    fn assert_field_set_locked(type_name: &str, pretty: &str, expected: &[&str]) {
        let actual = top_level_debug_fields(pretty);
        let added: Vec<&String> = actual
            .iter()
            .filter(|f| !expected.contains(&f.as_str()))
            .collect();
        let removed: Vec<&&str> = expected
            .iter()
            .filter(|e| !actual.iter().any(|a| a == *e))
            .collect();
        assert!(
            added.is_empty() && removed.is_empty(),
            "D6 PRIVACY GATE: the field set of `{type_name}` changed.\n  \
             added:   {added:?}\n  removed: {removed:?}\n  \
             expected: {expected:?}\n  actual:   {actual:?}\n\
             `{type_name}` is a D6 privacy-gated struct (see the module header). \
             If the added field is METADATA (an id, a timestamp, a model name, a \
             numeric token count), add it to this test's expected set. If it can \
             hold conversational content — message text, prompts, thinking, tool \
             payloads — the D6 contract is VIOLATED and the field must not exist."
        );
    }

    /// D6: the deserialization structs discard every content field on a line
    /// that carries them.
    ///
    /// Mechanism: `content`, `text`, `first_prompt`, `thinking`,
    /// `toolUseResult` and a nested tool-use `input` are simply absent from
    /// [`TranscriptLine`] / [`TranscriptMessage`] / [`TranscriptUsage`], and
    /// serde drops unnamed fields. Falsifying result: add
    /// `#[serde(default)] content: Option<String>` to `TranscriptMessage` and
    /// `CSQ-D6-LEAK-CONTENT` appears in the parsed value's `Debug`, failing
    /// here by name.
    #[test]
    fn transcript_structs_discard_every_content_field() {
        let rec: TranscriptLine = serde_json::from_str(d6_sentinel_line())
            .expect("the D6 fixture must parse, or this guard proves nothing");

        // Non-vacuity: the metadata really was extracted, so the absence of
        // sentinels below is a projection result and not a failed parse.
        assert_eq!(rec.cwd.as_deref(), Some("/repo/d6"));
        assert_eq!(rec.request_id.as_deref(), Some("req_d6"));
        let usage = rec
            .message
            .as_ref()
            .and_then(|m| m.usage.as_ref())
            .expect("fixture carries message.usage");
        assert_eq!((usage.input_tokens, usage.output_tokens), (11, 22));

        let rendered = format!("{rec:?}");
        for sentinel in D6_SENTINELS {
            assert!(
                !rendered.contains(sentinel),
                "D6 PRIVACY GATE: `{sentinel}` reached the parsed transcript value. \
                 A content field was added to TranscriptLine/TranscriptMessage/\
                 TranscriptUsage, so conversational text is now being captured. \
                 Parsed value: {rendered}"
            );
        }
    }

    /// D6, end to end: the REAL scan path over a transcript file full of
    /// content yields a session carrying its tokens and none of its text.
    ///
    /// This is the guard that covers the CARRIER types too — `UsageSnapshot`,
    /// `SnapshotUsage`, `NormalizedRequest` reached via
    /// [`ScannedSession::requests`] — which are not `Deserialize` and so cannot
    /// be probed through serde. Falsifying result: any sentinel in the scanned
    /// session's `Debug`, which requires a content field on some struct between
    /// the file and the ledger.
    #[test]
    fn scan_of_content_bearing_transcript_extracts_tokens_and_no_content() {
        let projects_root = TempDir::new().unwrap();
        let path = write_transcript(
            projects_root.path(),
            "-repo-d6",
            "sess-d6.jsonl",
            &[
                r#"{"type":"user","cwd":"/repo/d6","timestamp":"2026-05-06T11:29:00Z","sessionId":"sess-d6","message":{"role":"user","content":"CSQ-D6-LEAK-CONTENT"}}"#,
                d6_sentinel_line(),
            ],
        );

        let session = scan_one_transcript(&path, false, None, &mut ScanSkips::default())
            .expect("the content-bearing fixture is billable and must scan");

        // Non-vacuity: a scan that silently produced nothing would pass the
        // sentinel assertions below for the wrong reason.
        assert_eq!(session.session_id, "sess-d6");
        assert_eq!(session.project_path, "/repo/d6");
        assert_eq!(
            session.requests.len(),
            1,
            "one billable request: {session:?}"
        );
        assert_eq!(
            (
                session.input_tokens,
                session.output_tokens,
                session.cache_creation_tokens,
                session.cache_read_tokens
            ),
            (11, 22, 33, 44)
        );

        let rendered = format!("{session:?}");
        for sentinel in D6_SENTINELS {
            assert!(
                !rendered.contains(sentinel),
                "D6 PRIVACY GATE: `{sentinel}` survived the scan into ScannedSession. \
                 Transcript content is now being retained in memory past parsing. \
                 Scanned session: {rendered}"
            );
        }
    }

    /// D6: the field sets of the three deserialization structs are LOCKED.
    ///
    /// This is the allowlist half. The sentinel guards above only refuse field
    /// names someone already thought of; this one reds on ANY field added to a
    /// gated struct, which is the case that actually gets missed. Falsifying
    /// result: add any field to `TranscriptLine`, `TranscriptMessage` or
    /// `TranscriptUsage` and it is named here as `added`.
    #[test]
    fn transcript_struct_field_sets_are_locked() {
        let rec: TranscriptLine = serde_json::from_str(d6_sentinel_line())
            .expect("the D6 fixture must parse, or this guard proves nothing");
        let msg = rec.message.as_ref().expect("fixture carries message");
        let usage = msg.usage.as_ref().expect("fixture carries message.usage");

        assert_field_set_locked(
            "TranscriptLine",
            &format!("{rec:#?}"),
            &[
                "cwd",
                "timestamp",
                "session_id",
                "request_id",
                "uuid",
                "message",
            ],
        );
        assert_field_set_locked(
            "TranscriptMessage",
            &format!("{msg:#?}"),
            &["id", "model", "usage"],
        );
        assert_field_set_locked(
            "TranscriptUsage",
            &format!("{usage:#?}"),
            &[
                "input_tokens",
                "output_tokens",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
            ],
        );
    }
}
