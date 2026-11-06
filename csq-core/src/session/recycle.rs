//! Supervised in-place RECYCLE of a csq-launched Claude Code session (spec 36).
//!
//! A long-lived Claude Code process grows to multiple GiB; `/compact` and
//! `/clear` do not release it, only a restart does. While `csq run` supervises
//! the child (spawn + wait), it samples the child's RSS into
//! `<handle>/.csq-memory.json`, and on a request written by
//! `csq session recycle` it waits for a POSITIVELY evidenced turn end, re-runs
//! the launch gates, stops ONLY the claude child (and its identity-checked
//! descendants) and relaunches the same command with `--resume <session-id>`.
//!
//! Every file here is written through the private temp factory (0600, atomic
//! replace). Every kill-path decision that cannot be read or verified fails
//! toward NOT killing (`guard-reader-writer-parity.md` MUST-2).

use crate::platform::fs::write_private_tmp_synced_retained;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// A fixed-vocabulary failure tag (never carries paths, tokens or OS text).
pub type Tag = &'static str;

/// Memory view written by the supervisor, read by statusline / doctor / `csq session memory`.
pub const MEMORY_FILE: &str = ".csq-memory.json";
/// Recycle request written by `csq session recycle`, consumed by the supervisor.
pub const REQUEST_FILE: &str = ".csq-recycle-request.json";
/// Recycle outcome written by the supervisor.
pub const RESULT_FILE: &str = ".csq-recycle-result.json";
/// Supervisor identity marker: proves a live `csq run` supervises this handle's child.
pub const SUPERVISOR_FILE: &str = ".csq-supervisor.json";
/// Env override for the warn threshold (decimal integer bytes).
pub const WARN_ENV: &str = "CSQ_MEMORY_WARN_BYTES";
/// Default warn threshold: 2.5 GiB.
pub const DEFAULT_WARN_BYTES: u64 = 2 * 1024 * 1024 * 1024 + 512 * 1024 * 1024;
/// RSS sampling cadence.
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(30);
/// A memory file older than this is not shown (10 sample intervals).
pub const MEMORY_STALE_AFTER: Duration = Duration::from_secs(300);
/// Maximum `--reason` length in characters.
pub const REASON_MAX_CHARS: usize = 200;
/// Upper bound read from any of the small JSON files above.
const MAX_JSON_BYTES: u64 = 8192;
/// How much of the transcript tail is read to classify the turn state.
const TRANSCRIPT_TAIL_BYTES: u64 = 1024 * 1024;

// ── schemas ────────────────────────────────────────────────────────────────

/// Memory classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryState {
    /// Below the warn threshold.
    Ok,
    /// At or above the warn threshold.
    Warn,
    /// The sample failed; `tag` names why.
    Unknown,
}

/// `<handle>/.csq-memory.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// Schema version (1).
    pub v: u32,
    /// Child RSS in bytes; `null` when the state is `unknown`.
    pub rss_bytes: Option<u64>,
    /// Threshold in force for this sample.
    pub warn_bytes: u64,
    /// Classification.
    pub state: MemoryState,
    /// RFC3339 sample time.
    pub sampled_at: String,
    /// Fixed failure tag; present only for `unknown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// How the relaunch treats the conversation.
///
/// `Resume` is the original behaviour: `--resume <session-id>`, same conversation.
/// `Fresh` relaunches WITHOUT any conversation-selecting flag and appends exactly one
/// positional prompt — the session starts clean and receives its context as that prompt
/// (spec 36.10). A fresh launch gets a NEW session id; nothing asserts it equals the old one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Relaunch the same conversation (`--resume <id>`).
    #[default]
    Resume,
    /// Relaunch clean, with one fixed positional prompt.
    Fresh,
}

impl Mode {
    /// True for the mode that must NOT appear in the request JSON, so a resume
    /// request stays byte-identical to what earlier csq versions wrote.
    pub fn is_resume(&self) -> bool {
        matches!(self, Mode::Resume)
    }
}

/// `<handle>/.csq-recycle-request.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecycleRequest {
    /// Schema version (1).
    pub v: u32,
    /// Correlation id (uuid) echoed in every result written for this request.
    pub request_id: String,
    /// The Claude Code session id to resume; MUST equal the session the supervised child runs.
    pub session_id: String,
    /// Operator-supplied reason (validated).
    pub reason: String,
    /// RFC3339 request time.
    pub requested_at: String,
    /// `fresh` for a clean relaunch; absent (and never written) for a resume.
    #[serde(default, skip_serializing_if = "Mode::is_resume")]
    pub mode: Mode,
    /// Present ONLY on a cross-session request (design slice 2). Absent ⇒ this is the
    /// terminal asking for itself and every foreign check is skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<super::recycle_consent::RequesterRecord>,
    /// Single-use nonce minted by the daemon for a foreign request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Unix seconds after which a foreign request must not be acted on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
}

/// Recycle outcome vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Request consumed; waiting for a positively evidenced turn end.
    Waiting,
    /// The old child is being stopped / the new one is inside its settle window.
    InProgress,
    /// New child is alive past the settle window (or exited cleanly by the user inside it).
    Recycled,
    /// No quiet point within the cap; session left running.
    AbortedNotQuiet,
    /// Transcript, turn state or argv unresolvable; session left running.
    AbortedUnresolved,
    /// Request file unparsable; session left running.
    AbortedRequestUnreadable,
    /// Session id / pid identity could not be verified; session left running.
    AbortedIdentity,
    /// A launch gate or launch artifact check refused the relaunch; session left running.
    AbortedGate,
    /// The child exited while the request was waiting or before it could be stopped.
    AbortedChildExited,
    /// A SIGINT/SIGTERM/SIGHUP reached csq in the stop-to-spawn window; the replacement
    /// child was spawned and the signal forwarded to it.
    Interrupted,
    /// Spawn error, the new child died inside the settle window, or the stop itself failed.
    Failed,
    /// The capability layer was NOT ready after the stop, so the session was relaunched in RESUME
    /// mode instead: the conversation survives, the fresh handover did not happen, and `tag` names
    /// the readiness failure that caused the fallback.
    FreshFellBackToResume,
}

impl Outcome {
    /// True while a recycle is in flight (a second request must be refused).
    pub fn in_flight(self) -> bool {
        matches!(self, Outcome::Waiting | Outcome::InProgress)
    }
}

/// `<handle>/.csq-recycle-result.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecycleResult {
    /// Schema version (1).
    pub v: u32,
    /// Outcome.
    pub outcome: Outcome,
    /// Correlation id of the request, when one was read.
    #[serde(default)]
    pub request_id: Option<String>,
    /// The requested session id, when known.
    pub session_id: Option<String>,
    /// RFC3339 time the request was made.
    #[serde(default)]
    pub requested_at: Option<String>,
    /// Pid of the stopped child.
    pub old_pid: Option<u32>,
    /// Pid of the relaunched child.
    pub new_pid: Option<u32>,
    /// Last sampled RSS of the old child.
    pub rss_before_bytes: Option<u64>,
    /// Fixed tag for aborted / failed outcomes.
    pub tag: Option<String>,
    /// `fresh` when the request asked for a clean relaunch; absent for a resume.
    #[serde(default, skip_serializing_if = "Mode::is_resume")]
    pub mode: Mode,
    /// The foreign request's nonce, once consumed. A replay of the same nonce is refused
    /// from this record alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Nonces of EARLIER consumed foreign requests, newest last and bounded ([`MAX_CARRIED_NONCES`]).
    /// `nonce` above is the one this record's own recycle consumed; this list is what makes an
    /// OLDER captured request recognisable after another recycle has happened.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prior_nonces: Vec<String>,
    /// RFC3339 time of this write.
    pub at: String,
}

/// How many earlier consumed nonces a result carries.
///
/// The bound must exceed the number of requests that can be unexpired AT ONCE, or the ring
/// evicts a still-valid nonce and a captured request becomes replayable. Worst case: a consent
/// naming [`super::recycle_consent::MAX_CONSENT_ENTRIES`] (8) requesters, each throttled by
/// `RATE_WINDOW_SECS` (120 s) inside one 600 s TTL — 8 × 5 = 40. 64 covers it with headroom; the
/// file stays ~4 KiB of nonces.
pub const MAX_CARRIED_NONCES: usize = 64;

/// `<handle>/.csq-supervisor.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SupervisorMarker {
    /// Schema version (1).
    pub v: u32,
    /// The supervising `csq run` pid.
    pub csq_pid: u32,
    /// Start time of `csq_pid` (identity against pid reuse).
    pub csq_start: u64,
    /// The supervised claude child pid.
    pub child_pid: u32,
    /// Whether this launch can be relaunched at all (argv classified, program resolved,
    /// artifacts recorded, launch context present). `false` ⇒ `csq session recycle` refuses.
    pub relaunch_ok: bool,
    /// Fixed tag naming why `relaunch_ok` is false.
    #[serde(default)]
    pub relaunch_tag: Option<String>,
    /// The project root the session was launched in — where the capability layer's readiness CLI
    /// lives. Absent on markers written before the fresh contract, and a fresh request then
    /// refuses rather than guessing a root.
    #[serde(default)]
    pub cwd: Option<String>,
}

// ── private writes / bounded reads ─────────────────────────────────────────

pub(crate) fn write_json_private<T: Serialize>(
    handle: &Path,
    name: &str,
    value: &T,
) -> Result<(), Tag> {
    let bytes = serde_json::to_vec(value).map_err(|_| "recycle_serialize_failed")?;
    let target = handle.join(name);
    let writer = write_private_tmp_synced_retained(&target, &bytes)
        .map_err(|_| "recycle_file_write_failed")?;
    writer
        .replace(&target)
        .map_err(|_| "recycle_file_write_failed")
}

/// Opens `path` without following a final symlink and without blocking on a FIFO.
/// `Ok(None)` = absent.
#[cfg(unix)]
fn open_nofollow(path: &Path) -> Result<Option<std::fs::File>, Tag> {
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("recycle_file_unreadable"),
    }
}

/// `Ok(None)` = absent; `Err` = present but not a bounded regular file owned by this
/// user with no group/other access (the fd is `fstat`ed, so a swap after open is moot).
pub(crate) fn read_json_bounded<T: for<'de> Deserialize<'de>>(
    path: &Path,
) -> Result<Option<T>, Tag> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::MetadataExt;
        let Some(file) = open_nofollow(path)? else {
            return Ok(None);
        };
        let meta = file.metadata().map_err(|_| "recycle_file_unreadable")?;
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !meta.file_type().is_file()
            || meta.len() > MAX_JSON_BYTES
            || meta.uid() != euid
            || meta.mode() & 0o077 != 0
        {
            return Err("recycle_file_unreadable");
        }
        file
    };
    #[cfg(not(unix))]
    let file = {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("recycle_file_unreadable"),
        };
        if !meta.file_type().is_file() || meta.len() > MAX_JSON_BYTES {
            return Err("recycle_file_unreadable");
        }
        std::fs::File::open(path).map_err(|_| "recycle_file_unreadable")?
    };
    let mut buf = Vec::new();
    file.take(MAX_JSON_BYTES)
        .read_to_end(&mut buf)
        .map_err(|_| "recycle_file_unreadable")?;
    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|_| "recycle_file_unreadable")
}

/// RFC3339 now.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ── memory ─────────────────────────────────────────────────────────────────

/// Parses `CSQ_MEMORY_WARN_BYTES`: absent ⇒ default; present ⇒ ASCII digits, non-zero.
pub fn parse_warn_bytes(raw: Option<&str>) -> Result<u64, Tag> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_WARN_BYTES);
    };
    let raw = raw.trim();
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("memory_warn_bytes_invalid");
    }
    match raw.parse::<u64>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err("memory_warn_bytes_invalid"),
    }
}

/// Classifies one sample.
pub fn memory_record(rss: Result<u64, Tag>, warn_bytes: u64, now: &str) -> MemoryRecord {
    let (rss_bytes, state, tag) = match rss {
        Ok(n) if n >= warn_bytes => (Some(n), MemoryState::Warn, None),
        Ok(n) => (Some(n), MemoryState::Ok, None),
        Err(t) => (None, MemoryState::Unknown, Some(t.to_string())),
    };
    MemoryRecord {
        v: 1,
        rss_bytes,
        warn_bytes,
        state,
        sampled_at: now.to_string(),
        tag,
    }
}

/// Atomically writes `<handle>/.csq-memory.json` (0600).
pub fn write_memory(handle: &Path, record: &MemoryRecord) -> Result<(), Tag> {
    write_json_private(handle, MEMORY_FILE, record)
}

/// Reads `<handle>/.csq-memory.json`; `Ok(None)` = absent.
pub fn read_memory(handle: &Path) -> Result<Option<MemoryRecord>, Tag> {
    read_json_bounded(&handle.join(MEMORY_FILE))
}

/// The record when it is fresh enough to show (`now` and the sample time are RFC3339).
pub fn fresh_memory(handle: &Path, now: &str) -> Option<MemoryRecord> {
    let rec = read_memory(handle).ok()??;
    let then = chrono::DateTime::parse_from_rfc3339(&rec.sampled_at).ok()?;
    let now = chrono::DateTime::parse_from_rfc3339(now).ok()?;
    let age = now.signed_duration_since(then).to_std().ok()?;
    (age <= MEMORY_STALE_AFTER).then_some(rec)
}

/// The compact statusline segment, `Some` only for a fresh `warn` record.
pub fn statusline_segment(handle: &Path, now: &str) -> Option<String> {
    let rec = fresh_memory(handle, now)?;
    if rec.state != MemoryState::Warn {
        return None;
    }
    Some(format!(
        "[mem {:.1}G: recycle]",
        rec.rss_bytes? as f64 / (1024.0 * 1024.0 * 1024.0)
    ))
}

/// `VmRSS:   123456 kB` from `/proc/<pid>/status` text, in bytes.
pub fn parse_vmrss_status(text: &str) -> Result<u64, Tag> {
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .ok_or("rss_sample_failed")?;
    parse_kib(line)
}

/// `ps -o rss=` output (KiB), in bytes.
pub fn parse_ps_rss_kib(text: &str) -> Result<u64, Tag> {
    parse_kib(text)
}

fn parse_kib(text: &str) -> Result<u64, Tag> {
    let first = text.split_whitespace().next().ok_or("rss_sample_failed")?;
    first
        .parse::<u64>()
        .ok()
        .and_then(|k| k.checked_mul(1024))
        .ok_or("rss_sample_failed")
}

#[cfg(target_os = "macos")]
fn ps_field(pid: u32, field: &str, tag: Tag) -> Result<String, Tag> {
    use std::process::Stdio;
    let out = Command::new("/bin/ps")
        .args(["-o", field, "-p", &pid.to_string()])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| tag)?;
    if !out.status.success() {
        return Err(tag);
    }
    String::from_utf8(out.stdout).map_err(|_| tag)
}

/// Child RSS in bytes. Linux `/proc/<pid>/status`; macOS `ps -o rss=`; elsewhere unsupported.
pub fn sample_rss_bytes(pid: u32) -> Result<u64, Tag> {
    #[cfg(target_os = "linux")]
    {
        let text = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .map_err(|_| "rss_sample_failed")?;
        parse_vmrss_status(&text)
    }
    #[cfg(target_os = "macos")]
    {
        parse_ps_rss_kib(&ps_field(pid, "rss=", "rss_sample_failed")?)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err("rss_unsupported_platform")
    }
}

// ── request / result / supervisor marker ───────────────────────────────────

/// Session id shape: canonical 8-4-4-4-12 hex UUID.
pub fn validate_session_id(id: &str) -> Result<(), Tag> {
    let groups: Vec<&str> = id.split('-').collect();
    let lens = [8usize, 4, 4, 4, 12];
    let ok = groups.len() == 5
        && groups
            .iter()
            .zip(lens)
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(())
    } else {
        Err("recycle_session_id_invalid")
    }
}

/// Reason: at most 200 characters, no control characters.
pub fn validate_reason(reason: &str) -> Result<(), Tag> {
    if reason.chars().count() > REASON_MAX_CHARS || reason.chars().any(char::is_control) {
        Err("recycle_reason_invalid")
    } else {
        Ok(())
    }
}

/// Writes the request (0600, atomic) after validating both fields; mints the `request_id`.
///
/// NO capability-layer check happens here: the readiness gate belongs to the CALLER, which is
/// the only party that knows the target terminal ([`fresh_context_at`]). A duplicate gate here
/// would be one with the wrong inputs, and it would mask the verb's own refusal in tests.
pub fn write_request(
    handle: &Path,
    session_id: &str,
    reason: &str,
    now: &str,
    mode: Mode,
) -> Result<(), Tag> {
    validate_session_id(session_id)?;
    validate_reason(reason)?;
    let req = RecycleRequest {
        v: 1,
        request_id: uuid::Uuid::new_v4().to_string(),
        session_id: session_id.to_string(),
        reason: reason.to_string(),
        requested_at: now.to_string(),
        mode,
        requested_by: None,
        nonce: None,
        expires_at_unix: None,
    };
    write_json_private(handle, REQUEST_FILE, &req)
}

/// Reads the pending request; `Ok(None)` = none, `Err` = present but not trustworthy.
pub fn read_request(handle: &Path) -> Result<Option<RecycleRequest>, Tag> {
    let Some(req): Option<RecycleRequest> =
        read_json_bounded(&handle.join(REQUEST_FILE)).map_err(|_| "recycle_request_unreadable")?
    else {
        return Ok(None);
    };
    // Version and shape together: v1 is the SELF request (no requester fields) and v2 is a
    // FOREIGN request (requester fields mandatory). A pre-upgrade supervisor accepts v1 only, so
    // it refuses a v2 file as unreadable instead of silently acting on it as a self resume.
    let shape_ok = match req.v {
        1 => req.requested_by.is_none() && req.nonce.is_none() && req.expires_at_unix.is_none(),
        super::recycle_foreign::FOREIGN_REQUEST_VERSION => {
            req.requested_by.is_some() && req.nonce.is_some() && req.expires_at_unix.is_some()
        }
        _ => false,
    };
    if !shape_ok
        || validate_session_id(&req.session_id).is_err()
        || validate_reason(&req.reason).is_err()
        || req.request_id.len() > 64
        || !req
            .request_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err("recycle_request_unreadable");
    }
    // The foreign fields are all-or-nothing: a request that names a requester must carry a
    // nonce and an expiry, and a request that names none must carry neither — anything else
    // is ambiguity in front of a kill, and ambiguity refuses.
    match (&req.requested_by, &req.nonce, req.expires_at_unix) {
        (None, None, None) => {}
        (Some(r), Some(n), Some(exp)) => {
            if validate_session_id(&r.session_id).is_err()
                || r.handle.is_empty()
                || !Path::new(&r.handle).is_absolute()
                || n.len() < 16
                || n.len() > 64
                || !n.bytes().all(|b| b.is_ascii_hexdigit())
                || exp <= 0
            {
                return Err("recycle_request_unreadable");
            }
        }
        _ => return Err("recycle_request_unreadable"),
    }
    Ok(Some(req))
}

/// Decides whether a request that names a `requested_by` may be acted on (design slice 2,
/// ROOT-ratified with A1-A4). A request with no `requested_by` is the terminal's own and
/// this returns `Ok(())` — the self path is unchanged.
///
/// Order (each its own fixed tag): fresh-only ⇒ consent ⇒ expiry ⇒ replay. `consumed` is the
/// CARRIED nonce history — the nonces of earlier consumed foreign requests, newest last — plus
/// this consume's own nonce at the kill-point re-check.
/// A foreign request's target-side re-check, at consume and again at the kill point.
///
/// The consent's USE COUNT is deliberately not checked here: the daemon spends a use at ISSUE
/// time (ROOT ruling 2026-11-04), so by the time the supervisor acts the grant it was issued
/// under is already spent. What must still hold is the pair, the session binding and the expiry;
/// the request's single-use nonce is the target-side control.
pub fn foreign_verdict(
    req: &RecycleRequest,
    consent: Option<&super::recycle_consent::ConsentRecord>,
    now_unix: i64,
    consumed: &[String],
) -> Result<(), Tag> {
    let Some(requester) = &req.requested_by else {
        return Ok(());
    };
    // A third party may only ask for a CLEAN relaunch: restarting a conversation into
    // context a requester chose is not on offer.
    if req.mode != Mode::Fresh {
        return Err("xrecycle_target_mismatch");
    }
    let (Some(nonce), Some(exp)) = (req.nonce.as_deref(), req.expires_at_unix) else {
        return Err("recycle_request_unreadable");
    };
    super::recycle_consent::consent_allows_issued(consent, &req.session_id, requester, now_unix)?;
    if now_unix >= exp {
        return Err("xrecycle_request_stale");
    }
    if consumed.iter().any(|c| c == nonce) {
        return Err("xrecycle_replay");
    }
    Ok(())
}

/// Removes the request file. `true` when it is gone afterwards (absence is success).
pub fn remove_request(handle: &Path) -> bool {
    match std::fs::remove_file(handle.join(REQUEST_FILE)) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => {
            tracing::warn!(
                error_kind = "recycle_request_remove_failed",
                "request not removed"
            );
            false
        }
    }
}

/// Writes the result file.
pub fn write_result(handle: &Path, result: &RecycleResult) -> Result<(), Tag> {
    write_json_private(handle, RESULT_FILE, result)
}

/// Reads the result file.
pub fn read_result(handle: &Path) -> Result<Option<RecycleResult>, Tag> {
    read_json_bounded(&handle.join(RESULT_FILE))
}

/// Records that THIS process supervises `child_pid` for `handle`; `relaunch` carries
/// whether (and why not) the launch can be relaunched.
pub fn write_supervisor(
    handle: &Path,
    child_pid: u32,
    relaunch: Result<(), Tag>,
    cwd: &Path,
) -> Result<(), Tag> {
    let me = std::process::id();
    let start = crate::sessions::process_start_time(me).ok_or("recycle_supervisor_identity")?;
    write_json_private(
        handle,
        SUPERVISOR_FILE,
        &SupervisorMarker {
            v: 1,
            csq_pid: me,
            csq_start: start,
            child_pid,
            relaunch_ok: relaunch.is_ok(),
            relaunch_tag: relaunch.err().map(str::to_string),
            cwd: Some(cwd.display().to_string()),
        },
    )
}

/// The supervisor marker for `handle`, if it is present and bounded-readable. Absence and
/// unreadability are both `None`: the caller treats either as "not supervised".
pub fn read_supervisor(handle: &Path) -> Option<SupervisorMarker> {
    read_json_bounded(&handle.join(SUPERVISOR_FILE))
        .ok()
        .flatten()
}

/// Resolve the caller of a SELF recycle when the live-session listing has no row for it.
///
/// A headless (`--print`) Claude Code session has no controlling terminal, so the listing
/// classifier (the platform `listing_entry_kind_via` in `crate::sessions`) reports it
/// `NotSession` and `resolve_caller_from_env` yields `CallerError::HandleDirUnlisted` — a
/// COMPLETE listing that positively names no owner. That class, and only that class, may be
/// proved another way here; every other resolver class is final. The proof is the pair the
/// listing would otherwise have supplied: the handle dir's supervisor marker names the
/// supervised claude child, that child MUST be an ancestor of this process, and no process
/// between them may be a session (a nearer session is where the caller really runs). Reads
/// arrive through ports so the rule is testable without a live supervisor or process tree.
pub fn resolve_headless_caller(
    handle: &Path,
    marker_of: &dyn Fn(&Path) -> Option<SupervisorMarker>,
    ancestry_of: &dyn Fn(u32) -> Option<Option<crate::sessions::AncestorHops>>,
    is_session_hop: &dyn Fn(u32, u64) -> Option<bool>,
) -> Result<u32, Tag> {
    let marker = marker_of(handle).ok_or("recycle_caller_unresolved")?;
    // Outer `None` = the ancestry could not be read; `Some(None)` = the child is NOT an
    // ancestor. Both refuse: only a proved descendant may resolve.
    let between = ancestry_of(marker.child_pid)
        .ok_or("recycle_caller_unresolved")?
        .ok_or("recycle_caller_unresolved")?;
    // The claimed child must be the NEAREST session, exactly as `resolve_caller` requires on
    // the listed path: a session strictly between this process and the child is where the
    // caller really runs, so the handle dir merely NAMES an outer session. Without this walk
    // a nested session could recycle the session that launched it, without its consent.
    for (hop, hop_start) in between {
        match is_session_hop(hop, hop_start) {
            Some(false) => {}
            // A nearer session: the same class the listed path refuses.
            Some(true) => return Err("recycle_caller_target_mismatch"),
            // Unclassifiable hop is UNKNOWN, never "not a session".
            None => return Err("recycle_caller_unresolved"),
        }
    }
    Ok(marker.child_pid)
}

/// The capability layer's record filename inside a terminal's config dir.
const RECORD_FILE: &str = "coc-context-state.json";
/// The record grows with the session (handover, boundary, points, agents); 8 KiB is too tight.
const RECORD_MAX_BYTES: u64 = 64 * 1024;

/// The VERB-side precondition for a FRESH request: the capability layer's record shows a
/// handover WRITTEN and STAMPED for THIS session — and nothing more.
///
/// Why not the full readiness predicate here: `boundary.ready`/`boundary.committed` can only
/// be true after the Stop that ENDS the requesting turn (the capability layer's `boundaryReadyValid` requires
/// both, and requires the activity marker's nonce to be unmoved). A session asks for a fresh
/// relaunch mid-turn, when the last event is `PostToolUse`; checking the boundary here would
/// refuse every request by construction. The full predicate is re-run by the SUPERVISOR at the
/// quiet point — after the turn has ended and the Stop has committed — where it can pass.
///
/// Fixed tags only; no path and no record content ever leaves this function.
pub fn handover_written_at(config_dir: &Path, expected_session: &str) -> Result<(), Tag> {
    let raw = read_record_bounded(&config_dir.join(RECORD_FILE))?;
    let v: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| "recycle_handover_unreadable")?;
    let h = v
        .get("handover")
        .and_then(serde_json::Value::as_object)
        .ok_or("recycle_handover_unreadable")?;
    if h.get("state").and_then(serde_json::Value::as_str) != Some("written") {
        return Err("recycle_handover_not_written");
    }
    let sha = h
        .get("seed_sha256")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if sha.len() != 64
        || !sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("recycle_handover_not_stamped");
    }
    if h.get("session_id").and_then(serde_json::Value::as_str) != Some(expected_session) {
        return Err("recycle_handover_session_mismatch");
    }
    Ok(())
}

/// Bounded read of the capability layer's record. It is NOT csq's own file, so its mode is
/// the writer's (the capability layer writes these with the process umask — a real marker file measures
/// `-rw-r--r--`, and a `umask 002` host yields `-rw-rw-r--`), so requiring `0o600` here
/// would refuse every real system. What is still refused: a symlink (no-follow open), a
/// non-regular file, another owner, a record OTHER users could write (`0o002`), and one
/// past [`RECORD_MAX_BYTES`]. The GROUP-write case is accepted because the handle dir itself
/// can be group-writable under `umask 002`; the bound that makes it safe is the ACCOUNTS
/// ROOT, which `csq run` secures to `0o700` before the terminal dir is created
/// (`platform::fs::ensure_private_dir_root`, called from `cli::commands::run`), so no other
/// user can reach the file to exploit a group bit inside it.
fn read_record_bounded(path: &Path) -> Result<Vec<u8>, Tag> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Some(file) = open_nofollow(path).map_err(|_| "recycle_handover_unreadable")? else {
            return Err("recycle_handover_unreadable");
        };
        let meta = file.metadata().map_err(|_| "recycle_handover_unreadable")?;
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if !meta.file_type().is_file()
            || meta.len() > RECORD_MAX_BYTES
            || meta.uid() != euid
            || meta.mode() & 0o002 != 0
        {
            return Err("recycle_handover_unreadable");
        }
        let mut buf = Vec::new();
        file.take(RECORD_MAX_BYTES)
            .read_to_end(&mut buf)
            .map_err(|_| "recycle_handover_unreadable")?;
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        // Open FIRST, then fstat the opened handle: a check-then-open pair would let the
        // path be swapped between the two.
        let file = std::fs::File::open(path).map_err(|_| "recycle_handover_unreadable")?;
        let meta = file.metadata().map_err(|_| "recycle_handover_unreadable")?;
        if !meta.file_type().is_file() || meta.len() > RECORD_MAX_BYTES {
            return Err("recycle_handover_unreadable");
        }
        let mut buf = Vec::new();
        file.take(RECORD_MAX_BYTES)
            .read_to_end(&mut buf)
            .map_err(|_| "recycle_handover_unreadable")?;
        Ok(buf)
    }
}

/// `Ok` only when a LIVE `csq run` (pid + start time agree) supervises exactly
/// `claude_pid` AND this launch can be relaunched.
pub fn check_supervised(handle: &Path, claude_pid: u32) -> Result<(), Tag> {
    let marker: SupervisorMarker = match read_json_bounded(&handle.join(SUPERVISOR_FILE)) {
        Ok(Some(m)) => m,
        _ => return Err("recycle_unsupervised"),
    };
    let live = marker.v == 1
        && marker.child_pid == claude_pid
        && crate::sessions::process_start_time(marker.csq_pid)
            .is_some_and(|s| crate::sessions::same_start(s, marker.csq_start));
    if !live {
        return Err("recycle_unsupervised");
    }
    if marker.relaunch_ok {
        return Ok(());
    }
    Err(match marker.relaunch_tag.as_deref() {
        Some("recycle_argv_unclassifiable") => "recycle_argv_unclassifiable",
        Some("recycle_program_unresolved") => "recycle_program_unresolved",
        Some("recycle_launch_artifact_unreadable") => "recycle_launch_artifact_unreadable",
        Some("recycle_context_missing") => "recycle_context_missing",
        _ => "recycle_not_relaunchable",
    })
}

/// Refuses a new request while one is queued or in flight.
pub fn check_idle(handle: &Path) -> Result<(), Tag> {
    if handle.join(REQUEST_FILE).symlink_metadata().is_ok() {
        return Err("recycle_already_queued");
    }
    match read_result(handle) {
        Ok(Some(r)) if r.outcome.in_flight() => Err("recycle_in_flight"),
        Ok(_) => Ok(()),
        Err(_) => Err("recycle_in_flight"),
    }
}

/// Queues a request under the PER-TARGET CONSENT LOCK — the same lock the daemon's foreign
/// issue holds — so a self request and a foreign issue cannot both pass [`check_idle`] and then
/// overwrite each other. Whichever writes second sees the first request on disk and refuses:
/// that is the mechanism behind "a queued or in-flight recycle is never overwritten".
pub fn queue_request_locked(
    handle: &Path,
    id: &str,
    reason: &str,
    now: &str,
    mode: Mode,
) -> Result<(), Tag> {
    let _lock = crate::platform::lock::try_lock_file_bounded_nofollow(
        &super::recycle_consent::consent_lock_path(handle),
        50,
        std::time::Duration::from_millis(20),
    )
    .map_err(|_| "recycle_already_queued")?
    .ok_or("recycle_already_queued")?;
    check_idle(handle)?;
    write_request(handle, id, reason, now, mode)
}

// ── relaunch plan ──────────────────────────────────────────────────────────

/// How a claude option consumes the tokens after it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Arity {
    /// Boolean flag.
    Flag,
    /// Exactly one value token.
    Value,
    /// All following non-dash tokens (commander variadic).
    Variadic,
}

/// Options kept verbatim. This table is the ONLY set of options a recycle will replay;
/// anything else starting with `-` is unclassifiable (fail closed).
const KEEP: &[(&str, Arity)] = &[
    ("--verbose", Arity::Flag),
    ("--dangerously-skip-permissions", Arity::Flag),
    ("--allow-dangerously-skip-permissions", Arity::Flag),
    ("--ide", Arity::Flag),
    ("--strict-mcp-config", Arity::Flag),
    ("--no-session-persistence", Arity::Flag),
    ("--disable-slash-commands", Arity::Flag),
    ("--chrome", Arity::Flag),
    ("--no-chrome", Arity::Flag),
    ("--brief", Arity::Flag),
    ("--bare", Arity::Flag),
    ("--model", Arity::Value),
    ("--fallback-model", Arity::Value),
    ("--permission-mode", Arity::Value),
    ("--append-system-prompt", Arity::Value),
    ("--system-prompt", Arity::Value),
    ("--append-system-prompt-file", Arity::Value),
    ("--system-prompt-file", Arity::Value),
    ("--settings", Arity::Value),
    ("--setting-sources", Arity::Value),
    ("--agent", Arity::Value),
    ("--agents", Arity::Value),
    ("--plugin-dir", Arity::Value),
    ("--effort", Arity::Value),
    ("--name", Arity::Value),
    ("-n", Arity::Value),
    ("--max-turns", Arity::Value),
    ("--max-budget-usd", Arity::Value),
    ("--permission-prompt-tool", Arity::Value),
    ("--mcp-config", Arity::Variadic),
    ("--add-dir", Arity::Variadic),
    ("--allowed-tools", Arity::Variadic),
    ("--allowedTools", Arity::Variadic),
    ("--disallowed-tools", Arity::Variadic),
    ("--disallowedTools", Arity::Variadic),
    ("--tools", Arity::Variadic),
    ("--betas", Arity::Variadic),
    ("--file", Arity::Variadic),
];

/// Options stripped from a relaunch: they pick WHICH conversation (or fork it), which the
/// relaunch decides itself via `--resume <id>`. `-r/--resume` takes an optional value.
const STRIP: &[(&str, Arity)] = &[
    ("-c", Arity::Flag),
    ("--continue", Arity::Flag),
    ("--fork-session", Arity::Flag),
    ("--session-id", Arity::Value),
    ("-r", Arity::Value),
    ("--resume", Arity::Value),
];

fn lookup(table: &[(&str, Arity)], name: &str) -> Option<Arity> {
    table.iter().find(|(n, _)| *n == name).map(|(_, a)| *a)
}

/// The user's own claude arguments, reduced to what a relaunch may replay: known options
/// kept, conversation-selecting options stripped, positionals (the initial prompt)
/// DROPPED, `--` and everything after it dropped. An unknown option, a missing value, a
/// non-UTF-8 option name or `--opt=value` on a boolean flag is `Err` (fail closed).
pub fn classify_user_args(user: &[OsString]) -> Result<Vec<OsString>, Tag> {
    const BAD: Tag = "recycle_argv_unclassifiable";
    let mut out = Vec::new();
    let mut i = 0;
    while i < user.len() {
        let tok = &user[i];
        // A non-UTF-8 token cannot be classified as option, value or prompt: fail closed.
        let Some(s) = tok.to_str() else {
            return Err(BAD);
        };
        if s == "--" {
            break;
        }
        if !s.starts_with('-') || s == "-" {
            i += 1; // positional: dropped, never replayed
            continue;
        }
        let (name, inline) = match s.split_once('=') {
            Some((n, v)) if s.starts_with("--") => (n, Some(v)),
            _ => (s, None),
        };
        let (kept, arity) = match (lookup(KEEP, name), lookup(STRIP, name)) {
            (Some(a), _) => (true, a),
            (None, Some(a)) => (false, a),
            _ => return Err(BAD),
        };
        let mut taken: Vec<OsString> = vec![tok.clone()];
        i += 1;
        match (arity, inline) {
            (Arity::Flag, None) => {}
            (Arity::Flag, Some(_)) => return Err(BAD),
            (_, Some(_)) => {} // `--opt=value` is one token
            (Arity::Value, None) => {
                // `-r/--resume` may stand alone; every other Value option needs its value.
                let optional = matches!(name, "-r" | "--resume");
                match user.get(i) {
                    Some(v) if !optional || v.to_str().is_none_or(|t| !t.starts_with('-')) => {
                        taken.push(v.clone());
                        i += 1;
                    }
                    _ if optional => {}
                    _ => return Err(BAD),
                }
            }
            (Arity::Variadic, None) => {
                while let Some(v) = user.get(i) {
                    if v.to_str().is_some_and(|t| t.starts_with('-')) {
                        break;
                    }
                    taken.push(v.clone());
                    i += 1;
                }
                if taken.len() < 2 {
                    return Err(BAD);
                }
            }
        }
        if kept {
            out.extend(taken);
        }
    }
    Ok(out)
}

/// Everything needed to rebuild the launch: resolved program, csq's own prefix arguments,
/// and the classified user arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct RelaunchPlan {
    /// Absolute program path resolved at launch (never re-resolved through PATH later).
    pub program: PathBuf,
    /// csq-built arguments that precede the user's (`--mcp-config`, `--plugin-dir`, …).
    pub prefix: Vec<OsString>,
    /// The user's arguments after [`classify_user_args`].
    pub user: Vec<OsString>,
}

/// First absolute `PATH` entry holding an executable regular file named `program`.
pub fn resolve_program(program: &OsStr, path_env: Option<&OsStr>) -> Option<PathBuf> {
    let is_exec = |p: &Path| {
        let Ok(m) = std::fs::metadata(p) else {
            return false;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            m.is_file() && m.permissions().mode() & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            m.is_file()
        }
    };
    let direct = Path::new(program);
    if direct.is_absolute() {
        return is_exec(direct).then(|| direct.to_path_buf());
    }
    std::env::split_paths(path_env?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(program))
        .find(|c| is_exec(c))
}

/// Builds the plan from the launch `spec` and the user's raw `rest`. `spec`'s arguments must
/// END with `user_rest` (csq appends them last); otherwise the split is unknowable ⇒ `Err`.
pub fn build_plan(spec: &Command, user_rest: &[OsString]) -> Result<RelaunchPlan, Tag> {
    let args: Vec<OsString> = spec.get_args().map(OsString::from).collect();
    if args.len() < user_rest.len() || args[args.len() - user_rest.len()..] != *user_rest {
        return Err("recycle_argv_unclassifiable");
    }
    let user = classify_user_args(user_rest)?;
    let path_env = spec
        .get_envs()
        .find(|(k, _)| *k == OsStr::new("PATH"))
        .map(|(_, v)| v.map(OsString::from))
        .unwrap_or_else(|| std::env::var_os("PATH"));
    let program = resolve_program(spec.get_program(), path_env.as_deref())
        .ok_or("recycle_program_unresolved")?;
    Ok(RelaunchPlan {
        program,
        prefix: args[..args.len() - user_rest.len()].to_vec(),
        user,
    })
}

/// What a FRESH relaunch needs from the capability layer (the capability layer's terminal
/// context-state record and its readiness verdict).
///
/// The prompt is FIXED TEXT and carries no seed content: the model must never be
/// handed a path to model-authored text and told to read it, which would bypass
/// hashing, schema, age and DATA framing. The seed itself reaches the new session
/// through the capability layer's own injector, as validated data.
///
/// The proof (one `COC_RECYCLE_PROOF` value: `v1,<seed_sha256>,<resume_token>,<session_id>,<issued_at>`)
/// travels in `env` — NEVER in argv: argv is world-readable through `ps`, and a resume token there is a
/// disclosure. `env` entries are added on top of the carried launch map, after
/// `env_clear`, so the fresh child sees exactly them and the launch's own map.
#[derive(Debug, Clone, PartialEq)]
pub struct FreshContext {
    /// The single positional prompt appended to the relaunch argv.
    pub prompt: OsString,
    /// Environment entries carrying the proof. Never argv.
    pub env: Vec<(OsString, OsString)>,
}

/// The FIXED positional prompt of a fresh relaunch (the capability layer's route-B contract, accepted 2026-11-04).
/// It carries no seed content and names no path: the model must never be handed a path to
/// model-authored text and told to read it, which would bypass hashing, schema, age and DATA
/// framing. The seed reaches the new session through the capability layer's own injector.
pub const FRESH_PROMPT: &str = "Context recycle: continue from the handover seed injected at session start. If no seed was injected, say so in one line and wait.";

/// The ONE environment variable a fresh relaunch adds (the capability layer's contract (b)). It binds by seed
/// SHA-256, never by path, and is not a secret; it still never goes in argv, which `ps` exposes.
pub const PROOF_ENV: &str = "COC_RECYCLE_PROOF";

/// Where the capability layer's readiness CLI lives, relative to the TARGET's project root.
const READINESS_CLI_REL: &str = ".claude/bin/recycle-readiness.mjs";
/// The one schema a readiness line may declare.
const READINESS_SCHEMA: &str = "coc-recycle-readiness/v1";
/// The readiness CLI is killed at this deadline; a hung CLI is NOT ready.
const READINESS_KILL: Duration = Duration::from_secs(10);
/// A readiness line is one short JSON object; anything larger is not one.
const READINESS_CAP: u64 = 64 * 1024;

/// Whether the capability layer's route-B proof contract (W1–W6) has LANDED.
///
/// `false` until BOTH hold: the capability layer's cycle-fence (the consumer-side `context-meter.js` +
/// `context-boundary.js`) is on its dev branch — the flip-back commit names that landed sha — and W7,
/// the real-relaunch measurement against those landed artifacts, has passed. While it is
/// `false`, [`fresh_context_at`] refuses with `recycle_fresh_context_unavailable`, so a fresh
/// relaunch can never run against a half-installed capability layer; in a consumer repo the
/// verb would otherwise ship enabled and refuse every time. `true` only opened the seam for the
/// W7 measurement itself (`f7222d49b`); this constant is that experiment's off-switch. The
/// constant selects the seam only: both call sites already route through [`fresh_context_at`],
/// so no logic changes.
const LOOM_RECYCLE_CONTRACT_LANDED: bool = false;

/// The real readiness resolution, at an explicitly named terminal.
///
/// `project_root` is the TARGET project's root (the readiness CLI lives under it) and
/// `config_dir` is the TARGET terminal's absolute config dir — never the requester's.
/// `expected_session` is the OLD session id the proof must name.
///
/// Every failure is a fixed tag; nothing here reads the capability layer's record, and the proof string is passed
/// through after a structural check only.
pub fn fresh_context_at(
    project_root: &Path,
    config_dir: &Path,
    expected_session: &str,
) -> Result<FreshContext, Tag> {
    if !LOOM_RECYCLE_CONTRACT_LANDED {
        return Err("recycle_fresh_context_unavailable");
    }
    let path = std::env::var_os("PATH");
    resolve_fresh_context(
        project_root,
        config_dir,
        expected_session,
        path.as_deref(),
        READINESS_KILL,
    )
}

/// [`fresh_context_at`] with the PATH used to find `node` and the kill deadline supplied, so a
/// test can drive the real invocation without mutating the process environment or waiting 10 s.
fn resolve_fresh_context(
    project_root: &Path,
    config_dir: &Path,
    expected_session: &str,
    path_env: Option<&OsStr>,
    kill_after: Duration,
) -> Result<FreshContext, Tag> {
    // Relative inputs would make `current_dir` and the CLI path disagree with what we report.
    if !project_root.is_absolute() || !config_dir.is_absolute() {
        return Err("recycle_readiness_malformed");
    }
    let cli = project_root.join(READINESS_CLI_REL);
    // A missing capability layer is NOT ready — a fixed tag, never a spawn attempt.
    if !cli.is_file() {
        return Err("recycle_readiness_cli_missing");
    }
    let (code, stdout) = run_readiness(&cli, project_root, config_dir, path_env, kill_after)?;
    parse_readiness(code, &stdout, expected_session)
}

/// Runs the readiness CLI and returns `(exit code, stdout)`.
///
/// Contract (c): argv only, `cwd` = the target project root, an EMPTY environment plus HOME and
/// PATH, and a hard kill at the deadline. The proof does not exist yet, so it is not passed here.
fn run_readiness(
    cli: &Path,
    project_root: &Path,
    config_dir: &Path,
    path_env: Option<&OsStr>,
    kill_after: Duration,
) -> Result<(i32, Vec<u8>), Tag> {
    let node = resolve_program(OsStr::new("node"), path_env).ok_or("recycle_readiness_failed")?;
    let mut cmd = Command::new(&node);
    // EMPTY environment plus HOME and PATH, exactly as the contract states: the readiness CLI
    // must not inherit csq's own variables (an account or credential env would leak into it).
    cmd.env_clear();
    if let Some(home) = std::env::var_os("HOME") {
        cmd.env("HOME", home);
    }
    if let Some(path) = path_env {
        cmd.env("PATH", path);
    }
    cmd.arg(cli)
        .arg("--config-dir")
        .arg(config_dir)
        .current_dir(project_root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    // Its own process group, so a hung CLI is killed as a GROUP: a grandchild that inherited
    // the stdout pipe cannot outlive the deadline (the same shape as
    // `cli_deps::cli_shim::run_bounded`).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    // A transient ETXTBSY ("Text file busy") is retried within SPAWN_BUSY_BUDGET: in production
    // the executable is the real `node`, so the error means something was writing it while csq
    // launched it (an upgrade landing mid-launch). Every other error, and an exhausted budget,
    // keep the fixed tag.
    let mut child =
        match spawn_busy_retrying(&mut cmd, SPAWN_BUSY_BUDGET, SPAWN_BUSY_DELAY, &mut |_| {}) {
            Ok(child) => child,
            Err(_) => return Err("recycle_readiness_failed"),
        };
    // The reader reports through a channel so every wait below is deadline-bounded, even when
    // something other than the CLI holds the pipe open.
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    if let Some(out) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.take(READINESS_CAP).read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
    }
    let deadline = std::time::Instant::now() + kill_after;
    // Read the VERDICT first. Reaping the leader (`try_wait`/`wait`) frees its pid and with it
    // the process-group id we created (`process_group(0)`), so the group kill below must happen
    // while the leader is still unreaped. No wait call may run before the pipe closes or the
    // deadline fires — otherwise a grandchild that inherited stdout outlives the deadline with
    // no safe way to reach it (spec 36.10: "killed at 10 s in its own process group").
    let out = loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(left.min(Duration::from_millis(20))) {
            Ok(buf) => break buf,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if std::time::Instant::now() >= deadline {
                    kill_live_group(&mut child);
                    return Err("recycle_readiness_timeout");
                }
            }
            // The reader vanished without a buffer: no verdict we can trust.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                kill_live_group(&mut child);
                return Err("recycle_readiness_failed");
            }
        }
    };
    // The pipe closing means no stdout WRITER is left — NOT that the leader exited: a CLI may
    // close fd 1 and keep running, and `Take` also returns at the cap while it writes on. The
    // reap is therefore bounded by the SAME deadline, and an overrun kills the group exactly as
    // the timeout arm above does; only a reaped leader may produce a verdict.
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            // A wait that cannot reap must not abandon a running CLI and its open pipe: the
            // group is killed first, exactly as the deadline arm does.
            Err(_) => {
                kill_live_group(&mut child);
                return Err("recycle_readiness_failed");
            }
        }
        if std::time::Instant::now() >= deadline {
            kill_live_group(&mut child);
            return Err("recycle_readiness_timeout");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    match status.code() {
        Some(code) => Ok((code, out)),
        // Killed or stopped by a signal: not a verdict we can read.
        None => Err("recycle_readiness_failed"),
    }
}

/// The whole time a spawn may lose to transient `ETXTBSY` retries. The elapsed check runs
/// BETWEEN attempts, so one final attempt may overrun this by its own duration; the budget
/// bounds the wait, not a single syscall.
const SPAWN_BUSY_BUDGET: Duration = Duration::from_millis(100);
/// The pause between `ETXTBSY` attempts.
const SPAWN_BUSY_DELAY: Duration = Duration::from_millis(5);

/// Spawns `cmd`, retrying ONLY a transient `ETXTBSY` ("Text file busy") while `budget` remains,
/// pausing `delay` between attempts.
///
/// In production the executable is a REAL installed program (the `node` that runs the readiness
/// CLI, or the `claude` of a relaunch), so `ETXTBSY` means something was writing that executable
/// while csq launched it — the main real trigger is an upgrade of that program landing
/// mid-launch. This retry is a bounded TOLERANCE for that moment, not a claim that the race is
/// common. (In a parallel test binary the same error also arises from a concurrent `fork`
/// inheriting a sibling test's write descriptor.)
///
/// The retry re-resolves nothing itself, but each attempt re-enters `spawn`, so a writer that
/// closes mid-window can be followed by an exec of a file that is still a torn image: that fails
/// exec and keeps the caller's fixed tag. Every non-busy error is returned unchanged.
///
/// `on_attempt` is called with 1, 2, … immediately BEFORE each attempt, so a test can release a
/// held writer deterministically between attempts (production passes a no-op).
fn spawn_busy_retrying(
    cmd: &mut std::process::Command,
    budget: Duration,
    delay: Duration,
    on_attempt: &mut dyn FnMut(u32),
) -> std::io::Result<std::process::Child> {
    let start = std::time::Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        on_attempt(attempt);
        match cmd.spawn() {
            Ok(child) => return Ok(child),
            Err(e) if is_exec_busy(&e) && start.elapsed() < budget => {
                std::thread::sleep(delay);
            }
            Err(e) => return Err(e),
        }
    }
}

/// The RELAUNCH spawn of a session, with the same bounded `ETXTBSY` tolerance as a readiness
/// spawn — and for a sharper reason: it runs AFTER the old child is stopped, so losing it to a
/// transient writer (a `claude` upgrade landing mid-relaunch) leaves a DEAD session instead of a
/// refused gate. `on_attempt` exists for the same deterministic test hook as
/// [`spawn_busy_retrying`].
///
/// Unix-only, like every caller (the supervise/relaunch path is a Unix lifecycle); a non-unix
/// build has no relaunch to spawn.
#[cfg(unix)]
pub(super) fn spawn_relaunch(
    cmd: &mut std::process::Command,
    on_attempt: &mut dyn FnMut(u32),
) -> std::io::Result<std::process::Child> {
    spawn_busy_retrying(cmd, SPAWN_BUSY_BUDGET, SPAWN_BUSY_DELAY, on_attempt)
}

/// Whether `e` is the transient "Text file busy" spawn failure (`ETXTBSY`).
fn is_exec_busy(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::ETXTBSY)
    }
    #[cfg(not(unix))]
    {
        let _ = e;
        false
    }
}

/// Kills the readiness child's whole process group, then reaps the leader.
///
/// The only caller is [`run_readiness`]'s deadline arm, where NO wait call has run yet: the
/// leader is unreaped. That is what makes `-pgid` safe — an already-exited leader is still a
/// zombie, which pins the pgid against reuse — and what lets the kill reach a grandchild that
/// inherited stdout and would otherwise hold the pipe past the deadline.
fn kill_live_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    let pgid = child.id() as i32;
    let _ = child.kill();
    #[cfg(unix)]
    {
        // SAFETY: the leader has not been reaped on this path (the pipe read never calls
        // `wait`), so `-pgid` still names the group we created with `process_group(0)`.
        // A kill on a vanished group is ESRCH, which we ignore.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    let _ = child.wait();
}

/// The pure half: one JSON line in, a context or a fixed tag out.
///
/// The verdict and the exit code must AGREE (contract (c): 0 ready / 1 not-ready / 2 unknown);
/// a disagreement is a producer we cannot classify, so it is malformed rather than "probably fine".
fn parse_readiness(code: i32, stdout: &[u8], expected_session: &str) -> Result<FreshContext, Tag> {
    const MALFORMED: Tag = "recycle_readiness_malformed";
    let text = std::str::from_utf8(stdout).map_err(|_| MALFORMED)?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let line = lines.next().ok_or(MALFORMED)?;
    // "ONE JSON line": a second line means we would be guessing which answer counts.
    if lines.next().is_some() {
        return Err(MALFORMED);
    }
    let v: serde_json::Value = serde_json::from_str(line).map_err(|_| MALFORMED)?;
    if v.get("schema").and_then(|s| s.as_str()) != Some(READINESS_SCHEMA) {
        return Err(MALFORMED);
    }
    let verdict = v.get("verdict").and_then(|s| s.as_str()).ok_or(MALFORMED)?;
    match (code, verdict) {
        (0, "ready") => {
            let proof = v.get("proof").and_then(|s| s.as_str()).ok_or(MALFORMED)?;
            let proof = validate_proof(proof, expected_session)?;
            Ok(FreshContext {
                prompt: OsString::from(FRESH_PROMPT),
                env: vec![(OsString::from(PROOF_ENV), OsString::from(proof))],
            })
        }
        (1, "not-ready") => Err("recycle_not_ready"),
        (2, "unknown") => Err("recycle_readiness_unknown"),
        (c, _) if !(0..=2).contains(&c) => Err("recycle_readiness_failed"),
        _ => Err(MALFORMED),
    }
}

/// The strict proof pattern: `v1,<seed_sha256>,<resume_token>,<session_id>,<issued_at>`.
///
/// Structural only — csq never parses the capability layer's record. The `session_id` field MUST name the session
/// being relaunched, so a proof minted for another conversation can never ride this relaunch.
///
/// `pub(super)` so the supervisor can ASSERT the invariant instead of trusting the hook: a fresh
/// context that cannot carry a valid proof must never be exec'd (spec 36.10).
pub(super) fn validate_proof(proof: &str, expected_session: &str) -> Result<String, Tag> {
    const INVALID: Tag = "recycle_proof_invalid";
    let parts: Vec<&str> = proof.split(',').collect();
    let [version, sha, token, session, issued] = parts.as_slice() else {
        return Err(INVALID);
    };
    if *version != "v1" {
        return Err(INVALID);
    }
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(INVALID);
    }
    // Printable, bounded, and comma-free (the split above already guarantees the last).
    if token.is_empty() || token.len() > 256 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(INVALID);
    }
    if *session != expected_session {
        return Err(INVALID);
    }
    // Unix seconds or RFC 3339; the TTL itself is the capability layer's to enforce (it mints and consumes).
    if (*issued).parse::<i64>().is_err() && chrono::DateTime::parse_from_rfc3339(issued).is_err() {
        return Err(INVALID);
    }
    Ok(proof.to_string())
}

/// The relaunch argv (without the program). Pure.
///
/// `fresh: Some(ctx)` appends exactly one positional prompt and NO
/// conversation-selecting flag (`--resume`, `-r`, `--continue`, `--session-id`,
/// `--fork-session` are already stripped by [`classify_user_args`]). `None` is the
/// original resume behaviour, unchanged.
pub fn relaunch_argv(
    plan: &RelaunchPlan,
    session_id: &str,
    fresh: Option<&FreshContext>,
) -> Vec<OsString> {
    let mut v = plan.prefix.clone();
    v.extend(plan.user.iter().cloned());
    match fresh {
        Some(ctx) => v.push(ctx.prompt.clone()),
        None => {
            v.push(OsString::from("--resume"));
            v.push(OsString::from(session_id));
        }
    }
    v
}

/// The same env and cwd as `spec`, the plan's resolved program and [`relaunch_argv`].
///
/// The relaunch child starts from an EMPTY environment, exactly as the first
/// child did (`X1Launch::apply_to_command`): `spec` already carries the
/// post-scrub map, and a key the scrub REMOVED is simply absent from that map —
/// so copying the map without clearing first would re-admit it by inheritance
/// from csq's own environment.
pub fn relaunch_command(
    spec: &Command,
    plan: &RelaunchPlan,
    session_id: &str,
    fresh: Option<&FreshContext>,
) -> Command {
    let mut cmd = Command::new(&plan.program);
    cmd.env_clear();
    cmd.args(relaunch_argv(plan, session_id, fresh));
    for (k, v) in spec.get_envs() {
        match v {
            Some(v) => {
                cmd.env(k, v);
            }
            None => {
                cmd.env_remove(k);
            }
        }
    }
    // The fresh proof rides on the environment (never argv, which `ps` exposes),
    // applied after the carried map so it wins for its own keys.
    if let Some(ctx) = fresh {
        for (k, v) in &ctx.env {
            cmd.env(k, v);
        }
    }
    if let Some(d) = spec.get_current_dir() {
        cmd.current_dir(d);
    }
    cmd
}

/// an internal ticket: re-ensure the relaunched child's per-session `TMPDIR` and set it
/// explicitly, overriding whatever the carried spec holds.
///
/// [`relaunch_command`] replays the first child's env map verbatim, but a
/// session's `tmp/` can be removed mid-session (a user clearing temp space is
/// the population an internal ticket serves). A relaunch MUST therefore re-create and
/// re-verify it before the child starts — the same "created before the child
/// starts" contract every first launch meets — and refuse with the fixed tag
/// rather than exec with an unverified temp dir. Setting the value explicitly
/// also gives a session launched before an internal ticket (whose spec has no `TMPDIR`) the
/// per-session dir on its first relaunch.
pub fn relaunch_with_session_tmpdir(handle_dir: &Path, mut cmd: Command) -> Result<Command, Tag> {
    let tmp = crate::session::tmpdir::ensure_session_tmpdir(handle_dir)?;
    cmd.env("TMPDIR", tmp);
    Ok(cmd)
}

/// The X1 guard-manifest check at the recycle SPAWN instant. `handle_dir.parent()`
/// is the accounts root (`launch_x1::plan`'s `base_dir`); `repo_root` is the
/// child's cwd, with the same fail-closed fallback as `launch_x1::plan`. A
/// manifest that is present and not `verified` refuses the relaunch: the gate
/// check ran before the stop, and a same-uid writer could change a guarded file
/// in the stop-to-spawn window that `verify_artifacts` does not cover.
pub fn guard_manifest_refusal(handle_dir: &Path, repo_root: &Path) -> Result<(), Tag> {
    let Some(base_dir) = handle_dir.parent() else {
        return Err("recycle_guard_manifest_refused");
    };
    match crate::launch_isolation::verify_manifest(base_dir, handle_dir, repo_root) {
        crate::launch_isolation::ManifestCheck::Verified
        | crate::launch_isolation::ManifestCheck::Absent => Ok(()),
        crate::launch_isolation::ManifestCheck::Mismatch { .. }
        | crate::launch_isolation::ManifestCheck::Invalid { .. } => {
            Err("recycle_guard_manifest_refused")
        }
    }
}

// ── launch artifacts ───────────────────────────────────────────────────────

/// A csq-owned file the launch argv points at, recorded at launch so a relaunch days later
/// re-reads exactly what the first launch did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchArtifact {
    path: PathBuf,
    len: u64,
    sha256: [u8; 32],
}

const ARTIFACT_FLAGS: &[&str] = &[
    "--append-system-prompt-file",
    "--system-prompt-file",
    "--settings",
    "--mcp-config",
];

fn hash_regular_file(path: &Path) -> Result<(u64, [u8; 32]), Tag> {
    const BAD: Tag = "recycle_launch_artifact_unreadable";
    #[cfg(unix)]
    let mut f = open_nofollow(path).map_err(|_| BAD)?.ok_or(BAD)?;
    #[cfg(not(unix))]
    let mut f = std::fs::File::open(path).map_err(|_| BAD)?;
    let meta = f.metadata().map_err(|_| BAD)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
            return Err(BAD); // not ours, or group/other-writable
        }
    }
    if !meta.file_type().is_file() || meta.len() > 64 * 1024 * 1024 {
        return Err(BAD);
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|_| BAD)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((total, hasher.finalize().into()))
}

/// Records every file named by an artifact flag in `prefix` (inline JSON values are skipped).
pub fn record_artifacts(prefix: &[OsString]) -> Result<Vec<LaunchArtifact>, Tag> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < prefix.len() {
        if prefix[i]
            .to_str()
            .is_some_and(|f| ARTIFACT_FLAGS.contains(&f))
        {
            let value = &prefix[i + 1];
            if !value
                .to_str()
                .is_some_and(|v| v.trim_start().starts_with('{'))
            {
                let path = PathBuf::from(value);
                let (len, sha256) = hash_regular_file(&path)?;
                out.push(LaunchArtifact { path, len, sha256 });
            }
            i += 1;
        }
        i += 1;
    }
    Ok(out)
}

/// Every recorded artifact must still be the same regular file with the same bytes.
pub fn verify_artifacts(recorded: &[LaunchArtifact]) -> Result<(), Tag> {
    for a in recorded {
        match hash_regular_file(&a.path) {
            Ok((len, sha)) if len == a.len && sha == a.sha256 => {}
            _ => return Err("recycle_launch_artifact_changed"),
        }
    }
    Ok(())
}

/// Current `(len, sha256)` of every recorded artifact path (or the failure tag).
pub fn snapshot_artifacts(recorded: &[LaunchArtifact]) -> Vec<Result<(u64, [u8; 32]), Tag>> {
    recorded
        .iter()
        .map(|a| hash_regular_file(&a.path))
        .collect()
}

/// Reconciles the launch record with a gate re-run. `before`/`after` are snapshots taken
/// around the gates: an artifact the gates themselves rewrote (it changed between the two) is
/// re-recorded from the gates' own write; one that did NOT change during the gates must still
/// equal the launch record, else something else changed it (`recycle_launch_artifact_changed`).
pub fn reconcile_artifacts(
    recorded: &[LaunchArtifact],
    before: &[Result<(u64, [u8; 32]), Tag>],
    after: &[Result<(u64, [u8; 32]), Tag>],
) -> Result<Vec<LaunchArtifact>, Tag> {
    const BAD: Tag = "recycle_launch_artifact_changed";
    if before.len() != recorded.len() || after.len() != recorded.len() {
        return Err(BAD);
    }
    let mut out = Vec::with_capacity(recorded.len());
    for (i, a) in recorded.iter().enumerate() {
        match (&before[i], &after[i]) {
            (b, af) if b == af => match af {
                Ok((len, sha)) if *len == a.len && *sha == a.sha256 => out.push(a.clone()),
                _ => return Err(BAD),
            },
            (_, Ok((len, sha))) => out.push(LaunchArtifact {
                path: a.path.clone(),
                len: *len,
                sha256: *sha,
            }),
            _ => return Err(BAD),
        }
    }
    Ok(out)
}

// ── session binding ────────────────────────────────────────────────────────

/// Source of truth for "which conversation does this claude process run".
pub trait SessionProbe {
    /// The session id Claude Code's own registry records for `pid`. With `handle` the process's
    /// `CLAUDE_CONFIG_DIR` must also be that handle dir.
    fn session_id_of(&self, pid: u32, handle: Option<&Path>) -> Result<String, Tag>;
    /// Whether ANY other live claude process holds `session_id`.
    fn held_by_other(&self, session_id: &str, own_pid: u32) -> Result<bool, Tag>;
}

/// [`SessionProbe`] over Claude Code's registry ([`crate::sessions::lifecycle::registry_session_id`]).
#[cfg(unix)]
pub struct RegistryProbe {
    /// csq base dir (`~/.claude/accounts`).
    pub base: PathBuf,
    /// Home dir holding `.claude/sessions`.
    pub home: PathBuf,
}

#[cfg(unix)]
impl SessionProbe for RegistryProbe {
    fn session_id_of(&self, pid: u32, handle: Option<&Path>) -> Result<String, Tag> {
        crate::sessions::lifecycle::registry_session_id(pid, &self.base, &self.home, handle)
            .ok_or("recycle_session_unknown")
    }
    fn held_by_other(&self, session_id: &str, own_pid: u32) -> Result<bool, Tag> {
        const INCOMPLETE: Tag = "recycle_session_enumeration_incomplete";
        let listing = crate::sessions::try_list_detailed_kind(crate::sessions::CliKind::Claude)
            .ok_or(INCOMPLETE)?;
        if listing.incomplete || !listing.unreadable_pids.is_empty() || listing.restricted {
            return Err(INCOMPLETE);
        }
        for s in listing.sessions.iter().filter(|s| s.pid != own_pid) {
            let entry = match crate::sessions::lifecycle::registry_entry_present(s.pid, &self.home)
            {
                Ok(false) => EntryState::Absent,
                Ok(true) => EntryState::Present(crate::sessions::lifecycle::registry_session_id(
                    s.pid, &self.base, &self.home, None,
                )),
                Err(_) => EntryState::Unreadable,
            };
            if holder_verdict(entry, session_id)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// What the registry says about one other claude process.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryState {
    /// No registry entry exists at all.
    Absent,
    /// An entry exists; `Some(id)` when it validated, `None` when it could not be validated.
    Present(Option<String>),
    /// Existence itself could not be determined.
    Unreadable,
}

/// `Ok(true)` when the entry holds `session_id`. Only a TRULY absent entry means "holds nothing"
/// (same-user trust assumption, spec 36 §36.6: the registry is the user's own file, so a process
/// that never wrote one cannot be shown to hold the session). An entry that exists but cannot be
/// validated, or whose existence is unknown, may be this very session: fail closed.
#[cfg(unix)]
pub fn holder_verdict(entry: EntryState, session_id: &str) -> Result<bool, Tag> {
    match entry {
        EntryState::Absent => Ok(false),
        EntryState::Present(Some(other)) => Ok(other.eq_ignore_ascii_case(session_id)),
        EntryState::Present(None) | EntryState::Unreadable => {
            Err("recycle_session_enumeration_incomplete")
        }
    }
}

/// `Ok` only when `requested` is exactly the session the child `pid` runs and no other
/// live claude process holds it. Unknown ⇒ `Err` ⇒ no kill.
pub fn verify_session_binding(
    probe: &dyn SessionProbe,
    pid: u32,
    handle: &Path,
    requested: &str,
) -> Result<(), Tag> {
    let bound = probe.session_id_of(pid, Some(handle))?;
    if !bound.eq_ignore_ascii_case(requested) {
        return Err("recycle_session_id_mismatch");
    }
    if probe.held_by_other(requested, pid)? {
        return Err("recycle_session_id_shared");
    }
    Ok(())
}

// ── quiescence ─────────────────────────────────────────────────────────────

/// Quiet-point constants. The enforced mechanism for each is [`wait_for_quiet`].
#[derive(Debug, Clone, Copy)]
pub struct QuietParams {
    /// The main and every subagent transcript must each be unmodified for at least this long.
    pub dwell: Duration,
    /// Poll cadence.
    pub poll: Duration,
    /// Give up after this long.
    pub max_wait: Duration,
}

impl Default for QuietParams {
    fn default() -> Self {
        Self {
            dwell: Duration::from_secs(15),
            poll: Duration::from_secs(1),
            max_wait: Duration::from_secs(600),
        }
    }
}

/// Positive evidence about the turn, read from the main transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    /// The last conversation entry is an assistant message with `stop_reason: "end_turn"`
    /// and no `tool_use` block, followed only by bookkeeping entries.
    Ended,
    /// Anything else, with a fixed reason.
    Busy(&'static str),
}

/// Bookkeeping entry types Claude Code appends AFTER a finished assistant message, MEASURED
/// on real transcripts (spec 36 §36.6): `attachment`, `system` (stop-hook summary / turn
/// duration), `cost-state`, `agent-setting`, `last-prompt`, `mode`, `permission-mode`,
/// `ai-title`, `pr-link`, `atis-latch`, `isolation-latch`, `frame-link`, `tools-used`, `file-history-*`. `queue-operation` is
/// handled separately (queue depth); any other trailing type (notably `api-request*`, which
/// starts the NEXT turn) means busy.
const TRAILING_OK: &[&str] = &[
    "attachment",
    "system",
    "cost-state",
    "agent-setting",
    "last-prompt",
    "mode",
    "permission-mode",
    "ai-title",
    "pr-link",
    "atis-latch",
    "isolation-latch",
    "frame-link",
    "tools-used",
    "file-history-snapshot",
    "file-history-delta",
];

/// Classifies the end of a transcript. `tail` is the last bytes of the file;
/// `from_start` says whether `tail` begins at byte 0 (else the first line is partial and
/// ignored). Evidence: the main transcript `<projects>/<slug>/<session>.jsonl` is
/// append-only JSONL; an `assistant` entry with `message.stop_reason` `end_turn` (or
/// `stop_sequence`) and no `tool_use` content block is Claude's own record that the model
/// finished its turn and awaits the user. After it only the `TRAILING_OK` bookkeeping types and a
/// BALANCED `queue-operation` (`enqueue` cancelled by `remove`) are allowed: a pending
/// `enqueue` is queued user input, a `dequeue`, `api-request*`, `user` entry or unknown type
/// means the next turn started. A `tool_use` is an unanswered tool call. A torn or
/// unparsable trailing line is a write in progress ⇒ busy. No conversation entry in the
/// tail ⇒ `Err`.
pub fn turn_state(tail: &[u8], from_start: bool) -> Result<TurnState, Tag> {
    let mut lines: Vec<&[u8]> = tail.split(|b| *b == b'\n').collect();
    // The final element is what follows the last newline: non-empty = torn write.
    if lines.pop().is_some_and(|l| !l.is_empty()) {
        return Ok(TurnState::Busy("torn_tail"));
    }
    if !from_start && !lines.is_empty() {
        lines.remove(0);
    }
    let mut trailing: Vec<serde_json::Value> = Vec::new();
    for raw in lines.iter().rev().filter(|l| !l.is_empty()) {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) else {
            return Ok(TurnState::Busy("unparsable_tail"));
        };
        let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if v.get("isSidechain").and_then(|b| b.as_bool()) == Some(true) {
            continue; // subagent traffic is not the main turn
        }
        if ty == "user" {
            return Ok(TurnState::Busy("user_entry_last"));
        }
        if ty != "assistant" {
            trailing.push(v);
            continue;
        }
        let msg = v.get("message");
        let stop = msg
            .and_then(|m| m.get("stop_reason"))
            .and_then(|s| s.as_str());
        let has_tool_use = msg
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .is_some_and(|c| {
                c.iter()
                    .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
            });
        if has_tool_use {
            return Ok(TurnState::Busy("tool_use_pending"));
        }
        if !matches!(stop, Some("end_turn" | "stop_sequence")) {
            return Ok(TurnState::Busy("not_end_turn"));
        }
        let mut depth = 0usize;
        for e in trailing.iter().rev() {
            let ety = e.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if ety == "queue-operation" {
                match e.get("operation").and_then(|o| o.as_str()) {
                    Some("enqueue") => depth += 1,
                    Some("remove") => depth = depth.saturating_sub(1),
                    _ => return Ok(TurnState::Busy("next_turn_started")),
                }
                continue;
            }
            let queued_attachment = ety == "attachment"
                && e.get("attachment")
                    .and_then(|a| a.get("type"))
                    .and_then(|t| t.as_str())
                    == Some("queued_command");
            if queued_attachment || !TRAILING_OK.contains(&ety) {
                return Ok(TurnState::Busy("next_turn_started"));
            }
        }
        return Ok(if depth > 0 {
            TurnState::Busy("input_queued")
        } else {
            TurnState::Ended
        });
    }
    Err("recycle_turn_state_unknown")
}

/// Reads the transcript tail and classifies it with [`turn_state`].
pub fn read_turn_state(path: &Path) -> Result<TurnState, Tag> {
    const BAD: Tag = "recycle_turn_state_unknown";
    #[cfg(unix)]
    let mut f = open_nofollow(path)?.ok_or(BAD)?;
    #[cfg(not(unix))]
    let mut f = std::fs::File::open(path).map_err(|_| BAD)?;
    let len = f.metadata().map_err(|_| BAD)?.len();
    let start = len.saturating_sub(TRANSCRIPT_TAIL_BYTES);
    f.seek(SeekFrom::Start(start)).map_err(|_| BAD)?;
    let mut buf = Vec::new();
    f.take(TRANSCRIPT_TAIL_BYTES)
        .read_to_end(&mut buf)
        .map_err(|_| BAD)?;
    turn_state(&buf, start == 0)
}

/// Injected clock and probes for [`wait_for_quiet`].
pub trait QuietProbe {
    /// Time since the wait began.
    fn elapsed(&self) -> Duration;
    /// Advance (really or virtually) by `d`.
    fn sleep(&mut self, d: Duration);
    /// Whether the child is still running.
    fn child_alive(&mut self) -> bool;
    /// Age of the main transcript's last modification.
    fn transcript_age(&mut self) -> Result<Duration, Tag>;
    /// Positive turn-end evidence from the main transcript.
    fn turn_state(&mut self) -> Result<TurnState, Tag>;
    /// Age of the most recently modified subagent transcript (large when none).
    fn subagent_age(&mut self) -> Result<Duration, Tag>;
    /// The child's current descendants as `(pid, start time)`.
    fn descendants(&mut self) -> Result<Vec<(u32, u64)>, Tag>;
}

/// Result of [`wait_for_quiet`].
#[derive(Debug, PartialEq, Eq)]
pub enum QuietOutcome {
    /// Turn positively ended and nothing new is running, for the whole dwell.
    Quiet,
    /// The cap elapsed first.
    TimedOut,
    /// The child exited while waiting.
    ChildExited,
    /// A probe could not be read: fail toward not recycling.
    Unresolved(Tag),
}

/// Waits for the quiet point. Quiet = ALL of: the main transcript says the turn ENDED
/// ([`turn_state`]); the main and every subagent transcript are unmodified for `dwell`
/// (the dwell therefore starts at the turn-end evidence, so a recycle requested during a turn
/// happens `dwell` after that turn ends, not a long idle window later); and no live
/// descendant exists that is not in `baseline` (the set seen at launch settle, before any
/// turn: MCP servers). Absence of CPU is never consulted. Bounded by `max_wait`.
pub fn wait_for_quiet(
    p: &mut dyn QuietProbe,
    q: &QuietParams,
    baseline: &HashSet<(u32, u64)>,
) -> QuietOutcome {
    loop {
        if !p.child_alive() {
            return QuietOutcome::ChildExited;
        }
        let now = p.elapsed();
        let state = match p.turn_state() {
            Ok(s) => s,
            Err(t) => return QuietOutcome::Unresolved(t),
        };
        let main_age = match p.transcript_age() {
            Ok(a) => a,
            Err(t) => return QuietOutcome::Unresolved(t),
        };
        let sub_age = match p.subagent_age() {
            Ok(a) => a,
            Err(t) => return QuietOutcome::Unresolved(t),
        };
        let desc = match p.descendants() {
            Ok(d) => d,
            Err(t) => return QuietOutcome::Unresolved(t),
        };
        let foreign_descendant = desc.iter().any(|d| !baseline.contains(d));
        if state == TurnState::Ended
            && !foreign_descendant
            && main_age >= q.dwell
            && sub_age >= q.dwell
        {
            return QuietOutcome::Quiet;
        }
        if now >= q.max_wait {
            return QuietOutcome::TimedOut;
        }
        p.sleep(q.poll);
    }
}

/// `(pid, ppid)` pairs from `ps -A -o pid=,ppid=` output; unparsable lines are skipped.
pub fn parse_ps_pairs(text: &str) -> Vec<(u32, u32)> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
        })
        .collect()
}

/// Every transitive descendant of `root` in `pairs` (breadth first, `root` excluded).
pub fn descendants_of(pairs: &[(u32, u32)], root: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut queue = VecDeque::from([root]);
    while let Some(p) = queue.pop_front() {
        for (pid, ppid) in pairs {
            if *ppid == p && *pid != root && !out.contains(pid) {
                out.push(*pid);
                queue.push_back(*pid);
            }
        }
    }
    out
}

/// The descendants of `root` among `reads` (`pid -> (ppid, start)`, each entry read in ONE
/// platform call): a pid joins the tree only when ITS OWN read parent is already in the tree,
/// so a pid recycled between the `ps` listing and the read cannot be attributed by a stale
/// pairing. Breadth first; `root` excluded.
pub fn tree_from_reads(
    root: u32,
    reads: &std::collections::HashMap<u32, (u32, u64)>,
) -> Vec<(u32, u64)> {
    let mut tree: Vec<(u32, u64)> = Vec::new();
    let mut members: HashSet<u32> = HashSet::from([root]);
    let mut queue = VecDeque::from([root]);
    while let Some(parent) = queue.pop_front() {
        let mut kids: Vec<_> = reads
            .iter()
            .filter(|(pid, (ppid, _))| *ppid == parent && **pid != root && !members.contains(*pid))
            .map(|(pid, (_, start))| (*pid, *start))
            .collect();
        kids.sort_unstable();
        for (pid, start) in kids {
            members.insert(pid);
            tree.push((pid, start));
            queue.push_back(pid);
        }
    }
    tree
}

/// Live descendants of `root` with their start times. The `ps` listing only supplies
/// CANDIDATE pids; parent and start time come from one [`crate::sessions::process_ppid_and_start`]
/// read per pid, and a pid whose read fails (it exited, or cannot be identity-checked) is dropped.
#[cfg(unix)]
pub fn list_descendants(root: u32) -> Result<Vec<(u32, u64)>, Tag> {
    use std::process::Stdio;
    const BAD: Tag = "recycle_descendants_unreadable";
    let out = Command::new("/bin/ps")
        .args(["-A", "-o", "pid=,ppid="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| BAD)?;
    if !out.status.success() {
        return Err(BAD);
    }
    let text = String::from_utf8(out.stdout).map_err(|_| BAD)?;
    let reads: std::collections::HashMap<u32, (u32, u64)> = parse_ps_pairs(&text)
        .into_iter()
        .filter_map(|(pid, _)| crate::sessions::process_ppid_and_start(pid).map(|r| (pid, r)))
        .collect();
    Ok(tree_from_reads(root, &reads))
}

/// Claude Code's project-dir slug: every non-alphanumeric ASCII char becomes `-` (per char).
pub fn cwd_slug(cwd: &Path) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// `<handle>/projects/<slug(cwd)>/<id>.jsonl`, trying the literal then canonical cwd.
pub fn resolve_transcript(handle: &Path, cwd: &Path, session_id: &str) -> Result<PathBuf, Tag> {
    validate_session_id(session_id).map_err(|_| "recycle_transcript_unresolved")?;
    let projects = handle.join("projects");
    let mut cands = vec![cwd.to_path_buf()];
    if let Ok(c) = std::fs::canonicalize(cwd) {
        if c != cwd {
            cands.push(c);
        }
    }
    for c in cands {
        let p = projects
            .join(cwd_slug(&c))
            .join(format!("{session_id}.jsonl"));
        if std::fs::metadata(&p).is_ok_and(|m| m.is_file()) {
            return Ok(p);
        }
    }
    Err("recycle_transcript_unresolved")
}

/// Age of the file's last modification (clock going backwards ⇒ zero = "not quiet").
pub fn file_age(path: &Path) -> Result<Duration, Tag> {
    let m = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map_err(|_| "recycle_transcript_unresolved")?;
    Ok(std::time::SystemTime::now()
        .duration_since(m)
        .unwrap_or(Duration::ZERO))
}

/// Age of the most recently modified `*.jsonl` under `<transcript minus .jsonl>/subagents`
/// (a background subagent writes there). No directory ⇒ effectively infinite.
pub fn subagent_age(transcript: &Path) -> Result<Duration, Tag> {
    let dir = transcript.with_extension("").join("subagents");
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Duration::from_secs(u32::MAX.into()))
        }
        Err(_) => return Err("recycle_subagent_unreadable"),
    };
    let mut youngest = Duration::from_secs(u32::MAX.into());
    for e in entries {
        let e = e.map_err(|_| "recycle_subagent_unreadable")?;
        if e.path().extension().is_some_and(|x| x == "jsonl") {
            youngest =
                youngest.min(file_age(&e.path()).map_err(|_| "recycle_subagent_unreadable")?);
        }
    }
    Ok(youngest)
}

// ── stop ───────────────────────────────────────────────────────────────────

/// Stops ONLY `child`: verifies pid identity (`expected_start`), SIGTERM, waits up
/// to `grace`, then SIGKILL. Unverifiable identity fails toward NOT signalling.
/// `recycle_kill_failed` means SIGTERM was delivered but the escalation failed (the
/// child's state is unknown); the identity/signal tags mean nothing was killed.
#[cfg(unix)]
pub fn stop_child(
    child: &mut std::process::Child,
    expected_start: Option<u64>,
    grace: Duration,
) -> Result<std::process::ExitStatus, Tag> {
    // Already gone (it exited after the quiet point, before we could stop it): there is nothing to
    // stop and NOTHING to relaunch; the supervisor's loop reports the exit itself.
    if let Ok(Some(_)) = child.try_wait() {
        return Err("recycle_child_exited");
    }
    let pid = child.id();
    match (expected_start, crate::sessions::process_start_time(pid)) {
        (Some(e), Some(n)) if crate::sessions::same_start(e, n) => {}
        _ => return Err("recycle_pid_identity_changed"),
    }
    let raw = i32::try_from(pid).map_err(|_| "recycle_pid_identity_changed")?;
    // SAFETY: `raw` is the pid of our own un-reaped child (so it cannot have been
    // recycled), and SIGTERM carries no pointer arguments.
    if unsafe { libc::kill(raw, libc::SIGTERM) } != 0 {
        return Err("recycle_signal_failed");
    }
    let deadline = std::time::Instant::now() + grace;
    while std::time::Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    child.kill().map_err(|_| "recycle_kill_failed")?;
    child.wait().map_err(|_| "recycle_kill_failed")
}

/// Terminates descendants captured BEFORE the child was stopped. A pid is signalled only
/// while its start time still agrees with the capture (identity), never otherwise.
/// Returns how many were still alive when signalled.
#[cfg(unix)]
pub fn terminate_descendants(captured: &[(u32, u64)], grace: Duration) -> usize {
    let same = |pid: u32, start: u64| {
        crate::sessions::process_start_time(pid)
            .is_some_and(|s| crate::sessions::same_start(s, start))
    };
    let send = |sig: i32, pid: u32, start: u64| -> bool {
        let Ok(raw) = i32::try_from(pid) else {
            return false;
        };
        if raw <= 1 || !same(pid, start) {
            return false;
        }
        // SAFETY: signal 15/9 carry no pointers; identity was re-checked immediately above.
        unsafe { libc::kill(raw, sig) == 0 }
    };
    let signalled: Vec<_> = captured
        .iter()
        .filter(|(p, s)| send(libc::SIGTERM, *p, *s))
        .collect();
    let deadline = std::time::Instant::now() + grace;
    while std::time::Instant::now() < deadline && signalled.iter().any(|(p, s)| same(*p, *s)) {
        std::thread::sleep(Duration::from_millis(25));
    }
    for (p, s) in &signalled {
        send(libc::SIGKILL, *p, *s);
    }
    signalled.len()
}

#[cfg(unix)]
static WINDOW_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
struct WindowState {
    depth: usize,
    saved: Option<[libc::sigaction; 3]>,
}

#[cfg(unix)]
static WINDOW_STATE: std::sync::Mutex<WindowState> = std::sync::Mutex::new(WindowState {
    depth: 0,
    saved: None,
});

#[cfg(unix)]
const WINDOW_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// Process-wide handler body: records the FIRST signal and returns (async-signal-safe: one
/// atomic compare-exchange).
#[cfg(unix)]
extern "C" fn flag_window_signal(sig: libc::c_int) {
    let _ = WINDOW_SIGNAL.compare_exchange(
        0,
        sig,
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
    );
}

/// The stop-to-spawn window: while open, SIGINT/SIGTERM/SIGHUP are handled process-wide by a
/// handler that only sets a flag, so no thread takes the default action (which would kill csq
/// with the old child stopped and nothing relaunched). The previous dispositions are restored
/// when the last window closes; handlers are reset on `exec`, so the child is unaffected. A
/// window never blocks signals for the rest of the CLI.
#[cfg(unix)]
pub struct SignalWindow(());

#[cfg(unix)]
impl SignalWindow {
    /// Installs the handlers (nesting-safe); `None` when `sigaction` failed (nothing is left installed).
    pub fn open() -> Option<Self> {
        let mut st = WINDOW_STATE.lock().ok()?;
        if st.depth == 0 {
            WINDOW_SIGNAL.store(0, std::sync::atomic::Ordering::SeqCst);
            // SAFETY: every `sigaction` struct is zero-initialised then filled with a valid
            // handler address, an empty mask and flags before being passed to `sigaction(2)`.
            unsafe {
                let mut saved: [libc::sigaction; 3] = std::mem::zeroed();
                for (i, sig) in WINDOW_SIGNALS.iter().enumerate() {
                    let mut act: libc::sigaction = std::mem::zeroed();
                    act.sa_sigaction = flag_window_signal as extern "C" fn(libc::c_int) as usize;
                    libc::sigemptyset(&mut act.sa_mask);
                    act.sa_flags = libc::SA_RESTART;
                    if libc::sigaction(*sig, &act, &mut saved[i]) != 0 {
                        for j in 0..i {
                            libc::sigaction(WINDOW_SIGNALS[j], &saved[j], std::ptr::null_mut());
                        }
                        return None;
                    }
                }
                st.saved = Some(saved);
            }
        }
        st.depth += 1;
        Some(Self(()))
    }

    /// The first signal that arrived since the window opened, if any.
    pub fn pending(&self) -> Option<i32> {
        let s = WINDOW_SIGNAL.load(std::sync::atomic::Ordering::SeqCst);
        (s != 0).then_some(s)
    }

    /// Whether `sig`'s current disposition is this window's handler (test/diagnostic).
    pub fn handler_installed(sig: i32) -> bool {
        // SAFETY: `current` is a local out-parameter filled by `sigaction(2)`.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(sig, std::ptr::null(), &mut current) == 0
                && current.sa_sigaction == flag_window_signal as extern "C" fn(libc::c_int) as usize
        }
    }
}

#[cfg(unix)]
impl Drop for SignalWindow {
    fn drop(&mut self) {
        let Ok(mut st) = WINDOW_STATE.lock() else {
            return;
        };
        st.depth = st.depth.saturating_sub(1);
        if st.depth == 0 {
            if let Some(saved) = st.saved.take() {
                // SAFETY: `saved` was filled by `sigaction(2)` in `open`.
                unsafe {
                    for (i, sig) in WINDOW_SIGNALS.iter().enumerate() {
                        libc::sigaction(*sig, &saved[i], std::ptr::null_mut());
                    }
                }
            }
        }
    }
}

/// Serialises tests that open a [`SignalWindow`] (its handlers and flag are process-wide).
#[cfg(all(test, unix))]
pub(crate) static WINDOW_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Output sink used for loud terminal lines in tests and production.
pub type Out<'a> = &'a mut dyn Write;

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    const BASE: [(u32, u64); 1] = [(100, 1)];

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn classify_strips_conversation_flags_and_drops_every_positional() {
        let got = classify_user_args(&os(&[
            "-c",
            "--resume",
            "old",
            "-r",
            "--model",
            "m",
            "do the kickoff",
            "--fork-session",
            "--session-id",
            "u",
            "--dangerously-skip-permissions",
            "--",
            "-x",
            "tail prompt",
        ]))
        .unwrap();
        assert_eq!(got, os(&["--model", "m", "--dangerously-skip-permissions"]));
        let got =
            classify_user_args(&os(&["--continue", "--resume=abc", "--session-id=u"])).unwrap();
        assert!(got.is_empty());
        // Variadic options keep their values and the one after them is theirs (as commander parses it).
        let got = classify_user_args(&os(&["--add-dir", "a", "b", "--effort", "high"])).unwrap();
        assert_eq!(got, os(&["--add-dir", "a", "b", "--effort", "high"]));
    }

    #[test]
    fn classify_fails_closed_on_anything_unclassifiable() {
        for bad in [
            &["-p", "prompt"][..],
            &["--unknown-future-flag"][..],
            &["-d"][..],
            &["--from-pr", "12"][..],
            &["--model"][..],
            &["--verbose=1"][..],
            &["--add-dir"][..],
        ] {
            assert_eq!(
                classify_user_args(&os(bad)),
                Err("recycle_argv_unclassifiable"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn relaunch_argv_is_prefix_plus_user_plus_resume_and_never_continue() {
        let plan = RelaunchPlan {
            program: PathBuf::from("/bin/claude"),
            prefix: os(&["--mcp-config", "x.json"]),
            user: os(&["--model", "m"]),
        };
        assert_eq!(
            relaunch_argv(&plan, ID, None),
            os(&["--mcp-config", "x.json", "--model", "m", "--resume", ID])
        );
        assert!(!relaunch_argv(&plan, ID, None)
            .iter()
            .any(|a| a == "--continue" || a == "-c"));
    }

    fn fresh_ctx() -> FreshContext {
        FreshContext {
            prompt: OsString::from("PROMPT TEXT"),
            env: vec![(
                OsString::from(PROOF_ENV),
                OsString::from("v1,abc,RECYCLE_TOKEN,PROMPT TEXT,1"),
            )],
        }
    }

    #[test]
    fn fresh_relaunch_argv_drops_every_conversation_flag_and_appends_one_positional() {
        // The user args a real launch would carry, INCLUDING the flags a fresh
        // relaunch must not replay. classify_user_args is what removes them.
        let user = classify_user_args(&os(&[
            "--continue",
            "--resume",
            ID,
            "--session-id",
            ID,
            "--fork-session",
            "--model",
            "m",
            "original prompt",
        ]))
        .unwrap();
        assert_eq!(
            user,
            os(&["--model", "m"]),
            "conversation flags + positional dropped"
        );
        let plan = RelaunchPlan {
            program: PathBuf::from("/bin/claude"),
            prefix: os(&["--mcp-config", "x.json"]),
            user,
        };
        let ctx = fresh_ctx();
        let argv = relaunch_argv(&plan, ID, Some(&ctx));
        assert_eq!(
            argv,
            os(&["--mcp-config", "x.json", "--model", "m", "PROMPT TEXT"])
        );
        for banned in [
            "--resume",
            "-r",
            "--continue",
            "-c",
            "--session-id",
            "--fork-session",
            ID,
        ] {
            assert!(
                !argv.iter().any(|a| a == banned),
                "{banned} must not appear in a fresh argv"
            );
        }
        // Exactly ONE element is appended after prefix+user, and it is the prompt.
        // (Counting "tokens not starting with -" would also count option VALUES.)
        let tail = &argv[plan.prefix.len() + plan.user.len()..];
        assert_eq!(
            tail,
            os(&["PROMPT TEXT"]),
            "exactly one appended element: the prompt"
        );
        // The resume argv is untouched by the new parameter.
        assert_eq!(
            relaunch_argv(&plan, ID, None),
            os(&["--mcp-config", "x.json", "--model", "m", "--resume", ID])
        );
    }

    #[cfg(unix)]
    #[test]
    fn fresh_relaunch_command_carries_the_proof_in_the_environment_never_in_argv() {
        let mut spec = Command::new("sh");
        spec.args(["--plugin-dir", "p"]);
        spec.env("KEPT", "1");
        let plan = build_plan(&spec, &[]).unwrap();
        let ctx = fresh_ctx();
        let cmd = relaunch_command(&spec, &plan, ID, Some(&ctx));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"PROMPT TEXT".to_string()));
        assert!(
            !args.iter().any(|a| a.contains("RECYCLE_TOKEN")),
            "token never in argv"
        );
        assert!(!args.iter().any(|a| a == "--resume"));
        let env: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        // Exactly ONE variable is added by the fresh context (the capability layer's contract (b)).
        let added: Vec<_> = ctx
            .env
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect();
        assert_eq!(added.len(), 1, "one proof variable, never a family of them");
        assert_eq!(added[0].0, PROOF_ENV);
        assert!(env.contains(&(PROOF_ENV.into(), Some(added[0].1.clone()))));
        assert!(
            env.contains(&("KEPT".into(), Some("1".into()))),
            "launch map preserved"
        );
    }

    // ── the capability layer's readiness verdict (the capability layer's contract (c)) ───────────

    fn ready_line(proof: &str) -> String {
        format!(r#"{{"schema":"coc-recycle-readiness/v1","verdict":"ready","proof":"{proof}"}}"#)
    }

    fn good_proof() -> String {
        format!("v1,{},tok_1,{ID},1700000000", "a".repeat(64))
    }

    #[test]
    fn the_fresh_seam_stays_closed_until_the_contract_is_marked_landed() {
        // Compile-time tripwire: the flip is a deliberate act, not a side effect. Flipping it
        // requires the capability layer's cycle-fence on its dev branch AND a green W7 attempt 4; neither holds yet.
        const {
            assert!(
                !LOOM_RECYCLE_CONTRACT_LANDED,
                "the gate is closed until the capability layer's cycle-fence lands on its dev branch and W7 attempt 4 passes"
            )
        };
        // Closed means the seam never even LOOKS for the capability layer: the refusal comes
        // from the gate itself, not from a missing CLI in the target project.
        let p = std::path::Path::new("/nonexistent-project");
        assert_eq!(
            fresh_context_at(p, p, ID),
            Err("recycle_fresh_context_unavailable")
        );
    }

    #[test]
    fn a_ready_verdict_carries_exactly_one_proof_variable_and_the_fixed_prompt() {
        let proof = good_proof();
        let ctx = parse_readiness(0, ready_line(&proof).as_bytes(), ID).unwrap();
        assert_eq!(
            ctx.env,
            vec![(OsString::from(PROOF_ENV), OsString::from(proof))],
            "exactly COC_RECYCLE_PROOF, never a family of variables"
        );
        assert_eq!(ctx.prompt, OsString::from(FRESH_PROMPT));
        // The prompt carries no seed content and names no path.
        assert!(!FRESH_PROMPT.contains('/'));
        assert!(FRESH_PROMPT.starts_with("Context recycle:"));
    }

    #[test]
    fn not_ready_and_unknown_refuse_with_their_own_tags() {
        let line = |v: &str| format!(r#"{{"schema":"coc-recycle-readiness/v1","verdict":"{v}"}}"#);
        assert_eq!(
            parse_readiness(1, line("not-ready").as_bytes(), ID),
            Err("recycle_not_ready")
        );
        assert_eq!(
            parse_readiness(2, line("unknown").as_bytes(), ID),
            Err("recycle_readiness_unknown")
        );
    }

    #[test]
    fn an_unrecognised_readiness_code_is_not_ready_and_falls_back_to_resume() {
        // the capability layer's additive refusal code (announced 2026-11-05): `recycle-proof-seed-mismatch`
        // arrives as a `code` field on a not-ready verdict. The parser is VERDICT-driven and
        // ignores the payload, so a code it has never seen — now or later — can never be read
        // as ready; the supervisor turns this tag into the verified RESUME relaunch.
        let with_code = |verdict: &str, code: &str| {
            format!(
                r#"{{"schema":"coc-recycle-readiness/v1","verdict":"{verdict}","code":"{code}"}}"#
            )
        };
        assert_eq!(
            parse_readiness(
                1,
                with_code("not-ready", "recycle-proof-seed-mismatch").as_bytes(),
                ID
            ),
            Err("recycle_not_ready")
        );
        // The same holds under the 'unknown' verdict, which the supervisor also resumes from.
        assert_eq!(
            parse_readiness(
                2,
                with_code("unknown", "recycle-proof-seed-mismatch").as_bytes(),
                ID
            ),
            Err("recycle_readiness_unknown")
        );
    }

    #[test]
    fn a_readiness_answer_that_disagrees_with_its_own_exit_code_is_never_read_as_ready() {
        let ready = ready_line(&good_proof());
        let not_ready = r#"{"schema":"coc-recycle-readiness/v1","verdict":"not-ready"}"#;
        assert_eq!(
            parse_readiness(0, not_ready.as_bytes(), ID),
            Err("recycle_readiness_malformed"),
            "exit 0 must not be believed over a not-ready verdict"
        );
        assert_eq!(
            parse_readiness(1, ready.as_bytes(), ID),
            Err("recycle_readiness_malformed"),
            "exit 1 must not be overridden by a ready verdict"
        );
        // An exit code outside the contract is a failed CLI, not a verdict.
        assert_eq!(
            parse_readiness(3, ready.as_bytes(), ID),
            Err("recycle_readiness_failed")
        );
        assert_eq!(
            parse_readiness(-1, ready.as_bytes(), ID),
            Err("recycle_readiness_failed")
        );
    }

    #[test]
    fn a_malformed_readiness_line_is_refused() {
        let ready = ready_line(&good_proof());
        for bad in [
            String::new(),
            "not json".to_string(),
            format!("{ready}\n{ready}"),
            r#"{"schema":"other/v9","verdict":"ready","proof":"x"}"#.to_string(),
            r#"{"schema":"coc-recycle-readiness/v1","verdict":"ready"}"#.to_string(),
            r#"{"schema":"coc-recycle-readiness/v1"}"#.to_string(),
        ] {
            assert_eq!(
                parse_readiness(0, bad.as_bytes(), ID),
                Err("recycle_readiness_malformed"),
                "accepted a malformed line: {bad}"
            );
        }
    }

    #[test]
    fn the_proof_pattern_is_strict_and_binds_the_session() {
        let sha = "a".repeat(64);
        let other = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let ok = format!("v1,{sha},tok_1,{ID},1700000000");
        assert_eq!(validate_proof(&ok, ID), Ok(ok.clone()));
        // RFC 3339 is tolerated for issued_at; the 300 s TTL itself is the capability layer's to enforce.
        let rfc = format!("v1,{sha},tok_1,{ID},2026-11-04T00:00:00Z");
        assert_eq!(validate_proof(&rfc, ID), Ok(rfc.clone()));
        for (bad, why) in [
            (format!("v1,{sha},tok_1,{ID}"), "four fields"),
            (format!("v1,{sha},tok_1,{ID},1,extra"), "six fields"),
            (format!("v2,{sha},tok_1,{ID},1"), "wrong version"),
            (format!("v1,{},tok_1,{ID},1", "a".repeat(63)), "short sha"),
            (format!("v1,{},tok_1,{ID},1", "z".repeat(64)), "non-hex sha"),
            (format!("v1,{sha},,{ID},1"), "empty token"),
            (format!("v1,{sha},tok 1,{ID},1"), "token with a space"),
            (format!("v1,{sha},tok_1,{other},1"), "another session"),
            (format!("v1,{sha},tok_1,{ID},soon"), "unparseable issued_at"),
        ] {
            assert_eq!(
                validate_proof(&bad, ID),
                Err("recycle_proof_invalid"),
                "{why}"
            );
        }
    }

    /// A fake `node` that runs `body` as a shell script, plus the PATH that finds it.
    #[cfg(unix)]
    fn fake_node(body: &str) -> (tempfile::TempDir, OsString) {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let p = bin.join("node");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths([bin]).unwrap();
        (d, path)
    }

    /// A project root carrying the readiness CLI at its contract path.
    #[cfg(unix)]
    fn project_with_cli() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let cli = d.path().join(READINESS_CLI_REL);
        std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
        std::fs::write(&cli, "").unwrap();
        d
    }

    #[cfg(unix)]
    #[test]
    fn the_readiness_cli_gets_the_targets_config_dir_a_clean_env_and_the_project_root_cwd() {
        let project = project_with_cli();
        let cfg = tempfile::tempdir().unwrap();
        let cap = project.path().join("capture");
        let proof = good_proof();
        // The child's PATH is ONLY the fake bin dir, so anything not a shell builtin is named
        // absolutely (`/usr/bin/env`).
        let body = format!(
            "{{ printf 'arg:%s\\n' \"$@\"; printf 'cwd:%s\\n' \"$PWD\"; /usr/bin/env; }} > '{}'\nprintf '%s\\n' '{}'",
            cap.display(),
            ready_line(&proof)
        );
        let (_bind, path) = fake_node(&body);
        let ctx = resolve_fresh_context(
            project.path(),
            cfg.path(),
            ID,
            Some(path.as_os_str()),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(ctx.env[0].0.as_os_str(), OsStr::new(PROOF_ENV));
        let captured = std::fs::read_to_string(&cap).unwrap();
        let args: Vec<&str> = captured
            .lines()
            .filter_map(|l| l.strip_prefix("arg:"))
            .collect();
        let cli = project.path().join(READINESS_CLI_REL).display().to_string();
        let cfg_s = cfg.path().display().to_string();
        assert_eq!(
            args,
            vec![cli.as_str(), "--config-dir", cfg_s.as_str()],
            "argv only, and --config-dir names the TARGET, never the requester"
        );
        // The shell resolves its own PWD through symlinks (macOS /var -> /private/var).
        let cwd = std::fs::canonicalize(project.path()).unwrap();
        let cwd_s = cwd.display().to_string();
        let seen = captured.lines().find_map(|l| l.strip_prefix("cwd:"));
        assert_eq!(seen, Some(cwd_s.as_str()));
        let keys: Vec<&str> = captured
            .lines()
            .filter(|l| !l.starts_with("arg:") && !l.starts_with("cwd:"))
            .filter_map(|l| l.split('=').next())
            .collect();
        assert!(keys.contains(&"HOME") && keys.contains(&"PATH"));
        for k in &keys {
            assert!(
                matches!(*k, "HOME" | "PATH" | "PWD" | "SHLVL" | "_"),
                "the readiness CLI inherited {k}"
            );
        }
        assert!(
            !keys.contains(&PROOF_ENV),
            "the proof does not exist yet at readiness time"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_hung_readiness_cli_is_killed_at_the_deadline() {
        let project = project_with_cli();
        let cfg = tempfile::tempdir().unwrap();
        // Absolute: the scrubbed PATH holds only the fake bin dir.
        let (_bind, path) = fake_node("/bin/sleep 5");
        let started = std::time::Instant::now();
        assert_eq!(
            resolve_fresh_context(
                project.path(),
                cfg.path(),
                ID,
                Some(path.as_os_str()),
                Duration::from_millis(200)
            ),
            Err("recycle_readiness_timeout")
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the CLI must be killed at the deadline, not waited out"
        );
    }

    /// A CLI that exits at once but leaves a CHILD holding its stdout must not outlive the
    /// deadline: the deadline arms the group kill while the leader is still unreaped, so the
    /// grandchild gets the SIGKILL too.
    ///
    /// Discriminating check: removing `libc::kill(-pgid, SIGKILL)` from `kill_live_group` leaves
    /// the grandchild alive and this test fails on the `gone` assertion (proved by mutation in
    /// the lane's evidence).
    #[cfg(unix)]
    #[test]
    fn a_grandchild_holding_stdout_is_killed_with_the_group_at_the_deadline() {
        let project = project_with_cli();
        let cfg = tempfile::tempdir().unwrap();
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("grandchild.pid");
        // The leader backgrounds a child that inherits stdout, records its pid and exits. The
        // sleep is ABSOLUTE: the readiness CLI runs with a sanitized PATH that carries only the
        // fake-node dir, so a PATH lookup would fail and the "grandchild" would die at once —
        // closing the pipe and leaving this test green for the wrong reason.
        let body = format!("/bin/sleep 30 & echo $! > {}; exit 0", pidfile.display());
        let (_bind, path) = fake_node(&body);
        assert_eq!(
            resolve_fresh_context(
                project.path(),
                cfg.path(),
                ID,
                Some(path.as_os_str()),
                Duration::from_secs(1)
            ),
            Err("recycle_readiness_timeout"),
            "a pipe held past the deadline is a timeout, and it is NOT ready"
        );
        let pid: u32 = std::fs::read_to_string(&pidfile)
            .expect("the grandchild records its pid before the leader exits")
            .trim()
            .parse()
            .expect("a pid");
        let mut gone = false;
        for _ in 0..200 {
            // SAFETY: signal 0 only probes existence.
            if unsafe { libc::kill(pid as i32, 0) } != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            gone,
            "the stdout-holding grandchild must not outlive the deadline"
        );
    }

    /// Deterministic ETXTBSY both ways: OUR OWN write descriptor makes exec fail until it is
    /// dropped, and the drop happens INSIDE `on_attempt` for attempt 2 — strictly after attempt 1
    /// failed and strictly before attempt 2 runs. The test therefore cannot pass without the
    /// retry, and cannot red because a closer thread was scheduled late.
    ///
    /// LINUX ONLY: Darwin's exec does not fail while a writer holds the file (verified on the
    /// macOS leg), so on macOS the first attempt would succeed and this test would be vacuous.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_transiently_busy_executable_is_retried_and_then_runs() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Mutex;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("node");
        std::fs::write(&p, "#!/bin/sh\nexit 7\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let writer = Mutex::new(Some(
            std::fs::OpenOptions::new().write(true).open(&p).unwrap(),
        ));
        let mut seen = 0u32;
        let mut cmd = std::process::Command::new(&p);
        let mut child = spawn_busy_retrying(
            &mut cmd,
            Duration::from_secs(5),
            Duration::from_millis(1),
            &mut |attempt| {
                seen = attempt;
                if attempt == 2 {
                    writer.lock().unwrap().take();
                }
            },
        )
        .expect("a transiently busy executable must be retried, not refused");
        let status = child.wait().unwrap();
        assert!(
            seen >= 2,
            "the first attempt failed and the second one was needed"
        );
        assert_eq!(
            status.code(),
            Some(7),
            "the retried spawn really ran the program"
        );
    }

    /// The bound is STRUCTURAL and runs on the PRODUCTION constants: the attempt count cannot
    /// exceed budget/delay + 1 (the final attempt runs after the budget expires), and the two
    /// constants are pinned so LOWERING the production budget must be a deliberate test change
    /// rather than a silent reintroduction of the flake. LINUX ONLY for the exec property.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_persistently_busy_executable_still_fails_at_the_budget() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(SPAWN_BUSY_BUDGET, Duration::from_millis(100));
        assert_eq!(SPAWN_BUSY_DELAY, Duration::from_millis(5));
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("node");
        std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _writer = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        let mut seen = 0u32;
        let mut cmd = std::process::Command::new(&p);
        let err = spawn_busy_retrying(
            &mut cmd,
            SPAWN_BUSY_BUDGET,
            SPAWN_BUSY_DELAY,
            &mut |attempt| seen = attempt,
        )
        .expect_err("a writer that never closes must not be waited out forever");
        assert!(
            is_exec_busy(&err),
            "the failure is the busy signal, not something else"
        );
        assert!(seen >= 2, "the retry was exercised, not skipped");
        assert!(
            u128::from(seen) <= SPAWN_BUSY_BUDGET.as_millis() / SPAWN_BUSY_DELAY.as_millis() + 1,
            "attempts bounded by the PRODUCTION budget: {seen}"
        );
    }

    /// "Retries ONLY ETXTBSY", the other half: a DIFFERENT spawn failure is returned on the
    /// FIRST attempt even with a large budget. ENOENT is deterministic on every platform.
    #[test]
    fn a_non_busy_spawn_error_is_never_retried() {
        let mut seen = 0u32;
        let mut cmd = std::process::Command::new("/nonexistent/csq-etxtbsy-probe");
        let err = spawn_busy_retrying(
            &mut cmd,
            Duration::from_secs(5),
            Duration::from_millis(1),
            &mut |attempt| seen = attempt,
        )
        .expect_err("a missing program must not be waited out");
        assert_eq!(seen, 1, "exactly one attempt");
        assert!(!is_exec_busy(&err), "the error is not the busy signal");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn a_cli_that_closes_stdout_and_keeps_running_is_killed_at_the_deadline() {
        // Security R2 M3: the pipe closing is not the leader exiting. This CLI closes fd 1 at
        // once and outlives the deadline; the caller must still be bounded. The 4 s wait is
        // what makes the mutant red instead of hanging the suite.
        let project = project_with_cli();
        let cfg = tempfile::tempdir().unwrap();
        let (_bind, path) = fake_node("exec 1>&-; exec /bin/sleep 6");
        let (tx, rx) = std::sync::mpsc::channel();
        let project_path = project.path().to_path_buf();
        let cfg_path = cfg.path().to_path_buf();
        std::thread::spawn(move || {
            let r = resolve_fresh_context(
                &project_path,
                &cfg_path,
                ID,
                Some(path.as_os_str()),
                Duration::from_secs(1),
            );
            let _ = tx.send(r);
        });
        let got = rx
            .recv_timeout(Duration::from_secs(4))
            .expect("a CLI that outlives its stdout must not wedge the caller");
        assert!(
            matches!(got, Err("recycle_readiness_timeout")),
            "the reap must be deadline-bounded"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unresolvable_node_is_a_failed_run_never_a_ready_one() {
        let project = project_with_cli();
        let cfg = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_fresh_context(
                project.path(),
                cfg.path(),
                ID,
                Some(OsStr::new("/nonexistent-csq-test-bin")),
                Duration::from_secs(1)
            ),
            Err("recycle_readiness_failed")
        );
    }

    #[test]
    fn a_missing_readiness_cli_is_refused_before_any_spawn() {
        let project = tempfile::tempdir().unwrap();
        let cfg = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_fresh_context(project.path(), cfg.path(), ID, None, Duration::from_secs(1)),
            Err("recycle_readiness_cli_missing")
        );
    }

    #[test]
    fn a_well_formed_foreign_request_round_trips_through_read_request() {
        // A platform-ABSOLUTE handle: a leading `/` is root-without-prefix on Windows,
        // where `Path::is_absolute` is false and the request validator (correctly) refuses
        // the record as unreadable.
        let handle = std::env::temp_dir()
            .join("h-req")
            .to_string_lossy()
            .into_owned();
        let d = tempfile::tempdir().unwrap();
        let raw = serde_json::json!({
            "v": 2, "request_id": "deadbeef", "session_id": ID, "reason": "x",
            "requested_at": "t", "mode": "fresh",
            "requested_by": {"session_id": "99999999-8888-7777-6666-555555555555", "handle": handle},
            "nonce": "abcdef0123456789", "expires_at_unix": 4000000000i64
        });
        let p = d.path().join(REQUEST_FILE);
        std::fs::write(&p, serde_json::to_vec(&raw).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let got = read_request(d.path());
        assert!(
            got.is_ok(),
            "a well-formed foreign request must be readable, got {got:?}"
        );
        let req = got.unwrap().unwrap();
        assert_eq!(req.mode, Mode::Fresh);
        assert!(req.requested_by.is_some());
        let half = serde_json::json!({
            "v": 2, "request_id": "deadbeef", "session_id": ID, "reason": "x",
            "requested_at": "t", "mode": "fresh",
            "requested_by": {"session_id": "99999999-8888-7777-6666-555555555555", "handle": handle}
        });
        std::fs::write(&p, serde_json::to_vec(&half).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_request(d.path()), Err("recycle_request_unreadable"));
    }

    #[test]
    fn a_foreign_request_is_judged_by_mode_then_consent_then_ttl_then_replay() {
        use super::super::recycle_consent::{ConsentRecord, RequesterRecord};
        let who = RequesterRecord {
            session_id: "99999999-8888-7777-6666-555555555555".into(),
            handle: std::env::temp_dir()
                .join("h-req")
                .to_string_lossy()
                .into_owned(),
        };
        let base = RecycleRequest {
            v: 1,
            request_id: "deadbeef".into(),
            session_id: ID.into(),
            reason: String::new(),
            requested_at: "t".into(),
            mode: Mode::Fresh,
            requested_by: Some(who.clone()),
            nonce: Some("a".repeat(32)),
            expires_at_unix: Some(1000),
        };
        let consent = ConsentRecord {
            v: 1,
            target_session_id: ID.into(),
            allow: vec![who],
            expires_at_unix: 5000,
            max_uses: 1,
            used: 0,
        };
        // The terminal's own request is never judged by this function.
        let mine = RecycleRequest {
            requested_by: None,
            nonce: None,
            expires_at_unix: None,
            ..base.clone()
        };
        assert_eq!(foreign_verdict(&mine, None, 0, &[]), Ok(()));
        // Happy path.
        assert_eq!(foreign_verdict(&base, Some(&consent), 999, &[]), Ok(()));
        // A consent whose use was already SPENT at issue time still covers the issued request:
        // the daemon spends at issue, so the target-side check must not require a spare use.
        let mut spent = consent.clone();
        spent.used = spent.max_uses;
        assert_eq!(foreign_verdict(&base, Some(&spent), 999, &[]), Ok(()));
        // But expiry still binds.
        let mut expired = consent.clone();
        expired.expires_at_unix = 998;
        assert_eq!(
            foreign_verdict(&base, Some(&expired), 999, &[]),
            Err("xrecycle_consent_expired")
        );
        // A third party may never ask for a RESUME.
        let resume = RecycleRequest {
            mode: Mode::Resume,
            ..base.clone()
        };
        assert_eq!(
            foreign_verdict(&resume, Some(&consent), 999, &[]),
            Err("xrecycle_target_mismatch")
        );
        // No consent at all.
        assert_eq!(
            foreign_verdict(&base, None, 999, &[]),
            Err("xrecycle_not_consented")
        );
        // Expired at the TTL boundary (now == expiry is stale, not valid).
        assert_eq!(
            foreign_verdict(&base, Some(&consent), 1000, &[]),
            Err("xrecycle_request_stale")
        );
        // Replay of a nonce already recorded in the previous result.
        assert_eq!(
            foreign_verdict(&base, Some(&consent), 999, &["a".repeat(32)]),
            Err("xrecycle_replay")
        );
    }

    #[test]
    fn a_resume_request_stays_byte_identical_and_a_fresh_one_carries_its_mode() {
        let d = tempfile::tempdir().unwrap();
        write_request(d.path(), ID, "why", "2026-11-03T00:00:00Z", Mode::Resume).unwrap();
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.path().join(REQUEST_FILE)).unwrap()).unwrap();
        assert!(
            raw.get("mode").is_none(),
            "a resume request must not grow a mode field: earlier csq versions wrote this exact shape"
        );
        assert_eq!(read_request(d.path()).unwrap().unwrap().mode, Mode::Resume);
        // A request written by an older csq (no `mode`) still reads as resume.
        let legacy = serde_json::json!({
            "v": 1, "request_id": "deadbeef", "session_id": ID,
            "reason": "r", "requested_at": "t"
        });
        std::fs::write(
            d.path().join(REQUEST_FILE),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                d.path().join(REQUEST_FILE),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert_eq!(read_request(d.path()).unwrap().unwrap().mode, Mode::Resume);
        // The fresh/refusal gate belongs to the VERB, which knows the target terminal
        // (`fresh_is_refused_before_anything_is_queued` covers it there). This writer
        // must persist whatever mode it is given, or a supervisor could never consume one.
        remove_request(d.path());
        write_request(d.path(), ID, "", "t", Mode::Fresh).unwrap();
        assert_eq!(read_request(d.path()).unwrap().unwrap().mode, Mode::Fresh);
        // A fresh request written by another writer (same shape) still reads as fresh.
        let fresh = serde_json::json!({
            "v": 1, "request_id": "deadbeef", "session_id": ID,
            "reason": "r", "requested_at": "t", "mode": "fresh"
        });
        std::fs::write(
            d.path().join(REQUEST_FILE),
            serde_json::to_vec(&fresh).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                d.path().join(REQUEST_FILE),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert_eq!(read_request(d.path()).unwrap().unwrap().mode, Mode::Fresh);
    }

    // Unix fixture (`sh` on PATH, `/bin/sh`); the relaunch it covers is
    // Unix-only (`recycle_supervise` is `cfg(unix)`).
    #[cfg(unix)]
    #[test]
    fn build_plan_splits_prefix_from_user_and_refuses_an_unknowable_split() {
        let mut spec = Command::new("sh");
        spec.args(["--plugin-dir", "p", "--model", "m", "kickoff prompt"]);
        let plan = build_plan(&spec, &os(&["--model", "m", "kickoff prompt"])).unwrap();
        assert_eq!(plan.prefix, os(&["--plugin-dir", "p"]));
        assert_eq!(plan.user, os(&["--model", "m"]), "positional dropped");
        assert!(plan.program.is_absolute());
        assert_eq!(
            build_plan(&spec, &os(&["--different"])),
            Err("recycle_argv_unclassifiable")
        );
        let mut unknown = Command::new("sh");
        unknown.args(["-p", "x"]);
        assert_eq!(
            build_plan(&unknown, &os(&["-p", "x"])),
            Err("recycle_argv_unclassifiable")
        );
        let mut nope = Command::new("definitely-not-a-real-binary-xyz");
        nope.arg("--model");
        assert_eq!(
            build_plan(&nope, &os(&[])),
            Err("recycle_program_unresolved")
        );
    }

    // Unix fixture (`sh` on PATH, `/bin/sh`); the relaunch it covers is
    // Unix-only (`recycle_supervise` is `cfg(unix)`).
    #[cfg(unix)]
    #[test]
    fn resolve_program_ignores_relative_path_entries() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_program(OsStr::new("sh"), Some(OsStr::new("relative/bin"))),
            None
        );
        let found = resolve_program(
            OsStr::new("sh"),
            Some(
                std::env::join_paths(["/bin", d.path().to_str().unwrap()])
                    .unwrap()
                    .as_os_str(),
            ),
        );
        assert_eq!(found, Some(PathBuf::from("/bin/sh")));
    }

    #[test]
    fn session_id_and_reason_validation() {
        assert!(validate_session_id(ID).is_ok());
        for bad in [
            "",
            "abc",
            "123e4567e89b12d3a456426614174000",
            "../../etc/passwd",
            "123e4567-e89b-12d3-a456-42661417400g",
        ] {
            assert_eq!(
                validate_session_id(bad),
                Err("recycle_session_id_invalid"),
                "{bad}"
            );
        }
        assert!(validate_reason("memory at 3 GiB").is_ok());
        assert!(validate_reason(&"x".repeat(200)).is_ok());
        assert!(validate_reason(&"x".repeat(201)).is_err());
        assert!(validate_reason("a\nb").is_err());
        assert!(validate_reason("a\u{1b}[31m").is_err());
    }

    #[test]
    fn warn_bytes_parse_and_classify() {
        assert_eq!(parse_warn_bytes(None), Ok(DEFAULT_WARN_BYTES));
        assert_eq!(parse_warn_bytes(Some(" 1024 ")), Ok(1024));
        for bad in ["", "0", "-5", "+5", "1.5", "2GiB", "0x10"] {
            assert_eq!(
                parse_warn_bytes(Some(bad)),
                Err("memory_warn_bytes_invalid"),
                "{bad}"
            );
        }
        assert_eq!(memory_record(Ok(99), 100, "t").state, MemoryState::Ok);
        assert_eq!(memory_record(Ok(100), 100, "t").state, MemoryState::Warn);
        let u = memory_record(Err("rss_sample_failed"), 100, "t");
        assert_eq!(
            (u.state, u.rss_bytes, u.tag.as_deref()),
            (MemoryState::Unknown, None, Some("rss_sample_failed"))
        );
    }

    #[test]
    fn samplers_parse_platform_text() {
        assert_eq!(
            parse_vmrss_status("Name:\tx\nVmRSS:\t  2048 kB\n"),
            Ok(2048 * 1024)
        );
        assert!(parse_vmrss_status("Name:\tx\n").is_err());
        assert_eq!(parse_ps_rss_kib("  4096\n"), Ok(4096 * 1024));
        assert!(parse_ps_rss_kib("\n").is_err());
        assert_eq!(
            parse_ps_pairs("  10 1\n 11 10\nbad\n 12 11\n"),
            vec![(10, 1), (11, 10), (12, 11)]
        );
        assert_eq!(
            descendants_of(&[(10, 1), (11, 10), (12, 11), (20, 1)], 10),
            vec![11, 12]
        );
    }

    #[cfg(unix)]
    #[test]
    fn live_sampler_reads_own_process() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(sample_rss_bytes(std::process::id()).unwrap() > 1024 * 1024);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(
            sample_rss_bytes(std::process::id()),
            Err("rss_unsupported_platform")
        );
        let me = std::process::id();
        let mut child = Command::new("sleep").arg("5").spawn().unwrap();
        let cpid = child.id();
        std::thread::sleep(Duration::from_millis(100));
        let d = list_descendants(me).unwrap();
        assert!(d.iter().any(|(p, _)| *p == cpid), "{d:?}");
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn memory_and_request_files_are_0600_and_roundtrip() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let rec = memory_record(Ok(7), 5, "2026-11-03T00:00:00Z");
        write_memory(d.path(), &rec).unwrap();
        write_request(d.path(), ID, "why", "2026-11-03T00:00:00Z", Mode::Resume).unwrap();
        for f in [MEMORY_FILE, REQUEST_FILE] {
            let mode = std::fs::metadata(d.path().join(f))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{f}");
        }
        assert_eq!(read_memory(d.path()).unwrap(), Some(rec));
        let req = read_request(d.path()).unwrap().unwrap();
        assert_eq!(
            (req.v, req.session_id.as_str(), req.reason.as_str()),
            (1, ID, "why")
        );
        assert_eq!(req.request_id.len(), 36);
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(d.path().join(REQUEST_FILE)).unwrap()).unwrap();
        assert_eq!(raw.as_object().unwrap().len(), 5);
    }

    #[cfg(unix)]
    #[test]
    fn unparsable_forged_loose_mode_dir_symlink_and_fifo_requests_are_errors_never_a_hang() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(REQUEST_FILE);
        let put = |bytes: &[u8], mode: u32| {
            let _ = std::fs::remove_file(&p);
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        put(b"{nope", 0o600);
        assert_eq!(read_request(d.path()), Err("recycle_request_unreadable"));
        put(
            br#"{"v":1,"request_id":"a","session_id":"../x","reason":"r","requested_at":"t"}"#,
            0o600,
        );
        assert_eq!(read_request(d.path()), Err("recycle_request_unreadable"));
        let good = format!(
            r#"{{"v":1,"request_id":"ab-12","session_id":"{ID}","reason":"r","requested_at":"t"}}"#
        );
        put(good.as_bytes(), 0o600);
        assert!(read_request(d.path()).unwrap().is_some());
        put(good.as_bytes(), 0o644);
        assert_eq!(
            read_request(d.path()),
            Err("recycle_request_unreadable"),
            "group/other readable"
        );
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        assert_eq!(
            read_request(d.path()),
            Err("recycle_request_unreadable"),
            "directory"
        );
        std::fs::remove_dir(&p).unwrap();
        std::os::unix::fs::symlink("/etc/hosts", &p).unwrap();
        assert_eq!(
            read_request(d.path()),
            Err("recycle_request_unreadable"),
            "symlink"
        );
        std::fs::remove_file(&p).unwrap();
        // SAFETY: path is a NUL-free temp path; mkfifo has no other preconditions.
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(
            read_request(d.path()),
            Err("recycle_request_unreadable"),
            "fifo returns, no hang"
        );
        std::fs::remove_file(&p).unwrap();
        assert_eq!(read_request(d.path()), Ok(None));
    }

    #[test]
    fn statusline_segment_only_for_fresh_warn() {
        let d = tempfile::tempdir().unwrap();
        let t0 = "2026-11-03T00:00:00Z";
        assert_eq!(statusline_segment(d.path(), t0), None);
        write_memory(d.path(), &memory_record(Ok(3 << 30), 5 << 29, t0)).unwrap();
        assert_eq!(
            statusline_segment(d.path(), "2026-11-03T00:01:00Z").as_deref(),
            Some("[mem 3.0G: recycle]")
        );
        assert_eq!(
            statusline_segment(d.path(), "2026-11-03T01:00:00Z"),
            None,
            "stale"
        );
        write_memory(d.path(), &memory_record(Ok(1 << 30), 5 << 29, t0)).unwrap();
        assert_eq!(statusline_segment(d.path(), t0), None, "ok state");
        write_memory(
            d.path(),
            &memory_record(Err("rss_sample_failed"), 5 << 29, t0),
        )
        .unwrap();
        assert_eq!(statusline_segment(d.path(), t0), None, "unknown state");
    }

    fn line(v: serde_json::Value) -> Vec<u8> {
        let mut b = serde_json::to_vec(&v).unwrap();
        b.push(b'\n');
        b
    }
    fn asst(stop: &str, tool_use: bool) -> Vec<u8> {
        let content = if tool_use {
            serde_json::json!([{"type":"text","text":"x"},{"type":"tool_use","id":"t1"}])
        } else {
            serde_json::json!([{"type":"text","text":"x"}])
        };
        line(
            serde_json::json!({"type":"assistant","message":{"role":"assistant","stop_reason":stop,"content":content}}),
        )
    }
    fn typed(t: &str) -> Vec<u8> {
        line(serde_json::json!({ "type": t }))
    }

    #[test]
    fn turn_state_needs_a_terminal_assistant_entry_with_only_bookkeeping_after_it() {
        let mut ended = typed("user");
        ended.extend(asst("end_turn", false));
        assert_eq!(
            turn_state(&ended, true),
            Ok(TurnState::Busy("not_end_turn")).map(|_| TurnState::Ended)
        );
        ended.extend(typed("attachment"));
        ended.extend(line(
            serde_json::json!({"type":"system","subtype":"stop_hook_summary"}),
        ));
        assert_eq!(turn_state(&ended, true), Ok(TurnState::Ended));

        // pending tool_use (stop_reason tool_use) is busy, even with a trailing attachment
        let mut tool = typed("user");
        tool.extend(asst("tool_use", true));
        tool.extend(typed("attachment"));
        assert_eq!(
            turn_state(&tool, true),
            Ok(TurnState::Busy("tool_use_pending"))
        );
        // tool_use block inside an end_turn message is still unanswered
        assert_eq!(
            turn_state(&asst("end_turn", true), true),
            Ok(TurnState::Busy("tool_use_pending"))
        );
        // a new turn started after the end: api-request / queue-operation / user
        for next in ["api-request", "queue-operation", "user", "something-new"] {
            let mut s = asst("end_turn", false);
            s.extend(typed(next));
            assert!(
                matches!(turn_state(&s, true), Ok(TurnState::Busy(_))),
                "{next}"
            );
        }
        // a queued_command attachment is queued user input
        let mut q = asst("end_turn", false);
        q.extend(line(
            serde_json::json!({"type":"attachment","attachment":{"type":"queued_command"}}),
        ));
        assert!(matches!(turn_state(&q, true), Ok(TurnState::Busy(_))));
        // torn / unparsable tails are busy; no conversation entry at all is unknown
        let mut torn = asst("end_turn", false);
        torn.extend(b"{\"type\":\"assi");
        assert_eq!(turn_state(&torn, true), Ok(TurnState::Busy("torn_tail")));
        let mut bad = asst("end_turn", false);
        bad.extend(b"not json\n");
        assert_eq!(
            turn_state(&bad, true),
            Ok(TurnState::Busy("unparsable_tail"))
        );
        assert_eq!(
            turn_state(&typed("attachment"), true),
            Err("recycle_turn_state_unknown")
        );
        // sidechain entries are not the main turn
        let mut side = asst("end_turn", false);
        side.extend(line(serde_json::json!({"type":"assistant","isSidechain":true,"message":{"stop_reason":"tool_use","content":[{"type":"tool_use"}]}})));
        assert_eq!(turn_state(&side, true), Ok(TurnState::Ended));
    }

    struct Fake {
        t: Duration,
        state: TurnState,
        main_idle_from: Duration,
        sub_idle_from: Duration,
        alive_until: Option<Duration>,
        desc: Vec<(u32, u64)>,
        /// (appears_at, pid) new descendants
        spawn_at: Option<(Duration, (u32, u64))>,
    }
    impl QuietProbe for Fake {
        fn elapsed(&self) -> Duration {
            self.t
        }
        fn sleep(&mut self, d: Duration) {
            self.t += d;
        }
        fn child_alive(&mut self) -> bool {
            self.alive_until.is_none_or(|u| self.t < u)
        }
        fn transcript_age(&mut self) -> Result<Duration, Tag> {
            Ok(self.t.saturating_sub(self.main_idle_from))
        }
        fn turn_state(&mut self) -> Result<TurnState, Tag> {
            Ok(self.state)
        }
        fn subagent_age(&mut self) -> Result<Duration, Tag> {
            Ok(self.t.saturating_sub(self.sub_idle_from))
        }
        fn descendants(&mut self) -> Result<Vec<(u32, u64)>, Tag> {
            let mut d = self.desc.clone();
            if let Some((at, p)) = self.spawn_at {
                if self.t >= at {
                    d.push(p);
                }
            }
            Ok(d)
        }
    }
    fn fake(state: TurnState) -> Fake {
        Fake {
            t: Duration::ZERO,
            state,
            main_idle_from: Duration::ZERO,
            sub_idle_from: Duration::ZERO,
            alive_until: None,
            desc: vec![(100, 1)],
            spawn_at: None,
        }
    }

    #[test]
    fn quiet_wait_succeeds_on_positive_turn_end_with_idle_transcripts_and_baseline_descendants() {
        let mut p = fake(TurnState::Ended);
        assert_eq!(
            wait_for_quiet(
                &mut p,
                &QuietParams::default(),
                &BASE.iter().copied().collect()
            ),
            QuietOutcome::Quiet
        );
        assert!(
            p.t >= Duration::from_secs(15) && p.t <= Duration::from_secs(16),
            "the dwell starts at the turn end, not after another idle window: {:?}",
            p.t
        );
    }

    #[test]
    fn a_pending_tool_use_is_never_quiet_however_idle_everything_else_is() {
        let mut p = fake(TurnState::Busy("tool_use_pending"));
        assert_eq!(
            wait_for_quiet(
                &mut p,
                &QuietParams::default(),
                &BASE.iter().copied().collect()
            ),
            QuietOutcome::TimedOut
        );
        assert_eq!(p.t, Duration::from_secs(600));
    }

    #[test]
    fn a_new_descendant_is_busy_but_the_baseline_mcp_server_is_not() {
        let mut p = fake(TurnState::Ended);
        p.spawn_at = Some((Duration::from_secs(5), (200, 7)));
        assert_eq!(
            wait_for_quiet(
                &mut p,
                &QuietParams::default(),
                &BASE.iter().copied().collect()
            ),
            QuietOutcome::TimedOut,
            "a descendant that appeared after the baseline and stays alive keeps it busy"
        );
    }

    #[test]
    fn a_recently_written_subagent_transcript_blocks_quiet() {
        let mut p = fake(TurnState::Ended);
        p.sub_idle_from = Duration::from_secs(100_000); // age is saturating_sub => 0 forever
        assert_eq!(
            wait_for_quiet(
                &mut p,
                &QuietParams::default(),
                &BASE.iter().copied().collect()
            ),
            QuietOutcome::TimedOut
        );
    }

    #[test]
    fn quiet_wait_reports_child_exit_and_unreadable_probe() {
        let mut p = fake(TurnState::Busy("x"));
        p.alive_until = Some(Duration::from_secs(3));
        assert_eq!(
            wait_for_quiet(
                &mut p,
                &QuietParams::default(),
                &BASE.iter().copied().collect()
            ),
            QuietOutcome::ChildExited
        );
        struct Bad;
        impl QuietProbe for Bad {
            fn elapsed(&self) -> Duration {
                Duration::ZERO
            }
            fn sleep(&mut self, _: Duration) {}
            fn child_alive(&mut self) -> bool {
                true
            }
            fn transcript_age(&mut self) -> Result<Duration, Tag> {
                Ok(Duration::ZERO)
            }
            fn turn_state(&mut self) -> Result<TurnState, Tag> {
                Err("recycle_turn_state_unknown")
            }
            fn subagent_age(&mut self) -> Result<Duration, Tag> {
                Ok(Duration::ZERO)
            }
            fn descendants(&mut self) -> Result<Vec<(u32, u64)>, Tag> {
                Ok(vec![])
            }
        }
        assert_eq!(
            wait_for_quiet(
                &mut Bad,
                &QuietParams::default(),
                &BASE.iter().copied().collect()
            ),
            QuietOutcome::Unresolved("recycle_turn_state_unknown")
        );
    }

    #[test]
    fn transcript_resolution_uses_cwd_slug_and_fails_closed() {
        let d = tempfile::tempdir().unwrap();
        let cwd = Path::new("/work/my.proj");
        assert_eq!(cwd_slug(cwd), "-work-my-proj");
        assert_eq!(
            resolve_transcript(d.path(), cwd, ID),
            Err("recycle_transcript_unresolved")
        );
        let dir = d.path().join("projects").join("-work-my-proj");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{ID}.jsonl")), b"{}").unwrap();
        assert_eq!(
            resolve_transcript(d.path(), cwd, ID),
            Ok(dir.join(format!("{ID}.jsonl")))
        );
        assert!(resolve_transcript(d.path(), cwd, "../x").is_err());
        let t = dir.join(format!("{ID}.jsonl"));
        assert!(subagent_age(&t).unwrap() > Duration::from_secs(1_000_000));
        let sub = dir.join(ID).join("subagents");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("agent-1.jsonl"), b"{}").unwrap();
        assert!(subagent_age(&t).unwrap() < Duration::from_secs(60));
    }

    #[cfg(unix)]
    #[test]
    fn supervisor_marker_requires_matching_live_identity_and_a_relaunchable_launch() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        assert_eq!(check_supervised(d.path(), 5), Err("recycle_unsupervised"));
        write_supervisor(d.path(), 4242, Ok(()), d.path()).unwrap();
        assert_eq!(check_supervised(d.path(), 4242), Ok(()));
        assert_eq!(
            check_supervised(d.path(), 4243),
            Err("recycle_unsupervised"),
            "other claude pid"
        );
        write_supervisor(d.path(), 4242, Err("recycle_argv_unclassifiable"), d.path()).unwrap();
        assert_eq!(
            check_supervised(d.path(), 4242),
            Err("recycle_argv_unclassifiable")
        );
        write_supervisor(d.path(), 4242, Ok(()), d.path()).unwrap();
        let mut m: SupervisorMarker =
            serde_json::from_slice(&std::fs::read(d.path().join(SUPERVISOR_FILE)).unwrap())
                .unwrap();
        m.csq_start += 1000; // pid reuse: same pid, different start time
        let p = d.path().join(SUPERVISOR_FILE);
        std::fs::write(&p, serde_json::to_vec(&m).unwrap()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            check_supervised(d.path(), 4242),
            Err("recycle_unsupervised")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_headless_caller_resolves_only_when_it_descends_from_the_supervised_child() {
        let d = tempfile::tempdir().unwrap();
        // The stub REFUSES any handle but this test's dir, so a wiring that passed the wrong
        // handle through would fail here instead of silently resolving.
        let want = d.path().to_path_buf();
        let marker = move |h: &Path| -> Option<SupervisorMarker> {
            if h != want {
                return None;
            }
            Some(SupervisorMarker {
                v: 1,
                csq_pid: 10,
                csq_start: 1,
                child_pid: 4242,
                relaunch_ok: true,
                relaunch_tag: None,
                cwd: None,
            })
        };
        // Descendant, with a plain shell between: resolved.
        assert_eq!(
            resolve_headless_caller(
                d.path(),
                &marker,
                &|_| Some(Some(vec![(100, 5)])),
                // Bound to the hop's pid AND start: a stub fed a different hop fails here
                // instead of silently resolving. The shell is NOT a session, so Some(false).
                &|hop, start| {
                    assert_eq!((hop, start), (100, 5));
                    Some(false)
                }
            ),
            Ok(4242)
        );
        // THE NESTING REFUSAL: a session sits between this process and the claimed child, so
        // the handle dir only NAMES an outer session — the same class the listed path refuses.
        assert_eq!(
            resolve_headless_caller(
                d.path(),
                &marker,
                &|_| Some(Some(vec![(100, 5)])),
                &|hop, start| {
                    assert_eq!((hop, start), (100, 5));
                    Some(true)
                }
            ),
            Err("recycle_caller_target_mismatch")
        );
        // A hop that cannot be classified is UNKNOWN, never "not a session".
        assert_eq!(
            resolve_headless_caller(
                d.path(),
                &marker,
                &|_| Some(Some(vec![(100, 5)])),
                &|hop, start| {
                    assert_eq!((hop, start), (100, 5));
                    None
                }
            ),
            Err("recycle_caller_unresolved")
        );
        // Not an ancestor at all.
        assert_eq!(
            resolve_headless_caller(d.path(), &marker, &|_| Some(None), &|_, _| panic!(
                "no hop is consulted when the target is not an ancestor"
            )),
            Err("recycle_caller_unresolved")
        );
        // An unreadable ancestry is UNKNOWN, never "inside".
        assert_eq!(
            resolve_headless_caller(d.path(), &marker, &|_| None, &|_, _| panic!(
                "no hop is consulted when the ancestry is unreadable"
            )),
            Err("recycle_caller_unresolved")
        );
        // With no marker there is nothing to resolve, even for a claimed descendant, and
        // neither the ancestry nor the hop port is consulted.
        assert_eq!(
            resolve_headless_caller(
                d.path(),
                &|_| None,
                &|_| panic!("ancestry is not consulted without a marker"),
                &|_, _| panic!("no hop is consulted without a marker")
            ),
            Err("recycle_caller_unresolved")
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fresh_request_needs_a_written_and_stamped_handover_for_this_session() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(RECORD_FILE);
        let write = |v: serde_json::Value, mode: u32| {
            std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let stamped = "a".repeat(64);
        let good = serde_json::json!({
            "handover": {"state": "written", "seed_sha256": stamped, "session_id": ID}
        });
        // No record at all: unreadable, never "fine".
        assert_eq!(
            handover_written_at(d.path(), ID),
            Err("recycle_handover_unreadable")
        );
        // A record the writer produced with the process umask is ACCEPTED: `0644` on a
        // default host and `0664` on a `umask 002` host (the group bit is bounded by the
        // handle dir csq creates).
        write(good.clone(), 0o644);
        assert_eq!(handover_written_at(d.path(), ID), Ok(()));
        write(good.clone(), 0o664);
        assert_eq!(handover_written_at(d.path(), ID), Ok(()));
        // A record OTHER users could write is a forgeable precondition: refused.
        write(good.clone(), 0o646);
        assert_eq!(
            handover_written_at(d.path(), ID),
            Err("recycle_handover_unreadable")
        );
        // Still being written.
        write(
            serde_json::json!({"handover": {"state": "writing", "seed_sha256": stamped, "session_id": ID}}),
            0o644,
        );
        assert_eq!(
            handover_written_at(d.path(), ID),
            Err("recycle_handover_not_written")
        );
        // Written but not stamped.
        write(
            serde_json::json!({"handover": {"state": "written", "seed_sha256": "zz", "session_id": ID}}),
            0o644,
        );
        assert_eq!(
            handover_written_at(d.path(), ID),
            Err("recycle_handover_not_stamped")
        );
        // Another session's handover must never arm this one.
        write(good.clone(), 0o644);
        assert_eq!(
            handover_written_at(d.path(), "another-session"),
            Err("recycle_handover_session_mismatch")
        );
        // A SYMLINKED record is refused (no-follow open), even when it points at a good one.
        let target = d.path().join("real-record.json");
        std::fs::write(&target, serde_json::to_vec(&good).unwrap()).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(&target, &p).unwrap();
        assert_eq!(
            handover_written_at(d.path(), ID),
            Err("recycle_handover_unreadable")
        );
        std::fs::remove_file(&p).unwrap();
        // An OVERSIZED record is refused, never parsed.
        let mut huge = good.clone();
        huge["padding"] = serde_json::Value::String("x".repeat(70 * 1024));
        write(huge, 0o644);
        assert_eq!(
            handover_written_at(d.path(), ID),
            Err("recycle_handover_unreadable")
        );
    }

    #[test]
    fn a_second_request_is_refused_while_one_is_queued_or_in_flight() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(check_idle(d.path()), Ok(()));
        write_request(d.path(), ID, "", "t", Mode::Resume).unwrap();
        assert_eq!(check_idle(d.path()), Err("recycle_already_queued"));
        remove_request(d.path());
        let mut r = RecycleResult {
            v: 1,
            outcome: Outcome::Waiting,
            request_id: None,
            session_id: None,
            requested_at: None,
            old_pid: None,
            new_pid: None,
            rss_before_bytes: None,
            tag: None,
            mode: Mode::Resume,
            nonce: None,
            prior_nonces: Vec::new(),
            at: "t".into(),
        };
        write_result(d.path(), &r).unwrap();
        assert_eq!(check_idle(d.path()), Err("recycle_in_flight"));
        r.outcome = Outcome::InProgress;
        write_result(d.path(), &r).unwrap();
        assert_eq!(check_idle(d.path()), Err("recycle_in_flight"));
        r.outcome = Outcome::Recycled;
        write_result(d.path(), &r).unwrap();
        assert_eq!(check_idle(d.path()), Ok(()));
    }

    #[test]
    fn a_self_request_waits_for_the_issue_lock_and_refuses_a_queued_request() {
        // Security R2 M4: `check_idle` is a READ. Without a lock shared with the daemon's
        // foreign issue, a self request can pass it and then overwrite a request the daemon
        // wrote in the window. This test holds the lock (as `serve` does), writes the foreign
        // request while it is held, then releases: the self path must see it and refuse.
        let d = tempfile::tempdir().unwrap();
        let guard = crate::platform::lock::try_lock_file_bounded_nofollow(
            &crate::session::recycle_consent::consent_lock_path(d.path()),
            50,
            std::time::Duration::from_millis(20),
        )
        .unwrap()
        .expect("the fixture takes the lock");
        let handle = d.path().to_path_buf();
        let h =
            std::thread::spawn(move || queue_request_locked(&handle, ID, "r", "t", Mode::Resume));
        // Well past any plausible scheduling of the thread's check_idle if it did NOT block.
        std::thread::sleep(std::time::Duration::from_millis(150));
        // The daemon's write, under the lock.
        write_request(d.path(), ID, "r", "t", Mode::Resume).unwrap();
        drop(guard);
        assert_eq!(
            h.join().unwrap(),
            Err("recycle_already_queued"),
            "the locked write must see the request written under the lock"
        );
        assert!(d.path().join(REQUEST_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn launch_artifacts_must_still_be_the_same_regular_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("scaffold.md");
        std::fs::write(&f, b"rules").unwrap();
        let prefix = vec![
            OsString::from("--append-system-prompt-file"),
            f.clone().into_os_string(),
            OsString::from("--settings"),
            OsString::from("{\"inline\":true}"),
        ];
        let rec = record_artifacts(&prefix).unwrap();
        assert_eq!(rec.len(), 1, "inline JSON is not a file artifact");
        assert_eq!(verify_artifacts(&rec), Ok(()));
        std::fs::write(&f, b"swapped").unwrap();
        assert_eq!(
            verify_artifacts(&rec),
            Err("recycle_launch_artifact_changed")
        );
        std::fs::write(&f, b"rules").unwrap();
        assert_eq!(verify_artifacts(&rec), Ok(()));
        std::fs::remove_file(&f).unwrap();
        assert_eq!(
            verify_artifacts(&rec),
            Err("recycle_launch_artifact_changed")
        );
        std::os::unix::fs::symlink("/etc/hosts", &f).unwrap();
        assert_eq!(
            verify_artifacts(&rec),
            Err("recycle_launch_artifact_changed"),
            "symlink"
        );
        assert_eq!(
            record_artifacts(&prefix),
            Err("recycle_launch_artifact_unreadable")
        );
    }

    struct FakeProbe {
        own: Result<String, Tag>,
        shared: Result<bool, Tag>,
    }
    impl SessionProbe for FakeProbe {
        fn session_id_of(&self, _: u32, _: Option<&Path>) -> Result<String, Tag> {
            self.own.clone()
        }
        fn held_by_other(&self, _: &str, _: u32) -> Result<bool, Tag> {
            self.shared
        }
    }

    #[test]
    fn session_binding_requires_the_childs_own_id_and_no_other_holder() {
        let ok = FakeProbe {
            own: Ok(ID.into()),
            shared: Ok(false),
        };
        assert_eq!(verify_session_binding(&ok, 1, Path::new("/h"), ID), Ok(()));
        assert_eq!(
            verify_session_binding(&ok, 1, Path::new("/h"), OTHER),
            Err("recycle_session_id_mismatch")
        );
        let unknown = FakeProbe {
            own: Err("recycle_session_unknown"),
            shared: Ok(false),
        };
        assert_eq!(
            verify_session_binding(&unknown, 1, Path::new("/h"), ID),
            Err("recycle_session_unknown")
        );
        let shared = FakeProbe {
            own: Ok(ID.into()),
            shared: Ok(true),
        };
        assert_eq!(
            verify_session_binding(&shared, 1, Path::new("/h"), ID),
            Err("recycle_session_id_shared")
        );
        let unsure = FakeProbe {
            own: Ok(ID.into()),
            shared: Err("recycle_session_enumeration_incomplete"),
        };
        assert_eq!(
            verify_session_binding(&unsure, 1, Path::new("/h"), ID),
            Err("recycle_session_enumeration_incomplete")
        );
    }

    #[cfg(unix)]
    #[test]
    fn signal_window_installs_process_wide_handlers_only_while_open_and_restores_them() {
        let _serial = WINDOW_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            assert!(!SignalWindow::handler_installed(sig));
        }
        let w = SignalWindow::open().unwrap();
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            assert!(SignalWindow::handler_installed(sig), "{sig}");
        }
        assert_eq!(w.pending(), None);
        // A real process-directed signal during the window is flagged, not fatal.
        // SAFETY: raising SIGHUP at ourselves with the window's handler installed.
        unsafe { libc::kill(libc::getpid(), libc::SIGHUP) };
        wait_flag(&w);
        assert_eq!(w.pending(), Some(libc::SIGHUP));
        drop(w);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            assert!(!SignalWindow::handler_installed(sig), "restored: {sig}");
        }
    }

    #[cfg(unix)]
    fn wait_flag(w: &SignalWindow) {
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while w.pending().is_none() && std::time::Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn identity_checks_tolerate_one_second_of_start_time_drift_but_no_more() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        write_supervisor(d.path(), 4242, Ok(()), d.path()).unwrap();
        let p = d.path().join(SUPERVISOR_FILE);
        let mut m: SupervisorMarker = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        let put = |m: &SupervisorMarker| {
            std::fs::write(&p, serde_json::to_vec(m).unwrap()).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        m.csq_start += 1; // btime drift on Linux
        put(&m);
        assert_eq!(
            check_supervised(d.path(), 4242),
            Ok(()),
            "1 s drift is the same process"
        );
        m.csq_start += 1;
        put(&m);
        assert_eq!(
            check_supervised(d.path(), 4242),
            Err("recycle_unsupervised"),
            "2 s is not"
        );
    }

    // Unix fixture (`sh` on PATH, `/bin/sh`); the relaunch it covers is
    // Unix-only (`recycle_supervise` is `cfg(unix)`).
    #[cfg(unix)]
    #[test]
    fn the_relaunch_uses_the_program_resolved_at_launch_not_a_fresh_path_lookup() {
        let mut spec = Command::new("sh");
        spec.arg("--model").arg("m");
        let plan = build_plan(&spec, &os(&["--model", "m"])).unwrap();
        let cmd = relaunch_command(&spec, &plan, ID, None);
        assert!(
            Path::new(cmd.get_program()).is_absolute(),
            "{:?}",
            cmd.get_program()
        );
        assert_eq!(cmd.get_program(), plan.program.as_os_str());
    }

    /// Security R1 C1: the spec carries the post-scrub map, and the X1 scrub
    /// REMOVES keys rather than recording them as explicit `env_remove`s. Copying
    /// the map without clearing first re-admits every removed key by inheritance
    /// from csq's own environment on the second child.
    #[cfg(unix)]
    #[test]
    fn the_relaunch_child_inherits_only_the_spec_environment() {
        use std::os::unix::fs::PermissionsExt;

        let _g = crate::platform::test_env::lock();
        let d = tempfile::tempdir().unwrap();
        let script = d.path().join("print-env.sh");
        std::fs::write(&script, "#!/bin/sh\nenv\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // The parent carries a token the launch scrub would have removed from
        // the spec; the relaunch must not re-admit it.
        std::env::set_var("CSQ_RECYCLE_TEST_GITHUB_TOKEN", "ghp_canary");
        let mut spec = Command::new(&script);
        spec.env_clear();
        spec.env("PATH", "/usr/bin:/bin");
        spec.env("CSQ_RECYCLE_SPEC_MARKER", "kept");
        let plan = build_plan(&spec, &[]).unwrap();
        let out = relaunch_command(&spec, &plan, ID, None).output().unwrap();
        std::env::remove_var("CSQ_RECYCLE_TEST_GITHUB_TOKEN");

        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("CSQ_RECYCLE_SPEC_MARKER=kept"),
            "the spec environment must survive: {text}"
        );
        assert!(
            !text.contains("CSQ_RECYCLE_TEST_GITHUB_TOKEN"),
            "the parent environment leaked into the relaunch child: {text}"
        );
    }

    /// an internal ticket: the first child's env carries the per-session `TMPDIR`
    /// (`<handle dir>/tmp`, created by `session::tmpdir::ensure_session_tmpdir`);
    /// the relaunch replays that map under `env_clear`, so the replacement child
    /// keeps the SAME per-session temp dir — on the resume path AND the fresh
    /// path — instead of sending its temp writes back to the shared system temp
    /// dir this issue exists to get out of. Dropping the value here would leave
    /// the relaunched half of a session leaking into the ownerless folder.
    #[test]
    fn relaunch_command_carries_the_sessions_tmpdir_for_resume_and_fresh_relaunches() {
        let session_tmp = "/Users/u/.claude/accounts/term-4242/tmp";
        let mut spec = Command::new("/bin/claude");
        spec.env_clear();
        spec.env("PATH", "/usr/bin:/bin");
        spec.env("TMPDIR", session_tmp);
        let plan = RelaunchPlan {
            program: PathBuf::from("/bin/claude"),
            prefix: Vec::new(),
            user: Vec::new(),
        };
        let fresh = FreshContext {
            prompt: OsString::from(FRESH_PROMPT),
            env: vec![(OsString::from(PROOF_ENV), OsString::from("v1,proof"))],
        };

        for cmd in [
            relaunch_command(&spec, &plan, ID, None),
            relaunch_command(&spec, &plan, ID, Some(&fresh)),
        ] {
            let carried: Vec<(OsString, Option<OsString>)> = cmd
                .get_envs()
                .map(|(k, v)| (k.to_os_string(), v.map(OsString::from)))
                .collect();
            assert!(
                carried.iter().any(|(k, v)| {
                    k == OsStr::new("TMPDIR") && v.as_deref() == Some(OsStr::new(session_tmp))
                }),
                "the relaunch must replay the session TMPDIR: {carried:?}"
            );
        }
    }

    /// an internal ticket: the relaunch RE-ENSURES the per-session TMPDIR before the spawn,
    /// so a `tmp/` removed mid-session is recreated and a symlinked one refuses
    /// — and the value is set explicitly, so a session launched before an internal ticket
    /// (whose spec carries no `TMPDIR`) still gets one.
    ///
    /// This test REDs without [`relaunch_with_session_tmpdir`]: the carried map
    /// alone leaves `TMPDIR` absent (or stale), which the replay test above
    /// cannot detect because it supplies the value by hand.
    #[test]
    fn relaunch_re_ensures_the_session_tmpdir_and_refuses_a_symlinked_one() {
        let base = tempfile::tempdir().unwrap();
        let handle = base.path().join("term-4242");
        std::fs::create_dir(&handle).unwrap();
        let tmp = handle.join(crate::session::tmpdir::SESSION_TMPDIR_DIR);
        assert!(!tmp.exists(), "the first launch's tmp/ was removed");

        let plan = RelaunchPlan {
            program: PathBuf::from("/bin/claude"),
            prefix: Vec::new(),
            user: Vec::new(),
        };
        let spec = Command::new("/bin/claude");
        let next = relaunch_with_session_tmpdir(&handle, relaunch_command(&spec, &plan, ID, None))
            .expect("a real handle dir yields a usable TMPDIR");
        let carried: Vec<(OsString, Option<OsString>)> = next
            .get_envs()
            .map(|(k, v)| (k.to_os_string(), v.map(OsString::from)))
            .collect();
        assert!(
            carried
                .iter()
                .any(|(k, v)| k == OsStr::new("TMPDIR") && v.as_deref() == Some(tmp.as_os_str())),
            "TMPDIR must be the re-ensured path: {carried:?}"
        );
        assert!(
            tmp.is_dir(),
            "the relaunch re-created the dir before the spawn"
        );

        #[cfg(unix)]
        {
            std::fs::remove_dir(&tmp).unwrap();
            std::os::unix::fs::symlink(base.path().join("elsewhere"), &tmp).unwrap();
            let err =
                relaunch_with_session_tmpdir(&handle, relaunch_command(&spec, &plan, ID, None))
                    .unwrap_err();
            assert_eq!(err, crate::session::tmpdir::SESSION_TMPDIR_TAG);
        }
    }

    /// an internal ticket R2 C4: the supervisor actually calls the re-ensure helper. The
    /// helper test above would stay green if the wiring were dropped, so the
    /// supervisor source is pinned.
    #[test]
    fn the_supervisor_wires_the_relaunch_tmpdir_re_ensure() {
        let src = include_str!("recycle_supervise.rs");
        let needle = concat!("relaunch_with_session_tmpdir", "(handle, next)");
        assert_eq!(
            src.matches(needle).count(),
            1,
            "the relaunch must pass through the TMPDIR re-ensure"
        );
    }

    /// The spawn-instant X1 check: a present manifest that is not `verified`
    /// refuses the relaunch; verified/absent pass; the supervisor really calls it
    /// at the spawn instant (a helper-only green would not prove the wiring).
    #[test]
    fn guard_manifest_refusal_refuses_a_mismatch_and_passes_a_match() {
        let base = tempfile::tempdir().unwrap();
        let handle = base.path().join("term-1");
        std::fs::create_dir_all(&handle).unwrap();
        let digest = crate::launch_isolation::sha256_hex(b"{}");
        std::fs::write(
            base.path().join(crate::launch_isolation::MANIFEST_FILE),
            format!(
                r#"{{"manifest_version":1,"source":"local","entries":[{{"path":"settings.json","sha256":"{digest}","scope":"handle-dir"}}]}}"#
            ),
        )
        .unwrap();

        std::fs::write(handle.join("settings.json"), b"changed").unwrap();
        assert_eq!(
            guard_manifest_refusal(&handle, base.path()),
            Err("recycle_guard_manifest_refused"),
            "a mismatch refuses the relaunch"
        );
        std::fs::write(handle.join("settings.json"), b"{}").unwrap();
        assert_eq!(guard_manifest_refusal(&handle, base.path()), Ok(()));

        std::fs::write(
            base.path().join(crate::launch_isolation::MANIFEST_FILE),
            r#"{"manifest_version":1,"source":"local","entries":[]}"#,
        )
        .unwrap();
        assert_eq!(
            guard_manifest_refusal(&handle, base.path()),
            Err("recycle_guard_manifest_refused"),
            "an empty (invalid) manifest refuses"
        );

        std::fs::remove_file(base.path().join(crate::launch_isolation::MANIFEST_FILE)).unwrap();
        assert_eq!(guard_manifest_refusal(&handle, base.path()), Ok(()));

        let source = include_str!("recycle_supervise.rs");
        let needle = concat!(
            "guard_manifest_refusal(self.launch.handle, &self.launch",
            ".cwd)"
        );
        assert_eq!(
            source.matches(needle).count(),
            1,
            "the supervisor must re-check the guard manifest at the spawn instant"
        );
    }

    #[test]
    fn turn_end_parser_accepts_measured_bookkeeping_stop_sequence_and_balanced_queue_ops() {
        let q = |op: &str| line(serde_json::json!({"type":"queue-operation","operation":op}));
        // cost-state / agent-setting / isolation-latch / frame-link after the end (measured over 116
        // transcripts of the last 7 days: Ended 14 before, 63 after these rules)
        let mut s = asst("end_turn", false);
        s.extend(typed("cost-state"));
        s.extend(typed("agent-setting"));
        s.extend(typed("isolation-latch"));
        s.extend(typed("frame-link"));
        assert_eq!(turn_state(&s, true), Ok(TurnState::Ended));
        // stop_sequence with no tool_use is terminal
        let mut s = asst("stop_sequence", false);
        s.extend(typed("cost-state"));
        assert_eq!(turn_state(&s, true), Ok(TurnState::Ended));
        // an enqueue cancelled by a remove is balanced; a pending enqueue is queued input
        let mut s = asst("end_turn", false);
        s.extend(q("enqueue"));
        s.extend(q("remove"));
        s.extend(typed("cost-state"));
        assert_eq!(turn_state(&s, true), Ok(TurnState::Ended));
        let mut s = asst("end_turn", false);
        s.extend(q("enqueue"));
        s.extend(typed("cost-state"));
        assert_eq!(turn_state(&s, true), Ok(TurnState::Busy("input_queued")));
        // a dequeue means the queued input is being processed: the next turn started
        let mut s = asst("end_turn", false);
        s.extend(q("enqueue"));
        s.extend(q("dequeue"));
        assert_eq!(
            turn_state(&s, true),
            Ok(TurnState::Busy("next_turn_started"))
        );
        // max_tokens is not a finished turn
        assert_eq!(
            turn_state(&asst("max_tokens", false), true),
            Ok(TurnState::Busy("not_end_turn"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_option_token_is_unclassifiable() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0x2d, 0x2d, 0xff, 0xfe]);
        assert_eq!(
            classify_user_args(std::slice::from_ref(&bad)),
            Err("recycle_argv_unclassifiable")
        );
        assert_eq!(
            classify_user_args(&[OsString::from("--model"), OsString::from_vec(vec![0xff])])
                .map(|v| v.len()),
            Ok(2),
            "a non-UTF-8 VALUE of a known option is just a value"
        );
        assert_eq!(
            classify_user_args(&[OsString::from("--verbose"), bad]),
            Err("recycle_argv_unclassifiable")
        );
    }

    #[cfg(unix)]
    #[test]
    fn group_or_other_writable_artifacts_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("scaffold.md");
        std::fs::write(&f, b"rules").unwrap();
        let prefix = vec![
            OsString::from("--append-system-prompt-file"),
            f.clone().into_os_string(),
        ];
        for mode in [0o620, 0o602, 0o666] {
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                record_artifacts(&prefix),
                Err("recycle_launch_artifact_unreadable"),
                "{mode:o}"
            );
        }
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            record_artifacts(&prefix).is_ok(),
            "read-only to others is fine"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reconcile_accepts_a_gate_rewrite_but_not_an_outside_change() {
        let d = tempfile::tempdir().unwrap();
        let (gate_file, other) = (d.path().join("settings.json"), d.path().join("scaffold.md"));
        std::fs::write(&gate_file, b"v1").unwrap();
        std::fs::write(&other, b"rules").unwrap();
        let prefix = vec![
            OsString::from("--settings"),
            gate_file.clone().into_os_string(),
            OsString::from("--append-system-prompt-file"),
            other.clone().into_os_string(),
        ];
        let rec = record_artifacts(&prefix).unwrap();
        // the gates rewrite the settings file (changes between before and after)
        let before = snapshot_artifacts(&rec);
        std::fs::write(&gate_file, b"v2-written-by-the-gate").unwrap();
        let after = snapshot_artifacts(&rec);
        let fresh = reconcile_artifacts(&rec, &before, &after).unwrap();
        assert_eq!(
            verify_artifacts(&fresh),
            Ok(()),
            "re-recorded from the gate's own write"
        );
        assert_eq!(
            verify_artifacts(&rec),
            Err("recycle_launch_artifact_changed"),
            "the old record is stale"
        );
        // an outside change to the scaffold, NOT during the gates, is refused
        std::fs::write(&other, b"swapped").unwrap();
        let (b2, a2) = (snapshot_artifacts(&fresh), snapshot_artifacts(&fresh));
        assert_eq!(
            reconcile_artifacts(&fresh, &b2, &a2),
            Err("recycle_launch_artifact_changed")
        );
    }

    #[test]
    fn descendant_tree_uses_each_pids_own_read_parent() {
        use std::collections::HashMap;
        // 10 = root. 11 child of 10, 12 child of 11. 13 claims parent 99 (a recycled pid whose
        // read parent is outside the tree) and 14 has root's parent as its parent.
        let reads: HashMap<u32, (u32, u64)> = HashMap::from([
            (11, (10, 100)),
            (12, (11, 101)),
            (13, (99, 102)),
            (14, (1, 103)),
            (10, (1, 99)),
        ]);
        assert_eq!(tree_from_reads(10, &reads), vec![(11, 100), (12, 101)]);
    }

    #[cfg(unix)]
    #[test]
    fn holder_verdict_fails_closed_on_an_existing_but_unvalidated_entry() {
        use super::{holder_verdict, EntryState::*};
        assert_eq!(holder_verdict(Absent, "x"), Ok(false));
        assert_eq!(holder_verdict(Present(Some("X".into())), "x"), Ok(true));
        assert_eq!(holder_verdict(Present(Some("y".into())), "x"), Ok(false));
        assert!(holder_verdict(Present(None), "x").is_err());
        assert!(holder_verdict(Unreadable, "x").is_err());
    }
}
