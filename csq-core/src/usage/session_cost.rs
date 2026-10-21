//! Statusline session cost for non-Anthropic slots, priced from csq's manifest.
//!
//! Claude Code prices EVERY model at Anthropic rates, so the `cost.total_cost_usd`
//! it sends the statusline is wrong for a DeepSeek / MiniMax / Z.AI / Ollama slot.
//! For such a slot this module prices the session's transcript through the runtime
//! model manifest ([`ModelManifest`], spec 07 §7.11), converting usage records with
//! the SAME function the ledger uses
//! ([`attributed_session_to_events_with_manifest`]) so cache tokens bill identically.
//!
//! ## Which slots are manifest-priced
//!
//! [`pricing_gate_for_slot`] decides from csq's OWN binding metadata
//! ([`claude_code_slot_evidence`]: identity store `by_slot`, the pre-A++ legacy
//! mirrors, and THIS slot's `settings.json`), never from the model id or from the
//! mere presence of an `ANTHROPIC_BASE_URL`. The gate asks each predicate
//! separately instead of taking the precedence-ordered union detector's first
//! match, so a slot carrying BOTH an Anthropic and a third-party binding (rebound
//! without `csq logout`) is `$?`, not Anthropic:
//!
//! * Anthropic OAuth binding and no third-party binding → CC's number (a gateway
//!   URL on such a slot does not change what Anthropic bills).
//! * Anthropic AND third-party binding → `$?` (it is not knowable which one the
//!   spawned `claude` is talking to).
//! * Cloud Claude (Vertex / Bedrock, [`backend_for_slot`]) → CC's number; those
//!   are Claude models whatever their id looks like (`anthropic.claude-…`,
//!   `arn:aws:bedrock:…`).
//! * Third-party API-key provider (DeepSeek, MiniMax, Z.AI, Kimi bearer, Ollama)
//!   → manifest-priced.
//! * Anything else, including a binding that cannot be read → `$?`.
//!
//! The gate reads only the slot's own `settings.json` (twice at most); it never
//! scans the other slots' settings on a render.
//!
//! ## Outcomes
//!
//! * [`CostDisplay::CcReported`]: keep CC's number.
//! * [`CostDisplay::Priced`]: every request priced from the manifest.
//! * [`CostDisplay::Unknown`]: rendered `$?`; CC's Anthropic-priced figure is never
//!   substituted for a slot that might be third-party.
//!
//! ## Account/terminal separation
//!
//! This is a READ path. The per-session cache written below is DISPLAY state (token
//! counts, opaque request ids and a running USD total; no quota, no ledger row, no
//! credentials and no message content); it is never read by the quota or ledger
//! pipelines, so `account-terminal-separation.md` MUST 2 / MUST NOT 2 hold.
//!
//! ## Bounded, non-blocking reads
//!
//! [`FsTranscriptReader`] opens with `O_NOFOLLOW | O_NONBLOCK`, checks the OPENED
//! handle is a regular file, and the whole render (parent plus every subagent file
//! together) reads at most [`MAX_READ_BYTES`]; the fingerprint prefix and the read a rewrite
//! discards are charged against it like any other byte read. A transcript larger than the budget
//! is consumed over several renders and shows `$?` until caught up. The
//! `transcript_path` must resolve under Claude Code's `projects/` directory
//! (`<config dir>/projects` or `<claude home>/projects`); anything else is `$?`.
//!
//! ## Incremental, always-progressing cache
//!
//! The cache is keyed per session (`.csq-statusline-cost-<session_id>.json`) and is
//! written ONLY when the config dir is a csq handle dir (`term-<pid>`); otherwise
//! the cost is computed with no persistent state, so a permanent `config-N` never
//! receives a file (and a transcript above one budget stays `$?` there, because
//! nothing carries progress between renders).
//!
//! Per file it holds the byte offset after the last complete line, a hash of the
//! [`FINGERPRINT_BYTES`] before it (so a rewrite is detected, not assumed away),
//! the metadata-only snapshots of the recent tail, and a running total for
//! everything older. Snapshots older than [`FOLD_MARGIN_LINES`] lines are priced
//! and folded into `folded_usd`, so the entry stays small however large the
//! transcript grows, and a transcript over one budget converges after
//! `ceil(size / MAX_READ_BYTES)` renders.
//!
//! Request-id de-duplication stays correct because a request is folded only when
//! NONE of its snapshots is inside the tail window: its identity (`requestId`,
//! else `message.id`) is looked up across all retained snapshots first. What is
//! assumed, not verified: Claude Code writes a request's streaming snapshots within
//! [`FOLD_MARGIN_LINES`] lines of each other. When that is violated the cost is
//! `$?`, not a double count: each file keeps the hashes of its most recently
//! folded request ids ([`MAX_FOLDED_IDS`] per file, 8 bytes each in memory, at
//! most ~21 bytes each as JSON, so under 90 KiB per file, and the whole cache is
//! still refused above `MAX_CACHE_BYTES`); a tail snapshot whose request id is in
//! that set makes the entry uncertain ([`UnknownReason::RequestStraddlesFold`]).
//! The guarantee covers the newest [`MAX_FOLDED_IDS`] folded requests; a straddle
//! further back than that is not detected.
//!
//! A cache file is untrusted input: a negative, absurd or non-finite number, or an
//! internally inconsistent entry, discards the whole cache (`valid_entry`).
//!
//! Each new session id in a long-lived handle dir adds a cache file; on save the
//! dir keeps at most [`MAX_CACHE_FILES`] of this module's files (the newest).
//!
//! The folded total depends on the manifest and on the fallback model, so both are
//! hashed into the entry; a different manifest discards the entry and re-parses.

use super::aggregator::{
    attributed_session_to_events_with_manifest, AttributedSession, ScannedSession,
};
use super::request::{RequestCollector, SnapshotUsage, UsageSnapshot};
use crate::accounts::binding_guard::claude_code_slot_evidence;
use crate::providers::model_manifest::ModelManifest;
use crate::providers::settings::backend_for_slot;
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Most bytes read from transcripts in ONE RENDER, shared by the parent and every
/// subagent file. Bounds the parse time and memory of one statusline invocation.
pub const MAX_READ_BYTES: u64 = 32 * 1024 * 1024;

/// Bytes before the consumed offset that are re-read and hashed to prove the
/// transcript was appended to rather than rewritten. 4 KiB spans several whole
/// records, each carrying its own request id and timestamp, so two different
/// transcripts cannot share it by sharing a line's fixed-shape suffix. It does NOT
/// detect an in-place edit elsewhere in the file that leaves these bytes and the
/// length unchanged; Claude Code appends to transcripts, never edits them.
pub const FINGERPRINT_BYTES: u64 = 4096;

/// Snapshots within this many lines of the end of a file stay raw in the cache;
/// older, fully-closed requests are priced and folded into a running total.
pub const FOLD_MARGIN_LINES: u64 = 512;

/// Largest cache file loaded or written. A cache that would exceed it is not
/// saved; with folding that needs several hundred subagent files each carrying a
/// full tail window, and the render still shows a correct number or `$?`.
const MAX_CACHE_BYTES: u64 = 8 * 1024 * 1024;

/// Most subagent transcripts priced in one render; beyond it the cost is
/// `$?` rather than a partial sum.
pub const MAX_SUBAGENT_FILES: usize = 512;

const CACHE_VERSION: u32 = 4;

/// Folded-request hashes kept per file (newest win). Bounds both the cache size
/// and the straddle guarantee (see the module docs).
pub const MAX_FOLDED_IDS: usize = 4096;

/// Most `.csq-statusline-cost-*.json` files kept in one handle dir.
pub const MAX_CACHE_FILES: usize = 4;

/// Most directory entries examined when pruning old cache files.
const MAX_PRUNE_SCAN: usize = 4096;

/// Largest USD total a cache entry may carry; anything above is tampering.
const MAX_SANE_USD: f64 = 1.0e9;

/// Largest single token count a cache snapshot may carry.
const MAX_SANE_TOKENS: u64 = 1 << 40;

/// Longest id / model / path string a cache entry may carry.
const MAX_SANE_STR: usize = 4096;

/// Prefix of the display-state cache file inside a handle dir; the file is
/// `<prefix><session_id>.json`.
pub const CACHE_FILE_PREFIX: &str = ".csq-statusline-cost-";

/// The cache file name for `session_id`, or `None` when the id is not
/// `[A-Za-z0-9_-]{1,128}` (it becomes part of a file name).
pub fn cache_file_name(session_id: &str) -> Option<String> {
    let ok = (1..=128).contains(&session_id.len())
        && session_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ok.then(|| format!("{CACHE_FILE_PREFIX}{session_id}.json"))
}

/// True when `dir` is a csq handle dir: a real (non-symlink) directory named
/// `term-<digits>`. The cache is written only into such a dir.
fn is_handle_dir(dir: &Path) -> bool {
    let name_ok = dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(crate::session::handle_dir::is_term_handle_dir_name);
    name_ok
        && std::fs::symlink_metadata(dir)
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false)
}

/// What the statusline cost segment shows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CostDisplay {
    /// Anthropic or cloud-Claude slot: keep CC's own `total_cost_usd`.
    CcReported,
    /// Third-party slot priced from csq's manifest.
    Priced(f64),
    /// Could not price: render `$?`.
    Unknown(UnknownReason),
}

/// Why a cost is unknown. Fixed vocabulary, safe to log (no token or content).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownReason {
    ManifestInvalid,
    TranscriptUnavailable,
    ModelUnpriced,
    CatchingUp,
    TooManyTranscripts,
    /// The slot's binding is unreadable or not a Claude Code binding, so it cannot
    /// be shown to be Anthropic; CC's number is not substituted.
    BindingUnreadable,
    /// A transcript line too large to read (and carrying usage text) was skipped,
    /// so the total would be a lower bound.
    OverlongLine,
    /// A request already folded into the running total has a later snapshot, so
    /// the request would be priced twice.
    RequestStraddlesFold,
}

/// How a slot's session cost is sourced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PricingGate {
    /// Third-party API-key provider: price from the manifest.
    Manifest,
    /// Anthropic OAuth or cloud Claude: CC's number is correct.
    CcReported,
    /// No readable Claude Code binding, or evidence of BOTH an Anthropic and a
    /// third-party binding: `$?`.
    Unreadable,
}

/// Decides the pricing source from csq's binding metadata (read-only).
///
/// Sourced from [`claude_code_slot_evidence`], NOT `detect_bound_surface`: that
/// detector returns the first match in precedence order, which masks a
/// third-party binding behind a stale Anthropic identity
/// (`guard-reader-writer-parity.md` MUST-3).
pub fn pricing_gate_for_slot(base_dir: &Path, slot: AccountNum) -> PricingGate {
    let ev = claude_code_slot_evidence(base_dir, slot);
    // Codex / Gemini / native bindings have no Claude Code statusline.
    if ev.other_surface {
        return PricingGate::Unreadable;
    }
    // Cloud Claude (Vertex / Bedrock) runs Claude models whatever the id looks like.
    if backend_for_slot(base_dir, slot.get()).is_cloud() {
        return PricingGate::CcReported;
    }
    match (ev.anthropic, ev.third_party) {
        (true, Ok(false)) => PricingGate::CcReported,
        (false, Ok(true)) => PricingGate::Manifest,
        // Both bindings, an unreadable settings file, or no binding at all: it
        // cannot be shown which provider the run is billed by.
        _ => PricingGate::Unreadable,
    }
}

/// File metadata the cache is keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TranscriptStat {
    pub len: u64,
    pub mtime_ns: u64,
}

/// Injected transcript access, so tests never touch the real `~/.claude`.
pub trait TranscriptReader {
    fn stat(&self, path: &Path) -> std::io::Result<TranscriptStat>;
    /// Reads up to `max` bytes starting at `from`.
    fn read_range(&self, path: &Path, from: u64, max: u64) -> std::io::Result<Vec<u8>>;
    /// The `*.jsonl` files directly inside `dir`, sorted, at most
    /// [`MAX_SUBAGENT_FILES`]` + 1` of them (iteration stops there). An ABSENT
    /// `dir` is `Ok(vec![])` (a session with no subagents); a symlink,
    /// non-directory or any unreadable entry is an error, never a shorter list,
    /// so a refused or partly-read directory cannot read as "less subagent spend".
    fn list_jsonl(&self, dir: &Path) -> std::io::Result<Vec<PathBuf>>;
}

/// The production reader: no-follow, non-blocking, regular files only.
pub struct FsTranscriptReader;

impl FsTranscriptReader {
    fn open(path: &Path) -> std::io::Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            /// `FILE_FLAG_OPEN_REPARSE_POINT`: open a reparse point itself.
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = opts.open(path)?;
        if !file.metadata()?.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not a regular file",
            ));
        }
        Ok(file)
    }
}

impl TranscriptReader for FsTranscriptReader {
    fn stat(&self, path: &Path) -> std::io::Result<TranscriptStat> {
        // Stat the OPENED handle, so the regular-file check and the size/mtime
        // describe the same inode.
        let meta = Self::open(path)?.metadata()?;
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Ok(TranscriptStat {
            len: meta.len(),
            mtime_ns,
        })
    }

    fn list_jsonl(&self, dir: &Path) -> std::io::Result<Vec<PathBuf>> {
        // lstat the SESSION directory (`dir`'s parent) too: a symlinked
        // `<session>/` would otherwise be followed by the `subagents/` lstat below
        // and by `read_dir`, escaping the `projects/` confinement.
        if let Some(session_dir) = dir.parent() {
            match std::fs::symlink_metadata(session_dir) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(e) => return Err(e),
                Ok(m) if m.file_type().is_dir() => {}
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "session dir is not a real directory",
                    ))
                }
            }
        }
        // lstat: a symlinked `subagents/` is refused, matching the ledger
        // scanner's tier-3 admission (`aggregator::admit_dir`).
        match std::fs::symlink_metadata(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
            Ok(m) if m.file_type().is_dir() => {}
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "not a directory",
                ))
            }
        }
        jsonl_from_entries(std::fs::read_dir(dir)?.map(|e| e.map(|e| e.path())))
    }

    fn read_range(&self, path: &Path, from: u64, max: u64) -> std::io::Result<Vec<u8>> {
        let mut file = Self::open(path)?;
        file.seek(SeekFrom::Start(from))?;
        let mut buf = Vec::new();
        file.take(max).read_to_end(&mut buf)?;
        Ok(buf)
    }
}

/// The `*.jsonl` paths among `entries`, sorted, pulling at most
/// [`MAX_SUBAGENT_FILES`]` + 1` jsonl items. An entry error is an error, not a
/// skipped file (a skipped file would silently lower the cost).
fn jsonl_from_entries(
    entries: impl Iterator<Item = std::io::Result<PathBuf>>,
) -> std::io::Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let path = entry?;
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            out.push(path);
            if out.len() > MAX_SUBAGENT_FILES {
                break;
            }
        }
    }
    out.sort();
    Ok(out)
}

// PRIVACY: metadata-only projections (ids, timestamp, model, four counts). No
// content field exists here, so serde drops message text. Never add one.
#[derive(Deserialize)]
struct Line {
    #[serde(rename = "requestId", default)]
    request_id: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    message: Option<Message>,
}

#[derive(Deserialize)]
struct Message {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Default, Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
}

/// One cached usage snapshot (metadata only) and its line ordinal.
#[derive(Clone, Serialize, Deserialize)]
struct CachedSnap {
    l: u64,
    r: Option<String>,
    m: Option<String>,
    u: Option<String>,
    ts: Option<String>,
    model: Option<String>,
    i: u64,
    o: u64,
    cw: u64,
    cr: u64,
}

impl CachedSnap {
    /// The request identity the collector will group by, for fold decisions.
    /// Snapshots with neither id bill alone, so they get a unique key.
    fn identity(&self) -> String {
        if let Some(r) = self.r.as_deref().filter(|s| !s.is_empty()) {
            return format!("r:{r}");
        }
        if let Some(m) = self.m.as_deref().filter(|s| !s.is_empty()) {
            return format!("m:{m}");
        }
        format!("p:{}", self.l)
    }

    /// Hash of the request identity, for the folded-request set. `None` for a
    /// snapshot with neither id: it bills alone and cannot straddle anything.
    fn id_hash(&self) -> Option<u64> {
        let has_id = [self.r.as_deref(), self.m.as_deref()]
            .into_iter()
            .flatten()
            .any(|s| !s.is_empty());
        has_id.then(|| fnv1a(self.identity().as_bytes()))
    }
}

/// On-disk shape: one entry per transcript (the parent and each subagent file).
#[derive(Serialize, Deserialize)]
struct CacheFile {
    v: u32,
    entries: Vec<Cache>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Cache {
    path: String,
    len: u64,
    mtime_ns: u64,
    consumed: u64,
    lines: u64,
    fingerprint: u64,
    /// Hash of the manifest and fallback model the folded total was priced with.
    manifest_key: u64,
    /// USD for requests already folded out of `snaps`.
    folded_usd: f64,
    /// True when a folded request had no manifest rate.
    folded_unpriced: bool,
    /// Model of the first snapshot seen (the session's fallback model).
    first_model: Option<String>,
    /// Inside an over-long line that is being skipped.
    skipping: bool,
    /// An over-long skipped line contained usage text: the total is a lower bound.
    skipped_usage: bool,
    snaps: Vec<CachedSnap>,
    /// Hashes of request ids folded into `folded_usd`, oldest first, at most
    /// [`MAX_FOLDED_IDS`].
    folded_ids: Vec<u64>,
    /// A snapshot of an already-folded request arrived later: the total counts
    /// that request twice, so it is `$?` from now on (until the file is rewritten).
    straddled: bool,
}

/// FNV-1a: stable across Rust versions (unlike `DefaultHasher`), so a cache
/// written by one build is not spuriously invalidated by another.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn contains_usage(bytes: &[u8]) -> bool {
    bytes.windows(7).any(|w| w == b"\"usage\"")
}

fn parse_line(line: &str, ordinal: u64) -> Option<CachedSnap> {
    // Only lines bearing a usage object can contribute; skipping the serde parse
    // on the rest is the same prefilter the ledger scanner uses.
    if !line.contains("\"usage\"") {
        return None;
    }
    let rec: Line = serde_json::from_str(line).ok()?;
    let msg = rec.message?;
    let u = msg.usage?;
    Some(CachedSnap {
        l: ordinal,
        r: rec.request_id,
        m: msg.id,
        u: rec.uuid,
        ts: rec.timestamp,
        model: msg.model.filter(|m| !m.is_empty()),
        i: u.input_tokens,
        o: u.output_tokens,
        cw: u.cache_creation_input_tokens,
        cr: u.cache_read_input_tokens,
    })
}

/// Per-render limits; production uses [`Limits::PRODUCTION`], tests shrink them
/// so convergence is observable on small fixtures.
#[derive(Clone, Copy)]
struct Limits {
    read_budget: u64,
    cache_bytes: u64,
}

impl Limits {
    const PRODUCTION: Limits = Limits {
        read_budget: MAX_READ_BYTES,
        cache_bytes: MAX_CACHE_BYTES,
    };
}

fn load_cache(cache_path: &Path, max_bytes: u64) -> Vec<Cache> {
    // Same no-follow, bounded, regular-file read discipline as the transcript.
    let Some(bytes) = crate::platform::fs::read_regular_nofollow_bounded(cache_path, max_bytes)
        .ok()
        .flatten()
    else {
        return Vec::new();
    };
    match serde_json::from_slice::<CacheFile>(&bytes) {
        Ok(f)
            if f.v == CACHE_VERSION
                && f.entries.len() <= MAX_SUBAGENT_FILES + 1
                && f.entries.iter().all(valid_entry) =>
        {
            f.entries
        }
        _ => Vec::new(),
    }
}

/// True when every field of a loaded entry is sane. The cache file is writable by
/// the same user (and anything running as them), so a value that would turn into a
/// wrong dollar figure, or an entry whose parts contradict each other, is refused
/// as a whole: no cache beats a trusted wrong number.
fn valid_entry(c: &Cache) -> bool {
    let str_ok = |s: &Option<String>| s.as_ref().is_none_or(|s| s.len() <= MAX_SANE_STR);
    c.path.len() <= MAX_SANE_STR
        && c.folded_usd.is_finite()
        && (0.0..=MAX_SANE_USD).contains(&c.folded_usd)
        && c.consumed <= c.len
        && c.len <= (1 << 50)
        && c.lines <= (1 << 40)
        && c.snaps.len() as u64 <= c.lines
        && c.folded_ids.len() <= MAX_FOLDED_IDS
        && str_ok(&c.first_model)
        && c.snaps.iter().all(|s| {
            (1..=c.lines).contains(&s.l)
                && [s.i, s.o, s.cw, s.cr].iter().all(|n| *n <= MAX_SANE_TOKENS)
                && [&s.r, &s.m, &s.u, &s.ts, &s.model].into_iter().all(str_ok)
        })
}

fn save_cache(cache_path: &Path, entries: Vec<Cache>, max_bytes: u64) {
    // The cache only accelerates display. A failed write can never change the
    // number shown (the next render re-parses), so it is logged by fixed tag and
    // otherwise ignored; the tmp file is removed on every failure branch.
    let Ok(bytes) = serde_json::to_vec(&CacheFile {
        v: CACHE_VERSION,
        entries,
    }) else {
        return;
    };
    if bytes.len() as u64 > max_bytes {
        tracing::debug!(
            error_kind = "cost_cache_too_large",
            "statusline cost cache not saved"
        );
        return;
    }
    let tmp = crate::platform::fs::unique_tmp_path(cache_path);
    if std::fs::write(&tmp, &bytes).is_err() {
        let _ = std::fs::remove_file(&tmp);
        tracing::debug!(
            error_kind = "cost_cache_write",
            "statusline cost cache write failed"
        );
        return;
    }
    if crate::platform::fs::secure_file(&tmp).is_err()
        || crate::platform::fs::atomic_replace(&tmp, cache_path).is_err()
    {
        let _ = std::fs::remove_file(&tmp);
        tracing::debug!(
            error_kind = "cost_cache_write",
            "statusline cost cache write failed"
        );
        return;
    }
    prune_sibling_caches(cache_path);
}

/// Keeps at most [`MAX_CACHE_FILES`] of this module's cache files (the newest by
/// mtime, `current` always among them) in `current`'s directory. Only regular
/// files named `<CACHE_FILE_PREFIX>*.json` are touched; a symlink or any other
/// name is left alone. Failures are display-only and logged by fixed tag.
fn prune_sibling_caches(current: &Path) {
    let (Some(dir), Some(cur_name)) = (current.parent(), current.file_name()) else {
        return;
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut others: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    for entry in rd.flatten().take(MAX_PRUNE_SCAN) {
        let name = entry.file_name();
        let Some(n) = name.to_str() else { continue };
        if !n.starts_with(CACHE_FILE_PREFIX) || !n.ends_with(".json") || name == cur_name {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if meta.file_type().is_file() {
            others.push((
                meta.modified().unwrap_or(std::time::UNIX_EPOCH),
                entry.path(),
            ));
        }
    }
    others.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, path) in others.into_iter().skip(MAX_CACHE_FILES - 1) {
        if std::fs::remove_file(&path).is_err() {
            tracing::debug!(
                error_kind = "cost_cache_prune",
                "statusline cost cache prune failed"
            );
        }
    }
}

/// Everything one file's collection needs besides its cache entry.
struct Ctx<'a> {
    reader: &'a dyn TranscriptReader,
    path: &'a Path,
    from_subagent: bool,
    slot: AccountNum,
    fallback_model: &'a str,
    manifest: &'a ModelManifest,
    manifest_key: u64,
}

/// One file's state for this render, plus whether the read is caught up.
struct Collected {
    /// Full state including the transient unterminated last line (render only).
    state: Cache,
    caught_up: bool,
    /// The entry to persist for this file; `None` keeps the prior entry as is.
    persist: Option<Cache>,
}

/// Prices `snaps` through the manifest with the ledger's own conversion.
fn price(
    snaps: Vec<CachedSnap>,
    ctx: &Ctx<'_>,
    first_model: Option<String>,
) -> Result<f64, UnknownReason> {
    let file_key = ctx.path.to_string_lossy().into_owned();
    let mut collector = RequestCollector::new();
    for s in snaps {
        collector.push(
            UsageSnapshot {
                request_id: s.r,
                message_id: s.m,
                record_uuid: s.u,
                timestamp: s.ts,
                model: s.model,
                usage: SnapshotUsage {
                    input_tokens: s.i,
                    output_tokens: s.o,
                    cache_creation_tokens: s.cw,
                    cache_read_tokens: s.cr,
                },
            },
            &file_key,
            s.l,
            ctx.from_subagent,
        );
    }
    let requests = collector.finish();
    let session = ScannedSession::from_parts(
        String::new(),
        String::new(),
        String::new(),
        first_model,
        requests,
    );
    let events = attributed_session_to_events_with_manifest(
        &AttributedSession {
            slot: ctx.slot,
            session,
        },
        ctx.fallback_model,
        ctx.manifest,
    );
    let mut total = 0.0;
    for e in events {
        match e.cost_usd_estimate {
            Some(c) if c.is_finite() => total += c,
            // One unpriced request makes the sum a lower bound, not a cost.
            _ => return Err(UnknownReason::ModelUnpriced),
        }
    }
    Ok(total)
}

/// Folds closed requests older than [`FOLD_MARGIN_LINES`] into `folded_usd`.
/// A request is folded only if NONE of its snapshots is inside the tail window.
fn fold(st: &mut Cache, ctx: &Ctx<'_>) {
    if (st.snaps.len() as u64) <= FOLD_MARGIN_LINES {
        return;
    }
    let horizon = st.lines.saturating_sub(FOLD_MARGIN_LINES);
    let open: HashSet<String> = st
        .snaps
        .iter()
        .filter(|s| s.l > horizon)
        .map(CachedSnap::identity)
        .collect();
    let (foldable, keep): (Vec<CachedSnap>, Vec<CachedSnap>) = std::mem::take(&mut st.snaps)
        .into_iter()
        .partition(|s| s.l <= horizon && !open.contains(&s.identity()));
    st.snaps = keep;
    if foldable.is_empty() {
        return;
    }
    let mut known: HashSet<u64> = st.folded_ids.iter().copied().collect();
    for h in foldable.iter().filter_map(CachedSnap::id_hash) {
        if known.insert(h) {
            st.folded_ids.push(h);
        }
    }
    if st.folded_ids.len() > MAX_FOLDED_IDS {
        let excess = st.folded_ids.len() - MAX_FOLDED_IDS;
        st.folded_ids.drain(..excess);
    }
    match price(foldable, ctx, st.first_model.clone()) {
        Ok(c) => st.folded_usd += c,
        Err(_) => st.folded_unpriced = true,
    }
}

fn collect(ctx: &Ctx<'_>, prior: Option<&Cache>, budget: &mut u64) -> std::io::Result<Collected> {
    let stat = ctx.reader.stat(ctx.path)?;
    let path_key = ctx.path.to_string_lossy().into_owned();

    let cache = prior
        .filter(|c| {
            c.path == path_key
                && c.manifest_key == ctx.manifest_key
                && c.consumed <= stat.len
                && c.len <= stat.len
        })
        .cloned();

    // Fast path: the file is exactly as it was when the cache was written and
    // nothing was left unconsumed, so no read is needed.
    if let Some(c) = &cache {
        if c.len == stat.len && c.mtime_ns == stat.mtime_ns && c.consumed == c.len {
            return Ok(Collected {
                state: c.clone(),
                caught_up: true,
                persist: None,
            });
        }
    }
    // Read from FINGERPRINT_BYTES before the offset, to prove continuity.
    let fp_wanted = cache
        .as_ref()
        .map_or(0, |c| FINGERPRINT_BYTES.min(c.consumed));
    if *budget <= fp_wanted {
        // This render's read budget is spent by earlier files (or cannot even
        // cover the fingerprint, so no body byte could be read).
        return Ok(Collected {
            state: cache.unwrap_or_default(),
            caught_up: false,
            persist: None,
        });
    }
    // The window covers the fingerprint prefix AND the body: every byte read is
    // charged, so a render never reads more than its budget.
    let window = *budget;

    let (mut st, fp_len) = match cache {
        Some(c) => {
            let fp = FINGERPRINT_BYTES.min(c.consumed);
            (c, fp)
        }
        None => (
            Cache {
                path: path_key.clone(),
                manifest_key: ctx.manifest_key,
                ..Cache::default()
            },
            0,
        ),
    };
    let mut buf = ctx
        .reader
        .read_range(ctx.path, st.consumed - fp_len, window)?;
    *budget = budget.saturating_sub(buf.len() as u64);
    let mut take = window - fp_len;
    let mut skip = fp_len as usize;
    if fp_len > 0 {
        let head = &buf[..(fp_len as usize).min(buf.len())];
        if head.len() as u64 != fp_len || fnv1a(head) != st.fingerprint {
            // Rewritten, not appended: the cached prefix no longer describes it.
            st = Cache {
                path: path_key,
                manifest_key: ctx.manifest_key,
                ..Cache::default()
            };
            if *budget == 0 {
                // The discarded read spent the budget; the restart waits for the
                // next render rather than reading past this one's limit. The
                // EMPTY entry is persisted so that render starts at byte 0 with no
                // fingerprint to mismatch again (keeping the stale entry would
                // discard a read every render and never progress).
                return Ok(Collected {
                    persist: Some(st.clone()),
                    state: st,
                    caught_up: false,
                });
            }
            take = *budget;
            buf = ctx.reader.read_range(ctx.path, 0, take)?;
            *budget = budget.saturating_sub(buf.len() as u64);
            skip = 0;
        }
    }
    let had_prior = st.consumed > 0;
    finish_collect(ctx, st, &buf, skip, take, stat, had_prior)
}

fn finish_collect(
    ctx: &Ctx<'_>,
    mut st: Cache,
    buf: &[u8],
    skip: usize,
    take: u64,
    stat: TranscriptStat,
    had_prior: bool,
) -> std::io::Result<Collected> {
    let skip = skip.min(buf.len());
    let body = &buf[skip..];
    let start = st.consumed;
    // More file remains beyond what this read could take. A body that exactly
    // fills the window AND ends the file is caught up, not truncated.
    let truncated = body.len() as u64 >= take && start + (body.len() as u64) < stat.len;

    // Inside an over-long line from a previous render: drop up to its newline.
    let mut lead = 0usize;
    if st.skipping {
        match body.iter().position(|b| *b == b'\n') {
            Some(i) => {
                st.skipped_usage |= contains_usage(&body[..i]);
                lead = i + 1;
                st.skipping = false;
            }
            None => {
                st.skipped_usage |= contains_usage(body);
                lead = body.len();
            }
        }
    }
    let region = &body[lead..];
    // Complete lines end in '\n'; the remainder is a write in progress.
    let complete_end = region
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    // Request ids folded by EARLIER renders: a snapshot of one of them means the
    // request would be counted again.
    let folded: HashSet<u64> = st.folded_ids.iter().copied().collect();
    for raw in region[..complete_end].split(|b| *b == b'\n') {
        if raw.is_empty() {
            continue;
        }
        st.lines += 1;
        if let Ok(text) = std::str::from_utf8(raw) {
            if let Some(s) = parse_line(text, st.lines) {
                if st.first_model.is_none() {
                    st.first_model.clone_from(&s.model);
                }
                if !st.straddled && s.id_hash().is_some_and(|h| folded.contains(&h)) {
                    st.straddled = true;
                    tracing::warn!(
                        error_kind = "statusline_cost_request_straddles_fold",
                        "a transcript request has a snapshot after it was folded; cost is unknown"
                    );
                }
                st.snaps.push(s);
            }
        }
    }
    let mut consumed_rel = lead + complete_end;
    if !st.skipping && complete_end == 0 && !region.is_empty() && truncated {
        // One line fills the whole read window with no newline: it cannot be
        // parsed within budget. Skip past it so later lines still price; if it
        // carried usage text the total is a lower bound and stays `$?`.
        tracing::warn!(
            error_kind = "statusline_cost_overlong_line",
            "transcript line exceeds the read budget; skipping it"
        );
        st.skipped_usage |= contains_usage(region);
        st.skipping = true;
        consumed_rel = lead + region.len();
    }
    st.consumed = start + consumed_rel as u64;
    // Fingerprint the (up to) FINGERPRINT_BYTES bytes that precede `consumed`.
    if consumed_rel > 0 {
        let end = skip + consumed_rel;
        st.fingerprint = fnv1a(&buf[end.saturating_sub(FINGERPRINT_BYTES as usize)..end]);
    }
    fold(&mut st, ctx);
    st.len = stat.len.max(st.consumed);
    st.mtime_ns = stat.mtime_ns;
    // A round that consumed nothing from a non-empty prefix keeps the old cache.
    let persist = (consumed_rel > 0 || !had_prior).then(|| st.clone());

    let mut state = st;
    // A final line with no newline may be a finished record; count it for THIS
    // render only (never cached, so a half-written one cannot poison the cache).
    if !truncated && !state.skipping && complete_end < region.len() {
        if let Ok(text) = std::str::from_utf8(&region[complete_end..]) {
            if let Some(s) = parse_line(text, state.lines + 1) {
                if s.id_hash().is_some_and(|h| state.folded_ids.contains(&h)) {
                    state.straddled = true;
                }
                state.snaps.push(s);
            }
        }
    }
    Ok(Collected {
        state,
        caught_up: !truncated,
        persist,
    })
}

/// Inputs to [`statusline_cost`].
pub struct CostRequest<'a> {
    pub base_dir: &'a Path,
    /// The session's resolved config dir (`CLAUDE_CONFIG_DIR`). The cache is
    /// written into it only when it is a handle dir (`term-<pid>`).
    pub config_dir: &'a Path,
    /// Claude Code's home (`~/.claude`); `<claude_home>/projects` is the second
    /// root a transcript may live under (the first is `<config_dir>/projects`).
    pub claude_home: Option<&'a Path>,
    pub slot: AccountNum,
    /// The slot's configured model id (`providers::settings::model_id_for_slot`).
    pub model_id: Option<&'a str>,
    /// `transcript_path` from CC's stdin.
    pub transcript_path: Option<&'a str>,
    /// `session_id` from CC's stdin; keys the cache file. Invalid or absent means
    /// no persistent cache.
    pub session_id: Option<&'a str>,
}

/// Resolves `raw` to a transcript path whose directories contain no symlink and
/// which sits under a Claude Code `projects/` root. The final component is left
/// unresolved so the reader's no-follow open still refuses a symlinked file.
fn confine_transcript(req: &CostRequest<'_>, raw: &str) -> Option<PathBuf> {
    let path = PathBuf::from(raw);
    if !path.is_absolute() || path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
        return None;
    }
    let name = path.file_name()?;
    let parent = std::fs::canonicalize(path.parent()?).ok()?;
    let mut roots: Vec<PathBuf> = vec![req.config_dir.join("projects")];
    if let Some(h) = req.claude_home {
        roots.push(h.join("projects"));
    }
    let under = roots
        .iter()
        .filter_map(|r| std::fs::canonicalize(r).ok())
        .any(|r| parent.starts_with(&r));
    under.then(|| parent.join(name))
}

/// Decides what the statusline cost segment shows. `load_manifest` is injected
/// and called only for third-party slots; a present-but-invalid manifest yields
/// [`UnknownReason::ManifestInvalid`] rather than different prices (spec 07 §7.11).
pub fn statusline_cost(
    req: &CostRequest<'_>,
    reader: &dyn TranscriptReader,
    load_manifest: &dyn Fn() -> anyhow::Result<ModelManifest>,
) -> CostDisplay {
    statusline_cost_with(req, reader, load_manifest, Limits::PRODUCTION)
}

fn statusline_cost_with(
    req: &CostRequest<'_>,
    reader: &dyn TranscriptReader,
    load_manifest: &dyn Fn() -> anyhow::Result<ModelManifest>,
    limits: Limits,
) -> CostDisplay {
    match pricing_gate_for_slot(req.base_dir, req.slot) {
        PricingGate::CcReported => return CostDisplay::CcReported,
        PricingGate::Unreadable => return CostDisplay::Unknown(UnknownReason::BindingUnreadable),
        PricingGate::Manifest => {}
    }
    let manifest = match load_manifest() {
        Ok(m) => m,
        Err(_) => return CostDisplay::Unknown(UnknownReason::ManifestInvalid),
    };
    let Some(raw) = req.transcript_path else {
        return CostDisplay::Unknown(UnknownReason::TranscriptUnavailable);
    };
    let Some(path) = confine_transcript(req, raw) else {
        return CostDisplay::Unknown(UnknownReason::TranscriptUnavailable);
    };
    // CC's `total_cost_usd` covers the whole session, so the parent transcript
    // (`<cwd>/<session>.jsonl`) and its subagent children
    // (`<cwd>/<session>/subagents/*.jsonl`, the layout `usage::aggregator`
    // scans) are summed. Each file has its own cache entry.
    let children = match reader.list_jsonl(
        &path
            .with_extension("")
            .join(super::aggregator::SUBAGENTS_DIR),
    ) {
        Ok(c) => c,
        Err(_) => return CostDisplay::Unknown(UnknownReason::TranscriptUnavailable),
    };
    if children.len() > MAX_SUBAGENT_FILES {
        return CostDisplay::Unknown(UnknownReason::TooManyTranscripts);
    }
    let fallback = req.model_id.unwrap_or("");
    let manifest_key = match serde_json::to_vec(&manifest) {
        Ok(mut b) => {
            b.push(0);
            b.extend_from_slice(fallback.as_bytes());
            fnv1a(&b)
        }
        Err(_) => return CostDisplay::Unknown(UnknownReason::ManifestInvalid),
    };
    // Persistent state only in a handle dir and only for a valid session id.
    let cache_path = req
        .session_id
        .and_then(cache_file_name)
        .filter(|_| is_handle_dir(req.config_dir))
        .map(|n| req.config_dir.join(n));
    let prior = cache_path
        .as_deref()
        .map(|p| load_cache(p, limits.cache_bytes))
        .unwrap_or_default();
    let mut entries: Vec<Cache> = Vec::new();
    let mut total = 0.0;
    let mut result: Result<(), UnknownReason> = Ok(());
    let mut budget = limits.read_budget;
    let files =
        std::iter::once((path.clone(), false)).chain(children.into_iter().map(|c| (c, true)));
    for (file, from_subagent) in files {
        let key = file.to_string_lossy();
        let old = prior.iter().find(|c| c.path == key);
        let ctx = Ctx {
            reader,
            path: &file,
            from_subagent,
            slot: req.slot,
            fallback_model: fallback,
            manifest: &manifest,
            manifest_key,
        };
        let collected = match collect(&ctx, old, &mut budget) {
            Ok(c) => c,
            Err(_) => {
                result = Err(UnknownReason::TranscriptUnavailable);
                break;
            }
        };
        match collected.persist {
            Some(e) => entries.push(e),
            None => entries.extend(old.cloned()),
        }
        let st = collected.state;
        if st.skipped_usage {
            result = Err(UnknownReason::OverlongLine);
            continue;
        }
        if st.straddled {
            result = Err(UnknownReason::RequestStraddlesFold);
            continue;
        }
        if !collected.caught_up {
            result = Err(UnknownReason::CatchingUp);
            continue;
        }
        if st.folded_unpriced {
            result = Err(UnknownReason::ModelUnpriced);
            continue;
        }
        let first_model = st.first_model.clone();
        match price(st.snaps, &ctx, first_model) {
            Ok(c) => total += st.folded_usd + c,
            Err(r) => result = Err(r),
        }
    }
    // Entries for files that vanished are dropped by construction (only files
    // visited this render are rewritten).
    if let Some(p) = &cache_path {
        save_cache(p, entries, limits.cache_bytes);
    }
    match result {
        Ok(()) => CostDisplay::Priced(total),
        Err(r) => CostDisplay::Unknown(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::Write;
    use tempfile::TempDir;

    fn slot() -> AccountNum {
        AccountNum::try_from(7u16).unwrap()
    }

    fn bundled() -> anyhow::Result<ModelManifest> {
        Ok(ModelManifest::bundled())
    }

    fn line(req: &str, model: &str, ts: &str, i: u64, o: u64) -> String {
        format!(
            "{{\"requestId\":\"{req}\",\"timestamp\":\"{ts}\",\"message\":{{\"id\":\"m_{req}\",\"model\":\"{model}\",\"usage\":{{\"input_tokens\":{i},\"output_tokens\":{o},\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0}}}}}}\n"
        )
    }

    struct Env {
        _dir: TempDir,
        base: PathBuf,
        cfg: PathBuf,
        transcript: PathBuf,
    }

    impl Env {
        fn cache(&self) -> PathBuf {
            self.cfg.join(cache_file_name("sess1").unwrap())
        }
        fn subagents(&self) -> PathBuf {
            self.transcript.with_extension("").join("subagents")
        }
    }

    fn env(settings_model: Option<&str>, pin_base_url: bool) -> Env {
        let dir = TempDir::new().unwrap();
        let base = dir.path().to_path_buf();
        let cfg = base.join("term-1");
        std::fs::create_dir_all(&cfg).unwrap();
        let slot_dir = base.join("config-7");
        std::fs::create_dir_all(&slot_dir).unwrap();
        let mut envj = serde_json::Map::new();
        if let Some(m) = settings_model {
            envj.insert("ANTHROPIC_MODEL".into(), m.into());
        }
        if pin_base_url {
            envj.insert(
                "ANTHROPIC_BASE_URL".into(),
                "https://api.deepseek.com/anthropic".into(),
            );
        }
        std::fs::write(
            slot_dir.join("settings.json"),
            serde_json::json!({ "env": envj }).to_string(),
        )
        .unwrap();
        if !pin_base_url {
            // Anthropic OAuth binding via the pre-A++ legacy mirror.
            std::fs::create_dir_all(base.join("credentials")).unwrap();
            std::fs::write(base.join("credentials").join("7.json"), "{}").unwrap();
        }
        let proj = cfg.join("projects").join("p");
        std::fs::create_dir_all(&proj).unwrap();
        let transcript = proj.join("sess.jsonl");
        Env {
            _dir: dir,
            base,
            cfg,
            transcript,
        }
    }

    fn run(e: &Env, model: Option<&str>, reader: &dyn TranscriptReader) -> CostDisplay {
        statusline_cost(
            &CostRequest {
                base_dir: &e.base,
                config_dir: &e.cfg,
                claude_home: None,
                slot: slot(),
                model_id: model,
                transcript_path: e.transcript.to_str(),
                session_id: Some("sess1"),
            },
            reader,
            &bundled,
        )
    }

    fn expected(model: &str, ts: &str, i: u64, o: u64) -> f64 {
        use chrono::DateTime;
        let at = DateTime::parse_from_rfc3339(ts)
            .unwrap()
            .with_timezone(&chrono::Utc);
        ModelManifest::bundled()
            .rate_for_model_at(model, Some(at))
            .unwrap()
            .estimate_usd_with_cache(i, o, 0, 0)
    }

    #[test]
    fn deepseek_session_prices_from_manifest_not_stdin() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(
            &e.transcript,
            line(
                "a",
                "deepseek-v4-pro",
                "2026-09-20T12:00:00Z",
                1_000_000,
                100_000,
            ),
        )
        .unwrap();
        let got = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        let want = expected(
            "deepseek-v4-pro",
            "2026-09-20T12:00:00Z",
            1_000_000,
            100_000,
        );
        match got {
            CostDisplay::Priced(c) => assert!((c - want).abs() < 1e-9, "{c} vs {want}"),
            other => panic!("expected Priced, got {other:?}"),
        }
        assert!(want > 0.0);
    }

    #[test]
    fn anthropic_slot_keeps_cc_cost() {
        let e = env(None, false);
        std::fs::write(
            &e.transcript,
            line("a", "claude-opus-4-8", "2026-09-20T12:00:00Z", 10, 10),
        )
        .unwrap();
        assert_eq!(run(&e, None, &FsTranscriptReader), CostDisplay::CcReported);
        assert_eq!(
            run(&e, Some("claude-opus-4-8"), &FsTranscriptReader),
            CostDisplay::CcReported
        );
    }

    #[test]
    fn unpriced_model_is_unknown_never_cc() {
        let e = env(Some("kimi-for-coding"), true);
        std::fs::write(
            &e.transcript,
            line("a", "kimi-for-coding", "2026-09-20T12:00:00Z", 10, 10),
        )
        .unwrap();
        assert_eq!(
            run(&e, Some("kimi-for-coding"), &FsTranscriptReader),
            CostDisplay::Unknown(UnknownReason::ModelUnpriced)
        );
    }

    #[test]
    fn unreadable_transcript_and_invalid_manifest_are_unknown() {
        let e = env(Some("deepseek-v4-pro"), true);
        // transcript absent
        assert_eq!(
            run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader),
            CostDisplay::Unknown(UnknownReason::TranscriptUnavailable)
        );
        std::fs::write(&e.transcript, "").unwrap();
        let bad = || -> anyhow::Result<ModelManifest> { anyhow::bail!("invalid") };
        let got = statusline_cost(
            &CostRequest {
                base_dir: &e.base,
                config_dir: &e.cfg,
                claude_home: None,
                slot: slot(),
                model_id: Some("deepseek-v4-pro"),
                transcript_path: e.transcript.to_str(),
                session_id: Some("sess1"),
            },
            &FsTranscriptReader,
            &bad,
        );
        assert_eq!(got, CostDisplay::Unknown(UnknownReason::ManifestInvalid));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_transcript_is_refused() {
        let e = env(Some("deepseek-v4-pro"), true);
        let real = e.base.join("real.jsonl");
        // The symlink sits inside projects/ so only the no-follow open can refuse it.
        std::fs::write(
            &real,
            line("a", "deepseek-v4-pro", "2026-09-20T12:00:00Z", 1, 1),
        )
        .unwrap();
        std::os::unix::fs::symlink(&real, &e.transcript).unwrap();
        assert_eq!(
            run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader),
            CostDisplay::Unknown(UnknownReason::TranscriptUnavailable)
        );
    }

    /// Records every ranged read so a test can prove how many bytes were parsed.
    struct Counting {
        inner: FsTranscriptReader,
        reads: RefCell<Vec<(u64, usize)>>,
    }

    impl TranscriptReader for Counting {
        fn stat(&self, p: &Path) -> std::io::Result<TranscriptStat> {
            self.inner.stat(p)
        }
        fn list_jsonl(&self, d: &Path) -> std::io::Result<Vec<PathBuf>> {
            self.inner.list_jsonl(d)
        }
        fn read_range(&self, p: &Path, from: u64, max: u64) -> std::io::Result<Vec<u8>> {
            let v = self.inner.read_range(p, from, max)?;
            self.reads.borrow_mut().push((from, v.len()));
            Ok(v)
        }
    }

    #[test]
    fn incremental_cache_reparses_only_appended_tail() {
        let e = env(Some("deepseek-v4-pro"), true);
        let first: String = (0..200)
            .map(|n| {
                line(
                    &format!("r{n}"),
                    "deepseek-v4-pro",
                    "2026-09-20T12:00:00Z",
                    1000,
                    100,
                )
            })
            .collect();
        std::fs::write(&e.transcript, &first).unwrap();
        let rd = Counting {
            inner: FsTranscriptReader,
            reads: RefCell::new(vec![]),
        };
        let a = run(&e, Some("deepseek-v4-pro"), &rd);
        let appended = line("rz", "deepseek-v4-pro", "2026-09-20T12:00:05Z", 1000, 100);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&e.transcript)
            .unwrap()
            .write_all(appended.as_bytes())
            .unwrap();
        rd.reads.borrow_mut().clear();
        let b = run(&e, Some("deepseek-v4-pro"), &rd);
        let reads = rd.reads.borrow().clone();
        assert_eq!(reads.len(), 1, "{reads:?}");
        let (from, got_len) = reads[0];
        assert_eq!(from, first.len() as u64 - FINGERPRINT_BYTES);
        assert_eq!(got_len as u64, FINGERPRINT_BYTES + appended.len() as u64);
        // Same answer as a cold parse of the whole file.
        let cold = {
            std::fs::remove_file(e.cache()).unwrap();
            run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader)
        };
        assert_eq!(b, cold);
        let (CostDisplay::Priced(ca), CostDisplay::Priced(cb)) = (a, b) else {
            panic!("{a:?} {b:?}")
        };
        assert!(cb > ca);
    }

    #[test]
    fn rewritten_transcript_misses_the_cache() {
        let e = env(Some("deepseek-v4-pro"), true);
        let a: String = (0..20)
            .map(|n| {
                line(
                    &format!("r{n}"),
                    "deepseek-v4-pro",
                    "2026-09-20T12:00:00Z",
                    1000,
                    100,
                )
            })
            .collect();
        std::fs::write(&e.transcript, &a).unwrap();
        let _ = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        // Different content, strictly longer: an append-only assumption would
        // keep the stale prefix.
        let b: String = (0..25)
            .map(|n| {
                line(
                    &format!("q{n}"),
                    "deepseek-v4-pro",
                    "2026-09-20T12:00:00Z",
                    5000,
                    100,
                )
            })
            .collect();
        std::fs::write(&e.transcript, &b).unwrap();
        let got = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        std::fs::remove_file(e.cache()).unwrap();
        assert_eq!(got, run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader));
    }

    #[test]
    fn runtime_manifest_rate_change_changes_the_price() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(
            &e.transcript,
            line("a", "deepseek-v4-pro", "2026-09-20T12:00:00Z", 1_000_000, 0),
        )
        .unwrap();
        let before = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        // Install a runtime manifest whose deepseek-v4-pro input rate is 1234.
        let mut v = serde_json::to_value(ModelManifest::bundled()).unwrap();
        for rule in v["rates"].as_array_mut().unwrap() {
            let hit = rule["patterns"].as_array().unwrap().iter().any(|p| {
                p.as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case("deepseek-v4-pro"))
            });
            if hit {
                for ep in rule["epochs"].as_array_mut().unwrap() {
                    ep["rate"]["input_per_1m_usd"] = serde_json::json!(1234.0);
                    if ep["peak"].is_object() {
                        ep["peak"]["rate"]["input_per_1m_usd"] = serde_json::json!(1234.0);
                    }
                }
            }
        }
        let src = e.base.join("new-manifest.json");
        std::fs::write(&src, v.to_string()).unwrap();
        ModelManifest::install(&e.base, &src).unwrap();
        let base = e.base.clone();
        let loader = move || ModelManifest::load(&base);
        let after = statusline_cost(
            &CostRequest {
                base_dir: &e.base,
                config_dir: &e.cfg,
                claude_home: None,
                slot: slot(),
                model_id: Some("deepseek-v4-pro"),
                transcript_path: e.transcript.to_str(),
                session_id: Some("sess1"),
            },
            &FsTranscriptReader,
            &loader,
        );
        let (CostDisplay::Priced(b), CostDisplay::Priced(a)) = (before, after) else {
            panic!("{before:?} {after:?}")
        };
        assert!((a - 1234.0).abs() < 1e-6, "{a}");
        assert!((b - 1234.0).abs() > 1.0);
    }

    #[test]
    fn subagent_transcripts_are_priced_with_the_parent() {
        let e = env(Some("deepseek-v4-pro"), true);
        let ts = "2026-09-20T12:00:00Z";
        std::fs::write(
            &e.transcript,
            line("p", "deepseek-v4-pro", ts, 1_000_000, 0),
        )
        .unwrap();
        let parent_only = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        let sub = e.subagents();
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("agent-1.jsonl"),
            line("c", "deepseek-v4-pro", ts, 2_000_000, 0),
        )
        .unwrap();
        // A non-transcript sibling and an unrelated dir must not be read.
        std::fs::write(sub.join("notes.txt"), "x").unwrap();
        let both = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        let (CostDisplay::Priced(p), CostDisplay::Priced(b)) = (parent_only, both) else {
            panic!("{parent_only:?} {both:?}")
        };
        let want_child = expected("deepseek-v4-pro", ts, 2_000_000, 0);
        assert!(
            (b - (p + want_child)).abs() < 1e-9,
            "{b} vs {p}+{want_child}"
        );
        // Second render comes from the per-file cache and agrees.
        assert_eq!(run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader), both);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_subagents_dir_is_unknown_not_zero_spend() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(
            &e.transcript,
            line("p", "deepseek-v4-pro", "2026-09-20T12:00:00Z", 10, 0),
        )
        .unwrap();
        let real = e.base.join("elsewhere");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(e.transcript.with_extension("")).unwrap();
        std::os::unix::fs::symlink(&real, e.subagents()).unwrap();
        assert_eq!(
            run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader),
            CostDisplay::Unknown(UnknownReason::TranscriptUnavailable)
        );
    }

    /// The cache lives in the handle dir, so the share audit (which flags REAL
    /// files that are not deliberately per-terminal) must not report it, nor
    /// the tmp name `save_cache` stages it under.
    #[test]
    fn cache_file_is_not_reported_as_unshared_handle_state() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(
            &e.transcript,
            line("a", "deepseek-v4-pro", "2026-09-20T12:00:00Z", 10, 10),
        )
        .unwrap();
        let _ = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        assert!(e.cache().is_file());
        // The fixture's `projects/` is a real dir only so the transcript can sit
        // under it; in a real handle dir it is a shared symlink.
        std::fs::remove_dir_all(e.cfg.join("projects")).unwrap();
        let staged = crate::platform::fs::unique_tmp_path(&e.cache());
        std::fs::write(&staged, "x").unwrap();
        let reported = crate::session::share_audit::unshared_handle_dir_state(&e.base);
        assert!(reported.is_empty(), "{reported:?}");
        // Non-vacuity: an ordinary real file in the same dir IS reported.
        std::fs::write(e.cfg.join("stray.bin"), "x").unwrap();
        let reported = crate::session::share_audit::unshared_handle_dir_state(&e.base);
        assert_eq!(reported.len(), 1, "{reported:?}");
    }

    // ── Finding 1: the pricing gate reads csq's binding metadata ────────────

    fn write_settings(e: &Env, env_obj: serde_json::Value) {
        std::fs::write(
            e.base.join("config-7").join("settings.json"),
            serde_json::json!({ "env": env_obj }).to_string(),
        )
        .unwrap();
    }

    fn put_line(e: &Env, model: &str) {
        std::fs::write(
            &e.transcript,
            line("a", model, "2026-09-20T12:00:00Z", 1000, 100),
        )
        .unwrap();
    }

    #[test]
    fn bedrock_pinned_slot_keeps_cc_cost() {
        for id in [
            "anthropic.claude-sonnet-4-5-20250929-v1:0",
            "arn:aws:bedrock:us-east-1:123456789012:inference-profile/x",
        ] {
            // No identity, no base URL, a model id that does not start with "claude".
            let e = env(None, true);
            write_settings(
                &e,
                serde_json::json!({
                    "CLAUDE_CODE_USE_BEDROCK": "1",
                    "AWS_REGION": "us-east-1",
                    "ANTHROPIC_MODEL": id,
                }),
            );
            put_line(&e, id);
            assert_eq!(
                run(&e, Some(id), &FsTranscriptReader),
                CostDisplay::CcReported,
                "{id}"
            );
        }
    }

    #[test]
    fn gateway_base_url_on_anthropic_slot_keeps_cc_cost() {
        let e = env(None, false); // Anthropic OAuth binding
        write_settings(
            &e,
            serde_json::json!({ "ANTHROPIC_BASE_URL": "https://llm-gateway.example.com" }),
        );
        put_line(&e, "claude-opus-4-8");
        assert_eq!(
            run(&e, Some("claude-opus-4-8"), &FsTranscriptReader),
            CostDisplay::CcReported
        );
    }

    #[test]
    fn third_party_slots_are_manifest_priced() {
        for url in [
            "https://api.deepseek.com/anthropic",
            "https://api.minimaxi.com/anthropic",
        ] {
            let e = env(None, true);
            write_settings(&e, serde_json::json!({ "ANTHROPIC_BASE_URL": url }));
            assert_eq!(
                pricing_gate_for_slot(&e.base, slot()),
                PricingGate::Manifest,
                "{url}"
            );
        }
    }

    #[test]
    fn unreadable_binding_is_unknown_never_cc() {
        let e = env(None, true);
        std::fs::write(e.base.join("config-7").join("settings.json"), "{not json").unwrap();
        put_line(&e, "deepseek-v4-pro");
        assert_eq!(
            run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader),
            CostDisplay::Unknown(UnknownReason::BindingUnreadable)
        );
    }

    // ── Findings 2/3/5: progress, handle-dir-only cache, caps ───────────────

    fn many_lines(n: usize, tag: &str) -> String {
        (0..n)
            .map(|k| {
                line(
                    &format!("{tag}{k}"),
                    "deepseek-v4-pro",
                    "2026-09-20T12:00:00Z",
                    1000,
                    100,
                )
            })
            .collect()
    }

    fn run_with(
        e: &Env,
        sid: Option<&str>,
        cfg: &Path,
        limits: Limits,
        rd: &dyn TranscriptReader,
    ) -> CostDisplay {
        statusline_cost_with(
            &CostRequest {
                base_dir: &e.base,
                config_dir: cfg,
                claude_home: None,
                slot: slot(),
                model_id: Some("deepseek-v4-pro"),
                transcript_path: e.transcript.to_str(),
                session_id: sid,
            },
            rd,
            &bundled,
            limits,
        )
    }

    #[test]
    fn transcript_beyond_the_read_and_cache_caps_converges() {
        let e = env(Some("deepseek-v4-pro"), true);
        // ~270 KB of snapshots against a 32 KiB read budget and a 120 KiB cache cap:
        // without folding the snapshot list alone exceeds the cap, the save is
        // skipped, and every render restarts from byte 0.
        std::fs::write(&e.transcript, many_lines(1800, "r")).unwrap();
        let limits = Limits {
            read_budget: 32 * 1024,
            cache_bytes: 120 * 1024,
        };
        let mut renders = 0;
        let got = loop {
            renders += 1;
            let r = run_with(&e, Some("sess1"), &e.cfg, limits, &FsTranscriptReader);
            if !matches!(r, CostDisplay::Unknown(UnknownReason::CatchingUp)) || renders > 40 {
                break r;
            }
        };
        let size = std::fs::metadata(&e.transcript).unwrap().len();
        assert!(
            renders as u64 <= size / (32 * 1024) + 3,
            "renders={renders}"
        );
        let want = expected("deepseek-v4-pro", "2026-09-20T12:00:00Z", 1000, 100) * 1800.0;
        match got {
            CostDisplay::Priced(c) => assert!((c - want).abs() < want * 1e-9, "{c} vs {want}"),
            other => panic!("not converged after {renders} renders: {other:?}"),
        }
    }

    #[test]
    fn folding_keeps_a_request_split_across_the_window_in_one_piece() {
        let e = env(Some("deepseek-v4-pro"), true);
        // One request whose snapshots are the first and the LAST lines, with 1500
        // distinct requests between: the early snapshot must not be folded alone.
        let mut body = line("same", "deepseek-v4-pro", "2026-09-20T12:00:00Z", 10, 5);
        body.push_str(&many_lines(1500, "x"));
        body.push_str(&line(
            "same",
            "deepseek-v4-pro",
            "2026-09-20T12:00:00Z",
            10,
            50,
        ));
        std::fs::write(&e.transcript, &body).unwrap();
        let warm = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        std::fs::remove_file(e.cache()).unwrap();
        let rd = Counting {
            inner: FsTranscriptReader,
            reads: RefCell::new(vec![]),
        };
        let cold = run_with(&e, Some("sess1"), &e.cfg, Limits::PRODUCTION, &rd);
        let (CostDisplay::Priced(w), CostDisplay::Priced(c)) = (warm, cold) else {
            panic!("{warm:?} {cold:?}")
        };
        // `same` bills once with its LAST snapshot (output 50), plus 1500 others.
        let want = expected("deepseek-v4-pro", "2026-09-20T12:00:00Z", 10, 50)
            + 1500.0 * expected("deepseek-v4-pro", "2026-09-20T12:00:00Z", 1000, 100);
        assert!((w - want).abs() < want * 1e-9, "{w} vs {want}");
        assert!((c - want).abs() < want * 1e-9, "{c} vs {want}");
    }

    #[test]
    fn two_sessions_in_one_dir_keep_separate_caches() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(&e.transcript, many_lines(3, "a")).unwrap();
        let other = e.transcript.with_file_name("other.jsonl");
        std::fs::write(&other, many_lines(5, "b")).unwrap();
        let _ = run_with(
            &e,
            Some("sess1"),
            &e.cfg,
            Limits::PRODUCTION,
            &FsTranscriptReader,
        );
        let e2 = Env {
            _dir: TempDir::new().unwrap(),
            base: e.base.clone(),
            cfg: e.cfg.clone(),
            transcript: other.clone(),
        };
        let _ = run_with(
            &e2,
            Some("sess2"),
            &e.cfg,
            Limits::PRODUCTION,
            &FsTranscriptReader,
        );
        let f1 = e.cfg.join(cache_file_name("sess1").unwrap());
        let f2 = e.cfg.join(cache_file_name("sess2").unwrap());
        let (c1, c2) = (load_cache(&f1, u64::MAX), load_cache(&f2, u64::MAX));
        assert_eq!(c1.len(), 1);
        assert_eq!(c2.len(), 1);
        assert!(c1[0].path.ends_with("sess.jsonl"), "{}", c1[0].path);
        assert!(c2[0].path.ends_with("other.jsonl"), "{}", c2[0].path);
    }

    #[test]
    fn invalid_session_id_writes_no_cache() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(&e.transcript, many_lines(3, "a")).unwrap();
        for sid in [None, Some(""), Some("../x"), Some("a/b"), Some("a b")] {
            let _ = run_with(&e, sid, &e.cfg, Limits::PRODUCTION, &FsTranscriptReader);
        }
        let _ = run_with(
            &e,
            Some(&"a".repeat(129)),
            &e.cfg,
            Limits::PRODUCTION,
            &FsTranscriptReader,
        );
        let stray: Vec<_> = std::fs::read_dir(&e.cfg)
            .unwrap()
            .flatten()
            .map(|d| d.file_name())
            .filter(|n| n.to_string_lossy().starts_with(CACHE_FILE_PREFIX))
            .collect();
        assert!(stray.is_empty(), "{stray:?}");
    }

    #[test]
    fn non_handle_dir_writes_no_file() {
        let e = env(Some("deepseek-v4-pro"), true);
        let perm = e.base.join("config-9");
        let proj = perm.join("projects").join("p");
        std::fs::create_dir_all(&proj).unwrap();
        let t = proj.join("sess.jsonl");
        std::fs::write(&t, many_lines(4, "a")).unwrap();
        let e2 = Env {
            _dir: TempDir::new().unwrap(),
            base: e.base.clone(),
            cfg: perm.clone(),
            transcript: t,
        };
        let got = run_with(
            &e2,
            Some("sess1"),
            &perm,
            Limits::PRODUCTION,
            &FsTranscriptReader,
        );
        assert!(matches!(got, CostDisplay::Priced(_)), "{got:?}");
        let names: Vec<_> = std::fs::read_dir(&perm)
            .unwrap()
            .flatten()
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!names.iter().any(|n| n.starts_with(".csq")), "{names:?}");
    }

    #[test]
    fn body_exactly_filling_the_budget_is_caught_up() {
        let e = env(Some("deepseek-v4-pro"), true);
        let body = many_lines(6, "a");
        std::fs::write(&e.transcript, &body).unwrap();
        let limits = Limits {
            read_budget: body.len() as u64,
            cache_bytes: MAX_CACHE_BYTES,
        };
        let got = run_with(&e, None, &e.cfg, limits, &FsTranscriptReader);
        assert!(matches!(got, CostDisplay::Priced(_)), "{got:?}");
    }

    #[test]
    fn overlong_line_without_usage_is_skipped_and_later_lines_price() {
        let e = env(Some("deepseek-v4-pro"), true);
        let mut body = line("a", "deepseek-v4-pro", "2026-09-20T12:00:00Z", 1000, 100);
        body.push_str(&"x".repeat(40 * 1024));
        body.push('\n');
        body.push_str(&line(
            "b",
            "deepseek-v4-pro",
            "2026-09-20T12:00:01Z",
            1000,
            100,
        ));
        std::fs::write(&e.transcript, &body).unwrap();
        let limits = Limits {
            read_budget: 16 * 1024,
            cache_bytes: MAX_CACHE_BYTES,
        };
        let mut got = CostDisplay::Unknown(UnknownReason::CatchingUp);
        for _ in 0..10 {
            got = run_with(&e, Some("sess1"), &e.cfg, limits, &FsTranscriptReader);
            if !matches!(got, CostDisplay::Unknown(_)) {
                break;
            }
        }
        let want = 2.0 * expected("deepseek-v4-pro", "2026-09-20T12:00:00Z", 1000, 100);
        match got {
            CostDisplay::Priced(c) => assert!((c - want).abs() < want * 1e-6, "{c} vs {want}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn overlong_line_carrying_usage_is_dollar_question_mark() {
        let e = env(Some("deepseek-v4-pro"), true);
        let mut body = String::from("{\"usage\":\"");
        body.push_str(&"x".repeat(40 * 1024));
        body.push_str("\"}\n");
        body.push_str(&line(
            "b",
            "deepseek-v4-pro",
            "2026-09-20T12:00:01Z",
            1000,
            100,
        ));
        std::fs::write(&e.transcript, &body).unwrap();
        let limits = Limits {
            read_budget: 16 * 1024,
            cache_bytes: MAX_CACHE_BYTES,
        };
        let mut got = CostDisplay::Unknown(UnknownReason::CatchingUp);
        for _ in 0..10 {
            got = run_with(&e, Some("sess1"), &e.cfg, limits, &FsTranscriptReader);
            if got == CostDisplay::Unknown(UnknownReason::OverlongLine) {
                break;
            }
        }
        assert_eq!(got, CostDisplay::Unknown(UnknownReason::OverlongLine));
    }

    #[test]
    fn list_entry_error_is_an_error_and_scan_stops_at_the_bound() {
        let ok = |n: usize| Ok(PathBuf::from(format!("/x/{n}.jsonl")));
        let items: Vec<std::io::Result<PathBuf>> =
            vec![ok(1), Err(std::io::Error::other("boom")), ok(2)];
        assert!(jsonl_from_entries(items.into_iter()).is_err());
        let pulled = std::cell::Cell::new(0usize);
        let it = (0..100_000usize).map(|n| {
            pulled.set(pulled.get() + 1);
            ok(n)
        });
        let got = jsonl_from_entries(it).unwrap();
        assert_eq!(got.len(), MAX_SUBAGENT_FILES + 1);
        assert_eq!(pulled.get(), MAX_SUBAGENT_FILES + 1);
    }

    #[test]
    fn read_budget_is_shared_across_the_render() {
        let e = env(Some("deepseek-v4-pro"), true);
        let parent = many_lines(40, "p");
        std::fs::write(&e.transcript, &parent).unwrap();
        std::fs::create_dir_all(e.subagents()).unwrap();
        std::fs::write(e.subagents().join("a.jsonl"), many_lines(40, "c")).unwrap();
        let budget = parent.len() as u64 + 2048;
        let limits = Limits {
            read_budget: budget,
            cache_bytes: MAX_CACHE_BYTES,
        };
        let rd = Counting {
            inner: FsTranscriptReader,
            reads: RefCell::new(vec![]),
        };
        let first = run_with(&e, Some("sess1"), &e.cfg, limits, &rd);
        let read: usize = rd.reads.borrow().iter().map(|r| r.1).sum();
        assert_eq!(first, CostDisplay::Unknown(UnknownReason::CatchingUp));
        assert!(read as u64 <= budget, "read {read} > budget {budget}");
        let mut got = first;
        for _ in 0..6 {
            got = run_with(&e, Some("sess1"), &e.cfg, limits, &rd);
        }
        let want = 80.0 * expected("deepseek-v4-pro", "2026-09-20T12:00:00Z", 1000, 100);
        match got {
            CostDisplay::Priced(c) => assert!((c - want).abs() < want * 1e-9, "{c} vs {want}"),
            other => panic!("{other:?}"),
        }
    }

    // ── Finding 6: transcript confinement ───────────────────────────────────

    #[test]
    fn transcript_outside_projects_is_unknown() {
        let e = env(Some("deepseek-v4-pro"), true);
        let outside = e.base.join("outside.jsonl");
        std::fs::write(&outside, many_lines(2, "a")).unwrap();
        let traversal = e
            .cfg
            .join("projects")
            .join("p")
            .join("..")
            .join("..")
            .join("..")
            .join("outside.jsonl");
        std::fs::write(e.cfg.join("elsewhere.jsonl"), many_lines(2, "a")).unwrap();
        for raw in [outside, traversal, e.cfg.join("elsewhere.jsonl")] {
            let got = statusline_cost(
                &CostRequest {
                    base_dir: &e.base,
                    config_dir: &e.cfg,
                    claude_home: None,
                    slot: slot(),
                    model_id: Some("deepseek-v4-pro"),
                    transcript_path: raw.to_str(),
                    session_id: Some("sess1"),
                },
                &FsTranscriptReader,
                &bundled,
            );
            assert_eq!(
                got,
                CostDisplay::Unknown(UnknownReason::TranscriptUnavailable),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn transcript_under_claude_home_projects_is_accepted() {
        let e = env(Some("deepseek-v4-pro"), true);
        let home = e.base.join("claude-home");
        let t = home.join("projects").join("p").join("s.jsonl");
        std::fs::create_dir_all(t.parent().unwrap()).unwrap();
        std::fs::write(&t, many_lines(2, "a")).unwrap();
        let got = statusline_cost(
            &CostRequest {
                base_dir: &e.base,
                config_dir: &e.cfg,
                claude_home: Some(&home),
                slot: slot(),
                model_id: Some("deepseek-v4-pro"),
                transcript_path: t.to_str(),
                session_id: None,
            },
            &FsTranscriptReader,
            &bundled,
        );
        assert!(matches!(got, CostDisplay::Priced(_)), "{got:?}");
    }

    // ── Finding 8: rewrites the offset check must catch ─────────────────────

    /// Wraps a reader and perturbs `mtime_ns`, so a rewrite is not hidden by a
    /// filesystem whose timestamps tie within one test.
    struct Mtime<'a> {
        inner: &'a FsTranscriptReader,
        bump: &'a std::cell::Cell<u64>,
    }

    impl TranscriptReader for Mtime<'_> {
        fn stat(&self, p: &Path) -> std::io::Result<TranscriptStat> {
            let mut s = self.inner.stat(p)?;
            s.mtime_ns += self.bump.get();
            Ok(s)
        }
        fn list_jsonl(&self, d: &Path) -> std::io::Result<Vec<PathBuf>> {
            self.inner.list_jsonl(d)
        }
        fn read_range(&self, p: &Path, f: u64, m: u64) -> std::io::Result<Vec<u8>> {
            self.inner.read_range(p, f, m)
        }
    }

    fn rewrite_case(old: &str, new: &str) {
        let e = env(Some("deepseek-v4-pro"), true);
        let bump = std::cell::Cell::new(0);
        let rd = Mtime {
            inner: &FsTranscriptReader,
            bump: &bump,
        };
        std::fs::write(&e.transcript, old).unwrap();
        let _ = run(&e, Some("deepseek-v4-pro"), &rd);
        std::fs::write(&e.transcript, new).unwrap();
        bump.set(1_000_000);
        let got = run(&e, Some("deepseek-v4-pro"), &rd);
        std::fs::remove_file(e.cache()).unwrap();
        let cold = run(&e, Some("deepseek-v4-pro"), &rd);
        assert_eq!(got, cold);
        assert!(matches!(cold, CostDisplay::Priced(_)));
    }

    fn lines_with(tag: &str, model: &str, i: u64, n: usize) -> String {
        (0..n)
            .map(|k| line(&format!("{tag}{k}"), model, "2026-09-20T12:00:00Z", i, 100))
            .collect()
    }

    #[test]
    fn rewrite_landing_mid_line_misses_the_cache() {
        let old = lines_with("r", "deepseek-v4-pro", 1000, 20);
        let new = lines_with("longer-id-", "deepseek-v4-pro", 7000, 25);
        // The old offset must fall INSIDE a line of the new file.
        assert_ne!(new.as_bytes()[old.len() - 1], b'\n');
        assert!(new.len() > old.len());
        rewrite_case(&old, &new);
    }

    #[test]
    fn rewrite_to_the_same_length_misses_the_cache() {
        let old = lines_with("r", "deepseek-v4-pro", 1000, 20);
        let new = lines_with("q", "deepseek-v4-pro", 2000, 20);
        assert_eq!(old.len(), new.len());
        assert_ne!(old, new);
        rewrite_case(&old, &new);
    }

    // ── Round 2 ─────────────────────────────────────────────────────────────

    /// Captures every tracing event as `name=value` text.
    struct EventText(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    struct FieldText(String);

    impl tracing::field::Visit for FieldText {
        fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={:?} ", f.name(), v);
        }
    }

    impl tracing::Subscriber for EventText {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, e: &tracing::Event<'_>) {
            let mut v = FieldText(String::new());
            e.record(&mut v);
            self.0.lock().unwrap().push(v.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    fn capture<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
        let _g = crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let out = tracing::subscriber::with_default(EventText(events.clone()), run);
        let got = events.lock().unwrap().clone();
        (out, got)
    }

    const DEEPSEEK: &str = "https://api.deepseek.com/anthropic";

    /// Finding 1: an Anthropic binding that survived a rebind to a third-party
    /// provider (no `csq logout`) must not read as plain Anthropic.
    #[test]
    fn anthropic_and_third_party_evidence_is_dollar_question_mark() {
        let e = env(None, false); // Anthropic legacy mirror credentials/7.json
        write_settings(&e, serde_json::json!({ "ANTHROPIC_BASE_URL": DEEPSEEK }));
        put_line(&e, "deepseek-v4-pro");
        assert_eq!(
            pricing_gate_for_slot(&e.base, slot()),
            PricingGate::Unreadable
        );
        assert_eq!(
            run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader),
            CostDisplay::Unknown(UnknownReason::BindingUnreadable)
        );
    }

    #[test]
    fn gate_reads_only_this_slots_settings_and_logs_nothing_for_others() {
        let e = env(None, true); // pure third-party slot 7
        for n in (1..=20u16).filter(|n| *n != 7) {
            let d = e.base.join(format!("config-{n}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("settings.json"), "{not json").unwrap();
        }
        let (gate, events) = capture(|| pricing_gate_for_slot(&e.base, slot()));
        assert_eq!(gate, PricingGate::Manifest);
        let leaked: Vec<_> = events
            .iter()
            .filter(|t| t.contains("settings_json_invalid"))
            .collect();
        assert!(leaked.is_empty(), "other slots were scanned: {leaked:?}");
    }

    /// Finding 2.
    #[cfg(unix)]
    #[test]
    fn symlinked_session_dir_is_unknown_not_followed() {
        let e = env(Some("deepseek-v4-pro"), true);
        put_line(&e, "deepseek-v4-pro");
        // A real subagent transcript OUTSIDE projects/, reachable only through a
        // symlinked `<session>/`.
        let outside = e.base.join("outside");
        std::fs::create_dir_all(outside.join("subagents")).unwrap();
        std::fs::write(
            outside.join("subagents").join("a.jsonl"),
            line(
                "sub",
                "deepseek-v4-pro",
                "2026-09-20T12:00:00Z",
                1_000_000,
                0,
            ),
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, e.transcript.with_extension("")).unwrap();
        assert_eq!(
            run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader),
            CostDisplay::Unknown(UnknownReason::TranscriptUnavailable)
        );
    }

    type Edit = Box<dyn Fn(&mut serde_json::Value)>;

    /// Finding 3.
    fn tamper(e: &Env, edit: impl Fn(&mut serde_json::Value)) {
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(e.cache()).unwrap()).unwrap();
        edit(&mut v["entries"][0]);
        std::fs::write(e.cache(), serde_json::to_vec(&v).unwrap()).unwrap();
    }

    #[test]
    fn tampered_cache_values_are_treated_as_no_cache() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(&e.transcript, many_lines(1500, "r")).unwrap();
        let honest = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        assert!(matches!(honest, CostDisplay::Priced(c) if c > 0.0));
        let cases: [(&str, Edit); 4] = [
            ("negative", Box::new(|v| v["folded_usd"] = (-1.0e6).into())),
            ("absurd", Box::new(|v| v["folded_usd"] = 1.0e300.into())),
            (
                "tokens",
                Box::new(|v| v["snaps"][0]["i"] = (1u64 << 60).into()),
            ),
            ("consumed", Box::new(|v| v["consumed"] = u64::MAX.into())),
        ];
        for (name, edit) in cases {
            tamper(&e, &*edit);
            let got = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
            assert_eq!(got, honest, "{name}");
            // The re-parse rewrote an honest cache.
            let again = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
            assert_eq!(again, honest, "{name} (second render)");
        }
    }

    #[test]
    fn valid_entry_rejects_non_finite_and_inconsistent_fields() {
        let ok = Cache {
            len: 10,
            consumed: 10,
            ..Cache::default()
        };
        assert!(valid_entry(&ok));
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.01, 2.0e9] {
            let c = Cache {
                folded_usd: bad,
                ..ok.clone()
            };
            assert!(!valid_entry(&c), "{bad}");
        }
        let c = Cache {
            consumed: 11,
            ..ok.clone()
        };
        assert!(!valid_entry(&c));
        let c = Cache {
            folded_ids: vec![0; MAX_FOLDED_IDS + 1],
            ..ok.clone()
        };
        assert!(!valid_entry(&c));
    }

    /// Finding 4.
    #[test]
    fn request_straddling_the_fold_is_unknown_not_double_counted() {
        let e = env(Some("deepseek-v4-pro"), true);
        let ts = "2026-09-20T12:00:00Z";
        let mut body = line("same", "deepseek-v4-pro", ts, 10, 5);
        body.push_str(&many_lines(1500, "x"));
        std::fs::write(&e.transcript, &body).unwrap();
        let before = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        assert!(matches!(before, CostDisplay::Priced(_)), "{before:?}");
        // `same` is now folded; a LATE snapshot of it arrives.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&e.transcript)
            .unwrap()
            .write_all(line("same", "deepseek-v4-pro", ts, 10, 50).as_bytes())
            .unwrap();
        let (got, events) = capture(|| run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader));
        assert_eq!(
            got,
            CostDisplay::Unknown(UnknownReason::RequestStraddlesFold)
        );
        assert!(events
            .iter()
            .any(|t| t.contains("statusline_cost_request_straddles_fold")));
        // Persisted: the next renders stay `$?`.
        assert_eq!(
            run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader),
            CostDisplay::Unknown(UnknownReason::RequestStraddlesFold)
        );
    }

    #[test]
    fn appending_a_new_request_after_a_fold_still_prices() {
        let e = env(Some("deepseek-v4-pro"), true);
        let ts = "2026-09-20T12:00:00Z";
        let mut body = line("same", "deepseek-v4-pro", ts, 10, 5);
        body.push_str(&many_lines(1500, "x"));
        std::fs::write(&e.transcript, &body).unwrap();
        let _ = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&e.transcript)
            .unwrap()
            .write_all(line("fresh", "deepseek-v4-pro", ts, 10, 50).as_bytes())
            .unwrap();
        let got = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        let want = expected("deepseek-v4-pro", ts, 10, 5)
            + 1500.0 * expected("deepseek-v4-pro", ts, 1000, 100)
            + expected("deepseek-v4-pro", ts, 10, 50);
        match got {
            CostDisplay::Priced(c) => assert!((c - want).abs() < want * 1e-9, "{c} vs {want}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn folded_id_set_is_bounded_and_the_cache_stays_within_its_cap() {
        let e = env(Some("deepseek-v4-pro"), true);
        let n = MAX_FOLDED_IDS + 600;
        std::fs::write(&e.transcript, many_lines(n, "r")).unwrap();
        let _ = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        let bytes = std::fs::read(e.cache()).unwrap();
        let f: CacheFile = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(f.entries[0].folded_ids.len(), MAX_FOLDED_IDS);
        assert!((bytes.len() as u64) < MAX_CACHE_BYTES, "{}", bytes.len());
    }

    /// Finding 5.
    #[test]
    fn old_session_caches_are_pruned_to_the_newest_few() {
        let e = env(Some("deepseek-v4-pro"), true);
        put_line(&e, "deepseek-v4-pro");
        let now = std::time::SystemTime::now();
        for k in 0..6u64 {
            let p = e.cfg.join(format!("{CACHE_FILE_PREFIX}old{k}.json"));
            std::fs::write(&p, "{}").unwrap();
            let f = std::fs::File::options().write(true).open(&p).unwrap();
            // old5 is the newest, old0 the oldest; all older than the live file.
            f.set_modified(now - std::time::Duration::from_secs(3600 * (10 - k)))
                .unwrap();
        }
        std::fs::write(e.cfg.join(".claude.json"), "{}").unwrap();
        let got = run(&e, Some("deepseek-v4-pro"), &FsTranscriptReader);
        assert!(matches!(got, CostDisplay::Priced(_)), "{got:?}");
        let mut kept: Vec<String> = std::fs::read_dir(&e.cfg)
            .unwrap()
            .flatten()
            .map(|d| d.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(CACHE_FILE_PREFIX))
            .collect();
        kept.sort();
        let want: Vec<String> = [
            format!("{CACHE_FILE_PREFIX}old3.json"),
            format!("{CACHE_FILE_PREFIX}old4.json"),
            format!("{CACHE_FILE_PREFIX}old5.json"),
            cache_file_name("sess1").unwrap(),
        ]
        .into();
        assert_eq!(kept, want);
        assert!(
            e.cfg.join(".claude.json").exists(),
            "foreign file untouched"
        );
    }

    /// Finding 6.
    fn budgeted(e: &Env, rd: &Counting, budget: u64) -> (CostDisplay, u64) {
        rd.reads.borrow_mut().clear();
        let r = run_with(
            e,
            Some("sess1"),
            &e.cfg,
            Limits {
                read_budget: budget,
                cache_bytes: MAX_CACHE_BYTES,
            },
            rd,
        );
        let read: usize = rd.reads.borrow().iter().map(|r| r.1).sum();
        (r, read as u64)
    }

    fn counting() -> Counting {
        Counting {
            inner: FsTranscriptReader,
            reads: RefCell::new(vec![]),
        }
    }

    #[test]
    fn fingerprint_prefix_is_charged_to_the_render_budget() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(&e.transcript, many_lines(400, "r")).unwrap();
        let budget = 16 * 1024;
        let rd = counting();
        let mut last = CostDisplay::Unknown(UnknownReason::CatchingUp);
        for render in 0..40 {
            let (r, read) = budgeted(&e, &rd, budget);
            assert!(read <= budget, "render {render} read {read} > {budget}");
            last = r;
            if !matches!(r, CostDisplay::Unknown(UnknownReason::CatchingUp)) {
                break;
            }
        }
        let want = 400.0 * expected("deepseek-v4-pro", "2026-09-20T12:00:00Z", 1000, 100);
        match last {
            CostDisplay::Priced(c) => assert!((c - want).abs() < want * 1e-9, "{c} vs {want}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_read_a_rewrite_discards_is_charged_to_the_render_budget() {
        let e = env(Some("deepseek-v4-pro"), true);
        std::fs::write(&e.transcript, many_lines(400, "r")).unwrap();
        let budget = 16 * 1024;
        let rd = counting();
        let (first, _) = budgeted(&e, &rd, budget);
        assert_eq!(first, CostDisplay::Unknown(UnknownReason::CatchingUp));
        // Rewrite (not append): the cached prefix no longer matches.
        std::fs::write(&e.transcript, many_lines(400, "q")).unwrap();
        let mut last = first;
        for render in 0..40 {
            let (r, read) = budgeted(&e, &rd, budget);
            assert!(read <= budget, "render {render} read {read} > {budget}");
            last = r;
            if !matches!(r, CostDisplay::Unknown(UnknownReason::CatchingUp)) {
                break;
            }
        }
        let want = 400.0 * expected("deepseek-v4-pro", "2026-09-20T12:00:00Z", 1000, 100);
        match last {
            CostDisplay::Priced(c) => assert!((c - want).abs() < want * 1e-9, "{c} vs {want}"),
            other => panic!("{other:?}"),
        }
    }
}
