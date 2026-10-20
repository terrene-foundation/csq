//! Bounded per-identity history of Anthropic refresh-token fingerprints.
//!
//! PRIMARY METHODOLOGICAL DIRECTIVE (`keychain-fix-r8.md` C-F1): strict
//! current/previous-only recognition of "is this token still known" strands
//! any terminal that misses exactly one refresh cycle — `keychain::decide_cc_keychain_write`
//! sees a keychain item holding a token that is neither the marker account's
//! CURRENT canonical token nor anything else it can cheaply name, and refuses
//! forever (the sweep never re-tries with new information; the custodian
//! never adopts an older-but-legitimate token; `csq swap`/auto-rotate loop
//! "run the command again"; the session eventually 401s).
//!
//! The fix: remember the last `MAX_HISTORY_LEN` tokens a given identity's
//! canonical store has EVER held, as one-way SHA-256 fingerprints — never the
//! raw tokens themselves. A keychain item whose current fingerprint appears
//! in the marker account's OWN history is "same account, superseded" (rule 2
//! — safe to overwrite), not "a login csq did not write" (rule 3 — refuse and
//! harvest). Recognizing a stale-but-legitimate token this way generalizes
//! csq's healing window from "the last refresh" to "the last
//! `MAX_HISTORY_LEN` refreshes", closing the exact class of terminal that
//! previously needed hand-holding to recover.
//!
//! A fingerprint from a DIFFERENT account's history MUST NOT satisfy this
//! check — the history is read per-identity (`token_history_path_for`), so
//! there is no cross-account lookup path at all; this is structural, not a
//! runtime filter that could be bypassed.

use crate::accounts::identity_store::{token_history_path_for, IdentityId};
use crate::accounts::{anthropic_identity as ai, profiles_lock::ProfilesFileLock};
use crate::credentials::CredentialFile;
use crate::platform::fs::atomic_replace;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::warn;

/// The bounded history length (C-F1: "last N=16 entries").
pub(crate) const MAX_HISTORY_LEN: usize = 16;

/// `keychain-fix-r9.md` D-F9/S-L-2: bound on the token-history file this
/// module will read. [`MAX_HISTORY_LEN`] hex fingerprints (64 hex chars
/// each) plus JSON array overhead is well under 1.5 KB; 4 KiB is generous
/// headroom with no plausible legitimate content anywhere near the cap. A
/// file at or beyond this size is unparseable content (or a symlink/FIFO —
/// [`read_bounded`] rejects both), never a legitimate history — reading
/// further would only cost time on content this module is about to discard
/// as unparseable anyway.
const TOKEN_HISTORY_MAX_BYTES: u64 = 4096;

/// Reads `path` as a plain, regular file, bounded at
/// [`TOKEN_HISTORY_MAX_BYTES`]. Never follows a symlink (`symlink_metadata`,
/// not `metadata`) and never reads a FIFO/device/etc (`is_file()` check) —
/// mirrors `credentials::keychain::read_bounded_sentinel`'s discipline for
/// this module's own file. `None` on absence, an oversized file, a
/// non-regular file, or any read error — every one of those is "no history"
/// to this module's callers, never an error (see [`read_history`]'s doc).
fn read_bounded(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.len() > TOKEN_HISTORY_MAX_BYTES || !meta.file_type().is_file() {
        warn!(
            error_kind = "token_history_oversized_or_irregular",
            "token-history file exceeds the bounded read size or is not a plain \
             file; treating as empty history rather than reading further"
        );
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Lock path guarding `id`'s token-history read-modify-write cycle
/// (`keychain-fix-r9.md` D-F9/S-L-2) — mirrors
/// `credentials::keychain::pending_clears_lock_path`'s pattern: a sibling
/// `.lock` file, held only across the read+modify+write, never across any
/// network or subprocess call.
fn token_history_lock_path(base: &Path, id: IdentityId) -> PathBuf {
    token_history_path_for(base, id).with_extension("lock")
}

/// Directory (beside `token-history`) of the durable PENDING-INTENT spool
/// (D237 round-2 ruling C(2)). When [`append_history`]/[`start_new_segment`]
/// cannot take [`token_history_lock_path`] within the credential budget, the
/// fingerprint append / segment-start intent is written here as one
/// uniquely-named file instead of being dropped.
///
/// A spool DIRECTORY, not one appended file: the fallback exists precisely
/// because the lock could not be taken, so a read-modify-write of a shared
/// fallback file would be a lost-update race — the same silent drop this
/// queue exists to prevent. Each file is written `secure_file` → 0600 then
/// `atomic_replace` (§5a cleanup on every failure branch).
fn pending_history_dir(base: &Path, id: IdentityId) -> PathBuf {
    token_history_path_for(base, id).with_extension("pending.d")
}

/// Bound on one pending-intent file. A fingerprint is 64 hex chars; 4 KiB is
/// generous and makes every drain read bounded.
const PENDING_HISTORY_MAX_BYTES: u64 = 4096;

/// How many pending-intent files ONE drain applies. Bounds the locked
/// section; the remainder waits for the next writer.
const PENDING_HISTORY_DRAIN_MAX: usize = 64;

/// Hard cap on the TOTAL number of pending-intent files this spool will
/// hold (D237 round-2 correctness N5: the spool had no count bound at all).
///
/// Derivation from ENFORCED limits, never a measurement: the spool only
/// grows while the history lock is busy past its bounded
/// `CREDENTIAL_LOCK_BUDGET` wait, and every locked writer that obtains the
/// lock drains up to [`PENDING_HISTORY_DRAIN_MAX`] (64) intents. 256 is
/// `4 * PENDING_HISTORY_DRAIN_MAX` — four complete drain windows of
/// headroom, so a burst survives four consecutive lock-contended ticks
/// before the spool refuses. At the cap a NEW intent is REFUSED with a
/// fixed-vocabulary WARN naming that state (loud, never a silent drop); the
/// intents already queued keep draining, so the refusal is transient
/// pressure, never a permanently wedged queue.
const PENDING_HISTORY_MAX_FILES: usize = 256;

/// Subdirectory of [`pending_history_dir`] that bad entries are MOVED into
/// (D237 round-2 correctness N5 / security R2-M2). A file that cannot make
/// progress (irregular, oversized, unreadable, unparseable) is quarantined
/// rather than skipped in place: kept on disk for the operator to inspect
/// and NEVER deleted, but removed from the drain window so it can no longer
/// starve the entries behind it. The subdirectory has no `.json` extension,
/// so it is never itself enumerated as a drain candidate.
const PENDING_HISTORY_QUARANTINE_DIRNAME: &str = "quarantine";

/// One durable intent that could not be recorded on the history file because
/// its lock was busy. `Append` is an [`append_history`] call that timed out;
/// `StartSegment` is a [`start_new_segment`] call that timed out — the old
/// segment was INTENDED to be discarded, and readers must not keep
/// recognising it before the drain.
///
/// `captured_at_unix_nanos` is the time the CALLER attempted the operation
/// (taken before the lock wait), not the time this file was written (D237
/// round-2 correctness N5): the wait is exactly what made the intent
/// necessary, so the write time is up to one lock budget later than the
/// operation it records. Application orders the intent against the
/// per-entry capture times already persisted in the history file, so an
/// intent captured at T can never become "latest" ahead of an entry a
/// concurrent writer persisted at T+1. `#[serde(default)]` — a spool file
/// written before the timestamp existed deserializes to 0, which
/// [`apply_pending_intent`] treats as "time unknown" with the pre-timestamp
/// behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PendingHistoryIntent {
    Append {
        fingerprint: String,
        #[serde(default)]
        captured_at_unix_nanos: u64,
    },
    StartSegment {
        fingerprint: String,
        #[serde(default)]
        captured_at_unix_nanos: u64,
    },
}

impl PendingHistoryIntent {
    /// When the caller ATTEMPTED this operation (see the enum doc). `0`
    /// means the intent predates the field (unknown).
    fn captured_at_unix_nanos(&self) -> u64 {
        match self {
            Self::Append {
                captured_at_unix_nanos,
                ..
            }
            | Self::StartSegment {
                captured_at_unix_nanos,
                ..
            } => *captured_at_unix_nanos,
        }
    }

    fn fingerprint_hex(&self) -> &str {
        match self {
            Self::Append { fingerprint, .. } | Self::StartSegment { fingerprint, .. } => {
                fingerprint
            }
        }
    }
}

/// One entry of the ordered history: its fingerprint plus the UNIX-nanos
/// time its write was CAPTURED (D237 round-2 correctness N5). Old history
/// files carry no timestamps; those entries deserialize with time `0`
/// ("unknown/oldest"), which only ever places a newly-captured queued
/// intent AFTER them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HistoryEntry {
    fingerprint: Fingerprint,
    captured_at_unix_nanos: u64,
}

impl HistoryEntry {
    fn new(fingerprint: Fingerprint, captured_at_unix_nanos: u64) -> Self {
        Self {
            fingerprint,
            captured_at_unix_nanos,
        }
    }
}

/// UNIX-nanos capture time for a history operation. `0` when the system
/// clock is before the epoch (never in practice) — treated identically to a
/// legacy entry's unknown time.
fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Applies one intent to an in-memory history AT THE INTENT'S CAPTURE TIME
/// (D237 round-2 correctness N5 — strict sequence order). Shared by the
/// DRAIN ([`append_history`]/[`start_new_segment`], under the lock) and the
/// READ path ([`read_history`], lock-free) so a queued intent is honoured by
/// every reader even before it is persisted.
///
/// An intent captured at T is applied BEFORE every on-disk entry whose own
/// capture time is later than T: the history's last element must stay the
/// genuinely latest write, because history position feeds the keychain
/// recognition decision (`keychain::retired_history_in` requires a token to
/// sit strictly before the canonical in this list).
fn apply_pending_intent(history: &mut Vec<HistoryEntry>, intent: &PendingHistoryIntent) {
    let captured_at = intent.captured_at_unix_nanos();
    let Some(fp) = Fingerprint::from_hex(intent.fingerprint_hex()) else {
        return;
    };
    match intent {
        PendingHistoryIntent::Append { .. } => {
            if captured_at == 0 {
                // Legacy spool file (no timestamp): unknown time, so the
                // pre-timestamp behaviour — append at the end, deduped
                // against the current last entry.
                if history.last().map(|e| e.fingerprint) != Some(fp) {
                    history.push(HistoryEntry::new(fp, 0));
                    trim_history(history);
                }
                return;
            }
            // Insert exactly at the capture time: after every entry that
            // was captured at or before it, before every later one. A linear
            // scan (not `partition_point`) keeps the defined behaviour even
            // if the wall clock stepped backwards and the list is not
            // perfectly sorted: the first later entry wins.
            let pos = history
                .iter()
                .position(|e| e.captured_at_unix_nanos > captured_at)
                .unwrap_or(history.len());
            history.insert(pos, HistoryEntry::new(fp, captured_at));
            // A replay (or a concurrent writer that already persisted this
            // same fingerprint after the intent's position) must not leave
            // two adjacent identical entries.
            history.dedup_by(|a, b| a.fingerprint == b.fingerprint);
            trim_history(history);
        }
        PendingHistoryIntent::StartSegment { .. } => {
            if captured_at == 0 {
                // Legacy spool file: pre-timestamp truncate-to-suffix rule,
                // identical to `start_new_segment`'s own body.
                *history = match history.iter().rposition(|e| e.fingerprint == fp) {
                    Some(pos) => history[pos..].to_vec(),
                    None => vec![HistoryEntry::new(fp, 0)],
                };
                return;
            }
            // Discard everything captured at or before the segment start;
            // keep every genuinely LATER write (a concurrent append that
            // landed after this intent was captured is not part of the old
            // segment), with the new grant first.
            let mut new_segment = vec![HistoryEntry::new(fp, captured_at)];
            new_segment.extend(
                history
                    .iter()
                    .filter(|e| e.captured_at_unix_nanos > captured_at)
                    .copied(),
            );
            new_segment.dedup_by(|a, b| a.fingerprint == b.fingerprint);
            *history = new_segment;
        }
    }
}

/// Keeps the history at [`MAX_HISTORY_LEN`], oldest first.
fn trim_history(history: &mut Vec<HistoryEntry>) {
    if history.len() > MAX_HISTORY_LEN {
        let excess = history.len() - MAX_HISTORY_LEN;
        history.drain(0..excess);
    }
}

/// Counts this spool's drain candidates: a `.json` name whose entry is a
/// REGULAR FILE, directly under the spool directory — never the quarantine
/// subdirectory (which has no `.json` extension). Used only to enforce
/// [`PENDING_HISTORY_MAX_FILES`].
///
/// A junk directory or symlink named `*.json` (the drain quarantines it,
/// never applies it) and any non-`.json` file MUST NOT consume cap headroom:
/// counting them would refuse a new intent while the real records still have
/// room, and the drain that clears the junk cannot run on the enqueue path.
/// A `file_type()` error is treated as "not a regular file" — a vanished
/// entry holds no slot.
fn pending_intent_file_count(dir: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .filter(|e| {
            e.path().extension().is_some_and(|x| x == "json")
                && e.file_type().is_ok_and(|t| t.is_file())
        })
        .count()
}

/// Best-effort append of one durable intent to
/// [`pending_history_dir`]. Returns `true` when the intent reached disk.
/// Every failure branch removes the tmp file (§5a) and logs a
/// fixed-vocabulary tag; the only alternative to the spool would be dropping
/// the fingerprint, which D237 round-2 ruling C forbids.
///
/// At [`PENDING_HISTORY_MAX_FILES`] the enqueue is REFUSED loudly
/// (fixed-vocabulary WARN naming the full state) instead of growing the
/// spool without bound (D237 round-2 correctness N5). The already-queued
/// intents still drain, so the refusal is transient pressure rather than a
/// wedged queue.
fn enqueue_pending_intent(
    base: &Path,
    id: IdentityId,
    intent: PendingHistoryIntent,
    caller: &str,
) -> bool {
    static PENDING_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = pending_history_dir(base, id);
    if std::fs::create_dir_all(&dir).is_err() {
        warn!(
            error_kind = "token_history_pending_write_failed",
            caller,
            "token-history: could not create the pending-intent spool directory — \
             this fingerprint/segment intent could NOT be made durable"
        );
        return false;
    }
    let _ = crate::platform::fs::secure_dir(&dir);
    let queued = pending_intent_file_count(&dir);
    if queued >= PENDING_HISTORY_MAX_FILES {
        warn!(
            error_kind = "token_history_pending_spool_full",
            caller,
            cap = PENDING_HISTORY_MAX_FILES,
            "token-history: the pending-intent spool is AT ITS TOTAL FILE CAP — \
             REFUSING this intent loudly rather than growing the spool without \
             bound; the intents already queued still drain on the next locked \
             history write"
        );
        return false;
    }
    let seq = PENDING_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = dir.join(format!("{nanos:030}-{}-{seq}.json", std::process::id()));
    let Ok(json) = serde_json::to_string(&intent) else {
        warn!(
            error_kind = "token_history_pending_write_failed",
            caller, "token-history: could not serialize a pending intent"
        );
        return false;
    };
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if std::fs::write(&tmp, json.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "token_history_pending_write_failed",
            caller,
            "token-history: could not write a pending intent file — the fingerprint/\
             segment intent could NOT be made durable"
        );
        return false;
    }
    if crate::platform::fs::secure_file(&tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "token_history_pending_write_failed",
            caller,
            "token-history: could not secure a pending intent file — the fingerprint/\
             segment intent could NOT be made durable"
        );
        return false;
    }
    if atomic_replace(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "token_history_pending_write_failed",
            caller,
            "token-history: could not publish a pending intent file — the fingerprint/\
             segment intent could NOT be made durable"
        );
        return false;
    }
    true
}

/// Moves `path` out of the drain window into
/// [`PENDING_HISTORY_QUARANTINE_DIRNAME`], keeping it on disk for the
/// operator (D237 round-2 correctness N5 / security R2-M2). Never deletes.
/// A failed move logs a fixed-vocabulary WARN and leaves the file where it
/// is: the cap applies to the FILTERED set (see
/// [`read_pending_intents`]), so a file that cannot be moved still consumes
/// no drain slot and cannot starve progress.
fn quarantine_pending_intent(spool_dir: &Path, path: &Path, reason: &'static str) {
    let qdir = spool_dir.join(PENDING_HISTORY_QUARANTINE_DIRNAME);
    let dir_ready =
        std::fs::create_dir_all(&qdir).is_ok() && crate::platform::fs::secure_dir(&qdir).is_ok();
    if !dir_ready {
        warn!(
            error_kind = "token_history_pending_quarantine_failed",
            reason,
            "a token-history pending intent could not be quarantined (the \
             quarantine directory is unwritable); leaving it in place — it is \
             excluded from the drain window, never applied, never deleted"
        );
        return;
    }
    let Some(name) = path.file_name() else {
        return;
    };
    match std::fs::rename(path, qdir.join(name)) {
        Ok(()) => warn!(
            error_kind = "token_history_pending_quarantined",
            reason,
            "a token-history pending intent could not make progress; MOVED to \
             the quarantine subdirectory (kept on disk for inspection, never \
             deleted) so it can no longer starve the entries behind it"
        ),
        Err(_) => {
            // A concurrent reader may have quarantined it between our
            // enumeration and this rename; only warn when it is still there.
            if path.exists() {
                warn!(
                    error_kind = "token_history_pending_quarantine_failed",
                    reason,
                    "a token-history pending intent could not be quarantined; \
                     leaving it in place — it is excluded from the drain window, \
                     never applied, never deleted"
                );
            }
        }
    }
}

/// Reads [`pending_history_dir`] oldest-first (names begin with a
/// zero-padded timestamp), at most [`PENDING_HISTORY_DRAIN_MAX`] COMPLETE
/// intents.
///
/// FILTER BEFORE CAPPING (D237 round-2 correctness N5 / security R2-M2): a
/// file that is irregular, oversized, unparseable, or not UTF-8 is
/// QUARANTINED (moved to [`PENDING_HISTORY_QUARANTINE_DIRNAME`], kept on
/// disk, never deleted, never re-scanned as a drain candidate) and is not
/// counted against the per-drain window. The cap therefore applies to the
/// filtered set, so a head of junk files can no longer starve every valid
/// entry behind it.
///
/// QUARANTINE ONLY DETERMINISTIC FAILURES. Non-UTF-8 (`InvalidData`) can
/// never parse on a retry, so it is quarantined. Every other read error is
/// TRANSIENT — `PermissionDenied` mid ACL change, `Interrupted`,
/// `WouldBlock`, `TimedOut`, `EAGAIN`/`EMFILE` under fd pressure, `EIO` —
/// and the file is LEFT IN PLACE for the next drain. Quarantine is terminal,
/// so quarantining a transient error would silently drop a valid intent
/// (the exact loss D237 round-2 ruling C forbids). `NotFound` means a
/// concurrent reader already applied it; nothing to do.
fn read_pending_intents(base: &Path, id: IdentityId) -> Vec<(PathBuf, PendingHistoryIntent)> {
    let dir = pending_history_dir(base, id);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        if out.len() >= PENDING_HISTORY_DRAIN_MAX {
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            // Vanished between enumeration and stat: nothing to apply and
            // nothing to quarantine.
            continue;
        };
        if !meta.file_type().is_file() || meta.len() > PENDING_HISTORY_MAX_BYTES {
            quarantine_pending_intent(&dir, &path, "irregular_or_oversized");
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                quarantine_pending_intent(&dir, &path, "unreadable");
                continue;
            }
            Err(_) => {
                warn!(
                    error_kind = "token_history_pending_read_retry",
                    "token-history: a pending intent could not be read right now \
                     (a transient I/O error); leaving it in place for the next \
                     drain — never quarantined, never deleted"
                );
                continue;
            }
        };
        match serde_json::from_str::<PendingHistoryIntent>(&raw) {
            Ok(intent) => out.push((path, intent)),
            Err(_) => quarantine_pending_intent(&dir, &path, "unparseable"),
        }
    }
    out
}

/// Removes intent files whose contents were persisted by a successful
/// history write. A failed removal re-applies them next time — both intent
/// kinds are idempotent in the safe direction (an append dedupes against the
/// last entry; a segment start truncates to the same suffix).
fn remove_applied_intents(applied: &[(PathBuf, PendingHistoryIntent)]) {
    for (path, _) in applied {
        let _ = std::fs::remove_file(path);
    }
}

/// SHA-256 fingerprint of an Anthropic refresh token. One-way: there is no
/// path from a [`Fingerprint`] back to the token it was derived from, so
/// persisting or logging one never leaks credential bytes (`security.md`).
///
/// `pub` (widened from `pub(crate)` — `keychain-fix-r8.md` S-LOW-1): the
/// refresher's in-tick pre-refresh map is keyed by this type end to end, and
/// `keychain::sync_all_handle_dirs`/`sweep_sync_handle_dir` (both genuinely
/// `pub`, called from the `csq` binary crate) carry it in their signature.
/// All CONSTRUCTORS stay `pub(crate)` (`of_refresh_token`, `from_hex`) — an
/// external crate can hold and pass this type through, never mint one from
/// arbitrary bytes or a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Hashes a raw refresh-token string. Callers pass the token's plaintext
    /// only for the duration of this call — the return value never carries
    /// it.
    fn of_refresh_token(token: &str) -> Self {
        let digest = Sha256::digest(token.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// `None` on anything that is not exactly 32 decoded bytes — a
    /// corrupted or hand-edited history entry is dropped rather than
    /// treated as a wildcard match.
    fn from_hex(s: &str) -> Option<Self> {
        let decoded = hex::decode(s).ok()?;
        let bytes: [u8; 32] = decoded.try_into().ok()?;
        Some(Self(bytes))
    }
}

/// Extracts the Anthropic refresh-token fingerprint from a raw
/// `.credentials.json`-shaped JSON string (keychain item content or a
/// canonical credential file's serialized bytes) — the same
/// `claudeAiOauth.refreshToken` shape `keychain::oauth_identity` reads for
/// identity comparison. `None` when the JSON does not parse, or lacks a
/// `claudeAiOauth.refreshToken` string (Codex content, a stripped/sibling-only
/// item, or a malformed payload).
pub(crate) fn fingerprint_from_raw_json(raw_json: &str) -> Option<Fingerprint> {
    crate::credentials::keychain::inspect_secret_json(raw_json, |val| {
        let refresh = val.get("claudeAiOauth")?.get("refreshToken")?.as_str()?;
        // An empty refresh token is no credential: every such item would share
        // one fingerprint, so it identifies nothing.
        if refresh.is_empty() {
            return None;
        }
        Some(Fingerprint::of_refresh_token(refresh))
    })?
}

/// Extracts the Anthropic refresh-token fingerprint from an already-parsed
/// [`CredentialFile`]. `None` for a [`CredentialFile::Codex`] file — this
/// history is Anthropic-only (Codex tokens are never mirrored into CC's
/// keychain item, so a Codex fingerprint could never match anything
/// `keychain::decide_cc_keychain_write` classifies; recording one would only
/// spend bounded history slots on entries that can never match).
pub(crate) fn fingerprint_from_credential_file(creds: &CredentialFile) -> Option<Fingerprint> {
    creds
        .anthropic()
        .map(|a| Fingerprint::of_refresh_token(a.claude_ai_oauth.refresh_token.expose_secret()))
}

/// On-disk shape of `identities/<uuid>/token-history` — a bounded array of
/// hex-encoded fingerprints, newest last.
///
/// `captured_at_unix_nanos` is parallel to `fingerprints` and records when
/// each write was CAPTURED, so a queued intent can be applied at its own
/// position in the sequence instead of always at the end (D237 round-2
/// correctness N5). It is `#[serde(default)]` and omitted when empty: a
/// legacy history file has no timestamps and deserializes exactly as
/// before; its entries read as time-unknown (`0`, oldest). The
/// owner-verified list shares this struct and never writes timestamps.
#[derive(Default, Serialize, Deserialize)]
struct HistoryFile {
    fingerprints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    captured_at_unix_nanos: Vec<u64>,
}

/// Reads `id`'s bounded token-history, WITH any pending intents applied in
/// memory (D237 round-2 ruling C(2)). Absence, an unreadable file, or a
/// malformed entry are ALL treated as "no history" — never an error. This
/// history only WIDENS what `keychain::decide_cc_keychain_write`
/// recognises as "known"; failing to read it merely NARROWS recognition
/// back to the pre-C-F1 current-token-only behaviour, which is the safe
/// direction on a destructive-classification path
/// (`guard-reader-writer-parity.md` MUST-2: fail closed, never fail open).
///
/// Pending-intent application is the READ half of the drain's reader
/// parity: an append or segment-start that timed out under the history lock
/// is visible to every reader immediately, so recognition never degrades
/// while the intent waits for the next [`append_history`]/
/// [`start_new_segment`] (its DRAIN readers) to persist it. The reconcile
/// path reaches this function through
/// [`read_history_for_slot`] (`keychain::reconcile_keychain_to_marker_with_executor`,
/// `keychain::sweep_sync_handle_dir_with_executor`,
/// `keychain::force_sync_account_changed_with_executor`), so a queued
/// fingerprint is recognised by the very decision it was recorded for —
/// before it is drained to disk.
pub(crate) fn read_history(base: &Path, id: IdentityId) -> Vec<Fingerprint> {
    let mut history = read_history_on_disk(base, id);
    for (_, intent) in read_pending_intents(base, id) {
        apply_pending_intent(&mut history, &intent);
    }
    history.into_iter().map(|e| e.fingerprint).collect()
}

/// The on-disk history alone — no pending-intent application. Used by
/// [`read_history`] (which then applies intents) and by the drain writers,
/// which apply the intents themselves before writing the merged result.
///
/// Each entry keeps its captured time so an intent can be ordered against
/// it, not merely appended after it (D237 round-2 correctness N5). An
/// entry with no persisted time (legacy file, or a short timestamp array)
/// reads as `0` — time unknown, ordering it before every timed entry, which
/// is the only direction that can never make a stale token look newest.
fn read_history_on_disk(base: &Path, id: IdentityId) -> Vec<HistoryEntry> {
    let path = token_history_path_for(base, id);
    let Some(content) = read_bounded(&path) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<HistoryFile>(&content) else {
        warn!(
            error_kind = "token_history_unparseable",
            "token-history file present but unparseable; treating as empty history"
        );
        return Vec::new();
    };
    parsed
        .fingerprints
        .iter()
        .enumerate()
        .filter_map(|(i, s)| {
            Fingerprint::from_hex(s).map(|fingerprint| HistoryEntry {
                fingerprint,
                captured_at_unix_nanos: parsed.captured_at_unix_nanos.get(i).copied().unwrap_or(0),
            })
        })
        .collect()
}

/// Resolves `account`'s identity UUID and reads its token-history, or
/// `Vec::new()` when the slot has no UUID mapping yet (a legacy layout, or a
/// slot minted before this history existed) — the same graceful-empty
/// posture as an absent file.
///
/// Platform-independent pure fn — unconditional so it compiles and its own
/// module tests exercise `read_history` on every platform; its only
/// PRODUCTION callers (`keychain::sweep_sync_handle_dir_with_executor`,
/// `keychain::force_sync_account_changed_with_executor`,
/// `keychain::reconcile_keychain_to_marker_with_executor`) are all
/// `#[cfg(target_os = "macos")]`, so this is genuinely unreachable from
/// production code on other platforms — mirrors the same pattern already
/// used for `decide_cc_keychain_write` and its siblings in `super::keychain`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn read_history_for_slot(
    base: &Path,
    account: crate::types::AccountNum,
) -> Vec<Fingerprint> {
    match crate::accounts::profiles::resolve_slot_to_uuid(base, account.get()) {
        Some(uuid) => read_history(base, uuid),
        None => Vec::new(),
    }
}

/// One RETIRED binding of a slot: the displaced identity's canonical
/// fingerprint (when readable) plus its bounded token-history, oldest first,
/// exactly as [`read_history`] stores it.
///
/// The two forms are kept APART because they are NOT equal evidence (review
/// R1 M3 / coordinator ca6022c7 item 4): only [`Self::canonical`] is strong
/// (`keychain::decide_cc_keychain_write` treats it like `owner_verified`);
/// a history entry is position-bounded against this binding's OWN canonical
/// there, and `Intended::Strip` is never authorised by history alone.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct RetiredBinding {
    pub canonical: Option<Fingerprint>,
    pub history: Vec<Fingerprint>,
}

/// The RETIRED bindings of `slot`, for `keychain`'s recognition channels.
///
/// THE admission gate is `ProfilesFile::slot_binding_history[slot]` — the
/// identities this slot was previously bound to and displaced, written at
/// every production rebind by [`crate::accounts::profiles::record_binding_displacement`]
/// (`profiles::add_identity_mapping`, the Anthropic re-login publication,
/// and `csq move`'s swap) in the same locked save as their `by_slot`
/// overwrite. When that list is absent or empty this returns NOTHING: a
/// rebind that predates the field leaves no provable predecessor, and the
/// snapshot alone fails CLOSED (coordinator ca6022c7 item 1 — the earlier
/// same-email fallback is DROPPED: email is not account identity, `by_email`
/// is explicitly not an authority, and one address maps to several
/// account/org contexts). The operator remedy for a refused token in that
/// window is `csq login <n>` / `csq run <n>`, already named in the refusal
/// text.
///
/// The generation counter is deliberately NOT consulted (item 3): the first
/// bind already reaches generation 1, so `>= 1` cannot distinguish
/// "bound once" from "rebound" — history membership IS the gate.
///
/// Per identity, still excluded: currently-bound identities (someone's live
/// binding is never "retired"), identities never in this slot's history, and
/// REMOVED identities ([`crate::accounts::identity_store::is_identity_removed`],
/// review R1 L1 — a logged-out identity's surviving directory is not
/// evidence; the removal check fails closed on a stat error).
///
/// LOGOUT IS DELIBERATELY FAIL-CLOSED here (review R1 L4): `csq logout`
/// unbinds without recording a displacement, so a terminal holding the
/// logged-out identity's token is refused — the owner's named remedy is the
/// re-login path (`csq login <n>`). Recording logout as a retirement would
/// ADMIT those terminals and is the owner's call, not this reader's.
///
/// Bounded: at most `RETIRED_IDENTITIES_CAP` bindings, each through
/// [`read_history`]'s own bounded read. Every failure mode (absent profiles,
/// unreadable identity dir, unparseable credentials) NARROWS the result
/// toward empty, never errors — the same posture as [`read_history`]. Never
/// terminal-derived (`account-terminal-separation.md` MUST-1 — the slot
/// argument is the caller's marker resolution; the identities come from
/// `profiles.json` + the identity store).
///
/// Lock discipline (review R2 L-R2-5): mirrors
/// [`read_owner_verified_for_slot`] — a nonblocking acquire, then the
/// lock-held read. A held lock means a writer is mid-mutation (a rebind or
/// a move), so reading anyway could admit retired identities from a
/// snapshot that writer is about to replace and authorise a Strip/Write
/// from stale lineage. Busy ⇒ empty: recognition absent ⇒ the harvest-first
/// refusal stands (fail closed by narrowing).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn retired_bindings_for_slot(
    base: &Path,
    slot: crate::types::AccountNum,
) -> Vec<RetiredBinding> {
    let Ok(Some(lock)) = ProfilesFileLock::try_acquire(base) else {
        return Vec::new();
    };
    retired_bindings_for_slot_locked(&lock, base, slot)
}

/// [`retired_bindings_for_slot`] against a caller-held profiles snapshot
/// (review R1 L3: one decision reads ONE snapshot — a caller that already
/// holds `profiles.json` must not trigger a second, possibly-torn disk
/// read here).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn retired_bindings_for_slot_with_profiles(
    base: &Path,
    profiles: &crate::accounts::profiles::ProfilesFile,
    slot: crate::types::AccountNum,
) -> Vec<RetiredBinding> {
    const RETIRED_IDENTITIES_CAP: usize = 64;
    let slot_key = slot.to_string();
    let history_ids: std::collections::HashSet<IdentityId> = profiles
        .slot_binding_history
        .get(&slot_key)
        .map(|ids| ids.iter().copied().collect())
        .unwrap_or_default();
    if history_ids.is_empty() {
        return Vec::new();
    }
    let bound: std::collections::HashSet<IdentityId> = profiles.by_slot.values().copied().collect();
    let Ok(entries) = std::fs::read_dir(crate::accounts::identity_store::identities_dir(base))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        if out.len() >= RETIRED_IDENTITIES_CAP {
            break;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(id) = name.parse::<IdentityId>() else {
            continue;
        };
        if !history_ids.contains(&id) {
            continue;
        }
        // A currently-bound identity is the live binding of SOME slot —
        // never "retired" for this one.
        if bound.contains(&id) {
            continue;
        }
        if crate::accounts::identity_store::is_identity_removed(base, id) {
            continue;
        }
        let canonical = crate::credentials::file::load(
            &crate::accounts::identity_store::credentials_path_for(base, id),
        )
        .ok()
        .and_then(|creds| fingerprint_from_credential_file(&creds));
        out.push(RetiredBinding {
            canonical,
            history: read_history(base, id),
        });
    }
    out.sort_by_key(|b| b.canonical.as_ref().map(|f| f.to_hex()));
    out
}

/// [`retired_bindings_for_slot`] under the caller's profiles lock — the
/// lock-held load mirrors `keychain::read_owner_verified_with_profiles`
/// (review R1 L3). The caller guarantees `lock` protects `base`; a refused
/// protection claim narrows to empty rather than reading unlocked.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn retired_bindings_for_slot_locked(
    lock: &ProfilesFileLock,
    base: &Path,
    slot: crate::types::AccountNum,
) -> Vec<RetiredBinding> {
    if !lock.protects(base) {
        return Vec::new();
    }
    let Ok(profiles) =
        crate::accounts::profiles::load(&crate::accounts::profiles::profiles_path(base))
    else {
        return Vec::new();
    };
    retired_bindings_for_slot_with_profiles(base, &profiles, slot)
}

/// Appends `fp` to `id`'s bounded token-history (last [`MAX_HISTORY_LEN`]
/// entries, newest last), atomically and at 0600 (`security.md` MUST Rule 4,
/// Rule 5, and §5a: every failure branch after the tmp write removes it
/// before returning). Best-effort: a failure to append is logged and
/// non-fatal — the history is an availability aid for
/// `keychain::decide_cc_keychain_write`, never a correctness requirement (a
/// missing entry only means one more case falls through to the
/// harvest-first refusal, never an unsafe overwrite).
///
/// Skips the write entirely when `fp` already equals the history's most
/// recent entry, so an unchanged token (or a caller invoked twice for the
/// same refresh) does not grow the file or bump its mtime for nothing.
///
/// `keychain-fix-r9.md` D-F9/S-L-2: the read-modify-write cycle (read
/// current history, push, bound, write) is now serialized under
/// [`token_history_lock_path`] — held only across this in-process file I/O,
/// never across any network or subprocess call, mirroring
/// `credentials::keychain::record_pending_clear`'s lock discipline for its
/// own read-modify-write. Without it, two concurrent writers for the SAME
/// identity (the refresher and a `csq login` re-seed, say) could each read
/// the pre-write history, append their own fingerprint, and write —
/// whichever writes LAST silently discards the other's entry.
pub(crate) fn append_history(base: &Path, id: IdentityId, fp: Fingerprint) {
    // Capture BEFORE the lock wait: the wait is what can force the spool,
    // so the write time would order this append after concurrent writes
    // that it actually precedes (D237 round-2 correctness N5).
    let captured_at = now_unix_nanos();
    if !ensure_identity_dir(base, id, "append_history") {
        return;
    }
    let _guard =
        match crate::platform::lock::lock_credential_file(&token_history_lock_path(base, id)) {
            Ok(Some(g)) => g,
            Ok(None) => {
                // D237 round-2 ruling C(2): NEVER drop the fingerprint. The
                // intent is durable; the next `append_history`/
                // `start_new_segment` (this function's locked section is the
                // drain reader) applies it, and `read_history` already
                // honours it in memory. The 500 ms budget is kept here
                // deliberately: the canonical-lock holder nests this wait,
                // so lengthening it would widen a section this same wave is
                // bounding. A timeout is SAFE because of the queue.
                warn!(
                    error_kind = "token_history_lock_failed",
                    "token-history append: lock busy past the bounded wait — the \
                     fingerprint is QUEUED durably and applied by the next locked \
                     history write (never dropped)"
                );
                enqueue_pending_intent(
                    base,
                    id,
                    PendingHistoryIntent::Append {
                        fingerprint: fp.to_hex(),
                        captured_at_unix_nanos: captured_at,
                    },
                    "append_history",
                );
                return;
            }
            Err(e) => {
                warn!(
                    error_kind = "token_history_lock_failed",
                    "token-history append: could not lock the history file — the \
                     fingerprint is QUEUED durably and applied by the next locked \
                     history write (never dropped): {}",
                    crate::error::redact_tokens(&e.to_string())
                );
                enqueue_pending_intent(
                    base,
                    id,
                    PendingHistoryIntent::Append {
                        fingerprint: fp.to_hex(),
                        captured_at_unix_nanos: captured_at,
                    },
                    "append_history",
                );
                return;
            }
        };
    // DRAIN: apply every queued intent first, so this write persists them
    // together with the current fingerprint.
    let pending = read_pending_intents(base, id);
    let mut history = read_history_on_disk(base, id);
    for (_, intent) in &pending {
        apply_pending_intent(&mut history, intent);
    }
    if history.last().map(|e| e.fingerprint) != Some(fp) {
        history.push(HistoryEntry::new(fp, captured_at));
        trim_history(&mut history);
    } else if pending.is_empty() {
        return;
    }
    if write_history_file(base, id, &history, "append_history") {
        remove_applied_intents(&pending);
    } else {
        // The write failed (logged inside). Queue the fingerprint so it is
        // not lost with the write it was meant to join; applied intents are
        // deduped on the next drain, so re-queueing cannot duplicate it.
        enqueue_pending_intent(
            base,
            id,
            PendingHistoryIntent::Append {
                fingerprint: fp.to_hex(),
                captured_at_unix_nanos: captured_at,
            },
            "append_history_write_failed",
        );
    }
}

/// `keychain-fix-r9.md` D-Q2: begins a NEW history segment for `id` —
/// discards every prior fingerprint and keeps ONLY `current`, so an
/// old-grant token already in the (now-discarded) history is no longer
/// recognised as "known" (`keychain::decide_cc_keychain_write` rule 2)
/// after a fresh `csq login` grant for this identity. Called by
/// `accounts::login::finalize_login` once the identity UUID is resolved —
/// AFTER the fresh grant has already been written to the canonical store
/// (`credentials::file::save_uuid_credentials`'s own `record_write` call
/// already appended it onto the OLD segment; this call is what actually
/// starts the new one). Locked the same way [`append_history`] is, for the
/// same reason.
pub(crate) fn start_new_segment(base: &Path, id: IdentityId, current: Fingerprint) {
    // See `append_history`: the attempt is captured before the lock wait so
    // a queued segment start orders against concurrent writes correctly.
    let captured_at = now_unix_nanos();
    if !ensure_identity_dir(base, id, "start_new_segment") {
        return;
    }
    let _guard =
        match crate::platform::lock::lock_credential_file(&token_history_lock_path(base, id)) {
            Ok(Some(g)) => g,
            Ok(None) => {
                // D237 round-2 ruling C(2): a timed-out segment start MUST
                // NOT leave the old segment silently intended-to-be-cleared.
                // The intent is durable; `read_history` already stops
                // recognising the old segment, and the next locked history
                // write applies it for good.
                warn!(
                    error_kind = "token_history_lock_failed",
                    "token-history start_new_segment: lock busy past the bounded \
                     wait — the segment-start intent is QUEUED durably and applied \
                     by the next locked history write (the old segment is never \
                     left intended-to-be-cleared without a recorded intent)"
                );
                enqueue_pending_intent(
                    base,
                    id,
                    PendingHistoryIntent::StartSegment {
                        fingerprint: current.to_hex(),
                        captured_at_unix_nanos: captured_at,
                    },
                    "start_new_segment",
                );
                return;
            }
            Err(e) => {
                warn!(
                    error_kind = "token_history_lock_failed",
                    "token-history start_new_segment: could not lock the history file \
                     — the segment-start intent is QUEUED durably and applied by the \
                     next locked history write: {}",
                    crate::error::redact_tokens(&e.to_string())
                );
                enqueue_pending_intent(
                    base,
                    id,
                    PendingHistoryIntent::StartSegment {
                        fingerprint: current.to_hex(),
                        captured_at_unix_nanos: captured_at,
                    },
                    "start_new_segment",
                );
                return;
            }
        };
    // DRAIN: apply queued intents to this segment as well — a queued append
    // lands in the segment being finalized; a queued prior segment start is
    // superseded by this one, exactly as if both had run in order.
    let pending = read_pending_intents(base, id);
    let mut existing = read_history_on_disk(base, id);
    for (_, intent) in &pending {
        apply_pending_intent(&mut existing, intent);
    }
    // `keychain-fix-r10.md` S-L-4/C-B4: never a blind overwrite to `[current]`
    // — `current`'s fingerprint is computed by THIS function's caller before
    // the lock above is even attempted, so a concurrent `append_history` call
    // for the SAME identity can land between that computation and this lock
    // acquisition, appending `current` itself (a race with the write this
    // segment start is finalizing) or something AFTER it (a genuinely later
    // refresh this call has no knowledge of). Read the on-disk history INSIDE
    // the lock and truncate to the suffix starting at the LAST occurrence of
    // `current` — preserving any such concurrently-appended entries — or
    // start fresh at `[current]` only when it is genuinely absent.
    let new_segment: Vec<HistoryEntry> =
        match existing.iter().rposition(|e| e.fingerprint == current) {
            Some(pos) => existing[pos..].to_vec(),
            None => vec![HistoryEntry::new(current, captured_at)],
        };
    if write_history_file(base, id, &new_segment, "start_new_segment") {
        remove_applied_intents(&pending);
    } else {
        // The write failed (logged inside): record the intent so the old
        // segment is not left intended-to-be-cleared with nothing on disk
        // saying so. Already-queued intents stay in place and re-apply.
        enqueue_pending_intent(
            base,
            id,
            PendingHistoryIntent::StartSegment {
                fingerprint: current.to_hex(),
                captured_at_unix_nanos: captured_at,
            },
            "start_new_segment_write_failed",
        );
    }
}

/// `keychain-fix-r10.md` S-N-2: verifies `id`'s identity dir ALREADY exists
/// — never creates it. Both of this function's callers ([`append_history`],
/// [`start_new_segment`]) run only AFTER a canonical credential write has
/// already created and secured the identity dir (`file::save_uuid_credentials`
/// creates it before calling `record_write`; `accounts::login::finalize_login`
/// calls `start_new_segment` only after `save_canonical_for` has already
/// written the canonical file into that same dir) — so the dir is GUARANTEED
/// present on every legitimate call. The PRIOR `create_dir_all` here was
/// therefore only ever load-bearing for one case: a stale or racing history
/// write landing AFTER logout has already REMOVED the identity dir entirely.
/// Creating it in that case resurrects an empty, credential-less ghost
/// directory — containing nothing but a `token-history` file — that nothing
/// downstream ever reaps, and that a directory-presence-based identity
/// enumeration could misread as a still-existing account. Returns `false`
/// (logged, non-fatal — history is an availability aid, never a correctness
/// requirement, same as every other failure mode in this module) when the
/// dir is absent, so the write is skipped rather than resurrecting it.
fn ensure_identity_dir(base: &Path, id: IdentityId, caller: &str) -> bool {
    let dir = token_history_path_for(base, id)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| base.to_path_buf());
    if !dir.is_dir() {
        warn!(
            error_kind = "token_history_identity_dir_absent",
            caller,
            "token-history: identity dir does not exist (likely removed by \
             logout) — skipping this write rather than resurrecting it"
        );
        return false;
    }
    true
}

/// Shared atomic-write tail for [`append_history`]/[`start_new_segment`] —
/// both callers MUST already hold [`token_history_lock_path`]'s lock, since
/// this function only writes; it does not itself lock. Writes at 0600
/// (`security.md` MUST Rule 4, Rule 5, and §5a: every failure branch after
/// the tmp write removes it before returning). Best-effort: a failure is
/// logged and non-fatal — the history is an availability aid for
/// `keychain::decide_cc_keychain_write`, never a correctness requirement.
/// Returns `true` only when the list reached disk (the drain gates its
/// intent-file removal on it).
///
/// Each entry's captured time is persisted beside its fingerprint so a
/// later drain can order a queued intent against these entries instead of
/// blind-appending it (D237 round-2 correctness N5).
fn write_history_file(base: &Path, id: IdentityId, entries: &[HistoryEntry], caller: &str) -> bool {
    let file = HistoryFile {
        fingerprints: entries.iter().map(|e| e.fingerprint.to_hex()).collect(),
        captured_at_unix_nanos: entries.iter().map(|e| e.captured_at_unix_nanos).collect(),
    };
    write_history_json(&token_history_path_for(base, id), &file, caller)
}

/// Shared atomic 0600 write of a fingerprint list to `path` (see
/// [`write_history_file`]); also the writer for the owner-verified list,
/// whose entries carry no sequence (a set, not an ordering).
///
/// `#[cfg(test)]`: the owner-verified list is the only remaining caller —
/// production's ordered-history write goes through [`write_history_file`],
/// which persists per-entry capture times. Gating it here keeps the
/// production lib free of a writer no production path reaches.
#[cfg(test)]
fn write_fingerprint_list(path: &Path, fingerprints: &[Fingerprint], caller: &str) -> bool {
    let file = HistoryFile {
        fingerprints: fingerprints.iter().map(|f| f.to_hex()).collect(),
        captured_at_unix_nanos: Vec::new(),
    };
    write_history_json(path, &file, caller)
}

/// The single §5a atomic-write tail shared by the ordered history and the
/// owner-verified list.
fn write_history_json(path: &Path, file: &HistoryFile, caller: &str) -> bool {
    let path = path.to_path_buf();
    let json = match serde_json::to_string(file) {
        Ok(j) => j,
        Err(_) => return false,
    };
    // §5a: treated as secret-bearing (fingerprints of Anthropic refresh
    // tokens — a hash, not the raw token, but §5a's own table names "OAuth
    // tokens, refresh tokens" without a fingerprint carve-out, so ambiguity
    // resolves toward secret-bearing here). `write_new_private` creates
    // the tmp file at 0o600 at creation, closing the window a separate
    // write + secure_file pair would leave open.
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if let Err(e) = crate::platform::fs::write_new_private(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        // `keychain-fix-r11.md` S-LOW-2: this function no longer calls
        // `create_dir_all`/`secure_dir` on the parent at all — that was the
        // SAME resurrection hazard `ensure_identity_dir` (S-N-2) already
        // named and was supposed to have closed: `ensure_identity_dir`'s
        // check and this write are two SEPARATE steps, and if `csq logout`
        // removes the identity dir in the window between them (nothing
        // requires the two to share a lock), a `create_dir_all` here would
        // silently recreate an empty, credential-less ghost directory —
        // exactly what `ensure_identity_dir`'s own doc says must never
        // happen. `ENOENT` (parent gone) now surfaces as an ordinary write
        // failure and is skipped cleanly, never resurrected.
        // `write_new_private`'s only failure paths are `open()` (parent
        // missing surfaces here as an ordinary io::Error) and `write_all`,
        // both wrapped as `PlatformError::Io` — so this match preserves the
        // ENOENT distinction the old `e.kind()` check made directly on the
        // io::Error `std::fs::write` used to return.
        let parent_gone = matches!(
            &e,
            crate::error::PlatformError::Io(io_err)
                if io_err.kind() == std::io::ErrorKind::NotFound
        );
        if parent_gone {
            warn!(
                error_kind = "token_history_identity_dir_absent",
                caller,
                "token-history write: identity dir does not exist (removed \
                 concurrently, e.g. by logout) — skipped, never resurrected"
            );
        } else {
            warn!(
                error_kind = "token_history_write_failed",
                caller,
                "token-history write: write failed: {}",
                crate::error::redact_tokens(&e.to_string())
            );
        }
        return false;
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "token_history_replace_failed",
            caller,
            "token-history write: atomic_replace failed: {}",
            crate::error::redact_tokens(&e.to_string())
        );
        return false;
    }
    true
}

/// Bound on the owner-verified superseded-login list (same bound as the
/// ordered history).
pub(crate) const MAX_OWNER_VERIFIED_LEN: usize = 16;

/// Path of `id`'s owner-verified list — a SEPARATE file beside the ordered
/// history, so the weak history-position channel (and its relative-expiry
/// guard) is never mixed with this strong, server-verified channel.
#[cfg(test)]
fn owner_verified_path_for(base: &Path, id: IdentityId) -> PathBuf {
    token_history_path_for(base, id).with_file_name("token-owner-verified")
}

/// Reads `id`'s owner-verified superseded-login fingerprints. Absent,
/// oversized, irregular, or corrupt file ⇒ empty (fail closed: recognition
/// narrows, never widens).
#[cfg(test)]
pub(crate) fn read_owner_verified(base: &Path, id: IdentityId) -> Vec<Fingerprint> {
    let Some(content) = read_bounded(&owner_verified_path_for(base, id)) else {
        return Vec::new();
    };
    let Ok(parsed) = serde_json::from_str::<HistoryFile>(&content) else {
        warn!(
            error_kind = "token_owner_verified_unparseable",
            "owner-verified list present but unparseable; treating as empty"
        );
        return Vec::new();
    };
    parsed
        .fingerprints
        .iter()
        .filter_map(|s| Fingerprint::from_hex(s))
        .collect()
}

/// Slot-keyed [`read_owner_verified`]; empty when the slot has no UUID.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn read_owner_verified_for_slot(
    base: &Path,
    account: crate::types::AccountNum,
) -> Vec<Fingerprint> {
    let Ok(Some(lock)) = ProfilesFileLock::try_acquire(base) else {
        return Vec::new();
    };
    let Ok(binding) = ai::capture_anthropic_binding_locked(&lock, base, account) else {
        return Vec::new();
    };
    read_owner_verified_v2_locked(&lock, base, &binding)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerProofV2Entry {
    fingerprint: String,
    credential_version: ai::CredentialVersion,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerProofV2 {
    version: u32,
    identity_uuid: IdentityId,
    email: String,
    account_uuid: uuid::Uuid,
    organization_uuid: uuid::Uuid,
    entries: Vec<OwnerProofV2Entry>,
}
enum OwnerProofRead {
    Absent,
    Valid(OwnerProofV2),
    Incompatible,
}
fn owner_verified_v2_path_for(base: &Path, id: IdentityId) -> PathBuf {
    token_history_path_for(base, id).with_file_name("token-owner-verified-v2")
}
fn read_owner_proof_v2(
    base: &Path,
    id: IdentityId,
    context: &ai::AnthropicContext,
) -> OwnerProofRead {
    let path = owner_verified_v2_path_for(base, id);
    #[cfg(windows)]
    let before_file = {
        use std::os::windows::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return OwnerProofRead::Absent
            }
            Err(_) => return OwnerProofRead::Incompatible,
        }
    };
    #[cfg(windows)]
    let metadata = match before_file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return OwnerProofRead::Incompatible,
    };
    #[cfg(not(windows))]
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return OwnerProofRead::Absent,
        Err(_) => return OwnerProofRead::Incompatible,
    };
    // Sixteen version/fingerprint entries plus context fit this fixed ceiling.
    if !metadata.is_file() || metadata.len() > 8192 {
        return OwnerProofRead::Incompatible;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0
            || metadata.uid() != {
                // SAFETY: geteuid has no memory or synchronization preconditions.
                unsafe { libc::geteuid() }
            }
        {
            return OwnerProofRead::Incompatible;
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let Ok(mut handle) = options.open(&path) else {
        return OwnerProofRead::Incompatible;
    };
    let Ok(opened) = handle.metadata() else {
        return OwnerProofRead::Incompatible;
    };
    if !opened.is_file() || opened.len() > 8192 {
        return OwnerProofRead::Incompatible;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.nlink() != 1
            || opened.mode() & 0o077 != 0
            || opened.uid() != {
                // SAFETY: geteuid has no memory or synchronization preconditions.
                unsafe { libc::geteuid() }
            }
        {
            return OwnerProofRead::Incompatible;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let (Ok(before_id), Ok(opened_id)) = (
            ai::windows_file_identity(&before_file),
            ai::windows_file_identity(&handle),
        ) else {
            return OwnerProofRead::Incompatible;
        };
        if opened.file_attributes() & 0x0400 != 0
            || before_id != opened_id
            || metadata.len() != opened.len()
            || metadata.last_write_time() != opened.last_write_time()
            || metadata.creation_time() != opened.creation_time()
        {
            return OwnerProofRead::Incompatible;
        }
    }
    let mut bytes = Vec::new();
    use std::io::Read;
    if (&mut handle).take(8193).read_to_end(&mut bytes).is_err() || bytes.len() > 8192 {
        return OwnerProofRead::Incompatible;
    }
    let (Ok(after), Ok(named)) = (handle.metadata(), std::fs::symlink_metadata(&path)) else {
        return OwnerProofRead::Incompatible;
    };
    let (Ok(opened_modified), Ok(after_modified), Ok(named_modified)) =
        (opened.modified(), after.modified(), named.modified())
    else {
        return OwnerProofRead::Incompatible;
    };
    if !after.is_file()
        || !named.is_file()
        || bytes.len() as u64 != opened.len()
        || after.len() != opened.len()
        || named.len() != opened.len()
        || after_modified != opened_modified
        || named_modified != opened_modified
    {
        return OwnerProofRead::Incompatible;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.dev() != opened.dev()
            || after.ino() != opened.ino()
            || named.dev() != opened.dev()
            || named.ino() != opened.ino()
            || after.ctime() != opened.ctime()
            || after.ctime_nsec() != opened.ctime_nsec()
            || named.ctime() != opened.ctime()
            || named.ctime_nsec() != opened.ctime_nsec()
        {
            return OwnerProofRead::Incompatible;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let Ok(named_file) = options.open(&path) else {
            return OwnerProofRead::Incompatible;
        };
        let Ok(named_held) = named_file.metadata() else {
            return OwnerProofRead::Incompatible;
        };
        let (Ok(named_id), Ok(opened_id)) = (
            ai::windows_file_identity(&named_file),
            ai::windows_file_identity(&handle),
        ) else {
            return OwnerProofRead::Incompatible;
        };
        if named_id != opened_id
            || named.file_attributes() & 0x0400 != 0
            || named_held.len() != after.len()
            || named_held.last_write_time() != after.last_write_time()
            || named_held.creation_time() != after.creation_time()
            || after.last_write_time() != opened.last_write_time()
            || after.creation_time() != opened.creation_time()
        {
            return OwnerProofRead::Incompatible;
        }
    }
    let Ok(file) = serde_json::from_slice::<OwnerProofV2>(&bytes) else {
        return OwnerProofRead::Incompatible;
    };
    if file.version != 2
        || file.identity_uuid != id
        || file.email != context.email()
        || file.account_uuid != context.account_uuid()
        || file.organization_uuid != context.organization_uuid()
        || file.entries.len() > MAX_OWNER_VERIFIED_LEN
        || file
            .entries
            .iter()
            .any(|entry| Fingerprint::from_hex(&entry.fingerprint).is_none())
    {
        return OwnerProofRead::Incompatible;
    }
    OwnerProofRead::Valid(file)
}
pub(crate) fn read_owner_verified_v2_locked(
    lock: &ProfilesFileLock,
    base: &Path,
    binding: &ai::CapturedBinding,
) -> Vec<Fingerprint> {
    let ai::StoredAnthropicContext::Known(context) = binding.context() else {
        return Vec::new();
    };
    if !ai::binding_matches_locked(lock, base, binding).unwrap_or(false) {
        return Vec::new();
    }
    match read_owner_proof_v2(base, binding.identity(), context) {
        OwnerProofRead::Valid(file) => file
            .entries
            .iter()
            .filter_map(|entry| Fingerprint::from_hex(&entry.fingerprint))
            .collect(),
        OwnerProofRead::Absent | OwnerProofRead::Incompatible => Vec::new(),
    }
}
pub(crate) fn record_owner_verified_v2(
    base: &Path,
    binding: &ai::CapturedBinding,
    proof: &ai::VerifiedAnthropicContext,
) -> OwnerVerifiedRecord {
    let Ok(lock) = ProfilesFileLock::acquire(base) else {
        return OwnerVerifiedRecord::Failed;
    };
    record_owner_verified_v2_locked(&lock, base, binding, proof)
}
pub(crate) fn record_owner_verified_v2_locked(
    lock: &ProfilesFileLock,
    base: &Path,
    binding: &ai::CapturedBinding,
    proof: &ai::VerifiedAnthropicContext,
) -> OwnerVerifiedRecord {
    let ai::StoredAnthropicContext::Known(context) = binding.context() else {
        return OwnerVerifiedRecord::Failed;
    };
    if ai::compare_verified_owner(binding.context(), proof) != ai::OwnerVerdict::Owned {
        return OwnerVerifiedRecord::Failed;
    }
    if !ai::binding_matches_locked(lock, base, binding).unwrap_or(false) {
        return OwnerVerifiedRecord::Rebound;
    }
    if !ensure_identity_dir(base, binding.identity(), "record_owner_verified_v2") {
        return OwnerVerifiedRecord::Failed;
    }
    let path = owner_verified_v2_path_for(base, binding.identity());
    let Ok(Some(_proof_lock)) =
        crate::platform::lock::lock_credential_file(&path.with_extension("lock"))
    else {
        return OwnerVerifiedRecord::Failed;
    };
    let mut file = match read_owner_proof_v2(base, binding.identity(), context) {
        OwnerProofRead::Absent => OwnerProofV2 {
            version: 2,
            identity_uuid: binding.identity(),
            email: context.email().into(),
            account_uuid: context.account_uuid(),
            organization_uuid: context.organization_uuid(),
            entries: Vec::new(),
        },
        OwnerProofRead::Valid(file) => file,
        // Never reinterpret a corrupt, foreign, unreadable or future envelope as empty.
        OwnerProofRead::Incompatible => return OwnerVerifiedRecord::Failed,
    };
    let fingerprint = proof.fingerprint().to_hex();
    if file.entries.iter().any(|entry| {
        entry.fingerprint == fingerprint && entry.credential_version == proof.credential_version()
    }) {
        return OwnerVerifiedRecord::Written;
    }
    file.entries
        .retain(|entry| entry.fingerprint != fingerprint);
    file.entries.push(OwnerProofV2Entry {
        fingerprint,
        credential_version: proof.credential_version(),
    });
    if file.entries.len() > MAX_OWNER_VERIFIED_LEN {
        file.entries.remove(0);
    }
    let Ok(bytes) = serde_json::to_vec(&file) else {
        return OwnerVerifiedRecord::Failed;
    };
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    if crate::platform::fs::write_new_private(&tmp, &bytes).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return OwnerVerifiedRecord::Failed;
    }
    if atomic_replace(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return OwnerVerifiedRecord::Failed;
    }
    OwnerVerifiedRecord::Written
}

/// Records `fp` as a server-verified (`/api/oauth/profile` owner match)
/// SUPERSEDED login of `id`. Bounded (oldest evicted), deduplicated, locked,
/// atomic 0600; best-effort and non-fatal like the history.
#[cfg(test)]
pub(crate) fn record_owner_verified(base: &Path, id: IdentityId, fp: Fingerprint) {
    record_owner_verified_if(base, id, fp, || true);
}

/// Outcome of [`record_owner_verified_if`]. The three causes are distinct
/// operator/caller facts and MUST NOT be folded into one `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnerVerifiedRecord {
    /// The fingerprint is on disk (written now, or already present).
    Written,
    /// The locked `still_bound` re-check returned `false`: the slot no longer
    /// maps to the identity whose anchor email was checked. Nothing written.
    Rebound,
    /// The identity dir is missing, the list lock could not be taken, or the
    /// write failed. Nothing (reliably) written; the binding is not known to
    /// have changed, so a caller may continue with other candidates.
    Failed,
}

/// [`record_owner_verified`] with a re-check UNDER the list lock: `still_bound`
/// runs after the lock is held and before anything is written. The guarantee
/// that no OTHER identity's list is written comes from the path being keyed by
/// the threaded `id` (this function never resolves a slot); `still_bound` is a
/// conservative early stop for the caller (the custodian passes "does
/// `by_slot[account]` still resolve to `id`?"), NOT serialisation against
/// `csq login` — that command does not take this list lock, so the binding can
/// still move right after the check. `false` returns [`OwnerVerifiedRecord::Rebound`]
/// with a fixed-vocabulary WARN (no fingerprint, no email).
#[cfg(test)]
pub(crate) fn record_owner_verified_if(
    base: &Path,
    id: IdentityId,
    fp: Fingerprint,
    still_bound: impl FnOnce() -> bool,
) -> OwnerVerifiedRecord {
    if !ensure_identity_dir(base, id, "record_owner_verified") {
        return OwnerVerifiedRecord::Failed;
    }
    let path = owner_verified_path_for(base, id);
    let _guard = match crate::platform::lock::lock_file(&path.with_extension("lock")) {
        Ok(g) => g,
        Err(e) => {
            warn!(
                error_kind = "token_owner_verified_lock_failed",
                "owner-verified record: could not lock (non-fatal): {}",
                crate::error::redact_tokens(&e.to_string())
            );
            return OwnerVerifiedRecord::Failed;
        }
    };
    if !still_bound() {
        warn!(
            error_kind = "token_owner_verified_slot_rebound",
            "owner-verified record skipped: slot no longer maps to the identity that was checked"
        );
        return OwnerVerifiedRecord::Rebound;
    }
    let mut list = read_owner_verified(base, id);
    if list.contains(&fp) {
        return OwnerVerifiedRecord::Written;
    }
    list.push(fp);
    if list.len() > MAX_OWNER_VERIFIED_LEN {
        let excess = list.len() - MAX_OWNER_VERIFIED_LEN;
        list.drain(0..excess);
    }
    if write_fingerprint_list(&path, &list, "record_owner_verified") {
        OwnerVerifiedRecord::Written
    } else {
        OwnerVerifiedRecord::Failed
    }
}

/// Convenience: fingerprints `creds` (Anthropic only) and appends it to
/// `id`'s history in one call — the shape every canonical-store writer
/// (`save_uuid_credentials`) uses.
pub(crate) fn record_write(base: &Path, id: IdentityId, creds: &CredentialFile) {
    if let Some(fp) = fingerprint_from_credential_file(creds) {
        append_history(base, id, fp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{
        AnthropicCredentialFile, CodexCredentialFile, CodexTokensFile, OAuthPayload,
    };
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;

    /// `keychain-fix-r10.md` S-N-2: `ensure_identity_dir` no longer creates
    /// the identity dir (see its own doc) — every test below that exercises
    /// `append_history`/`start_new_segment` directly, rather than through
    /// the real production chokepoint (`credentials::file::save_uuid_credentials`,
    /// which always creates the dir first), must plant it first, exactly as
    /// that chokepoint does.
    fn plant_identity_dir(base: &Path, id: IdentityId) {
        let dir = token_history_path_for(base, id)
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
    }

    fn anthropic_file(refresh: &str) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at".into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at: 0,
                scopes: Vec::new(),
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    fn codex_file() -> CredentialFile {
        CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: None,
                access_token: "codex-at".into(),
                refresh_token: Some("codex-rt".into()),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        })
    }

    #[test]
    fn fingerprint_from_raw_json_extracts_refresh_token() {
        let raw = r#"{"claudeAiOauth":{"accessToken":"at","refreshToken":"rt-1"}}"#;
        let fp = fingerprint_from_raw_json(raw).expect("should parse");
        assert_eq!(fp, Fingerprint::of_refresh_token("rt-1"));
    }

    #[test]
    fn fingerprint_from_raw_json_none_on_missing_refresh_token() {
        let raw = r#"{"claudeAiOauth":{"accessToken":"at"}}"#;
        assert!(fingerprint_from_raw_json(raw).is_none());
    }

    #[test]
    fn fingerprint_from_raw_json_none_on_empty_refresh_token() {
        let raw = r#"{"claudeAiOauth":{"accessToken":"at","refreshToken":""}}"#;
        assert!(fingerprint_from_raw_json(raw).is_none());
    }

    #[test]
    fn fingerprint_from_raw_json_none_on_non_json() {
        assert!(fingerprint_from_raw_json("not json").is_none());
    }

    #[test]
    fn fingerprint_is_stable_and_distinguishes_tokens() {
        let a = Fingerprint::of_refresh_token("token-a");
        let a2 = Fingerprint::of_refresh_token("token-a");
        let b = Fingerprint::of_refresh_token("token-b");
        assert_eq!(a, a2, "same token must fingerprint identically");
        assert_ne!(
            a, b,
            "different tokens must not collide in this test corpus"
        );
    }

    #[test]
    fn hex_round_trips() {
        let fp = Fingerprint::of_refresh_token("rt-round-trip");
        let hex = fp.to_hex();
        assert_eq!(hex.len(), 64, "sha256 hex is 32 bytes = 64 hex chars");
        assert_eq!(Fingerprint::from_hex(&hex), Some(fp));
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert!(Fingerprint::from_hex("deadbeef").is_none());
    }

    #[test]
    fn from_hex_rejects_non_hex() {
        assert!(Fingerprint::from_hex(&"z".repeat(64)).is_none());
    }

    #[test]
    fn read_history_absent_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        assert!(read_history(dir.path(), id).is_empty());
    }

    #[test]
    fn read_history_unparseable_file_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        let path = token_history_path_for(dir.path(), id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not json at all").unwrap();
        assert!(read_history(dir.path(), id).is_empty());
    }

    #[test]
    fn append_then_read_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let fp = Fingerprint::of_refresh_token("rt-1");
        append_history(dir.path(), id, fp);
        let history = read_history(dir.path(), id);
        assert_eq!(history, vec![fp]);
    }

    #[test]
    fn append_is_bounded_to_max_history_len() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        for i in 0..(MAX_HISTORY_LEN + 5) {
            append_history(
                dir.path(),
                id,
                Fingerprint::of_refresh_token(&format!("rt-{i}")),
            );
        }
        let history = read_history(dir.path(), id);
        assert_eq!(history.len(), MAX_HISTORY_LEN, "history must stay bounded");
        // Newest-last: the surviving entries are the LAST MAX_HISTORY_LEN tokens appended.
        assert_eq!(
            history.last(),
            Some(&Fingerprint::of_refresh_token(&format!(
                "rt-{}",
                MAX_HISTORY_LEN + 4
            )))
        );
        assert_eq!(
            history.first(),
            Some(&Fingerprint::of_refresh_token("rt-5")),
            "the oldest 5 entries must have been dropped"
        );
    }

    #[test]
    fn owner_verified_round_trips_dedups_and_is_separate_from_history() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let fp = Fingerprint::of_refresh_token("rt-sup");
        record_owner_verified(dir.path(), id, fp);
        record_owner_verified(dir.path(), id, fp);
        assert_eq!(read_owner_verified(dir.path(), id), vec![fp]);
        assert!(
            read_history(dir.path(), id).is_empty(),
            "owner-verified fingerprints must never enter the ordered history"
        );
    }

    #[test]
    fn owner_verified_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        for i in 0..(MAX_OWNER_VERIFIED_LEN + 3) {
            record_owner_verified(
                dir.path(),
                id,
                Fingerprint::of_refresh_token(&format!("ov-{i}")),
            );
        }
        let l = read_owner_verified(dir.path(), id);
        assert_eq!(l.len(), MAX_OWNER_VERIFIED_LEN);
        assert_eq!(l.first(), Some(&Fingerprint::of_refresh_token("ov-3")));
    }

    #[test]
    fn owner_verified_corrupt_or_absent_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        assert!(read_owner_verified(dir.path(), id).is_empty());
        plant_identity_dir(dir.path(), id);
        std::fs::write(owner_verified_path_for(dir.path(), id), b"{garbage").unwrap();
        assert!(read_owner_verified(dir.path(), id).is_empty());
    }

    #[test]
    fn owner_verified_skipped_when_identity_dir_absent() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        record_owner_verified(dir.path(), id, Fingerprint::of_refresh_token("x"));
        assert!(
            !owner_verified_path_for(dir.path(), id)
                .parent()
                .unwrap()
                .exists(),
            "must not resurrect a removed identity dir"
        );
    }

    /// `keychain-fix-r10.md` T-c: an ordering proof for the history lock —
    /// `append_history`'s read-modify-write cycle (`lock` -> `read_history`
    /// -> push -> `write_history_file`) MUST be serialized by
    /// `token_history_lock_path`'s `flock`, or concurrent appends for the
    /// SAME identity lose each other's writes (a classic read-modify-write
    /// race: both threads read the same starting state, both compute a
    /// one-longer array, the second write clobbers the first). Genuine OS
    /// threads (not tokio tasks) against the SAME identity, each appending
    /// its OWN distinct fingerprint — the invariant under test is "no
    /// fingerprint is lost", which holds regardless of the actual
    /// interleaving order the OS scheduler picks, so this is not a timing
    /// guess.
    ///
    /// RED: this cannot be RED-verified by deleting the `lock_file` call
    /// alone and re-running once — a lost update is a race, not a
    /// deterministic branch — but was verified BY EXECUTION: with the lock
    /// call removed, `history.len()` came back less than `THREADS` on
    /// repeated runs (flaky-losing, never flaky-passing), confirming the
    /// lock is what removes the race rather than coincidental ordering.
    #[test]
    fn append_history_concurrent_writes_for_same_identity_lose_nothing() {
        const THREADS: usize = 12;
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let base = dir.path().to_path_buf();

        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let base = base.clone();
                std::thread::spawn(move || {
                    append_history(&base, id, Fingerprint::of_refresh_token(&format!("rt-{i}")));
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let history = read_history(dir.path(), id);
        assert_eq!(
            history.len(),
            THREADS,
            "every concurrent append must be preserved — the lock must \
             serialize the read-modify-write cycle, got {history:?}"
        );
        for i in 0..THREADS {
            assert!(
                history.contains(&Fingerprint::of_refresh_token(&format!("rt-{i}"))),
                "thread {i}'s fingerprint must be present"
            );
        }
    }

    /// Every pending-intent spool file for `id`, name-sorted.
    fn pending_history_files(base: &Path, id: IdentityId) -> Vec<PathBuf> {
        let Ok(rd) = std::fs::read_dir(pending_history_dir(base, id)) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        paths.sort();
        paths
    }

    /// D237 round-2 ruling C(2), row 1: an append whose history lock is held
    /// past the bounded wait is QUEUED durably — never dropped — and the
    /// DRAIN reader (the next `append_history`'s locked section) records it.
    ///
    /// RED (assertion) under a mutation restoring the pre-fix `Ok(None)` arm
    /// (`return;` without `enqueue_pending_intent`): the spool stays empty.
    #[test]
    fn append_history_under_a_held_lock_is_queued_and_the_next_append_drains_it() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let queued = Fingerprint::of_refresh_token("queued-under-contention");
        let later = Fingerprint::of_refresh_token("appended-after-the-drain");

        // Held on a second thread: Windows locks are re-entrant on the
        // holding thread, so a same-thread hold never reaches `Ok(None)`.
        let held = crate::platform::lock::HeldOnOtherThread::hold(&token_history_lock_path(
            dir.path(),
            id,
        ));
        append_history(dir.path(), id, queued);
        assert_eq!(
            pending_history_files(dir.path(), id).len(),
            1,
            "a timed-out append must be durably queued, never dropped"
        );
        // Readers honour the queued intent BEFORE any drain: recognition
        // never degrades while the intent waits.
        assert!(
            read_history(dir.path(), id).contains(&queued),
            "read_history must apply queued intents in memory"
        );
        held.release();

        // The drain reader: append_history's own locked section.
        append_history(dir.path(), id, later);
        let history = read_history(dir.path(), id);
        assert!(
            history.contains(&queued),
            "the next locked append must record the queued fingerprint: {history:?}"
        );
        assert!(history.contains(&later));
        assert!(
            pending_history_files(dir.path(), id).is_empty(),
            "applied intent files must be removed only after the history write"
        );
    }

    /// D237 round-2 ruling C(2), row 2: a `start_new_segment` whose lock is
    /// held past the bounded wait records the CLEAR INTENT durably; readers
    /// already stop recognising the old segment, and the next locked writer
    /// applies it for good.
    ///
    /// RED (assertion) under a mutation restoring the pre-fix `Ok(None)` arm:
    /// no intent is queued and `read_history` still reports the old grant.
    #[test]
    fn start_new_segment_timeout_queues_the_intent_and_the_next_writer_applies_it() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let old = Fingerprint::of_refresh_token("old-grant");
        let current = Fingerprint::of_refresh_token("fresh-grant");
        append_history(dir.path(), id, old);
        assert_eq!(read_history(dir.path(), id), vec![old]);

        // Held on a second thread: Windows locks are re-entrant on the
        // holding thread, so a same-thread hold never reaches `Ok(None)`.
        let held = crate::platform::lock::HeldOnOtherThread::hold(&token_history_lock_path(
            dir.path(),
            id,
        ));
        start_new_segment(dir.path(), id, current);
        assert_eq!(
            pending_history_files(dir.path(), id).len(),
            1,
            "a timed-out segment start must queue its intent, never drop it"
        );
        let visible = read_history(dir.path(), id);
        assert!(
            !visible.contains(&old),
            "readers must already honour the queued segment start: {visible:?}"
        );
        assert!(visible.contains(&current));
        held.release();

        // The drain reader: append_history's locked section applies the
        // queued segment start, then appends (deduped — `current` is last).
        append_history(dir.path(), id, current);
        let history = read_history(dir.path(), id);
        assert_eq!(
            history,
            vec![current],
            "the old segment must be cleared once the queued intent is applied"
        );
        assert!(
            pending_history_files(dir.path(), id).is_empty(),
            "the applied intent file must be removed"
        );
    }

    /// Every quarantined file for `id`, name-sorted.
    fn quarantined_history_files(base: &Path, id: IdentityId) -> Vec<PathBuf> {
        let qdir = pending_history_dir(base, id).join(PENDING_HISTORY_QUARANTINE_DIRNAME);
        let Ok(rd) = std::fs::read_dir(qdir) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        paths.sort();
        paths
    }

    /// D237 round-2 correctness N5 / security R2-M2, row 1: junk files at
    /// the HEAD of the spool (names sort before every real intent) must not
    /// starve the valid entry behind them. They are quarantined — kept on
    /// disk, out of the drain window — and the valid intent is applied and
    /// later MERGED by a locked writer.
    ///
    /// RED (assertion) under the pre-fix `paths.sort()` +
    /// `take(PENDING_HISTORY_DRAIN_MAX)` before the parse filter: the first
    /// `PENDING_HISTORY_DRAIN_MAX` entries are all junk, `read_history`
    /// never sees the valid fingerprint (`contains` fails), and the spool
    /// never drains it.
    #[test]
    fn junk_spool_files_at_the_head_do_not_starve_a_valid_intent() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let spool = pending_history_dir(dir.path(), id);
        std::fs::create_dir_all(&spool).unwrap();
        // One more junk file than a single drain window, each name sorting
        // before the nanos-prefixed valid entry below.
        let junk_count = PENDING_HISTORY_DRAIN_MAX + 8;
        for i in 0..junk_count {
            std::fs::write(spool.join(format!("{i:030}-0-0.json")), b"not an intent").unwrap();
        }
        let valid = Fingerprint::of_refresh_token("rt-behind-the-junk");
        assert!(enqueue_pending_intent(
            dir.path(),
            id,
            PendingHistoryIntent::Append {
                fingerprint: valid.to_hex(),
                captured_at_unix_nanos: now_unix_nanos(),
            },
            "test",
        ));

        // The READ path is a drain reader too: the valid intent must be
        // honoured even though every junk file sorts ahead of it.
        assert!(
            read_history(dir.path(), id).contains(&valid),
            "the valid intent behind the junk head must still be applied"
        );
        assert_eq!(
            quarantined_history_files(dir.path(), id).len(),
            junk_count,
            "every unparseable head file must be QUARANTINED (kept on disk, out \
             of the drain window), never deleted"
        );
        assert_eq!(
            pending_history_files(dir.path(), id).len(),
            1,
            "only the valid intent may remain a drain candidate"
        );

        // And the DRAIN applies it to disk, then removes the intent file.
        let later = Fingerprint::of_refresh_token("rt-appended-after-the-drain");
        append_history(dir.path(), id, later);
        assert_eq!(
            read_history(dir.path(), id),
            vec![valid, later],
            "the drain must merge the valid intent, not lose it behind the junk"
        );
        assert!(
            pending_history_files(dir.path(), id).is_empty(),
            "the applied intent file must be removed after the history write"
        );
        assert_eq!(
            quarantined_history_files(dir.path(), id).len(),
            junk_count,
            "quarantine is terminal for these files — a later drain must not \
             re-quarantine or drop them"
        );
    }

    /// D237 round-2 correctness N5, row 2: STRICT SEQUENCE ORDER. An intent
    /// captured at T must be applied at T's position, never after an entry
    /// persisted at T+1 — history position feeds the keychain recognition
    /// decision (`keychain::retired_history_in`).
    ///
    /// RED (assertion) under the pre-fix "apply every pending intent after
    /// the on-disk history" behaviour: `read_history` returns
    /// `[later_on_disk, earlier]` — the older fingerprint becomes "latest".
    #[test]
    fn an_intent_captured_before_an_on_disk_entry_is_applied_in_sequence_order() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let earlier = Fingerprint::of_refresh_token("rt-earlier-intent");
        let later_on_disk = Fingerprint::of_refresh_token("rt-later-on-disk");
        // Synthetic capture times keep the ordering explicit; any real
        // `append_history` call below captures a much later wall-clock time.
        let t = 1_000_000_000u64;
        assert!(enqueue_pending_intent(
            dir.path(),
            id,
            PendingHistoryIntent::Append {
                fingerprint: earlier.to_hex(),
                captured_at_unix_nanos: t,
            },
            "test",
        ));
        // A concurrent locked writer persisted T+1 before anything drained
        // the intent (the intent file is written AFTER its lock wait, so
        // this window is real, not hypothetical).
        assert!(write_history_file(
            dir.path(),
            id,
            &[HistoryEntry::new(later_on_disk, t + 1)],
            "test",
        ));

        assert_eq!(
            read_history(dir.path(), id),
            vec![earlier, later_on_disk],
            "the T+1 entry must remain LAST — the older intent is not 'latest'"
        );

        // The drain persists the same order and appends the newest write.
        let newest = Fingerprint::of_refresh_token("rt-newest");
        append_history(dir.path(), id, newest);
        assert_eq!(
            read_history(dir.path(), id),
            vec![earlier, later_on_disk, newest],
            "the drain must preserve sequence order on disk"
        );
        assert!(pending_history_files(dir.path(), id).is_empty());
    }

    /// D237 round-2 correctness N5, row 3: the spool has a TOTAL file cap.
    /// At the cap a new enqueue is REFUSED (loudly — a fixed-vocabulary
    /// WARN naming the state), and the already-queued entries still drain.
    ///
    /// RED (assertion) under the pre-fix unbounded enqueue: the 257th write
    /// succeeds, so `pending_intent_file_count` exceeds
    /// `PENDING_HISTORY_MAX_FILES`.
    #[test]
    fn the_spool_refuses_loudly_at_its_total_cap_and_still_drains() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let spool = pending_history_dir(dir.path(), id);
        std::fs::create_dir_all(&spool).unwrap();
        for i in 0..PENDING_HISTORY_MAX_FILES {
            assert!(
                enqueue_pending_intent(
                    dir.path(),
                    id,
                    PendingHistoryIntent::Append {
                        fingerprint: Fingerprint::of_refresh_token(&format!("rt-cap-{i}")).to_hex(),
                        captured_at_unix_nanos: i as u64 + 1,
                    },
                    "test",
                ),
                "enqueue {i} must succeed below the total cap"
            );
        }
        assert_eq!(
            pending_intent_file_count(&spool),
            PENDING_HISTORY_MAX_FILES,
            "test precondition: the spool is exactly at its cap"
        );

        let refused = enqueue_pending_intent(
            dir.path(),
            id,
            PendingHistoryIntent::Append {
                fingerprint: Fingerprint::of_refresh_token("rt-over-cap").to_hex(),
                captured_at_unix_nanos: PENDING_HISTORY_MAX_FILES as u64 + 1,
            },
            "test",
        );
        assert!(
            !refused,
            "an enqueue AT the cap must be refused — the spool must never grow \
             without bound"
        );
        assert_eq!(
            pending_intent_file_count(&spool),
            PENDING_HISTORY_MAX_FILES,
            "the refusal must not add a file"
        );

        // The refusal is transient pressure, not a wedged queue: one locked
        // writer drains a full window and appends its own fingerprint.
        let newest = Fingerprint::of_refresh_token("rt-cap-drain");
        append_history(dir.path(), id, newest);
        assert!(
            pending_intent_file_count(&spool) < PENDING_HISTORY_MAX_FILES,
            "existing queue entries must still drain after the refusal"
        );
        let history = read_history(dir.path(), id);
        assert_eq!(
            history.len(),
            MAX_HISTORY_LEN,
            "the drain plus the remaining queued intents must fill the bounded \
             history only"
        );
        assert_eq!(
            history.last(),
            Some(&newest),
            "the newest locked write must remain last"
        );
    }

    /// R3 finding sec M-D / corr L-3, token-history half: the cap counts
    /// DRAIN CANDIDATES only. A non-`.json` file and a directory named
    /// `*.json` (quarantined by the drain, never applied) must not consume
    /// cap headroom and refuse a real intent while the spool has room.
    ///
    /// RED (assertion) under the pre-fix `read_dir(...).filter(.json).count()`
    /// count: the directory's `.json` name makes the count reach the cap, so
    /// the enqueue below returns `false`.
    #[test]
    fn pending_intent_cap_counts_only_regular_json_files() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let spool = pending_history_dir(dir.path(), id);
        std::fs::create_dir_all(&spool).unwrap();
        for i in 0..PENDING_HISTORY_MAX_FILES - 1 {
            std::fs::write(spool.join(format!("{i:030}-0-0.json")), b"{}").unwrap();
        }
        std::fs::write(spool.join("junk.txt"), b"not an intent").unwrap();
        std::fs::write(spool.join("no-extension"), b"not an intent").unwrap();
        std::fs::create_dir(spool.join("directory-named-like-an-intent.json")).unwrap();
        assert_eq!(
            pending_intent_file_count(&spool),
            PENDING_HISTORY_MAX_FILES - 1,
            "test precondition: only regular `.json` files count toward the cap"
        );
        assert!(
            enqueue_pending_intent(
                dir.path(),
                id,
                PendingHistoryIntent::Append {
                    fingerprint: Fingerprint::of_refresh_token("rt-junk-headroom").to_hex(),
                    captured_at_unix_nanos: PENDING_HISTORY_MAX_FILES as u64 + 1,
                },
                "test",
            ),
            "junk that is not a drain candidate must NOT consume cap headroom and \
             refuse a real intent while the spool has room"
        );
    }

    /// R3 finding sec M-D / corr L-3, token-history half: a TRANSIENT read
    /// error must leave the intent in the spool for the next drain.
    /// Quarantine is terminal, so moving a valid intent there on a
    /// permission/interrupt/EMFILE blip is the silent fingerprint loss D237
    /// round-2 ruling C forbids.
    ///
    /// RED (both quarantine assertions) under the pre-fix `Err(_) =>
    /// quarantine`: the unreadable intent is moved into the quarantine
    /// directory and no longer exists in the spool.
    ///
    /// Non-vacuity: `pending_intent_non_utf8_is_quarantined` proves the
    /// quarantine path still fires for a DETERMINISTIC failure.
    #[cfg(unix)]
    #[test]
    fn pending_intent_transient_read_error_is_left_for_the_next_drain() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let spool = pending_history_dir(dir.path(), id);
        std::fs::create_dir_all(&spool).unwrap();
        let made = |fp: &str| {
            serde_json::to_vec(&PendingHistoryIntent::Append {
                fingerprint: Fingerprint::of_refresh_token(fp).to_hex(),
                captured_at_unix_nanos: 1,
            })
            .unwrap()
        };
        let unreadable = spool.join("000000000000000000000000000000-0-0.json");
        let valid = spool.join("000000000000000000000000000001-0-0.json");
        std::fs::write(&unreadable, made("rt-unreadable")).unwrap();
        std::fs::write(&valid, made("rt-readable")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(
            std::fs::read_to_string(&unreadable).is_err(),
            "running as a user that bypasses mode bits (root) — the transient \
             permission-denied arm is unreachable in this environment"
        );

        let drained = read_pending_intents(dir.path(), id);
        assert_eq!(
            drained.len(),
            1,
            "the readable intent behind the unreadable one must still drain"
        );
        assert_eq!(drained[0].0, valid);
        assert!(
            unreadable.exists(),
            "a transiently unreadable intent MUST stay in the spool for the next \
             drain — quarantine is terminal"
        );
        assert!(
            quarantined_history_files(dir.path(), id).is_empty(),
            "a transient read error MUST NOT quarantine the intent"
        );
    }

    /// Non-vacuity control for the transient-retry policy: a DETERMINISTIC
    /// read failure (bytes that are not UTF-8) is still quarantined, kept on
    /// disk, and never applied or deleted.
    #[test]
    fn pending_intent_non_utf8_is_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let spool = pending_history_dir(dir.path(), id);
        std::fs::create_dir_all(&spool).unwrap();
        let undecodable = spool.join("000000000000000000000000000000-0-0.json");
        std::fs::write(&undecodable, [0xff, 0xfe, 0x00]).unwrap();

        assert!(
            read_pending_intents(dir.path(), id).is_empty(),
            "undecodable bytes can never parse on a retry — nothing is applied"
        );
        assert!(
            !undecodable.exists(),
            "the deterministic failure is MOVED out of the drain window"
        );
        assert_eq!(
            quarantined_history_files(dir.path(), id).len(),
            1,
            "the deterministic failure must be quarantined (kept on disk), not deleted"
        );
    }

    #[test]
    fn append_skips_write_when_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let fp = Fingerprint::of_refresh_token("rt-same");
        append_history(dir.path(), id, fp);
        let path = token_history_path_for(dir.path(), id);
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        append_history(dir.path(), id, fp);
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "re-appending the same fingerprint must not rewrite the file"
        );
        assert_eq!(read_history(dir.path(), id), vec![fp]);
    }

    #[cfg(unix)]
    #[test]
    fn append_writes_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        append_history(dir.path(), id, Fingerprint::of_refresh_token("rt-perm"));
        let path = token_history_path_for(dir.path(), id);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "token-history MUST land at 0600 (security.md MUST Rule 5)"
        );
    }

    /// `keychain-fix-r10.md` S-N-2: this module no longer creates or secures
    /// the identity dir itself (see `ensure_identity_dir`'s doc) — that
    /// responsibility moved entirely to the canonical-write chokepoint
    /// (`credentials::file::save_uuid_credentials`, whose OWN
    /// `save_uuid_credentials_identity_dir_at_0o700` test covers the
    /// creation half). This test now covers what remains this module's job:
    /// given a dir the canonical writer already created and secured, append
    /// a history entry, and confirm this module neither writes anything
    /// (verified by the round-trip) nor loosens the permissions it found.
    #[cfg(unix)]
    #[test]
    fn append_writes_succeed_against_an_existing_0700_identity_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        let identity_dir = token_history_path_for(dir.path(), id)
            .parent()
            .unwrap()
            .to_path_buf();
        // Models what `save_uuid_credentials` already did before this
        // module is ever called.
        std::fs::create_dir_all(&identity_dir).unwrap();
        std::fs::set_permissions(&identity_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let fp = Fingerprint::of_refresh_token("rt-dir-perm");
        append_history(dir.path(), id, fp);

        assert_eq!(
            read_history(dir.path(), id),
            vec![fp],
            "append must succeed when the identity dir already exists"
        );
        let mode = std::fs::metadata(&identity_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "this module must not alter the identity dir's permissions"
        );
    }

    /// `keychain-fix-r10.md` S-N-2: `append_history`/`start_new_segment` must
    /// NOT resurrect an identity dir that does not exist — most notably one
    /// LOGOUT has already removed (`accounts::logout` does a bare
    /// `remove_dir_all` with no tombstone, so "never existed" and "removed
    /// by logout" are indistinguishable from the filesystem's own
    /// perspective; both must be handled identically: skip, never create).
    ///
    /// RED: reverting `ensure_identity_dir` to `std::fs::create_dir_all(&dir)`
    /// makes this assertion fail — the identity dir gets resurrected as an
    /// empty, credential-less ghost directory containing only a
    /// `token-history` file.
    #[test]
    fn append_does_not_resurrect_a_removed_identity_dir() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        let identity_dir = token_history_path_for(dir.path(), id)
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(!identity_dir.exists(), "test precondition");

        append_history(
            dir.path(),
            id,
            Fingerprint::of_refresh_token("rt-post-logout"),
        );

        assert!(
            !identity_dir.exists(),
            "append_history must NOT create the identity dir when it is absent"
        );
        assert_eq!(
            read_history(dir.path(), id),
            Vec::new(),
            "the write must have been skipped, not silently succeeded"
        );
    }

    /// `keychain-fix-r11.md` S-LOW-2: `write_history_file` itself — the
    /// shared atomic-write tail BOTH `append_history` and
    /// `start_new_segment` share, called AFTER `ensure_identity_dir`'s own
    /// check — must not resurrect the identity dir either, closing the
    /// residual TOCTOU window between that check and this write (the two
    /// steps do not share a lock with `csq logout`'s removal). Calls
    /// `write_history_file` DIRECTLY against an absent identity dir,
    /// bypassing `ensure_identity_dir` entirely, to prove the write tail's
    /// OWN behaviour rather than the gate's.
    ///
    /// RED: reverting this fix (restoring the `create_dir_all`/`secure_dir`
    /// block before the write) makes this assertion fail — the identity dir
    /// is resurrected as an empty ghost directory.
    #[test]
    fn write_history_file_does_not_create_dir_on_enoent() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        let identity_dir = token_history_path_for(dir.path(), id)
            .parent()
            .unwrap()
            .to_path_buf();
        assert!(!identity_dir.exists(), "test precondition");

        write_history_file(
            dir.path(),
            id,
            &[HistoryEntry::new(
                Fingerprint::of_refresh_token("rt-toctou"),
                1,
            )],
            "write_history_file_does_not_create_dir_on_enoent",
        );

        assert!(
            !identity_dir.exists(),
            "write_history_file must NOT create the identity dir on ENOENT — \
             a TOCTOU race with logout's removal must skip cleanly, not \
             resurrect an empty ghost directory"
        );
    }

    #[test]
    fn read_history_oversized_file_is_treated_as_empty() {
        // `keychain-fix-r9.md` D-F9/S-L-2: a file at/above
        // TOKEN_HISTORY_MAX_BYTES must never be read further — RED under a
        // mutation that removes the size check would instead attempt to
        // parse arbitrarily large content.
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        let path = token_history_path_for(dir.path(), id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let oversized = "x".repeat(TOKEN_HISTORY_MAX_BYTES as usize + 1);
        std::fs::write(&path, oversized).unwrap();
        assert!(
            read_history(dir.path(), id).is_empty(),
            "an oversized token-history file must be treated as empty, never read"
        );
    }

    /// `keychain-fix-r10.md` T-b: the oversized-file gate must reject on
    /// SIZE alone, before ever attempting to parse — proven with a
    /// genuinely VALID, PARSEABLE `HistoryFile` JSON (not garbage bytes like
    /// the sibling test above) padded past `TOKEN_HISTORY_MAX_BYTES` via a
    /// large `fingerprints` array. If the gate were instead "parse, then
    /// reject if too large" this fixture's valid content would still parse
    /// successfully, silently defeating the point of bounding the read.
    ///
    /// RED: reverting `read_bounded`'s `meta.len() > TOKEN_HISTORY_MAX_BYTES`
    /// check to a no-op makes this fixture parse and return non-empty
    /// history, since it IS valid JSON.
    #[test]
    fn read_history_valid_oversized_json_is_still_treated_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        let path = token_history_path_for(dir.path(), id);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // Enough hex-encoded fingerprints (64 hex chars each) to comfortably
        // exceed TOKEN_HISTORY_MAX_BYTES while staying valid, parseable JSON.
        let padded_fp = "ab".repeat(32);
        let entries: Vec<String> = std::iter::repeat_n(format!("\"{padded_fp}\""), 200).collect();
        let valid_oversized = format!("{{\"fingerprints\":[{}]}}", entries.join(","));
        assert!(
            valid_oversized.len() as u64 > TOKEN_HISTORY_MAX_BYTES,
            "test precondition: fixture must actually exceed the bound"
        );
        // Confirm it really is valid, parseable JSON matching HistoryFile's shape.
        serde_json::from_str::<HistoryFile>(&valid_oversized)
            .expect("fixture must be genuinely valid JSON for this test to mean anything");
        std::fs::write(&path, &valid_oversized).unwrap();
        assert!(
            read_history(dir.path(), id).is_empty(),
            "a VALID but oversized token-history file must still be treated as \
             empty — the size gate must reject before ever attempting to parse"
        );
    }

    #[test]
    fn start_new_segment_clears_prior_entries_and_keeps_only_current() {
        // `keychain-fix-r9.md` D-Q2: after `start_new_segment`, only the
        // CURRENT fingerprint is known — an OLDER, previously-recorded
        // fingerprint from a prior grant must no longer be present.
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let old_grant_fp = Fingerprint::of_refresh_token("rt-old-grant");
        let new_grant_fp = Fingerprint::of_refresh_token("rt-new-grant");
        append_history(dir.path(), id, old_grant_fp);
        assert_eq!(read_history(dir.path(), id), vec![old_grant_fp]);

        start_new_segment(dir.path(), id, new_grant_fp);

        assert_eq!(
            read_history(dir.path(), id),
            vec![new_grant_fp],
            "the old grant's fingerprint must be gone; only the new grant's remains"
        );
    }

    /// `keychain-fix-r10.md` S-L-4/C-B4: a concurrent `append_history` call
    /// landing between the caller computing `current` and `start_new_segment`
    /// acquiring the lock (modelled here by writing history directly to disk
    /// BEFORE calling `start_new_segment`, since both this test and the real
    /// race land their write before the lock is taken) must NOT be discarded.
    /// History already holds `[old, current, concurrently_appended]` — the
    /// concurrently-appended entry is genuinely AFTER `current` and must
    /// survive; only entries strictly BEFORE `current`'s last occurrence are
    /// the stale prior segment this call intends to clear.
    ///
    /// RED: reverting to the pre-fix blind `write_history_file(base, id,
    /// &[current], ..)` makes `read_history` come back `[current]` — the
    /// concurrently-appended entry is silently lost.
    #[test]
    fn start_new_segment_preserves_a_concurrently_appended_entry() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let old_fp = Fingerprint::of_refresh_token("rt-old-grant");
        let current_fp = Fingerprint::of_refresh_token("rt-current-grant");
        let concurrent_fp = Fingerprint::of_refresh_token("rt-concurrently-appended");

        // Models the on-disk state a racing `append_history(current_fp)`
        // followed by `append_history(concurrent_fp)` would have produced,
        // landing entirely before `start_new_segment`'s own lock acquisition.
        append_history(dir.path(), id, old_fp);
        append_history(dir.path(), id, current_fp);
        append_history(dir.path(), id, concurrent_fp);
        assert_eq!(
            read_history(dir.path(), id),
            vec![old_fp, current_fp, concurrent_fp]
        );

        start_new_segment(dir.path(), id, current_fp);

        assert_eq!(
            read_history(dir.path(), id),
            vec![current_fp, concurrent_fp],
            "the stale entry BEFORE current must be cleared, but the \
             concurrently-appended entry AFTER current must survive"
        );
    }

    #[test]
    fn history_file_never_contains_raw_token_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let raw_token = "sk-ant-ort01-super-secret-refresh-token-value";
        append_history(dir.path(), id, Fingerprint::of_refresh_token(raw_token));
        let path = token_history_path_for(dir.path(), id);
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains(raw_token),
            "token-history MUST NEVER contain the raw token — only its fingerprint"
        );
        assert!(
            !content.contains("sk-ant"),
            "token-history MUST NEVER contain a token prefix"
        );
    }

    #[test]
    fn fingerprint_from_credential_file_none_for_codex() {
        assert!(fingerprint_from_credential_file(&codex_file()).is_none());
    }

    #[test]
    fn fingerprint_from_credential_file_matches_raw_json_extraction() {
        let creds = anthropic_file("rt-parity");
        let from_struct = fingerprint_from_credential_file(&creds).unwrap();
        let raw = r#"{"claudeAiOauth":{"accessToken":"at","refreshToken":"rt-parity"}}"#;
        let from_json = fingerprint_from_raw_json(raw).unwrap();
        assert_eq!(from_struct, from_json);
    }

    #[test]
    fn record_write_appends_for_anthropic_and_noops_for_codex() {
        let dir = tempfile::tempdir().unwrap();
        let id = IdentityId::new_v4();
        plant_identity_dir(dir.path(), id);
        let creds = anthropic_file("rt-record");
        record_write(dir.path(), id, &creds);
        assert_eq!(read_history(dir.path(), id).len(), 1);

        record_write(dir.path(), id, &codex_file());
        assert_eq!(
            read_history(dir.path(), id).len(),
            1,
            "a Codex write must not append to the Anthropic-only history"
        );
    }
    /// Coordinator ca6022c7 item 3 + R1 M1 + review R2 L-R2-4: HISTORY
    /// MEMBERSHIP IS THE GATE, and this fixture can go RED. Alongside the
    /// slot's single binding it plants two UNBOUND identities that are NOT
    /// in the slot's history — one sharing the binding's email but a
    /// DIFFERENT org (the dropped same-email fallback's shape: re-adding
    /// that fallback admits it) and one tombstoned (an admit-everything
    /// reader admits it). With those planted, a first bind (generation 1,
    /// no displacement) must still admit NOTHING. The earlier shape planted
    /// only the current binding, which `bound.contains` excludes regardless
    /// of the gate — no perturbation could redden it (review R2 L-R2-4).
    /// Fixture drives the REAL writers
    /// ([`crate::accounts::profiles::add_identity_mapping`],
    /// [`crate::accounts::profiles::remove_slot_mapping`]), not a
    /// hand-written profiles.json (R1 M5). Read via `_locked`: the lock is
    /// held here, and the no-lock entry point deliberately narrows to empty
    /// under a held lock (review R2 L-R2-5).
    #[test]
    fn retired_bindings_empty_without_recorded_history() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let slot: crate::types::AccountNum = 9u16.try_into().unwrap();
        let first = IdentityId::new_v4();
        let same_email = IdentityId::new_v4();
        let tombstoned = IdentityId::new_v4();
        for (id, refresh) in [
            (first, "rt-first-bind"),
            (same_email, "rt-same-email-unbound"),
            (tombstoned, "rt-tombstoned-unbound"),
        ] {
            plant_identity_dir(base, id);
            std::fs::write(
                crate::accounts::identity_store::credentials_path_for(base, id),
                format!(
                    r#"{{"claudeAiOauth":{{"accessToken":"at","refreshToken":"{refresh}","expiresAt":4102444800000,"scopes":[]}}}}"#
                ),
            )
            .unwrap();
        }
        // `same_email`'s identity metadata: the binding's email, a
        // DIFFERENT organization (email is not account identity).
        let metadata = serde_json::to_vec(&serde_json::json!({
            "provider": "anthropic",
            "email": "a@example.com",
            "account_uuid": "11111111-1111-4111-8111-111111111111",
            "organization_uuid": "33333333-3333-4333-8333-333333333333"
        }))
        .unwrap();
        crate::platform::fs::write_new_private(
            &crate::accounts::identity_store::identity_json_path_for(base, same_email),
            &metadata,
        )
        .unwrap();

        let lock = ProfilesFileLock::acquire(base).unwrap();
        // The slot's only binding — generation 1, no displacement.
        crate::accounts::profiles::add_identity_mapping(&lock, base, 9, "a@example.com", first)
            .unwrap();
        // `same_email`: bound to slot 3, then UNBOUND — unbound,
        // non-removed, never in slot 9's history.
        crate::accounts::profiles::add_identity_mapping(
            &lock,
            base,
            3,
            "a@example.com",
            same_email,
        )
        .unwrap();
        crate::accounts::profiles::remove_slot_mapping(&lock, base, 3).unwrap();
        // `tombstoned`: bound to slot 4, logged out, then unbound.
        crate::accounts::profiles::add_identity_mapping(
            &lock,
            base,
            4,
            "t@example.com",
            tombstoned,
        )
        .unwrap();
        crate::accounts::identity_store::mark_identity_removed(base, tombstoned);
        crate::accounts::profiles::remove_slot_mapping(&lock, base, 4).unwrap();

        assert!(
            retired_bindings_for_slot_locked(&lock, base, slot).is_empty(),
            "a first bind (generation 1, no displacement) must admit NOTHING — not an unbound \
             same-email/different-org identity, not a tombstoned one"
        );
    }

    /// Coordinator ca6022c7 items 1–3 + R1 M3/M5, production-shaped: rebinds
    /// driven through the REAL writer record `slot_binding_history`, and the
    /// reader admits exactly the still-unbound, non-removed history members —
    /// canonical and own-history kept APART on [`RetiredBinding`]. Legs:
    /// A→D→B via `add_identity_mapping`; A is admitted with its canonical +
    /// appended history; D is in history but REMOVED (tombstone) and must be
    /// skipped (R1 L1); B (the current binding) never appears; an unrelated
    /// unbound identity that was never in this slot's history never appears.
    /// A's canonical enters through the production pair
    /// ([`crate::credentials::file::save`] + [`record_write`]), exactly as
    /// `save_uuid_credentials` writes it — never a bare fs::write (review R2
    /// §5a). The lock is HELD for the detail assertions, so they read via
    /// `_locked`; the no-lock entry point narrows to empty under the held
    /// lock and returns the same answer once it is released (review R2
    /// L-R2-5).
    #[test]
    fn retired_bindings_follow_the_production_rebind() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let slot: crate::types::AccountNum = 4u16.try_into().unwrap();

        let a_id = IdentityId::new_v4();
        let d_id = IdentityId::new_v4();
        let b_id = IdentityId::new_v4();
        let unrelated = IdentityId::new_v4();

        for (id, refresh) in [
            (d_id, "rt-d-removed"),
            (b_id, "rt-b-current"),
            (unrelated, "rt-never-bound"),
        ] {
            plant_identity_dir(base, id);
            std::fs::write(
                crate::accounts::identity_store::credentials_path_for(base, id),
                format!(
                    r#"{{"claudeAiOauth":{{"accessToken":"at","refreshToken":"{refresh}","expiresAt":4102444800000,"scopes":[]}}}}"#
                ),
            )
            .unwrap();
        }
        // A's canonical through the production writer pair.
        plant_identity_dir(base, a_id);
        let a_creds = anthropic_file("rt-a-canonical");
        crate::credentials::file::save(
            &crate::accounts::identity_store::credentials_path_for(base, a_id),
            &a_creds,
        )
        .unwrap();
        record_write(base, a_id, &a_creds);
        // A's OWN bounded history (an older token it once held); the
        // production write above is already its newest entry.
        let a_old_fp = Fingerprint::of_refresh_token("rt-a-old");
        append_history(base, a_id, a_old_fp);

        let lock = ProfilesFileLock::acquire(base).unwrap();
        // A→D→B: the real writer records each displacement.
        crate::accounts::profiles::add_identity_mapping(&lock, base, 4, "a@example.com", a_id)
            .unwrap();
        crate::accounts::profiles::add_identity_mapping(&lock, base, 4, "d@example.com", d_id)
            .unwrap();
        // D is logged out before the last rebind: tombstoned, and (per the
        // reader's contract) skipped even though it sits in the history.
        crate::accounts::identity_store::mark_identity_removed(base, d_id);
        crate::accounts::profiles::add_identity_mapping(&lock, base, 4, "b@example.com", b_id)
            .unwrap();

        // Review R2 L-R2-5: a HELD lock means a writer is mid-mutation —
        // the no-lock entry point must narrow to empty rather than admit
        // identities from a snapshot that writer is about to replace.
        assert!(
            crate::accounts::profiles_lock::on_other_thread(|| retired_bindings_for_slot(
                base, slot
            )
            .is_empty()),
            "a held profiles lock must narrow the lockless reader to empty"
        );

        let bindings = retired_bindings_for_slot_locked(&lock, base, slot);
        assert_eq!(
            bindings.len(),
            1,
            "exactly the one still-unbound, non-removed history member (A)"
        );
        let b = &bindings[0];
        assert_eq!(
            b.canonical,
            Some(Fingerprint::of_refresh_token("rt-a-canonical")),
            "the retired binding's canonical fingerprint is carried separately (strong half)"
        );
        assert_eq!(
            b.history,
            vec![Fingerprint::of_refresh_token("rt-a-canonical"), a_old_fp],
            "the retired binding's own bounded history is carried separately (weak half) — the \
             production canonical write appended its fingerprint, the older entry follows"
        );
        assert!(
            !bindings
                .iter()
                .any(|x| x.canonical == Some(Fingerprint::of_refresh_token("rt-b-current"))),
            "the CURRENT binding is never retired"
        );
        assert!(
            !bindings
                .iter()
                .any(|x| x.canonical == Some(Fingerprint::of_refresh_token("rt-never-bound"))),
            "an unbound identity never in this slot's history never appears"
        );

        // With the lock released, the no-lock entry point acquires it and
        // returns the same answer — the full path production callers take.
        drop(lock);
        let released = retired_bindings_for_slot(base, slot);
        assert_eq!(
            released.len(),
            1,
            "the no-lock reader acquires a free lock and admits A"
        );
        assert_eq!(
            released[0].canonical,
            Some(Fingerprint::of_refresh_token("rt-a-canonical"))
        );
    }

    /// Review R2 M-R2-1 (`csq move` lineage): the account's retired lineage
    /// travels WITH the account to its new slot, and the vacated slot keeps
    /// NONE of it. Production shape: FROM rebound X→A, moved to an EMPTY
    /// target (`swap_slot_mapping`, the only shape `csq move` allows —
    /// `TargetExists`), then TO rebound A→C. TO must admit A (the moved
    /// account's own canonical — its repointed terminals hold A's token)
    /// AND X (A's pre-move lineage — the measured slot-4 defect is exactly
    /// these terminals being refused); FROM must admit neither.
    #[test]
    fn retired_bindings_follow_the_account_through_a_move() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let from: crate::types::AccountNum = 2u16.try_into().unwrap();
        let to: crate::types::AccountNum = 5u16.try_into().unwrap();

        let x_id = IdentityId::new_v4();
        let a_id = IdentityId::new_v4();
        let c_id = IdentityId::new_v4();
        for (id, refresh) in [
            (x_id, "rt-x-first-tenant"),
            (a_id, "rt-a-moved"),
            (c_id, "rt-c-new-tenant"),
        ] {
            plant_identity_dir(base, id);
            std::fs::write(
                crate::accounts::identity_store::credentials_path_for(base, id),
                format!(
                    r#"{{"claudeAiOauth":{{"accessToken":"at","refreshToken":"{refresh}","expiresAt":4102444800000,"scopes":[]}}}}"#
                ),
            )
            .unwrap();
        }

        let lock = ProfilesFileLock::acquire(base).unwrap();
        // FROM: X first, then the rebind X→A (the real writer records X).
        crate::accounts::profiles::add_identity_mapping(&lock, base, 2, "x@example.com", x_id)
            .unwrap();
        crate::accounts::profiles::add_identity_mapping(&lock, base, 2, "a@example.com", a_id)
            .unwrap();
        // Move FROM→TO (target required empty).
        assert!(crate::accounts::profiles::swap_slot_mapping(&lock, base, 2, 5).unwrap());
        // TO: rebind A→C (A is now TO's own retired prior binding).
        crate::accounts::profiles::add_identity_mapping(&lock, base, 5, "c@example.com", c_id)
            .unwrap();

        let to_retired = retired_bindings_for_slot_locked(&lock, base, to);
        assert!(
            to_retired
                .iter()
                .any(|b| b.canonical == Some(Fingerprint::of_refresh_token("rt-a-moved"))),
            "TO admits A — the moved account's canonical, whose terminals moved with it"
        );
        assert!(
            to_retired
                .iter()
                .any(|b| b.canonical == Some(Fingerprint::of_refresh_token("rt-x-first-tenant"))),
            "TO admits X — A's pre-move lineage followed the repointed terminals, \
             not the slot number"
        );
        assert!(
            retired_bindings_for_slot_locked(&lock, base, from).is_empty(),
            "the vacated slot keeps NO lineage (review R2 M-R2-1: cross-slot breadth)"
        );
    }

    /// Review R3 M1 (reader level): a STALE history entry left on an
    /// unbound slot (logout by a pre-fix binary, rollback unbind) must
    /// never be admitted. Legs: (a) an entry sitting on the empty move
    /// TARGET is DROPPED by the move; (b) a stale entry planted on the
    /// vacated FROM after the move is cleared by FROM's first bind — the
    /// rebound FROM admits NOTHING.
    #[test]
    fn stale_history_on_an_unbound_slot_never_reaches_a_rebound_from() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let from: crate::types::AccountNum = 2u16.try_into().unwrap();
        let to: crate::types::AccountNum = 5u16.try_into().unwrap();

        let x_id = IdentityId::new_v4();
        let a_id = IdentityId::new_v4();
        let c_id = IdentityId::new_v4();
        let stale_id = IdentityId::new_v4();
        for (id, refresh) in [
            (x_id, "rt-x-lineage"),
            (a_id, "rt-a-tenant"),
            (c_id, "rt-c-newcomer"),
            (stale_id, "rt-stale-leftover"),
        ] {
            plant_identity_dir(base, id);
            std::fs::write(
                crate::accounts::identity_store::credentials_path_for(base, id),
                format!(
                    r#"{{"claudeAiOauth":{{"accessToken":"at","refreshToken":"{refresh}","expiresAt":4102444800000,"scopes":[]}}}}"#
                ),
            )
            .unwrap();
        }

        let lock = ProfilesFileLock::acquire(base).unwrap();
        // FROM: X first, then the rebind X→A (the real writer records X).
        crate::accounts::profiles::add_identity_mapping(&lock, base, 2, "x@example.com", x_id)
            .unwrap();
        crate::accounts::profiles::add_identity_mapping(&lock, base, 2, "a@example.com", a_id)
            .unwrap();
        // Plant a STALE entry on the UNBOUND TO — the pre-fix-unbind shape.
        let ppath = crate::accounts::profiles::profiles_path(base);
        let mut pf = crate::accounts::profiles::load(&ppath).unwrap();
        pf.slot_binding_history.insert("5".into(), vec![stale_id]);
        crate::accounts::profiles::save(&ppath, &pf).unwrap();
        // Move FROM→TO (target required empty); the move must DROP the
        // stale entry rather than carry it to FROM.
        assert!(crate::accounts::profiles::swap_slot_mapping(&lock, base, 2, 5).unwrap());
        // Plant a stale entry on the now-UNBOUND FROM (a rollback / pre-fix
        // logout after the move), then first-bind C there.
        let mut pf = crate::accounts::profiles::load(&ppath).unwrap();
        pf.slot_binding_history.insert("2".into(), vec![stale_id]);
        crate::accounts::profiles::save(&ppath, &pf).unwrap();
        crate::accounts::profiles::add_identity_mapping(&lock, base, 2, "c@example.com", c_id)
            .unwrap();

        let from_retired = retired_bindings_for_slot_locked(&lock, base, from);
        assert!(
            from_retired.is_empty(),
            "FROM admits NOTHING once rebound — the stale entry was dropped and \
             the first bind cleared the rest (review R3 M1)"
        );
        let to_retired = retired_bindings_for_slot_locked(&lock, base, to);
        assert!(
            to_retired
                .iter()
                .any(|b| b.canonical == Some(Fingerprint::of_refresh_token("rt-x-lineage"))),
            "TO admits X — A's pre-move lineage followed the repointed terminals, \
             not the slot number"
        );
        assert!(
            !to_retired
                .iter()
                .any(|b| b.canonical == Some(Fingerprint::of_refresh_token("rt-stale-leftover"))),
            "the stale entry never travels to TO (review R3 M1)"
        );
    }

    #[test]
    fn r2_buffer_fingerprint_guard_preserves_digest_and_none_semantics() {
        for (json, expected) in [
            (
                r#"{"claudeAiOauth":{"accessToken":"fake-access","refreshToken":"fake-refresh"},"siblings":{"token":"fake-sibling"}}"#,
                "fake-refresh",
            ),
            (
                r#"{"claudeAiOauth":{"refreshToken":"fake-old","other":"fake-metadata","refreshToken":"fake-last"}}"#,
                "fake-last",
            ),
            (
                r#"{"claudeAiOauth":{"refreshToken":"fake\u002d雪"}}"#,
                "fake-雪",
            ),
        ] {
            assert_eq!(
                fingerprint_from_raw_json(json),
                Some(Fingerprint::of_refresh_token(expected))
            );
        }
        for json in [
            r#"{"claudeAiOauth":{"refreshToken":""}}"#,
            r#"{"claudeAiOauth":{"refreshToken":false}}"#,
            r#"{"claudeAiOauth":{"accessToken":"fake-access"}}"#,
            r#"{"claudeAiOauth":{"refreshToken":"fake-prefix"},"bad":["fake-sibling",]}"#,
            r#"{"claudeAiOauth":{"refreshToken":"fake-prefix"},"bad":{"fake-key":}}"#,
            r#"["fake-array"]"#,
            "not-json",
        ] {
            assert!(fingerprint_from_raw_json(json).is_none());
        }
    }
    fn org_identity_proof_fixture(
        base: &Path,
    ) -> (ai::CapturedBinding, ai::VerifiedAnthropicContext) {
        let id = IdentityId::new_v4();
        let slot = crate::types::AccountNum::try_from(1u16).unwrap();
        let context = ai::AnthropicContext::new(
            "fixture@example.test",
            uuid::Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            uuid::Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        )
        .unwrap();
        let mut profiles = crate::accounts::profiles::ProfilesFile::empty();
        profiles.by_slot.insert("1".into(), id);
        profiles.anthropic_contexts.push(ai::AnthropicContextEntry {
            email: context.email().into(),
            account_uuid: context.account_uuid(),
            organization_uuid: context.organization_uuid(),
            identity_uuid: id,
            extra: Default::default(),
        });
        crate::accounts::profiles::save(&crate::accounts::profiles::profiles_path(base), &profiles)
            .unwrap();
        plant_identity_dir(base, id);
        let metadata = serde_json::to_vec(&serde_json::json!({
            "provider":"anthropic", "email":context.email(),
            "account_uuid":context.account_uuid(), "organization_uuid":context.organization_uuid()
        }))
        .unwrap();
        crate::platform::fs::write_new_private(
            &crate::accounts::identity_store::identity_json_path_for(base, id),
            &metadata,
        )
        .unwrap();
        let mut creds = anthropic_file("fake-org-refresh");
        // Exact-grant owner proof requires a nonzero expiry; the generic
        // fingerprint-only fixture intentionally uses zero elsewhere.
        match &mut creds {
            CredentialFile::Anthropic(anthropic) => {
                anthropic.claude_ai_oauth.expires_at = 4_102_444_800_000;
            }
            _ => unreachable!("owner proof fixture must be Anthropic"),
        }
        crate::credentials::file::save(
            &crate::accounts::identity_store::credentials_path_for(base, id),
            &creds,
        )
        .unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "account":{"email":context.email(),"uuid":context.account_uuid()},
            "organization":{"uuid":context.organization_uuid()}
        }))
        .unwrap();
        let http: crate::daemon::usage_poller::HttpGetFn =
            std::sync::Arc::new(move |url, token, _| {
                assert_eq!(url, "https://api.anthropic.com/api/oauth/profile");
                assert_eq!(token, "at", "profile must verify the exact fixture grant");
                Ok((200, body.clone()))
            });
        let proof = ai::verify_anthropic_context_with(creds.expect_anthropic(), &http).unwrap();
        (ai::capture_anthropic_binding(base, slot).unwrap(), proof)
    }

    #[test]
    fn owner_proof_org_identity_regression_legacy_ignored_and_known_proof_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, proof) = org_identity_proof_fixture(dir.path());
        record_owner_verified(dir.path(), binding.identity(), proof.fingerprint());
        let legacy = owner_verified_path_for(dir.path(), binding.identity());
        let before = std::fs::read(&legacy).unwrap();
        assert!(read_owner_verified_for_slot(dir.path(), binding.slot()).is_empty());
        assert!(matches!(
            record_owner_verified_v2(dir.path(), &binding, &proof),
            OwnerVerifiedRecord::Written
        ));
        assert_eq!(
            read_owner_verified_for_slot(dir.path(), binding.slot()),
            vec![proof.fingerprint()]
        );
        assert_eq!(std::fs::read(legacy).unwrap(), before);
        let bytes =
            std::fs::read(owner_verified_v2_path_for(dir.path(), binding.identity())).unwrap();
        assert!(!String::from_utf8(bytes)
            .unwrap()
            .contains("fake-org-refresh"));
    }

    #[test]
    fn owner_proof_org_identity_regression_incompatible_envelopes_are_preserved() {
        for incompatible in [b"not-json".as_slice(), br#"{"version":3}"#.as_slice()] {
            let dir = tempfile::tempdir().unwrap();
            let (binding, proof) = org_identity_proof_fixture(dir.path());
            let path = owner_verified_v2_path_for(dir.path(), binding.identity());
            crate::platform::fs::write_new_private(&path, incompatible).unwrap();
            assert!(read_owner_verified_for_slot(dir.path(), binding.slot()).is_empty());
            assert!(matches!(
                record_owner_verified_v2(dir.path(), &binding, &proof),
                OwnerVerifiedRecord::Failed
            ));
            assert_eq!(std::fs::read(path).unwrap(), incompatible);
        }
    }

    #[test]
    fn owner_proof_org_identity_regression_rebind_refuses_without_creating_proof() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, proof) = org_identity_proof_fixture(dir.path());
        let path = crate::accounts::profiles::profiles_path(dir.path());
        let mut profiles = crate::accounts::profiles::load(&path).unwrap();
        profiles.by_slot.insert("1".into(), IdentityId::new_v4());
        crate::accounts::profiles::save(&path, &profiles).unwrap();
        assert!(matches!(
            record_owner_verified_v2(dir.path(), &binding, &proof),
            OwnerVerifiedRecord::Rebound
        ));
        assert!(!owner_verified_v2_path_for(dir.path(), binding.identity()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn owner_proof_org_identity_regression_symlink_refuses_without_touching_target() {
        let dir = tempfile::tempdir().unwrap();
        let (binding, proof) = org_identity_proof_fixture(dir.path());
        let target = dir.path().join("unrelated.json");
        crate::platform::fs::write_new_private(&target, b"preserve").unwrap();
        let path = owner_verified_v2_path_for(dir.path(), binding.identity());
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read_owner_verified_for_slot(dir.path(), binding.slot()).is_empty());
        assert!(matches!(
            record_owner_verified_v2(dir.path(), &binding, &proof),
            OwnerVerifiedRecord::Failed
        ));
        assert_eq!(std::fs::read(target).unwrap(), b"preserve");
        assert!(path.symlink_metadata().unwrap().file_type().is_symlink());
    }
}
