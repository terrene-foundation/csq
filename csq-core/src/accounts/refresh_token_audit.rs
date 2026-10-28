//! Duplicate-refresh-token audit (orgident r4 F5/L3).
//!
//! Two bound identities must never hold ONE refresh-token grant: each identity's
//! refresher would rotate the shared token and strand the other, and Anthropic's reuse
//! detection may revoke the whole token family. Current code cannot mint such a pair,
//! but an earlier release may have left one on a user's disk, and the new refusals never
//! rewrite an existing saved credential. This module finds those pairs, warns, and
//! suppresses refresh for every holder but one until `csq login` re-binds the slot.
//!
//! # Contract
//!
//! * [`audit`] is a pure read. It compares the canonical Anthropic credential of every
//!   bound identity pairwise, in constant time (`tokens_match`). Tokens are never put
//!   in a map, a set, a log line or an output string; a group of identities is tracked by
//!   index only.
//! * Holder choice: the LOWEST slot number in the colliding group keeps refreshing. It is
//!   deterministic and stable across daemon restarts. "Most recently written" was rejected
//!   because the holder's own refresher rewrites its canonical, so the choice would flip
//!   on every rotation.
//! * Fail closed on the audit's own failures: a canonical that exists but cannot be read
//!   makes its slots [`SlotState::Undetermined`]. Undetermined neither suppresses nor
//!   un-suppresses: an existing suppression for that slot is kept as it was.
//! * Suppression is persisted in `<base>/refresh-suppressed.json` (version 2:
//!   `{slot: {holder, identity_uuid}}`, slot numbers and identity ids only, no credential
//!   bytes) so the daemon's refresher, `csq doctor`, the desktop and a launch gate read one
//!   fact. Every successful write ALSO writes `refresh-suppressed.last-good.json` first.
//! * IDENTITY-ANCHORED: an entry for identity I counts for whichever canonical slot currently
//!   binds I. The slot key in the file is display only. The refresh check runs where the token
//!   is presented (`refresh::check::broker_check`, by the captured binding's identity), so a
//!   `csq move` between a tick's snapshot and the refresh cannot carry I past the brake.
//! * A suppression is released ONLY by (i) that slot's own login ([`clear_on_login`], inside
//!   the login's profiles lock via [`clear_on_login_locked`]) or (ii) its identity being
//!   unbound from every canonical slot. Tokens becoming unequal NEVER release it: the
//!   holder's own refresher rotates the shared token, so "the pair no longer collides" is
//!   exactly the state a holder refresh produces, and the suppressed slot still holds the
//!   stale grant. A later audit therefore only ADDS entries.
//! * `csq move` re-keys the display keys under the profiles lock ([`rekey_on_move`]); a
//!   failure of that write changes no decision.
//! * The state file is read through the guarded reader (no-follow, regular file, owner, no
//!   group/other write, size cap; a FIFO never blocks). A damaged, refused, deleted or v1
//!   primary is never trusted as "suppress nothing": the answer is the union of the
//!   last-good copy (v1 entries carried forward, bound to the slot's current identity) and a
//!   live in-process [`audit`]. `apply` NEVER overwrites a damaged primary: it returns Err and
//!   `csq doctor` says to repair or remove it.
//! * The startup audit runs INSIDE the profiles lock. If its persist fails, the report is kept
//!   in memory and unioned into every lookup until [`persist_pending`] succeeds.
//! * Warnings are throttled per slot and per window, never per tick.

use crate::accounts::anthropic_identity::{self as ai, SlotKey};
use crate::accounts::identity_store::{self, IdentityId};
use crate::accounts::profiles::ProfilesFile;
use crate::accounts::profiles_lock::ProfilesFileLock;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Fixed-vocabulary tag shown on the status surfaces (`last_refresh_error`).
pub const SUPPRESSED_TAG: &str = "refresh_suppressed_duplicate_grant";

const STATE_FILE: &str = "refresh-suppressed.json";
/// Written before the primary on every successful write; read through the same guarded reader.
const LAST_GOOD_FILE: &str = "refresh-suppressed.last-good.json";
const STATE_MAX_BYTES: u64 = 64 * 1024;
/// Current state-file version. Version 1 keyed entries by slot number alone.
const STATE_VERSION: u32 = 2;
/// One warning per (accounts root, kind, slot) per window.
const WARN_WINDOW: Duration = Duration::from_secs(600);
const WARN_CAP: usize = 512;

/// Test instrumentation: how many suppression lookups and live-audit fallbacks ran per
/// accounts root, so a surface can prove it checks once per call, not once per row.
#[cfg(any(test, feature = "test-utils"))]
static LOOKUP_COUNTS: Mutex<BTreeMap<(PathBuf, &'static str), usize>> = Mutex::new(BTreeMap::new());

#[cfg(any(test, feature = "test-utils"))]
fn count_lookup(base: &Path, kind: &'static str) {
    let mut map = LOOKUP_COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    *map.entry((base.to_path_buf(), kind)).or_insert(0) += 1;
}

/// Number of `suppressed_slots` calls (`"lookup"`) or live-audit fallbacks (`"live"`) so far
/// for `base`.
#[cfg(any(test, feature = "test-utils"))]
pub fn lookup_count_for_test(base: &Path, kind: &'static str) -> usize {
    let map = LOOKUP_COUNTS.lock().unwrap_or_else(|e| e.into_inner());
    map.get(&(base.to_path_buf(), kind)).copied().unwrap_or(0)
}

type ThrottleKey = (PathBuf, &'static str, u16);
static THROTTLE: Mutex<BTreeMap<ThrottleKey, Instant>> = Mutex::new(BTreeMap::new());

/// True when a warning of `kind` for `slot` may be emitted now; records it. Entries older
/// than the window are dropped and the map is capped, evicting the oldest.
fn throttle_allows(base: &Path, kind: &'static str, slot: u16, now: Instant) -> bool {
    let mut map = THROTTLE.lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, at| now.saturating_duration_since(*at) < WARN_WINDOW);
    let key = (base.to_path_buf(), kind, slot);
    if map.contains_key(&key) {
        return false;
    }
    if map.len() >= WARN_CAP {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
    }
    map.insert(key, now);
    true
}

/// The refresher's suppression warning: once per slot per window, not once per tick.
pub fn warn_suppressed_throttled(base: &Path, slot: u16, holder: u16) {
    if throttle_allows(base, "suppressed", slot, Instant::now()) {
        tracing::warn!(
            account = slot,
            holder_slot = holder,
            error_kind = "refresh_suppressed_duplicate_grant",
            "refresh suppressed: this slot shares a refresh grant with another slot; \
             run `csq login` for it"
        );
    }
}

/// Per-slot audit verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotState {
    /// No other identity shares this slot's refresh token.
    Clear,
    /// Shares a grant with `others`; this slot keeps refreshing (lowest slot).
    Holder { others: Vec<u16> },
    /// Shares a grant with `holder`, which keeps refreshing; this slot does not.
    Suppressed { holder: u16 },
    /// Its canonical credential could not be read; nothing is known.
    Undetermined,
}

/// Result of one audit pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReport {
    pub slots: BTreeMap<u16, SlotState>,
    /// The identity each examined slot was bound to when the audit read `profiles.json`.
    /// `apply` drops a verdict whose binding changed since.
    pub bound: BTreeMap<u16, IdentityId>,
    /// `profiles.json` itself could not be read, so no slot was examined.
    pub profiles_unreadable: bool,
}

/// Compare two token byte strings in constant time. Every position up to the longer
/// length is visited exactly once, and the length difference is folded into the verdict
/// rather than short-circuiting. `visited` exists so a test can observe that the walk
/// never stops at the first mismatching byte.
fn tokens_match(a: &[u8], b: &[u8], visited: &mut usize) -> bool {
    let n = a.len().max(b.len());
    let mut acc = subtle::Choice::from(u8::from(a.len() == b.len()));
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        acc &= x.ct_eq(&y);
        *visited += 1;
    }
    bool::from(acc)
}

struct Held {
    slots: Vec<u16>,
    /// `None` when the canonical is unreadable.
    refresh: Option<zeroize::Zeroizing<Vec<u8>>>,
}

/// Read every bound identity's canonical credential and classify each slot.
pub fn audit(base: &Path) -> AuditReport {
    let pf = match ai::read_profiles_snapshot(base) {
        Ok(pf) => pf,
        Err(_) => {
            if throttle_allows(base, "profiles", 0, Instant::now()) {
                tracing::warn!(
                    error_kind = "refresh_audit_profiles_unreadable",
                    "duplicate-grant audit could not read profiles.json; no slot examined"
                );
            }
            return AuditReport {
                slots: BTreeMap::new(),
                bound: BTreeMap::new(),
                profiles_unreadable: true,
            };
        }
    };
    let mut report = AuditReport::default();
    // identity -> its slots (validated through AccountNum, never raw u16 to a path).
    let mut by_identity: BTreeMap<String, (IdentityId, Vec<u16>)> = BTreeMap::new();
    for (slot, identity) in &pf.by_slot {
        // Canonical keys only: "01" is not the key the writers mint and must not collapse
        // onto slot 1.
        let Some(slot) = SlotKey::from_key(slot).account() else {
            continue;
        };
        report.bound.insert(slot.get(), *identity);
        by_identity
            .entry(identity.to_canonical_string())
            .or_insert_with(|| (*identity, Vec::new()))
            .1
            .push(slot.get());
    }
    let mut held: Vec<Held> = Vec::new();
    for (_, (identity, mut slots)) in by_identity {
        slots.sort_unstable();
        let path = identity_store::credentials_path_for(base, identity);
        match std::fs::symlink_metadata(&path) {
            // No canonical: nothing to refresh, nothing to share.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                for s in slots {
                    report.slots.insert(s, SlotState::Clear);
                }
                continue;
            }
            Err(_) => {
                warn_unreadable(base, &slots);
                held.push(Held {
                    slots,
                    refresh: None,
                });
                continue;
            }
            Ok(_) => (),
        }
        match ai::load_anthropic_canonical(&path) {
            Ok(file) => match file.anthropic() {
                Some(a) => held.push(Held {
                    slots,
                    refresh: Some(zeroize::Zeroizing::new(
                        a.claude_ai_oauth
                            .refresh_token
                            .expose_secret()
                            .as_bytes()
                            .to_vec(),
                    )),
                }),
                // Not an Anthropic canonical: no Anthropic grant to share.
                None => {
                    for s in slots {
                        report.slots.insert(s, SlotState::Clear);
                    }
                }
            },
            Err(_) => {
                warn_unreadable(base, &slots);
                held.push(Held {
                    slots,
                    refresh: None,
                });
            }
        }
    }
    // Union-find over identity indices. Pairwise constant-time compare, no keyed map.
    let n = held.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    for i in 0..n {
        for j in (i + 1)..n {
            if let (Some(a), Some(b)) = (&held[i].refresh, &held[j].refresh) {
                let mut visited = 0usize;
                if tokens_match(a, b, &mut visited) {
                    let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                    parent[ri.max(rj)] = ri.min(rj);
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }
    for members in groups.values() {
        if members.len() == 1 {
            let h = &held[members[0]];
            let state = if h.refresh.is_some() {
                SlotState::Clear
            } else {
                SlotState::Undetermined
            };
            for s in &h.slots {
                report.slots.insert(*s, state.clone());
            }
            continue;
        }
        let all: Vec<u16> = {
            let mut v: Vec<u16> = members
                .iter()
                .flat_map(|&m| held[m].slots.iter().copied())
                .collect();
            v.sort_unstable();
            v
        };
        let holder = all[0];
        for &m in members {
            for s in &held[m].slots {
                let state = if held[m].slots.contains(&holder) {
                    SlotState::Holder {
                        others: all.iter().copied().filter(|o| o != s).collect(),
                    }
                } else {
                    SlotState::Suppressed { holder }
                };
                report.slots.insert(*s, state);
            }
        }
    }
    report
}

fn warn_unreadable(base: &Path, slots: &[u16]) {
    for slot in slots {
        if throttle_allows(base, "canonical", *slot, Instant::now()) {
            tracing::warn!(
                slot,
                error_kind = "refresh_audit_canonical_unreadable",
                "duplicate-grant audit could not read this slot's saved credential; \
                 status UNDETERMINED, suppression unchanged"
            );
        }
    }
}

// ── persisted suppression ──────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq, Clone)]
struct Entry {
    /// The slot that keeps refreshing the shared grant (display only).
    holder: u16,
    /// The identity that was suppressed. THIS is the anchor: the entry counts for whichever
    /// canonical slot currently binds it.
    identity_uuid: IdentityId,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct StateFile {
    version: u32,
    /// Canonical slot key (the slot that bound the identity when it was written; display
    /// only, never consulted for a decision) -> entry.
    suppressed: BTreeMap<String, Entry>,
}

impl StateFile {
    fn new() -> Self {
        StateFile {
            version: STATE_VERSION,
            suppressed: BTreeMap::new(),
        }
    }
}

/// What the guarded reader found.
enum StateRead {
    /// No file: nothing persisted.
    Absent,
    Current(StateFile),
    /// The old slot-keyed format. Its entries are carried forward, bound to the slot's
    /// current identity.
    V1(BTreeMap<u16, u16>),
    /// Refused (symlink, FIFO, not regular, foreign owner, group/other-writable, too big)
    /// or not parseable.
    Unreadable,
}

fn state_path(base: &Path) -> PathBuf {
    base.join(STATE_FILE)
}

fn last_good_path(base: &Path) -> PathBuf {
    base.join(LAST_GOOD_FILE)
}

fn read_state_at(path: &Path) -> StateRead {
    let bytes =
        match crate::platform::fs::read_private_regular_nofollow_bounded(path, STATE_MAX_BYTES) {
            Ok(None) => return StateRead::Absent,
            Ok(Some(bytes)) => bytes,
            Err(_) => return StateRead::Unreadable,
        };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return StateRead::Unreadable;
    };
    match value.get("version").and_then(serde_json::Value::as_u64) {
        Some(2) => serde_json::from_value::<StateFile>(value)
            .map(StateRead::Current)
            .unwrap_or(StateRead::Unreadable),
        Some(1) => {
            let Some(map) = value.get("suppressed").and_then(|m| m.as_object()) else {
                return StateRead::Unreadable;
            };
            let mut old = BTreeMap::new();
            for (key, holder) in map {
                let (Ok(slot), Some(holder)) = (
                    key.parse::<u16>(),
                    holder.as_u64().and_then(|h| u16::try_from(h).ok()),
                ) else {
                    return StateRead::Unreadable;
                };
                old.insert(slot, holder);
            }
            StateRead::V1(old)
        }
        _ => StateRead::Unreadable,
    }
}

fn read_state(base: &Path) -> StateRead {
    read_state_at(&state_path(base))
}

/// Test instrumentation: accounts roots whose state writes must fail (see
/// [`fail_state_writes_for_test`]).
#[cfg(any(test, feature = "test-utils"))]
static FAIL_STATE_WRITES: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Make every state write under `base` fail (`on`) or work again (`!on`).
#[cfg(any(test, feature = "test-utils"))]
pub fn fail_state_writes_for_test(base: &Path, on: bool) {
    let mut roots = FAIL_STATE_WRITES.lock().unwrap_or_else(|e| e.into_inner());
    roots.retain(|r| r != base);
    if on {
        roots.push(base.to_path_buf());
    }
}

#[cfg(any(test, feature = "test-utils"))]
fn state_writes_fail(base: &Path) -> bool {
    FAIL_STATE_WRITES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|r| r == base)
}

/// tmp -> `secure_file` -> `atomic_replace`, removing the tmp file on every failure branch
/// (security.md §4, §5, §5a).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ()> {
    let tmp = crate::platform::fs::unique_tmp_path(path);
    if std::fs::write(&tmp, bytes).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(());
    }
    if crate::platform::fs::secure_file(&tmp).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(());
    }
    if crate::platform::fs::atomic_replace(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(());
    }
    Ok(())
}

/// Write the last-good copy first, then the primary; a failure of either is an error. The
/// copy is read through the same guarded reader and is what survives a damaged primary.
///
/// The re-verified marks are removed BEFORE anything is written. If the removal fails this
/// returns Err and nothing else is touched, so a primary that was damaged stays damaged and
/// its marks stay valid for that same episode: a failed clear can never turn into an open
/// gate. (The marks also carry the episode fingerprint, so they are void for any other
/// state of the record even if this removal were skipped.)
fn write_state(base: &Path, state: &StateFile) -> Result<(), ()> {
    #[cfg(any(test, feature = "test-utils"))]
    if state_writes_fail(base) {
        return Err(());
    }
    clear_reverified(base)?;
    let path = state_path(base);
    let good = last_good_path(base);
    if state.suppressed.is_empty()
        && std::fs::symlink_metadata(&path).is_err()
        && std::fs::symlink_metadata(&good).is_err()
    {
        // Nothing to persist and no record on disk: the state is determined (empty).
        return Ok(());
    }
    let bytes = serde_json::to_vec(state).map_err(|_| ())?;
    write_atomic(&good, &bytes)?;
    write_atomic(&path, &bytes)?;
    Ok(())
}

const REVERIFIED: &str = "refresh-suppression-reverified.json";
const REVERIFIED_VERSION: u32 = 2;

fn reverified_path(base: &Path) -> PathBuf {
    base.join(REVERIFIED)
}

/// The slots' logins recorded while the suppression record was unknown, bound to the damage
/// EPISODE they were made in.
#[derive(serde::Serialize, serde::Deserialize)]
struct Reverified {
    version: u32,
    /// [`episode_fingerprint`] at the time of the first mark of this episode. A mark counts
    /// only while the record's current fingerprint is equal.
    episode: String,
    /// Identity uuids whose slot completed a `csq login` inside that episode.
    identities: Vec<String>,
}

/// Fingerprint of one record file WITHOUT following a symlink and without ever blocking: `None`
/// when it cannot be established (the caller then fails closed). Distinct for an absent file,
/// a symlink (with its target), any other non-regular file, and a regular file (device, inode,
/// size, modification and change time to the nanosecond, and a SHA-256 of its bytes up to the
/// size cap). A file that is deleted and written again, replaced, repaired or damaged anew
/// has a different fingerprint even when its bytes are identical, unless the same inode is
/// reused within the filesystem's timestamp granularity.
fn file_fingerprint(path: &Path) -> Option<String> {
    use std::io::Read;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some("absent".to_string()),
        Err(_) => return None,
    };
    let kind = meta.file_type();
    #[cfg(unix)]
    let stamp = {
        use std::os::unix::fs::MetadataExt;
        format!(
            "{}:{}:{}:{}.{}:{}.{}",
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec()
        )
    };
    #[cfg(not(unix))]
    let stamp = {
        let nanos = |t: std::io::Result<std::time::SystemTime>| {
            t.ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos())
        };
        format!(
            "{}:{}:{}",
            meta.len(),
            nanos(meta.modified()),
            nanos(meta.created())
        )
    };
    if kind.is_symlink() {
        let target = std::fs::read_link(path).ok()?;
        return Some(format!("symlink:{stamp}:{}", target.display()));
    }
    if !kind.is_file() {
        return Some(format!("other:{stamp}"));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let bytes = match opts.open(path) {
        Ok(file)
            if file
                .metadata()
                .map(|m| m.file_type().is_file())
                .unwrap_or(false) =>
        {
            let mut buf = Vec::new();
            file.take(STATE_MAX_BYTES + 1).read_to_end(&mut buf).ok()?;
            Some(buf)
        }
        // Refused to open (permissions) or swapped for a non-file: the metadata stamp alone
        // still tells episodes apart.
        _ => None,
    };
    Some(regular_file_fingerprint(&stamp, bytes.as_deref()))
}

/// The fingerprint of a regular file from its metadata `stamp` and its content (`None` when
/// the content could not be read). Pure: no I/O, so a test can hold the metadata equal and
/// vary only the bytes.
fn regular_file_fingerprint(stamp: &str, bytes: Option<&[u8]>) -> String {
    use sha2::{Digest, Sha256};
    let digest = match bytes {
        Some(bytes) => Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        None => "unread".to_string(),
    };
    format!("file:{stamp}:{digest}")
}

/// What the record looks like right now: the primary and the last-good copy. Two marks
/// belong to the same damage episode only when this string is equal. `None` when either
/// file cannot be fingerprinted (fail closed).
fn episode_fingerprint(base: &Path) -> Option<String> {
    Some(format!(
        "primary={};last_good={}",
        file_fingerprint(&state_path(base))?,
        file_fingerprint(&last_good_path(base))?
    ))
}

/// The marks, through the guarded reader. Any read problem (symlink, FIFO, foreign owner,
/// group/other-writable, too big, unparseable, another version) yields `None`, which keeps a
/// launch gate refusing (fail closed).
fn read_reverified(base: &Path) -> Option<Reverified> {
    let bytes = crate::platform::fs::read_private_regular_nofollow_bounded(
        &reverified_path(base),
        STATE_MAX_BYTES,
    )
    .ok()??;
    let marks = serde_json::from_slice::<Reverified>(&bytes).ok()?;
    (marks.version == REVERIFIED_VERSION).then_some(marks)
}

/// Record that `identity`'s slot logged in during the damage episode `episode` (the
/// fingerprint the caller took BEFORE it judged the record unknown). Marks of any other
/// episode are discarded, never extended.
fn mark_reverified(base: &Path, identity: IdentityId, episode: &str) -> Result<(), ()> {
    let mut identities = match read_reverified(base) {
        Some(marks) if marks.episode == episode => marks.identities,
        _ => Vec::new(),
    };
    let id = identity.as_uuid().to_string();
    if !identities.contains(&id) {
        identities.push(id);
    }
    let marks = Reverified {
        version: REVERIFIED_VERSION,
        episode: episode.to_string(),
        identities,
    };
    let bytes = serde_json::to_vec(&marks).map_err(|_| ())?;
    write_atomic(&reverified_path(base), &bytes)
}

/// Test instrumentation: accounts roots whose re-verified-marks removal must fail (see
/// [`fail_reverified_clear_for_test`]).
#[cfg(any(test, feature = "test-utils"))]
static FAIL_REVERIFIED_CLEAR: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Make every removal of the re-verified marks under `base` fail (`on`) or work again (`!on`).
#[cfg(any(test, feature = "test-utils"))]
pub fn fail_reverified_clear_for_test(base: &Path, on: bool) {
    let mut roots = FAIL_REVERIFIED_CLEAR
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    roots.retain(|r| r != base);
    if on {
        roots.push(base.to_path_buf());
    }
}

#[cfg(any(test, feature = "test-utils"))]
fn reverified_clear_fails(base: &Path) -> bool {
    FAIL_REVERIFIED_CLEAR
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|r| r == base)
}

/// Remove ONLY the re-verified marks (never the suppression record). `Err` when they could
/// not be removed; the caller must then leave the record exactly as it is.
fn clear_reverified(base: &Path) -> Result<(), ()> {
    let path = reverified_path(base);
    #[cfg(any(test, feature = "test-utils"))]
    let injected = reverified_clear_fails(base);
    #[cfg(not(any(test, feature = "test-utils")))]
    let injected = false;
    let removed = if injected {
        Err(std::io::Error::other("injected"))
    } else {
        std::fs::remove_file(&path)
    };
    match removed {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            // unlink already handles a symlink or FIFO; an EMPTY directory planted in the
            // way is the one other shape csq can clear without recursing.
            if !injected && std::fs::remove_dir(&path).is_ok() {
                return Ok(());
            }
            tracing::warn!(
                error_kind = "refresh_suppression_reverified_clear_failed",
                "could not remove the re-verified marks; the suppression record is left unchanged"
            );
            Err(())
        }
    }
}

/// The marks path when the marks are in a state that blocks, or outlives, their clearing.
/// STATE-BASED, not cause-based, so no shape of obstruction can be missed. It is raised when
/// any of these holds:
/// * (i) the path exists in ANY form while the suppression record is `determined` (marks must
///   never outlive the damage episode, whatever blocked their removal);
/// * (ii) the path exists and is not a private regular file (a symlink, FIFO, directory, or a
///   regular file that is foreign-owned or readable/writable by group or other), at any time;
/// * (iii) the path cannot be inspected for any reason other than "not found" (for example
///   the accounts dir lost search permission): the detector must not go silent exactly when
///   it cannot look, so this is reported too, with a fixed-vocabulary kind.
///
/// `None` only when the path is absent (`NotFound`), or is a private regular file while the
/// record is undetermined (the one state in which marks legitimately exist).
fn reverified_clear_blocked(base: &Path, determined: bool) -> Option<ClearBlocked> {
    let path = reverified_path(base);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            return Some(ClearBlocked::Uninspectable(
                path,
                inspect_error_kind(e.kind()),
            ))
        }
    };
    let private_regular = meta.file_type().is_file() && is_private_owner_mode(&meta);
    (determined || !private_regular).then_some(ClearBlocked::Present(path))
}

/// What [`reverified_clear_blocked`] found.
enum ClearBlocked {
    /// The path exists in a form that blocks or outlives the clear (arms i and ii).
    Present(PathBuf),
    /// The path could not be inspected; the fixed kind says why (arm iii).
    Uninspectable(PathBuf, &'static str),
}

/// Fixed vocabulary for an inspection failure: never raw error text.
fn inspect_error_kind(kind: std::io::ErrorKind) -> &'static str {
    match kind {
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::NotADirectory => "not_a_directory",
        _ => "io_error",
    }
}

/// Owned by this user with no group/other permission bits (always true off unix, where the
/// file's ACL governs, matching `secure_file`).
fn is_private_owner_mode(meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no memory or synchronization preconditions.
        let uid = unsafe { libc::geteuid() };
        meta.uid() == uid && meta.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        true
    }
}

/// True when `slot`'s bound identity completed a `csq login` during THE CURRENT damage
/// episode of the suppression record. That login published a fresh, unique grant for the
/// slot, so the slot is safe even though other slots' suppression is still unknown. A mark
/// made in any earlier episode (the record was repaired, deleted, replaced or damaged anew
/// since, by csq or by hand) does not count, and neither does a mark when the episode
/// cannot be fingerprinted. Only meaningful while [`suppression_undetermined`] holds.
pub fn slot_reverified_since_damage(base: &Path, slot: u16) -> bool {
    let Some(identity) = ai::read_profiles_snapshot(base)
        .ok()
        .and_then(|pf| pf.by_slot.get(&slot.to_string()).copied())
    else {
        return false;
    };
    let (Some(marks), Some(now)) = (read_reverified(base), episode_fingerprint(base)) else {
        return false;
    };
    marks.episode == now && marks.identities.contains(&identity.as_uuid().to_string())
}

/// Update ONLY the last-good copy (used when the primary is damaged and must not be
/// overwritten).
fn write_last_good_only(base: &Path, state: &StateFile) -> Result<(), ()> {
    #[cfg(any(test, feature = "test-utils"))]
    if state_writes_fail(base) {
        return Err(());
    }
    let bytes = serde_json::to_vec(state).map_err(|_| ())?;
    write_atomic(&last_good_path(base), &bytes)
}

/// The current slot (canonical key) that binds `identity`, lowest number first.
fn current_slot_key(pf: &ProfilesFile, identity: IdentityId) -> Option<String> {
    pf.by_slot
        .iter()
        .filter(|(_, id)| **id == identity)
        .filter_map(|(key, _)| {
            SlotKey::from_key(key)
                .account()
                .map(|a| (a.get(), key.clone()))
        })
        .min_by_key(|(n, _)| *n)
        .map(|(_, key)| key)
}

/// Why the persisted record is not the whole story.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Damage {
    /// Primary is a clean current-format file (or nothing was ever written).
    None,
    /// Primary is in the old slot-keyed format.
    OldFormat,
    /// Primary was deleted but a last-good copy with entries remains.
    Missing,
    /// Primary is refused or unparseable.
    Unreadable,
}

/// Everything persisted, merged into one view.
struct Persisted {
    /// Entries as last known (the primary, else the last-good copy, else carried-forward v1).
    state: StateFile,
    damage: Damage,
    /// True when nothing readable describes the suppressions although something should:
    /// the primary is damaged or missing and no usable last-good copy exists.
    unknown: bool,
    /// True when the primary may be (re)written: it is current, absent, or old-format. A
    /// damaged primary is NEVER overwritten.
    primary_writable: bool,
}

fn load_persisted(base: &Path, pf: Option<&ProfilesFile>) -> Persisted {
    let last_good = || match read_state_at(&last_good_path(base)) {
        StateRead::Current(state) => Some(state),
        _ => None,
    };
    match read_state(base) {
        StateRead::Current(state) => Persisted {
            state,
            damage: Damage::None,
            unknown: false,
            primary_writable: true,
        },
        StateRead::Absent => match read_state_at(&last_good_path(base)) {
            StateRead::Absent => Persisted {
                state: StateFile::new(),
                damage: Damage::None,
                unknown: false,
                primary_writable: true,
            },
            StateRead::Current(state) => Persisted {
                damage: if state.suppressed.is_empty() {
                    Damage::None
                } else {
                    Damage::Missing
                },
                state,
                unknown: false,
                primary_writable: true,
            },
            _ => Persisted {
                state: StateFile::new(),
                damage: Damage::Missing,
                unknown: true,
                primary_writable: false,
            },
        },
        StateRead::V1(old) => {
            let mut state = last_good().unwrap_or_else(StateFile::new);
            if let Some(pf) = pf {
                for (slot, holder) in old {
                    if let Some(identity_uuid) = pf.by_slot.get(&slot.to_string()) {
                        state.suppressed.insert(
                            slot.to_string(),
                            Entry {
                                holder,
                                identity_uuid: *identity_uuid,
                            },
                        );
                    }
                }
            }
            Persisted {
                state,
                damage: Damage::OldFormat,
                unknown: pf.is_none(),
                primary_writable: pf.is_some(),
            }
        }
        StateRead::Unreadable => {
            let good = last_good();
            Persisted {
                unknown: good.is_none(),
                state: good.unwrap_or_else(StateFile::new),
                damage: Damage::Unreadable,
                primary_writable: false,
            }
        }
    }
}

/// Unpersisted startup verdicts (the first detection when the persist failed), per accounts
/// root, kept in this process until a persist succeeds.
static PENDING: Mutex<BTreeMap<PathBuf, AuditReport>> = Mutex::new(BTreeMap::new());

fn remember_pending(base: &Path, report: &AuditReport) {
    let mut map = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    map.insert(base.to_path_buf(), report.clone());
}

fn forget_pending(base: &Path) {
    PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(base);
}

/// A login of `identity` ends its suppression in memory too.
fn forget_pending_identity(base: &Path, identity: IdentityId) {
    let mut map = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(report) = map.get_mut(base) {
        let slots: Vec<u16> = report
            .bound
            .iter()
            .filter(|(_, id)| **id == identity)
            .map(|(slot, _)| *slot)
            .collect();
        for slot in slots {
            report.slots.insert(slot, SlotState::Clear);
        }
    }
}

fn entries_of(report: &AuditReport) -> Vec<(String, Entry)> {
    report
        .slots
        .iter()
        .filter_map(|(slot, verdict)| match verdict {
            SlotState::Suppressed { holder } => report.bound.get(slot).map(|id| {
                (
                    slot.to_string(),
                    Entry {
                        holder: *holder,
                        identity_uuid: *id,
                    },
                )
            }),
            _ => None,
        })
        .collect()
}

fn pending_entries(base: &Path) -> Vec<(String, Entry)> {
    PENDING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(base)
        .map(entries_of)
        .unwrap_or_default()
}

/// What a live in-process audit suppresses right now.
fn live_entries(base: &Path) -> Vec<(String, Entry)> {
    #[cfg(any(test, feature = "test-utils"))]
    count_lookup(base, "live");
    entries_of(&audit(base))
}

/// The resolved answer: which identities are suppressed and where each currently lives.
struct View {
    /// slot -> holder, for every canonical slot that currently binds a suppressed identity.
    slots: BTreeMap<u16, u16>,
    /// suppressed identity -> holder.
    identities: std::collections::HashMap<IdentityId, u16>,
}

/// An entry for identity I counts for whichever canonical slot currently binds I. When
/// profiles cannot be read the binding cannot be checked, so every entry counts at its
/// recorded slot (fail closed: a stale suppression is recoverable by `csq login`, a
/// presented stale grant is not).
fn resolve(entries: Vec<(String, Entry)>, pf: Option<&ProfilesFile>) -> View {
    let mut identities = std::collections::HashMap::new();
    for (_, entry) in &entries {
        identities
            .entry(entry.identity_uuid)
            .or_insert(entry.holder);
    }
    let mut slots = BTreeMap::new();
    match pf {
        Some(pf) => {
            let mut bound = std::collections::HashSet::new();
            for (key, id) in &pf.by_slot {
                if let (Some(slot), Some(holder)) =
                    (SlotKey::from_key(key).account(), identities.get(id))
                {
                    slots.insert(slot.get(), *holder);
                    bound.insert(*id);
                }
            }
            identities.retain(|id, _| bound.contains(id));
        }
        None => {
            for (key, entry) in &entries {
                if let Some(slot) = SlotKey::from_key(key).account() {
                    slots.insert(slot.get(), entry.holder);
                }
            }
        }
    }
    View { slots, identities }
}

fn warn_state_degraded(base: &Path, damage: Damage) {
    let kind = match damage {
        Damage::None => return,
        Damage::OldFormat => "refresh_suppression_state_old_format",
        Damage::Missing => "refresh_suppression_state_missing",
        Damage::Unreadable => "refresh_suppression_state_unreadable",
    };
    if throttle_allows(base, kind, 0, Instant::now()) {
        tracing::warn!(
            error_kind = kind,
            "refresh-suppressed.json is refused, unreadable, missing or in an old format; the \
             last-good copy and a live audit decide suppression until it is repaired"
        );
    }
}

fn suppression_view(base: &Path) -> View {
    let pf = ai::read_profiles_snapshot(base).ok();
    let persisted = load_persisted(base, pf.as_ref());
    let degraded = persisted.damage != Damage::None || persisted.unknown;
    let mut entries: Vec<(String, Entry)> = persisted.state.suppressed.into_iter().collect();
    if degraded {
        warn_state_degraded(base, persisted.damage);
        entries.extend(live_entries(base));
    }
    entries.extend(pending_entries(base));
    resolve(entries, pf.as_ref())
}

/// Slots whose refresh is currently suppressed (slot -> holder). Identity-anchored: a slot
/// is listed while it binds an identity that carries a suppression, wherever that identity
/// was first suppressed.
///
/// A launch gate (`csq run`, `csq swap`, the desktop launch) uses this and
/// [`is_refresh_suppressed`] to refuse starting a session in a suppressed slot.
///
/// Failure behaviour, stated per case:
/// * `profiles.json` unreadable: FAILS CLOSED. Every persisted entry counts at its recorded
///   slot.
/// * state file damaged, old-format or deleted: FAILS CLOSED as far as anything is known:
///   the answer is the union of the last-good copy (`refresh-suppressed.last-good.json`,
///   read through the same guarded reader) and a live audit.
/// * state file damaged AND no usable last-good copy: NOT fully closed, because nothing
///   records the old suppressions; only the live audit applies.
///   [`suppression_undetermined`] is true exactly then, and a caller that must fail closed
///   treats the slot as suppressed.
pub fn suppressed_slots(base: &Path) -> BTreeMap<u16, u16> {
    #[cfg(any(test, feature = "test-utils"))]
    count_lookup(base, "lookup");
    suppression_view(base).slots
}

/// The predicate the refresher and a launch gate consult before presenting a slot's refresh
/// token or starting a session in it. Same failure behaviour as [`suppressed_slots`].
pub fn is_refresh_suppressed(base: &Path, slot: u16) -> bool {
    suppressed_slots(base).contains_key(&slot)
}

/// True when `identity` carries a suppression anywhere. Checked where the token is
/// presented (`refresh::check::broker_check`), so a `csq move` between a tick's snapshot and
/// the refresh cannot carry the identity past the brake.
pub fn identity_refresh_suppressed(base: &Path, identity: IdentityId) -> bool {
    suppression_view(base).identities.contains_key(&identity)
}

/// The holder slot recorded for a suppressed `identity`, for the fixed warning.
pub fn identity_suppression_holder(base: &Path, identity: IdentityId) -> Option<u16> {
    suppression_view(base).identities.get(&identity).copied()
}

/// True when the persisted record is damaged or deleted and no usable last-good copy exists
/// to say what was suppressed (see [`suppressed_slots`]). A fail-closed caller treats every
/// slot's answer as untrusted while this holds.
pub fn suppression_undetermined(base: &Path) -> bool {
    let pf = ai::read_profiles_snapshot(base).ok();
    load_persisted(base, pf.as_ref()).unknown
}

/// Fold an audit report into the persisted state. ADDITIVE: the holder's own refresh makes a
/// pair unequal while the suppressed slot still holds the stale grant, so a prior entry is
/// dropped only when its identity is no longer bound by any canonical slot, judged against
/// `profiles.json` read again UNDER the lock. A verdict is re-keyed through the identity's
/// CURRENT binding (a move that beat the persist does not lose it). A damaged primary is
/// NEVER overwritten.
fn apply_report_locked(
    lock: &ProfilesFileLock,
    base: &Path,
    report: &AuditReport,
) -> Result<(), ()> {
    if report.profiles_unreadable {
        return Ok(());
    }
    if !lock.protects(base) {
        return Err(());
    }
    let pf = ai::read_profiles_snapshot(base).map_err(|_| ())?;
    let persisted = load_persisted(base, Some(&pf));
    if !persisted.primary_writable {
        return Err(());
    }
    let mut next = StateFile::new();
    let carried = persisted
        .state
        .suppressed
        .into_values()
        .chain(entries_of(report).into_iter().map(|(_, entry)| entry));
    for entry in carried {
        if let Some(key) = current_slot_key(&pf, entry.identity_uuid) {
            next.suppressed.entry(key).or_insert(entry);
        }
    }
    write_state(base, &next)
}

/// Persist `report` under the profiles lock (a report read earlier is re-validated against
/// the binding read under the lock).
fn apply(base: &Path, report: &AuditReport) -> Result<(), ()> {
    let lock = ProfilesFileLock::acquire(base).map_err(|_| ())?;
    apply_report_locked(&lock, base, report)
}

/// Outcome of the startup audit.
pub struct StartupAudit {
    pub report: AuditReport,
    /// False when the verdicts could not be written; they are then held in memory and
    /// [`persist_pending`] retries the write.
    pub persisted: bool,
}

/// Daemon-startup entry: audit INSIDE the profiles lock (so no login can publish a fresh
/// grant between the read and the persist), warn (fixed vocabulary, slot numbers only, never
/// a token), persist the suppression. Only local file I/O runs under the lock.
pub fn run_startup_audit_outcome(base: &Path) -> StartupAudit {
    let (report, persisted) = match ProfilesFileLock::acquire(base) {
        Ok(lock) => {
            let report = audit(base);
            let persisted = apply_report_locked(&lock, base, &report).is_ok();
            (report, persisted)
        }
        Err(_) => (audit(base), false),
    };
    for (slot, verdict) in &report.slots {
        if let SlotState::Suppressed { holder } = verdict {
            tracing::warn!(
                slot,
                holder_slot = holder,
                error_kind = "refresh_duplicate_grant_detected",
                "two slots hold one refresh grant; refresh is suppressed for the first slot \
                 until `csq login` re-binds it"
            );
        }
    }
    if persisted {
        forget_pending(base);
    } else if !report.profiles_unreadable {
        tracing::warn!(
            error_kind = "refresh_suppression_persist_failed",
            "could not persist refresh suppression state; held in memory and retried"
        );
        remember_pending(base, &report);
    }
    StartupAudit { report, persisted }
}

/// [`run_startup_audit_outcome`] returning just the report.
pub fn run_startup_audit(base: &Path) -> AuditReport {
    run_startup_audit_outcome(base).report
}

/// Retry persisting an unpersisted startup report (called each refresher tick). True when
/// nothing is pending or the write now succeeded.
pub fn persist_pending(base: &Path) -> bool {
    let report = {
        let map = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(base) {
            Some(report) => report.clone(),
            None => return true,
        }
    };
    if apply(base, &report).is_ok() {
        forget_pending(base);
        true
    } else {
        if throttle_allows(base, "persist_retry", 0, Instant::now()) {
            tracing::warn!(
                error_kind = "refresh_suppression_persist_failed",
                "could not persist refresh suppression state; held in memory and retried"
            );
        }
        false
    }
}

/// A successful `csq login` of `slot` ends THAT slot's suppression (and its identity's).
/// Nothing else does except the identity being unbound.
pub fn clear_on_login(base: &Path, slot: u16) {
    let Ok(lock) = ProfilesFileLock::acquire(base) else {
        tracing::warn!(
            error_kind = "refresh_suppression_clear_lock_failed",
            "could not lock to clear refresh suppression after login"
        );
        return;
    };
    clear_on_login_locked(&lock, base, slot);
}

/// [`clear_on_login`] for a caller that already holds the profiles lock (the login
/// receipt), so the clear happens inside the same critical section that published the
/// fresh binding and no audit can interleave between the two.
pub fn clear_on_login_locked(lock: &ProfilesFileLock, base: &Path, slot: u16) {
    if !lock.protects(base) {
        tracing::warn!(
            error_kind = "refresh_suppression_clear_lock_failed",
            "could not lock to clear refresh suppression after login"
        );
        return;
    }
    let pf = ai::read_profiles_snapshot(base).ok();
    let slot_key = slot.to_string();
    let logged_in = pf
        .as_ref()
        .and_then(|pf| pf.by_slot.get(&slot_key).copied());
    if let Some(identity) = logged_in {
        forget_pending_identity(base, identity);
    }
    // Fingerprint BEFORE judging: a record that changes between the two leaves a mark that
    // no longer matches and is void.
    let episode = episode_fingerprint(base);
    let persisted = load_persisted(base, pf.as_ref());
    if persisted.unknown {
        // Nothing readable records a suppression; the live audit decides, and a freshly
        // logged-in slot holds a fresh grant. Record that THIS identity was re-verified in
        // THIS damage episode so the launch gate lets this slot (only) start again while the
        // record stays in this state.
        if let Some(identity) = logged_in {
            let marked = match episode.as_deref() {
                Some(episode) => mark_reverified(base, identity, episode),
                None => Err(()),
            };
            if marked.is_err() {
                tracing::warn!(
                    error_kind = "refresh_suppression_reverified_persist_failed",
                    "could not record that the slot was re-verified by its login"
                );
            }
        }
        return;
    }
    let mut state = persisted.state;
    let before = state.suppressed.len();
    state
        .suppressed
        .retain(|key, entry| *key != slot_key && Some(entry.identity_uuid) != logged_in);
    // A V1 or missing primary is rewritten even when nothing changed, so it becomes a clean v2.
    if state.suppressed.len() == before && persisted.damage == Damage::None {
        return;
    }
    let written = if persisted.primary_writable {
        write_state(base, &state)
    } else {
        write_last_good_only(base, &state)
    };
    if written.is_err() {
        tracing::warn!(
            error_kind = "refresh_suppression_persist_failed",
            "could not persist refresh suppression state"
        );
    }
}

/// `csq move`: `by_slot[from]` and `by_slot[to]` were just swapped under `lock`; swap the
/// entries' display keys (and any holder number) the same way. DISPLAY ONLY: suppression is
/// identity-anchored, so a failure here changes no decision.
pub fn rekey_on_move(lock: &ProfilesFileLock, base: &Path, from: u16, to: u16) {
    if !lock.protects(base) {
        tracing::warn!(
            error_kind = "refresh_suppression_rekey_skipped",
            "refresh suppression display keys were not updated after a slot move: the lock \
             does not cover this accounts root; the suppression itself follows the identity"
        );
        return;
    }
    let StateRead::Current(state) = read_state(base) else {
        return;
    };
    if state.suppressed.is_empty() {
        return;
    }
    let (from_key, to_key) = (from.to_string(), to.to_string());
    let swap_slot = |s: u16| {
        if s == from {
            to
        } else if s == to {
            from
        } else {
            s
        }
    };
    let mut next = StateFile::new();
    for (key, entry) in state.suppressed {
        let key = if key == from_key {
            to_key.clone()
        } else if key == to_key {
            from_key.clone()
        } else {
            key
        };
        next.suppressed.insert(
            key,
            Entry {
                holder: swap_slot(entry.holder),
                identity_uuid: entry.identity_uuid,
            },
        );
    }
    if write_state(base, &next).is_err() {
        tracing::warn!(
            error_kind = "refresh_suppression_rekey_failed",
            "could not update refresh suppression display keys after a slot move; the \
             suppression itself follows the identity"
        );
    }
}

/// Operator text shared by `csq doctor` and any surface that prints these facts. One
/// line per finding; slot numbers and fixed words only.
pub fn operator_lines(base: &Path) -> Vec<String> {
    let report = audit(base);
    let persisted = suppressed_slots(base);
    let mut lines = Vec::new();
    let pf = ai::read_profiles_snapshot(base).ok();
    let state = load_persisted(base, pf.as_ref());
    match state.damage {
        Damage::Unreadable => lines.push(format!(
            "Refresh audit: refresh-suppressed.json is damaged (unreadable or refused); repair \
             or remove it. It is never rewritten while damaged. {}",
            if state.unknown {
                "No last-good copy exists, so only the live audit applies until it is repaired"
            } else {
                "The last-good copy (refresh-suppressed.last-good.json) and the live audit keep \
                 applying; `csq login <slot>` ends one slot's suppression"
            }
        )),
        Damage::Missing => lines.push(
            "Refresh audit: refresh-suppressed.json is missing; the last-good copy still applies \
             and the next daemon start restores it"
                .to_string(),
        ),
        _ => {}
    }
    match reverified_clear_blocked(base, !state.unknown) {
        Some(ClearBlocked::Present(path)) => lines.push(format!(
            "Refresh audit: {} must not exist in its present form (it is not a private regular \
             file, or it exists while the suppression record is determined); if csq cannot \
             remove it, refresh-suppression state writes are refused and new suppressions are \
             held in memory only. Remove or repair that path; the next daemon tick then \
             persists them",
            path.display()
        )),
        Some(ClearBlocked::Uninspectable(path, kind)) => lines.push(format!(
            "Refresh audit: cannot inspect {}: {kind}; check the accounts dir permissions. \
             Until it can be inspected csq cannot tell whether stale marks remain",
            path.display()
        )),
        None => {}
    }
    if report.profiles_unreadable {
        lines.push("Refresh audit: UNDETERMINED (profiles.json could not be read)".to_string());
    }
    for (slot, verdict) in &report.slots {
        match verdict {
            SlotState::Suppressed { holder } => lines.push(format!(
                "Refresh audit: slots {holder} and {slot} hold the same refresh grant; refresh is \
                 suppressed for slot {slot}{} — run `csq login {slot}`",
                if persisted.contains_key(slot) {
                    ""
                } else {
                    " once the daemon restarts"
                }
            )),
            SlotState::Undetermined => lines.push(format!(
                "Refresh audit: slot {slot} UNDETERMINED (saved credential unreadable); \
                 suppression unchanged"
            )),
            _ => {}
        }
    }
    // A persisted suppression the audit did not reproduce (stale, or undetermined).
    for (slot, holder) in &persisted {
        if !matches!(report.slots.get(slot), Some(SlotState::Suppressed { .. })) {
            lines.push(format!(
                "Refresh audit: refresh stays suppressed for slot {slot} (holder slot {holder}) \
                 until `csq login {slot}`"
            ));
        }
    }
    lines
}

#[cfg(test)]
mod tests;
