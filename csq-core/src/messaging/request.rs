//! Sender-bound request outcomes survive legacy message rewrites and history eviction.
use super::{
    limits::{check_body, Limits, Liveness},
    model::{Message, Receipt, Recipient, Sender, VerifiedSession},
    store::{self, Dest},
};
use crate::sessions::directives::{
    acquire_message_store_lock_as, canonical_uuid, ensure_dir_as, write_atomic_as, DirectiveError,
    FsOps, UndeterminedCause as Cause, MAX_RECORD_BYTES,
};
use crate::sessions::directives::{check_store_dir_as, read_regular_bounded_as};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};
const LABEL: &str = "message store";
/// Fixed request horizon; contention qualification measures its lock-wait component.
pub const WINDOW_SECS: u64 = 600;
/// Shared-history policy: allow one second of legacy upward rounding plus
/// one second of margin. This is a stated allowance, not a measured host bound.
/// It does not relax message-record skew or same-context callback rollback.
const REQUEST_CLOCK_JITTER_SECS: u64 = 2;
const CAPACITY: usize = 1024;
/// Raw request intent remains stable when a recipient name or parent disappears.
#[derive(Clone, Copy, Serialize)]
pub enum Intent<'a> {
    /// Explicit addressing, including the original unresolved target spelling.
    Send {
        target: &'a str,
        parent: Option<&'a str>,
        body: &'a str,
        /// The sender's wake choice. Serialized only when `false`, so the digest of every
        /// default (`wake:true`) request is byte-identical to the one stored before the
        /// flag existed; a retry that flips it no longer matches its original.
        #[serde(skip_serializing_if = "wake_is_default")]
        wake: bool,
    },
    /// The original reply parent and body.
    Reply {
        parent: &'a str,
        body: &'a str,
        /// See [`Intent::Send`]'s `wake`.
        #[serde(skip_serializing_if = "wake_is_default")]
        wake: bool,
    },
}
fn wake_is_default(wake: &bool) -> bool {
    *wake
}
/// Historical outcome within the authoritative request horizon; ambiguity is an error.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A healthy initialized ledger has no admitted request for this fresh key.
    NotStored,
    /// Original successful receipt and recipient, preserved after message deletion.
    Stored(Receipt, Recipient),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: u8,
    init: String,
    floor: u64,
    clock: u64,
    entries: BTreeMap<String, Entry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    issued: u64,
    intent: String,
    record: String,
    receipt: Receipt,
    to: Recipient,
    committed: bool,
}
fn uncertain() -> DirectiveError {
    DirectiveError::undet("message store: request outcome undetermined")
}
fn digest(value: impl Serialize) -> Result<String, DirectiveError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| uncertain())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
/// Mint once before resolving the target or attempting any mutation.
pub fn mint(now: u64) -> String {
    format!("{now}.{}", uuid::Uuid::new_v4())
}
fn issued(token: &str) -> Result<u64, DirectiveError> {
    let bad = || DirectiveError::invalid("request token must be epoch.UUIDv4");
    let (epoch, id) = token.split_once('.').ok_or_else(bad)?;
    let timestamp: u64 = epoch.parse().map_err(|_| bad())?;
    if timestamp == 0 || timestamp.to_string() != epoch || !canonical_uuid(id) {
        return Err(bad());
    }
    let uuid = uuid::Uuid::parse_str(id).map_err(|_| bad())?;
    if uuid.as_bytes()[6] >> 4 != 4 || uuid.as_bytes()[8] & 0xc0 != 0x80 {
        return Err(bad());
    }
    Ok(timestamp)
}
/// Expired or future tokens never authorize a new operation.
pub fn validate(token: &str, now: u64) -> Result<(), DirectiveError> {
    let timestamp = issued(token)?;
    if timestamp > now || now - timestamp >= WINDOW_SECS {
        return Err(uncertain().with_cause(Cause::Clock));
    }
    Ok(())
}
fn supplied_key(token: &str, now: Option<u64>) -> Result<u64, DirectiveError> {
    let invalid =
        |message| DirectiveError::new(csq_sdk::SdkErrorCode::InvalidIdempotencyKey, message);
    let timestamp = issued(token).map_err(|_| {
        invalid("idempotency key must be epoch.UUIDv4; resend WITHOUT idempotency_key")
    })?;
    if let Some(now) = now {
        if timestamp > now {
            return Err(invalid(
                "idempotency key is in the future; resend WITHOUT idempotency_key",
            ));
        }
        if now - timestamp >= WINDOW_SECS {
            return Err(invalid(
                "idempotency key expired; prior outcome is unrecoverable; resend WITHOUT idempotency_key is a new send",
            ));
        }
    }
    Ok(timestamp)
}
/// Valid admitted keys retain recovery instructions for genuinely undetermined outcomes.
pub fn with_key<T>(
    now: Result<u64, DirectiveError>,
    supplied: Option<&str>,
    op: impl FnOnce(u64, &str) -> Result<T, DirectiveError>,
) -> Result<T, DirectiveError> {
    let (now, minted) = match supplied {
        Some(token) => {
            supplied_key(token, now.as_ref().ok().copied())?;
            (
                now.map_err(|e| e.with_cause(Cause::Clock)),
                token.to_owned(),
            )
        }
        None => {
            let now = now.map_err(|e| diagnostic_error(e.with_cause(Cause::Clock)))?;
            (Ok(now), mint(now))
        }
    };
    now.and_then(|now| {
        validate(&minted, now)?;
        op(now, &minted)
    })
    .map_err(|e| recovery_error(e, &minted))
}
fn diagnostic_error(mut e: DirectiveError) -> DirectiveError {
    if e.code == csq_sdk::SdkErrorCode::Undetermined {
        let cause = e.cause.unwrap_or(Cause::Unknown);
        let message = if e.message == "sender identity unpinned; key refused" {
            "sender identity unpinned; key refused"
        } else {
            "message store: request outcome undetermined"
        };
        e.message = format!("{message}; cause={}", cause.as_str());
        if let Some(attempts) = e.attempts {
            e.message.push_str(&format!("; attempts={attempts}"));
        }
        tracing::debug!(
            event = "message_request",
            stage = "recovery",
            cause = cause.as_str()
        );
    }
    e
}
fn recovery_error(e: DirectiveError, minted: &str) -> DirectiveError {
    let mut e = diagnostic_error(e);
    if e.code == csq_sdk::SdkErrorCode::Undetermined {
        e.message = format!(
            "{}; idempotency_key={minted}; retry the same call with key={minted}; or csq sessions lookup-message --idempotency-key {minted}",
            e.message
        );
    }
    e
}
/// Consult retained positive outcomes for every supplied canonical key before age admission.
pub fn with_key_recovery<T>(
    now: Result<u64, DirectiveError>,
    supplied: Option<&str>,
    recover: impl FnOnce(u64, &str) -> Result<Option<T>, DirectiveError>,
    op: impl FnOnce(u64, &str) -> Result<T, DirectiveError>,
) -> Result<T, DirectiveError> {
    if let Some(key) = supplied {
        supplied_key(key, None)?;
        if let Ok(now) = now.as_ref() {
            if let Some(value) = recover(*now, key).map_err(|e| recovery_error(e, key))? {
                return Ok(value);
            }
        }
    }
    with_key(now, supplied, op)
}
/// True selects keyed admission; false selects an automatic unprotected legacy send.
pub const UNPROTECTED_WARNING: &str =
    "sent without duplicate protection: sender identity not pinned";
pub fn protection(supplied: bool, session: &VerifiedSession) -> Result<bool, DirectiveError> {
    if session.as_recipient().started_exact.is_some() {
        return Ok(true);
    }
    if supplied {
        return Err(
            DirectiveError::undet("sender identity unpinned; key refused")
                .with_cause(Cause::SenderIdentity),
        );
    }
    tracing::warn!(reason = "duplicate_protection_sender_unpinned");
    Ok(false)
}
pub(super) fn request_id(from: &Sender, token: &str) -> Result<String, DirectiveError> {
    from.started_exact.ok_or(
        DirectiveError::undet("sender identity unpinned; key refused")
            .with_cause(Cause::SenderIdentity),
    )?;
    let hash = digest((
        "csq.request.v1",
        from.pid,
        from.started_at,
        from.started_exact,
        from.surface,
        token,
    ))?;
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).map_err(|_| uncertain())?;
    }
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}
fn record_digest(m: &Message) -> Result<String, DirectiveError> {
    digest((
        &m.id,
        &m.thread,
        &m.in_reply_to,
        m.from.pid,
        m.from.started_at,
        m.from.started_exact,
        m.from.surface,
        m.to,
        &m.body,
        m.created_at,
    ))
}
fn persist(dir: &Path, ledger: &Ledger, fs: &FsOps<'_>) -> Result<(), DirectiveError> {
    let started = std::time::Instant::now();
    tracing::debug!(
        event = "message_request",
        stage = "ledger_write",
        outcome = "start",
        elapsed_ms = 0u64
    );
    let result = (|| {
        let bytes = serde_json::to_vec(ledger).map_err(|_| uncertain())?;
        if bytes.len() as u64 > MAX_RECORD_BYTES || ledger.entries.len() > CAPACITY {
            return Err(uncertain());
        }
        synced_write(&dir.join("ledger.json"), &bytes, fs)?;
        sync_directory(dir)
    })()
    .map_err(|e: DirectiveError| e.with_cause(Cause::LedgerWrite));
    tracing::debug!(
        event = "message_request",
        stage = "ledger_write",
        outcome = if result.is_ok() { "complete" } else { "error" },
        cause = result
            .as_ref()
            .err()
            .and_then(|e| e.cause)
            .unwrap_or(Cause::Unknown)
            .as_str(),
        elapsed_ms = started.elapsed().as_millis() as u64
    );
    result
}
fn synced_write(path: &Path, bytes: &[u8], fs: &FsOps<'_>) -> Result<(), DirectiveError> {
    let synced = FsOps {
        write_tmp: &crate::platform::fs::write_new_private_synced,
        secure: fs.secure,
        replace: fs.replace,
    };
    write_atomic_as(LABEL, path, bytes, &synced)
}
#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), DirectiveError> {
    use std::os::unix::fs::OpenOptionsExt;
    // `false` is an absent directory: refuse before the open, exactly as the Windows twin
    // does, rather than leaving the refusal to whatever the open happens to report.
    if !check_store_dir_as(LABEL, path)? {
        return Err(DirectiveError::undet(
            "message store: sync request authority",
        ));
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| {
            DirectiveError::undetermined("message store: sync request authority", e.kind())
        })
}
/// Windows has no `fsync(2)` on a directory fd; the NTFS equivalent is `FlushFileBuffers`
/// on a directory handle, which CreateFileW opens only with `FILE_FLAG_BACKUP_SEMANTICS`
/// and flushes only with write access. `FILE_FLAG_OPEN_REPARSE_POINT` is the
/// `O_NOFOLLOW` analogue: a junction or symlink is opened as itself and then refused.
/// Any failure (including a filesystem that cannot flush directories) refuses.
#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<(), DirectiveError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let refused = || DirectiveError::undet("message store: sync request authority");
    if !check_store_dir_as(LABEL, path)? {
        return Err(refused());
    }
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| {
            DirectiveError::undetermined("message store: sync request authority", e.kind())
        })?;
    let held = directory.metadata().map_err(|e| {
        DirectiveError::undetermined("message store: sync request authority", e.kind())
    })?;
    if !held.is_dir() || held.file_type().is_symlink() {
        return Err(refused());
    }
    directory.sync_all().map_err(|e| {
        DirectiveError::undetermined("message store: sync request authority", e.kind())
    })
}
/// No directory-durability primitive is implemented for this target: keyed requests refuse.
#[cfg(not(any(unix, windows)))]
fn sync_directory(_path: &Path) -> Result<(), DirectiveError> {
    Err(DirectiveError::undet(
        "message store: keyed requests unsupported: durable directory synchronization unavailable",
    ))
}
fn open(
    dir: &Path,
    now: u64,
    expiry: u64,
    fs: &FsOps<'_>,
    initialize: bool,
) -> Result<Ledger, DirectiveError> {
    let path = dir.join("requests");
    let base = dir
        .parent()
        .ok_or_else(|| uncertain().with_cause(Cause::LedgerRead))?;
    if !check_store_dir_as(LABEL, base).map_err(|e| e.with_cause(Cause::LedgerRead))? {
        return Err(uncertain().with_cause(Cause::LedgerRead));
    }
    let marker_path = base.join(".message-requests-initialized");
    let marker = read_regular_bounded_as(LABEL, &marker_path, 64)
        .map_err(|e| e.into_err_as(LABEL).with_cause(Cause::LedgerRead))?;
    if let Some(value) = &marker {
        if issued(value).map_err(|_| uncertain().with_cause(Cause::LedgerRead))?
            > now.saturating_add(REQUEST_CLOCK_JITTER_SECS)
        {
            return Err(uncertain().with_cause(Cause::LedgerRead));
        }
    }
    if !check_store_dir_as(LABEL, &path).map_err(|e| e.with_cause(Cause::LedgerRead))? {
        if !initialize || marker.is_some() {
            return Err(uncertain().with_cause(Cause::LedgerRead));
        }
        ensure_dir_as(LABEL, &path).map_err(|e| e.with_cause(Cause::LedgerWrite))?;
        let ledger = Ledger {
            schema: 1,
            init: mint(now),
            floor: now.min(expiry.saturating_sub(WINDOW_SECS)),
            clock: now,
            entries: BTreeMap::new(),
        };
        persist(&path, &ledger, fs)?;
        synced_write(&marker_path, ledger.init.as_bytes(), fs)
            .map_err(|e| e.with_cause(Cause::LedgerWrite))?;
        sync_directory(dir).map_err(|e| e.with_cause(Cause::LedgerWrite))?;
        sync_directory(base).map_err(|e| e.with_cause(Cause::LedgerWrite))?;
        return Ok(ledger);
    }
    let marker = marker.ok_or_else(|| uncertain().with_cause(Cause::LedgerRead))?;
    let text = read_regular_bounded_as(LABEL, &path.join("ledger.json"), MAX_RECORD_BYTES)
        .map_err(|e| e.into_err_as(LABEL).with_cause(Cause::LedgerRead))?
        .ok_or_else(|| uncertain().with_cause(Cause::LedgerRead))?;
    let mut ledger = decode_ledger(&text, &marker, Some(now))?;
    // Publish the clock and replay floor atomically with pruning, before any absence answer.
    ledger.clock = ledger.clock.max(now);
    ledger.floor = ledger
        .floor
        .max(ledger.clock.min(expiry.saturating_sub(WINDOW_SECS)));
    ledger.entries.retain(|_, e| e.issued > ledger.floor);
    persist(&path, &ledger, fs)?;
    Ok(ledger)
}
fn decode_ledger(text: &str, marker: &str, now: Option<u64>) -> Result<Ledger, DirectiveError> {
    let raw: serde_json::Value =
        serde_json::from_str(text).map_err(|_| uncertain().with_cause(Cause::LedgerRead))?;
    let ledger: Ledger = serde_json::from_value(raw.clone())
        .map_err(|_| uncertain().with_cause(Cause::LedgerRead))?;
    let hex = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if serde_json::to_value(&ledger).map_err(|_| uncertain().with_cause(Cause::LedgerRead))? != raw
        || ledger.schema != 1
        || ledger.init != marker
        || issued(&ledger.init).map_err(|_| uncertain().with_cause(Cause::LedgerRead))?
            > ledger.clock
        || ledger.floor > ledger.clock
        || now.is_some_and(|now| now.saturating_add(REQUEST_CLOCK_JITTER_SECS) < ledger.clock)
        || ledger.entries.len() > CAPACITY
        || ledger.entries.iter().any(|(id, e)| {
            !canonical_uuid(id)
                || e.receipt.id != *id
                || !canonical_uuid(&e.receipt.thread)
                || e.issued <= ledger.floor
                || e.issued > ledger.clock
                || e.receipt.created_at > ledger.clock
                || !hex(&e.intent)
                || !hex(&e.record)
                || e.receipt.status != super::model::Status::Queued
                || e.receipt.surfaced_at.is_some()
                || e.receipt.read_at.is_some()
                || e.receipt.acked_at.is_some()
                || e.receipt.ack_note_framed.is_some()
        })
    {
        return Err(uncertain().with_cause(Cause::LedgerRead));
    }
    Ok(ledger)
}
fn public_record(dir: &Path, id: &str, now: u64) -> Result<Option<Message>, DirectiveError> {
    store::request_record(dir, id, now).map_err(|e| e.with_cause(Cause::RecordUncertain))
}
fn outcome(
    dir: &Path,
    now: u64,
    fs: &FsOps<'_>,
    ledger: &mut Ledger,
    id: &str,
) -> Result<Lookup, DirectiveError> {
    let Some(entry) = ledger.entries.get_mut(id) else {
        return Ok(Lookup::NotStored);
    };
    if !entry.committed {
        let m = public_record(dir, id, now)?
            .ok_or_else(|| uncertain().with_cause(Cause::RecordUncertain))?;
        if record_digest(&m)? != entry.record {
            return Err(uncertain().with_cause(Cause::RecordUncertain));
        }
        entry.committed = true;
        persist(&dir.join("requests"), ledger, fs)?;
    }
    let entry = &ledger.entries[id];
    Ok(Lookup::Stored(entry.receipt.clone(), entry.to))
}
fn intent_digest(intent: Intent<'_>) -> Result<String, DirectiveError> {
    match intent {
        Intent::Send {
            target,
            parent,
            body,
            ..
        } => {
            if target.is_empty()
                || target.len() > 4096
                || parent.is_some_and(|id| !canonical_uuid(id))
            {
                return Err(DirectiveError::invalid("request intent is invalid"));
            }
            check_body(body)?;
        }
        Intent::Reply { parent, body, .. } => {
            if !canonical_uuid(parent) {
                return Err(DirectiveError::invalid("request intent is invalid"));
            }
            check_body(body)?;
        }
    }
    digest(intent)
}
pub(super) fn begin(
    dir: &Path,
    now: u64,
    upper: u64,
    fs: &FsOps<'_>,
    from: &Sender,
    token: &str,
    intent: Intent<'_>,
) -> Result<Option<(Receipt, Recipient)>, DirectiveError> {
    issued(token)?;
    let intent = intent_digest(intent)?;
    let id = request_id(from, token)?;
    let mut ledger = open(dir, now, upper, fs, true)?;
    validate(token, upper)?;
    if issued(token)? <= ledger.floor {
        return Err(uncertain());
    }
    if ledger.entries.get(&id).is_some_and(|e| e.intent != intent) {
        return Err(DirectiveError::invalid(
            "request key was used with different intent",
        ));
    }
    match outcome(dir, now, fs, &mut ledger, &id)? {
        Lookup::NotStored => Ok(None),
        Lookup::Stored(r, to) => Ok(Some((r, to))),
    }
}
pub(super) fn prepare(
    dir: &Path,
    now: u64,
    upper: u64,
    fs: &FsOps<'_>,
    token: &str,
    intent: Intent<'_>,
    m: &Message,
) -> Result<(), DirectiveError> {
    let mut ledger = open(dir, now, upper, fs, false)?;
    validate(token, upper)?;
    if issued(token)? <= ledger.floor {
        return Err(uncertain());
    }
    if public_record(dir, &m.id, now)?.is_some() {
        return Err(uncertain());
    }
    if ledger.entries.len() >= CAPACITY || ledger.entries.contains_key(&m.id) {
        return Err(uncertain());
    }
    if request_id(&m.from, token)? != m.id {
        return Err(uncertain());
    }
    ledger.entries.insert(
        m.id.clone(),
        Entry {
            issued: issued(token)?,
            intent: intent_digest(intent)?,
            record: record_digest(m)?,
            receipt: m.receipt(),
            to: m.to,
            committed: false,
        },
    );
    persist(&dir.join("requests"), &ledger, fs)
}
pub(super) fn commit(
    dir: &Path,
    now: u64,
    fs: &FsOps<'_>,
    from: &Sender,
    token: &str,
) -> Result<(), DirectiveError> {
    let mut ledger = open(dir, now, now, fs, false)?;
    ledger
        .entries
        .get_mut(&request_id(from, token)?)
        .ok_or_else(uncertain)?
        .committed = true;
    persist(&dir.join("requests"), &ledger, fs)
}
/// Advance captured time through the operation; round elapsed time upward to refuse late retries.
pub fn decision_time(now: u64, started: std::time::Instant) -> u64 {
    let elapsed = started.elapsed();
    now.saturating_add(elapsed.as_secs())
        .saturating_add(u64::from(elapsed.subsec_nanos() != 0))
}
/// Refuse clock rollback and account for elapsed work when the wall clock stops.
pub fn frontend_time(
    initial: u64,
    started: std::time::Instant,
    fresh: Result<u64, DirectiveError>,
) -> Result<u64, DirectiveError> {
    let fresh = fresh.map_err(|e| e.with_cause(Cause::Clock))?;
    if fresh < initial {
        return Err(
            DirectiveError::undet("message store: system clock moved backwards")
                .with_cause(Cause::Clock),
        );
    }
    Ok(fresh.max(decision_time(initial, started)))
}
/// Observed UTC and the original operation deadline are separate authority inputs.
#[derive(Clone, Copy)]
pub struct Clock {
    observed: u64,
    initial: u64,
    started: std::time::Instant,
}
impl From<u64> for Clock {
    fn from(observed: u64) -> Self {
        Self {
            observed,
            initial: observed,
            started: std::time::Instant::now(),
        }
    }
}
impl Clock {
    /// Fresh observed UTC for an unkeyed operation, without the projected expiry bound.
    pub fn observed(self) -> u64 {
        self.observed
    }
    pub(super) fn upper(self, backend_started: std::time::Instant) -> u64 {
        decision_time(self.initial, self.started).max(decision_time(self.observed, backend_started))
    }
}
/// Admission-only UTC continuity for one logical request, including retries.
/// A regression remains ambiguous until a new logical invocation. Read-only
/// recovery keeps its independent raw provider; captures only raise the floor.
pub(crate) struct AdmissionProvider<'a> {
    wall: &'a dyn Fn() -> Result<u64, DirectiveError>,
    last: std::cell::Cell<Option<u64>>,
    rolled_back: std::cell::Cell<bool>,
}
impl<'a> AdmissionProvider<'a> {
    pub(crate) fn new(wall: &'a dyn Fn() -> Result<u64, DirectiveError>) -> Self {
        Self {
            wall,
            last: std::cell::Cell::new(None),
            rolled_back: std::cell::Cell::new(false),
        }
    }
    // A successful raw preflight raises the next admitted observation floor.
    // Lower captures do not themselves latch rollback or reset a prior fault.
    pub(crate) fn capture(&self) -> Result<u64, DirectiveError> {
        let now = (self.wall)().map_err(|e| e.with_cause(Cause::Clock))?;
        self.last
            .set(Some(self.last.get().map_or(now, |last| last.max(now))));
        Ok(now)
    }
    pub(crate) fn observe(&self) -> Result<u64, DirectiveError> {
        if self.rolled_back.get() {
            return Err(uncertain().with_cause(Cause::Clock));
        }
        let now = (self.wall)().map_err(|e| e.with_cause(Cause::Clock))?;
        if self.last.get().is_some_and(|last| now < last) {
            self.rolled_back.set(true);
            return Err(uncertain().with_cause(Cause::Clock));
        }
        self.last.set(Some(now));
        Ok(now)
    }
}
/// Original request clock with an explicit admission-time observation provider.
/// Fixed asserted epochs never perform an ambient wall-clock read.
pub struct AdmissionClock<'a> {
    original: Clock,
    wall: Option<&'a dyn Fn() -> Result<u64, DirectiveError>>,
    last: std::cell::Cell<u64>,
}
impl<'a> AdmissionClock<'a> {
    pub fn new(original: Clock, wall: &'a dyn Fn() -> Result<u64, DirectiveError>) -> Self {
        Self {
            original,
            wall: Some(wall),
            last: std::cell::Cell::new(original.observed),
        }
    }
    pub fn asserted(original: Clock) -> Self {
        Self {
            original,
            wall: None,
            last: std::cell::Cell::new(original.observed),
        }
    }
    pub(super) fn observe(&self) -> Result<u64, DirectiveError> {
        let now = match self.wall {
            Some(wall) => wall().map_err(|_| uncertain().with_cause(Cause::Clock))?,
            None => self.original.observed,
        };
        if now < self.last.get() {
            return Err(uncertain().with_cause(Cause::Clock));
        }
        self.last.set(now);
        Ok(now)
    }
    pub(super) fn upper(&self, backend_started: std::time::Instant, observed: u64) -> u64 {
        self.original.upper(backend_started).max(observed)
    }
}

/// Carry the original elapsed deadline while retaining fresh UTC for ledger rollback checks.
pub fn clock(
    initial: u64,
    started: std::time::Instant,
    fresh: Result<u64, DirectiveError>,
) -> Result<Clock, DirectiveError> {
    let observed = fresh.map_err(|e| e.with_cause(Cause::Clock))?;
    if observed < initial {
        return Err(uncertain().with_cause(Cause::Clock));
    }
    Ok(Clock {
        observed,
        initial,
        started,
    })
}
fn under_lock<T>(
    base: &Path,
    now: u64,
    f: impl FnOnce(&Path, u64, u64) -> Result<T, DirectiveError>,
) -> Result<T, DirectiveError> {
    under_lock_with_admission_clock(base, AdmissionClock::asserted(now.into()), f)
}
fn under_lock_with_admission_clock<T>(
    base: &Path,
    clock: AdmissionClock<'_>,
    f: impl FnOnce(&Path, u64, u64) -> Result<T, DirectiveError>,
) -> Result<T, DirectiveError> {
    let started = std::time::Instant::now();
    let dir = store::store_dir(base);
    ensure_dir_as(LABEL, &dir)?;
    #[cfg(test)]
    let wait_started = std::time::Instant::now();
    let _lock = acquire_message_store_lock_as(LABEL, &dir.join(".lock"))?;
    #[cfg(test)]
    tests::note_lock_wait(wait_started.elapsed());
    #[cfg(windows)]
    ensure_windows_lock_file(&dir.join(".lock"))?;
    let now = clock.observe()?;
    f(&dir, now, clock.upper(started, now))
}
/// Check immutable intent before resolving a target; repeats under the send lock.
pub fn replay(
    base: &Path,
    now: impl Into<Clock>,
    fs: &FsOps<'_>,
    session: &VerifiedSession,
    token: &str,
    intent: Intent<'_>,
) -> Result<Option<(Receipt, Recipient)>, DirectiveError> {
    replay_with_admission_clock(
        base,
        AdmissionClock::asserted(now.into()),
        fs,
        session,
        token,
        intent,
    )
}
pub fn replay_with_admission_clock(
    base: &Path,
    now: AdmissionClock<'_>,
    fs: &FsOps<'_>,
    session: &VerifiedSession,
    token: &str,
    intent: Intent<'_>,
) -> Result<Option<(Receipt, Recipient)>, DirectiveError> {
    super::limits::check_sender(session.sender())?;
    let admission = now;
    let clock = admission.original;
    let now = clock.observed;
    if issued(token)? > now {
        return Err(uncertain().with_cause(Cause::Clock));
    }
    under_lock_with_admission_clock(base, admission, |dir, now, upper| {
        begin(
            dir,
            now,
            upper.max(decision_time(clock.initial, clock.started)),
            fs,
            session.sender(),
            token,
            intent,
        )
    })
}
/// Initialize strict request authority under the same store lock; never reset lost authority.
pub fn initialize(base: &Path, now: u64, fs: &FsOps<'_>) -> Result<(), DirectiveError> {
    under_lock(base, now, |dir, now, upper| {
        open(dir, now, upper, fs, true).map(|_| ())
    })
}
pub fn initialize_with_admission_clock(
    base: &Path,
    now: AdmissionClock<'_>,
    fs: &FsOps<'_>,
) -> Result<(), DirectiveError> {
    under_lock_with_admission_clock(base, now, |dir, now, upper| {
        open(dir, now, upper, fs, true).map(|_| ())
    })
}
/// Read retained positive evidence only; None is not a historical absence certificate.
pub fn recover_existing(
    base: &Path,
    now: u64,
    _fs: &FsOps<'_>,
    session: &VerifiedSession,
    token: &str,
    intent: Option<Intent<'_>>,
) -> Result<Option<(Receipt, Recipient)>, DirectiveError> {
    recover_existing_inner(base, now, _fs, session, token, intent, false)
}

/// Retry recovery refuses absent authority; it never initializes or repairs it.
pub fn recover_existing_for_retry(
    base: &Path,
    now: u64,
    fs: &FsOps<'_>,
    session: &VerifiedSession,
    token: &str,
    intent: Option<Intent<'_>>,
) -> Result<Option<(Receipt, Recipient)>, DirectiveError> {
    recover_existing_inner(base, now, fs, session, token, intent, true)
}

fn recover_existing_inner(
    base: &Path,
    now: u64,
    _fs: &FsOps<'_>,
    session: &VerifiedSession,
    token: &str,
    intent: Option<Intent<'_>>,
    require_initialized: bool,
) -> Result<Option<(Receipt, Recipient)>, DirectiveError> {
    super::limits::check_sender(session.sender())?;
    let timestamp = issued(token).map_err(|_| {
        DirectiveError::new(
            csq_sdk::SdkErrorCode::InvalidIdempotencyKey,
            "idempotency key must be epoch.UUIDv4; resend WITHOUT idempotency_key",
        )
    })?;
    let dir = store::store_dir(base);
    if !check_store_dir_as(LABEL, base).map_err(|e| e.with_cause(Cause::LedgerRead))? {
        return Err(uncertain().with_cause(Cause::LedgerRead));
    }
    let marker_path = base.join(".message-requests-initialized");
    let marker = read_regular_bounded_as(LABEL, &marker_path, 64)
        .map_err(|e| e.into_err_as(LABEL).with_cause(Cause::LedgerRead))?;
    let requests = dir.join("requests");
    if marker.is_none()
        && !check_store_dir_as(LABEL, &requests).map_err(|e| e.with_cause(Cause::LedgerRead))?
    {
        if require_initialized {
            return Err(uncertain().with_cause(Cause::LedgerRead));
        }
        return Ok(None);
    }
    #[cfg(test)]
    let wait_started = std::time::Instant::now();
    let guard = acquire_existing_lock(&dir.join(".lock"))?;
    #[cfg(test)]
    tests::note_positive_lock_wait(wait_started.elapsed());
    if !check_store_dir_as(LABEL, &requests).map_err(|e| e.with_cause(Cause::LedgerRead))? {
        return Err(uncertain().with_cause(Cause::LedgerRead));
    }
    let marker = read_regular_bounded_as(LABEL, &marker_path, 64)
        .map_err(|e| e.into_err_as(LABEL).with_cause(Cause::LedgerRead))?
        .ok_or_else(|| uncertain().with_cause(Cause::LedgerRead))?;
    let text = read_regular_bounded_as(LABEL, &requests.join("ledger.json"), MAX_RECORD_BYTES)
        .map_err(|e| e.into_err_as(LABEL).with_cause(Cause::LedgerRead))?
        .ok_or_else(|| uncertain().with_cause(Cause::LedgerRead))?;
    let ledger =
        decode_ledger(&text, &marker, None).map_err(|e| e.with_cause(Cause::LedgerRead))?;
    if issued(&ledger.init).map_err(|_| uncertain().with_cause(Cause::LedgerRead))? > ledger.clock {
        return Err(uncertain().with_cause(Cause::LedgerRead));
    }
    let id = request_id(session.sender(), token)?;
    let result = match ledger.entries.get(&id) {
        None => None,
        Some(entry) => {
            if entry.issued != timestamp {
                return Err(uncertain().with_cause(Cause::LedgerRead));
            }
            if intent
                .map(intent_digest)
                .transpose()?
                .is_some_and(|intent| intent != entry.intent)
            {
                return Err(DirectiveError::invalid(
                    "request key was used with different intent",
                ));
            }
            if !entry.committed {
                let record = public_record(&dir, &id, now.max(ledger.clock))?
                    .ok_or_else(|| uncertain().with_cause(Cause::RecordUncertain))?;
                if record_digest(&record)? != entry.record
                    || record.id != entry.receipt.id
                    || record.thread != entry.receipt.thread
                    || record.created_at != entry.receipt.created_at
                    || record.to != entry.to
                {
                    return Err(uncertain().with_cause(Cause::RecordUncertain));
                }
            }
            Some((entry.receipt.clone(), entry.to))
        }
    };
    if !guard.matches_path() {
        return Err(uncertain().with_cause(Cause::LockUnavailable));
    }
    Ok(result)
}
#[cfg(unix)]
fn acquire_existing_lock(
    path: &Path,
) -> Result<crate::sessions::directives::ExistingMessageStoreLock, DirectiveError> {
    crate::sessions::directives::acquire_existing_message_store_lock_as(LABEL, path)
}
/// Windows store locks are named mutexes keyed by the lock PATH, so the mutex alone binds
/// no file. Recovery binds the path to a file IDENTITY instead, as the unix guard binds its
/// flock inode: before the wait it opens the lock file and its directory with
/// `FILE_FLAG_OPEN_REPARSE_POINT` (a junction or symlink is opened as itself, then refused)
/// and records each handle's volume serial number and file index; after the wait, and
/// again before the result is returned, it re-opens both paths the same way and refuses
/// unless both identities still match. Recovery never initializes: the lock file must
/// already exist (`under_lock_with_admission_clock`, and the keyed send pass in
/// `store::do_send_with_admission_clock`, create it under the held mutex).
#[cfg(windows)]
struct ExistingLock {
    _lock: crate::platform::lock::FileLockGuard,
    path: std::path::PathBuf,
    file: (u32, u64),
    directory: (u32, u64),
}
#[cfg(windows)]
impl ExistingLock {
    /// A CONSISTENCY check, not the lock. Mutual exclusion is the path-keyed named mutex
    /// held in `_lock`; this only confirms that the lock file and its directory at `path`
    /// are still the objects whose identities were recorded before the wait, so recovery
    /// refuses when the path was re-pointed. A `true` here grants nothing the mutex does
    /// not already hold, and two re-opens are not atomic with each other or with the caller.
    fn matches_path(&self) -> bool {
        let Some(parent) = self.path.parent() else {
            return false;
        };
        windows_lock_identity(&self.path, false).is_some_and(|id| id == self.file)
            && windows_lock_identity(parent, true).is_some_and(|id| id == self.directory)
    }
}
/// Handle identity of `path` opened without following reparse points; `None` refuses.
/// A file must be a regular, single-link, non-reparse file (the shared
/// `windows_file_identity` contract); a directory must be a non-reparse directory.
#[cfg(windows)]
fn windows_lock_identity(path: &Path, directory: bool) -> Option<(u32, u64)> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let flags = if directory {
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
    } else {
        FILE_FLAG_OPEN_REPARSE_POINT
    };
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .ok()?;
    if !directory {
        let metadata = held.metadata().ok()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return None;
        }
        return crate::accounts::anthropic_identity::windows_file_identity(&held).ok();
    }
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `held` owns a live handle for this call and `info` is writable storage.
    let ok = unsafe { GetFileInformationByHandle(held.as_raw_handle() as _, info.as_mut_ptr()) };
    if ok == 0 {
        return None;
    }
    // SAFETY: a successful call initialized the structure.
    let info = unsafe { info.assume_init() };
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return None;
    }
    Some((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}
/// The Windows recovery-lock wait: 50 x 100 ms (5 s) in EVERY build. It is not
/// test-scaled: the unix existing-lock wait uses `LOCK_ATTEMPTS`/`LOCK_DELAY`, which differ
/// between the production and the test build (the test build is 100 x 5 ms), so this
/// constant is a fixed Windows budget, not a mirror of unix. A test holder that outlives
/// one second therefore still contends rather than timing the recovery out early.
#[cfg(windows)]
const EXISTING_LOCK_ATTEMPTS: u32 = 50;
#[cfg(windows)]
const EXISTING_LOCK_DELAY: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(windows)]
fn acquire_existing_lock(path: &Path) -> Result<ExistingLock, DirectiveError> {
    let bad = || {
        DirectiveError::undet(format!("{LABEL}: existing lock unavailable"))
            .with_cause(Cause::LockUnavailable)
    };
    let parent = path.parent().ok_or_else(bad)?;
    let file = windows_lock_identity(path, false).ok_or_else(bad)?;
    let directory = windows_lock_identity(parent, true).ok_or_else(bad)?;
    // The wait itself is the mutex; a timeout carries the same typed cause as unix.
    let lock = crate::platform::lock::try_lock_file_bounded(
        path,
        EXISTING_LOCK_ATTEMPTS,
        EXISTING_LOCK_DELAY,
    )
    .map_err(|_| bad())?
    .ok_or_else(|| {
        DirectiveError::undet(format!("{LABEL}: existing lock timed out"))
            .with_cause(Cause::LockTimeout)
    })?;
    let guard = ExistingLock {
        _lock: lock,
        path: path.to_path_buf(),
        file,
        directory,
    };
    if !guard.matches_path() {
        return Err(bad());
    }
    Ok(guard)
}
/// Create the Windows lock file under the held store mutex so positive recovery has an
/// identity to bind. An existing entry must be a regular, non-reparse file: a directory,
/// junction, symlink or other reparse point planted at `.lock` refuses here with an
/// operator-readable reason, rather than letting the write proceed and every later
/// positive recovery refuse with no reason. A regular entry is then judged by
/// `refuse_hard_linked_lock` (reparse attribute, link count); the file index is still
/// left for recovery's checks to judge.
#[cfg(windows)]
pub(super) fn ensure_windows_lock_file(path: &Path) -> Result<(), DirectiveError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    // Inspect BEFORE creating: `CreateFile` on an existing directory with write access
    // fails with ERROR_ACCESS_DENIED (not ERROR_FILE_EXISTS), which `create_new` reports as
    // PermissionDenied and never as AlreadyExists, so a planted directory must be judged
    // from its own metadata, not from the kind of the create error.
    let regular = |existing: &std::fs::Metadata| {
        existing.file_type().is_file()
            && !existing.file_type().is_symlink()
            && existing.file_attributes()
                & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                == 0
    };
    match std::fs::symlink_metadata(path) {
        Ok(existing) if regular(&existing) => return refuse_hard_linked_lock(path),
        Ok(_) => return Err(windows_planted_lock_error()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(DirectiveError::undetermined(
                "message store: inspect request lock",
                e.kind(),
            )
            .with_cause(Cause::LockUnavailable))
        }
    }
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost a creation race: judge what the winner left, same as above.
            let existing = std::fs::symlink_metadata(path).map_err(|e| {
                DirectiveError::undetermined("message store: inspect request lock", e.kind())
                    .with_cause(Cause::LockUnavailable)
            })?;
            if regular(&existing) {
                refuse_hard_linked_lock(path)
            } else {
                Err(windows_planted_lock_error())
            }
        }
        Err(e) => Err(
            DirectiveError::undetermined("message store: create request lock", e.kind())
                .with_cause(Cause::LockUnavailable),
        ),
    }
}
/// Refuse a regular `.lock` that has more than one hard link: another name for the same
/// file means the lock identity is shared with a path the store does not control. Opened
/// with `FILE_FLAG_OPEN_REPARSE_POINT`, then judged from one handle query: a reparse
/// attribute is a planted lock (`windows_planted_lock_error`), a link count above one is
/// the hard-link refusal, and a count of zero is a planted-lock refusal too, and an
/// unreadable handle is its own `windows_uninspectable_lock_error` (all
/// `Cause::LockUnavailable`), fail closed.
#[cfg(windows)]
fn refuse_hard_linked_lock(path: &Path) -> Result<(), DirectiveError> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT,
    };
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| {
            DirectiveError::undetermined("message store: inspect request lock", e.kind())
                .with_cause(Cause::LockUnavailable)
        })?;
    // SAFETY: zero is a valid buffer; the API fills it synchronously from the
    // live owned handle and retains no pointer.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(held.as_raw_handle() as isize, &mut info) } == 0 {
        return Err(windows_uninspectable_lock_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(windows_planted_lock_error());
    }
    match info.nNumberOfLinks {
        1 => Ok(()),
        0 => Err(windows_planted_lock_error()),
        _ => Err(windows_hard_linked_lock_error()),
    }
}
/// The fixed refusal for a hard-linked `.lock` (link count above one).
#[cfg(windows)]
fn windows_hard_linked_lock_error() -> DirectiveError {
    DirectiveError::undet(
        "message store: request lock is a hard link (it has more than one name); remove \
         the extra link to restore keyed requests",
    )
    .with_cause(Cause::LockUnavailable)
}
/// The fixed refusal when the Windows `.lock` handle could not be queried: the
/// state is unknown, which is not evidence of a planted object.
#[cfg(windows)]
fn windows_uninspectable_lock_error() -> DirectiveError {
    DirectiveError::undet(
        "message store: could not inspect request lock (its handle information was \
         unreadable); retry, or check the .lock file's permissions",
    )
    .with_cause(Cause::LockUnavailable)
}
/// The fixed refusal for a non-regular object at the Windows `.lock` path.
#[cfg(windows)]
fn windows_planted_lock_error() -> DirectiveError {
    DirectiveError::undet(
        "message store: request lock is not a regular file (a directory, junction or link \
         is at .lock); remove it to restore keyed requests",
    )
    .with_cause(Cause::LockUnavailable)
}
/// No handle-identity primitive is implemented for this target: recovery refuses.
#[cfg(not(any(unix, windows)))]
struct ExistingLock;
#[cfg(not(any(unix, windows)))]
impl ExistingLock {
    fn matches_path(&self) -> bool {
        false
    }
}
#[cfg(not(any(unix, windows)))]
fn acquire_existing_lock(_path: &Path) -> Result<ExistingLock, DirectiveError> {
    Err(
        DirectiveError::undet(format!("{LABEL}: existing lock identity unavailable"))
            .with_cause(Cause::LockUnavailable),
    )
}

/// A sender-bound historical query; missing or unreadable authority remains undetermined.
pub fn lookup(
    base: &Path,
    now: u64,
    fs: &FsOps<'_>,
    session: &VerifiedSession,
    token: &str,
) -> Result<Lookup, DirectiveError> {
    lookup_with_admission_clock(
        base,
        AdmissionClock::asserted(now.into()),
        fs,
        session,
        token,
    )
}
pub fn lookup_with_admission_clock(
    base: &Path,
    now: AdmissionClock<'_>,
    fs: &FsOps<'_>,
    session: &VerifiedSession,
    token: &str,
) -> Result<Lookup, DirectiveError> {
    let admission = now;
    let now = admission.original.observed;
    let started = std::time::Instant::now();
    super::limits::check_sender(session.sender())?;
    if let Some((receipt, recipient)) = recover_existing(base, now, fs, session, token, None)? {
        return Ok(Lookup::Stored(receipt, recipient));
    }
    let timestamp = issued(token).map_err(|_| {
        DirectiveError::new(
            csq_sdk::SdkErrorCode::InvalidIdempotencyKey,
            "idempotency key must be epoch.UUIDv4",
        )
    })?;
    if timestamp > now {
        return Err(DirectiveError::new(
            csq_sdk::SdkErrorCode::InvalidIdempotencyKey,
            "idempotency key is in the future",
        ));
    }
    under_lock_with_admission_clock(base, admission, |dir, now, upper| {
        let upper = upper.max(decision_time(now, started));
        let mut ledger = open(dir, now, upper, fs, false)?;
        if upper - timestamp >= WINDOW_SECS {
            return Err(DirectiveError::new(
                csq_sdk::SdkErrorCode::Undetermined,
                "idempotency key expired; prior outcome is unrecoverable",
            ));
        }
        validate(token, upper)?;
        if issued(token)? <= ledger.floor {
            return Err(uncertain());
        }
        outcome(
            dir,
            now,
            fs,
            &mut ledger,
            &request_id(session.sender(), token)?,
        )
    })
}
/// Send once per immutable sender incarnation and token, preserving original addressing.
#[allow(clippy::too_many_arguments)]
pub fn send(
    base: &Path,
    now: impl Into<Clock>,
    fs: &FsOps<'_>,
    limits: &Limits,
    live: &dyn Fn(&Recipient) -> Liveness,
    session: &VerifiedSession,
    to: Recipient,
    raw_target: &str,
    body: &str,
    parent: Option<&str>,
    token: &str,
) -> Result<(Receipt, Recipient), DirectiveError> {
    send_with_admission_clock(
        base,
        AdmissionClock::asserted(now.into()),
        fs,
        limits,
        live,
        session,
        to,
        raw_target,
        body,
        parent,
        token,
        true,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn send_with_admission_clock(
    base: &Path,
    now: AdmissionClock<'_>,
    fs: &FsOps<'_>,
    limits: &Limits,
    live: &dyn Fn(&Recipient) -> Liveness,
    session: &VerifiedSession,
    to: Recipient,
    raw_target: &str,
    body: &str,
    parent: Option<&str>,
    token: &str,
    wake: bool,
) -> Result<(Receipt, Recipient), DirectiveError> {
    let admission = now;
    let clock = admission.original;
    let now = clock.observed;
    if issued(token)? > now {
        return Err(uncertain().with_cause(Cause::Clock));
    }
    store::do_send_with_admission_clock(
        base,
        now,
        fs,
        limits,
        live,
        session,
        Dest::To(to, parent),
        body,
        Some((
            token,
            clock,
            Intent::Send {
                target: raw_target,
                parent,
                body,
                wake,
            },
        )),
        Some(&admission),
    )
}
/// Reply retries do not require the already-committed request's parent to remain present.
#[allow(clippy::too_many_arguments)]
pub fn reply(
    base: &Path,
    now: impl Into<Clock>,
    fs: &FsOps<'_>,
    limits: &Limits,
    live: &dyn Fn(&Recipient) -> Liveness,
    session: &VerifiedSession,
    parent: &str,
    body: &str,
    token: &str,
) -> Result<(Receipt, Recipient), DirectiveError> {
    reply_with_admission_clock(
        base,
        AdmissionClock::asserted(now.into()),
        fs,
        limits,
        live,
        session,
        parent,
        body,
        token,
        true,
    )
}
#[allow(clippy::too_many_arguments)]
pub fn reply_with_admission_clock(
    base: &Path,
    now: AdmissionClock<'_>,
    fs: &FsOps<'_>,
    limits: &Limits,
    live: &dyn Fn(&Recipient) -> Liveness,
    session: &VerifiedSession,
    parent: &str,
    body: &str,
    token: &str,
    wake: bool,
) -> Result<(Receipt, Recipient), DirectiveError> {
    let admission = now;
    let clock = admission.original;
    let now = clock.observed;
    if issued(token)? > now {
        return Err(uncertain().with_cause(Cause::Clock));
    }
    store::do_send_with_admission_clock(
        base,
        now,
        fs,
        limits,
        live,
        session,
        Dest::ReplyTo(parent),
        body,
        Some((token, clock, Intent::Reply { parent, body, wake })),
        Some(&admission),
    )
}
#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;

/// Pin exact start evidence only in external test fixtures; unavailable in production builds.
#[cfg(feature = "test-utils")]
pub fn pin_test_session(session: VerifiedSession, exact: u64) -> VerifiedSession {
    let mut sender = session.sender().clone();
    sender.started_exact = Some(exact);
    VerifiedSession::from_resolved(sender)
}

// Contention fixtures hold the lock with `libc::flock`, which only exists on unix.
#[cfg(all(test, unix))]
#[path = "clock_admission_tests.rs"]
mod clock_admission_tests;

#[cfg(test)]
#[path = "clock_late_publication_tests.rs"]
mod clock_late_publication_tests;

#[cfg(test)]
#[path = "request_admission_provider_tests.rs"]
mod admission_provider_tests;

#[cfg(test)]
mod intent_wire_tests {
    use super::*;

    /// The digest input of a default request is frozen: dropping `skip_serializing_if` would
    /// add `"wake":true` and make every pre-flag stored key refuse its own retry.
    #[test]
    fn a_default_intent_serializes_without_a_wake_field_and_no_wake_adds_it() {
        let send = |wake| Intent::Send {
            target: "t",
            parent: None,
            body: "b",
            wake,
        };
        assert_eq!(
            serde_json::to_string(&send(true)).unwrap(),
            r#"{"Send":{"target":"t","parent":null,"body":"b"}}"#
        );
        assert_eq!(
            serde_json::to_string(&send(false)).unwrap(),
            r#"{"Send":{"target":"t","parent":null,"body":"b","wake":false}}"#
        );
        let reply = |wake| Intent::Reply {
            parent: "p",
            body: "b",
            wake,
        };
        assert_eq!(
            serde_json::to_string(&reply(true)).unwrap(),
            r#"{"Reply":{"parent":"p","body":"b"}}"#
        );
        assert_ne!(
            digest(send(true)).unwrap(),
            digest(send(false)).unwrap(),
            "a retry that flips wake must not match its original"
        );
    }
}
