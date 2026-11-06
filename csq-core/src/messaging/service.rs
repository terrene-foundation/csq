//! Registered service identities (design an internal ticket, workspace `service-sender`).
//!
//! A *service* is a non-session identity a same-UID process may claim so scheduled jobs
//! can send csq messages. It is NOT an approval and never renders as a session: see
//! `Origin::Service` and the frame header. Registration is not exclusivity (ROOT
//! amendment A): any same-UID process can register a name; the protection is the
//! `service:<name>` framing, the audit trail of every admission and refusal, and
//! revocability.
//!
//! Registry layout: `<base>/services/<name>.json`, directory `0700`, records `0600`,
//! written through the target-taking private-tmp factory (`write_private_tmp_synced_retained`)
//! and published with `replace`/`publish_noreplace`. The factory's retained writer owns
//! cleanup on every failure branch (`security.md` §4/§5a), and the non-force publish is
//! exclusive (`publish_noreplace`), so two concurrent `register` calls cannot silently
//! overwrite each other.
//!
//! Read path: [`load`] opens the record without following a link — `O_NOFOLLOW` on Unix,
//! `FILE_FLAG_OPEN_REPARSE_POINT` on Windows — and judges it from the open handle: on Unix a
//! regular file, owned by the current euid, with no group/other mode bits, ≤ 4 KiB; on
//! Windows a regular, single-link, non-reparse file (no POSIX owner/mode bits exist there).
//! It then checks the record body (`v == 1`, the requested name, a canonical UUIDv4
//! `registration_id`, a nonzero `created_at`, and `uid == peer_uid`). ANY failure refuses: an
//! unreadable or ambiguous registry never admits a send (`guard-reader-writer-parity` MUST-2).

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The daemon route a service send POSTs to (Unix socket only).
pub const SEND_SERVICE_ROUTE: &str = "/api/message/send-service";

/// Longest service name, in bytes (the grammar is ASCII).
pub const SERVICE_NAME_MAX: usize = 32;

/// Longest registry record accepted on the read path.
pub const RECORD_MAX_BYTES: u64 = 4096;

/// A fixed refusal tag. Every value reachable here is in the design's closed vocabulary
/// (§11); none carries request text.
pub type Tag = &'static str;

// ── name grammar ────────────────────────────────────────────────────────

/// Whether `name` is one of the RESERVED shapes that could pass for a session label or a
/// target: `term-<digits>`, a lowercase 8-4-4-4-12 UUID, or the literals `claude-code`,
/// `codex`, `service`.
fn is_reserved(name: &str) -> bool {
    if matches!(name, "claude-code" | "codex" | "service") {
        return true;
    }
    if let Some(digits) = name.strip_prefix("term-") {
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    }
    is_lowercase_uuid(name)
}

/// Exactly a lowercase 8-4-4-4-12 hex UUID (this deliberately ignores the length cap so a
/// UUID is reported as RESERVED rather than merely malformed).
fn is_lowercase_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
}

/// The bare §11.4 name grammar, WITHOUT the reserved-shape check: `^[a-z0-9][a-z0-9-]{0,31}$`.
///
/// This is the predicate an AUDIT record may rely on before echoing a caller-supplied name
/// (`EventKind::ServiceMessageRefused`). A reserved spelling that still fits the grammar
/// (`term-<digits>`, `claude-code`/`codex`/`service`) PASSES it — it is safe to record — even
/// though [`validate_service_name`] refuses to register or send as it. A lowercase UUID is
/// 36 bytes, so it fails the length cap and is NOT recorded (nothing over 32 bytes is).
#[must_use]
pub fn grammar_ok(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > SERVICE_NAME_MAX {
        return false;
    }
    (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

/// `^[a-z0-9][a-z0-9-]{0,31}$`, then the reserved shapes. A fixed charset with no path
/// characters, no `:` and no `.`, safe to place on the audit chain and in a file name.
pub fn validate_service_name(name: &str) -> Result<(), Tag> {
    if is_reserved(name) {
        return Err("service_name_reserved");
    }
    if grammar_ok(name) {
        Ok(())
    } else {
        Err("service_name_invalid")
    }
}

/// Whether `s` is a canonical lowercase hyphenated UUID **version 4** — the shape
/// [`register`] mints for `registration_id`. Used by the read path and by every render
/// that re-checks a stored service reference.
#[must_use]
pub fn is_registration_id(s: &str) -> bool {
    if !crate::sessions::directives::canonical_uuid(s) {
        return false;
    }
    match uuid::Uuid::parse_str(s) {
        Ok(uuid) => {
            let bytes = uuid.as_bytes();
            bytes[6] >> 4 == 4 && bytes[8] & 0xc0 == 0x80
        }
        Err(_) => false,
    }
}

// ── record + paths ─────────────────────────────────────────────────────

/// One registered service. The registry file is the only authority; `list` shows
/// `created_at` and `registration_id` so an owner can spot a registration they did not
/// create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecord {
    /// Record schema version; only `1` is accepted.
    pub v: u32,
    /// The registered name (grammar re-checked on every load).
    pub name: String,
    /// The creating effective uid. A record whose uid differs from the daemon's peer uid
    /// grants nothing.
    pub uid: u32,
    /// Fresh UUIDv4 minted on every registration (and re-registration).
    pub registration_id: String,
    /// Unix seconds at registration.
    pub created_at: u64,
}

/// `<base>/services`.
#[must_use]
pub fn service_dir(base: &Path) -> PathBuf {
    base.join("services")
}

/// `<base>/services/<name>.json`. Callers MUST validate `name` first; every function in
/// this module does, so a traversal spelling never reaches the path join.
#[must_use]
pub fn record_path(base: &Path, name: &str) -> PathBuf {
    service_dir(base).join(format!("{name}.json"))
}

/// The daemon process's (== the listener-verified peer's) effective uid. On non-Unix
/// targets there is no peer credential; the route refuses before calling the registry.
#[must_use]
pub fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid() takes no arguments, reads no memory and cannot fail.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// The caller's uid where the platform HAS a uid; `None` elsewhere.
///
/// A signed refusal record must not assert a uid that does not exist: `0` is never
/// fabricated on a platform without uids. [`current_uid`] keeps its numeric return for the
/// registry `uid` gate, which is only reachable on Unix (the route refuses earlier on the
/// other targets).
#[must_use]
pub fn current_uid_opt() -> Option<u32> {
    #[cfg(unix)]
    {
        Some(current_uid())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

// ── read path ───────────────────────────────────────────────────────────

/// Open the record without following a symlink and without blocking on a FIFO swapped in
/// for a regular file.
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
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
        // Open a reparse point AS ITSELF (the `O_NOFOLLOW` analogue), so the handle check
        // below judges the planted object rather than its target.
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

/// Fail-closed judgement of the open handle: a regular file, owned by the current euid, with
/// no group/other mode bits. Sampled from the handle (`fstat`) so a swap after the open
/// cannot redirect the read.
#[cfg(unix)]
fn check_record_handle(file: &std::fs::File) -> bool {
    use std::os::unix::fs::MetadataExt;
    match file.metadata() {
        Ok(meta) => {
            meta.is_file()
                && meta.uid() == current_uid()
                && meta.mode() & 0o077 == 0
                && meta.len() <= RECORD_MAX_BYTES
        }
        Err(_) => false,
    }
}

/// Windows has no POSIX owner/mode bits: the record is judged from the open handle as a
/// regular, single-link, non-reparse file (`windows_file_identity`), which is the platform's
/// equivalent of the Unix no-symlink/private-file judgement. Ownership is the per-user
/// profile ACL the registry directory inherits; the spec states this platform split.
#[cfg(windows)]
fn check_record_handle(file: &std::fs::File) -> bool {
    match file.metadata() {
        Ok(meta) => {
            meta.is_file()
                && meta.len() <= RECORD_MAX_BYTES
                && crate::accounts::anthropic_identity::windows_file_identity(file).is_ok()
        }
        Err(_) => false,
    }
}

#[cfg(not(any(unix, windows)))]
fn check_record_handle(file: &std::fs::File) -> bool {
    match file.metadata() {
        Ok(meta) => meta.is_file() && meta.len() <= RECORD_MAX_BYTES,
        Err(_) => false,
    }
}

/// The registry directory must be a real directory owned by us with no group/other access.
/// On Windows there are no POSIX mode bits or uid, so the checks are: a real directory (not
/// a symlink or any other reparse point — a junction is a reparse point too).
fn check_registry_dir(dir: &Path) -> Result<(), Tag> {
    let meta = std::fs::symlink_metadata(dir).map_err(|_| "service_registry_unreadable")?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err("service_registry_unreadable");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.uid() != current_uid() || meta.mode() & 0o077 != 0 {
            return Err("service_registry_unreadable");
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err("service_registry_unreadable");
        }
    }
    Ok(())
}

/// Load and fully validate `<base>/services/<name>.json`.
///
/// `peer_uid` is the listener-verified caller. The record's `uid` must equal it; a
/// registry copied from another account grants nothing. A missing record is
/// `service_unknown`; every other unreadable or inconsistent state is
/// `service_registry_unreadable` (fail closed).
pub fn load(base: &Path, name: &str, peer_uid: u32) -> Result<ServiceRecord, Tag> {
    validate_service_name(name)?;
    // No registry directory means no registration: that is `service_unknown`, not an
    // unreadable registry. Anything else (a symlink, a non-directory, a foreign/loose
    // directory) is fail-closed `service_registry_unreadable`.
    match std::fs::symlink_metadata(service_dir(base)) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("service_unknown")
        }
        Err(_) => return Err("service_registry_unreadable"),
    }
    check_registry_dir(&service_dir(base))?;
    let path = record_path(base, name);
    let file = match open_nofollow(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err("service_unknown")
        }
        Err(_) => return Err("service_registry_unreadable"),
    };
    if !check_record_handle(&file) {
        return Err("service_registry_unreadable");
    }
    let mut bytes = Vec::new();
    file.take(RECORD_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "service_registry_unreadable")?;
    if bytes.len() as u64 > RECORD_MAX_BYTES {
        return Err("service_registry_unreadable");
    }
    let text = String::from_utf8(bytes).map_err(|_| "service_registry_unreadable")?;
    let record: ServiceRecord =
        serde_json::from_str(&text).map_err(|_| "service_registry_unreadable")?;
    if record.v != 1
        || record.name != name
        || !is_registration_id(&record.registration_id)
        || record.created_at == 0
    {
        return Err("service_registry_unreadable");
    }
    if record.uid != peer_uid {
        return Err("service_uid_mismatch");
    }
    Ok(record)
}

// ── write path ──────────────────────────────────────────────────────────

/// Register `name` for the current euid and return the minted record.
///
/// Reads the euid internally: the caller cannot choose which uid a record binds to. An
/// existing record refuses with `service_exists` unless `force`; a forced registration
/// mints a fresh `registration_id`, so the old identity's idempotency keys do not replay
/// against the new one.
pub fn register(base: &Path, name: &str, now: u64, force: bool) -> Result<ServiceRecord, Tag> {
    validate_service_name(name)?;
    // `created_at == 0` is the record's own "unreadable" marker on the load path (a 1970
    // clock is not a registration time any real reader can distinguish from a corrupt
    // record). Refuse it at the WRITE, so a registration that can never load is never
    // reported as registered.
    if now == 0 {
        return Err("undetermined");
    }
    let dir = service_dir(base);
    crate::platform::fs::ensure_private_dir(&dir).map_err(|_| "service_registry_unreadable")?;
    check_registry_dir(&dir)?;
    let path = record_path(base, name);
    let record = ServiceRecord {
        v: 1,
        name: name.to_string(),
        uid: current_uid(),
        registration_id: uuid::Uuid::new_v4().hyphenated().to_string(),
        created_at: now,
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| "service_registry_unreadable")?;
    // The target-taking retained factory creates the temp `0600` (private by creation),
    // syncs it, and owns its cleanup on Drop — including every failure branch below and a
    // failed exclusive create (`security.md` §5a). Publication is a rename/link, never a
    // write in place.
    let writer = crate::platform::fs::write_private_tmp_synced_retained(&path, &bytes)
        .map_err(|_| "service_registry_unreadable")?;
    if force {
        writer
            .replace(&path)
            .map_err(|_| "service_registry_unreadable")?;
    } else {
        use crate::platform::fs::PublishOutcome;
        match writer
            .publish_noreplace(&path)
            .map_err(|_| "service_registry_unreadable")?
        {
            PublishOutcome::Published => {}
            PublishOutcome::AlreadyExists => return Err("service_exists"),
        }
    }
    Ok(record)
}

/// Unlink the record. The daemon reads per send (no cache), so the NEXT send refuses.
pub fn revoke(base: &Path, name: &str) -> Result<(), Tag> {
    validate_service_name(name)?;
    let path = record_path(base, name);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            // Not the regular record this module writes: refuse rather than unlink an
            // object whose meaning we cannot prove (the load path refuses it too).
            Err("service_registry_unreadable")
        }
        Ok(_) => std::fs::remove_file(&path).map_err(|_| "service_registry_unreadable"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err("service_unknown"),
        Err(_) => Err("service_registry_unreadable"),
    }
}

/// Every readable record (sorted by name) and the number of entries that could not be read
/// or validated. An unreadable entry is reported, never silently dropped; a missing
/// registry directory is an empty registry.
pub fn list(base: &Path) -> Result<(Vec<ServiceRecord>, usize), Tag> {
    let dir = service_dir(base);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(_) => return Err("service_registry_unreadable"),
    };
    check_registry_dir(&dir)?;
    let uid = current_uid();
    let mut records = Vec::new();
    let mut unreadable = 0usize;
    for entry in entries {
        let Ok(entry) = entry else {
            unreadable += 1;
            continue;
        };
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        match load(base, stem, uid) {
            Ok(record) => records.push(record),
            Err(_) => unreadable += 1,
        }
    }
    records.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((records, unreadable))
}

// ── verified wrapper ────────────────────────────────────────────────────

/// A [`ServiceRecord`] the daemon loaded and validated for an admission. Only the daemon
/// route constructs one, after [`load`] proved the record against the peer uid; the store
/// takes it instead of a raw record so no other surface can mint a service sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedService {
    record: ServiceRecord,
}

impl VerifiedService {
    /// Wrap a record [`load`] returned. `pub(crate)` on purpose: the daemon route is the
    /// only production caller, and visibility (not a comment) is what stops another
    /// in-crate surface from wrapping an unvalidated record.
    #[cfg_attr(not(unix), allow(dead_code))] // the only production caller is the Unix-only route
    #[must_use]
    pub(crate) fn from_record(record: ServiceRecord) -> Self {
        Self { record }
    }

    /// The validated record.
    #[must_use]
    pub fn record(&self) -> &ServiceRecord {
        &self.record
    }
}

// ── wire types ──────────────────────────────────────────────────────────

/// Body of [`SEND_SERVICE_ROUTE`]. `deny_unknown_fields`: an extra field is a refusal, never
/// silently ignored. The caller's identity is NOT here — it comes from the socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendServiceRequest {
    /// Registered service name.
    pub service: String,
    /// `<pid>:<started_at>` of the addressed live session.
    pub target: String,
    /// Message body.
    pub message: String,
    /// Optional message id this answers (refused for a service; see `service_no_inbox`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    /// Optional idempotency key, `epoch.UUIDv4`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Wake the recipient (always true for a Codex recipient).
    #[serde(default = "default_wake")]
    pub wake: bool,
}

fn default_wake() -> bool {
    true
}

/// The addressed session on a service-send receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendServiceTo {
    /// Process id.
    pub pid: u32,
    /// Process start, unix seconds.
    pub started_at: u64,
    /// Wire surface name (`claude-code` / `codex`).
    pub surface: String,
}

/// Success answer of [`SEND_SERVICE_ROUTE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendServiceResponse {
    /// The ordinary message receipt.
    pub receipt: super::model::Receipt,
    /// The re-verified recipient the daemon actually stored to.
    pub to: SendServiceTo,
}

/// Error answer of [`SEND_SERVICE_ROUTE`]: one fixed tag, never request text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendServiceError {
    /// Fixed refusal tag.
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn base() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn name_grammar_accepts_the_documented_shape() {
        for name in [
            "a",
            "job-1",
            "nightly-backup-2026",
            &"x".repeat(SERVICE_NAME_MAX),
        ] {
            assert!(validate_service_name(name).is_ok(), "{name:?}");
        }
        assert!(validate_service_name("9lives").is_ok());
    }

    #[test]
    fn name_grammar_refuses_invalid_shapes() {
        for name in [
            "",
            "-leading",
            "Upper",
            "has space",
            "has.dot",
            "has/slash",
            "has:colon",
            "under_score",
            &"x".repeat(SERVICE_NAME_MAX + 1),
        ] {
            assert_eq!(
                validate_service_name(name),
                Err("service_name_invalid"),
                "{name:?}"
            );
        }
    }

    #[test]
    fn reserved_shapes_are_refused_by_their_own_tag() {
        let uuid = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
        assert_eq!(validate_service_name(uuid), Err("service_name_reserved"));
        for name in ["term-12", "term-0", "claude-code", "codex", "service"] {
            assert_eq!(
                validate_service_name(name),
                Err("service_name_reserved"),
                "{name}"
            );
        }
    }

    #[test]
    fn non_reserved_near_misses_are_allowed() {
        for name in ["term-", "term-12x", "term", "claude", "codes", "term-1-2"] {
            assert!(validate_service_name(name).is_ok(), "{name}");
        }
    }

    /// The audit predicate: the bare grammar accepts a reserved-but-safe spelling that
    /// `validate_service_name` refuses, and refuses everything the grammar cannot safely
    /// place on the chain.
    #[test]
    fn grammar_ok_is_the_bare_charset_and_length_rule() {
        for name in [
            "nightly",
            "a",
            &"x".repeat(SERVICE_NAME_MAX),
            "term-34743",
            "claude-code",
        ] {
            assert!(grammar_ok(name), "{name:?}");
        }
        for name in [
            "",
            "-leading",
            "Upper",
            "has space",
            "has.dot",
            "has/slash",
            "has:colon",
            &"x".repeat(SERVICE_NAME_MAX + 1),
            // A lowercase UUID is reserved but 36 bytes: over the grammar's length cap, so
            // it is never echoed into the chain.
            "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
        ] {
            assert!(!grammar_ok(name), "{name:?}");
        }
        // Reserved shapes pass the grammar but are refused as sendable names.
        assert!(grammar_ok("term-1"));
        assert_eq!(
            validate_service_name("term-1"),
            Err("service_name_reserved")
        );
    }

    #[test]
    fn a_registration_at_the_epoch_is_refused() {
        let dir = base();
        assert_eq!(
            register(dir.path(), "job", 0, false).unwrap_err(),
            "undetermined"
        );
        assert!(
            !service_dir(dir.path()).exists(),
            "a refused registration writes nothing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn register_writes_private_atomic_records_and_load_reads_them() {
        use std::os::unix::fs::MetadataExt;
        let dir = base();
        let record = register(dir.path(), "nightly", 1_700_000_000, false).unwrap();
        assert_eq!(record.v, 1);
        assert_eq!(record.name, "nightly");
        assert_eq!(record.uid, current_uid());
        assert!(is_registration_id(&record.registration_id));
        let registry = service_dir(dir.path());
        assert_eq!(
            std::fs::metadata(&registry).unwrap().mode() & 0o777,
            0o700,
            "the registry directory must be 0700"
        );
        let path = record_path(dir.path(), "nightly");
        assert_eq!(
            std::fs::metadata(&path).unwrap().mode() & 0o777,
            0o600,
            "a registry record must be 0600"
        );
        assert_eq!(load(dir.path(), "nightly", current_uid()).unwrap(), record);
    }

    #[test]
    fn register_refuses_existing_unless_force_mints_a_new_identity() {
        let dir = base();
        let first = register(dir.path(), "job", 10, false).unwrap();
        assert_eq!(
            register(dir.path(), "job", 11, false).unwrap_err(),
            "service_exists"
        );
        let forced = register(dir.path(), "job", 12, true).unwrap();
        assert_ne!(forced.registration_id, first.registration_id);
        assert_eq!(forced.created_at, 12);
        assert_eq!(
            load(dir.path(), "job", current_uid())
                .unwrap()
                .registration_id,
            forced.registration_id
        );
    }

    #[test]
    fn revoke_takes_effect_on_the_next_load() {
        let dir = base();
        register(dir.path(), "job", 10, false).unwrap();
        assert!(load(dir.path(), "job", current_uid()).is_ok());
        revoke(dir.path(), "job").unwrap();
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_unknown"
        );
        assert_eq!(revoke(dir.path(), "job").unwrap_err(), "service_unknown");
    }

    #[test]
    fn a_record_bound_to_another_uid_is_refused() {
        let dir = base();
        register(dir.path(), "job", 10, false).unwrap();
        let other = if current_uid() == 0 { 1 } else { 0 };
        assert_eq!(
            load(dir.path(), "job", other).unwrap_err(),
            "service_uid_mismatch"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_fails_closed_on_symlink_oversize_malformed_and_wrong_mode() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = base();
        register(dir.path(), "job", 10, false).unwrap();
        let path = record_path(dir.path(), "job");
        let original = std::fs::read(&path).unwrap();

        // A symlink at the record path is never followed.
        let target = service_dir(dir.path()).join("other.json");
        std::fs::write(&target, &original).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&path).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_registry_unreadable"
        );
        std::fs::remove_file(&path).unwrap();

        // Oversize.
        std::fs::write(&path, vec![b'x'; RECORD_MAX_BYTES as usize + 1]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_registry_unreadable"
        );

        // Malformed JSON.
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_registry_unreadable"
        );

        // Wrong schema version.
        std::fs::write(
            &path,
            br#"{"v":2,"name":"job","uid":0,"registration_id":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","created_at":1}"#,
        )
        .unwrap();
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_registry_unreadable"
        );

        // A name that does not match the requested record.
        std::fs::write(
            &path,
            format!(
                r#"{{"v":1,"name":"other","uid":{},"registration_id":"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","created_at":1}}"#,
                current_uid()
            ),
        )
        .unwrap();
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_registry_unreadable"
        );

        // A group-readable record is not the 0600 file this module writes.
        std::fs::write(&path, &original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_registry_unreadable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_registry_directory_is_refused() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = base();
        let elsewhere = base();
        std::fs::create_dir(elsewhere.path().join("services")).unwrap();
        std::fs::set_permissions(
            elsewhere.path().join("services"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        symlink(elsewhere.path().join("services"), service_dir(dir.path())).unwrap();
        assert_eq!(
            register(dir.path(), "job", 10, false).unwrap_err(),
            "service_registry_unreadable"
        );
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_registry_unreadable"
        );
    }

    #[test]
    fn list_reports_records_and_unreadable_entries() {
        let dir = base();
        register(dir.path(), "alpha", 10, false).unwrap();
        register(dir.path(), "beta", 20, false).unwrap();
        std::fs::write(service_dir(dir.path()).join("junk.json"), b"nope").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(service_dir(dir.path()).join("junk.json"), {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o600)
        })
        .unwrap();
        let (records, unreadable) = list(dir.path()).unwrap();
        assert_eq!(
            records.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert_eq!(unreadable, 1);
    }

    #[test]
    fn a_missing_registry_is_an_empty_list_and_unknown_service() {
        let dir = base();
        assert_eq!(list(dir.path()).unwrap(), (Vec::new(), 0));
        assert_eq!(
            load(dir.path(), "job", current_uid()).unwrap_err(),
            "service_unknown"
        );
    }

    #[test]
    fn registration_ids_are_canonical_uuids_v4() {
        let dir = base();
        let record = register(dir.path(), "job", 10, false).unwrap();
        assert!(is_registration_id(&record.registration_id));
        assert!(!is_registration_id("0A1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D"));
        // Version 1 UUID (the third group starts with '1').
        assert!(!is_registration_id("0a1b2c3d-4e5f-1a6b-8c7d-9e0f1a2b3c4d"));
        assert!(!is_registration_id("not-a-uuid"));
    }
}
