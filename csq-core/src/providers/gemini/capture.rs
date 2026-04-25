//! Event types + NDJSON writer for the Gemini surface.
//!
//! Two layers live here:
//!
//! 1. [`EventKind`] — the kind-specific payload union (counter
//!    increment, 429 parse, effective-model observation, ToS-guard
//!    trip, schema-drift signal). Used by csq-cli emitters.
//! 2. [`EventEnvelope`] — the spec-pinned wrapper around an
//!    `EventKind` carrying `v` (schema version), `id` (UUIDv7), `ts`
//!    (RFC 3339 UTC), `slot`, and `surface`. The on-disk NDJSON line
//!    AND the daemon HTTP IPC payload share this exact shape so the
//!    daemon's dedup-by-id works uniformly across both paths.
//!
//! # Why frozen here
//!
//! Per spec 05 §5.8.1 (FROZEN — PR-G0): the NDJSON event log is the
//! durability floor for Gemini quota signals when the daemon is
//! down. Single-writer (csq-cli writes; daemon drains and
//! truncates). The file shape is:
//!
//! ```text
//! ~/.claude/accounts/gemini-events-<slot>.ndjson
//! ```
//!
//! One JSON object per line. Each line is an [`EventEnvelope`].
//!
//! # Writer discipline (PR-G3, this module)
//!
//! Per spec 05 §5.8.1 "Write discipline":
//!
//! 1. Serialise envelope to a single line + `\n`.
//! 2. Open with `O_APPEND` + mode 0o600 (POSIX guarantees writes
//!    `<= PIPE_BUF` are atomic — every `EventKind` payload is well
//!    under that bound).
//! 3. `write_all` in one syscall.
//! 4. `sync_data` to flush to the underlying block device.
//! 5. Close the handle (no long-lived file).
//!
//! On any step failure, the emitter logs `error_kind =
//! "gemini_event_ndjson_write_failed"` and returns `Ok(())` to the
//! spawn path — event loss is preferable to spawn failure
//! (§7.2.3.1 drop-on-unavailable philosophy).

use crate::error::redact_tokens;
use crate::types::AccountNum;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use super::event_id::new_uuidv7;

/// Current event-envelope schema version. Drainer rejects any
/// envelope with `v != EVENT_SCHEMA_VERSION` and quarantines the
/// file (per spec 05 §5.8.1 drain discipline).
pub const EVENT_SCHEMA_VERSION: u8 = 1;

/// Surface tag in every envelope. v1 only carries `"gemini"`;
/// future surfaces adopting the NDJSON pattern declare their own.
/// Resolved from [`crate::providers::catalog::Surface::Gemini::as_str`]
/// to keep the wire string and the enum in lock-step (PR-G2b).
pub const EVENT_SURFACE_GEMINI: &str = super::SURFACE_GEMINI;

/// Hard cap on per-slot NDJSON log size. Beyond this, the emitter
/// refuses to write and logs `error_kind =
/// "gemini_event_ndjson_log_full"` — operator action needed (drain
/// stalled). 10 MiB chosen so a pathological runaway never fills
/// the disk; healthy steady-state size is bytes (drain cadence is
/// sub-minute under a running daemon).
pub const NDJSON_LOG_SIZE_CAP_BYTES: u64 = 10 * 1024 * 1024;

/// Returns the canonical path of the NDJSON event log for `slot`
/// under `base_dir` (typically `~/.claude/accounts`). Sole source of
/// truth — emitters and drainers MUST NOT construct the path inline
/// (per spec 05 §5.8.1).
pub fn ndjson_path(base_dir: &Path, slot: AccountNum) -> PathBuf {
    base_dir.join(format!("gemini-events-{}.ndjson", slot.get()))
}

/// Kind-specific payload of an [`EventEnvelope`]. Externally tagged
/// (`#[serde(tag = "kind", content = "payload")]`) so the on-disk
/// shape matches the spec example:
///
/// ```json
/// {"v":1,"id":"...","ts":"...","slot":3,"surface":"gemini",
///  "kind":"rate_limited",
///  "payload":{"retry_delay_s":3600,"quota_metric":"...","cap":250}}
/// ```
///
/// The `Empty` payload variant for `counter_increment` serialises as
/// `{}`, matching the spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum EventKind {
    /// csq-cli successfully spawned `gemini` — increments the
    /// per-slot counter.
    CounterIncrement(EmptyPayload),
    /// 429 RESOURCE_EXHAUSTED parsed from a response body.
    RateLimited(RateLimitedPayload),
    /// Per-response `modelVersion` capture (silent-downgrade
    /// detection). Debounced on the receive side per spec 05 §5.8
    /// step 3.
    EffectiveModelObserved(EffectiveModelPayload),
    /// EP4 ToS-guard sentinel tripped — csq-cli detected an
    /// OAuth-flow marker on an AI-Studio-provisioned slot. csq-cli
    /// kills the child after emitting this.
    TosGuardTripped(TosGuardPayload),
    /// Schema-drift signal — csq-cli's parser failed to match the
    /// expected response shape. After 5 strikes the daemon flips
    /// `QuotaKind::Unknown` per the circuit-breaker policy.
    QuotaSchemaDrift(EmptyPayload),
}

/// Empty payload that serialises as `{}`. Used by the two event
/// kinds that carry no kind-specific data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EmptyPayload {}

/// Payload for [`EventKind::RateLimited`]. Field order matches the
/// spec example.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitedPayload {
    pub retry_delay_s: u32,
    pub quota_metric: String,
    /// Daily cap (`quotaValue` from RESOURCE_EXHAUSTED body) when
    /// known. `None` if the body did not carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<u64>,
}

/// Payload for [`EventKind::EffectiveModelObserved`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectiveModelPayload {
    pub selected: String,
    pub effective: String,
}

/// Payload for [`EventKind::TosGuardTripped`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TosGuardPayload {
    pub trigger: String,
}

/// On-disk NDJSON line + on-the-wire IPC payload. Carries the
/// dedup-key (`id`) plus the per-slot/per-surface routing fields.
///
/// Schema is FROZEN (spec 05 §5.8.1). Adding a new top-level field
/// requires bumping [`EVENT_SCHEMA_VERSION`] and updating the
/// daemon drainer's version check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventEnvelope {
    /// Event-envelope schema version. Drainer rejects any value
    /// other than [`EVENT_SCHEMA_VERSION`].
    pub v: u8,
    /// 26-char base32 UUIDv7. Daemon dedup key — same `id`
    /// arriving via IPC AND drained from NDJSON applies once.
    pub id: String,
    /// RFC 3339 UTC timestamp with `Z` suffix. Diagnostic only —
    /// drainer uses file order, not `ts`, for sequencing.
    pub ts: String,
    /// Slot number. Drainer asserts this matches the slot encoded
    /// in the file path; mismatch → quarantine.
    pub slot: u16,
    /// Surface tag. v1 only carries `"gemini"`; reserved for
    /// future surfaces.
    pub surface: String,
    /// Kind-flat-payload. See [`EventKind`].
    #[serde(flatten)]
    pub kind: EventKind,
}

impl EventEnvelope {
    /// Builds an envelope for `slot` carrying `kind`, populating
    /// `v`, `id` (fresh UUIDv7), `ts` (now UTC), `surface`. Emitters
    /// call this then either pass to [`append_event`] for the
    /// NDJSON path or send via daemon HTTP for the live IPC path.
    pub fn new(slot: AccountNum, kind: EventKind) -> Self {
        Self {
            v: EVENT_SCHEMA_VERSION,
            id: new_uuidv7(),
            ts: now_rfc3339_utc(),
            slot: slot.get(),
            surface: EVENT_SURFACE_GEMINI.to_string(),
            kind,
        }
    }
}

/// Errors raised by the NDJSON writer. Every variant is fixed
/// vocabulary so log queries can disambiguate failure modes.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// Per-slot log file exceeded [`NDJSON_LOG_SIZE_CAP_BYTES`].
    /// Caller surfaces this as `error_kind =
    /// "gemini_event_ndjson_log_full"`.
    #[error("gemini event log full ({size} bytes >= cap)")]
    LogFull { size: u64 },
    /// JSON serialisation failed. Should be impossible given the
    /// spec-frozen envelope shape; caught for defence in depth.
    #[error("gemini event serialisation failed: {0}")]
    Serialise(String),
    /// Filesystem write failure (open, write, sync, or close).
    /// Caller surfaces as `error_kind =
    /// "gemini_event_ndjson_write_failed"`.
    #[error("gemini event ndjson io: {0}")]
    Io(#[source] std::io::Error),
}

/// Appends `envelope` to the per-slot NDJSON log under `base_dir`.
/// Implements the writer discipline pinned by spec 05 §5.8.1:
/// O_APPEND + 0o600 + `sync_data` + close-per-event.
///
/// Returns `Ok(envelope)` on successful durable write so the caller
/// can chain a daemon HTTP send while keeping the NDJSON path as
/// the source of truth.
///
/// Per the drop-on-unavailable philosophy (spec 07 §7.2.3.1), the
/// CLI emitter logs and swallows any [`WriteError`] returned here
/// rather than propagating to the spawn path. This function returns
/// the error so call sites can distinguish "log full" (operator
/// action needed) from "transient I/O" (silently drop).
pub fn append_event(base_dir: &Path, envelope: &EventEnvelope) -> Result<(), WriteError> {
    let slot = match AccountNum::try_from(envelope.slot) {
        Ok(s) => s,
        Err(_) => {
            return Err(WriteError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "envelope slot out of range",
            )));
        }
    };
    let path = ndjson_path(base_dir, slot);

    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() >= NDJSON_LOG_SIZE_CAP_BYTES {
            warn!(
                error_kind = "gemini_event_ndjson_log_full",
                slot = envelope.slot,
                size = meta.len(),
                "gemini event log exceeded cap; refusing further writes"
            );
            return Err(WriteError::LogFull { size: meta.len() });
        }
    }

    let line_no_redact = serde_json::to_string(envelope).map_err(|e| {
        WriteError::Serialise(format!(
            "envelope-encode: {}",
            redact_tokens(&e.to_string())
        ))
    })?;
    // Defence in depth: redact accidentally-serialised tokens before
    // they hit the disk. Spec 05 §5.8.1 mandates the redactor pass.
    let line = redact_tokens(&line_no_redact);
    let mut bytes = line.into_bytes();
    bytes.push(b'\n');

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(&path).map_err(WriteError::Io)?;
    file.write_all(&bytes).map_err(WriteError::Io)?;
    file.sync_data().map_err(WriteError::Io)?;
    drop(file);
    // PR-G3 redteam M1: defence in depth — re-assert 0o600 after
    // every write so a future code path that opens this file with a
    // different mode-flag cannot regress permissions silently. Cheap
    // (one stat + chmod) and matches the pattern used elsewhere in
    // csq-core for credential-adjacent files. No-op on Windows.
    if let Err(e) = crate::platform::fs::secure_file(&path) {
        warn!(
            error_kind = "gemini_event_ndjson_secure_file_failed",
            path = %path.display(),
            error = %e,
            "secure_file post-append failed; permissions may be wrong"
        );
    }
    Ok(())
}

/// Returns the current time as an RFC 3339 string with `Z` suffix
/// (UTC). Hand-rolled so capture.rs does not pull a chrono-shaped
/// dependency for a single helper. Format: `YYYY-MM-DDTHH:MM:SS.sssZ`
/// — millisecond precision matches the UUIDv7 timestamp resolution.
fn now_rfc3339_utc() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let ms = dur.subsec_millis();
    let (y, mo, d, h, mi, s) = unix_to_civil(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z")
}

/// Converts `unix_secs` to a (year, month, day, hour, minute, second)
/// tuple in UTC. Algorithm from Howard Hinnant's date library
/// — the same one used elsewhere in csq for ISO-8601 formatting.
fn unix_to_civil(unix_secs: u64) -> (i64, u8, u8, u8, u8, u8) {
    let days = unix_secs / 86_400;
    let secs_of_day = unix_secs % 86_400;
    let h = (secs_of_day / 3600) as u8;
    let mi = ((secs_of_day % 3600) / 60) as u8;
    let s = (secs_of_day % 60) as u8;
    // Days since 1970-01-01 → civil date (Hinnant's algorithm).
    let z = days as i64 + 719468;
    let era = z.div_euclid(146097);
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let mo = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn slot(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    fn read_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn envelope_round_trip_counter_increment() {
        let env = EventEnvelope::new(slot(3), EventKind::CounterIncrement(EmptyPayload {}));
        let json = serde_json::to_string(&env).unwrap();
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn envelope_serialises_with_v_id_ts_slot_surface_kind_payload() {
        // Asserts the on-disk shape pinned by spec 05 §5.8.1.
        let env = EventEnvelope::new(
            slot(5),
            EventKind::RateLimited(RateLimitedPayload {
                retry_delay_s: 3600,
                quota_metric: "generativelanguage.googleapis.com/x".into(),
                cap: Some(250),
            }),
        );
        let json: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert_eq!(json["v"], 1);
        assert!(json["id"].as_str().unwrap().len() == 26);
        assert_eq!(json["slot"], 5);
        assert_eq!(json["surface"], "gemini");
        assert_eq!(json["kind"], "rate_limited");
        assert_eq!(json["payload"]["retry_delay_s"], 3600);
        assert_eq!(json["payload"]["cap"], 250);
    }

    #[test]
    fn append_event_creates_file_with_one_line() {
        let dir = TempDir::new().unwrap();
        let env = EventEnvelope::new(slot(1), EventKind::CounterIncrement(EmptyPayload {}));
        append_event(dir.path(), &env).unwrap();

        let lines = read_lines(&ndjson_path(dir.path(), slot(1)));
        assert_eq!(lines.len(), 1);
        let parsed: EventEnvelope = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed, env);
    }

    #[test]
    fn append_event_appends_subsequent_lines() {
        let dir = TempDir::new().unwrap();
        for _ in 0..5 {
            let env = EventEnvelope::new(slot(2), EventKind::CounterIncrement(EmptyPayload {}));
            append_event(dir.path(), &env).unwrap();
        }
        let lines = read_lines(&ndjson_path(dir.path(), slot(2)));
        assert_eq!(lines.len(), 5);
        // Every line must parse independently.
        for line in lines {
            let _: EventEnvelope = serde_json::from_str(&line).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn append_event_creates_file_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let env = EventEnvelope::new(slot(7), EventKind::CounterIncrement(EmptyPayload {}));
        append_event(dir.path(), &env).unwrap();
        let meta = std::fs::metadata(ndjson_path(dir.path(), slot(7))).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "log file must be 0600, got {mode:o}");
    }

    #[test]
    fn append_event_refuses_when_log_exceeds_cap() {
        let dir = TempDir::new().unwrap();
        let path = ndjson_path(dir.path(), slot(4));
        // Pre-populate to slightly above the cap so the next write
        // hits the size guard.
        let payload = vec![b'x'; (NDJSON_LOG_SIZE_CAP_BYTES + 1) as usize];
        std::fs::write(&path, &payload).unwrap();

        let env = EventEnvelope::new(slot(4), EventKind::CounterIncrement(EmptyPayload {}));
        let err = append_event(dir.path(), &env).unwrap_err();
        match err {
            WriteError::LogFull { size } => {
                assert!(size >= NDJSON_LOG_SIZE_CAP_BYTES);
            }
            other => panic!("expected LogFull, got {other:?}"),
        }
    }

    #[test]
    fn redactor_runs_over_serialised_line() {
        // A future variant or a buggy caller might end up with a
        // key-shaped string in a payload field. Defence in depth:
        // the redactor MUST sanitise the line before write.
        let dir = TempDir::new().unwrap();
        let env = EventEnvelope::new(
            slot(8),
            EventKind::RateLimited(RateLimitedPayload {
                retry_delay_s: 1,
                quota_metric: "AIzaSyTHIS_IS_A_KEY_LOOKING_STRING_xxxxxxx".into(),
                cap: None,
            }),
        );
        append_event(dir.path(), &env).unwrap();
        let content = std::fs::read_to_string(ndjson_path(dir.path(), slot(8))).unwrap();
        assert!(
            !content.contains("AIzaSy"),
            "redactor must scrub AIza* tokens before write: {content}"
        );
    }

    #[test]
    fn unix_to_civil_known_dates() {
        // 1970-01-01T00:00:00Z
        assert_eq!(unix_to_civil(0), (1970, 1, 1, 0, 0, 0));
        // 2026-04-25T22:30:00Z. Computed by hand: 56 years (incl. 14
        // leap years between 1972 and 2024) = 20454 days from 1970-01-01
        // to 2026-01-01; +114 days to 2026-04-25; +22h30m = 81000s.
        // Total = 20568 * 86400 + 81000 = 1_777_156_200.
        assert_eq!(unix_to_civil(1_777_156_200), (2026, 4, 25, 22, 30, 0));
        // Leap-year boundary regression: 2024 IS a leap year (Feb 29).
        // 2024-02-29T00:00:00Z = 1709164800.
        assert_eq!(unix_to_civil(1_709_164_800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn unknown_kind_fails_parse() {
        // Defence in depth — a malformed event must NOT silently
        // deserialise as a default variant.
        let json = r#"{"v":1,"id":"x","ts":"x","slot":1,"surface":"gemini","kind":"made_up","payload":{}}"#;
        let result: Result<EventEnvelope, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn payload_does_not_carry_secret_fields() {
        // Schema invariant: NO field in any payload variant may hold
        // the API key. Enumerate every variant; the redactor pass
        // already covers accidental literal leaks.
        let key_shape = "AIzaSyTESTKEYxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let envelopes = [
            EventEnvelope::new(slot(1), EventKind::CounterIncrement(EmptyPayload {})),
            EventEnvelope::new(
                slot(1),
                EventKind::RateLimited(RateLimitedPayload {
                    retry_delay_s: 1,
                    quota_metric: "x".into(),
                    cap: None,
                }),
            ),
            EventEnvelope::new(
                slot(1),
                EventKind::EffectiveModelObserved(EffectiveModelPayload {
                    selected: "gemini-2.5-pro".into(),
                    effective: "gemini-2.0-flash".into(),
                }),
            ),
            EventEnvelope::new(
                slot(1),
                EventKind::TosGuardTripped(TosGuardPayload {
                    trigger: "Opening browser".into(),
                }),
            ),
            EventEnvelope::new(slot(1), EventKind::QuotaSchemaDrift(EmptyPayload {})),
        ];
        for env in envelopes {
            let s = serde_json::to_string(&env).unwrap();
            assert!(
                !s.contains(key_shape),
                "envelope serialised form must not echo a key-shaped string: {s}"
            );
            assert!(!s.contains("AIza"), "envelope must not contain AIza: {s}");
        }
    }
}
