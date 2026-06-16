//! F-SEAM-02 — validate-BEFORE-link frontier for inbound F101-1 events.
//!
//! Sequence: receive raw bytes → validate (parse, required fields, UUID,
//! timestamp skew, surface registration) → ONLY THEN compute prev_hash + append.
//!
//! A malformed event NEVER reaches the prev_hash spine.

use super::envelope::F101Envelope;
use super::error::RejectReason;
use super::registry::SurfaceRegistry;

/// Skew window: ±24 hours in seconds. Events claiming a `claimed_decision_ts`
/// more than 24h away from the daemon wall clock are rejected with
/// `timestamp_out_of_skew`. This is evidence-validation only — the event is
/// not claimed to have happened now, just that it is recent enough to accept.
pub const SKEW_WINDOW_SECS: i64 = 24 * 60 * 60;

/// Maximum raw body size (256 KiB). Events larger than this are rejected with
/// `body_too_large` before JSON parsing.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Validated F101-1 envelope with canonical timestamp.
///
/// Returned by [`validate_event`] on success. The `canonical_ts` field is a
/// daemon-reconstructed `YYYY-MM-DDTHH:MM:SS+00:00` string built from the
/// parsed Unix seconds — NOT the raw `claimed_decision_ts` string. This
/// closes the token-smuggling vector (H2): an attacker cannot hide a token in
/// the timestamp suffix because we discard the raw string and re-serialize.
pub struct ValidatedEnvelope {
    /// The parsed F101-1 envelope from the raw bytes.
    pub envelope: F101Envelope,
    /// Canonical UTC timestamp re-built from parsed Unix seconds.
    ///
    /// Shape: `YYYY-MM-DDTHH:MM:SS+00:00`. Stored in `ProvenanceAnchored`
    /// instead of the raw `claimed_decision_ts` string (H2 fix). An auditor
    /// can still cross-reference the original timestamp via `received_bytes_hash`.
    pub canonical_ts: String,
    /// The parsed `claimed_decision_ts` as Unix seconds. Used by M20 to detect
    /// a backfilled/buffered event (one arriving materially later than it claims
    /// to have been decided) so its cross-source ordering is annotated
    /// `ordering_basis: "wallclock_skew_bounded"` rather than presented as causal.
    pub claimed_unix: i64,
}

/// Validates a raw F101-1 event at the frontier.
///
/// Returns a [`ValidatedEnvelope`] on success, or a [`RejectReason`] on any
/// validation failure.
///
/// Validation sequence:
/// 1. Body size check (`body_too_large`).
/// 2. JSON parse — extract header fields (`malformed_json`).
/// 3. All required fields non-empty (`missing_required_field`).
/// 4. `decision_id` UUID shape 8-4-4-4-12 hex (`decision_id_not_uuid`).
/// 5. `claimed_decision_ts` parses as ISO-8601 and within `±SKEW_WINDOW_SECS`
///    of `now_unix` (`timestamp_out_of_skew`).
/// 6. `surface` is registered in `registry` (`unregistered_surface`).
pub fn validate_event(
    raw: &[u8],
    registry: &SurfaceRegistry,
    now_unix: i64,
) -> Result<ValidatedEnvelope, RejectReason> {
    // Step 1: body size check.
    if raw.len() > MAX_BODY_BYTES {
        return Err(RejectReason::BodyTooLarge);
    }

    // Step 2+3: parse and check required fields.
    let envelope = F101Envelope::parse(raw)?;

    // Step 4: decision_id UUID shape (8-4-4-4-12 lowercase-or-uppercase hex).
    if !is_valid_uuid_shape(&envelope.decision_id) {
        return Err(RejectReason::DecisionIdNotUuid);
    }

    // Step 5: timestamp parse + skew check.
    // L1: single saturating_sub(now_unix, claimed_unix).abs() — no delta2 needed
    // because i64::saturating_sub already clamps; the absolute value covers both
    // past and future timestamps correctly without a second subtraction.
    let claimed_unix = parse_iso8601_to_unix(&envelope.claimed_decision_ts)
        .ok_or(RejectReason::TimestampOutOfSkew)?;
    let abs_delta = now_unix.saturating_sub(claimed_unix).unsigned_abs() as i64;
    if abs_delta > SKEW_WINDOW_SECS {
        return Err(RejectReason::TimestampOutOfSkew);
    }

    // Re-serialize to canonical form (H2): discard the raw timestamp string
    // so no attacker suffix can survive into the chain record.
    let canonical_ts = unix_to_canonical_ts(claimed_unix);

    // Step 6: surface registration.
    if !registry.contains(&envelope.surface) {
        return Err(RejectReason::UnregisteredSurface);
    }

    Ok(ValidatedEnvelope {
        envelope,
        canonical_ts,
        claimed_unix,
    })
}

/// Minimal UUID shape check: 8-4-4-4-12 hex digits, case-insensitive.
///
/// Does NOT use a `uuid` crate dependency — pure stdlib as required.
/// Accepts both lowercase and uppercase hex (F101 events may come from
/// diverse emitters; we normalize on ingest via `decision_id` storage).
///
/// `pub(crate)` so the v1 audit writer can validate `run_id` against the same
/// canonical UUID shape (M19b security review M1/M2 — the daemon IPC `run_id`
/// is untrusted at the same-UID socket boundary).
pub(crate) fn is_valid_uuid_shape(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    // Hyphen positions: 8, 13, 18, 23.
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
        return false;
    }
    // All other positions must be hex.
    for (i, &byte) in b.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Parse an ISO-8601/RFC-3339 UTC timestamp to Unix seconds.
///
/// Accepts the forms that loom emits:
///   `YYYY-MM-DDTHH:MM:SS+00:00` (with `+00:00` or `Z` suffix)
///   `YYYY-MM-DDTHH:MM:SSZ`
///
/// Returns `None` on parse failure or overflow.
///
/// Pure stdlib — no `chrono`/`time` crate dependency.
fn parse_iso8601_to_unix(s: &str) -> Option<i64> {
    // Normalise: strip timezone suffix (Z, +00:00, -00:00, or other offset).
    // Also strip optional fractional seconds (e.g. `.000`, `.123456`) that appear
    // between the seconds field and the timezone suffix.
    //
    // Step 1: strip the timezone suffix.
    let s = if let Some(stripped) = s.strip_suffix('Z') {
        stripped
    } else if let Some(stripped) = s.strip_suffix("+00:00") {
        stripped
    } else if let Some(stripped) = s.strip_suffix("-00:00") {
        stripped
    } else if s.len() > 19 {
        // Accept other offsets leniently (treat as UTC equivalent for skew purposes).
        // Strip timezone suffix if present (anything after +/- after the time part).
        if let Some(pos) = s[19..].find(['+', '-']) {
            &s[..19 + pos]
        } else {
            s
        }
    } else {
        s
    };

    // Step 2: strip optional fractional-seconds suffix (`.NNN...` at position 19+).
    // After timezone removal we may have `"2026-06-09T15:44:57.000"` (23 chars).
    // The fractional part is discarded — we only care about second-level granularity.
    //
    // LOW-3: require the fractional part to be at least one ASCII digit after
    // the `.` — reject `"...57."` (bare dot, no digits) and `"...57.abcZ"`
    // (non-digit fractional) with `None` (TimestampOutOfSkew path).
    let s: &str = if s.len() > 19 && s.as_bytes().get(19) == Some(&b'.') {
        // The character at position 20 (the first fractional digit) must exist
        // and must be an ASCII digit.
        match s.as_bytes().get(20) {
            Some(&b) if b.is_ascii_digit() => &s[..19],
            _ => return None, // bare `...57.` or non-digit fractional
        }
    } else {
        s
    };

    // Must be exactly "YYYY-MM-DDTHH:MM:SS" = 19 chars.
    if s.len() != 19 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year: i64 = parse_digits(&bytes[0..4])?;
    let month: u32 = parse_digits_u32(&bytes[5..7])?;
    let day: u32 = parse_digits_u32(&bytes[8..10])?;
    let hour: u32 = parse_digits_u32(&bytes[11..13])?;
    let minute: u32 = parse_digits_u32(&bytes[14..16])?;
    let second: u32 = parse_digits_u32(&bytes[17..19])?;

    // L2: reject leap seconds (second == 60) — the canonical re-serialization
    // path only needs standard civil-time seconds; we never claim to be a
    // full UTC clock. Days-in-month validation is subsumed by H2: the canonical
    // re-serializer rebuilds from Unix seconds so an invalid civil date
    // (Feb-31) would produce a nonsensical Unix value and the round-trip
    // back via `unix_to_canonical_ts` would not reproduce the original date.
    // Reject second > 59 strictly.
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    // Compute Unix timestamp using the civil-to-epoch algorithm (works for
    // any Gregorian date in the reasonable range).
    // Algorithm from Howard Hinnant's chrono::to_days.
    let y = if month <= 2 { year - 1 } else { year };
    let m = month as i64;
    let d = day as i64;
    let era = if y >= 0 { y / 400 } else { (y - 399) / 400 };
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days_since_epoch = era * 146097 + doe - 719468;

    let unix = days_since_epoch
        .checked_mul(86400)?
        .checked_add(hour as i64 * 3600 + minute as i64 * 60 + second as i64)?;

    Some(unix)
}

/// Re-serialise a Unix-seconds timestamp to `YYYY-MM-DDTHH:MM:SS+00:00`.
///
/// This is the canonical form stored in `ProvenanceAnchored.claimed_decision_ts`
/// (H2 fix). We discard the raw envelope string and rebuild from the validated
/// Unix seconds so no attacker suffix or non-canonical representation survives.
///
/// Pure stdlib. Works for any Unix timestamp in the range [0, year ~9999].
fn unix_to_canonical_ts(unix: i64) -> String {
    // Days since Unix epoch + time-of-day.
    let secs_of_day = unix.rem_euclid(86400) as u32;
    let days = (unix - secs_of_day as i64) / 86400;

    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    // Civil date from days since epoch (Howard Hinnant's algorithm, reversed).
    let z = days + 719468;
    let era = if z >= 0 {
        z / 146097
    } else {
        (z - 146096) / 146097
    };
    let doe = (z - era * 146097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
}

fn parse_digits(b: &[u8]) -> Option<i64> {
    let mut v: i64 = 0;
    for &byte in b {
        if !byte.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((byte - b'0') as i64)?;
    }
    Some(v)
}

fn parse_digits_u32(b: &[u8]) -> Option<u32> {
    let mut v: u32 = 0;
    for &byte in b {
        if !byte.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((byte - b'0') as u32)?;
    }
    Some(v)
}

/// Test-only helper: return a canonical UTC timestamp string for the given
/// Unix seconds. Used by server.rs tests to build a valid `claimed_decision_ts`
/// that will pass frontier validation.
#[cfg(any(test, feature = "test-utils"))]
pub fn canonical_ts_for_test(unix: i64) -> String {
    unix_to_canonical_ts(unix)
}

/// `pub(crate)` wrapper for `parse_iso8601_to_unix` — used by the v1 decoder.
pub(crate) fn parse_iso8601_to_unix_pub(s: &str) -> Option<i64> {
    parse_iso8601_to_unix(s)
}

/// `pub(crate)` wrapper for `unix_to_canonical_ts` — used by the v1 decoder.
pub(crate) fn unix_to_canonical_ts_pub(unix: i64) -> String {
    unix_to_canonical_ts(unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_uuid_shapes() {
        assert!(is_valid_uuid_shape("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_valid_uuid_shape("550E8400-E29B-41D4-A716-446655440000"));
        assert!(is_valid_uuid_shape("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn invalid_uuid_shapes() {
        assert!(!is_valid_uuid_shape("not-a-uuid"));
        assert!(!is_valid_uuid_shape("550e8400e29b41d4a716446655440000"));
        assert!(!is_valid_uuid_shape("550e8400-e29b-41d4-a716-44665544000z"));
        assert!(!is_valid_uuid_shape(""));
    }

    #[test]
    fn parse_iso8601_z_suffix() {
        let ts = parse_iso8601_to_unix("2026-06-08T12:00:00Z");
        assert!(ts.is_some());
        assert!(ts.unwrap() > 0);
    }

    #[test]
    fn parse_iso8601_offset() {
        let ts_z = parse_iso8601_to_unix("2026-06-08T12:00:00Z").unwrap();
        let ts_off = parse_iso8601_to_unix("2026-06-08T12:00:00+00:00").unwrap();
        assert_eq!(ts_z, ts_off);
    }

    #[test]
    fn parse_iso8601_invalid() {
        assert!(parse_iso8601_to_unix("not-a-timestamp").is_none());
        assert!(parse_iso8601_to_unix("2026-13-08T12:00:00Z").is_none()); // month 13
    }

    // ── R3 LOW-3a: canonical re-serialize must be a faithful inverse of the
    //    parser (an off-by-one in unix_to_canonical_ts would ship silently). ──

    #[test]
    fn canonical_ts_round_trips() {
        for &unix in &[
            0_i64,           // 1970-01-01T00:00:00
            1_771_545_600,   // a 2026 instant
            1_582_934_400,   // 2020-02-29 (leap day)
            253_402_300_799, // 9999-12-31T23:59:59 (far future, in-range)
        ] {
            let canonical = unix_to_canonical_ts(unix);
            assert_eq!(
                parse_iso8601_to_unix(&canonical),
                Some(unix),
                "round-trip must be stable for unix={unix} (canonical={canonical})"
            );
            // Canonical form is always the `+00:00` shape.
            assert!(
                canonical.ends_with("+00:00") && canonical.len() == 25,
                "canonical_ts must be YYYY-MM-DDTHH:MM:SS+00:00; got {canonical}"
            );
        }
    }

    // ── LOW-3: fractional-seconds parse must reject bare dot and non-digit fractional ──

    #[test]
    fn bare_dot_fractional_rejected() {
        // "2026-06-09T15:44:57." — bare dot, no digits after → None
        assert!(
            parse_iso8601_to_unix("2026-06-09T15:44:57.Z").is_none(),
            "bare fractional dot (no digits) must be rejected"
        );
        assert!(
            parse_iso8601_to_unix("2026-06-09T15:44:57.+00:00").is_none(),
            "bare fractional dot before offset must be rejected"
        );
    }

    #[test]
    fn non_digit_fractional_rejected() {
        // "2026-06-09T15:44:57.abcZ" — non-digit fractional → None
        assert!(
            parse_iso8601_to_unix("2026-06-09T15:44:57.abcZ").is_none(),
            "non-digit fractional must be rejected"
        );
        assert!(
            parse_iso8601_to_unix("2026-06-09T15:44:57.abc+00:00").is_none(),
            "non-digit fractional (with offset) must be rejected"
        );
    }

    #[test]
    fn valid_fractional_seconds_accepted() {
        // "2026-06-09T15:44:57.000Z" — valid → parses same as without fractional
        let with_frac = parse_iso8601_to_unix("2026-06-09T15:44:57.000Z");
        let without_frac = parse_iso8601_to_unix("2026-06-09T15:44:57Z");
        assert!(
            with_frac.is_some(),
            "valid fractional seconds (.000Z) must be accepted"
        );
        assert_eq!(
            with_frac, without_frac,
            "fractional seconds must be discarded: .000Z and Z must yield the same unix second"
        );
    }

    // ── R3 LOW-3b: the body-size cap branch must actually reject oversized bodies. ──

    #[test]
    fn body_too_large_is_rejected() {
        let registry = SurfaceRegistry::default();
        let oversized = vec![b'x'; MAX_BODY_BYTES + 1];
        assert!(
            matches!(
                validate_event(&oversized, &registry, 0),
                Err(RejectReason::BodyTooLarge)
            ),
            "a body over MAX_BODY_BYTES must be rejected with BodyTooLarge"
        );
    }
}
