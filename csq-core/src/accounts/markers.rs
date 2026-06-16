//! Account marker files — durable identity markers for CC sessions.
//!
//! `.csq-account` — written by csq during setup, contains account number.
//! `.current-account` — fast-path cache, written by snapshot_account().
//! `.live-pid` — PID of the CC process, used for snapshot caching.
//!
//! # Schema-compat reader (M1-5, issue #292 Phase 1)
//!
//! [`read_identity_marker`] is the forward-compatible read path that accepts
//! BOTH the current numeric format (`"3"`) AND the future UUID format
//! (`"550e8400-e29b-41d4-a716-446655440000"`). Phase 1 writers continue
//! emitting numeric strings; the Phase 4 writer migration will switch to
//! UUIDs. Readers are upgraded first so the transition is backwards-safe.
//!
//! **No-silent-fallback guarantee** (`account-terminal-separation.md` MUST
//! Rule 3): a parse failure returns `None`. The function NEVER returns
//! `numeric: Some(0)`, `numeric: Some(1)`, or any invented fallback — the
//! marker is the SOLE authority for which account a session is using.

use crate::accounts::identity_store::IdentityId;
use crate::error::CredentialError;
use crate::platform::fs::{atomic_replace, secure_file};
use crate::types::AccountNum;
use std::path::Path;

/// Dual-format identity marker returned by [`read_identity_marker`].
///
/// Exactly one of the two fields is `Some` on a successful parse:
/// - `numeric` is `Some` when the marker file contains a valid account number
///   string (e.g. `"3"`). This is the Phase 1 / current format.
/// - `uuid` is `Some` when the marker file contains a canonical UUID-v4
///   string (e.g. `"550e8400-e29b-41d4-a716-446655440000"`). This is the
///   Phase 4 / future format.
///
/// Both being `None` is impossible from a successful parse path: a parse
/// failure is signalled by returning `Option<IdentityMarker>::None` at the
/// function level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMarker {
    /// Present when the marker held a numeric account number string.
    pub numeric: Option<AccountNum>,
    /// Present when the marker held a canonical UUID-v4 string.
    pub uuid: Option<IdentityId>,
}

/// Reads the `.csq-account` marker from a config directory.
/// Returns None if the file doesn't exist or contains invalid content.
pub fn read_csq_account(config_dir: &Path) -> Option<AccountNum> {
    let path = config_dir.join(".csq-account");
    read_account_marker(&path)
}

/// Reads the `.csq-account` marker accepting BOTH numeric AND UUID formats.
///
/// Returns `Some(IdentityMarker)` with exactly one field populated:
/// - `numeric` if the file contained a valid account number string.
/// - `uuid` if the file contained a canonical UUID-v4 string.
///
/// Returns `None` if:
/// - The file does not exist or cannot be read.
/// - The content is empty after trimming.
/// - The content is neither a valid `AccountNum` nor a valid UUID-v4.
///
/// **No-silent-fallback guarantee**: this function NEVER returns
/// `IdentityMarker { numeric: Some(1), .. }` or any other invented default
/// on invalid input. The marker is the SOLE authority for which account a
/// session is using (`account-terminal-separation.md` MUST Rule 3).
pub fn read_identity_marker(config_dir: &Path) -> Option<IdentityMarker> {
    let path = config_dir.join(".csq-account");
    parse_identity_marker_file(&path)
}

/// Reads the `.current-account` identity marker accepting BOTH formats.
///
/// Same semantics as [`read_identity_marker`] but reads `.current-account`.
/// Phase 1 callers that only care about numeric semantics should call
/// [`read_current_account`] instead (extracts `.numeric` for them).
pub fn read_current_identity_marker(config_dir: &Path) -> Option<IdentityMarker> {
    let path = config_dir.join(".current-account");
    parse_identity_marker_file(&path)
}

/// Parses a marker file at `path` into an [`IdentityMarker`].
///
/// Tries numeric first (cheaper), then UUID. The two parsers are mutually
/// exclusive by construction:
/// - `AccountNum::from_str` accepts only decimal integers in `1..=999`.
/// - `IdentityId::from_str` (`uuid::Uuid::parse_str`) rejects those strings
///   because they lack the required UUID hyphen structure.
///
/// Any other content (empty, mixed, multi-line with corruption, `"3.5"`,
/// `"-1"`, overflow numbers, partial UUIDs) returns `None`.
fn parse_identity_marker_file(path: &Path) -> Option<IdentityMarker> {
    let raw = std::fs::read_to_string(path).ok()?;
    let content = raw.trim();

    // Reject empty strings explicitly (trim() reduces whitespace-only to "").
    if content.is_empty() {
        return None;
    }

    // Attempt numeric parse first. AccountNum::from_str rejects:
    //   - "0" and values > 999 (out-of-range)
    //   - negative strings like "-1" (u16 parse fails)
    //   - floats like "3.5" (parse::<u16> fails)
    //   - UUIDs (obviously not valid u16)
    if let Ok(account) = content.parse::<AccountNum>() {
        return Some(IdentityMarker {
            numeric: Some(account),
            uuid: None,
        });
    }

    // Attempt UUID parse. IdentityId::from_str rejects:
    //   - "not-a-uuid", "abc", "3", "3.5", "", "-1" etc.
    //   - Partial UUIDs (wrong length or structure)
    //   - Mixed inputs like "3-uuid" or "uuid 3"
    if let Ok(id) = content.parse::<IdentityId>() {
        return Some(IdentityMarker {
            numeric: None,
            uuid: Some(id),
        });
    }

    // Neither parsed — no silent fallback.
    None
}

/// Reads the `.csq-account` marker as an [`IdentityId`].
///
/// Returns `Some(uuid)` only when the file content parses as a canonical
/// UUID-v4. Returns `None` if the file is absent, contains numeric
/// (legacy) content, or fails to parse. Phase 1+ readers that need the
/// account-number view should keep calling [`read_csq_account`] (which
/// remains numeric-only by contract). M4-7 introduces this accessor as
/// the UUID-side counterpart so callers that genuinely want
/// slot-independent identity can take the explicit path without
/// re-deriving from `read_identity_marker`.
///
/// **No-silent-fallback guarantee** (`account-terminal-separation.md`
/// MUST Rule 3): a parse failure or a numeric marker returns `None`.
/// The function NEVER invents an `IdentityId` from a slot number — that
/// would re-introduce the terminal-attribution failure mode the marker
/// is designed to close.
pub fn read_csq_account_uuid(config_dir: &Path) -> Option<IdentityId> {
    read_identity_marker(config_dir).and_then(|m| m.uuid)
}

/// Writes the `.csq-account` marker as the canonical UUID string of
/// the given [`IdentityId`].
///
/// **M4-7 content-semantic flip (issue #292 Phase 4, spec 02 §INV-03 +
/// §2.3.1):** the marker file content is the slot's identity UUID, not
/// the decimal slot id. The filename `.csq-account` is retained
/// (user-decided OQ #3 — flip content only, never rename the marker
/// file). The M1-5 reader (`read_csq_account`, `read_identity_marker`)
/// has been UUID-tolerant since Phase 1; callers needing the decimal
/// slot id can keep using `read_csq_account` against legacy installs
/// because the writer flip is paired with a `write_csq_account_legacy`
/// affordance for those cases.
///
/// Pure-legacy installs (no Phase-1 mint, no `by_slot` entry in
/// `profiles.json`) MUST go through [`write_csq_account_legacy`]
/// instead — that affordance preserves the decimal write so legacy
/// readers do not see a UUID where they expect a number.
pub fn write_csq_account(config_dir: &Path, id: IdentityId) -> Result<(), CredentialError> {
    let path = config_dir.join(".csq-account");
    write_uuid_marker(&path, id)
}

/// Writes the `.csq-account` marker with the legacy decimal slot-id
/// content.
///
/// Migration affordance for pure-legacy installs that have not yet
/// reached daemon Pass 0 (no `by_slot` mapping in `profiles.json`).
/// Once `phase4_gate_check` refuses pure-legacy installs (a future
/// shard), this writer is the only remaining caller-of-last-resort
/// for the decimal-content marker.
///
/// The M1-5 reader accepts both decimal and UUID content (see
/// [`read_identity_marker`]), so a marker file written by this
/// function continues to parse via [`read_csq_account`].
pub fn write_csq_account_legacy(
    config_dir: &Path,
    account: AccountNum,
) -> Result<(), CredentialError> {
    let path = config_dir.join(".csq-account");
    write_account_marker(&path, account)
}

/// Reads the `.current-account` fast-path marker.
///
/// Returns the numeric account number if the marker file contains a valid
/// account number string. Returns `None` if the file is absent, unreadable,
/// or contains content that is not a numeric account number (including UUID
/// strings — Phase 1 callers that need UUID support should call
/// [`read_current_identity_marker`] directly).
pub fn read_current_account(config_dir: &Path) -> Option<AccountNum> {
    read_current_identity_marker(config_dir).and_then(|m| m.numeric)
}

/// Writes the `.current-account` fast-path marker.
pub fn write_current_account(
    config_dir: &Path,
    account: AccountNum,
) -> Result<(), CredentialError> {
    let path = config_dir.join(".current-account");
    write_account_marker(&path, account)
}

/// Reads the `.live-pid` file. Returns None if missing, invalid,
/// or if the path is a symlink. Refusing symlinks closes a
/// cross-handle PID forgery vector where a poisoned handle dir
/// could point `.live-pid` at another process's status file and
/// trick the daemon's sweep into treating a dead handle as live.
pub fn read_live_pid(config_dir: &Path) -> Option<u32> {
    read_pid_marker(config_dir, ".live-pid")
}

/// Reads the `.live-cc-pid` file, used on non-Unix platforms to
/// record the spawned CC child process PID. On Unix this file is
/// never written (exec replaces csq-cli with claude so there is a
/// single PID). The sweep treats the handle dir as live if EITHER
/// `.live-pid` or `.live-cc-pid` is alive, closing the Windows
/// crash-recovery window where csq-cli died but CC survived as an
/// orphaned child.
pub fn read_live_cc_pid(config_dir: &Path) -> Option<u32> {
    read_pid_marker(config_dir, ".live-cc-pid")
}

fn read_pid_marker(config_dir: &Path, name: &str) -> Option<u32> {
    let path = config_dir.join(name);
    // symlink_metadata does NOT follow symlinks; if the path is a
    // symlink we refuse rather than read through it.
    match path.symlink_metadata() {
        Ok(meta) if meta.file_type().is_file() => {}
        _ => return None,
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Writes the `.live-pid` file.
pub fn write_live_pid(config_dir: &Path, pid: u32) -> Result<(), CredentialError> {
    write_pid_marker(config_dir, ".live-pid", pid)
}

/// Writes the `.live-cc-pid` file. Only used on non-Unix — see
/// [`read_live_cc_pid`] for the rationale.
pub fn write_live_cc_pid(config_dir: &Path, pid: u32) -> Result<(), CredentialError> {
    write_pid_marker(config_dir, ".live-cc-pid", pid)
}

fn write_pid_marker(config_dir: &Path, name: &str, pid: u32) -> Result<(), CredentialError> {
    let path = config_dir.join(name);
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    std::fs::write(&tmp, pid.to_string().as_bytes()).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    atomic_replace(&tmp, &path).map_err(|e| CredentialError::Io {
        path: path.clone(),
        source: std::io::Error::other(e.to_string()),
    })?;
    Ok(())
}

fn read_account_marker(path: &Path) -> Option<AccountNum> {
    parse_identity_marker_file(path).and_then(|m| m.numeric)
}

fn write_account_marker(path: &Path, account: AccountNum) -> Result<(), CredentialError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = crate::platform::fs::unique_tmp_path(path);
    std::fs::write(&tmp, account.to_string().as_bytes()).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    secure_file(&tmp).ok();
    atomic_replace(&tmp, path).map_err(|e| CredentialError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?;
    Ok(())
}

/// Writes the canonical UUID-v4 string form of `id` to `path` via the
/// same atomic-replace + permission flip pipeline as the legacy
/// numeric writer. Used by the M4-7 UUID writer flip (spec 02
/// §INV-03 + §2.3.1).
fn write_uuid_marker(path: &Path, id: IdentityId) -> Result<(), CredentialError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let tmp = crate::platform::fs::unique_tmp_path(path);
    let canonical = id.to_canonical_string();
    std::fs::write(&tmp, canonical.as_bytes()).map_err(|e| CredentialError::Io {
        path: tmp.clone(),
        source: e,
    })?;
    secure_file(&tmp).ok();
    atomic_replace(&tmp, path).map_err(|e| CredentialError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::other(e.to_string()),
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ─── Existing regression tests (preserved, now route through new parser) ───

    /// M4-7: legacy decimal-content writer round-trips through the
    /// numeric reader. Validates [`write_csq_account_legacy`] preserves
    /// the pre-M4-7 behavior for pure-legacy installs.
    #[test]
    fn write_read_csq_account_legacy() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();

        write_csq_account_legacy(dir.path(), account).unwrap();
        assert_eq!(read_csq_account(dir.path()), Some(account));
    }

    /// M4-7 acceptance: `markers::write_csq_account` writes the
    /// canonical UUID-v4 string, and `read_csq_account_uuid` reads it
    /// back as `Some(IdentityId)`. The same file is also parseable via
    /// `read_identity_marker` (returns `IdentityMarker { numeric: None,
    /// uuid: Some(_) }`), so M1-5 callers remain compatible.
    #[test]
    fn marker_round_trip_uuid_content() {
        let dir = TempDir::new().unwrap();
        let id = IdentityId::new_v4();

        write_csq_account(dir.path(), id).unwrap();

        // Direct UUID accessor returns the canonical id.
        assert_eq!(read_csq_account_uuid(dir.path()), Some(id));

        // The M1-5 reader sees uuid: Some(_), numeric: None.
        let m = read_identity_marker(dir.path()).expect("UUID marker must parse");
        assert!(m.numeric.is_none(), "UUID marker must not parse as numeric");
        assert_eq!(m.uuid, Some(id), "UUID marker round-trips identity");

        // Legacy decimal reader returns None (it only extracts numeric).
        assert_eq!(
            read_csq_account(dir.path()),
            None,
            "UUID-content marker is non-numeric; legacy reader returns None per M1-5 contract"
        );
    }

    #[test]
    fn write_read_current_account() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(3u16).unwrap();

        write_current_account(dir.path(), account).unwrap();
        assert_eq!(read_current_account(dir.path()), Some(account));
    }

    #[test]
    fn read_missing_marker_returns_none() {
        let dir = TempDir::new().unwrap();
        assert_eq!(read_csq_account(dir.path()), None);
        assert_eq!(read_current_account(dir.path()), None);
    }

    #[test]
    fn read_invalid_marker_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".csq-account"), "not-a-number").unwrap();
        assert_eq!(read_csq_account(dir.path()), None);
    }

    #[test]
    fn read_out_of_range_marker_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".csq-account"), "0").unwrap();
        assert_eq!(read_csq_account(dir.path()), None);

        std::fs::write(dir.path().join(".csq-account"), "1000").unwrap();
        assert_eq!(read_csq_account(dir.path()), None);
    }

    #[test]
    fn write_read_live_pid() {
        let dir = TempDir::new().unwrap();
        write_live_pid(dir.path(), 12345).unwrap();
        assert_eq!(read_live_pid(dir.path()), Some(12345));
    }

    #[test]
    fn read_missing_pid_returns_none() {
        let dir = TempDir::new().unwrap();
        assert_eq!(read_live_pid(dir.path()), None);
    }

    // ─── M1-5 acceptance tests for read_identity_marker ─────────────────────

    /// Acceptance: numeric "3" → IdentityMarker { numeric: Some(3), uuid: None }
    #[test]
    fn m1_5_numeric_string_returns_numeric_marker() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".csq-account"), "3").unwrap();

        let result = read_identity_marker(dir.path());
        assert!(result.is_some(), "numeric marker must parse");
        let m = result.unwrap();
        assert_eq!(
            m.numeric,
            Some(AccountNum::try_from(3u16).unwrap()),
            "numeric field must be Some(3)"
        );
        assert!(
            m.uuid.is_none(),
            "uuid field must be None for numeric input"
        );
    }

    /// Acceptance: UUID string → IdentityMarker { numeric: None, uuid: Some(<id>) }
    #[test]
    fn m1_5_uuid_string_returns_uuid_marker() {
        let dir = TempDir::new().unwrap();
        let canonical = "550e8400-e29b-41d4-a716-446655440000";
        std::fs::write(dir.path().join(".csq-account"), canonical).unwrap();

        let result = read_identity_marker(dir.path());
        assert!(result.is_some(), "UUID marker must parse");
        let m = result.unwrap();
        assert!(
            m.numeric.is_none(),
            "numeric field must be None for UUID input"
        );
        assert!(m.uuid.is_some(), "uuid field must be Some for UUID input");
        assert_eq!(
            m.uuid.unwrap().to_canonical_string(),
            canonical,
            "parsed UUID must round-trip to the same canonical form"
        );
    }

    /// Acceptance: exactly one field is Some on a valid parse.
    #[test]
    fn m1_5_exactly_one_field_populated_on_success() {
        let dir = TempDir::new().unwrap();

        // numeric path
        std::fs::write(dir.path().join(".csq-account"), "7").unwrap();
        let m = read_identity_marker(dir.path()).unwrap();
        let populated = m.numeric.is_some() as u8 + m.uuid.is_some() as u8;
        assert_eq!(
            populated, 1,
            "exactly one field must be Some (numeric path)"
        );

        // UUID path
        std::fs::write(
            dir.path().join(".csq-account"),
            "550e8400-e29b-41d4-a716-446655440001",
        )
        .unwrap();
        let m = read_identity_marker(dir.path()).unwrap();
        let populated = m.numeric.is_some() as u8 + m.uuid.is_some() as u8;
        assert_eq!(populated, 1, "exactly one field must be Some (UUID path)");
    }

    /// Acceptance: reject well-known invalid inputs → None.
    #[test]
    fn m1_5_rejects_invalid_inputs() {
        let dir = TempDir::new().unwrap();
        let invalid_cases = [
            "",           // empty
            "0",          // out-of-range (below minimum)
            "abc",        // non-numeric, non-UUID
            "3.5",        // float — not a valid u16 or UUID
            "not-a-uuid", // garbage that looks like it has hyphens
            "-1",         // negative (u16 parse rejects)
            "99999",      // overflows AccountNum (> 999)
            "1000",       // exactly at overflow boundary
        ];
        for input in &invalid_cases {
            std::fs::write(dir.path().join(".csq-account"), input).unwrap();
            let result = read_identity_marker(dir.path());
            assert!(
                result.is_none(),
                "expected None for input {input:?}, got {result:?} — no silent fallback allowed"
            );
        }
    }

    /// Acceptance: no silent fallback to any invented value on provably-invalid
    /// input. These strings are neither valid AccountNum strings nor valid
    /// UUID-v4 strings, so the parser MUST return None — not invent a default.
    ///
    /// Note: slot 0 is unrepresentable by AccountNum (out-of-range validation);
    /// slot 1 would only be a "fallback" if returned for input that is not the
    /// literal string "1". This test uses inputs that are clearly not "1".
    #[test]
    fn m1_5_no_silent_fallback_on_invalid_input() {
        let dir = TempDir::new().unwrap();
        // These inputs are provably invalid — neither a valid AccountNum
        // (1..=999 decimal integer) nor a valid UUID-v4.
        for bad in ["0", "", "abc", "3.5", "-1", "999999"] {
            std::fs::write(dir.path().join(".csq-account"), bad).unwrap();
            let result = read_identity_marker(dir.path());
            assert!(
                result.is_none(),
                "MUST NOT return Some for invalid input {bad:?} — no silent fallback allowed, \
                 got {result:?}"
            );
        }
    }

    /// Acceptance: reject mixed/malformed inputs.
    #[test]
    fn m1_5_rejects_mixed_inputs() {
        let dir = TempDir::new().unwrap();
        let mixed_cases = [
            "3-uuid",                                     // numeric prefix + hyphen
            "uuid 3",                                     // UUID prefix + space
            "  3  extra",                                 // trailing garbage after trim
            "3\n4",                                       // multi-line, second line corrupts
            "550e8400-e29b-41d4-a716-446655440000 extra", // UUID + trailing garbage
        ];
        for input in &mixed_cases {
            std::fs::write(dir.path().join(".csq-account"), input).unwrap();
            let result = read_identity_marker(dir.path());
            assert!(
                result.is_none(),
                "expected None for mixed input {input:?}, got {result:?}"
            );
        }
    }

    /// Acceptance: leading/trailing whitespace is trimmed; "3\n" and "  3  "
    /// both parse to Some(numeric=3). This matches the existing behavior of
    /// read_csq_account which also trims.
    #[test]
    fn m1_5_trims_whitespace() {
        let dir = TempDir::new().unwrap();
        for padded in ["3\n", "  3  ", "3\r\n"] {
            std::fs::write(dir.path().join(".csq-account"), padded).unwrap();
            let m = read_identity_marker(dir.path())
                .unwrap_or_else(|| panic!("expected Some for whitespace-padded input {padded:?}"));
            assert_eq!(
                m.numeric,
                Some(AccountNum::try_from(3u16).unwrap()),
                "trimmed numeric must parse correctly"
            );
        }
    }

    /// Acceptance: multi-line where line 2 is non-empty and would corrupt →
    /// trim reduces "3\nextra" to "3\nextra" which does NOT parse as AccountNum
    /// (parse_str for u16 would fail on the '\n') and does not parse as UUID.
    #[test]
    fn m1_5_multiline_with_corruption_returns_none() {
        let dir = TempDir::new().unwrap();
        // "3\nextra" trims to "3\nextra" which contains a newline in the middle
        std::fs::write(dir.path().join(".csq-account"), "3\nextra").unwrap();
        assert_eq!(
            read_identity_marker(dir.path()),
            None,
            "multi-line content with corruption must return None"
        );
    }

    /// Acceptance: missing file returns None (not a panic).
    #[test]
    fn m1_5_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        // Do NOT write the file.
        assert_eq!(read_identity_marker(dir.path()), None);
    }

    /// Acceptance: integration test — write UUID to file, assert read_identity_marker
    /// extracts uuid: Some(...) correctly.
    #[test]
    fn m1_5_integration_uuid_file_round_trip() {
        let dir = TempDir::new().unwrap();
        let id = IdentityId::new_v4();
        let canonical = id.to_canonical_string();
        std::fs::write(dir.path().join(".csq-account"), &canonical).unwrap();

        let result = read_identity_marker(dir.path());
        assert!(result.is_some(), "UUID written to file must round-trip");
        let m = result.unwrap();
        assert!(m.numeric.is_none());
        assert_eq!(
            m.uuid.unwrap(),
            id,
            "parsed UUID must equal the one written"
        );
    }

    /// Acceptance: all boundary AccountNum values parse correctly.
    #[test]
    fn m1_5_boundary_numeric_values() {
        let dir = TempDir::new().unwrap();

        // minimum valid
        std::fs::write(dir.path().join(".csq-account"), "1").unwrap();
        let m = read_identity_marker(dir.path()).expect("1 must parse");
        assert_eq!(m.numeric, Some(AccountNum::try_from(1u16).unwrap()));

        // maximum valid
        std::fs::write(dir.path().join(".csq-account"), "999").unwrap();
        let m = read_identity_marker(dir.path()).expect("999 must parse");
        assert_eq!(m.numeric, Some(AccountNum::try_from(999u16).unwrap()));

        // just over maximum
        std::fs::write(dir.path().join(".csq-account"), "1000").unwrap();
        assert_eq!(
            read_identity_marker(dir.path()),
            None,
            "1000 is out of range — must return None"
        );
    }

    /// Property test: 10k deterministic random strings → no panic, no invented
    /// fallback. Uses a hand-rolled PRNG loop (no proptest dep needed).
    ///
    /// The invariant under test is the **no-silent-fallback guarantee**:
    /// - The parser MUST NOT invent a value. If it returns `Some(m)`, then `m`
    ///   must be the faithful parse of the input string — not a default.
    /// - Concretely: if the input string is neither a valid `AccountNum` nor a
    ///   valid UUID, the function MUST return `None`.
    /// - If the parser returns `Some`, exactly one field is populated (no
    ///   Both-Some corruption).
    ///
    /// Note: the string `"1"` legitimately parses to `numeric: Some(1)`. That
    /// is correct behavior, not a "fallback." The fallback guard only fires
    /// when the content does NOT represent a valid account number or UUID but
    /// the parser invents one anyway — that is the pattern this test detects.
    ///
    /// Strategy: generate strings of length 1..=50 from an alphabet that
    /// includes digits, hyphens, letters, and special chars. These cover
    /// partial UUIDs, partial integers, mixed garbage, and edge cases.
    #[test]
    fn m1_5_property_10k_random_strings_no_panic_no_fallback() {
        // xorshift32 — deterministic, no external dependency
        let mut state: u32 = 0xDEAD_BEEF;
        let next = |s: &mut u32| -> u32 {
            *s ^= *s << 13;
            *s ^= *s >> 17;
            *s ^= *s << 5;
            *s
        };

        let alphabet: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz-_. \t\n/ABCDEF!@#$%^&*()[]{}|";
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".csq-account");

        for _ in 0..10_000 {
            let len = (next(&mut state) % 50 + 1) as usize;
            let bytes: Vec<u8> = (0..len)
                .map(|_| alphabet[(next(&mut state) as usize) % alphabet.len()])
                .collect();
            let s = String::from_utf8_lossy(&bytes).into_owned();
            std::fs::write(&path, s.as_bytes()).unwrap();

            // Must never panic (the key property — absence of panic IS the test).
            let result = read_identity_marker(dir.path());

            if let Some(ref m) = result {
                // If we got Some, exactly one field must be populated.
                // Both-Some is a structural invariant violation.
                let count = m.numeric.is_some() as u8 + m.uuid.is_some() as u8;
                assert_eq!(
                    count, 1,
                    "property violation: both fields Some for string {s:?} — parser corruption"
                );

                // Cross-verify: if numeric is Some(n), the trimmed content must
                // round-trip back through AccountNum::from_str successfully.
                // This proves the parser didn't invent a value.
                if let Some(account) = m.numeric {
                    let trimmed = s.trim();
                    let reparsed: Option<AccountNum> = trimmed.parse().ok();
                    assert_eq!(
                        reparsed,
                        Some(account),
                        "property violation: numeric result {account} does not match \
                         re-parse of trimmed input {trimmed:?}"
                    );
                }

                // If uuid is Some(id), the trimmed content must parse as IdentityId.
                if let Some(id) = m.uuid {
                    let trimmed = s.trim();
                    let reparsed: Option<IdentityId> = trimmed.parse().ok();
                    assert_eq!(
                        reparsed.map(|i| i.to_canonical_string()),
                        Some(id.to_canonical_string()),
                        "property violation: UUID result does not match re-parse of \
                         trimmed input {trimmed:?}"
                    );
                }
            }
        }
    }

    /// Verify read_current_account backward-compat: UUID in .current-account
    /// returns None (numeric semantics only), not a panic.
    #[test]
    fn m1_5_read_current_account_compat_with_uuid() {
        let dir = TempDir::new().unwrap();
        let id = IdentityId::new_v4();
        std::fs::write(
            dir.path().join(".current-account"),
            id.to_canonical_string(),
        )
        .unwrap();

        // Existing callers of read_current_account must still get Option<AccountNum>.
        // A UUID file should return None from read_current_account (no numeric to extract).
        assert_eq!(
            read_current_account(dir.path()),
            None,
            "UUID in .current-account must return None from read_current_account (numeric only)"
        );

        // But read_current_identity_marker must return the UUID.
        let m =
            read_current_identity_marker(dir.path()).expect("UUID must parse via identity reader");
        assert!(m.numeric.is_none());
        assert_eq!(m.uuid.unwrap(), id);
    }
}
