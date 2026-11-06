//! The TARGET session's opt-in for a cross-session (orchestrator-triggered) recycle
//! (design: `internal-design-docs`, ROOT-ratified
//! 2026-11-04 with amendments A1-A4).
//!
//! Load-bearing framing: on one host, same uid already means same power — any process running as this
//! user can SIGKILL the target. Consent, expiry, use-counts and identity binding therefore buy
//! LEGITIMATE INTENT, ACCIDENT CONTROL and ATTRIBUTION. They are not a capability boundary, and this
//! module never pretends otherwise.
//!
//! A consent is written by the TARGET's own terminal (A1) — `csq session consent` run from inside the
//! target's session — never by a peer on its behalf. It names explicit requesters (no wildcard, no
//! peer-chosen name), is bound to the target's CURRENT session id (a `/clear` or a fresh relaunch
//! voids it), carries a mandatory expiry, and defaults to a single use.

use super::recycle::{read_json_bounded, write_json_private, Tag};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// `<handle>/.csq-recycle-consent.json`.
pub const CONSENT_FILE: &str = ".csq-recycle-consent.json";
/// `<handle>/.csq-recycle-consent.lock`: serializes every read-modify-write of the consent —
/// the daemon's issue-time use consumption and the target's own grant/revoke.
pub const CONSENT_LOCK_FILE: &str = ".csq-recycle-consent.lock";

/// Path of the consent lock for `handle`.
pub fn consent_lock_path(handle: &Path) -> std::path::PathBuf {
    handle.join(CONSENT_LOCK_FILE)
}
/// Schema version.
pub const CONSENT_VERSION: u32 = 1;
/// An explicit list only: a consent with more entries than this is refused as malformed
/// rather than silently truncated.
pub const MAX_CONSENT_ENTRIES: usize = 8;
/// Default consent lifetime (seconds). Bounded so a forgotten grant cannot live forever.
pub const DEFAULT_CONSENT_TTL_SECS: i64 = 12 * 60 * 60;
/// Hard cap on a consent's lifetime, whatever `--ttl` asks for.
pub const MAX_CONSENT_TTL_SECS: i64 = 7 * 24 * 60 * 60;
/// Most issues one consent may authorise. A typo in `--max-uses` must not mint an effectively
/// unlimited grant; the CLI floors at 1 and caps here.
pub const MAX_CONSENT_USES: u32 = 64;

/// One explicitly named requester.
///
/// The identity is the REQUESTER'S CONVERSATION, not its pid: a session that is itself recycled with
/// `--resume` keeps its id and its consent; a fresh relaunch mints a new id and must be re-granted.
/// `handle` is the requester's config dir, so two accounts cannot be confused for each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequesterRecord {
    /// The requester's Claude Code session id (from Claude Code's own registry at request time).
    pub session_id: String,
    /// The requester's handle dir, canonical absolute.
    pub handle: String,
}

/// `<handle>/.csq-recycle-consent.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Schema version (1).
    pub v: u32,
    /// The TARGET session id this consent is bound to. A different id voids the consent.
    pub target_session_id: String,
    /// The explicitly allowed requesters.
    pub allow: Vec<RequesterRecord>,
    /// Unix seconds after which the consent is void (mandatory).
    pub expires_at_unix: i64,
    /// Uses granted. `used >= max_uses` means spent.
    pub max_uses: u32,
    /// Uses already consumed by an acted-on request.
    #[serde(default)]
    pub used: u32,
}

/// Why a consent refuses. All fixed vocabulary — never a path, token or OS string.
pub type Refusal = Tag;

/// Reads the consent; `Ok(None)` = none, `Err` = present but not trustworthy.
pub fn read_consent(handle: &Path) -> Result<Option<ConsentRecord>, Refusal> {
    let Some(rec): Option<ConsentRecord> =
        read_json_bounded(&handle.join(CONSENT_FILE)).map_err(|_| "xrecycle_consent_unreadable")?
    else {
        return Ok(None);
    };
    validate(&rec)?;
    Ok(Some(rec))
}

fn validate(rec: &ConsentRecord) -> Result<(), Refusal> {
    if rec.v != CONSENT_VERSION
        || super::recycle::validate_session_id(&rec.target_session_id).is_err()
        || rec.allow.is_empty()
        || rec.allow.len() > MAX_CONSENT_ENTRIES
        || rec.max_uses == 0
        || rec.used > rec.max_uses
        || rec.expires_at_unix <= 0
    {
        return Err("xrecycle_consent_unreadable");
    }
    for r in &rec.allow {
        // A malformed entry refuses the whole file: a half-valid consent is ambiguity,
        // and ambiguity must never authorise a kill.
        if super::recycle::validate_session_id(&r.session_id).is_err()
            || r.handle.is_empty()
            || !Path::new(&r.handle).is_absolute()
        {
            return Err("xrecycle_consent_unreadable");
        }
    }
    Ok(())
}

/// Writes the consent (0600, atomic) after validating it.
pub fn write_consent(handle: &Path, rec: &ConsentRecord) -> Result<(), Refusal> {
    validate(rec)?;
    if rec.expires_at_unix <= chrono::Utc::now().timestamp() {
        // A consent that is already expired is a mistake, not a grant.
        return Err("xrecycle_consent_expired");
    }
    write_json_private(handle, CONSENT_FILE, rec)
}

/// Removes the consent. `true` when it is gone afterwards (absence is success).
pub fn revoke_consent(handle: &Path) -> bool {
    match std::fs::remove_file(handle.join(CONSENT_FILE)) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

/// Decides whether `requester` may recycle `target_session` now.
///
/// Checks, in order (each its own fixed tag):
/// 1. the consent exists and is readable;
/// 2. it is bound to the TARGET's current session id (`/clear` voids it);
/// 3. the requester is named explicitly (session id AND handle);
/// 4. it has not expired.
///
/// Deliberately NOT the use count: this is the check for an ALREADY-ISSUED request. The daemon
/// spends a use at ISSUE time ([`consent_allows`] is what refuses a spent consent there), so the
/// supervisor's kill-point re-check must not read the spent use as a refusal — the request's
/// single-use nonce is the target-side control.
pub fn consent_allows_issued(
    consent: Option<&ConsentRecord>,
    target_session: &str,
    requester: &RequesterRecord,
    now_unix: i64,
) -> Result<(), Refusal> {
    let Some(rec) = consent else {
        return Err("xrecycle_not_consented");
    };
    if rec.target_session_id != target_session {
        // A consent granted to a previous conversation of this terminal never transfers.
        return Err("xrecycle_not_consented");
    }
    if !rec.allow.iter().any(|r| r == requester) {
        return Err("xrecycle_not_consented");
    }
    if now_unix >= rec.expires_at_unix {
        return Err("xrecycle_consent_expired");
    }
    Ok(())
}

/// Decides whether `requester` may obtain a NEW request now: [`consent_allows_issued`] plus a
/// use left. Only the daemon's issue path calls this; the use is spent under the consent lock
/// immediately before the request is written.
///
/// Returns `Ok(())` only when every check passes.
pub fn consent_allows(
    consent: Option<&ConsentRecord>,
    target_session: &str,
    requester: &RequesterRecord,
    now_unix: i64,
) -> Result<(), Refusal> {
    consent_allows_issued(consent, target_session, requester, now_unix)?;
    if consent.is_some_and(|rec| rec.used >= rec.max_uses) {
        return Err("xrecycle_consent_spent");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &str = "123e4567-e89b-12d3-a456-426614174000";
    const OTHER: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const REQ: &str = "99999999-8888-7777-6666-555555555555";

    /// A platform-ABSOLUTE handle: a leading `/` is root-without-prefix on Windows, where
    /// `Path::is_absolute` is false and `validate` (correctly) refuses the record.
    fn abs_handle(leaf: &str) -> String {
        std::env::temp_dir()
            .join(leaf)
            .to_string_lossy()
            .into_owned()
    }

    fn requester() -> RequesterRecord {
        RequesterRecord {
            session_id: REQ.into(),
            handle: abs_handle("term-7"),
        }
    }

    fn record() -> ConsentRecord {
        ConsentRecord {
            v: CONSENT_VERSION,
            target_session_id: TARGET.into(),
            allow: vec![requester()],
            expires_at_unix: chrono::Utc::now().timestamp() + 600,
            max_uses: 1,
            used: 0,
        }
    }

    #[test]
    fn a_fresh_consent_allows_only_its_named_requester_for_its_own_session() {
        let rec = record();
        let now = chrono::Utc::now().timestamp();
        assert_eq!(
            consent_allows(Some(&rec), TARGET, &requester(), now),
            Ok(())
        );
        // A different requester, a different handle, a different target session: all refused.
        let stranger = RequesterRecord {
            session_id: REQ.into(),
            handle: abs_handle("term-8"),
        };
        assert_eq!(
            consent_allows(Some(&rec), TARGET, &stranger, now),
            Err("xrecycle_not_consented")
        );
        assert_eq!(
            consent_allows(Some(&rec), OTHER, &requester(), now),
            Err("xrecycle_not_consented"),
            "a consent never transfers to another conversation"
        );
        assert_eq!(
            consent_allows(None, TARGET, &requester(), now),
            Err("xrecycle_not_consented")
        );
    }

    #[test]
    fn expiry_and_use_count_are_enforced() {
        let rec = record();
        let later = rec.expires_at_unix + 1;
        assert_eq!(
            consent_allows(Some(&rec), TARGET, &requester(), later),
            Err("xrecycle_consent_expired")
        );
        let mut spent = rec.clone();
        spent.used = spent.max_uses;
        assert_eq!(
            consent_allows(Some(&spent), TARGET, &requester(), 0),
            Err("xrecycle_consent_spent")
        );
    }

    #[test]
    fn a_malformed_or_already_expired_consent_is_never_written() {
        let d = tempfile::tempdir().unwrap();
        let mut rec = record();
        rec.allow.clear();
        assert_eq!(
            write_consent(d.path(), &rec),
            Err("xrecycle_consent_unreadable"),
            "no wildcard: an empty allow list is malformed, not 'everyone'"
        );
        let mut rec = record();
        rec.expires_at_unix = chrono::Utc::now().timestamp() - 1;
        assert_eq!(
            write_consent(d.path(), &rec),
            Err("xrecycle_consent_expired")
        );
        let mut rec = record();
        rec.allow[0].handle = "relative/path".into();
        assert_eq!(
            write_consent(d.path(), &rec),
            Err("xrecycle_consent_unreadable"),
            "a handle must be absolute"
        );
        assert!(!d.path().join(CONSENT_FILE).exists(), "nothing was written");
    }

    #[test]
    fn write_read_and_revoke_a_consent() {
        let d = tempfile::tempdir().unwrap();
        let rec = record();
        write_consent(d.path(), &rec).unwrap();
        assert_eq!(read_consent(d.path()).unwrap().as_ref(), Some(&rec));
        assert!(revoke_consent(d.path()));
        assert_eq!(read_consent(d.path()).unwrap(), None);
        assert!(!d.path().join(CONSENT_FILE).exists());
    }

    #[test]
    fn a_spent_consent_refuses_a_new_issue_but_still_covers_the_issued_request() {
        let mut spent = record();
        spent.used = spent.max_uses;
        let now = chrono::Utc::now().timestamp();
        assert_eq!(
            consent_allows(Some(&spent), TARGET, &requester(), now),
            Err("xrecycle_consent_spent"),
            "the issue-time check refuses once the uses are spent"
        );
        assert_eq!(
            consent_allows_issued(Some(&spent), TARGET, &requester(), now),
            Ok(()),
            "the request issued under that use is still valid at the kill point"
        );
        assert_eq!(
            consent_allows_issued(None, TARGET, &requester(), now),
            Err("xrecycle_not_consented")
        );
        let mut expired = record();
        expired.expires_at_unix = now - 1;
        assert_eq!(
            consent_allows_issued(Some(&expired), TARGET, &requester(), now),
            Err("xrecycle_consent_expired"),
            "the issued check still enforces expiry"
        );
    }
}
