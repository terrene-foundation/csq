//! Read + classify a handle dir's `.claude.json` `oauthAccount` — the local
//! record of which Anthropic account a Claude Code session authenticated as.
//!
//! Claude Code writes `oauthAccount.emailAddress` into each session's
//! `CLAUDE_CONFIG_DIR/.claude.json` on `/login`. It is the ONLY local record of
//! which account a session is actually on (the keychain token itself is
//! account-anonymous). Two consumers depend on it:
//!
//! - The daemon custodian's wrong-account guard
//!   (`daemon::custodian::candidate_account_matches`) compares this against the
//!   bound account's `identity.json` email before adopting a harvested token —
//!   fail-closed on absence (`account-terminal-separation.md`).
//! - The `csq doctor` custodian-identity canary
//!   (`check_custodian_identity_canary`, an internal ticket) surfaces the degraded case
//!   where Claude Code has stopped writing the field: without it the guard
//!   refuses EVERY adoption and the credential refresh war silently returns.
//!
//! This module single-sources the parse so both consumers agree on what
//! "present / absent / drifted" means, and so the classifier is testable on
//! every platform (the keychain harvest that feeds the custodian is macOS-only).

use std::path::Path;

/// A `.claude.json` past this size is not buffered + JSON-parsed: the gate reader
/// [`read_oauth_email`] returns `None` (refuse) and the canary
/// [`classify_oauth_account`] returns [`OauthAccountState::FieldMissing`] (a
/// present, gate-refusing, non-fresh state). Claude Code's `.claude.json` carries
/// per-project history and can grow, but a realistic file is well under 1 MiB
/// (the maintainer host's largest live file was 42 KB) — this ceiling never
/// false-rejects a real one while bounding the read done on the daemon thread
/// under the swap lock (keychain harvest) and on the `csq doctor` path.
const MAX_CLAUDE_JSON_BYTES: u64 = 16 * 1024 * 1024;

/// Classification of a handle dir's `.claude.json` with respect to the
/// `oauthAccount.emailAddress` field the custodian's wrong-account gate depends
/// on (an internal ticket). Distinguishes a benign not-yet-populated dir from the
/// dangerous format-drift case so the `csq doctor` canary can alarm only on the
/// latter.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OauthAccountState {
    /// `oauthAccount.emailAddress` is present and non-empty after trim — healthy.
    Present,
    /// `.claude.json` is ABSENT or CONTENT-EMPTY (whitespace-only, or an empty
    /// JSON object `{}`). Claude Code has not (yet) written a usable file: a
    /// fresh / not-yet-populated session. Benign — the custodian fails closed for
    /// this dir this tick and self-heals once CC writes the field. NOT a drift
    /// signal.
    ///
    /// Empirically grounded (28 live sessions on the maintainer host, 2026-07-03,
    /// sizes 1999 B–42 KB): every populated `.claude.json` carried a usable
    /// `oauthAccount.emailAddress`; the ONLY no-email state observed was an
    /// ABSENT file. Claude Code writes `oauthAccount` as part of its first
    /// populated write, so "content present" and "no oauthAccount" do not
    /// co-occur in the fresh/not-yet-populated case — which is why a populated
    /// file lacking the field is drift, not a pre-login transient.
    NotYetPopulated,
    /// `.claude.json` is PRESENT with non-trivial content the wrong-account gate
    /// cannot extract a usable `oauthAccount.emailAddress` from. This is the
    /// format-drift / gate-degradation signal (an internal ticket). It covers EVERY present,
    /// non-fresh shape that makes `read_oauth_email` (the gate's reader) return
    /// `None`:
    /// - a populated JSON object with `oauthAccount` omitted, renamed, non-object,
    ///   or its `emailAddress` missing / empty;
    /// - a non-object JSON value (array / scalar) with real content;
    /// - an UNPARSEABLE non-empty file;
    /// - a file past [`MAX_CLAUDE_JSON_BYTES`] the gate refuses to read.
    ///
    /// On an authenticated (credential-bound) session ALL of these make the gate
    /// refuse every adoption for the account — the credential refresh war returns
    /// silently. The canary MUST surface the whole set (not just the missing-field
    /// sub-case), because the gate degrades to all-refuse on all of them
    /// identically (redteam R1 security-reviewer MEDIUM — false-negative blind
    /// spot on unparseable / non-object drift).
    FieldMissing,
}

/// Read `path` to a `String`, bounding the READ itself to at most
/// [`MAX_CLAUDE_JSON_BYTES`]. Returns:
/// - `Ok(Some(s))` — read fully within the bound;
/// - `Ok(None)` — present but oversized (the read hit the cap);
/// - `Err(e)` — open/read failed (absent when `e.kind() == NotFound`; otherwise
///   present-but-unreadable: perms, invalid UTF-8, IO).
///
/// Bounding the READ (via `Read::take`) rather than a prior `metadata().len()`
/// stat removes the stat→read TOCTOU where a same-user writer could enlarge the
/// file between the two syscalls and force an unbounded `read_to_string`
/// (redteam R2 rust-specialist LOW). One fewer syscall, and the buffer can never
/// exceed the cap regardless of concurrent growth.
fn read_bounded_claude_json(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let mut buf = String::new();
    // take(MAX+1): reading MAX+1 bytes proves the file exceeds the bound.
    file.take(MAX_CLAUDE_JSON_BYTES + 1)
        .read_to_string(&mut buf)?;
    if buf.len() as u64 > MAX_CLAUDE_JSON_BYTES {
        return Ok(None);
    }
    Ok(Some(buf))
}

/// Parse a handle dir's `.claude.json` into a JSON value, bounded by
/// [`MAX_CLAUDE_JSON_BYTES`]. `None` on absent / unreadable / oversized /
/// unparseable — callers treat `None` as "CC has written nothing usable here".
fn parse_claude_json(handle_dir: &Path) -> Option<serde_json::Value> {
    let content = read_bounded_claude_json(&handle_dir.join(".claude.json")).ok()??;
    serde_json::from_str(&content).ok()
}

/// Extract `oauthAccount.emailAddress` from an already-parsed value, trimmed.
/// `None` when the field is absent, not a string, or empty after trim.
fn oauth_email_of(json: &serde_json::Value) -> Option<String> {
    let email = json
        .get("oauthAccount")
        .and_then(|a| a.get("emailAddress"))
        .and_then(|v| v.as_str())?
        .trim();
    if email.is_empty() {
        None
    } else {
        Some(email.to_owned())
    }
}

/// Read the handle dir's `.claude.json` `oauthAccount.emailAddress`, trimmed.
///
/// Returns `None` on absent / unreadable / oversized / unparseable / empty —
/// callers MUST treat `None` as "account unknown" (the custodian fails closed).
/// This is the signal the daemon custodian captures under the swap lock as
/// `HarvestCandidate.candidate_email`.
pub fn read_oauth_email(handle_dir: &Path) -> Option<String> {
    oauth_email_of(&parse_claude_json(handle_dir)?)
}

/// Bounded read of a handle dir's `.claude.json` raw content, for callers that
/// need to parse + modify + rewrite it (e.g. the swap-time `oauthAccount` reconcile,
/// an internal ticket). `None` on absent / oversized / unreadable — callers skip (never
/// clobber a file they cannot safely round-trip). Single-sources the
/// [`MAX_CLAUDE_JSON_BYTES`] bound so a modify-in-place caller never buffers an
/// unbounded file.
pub fn read_raw(handle_dir: &Path) -> Option<String> {
    read_bounded_claude_json(&handle_dir.join(".claude.json"))
        .ok()
        .flatten()
}

/// Classify a handle dir's `.claude.json` for the custodian-identity canary
/// (an internal ticket). See [`OauthAccountState`] for the three outcomes.
///
/// The canary's drift-set MUST equal the wrong-account gate's refuse-set
/// ([`read_oauth_email`] returns `None`) MINUS the genuinely benign fresh subset
/// (absent / empty). Staged reads distinguish those:
/// - absent (`File::open` → `NotFound`)         → [`OauthAccountState::NotYetPopulated`]
/// - present but oversized                      → [`OauthAccountState::FieldMissing`]
/// - present but unreadable (perms/UTF-8/IO)    → [`OauthAccountState::FieldMissing`]
/// - whitespace-only / empty JSON object `{}`   → [`OauthAccountState::NotYetPopulated`]
/// - present, non-empty, UNPARSEABLE            → [`OauthAccountState::FieldMissing`]
/// - present, non-empty, usable email           → [`OauthAccountState::Present`]
/// - present, non-empty, no usable email        → [`OauthAccountState::FieldMissing`]
///
/// Unlike [`read_oauth_email`] (which collapses absent / oversize / unparseable
/// all to `None`), this fn reads in stages so a PRESENT-but-degraded file (which
/// breaks the gate) is not misreported as a benign fresh dir — the redteam R1
/// security-reviewer MEDIUM (false-negative blind spot on unparseable / non-object
/// drift).
pub fn classify_oauth_account(handle_dir: &Path) -> OauthAccountState {
    let path = handle_dir.join(".claude.json");
    let content = match read_bounded_claude_json(&path) {
        // Present but oversized: read_oauth_email bails on size and refuses
        // adoption. A gate-refusing, non-fresh state → surface.
        Ok(None) => return OauthAccountState::FieldMissing,
        Ok(Some(c)) => c,
        // Absent → CC has written nothing here yet → fresh.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return OauthAccountState::NotYetPopulated;
        }
        // Present but unreadable (perms / invalid UTF-8 / IO) → gate refuses → degraded.
        Err(_) => return OauthAccountState::FieldMissing,
    };
    if content.trim().is_empty() {
        // Empty / whitespace-only file → CC created it but wrote nothing → fresh.
        return OauthAccountState::NotYetPopulated;
    }
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        // Present, non-empty, unparseable → the gate's read_oauth_email returns
        // None and refuses. A CC that drifted to an unparseable shape breaks the
        // gate exactly like a missing field → surface it, never hide it as fresh.
        return OauthAccountState::FieldMissing;
    };
    // An empty JSON object `{}` is CC's initialized-but-idle shape → fresh.
    if matches!(json.as_object(), Some(o) if o.is_empty()) {
        return OauthAccountState::NotYetPopulated;
    }
    // Present, non-empty, parseable. A usable oauthAccount.emailAddress → healthy;
    // anything else (object without the field, field renamed / emptied, oauthAccount
    // a non-object, or a non-object top-level JSON value) → the gate cannot extract
    // an account identity → FieldMissing (drift).
    if oauth_email_of(&json).is_some() {
        OauthAccountState::Present
    } else {
        OauthAccountState::FieldMissing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_claude_json(dir: &Path, body: &str) {
        let mut f = std::fs::File::create(dir.join(".claude.json")).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    // ── read_raw ──────────────────────────────────────────────────────────────

    #[test]
    fn read_raw_returns_content_or_none() {
        let dir = tempfile::TempDir::new().unwrap();
        // Absent → None.
        assert_eq!(read_raw(dir.path()), None);
        // Present → verbatim content.
        write_claude_json(dir.path(), r#"{"a":1}"#);
        assert_eq!(read_raw(dir.path()).as_deref(), Some(r#"{"a":1}"#));
        // Oversized → None (bounded, not buffered).
        let pad = "x".repeat((MAX_CLAUDE_JSON_BYTES as usize) + 1);
        write_claude_json(dir.path(), &format!(r#"{{"_pad":"{pad}"}}"#));
        assert_eq!(read_raw(dir.path()), None);
    }

    // ── read_oauth_email ──────────────────────────────────────────────────────

    #[test]
    fn read_oauth_email_returns_trimmed_email() {
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(
            dir.path(),
            r#"{"oauthAccount":{"emailAddress":"  User@Example.com  "}}"#,
        );
        assert_eq!(
            read_oauth_email(dir.path()).as_deref(),
            Some("User@Example.com")
        );
    }

    #[test]
    fn read_oauth_email_none_when_absent_empty_or_unparseable() {
        let dir = tempfile::TempDir::new().unwrap();
        // absent
        assert_eq!(read_oauth_email(dir.path()), None);
        // empty email
        write_claude_json(dir.path(), r#"{"oauthAccount":{"emailAddress":""}}"#);
        assert_eq!(read_oauth_email(dir.path()), None);
        // unparseable
        write_claude_json(dir.path(), "not json {");
        assert_eq!(read_oauth_email(dir.path()), None);
    }

    #[test]
    fn read_oauth_email_skips_oversize_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let pad = "x".repeat((MAX_CLAUDE_JSON_BYTES as usize) + 1);
        write_claude_json(
            dir.path(),
            &format!(r#"{{"oauthAccount":{{"emailAddress":"user@example.com"}},"_pad":"{pad}"}}"#),
        );
        assert_eq!(read_oauth_email(dir.path()), None);
    }

    // ── classify_oauth_account ────────────────────────────────────────────────

    #[test]
    fn classify_present_when_email_usable() {
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(
            dir.path(),
            r#"{"numStartups":3,"oauthAccount":{"emailAddress":"user@example.com"}}"#,
        );
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::Present
        );
    }

    #[test]
    fn classify_not_yet_populated_when_absent() {
        let dir = tempfile::TempDir::new().unwrap();
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::NotYetPopulated
        );
    }

    #[test]
    fn classify_not_yet_populated_when_empty_object_or_whitespace() {
        // CC's initialized-but-idle shape (`{}`) and a whitespace-only file are
        // both fresh (not-yet-populated), never drift.
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(dir.path(), "{}");
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::NotYetPopulated
        );
        write_claude_json(dir.path(), "   \n  ");
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::NotYetPopulated
        );
    }

    #[test]
    fn classify_field_missing_when_unparseable() {
        // R1 security-reviewer MEDIUM: an unparseable present file breaks the gate
        // (read_oauth_email → None → all-refuse) exactly like a missing field →
        // MUST surface as drift, not hide as fresh. (Exercises the serde `Err` arm.)
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(dir.path(), "not json {");
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::FieldMissing
        );
    }

    #[test]
    fn classify_field_missing_when_non_object_top_level() {
        // A non-empty JSON array / scalar is content the gate can't read an email
        // from → drift. (Exercises the parseable-but-no-oauthAccount arm, distinct
        // from the unparseable arm above — redteam R2 NIT F5.)
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(dir.path(), "[1,2,3]");
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::FieldMissing
        );
    }

    #[cfg(unix)]
    #[test]
    fn classify_field_missing_when_present_but_unreadable() {
        // R2 testing-specialist F3: a present-but-unreadable file (perms) makes the
        // gate refuse (read_oauth_email → None) — it MUST classify as drift, not the
        // absent/fresh case. Distinguished from NotFound by the Err(kind) match.
        use std::os::unix::fs::PermissionsExt;
        // Root bypasses file perms, so a 0o000 file stays readable → skip under root.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".claude.json");
        std::fs::write(&path, r#"{"oauthAccount":{"emailAddress":"u@x.com"}}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let got = classify_oauth_account(dir.path());
        // Restore perms so TempDir cleanup can remove the file.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        assert_eq!(got, OauthAccountState::FieldMissing);
    }

    #[test]
    fn classify_field_missing_when_oversized() {
        // R1 security-reviewer MEDIUM: a file past the gate's read ceiling makes
        // read_oauth_email bail (→ None → all-refuse). Present + gate-refusing →
        // drift, not the absent/fresh case.
        let dir = tempfile::TempDir::new().unwrap();
        let pad = "x".repeat((MAX_CLAUDE_JSON_BYTES as usize) + 1);
        write_claude_json(
            dir.path(),
            &format!(r#"{{"oauthAccount":{{"emailAddress":"user@example.com"}},"_pad":"{pad}"}}"#),
        );
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::FieldMissing
        );
    }

    #[test]
    fn classify_field_missing_when_oauth_account_is_non_object() {
        // R1 deep-analyst Finding 3: `oauthAccount` present as a scalar/null on a
        // populated object → no usable email → drift.
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(dir.path(), r#"{"numStartups":3,"oauthAccount":"garbage"}"#);
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::FieldMissing
        );
        write_claude_json(dir.path(), r#"{"numStartups":3,"oauthAccount":null}"#);
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::FieldMissing
        );
    }

    #[test]
    fn classify_field_missing_when_populated_but_no_oauth_account() {
        // The an internal ticket drift signal: CC populated the file but no oauthAccount at all.
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(
            dir.path(),
            r#"{"numStartups":3,"userID":"abc","projects":{}}"#,
        );
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::FieldMissing
        );
    }

    #[test]
    fn classify_field_missing_when_oauth_account_present_but_email_renamed() {
        // Drift sub-case: oauthAccount object present, emailAddress renamed/removed.
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(
            dir.path(),
            r#"{"numStartups":3,"oauthAccount":{"email":"user@example.com"}}"#,
        );
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::FieldMissing
        );
    }

    #[test]
    fn classify_field_missing_when_email_empty_but_object_populated() {
        // oauthAccount.emailAddress present but empty → not usable → drift on a
        // populated object.
        let dir = tempfile::TempDir::new().unwrap();
        write_claude_json(
            dir.path(),
            r#"{"numStartups":3,"oauthAccount":{"emailAddress":"   "}}"#,
        );
        assert_eq!(
            classify_oauth_account(dir.path()),
            OauthAccountState::FieldMissing
        );
    }
}
