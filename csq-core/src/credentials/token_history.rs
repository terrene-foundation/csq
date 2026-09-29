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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    let val: serde_json::Value = serde_json::from_str(raw_json).ok()?;
    let refresh = val.get("claudeAiOauth")?.get("refreshToken")?.as_str()?;
    Some(Fingerprint::of_refresh_token(refresh))
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
#[derive(Default, Serialize, Deserialize)]
struct HistoryFile {
    fingerprints: Vec<String>,
}

/// Reads `id`'s bounded token-history. Absence, an unreadable file, or a
/// malformed entry are ALL treated as "no history" — never an error. This
/// history only WIDENS what `keychain::decide_cc_keychain_write`
/// recognises as "known"; failing to read it merely NARROWS recognition
/// back to the pre-C-F1 current-token-only behaviour, which is the safe
/// direction on a destructive-classification path
/// (`guard-reader-writer-parity.md` MUST-2: fail closed, never fail open).
pub(crate) fn read_history(base: &Path, id: IdentityId) -> Vec<Fingerprint> {
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
        .filter_map(|s| Fingerprint::from_hex(s))
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
    if !ensure_identity_dir(base, id, "append_history") {
        return;
    }
    let _guard = match crate::platform::lock::lock_file(&token_history_lock_path(base, id)) {
        Ok(g) => g,
        Err(e) => {
            warn!(
                error_kind = "token_history_lock_failed",
                "token-history append: could not lock the history file — this \
                 refresh's fingerprint was NOT recorded (non-fatal): {}",
                crate::error::redact_tokens(&e.to_string())
            );
            return;
        }
    };
    let mut history = read_history(base, id);
    if history.last() == Some(&fp) {
        return;
    }
    history.push(fp);
    if history.len() > MAX_HISTORY_LEN {
        let excess = history.len() - MAX_HISTORY_LEN;
        history.drain(0..excess);
    }
    write_history_file(base, id, &history, "append_history");
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
    if !ensure_identity_dir(base, id, "start_new_segment") {
        return;
    }
    let _guard = match crate::platform::lock::lock_file(&token_history_lock_path(base, id)) {
        Ok(g) => g,
        Err(e) => {
            warn!(
                error_kind = "token_history_lock_failed",
                "token-history start_new_segment: could not lock the history file \
                 — the old segment was NOT cleared (non-fatal): {}",
                crate::error::redact_tokens(&e.to_string())
            );
            return;
        }
    };
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
    let existing = read_history(base, id);
    let new_segment: Vec<Fingerprint> = match existing.iter().rposition(|fp| *fp == current) {
        Some(pos) => existing[pos..].to_vec(),
        None => vec![current],
    };
    write_history_file(base, id, &new_segment, "start_new_segment");
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
fn write_history_file(base: &Path, id: IdentityId, fingerprints: &[Fingerprint], caller: &str) {
    let path = token_history_path_for(base, id);
    let file = HistoryFile {
        fingerprints: fingerprints.iter().map(|f| f.to_hex()).collect(),
    };
    let json = match serde_json::to_string(&file) {
        Ok(j) => j,
        Err(_) => return,
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
        return;
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "token_history_replace_failed",
            caller,
            "token-history write: atomic_replace failed: {}",
            crate::error::redact_tokens(&e.to_string())
        );
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
            &[Fingerprint::of_refresh_token("rt-toctou")],
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
}
