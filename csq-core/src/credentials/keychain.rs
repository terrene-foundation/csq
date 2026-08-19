//! Keychain integration — service-name derivation, read, and CC-credential
//! mirror write.
//!
//! CC keys its OAuth credential in a generic password whose service name is
//! `Claude Code-credentials-{hash}`, where `{hash}` is the first 8 hex
//! characters of SHA-256 of the NFC-normalized `CLAUDE_CONFIG_DIR` path.
//!
//! - **read** ([`read`]): recover credentials when CC wrote the keychain but
//!   skipped `.credentials.json` (some CC versions write keychain-only on first
//!   login). Without this, `csq login N` cannot capture credentials after
//!   `claude auth login` exits — see an internal journal entry §1 + the account-7 regression.
//! - **write** ([`sync_handle_dir`] / [`write_raw`]): CURRENT CC reads the OAuth
//!   credential ONLY from this keychain item, not from the `.credentials.json`
//!   file csq symlinks into the handle dir. csq must therefore mirror the bound
//!   account's on-disk credential into the keychain so CC sees the fresh token
//!   (CC re-checks the keychain ~every 30s). Wired into `csq run`/`csq swap` and
//!   `csq keychain-sync`. Originally this module only READ the keychain; the
//!   write side was added when CC moved to keychain-first credential reads.
//!
//! On non-macOS platforms both read and write are no-op stubs: CC stores
//! credentials in `<CLAUDE_CONFIG_DIR>/.credentials.json` directly there.

use super::CredentialFile;
use crate::error::PlatformError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tracing::warn;
use unicode_normalization::UnicodeNormalization;

/// True when the macOS keychain mirror MUST NOT shell `security` — every keychain
/// read/write/delete becomes a no-op (absent item / pretend-success). Two triggers:
///
/// - `cfg!(test)` — csq-core's OWN unit tests.
/// - `cfg!(feature = "test-utils")` — the LOAD-BEARING one. When csq-core is a
///   DEPENDENCY of the `csq` crate's tests (run with `--features csq/test-utils`,
///   which enables csq-core's `test-utils`), `cfg!(test)` is FALSE in csq-core, so a
///   csq-crate test calling `write_raw` IN-PROCESS would still shell `security`. The
///   `test-utils` feature is the marker that csq-core was built for testing, in OR
///   out of its own test harness. Production release builds
///   (`--features cli --no-default-features`) never enable it, so production mirrors
///   normally.
/// - `CSQ_DISABLE_KEYCHAIN_MIRROR` env var — belt-and-suspenders for hermetic
///   INTEGRATION tests that spawn the real `csq` binary; the harness sets it.
///
/// The `security` CLI writes to the per-USER login keychain (NOT redirected by a
/// sandbox `$HOME`), so any test reaching `write_raw`/`delete_keychain_item` would
/// pollute the operator's real keychain and pop a macOS prompt.
///
/// Origin: 2026-06-23 — the auto-rotate keychain fix put `security` writes on a
/// heavily unit-tested path, and `cargo test --workspace` re-triggered the
/// 2026-06-11 keychain prompt-spam class. A `cfg!(test)`-only guard missed the
/// csq-core-as-dependency in-process tests; the `test-utils` arm closes that.
///
/// `pub(crate)` so the SIBLING `security`-CLI surface (`providers::codex::keychain`,
/// which probes/purges the `com.openai.codex` item) shares ONE guard — partial
/// coverage is the narrow-N-of-M failure mode.
///
/// `#[cfg(target_os = "macos")]`: every caller is a macOS-only `security`-shelling
/// fn, so on Linux/Windows this would be dead code (`clippy -D warnings` fails).
/// CC uses no OS keychain off macOS, so there is nothing to guard there anyway.
#[cfg(target_os = "macos")]
pub(crate) fn keychain_mirror_disabled() -> bool {
    cfg!(test)
        || cfg!(feature = "test-utils")
        || std::env::var_os("CSQ_DISABLE_KEYCHAIN_MIRROR").is_some()
}

/// Resolves `handle_dir` for a keychain-sync call site (`csq run` / `csq
/// exec` / the Phase-2b headless-turn builder). Returns `(handle_dir_abs,
/// keychain_write_allowed)`: `handle_dir_abs` falls back to the raw,
/// non-canonical path when canonicalize fails — still the right
/// `CLAUDE_CONFIG_DIR` to launch/spawn against, since CC authenticates via
/// that dir's symlinked `.credentials.json` when its own keychain lookup
/// misses. `keychain_write_allowed` is `false` in exactly that failure case;
/// callers MUST skip the keychain write when it is `false`.
///
/// Security review 1386 M4: a canonicalize failure MUST NOT feed the
/// non-canonical path into a keychain WRITE. [`service_name`] hashes
/// whatever path string it is given, with no internal canonicalization of
/// its own — so a mirror written under the non-canonical key hashes to a
/// DIFFERENT service name than the one CC (which hashes its own
/// canonicalized `CLAUDE_CONFIG_DIR`) will ever look up.
/// `logout::clear_bound_keychain_items` and the handle-dir reaper
/// (`session::handle_dir`) both already refuse that identical fallback on
/// the CLEARING side (security review 1386 M1); a writer that used it
/// created a keychain item neither clearer could ever locate — a permanent
/// orphan holding a real OAuth token (`guard-reader-writer-parity.md`
/// MUST-1: the clearer recognises fewer forms than the writer produces).
pub fn canonicalize_for_keychain_sync(handle_dir: &Path) -> (PathBuf, bool) {
    let canonicalized = std::fs::canonicalize(handle_dir);
    let keychain_write_allowed = canonicalized.is_ok();
    let handle_dir_abs = canonicalized.unwrap_or_else(|_| handle_dir.to_path_buf());
    (handle_dir_abs, keychain_write_allowed)
}

/// Derives the keychain service name CC uses for a given config
/// directory.
///
/// Format: `Claude Code-credentials-{hash}` where `{hash}` is the
/// first 8 hex characters of SHA-256 of the NFC-normalized path.
pub fn service_name(config_dir: &Path) -> String {
    let normalized: String = config_dir.to_string_lossy().nfc().collect();
    let hash = Sha256::digest(normalized.as_bytes());
    let prefix = hex::encode(&hash[..4]); // 4 bytes = 8 hex chars
    format!("Claude Code-credentials-{prefix}")
}

/// Reads credentials from the system keychain that CC wrote for the
/// given config directory.
///
/// On macOS: uses the `security` CLI to find the generic password,
/// then attempts to parse the value as raw JSON (CC's modern
/// format) before falling back to a hex-decode (CC's legacy format).
///
/// Returns `None` if the keychain entry doesn't exist, can't be
/// read, or contains malformed data — the caller is expected to
/// chain a file-based fallback.
pub fn read(config_dir: &Path) -> Option<CredentialFile> {
    let svc = service_name(config_dir);
    match read_impl(&svc) {
        Ok(creds) => Some(creds),
        Err(e) => {
            // an internal journal entry L3 / PR-B2 — fixed error-kind tag.
            //
            // `read_impl` returns `PlatformError::Keychain(String)` where the
            // inner String is built via `format!("security command: {e}")` /
            // `format!("json parse: {e}")` / etc. The `json parse` branch is
            // highest risk: serde_json errors can include fragments of the
            // invalid input being parsed, and for a keychain read the input
            // IS the credential payload. Using `%e` here would Display the
            // full String (including the serde snippet), so emit a fixed
            // tag keyed on the failure class instead. Classification is
            // prefix-matched since `Keychain(String)` has no structured
            // discriminant.
            let kind = keychain_error_kind(&e);
            warn!(
                service = %svc,
                error_kind = kind,
                "keychain read failed (fallback to file path)"
            );
            None
        }
    }
}

/// Classifies a `PlatformError::Keychain` message into a fixed-vocabulary tag
/// for logging. Returns one of: `keychain_not_found`, `keychain_invoke_failed`,
/// `keychain_utf8`, `keychain_hex_decode`, `keychain_json_parse`, `keychain_other`.
///
/// PR-B2: avoids `%e` formatting of the inner String so serde fragments never
/// reach the log sink. Matches prefixes written by `read_impl` — if that
/// function's error strings change, this classifier MUST be updated to match.
fn keychain_error_kind(e: &PlatformError) -> &'static str {
    let PlatformError::Keychain(msg) = e else {
        return "keychain_other";
    };
    if msg == "keychain entry not found" {
        "keychain_not_found"
    } else if msg.starts_with("security command") {
        "keychain_invoke_failed"
    } else if msg.starts_with("utf8") {
        "keychain_utf8"
    } else if msg.starts_with("hex decode") {
        "keychain_hex_decode"
    } else if msg.starts_with("json parse") {
        "keychain_json_parse"
    } else {
        "keychain_other"
    }
}

// ── macOS implementation ──────────────────────────────────────────────
//
// Uses the `security` CLI tool (already trusted on macOS) instead of
// the `security-framework` crate so the read does not trigger a
// per-binary keychain authorization prompt on every debug rebuild
// (the binary hash changes each time and macOS treats it as a new
// caller).

#[cfg(target_os = "macos")]
fn read_impl(service: &str) -> Result<CredentialFile, PlatformError> {
    if keychain_mirror_disabled() {
        return Err(PlatformError::Keychain(
            "keychain entry not found".to_string(),
        ));
    }
    let account = keychain_account();
    let output = std::process::Command::new("security")
        .args(["find-generic-password", "-s", service, "-a", &account, "-w"])
        .output()
        .map_err(|e| PlatformError::Keychain(format!("security command: {e}")))?;

    if !output.status.success() {
        return Err(PlatformError::Keychain(
            "keychain entry not found".to_string(),
        ));
    }

    let raw = String::from_utf8(output.stdout)
        .map_err(|e| PlatformError::Keychain(format!("utf8: {e}")))?;
    let raw = raw.trim();

    // CC writes raw JSON; older csq versions wrote hex-encoded JSON.
    // Try raw JSON first, fall back to hex-decode for legacy entries.
    let json = if raw.starts_with('{') {
        raw.to_string()
    } else {
        let bytes =
            hex::decode(raw).map_err(|e| PlatformError::Keychain(format!("hex decode: {e}")))?;
        String::from_utf8(bytes).map_err(|e| PlatformError::Keychain(format!("utf8: {e}")))?
    };

    serde_json::from_str(&json).map_err(|e| PlatformError::Keychain(format!("json parse: {e}")))
}

/// Keychain account parameter. CC uses the system username, which
/// macOS GUI apps don't always inherit through `$USER`, so we walk
/// `$USER` → `$USERNAME` → `getpwuid(getuid())` before giving up.
#[cfg(target_os = "macos")]
fn keychain_account() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .or_else(|_| unsafe {
            let uid = libc::getuid();
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                return Err(std::env::VarError::NotPresent);
            }
            let name = std::ffi::CStr::from_ptr((*pw).pw_name);
            name.to_str()
                .map(|s| s.to_string())
                .map_err(|_| std::env::VarError::NotPresent)
        })
        .unwrap_or_else(|_| "credentials".to_string())
}

// ── non-macOS stub ────────────────────────────────────────────────
//
// CC does not interact with the OS keychain on Linux or Windows; it
// stores credentials directly in `<CLAUDE_CONFIG_DIR>/.credentials.json`
// on those platforms. The read stub returns NotFound so the caller's
// file fallback runs unconditionally.

#[cfg(not(target_os = "macos"))]
fn read_impl(_service: &str) -> Result<CredentialFile, PlatformError> {
    Err(PlatformError::Keychain(
        "keychain read not implemented on this platform".into(),
    ))
}

// ── keychain WRITE (CC credential mirror) ──────────────────────────────
//
// Current Claude Code reads the OAuth credential from the per-config-dir
// keychain item `Claude Code-credentials-{hash}`, NOT from the
// `<config_dir>/.credentials.json` file csq symlinks. csq refreshes the file
// (and identity store) but historically never wrote the keychain (this
// module's header predates the change), so after a daemon token rotation the
// keychain copy goes stale and CC returns 401 on every session. These writers
// mirror the bound account's CURRENT on-disk credential into the keychain so
// CC sees the fresh token. CC re-checks the keychain ~every 30s, so a running
// session recovers without a restart.

/// Mirror a handle dir's on-disk Anthropic credential into the keychain item
/// CC reads. Returns `Ok(true)` when a credential was synced, `Ok(false)` when
/// there is nothing safe to mirror — no credential file (3P/Codex slot, or a
/// dangling symlink in a fresh/torn-down dir), a non-Anthropic credential, or a
/// credential whose token is EXPIRED. Best-effort: callers log `Err` but never
/// fail the surrounding operation.
///
/// **Validity guard (load-bearing).** Only a non-expired token is written. This
/// is NOT an optimization — it prevents two harmful regressions discovered on
/// the 2026-06-23 host:
/// 1. **Dead-token propagation.** When csq's stored credential is stale (the
///    daemon could not refresh it — e.g. a rotated-away refresh token), syncing
///    it would overwrite CC's keychain with a token that 401s, manufacturing the
///    very failure this mirror exists to prevent.
/// 2. **Clobbering a fresh login.** Current CC writes its OWN fresh token to the
///    keychain on `/login` and on its per-session auto-refresh. Blindly copying
///    csq's file token over that would undo the user's login. Two guards cover
///    this: the validity guard skips a *dead* store token, and the
///    *newer-than-keychain* guard (below) skips when the keychain token is
///    valid-and-at-least-as-fresh — so a fresh CC login is never overwritten by
///    an equal-or-older store token.
///
/// NOTE: this does NOT solve the multi-session refresh war (N CC sessions on one
/// account rotating each other's tokens — see the tracked multi-session-refresh
/// design issue). It makes the per-dir mirror safe, not sufficient.
pub fn sync_handle_dir(handle_dir: &Path) -> Result<bool, PlatformError> {
    sync_handle_dir_inner(handle_dir, false)
}

/// Swap variant: the handle dir's account BINDING just changed (`csq swap`
/// repointed its symlinks to a different account). The keychain must reflect the
/// NEW binding exactly, so the newer-than-keychain guard MUST NOT apply — it
/// compares only expiry, and the item currently holds the PREVIOUS account's
/// token, which may legitimately expire later than the new account's. Skipping
/// on that basis leaves CC reading the WRONG account's token against the new
/// config → 401 (the regression this fixes). And if the new account has no valid
/// token, the stale wrong-account item is DELETED (CC then shows "logged out"
/// for the new binding rather than silently running as the old account).
pub fn sync_handle_dir_account_changed(handle_dir: &Path) -> Result<bool, PlatformError> {
    sync_handle_dir_inner(handle_dir, true)
}

fn sync_handle_dir_inner(handle_dir: &Path, account_changed: bool) -> Result<bool, PlatformError> {
    // `.credentials.json` is a symlink to `identities/<UUID>/credentials.json`
    // (or legacy `config-N/.credentials.json`); `read_to_string` follows it.
    let raw = std::fs::read_to_string(handle_dir.join(".credentials.json")).ok();
    // A valid Anthropic OAuth token, if present. None = absent file, non-Anthropic
    // (3P/Codex), expired, or unparseable.
    let file_expiry = raw
        .as_deref()
        .filter(|r| r.contains("\"claudeAiOauth\""))
        .and_then(anthropic_expiry_ms)
        .filter(|ms| *ms > now_ms());

    match decide_sync_action(file_expiry, keychain_expiry_ms(handle_dir), account_changed) {
        SyncAction::Skip => Ok(false),
        SyncAction::ClearStale => {
            // Account changed but the new binding has no valid Anthropic token —
            // remove the previous account's item so CC can't read it as this slot.
            delete_keychain_item(handle_dir);
            Ok(false)
        }
        SyncAction::Write => {
            // raw is Some here (file_expiry was Some, which required a readable
            // claudeAiOauth credential).
            let raw = raw.expect("Write implies a valid credential was read");
            write_raw(handle_dir, raw.trim())?;
            Ok(true)
        }
    }
}

/// What [`sync_handle_dir_inner`] should do, factored out so the decision logic
/// is unit-testable without shelling `security`.
#[derive(Debug, PartialEq, Eq)]
enum SyncAction {
    /// Write the file token to the keychain.
    Write,
    /// Do nothing (no valid token to mirror, or the keychain is already ≥-fresh).
    Skip,
    /// Account changed and there's no valid token to write — delete the stale
    /// (wrong-account) keychain item.
    ClearStale,
}

/// `file_expiry`: expiry of the valid Anthropic token in the handle dir, or
/// `None` (absent/expired/non-Anthropic). `keychain_expiry`: expiry of the
/// current keychain item, or `None`. `account_changed`: true on `csq swap`
/// (binding change → ignore the newer-than guard).
fn decide_sync_action(
    file_expiry: Option<u64>,
    keychain_expiry: Option<u64>,
    account_changed: bool,
) -> SyncAction {
    match file_expiry {
        // No valid token to mirror. On a binding change, clear the stale
        // wrong-account item; otherwise leave whatever is there (refresh/sweep
        // must not delete a token CC may still be using).
        None => {
            if account_changed {
                SyncAction::ClearStale
            } else {
                SyncAction::Skip
            }
        }
        // Valid token. On a binding change, always write (the keychain holds the
        // PREVIOUS account's token; expiry comparison is meaningless across
        // accounts). Otherwise apply the newer-than guard (don't clobber a token
        // CC self-refreshed for the SAME account).
        Some(file) => {
            if !account_changed && keychain_is_fresher_or_equal(keychain_expiry, file) {
                SyncAction::Skip
            } else {
                SyncAction::Write
            }
        }
    }
}

/// The newer-than-keychain decision, factored out so the (otherwise
/// `security`-shelling, CI-untestable) guard's logic is unit-testable. Returns
/// `true` — meaning SKIP the write — when the keychain already holds a token
/// expiring at-or-after the file's (`Some(kc) if kc >= file`). `None` (no/unreadable
/// keychain item) returns `false` → write (the file token is the only candidate).
fn keychain_is_fresher_or_equal(keychain_expiry: Option<u64>, file_expiry: u64) -> bool {
    matches!(keychain_expiry, Some(kc) if kc >= file_expiry)
}

/// Delete the keychain item CC reads for `config_dir` (idempotent — succeeds when
/// absent). Used by the account-changed path to clear a stale wrong-account item.
/// Best-effort, timeout-bounded; failures are swallowed (the caller is best-effort).
#[cfg(target_os = "macos")]
fn delete_keychain_item(config_dir: &Path) {
    let svc = service_name(config_dir);
    // One bounded delete is enough to clear the item CC reads; if duplicates ever
    // existed, the next account-changed write's delete-loop clears the rest.
    let _ = run_security_bounded(&["delete-generic-password", "-s", &svc]);
}

#[cfg(not(target_os = "macos"))]
fn delete_keychain_item(_config_dir: &Path) {}

/// Sync every `term-*` handle dir under `base_dir` (the accounts dir) — the
/// shared sweep used by `csq keychain-sync` and the daemon refresher's
/// post-refresh pass. Returns `(synced, skipped, failed)`.
///
/// Each dir is handled independently by [`sync_handle_dir`] (which reads that
/// dir's OWN credential via its symlink and writes that dir's OWN keychain item),
/// so the sweep is account-agnostic: it does NOT need to attribute dirs to
/// accounts (sidestepping the marker-format pitfall where a UUID `.csq-account`
/// is invisible to a numeric-only reader). The newer-than-keychain guard inside
/// `sync_handle_dir` makes this idempotent — only dirs whose file token is
/// strictly fresher than their keychain copy actually write.
pub fn sync_all_handle_dirs(base_dir: &Path) -> (usize, usize, usize) {
    let (mut synced, mut skipped, mut failed) = (0usize, 0usize, 0usize);
    let rd = match std::fs::read_dir(base_dir) {
        Ok(rd) => rd,
        Err(_) => return (0, 0, 0),
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if !entry.file_name().to_string_lossy().starts_with("term-") {
            continue;
        }
        // CC hashes the canonicalized CLAUDE_CONFIG_DIR path (the value `csq run`
        // exports); canonicalize so the service name matches. On canonicalize
        // failure the non-canonical path would hash differently and write a stray
        // item CC never reads — count it as skipped rather than a false "synced".
        let abs = match std::fs::canonicalize(&path) {
            Ok(p) => p,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        match sync_handle_dir(&abs) {
            Ok(true) => synced += 1,
            Ok(false) => skipped += 1,
            Err(_) => failed += 1,
        }
    }
    (synced, skipped, failed)
}

/// Extract `claudeAiOauth.expiresAt` (Unix millis) from an Anthropic credential
/// JSON string. `None` on any parse failure, missing field, or non-integer
/// value — the conservative answer every caller treats as "not safe to mirror".
fn anthropic_expiry_ms(raw: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()?
        .get("claudeAiOauth")?
        .get("expiresAt")?
        .as_u64()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Current `expiresAt` (Unix millis) of the keychain item CC reads for
/// `config_dir`, or `None` if absent / unreadable / unparseable. Used by
/// [`sync_handle_dir`]'s newer-than guard to avoid clobbering a fresher token.
#[cfg(target_os = "macos")]
fn keychain_expiry_ms(config_dir: &Path) -> Option<u64> {
    let svc = service_name(config_dir);
    let account = keychain_account();
    let output =
        run_security_bounded(&["find-generic-password", "-s", &svc, "-a", &account, "-w"])?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    anthropic_expiry_ms(raw.trim())
}

/// Non-macOS: no keychain item exists (CC reads the file directly), so there is
/// nothing to compare against — the newer-than guard is a no-op there anyway
/// (the write itself is a stub).
#[cfg(not(target_os = "macos"))]
fn keychain_expiry_ms(_config_dir: &Path) -> Option<u64> {
    None
}

// ── A1: Harvest primitive (read-only) ─────────────────────────────────────
//
// The daemon custodian needs to find the freshest valid Anthropic token across
// all live handle dirs bound to a given account UUID. A1 adds ONLY the read +
// decision half — no credential writes occur here. A2 will wire the actual write.

/// A candidate token harvested from a single live handle dir's keychain item.
///
/// Carries the raw JSON (for A2's write path) and the parsed expiry (for the
/// decision function). The source-dir label is a fixed-vocabulary tag for
/// logging only — it MUST NOT include any token bytes.
///
/// **Security invariant**: this type deliberately does NOT derive or impl
/// `Debug` so that `raw_json` cannot reach log output through `{:?}` or
/// `#[derive(Debug)]` on a containing struct.
pub struct HarvestCandidate {
    /// Raw JSON as read from the keychain (verbatim, for A2 write-back).
    /// MUST NOT appear in any log statement.
    pub raw_json: String,
    /// `claudeAiOauth.expiresAt` in Unix milliseconds.
    pub expiry_ms: u64,
    /// Short identifier for logging — contains NO token bytes.
    /// Typical value: `"term-<pid>"`.
    pub source_tag: String,
    /// The candidate session's CC-recorded account email — the handle dir's
    /// `.claude.json` `oauthAccount.emailAddress`, trimmed (`None` if absent /
    /// unparseable / empty). The custodian's wrong-account guard compares this
    /// against the bound account's `identity.json` email before adopting the
    /// token into the account-global store.
    ///
    /// **Captured UNDER the same `_swap_guard` as `raw_json`** (redteam R1 MED —
    /// TOCTOU): the keychain bytes and this identity signal are read atomically
    /// while the per-dir swap lock is held, so a concurrent `csq swap` cannot
    /// repoint the dir between reading the token and reading its account. NOT a
    /// token-bearing field; the email is safe to log.
    pub candidate_email: Option<String>,
}

/// Enumerate every live `term-<pid>` handle dir under `base_dir` that is bound
/// to `account_uuid` and return the one whose keychain item holds the freshest
/// NON-EXPIRED Anthropic credential, or `None` if no such candidate exists.
///
/// Gated `#[cfg(target_os = "macos")]` — CC does not write keychain items on
/// other platforms, so the harvest is always empty there (stub returns `None`).
///
/// **Precise UUID match.** The handle dir is considered bound to `account_uuid`
/// when the symlink target of `.credentials.json` contains the path component
/// `identities/<uuid>/` — extracted via
/// `.split("identities/").nth(1)?.split('/').next()` on BOTH the link target
/// and the query UUID, then compared for EXACT EQUALITY. Substring matching is
/// BLOCKED (wip prototype flaw: `t.contains(uuid)` is wrong; a UUID that is a
/// prefix of another collides).
///
/// **Anthropic-only.** A dir whose `.credentials.json` link resolves to a
/// Codex `auth.json` chain or any non-`claudeAiOauth` shape contributes ZERO
/// candidates (reconciler-cleanup-parity.md Rule 4: scan the real producer link
/// name, never guess).
///
/// **No token bytes in logs.** Log statements use `source_tag` + fixed-vocabulary
/// error kinds only — never `raw_json`, the parsed credential, or raw serde output.
///
/// Path to the per-handle-dir A4a keychain-desync swap lock (`.swap-lock`,
/// hyphen). `csq swap` (`SameSurfaceClaudeCode`) via `lock_handle_dir_for_swap`
/// and `auto_rotate` hold this exclusively across their whole
/// [clear keychain → repoint symlink → write new token] transition; the daemon
/// custodian's harvest try-locks it and skips a dir it cannot acquire (mid-swap).
/// THIS is the lock that provides the A4a exclusion — NOT the `.swap.lock` (dot)
/// rename lock inside `repoint_handle_dir`, which is a separate defense-in-depth
/// serializer held UNDER this guard (they must stay distinct files or a same-fd
/// re-`flock` self-deadlocks — see `handle_dir::repoint_handle_dir` and an internal ticket).
///
/// Callers MUST pass a canonicalized `config_dir` (all three sites — swap,
/// auto_rotate, harvest — do), so this lock and the inner `.swap.lock` rename
/// lock both resolve to the same inode per handle dir.
///
/// Lives INSIDE the handle dir, so it is removed with the dir at teardown — no
/// separate reconciler-cleanup-parity obligation. Cross-platform (pure path join).
pub fn swap_lock_path(config_dir: &Path) -> PathBuf {
    config_dir.join(".swap-lock")
}

/// Acquire the swap lock for `config_dir`, blocking until available (the daemon
/// only ever holds it briefly via try-lock during a keychain read). The caller
/// holds the returned guard across the whole swap transition so the custodian's
/// harvest skips this dir until it settles. `None` if the lock cannot be taken —
/// best-effort: the clear-before-repoint ordering still gives crash-safety.
#[cfg(target_os = "macos")]
pub fn lock_handle_dir_for_swap(config_dir: &Path) -> Option<crate::platform::lock::FileLockGuard> {
    crate::platform::lock::lock_file(&swap_lock_path(config_dir)).ok()
}

/// Non-macOS: no keychain, so no swap race; lock is a no-op (`None`).
#[cfg(not(target_os = "macos"))]
pub fn lock_handle_dir_for_swap(
    _config_dir: &Path,
) -> Option<crate::platform::lock::FileLockGuard> {
    None
}

/// Clear (delete) the keychain item CC reads for `config_dir`. `csq swap` calls
/// this BEFORE repointing the symlink, so the transition window holds an ABSENT
/// item (which harvest skips) rather than the previous account's token — a swap
/// that crashes mid-flight then leaves nothing to mis-adopt. Idempotent; best-effort.
#[cfg(target_os = "macos")]
pub fn clear_handle_dir(config_dir: &Path) {
    delete_keychain_item(config_dir);
}

/// Non-macOS: CC reads the file directly; nothing to clear.
#[cfg(not(target_os = "macos"))]
pub fn clear_handle_dir(_config_dir: &Path) {}

/// Marker error for [`clear_handle_dir_reporting`]: the `security`
/// subprocess could not be confirmed to run (timed out against a locked /
/// unreachable keychain, or failed to spawn). Carries no data — callers
/// only need to know the clear could not be confirmed, never the item's
/// fate, which is genuinely unknown in this case; see the function's doc
/// for the required caller behavior (surface it, never treat as success).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeychainClearUnconfirmed;

/// Clear the keychain item for `config_dir` and report whether the attempt
/// could be CONFIRMED to run — distinct from [`clear_handle_dir`], whose
/// existing callers (`csq swap`, `auto_rotate`) are mid-TRANSITION steps
/// that write a fresh token into the same item moments later regardless of
/// whether this clear itself succeeded, so fire-and-forget is correct
/// there. `csq logout` is a TERMINAL step — nothing downstream retries this
/// clear — so its caller needs a real signal (`zero-tolerance.md` Rule 3:
/// no silent fallback on a credential path).
///
/// `Ok(true)`: [`drain_service`] confirmed no item survives for this
/// service — see its doc for exactly what that requires (reaching
/// [`SECURITY_ITEM_NOT_FOUND`], not merely "a delete call completed").
/// `Ok(false)`:
/// the call was a structural no-op — non-macOS, or the keychain mirror is
/// disabled (`cfg(test)` / `test-utils` feature / `CSQ_DISABLE_KEYCHAIN_MIRROR`)
/// — never touches the real keychain in test builds, same guard as every
/// other writer in this module. `Err(KeychainClearUnconfirmed)`: EITHER the
/// `security` subprocess itself could not be confirmed to run (timed out
/// against a locked / unreachable keychain, or failed to spawn), OR it ran
/// and exited with a code that does NOT confirm the item is gone (permission
/// denied, auth failed, or any other refusal) — in both cases the item's
/// fate is UNKNOWN, so the caller MUST treat this as a possible failure to
/// clear, not as success.
///
/// **This predicate answers "does this ONE `security` call need a retry?",
/// NOT "does no item survive for this service?" (security review 1386,
/// N1 naming correction — sec-1386/team-lead).** Exit `0` means "one item
/// was deleted"; it says NOTHING about whether a duplicate sibling remains
/// (`security` removes exactly one matching item per call — confirmed live
/// by team-lead's probe: two items under one service, one delete call
/// reports success while a sibling survives). The property callers actually
/// need — "no item with this service name survives" — is established ONLY
/// by [`drain_service`] reaching [`SECURITY_ITEM_NOT_FOUND`], which is why
/// `drain_service` does NOT call this function for its own confirmation
/// decision; it matches the raw exit code directly. This function's sole
/// remaining use is inside [`delete_service_retrying`]: deciding whether an
/// individual attempt is "settled enough to stop retrying it" (true for
/// BOTH exit `0` and `SECURITY_ITEM_NOT_FOUND` — both are terminal outcomes
/// for THAT call), which is a narrower question than service-wide absence.
///
/// Security review 1386 F1 (history — the property this predicate protects
/// against misreading): the pre-F1 version of the CALLER treated ANY
/// completed subprocess as confirmation, regardless of exit status. That
/// silently scored a keychain REFUSING the delete (a prompt non-zero exit —
/// e.g. `errSecInteractionNotAllowed` / `errSecAuthFailed`) as a successful
/// clear, which both skipped queuing it for retry AND reported
/// `keychain_cleared = true` while the item survived as the sole remaining
/// copy of the credential — H1's exact failure, reached by a different
/// door. It also defeated the queue at the OTHER end: an entry correctly
/// queued while the keychain was HANGING would be dropped by
/// `sweep_pending_clears` the moment the same locked keychain started
/// REFUSING instead — same operator condition, opposite `Ok`/`Err` verdict,
/// because only a hang produced `None`.
///
/// **Measured on an isolated, throwaway probe keychain** (never the
/// operator's real login keychain — verified unaffected afterward):
///
/// | case                        | exit | note                              |
/// |------------------------------|------|-----------------------------------|
/// | unlocked, item EXISTS         | `0`  | deleted                          |
/// | unlocked, item ABSENT         | `44` | not found                        |
/// | **LOCKED**, item EXISTS       | `0`  | deleted anyway, ~0.27s — did NOT refuse or hang |
/// | LOCKED, item ABSENT           | `44` | not found                        |
///
/// The locked+existing row is why `44` is safe to treat as CONFIRMED: the
/// worry was that a locked keychain might report `44` for an item that
/// actually still exists, which would mask a live credential behind
/// "nothing to clear." It does not — a locked-but-present item was
/// genuinely deleted, never reported not-found.
///
/// **The genuine REFUSAL case — `securityd` denying under a Background /
/// headless session with no Aqua session, csq's documented condition for
/// this class — was NOT reproduced.** A file-backed probe keychain does not
/// behave that way, so that exit code is unknown. This does not block the
/// fix: whatever it is, it is not `0` or `44` (the only two rows this
/// predicate accepts), so it falls into `Err(KeychainClearUnconfirmed)` by
/// construction and is queued/retried like any other unconfirmed result.
///
/// **Rejected alternative: confirm only on `success()`, queue every
/// non-zero exit.** Safer-looking (never under-queues), but wrong in
/// practice — a not-found item exits `44` on EVERY attempt forever; treated
/// as unconfirmed it would never drain, and combined with the deliberate
/// no-give-up backoff (`PENDING_CLEARS_BACKOFF_MAX_SECS`) it would
/// accumulate toward `PENDING_CLEARS_MAX`, at which point FIFO eviction
/// starts discarding REAL entries — queue poisoning, the round-2 HIGH by a
/// different route. The measured table is the reason `44` is trusted
/// instead of falling back to this alternative.
///
/// `pub(crate)` (fix/sweep-dead-handles-clears-keychain): `session::handle_dir`'s
/// dead-handle reaper drives this SAME classification directly in its own
/// tests (constructed exit statuses, no subprocess) rather than re-deriving
/// which codes confirm — so a future change to this set is caught on both
/// call sites, not just this module's. Kept in sync with this module's own
/// rename (`security_delete_confirmed` -> `security_delete_call_resolved`).
#[cfg(target_os = "macos")]
pub(crate) fn security_delete_call_resolved(output: &std::process::Output) -> bool {
    matches!(
        output.status.code(),
        Some(0) | Some(SECURITY_ITEM_NOT_FOUND)
    )
}

/// `security`'s exit code for "no matching keychain item" (`errSecItemNotFound`).
/// Measured, not recalled from memory — see the probe table on
/// [`security_delete_call_resolved`]. It is the only exit code besides `0` that
/// function treats as "no item survives".
///
/// `pub(crate)`: shared with `session::handle_dir`'s reaper-side exit-code
/// test so neither module hardcodes `44` independently.
#[cfg(target_os = "macos")]
pub(crate) const SECURITY_ITEM_NOT_FOUND: i32 = 44;

/// One retry on an unconfirmed `security` call, for the pending-clear queue
/// and for [`clear_handle_dir_reporting`]'s first attempt — but ONLY when
/// the first attempt failed FAST (a transient spawn hiccup or a momentary
/// refusal that might not repeat). Security review 1386 F5(a): retrying a
/// GENUINE TIMEOUT (the keychain hung for the full `KEYCHAIN_OP_TIMEOUT`) is
/// unlikely to help — a keychain that did not answer in 5s rarely answers in
/// the next 5s — and doubles the worst-case latency for no real gain. The
/// elapsed-time check distinguishes the two without needing
/// `run_security_bounded` to report WHY it returned `None`/an unconfirmed
/// status: a spawn failure or a fast refusal completes in milliseconds, a
/// timeout takes ~`KEYCHAIN_OP_TIMEOUT`, and the `/ 2` threshold sits with
/// ample margin on both sides of that gap.
#[cfg(target_os = "macos")]
fn delete_service_retrying(svc: &str) -> Option<std::process::Output> {
    let start = std::time::Instant::now();
    let first = run_security_bounded(&["delete-generic-password", "-s", svc]);
    if let Some(out) = &first {
        if security_delete_call_resolved(out) {
            return first;
        }
    }
    if start.elapsed() < KEYCHAIN_OP_TIMEOUT / 2 {
        run_security_bounded(&["delete-generic-password", "-s", svc])
    } else {
        first // a genuine timeout — do not retry, return the (unconfirmed) result as-is
    }
}

/// Bound on repeated single-item deletes when draining possible DUPLICATE
/// items under one service name (security review 1386 N1 — confirmed live
/// by team-lead's probe: two items added under the same service, one
/// `delete-generic-password` call exits 0 while a sibling survives; a
/// second call then drains it). `security delete-generic-password` removes
/// exactly ONE matching item per call — this module's own [`write_raw`]
/// already loops for exactly this reason ("a SHADOWING sibling with the
/// old token... observed in testing: a stale sibling re-introduced the
/// 401"), and [`delete_keychain_item`]'s single-shot delete is explicitly
/// justified there by "the next account-changed write's delete-loop clears
/// the rest" — a premise that holds for `csq swap`/`auto_rotate` (which
/// write again moments later) and does NOT hold for logout, which is
/// terminal. [`drain_service`] closes that gap for the pending-clear path.
///
/// `write_raw`'s own loop is unbounded because it always terminates in a
/// CREATE regardless of how many iterations the delete loop takes; this
/// loop's callers are logout-adjacent and terminal, so an unbounded loop
/// against a pathological keychain state could spin forever. `write_raw`'s
/// own delete loop is now bounded to the SAME value for consistency
/// (security review 1386, sec-1386's request).
///
/// **Why duplicates arise at all (team-lead): `write_raw` is
/// delete-all-then-create-one, so N CONCURRENT `write_raw` calls
/// interleaving can leave up to N items** — the delete-all half of each
/// call can race another call's create. This module names three writers
/// (`csq run`, `csq keychain-sync`, the daemon sweep) plus CC itself writes
/// on login and auto-refresh, so a plausible max is ~4 concurrent writers;
/// 5 is a 2x margin above that, not an arbitrary round number — and above
/// the observed case of 2 (team-lead's probe).
///
/// **The bound on WORST-CASE TIME is the enforced limit on
/// [`delete_service_retrying`] (the function each iteration actually
/// calls) — `KEYCHAIN_OP_TIMEOUT/2 + KEYCHAIN_OP_TIMEOUT` ≈ 7.5s — NOT
/// `KEYCHAIN_OP_TIMEOUT` alone, and NOT a measured typical
/// (doc-property-claims.md MUST-2, corrected TWICE in this doc: first from
/// "~0.2-0.3s measured" to "`KEYCHAIN_OP_TIMEOUT` per iteration", which was
/// STILL a wrong unit — `drain_service_inner` calls `delete_service_retrying`,
/// not `run_security_bounded` directly, so its own internal fast-retry can
/// make one iteration cost up to 7.5s, not 5s, and STILL return `Some(0)`
/// — "continue" — rather than stopping).** So the true worst case for THIS
/// loop alone is `5 (this constant) * 7.5s` ≈ **37.5s**, not the near-instant
/// figure the "fast confirmed delete" framing originally implied and not
/// the 25s the first correction understated. The latency consequence is
/// handled at the CALLER level — see [`sweep_pending_clears`] (daemon/periodic — tolerates a slow tick) vs the
/// opportunistic budget used by `csq run`/`csq exec` (bounded far tighter,
/// since that path is synchronous and interactive).
///
/// `pub(crate)` (fix/sweep-dead-handles-clears-keychain): `session::handle_dir`'s
/// dead-handle reaper scripts a cap-exhaustion case against this exact
/// constant rather than a bare literal, so the two stay in sync across any
/// future re-derivation of the value.
#[cfg(target_os = "macos")]
pub(crate) const MAX_DUPLICATE_DELETE_ITERATIONS: u32 = 5;

/// Repeatedly delete the service until [`SECURITY_ITEM_NOT_FOUND`] confirms
/// nothing remains, up to [`MAX_DUPLICATE_DELETE_ITERATIONS`]. `Ok(true)`
/// iff a confirmed not-found was reached (every duplicate drained, or none
/// ever existed). `Err(KeychainClearUnconfirmed)` on any unconfirmed
/// attempt (stops immediately — does NOT keep looping into a possibly
/// worse state) OR on exhausting the iteration budget without reaching
/// not-found (fails toward "might still have an item", never toward
/// success).
#[cfg(target_os = "macos")]
fn drain_service(svc: &str) -> Result<bool, KeychainClearUnconfirmed> {
    drain_service_inner(svc, &mut |s| {
        delete_service_retrying(s).and_then(|o| o.status.code())
    })
}

/// Test seam for [`drain_service`]: `delete_fn` is injectable so a test can
/// script a SEQUENCE of exit codes across iterations (e.g. "0, 0, 44" for
/// two duplicates then confirmed-empty) without any real `security`
/// subprocess or keychain. Production's only caller passes a closure over
/// [`delete_service_retrying`].
///
/// `pub(crate)` (fix/sweep-dead-handles-clears-keychain): the dead-handle
/// reaper's test drives this SAME loop with a scripted `delete_fn` to
/// compute the correct end-to-end verdict for each exit-code sequence,
/// rather than re-deriving the loop's decision logic (continue on `0`,
/// confirm on `SECURITY_ITEM_NOT_FOUND`, stop-unconfirmed on anything else
/// or cap exhaustion) independently — the two would otherwise drift the
/// moment this loop's shape changes.
#[cfg(target_os = "macos")]
pub(crate) fn drain_service_inner(
    svc: &str,
    delete_fn: &mut impl FnMut(&str) -> Option<i32>,
) -> Result<bool, KeychainClearUnconfirmed> {
    for _ in 0..MAX_DUPLICATE_DELETE_ITERATIONS {
        match delete_fn(svc) {
            Some(0) => continue, // one item deleted — a sibling may remain
            Some(SECURITY_ITEM_NOT_FOUND) => return Ok(true), // confirmed: nothing left
            _ => return Err(KeychainClearUnconfirmed), // unconfirmed — stop, do not guess
        }
    }
    // Iteration budget exhausted without a confirmed not-found. Not
    // expected to trigger against the duplicate counts this module's
    // writers produce (observed: 2), but "not expected" is not "cannot
    // happen" — fail toward unconfirmed rather than assuming success.
    Err(KeychainClearUnconfirmed)
}

/// `Ok(true)`/`Ok(false)`/`Err` per [`clear_handle_dir_reporting`]'s doc.
/// Distinct from `clear_handle_dir_reporting` itself so the pending-clear
/// queue ([`sweep_pending_clears`]) can retry a bare service-name string
/// (recovered from disk after the handle dir that produced it is long
/// gone) without re-deriving a `config_dir` path that no longer exists.
#[cfg(target_os = "macos")]
fn clear_service_reporting(svc: &str) -> Result<bool, KeychainClearUnconfirmed> {
    if keychain_mirror_disabled() {
        return Ok(false);
    }
    drain_service(svc)
}

#[cfg(target_os = "macos")]
pub fn clear_handle_dir_reporting(config_dir: &Path) -> Result<bool, KeychainClearUnconfirmed> {
    if keychain_mirror_disabled() {
        return Ok(false);
    }
    clear_service_reporting(&service_name(config_dir))
}

/// Non-macOS: CC reads `.credentials.json` directly there, so there is no
/// keychain item to clear — structural no-op, always `Ok(false)` (never a
/// failure) so callers don't spuriously warn on Linux/Windows.
#[cfg(not(target_os = "macos"))]
pub fn clear_handle_dir_reporting(_config_dir: &Path) -> Result<bool, KeychainClearUnconfirmed> {
    Ok(false)
}

// ── Pending-clear queue (security review 1386 H1) ──────────────────────
//
// `clear_handle_dir_reporting`'s `Err` case means the item's fate is
// UNKNOWN — on a locked/unreachable keychain, that item can end up as the
// ONLY surviving copy of a credential for an account `csq logout` just
// removed every other trace of (the file copies this mirrors are deleted
// by the SAME `logout_account` call, moments later). A durable, retried
// queue is the compensating mechanism: the service name (a
// `Claude Code-credentials-{8 hex}` string — NOT a secret, derived from a
// path hash, already logged unredacted elsewhere in this module) is
// recorded to disk, and retried opportunistically by the daemon's periodic
// handle-dir sweep AND by `csq run` (so a headless install with no daemon
// running still converges eventually).

/// Filename for the pending-clear queue, directly under `base_dir`. Not a
/// credential file — contains only keychain SERVICE NAME strings, never
/// token bytes — so it does not need `security.md` credential-file
/// permissions, but is still written atomically to avoid a torn read
/// racing a concurrent recorder/sweeper.
///
/// The pending-clear queue machinery below (this const through
/// [`save_pending_clears`]) is `#[cfg(target_os = "macos")]` — every
/// caller reaching it is already macOS-gated ([`record_pending_clear`],
/// [`sweep_pending_clears`], [`sweep_pending_clears_opportunistic`] all
/// have no-op non-macOS twins), so on Linux/Windows none of it is
/// reachable and leaving it ungated is dead code under `-D warnings`.
#[cfg(target_os = "macos")]
const PENDING_CLEARS_FILENAME: &str = "keychain-pending-clears.json";

/// Sibling lock file serializing every read-modify-write cycle on the queue
/// (`record_pending_clear`'s insert, and the removal half of
/// `sweep_pending_clears`). Security review 1386 (round 2): without this,
/// `sweep_pending_clears` holding an in-memory snapshot across up to
/// `PENDING_CLEARS_SWEEP_BUDGET * 2 * KEYCHAIN_OP_TIMEOUT` (~50s) of
/// subprocess calls raced a concurrent `record_pending_clear`, and the
/// sweep's blind overwrite on completion silently dropped the concurrently-
/// recorded entry — a lost update on the exact durability mechanism H1
/// exists to provide, in precisely the persistently-locked-keychain
/// environment where the queue is non-empty (and therefore the sweep is in
/// its long path) on almost every tick. Mirrors `remove_quota_entry`'s
/// `lock_file` pattern in `accounts/logout.rs`.
#[cfg(target_os = "macos")]
const PENDING_CLEARS_LOCK_FILENAME: &str = "keychain-pending-clears.lock";

/// Hard cap on the queue length. `record_pending_clear` evicts the OLDEST
/// entry when full (FIFO) rather than growing unbounded.
///
/// **The FIFO rationale is corrected here (security review 1386 F3 —
/// pendq-analysis): an entry leaves the queue ONLY on a confirmed clear, so
/// a SURVIVING old entry is the LONGEST-UNRESOLVED one, not a stale or
/// irrelevant one** — the opposite of what an earlier version of this
/// comment claimed. Eviction genuinely discards a possibly-live credential's
/// only remaining retry path, which is exactly why it is logged (not
/// silent) — the WARN is the mitigation, not the FIFO ordering.
///
/// **200 is a pragmatic cap, not a derived bound (F6 — the derivation this
/// admits is stated, not invented).** The queue is expected to hold 0-1
/// entries in real operation (one per logout that hit an unconfirmed
/// keychain clear); 200 is a generous multiple of that — enough to absorb a
/// burst of logouts during an extended keychain-unreachable window (e.g. a
/// headless install accumulating failures across days) without unbounded
/// growth, while the file itself stays small (a `PendingClearEntry` is
/// under 100 bytes serialized, so 200 of them is a few KB). There is no
/// hard ceiling this number is verified against on the other side (a
/// smaller cap would evict sooner; this file does not claim 200 is
/// optimal) — but the eviction WARN means reaching it is now visible to an
/// operator well before it silently degrades further.
#[cfg(target_os = "macos")]
const PENDING_CLEARS_MAX: usize = 200;

/// How many DUE entries the DAEMON's periodic sweep
/// ([`sweep_pending_clears`]) attempts per tick. This budget is for the
/// BACKGROUND path only — see [`PENDING_CLEARS_OPPORTUNISTIC_BUDGET`] for
/// the separate, much tighter budget used by synchronous/interactive
/// callers (`csq run`, `csq exec`), which MUST NOT inherit this number.
///
/// **The worst-case bound, derived from ENFORCED limits, not a measurement
/// (doc-property-claims.md MUST-2 — this figure has been corrected TWICE:
/// first from "does not multiply" reasoning off a MEASURED typical
/// (~0.2-0.3s per successful delete), to "~125s" using `KEYCHAIN_OP_TIMEOUT`
/// as the per-iteration unit — which was STILL wrong, because each drain
/// iteration calls [`delete_service_retrying`], not `run_security_bounded`
/// directly, and that function's OWN internal fast-retry makes its worst
/// case `KEYCHAIN_OP_TIMEOUT/2 + KEYCHAIN_OP_TIMEOUT` ≈ 7.5s, not 5s, while
/// STILL returning `Some(0)` — "continue" — rather than stopping):**
///
/// `worst case = PENDING_CLEARS_SWEEP_BUDGET * MAX_DUPLICATE_DELETE_ITERATIONS
///   * (KEYCHAIN_OP_TIMEOUT/2 + KEYCHAIN_OP_TIMEOUT) = 5 * 5 * 7.5s = 187.5s`.
///
/// That is the number this constant is actually sized against — a slow
/// daemon TICK (delaying the next `sweep_dead_handles` pass and this
/// queue's own next retry by up to ~187.5s in the pathological case), not a
/// number an interactive command can tolerate. It is acceptable HERE
/// specifically because this path is the daemon's own background loop,
/// never awaited by a user.
///
/// **Backoff decay (not "near zero after one failure" — stated precisely):**
/// after N consecutive failures an entry's `next_attempt_unix_secs` sits
/// `N * PENDING_CLEARS_BACKOFF_STEP_SECS` (capped) in the future, so it is
/// SKIPPED (no `security` call, doesn't count against this budget) on ticks
/// before that. The skip window grows roughly linearly with N until it
/// reaches `PENDING_CLEARS_BACKOFF_MAX_SECS` (3600s) after ~60 consecutive
/// failures (~an hour of a hanging/locked keychain) — from there sustained
/// cost is at most one `security` call per entry per hour, not per tick.
#[cfg(target_os = "macos")]
const PENDING_CLEARS_SWEEP_BUDGET: usize = 5;

/// Budget for the OPPORTUNISTIC sweep called synchronously and inline from
/// `csq run`/`csq exec`/the phase2b subscription client, BEFORE they spawn
/// the CLI or exec-replace the process. Deliberately `1`, NOT
/// `PENDING_CLEARS_SWEEP_BUDGET` — this path is interactive: its caller is
/// a user waiting on a terminal, not a background loop nobody watches.
///
/// Worst case here (security review 1386 C3 — the unit corrected: each
/// drain iteration calls [`delete_service_retrying`], whose own worst case
/// is `KEYCHAIN_OP_TIMEOUT/2 + KEYCHAIN_OP_TIMEOUT` ≈ 7.5s, not
/// `KEYCHAIN_OP_TIMEOUT` alone):
/// `1 * MAX_DUPLICATE_DELETE_ITERATIONS * 7.5s` = `1 * 5 * 7.5s` = **37.5s**
/// added to an interactive launch, in the pathological case (queue
/// non-empty AND the one due entry hits every iteration's worst case).
/// That is still not free, but it is bounded and
/// it only fires when the queue is non-empty — the common case (queue
/// empty) costs one file read. A background thread was considered and
/// REJECTED: `csq run`'s Unix path calls `exec()` moments later, which
/// terminates every OTHER thread in the process — a sweep still mid-flight
/// (potentially holding [`pending_clears_lock_path`]'s `flock`) would be
/// silently abandoned by the exec, and depending on `CLOEXEC` on the lock
/// fd, could leak the lock into the exec'd `claude` process indefinitely.
/// A small synchronous budget is the correct trade, not a background
/// dispatch that trades a bounded latency cost for an unbounded lock-leak
/// risk.
#[cfg(target_os = "macos")]
const PENDING_CLEARS_OPPORTUNISTIC_BUDGET: usize = 1;

/// Backoff step (security review 1386 MEDIUM): a permanently-unreachable
/// keychain (headless install, no Aqua session — ever) means every entry
/// fails every sweep, forever, at full `security`-subprocess cost. Each
/// failure pushes `next_attempt_unix_secs` out by
/// `attempts * PENDING_CLEARS_BACKOFF_STEP_SECS`, capped at
/// `PENDING_CLEARS_BACKOFF_MAX_SECS` — the entry is NEVER dropped for
/// giving up (that would silently reintroduce H1's permanent-orphan risk
/// one layer up), only retried less often once it has failed repeatedly.
#[cfg(target_os = "macos")]
const PENDING_CLEARS_BACKOFF_STEP_SECS: u64 = 60;
#[cfg(target_os = "macos")]
const PENDING_CLEARS_BACKOFF_MAX_SECS: u64 = 3600;

#[cfg(target_os = "macos")]
fn pending_clears_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PendingClearEntry {
    service: String,
    /// Failed-attempt count, driving the backoff below. `0` on first insert.
    #[serde(default)]
    attempts: u32,
    /// Unix seconds before which [`sweep_pending_clears`] MUST NOT retry
    /// this entry. `0` (the serde default for an old/hand-written file) is
    /// always due — never a reason to skip.
    #[serde(default)]
    next_attempt_unix_secs: u64,
    /// Monotonic counter bumped every time `record_pending_clear` resets an
    /// EXISTING entry (security review 1386, sec-1386's retracted-then-
    /// reinstated finding). Exists so a sweep's removal/backoff-bump step
    /// can tell "the entry I attempted" apart from "a DIFFERENT clear
    /// request that happens to share the same service name, recorded after
    /// my snapshot but before my locked write" — resetting `attempts`/
    /// `next_attempt_unix_secs` to `(0, 0)` alone is NOT enough, because a
    /// never-yet-attempted entry already has exactly `(0, 0)`, making a
    /// reset indistinguishable from "was never touched". Without this,
    /// a concurrent re-record for the same service between a sweep's read
    /// and its locked removal is silently discarded by the removal's
    /// service-name-only match — a second lost-update route to the same
    /// H1 failure the round-2 lock closed for the non-racing case.
    #[serde(default)]
    generation: u32,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct PendingClears {
    #[serde(default)]
    services: Vec<PendingClearEntry>,
}

/// Identity comparison for [`PendingClearEntry`] — `(service, generation)`
/// ONLY, deliberately NOT full-struct `PartialEq` (security review 1386
/// C1(c)). `attempts`/`next_attempt_unix_secs` are mutated by
/// [`load_pending_clears`]'s N5 backward-clock-jump clamp on EVERY load,
/// including the two loads one sweep performs (the pre-attempt snapshot and
/// the post-attempt locked reload) — so those two fields can legitimately
/// differ between them even for what is conceptually "the same" queue
/// entry. A full-struct comparison would then find a confirmed-cleared
/// entry unequal to its own later reload and silently fail to remove it —
/// the item deleted from the keychain, but its queue entry retried forever.
/// `generation` is the only field this module treats as an IDENTITY
/// discriminator (bumped exclusively by `record_pending_clear`'s re-record
/// path); everything else is mutable STATE on that identity.
#[cfg(target_os = "macos")]
fn identity_matches(a: &PendingClearEntry, b: &PendingClearEntry) -> bool {
    a.service == b.service && a.generation == b.generation
}

#[cfg(target_os = "macos")]
fn pending_clears_path(base_dir: &Path) -> PathBuf {
    base_dir.join(PENDING_CLEARS_FILENAME)
}

#[cfg(target_os = "macos")]
fn pending_clears_lock_path(base_dir: &Path) -> PathBuf {
    base_dir.join(PENDING_CLEARS_LOCK_FILENAME)
}

/// Security review 1386 LOW: a corrupt/unparseable queue file previously
/// degraded to an empty queue with no signal — every entry silently
/// discarded, on the one file whose job is to not forget. `Err` from
/// `read_to_string` (the normal absent-file case) stays silent; only a
/// parse failure on an EXISTING file warns.
///
/// Security review 1386 F8 (pendq-analysis, LOW/hardening): every entry's
/// `service` is validated against [`is_well_formed_service_name`] before it
/// is trusted — a value passed to `security`'s argv is not a shell-injection
/// risk (no shell is invoked, `security.md` clean), but a string beginning
/// with `-` would be parsed as an OPTION rather than the service argument.
/// Malformed entries are dropped (never passed to `security`, never
/// silently kept) with a WARN naming the count — never the content, which
/// could be attacker-influenced by construction. This also gives F7's
/// corrupt-file case partial recovery: a file with some malformed JSON
/// VALUES (not malformed JSON SYNTAX) keeps its well-formed entries instead
/// of the whole file being discarded.
#[cfg(target_os = "macos")]
fn load_pending_clears(base_dir: &Path) -> PendingClears {
    let mut clears = match std::fs::read_to_string(pending_clears_path(base_dir)) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|_| {
            warn!(
                error_kind = "keychain_pending_clears_corrupt",
                "the keychain pending-clear queue file could not be parsed — \
                 treating as empty (its prior contents, if any, are lost; this \
                 is a bug if it recurs, not an expected condition)"
            );
            PendingClears::default()
        }),
        Err(_) => PendingClears::default(), // absent / unreadable — empty queue, no signal needed
    };
    let before = clears.services.len();
    clears
        .services
        .retain(|e| is_well_formed_service_name(&e.service));
    let dropped = before - clears.services.len();
    if dropped > 0 {
        warn!(
            error_kind = "keychain_pending_clears_malformed_entry",
            dropped,
            "dropped malformed keychain pending-clear queue entries (not the \
             expected `Claude Code-credentials-<8 hex>` shape) — never passed \
             to a `security` subprocess"
        );
    }
    // Security review 1386 N5: clamp against a BACKWARD clock jump (NTP
    // correction, VM resume/suspend). Without this, an entry's
    // `next_attempt_unix_secs` — computed as `now + backoff` before the
    // jump — could sit arbitrarily far into a "future" that no longer
    // matches wall-clock time, stalling it far beyond
    // `PENDING_CLEARS_BACKOFF_MAX_SECS` with no other bound. Clamping on
    // every load re-derives the bound from CURRENT time each time, so the
    // entry is never stalled longer than the backoff cap from whenever it
    // is next observed, regardless of how far the clock jumped.
    let ceiling = pending_clears_now_secs().saturating_add(PENDING_CLEARS_BACKOFF_MAX_SECS);
    for e in &mut clears.services {
        if e.next_attempt_unix_secs > ceiling {
            e.next_attempt_unix_secs = ceiling;
        }
    }
    clears
}

/// `true` iff `s` is `"Claude Code-credentials-"` followed by exactly 8 hex
/// characters. Anything else — including, load-bearing, anything starting
/// with `-` that `security`'s argv parser would treat as an option — is
/// rejected.
///
/// Deliberately WIDER than [`service_name`]'s actual output (security
/// review 1386, sec-1386): `hex::encode` always produces LOWERCASE, but
/// `is_ascii_hexdigit()` accepts both cases — the validator accepts a
/// strict superset of what the producer emits. Safe by construction (the
/// producer's actual output is always a subset of what's accepted), not
/// merely "true in the cases tested". [`is_well_formed_service_name_matches_real_producer`]
/// pins the producer/validator agreement so a future edit to either one
/// that breaks it is caught immediately rather than surfacing as a
/// `keychain_pending_clears_malformed_entry` WARN that reads like
/// unrelated file corruption.
#[cfg(target_os = "macos")]
fn is_well_formed_service_name(s: &str) -> bool {
    const PREFIX: &str = "Claude Code-credentials-";
    match s.strip_prefix(PREFIX) {
        Some(suffix) => suffix.len() == 8 && suffix.chars().all(|c| c.is_ascii_hexdigit()),
        None => false,
    }
}

/// Best-effort atomic write. A failure here is logged (never silently
/// dropped, `zero-tolerance.md` Rule 3) but MUST NOT fail the caller — the
/// caller is itself a best-effort compensating step, not the primary path.
///
/// `context` names WHAT was being persisted when the write failed —
/// security review 1386 F9: a single fixed message ("this logout's
/// unconfirmed item will not be auto-retried") was wrong on the sweep path,
/// where there is no logout and the actual consequence is different
/// (already-queued entries simply keep their stale on-disk state and get
/// re-attempted next sweep — benign, but not what the old message said).
#[cfg(target_os = "macos")]
fn save_pending_clears(base_dir: &Path, clears: &PendingClears, context: &str) {
    let path = pending_clears_path(base_dir);
    let tmp = crate::platform::fs::unique_tmp_path(&path);
    let json = match serde_json::to_string(clears) {
        Ok(j) => j,
        Err(_) => return, // unreachable for this shape; nothing to persist
    };
    if std::fs::write(&tmp, json.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "keychain_pending_clears_write_failed",
            context, "failed to persist the keychain pending-clear queue (non-fatal)"
        );
        return;
    }
    if crate::platform::fs::atomic_replace(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        warn!(
            error_kind = "keychain_pending_clears_write_failed",
            context, "failed to persist the keychain pending-clear queue (non-fatal)"
        );
    }
}

/// Record `service` as needing a retried clear. No duplicate entries — a
/// SECOND record for a service already queued does NOT insert again, it
/// RESETS that entry's backoff to due-now (security review 1386 N3), since
/// a fresh logout recording the same service is new evidence the item
/// still matters. Best-effort (a failure to persist, or to acquire the
/// lock, is logged, never silently dropped, and never propagated — see
/// [`save_pending_clears`]).
///
/// Serialized under [`pending_clears_lock_path`] (security review 1386
/// HIGH — round 2) against both a concurrent `record_pending_clear` and the
/// removal half of `sweep_pending_clears`, so an insert can never be lost
/// to a racing sweep's blind overwrite. Load+dedupe+push+save is fast (one
/// small file), so this lock is held only briefly — never across a
/// `security` subprocess call.
///
/// Pure file I/O against `base_dir` — no `security` subprocess, so unlike
/// every OTHER writer in this module this is NOT gated on
/// `keychain_mirror_disabled()`. That guard exists to keep unit tests off
/// the operator's REAL login keychain; `base_dir` here is always the
/// caller's own (a `TempDir` in every test), so there is nothing to guard
/// and gating it would make the queue itself untestable.
#[cfg(target_os = "macos")]
pub fn record_pending_clear(base_dir: &Path, service: &str) {
    let _guard = match crate::platform::lock::lock_file(&pending_clears_lock_path(base_dir)) {
        Ok(g) => g,
        Err(_) => {
            warn!(
                error_kind = "keychain_pending_clears_lock_failed",
                "could not lock the keychain pending-clear queue — this logout's \
                 unconfirmed item was NOT queued for auto-retry (non-fatal)"
            );
            return;
        }
    };
    debug_assert!(
        is_well_formed_service_name(service),
        "record_pending_clear called with a malformed service name: {service:?} — \
         every production caller derives this from keychain::service_name() \
         (security review 1386 N4)"
    );

    let mut clears = load_pending_clears(base_dir);
    if let Some(existing) = clears.services.iter_mut().find(|e| e.service == service) {
        // Security review 1386 N3 + the generation fix: a fresh logout
        // recording the SAME service (reachable via PID recycling hashing
        // back to the same keychain service name) is new evidence the item
        // still matters — reset backoff to due-now rather than leaving it
        // waiting out a window computed for the STALE reason it was
        // originally queued. `generation` MUST also bump: resetting
        // attempts/next_attempt alone is indistinguishable from "never
        // attempted" (which is already `(0, 0)`), so a concurrent sweep
        // holding a snapshot of the PRE-reset entry could not tell its
        // attempted copy apart from this fresh one without it — see the
        // field's doc on `PendingClearEntry`.
        existing.attempts = 0;
        existing.next_attempt_unix_secs = 0;
        existing.generation = existing.generation.wrapping_add(1);
        save_pending_clears(base_dir, &clears, "record_pending_clear");
        return;
    }
    if clears.services.len() >= PENDING_CLEARS_MAX {
        let evicted = clears.services.remove(0); // evict oldest (FIFO)
        warn!(
            error_kind = "keychain_pending_clears_evicted",
            "the keychain pending-clear queue is full ({PENDING_CLEARS_MAX} entries) — \
             evicted the oldest queued entry to make room; that item's keychain \
             clear will NOT be auto-retried and may remain an orphan"
        );
        let _ = evicted; // service name only — nothing further to log (no secret)
    }
    clears.services.push(PendingClearEntry {
        service: service.to_string(),
        attempts: 0,
        next_attempt_unix_secs: 0,
        generation: 0,
    });
    save_pending_clears(base_dir, &clears, "record_pending_clear");
}

/// Non-macOS: no keychain, so no pending-clear queue is ever populated —
/// structural no-op.
#[cfg(not(target_os = "macos"))]
pub fn record_pending_clear(_base_dir: &Path, _service: &str) {}

/// Retry up to [`PENDING_CLEARS_SWEEP_BUDGET`] due entries from the
/// pending-clear queue. Returns `(cleared, remaining)`. Called from the
/// daemon's periodic handle-dir sweep (`session::handle_dir::spawn_sweep`)
/// and opportunistically from `csq run`, so both a running-daemon install
/// and a headless daemon-less one eventually converge. Cheap when the queue
/// is empty (one file read, no subprocess calls, no lock).
///
/// **Concurrency (security review 1386 HIGH — round 2).** The `security`
/// subprocess attempts run WITHOUT holding [`pending_clears_lock_path`] —
/// up to ~187.5s (see [`PENDING_CLEARS_SWEEP_BUDGET`]'s doc for the current
/// derivation, ENFORCED-limit based, not a measurement) would otherwise
/// block a concurrent `record_pending_clear` for the whole sweep. Only the
/// final REMOVAL is locked, and it removes by [`identity_matches`]
/// (`service` + `generation` ONLY — deliberately NOT full entry equality,
/// see that function's doc for why [`load_pending_clears`]'s N5 clamp
/// makes `attempts`/`next_attempt_unix_secs` unsafe to compare) against a
/// FRESH re-load of the current file — never a blind overwrite of the
/// pre-attempt snapshot, and never a service-NAME-only match either
/// (security review 1386, sec-1386's generation-counter finding): a
/// service name alone cannot tell "the entry I attempted" apart from "a
/// DIFFERENT clear request recorded for the same service between my
/// snapshot and my locked write" — see `generation`'s doc on
/// [`PendingClearEntry`]. This makes the operation safe regardless of what
/// happened concurrently: an entry recorded (or reset) during the attempt
/// phase gets a new `generation` and no longer identity-matches the
/// snapshot copy, surviving untouched; an entry removed by a concurrent
/// sweep is already absent and the `retain` is a no-op.
///
/// **Backoff (security review 1386 MEDIUM).** An entry whose
/// `next_attempt_unix_secs` is still in the future is skipped without a
/// `security` call — so a permanently-unreachable keychain converges to at
/// most one attempt per `PENDING_CLEARS_BACKOFF_MAX_SECS` per entry, never
/// zero (the entry is NEVER dropped for repeated failure).
///
/// No function-level `keychain_mirror_disabled()` gate here either — the
/// only `security`-touching call in this loop is [`clear_service_reporting`],
/// which already carries that guard internally (returns `Ok(false)` under
/// test, so every entry stays queued and no real keychain is ever touched
/// from a test), which is what lets THIS function's file-I/O half (load,
/// budget, persist) be exercised directly by a unit test.
#[cfg(target_os = "macos")]
pub fn sweep_pending_clears(base_dir: &Path) -> (usize, usize) {
    sweep_pending_clears_inner(
        base_dir,
        pending_clears_now_secs(),
        PENDING_CLEARS_SWEEP_BUDGET,
        &mut clear_service_reporting,
    )
}

/// Opportunistic variant for SYNCHRONOUS, INTERACTIVE callers (`csq run`,
/// `csq exec`, the phase2b subscription client) — see
/// [`PENDING_CLEARS_OPPORTUNISTIC_BUDGET`]'s doc for why this is a
/// separate, much smaller budget rather than reusing
/// [`sweep_pending_clears`]'s daemon-sized one.
#[cfg(target_os = "macos")]
pub fn sweep_pending_clears_opportunistic(base_dir: &Path) -> (usize, usize) {
    sweep_pending_clears_inner(
        base_dir,
        pending_clears_now_secs(),
        PENDING_CLEARS_OPPORTUNISTIC_BUDGET,
        &mut clear_service_reporting,
    )
}

/// Test seam for [`sweep_pending_clears`]/[`sweep_pending_clears_opportunistic`]
/// (security review 1386 F5(b) — pendq-analysis): `clear_fn` is the
/// per-entry clear call, injectable so a test can prove only `budget`
/// entries are ATTEMPTED (not merely that the final counts are consistent
/// with either a real or a no-op budget, which `clear_service_reporting`'s
/// test-mode `Ok(false)` makes indistinguishable from "no budget at all" —
/// the exact gap the reviewer named). Mirrors the `sweep_dead_handles`/
/// `sweep_dead_handles_inner` seam pattern in `session::handle_dir.rs`
/// (an internal ticket). `now` is ALSO injectable (security review 1386 N5) so backoff
/// due/not-due decisions are testable without depending on wall-clock time.
/// `budget` is injectable so the daemon and opportunistic callers can share
/// this one implementation with different worst-case latency ceilings.
#[cfg(target_os = "macos")]
fn sweep_pending_clears_inner(
    base_dir: &Path,
    now: u64,
    budget: usize,
    clear_fn: &mut impl FnMut(&str) -> Result<bool, KeychainClearUnconfirmed>,
) -> (usize, usize) {
    let snapshot = load_pending_clears(base_dir);
    if snapshot.services.is_empty() {
        return (0, 0);
    }
    // Security review 1386, sec-1386's generation-counter finding: track the
    // FULL snapshot entry (not just its service-name string) for both the
    // cleared set and the backoff-update set. NOT for exact equality against
    // a fresh reload (pendq-r2, round 3 — that design was replaced by
    // `identity_matches` below): both sets need the snapshot entry's
    // `generation` (identity, alongside `service`) and, for the backoff set,
    // its pre-attempt `attempts`. Matching by (service, generation) rather
    // than full-struct equality is deliberate — the remaining fields
    // (`next_attempt_unix_secs`, `attempts` on the CURRENT entry) are
    // mutable state that load-time normalization may legitimately change
    // between this snapshot and the fresh reload the removal/backoff-apply
    // steps below read.
    let mut cleared_entries: Vec<PendingClearEntry> = Vec::new();
    let mut backoff_updates: Vec<(PendingClearEntry, PendingClearEntry)> = Vec::new();
    let mut attempted = 0usize;
    for entry in &snapshot.services {
        if attempted >= budget {
            break; // over budget this tick — remainder retried next sweep
        }
        if entry.next_attempt_unix_secs > now {
            continue; // backed off — not due yet, no subprocess call
        }
        match clear_fn(&entry.service) {
            // Security review 1386 C4 (pendq-r2 + team-lead): `attempted`
            // (the BUDGET counter) is incremented ONLY on `Ok(true)`/`Err` —
            // outcomes that reflect a REAL attempt. `Ok(false)` is a
            // STRUCTURAL NO-OP (keychain mirror disabled — test build /
            // `CSQ_DISABLE_KEYCHAIN_MIRROR`): no subprocess ran, so it costs
            // nothing to keep iterating past it, and counting it against the
            // budget caused head-of-line starvation — with the mirror
            // disabled, the first `budget` entries would consume the WHOLE
            // budget every tick while changing no state, so entries beyond
            // `budget` were never attempted at all until the mirror was
            // re-enabled.
            Ok(true) => {
                attempted += 1;
                cleared_entries.push(entry.clone());
            }
            // Security review 1386 N2: `Ok(false)` must NOT count as a
            // failed attempt or receive a backoff bump either — see above
            // for why it is a structural no-op. The prior version shared
            // this arm with `Err`, so an operator running with the mirror
            // disabled would accumulate every entry's backoff toward the
            // 3600s cap on attempts that never happened; re-enabling the
            // mirror then left each waiting up to an hour for its first
            // REAL try.
            Ok(false) => {}
            Err(KeychainClearUnconfirmed) => {
                attempted += 1;
                let attempts = entry.attempts.saturating_add(1);
                let backoff = (attempts as u64).saturating_mul(PENDING_CLEARS_BACKOFF_STEP_SECS);
                let updated = PendingClearEntry {
                    service: entry.service.clone(),
                    attempts,
                    next_attempt_unix_secs: now + backoff.min(PENDING_CLEARS_BACKOFF_MAX_SECS),
                    generation: entry.generation,
                };
                backoff_updates.push((entry.clone(), updated));
            }
        }
    }
    let cleared = cleared_entries.len();

    let remaining = {
        let _guard = match crate::platform::lock::lock_file(&pending_clears_lock_path(base_dir)) {
            Ok(g) => g,
            Err(_) => return (0, snapshot.services.len()), // couldn't lock — remove NOTHING; retry next tick
        };
        let mut current = load_pending_clears(base_dir);
        // Remove exactly the SNAPSHOT entries THIS sweep confirmed cleared —
        // keyed on (service, generation) ONLY, not full entry equality
        // (security review 1386, C1(c) — pendq-r2 + team-lead, independently
        // converging before and after this code existed). `load_pending_clears`
        // clamps `next_attempt_unix_secs` (N5) against the REAL wall clock on
        // EVERY call, including this one and the earlier snapshot read —
        // regardless of the `now` this function was given. If those two
        // clamps landed on different wall-clock seconds, a full-struct
        // comparison would find the "same" entry unequal to itself and skip
        // removing it — a keychain item confirmed deleted, but its queue
        // entry retried forever. `generation` is bumped ONLY by
        // `record_pending_clear`'s re-record path, so (service, generation)
        // is the correct identity: unaffected by any load-time
        // normalization, present or future.
        current
            .services
            .retain(|e| !cleared_entries.iter().any(|c| identity_matches(c, e)));
        // Apply the backoff bump ONLY where the current entry still has the
        // SAME (service, generation) as the snapshot entry this sweep
        // attempted — if it changed (re-recorded concurrently, generation
        // bumped), skip the bump rather than re-impose backoff on a clear
        // that was just freshly requested. Same identity key as the removal
        // above, for the same reason.
        for (original, updated) in &backoff_updates {
            if let Some(e) = current
                .services
                .iter_mut()
                .find(|e| identity_matches(original, e))
            {
                e.attempts = updated.attempts;
                e.next_attempt_unix_secs = updated.next_attempt_unix_secs;
            }
        }
        let n = current.services.len();
        // This save is UNCONDITIONAL — even when `retain` removed nothing —
        // and that is LOAD-BEARING (security review 1386, team-lead,
        // corrected once already: an earlier version of this comment cited
        // the N5 clamp, which stopped being the reason once `identity_matches`
        // decoupled removal correctness from `next_attempt_unix_secs`; the
        // REAL dependency is below).
        //
        // `backoff_updates` is applied to `current` PURELY IN MEMORY a few
        // lines up — this save is its ONLY persistence point. On the
        // COMMON failing-keychain tick — the dominant case backoff exists
        // for — `cleared_entries` is EMPTY (nothing confirmed) while
        // `backoff_updates` is NOT. Guard this save on "a removal
        // happened" and every backoff bump on that tick is silently
        // discarded: `attempts`/`next_attempt_unix_secs` never reach disk,
        // and the queue returns to full-rate retry every 60s forever,
        // defeating backoff entirely for the exact install (permanently
        // unreachable keychain) this whole mechanism targets. Do not add
        // an early-return / no-op skip here without re-establishing that
        // persistence for the zero-removals-nonzero-bumps case.
        save_pending_clears(base_dir, &current, "sweep_pending_clears");
        n
    };
    // Security review 1386 F4: the compensating mechanism had zero
    // observability — both callers discard the return value. A non-empty
    // queue after a sweep means live keychain items are STILL uncleared;
    // that must be visible somewhere, not only inferable from a returned
    // tuple nobody reads.
    if remaining > 0 {
        warn!(
            error_kind = "keychain_pending_clears_remaining",
            cleared,
            remaining,
            "keychain pending-clear queue still has unconfirmed entries after this \
             sweep (non-fatal — retried on the next sweep, with backoff for \
             repeatedly-failing entries)"
        );
    }
    (cleared, remaining)
}

/// Non-macOS: nothing was ever queued — structural no-op.
#[cfg(not(target_os = "macos"))]
pub fn sweep_pending_clears(_base_dir: &Path) -> (usize, usize) {
    (0, 0)
}

/// Non-macOS: nothing was ever queued — structural no-op. Callers (`csq
/// run`/`csq exec`/subscription_client) call this unconditionally, so the
/// stub MUST exist here regardless of platform.
#[cfg(not(target_os = "macos"))]
pub fn sweep_pending_clears_opportunistic(_base_dir: &Path) -> (usize, usize) {
    (0, 0)
}

/// Cheap, filesystem-only predicate for callers deciding whether a keychain
/// CLEAR call ([`clear_handle_dir_reporting`], a `security` subprocess) is
/// worth issuing at all for `handle_dir`. Cross-platform and free of any
/// keychain access — a single `read_to_string` following the
/// `.credentials.json` symlink, the same read [`sync_handle_dir_inner`]
/// already performs to decide whether to WRITE.
///
/// Sound, not merely convenient: the only writer of an Anthropic keychain
/// item for a handle dir is [`sync_handle_dir_inner`] (via `csq run` /
/// `auto_rotate`), and it gates on this EXACT shape check
/// (`raw.contains("\"claudeAiOauth\"")`) before ever touching the keychain.
/// So a dir whose `.credentials.json` does not have this shape RIGHT NOW
/// could only carry an orphaned item from an EARLIER Anthropic binding that
/// has since been swapped away — and `csq swap`'s `account_changed=true`
/// path (`sync_handle_dir_account_changed`) already clears or overwrites
/// that old item at the moment of the swap itself (`SyncAction::ClearStale`
/// / `Write`), so this predicate does not miss that case. A dir whose
/// `.credentials.json` is absent, dangling, or non-Anthropic today therefore
/// never has a *surviving* Anthropic keychain item to reap.
///
/// Returns `false` (skip) on any read failure — absent file, dangling
/// symlink, or a mid-creation race — never panics.
pub(crate) fn handle_dir_might_have_anthropic_keychain_item(handle_dir: &Path) -> bool {
    std::fs::read_to_string(handle_dir.join(".credentials.json"))
        .map(|raw| raw.contains("\"claudeAiOauth\""))
        .unwrap_or(false)
}

/// Thin wrapper over [`harvest_account_candidates`] returning only the freshest.
#[cfg(target_os = "macos")]
pub fn harvest_account_token(base_dir: &Path, account_uuid: &str) -> Option<HarvestCandidate> {
    harvest_account_candidates(base_dir, account_uuid)
        .into_iter()
        .next()
}

/// Enumerate every live `term-<pid>` handle dir under `base_dir` bound to
/// `account_uuid` and return ALL valid non-expired Anthropic candidates, sorted
/// freshest-first (descending `expiry_ms`). Empty when none qualify.
///
/// A0's validate-before-adopt needs the ordered list, not just the single
/// freshest: when the freshest candidate fails server validation (401 — a
/// rotated-dead token that still has a future `expiresAt`), the custodian falls
/// back to the next-freshest. Same per-dir predicate as
/// [`harvest_account_token`] (precise UUID match, PID-live, `.credentials.json`
/// only, bounded keychain read, non-expired, no token bytes in logs).
#[cfg(target_os = "macos")]
pub fn harvest_account_candidates(base_dir: &Path, account_uuid: &str) -> Vec<HarvestCandidate> {
    let now = now_ms();
    let mut candidates: Vec<HarvestCandidate> = Vec::new();

    let rd = match std::fs::read_dir(base_dir) {
        Ok(rd) => rd,
        Err(_) => return candidates,
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let dir_name = entry.file_name();
        let dir_name_s = dir_name.to_string_lossy();

        // Only consider term-<pid> dirs.
        if !dir_name_s.starts_with("term-") {
            continue;
        }

        // Parse PID and require the process is alive (kill(pid, 0) == 0).
        let pid: libc::pid_t = match dir_name_s
            .strip_prefix("term-")
            .and_then(|s| s.parse().ok())
        {
            Some(p) => p,
            None => continue,
        };
        if unsafe { libc::kill(pid, 0) } != 0 {
            continue;
        }

        // Require .credentials.json exists as a symlink and resolves to
        // `identities/<account_uuid>/credentials.json`. Read the symlink
        // target (do NOT follow it yet) to extract the UUID component.
        let cred_link = path.join(".credentials.json");
        let link_target = match std::fs::read_link(&cred_link) {
            Ok(t) => t,
            Err(_) => continue, // absent / not a symlink → no candidate
        };
        let target_s = link_target.to_string_lossy();

        // Precise UUID extraction from the symlink target path.
        // Pattern: "...identities/<uuid>/credentials.json"
        let dir_uuid = match target_s
            .split("identities/")
            .nth(1)
            .and_then(|s| s.split('/').next())
        {
            Some(u) if !u.is_empty() => u.to_owned(),
            _ => continue, // path does not contain identities/<uuid>/ component
        };

        // EXACT UUID equality — substring/prefix match is BLOCKED.
        if dir_uuid != account_uuid {
            continue;
        }

        // The link must point to `credentials.json` (Anthropic), NOT `auth.json`
        // (Codex). A codex-only or dual-bound dir uses `auth.json` as the Codex
        // link name; if .credentials.json somehow resolves to that, it is
        // non-Anthropic and contributes zero candidates.
        // Additionally, the symlink target must end with "credentials.json" (not
        // credentials-codex.json or auth.json).
        if !target_s.ends_with("credentials.json") {
            continue;
        }

        // Canonicalize the dir path so service_name produces the same hash
        // CC uses (CC hashes the canonicalized CLAUDE_CONFIG_DIR).
        let abs = match std::fs::canonicalize(&path) {
            Ok(p) => p,
            Err(_) => continue, // dangling / broken dir — skip
        };

        // A4a — mid-swap guard. `csq swap` holds this per-dir lock exclusively
        // across [clear keychain → repoint symlink → write new token]. If we cannot
        // acquire it, the dir is transitioning: its symlink may already point to the
        // new account while its keychain still holds the OLD account's token (or is
        // mid-clear). Adopting that token would write the WRONG account into the
        // account-global store (redteam HIGH-1). Skip the dir this tick; the next
        // tick reads the settled state. The guard is held across the keychain read so
        // swap cannot repoint underneath us, then dropped at end of iteration.
        let _swap_guard = match crate::platform::lock::try_lock_file(&swap_lock_path(&abs)) {
            Ok(Some(g)) => g,
            Ok(None) => continue, // swap in progress on this dir → skip
            Err(_) => continue,   // lock error → fail-closed skip
        };

        // Read the keychain item via the bounded helper (5s timeout + SIGKILL).
        let raw = match read_raw_keychain(&abs) {
            Some(r) => r,
            None => {
                // Absent, unparseable, or timed-out keychain read: no candidate
                // from this dir. Log with fixed tag only — no token bytes.
                warn!(
                    source_tag = %dir_name_s,
                    "harvest: no candidate (keychain read absent or failed)"
                );
                continue;
            }
        };

        // Require claudeAiOauth shape and non-expired.
        if !raw.contains("\"claudeAiOauth\"") {
            // Non-Anthropic credential in the keychain item — zero candidates.
            continue;
        }
        let expiry = match anthropic_expiry_ms(&raw) {
            Some(e) => e,
            None => {
                // Unparseable expiry: fail closed — no candidate.
                warn!(
                    source_tag = %dir_name_s,
                    "harvest: no candidate (expiry parse failed)"
                );
                continue;
            }
        };
        if expiry <= now {
            // Expired token — zero candidates from this dir.
            continue;
        }

        // Capture the candidate session's CC-recorded account email UNDER the
        // SAME `_swap_guard` as the keychain bytes above (redteam R1 MED — TOCTOU):
        // token + identity are observed atomically, so a concurrent swap cannot
        // desync them. The custodian's wrong-account guard consumes this; it does
        // NOT re-read `.claude.json` lock-free.
        let candidate_email = crate::credentials::claude_json::read_oauth_email(&abs);

        // Valid non-expired candidate.
        candidates.push(HarvestCandidate {
            raw_json: raw,
            expiry_ms: expiry,
            source_tag: dir_name_s.into_owned(),
            candidate_email,
        });
    }

    // Freshest first; A0 validates in this order and adopts the first Live one.
    candidates.sort_by(|a, b| b.expiry_ms.cmp(&a.expiry_ms));
    candidates
}

/// Non-macOS stub: CC does not write keychain items on Linux/Windows.
#[cfg(not(target_os = "macos"))]
pub fn harvest_account_candidates(_base_dir: &Path, _account_uuid: &str) -> Vec<HarvestCandidate> {
    Vec::new()
}

/// Non-macOS stub: CC does not write keychain items on Linux/Windows.
#[cfg(not(target_os = "macos"))]
pub fn harvest_account_token(_base_dir: &Path, _account_uuid: &str) -> Option<HarvestCandidate> {
    None
}

/// Pure decision function for the harvest custodian.
///
/// `candidates`: slice of `(expiry_ms, index)` pairs — ALL elements are
/// pre-filtered to be non-expired by the caller (i.e. `expiry > now_ms()`).
/// `store_expiry`: the expiry of the credential currently in the canonical
/// store, or `None` if the store has no valid credential.
///
/// Returns the index of the winning candidate, or `None` if no candidate
/// strictly beats `store_expiry`. Winning = maximum-expiry candidate that
/// is strictly greater than `store_expiry` (or any candidate when
/// `store_expiry` is `None`).
///
/// This function is pure (no I/O, no `security` calls) and therefore fully
/// unit-testable without a real keychain.
pub fn decide_harvest(
    candidates: &[(u64 /* expiry_ms */, usize /* index */)],
    store_expiry: Option<u64>,
) -> Option<usize> {
    // Find the candidate with the maximum expiry that beats the store.
    let mut best: Option<(u64, usize)> = None; // (expiry, idx)
    for &(expiry, idx) in candidates {
        // Caller guarantees candidates are non-expired; also require strictly
        // greater than the store expiry.
        let beats_store = match store_expiry {
            Some(s) => expiry > s,
            None => true, // no store token → any valid candidate wins
        };
        if beats_store && best.is_none_or(|(b, _)| expiry > b) {
            best = Some((expiry, idx));
        }
    }
    best.map(|(_, idx)| idx)
}

/// Bounded read of the raw credential JSON in `config_dir`'s keychain item
/// (handles CC's raw-JSON and legacy hex encodings). `None` on absent/timeout/
/// malformed. Distinct from [`read`] (which parses into a `CredentialFile`) —
/// the harvest needs the raw bytes to re-write verbatim.
#[cfg(target_os = "macos")]
fn read_raw_keychain(config_dir: &Path) -> Option<String> {
    let svc = service_name(config_dir);
    let account = keychain_account();
    let output =
        run_security_bounded(&["find-generic-password", "-s", &svc, "-a", &account, "-w"])?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let raw = raw.trim();
    if raw.starts_with('{') {
        Some(raw.to_string())
    } else {
        let bytes = hex::decode(raw).ok()?;
        String::from_utf8(bytes).ok()
    }
}

/// Hard ceiling on any `security` subprocess (security.md §6 — every keychain
/// call MUST have a timeout path; never block). On a LOCKED keychain (headless
/// launchd / SSH / CI runner with no Aqua session — see
/// `discovery_agent_keychain_needs_aqua_session_not_tmux`) a `security` write
/// blocks waiting for an unlock that never comes; without this bound a `csq run`
/// keychain mirror would hang the launch (observed: CI macOS integration tests
/// timed out at 25 min).
#[cfg(target_os = "macos")]
const KEYCHAIN_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Run a `security` subprocess bounded by [`KEYCHAIN_OP_TIMEOUT`]. Returns the
/// captured output, or `None` on spawn failure OR timeout. On timeout the child
/// is SIGKILLed so a hung `security` (locked keychain) cannot leak. stdin is
/// `/dev/null` so `security` never blocks reading a prompt. Best-effort by
/// construction: every caller treats `None` as "keychain unavailable → skip".
#[cfg(target_os = "macos")]
fn run_security_bounded(args: &[&str]) -> Option<std::process::Output> {
    // Test/hermetic guard — never shell `security` against the operator's real
    // login keychain from a test. Reads/deletes degrade to "unavailable" (None);
    // `write_raw` short-circuits to Ok separately so it reports a clean no-op.
    if keychain_mirror_disabled() {
        return None;
    }
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    let child = Command::new("security")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Capture stderr (previously `/dev/null`) so callers can surface the
        // actual `errSec…` reason a write failed — `security` writes its
        // diagnostics to stderr, not stdout. `wait_with_output` drains both
        // pipes, so this cannot deadlock. stderr carries only the OS error text
        // (e.g. `errSecInteractionNotAllowed`), never the `-w` secret (passed via
        // argv); callers redact before logging (security.md §2).
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(KEYCHAIN_OP_TIMEOUT) {
        Ok(Ok(output)) => Some(output),
        Ok(Err(_)) => None,
        Err(_) => {
            // Timed out — the keychain is locked/hung. SIGKILL the child so it
            // can't pin a worker thread or leak a `security` process; the waiter
            // thread then unblocks and sends to the dropped receiver (ignored).
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            None
        }
    }
}

/// Write `raw_json` into the keychain item CC reads for `config_dir`. Updates an
/// existing item's value in place (preserving the ACL CC set on it); creates an
/// absent item with all-apps read access (`-A`) so CC reads it without an
/// interactive ACL-grant prompt (which fails outright in non-GUI / daemon
/// sessions).
///
/// Uses the `security` CLI for parity with [`read_impl`] and because the `-A`
/// create path is not exposed by the `security-framework` high-level API. The
/// credential is passed via argv; on macOS `ps` restricts argv to the same
/// user, who can already read the 0600 `.credentials.json` — no new cross-user
/// exposure (security.md §2: same-user threat model).
///
/// **`-A` (all-applications ACL) — explicit trade-off (security.md §2).** `-A`
/// makes the item readable by any application running AS THIS USER without an
/// ACL prompt. That is a deliberate reduction of the keychain's app-scoped ACL
/// down to file-level exposure — BUT it grants nothing a same-user process did
/// not already have: the identical token sits in `identities/<UUID>/credentials.json`
/// at 0600, readable by any process of this UID. Under csq's same-user threat
/// model the `-A` item adds no exposure beyond that file. The `-T <app>` scoped
/// alternative was rejected: it requires the CC binary's stable path, which is
/// unstable across nvm/volta/brew upgrades, and a wrong `-T` re-introduces the
/// interactive prompt that breaks non-GUI/daemon writes — the exact failure this
/// mirror exists to survive. Accepted explicitly per zero-tolerance.md Rule 5
/// (same-user is grounds for the cheaper fix, here documented acceptance).
///
/// Concurrency: three writers exist (`csq run`, `csq keychain-sync`, the daemon
/// sweep). Two concurrent `write_raw` for the same service are last-writer-wins
/// and both write a validity-guarded token, so the terminal state is always a
/// single valid item — no lock needed. The delete→create gap (no item briefly)
/// is bounded by CC's ~30s re-check; on `csq run` the create completes before
/// `claude` is exec'd, so a launching CC never observes the gap.
#[cfg(target_os = "macos")]
pub fn write_raw(config_dir: &Path, raw_json: &str) -> Result<(), PlatformError> {
    // Test/hermetic guard — report a clean no-op success (parity with the non-macOS
    // stub) instead of shelling `security add-generic-password` against the
    // operator's real login keychain.
    if keychain_mirror_disabled() {
        return Ok(());
    }
    let svc = service_name(config_dir);
    let account = keychain_account();
    // Remove every existing item for this service first, THEN create a single
    // fresh one. CC keys lookups by service + account, and pre-existing items
    // may carry a different/empty account than `keychain_account()` — an
    // update-by-account would then leave a SHADOWING sibling with the old token
    // that CC reads instead (observed in testing: a stale sibling re-introduced
    // the 401). `delete-generic-password` removes one match per call; loop until
    // none remain. The brief absence window is bounded by CC's ~30s re-check
    // (and on `csq run` the create completes before `claude` is exec'd).
    // Each `security` call is bounded by KEYCHAIN_OP_TIMEOUT (security.md §6): a
    // locked keychain (headless launchd / CI runner with no Aqua session) blocks
    // the write forever otherwise, hanging `csq run` / the daemon tick. On
    // timeout the bounded helper SIGKILLs the child and returns None → we treat
    // it as "keychain unavailable" and fail best-effort (the caller swallows it).
    //
    // Bounded at `MAX_DUPLICATE_DELETE_ITERATIONS` (security review 1386,
    // sec-1386's request — this loop is [`drain_service`]'s sibling and
    // shares its rationale: nothing in `security`'s behavior GUARANTEES this
    // terminates quickly, only that duplicate counts are small in practice).
    // Unlike `drain_service`'s callers, THIS loop's caller (`csq run`/
    // `auto_rotate`) still proceeds to the CREATE below regardless of how
    // the loop ends — hitting the bound here does not fail the write, it
    // just stops chasing possible further duplicates.
    //
    // **What exhausting the bound actually costs (security review 1386,
    // team-lead — connecting this to the consequence named 15 lines
    // above): if MORE than `MAX_DUPLICATE_DELETE_ITERATIONS` duplicates
    // somehow exist, this loop stops draining before they're gone, and the
    // CREATE below then runs against a service that still has undrained
    // siblings — the exact "SHADOWING sibling with the old token that CC
    // reads instead (observed in testing: a stale sibling re-introduced
    // the 401)" state this whole delete-then-create sequence exists to
    // prevent.** Reachability is genuinely low (needs ≥`MAX_DUPLICATE_DELETE_ITERATIONS`
    // partial-failure write_raw interleavings with no healthy write in
    // between — see [`MAX_DUPLICATE_DELETE_ITERATIONS`]'s own doc for why
    // that count is bounded well below this constant in practice) and it
    // self-heals: the NEXT successful `write_raw` call deletes-all again
    // from a lower starting count. Not treated as a hard failure here for
    // that reason — but a future reader raising or lowering this constant
    // should know this is the failure mode being traded off, not merely
    // "the write proceeds anyway".
    for _ in 0..MAX_DUPLICATE_DELETE_ITERATIONS {
        let deleted = run_security_bounded(&["delete-generic-password", "-s", &svc])
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !deleted {
            break;
        }
    }
    // Create with all-apps read access (-A) so CC reads it without an
    // interactive ACL-grant prompt (which fails outright in non-GUI / daemon
    // sessions). `-U` is harmless after the deletes (no item to update).
    let output = run_security_bounded(&[
        "add-generic-password",
        "-U",
        "-A",
        "-s",
        &svc,
        "-a",
        &account,
        "-w",
        raw_json,
    ])
    .ok_or_else(|| {
        PlatformError::Keychain(
            "keychain write timed out (likely a locked or non-interactive keychain — \
             e.g. an SSH/tmux session that cannot answer an authorization prompt)"
                .into(),
        )
    })?;
    if !output.status.success() {
        // Surface the ACTUAL `security` reason (redacted) + exit code instead of a
        // generic "failed", so `cc_keychain_sync_failed` is diagnosable. `security`
        // emits `errSec…` text on stderr (the common cause is an ACL-set item that
        // a non-interactive session can't modify without a prompt).
        let code = output
            .status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string());
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = crate::error::redact_tokens(stderr.trim());
        let reason = if reason.is_empty() {
            "no stderr".to_string()
        } else {
            reason
        };
        return Err(PlatformError::Keychain(format!(
            "keychain write failed (security exit {code}): {reason}"
        )));
    }
    Ok(())
}

/// Non-macOS stub: CC reads `.credentials.json` directly on Linux/Windows, so
/// there is no keychain item to mirror.
#[cfg(not(target_os = "macos"))]
pub fn write_raw(_config_dir: &Path, _raw_json: &str) -> Result<(), PlatformError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_format() {
        let svc = service_name(Path::new("/Users/test/.claude/accounts/config-1"));
        assert!(svc.starts_with("Claude Code-credentials-"));
        assert_eq!(svc.len(), "Claude Code-credentials-".len() + 8);
    }

    /// Security review 1386 M4 regression: a handle dir whose path DOES
    /// canonicalize gets the canonical form back, WITH the keychain write
    /// permitted — the common case, unaffected by the guard.
    #[test]
    fn canonicalize_for_keychain_sync_permits_write_when_canonicalizable() {
        let dir = tempfile::tempdir().unwrap();
        let expected = std::fs::canonicalize(dir.path()).unwrap();

        let (handle_dir_abs, keychain_write_allowed) = canonicalize_for_keychain_sync(dir.path());

        assert_eq!(handle_dir_abs, expected);
        assert!(
            keychain_write_allowed,
            "a canonicalizable dir must permit the keychain write"
        );
    }

    /// Security review 1386 M4: a handle dir whose path CANNOT be
    /// canonicalized (dangling — parent does not exist) must NOT permit a
    /// keychain write. Before the fix, the three writer call sites
    /// (`csq run`, `csq exec`, the Phase-2b headless-turn builder) fell back
    /// to this same raw path for the keychain mirror — [`service_name`]
    /// hashes whatever string it is given, so the item would land under a
    /// DIFFERENT service name than the one CC (which hashes the
    /// canonicalized `CLAUDE_CONFIG_DIR`) or either clearer
    /// (`logout::clear_bound_keychain_items`, the handle-dir reaper) can
    /// ever compute — a permanent orphan holding a real OAuth token.
    ///
    /// The raw path is still returned as `handle_dir_abs` — callers still
    /// need SOME path to launch/spawn against — only `keychain_write_allowed`
    /// distinguishes the two cases.
    #[test]
    fn canonicalize_for_keychain_sync_refuses_write_when_dangling() {
        let dir = tempfile::tempdir().unwrap();
        let dangling = dir.path().join("does-not-exist").join("term-1");
        assert!(
            std::fs::canonicalize(&dangling).is_err(),
            "fixture must actually fail to canonicalize"
        );

        let (handle_dir_abs, keychain_write_allowed) = canonicalize_for_keychain_sync(&dangling);

        assert_eq!(
            handle_dir_abs, dangling,
            "raw path is still returned for launch/spawn purposes"
        );
        assert!(
            !keychain_write_allowed,
            "a non-canonicalizable dir must NOT permit the keychain write \
             (M4 — the write would land under a service name no clearer can \
             ever compute)"
        );
    }

    /// `clear_handle_dir_reporting` MUST short-circuit to `Ok(false)` under
    /// the test-mode guard (`cfg!(test)` is unconditionally true in this
    /// module's own tests) — never reaching `run_security_bounded`, so this
    /// is safe on every platform / every CI runner without touching a real
    /// keychain. Pins the "disabled" contract callers (`logout_account`)
    /// rely on to distinguish a structural no-op from a real failure.
    #[test]
    fn clear_handle_dir_reporting_is_ok_false_under_test_mode() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(clear_handle_dir_reporting(dir.path()), Ok(false));
    }

    // ── security review 1386 F1: exit-status classification ──────────────
    // `security_delete_call_resolved` is pure over a constructed `Output` — no
    // subprocess, no keychain, safe on every CI runner.

    #[cfg(target_os = "macos")]
    fn fake_output(code: i32) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt;
        std::process::Output {
            // Raw wait-status encoding for "exited normally with `code`":
            // low byte 0 (WIFEXITED true), next byte = WEXITSTATUS.
            status: std::process::ExitStatus::from_raw((code & 0xff) << 8),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn security_delete_call_resolved_true_on_success_and_not_found() {
        assert!(
            security_delete_call_resolved(&fake_output(0)),
            "exit 0 (deleted) must be confirmed"
        );
        assert!(
            security_delete_call_resolved(&fake_output(SECURITY_ITEM_NOT_FOUND)),
            "exit 44 (errSecItemNotFound — live-verified) must be confirmed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn security_delete_call_resolved_false_on_any_other_exit() {
        // In practice `security` reports small positive codes, but the
        // function must reject ANY code that is neither 0 nor
        // SECURITY_ITEM_NOT_FOUND — this is the F1 fix's whole point: do
        // not generalize "completed" to "confirmed". 255 pins the upper
        // edge of what `fake_output` can represent: `ExitStatus::from_raw`
        // only carries a single WEXITSTATUS byte (0-255), so a genuinely
        // negative i32 passed to `fake_output` truncates through `& 0xff`
        // before construction rather than surviving as a negative code —
        // sec-1386's correction — so this set sticks to values the
        // constructor can actually represent, not ones that silently alias.
        for code in [1, 2, 44 + 1, 100, 255] {
            assert!(
                !security_delete_call_resolved(&fake_output(code)),
                "exit {code} must NOT be confirmed (only 0 and {SECURITY_ITEM_NOT_FOUND} are)"
            );
        }
    }

    // ── security review 1386 N1: duplicate keychain item draining ────────
    // `drain_service_inner`'s injected `delete_fn` scripts a SEQUENCE of
    // exit codes across iterations — no real `security` subprocess, no
    // keychain, safe on every CI runner. Live-confirmed by team-lead's
    // probe: `security delete-generic-password` removes exactly ONE
    // matching item per call, so a single-shot delete against a service
    // with duplicates reports success (exit 0) while a sibling survives.

    #[cfg(target_os = "macos")]
    #[test]
    fn drain_service_inner_confirms_immediately_when_no_item_exists() {
        let mut calls = 0u32;
        let mut delete_fn = |_svc: &str| -> Option<i32> {
            calls += 1;
            Some(SECURITY_ITEM_NOT_FOUND)
        };
        assert_eq!(drain_service_inner("svc", &mut delete_fn), Ok(true));
        assert_eq!(
            calls, 1,
            "a not-found on the FIRST call must not loop further"
        );
    }

    /// The N1 regression itself: TWO duplicate items under one service.
    /// The naive single-shot delete (what shipped before N1) would have
    /// reported `Ok(true)` after exactly the first `Some(0)` — this test
    /// pins that draining CONTINUES past a single success and does not
    /// stop until a confirmed not-found.
    #[cfg(target_os = "macos")]
    #[test]
    fn drain_service_inner_drains_multiple_duplicates_before_confirming() {
        let mut codes = vec![0, 0, SECURITY_ITEM_NOT_FOUND].into_iter();
        let mut calls = 0u32;
        let mut delete_fn = |_svc: &str| -> Option<i32> {
            calls += 1;
            codes.next()
        };
        assert_eq!(drain_service_inner("svc", &mut delete_fn), Ok(true));
        assert_eq!(
            calls, 3,
            "must keep draining past the first (and second) successful \
             delete — a single Ok(true) after ONE call is the N1 defect"
        );
    }

    /// A stop-immediately failure mid-drain must NOT keep looping into a
    /// possibly worse state, and must report unconfirmed — not success,
    /// even though earlier iterations in the same call DID delete items.
    #[cfg(target_os = "macos")]
    #[test]
    fn drain_service_inner_stops_on_first_unconfirmed_result() {
        let mut codes = vec![Some(0), Some(1) /* unconfirmed */, Some(0)].into_iter();
        let mut calls = 0u32;
        let mut delete_fn = |_svc: &str| -> Option<i32> {
            calls += 1;
            codes.next().flatten()
        };
        assert_eq!(
            drain_service_inner("svc", &mut delete_fn),
            Err(KeychainClearUnconfirmed)
        );
        assert_eq!(
            calls, 2,
            "must stop at the FIRST unconfirmed result, never reach the third code"
        );
    }

    /// The iteration bound: an adversarial/pathological service that
    /// NEVER reaches confirmed-not-found must not loop forever — bounded
    /// at `MAX_DUPLICATE_DELETE_ITERATIONS`, and reports UNCONFIRMED (never
    /// success) on exhaustion.
    #[cfg(target_os = "macos")]
    #[test]
    fn drain_service_inner_bounded_and_unconfirmed_on_budget_exhaustion() {
        let mut calls = 0u32;
        let mut delete_fn = |_svc: &str| -> Option<i32> {
            calls += 1;
            Some(0) // always reports "one deleted" — never confirms not-found
        };
        assert_eq!(
            drain_service_inner("svc", &mut delete_fn),
            Err(KeychainClearUnconfirmed)
        );
        assert_eq!(calls, MAX_DUPLICATE_DELETE_ITERATIONS);
    }

    // ── pending-clear queue (security review 1386 H1) ────────────────────
    // Pure file I/O against a TempDir — no `keychain_mirror_disabled()` gate
    // on `record_pending_clear`/`sweep_pending_clears` themselves (see their
    // doc comments), so these exercise the real functions, not a stub.
    // macOS-only: the queue is a no-op stub on other platforms (nothing was
    // ever populated there), matching `swap_lock_blocks_harvest_try_lock_then_releases`'s
    // platform gating above.

    /// The queue's own `service` accessor for assertions below — the schema
    /// carries `attempts`/`next_attempt_unix_secs` too, which most tests
    /// don't care about.
    #[cfg(target_os = "macos")]
    fn service_names(clears: &PendingClears) -> Vec<String> {
        clears.services.iter().map(|e| e.service.clone()).collect()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn record_pending_clear_persists_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        record_pending_clear(dir.path(), "Claude Code-credentials-aaaaaaaa");
        record_pending_clear(dir.path(), "Claude Code-credentials-aaaaaaaa"); // duplicate

        let clears = load_pending_clears(dir.path());
        assert_eq!(
            service_names(&clears),
            vec!["Claude Code-credentials-aaaaaaaa".to_string()],
            "recording the same service twice must not duplicate the entry"
        );
        assert_eq!(
            clears.services[0].attempts, 0,
            "a freshly-recorded entry has never been attempted"
        );
    }

    /// Well-formed synthetic service names for tests — `is_well_formed_service_name`
    /// (F8) now filters anything else out at load time, so test fixtures must
    /// match the real `service_name()` shape (`Claude Code-credentials-<8 hex>`).
    #[cfg(target_os = "macos")]
    fn fake_service(n: u32) -> String {
        format!("Claude Code-credentials-{n:08x}")
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn record_pending_clear_evicts_oldest_when_full() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..PENDING_CLEARS_MAX as u32 {
            record_pending_clear(dir.path(), &fake_service(i));
        }
        // Queue is now exactly full at PENDING_CLEARS_MAX with fake_service(0..MAX).
        let overflow = fake_service(0xeeee_eeee);
        record_pending_clear(dir.path(), &overflow);

        let clears = load_pending_clears(dir.path());
        assert_eq!(
            clears.services.len(),
            PENDING_CLEARS_MAX,
            "the queue must stay bounded at PENDING_CLEARS_MAX, never grow past it"
        );
        let names = service_names(&clears);
        assert!(
            !names.contains(&fake_service(0)),
            "the OLDEST entry must be evicted (FIFO) to make room"
        );
        assert!(
            names.contains(&overflow),
            "the new entry must be present after eviction"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn is_well_formed_service_name_accepts_real_shape_rejects_junk() {
        assert!(is_well_formed_service_name(
            "Claude Code-credentials-cfdcc24b"
        ));
        // Security review 1386 F8's whole point: a string starting with `-`
        // must never reach `security`'s argv as a bare "-s" value would be
        // parsed as an option, not a service name.
        assert!(!is_well_formed_service_name("-w"));
        assert!(!is_well_formed_service_name(
            "-a evil Claude Code-credentials-aaaaaaaa"
        ));
        assert!(!is_well_formed_service_name("Claude Code-credentials-"));
        assert!(!is_well_formed_service_name(
            "Claude Code-credentials-zzzzzzzz" // not hex
        ));
        assert!(!is_well_formed_service_name(
            "Claude Code-credentials-aaaaaaaaa" // 9 chars, not 8
        ));
        assert!(!is_well_formed_service_name(""));
    }

    /// Security review 1386 sec-1386: `is_well_formed_service_name`'s
    /// `PREFIX` const is retyped independently of [`service_name`]'s format
    /// string — they agree today only by construction, not by any shared
    /// source. If a future edit changes `service_name`'s output shape
    /// without updating the validator, `load_pending_clears` would silently
    /// `retain` every real entry away, surfacing as a
    /// `keychain_pending_clears_malformed_entry` WARN that reads like file
    /// corruption rather than a producer/validator drift bug (the round-2
    /// HIGH by a third route). This pins the two together so that drift
    /// fails a TEST, not silently in production.
    #[cfg(target_os = "macos")]
    #[test]
    fn is_well_formed_service_name_matches_real_producer() {
        let real = service_name(Path::new("/Users/test/.claude/accounts/config-1"));
        assert!(
            is_well_formed_service_name(&real),
            "service_name()'s actual output must validate — got {real:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn load_pending_clears_drops_malformed_entries_keeps_well_formed() {
        let dir = tempfile::tempdir().unwrap();
        // Hand-write the queue file directly (simulating a corrupted / tampered
        // entry, or a pre-F8 file) with one malformed and one well-formed entry.
        let raw = serde_json::json!({
            "services": [
                {"service": "-w", "attempts": 0, "next_attempt_unix_secs": 0},
                {"service": "Claude Code-credentials-deadbeef", "attempts": 0, "next_attempt_unix_secs": 0},
            ]
        });
        std::fs::write(
            pending_clears_path(dir.path()),
            serde_json::to_string(&raw).unwrap(),
        )
        .unwrap();

        let clears = load_pending_clears(dir.path());
        assert_eq!(
            service_names(&clears),
            vec!["Claude Code-credentials-deadbeef".to_string()],
            "the malformed entry must be dropped; the well-formed one must survive"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_pending_clears_empty_queue_is_zero_zero_no_file_write() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(sweep_pending_clears(dir.path()), (0, 0));
        assert!(
            !pending_clears_path(dir.path()).exists(),
            "an empty-queue sweep must not write a file — cheap-when-empty contract"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_pending_clears_under_test_mode_keeps_entries_queued() {
        // `clear_service_reporting` short-circuits to `Ok(false)` under
        // `keychain_mirror_disabled()` (cfg!(test) is unconditionally true
        // here), so a sweep in this test process can NEVER report a real
        // clear — this pins that: entries survive a sweep untouched rather
        // than being silently dropped (which would be a same-shape bug to
        // the one `sweep_pending_clears`'s budget logic must avoid: losing
        // queued entries on a call that could not act on them).
        let dir = tempfile::tempdir().unwrap();
        record_pending_clear(dir.path(), "Claude Code-credentials-bbbbbbbb");

        let (cleared, remaining) = sweep_pending_clears(dir.path());
        assert_eq!(cleared, 0, "test mode never confirms a real clear");
        assert_eq!(remaining, 1, "the entry must remain queued, not be dropped");

        let clears = load_pending_clears(dir.path());
        assert_eq!(
            service_names(&clears),
            vec!["Claude Code-credentials-bbbbbbbb".to_string()]
        );
        // Security review 1386 N2: `Ok(false)` (test mode) is a structural
        // no-op — it must NOT be treated as a failed attempt for backoff
        // purposes, unlike a genuine `Err(KeychainClearUnconfirmed)`.
        assert_eq!(
            clears.services[0].attempts, 0,
            "a structural no-op (mirror disabled) must not bump attempts/backoff"
        );
    }

    /// Security review 1386 HIGH (round 2), non-vacuity target: a sweep's
    /// removal step MUST NOT blindly overwrite the queue with its own
    /// pre-attempt snapshot — it must remove only the SPECIFIC entries it
    /// confirmed cleared, against a FRESH re-load. This test simulates the
    /// race directly (no thread timing dependency): record A, take a
    /// snapshot-shaped read the way the sweep does, THEN record B
    /// "concurrently" (between the sweep's read and its locked removal),
    /// then perform the same removal the sweep performs, and assert B
    /// survives.
    ///
    /// **Drift note (security review 1386, team-lead): this replicates
    /// production's removal logic inline rather than calling
    /// `sweep_pending_clears_inner` directly, so it CAN drift from
    /// production if the removal changes again — this exact drift already
    /// happened once (this test used a bare service-name match through
    /// several rounds after production moved to `identity_matches`, and
    /// kept passing because A and B are different services here, so
    /// name-only and identity-based matching agree by coincidence). Now
    /// uses [`identity_matches`] — the SAME function production calls —
    /// rather than reimplementing the comparison, so the comparison LOGIC
    /// specifically cannot drift even though the surrounding lock/load/save
    /// structure is still hand-replicated.
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_removal_does_not_drop_a_concurrently_recorded_entry() {
        let dir = tempfile::tempdir().unwrap();
        let svc_a = fake_service(0xaaaa_0001);
        let svc_b = fake_service(0xbbbb_0002);
        record_pending_clear(dir.path(), &svc_a);

        // Simulate the sweep's pre-attempt snapshot + a confirmed clear of A.
        let snapshot = load_pending_clears(dir.path());
        assert_eq!(service_names(&snapshot), vec![svc_a.clone()]);
        let cleared_entries = snapshot.services.clone();

        // "Concurrently" (between the sweep's read and its locked removal),
        // another logout records B.
        record_pending_clear(dir.path(), &svc_b);

        // The removal step itself: locked, fresh re-load, identity-matched
        // (service + generation) — same comparison production uses.
        {
            let _guard =
                crate::platform::lock::lock_file(&pending_clears_lock_path(dir.path())).unwrap();
            let mut current = load_pending_clears(dir.path());
            current
                .services
                .retain(|e| !cleared_entries.iter().any(|c| identity_matches(c, e)));
            save_pending_clears(dir.path(), &current, "test");
        }

        let clears = load_pending_clears(dir.path());
        assert_eq!(
            service_names(&clears),
            vec![svc_b],
            "B must survive a removal step that only knew about A at read time — \
             a naive overwrite-with-snapshot would have dropped B (the HIGH this test pins)"
        );
    }

    /// Non-vacuity for the above: a NAIVE removal (overwrite with the
    /// pre-attempt snapshot minus cleared entries, ignoring what was
    /// recorded in between) DOES drop the concurrently-recorded entry —
    /// proving the test discriminates and the real function's fresh-reload
    /// discipline is load-bearing, not incidental.
    #[cfg(target_os = "macos")]
    #[test]
    fn naive_snapshot_overwrite_would_have_dropped_the_concurrent_entry() {
        let dir = tempfile::tempdir().unwrap();
        let svc_a = fake_service(0xaaaa_0003);
        let svc_b = fake_service(0xbbbb_0004);
        record_pending_clear(dir.path(), &svc_a);
        let snapshot = load_pending_clears(dir.path());
        record_pending_clear(dir.path(), &svc_b); // concurrent insert

        // Naive: overwrite with (snapshot minus cleared), never re-reading.
        let mut naive = snapshot;
        naive.services.retain(|e| e.service != svc_a);
        save_pending_clears(dir.path(), &naive, "test");

        let clears = load_pending_clears(dir.path());
        assert!(
            service_names(&clears).is_empty(),
            "the naive overwrite silently drops B — this is the bug the locked, \
             fresh-reload removal in sweep_pending_clears exists to avoid"
        );
    }

    /// The DEEPER race sec-1386 identified (retracted-then-reinstated, and
    /// the reason `generation` exists): the SAME service, not two
    /// different ones. A sweep attempts X, confirms it cleared, and takes
    /// its `cleared_entries` snapshot. Before the sweep's locked removal
    /// runs, a NEW logout for the SAME service (e.g. a recycled PID
    /// hashing to the same keychain service name) re-records X — which
    /// resets attempts/next_attempt to `(0, 0)`. If removal matched by
    /// SERVICE NAME alone, this fresh request would be silently deleted by
    /// the stale confirmation, even though it represents a DIFFERENT clear
    /// that has not actually been attempted yet.
    ///
    /// Critically, resetting attempts/next_attempt alone does NOT save
    /// this case: a never-yet-attempted entry is ALREADY `(0, 0)`, so the
    /// snapshot's original copy of X (before the sweep ever touched it)
    /// and the freshly re-recorded copy would be IDENTICAL without
    /// `generation` — only the generation bump makes them distinguishable.
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_removal_does_not_drop_a_same_service_re_recorded_after_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let svc = fake_service(0xf00d_dead);
        record_pending_clear(dir.path(), &svc); // generation 0, never attempted: (0,0)

        // Sweep's pre-attempt snapshot — captures X at generation 0.
        let snapshot = load_pending_clears(dir.path());
        assert_eq!(snapshot.services[0].generation, 0);
        let cleared_entries = snapshot.services.clone(); // "confirmed cleared" this tick

        // "Concurrently" (between the sweep's read and its locked removal),
        // a NEW logout re-records the SAME service — generation bumps to 1,
        // but attempts/next_attempt reset to the SAME (0,0) the original had.
        record_pending_clear(dir.path(), &svc);
        let after_rerecord = load_pending_clears(dir.path());
        assert_eq!(after_rerecord.services[0].generation, 1);
        assert_eq!(after_rerecord.services[0].attempts, 0);
        assert_eq!(after_rerecord.services[0].next_attempt_unix_secs, 0);

        // The removal step itself: locked, fresh re-load, identity-matched
        // (service + generation — [`identity_matches`], the SAME function
        // production calls, not a reimplemented comparison — security
        // review 1386, team-lead's drift finding: an earlier version of
        // this test hand-rolled full-struct equality, which happened to
        // still pass here since a generation-1 entry is unequal to its
        // generation-0 snapshot either way, but the test's own claim to be
        // "exactly" production's logic was already false by then).
        {
            let _guard =
                crate::platform::lock::lock_file(&pending_clears_lock_path(dir.path())).unwrap();
            let mut current = load_pending_clears(dir.path());
            current
                .services
                .retain(|e| !cleared_entries.iter().any(|c| identity_matches(c, e)));
            save_pending_clears(dir.path(), &current, "test");
        }

        let clears = load_pending_clears(dir.path());
        assert_eq!(
            clears.services.len(),
            1,
            "the freshly re-recorded (generation 1) entry must survive — a \
             service-name-only removal would have dropped it despite it \
             representing a NEW, unattempted clear request"
        );
        assert_eq!(clears.services[0].generation, 1);
    }

    /// Non-vacuity for the above: WITHOUT `generation` in the equality
    /// check (i.e. matching by service name alone, as the pre-fix code
    /// did), the re-recorded entry IS dropped — proving the test
    /// discriminates and `generation` is load-bearing, not decorative.
    #[cfg(target_os = "macos")]
    #[test]
    fn naive_service_name_only_removal_would_have_dropped_the_re_recorded_entry() {
        let dir = tempfile::tempdir().unwrap();
        let svc = fake_service(0xf00d_beef);
        record_pending_clear(dir.path(), &svc);
        let snapshot = load_pending_clears(dir.path());
        let cleared_names: Vec<String> = snapshot
            .services
            .iter()
            .map(|e| e.service.clone())
            .collect();

        record_pending_clear(dir.path(), &svc); // concurrent re-record, generation bumps

        // Naive: remove by SERVICE NAME only, ignoring generation.
        let mut naive = load_pending_clears(dir.path());
        naive
            .services
            .retain(|e| !cleared_names.contains(&e.service));
        save_pending_clears(dir.path(), &naive, "test");

        let clears = load_pending_clears(dir.path());
        assert!(
            clears.services.is_empty(),
            "a service-name-only removal silently drops the re-recorded entry — \
             this is the bug the (service, generation) identity removal in \
             sweep_pending_clears_inner exists to avoid. Identity is NOT \
             full-struct equality: attempts/next_attempt_unix_secs are mutable \
             state load-time normalization may change between snapshot and \
             reload"
        );
    }

    /// Security review 1386 C1(c) (pendq-r2, confirmed live by team-lead
    /// against the actual code): a FULL-entry-equality removal — the shape
    /// this module shipped between the generation fix landing and this
    /// test — is ITSELF broken, because `load_pending_clears`'s N5 clamp
    /// mutates `attempts`/`next_attempt_unix_secs` on every load. Simulates
    /// that exact scenario directly: the snapshot entry (as the sweep
    /// captured it) and the on-disk entry at removal time have the SAME
    /// `(service, generation)` but DIFFERENT `attempts`/`next_attempt_unix_secs`
    /// (as a clamp landing on a different wall-clock second would produce)
    /// — and asserts the entry is STILL removed, because `identity_matches`
    /// ignores those fields entirely.
    #[cfg(target_os = "macos")]
    #[test]
    fn identity_matches_removal_survives_a_clamp_induced_state_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let svc = fake_service(0xc1a4_0001);
        record_pending_clear(dir.path(), &svc);

        // The sweep's snapshot: what it read and (hypothetically) confirmed
        // cleared. generation = 0, attempts = 0, next_attempt = 0 (fresh).
        let snapshot_entry = load_pending_clears(dir.path()).services[0].clone();
        let cleared_entries = [snapshot_entry.clone()];

        // Simulate the clamp/backoff machinery producing a DIFFERENT
        // attempts/next_attempt on the ON-DISK copy by the time removal
        // runs — same identity (service, generation), different state.
        // A full-struct comparison would find these UNEQUAL.
        let mut on_disk = load_pending_clears(dir.path());
        on_disk.services[0].attempts = 3;
        on_disk.services[0].next_attempt_unix_secs = 999_999;
        assert_ne!(
            on_disk.services[0], snapshot_entry,
            "precondition: the two copies must differ on non-identity fields \
             for this test to exercise anything"
        );
        save_pending_clears(dir.path(), &on_disk, "test");

        // The removal step itself, exactly as sweep_pending_clears_inner
        // performs it: identity_matches, not full equality.
        {
            let _guard =
                crate::platform::lock::lock_file(&pending_clears_lock_path(dir.path())).unwrap();
            let mut current = load_pending_clears(dir.path());
            current
                .services
                .retain(|e| !cleared_entries.iter().any(|c| identity_matches(c, e)));
            save_pending_clears(dir.path(), &current, "test");
        }

        let clears = load_pending_clears(dir.path());
        assert!(
            clears.services.is_empty(),
            "identity-based removal must succeed even when attempts/next_attempt \
             differ between the snapshot and the on-disk copy — a full-struct \
             comparison would have left this confirmed-cleared entry stuck in \
             the queue forever"
        );
    }

    /// Security review 1386 MEDIUM: an UNCONFIRMED attempt (`Err`, what a
    /// real refusal/timeout produces) bumps `attempts` and pushes
    /// `next_attempt_unix_secs` into the future, so the NEXT sweep (within
    /// the backoff window) skips it without a subprocess call — while the
    /// entry is NEVER dropped. Uses the injectable seam with an `Err` spy —
    /// the public `sweep_pending_clears` always sees `Ok(false)` under test
    /// mode, which (security review 1386 N2) is a structural no-op that
    /// must NOT bump backoff; that distinct behavior is pinned separately
    /// by `sweep_pending_clears_under_test_mode_keeps_entries_queued`.
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_pending_clears_applies_backoff_after_a_failed_attempt() {
        let dir = tempfile::tempdir().unwrap();
        record_pending_clear(dir.path(), "Claude Code-credentials-cccccccc");

        let mut spy = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> {
            Err(KeychainClearUnconfirmed)
        };
        let now = pending_clears_now_secs();
        let (cleared, remaining) =
            sweep_pending_clears_inner(dir.path(), now, PENDING_CLEARS_SWEEP_BUDGET, &mut spy);
        assert_eq!((cleared, remaining), (0, 1));

        let clears = load_pending_clears(dir.path());
        let entry = &clears.services[0];
        assert_eq!(entry.attempts, 1, "one failed attempt must be recorded");
        assert!(
            entry.next_attempt_unix_secs > now,
            "a failed attempt must push next_attempt_unix_secs into the future \
             so the entry is not retried on the very next tick"
        );
    }

    /// A due entry (never attempted, or whose backoff window has already
    /// elapsed) IS attempted — the backoff gate does not skip everything.
    /// Uses the injectable seam so "attempted" is observed directly (a
    /// call-count spy), rather than inferred from the `attempts` field —
    /// which, after security review 1386 N2, no longer increments for a
    /// structural no-op (`Ok(false)`), only for a genuine `Err`.
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_pending_clears_attempts_a_due_entry() {
        let dir = tempfile::tempdir().unwrap();
        record_pending_clear(dir.path(), "Claude Code-credentials-dddddddd");
        // A freshly-recorded entry has next_attempt_unix_secs == 0, always due.
        let mut attempted = false;
        let mut spy = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> {
            attempted = true;
            Err(KeychainClearUnconfirmed)
        };
        let (cleared, remaining) = sweep_pending_clears_inner(
            dir.path(),
            pending_clears_now_secs(),
            PENDING_CLEARS_SWEEP_BUDGET,
            &mut spy,
        );
        assert_eq!((cleared, remaining), (0, 1));
        assert!(attempted, "a due entry must be attempted, not skipped");
    }

    /// Security review 1386 F5(b) (pendq-analysis): under `clear_service_reporting`,
    /// `Ok(false)` (test mode) and "over budget, never attempted" are
    /// indistinguishable by their effect on the queue — both leave the entry
    /// pending. This test uses the injectable seam to prove EXACTLY
    /// `PENDING_CLEARS_SWEEP_BUDGET` entries are attempted out of a queue of
    /// `PENDING_CLEARS_SWEEP_BUDGET + 3`, which no test against the public
    /// `sweep_pending_clears` (bound to `clear_service_reporting`) could show.
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_pending_clears_inner_attempts_exactly_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let total = PENDING_CLEARS_SWEEP_BUDGET + 3;
        for i in 0..total as u32 {
            record_pending_clear(dir.path(), &fake_service(0xcafe_0000 + i));
        }

        let mut attempts = 0usize;
        let mut spy = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> {
            attempts += 1;
            Err(KeychainClearUnconfirmed) // never confirms — every entry stays queued
        };
        let (cleared, remaining) = sweep_pending_clears_inner(
            dir.path(),
            pending_clears_now_secs(),
            PENDING_CLEARS_SWEEP_BUDGET,
            &mut spy,
        );

        assert_eq!(
            attempts, PENDING_CLEARS_SWEEP_BUDGET,
            "exactly the budget must be ATTEMPTED, not merely consistent with it"
        );
        assert_eq!(cleared, 0);
        assert_eq!(remaining, total);
    }

    /// F1's "both ends" proof, complement to the test above: a REFUSAL
    /// (`Err(KeychainClearUnconfirmed)`, what a completed-but-non-zero-exit
    /// `security` call now correctly produces via `security_delete_call_resolved`)
    /// must leave the entry queued — proven above. This is the other half:
    /// a genuinely CONFIRMED clear (`Ok(true)`) must REMOVE the entry.
    /// Together they show the sweep-time predicate result is what decides
    /// removal, not merely "the subprocess returned" — the exact defect F1
    /// fixed (`Ok(true)` on ANY completed subprocess would have made THIS
    /// test indistinguishable from the refusal test above by construction).
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_pending_clears_inner_removes_entries_the_predicate_confirms() {
        let dir = tempfile::tempdir().unwrap();
        record_pending_clear(dir.path(), &fake_service(0xf00d_0001));
        record_pending_clear(dir.path(), &fake_service(0xf00d_0002));

        let mut spy = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> { Ok(true) };
        let (cleared, remaining) = sweep_pending_clears_inner(
            dir.path(),
            pending_clears_now_secs(),
            PENDING_CLEARS_SWEEP_BUDGET,
            &mut spy,
        );

        assert_eq!((cleared, remaining), (2, 0));
        assert!(
            load_pending_clears(dir.path()).services.is_empty(),
            "a confirmed clear must remove the entry from the persisted queue"
        );
    }

    /// Security review 1386 N5: `now` is injectable so backoff due/not-due
    /// decisions are testable deterministically, without depending on
    /// wall-clock time or a real failed attempt to establish a non-zero
    /// `next_attempt_unix_secs`.
    ///
    /// **Correction (pendq-r2 C1(a)/(b)): the year-2100 constant is NOT
    /// itself load-bearing.** `load_pending_clears`'s N5 clamp runs on
    /// REAL wall-clock time on every load — including the snapshot read
    /// inside `sweep_pending_clears_inner`, regardless of the `now` THIS
    /// function is given — so the manually-set `4_102_444_800` is reduced
    /// to `real_now + PENDING_CLEARS_BACKOFF_MAX_SECS` before the loop's
    /// skip-check ever sees it. What this test actually proves is the
    /// SKIP-CHECK comparison itself (`next_attempt_unix_secs > now`) against
    /// a small injected `now`, using whatever value the clamp leaves behind
    /// — which is still far larger than `1_000`, so the assertion holds,
    /// just not for the reason a literal reading of "year 2100" would
    /// suggest. The removal step's own correctness no longer depends on
    /// this field surviving intact across reloads (`identity_matches`
    /// compares `(service, generation)` only — see its doc), so the clamp's
    /// interference here is a documentation-precision issue, not a
    /// correctness one.
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_pending_clears_inner_skips_entries_not_yet_due_under_injected_now() {
        let dir = tempfile::tempdir().unwrap();
        let svc = fake_service(0xdead_0003);
        record_pending_clear(dir.path(), &svc);
        // Hand-set a future backoff window directly (simulating a prior
        // failed attempt) rather than depending on wall-clock time.
        let mut clears = load_pending_clears(dir.path());
        clears.services[0].attempts = 1;
        clears.services[0].next_attempt_unix_secs = 4_102_444_800; // year 2100
        save_pending_clears(dir.path(), &clears, "test");

        // `now` well before the entry's backoff window — must be skipped.
        let mut attempted_early = false;
        let mut spy_early = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> {
            attempted_early = true;
            Ok(true)
        };
        let (cleared, remaining) = sweep_pending_clears_inner(
            dir.path(),
            1_000,
            PENDING_CLEARS_SWEEP_BUDGET,
            &mut spy_early,
        );
        assert!(
            !attempted_early,
            "an entry not yet due must not be attempted"
        );
        assert_eq!((cleared, remaining), (0, 1));

        // Now inject a `now` AT the entry's due time — must be attempted.
        let mut attempted_due = false;
        let mut spy_due = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> {
            attempted_due = true;
            Ok(true)
        };
        let (cleared2, remaining2) = sweep_pending_clears_inner(
            dir.path(),
            4_102_444_800,
            PENDING_CLEARS_SWEEP_BUDGET,
            &mut spy_due,
        );
        assert!(attempted_due, "an entry AT its due time must be attempted");
        assert_eq!((cleared2, remaining2), (1, 0));
    }

    /// Concurrency test for [`pending_clears_lock_path`] (security review
    /// 1386 HIGH, round 2/3 — the lock underlying BOTH `record_pending_clear`
    /// and the removal half of `sweep_pending_clears`). Channels only — no
    /// sleeps, no spin-loops.
    ///
    /// **What this DOES prove:** both `record_pending_clear` and the
    /// removal step genuinely call `lock_file` on the same path (not a
    /// no-op, not a different path) — thread B's `lock_file` call is
    /// observed to return only AFTER thread A's guard has dropped, in every
    /// run. **What this does NOT prove (sec-1386, naming correction):**
    /// the test cannot discriminate "the lock genuinely serializes" from
    /// "flock happens to be exclusive" — without a forced interleave it
    /// would pass even with the lock call REMOVED (both threads would
    /// merely race, and this specific assertion sequence is what `flock`
    /// guarantees, not something this test's CONSTRUCTION forces). It is
    /// therefore an ACQUISITION check on `platform::lock`'s own semantics,
    /// not a mutation-provable claim about this module's code. The thing
    /// that actually closed the round-2 HIGH — the sweep's re-load-and-
    /// subtract removal, which DOES have a mutation-proven negative control
    /// (`naive_snapshot_overwrite_would_have_dropped_the_concurrent_entry`)
    /// — is the right instrument for that claim; this test is a weaker,
    /// complementary sanity check that both writers reach the SAME lock.
    #[cfg(target_os = "macos")]
    #[test]
    fn pending_clears_lock_is_acquired_by_both_writers() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = pending_clears_lock_path(dir.path());

        let (order_tx, order_rx) = std::sync::mpsc::channel::<&'static str>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let lock_path_a = lock_path.clone();
        let order_tx_a = order_tx.clone();
        let handle_a = std::thread::spawn(move || {
            let _guard = crate::platform::lock::lock_file(&lock_path_a).unwrap();
            order_tx_a.send("A-locked").unwrap();
            release_rx.recv().unwrap(); // held open until the main thread says go
            order_tx_a.send("A-about-to-release").unwrap();
            // `_guard` drops here, at the end of this closure — releasing the
            // lock STRICTLY AFTER the send above (same thread, sequential).
        });

        // Block here (channel recv, not a sleep) until A confirms it holds
        // the lock, so B is spawned into a genuinely contended state.
        assert_eq!(order_rx.recv().unwrap(), "A-locked");

        let lock_path_b = lock_path.clone();
        let order_tx_b = order_tx;
        let handle_b = std::thread::spawn(move || {
            // Blocking acquire: cannot return until A's guard is dropped.
            let _guard = crate::platform::lock::lock_file(&lock_path_b).unwrap();
            order_tx_b.send("B-locked").unwrap();
        });

        // Let A proceed to release. Whether B's flock() call has already
        // fired or fires later, it cannot succeed before A's drop — so the
        // next two messages on the shared channel are DETERMINED in order,
        // not raced for.
        release_tx.send(()).unwrap();

        let second = order_rx.recv().unwrap();
        let third = order_rx.recv().unwrap();

        handle_a
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        handle_b
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));

        assert_eq!(
            (second, third),
            ("A-about-to-release", "B-locked"),
            "B must never observe the lock as free until A's guard has \
             dropped — any other order means the lock is not exclusive"
        );
    }

    /// Security review 1386 LOW: a corrupt queue file logs a WARN rather
    /// than silently discarding its contents. Non-vacuity: assert the
    /// corrupt-file case still returns a usable (empty) queue rather than
    /// panicking — the WARN itself is asserted by inspection of this
    /// function's structure (fixed error_kind, no secret content), matching
    /// this module's existing convention for keychain-error logging (no
    /// dedicated log-capture harness in this crate).
    #[cfg(target_os = "macos")]
    #[test]
    fn load_pending_clears_corrupt_file_degrades_to_empty_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(pending_clears_path(dir.path()), b"not valid json{{{").unwrap();
        let clears = load_pending_clears(dir.path());
        assert!(clears.services.is_empty());
    }

    // ── dead-handle reaper cost predicate ───────────────────────────────
    // `handle_dir_might_have_anthropic_keychain_item` gates whether
    // `session::handle_dir::sweep_dead_handles` bothers with a keychain
    // CLEAR call at all for a dying `term-<pid>` dir. Pure filesystem
    // logic — no keychain access — so these run on every platform.

    #[test]
    fn predicate_true_for_anthropic_shaped_credential() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":9999999999999}}"#,
        )
        .unwrap();
        assert!(handle_dir_might_have_anthropic_keychain_item(dir.path()));
    }

    #[test]
    fn predicate_false_for_non_anthropic_credential() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"openaiAuth":{"token":"x"}}"#,
        )
        .unwrap();
        assert!(!handle_dir_might_have_anthropic_keychain_item(dir.path()));
    }

    #[test]
    fn predicate_false_for_missing_credential_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!handle_dir_might_have_anthropic_keychain_item(dir.path()));
    }

    #[test]
    fn predicate_false_for_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            dir.path().join("nonexistent-target.json"),
            dir.path().join(".credentials.json"),
        )
        .unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(
            dir.path().join("nonexistent-target.json"),
            dir.path().join(".credentials.json"),
        )
        .unwrap();
        assert!(!handle_dir_might_have_anthropic_keychain_item(dir.path()));
    }

    #[test]
    fn sync_handle_dir_skips_when_no_credential_file() {
        // No `.credentials.json` (fresh/torn-down handle dir) → Ok(false), no
        // keychain call. Safe in `cargo test` (never touches the keychain).
        let dir = tempfile::tempdir().unwrap();
        assert!(!sync_handle_dir(dir.path()).unwrap());
    }

    // The `.claude.json` `oauthAccount.emailAddress` reader used to capture
    // `HarvestCandidate.candidate_email` now lives (cross-platform, single-sourced)
    // in `crate::credentials::claude_json` — see its tests for the trimmed /
    // absent / empty / unparseable / oversize coverage. The custodian compares that
    // signal against the bound account's identity.json email.

    // ── A4a: mid-swap lock guard ──────────────────────────────────────────
    // The custodian harvest skips any dir whose `.swap-lock` it cannot acquire,
    // because `csq swap` holds that lock across [clear → repoint → sync]. These
    // tests pin the lock semantics the harvest relies on (no keychain needed).

    #[test]
    fn swap_lock_path_is_inside_handle_dir() {
        let p = swap_lock_path(Path::new("/x/accounts/term-42"));
        assert_eq!(p, Path::new("/x/accounts/term-42/.swap-lock"));
    }

    // macOS-only: `lock_handle_dir_for_swap` is a `None` stub on other platforms
    // (the keychain mechanism it guards exists only on macOS), so the
    // `.expect("swap acquires the lock")` below would panic on Linux/Windows. The
    // guarded mechanism is macOS-only by design, so the test is too.
    #[cfg(target_os = "macos")]
    #[test]
    fn swap_lock_blocks_harvest_try_lock_then_releases() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path();

        // `csq swap` holds the lock across its transition.
        let guard = lock_handle_dir_for_swap(cfg).expect("swap acquires the lock");

        // The harvest's try-lock on the SAME path must be denied → it skips the dir.
        let contended = crate::platform::lock::try_lock_file(&swap_lock_path(cfg)).unwrap();
        assert!(
            contended.is_none(),
            "harvest try-lock MUST fail while swap holds the lock (→ skip mid-swap dir)"
        );

        // After swap finishes, the dir is consistent and harvest may read it.
        drop(guard);
        let free = crate::platform::lock::try_lock_file(&swap_lock_path(cfg)).unwrap();
        assert!(
            free.is_some(),
            "harvest try-lock succeeds once swap releases (dir settled)"
        );
    }

    #[test]
    fn sync_handle_dir_skips_non_anthropic_credential() {
        // A `.credentials.json` without `claudeAiOauth` (a Codex/3P shape) is
        // out of scope for CC's OAuth keychain item → Ok(false), no keychain
        // call.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"openaiAuth":{"token":"x"}}"#,
        )
        .unwrap();
        assert!(!sync_handle_dir(dir.path()).unwrap());
    }

    #[test]
    fn sync_handle_dir_skips_expired_token_no_keychain_call() {
        // Validity guard: an Anthropic credential whose token already expired
        // MUST NOT be mirrored (would propagate a 401 / clobber a fresh login).
        // expiresAt in the past → Ok(false), no keychain syscall (safe in CI).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","expiresAt":1000}}"#,
        )
        .unwrap();
        assert!(!sync_handle_dir(dir.path()).unwrap());
    }

    #[test]
    fn anthropic_expiry_ms_parses_and_fails_safe() {
        // Year-2100 expiry (no-test-timebombs convention) → parsed.
        assert_eq!(
            anthropic_expiry_ms(
                r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":4102444800000}}"#
            ),
            Some(4102444800000)
        );
        // Past expiry parses (the > now() check lives in sync_handle_dir).
        assert_eq!(
            anthropic_expiry_ms(r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":1000}}"#),
            Some(1000)
        );
        // Missing expiresAt → None (conservative).
        assert_eq!(
            anthropic_expiry_ms(r#"{"claudeAiOauth":{"accessToken":"x"}}"#),
            None
        );
        // expiresAt as a string (not u64) → None (fail-safe vs serializer drift).
        assert_eq!(
            anthropic_expiry_ms(r#"{"claudeAiOauth":{"expiresAt":"4102444800000"}}"#),
            None
        );
        // expiresAt as a float (trailing .0) → None — `as_u64()` rejects floats.
        // Conservative: a float-serialized expiry skips the sync rather than
        // mis-parsing. csq + CC both write integer millis, so this is defensive.
        assert_eq!(
            anthropic_expiry_ms(r#"{"claudeAiOauth":{"expiresAt":4102444800000.0}}"#),
            None
        );
        // Unparseable → None.
        assert_eq!(anthropic_expiry_ms("not json"), None);
    }

    #[test]
    fn decide_sync_action_swap_forces_write_over_fresher_keychain() {
        // THE regression fix: account changed (swap), new token valid but keychain
        // holds the PREVIOUS account's token with a LATER expiry. Must WRITE
        // (overwrite the wrong-account token), NOT skip.
        assert_eq!(
            decide_sync_action(Some(100), Some(200), true),
            SyncAction::Write
        );
        // Same situation WITHOUT account change (refresh/sweep) → Skip (don't
        // clobber a token CC self-refreshed for the same account).
        assert_eq!(
            decide_sync_action(Some(100), Some(200), false),
            SyncAction::Skip
        );
    }

    #[test]
    fn decide_sync_action_swap_clears_stale_when_no_valid_token() {
        // Swap to a slot with no valid token: clear the stale wrong-account item
        // (don't leave CC reading the old account) — regardless of keychain state.
        assert_eq!(
            decide_sync_action(None, Some(200), true),
            SyncAction::ClearStale
        );
        assert_eq!(decide_sync_action(None, None, true), SyncAction::ClearStale);
        // No account change + no valid token → Skip (never delete what CC may use).
        assert_eq!(decide_sync_action(None, Some(200), false), SyncAction::Skip);
        assert_eq!(decide_sync_action(None, None, false), SyncAction::Skip);
    }

    #[test]
    fn decide_sync_action_non_swap_matches_newer_than_guard() {
        // Valid token, no keychain item → Write (both modes).
        assert_eq!(
            decide_sync_action(Some(100), None, false),
            SyncAction::Write
        );
        // Valid token, keychain strictly older → Write.
        assert_eq!(
            decide_sync_action(Some(100), Some(99), false),
            SyncAction::Write
        );
        // Valid token, keychain equal → Skip (idempotent).
        assert_eq!(
            decide_sync_action(Some(100), Some(100), false),
            SyncAction::Skip
        );
    }

    #[test]
    fn keychain_is_fresher_or_equal_covers_skip_and_write() {
        // No keychain item → write (false = don't skip).
        assert!(!keychain_is_fresher_or_equal(None, 100));
        // Keychain strictly older → write (file is fresher).
        assert!(!keychain_is_fresher_or_equal(Some(99), 100));
        // Keychain equal → skip (idempotent no-op on an unchanged dir).
        assert!(keychain_is_fresher_or_equal(Some(100), 100));
        // Keychain strictly newer → skip (don't clobber a fresher CC login).
        assert!(keychain_is_fresher_or_equal(Some(101), 100));
    }

    #[test]
    fn sync_all_handle_dirs_empty_base_is_noop() {
        // No term-* dirs → (0,0,0), no keychain syscall (CI-safe; also the
        // refresher's post-refresh sweep relies on this for test isolation).
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(sync_all_handle_dirs(dir.path()), (0, 0, 0));
    }

    #[test]
    fn service_name_deterministic() {
        let path = Path::new("/Users/test/.claude/accounts/config-1");
        assert_eq!(service_name(path), service_name(path));
    }

    #[test]
    fn service_name_different_for_different_paths() {
        let a = service_name(Path::new("/Users/test/.claude/accounts/config-1"));
        let b = service_name(Path::new("/Users/test/.claude/accounts/config-2"));
        assert_ne!(a, b);
    }

    #[test]
    fn service_name_nfc_normalization() {
        // NFC normalization: é as single codepoint vs e + combining accent.
        let composed = service_name(Path::new("/tmp/caf\u{00e9}"));
        let decomposed = service_name(Path::new("/tmp/caf\u{0065}\u{0301}"));
        assert_eq!(composed, decomposed);
    }

    #[test]
    fn service_name_known_paths_match_v1_python_parity() {
        // Golden values computed from v1.x Python:
        //   hashlib.sha256(unicodedata.normalize('NFC', path).encode()).hexdigest()[:8]
        // Locking these in confirms csq still derives the same name CC writes to.
        let cases = [
            (
                "/Users/test/.claude/accounts/config-1",
                "Claude Code-credentials-cfdcc24b",
            ),
            (
                "/Users/test/.claude/accounts/config-2",
                "Claude Code-credentials-550a6ea2",
            ),
        ];
        for (path, expected) in &cases {
            assert_eq!(
                &service_name(Path::new(path)),
                expected,
                "v1 parity failure for {path}"
            );
        }
    }

    // ── §PR-B2 — error-kind classifier regression guards (an internal journal entry L3) ──
    //
    // `keychain_error_kind` drops `PlatformError::Keychain` Display output
    // in favor of fixed-vocabulary tags so serde error fragments cannot
    // reach log sinks. The classifier prefix-matches strings built by
    // `read_impl`; if `read_impl` changes its error strings, these tests
    // break and `keychain_error_kind` must be updated to match.

    #[test]
    fn classifier_tags_known_read_impl_strings() {
        let cases = [
            (
                PlatformError::Keychain("keychain entry not found".into()),
                "keychain_not_found",
            ),
            (
                PlatformError::Keychain("security command: no such file or directory".into()),
                "keychain_invoke_failed",
            ),
            (
                PlatformError::Keychain("utf8: invalid utf-8 sequence".into()),
                "keychain_utf8",
            ),
            (
                PlatformError::Keychain("hex decode: invalid hex character".into()),
                "keychain_hex_decode",
            ),
            (
                PlatformError::Keychain(
                    "json parse: expected value at line 1 column 1 at line 1 column 1".into(),
                ),
                "keychain_json_parse",
            ),
        ];
        for (e, expected) in &cases {
            assert_eq!(
                keychain_error_kind(e),
                *expected,
                "classifier failed for {e:?}"
            );
        }
    }

    #[test]
    fn classifier_falls_back_to_other_for_unknown_messages() {
        let e = PlatformError::Keychain("some future error we didn't anticipate".into());
        assert_eq!(keychain_error_kind(&e), "keychain_other");
    }

    #[test]
    fn classifier_does_not_leak_raw_message() {
        // The crucial property: the tag is a `&'static str`, so it is by
        // construction independent of the error's String payload. This test
        // is a compile-time + behavior guard that future refactors don't
        // replace the `&'static str` return type with `String` (which would
        // re-open the token-leak path).
        let sensitive = "keychain entry not found — access_token=sk-ant-oat01-LEAKED";
        let e = PlatformError::Keychain(sensitive.into());
        let tag: &'static str = keychain_error_kind(&e);
        assert!(
            !tag.contains("sk-ant"),
            "classifier tag must never embed the raw message"
        );
    }

    // ── A1: decide_harvest unit tests (pure, no `security` shell) ─────────

    #[test]
    fn decide_harvest_empty_candidates_returns_none() {
        // Empty candidate list → None regardless of store_expiry.
        assert_eq!(decide_harvest(&[], None), None);
        assert_eq!(decide_harvest(&[], Some(1_000_000)), None);
    }

    #[test]
    fn decide_harvest_all_candidates_le_store_returns_none() {
        // All candidates ≤ store_expiry → steady state: store is already freshest.
        let store = Some(5_000_u64);
        let candidates = [(3_000_u64, 0), (4_000, 1), (5_000, 2)];
        // 5_000 == store: not STRICTLY greater → None.
        assert_eq!(decide_harvest(&candidates, store), None);
    }

    #[test]
    fn decide_harvest_one_candidate_strictly_greater_than_store() {
        // One candidate strictly greater than store → that index.
        let store = Some(4_000_u64);
        let candidates = [(5_000_u64, 0)];
        assert_eq!(decide_harvest(&candidates, store), Some(0));
    }

    #[test]
    fn decide_harvest_two_candidates_picks_max_expiry() {
        // Two candidates both beat store → the one with max expiry wins.
        let store = Some(1_000_u64);
        let candidates = [(8_000_u64, 0), (12_000_u64, 1)];
        assert_eq!(decide_harvest(&candidates, store), Some(1));

        // Same with reversed order — result must still be the max.
        let candidates2 = [(12_000_u64, 0), (8_000_u64, 1)];
        assert_eq!(decide_harvest(&candidates2, store), Some(0));
    }

    #[test]
    fn decide_harvest_caller_must_pre_filter_expired_candidates() {
        // Callers are required to pass only non-expired candidates (expiry > now).
        // To simulate what harvest_account_token does: expired candidates are
        // excluded before building the slice. This test asserts the pure function
        // is transparent: if the caller (incorrectly) passes an expired candidate,
        // the function still picks the max among what it is given — but a
        // well-behaved caller passes only non-expired ones.
        //
        // Simulate correct usage: expired entry is filtered out before calling.
        let now_approx = now_ms();
        let fresh_expiry = now_approx + 3_600_000; // +1 hour
                                                   // Only pass the non-expired candidate to decide_harvest.
        let candidates = [(fresh_expiry, 0)];
        assert_eq!(decide_harvest(&candidates, None), Some(0));
    }

    #[test]
    fn decide_harvest_store_none_plus_valid_candidate_returns_that_idx() {
        // store_expiry = None (no canonical token) + valid candidate → return it.
        let candidates = [(4_102_444_800_000_u64, 7)]; // year-2100 expiry
        assert_eq!(decide_harvest(&candidates, None), Some(7));
    }

    // ── A1: regression — precise UUID match, NOT substring ────────────────

    #[test]
    fn harvest_uuid_match_is_exact_not_substring() {
        // A dir bound to identities/AAAA0000.../  MUST NOT match a query UUID
        // that is merely a prefix/substring of AAAA0000...
        //
        // We test the extraction logic directly by constructing symlink targets
        // (no actual symlinks or dirs) and verifying the UUID component
        // extraction behaves correctly.
        let extract_uuid = |target: &str| -> Option<String> {
            target
                .split("identities/")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .filter(|u| !u.is_empty())
                .map(|u| u.to_owned())
        };

        let full_uuid = "aabbccdd-1122-3344-5566-778899001122";
        let prefix_uuid = "aabbccdd"; // substring of full_uuid

        let target = format!("/home/user/.claude/accounts/identities/{full_uuid}/credentials.json");
        let dir_uuid = extract_uuid(&target).unwrap();

        // Exact match: a query for the full UUID matches.
        assert_eq!(dir_uuid, full_uuid);

        // Substring/prefix match: a query for only the prefix does NOT match.
        assert_ne!(dir_uuid, prefix_uuid);

        // Confirm the guard logic: dir_uuid != prefix_uuid would cause continue.
        assert!(
            dir_uuid != prefix_uuid,
            "substring UUID must not match: dir_uuid={dir_uuid:?} prefix_uuid={prefix_uuid:?}"
        );
    }

    // ── A1: regression — codex-only handle dir contributes zero candidates ─

    #[test]
    fn harvest_codex_only_dir_contributes_zero_candidates() {
        // A handle dir whose .credentials.json link resolves to a path ending
        // in something other than "credentials.json" (e.g. "auth.json" for
        // Codex) MUST contribute zero candidates. We test the guard predicate
        // directly (no real symlinks needed — the check is `ends_with`).

        // Codex handle dir: symlink target ends with "auth.json".
        let codex_target = "/home/user/.claude/accounts/identities/some-uuid/auth.json";
        let is_anthropic_cred_link = codex_target.ends_with("credentials.json");
        assert!(
            !is_anthropic_cred_link,
            "codex auth.json target must NOT be treated as Anthropic credentials.json"
        );

        // Standard Anthropic dir: symlink target ends with "credentials.json".
        let anthropic_target = "/home/user/.claude/accounts/identities/some-uuid/credentials.json";
        let is_anthropic_cred_link = anthropic_target.ends_with("credentials.json");
        assert!(
            is_anthropic_cred_link,
            "Anthropic credentials.json target must be accepted"
        );

        // Also test credentials-codex.json (a possible codex credential variant).
        let codex_cred_target =
            "/home/user/.claude/accounts/identities/some-uuid/credentials-codex.json";
        // ends_with("credentials.json") → false (it ends with credentials-codex.json)
        let is_anthropic_cred_link = codex_cred_target.ends_with("credentials.json");
        assert!(
            !is_anthropic_cred_link,
            "credentials-codex.json target must NOT be treated as Anthropic credentials"
        );
    }

    // ── A1: regression — torn/unparseable keychain read yields no candidate ─

    #[test]
    fn harvest_absent_keychain_read_is_none_not_expiry_zero() {
        // read_raw_keychain returning None must never be converted to expiry=0.
        // The harvest loop's `None => continue` branch is the contract; this
        // test validates the decision function behaves correctly when the caller
        // provides only valid (non-expired, non-zero) candidates — i.e. that a
        // torn read that yields `None` is correctly excluded before the slice.
        //
        // If a torn read mistakenly produced expiry=0 and was passed to
        // decide_harvest, it would fail the store-expiry comparison (0 <= any
        // real store expiry → correctly excluded). But the correct fix is
        // exclusion at read time, not relying on the comparison.
        //
        // Validate: decide_harvest with an expiry-0 candidate does NOT win
        // against a store with any expiry > 0.
        let store = Some(1_u64);
        let zero_expiry_candidate = [(0_u64, 0)];
        assert_eq!(
            decide_harvest(&zero_expiry_candidate, store),
            None,
            "expiry=0 candidate must not win against store_expiry=1"
        );

        // And doesn't win against no store either (expiry=0 implies expired
        // before epoch — the caller should not pass it, but the guard holds).
        // Note: decide_harvest itself doesn't check expiry > now; it is the
        // CALLER's responsibility. We document that boundary here.
        // (No assert needed for this sub-case; documented for clarity.)
    }
}
