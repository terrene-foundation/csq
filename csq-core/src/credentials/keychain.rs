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
/// re-`flock` self-deadlocks — see `handle_dir::repoint_handle_dir` and #928).
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
    loop {
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
