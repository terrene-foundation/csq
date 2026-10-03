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
//! - **write** ([`sync_all_handle_dirs`] / [`force_sync_account_changed`] /
//!   `decide_cc_keychain_write` + `apply_cc_keychain_write`, both private): CURRENT CC reads the OAuth
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
use crate::types::AccountNum;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
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
///   csq-crate test calling this module's write path IN-PROCESS would still shell
///   `security`. The
///   `test-utils` feature is the marker that csq-core was built for testing, in OR
///   out of its own test harness. Production release builds
///   (`--features cli --no-default-features`) never enable it, so production mirrors
///   normally.
/// - `CSQ_DISABLE_KEYCHAIN_MIRROR` env var — belt-and-suspenders for hermetic
///   INTEGRATION tests that spawn the real `csq` binary; the harness sets it.
///
/// The `security` CLI writes to the per-USER login keychain (NOT redirected by a
/// sandbox `$HOME`), so any test reaching `apply_cc_keychain_write`/
/// `force_sync_account_changed` would pollute the operator's real keychain and
/// pop a macOS prompt.
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
    cfg!(test) || cfg!(feature = "test-utils") || keychain_mirror_disabled_by_env()
}

/// `true` only when the PRODUCTION env var `CSQ_DISABLE_KEYCHAIN_MIRROR` is
/// set — the ONE branch of [`keychain_mirror_disabled`] a real, already-built
/// binary can hit outside of `cfg!(test)`/`cfg!(feature = "test-utils")`
/// (both compile-time markers a shipped binary never carries). Split out
/// (M-R3-1) so a caller that reports a user-visible RESULT — e.g. Codex's
/// residue probe/purge — can distinguish "we are inside our own unit test"
/// (silent, harmless) from "keychain access is disabled on a live binary"
/// (user-visible: a real item may still exist and was never actually
/// checked).
#[cfg(target_os = "macos")]
pub(crate) fn keychain_mirror_disabled_by_env() -> bool {
    std::env::var_os("CSQ_DISABLE_KEYCHAIN_MIRROR").is_some()
}

/// Cross-platform wrapper around [`keychain_mirror_disabled`] (F7) — that fn
/// is `#[cfg(target_os = "macos")]`; `sync_handle_dir_inner` is shared by
/// both platforms and needs to ask the question regardless.
///
/// Pre-existing bug fixed here (found while verifying an unrelated K1-K6
/// fix wave, 2026-09-26): this used to hardcode `false` on non-macOS on the
/// stated grounds that "`write_raw`'s stub already always no-ops" — but that
/// stub's non-macOS variant returns `Ok(true)` (a deliberate "preserves
/// pre-existing counting behavior" choice, per its own doc), NOT a no-op
/// that reports "not synced". So `sync_handle_dir_inner`'s `SyncAction::Write`
/// arm fell all the way through to `write_raw` even inside `cargo test`,
/// and reported a mirror write that never happened as `Ok(true)` — the
/// exact "inflated counted total" this whole gate exists to prevent,
/// reproduced only on non-macOS. Post-round-7c-D2 (`sweep_sync_handle_dir`)
/// the guard is checked even earlier — before the marker is resolved at all
/// — so `sweep_sync_handle_dir_disabled_mirror_reports_not_synced` pins the
/// same underlying invariant this fix originally guarded. Honoring
/// `cfg!(test)`/`test-utils` here — mirroring the macOS branch's own
/// hermetic-test short-circuit — makes both platforms agree.
#[cfg(target_os = "macos")]
fn keychain_mirror_disabled_now() -> bool {
    keychain_mirror_disabled()
}
#[cfg(not(target_os = "macos"))]
fn keychain_mirror_disabled_now() -> bool {
    cfg!(test) || cfg!(feature = "test-utils")
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

/// A keychain read, classified into the three outcomes a destructive or
/// security-bearing caller must be able to tell apart
/// (`guard-reader-writer-parity.md` MUST-1/MUST-2): "we asked, and there is
/// genuinely nothing" is a DIFFERENT fact from "we could not complete the ask
/// at all". `read_impl` already draws this line internally — see
/// `keychain_error_kind`'s `keychain_not_found` vs `keychain_invoke_failed`
/// (and its siblings) — but [`read`]'s `Option` return type erased the
/// distinction at csq's public boundary. [`read_classified`] is that boundary,
/// restored.
///
/// Deliberately does NOT `#[derive(Debug)]` (`credential-type-hygiene.md`
/// Rule 1): the `Found` variant carries a live [`CredentialFile`]. The manual
/// impl below redacts it; see `keychain_read_debug_redacts_found_credential`.
pub enum KeychainRead {
    /// `security` completed and returned a well-formed credential.
    Found(Box<CredentialFile>),
    /// `security` completed and reported the item is genuinely absent
    /// (`errSecItemNotFound`, classified as `keychain_not_found`) — this
    /// config dir has never had a keychain item, or it was deliberately
    /// cleared ([`force_sync_account_changed`] / `csq logout`). NOT the same fact as
    /// [`KeychainRead::CouldNotAsk`].
    NotFound,
    /// The ask itself did not complete: `security` timed out or failed to
    /// spawn, the payload was not valid UTF-8 / hex / JSON once retrieved, or
    /// (non-macOS) there is no OS keychain to ask at all. The item's actual
    /// state is UNKNOWN — a caller on a destructive/refusal path MUST NOT
    /// treat this the same as [`KeychainRead::NotFound`]
    /// (`guard-reader-writer-parity.md` MUST-2). `kind` is the same
    /// fixed-vocabulary tag [`read_classified`]'s log line uses
    /// (`keychain_error_kind`'s output) — never the raw error string, which
    /// may echo credential-adjacent bytes (security.md MUST-2).
    CouldNotAsk { kind: &'static str },
}

impl fmt::Debug for KeychainRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeychainRead::Found(_) => f.debug_tuple("Found").field(&"[REDACTED]").finish(),
            KeychainRead::NotFound => write!(f, "NotFound"),
            KeychainRead::CouldNotAsk { kind } => {
                f.debug_struct("CouldNotAsk").field("kind", kind).finish()
            }
        }
    }
}

impl KeychainRead {
    /// Collapses to `Option`, discarding the `NotFound`-vs-`CouldNotAsk`
    /// distinction. This is exactly what [`read`] does — see its doc for the
    /// one production caller this collapse is currently safe for.
    pub fn found(self) -> Option<CredentialFile> {
        match self {
            KeychainRead::Found(c) => Some(*c),
            KeychainRead::NotFound | KeychainRead::CouldNotAsk { .. } => None,
        }
    }
}

/// Reads credentials from the system keychain that CC wrote for the given
/// config directory, classified per [`KeychainRead`] — the boundary [`read`]
/// collapses. Callers on a destructive or diagnostic path MUST use this
/// instead of [`read`] (`guard-reader-writer-parity.md` MUST-1/MUST-2); today
/// the only caller that needs the distinction is expected to be a FUTURE one,
/// since csq's one production caller (`credentials::post_login`) already
/// collapses both non-`Found` outcomes identically for a documented reason —
/// see that module.
///
/// On macOS: uses the `security` CLI to find the generic password, then
/// attempts to parse the value as raw JSON (CC's modern format) before
/// falling back to a hex-decode (CC's legacy format).
pub fn read_classified(config_dir: &Path) -> KeychainRead {
    let svc = service_name(config_dir);
    match read_impl(&svc, config_dir) {
        Ok(creds) => KeychainRead::Found(Box::new(creds)),
        Err(e) => {
            // an internal journal entry L3 / PR-B2 — fixed error-kind tag.
            //
            // `read_impl` returns `PlatformError::Keychain(String)` built
            // from FIXED-VOCABULARY strings only (R9-6: `"json parse
            // failed"`, `"utf8 decode failed"`, etc. — no payload-derived
            // `{e}`/`{body}` interpolation anywhere in this crate's
            // keychain-content parse paths; `security exit {code}` is the
            // ONE exception, and `code` is a numeric exit status, never
            // payload). Using `%e` here would still Display the full inner
            // String, so this emits a fixed tag keyed on the failure class
            // instead — belt-and-suspenders on top of R9-6's fix at the
            // source, not a substitute for it. Classification is
            // prefix-matched since `Keychain(String)` has no structured
            // discriminant.
            let kind = keychain_error_kind(&e);
            warn!(
                service = %svc,
                error_kind = kind,
                "keychain read failed"
            );
            classify_keychain_error_kind(kind)
        }
    }
}

/// Pure mapping from a [`keychain_error_kind`] tag to the [`KeychainRead`]
/// outcome it represents. `keychain_not_found` is the ONLY tag meaning
/// "asked, and `security` reported the item missing" — every other tag means
/// the ask itself did not resolve (timeout/spawn failure, or a payload that
/// arrived but could not be decoded), which is a DIFFERENT fact
/// (`guard-reader-writer-parity.md` MUST-1). Factored out of
/// [`read_classified`] so this decision is directly unit-testable without
/// driving a real (or `keychain_mirror_disabled`-stubbed) `security` call —
/// see `classify_keychain_error_kind_*` below.
fn classify_keychain_error_kind(kind: &'static str) -> KeychainRead {
    if kind == "keychain_not_found" {
        KeychainRead::NotFound
    } else {
        KeychainRead::CouldNotAsk { kind }
    }
}

/// Reads credentials from the system keychain that CC wrote for the given
/// config directory, collapsed to `Option`.
///
/// Returns `None` if the keychain entry doesn't exist, can't be read, or
/// contains malformed data — the caller is expected to chain a file-based
/// fallback.
///
/// **Lossy by design — safe ONLY because its one production caller,
/// `credentials::post_login::read_fresh_after_login`, does not need the
/// `NotFound`-vs-`CouldNotAsk` distinction: that caller's closure feeds a
/// bounded retry loop which ALSO reads `.credentials.json` on the SAME
/// attempt, so "no keychain candidate this round, for whichever reason" and
/// "try the file candidate instead" is the correct response either way**
/// (`doc-property-claims.md` MUST-1 — the mechanism, not an unqualified
/// claim). That caller in fact calls [`read_classified`] directly and
/// collapses explicitly, rather than going through this wrapper — see
/// `post_login.rs`. Any NEW caller, especially on a destructive or
/// diagnostic path, MUST call [`read_classified`] instead of reaching for
/// this (`guard-reader-writer-parity.md` MUST-1/MUST-2).
pub fn read(config_dir: &Path) -> Option<CredentialFile> {
    read_classified(config_dir).found()
}

/// Classifies a `PlatformError::Keychain` message into a fixed-vocabulary tag
/// for logging. Returns one of: `keychain_not_found`, `keychain_invoke_failed`,
/// `keychain_denied`, `keychain_utf8`, `keychain_hex_decode`, `keychain_json_parse`,
/// `keychain_other`.
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
    } else if msg.starts_with("security command") || msg.starts_with("security unavailable") {
        // "security command: {e}" — legacy spawn-failure string (pre-C5, kept
        // for classifier back-compat / hand-constructed test errors).
        // "security unavailable (spawn failure or timeout)" — `read_impl`'s
        // current string when `run_security_bounded` returns `None`. Both
        // mean "the `security` invocation never completed" — timeout or
        // spawn failure — which is a DIFFERENT fact from "it completed and
        // reported the item missing" (`keychain_not_found` above), so this
        // stays a distinct tag rather than folding into that one.
        "keychain_invoke_failed"
    } else if msg.starts_with("security exit") {
        // `read_impl_error_for_exit`'s string for a COMPLETED `security`
        // invocation that exited non-zero with a code OTHER than
        // `SECURITY_ITEM_NOT_FOUND` — e.g. `errSecInteractionNotAllowed`
        // (no Aqua session / keychain access denied) or `errSecAuthFailed`.
        // This is NOT "the item is absent" — it is "we asked and were
        // refused" — so it MUST NOT collapse into `keychain_not_found`
        // (`guard-reader-writer-parity.md` MUST-1/MUST-2). The message
        // carries only the numeric exit code, never stderr or the payload
        // (security.md MUST-2).
        "keychain_denied"
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

/// Maps a completed `security find-generic-password` invocation's exit code
/// into the `PlatformError::Keychain` [`read_impl`] reports. `SECURITY_ITEM_NOT_FOUND`
/// (44, `errSecItemNotFound`) is the ONLY code meaning "asked, and the item is
/// genuinely absent" — every other exit (e.g. `errSecInteractionNotAllowed` /
/// `errSecAuthFailed` when the keychain is locked or access is denied) means
/// "asked, and were refused", a DIFFERENT fact that MUST NOT classify as
/// [`KeychainRead::NotFound`] (`guard-reader-writer-parity.md` MUST-1/MUST-2).
/// The message carries only the numeric exit code — never stderr or the
/// payload — so a denial's `security` diagnostics can never reach a log sink
/// (security.md MUST-2). Factored out so this mapping is unit-testable without
/// shelling `security` (`keychain_mirror_disabled()` forces the "not found"
/// branch in every test process, so `read_impl` itself cannot exercise this).
#[cfg(target_os = "macos")]
fn read_impl_error_for_exit(code: Option<i32>) -> PlatformError {
    match code {
        Some(SECURITY_ITEM_NOT_FOUND) => {
            PlatformError::Keychain("keychain entry not found".to_string())
        }
        other => PlatformError::Keychain(format!("security exit {other:?}")),
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
fn read_impl(service: &str, config_dir: &Path) -> Result<CredentialFile, PlatformError> {
    if keychain_mirror_disabled() {
        return Err(PlatformError::Keychain(
            "keychain entry not found".to_string(),
        ));
    }
    // F4b: use the RECORDED account for this specific config dir when one
    // exists (R7-10 — `keychain_account_for`), not a fresh live
    // `keychain_account()` derivation. A read that used the live
    // derivation could target a DIFFERENT (service, account) pair than the
    // one `write_raw`/`force_sync_account_changed` actually wrote for this same
    // dir, if the live derivation and the recorded one ever diverge
    // (`RECORDED_ACCOUNT_FILE`'s own doc: different process, different
    // time, possibly a stripped env) -- the read/write halves of this
    // module must target the SAME item.
    let account = keychain_account_for(config_dir);
    // C5 (security.md §6): route through `run_security_bounded` rather than a
    // bare `.output()` — a locked/hung keychain must not block this read
    // forever (this fn feeds `read()`, which callers may render a statusline
    // from). `None` here means "could not run it at all" (spawn failure OR
    // SIGKILLed timeout, per `run_security_bounded`'s doc comment) — that is
    // NOT the same fact as "asked, and the item is absent", so it gets its
    // own error string/classifier tag rather than being folded into
    // "keychain entry not found" below (which is reserved for a completed
    // `security` invocation that reports the item missing).
    let bo = run_security_bounded(
        &["find-generic-password", "-s", service, "-a", &account, "-w"],
        None,
    )
    .ok_or_else(|| {
        PlatformError::Keychain("security unavailable (spawn failure or timeout)".to_string())
    })?;

    if !bo.output.status.success() {
        return Err(read_impl_error_for_exit(bo.output.status.code()));
    }

    // BUG-R3-1: a descendant of the awaited process can still hold the
    // stdout pipe open past `run_bounded`'s deadline, leaving `bo.output.stdout`
    // empty or truncated even though the process itself exited successfully.
    // `security` forks no descendants, so this should not occur in practice —
    // but treating an INCOMPLETE capture as a genuine (possibly empty) payload
    // would misread "we don't actually know what this item holds" as "here is
    // its content", which is exactly the class of bug this guards against.
    if !bo.stdout_complete {
        return Err(PlatformError::Keychain(
            "security output incomplete (stdout not fully captured)".to_string(),
        ));
    }

    // R9-6: fixed vocabulary only, matching the `hex decode failed` arm
    // below — `FromUtf8Error`'s `Display` is not drawn from a closed
    // vocabulary this crate controls (it reports the invalid byte's
    // position, and different std versions have varied what else it
    // includes), and the bytes it describes are the credential payload
    // itself. The `utf8` prefix is preserved so `keychain_error_kind`'s
    // `msg.starts_with("utf8")` classification is unaffected.
    let raw = String::from_utf8(bo.output.stdout)
        .map_err(|_| PlatformError::Keychain("utf8 decode failed".to_string()))?;
    let raw = raw.trim();

    // CC writes raw JSON; older csq versions wrote hex-encoded JSON.
    // Try raw JSON first, fall back to hex-decode for legacy entries.
    let json = if raw.starts_with('{') {
        raw.to_string()
    } else {
        // L-2: `FromHexError`'s `Display` can echo a character FROM THE
        // PAYLOAD (e.g. "invalid character 'x' at position N") — the
        // payload here is credential-adjacent, so no part of `e` may reach
        // an error string. Fixed vocabulary only (security.md MUST-2).
        let bytes = hex::decode(raw)
            .map_err(|_| PlatformError::Keychain("hex decode failed".to_string()))?;
        String::from_utf8(bytes)
            .map_err(|_| PlatformError::Keychain("utf8 decode failed".to_string()))?
    };

    // R9-6: `serde_json::Error`'s `Display` CAN echo a literal fragment of
    // the invalid payload (e.g. `invalid type: string "..."`, `unknown
    // field ...`) — the payload here is the credential JSON itself, so no
    // part of `e` may reach an error string (security.md MUST-2). Fixed
    // vocabulary only; the `json parse` prefix is preserved so
    // `keychain_error_kind`'s `msg.starts_with("json parse")`
    // classification is unaffected.
    serde_json::from_str(&json)
        .map_err(|_| PlatformError::Keychain("json parse failed".to_string()))
}

/// Keychain account parameter — mirrors CC's own `getUsername()`
/// (`macOsKeychainHelpers.ts`; re-derived kc-simplify-brief Step 0 against
/// the INSTALLED 2.1.282 bundle's minified source, not the 2.1.88 decompile):
/// `process.env.USER || userInfo().username`, catch → the fixed fallback
/// `"claude-code-user"`, THEN validated against `/^[a-zA-Z0-9._-]+$/` — a
/// name failing that regex is replaced with the SAME fallback (added since
/// the 2.1.88 decompile; not present in earlier revisions of this doc).
/// csq's single-item (service, account) read/write (S1/S2) targets the
/// wrong keychain item entirely if this derivation ever diverges from CC's
/// — account-name PARITY is the root-cause fix this module now depends on,
/// not a cosmetic match.
///
/// Node's `os.userInfo()` reads no env var on POSIX; it is a direct
/// `getpwuid(getuid())`-equivalent syscall, which is what the `unsafe`
/// block below performs. CC does NOT consult `$USERNAME` (that is a
/// Windows-only env var CC's macOS path never reads) — the previous
/// revision of this function did, which is corrected here.
#[cfg(target_os = "macos")]
fn keychain_account() -> String {
    const CC_FALLBACK: &str = "claude-code-user";
    let candidate = std::env::var("USER")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| unsafe {
            let uid = libc::getuid();
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                return None;
            }
            let name = std::ffi::CStr::from_ptr((*pw).pw_name);
            name.to_str().ok().map(|s| s.to_string())
        })
        .unwrap_or_else(|| CC_FALLBACK.to_string());
    if is_valid_cc_username(&candidate) {
        candidate
    } else {
        CC_FALLBACK.to_string()
    }
}

/// CC's post-2.1.88 username validation regex, `/^[a-zA-Z0-9._-]+$/`,
/// reimplemented as a char-class test (no `regex` dependency needed for one
/// fixed pattern). Platform-independent so it is unit-testable off macOS.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_valid_cc_username(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// R9-4 — bounded, NON-FOLLOWING read of a small on-disk sentinel/hint
/// file ([`RECORDED_ACCOUNT_FILE`], the keychain-account username hint —
/// v4 removed the account-change-pending marker this reader once ALSO
/// served; `RECORDED_ACCOUNT_FILE` is the only remaining caller).
/// Returns `None` for anything that is not a plain regular file reachable
/// WITHOUT following a symlink at `path`, or that cannot be decoded as
/// UTF-8 within `max_bytes` — ABSENT and MALFORMED collapse to the SAME
/// safe outcome here, matching every caller's existing "treat as absent"
/// fallback (`keychain_account_for` re-derives live; a hint reader with
/// `None` behaves exactly as an absent hint).
///
/// **Unix:** opens with `O_NOFOLLOW` (refuses a symlink AT `path` — an
/// attacker-planted symlink pointing at an arbitrary file this process can
/// read would otherwise have its content silently adopted as this dir's
/// account hint) combined with `O_NONBLOCK` (a
/// FIFO opened for reading blocks indefinitely until a writer appears
/// unless `O_NONBLOCK` is set — without it, a FIFO planted at `path` would
/// hang this call forever; `O_NONBLOCK` has no effect on a regular file's
/// open). After a successful open, `metadata()` is called on the OPEN
/// FILE DESCRIPTOR (`fstat`, not a path-based `stat` — immune to a
/// path-swap race between open and the check) and MUST report a regular
/// file; a FIFO, device, socket, or directory that somehow got this far
/// (e.g. `O_NOFOLLOW` on a non-symlink node) is rejected. The read itself
/// is capped via [`std::io::Read::take`] at `max_bytes`, so a file that IS
/// regular but adversarially large can neither exhaust memory nor (via a
/// slow filesystem) block this call for long.
///
/// Its only PRODUCTION caller ([`keychain_account_for`]) is macOS-only, so
/// on a non-macOS build this is currently reachable only from this
/// crate's own tests.
///
/// **Non-Unix (Windows):** `custom_flags`/`O_NOFOLLOW` have no Windows
/// equivalent exposed the same way; a defensive `symlink_metadata` check
/// (which itself does not follow a reparse point) gates the read, with the
/// same regular-file requirement and byte cap. TOCTOU-narrower than the
/// Unix path (a race remains between the check and the open), which is an
/// accepted, honestly-stated limitation: Windows symlinks require elevated
/// privileges/dev-mode to create in the first place, unlike Unix.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn read_bounded_sentinel(path: &Path, max_bytes: u64) -> Option<String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .ok()?;
        let meta = file.metadata().ok()?;
        if !meta.is_file() {
            return None;
        }
        let mut buf = String::new();
        file.take(max_bytes).read_to_string(&mut buf).ok()?;
        Some(buf)
    }
    #[cfg(not(unix))]
    {
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        use std::io::Read;
        let file = std::fs::File::open(path).ok()?;
        let mut buf = String::new();
        file.take(max_bytes).read_to_string(&mut buf).ok()?;
        Some(buf)
    }
}

/// R7-10 — per-handle-dir file recording the EXACT username a CLI-context
/// writer ([`csq run`]/[`csq exec`]/`csq swap`) derived via
/// [`keychain_account`] at the moment it last mirrored a token into the
/// keychain for this dir. Not secret (an OS username, not a credential) —
/// no `secure_file`/0600 requirement, unlike every credential-bearing file
/// this module touches.
///
/// **R9-3 — the hint is PARITY INSURANCE, not a source of truth in its own
/// right, and a MISSING hint in a daemon-side process means the account
/// name is UNVERIFIED.** `keychain_account`'s own derivation reads
/// `$USER`/`getpwuid` at CALL time; a later csq-internal keychain call for
/// the SAME handle dir (auto_rotate's tick, the daemon's periodic sweep, a
/// headless `subscription_client` turn) runs in a DIFFERENT process, at a
/// DIFFERENT time, under a DIFFERENT environment (the daemon's env is
/// stripped relative to an interactive shell, and its effective `$USER` can
/// differ under a re-exec) — so its own live derivation is NOT guaranteed to
/// reproduce the SAME account string the CLI writer used when the item was
/// created, even though both derivations are individually correct
/// implementations of CC's own `getUsername()`. When a CLI writer's hint
/// IS present and valid, [`keychain_account_for`] uses it and the account
/// name is CONFIRMED correct for this dir. When it is ABSENT — because no
/// CLI writer has ever recorded one for this dir, or (deliberately, R9-3)
/// because the only prior writer was daemon-side — a daemon-side caller's
/// fallback to a live [`keychain_account`] derivation is a BEST-EFFORT
/// guess, not a verified match; it is CORRECT in the common case (most
/// hosts run one OS user) and UNVERIFIED in general. Daemon-side callers
/// MUST NOT themselves write this hint (see `auto_rotate::tick`'s v4
/// forced-sync call site, which deliberately does not call this) — doing
/// so would let a daemon-context derivation, taken under a stripped
/// environment, silently REPLACE a CLI-confirmed value for every later
/// reader, converting a verified fact into a guess.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const RECORDED_ACCOUNT_FILE: &str = ".csq-keychain-account";

/// R9-4: max size for [`RECORDED_ACCOUNT_FILE`]'s bounded, non-following
/// read ([`read_bounded_sentinel`]) — a valid CC username is at most a
/// couple dozen bytes (`is_valid_cc_username`'s charset), so 256 bytes is
/// generous headroom with no plausible legitimate content anywhere near
/// the cap.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const KEYCHAIN_ACCOUNT_HINT_MAX_BYTES: u64 = 256;

/// Resolve the keychain account name for `config_dir`: prefer
/// [`RECORDED_ACCOUNT_FILE`] (R7-10) when it exists AND its content passes
/// the SAME validation [`keychain_account`] itself applies, falling back to
/// a live [`keychain_account`] derivation otherwise (file absent,
/// unreadable, or content that fails CC's own username regex — never trust
/// an invalid recorded value over a fresh derivation).
// macOS-only: its fallback branch calls `keychain_account()`, itself
// macOS-only (real keychain items exist only there); there is nothing to
// resolve an account name FOR off macOS.
#[cfg(target_os = "macos")]
pub(crate) fn keychain_account_for(config_dir: &Path) -> String {
    match read_bounded_sentinel(
        &config_dir.join(RECORDED_ACCOUNT_FILE),
        KEYCHAIN_ACCOUNT_HINT_MAX_BYTES,
    ) {
        Some(recorded) => {
            let recorded = recorded.trim();
            if is_valid_cc_username(recorded) {
                recorded.to_string()
            } else {
                keychain_account()
            }
        }
        None => keychain_account(),
    }
}

/// Non-macOS: no keychain account attribute exists to resolve — structural
/// no-op. Exists purely so callers that are NOT themselves macOS-gated
/// (`session::handle_dir::clear_dead_handle_keychain_item_inner`, capturing
/// this value to store on a [`PendingClearEntry`]) compile identically on
/// every platform; the value is never meaningfully consulted off macOS
/// (`record_pending_clear`'s own non-macOS twin is a no-op).
#[cfg(not(target_os = "macos"))]
pub(crate) fn keychain_account_for(_config_dir: &Path) -> String {
    String::new()
}

/// **Fresh-launch and CLI-swap callers** — `csq run`, `csq exec`, `csq
/// swap` (same-surface AND cross-surface routes), and the phase2b headless
/// `subscription_client` turn builder (itself a FRESH capture dir, exactly
/// like `run`/`exec` — `force_sync_for_launch_locked` calls this
/// unconditionally, and correctly, for all four) call this once, at the
/// point each mirrors its launch/swap's token into the keychain, to persist
/// the EXACT username `keychain_account` derived for THAT call (R7-10) —
/// see `RECORDED_ACCOUNT_FILE`'s doc for why a later caller cannot simply
/// re-derive it live, and for why a TRULY daemon-context caller with no
/// fresh launch of its own (`auto_rotate`'s rotation tick, the daemon's
/// periodic sweep) MUST NEVER call this function — see R9-3(c)'s note at
/// `auto_rotate::tick`'s call site.
///
/// **R9-3 — parity insurance, not an optional nicety.** Best-effort in the
/// sense that an I/O failure here is logged (fixed tag
/// `keychain_account_hint_write_failed`) and does not fail the surrounding
/// operation — but it is NOT "just an optimization" in the sense of being
/// safe to skip: every reader (`keychain_account_for`) falls back to a
/// live derivation when the hint is absent, and that fallback is a
/// BEST-EFFORT GUESS, not a verified match, for any process whose
/// environment can diverge from the CLI call that actually wrote X (see
/// `RECORDED_ACCOUNT_FILE`'s doc). Skipping this call at a CLI writer
/// site therefore does not merely lose an optimization — it leaves every
/// later daemon-side reader of this dir unverified rather than confirmed.
/// Validated against CC's own username regex before writing, so an
/// already-invalid derivation (which `keychain_account` itself would have
/// already replaced with its fallback) can never land in the file either
/// way.
#[cfg(target_os = "macos")]
pub fn record_keychain_account_hint(config_dir: &Path) {
    let account = keychain_account();
    if !is_valid_cc_username(&account) {
        return;
    }
    let target = config_dir.join(RECORDED_ACCOUNT_FILE);
    let tmp = crate::platform::fs::unique_tmp_path(&target);
    if std::fs::write(&tmp, account.as_bytes()).is_err() {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "keychain_account_hint_write_failed",
            "could not record this handle dir's keychain account; daemon-side \
             keychain paths fall back to their own username derivation"
        );
        return;
    }
    if crate::platform::fs::atomic_replace(&tmp, &target).is_err() {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!(
            error_kind = "keychain_account_hint_write_failed",
            "could not record this handle dir's keychain account; daemon-side \
             keychain paths fall back to their own username derivation"
        );
    }
}

/// KC4-2: records the keychain-account hint ONLY when none is already
/// present at `config_dir`. `csq swap`'s same-surface ClaudeCode route MUST
/// use this rather than the unconditional [`record_keychain_account_hint`] —
/// the handle dir's running CC session had its keychain username fixed at
/// ITS OWN launch (whichever earlier `csq run`/`csq exec`/swap wrote the
/// hint first), and that value does not change just because the dir's
/// BOUND ACCOUNT is now being swapped. Overwriting it on a later swap —
/// including one that then aborts before the switch completes — would
/// replace a CLI-confirmed value with a fresh derivation that may not even
/// belong to the still-running session's environment.
#[cfg(target_os = "macos")]
pub fn record_keychain_account_hint_if_absent(config_dir: &Path) {
    if config_dir.join(RECORDED_ACCOUNT_FILE).exists() {
        return;
    }
    record_keychain_account_hint(config_dir);
}

#[cfg(not(target_os = "macos"))]
pub fn record_keychain_account_hint_if_absent(_config_dir: &Path) {}

/// Non-macOS: no keychain, so nothing to record.
#[cfg(not(target_os = "macos"))]
pub fn record_keychain_account_hint(_config_dir: &Path) {}

// ── non-macOS stub ────────────────────────────────────────────────
//
// CC does not interact with the OS keychain on Linux or Windows; it
// stores credentials directly in `<CLAUDE_CONFIG_DIR>/.credentials.json`
// on those platforms. The read stub returns NotFound so the caller's
// file fallback runs unconditionally.

#[cfg(not(target_os = "macos"))]
fn read_impl(_service: &str, _config_dir: &Path) -> Result<CredentialFile, PlatformError> {
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

/// Sync `handle_dir`'s current on-disk Anthropic credential into the ONE
/// keychain item CC reads for it — the ORDINARY (same-account) path (K5).
/// Applies the newer-than-keychain freshness guard and allows same-account
/// subscription-metadata backfill (`write_raw`'s own doc). This is the
/// entire non-forced sync surface in v4 — there is no longer a separate
/// "account changed" variant of this function: a binding CHANGE is handled
/// exclusively by [`force_sync_account_changed`], called directly by the
/// site that KNOWS the binding is new (`csq swap`, `auto_rotate::tick`,
/// `csq run`/`csq exec`/phase2b's fresh-dir launch path), never inferred
/// here from a marker (`CLAUDE.md` v4 "switch now or say so").
///
/// round 7c D2: the sweep NEVER harvests — the daemon custodian's tick does
/// that (`custodian::reconcile_account`). This function routes through the
/// same single policy every other CC-keychain-item writer uses
/// ([`decide_cc_keychain_write`] + [`apply_cc_keychain_write`]) rather than
/// the pre-D2 bespoke newer-than-keychain walk, and decides the account from
/// the handle dir's MARKER (`markers::resolve_marker_to_slot`), never from
/// the `.credentials.json` symlink — the two can disagree (a dir whose
/// marker was updated but whose symlink repoint has not yet landed), and the
/// marker is the authority `account-terminal-separation.md` MUST NOT Rule 3
/// names. `handle_dir_symlinks_are_consistent` is checked first so a dir
/// mid-repoint (mixed symlink targets, a leftover `.swap-tmp`) is skipped
/// rather than acted on with a possibly-stale marker/canonical pairing.
///
/// `refreshed`: this tick's pre-refresh identity per account (round 7c D2) —
/// `sweep_pre_refresh` in the [`KnownTokens`] built here, so a keychain item
/// CC self-refreshed BEFORE this tick's refresh landed on disk is still
/// recognized as "known" (rule 2) rather than treated as an unmatched
/// foreign login (rule 3). Callers with no such context (`csq keychain-sync`,
/// `finalize_login`'s post-login mirror) pass an empty map.
#[cfg(target_os = "macos")]
fn sweep_sync_handle_dir(
    base: &Path,
    handle_dir: &Path,
    refreshed: &HashMap<AccountNum, crate::credentials::token_history::Fingerprint>,
) -> Result<bool, PlatformError> {
    if keychain_mirror_disabled_now() {
        return Ok(false);
    }
    sweep_sync_handle_dir_with_executor(&SecurityCliExecutor, base, handle_dir, refreshed)
}

/// Executor-injected core of [`sweep_sync_handle_dir`] — no
/// `keychain_mirror_disabled_now()` short-circuit here (that guard belongs
/// to the public/production entry point), mirroring
/// [`reconcile_keychain_to_marker_with_executor`]'s identical split, so a
/// test can drive the real decision against a `RecordingExecutor` instead of
/// every call being hermetically no-op'd under `cfg!(test)`.
#[cfg(target_os = "macos")]
fn sweep_sync_handle_dir_with_executor(
    exec: &impl KeychainExecutor,
    base: &Path,
    handle_dir: &Path,
    refreshed: &HashMap<AccountNum, crate::credentials::token_history::Fingerprint>,
) -> Result<bool, PlatformError> {
    if !crate::session::handle_dir::handle_dir_symlinks_are_consistent(base, handle_dir) {
        return Ok(false);
    }
    let Some(account) = crate::accounts::markers::resolve_marker_to_slot(base, handle_dir) else {
        warn!(
            error_kind = "keychain_sweep_marker_unreadable",
            "post-refresh keychain sweep: handle dir's marker could not be resolved; skipped"
        );
        return Ok(false);
    };
    // No valid token to mirror (3P/Codex slot, unreadable, or expired) —
    // leave whatever X holds; matches the pre-D2 `file_expiry: None` ->
    // `SyncAction::Skip` behaviour exactly (this sweep never strips).
    let target = crate::accounts::identity_store::target_token_for_forced_write(base, account);
    let Some(raw) = target.as_valid_str() else {
        return Ok(false);
    };
    let svc = service_name(handle_dir);
    let ours = keychain_account_for(handle_dir);
    let x = exec.find(&svc, &ours);
    // C-F1: widen recognition to the marker account's own token history —
    // this is precisely what stops the sweep refusing forever against a
    // terminal that missed one refresh (see this function's own doc + the
    // module-level directive on `token_history`).
    let history = crate::credentials::token_history::read_history_for_slot(base, account);
    let known = KnownTokens {
        marker_account_canonical: Some(raw),
        sweep_pre_refresh: refreshed.get(&account).copied(),
        marker_account_history: &history,
        ..KnownTokens::default()
    };
    match decide_cc_keychain_write(&x, &known, Intended::Token(raw)) {
        WriteDecision::NoWrite => Ok(false),
        // Rule 3: the sweep does NOT harvest — that is the custodian tick's
        // job. Skip and warn (fixed vocabulary; no path, no token bytes).
        WriteDecision::RefuseUnharvested => {
            warn!(
                error_kind = "keychain_sweep_foreign_login_unharvested",
                "post-refresh keychain sweep: item holds a login that matches no known \
                 account; skipped (harvesting happens on the custodian's own tick, not here)"
            );
            Ok(false)
        }
        // `keychain-fix-r11.md` S-M-3 residual: `raw` was already confirmed
        // Valid by `target_token_for_forced_write` before this call — this
        // backstop firing here would mean the token expired in the
        // (sub-tick) window between that read and this decision. Genuine
        // bug/race, not the ordinary "unharvested" case; skip and warn under
        // its own tag rather than conflating the two.
        WriteDecision::RefuseIntendedExpired => {
            warn!(
                error_kind = "keychain_sweep_intended_expired",
                "post-refresh keychain sweep: the token this tick intended to mirror was \
                 already expired at decision time; skipped"
            );
            Ok(false)
        }
        WriteDecision::Unknown(_) => {
            warn!(
                error_kind = "keychain_sweep_unclassified",
                "post-refresh keychain sweep: item could not be classified; skipped"
            );
            Ok(false)
        }
        decision @ WriteDecision::Write(_) => {
            match apply_cc_keychain_write(
                exec, &svc, &ours, &x, decision, /* backfill_allowed */ true,
            ) {
                ApplyOutcome::Applied { .. } => Ok(true),
                ApplyOutcome::AbsentWriteFailed | ApplyOutcome::WriteFailed => Err(
                    PlatformError::Keychain("post-refresh keychain sweep write failed".to_string()),
                ),
                ApplyOutcome::NoOp => {
                    unreachable!("apply_cc_keychain_write never no-ops a Write decision")
                }
            }
        }
        WriteDecision::StripAllowed => {
            unreachable!("the sweep always passes Intended::Token, never Intended::Strip")
        }
    }
}

/// Non-macOS: no OS keychain item exists to sync — matches the pre-D2 stub
/// shape (the write side of this module is a no-op there entirely).
#[cfg(not(target_os = "macos"))]
fn sweep_sync_handle_dir(
    _base: &Path,
    _handle_dir: &Path,
    _refreshed: &HashMap<AccountNum, crate::credentials::token_history::Fingerprint>,
) -> Result<bool, PlatformError> {
    Ok(false)
}

/// Sync every `term-*` handle dir under `base_dir` (the accounts dir) — the
/// shared sweep used by `csq keychain-sync`, `finalize_login`'s post-login
/// mirror, and the daemon refresher's post-refresh pass. Returns `(synced,
/// skipped, failed)`.
///
/// `refreshed` (round 7c D2): this tick's pre-refresh identity per account —
/// see `sweep_sync_handle_dir`'s doc. Callers with no refresh-tick context
/// pass `&HashMap::new()`.
///
/// Each dir is handled independently by `sweep_sync_handle_dir`, which
/// decides the account from the handle dir's OWN marker (not by attribution
/// from the caller), so the sweep needs no external account list. The single
/// policy's rule 2 (matches a known account) makes this idempotent — a dir
/// whose keychain item already agrees with its marker account's canonical
/// token is a no-op.
pub fn sync_all_handle_dirs(
    base_dir: &Path,
    refreshed: &HashMap<AccountNum, crate::credentials::token_history::Fingerprint>,
) -> (usize, usize, usize) {
    sync_all_handle_dirs_with(base_dir, &|d| sweep_sync_handle_dir(base_dir, d, refreshed))
}

/// [`sync_all_handle_dirs`] with the per-dir sync injected, so a test can
/// observe which dir each visited call is synced with (round-10 mutation M8:
/// the loop body was otherwise unreachable from tests).
fn sync_all_handle_dirs_with(
    base_dir: &Path,
    sync: &dyn Fn(&Path) -> Result<bool, PlatformError>,
) -> (usize, usize, usize) {
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
        // S3/bounded-lock (kc-simplify-brief): hold the per-handle-dir swap
        // lock across this dir's whole read (X's classification) -> write
        // (X updated in place), same as `csq run`/`csq exec`/`csq
        // swap`/auto_rotate — so this periodic sweep cannot interleave its
        // RMW with a concurrent `csq swap` or auto-rotation repointing
        // this SAME dir.
        //
        // BOUNDED (round 2): a sweep iterates EVERY live handle dir in one
        // call — blocking indefinitely on ONE stuck lock would starve
        // every OTHER dir behind it. Same ~20.25s ceiling as the
        // interactive callers; on timeout this dir's mirror is SKIPPED
        // (counted, never silently dropped) with a fixed-tag warn and the
        // sweep moves on to the next dir.
        match lock_handle_dir_for_swap_bounded(&abs) {
            BoundedLockOutcome::Acquired(_keychain_guard) => match sync(&abs) {
                Ok(true) => synced += 1,
                Ok(false) => skipped += 1,
                Err(_) => failed += 1,
            },
            // R7-4: non-macOS never reaches here in practice (this fn's
            // production caller is macOS-gated), but proceeds exactly as
            // pre-v3 with no warn if it ever does.
            BoundedLockOutcome::NotNeeded => match sync(&abs) {
                Ok(true) => synced += 1,
                Ok(false) => skipped += 1,
                Err(_) => failed += 1,
            },
            BoundedLockOutcome::TimedOut => {
                skipped += 1;
                warn!(
                    error_kind = "keychain_sync_lock_timed_out",
                    "sync_all_handle_dirs: could not acquire the per-handle-dir keychain \
                     lock within the bound for one dir; skipped this tick (non-fatal — \
                     retried on the next sweep)"
                );
            }
            BoundedLockOutcome::Failed => {
                skipped += 1;
                warn!(
                    error_kind = "keychain_sync_lock_failed",
                    "sync_all_handle_dirs: the per-handle-dir keychain lock file itself \
                     could not be opened/locked for one dir (not ordinary contention); \
                     skipped this tick"
                );
            }
        }
    }
    (synced, skipped, failed)
}

/// Extract `claudeAiOauth.expiresAt` (Unix millis) from an Anthropic credential
/// JSON string. `None` on any parse failure, missing field, or non-integer
/// value — the conservative answer every caller treats as "not safe to mirror".
///
/// `pub(crate)`: also the validity check
/// [`crate::accounts::identity_store::target_token_for_forced_write`] uses to
/// classify its `TargetToken` (H1) — one parser, shared, so the two modules
/// cannot silently disagree on what counts as a live Anthropic token
/// (`guard-reader-writer-parity.md` MUST-1).
pub(crate) fn anthropic_expiry_ms(raw: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()?
        .get("claudeAiOauth")?
        .get("expiresAt")?
        .as_u64()
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// round 7c D2: `classify_expiry_output` / `keychain_expiry_ms` (the
// pre-round-7c-D2 newer-than-keychain guard's `security find-generic-password
// -w` classifier) were removed here — their sole caller,
// `sync_handle_dir_inner`'s `decide_sync_action`, was replaced by
// `sweep_sync_handle_dir`, which classifies X via [`RawContentClassification`]
// (already read once via [`KeychainExecutor::find`]) rather than a second,
// bespoke `security` shell-out.
//
// `keychain-fix-r8.md` (KA): `KeychainExpiryRead` / `expiry_read_from_content`
// / `keychain_is_fresher_or_equal_or_unknown` were themselves removed with
// `write_raw`/`write_raw_with_executor` below — that R7-6 newer-than guard was
// the type's only remaining caller, and every CC-keychain-item writer now
// routes through `decide_cc_keychain_write`/`apply_cc_keychain_write`, whose
// own rule 2 (known-token match) + F5 (`NoWrite` on an already-current X)
// supersede the freshness re-check this type existed for.

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
    /// The `term-<pid>` handle-dir basename this candidate's `.claude.json` can
    /// still be read from, or `None` when no such dir survives (`keychain-fix-
    /// r9.md` S-L-3). Distinct from `source_tag`: for the pending-clear retry
    /// path (`decide_and_clear_queued_service_with_executor`) `source_tag` is a
    /// keychain SERVICE name, not a handle-dir basename — `base_dir.join(source_tag)`
    /// would build a path that never exists. This field is `Some(basename)` only
    /// when the tag is genuinely a handle-dir name (the harvest sweep and the
    /// dead-handle reaper, both of which read from a config dir that still
    /// exists at capture time); the retry-queue path sets it `None` because the
    /// config dir is already gone by retry time. Consumers MUST use this field
    /// — never `source_tag` — to decide whether `base_dir.join(..)` is safe.
    pub handle_dir_tag: Option<String>,
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

/// Bound sized against what a lock HOLDER can legitimately take, not just
/// against ONE RMW (R7-8 — `tooling-self-verification.md` Rule 3: a
/// bound's constant is re-derived from the two outcomes it separates, not
/// adopted because a test passed with it). `csq swap`'s `_swap_guard` and
/// `auto_rotate::tick`'s lock (acquired via `lock_handle_dir_for_swap_bounded`
/// directly since v4) each hold this SAME lock across the FULL guarded span
/// of a swap transition: [`force_sync_account_changed`] (ONE RMW — a single
/// `find` + a single `add`/`delete`, EACH call bounded at
/// [`KEYCHAIN_OP_TIMEOUT`] + [`MIN_POST_EXIT_GRACE`] = 5.25s per call. The
/// write is now delete-then-create, so the RMW's `security` calls are the
/// outer `find`, 1 to [`MAX_DUPLICATE_DELETE_ITERATIONS`] (5) deletes, the
/// add, and at most one siblings-only re-add after a failed add: 4 to 8
/// calls, so **8 * 5.25s = 42s** non-interactive worst case) → `repoint_handle_dir` (fast fs symlink
/// work) → `begin_swap_audit`/`finish_swap_audit` (the audit-chain
/// INTENT/RESULT record writes). v4 ("switch now or say so") removed the
/// SEPARATE post-repoint sync this doc previously enumerated here — the
/// keychain write happens exactly ONCE, before the repoint, not once before
/// and once after — so the guarded span's `security`-call budget is this
/// single RMW (4 to 8 calls, above), not a clear plus a second full sync.
///
/// **Interactive swaps (K2): inside [`with_interactive_keychain`] (and only
/// there; a bare TTY keeps 5s) each `security` call is bounded by
/// [`KEYCHAIN_INTERACTIVE_OP_TIMEOUT`] (60s) instead, so the holder bound for
/// the RMW's calls is up to `8 * (60s + MIN_POST_EXIT_GRACE)` = 482s (the 4 to
/// 8 calls above), not 42s. Waiters already treat `TimedOut` as "skip the
/// mirror".**
///
/// **TRUE holder worst case (non-interactive): `42s` (the one RMW) + UNBOUNDED (repoint +
/// audit-chain fs work — neither is `security`-shelling, so neither is
/// bounded by [`KEYCHAIN_OP_TIMEOUT`]; a stalled filesystem is not modeled
/// here) — at minimum **42s** in the `security`-call budget alone, before
/// whatever the repoint+audit step actually costs on a given host.**
///
/// **This bound (20.25s, derived below) does NOT cover that span, and is
/// not raised to try — doc-property-claims.md MUST-2: a bound derived from
/// an enforced limit, stated as what it actually is, never inflated to
/// "always suffices" against an unbounded holder.** Raising
/// [`HANDLE_LOCK_BOUND_ATTEMPTS`] to chase a holder whose own span includes
/// genuinely unbounded filesystem work (repoint, audit-chain writes) cannot
/// close this gap — any finite waiter bound can still be exceeded by an
/// arbitrarily slow repoint/audit step, so the honest fix is not "wait
/// longer", it is what happens on timeout (below). **What actually
/// happens when the waiter's bound is exceeded — by a legitimately slow
/// (not wedged) holder, not a hypothetical one:** the waiter's
/// [`lock_handle_dir_for_swap_bounded`] call returns
/// [`BoundedLockOutcome::TimedOut`] WHILE THE HOLDER MAY STILL BE HOLDING
/// THE LOCK — the waiter gives up on ITS OWN bound, it does not learn that
/// the holder released anything. EVERY caller (`csq run`, `csq exec`, `csq
/// swap`'s cross-surface exec path, the daemon's periodic
/// [`sync_all_handle_dirs`] sweep, `phase2b`'s headless turn) then skips
/// the keychain mirror for that dir with a fixed-tag
/// `keychain_sync_lock_timed_out` warn and proceeds via the symlinked
/// `.credentials.json` file fallback — NEVER proceeding unlocked against
/// the keychain item itself. For the periodic sweep specifically, this is
/// not a permanent skip: the NEXT sweep tick simply retries the lock from
/// scratch, and F3's failure-fallback marker ensures an account-changed
/// dir that was skipped here is not silently forgotten in the meantime.
///
/// **The attempts/delay product MUST equal the number this doc states.**
/// `try_lock_file_bounded`'s loop performs `attempts` flock TRIES but only
/// `attempts - 1` SLEEPS between them (the last try is never followed by a
/// sleep) — so the true wall-clock bound is `(attempts - 1) * delay`, NOT
/// `attempts * delay`. A prior revision stated `41 * 250ms = 10.25s` while
/// the code actually waited `(41-1) * 250ms = 10.0s` — a real, measured
/// discrepancy between the claimed and true bound (R7-8). Current values:
/// `(82 - 1) * 250ms = 81 * 250ms = 20.25s`, the figure used above.
/// `try_lock_file_bounded` obtains the OS lock handle ONCE and only
/// retries the acquisition attempt, so 82 attempts costs one `open(2)`
/// plus 82 cheap `flock` tries, not 82 opens.
#[cfg(target_os = "macos")]
const HANDLE_LOCK_BOUND_ATTEMPTS: u32 = 82;
#[cfg(target_os = "macos")]
const HANDLE_LOCK_BOUND_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Outcome of [`lock_handle_dir_for_swap_bounded`] (R7-4). Collapsing this
/// into a single `Option<FileLockGuard>` made a genuine `flock`/`open`
/// failure (disk I/O error, permission denial on the lock file)
/// indistinguishable from a lock that was merely HELD by a concurrent
/// holder for the whole bound — the former is unexpected and worth its own
/// log tag (`keychain_sync_lock_failed`); the latter is the routine,
/// expected outcome of contention and keeps its existing tag
/// (`keychain_sync_lock_timed_out`). `NotNeeded` separates a THIRD case
/// that a bare `Option` also collapsed into the timeout tag: on non-macOS
/// there is no keychain to lock at all, so every caller previously logged
/// a spurious "lock timed out" on every single run.
#[derive(Debug)]
pub enum BoundedLockOutcome {
    /// The lock was acquired within the bound; holds the RAII guard.
    Acquired(crate::platform::lock::FileLockGuard),
    /// Non-macOS: no keychain mirror exists on this platform, so there is
    /// nothing to lock. NOT a failure — the caller proceeds exactly as it
    /// did before this lock existed (no warn; counted synced/skipped
    /// exactly as its own downstream call reports).
    NotNeeded,
    /// Every attempt within the bound found the lock held by another
    /// holder (a concurrent `csq swap`/`auto_rotate`/another launch on
    /// this SAME handle dir). Expected under contention.
    TimedOut,
    /// The underlying `open`/`flock` syscall itself errored (permission
    /// denied, disk I/O error, etc.) — distinct from `TimedOut` because it
    /// is NOT ordinary contention and merits its own log tag, so an
    /// operator can tell "someone else is using it" (self-healing on the
    /// next sweep) from "the lock file itself is broken" (will not
    /// self-heal).
    Failed,
}

/// Parameterized core of [`lock_handle_dir_for_swap_bounded`] — split out
/// (R7-4) so the `Ok(Some)`/`Ok(None)`/`Err` -> `BoundedLockOutcome` mapping
/// is unit-testable with a SMALL attempts/delay pair, instead of only
/// through the production 20.25s bound (`HANDLE_LOCK_BOUND_ATTEMPTS` *
/// `HANDLE_LOCK_BOUND_DELAY`), which would make a mapping test cost 20+
/// real seconds per run. Behavior-preserving: the production fn below
/// calls this with the SAME constants it always used.
#[cfg(target_os = "macos")]
fn lock_bounded_with_params(
    config_dir: &Path,
    attempts: u32,
    delay: std::time::Duration,
) -> BoundedLockOutcome {
    match crate::platform::lock::try_lock_file_bounded(&swap_lock_path(config_dir), attempts, delay)
    {
        Ok(Some(guard)) => BoundedLockOutcome::Acquired(guard),
        Ok(None) => BoundedLockOutcome::TimedOut,
        Err(_) => BoundedLockOutcome::Failed,
    }
}

/// Bounded variant of [`lock_handle_dir_for_swap`] for callers that MUST
/// NOT block indefinitely on a contended lock: `csq run`/`csq exec`
/// (interactive launch latency) and the periodic
/// [`sync_all_handle_dirs`] sweep (must not starve every OTHER dir behind
/// one stuck lock). See [`BoundedLockOutcome`] (R7-4) for what each
/// non-`Acquired` outcome means and how a caller MUST respond to it — per
/// S3/bounded-lock discipline, `TimedOut`/`Failed` MUST skip the mirror
/// sync for that dir with a fixed-tag warn rather than proceed unlocked;
/// never silently drop the lock requirement to keep going.
#[cfg(target_os = "macos")]
pub fn lock_handle_dir_for_swap_bounded(config_dir: &Path) -> BoundedLockOutcome {
    lock_bounded_with_params(
        config_dir,
        HANDLE_LOCK_BOUND_ATTEMPTS,
        HANDLE_LOCK_BOUND_DELAY,
    )
}

/// Non-macOS: no keychain, so no swap race; lock is a no-op (`NotNeeded`,
/// never `TimedOut` — R7-4: a bare `Option` here made every non-macOS
/// caller log a spurious "lock timed out" on every single invocation).
#[cfg(not(target_os = "macos"))]
pub fn lock_handle_dir_for_swap_bounded(_config_dir: &Path) -> BoundedLockOutcome {
    BoundedLockOutcome::NotNeeded
}

/// Marker error for [`clear_handle_dir_reporting`]: the `security`
/// subprocess could not be confirmed to run (timed out against a locked /
/// unreachable keychain, or failed to spawn). Carries no data — callers
/// only need to know the clear could not be confirmed, never the item's
/// fate, which is genuinely unknown in this case; see the function's doc
/// for the required caller behavior (surface it, never treat as success).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeychainClearUnconfirmed;

/// Clear the keychain item for `config_dir` and report whether the attempt
/// could be CONFIRMED to run — distinct from [`force_sync_account_changed`],
/// whose existing callers (`csq swap`, `auto_rotate`) already surface an
/// unreadable/unconfirmed X as a hard `Err` (v4 "switch now or say so"; the
/// switch does not proceed on it). `csq logout` is a TERMINAL step —
/// nothing downstream retries this clear — so its caller needs a real
/// signal here too (`zero-tolerance.md` Rule 3: no silent fallback on a
/// credential path).
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
// Platform-independent constant — unconditional so classify_raw_content
// (now unconditional) can pattern-match it by name off macOS too; a
// cfg-gated const here would otherwise silently shadow-bind as a new
// variable in that match arm rather than fail to compile.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const SECURITY_ITEM_NOT_FOUND: i32 = 44;

/// `security`'s exit code for `errSecInteractionNotAllowed` — a read that
/// COMPLETED and was REFUSED because the keychain is locked and no UI is
/// available to prompt for it (headless/SSH/launchd Background session).
/// F4 (owner decision, "switch now or say so", 2026-09-26): the ONLY exit
/// code [`classify_raw_content`] treats as [`UnreadableKind::Inaccessible`]
/// — measured live on `esperie-mac-mini`, in a Background (SSH-like)
/// launchd session, against a throwaway keychain: an unlocked read exits
/// `0`; a LOCKED read of a present item exits `36`; a locked read of an
/// ABSENT item exits `44` (still `SECURITY_ITEM_NOT_FOUND`/`Absent`, not
/// this). Every other completed exit — including a signal-terminated
/// child, whose `ExitStatus::code()` is `None` on Unix — is `Transient`:
/// nothing besides this exit code was actually shown to mean "CC would
/// also fail to read the same item".
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) const SECURITY_ERR_INTERACTION_NOT_ALLOWED: i32 = 36;

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
    // Only `output.status` matters here (BUG-R3-1's completeness flags govern
    // parsed-content callers; a delete confirmation never parses stdout).
    let start = std::time::Instant::now();
    let first =
        run_security_bounded(&["delete-generic-password", "-s", svc], None).map(|bo| bo.output);
    if let Some(out) = &first {
        if security_delete_call_resolved(out) {
            return first;
        }
    }
    if start.elapsed() < KEYCHAIN_OP_TIMEOUT / 2 {
        run_security_bounded(&["delete-generic-password", "-s", svc], None).map(|bo| bo.output)
    } else {
        first // a genuine timeout — do not retry, return the (unconfirmed) result as-is
    }
}

/// Bound on repeated single-item deletes when draining possible DUPLICATE
/// items under one service name (security review 1386 N1 — confirmed live
/// by team-lead's probe, on the PRE-v3 design: two items added under the
/// same service, one `delete-generic-password` call exits 0 while a
/// sibling survives; a second call then drains it). `security
/// delete-generic-password` removes exactly ONE matching item per call.
///
/// **doc-property-claims.md MUST-4 (this rationale is now logout-path
/// only, not a description of `write_raw`).** A prior revision of this doc
/// said `write_raw` "already loops for exactly this reason" and that
/// `delete_keychain_item`'s single-shot delete relied on "the next
/// account-changed write's delete-loop" to clear stragglers — both
/// describe the PRE-v3 delete-all-then-create-one design. The v3 write
/// path (since retired; its executor-level successor is
/// `KeychainExecutor::add`) was update-in-place with `-U`; that is itself
/// superseded: `add` now deletes (looping to exit 44, bounded by this same
/// constant) and then creates, so a write DOES issue deletes. [`drain_service`] (and this constant) now
/// exist solely for the CLEAR/logout-adjacent paths —
/// [`clear_service_reporting`], reached from the pending-clears queue
/// populated at `csq logout` time (`accounts::logout`) and by the
/// dead-handle reaper (`session::handle_dir`) — where a duplicate, if one
/// is resident, must be fully drained because nothing writes again
/// afterward to naturally clobber a straggler.
///
/// **Why a duplicate could be resident at all, under v3: NOT created by
/// the write path: `KeychainExecutor::add` deletes (to exit 44) then
/// creates, and two concurrent writers are serialized by the swap lock, so
/// it is not expected to leave one. A resident duplicate is a LEFTOVER from
/// an older csq, or from out-of-band keychain manipulation (an operator, or
/// a future regression) — "not expected" is not "cannot happen", which is exactly
/// why this drain loop still runs on every clear rather than assuming a
/// single delete always suffices.**
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
// Platform-independent constant — unconditional so plan_mirror_write (now
// unconditional) can reference it off macOS too.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

/// Decide-then-clear for the dead-handle-dir reaper
/// (`session::handle_dir::sweep_dead_handles`) and the pending-clear retry
/// queue below (`keychain-fix-r8.md` C-F3) — DISTINCT from
/// [`clear_handle_dir_reporting`] (used by `csq logout`, which intentionally
/// deletes CC's keychain item unconditionally: logout means "this account's
/// credentials are gone everywhere", so there is no known-account gate to
/// apply — `csq logout` stays as-is per that brief). Neither the reaper nor
/// the retry queue is an intentional account removal — they clean up an
/// ABANDONED SESSION — so they must not destroy the only live copy of a
/// login nobody else recorded.
///
/// Routes through the SAME single policy every other CC-keychain-item
/// writer uses (`decide_cc_keychain_write` + `apply_cc_keychain_write`),
/// with `Intended::Strip` and `known` built from `config_dir`'s marker
/// account (its own canonical token + bounded token history):
///
/// - X holds no login, or holds a token matching the marker account's own
///   canonical file or its token history -> safe to delete (`Ok(true)`).
/// - X holds an unmatched but otherwise VALID Anthropic token -> `try_adopt`
///   is given one chance to adopt it for the marker account before it is
///   lost forever (see that parameter's own doc). Adopted -> X now matches
///   itself by construction; delete. Not adopted -> kept, `Err`
///   (unconfirmed — the SAME variant the caller already treats as
///   "re-queue and warn", [`KeychainClearUnconfirmed`]).
/// - X itself could not be classified (unreadable, or a `claudeAiOauth` key
///   present but unparseable) -> kept, `Err`.
#[cfg(target_os = "macos")]
pub(crate) fn decide_and_clear_dead_handle(
    base_dir: &Path,
    config_dir: &Path,
    try_adopt: &dyn Fn(AccountNum, &HarvestCandidate) -> bool,
) -> Result<bool, KeychainClearUnconfirmed> {
    if keychain_mirror_disabled() {
        return Ok(false);
    }
    decide_and_clear_dead_handle_with_executor(
        &SecurityCliExecutor,
        base_dir,
        config_dir,
        try_adopt,
    )
}

/// Executor-injected core of [`decide_and_clear_dead_handle`] — no
/// `keychain_mirror_disabled()` short-circuit here (that guard belongs to
/// the public entry point), so a test can drive this directly against a
/// [`RecordingExecutor`].
#[cfg(target_os = "macos")]
fn decide_and_clear_dead_handle_with_executor(
    exec: &(impl KeychainExecutor + ?Sized),
    base_dir: &Path,
    config_dir: &Path,
    try_adopt: &dyn Fn(AccountNum, &HarvestCandidate) -> bool,
) -> Result<bool, KeychainClearUnconfirmed> {
    let svc = service_name(config_dir);
    let ours = keychain_account_for(config_dir);
    let x = exec.find(&svc, &ours);

    let marker_account = crate::accounts::markers::resolve_marker_to_slot(base_dir, config_dir);
    let marker_raw: Option<String> = marker_account.and_then(|acct| {
        crate::accounts::identity_store::target_token_for_forced_write(base_dir, acct)
            .as_valid_str()
            .map(str::to_string)
    });
    let history = marker_account
        .map(|acct| crate::credentials::token_history::read_history_for_slot(base_dir, acct))
        .unwrap_or_default();
    let known = KnownTokens {
        marker_account_canonical: marker_raw.as_deref(),
        marker_account_history: &history,
        ..KnownTokens::default()
    };

    match decide_cc_keychain_write(&x, &known, Intended::Strip) {
        WriteDecision::StripAllowed => apply_dead_handle_strip(exec, &svc, &ours, &x),
        WriteDecision::RefuseUnharvested => {
            if let (Some(acct), RawContentClassification::Content(raw)) = (marker_account, &x) {
                if let Some(expiry_ms) = anthropic_expiry_ms(raw) {
                    let dir_tag = config_dir
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let candidate = HarvestCandidate {
                        raw_json: raw.clone(),
                        expiry_ms,
                        source_tag: dir_tag.clone(),
                        candidate_email: crate::credentials::claude_json::read_oauth_email(
                            config_dir,
                        ),
                        // `config_dir` still exists at this point (removed only
                        // after this call returns — see this fn's own doc), so
                        // `dir_tag` is a genuine handle-dir basename.
                        handle_dir_tag: Some(dir_tag),
                    };
                    if try_adopt(acct, &candidate) {
                        // X's own content IS the token just adopted — re-decide
                        // directly against it, bypassing the (now-stale) store
                        // snapshot captured in `known` above.
                        let self_known = KnownTokens {
                            csq_written: Some(raw.as_str()),
                            ..KnownTokens::default()
                        };
                        if let WriteDecision::StripAllowed =
                            decide_cc_keychain_write(&x, &self_known, Intended::Strip)
                        {
                            return apply_dead_handle_strip(exec, &svc, &ours, &x);
                        }
                    }
                }
            }
            warn!(
                error_kind = "dead_handle_keychain_unmatched_kept",
                "dead-handle keychain clear: item holds a login unmatched to the marker \
                 account and could not be confirmed; kept, not deleted, queued for \
                 automatic decide+adopt retry (never a blind delete — keychain-fix-r9.md \
                 S-M-2)"
            );
            // `keychain-fix-r9.md` S-M-2/D-F4: `Err(KeychainClearUnconfirmed)`, NOT
            // `Ok(false)` — this WAS a deliberate keep-and-never-queue (see the
            // retracted rationale this replaces, in git history), back when the
            // retry queue's ONLY disposition was `clear_service_reporting`'s
            // unconditional blind delete: queuing an unconfirmed candidate there
            // would have destroyed it on the very next tick, one layer later than
            // this very refusal. `PendingClearOrigin` closes that gap — the
            // caller (`session::handle_dir::clear_dead_handle_keychain_item`)
            // queues this `Err` as a `DeadHandle`-origin entry, which retries with
            // the SAME decide+adopt policy this call just ran, never a blind
            // delete. The dir is removed immediately after this call returns
            // (this function's own top-level doc), so `Err` here is the ONLY way
            // this candidate is not permanently lost the instant that happens.
            Err(KeychainClearUnconfirmed)
        }
        WriteDecision::Unknown(_) => Err(KeychainClearUnconfirmed),
        WriteDecision::RefuseIntendedExpired => {
            unreachable!("Intended::Strip never produces RefuseIntendedExpired (Token-arm only)")
        }
        WriteDecision::Write(_) | WriteDecision::NoWrite => {
            unreachable!("Intended::Strip never decides Write/NoWrite")
        }
    }
}

/// Apply a confirmed [`WriteDecision::StripAllowed`] and map
/// [`ApplyOutcome`] onto this module's `Result<bool, KeychainClearUnconfirmed>`
/// shape — shared by [`decide_and_clear_dead_handle_with_executor`]'s two
/// call sites (the direct rule-2 match and the post-adopt re-decide).
///
/// **`keychain-fix-r9.md` D-F5.** The pre-decide legacy path
/// ([`drain_service`]/[`drain_service_inner`]) drained EVERY duplicate item
/// resident under a service (security review 1386 N1: `security
/// delete-generic-password` removes exactly ONE matching item per call, so
/// a single-shot delete against a service with a resident duplicate reports
/// success while a sibling survives). The decide-gated strip path here used
/// to call [`apply_cc_keychain_write`] exactly once — a single delete —
/// which reintroduced the N1 gap for this path alone. This wrapper now
/// drains any lingering duplicate the SAME way, bounded and scoped to CC's
/// own `svc`/`account` (never a bare by-service-only match like the legacy
/// path), but ONLY when the first strip fully DELETED X (no sibling object
/// to preserve) — see [`drain_duplicate_cc_items`]'s own doc for why a
/// sibling-preserving strip must never be drained.
#[cfg(target_os = "macos")]
fn apply_dead_handle_strip(
    exec: &(impl KeychainExecutor + ?Sized),
    svc: &str,
    ours: &str,
    x: &RawContentClassification,
) -> Result<bool, KeychainClearUnconfirmed> {
    // Computed from `x` (the SAME content `decide_cc_keychain_write` already
    // authorized stripping) — not from `ApplyOutcome`, which cannot
    // distinguish "deleted outright" from "wrote a sibling remainder back":
    // both resolve to `Applied { wrote_token: false }`.
    let deletes_outright = match x {
        RawContentClassification::Content(json) => extract_sibling_object(json).is_empty(),
        RawContentClassification::Absent | RawContentClassification::Unreadable(_) => true,
    };
    match apply_cc_keychain_write(exec, svc, ours, x, WriteDecision::StripAllowed, false) {
        ApplyOutcome::Applied { .. } => {
            if deletes_outright {
                drain_duplicate_cc_items(exec, svc, ours)?;
            }
            Ok(true)
        }
        // X was already confirmed Absent — nothing was at risk of being lost.
        ApplyOutcome::AbsentWriteFailed => Ok(false),
        ApplyOutcome::WriteFailed => Err(KeychainClearUnconfirmed),
        ApplyOutcome::NoOp => {
            unreachable!("apply_cc_keychain_write never no-ops a StripAllowed decision")
        }
    }
}

/// `keychain-fix-r9.md` D-F5. Bounded drain for a duplicate item lingering
/// under the SAME `svc`+`account` [`apply_dead_handle_strip`] just
/// confirmed-deleted. `security delete-generic-password` removes exactly
/// ONE matching item per call (security review 1386 N1); two never-
/// consolidated items under one service both survive a single call.
///
/// Called ONLY when the first strip fully DELETED X — never on a
/// sibling-preserving strip, which just wrote a REMAINDER back to this
/// exact `svc`+`account` and must not be re-found-and-deleted here.
///
/// Bounded at [`MAX_DUPLICATE_DELETE_ITERATIONS`], mirroring
/// [`drain_service_inner`]'s shape — but built from this module's injected
/// [`KeychainExecutor`] rather than raw `security` exit codes: this
/// trait's `delete` confirms BOTH "just deleted one" and "already absent"
/// as `true` ([`security_delete_call_resolved`] resolves both `0` and
/// [`SECURITY_ITEM_NOT_FOUND`] to `true`), so the delete call's own return
/// value cannot distinguish "a sibling remains" from "confirmed drained" —
/// `find` is what does, exactly as `drain_service_inner`'s exit-code
/// inspection did for the legacy path. Every iteration re-`find`s and
/// re-deletes the SAME `svc`+`account` this call was scoped to (never a
/// bare by-service-only match), stopping at the first confirmed `Absent`
/// (mirrors the old path's "stop on 44"). An unconfirmed result — a
/// failed delete, or a re-`find` that itself cannot classify X — stops the
/// loop with `Err` rather than guessing further; the FIRST item is already
/// confirmed gone by the time this runs, so `Err` here only means the
/// caller cannot be told the drain is FULLY clean, not that the original
/// clear failed.
#[cfg(target_os = "macos")]
fn drain_duplicate_cc_items(
    exec: &(impl KeychainExecutor + ?Sized),
    svc: &str,
    account: &str,
) -> Result<(), KeychainClearUnconfirmed> {
    for _ in 0..MAX_DUPLICATE_DELETE_ITERATIONS {
        match exec.find(svc, account) {
            RawContentClassification::Absent => return Ok(()),
            RawContentClassification::Unreadable(_) => return Err(KeychainClearUnconfirmed),
            RawContentClassification::Content(_) => {
                if !exec.delete(svc, account) {
                    return Err(KeychainClearUnconfirmed);
                }
                // A duplicate may have just been removed — re-check.
            }
        }
    }
    // Iteration budget exhausted without a confirmed `Absent` — fail toward
    // "might still have a duplicate", never toward success.
    Err(KeychainClearUnconfirmed)
}

/// Non-macOS: no keychain item exists to mutate — structural no-op,
/// mirroring [`clear_handle_dir_reporting`]'s stub.
#[cfg(not(target_os = "macos"))]
pub(crate) fn decide_and_clear_dead_handle(
    _base_dir: &Path,
    _config_dir: &Path,
    _try_adopt: &dyn Fn(AccountNum, &HarvestCandidate) -> bool,
) -> Result<bool, KeychainClearUnconfirmed> {
    Ok(false)
}

/// Decide-then-clear for the pending-clear RETRY queue
/// (`sweep_pending_clears`/`sweep_pending_clears_opportunistic`,
/// `keychain-fix-r8d.md` item 1) — the SIBLING of
/// [`decide_and_clear_dead_handle`] for the case where the config dir is
/// long gone and all that survives is a bare service-name string plus
/// (since round 8d) the marker account [`record_pending_clear`] captured
/// when the entry was queued.
///
/// **`account: None` is a FAIL-CLOSED KEEP, not a delete (`guard-reader-
/// writer-parity.md` MUST-2).** With no marker account there is no `known`
/// to decide against — every legacy entry queued before this fix
/// deserializes to exactly this case (`PendingClearEntry::account`'s
/// `#[serde(default)]`), as does any entry whose recorded value failed to
/// re-validate to an [`AccountNum`] (`sweep_pending_clears_inner`'s
/// `AccountNum::try_from` conversion). Returns `Err(KeychainClearUnconfirmed)`
/// WITHOUT ever calling `security` — the entry stays queued (backed off,
/// never dropped — see [`PENDING_CLEARS_BACKOFF_MAX_SECS`]) rather than
/// being cleared blind. This is a deliberate, permanent disposition for
/// pre-fix entries: nothing will ever populate their account after the
/// fact, so they retry forever at the backoff ceiling — visible via the
/// `keychain_pending_clears_remaining` WARN — rather than either silently
/// dropping (losing the retry) or deleting unconditionally (the exact bug
/// this whole item exists to close).
///
/// **`account: Some(_)`** builds `known` from that account's canonical
/// token + bounded token history — identical shape to
/// [`decide_and_clear_dead_handle`] — and resolves `ours` (the keychain
/// account attribute) from `keychain_account_hint` when the entry recorded
/// one (`keychain-fix-r9.md` D-F5: the per-dir hint file
/// [`keychain_account_for`] would have read no longer exists by retry time,
/// so the value it resolved to WHEN QUEUED is captured and threaded through
/// instead), falling back to a live [`keychain_account`] re-derivation only
/// for an entry that predates this fix and never captured one.
///
/// `try_adopt` mirrors [`decide_and_clear_dead_handle`]'s parameter
/// exactly — one chance to adopt an unmatched-but-valid Anthropic token
/// into the marker account before this retry gives up on it.
///
/// This function is the [`PendingClearOrigin::DeadHandle`] disposition only
/// — [`clear_queued_entry`] is the dispatch point that routes a
/// [`PendingClearOrigin::Logout`] entry elsewhere (unconditional delete)
/// instead of ever calling this. `candidate_email`/`keychain_account_hint`
/// are the entry's own recorded fields (`keychain-fix-r9.md` items 1/D-F5),
/// threaded straight through rather than always `None`/a live re-derivation.
#[cfg(target_os = "macos")]
fn decide_and_clear_queued_service(
    base_dir: &Path,
    svc: &str,
    account: Option<AccountNum>,
    candidate_email: Option<&str>,
    keychain_account_hint: Option<&str>,
    try_adopt: &dyn Fn(AccountNum, &HarvestCandidate) -> bool,
) -> Result<bool, KeychainClearUnconfirmed> {
    if keychain_mirror_disabled() {
        return Ok(false);
    }
    decide_and_clear_queued_service_with_executor(
        &SecurityCliExecutor,
        base_dir,
        svc,
        account,
        candidate_email,
        keychain_account_hint,
        try_adopt,
    )
}

/// Executor-injected core of [`decide_and_clear_queued_service`] — no
/// `keychain_mirror_disabled()` short-circuit here, so a test can drive
/// this directly against a scripted executor.
#[cfg(target_os = "macos")]
fn decide_and_clear_queued_service_with_executor(
    exec: &(impl KeychainExecutor + ?Sized),
    base_dir: &Path,
    svc: &str,
    account: Option<AccountNum>,
    candidate_email: Option<&str>,
    keychain_account_hint: Option<&str>,
    try_adopt: &dyn Fn(AccountNum, &HarvestCandidate) -> bool,
) -> Result<bool, KeychainClearUnconfirmed> {
    let Some(acct) = account else {
        warn!(
            error_kind = "keychain_pending_clear_no_account",
            "pending-clear retry: this queue entry has no marker account on \
             record (queued before keychain-fix-r8d, or an out-of-range \
             recorded value) — kept, not deleted, rather than clearing blind"
        );
        return Err(KeychainClearUnconfirmed);
    };
    // `keychain-fix-r9.md` D-F5: prefer the per-dir hint CAPTURED AT QUEUE
    // TIME over a live re-derivation — the config dir that would let
    // `keychain_account_for` re-read the hint file no longer exists by
    // retry time, so the value recorded when the entry was queued is the
    // only way this retry can target the SAME account attribute the
    // dead-handle reaper's own first attempt did.
    let ours = keychain_account_hint
        .map(str::to_string)
        .unwrap_or_else(keychain_account);
    let x = exec.find(svc, &ours);

    let marker_raw: Option<String> =
        crate::accounts::identity_store::target_token_for_forced_write(base_dir, acct)
            .as_valid_str()
            .map(str::to_string);
    let history = crate::credentials::token_history::read_history_for_slot(base_dir, acct);
    let known = KnownTokens {
        marker_account_canonical: marker_raw.as_deref(),
        marker_account_history: &history,
        ..KnownTokens::default()
    };

    match decide_cc_keychain_write(&x, &known, Intended::Strip) {
        WriteDecision::StripAllowed => apply_dead_handle_strip(exec, svc, &ours, &x),
        WriteDecision::RefuseUnharvested => {
            if let RawContentClassification::Content(raw) = &x {
                if let Some(expiry_ms) = anthropic_expiry_ms(raw) {
                    let candidate = HarvestCandidate {
                        raw_json: raw.clone(),
                        expiry_ms,
                        source_tag: svc.to_string(),
                        // `keychain-fix-r9.md` item 1: no config dir
                        // survives to read `.claude.json`'s OAuth email
                        // from at retry time — the email CAPTURED AT QUEUE
                        // TIME (while the dir still existed) is threaded
                        // through instead of always `None`.
                        candidate_email: candidate_email.map(str::to_string),
                        // `svc` is a keychain SERVICE name, not a handle-dir
                        // basename — the config dir this entry was queued from
                        // is already gone by retry time (`keychain-fix-r9.md`
                        // S-L-3). `None` here is what stops
                        // `identity_unconfirmed_reason` from building a path
                        // out of a service name.
                        handle_dir_tag: None,
                    };
                    if try_adopt(acct, &candidate) {
                        let self_known = KnownTokens {
                            csq_written: Some(raw.as_str()),
                            ..KnownTokens::default()
                        };
                        if let WriteDecision::StripAllowed =
                            decide_cc_keychain_write(&x, &self_known, Intended::Strip)
                        {
                            return apply_dead_handle_strip(exec, svc, &ours, &x);
                        }
                    }
                }
            }
            // The entry exists because its handle dir is GONE, so an item
            // that stays unidentified belongs to a dead terminal and would
            // collide with a recycled PID. Save it, then delete it. Only when
            // no directory that hashes to this service exists (a re-created
            // dir may have a live owner), and only if the save succeeded;
            // otherwise keep it as before.
            if let RawContentClassification::Content(raw) = &x {
                if !handle_dir_exists_for_service(base_dir, svc)
                    && quarantine_foreign_item(base_dir, svc, raw).is_ok()
                {
                    // Re-check immediately before the delete: a dir created
                    // since the first check may have a live owner.
                    if handle_dir_exists_for_service(base_dir, svc) {
                        warn!(
                            error_kind = "keychain_pending_clear_quarantined_dir_reappeared",
                            svc_hash = quarantine_svc_hash(svc),
                            "pending-clear retry: an unidentified login was saved to the \
                             quarantine folder, but its handle dir reappeared before the \
                             delete; kept and stays queued"
                        );
                        return Err(KeychainClearUnconfirmed);
                    }
                    // Absent view: delete the whole item, merge nothing.
                    let outcome = apply_dead_handle_strip(
                        exec,
                        svc,
                        &ours,
                        &RawContentClassification::Absent,
                    );
                    return match outcome {
                        Ok(true) => {
                            warn!(
                                error_kind = "keychain_pending_clear_quarantined_foreign_item",
                                svc_hash = quarantine_svc_hash(svc),
                                "pending-clear retry: an unidentified login for a dead \
                                 handle dir was saved to the quarantine folder and removed"
                            );
                            Ok(true)
                        }
                        Ok(false) | Err(_) => {
                            warn!(
                                error_kind =
                                    "keychain_pending_clear_quarantined_removal_unconfirmed",
                                svc_hash = quarantine_svc_hash(svc),
                                "pending-clear retry: an unidentified login for a dead \
                                 handle dir was saved to the quarantine folder but its \
                                 removal is unconfirmed; stays queued"
                            );
                            Err(KeychainClearUnconfirmed)
                        }
                    };
                }
            }
            if warn_due(svc) {
                warn!(
                    error_kind = "keychain_pending_clear_unmatched_kept",
                    "pending-clear retry: item holds a login unmatched to the \
                     recorded marker account and could not be confirmed; kept, \
                     not deleted (stays queued, backed off, never dropped)"
                );
            }
            // `Err`, not `Ok(false)` — DELIBERATELY different from
            // `decide_and_clear_dead_handle`'s choice for its own
            // structurally-identical branch. That function returns
            // `Ok(false)` because ITS caller queues an `Err` into THIS
            // retry path, which (pre-item-1) was an unconditional blind
            // delete — queuing an unconfirmed candidate there would have
            // destroyed it on the very next tick. This function IS that
            // retry path post-fix: it re-runs the same decide+adopt
            // policy on every attempt, so returning `Err` here costs only
            // a backoff bump (`sweep_pending_clears_inner`'s `Err` arm) —
            // never a blind delete — and backing off is the CORRECT
            // disposition for "this candidate has not been claimable so
            // far", rather than retrying the adopt HTTP call and a fresh
            // `security find` on every single tick with no backoff at all.
            Err(KeychainClearUnconfirmed)
        }
        WriteDecision::Unknown(_) => Err(KeychainClearUnconfirmed),
        WriteDecision::RefuseIntendedExpired => {
            unreachable!("Intended::Strip never produces RefuseIntendedExpired (Token-arm only)")
        }
        WriteDecision::Write(_) | WriteDecision::NoWrite => {
            unreachable!("Intended::Strip never decides Write/NoWrite")
        }
    }
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

/// `keychain-fix-r9.md` S-M-1/D-F2: which caller queued this entry, and
/// therefore which retry disposition applies. The two production callers of
/// [`record_pending_clear`] have OPPOSITE safety requirements for the same
/// bare service-name retry:
///
/// - [`Logout`](Self::Logout): `csq logout` already attempted an
///   UNCONDITIONAL delete-by-service-name (`clear_handle_dir_reporting` ->
///   `clear_service_reporting` -> `drain_service`) moments before queuing —
///   logout means "this account's credentials are gone everywhere", so there
///   is no known-token gate to apply on the FIRST attempt, and none on the
///   RETRY either: re-running `decide_and_clear_queued_service`'s decide+
///   adopt policy on a logout-origin entry would let an unrelated, unmatched
///   login this dir happens to hold survive a logout that intended to
///   destroy it outright.
/// - [`DeadHandle`](Self::DeadHandle): the dead-handle reaper's per-dir clear
///   ALREADY routes through decide+adopt on its first attempt
///   (`decide_and_clear_dead_handle`) — an abandoned SESSION, not an
///   intentional account removal, must not destroy the only live copy of a
///   login nobody else recorded. The retry preserves that same policy.
///
/// `#[serde(default)]` on the field resolves an entry with no recorded
/// origin (every entry queued before this fix) to [`DeadHandle`](Self::DeadHandle)
/// — the MORE CONSERVATIVE of the two dispositions (decide+adopt, never a
/// blind delete) — per `guard-reader-writer-parity.md` MUST-2: an unreadable/
/// absent input on a destructive path fails closed toward the safer branch.
///
/// Unconditional (not `#[cfg(target_os = "macos")]`): [`record_pending_clear`]'s
/// non-macOS no-op stub takes this same parameter so its two production
/// callers (`accounts::logout`, `session::handle_dir`) compile identically on
/// every platform — mirrors [`HarvestCandidate`]'s own unconditional shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub(crate) enum PendingClearOrigin {
    /// Logout intentionally destroys this login; retry with the SAME
    /// unconditional delete logout's first attempt used.
    Logout,
    /// An abandoned session's dir was reaped; retry with decide+adopt, never
    /// a blind delete. Also the fail-closed default for legacy entries.
    #[default]
    DeadHandle,
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
    /// `keychain-fix-r8d.md` item 1: the marker account this entry's dir was
    /// bound to WHEN QUEUED (`record_pending_clear`'s new `account`
    /// parameter) — resolved and captured at queue time because by RETRY
    /// time the dir is long gone and there is nothing left to re-resolve it
    /// from. Raw `u16`, not [`AccountNum`]: this file's own JSON, so an
    /// out-of-range value here would be a bug in this module, not
    /// attacker input — but storing the validated type would make ONE
    /// entry with a corrupt value fail `serde_json::from_str` for the
    /// WHOLE queue (`load_pending_clears`'s per-entry `service`-name
    /// recovery has no equivalent for a field inside the same struct), so
    /// validation happens at USE time
    /// ([`decide_and_clear_queued_service`]), where an out-of-range value
    /// is treated exactly like `None` — fail closed, never a delete.
    /// `#[serde(default)]` (`None`) is what every entry queued BEFORE this
    /// fix deserializes to — a legacy entry with no recorded provenance,
    /// handled the same way (guard-reader-writer-parity.md MUST-2: an
    /// unreadable/absent input on a destructive path fails closed, keeping
    /// the item rather than deleting it blind).
    #[serde(default)]
    account: Option<u16>,
    /// `keychain-fix-r9.md` S-M-1/D-F2: which caller queued this entry — see
    /// [`PendingClearOrigin`]'s own doc for the retry-disposition split.
    #[serde(default)]
    origin: PendingClearOrigin,
    /// `keychain-fix-r9.md` item 1: the OAuth email `.claude.json` recorded
    /// for this dir at QUEUE TIME (`claude_json::read_oauth_email`) — like
    /// `account`, resolved when queued because by RETRY time the config dir
    /// is long gone and there is nothing left to re-read it from. Only ever
    /// populated for a [`PendingClearOrigin::DeadHandle`] entry: the
    /// decide+adopt retry threads it into the [`HarvestCandidate`] the same
    /// way [`decide_and_clear_dead_handle`]'s own first attempt does, rather
    /// than always retrying with `candidate_email: None`. A `Logout`-origin
    /// entry never reads this field (its retry is an unconditional delete
    /// with no candidate to adopt at all).
    #[serde(default)]
    candidate_email: Option<String>,
    /// `keychain-fix-r9.md` D-F5: the keychain ACCOUNT ATTRIBUTE
    /// (`keychain_account_for(config_dir)`) resolved at QUEUE TIME — the
    /// same per-dir hint [`decide_and_clear_dead_handle_with_executor`]'s
    /// OWN first attempt already prefers over a live derivation. By RETRY
    /// time the config dir is gone, so nothing can re-resolve the hint FILE
    /// — capturing it now is the only way the retry targets the SAME
    /// account attribute the first attempt did, rather than falling back to
    /// [`keychain_account`]'s live (and possibly different) OS-username
    /// derivation. `None` when the entry predates this fix, or for a
    /// `Logout`-origin entry (whose retry is delete-by-service-name with no
    /// account-attribute filter at all — see [`PendingClearOrigin::Logout`]).
    #[serde(default)]
    keychain_account_hint: Option<String>,
    /// `keychain-fix-r11.md` S-LOW-1/D-4b: the QUEUED handle dir's own
    /// identity -- `(inode, ctime)` of the dir itself, captured at QUEUE TIME
    /// (before it is removed) via `record_pending_clear_with_identity`.
    /// `live_handle_dir_maps_to_service` uses this to tell "a live dir whose
    /// service happens to match, because it IS the same dir this entry was
    /// queued against" apart from "a DIFFERENT, NEWER dir that has since
    /// taken over the same reused PID" -- only the second is a genuine live
    /// collision. `None` for an entry queued before this fix (or via the
    /// plain `record_pending_clear` wrapper some call sites still use):
    /// `live_handle_dir_maps_to_service` falls back to its PRE-fix
    /// conservative behaviour for those (any live matching dir counts as a
    /// collision), never to "no collision" -- guard-reader-writer-parity.md
    /// MUST-2, since the destructive branch here is the Logout entry's blind
    /// delete.
    #[serde(default)]
    queued_inode: Option<u64>,
    #[serde(default)]
    queued_ctime: Option<i64>,
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
/// `keychain-fix-r10.md` S-N-1: parses the pending-clears file leniently —
/// one unparseable ENTRY is dropped (with a WARN naming the count, never the
/// content) rather than taking down the whole file.
///
/// `serde_json::from_str::<PendingClears>` on the WHOLE raw string fails
/// closed the instant ANY single element of the `services` array fails to
/// deserialize (a field of the wrong JSON type, for instance) — the
/// `is_well_formed_service_name` retain step below this function's caller
/// only runs AFTER that whole-struct parse succeeds, so it could never
/// recover from this failure mode despite this module's own prior doc
/// comment claiming it did ("a file with some malformed JSON VALUES … keeps
/// its well-formed entries instead of the whole file being discarded" —
/// `doc-property-claims.md`: true of a malformed SERVICE NAME, false of a
/// malformed ENTRY SHAPE). Parses the top level as a generic [`serde_json::Value`]
/// first, then deserializes each `services` array element INDIVIDUALLY —
/// dropping only the ones that fail, keeping every sibling.
#[cfg(target_os = "macos")]
fn parse_pending_clears_lenient(raw: &str) -> PendingClears {
    let Ok(top) = serde_json::from_str::<serde_json::Value>(raw) else {
        warn!(
            error_kind = "keychain_pending_clears_corrupt",
            "the keychain pending-clear queue file could not be parsed as JSON \
             at all — treating as empty (its prior contents, if any, are lost; \
             this is a bug if it recurs, not an expected condition)"
        );
        return PendingClears::default();
    };
    let Some(raw_entries) = top.get("services").and_then(|v| v.as_array()) else {
        // No `services` array at all (or the wrong shape) — an empty queue,
        // same as a freshly-materialized file, never an error.
        return PendingClears::default();
    };
    let mut services = Vec::with_capacity(raw_entries.len());
    let mut dropped = 0usize;
    for entry in raw_entries {
        match serde_json::from_value::<PendingClearEntry>(entry.clone()) {
            Ok(e) => services.push(e),
            Err(_) => dropped += 1,
        }
    }
    if dropped > 0 {
        warn!(
            error_kind = "keychain_pending_clears_entry_unparseable",
            dropped,
            "dropped unparseable keychain pending-clear queue entries (bad JSON \
             shape, not just a malformed service name) — every well-formed \
             sibling entry in the same file is preserved"
        );
    }
    PendingClears { services }
}

#[cfg(target_os = "macos")]
fn load_pending_clears(base_dir: &Path) -> PendingClears {
    let mut clears = match std::fs::read_to_string(pending_clears_path(base_dir)) {
        Ok(raw) => parse_pending_clears_lenient(&raw),
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
    // `keychain-fix-r10.md` S-L-3, security.md §5a: `std::fs::write` creates
    // `tmp` at umask-default permissions (typically 0o644) with the queue
    // content (service names, account numbers, email hints) inside. Clamp to
    // 0o600 BEFORE the atomic rename, with the same cleanup-on-failure this
    // function already applies to its other two fallible steps.
    if crate::platform::fs::secure_file(&tmp).is_err() {
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
/// `save_pending_clears`).
///
/// Serialized under `pending_clears_lock_path` (security review 1386
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
///
/// `account` (`keychain-fix-r8d.md` item 1): the marker account `service`'s
/// dir was bound to AT QUEUE TIME — the caller resolves it (e.g.
/// `accounts::markers::resolve_marker_to_slot`) before this call, since by
/// retry time (`sweep_pending_clears`) the dir is gone and there is nothing
/// left to resolve it from. `None` for a caller that genuinely has no
/// marker to resolve (e.g. the dir never carried one) — the retry path
/// treats that identically to a legacy pre-fix entry: fail closed, keep,
/// never delete blind.
#[cfg(target_os = "macos")]
pub(crate) fn record_pending_clear(
    base_dir: &Path,
    service: &str,
    account: Option<AccountNum>,
    origin: PendingClearOrigin,
    candidate_email: Option<String>,
    keychain_account_hint: Option<String>,
) {
    record_pending_clear_with_identity(
        base_dir,
        service,
        account,
        origin,
        candidate_email,
        keychain_account_hint,
        None,
    )
}

/// `keychain-fix-r11.md` S-LOW-1/D-4b: identical to [`record_pending_clear`]
/// except for the trailing `queued_identity` — `(inode, ctime)` of the
/// handle dir THIS entry is being queued for, captured by the caller from
/// the dir's own `std::fs::metadata` BEFORE it is removed (by retry time
/// there is nothing left to re-derive it from). `record_pending_clear`
/// itself is kept as a thin wrapper passing `None` — every test call site
/// and any caller with no dir left to stat (a bare service-name re-record)
/// keeps working unchanged; only [`live_handle_dir_maps_to_service`] reads
/// this field, and it treats `None` the same conservative way it always has
/// (see that field's own doc on [`PendingClearEntry`]).
#[cfg(target_os = "macos")]
pub(crate) fn record_pending_clear_with_identity(
    base_dir: &Path,
    service: &str,
    account: Option<AccountNum>,
    origin: PendingClearOrigin,
    candidate_email: Option<String>,
    keychain_account_hint: Option<String>,
    queued_identity: Option<(u64, i64)>,
) {
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
        // A fresh record for the same service is new evidence about WHICH
        // account it belongs to as well — overwrite, don't keep whatever
        // (possibly stale, possibly absent) account an earlier record for
        // this same service carried.
        existing.account = account.map(|a| a.get());
        // `keychain-fix-r9.md` S-M-1/D-F2: a fresh record also overwrites
        // origin and candidate email — same rationale as `account` above:
        // this is new evidence about the CURRENT reason the entry is
        // queued, not a reason to keep whatever a prior record carried.
        existing.origin = origin;
        existing.candidate_email = candidate_email;
        existing.keychain_account_hint = keychain_account_hint;
        existing.queued_inode = queued_identity.map(|(ino, _)| ino);
        existing.queued_ctime = queued_identity.map(|(_, ctime)| ctime);
        save_pending_clears(base_dir, &clears, "record_pending_clear");
        return;
    }
    if clears.services.len() >= PENDING_CLEARS_MAX {
        // `keychain-fix-r10.md` C-I2: a `Logout`-origin entry is HIGHER
        // stakes to lose than a `DeadHandle` one — logout is the only
        // remaining record that this specific account's keychain item still
        // needs clearing; a `DeadHandle` reaper entry has other self-healing
        // paths (the custodian, a later sweep re-discovering the dead dir).
        // Evict the OLDEST `DeadHandle` entry first (still FIFO within that
        // class); only when none remain does a `Logout` entry get evicted —
        // logged at ERROR, distinct from the routine WARN below, since that
        // is the queue running out of headroom for the class it can least
        // afford to lose.
        let evict_idx = clears
            .services
            .iter()
            .position(|e| e.origin == PendingClearOrigin::DeadHandle)
            .unwrap_or(0);
        let evicted = clears.services.remove(evict_idx);
        if evicted.origin == PendingClearOrigin::Logout {
            tracing::error!(
                error_kind = "keychain_pending_clears_evicted_logout",
                "the keychain pending-clear queue is full ({PENDING_CLEARS_MAX} \
                 entries) with NO DeadHandle entries left to evict — evicted a \
                 Logout-origin entry instead; that account's keychain item will \
                 NOT be auto-retried and may remain a live orphan after logout"
            );
        } else {
            warn!(
                error_kind = "keychain_pending_clears_evicted",
                "the keychain pending-clear queue is full ({PENDING_CLEARS_MAX} entries) — \
                 evicted the oldest DeadHandle entry to make room; that item's keychain \
                 clear will NOT be auto-retried and may remain an orphan"
            );
        }
        let _ = evicted; // service name only — nothing further to log (no secret)
    }
    clears.services.push(PendingClearEntry {
        service: service.to_string(),
        attempts: 0,
        next_attempt_unix_secs: 0,
        generation: 0,
        account: account.map(|a| a.get()),
        origin,
        candidate_email,
        keychain_account_hint,
        queued_inode: queued_identity.map(|(ino, _)| ino),
        queued_ctime: queued_identity.map(|(_, ctime)| ctime),
    });
    save_pending_clears(base_dir, &clears, "record_pending_clear_with_identity");
}

/// Non-macOS: no keychain, so no pending-clear queue is ever populated —
/// structural no-op.
#[cfg(not(target_os = "macos"))]
pub(crate) fn record_pending_clear(
    _base_dir: &Path,
    _service: &str,
    _account: Option<AccountNum>,
    _origin: PendingClearOrigin,
    _candidate_email: Option<String>,
    _keychain_account_hint: Option<String>,
) {
}

/// Non-macOS: no keychain, so no pending-clear queue is ever populated —
/// structural no-op. Unconditional so `session::handle_dir`/`accounts::logout`
/// call sites compile identically on every platform.
#[cfg(not(target_os = "macos"))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_pending_clear_with_identity(
    _base_dir: &Path,
    _service: &str,
    _account: Option<AccountNum>,
    _origin: PendingClearOrigin,
    _candidate_email: Option<String>,
    _keychain_account_hint: Option<String>,
    _queued_identity: Option<(u64, i64)>,
) {
}

/// `keychain-fix-r11.md` S-MEDIUM-1 / D-4 (regression fix over the retired
/// `drop_pending_clear_for_service`): resolves any pending-clear queue entry
/// for `svc` by running its OWN disposition against the real keychain item —
/// called by [`session::handle_dir::create_handle_dir`]/
/// [`session::handle_dir::create_handle_dir_named`] the moment a FRESH
/// handle dir is created, using that dir's own canonicalized [`service_name`].
/// PID reuse makes `term-<pid>`'s canonicalized path — and therefore its
/// keychain service name — IDENTICAL to whatever prior session last
/// occupied that same PID: a `Logout`- or `DeadHandle`-origin entry
/// surviving from that earlier session would otherwise sit in the queue
/// ready to retry against THIS session's service name the next time
/// [`sweep_pending_clears`] runs, well before this fresh session has done
/// anything to earn a clear.
///
/// The PRIOR fix here (`keychain-fix-r10.md` S-M-2) simply DROPPED the queue
/// entry — which stopped a LATER retry from misfiring, but left whatever
/// stale keychain item the disposition was supposed to clear sitting
/// untouched under the reused service name, with no further chance to ever
/// be cleared (the entry that would have cleared it is gone). This resolves
/// it instead, synchronously, HERE — under the caller's per-dir swap lock,
/// before this session's own `force_sync_for_launch` write ever lands — and
/// removes the queue entry ONLY on a CONFIRMED clear (`Ok(true)`), mirroring
/// [`sweep_pending_clears_inner`]'s own three-way disposition: `Ok(false)`
/// (the keychain mirror is administratively disabled — a STRUCTURAL no-op,
/// nothing was actually attempted) and `Err` (attempted, unconfirmed) both
/// leave the entry queued for [`sweep_pending_clears`]'s own retry — never
/// silently re-dropped, and never removed on a no-op that cleared nothing.
///
/// Deliberately bypasses [`clear_queued_entry`]'s S-M-2 live-collision
/// downgrade rather than calling it: by the time this runs, `.live-pid` for
/// the JUST-CREATED dir is already written, so
/// [`live_handle_dir_maps_to_service`] would find THIS dir's own PID and
/// misread it as "a different, later session has since taken this service"
/// — it is not a different session, it IS this call's own fresh dir, and
/// nothing has been written to ITS keychain item yet. A blind
/// [`PendingClearOrigin::Logout`] delete is therefore exactly as safe here
/// as it is on a logout's own first attempt.
#[cfg(target_os = "macos")]
pub(crate) fn resolve_pending_clear_at_creation(base_dir: &Path, svc: &str) {
    let http_get: crate::daemon::usage_poller::HttpGetFn =
        std::sync::Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
            crate::http::get_bearer_node(url, token, headers)
        });
    resolve_pending_clear_at_creation_with(
        base_dir,
        svc,
        &mut |s| clear_service_reporting(s),
        &mut |s, acct, candidate_email, keychain_account_hint| {
            decide_and_clear_queued_service(
                base_dir,
                s,
                acct,
                candidate_email,
                keychain_account_hint,
                &|account, candidate| {
                    crate::daemon::custodian::adopt_single_candidate_before_delete(
                        base_dir, account, candidate, &http_get,
                    )
                },
            )
        },
    );
}

/// Test seam for [`resolve_pending_clear_at_creation`]: `logout_clear_fn`/
/// `dead_handle_clear_fn` are injectable so a test can prove the origin
/// dispatch AND the confirmed-clear-only removal without shelling `security`
/// or making an HTTP adopt call — mirroring [`clear_queued_entry_inner`]'s
/// identical split for the SAME reason. Production's only caller
/// ([`resolve_pending_clear_at_creation`] above) always passes the real
/// [`clear_service_reporting`] / [`decide_and_clear_queued_service`] pair.
#[cfg(target_os = "macos")]
fn resolve_pending_clear_at_creation_with(
    base_dir: &Path,
    svc: &str,
    logout_clear_fn: &mut impl FnMut(&str) -> Result<bool, KeychainClearUnconfirmed>,
    dead_handle_clear_fn: &mut impl FnMut(
        &str,
        Option<AccountNum>,
        Option<&str>,
        Option<&str>,
    ) -> Result<bool, KeychainClearUnconfirmed>,
) {
    let _guard = match crate::platform::lock::lock_file(&pending_clears_lock_path(base_dir)) {
        Ok(g) => g,
        Err(e) => {
            warn!(
                error_kind = "keychain_pending_clears_lock_failed",
                "could not lock the keychain pending-clear queue to resolve a stale \
                 entry for a freshly created handle dir (non-fatal); entry, if any, \
                 stays queued for the daemon's own retry: {}",
                crate::error::redact_tokens(&e.to_string())
            );
            return;
        }
    };
    let mut clears = load_pending_clears(base_dir);
    let Some(idx) = clears.services.iter().position(|e| e.service == svc) else {
        return;
    };
    let entry = clears.services[idx].clone();
    let account = entry.account.and_then(|n| AccountNum::try_from(n).ok());
    let outcome = match entry.origin {
        PendingClearOrigin::Logout => logout_clear_fn(svc),
        PendingClearOrigin::DeadHandle => dead_handle_clear_fn(
            svc,
            account,
            entry.candidate_email.as_deref(),
            entry.keychain_account_hint.as_deref(),
        ),
    };
    match outcome {
        // `Ok(true)`: a real clear was confirmed — remove the entry.
        Ok(true) => {
            clears.services.remove(idx);
            save_pending_clears(base_dir, &clears, "resolve_pending_clear_at_creation");
        }
        // `Ok(false)`: structural no-op (`keychain_mirror_disabled()`) —
        // nothing was attempted, so nothing changed; leave the entry queued
        // exactly as `sweep_pending_clears_inner`'s own `Ok(false)` arm does.
        Ok(false) => {}
        Err(KeychainClearUnconfirmed) => {
            warn!(
                error_kind = "keychain_pending_clear_unconfirmed_at_creation",
                "post-creation pending-clear resolve did not confirm; entry stays \
                 queued for the daemon's own retry"
            );
        }
    }
}

/// Non-macOS: no keychain, so no pending-clear queue is ever populated —
/// structural no-op. Unconditional (not gated further) so
/// `session::handle_dir::create_handle_dir`/`create_handle_dir_named`'s call
/// sites compile identically on every platform.
#[cfg(not(target_os = "macos"))]
pub(crate) fn resolve_pending_clear_at_creation(_base_dir: &Path, _svc: &str) {}

/// Retry up to `PENDING_CLEARS_SWEEP_BUDGET` due entries from the
/// pending-clear queue. Returns `(cleared, remaining)`. Called from the
/// daemon's periodic handle-dir sweep (`session::handle_dir::spawn_sweep`)
/// and opportunistically from `csq run`, so both a running-daemon install
/// and a headless daemon-less one eventually converge. Cheap when the queue
/// is empty (one file read, no subprocess calls, no lock).
///
/// **Concurrency (security review 1386 HIGH — round 2).** The `security`
/// subprocess attempts run WITHOUT holding `pending_clears_lock_path` —
/// up to ~187.5s (see `PENDING_CLEARS_SWEEP_BUDGET`'s doc for the current
/// derivation, ENFORCED-limit based, not a measurement) would otherwise
/// block a concurrent `record_pending_clear` for the whole sweep. Only the
/// final REMOVAL is locked, and it removes by `identity_matches`
/// (`service` + `generation` ONLY — deliberately NOT full entry equality,
/// see that function's doc for why `load_pending_clears`'s N5 clamp
/// makes `attempts`/`next_attempt_unix_secs` unsafe to compare) against a
/// FRESH re-load of the current file — never a blind overwrite of the
/// pre-attempt snapshot, and never a service-NAME-only match either
/// (security review 1386, sec-1386's generation-counter finding): a
/// service name alone cannot tell "the entry I attempted" apart from "a
/// DIFFERENT clear request recorded for the same service between my
/// snapshot and my locked write" — see `generation`'s doc on
/// `PendingClearEntry`. This makes the operation safe regardless of what
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
/// only `security`-touching call in this loop is
/// `decide_and_clear_queued_service`, which already carries that guard
/// internally (returns `Ok(false)` under test, so every entry stays queued
/// and no real keychain is ever touched from a test), which is what lets
/// THIS function's file-I/O half (load, budget, persist) be exercised
/// directly by a unit test.
///
/// `keychain-fix-r8d.md` item 1: the per-entry clear now routes through
/// `clear_queued_entry` (known = the entry's recorded marker account's
/// canonical token + bounded token history, plus a single-candidate adopt
/// via the same Node-transport `HttpGetFn` `daemon::server`/
/// `daemon::refresher` construct their own `reconcile_account` calls use)
/// rather than the old unconditional `clear_service_reporting` blind delete
/// for EVERY entry — `keychain-fix-r9.md` S-M-1/D-F2 restores that
/// unconditional delete specifically for `PendingClearOrigin::Logout`
/// entries, at the dispatch point, per `clear_queued_entry`'s own doc.
#[cfg(target_os = "macos")]
pub fn sweep_pending_clears(base_dir: &Path) -> (usize, usize) {
    let http_get: crate::daemon::usage_poller::HttpGetFn =
        std::sync::Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
            crate::http::get_bearer_node(url, token, headers)
        });
    sweep_pending_clears_inner(
        base_dir,
        pending_clears_now_secs(),
        PENDING_CLEARS_SWEEP_BUDGET,
        &mut |svc, account, origin, candidate_email, keychain_account_hint, queued_identity| {
            clear_queued_entry(
                base_dir,
                svc,
                account,
                origin,
                candidate_email,
                keychain_account_hint,
                queued_identity,
                &|acct, candidate| {
                    crate::daemon::custodian::adopt_single_candidate_before_delete(
                        base_dir, acct, candidate, &http_get,
                    )
                },
            )
        },
    )
}

/// Opportunistic variant for SYNCHRONOUS, INTERACTIVE callers (`csq run`,
/// `csq exec`, the phase2b subscription client) — see
/// `PENDING_CLEARS_OPPORTUNISTIC_BUDGET`'s doc for why this is a
/// separate, much smaller budget rather than reusing
/// [`sweep_pending_clears`]'s daemon-sized one.
#[cfg(target_os = "macos")]
pub fn sweep_pending_clears_opportunistic(base_dir: &Path) -> (usize, usize) {
    let http_get: crate::daemon::usage_poller::HttpGetFn =
        std::sync::Arc::new(|url: &str, token: &str, headers: &[(&str, &str)]| {
            crate::http::get_bearer_node(url, token, headers)
        });
    sweep_pending_clears_inner(
        base_dir,
        pending_clears_now_secs(),
        PENDING_CLEARS_OPPORTUNISTIC_BUDGET,
        &mut |svc, account, origin, candidate_email, keychain_account_hint, queued_identity| {
            clear_queued_entry(
                base_dir,
                svc,
                account,
                origin,
                candidate_email,
                keychain_account_hint,
                queued_identity,
                &|acct, candidate| {
                    crate::daemon::custodian::adopt_single_candidate_before_delete(
                        base_dir, acct, candidate, &http_get,
                    )
                },
            )
        },
    )
}

/// Dispatches a queued entry's retry by its recorded ORIGIN
/// (`keychain-fix-r9.md` S-M-1/D-F2): [`PendingClearOrigin::Logout`] retries
/// with the SAME unconditional delete-by-service-name
/// [`clear_service_reporting`] uses — the disposition logout's own first
/// attempt already applied, and intentionally applies again here, never
/// decide+adopt (which would let an unrelated, unmatched login this service
/// happens to hold survive a logout that intended to destroy it outright).
/// [`PendingClearOrigin::DeadHandle`] (the fail-closed default for any
/// legacy or unrecognized entry) keeps the existing decide+adopt policy via
/// [`decide_and_clear_queued_service`].
///
/// `keychain-fix-r10.md` S-M-2, corrected by `keychain-fix-r11.md` S-LOW-1/
/// D-4b: a `Logout`-origin entry whose service now maps to a GENUINE live
/// collision — a DIFFERENT, NEWER handle dir than the one this entry was
/// queued against ([`live_handle_dir_maps_to_service`]) — is neither deleted
/// NOR downgraded to decide+adopt. It is KEPT, untouched, this retry (see
/// [`clear_queued_entry_inner`]). The S-M-2 "downgrade to decide+adopt" this
/// doc previously described here was ITSELF unsafe: `decide_and_clear_queued_
/// service` is called with THIS entry's own RECORDED account — captured at
/// QUEUE TIME, for the OLD occupant — never re-derived from the CURRENT
/// dir's own marker. Against a genuinely different live session that
/// happens to share the reused PID, that is exactly the wrong account to
/// decide+adopt against. (The prior doc here claimed the opposite — "it
/// reads the CURRENT dir's own marker/candidate" — which was FALSE; grep
/// confirms `account`/`candidate_email`/`keychain_account_hint` are this
/// entry's own recorded fields, passed straight through.)
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn clear_queued_entry(
    base_dir: &Path,
    svc: &str,
    account: Option<AccountNum>,
    origin: PendingClearOrigin,
    candidate_email: Option<&str>,
    keychain_account_hint: Option<&str>,
    queued_identity: Option<(u64, i64)>,
    try_adopt: &dyn Fn(AccountNum, &HarvestCandidate) -> bool,
) -> Result<bool, KeychainClearUnconfirmed> {
    let svc_has_live_handle_dir = live_handle_dir_maps_to_service(base_dir, svc, queued_identity);
    clear_queued_entry_inner(
        svc,
        origin,
        account,
        svc_has_live_handle_dir,
        &mut |s| clear_service_reporting(s),
        &mut |s, a| {
            decide_and_clear_queued_service(
                base_dir,
                s,
                a,
                candidate_email,
                keychain_account_hint,
                try_adopt,
            )
        },
    )
}

/// `true` iff a LIVE `term-*` handle dir under `base_dir` canonicalizes to a
/// path whose [`service_name`] equals `svc` AND (`keychain-fix-r11.md`
/// S-LOW-1/D-4b) is genuinely a DIFFERENT, NEWER dir than the one THIS entry
/// was queued against — never the SAME physical dir the entry's own queueing
/// event already accounted for. Two hardenings over the `keychain-fix-r10.md`
/// S-M-2 predicate this replaces:
///
/// 1. **Dir identity, not just PID-reuse plausibility.** `queued_identity`
///    (`(inode, ctime)`, captured at queue time — see
///    [`PendingClearEntry::queued_inode`]/`queued_ctime`) is compared
///    against each live candidate's OWN current identity. A dir whose
///    identity MATCHES `queued_identity` is the SAME dir the entry was
///    queued against — not a collision, just the entry's own subject still
///    being alive (e.g. queued speculatively before it actually died) — and
///    is skipped. `None` (a legacy entry, or one recorded via the plain
///    [`record_pending_clear`] wrapper) falls back to the PRE-fix
///    conservative behaviour: ANY live matching dir counts as a collision,
///    since there is nothing to compare against and the destructive branch
///    (a blind Logout delete) is the one that must fail closed
///    (`guard-reader-writer-parity.md` MUST-2).
/// 2. **Identity-aware liveness, not bare `kill(pid, 0)`.** The candidate's
///    owning PID must ALSO independently resolve a start time via
///    [`crate::sessions::macos::read_start_time`] — a second, differently
///    sourced signal before treating a bare-alive PID as a genuine
///    collision, guarding against a THIRD-level PID recycle this predicate
///    cannot otherwise distinguish from the dir it is actually protecting.
///
/// `false` on any I/O failure (absent `base_dir`, an unreadable entry, a
/// canonicalize failure) for the SAME fail-closed reason MUST-2 gives above:
/// this predicate fails toward "no live collision found", which is the safe
/// direction ONLY because [`clear_queued_entry_inner`] now KEEPS the entry
/// (does nothing) on a positive collision rather than acting on it — a
/// `false` here simply proceeds to the entry's OWN origin disposition, never
/// to an unconditional destructive default.
#[cfg(target_os = "macos")]
fn live_handle_dir_maps_to_service(
    base_dir: &Path,
    svc: &str,
    queued_identity: Option<(u64, i64)>,
) -> bool {
    use std::os::unix::fs::MetadataExt;

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("term-") || !path.is_dir() {
            continue;
        }
        if let Some(queued) = queued_identity {
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if (meta.ino(), meta.ctime()) == queued {
                continue; // the SAME dir the entry was queued against
            }
        }
        let pid = crate::accounts::markers::read_live_pid(&path)
            .or_else(|| name.strip_prefix("term-").and_then(|s| s.parse().ok()));
        let Some(pid) = pid else { continue };
        if !crate::platform::process::is_pid_alive(pid) {
            continue;
        }
        // Identity-aware liveness (S-LOW-1/D-4b): a second, independently
        // sourced confirmation beyond bare `kill(pid, 0)`.
        if crate::sessions::macos::read_start_time(pid).is_none() {
            continue;
        }
        let Ok(abs) = std::fs::canonicalize(&path) else {
            continue;
        };
        if service_name(&abs) == svc {
            return true;
        }
    }
    false
}

/// Test seam for [`clear_queued_entry`]'s ORIGIN dispatch. Both real
/// closures collapse to `Ok(false)` under test via their OWN independent
/// `keychain_mirror_disabled()` guards (`clear_service_reporting`'s and
/// `decide_and_clear_queued_service`'s), which makes the DISPATCH itself
/// unobservable through the return value alone — a test drives this
/// directly with scripted closures to prove a `Logout`-origin entry reaches
/// `logout_clear_fn` and a `DeadHandle`-origin entry reaches
/// `dead_handle_clear_fn`, never the other way around. `svc_has_live_handle_dir`
/// is the pre-computed result of [`live_handle_dir_maps_to_service`] — passed
/// in rather than recomputed here so this pure-decision function stays
/// testable without touching real directories.
///
/// `keychain-fix-r11.md` S-LOW-1/D-4b: a genuine live collision on a
/// `Logout`-origin entry now returns `Ok(false)` directly — KEEPING the
/// entry, calling NEITHER closure — rather than the retired
/// `keychain-fix-r10.md` S-M-2 downgrade to `dead_handle_clear_fn` (which
/// ran decide+adopt against this entry's own STALE recorded account, not the
/// live dir's actual owner; see [`clear_queued_entry`]'s doc for why that was
/// unsafe). `Ok(false)` is the SAME "structural no-op, nothing attempted"
/// signal `sweep_pending_clears_inner` already treats as free — it does not
/// count against budget or receive a backoff bump, so the entry is retried
/// again next tick with no cost.
#[cfg(target_os = "macos")]
fn clear_queued_entry_inner(
    svc: &str,
    origin: PendingClearOrigin,
    account: Option<AccountNum>,
    svc_has_live_handle_dir: bool,
    logout_clear_fn: &mut impl FnMut(&str) -> Result<bool, KeychainClearUnconfirmed>,
    dead_handle_clear_fn: &mut impl FnMut(
        &str,
        Option<AccountNum>,
    ) -> Result<bool, KeychainClearUnconfirmed>,
) -> Result<bool, KeychainClearUnconfirmed> {
    match origin {
        // S-LOW-1/D-4b: a genuine live collision KEEPS the entry — neither
        // closure runs. Checked BEFORE the unconditional-delete arm so it
        // takes priority.
        PendingClearOrigin::Logout if svc_has_live_handle_dir => Ok(false),
        PendingClearOrigin::Logout => logout_clear_fn(svc),
        PendingClearOrigin::DeadHandle => dead_handle_clear_fn(svc, account),
    }
}

/// Test seam for [`sweep_pending_clears`]/[`sweep_pending_clears_opportunistic`]
/// (security review 1386 F5(b) — pendq-analysis): `clear_fn` is the
/// per-entry clear call, injectable so a test can prove only `budget`
/// entries are ATTEMPTED (not merely that the final counts are consistent
/// with either a real or a no-op budget, which
/// [`decide_and_clear_queued_service`]'s test-mode `Ok(false)` makes
/// indistinguishable from "no budget at all" — the exact gap the reviewer
/// named). Mirrors the `sweep_dead_handles`/`sweep_dead_handles_inner` seam
/// pattern in `session::handle_dir.rs` (an internal ticket). `now` is ALSO injectable
/// (security review 1386 N5) so backoff due/not-due decisions are testable
/// without depending on wall-clock time. `budget` is injectable so the
/// daemon and opportunistic callers can share this one implementation with
/// different worst-case latency ceilings.
///
/// `clear_fn` takes `(service, account, origin, candidate_email,
/// keychain_account_hint)` — `account` is the entry's recorded `Option<u16>`
/// re-validated to `Option<AccountNum>` (`keychain-fix-r8d.md` item 1): a
/// value outside `1..=MAX_ACCOUNTS` (which this module's own writer never
/// produces, but a hand-edited or otherwise corrupted queue file could) is
/// treated identically to `None` — never trusted past this point.
/// `origin`/`candidate_email`/`keychain_account_hint` are the entry's own
/// recorded fields, borrowed straight through (`keychain-fix-r9.md` items
/// 1/D-F5): `origin` selects the retry disposition, and the other two are
/// only ever consulted on a [`PendingClearOrigin::DeadHandle`] entry.
#[cfg(target_os = "macos")]
fn sweep_pending_clears_inner(
    base_dir: &Path,
    now: u64,
    budget: usize,
    clear_fn: &mut impl FnMut(
        &str,
        Option<AccountNum>,
        PendingClearOrigin,
        Option<&str>,
        Option<&str>,
        Option<(u64, i64)>,
    ) -> Result<bool, KeychainClearUnconfirmed>,
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
        let account = entry.account.and_then(|n| AccountNum::try_from(n).ok());
        let queued_identity = entry.queued_inode.zip(entry.queued_ctime);
        match clear_fn(
            &entry.service,
            account,
            entry.origin,
            entry.candidate_email.as_deref(),
            entry.keychain_account_hint.as_deref(),
            queued_identity,
        ) {
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
                    account: entry.account,
                    origin: entry.origin,
                    candidate_email: entry.candidate_email.clone(),
                    keychain_account_hint: entry.keychain_account_hint.clone(),
                    queued_inode: entry.queued_inode,
                    queued_ctime: entry.queued_ctime,
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
    if remaining > 0 && warn_due("pending-clears-remaining") {
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
/// has since been swapped away — and `csq swap`'s v4 forced write
/// ([`force_sync_account_changed`]) already clears or overwrites that old
/// item at the moment of the swap itself, so this predicate does not miss
/// that case. A dir whose
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

        // Read the keychain item via the bounded helper (5s timeout + SIGKILL),
        // then run the read result through the pure decision function so the
        // "a `None` read never becomes an expiry=0 candidate" contract is
        // exercised by production code AND directly unit-testable (see
        // `harvest_candidate_expiry` and its tests — this is the fn the test
        // formerly named `harvest_absent_keychain_read_is_none_not_expiry_zero`
        // claimed to cover without actually calling it).
        let raw = read_raw_keychain(&abs);
        let raw_present = raw.is_some();
        let expiry = match harvest_candidate_expiry(raw.as_deref(), now) {
            Ok(e) => e,
            Err(HarvestSkipReason::ReadAbsentOrFailed) => {
                debug_assert!(!raw_present, "ReadAbsentOrFailed implies raw was None");
                // Absent, unparseable, or timed-out keychain read: no candidate
                // from this dir. Log with fixed tag only — no token bytes.
                warn!(
                    source_tag = %dir_name_s,
                    "harvest: no candidate (keychain read absent or failed)"
                );
                continue;
            }
            // Non-Anthropic credential in the keychain item — zero candidates.
            Err(HarvestSkipReason::NonAnthropic) => continue,
            Err(HarvestSkipReason::ExpiryUnparseable) => {
                // Unparseable expiry: fail closed — no candidate.
                warn!(
                    source_tag = %dir_name_s,
                    "harvest: no candidate (expiry parse failed)"
                );
                continue;
            }
            // Expired token — zero candidates from this dir.
            Err(HarvestSkipReason::Expired) => continue,
        };
        let raw = raw.expect("Ok(_) from harvest_candidate_expiry implies raw was Some");

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
            source_tag: dir_name_s.clone().into_owned(),
            candidate_email,
            // `dir_name_s` IS the handle-dir basename read from `base_dir` above.
            handle_dir_tag: Some(dir_name_s.into_owned()),
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

/// Why a handle dir's raw keychain read contributes zero harvest candidates —
/// factored out of [`harvest_account_candidates`]'s loop so each branch is a
/// directly testable outcome of [`harvest_candidate_expiry`], rather than
/// something only reachable by shelling `security`.
///
/// `#[cfg(target_os = "macos")]`: this type's ONLY production caller,
/// [`harvest_account_candidates`], is macOS-only (CC does not write
/// keychain items elsewhere, so the harvest is always empty there — see
/// that function's non-macOS stub). Ungated, this became genuinely dead
/// code cross-compiling for `x86_64-pc-windows-gnu` — `clippy --all-targets`
/// on that target has no `#[cfg(test)]` code active in the plain-lib
/// build, and no non-macOS production path reaches it either — caught by
/// the required `Clippy` job's windows-gnu cross-compile step, not by any
/// macOS-run gate (`durable-instruments.md`: the instrument that would
/// have caught this needed to run on a DIFFERENT cfg than the one this
/// session's local gates exercised).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HarvestSkipReason {
    /// [`read_raw_keychain`] itself returned `None` — absent item, timeout,
    /// spawn failure, or an undecodable (non-UTF8/hex/JSON) payload. This is
    /// the case `harvest_absent_keychain_read_is_none_not_expiry_zero`'s NAME
    /// promises to cover: a `None` read here is NEVER converted to an
    /// `expiry_ms` of `0` — it short-circuits to this variant before
    /// `anthropic_expiry_ms` is even called.
    ReadAbsentOrFailed,
    /// The keychain held a credential, but not a `claudeAiOauth`-shaped one
    /// (e.g. a Codex item under the same service — should not normally
    /// occur, since the service name is derived from the Anthropic-specific
    /// `.credentials.json` symlink target, but is checked defensively).
    NonAnthropic,
    /// A `claudeAiOauth`-shaped credential whose `expiresAt` could not be
    /// parsed.
    ExpiryUnparseable,
    /// A valid, parseable Anthropic credential — but already expired
    /// (`expiry_ms <= now`).
    Expired,
}

/// Pure decision: given the raw keychain read result exactly as
/// [`read_raw_keychain`] returns it (`None` on absent/timeout/malformed) and
/// the current time, decide whether this handle dir contributes a harvest
/// candidate. `Ok(expiry_ms)` on a valid, non-expired Anthropic credential;
/// `Err(reason)` otherwise. No I/O, no logging, no `security` shell — the
/// caller logs using `reason` for the fixed-vocabulary tag. Mirrors
/// [`decide_harvest`]'s "pure decision, real caller does I/O" split.
///
/// `#[cfg(target_os = "macos")]` for the same reason as [`HarvestSkipReason`]:
/// its sole caller is macOS-only.
#[cfg(target_os = "macos")]
fn harvest_candidate_expiry(raw: Option<&str>, now: u64) -> Result<u64, HarvestSkipReason> {
    let raw = raw.ok_or(HarvestSkipReason::ReadAbsentOrFailed)?;
    if !raw.contains("\"claudeAiOauth\"") {
        return Err(HarvestSkipReason::NonAnthropic);
    }
    let expiry = anthropic_expiry_ms(raw).ok_or(HarvestSkipReason::ExpiryUnparseable)?;
    if expiry <= now {
        return Err(HarvestSkipReason::Expired);
    }
    Ok(expiry)
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

/// Classification of a keychain item's raw content (C1) — the THREE
/// outcomes a caller that might WRITE based on this read must be able to
/// tell apart, replacing the `Option<String>` that used to collapse
/// "confirmed absent" and "we don't actually know" into the same `None`
/// (exactly BUG-2/BUG-R3-1's class, one level up: at the WRITE decision
/// rather than the expiry-comparison decision).
// Platform-independent pure content classification enum — unconditional so it compiles and
// its tests run on every platform; its only PRODUCTION caller is still
// macOS-gated, so it is genuinely unused in a non-test, non-macOS build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnreadableKind {
    /// F3/F4 (owner decision, "switch now or say so", 2026-09-26): `security`
    /// COMPLETED and exited with `SECURITY_ERR_INTERACTION_NOT_ALLOWED` (36)
    /// — ONLY that exit, not "any non-44 failure". Measured live on
    /// `esperie-mac-mini`, in a Background (SSH-like) launchd session,
    /// against a throwaway keychain: an unlocked read of a present item
    /// exits `0`; a LOCKED read of a present item exits `36`; a locked read
    /// of an ABSENT item exits `44` (`Absent`, not `Unreadable` at all).
    /// Every OTHER completed exit code — `errSecAuthFailed`, an ACL denial,
    /// anything else `security` can return, and a signal-terminated child
    /// whose `ExitStatus::code()` is `None` on Unix — is `Transient`.
    ///
    /// S5: a launch-time caller's handle dir is FRESH — no CC session has
    /// ever run against it — so `Inaccessible` (exit 36, a PRESENT item)
    /// there names a STALE item from an earlier occupant (PID reuse), not
    /// "CC would also fail to read the current account's item". The prior
    /// doc here claimed the opposite ("a launch-time caller may proceed
    /// without the mirror ONLY on this variant") and is retracted — see
    /// `decide_launch_disposition`, which now REFUSES on this variant.
    Inaccessible,
    /// The ask itself did not resolve as a clean "refused with exit 36" —
    /// spawn failure/timeout (`security` never returned), a
    /// signal-terminated child, an INCOMPLETE stdout capture, a payload
    /// that arrived but failed to decode (non-UTF-8, bad hex, empty, not a
    /// JSON object), or ANY completed exit other than 36 or 44. A
    /// launch-time caller MUST NOT proceed: unlike
    /// [`UnreadableKind::Inaccessible`], nothing here tells us CC would
    /// ALSO fail to read the same item — an incomplete or malformed capture
    /// may be a transient race that a fresh CC read resolves cleanly
    /// moments later.
    Transient,
}

/// `pub` (widened from `pub(crate)` for round 7c D-F7, and from
/// module-private before that, 2026-09-26, for the single-writer-policy
/// directive): the daemon harvest-IPC route (`server.rs`/`client.rs`) names
/// this type, and a cross-crate test harness (`csq`'s `swap::tests`)
/// scripts a `KeychainExecutor::find` result against it via
/// `set_test_keychain_executor`. No variant or semantics changed by either
/// widening.
///
/// (`KeychainExecutor` is not linked above: it is `#[cfg(target_os =
/// "macos")]`-gated, so an intra-doc link to it is unresolvable on a
/// non-macOS `cargo doc` build — pre-existing, unrelated to this comment's
/// own content; `keychain-fix-r8.md` fix.)
///
/// `credential-type-hygiene.md` Rule 1: `Content(String)` carries a live
/// OAuth credential payload (`claudeAiOauth` and possibly sibling keys), so
/// `Debug` is hand-written to redact it — see the manual `impl` below — the
/// same reason `ForcedWriteAttempt` (S-LOW-1) does not `#[derive(Debug)]`.
/// This was safe to leave derived while the type was module-private with no
/// production `{:?}` call site; widening it to `pub(crate)` raises the
/// exposure (delegation prompts, a future logger, a test assertion printed
/// on failure), so the redaction is added in the same change that widens it.
/// `pub` (widened from `pub(crate)` for round 7c D-F7): a cross-crate test
/// harness scripting a `KeychainExecutor::find` result needs to name a
/// variant of this enum. `Debug` stays redacted (below) regardless of
/// visibility, so the exposure this comment originally guarded against
/// (a future logger, a test assertion printed on failure) remains covered.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, PartialEq, Eq)]
pub enum RawContentClassification {
    /// `security` completed and reported `SECURITY_ITEM_NOT_FOUND` (exit
    /// 44) — and ONLY that exit. Nothing exists to merge with or destroy;
    /// safe to create fresh.
    Absent,
    /// A COMPLETE, non-empty, successfully decoded (raw JSON or legacy hex)
    /// payload that parses as a JSON OBJECT. Safe to read and merge with.
    Content(String),
    /// Every other case: spawn failure/timeout, an INCOMPLETE stdout
    /// capture (BUG-R3-1/F6), a non-44 failure exit, non-UTF-8 bytes, bad
    /// hex, an empty payload, or content that decodes but is not a JSON
    /// object (or does not parse as JSON at all). The item's real state is
    /// UNKNOWN — MUST NOT be treated as either `Absent` or `Content`; a
    /// caller about to WRITE or DELETE based on this classification MUST
    /// fail closed instead (C1). F5/KC4-7: carries [`UnreadableKind`] so a
    /// LAUNCH-TIME caller can pick a more specific operator message for
    /// "a stale item exists and the keychain is locked" ([`UnreadableKind::Inaccessible`])
    /// versus a generic "busy or unavailable, retry" ([`UnreadableKind::Transient`]) —
    /// S5: every caller (launch, the ordinary sync path, `csq swap`) now
    /// REFUSES on both kinds; the distinction is message-only, per C1's
    /// original fail-closed contract.
    Unreadable(UnreadableKind),
}

impl fmt::Debug for RawContentClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RawContentClassification::Absent => write!(f, "Absent"),
            RawContentClassification::Content(_) => {
                f.debug_tuple("Content").field(&"[REDACTED]").finish()
            }
            RawContentClassification::Unreadable(kind) => {
                f.debug_tuple("Unreadable").field(kind).finish()
            }
        }
    }
}

/// Pure classifier from a completed (or absent) `security
/// find-generic-password -w` invocation to [`RawContentClassification`] —
/// unit-testable with a synthetic [`BoundedOutput`], mirroring
/// [`classify_expiry_output`]'s shape and the same defenses: only exit 44
/// is `Absent`; an incomplete capture, an empty payload, or content that
/// fails to decode/parse as a JSON object is `Unreadable`, never silently
/// treated as "nothing here" or "here is its content".
// Platform-independent pure classifier — unconditional so it compiles and
// its tests run on every platform; its only PRODUCTION caller is still
// macOS-gated, so it is genuinely unused in a non-test, non-macOS build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn classify_raw_content(output: Option<BoundedOutput>) -> RawContentClassification {
    let bo = match output {
        Some(bo) => bo,
        None => return RawContentClassification::Unreadable(UnreadableKind::Transient),
    };
    if !bo.output.status.success() {
        return match bo.output.status.code() {
            Some(SECURITY_ITEM_NOT_FOUND) => RawContentClassification::Absent,
            // F3/F4 (owner decision, "switch now or say so", 2026-09-26):
            // exit 36 (`errSecInteractionNotAllowed`) is the ONLY completed
            // exit this classifies `Inaccessible` — measured live (see
            // `SECURITY_ERR_INTERACTION_NOT_ALLOWED`'s doc). Every other
            // completed-but-failed exit, AND a signal-terminated child
            // (`code()` is `None` on Unix, which the wildcard arm below
            // also catches — a signal death tells us nothing about whether
            // CC could read the same item), is `Transient`: refuse the
            // launch rather than proceed on an unmeasured code.
            Some(SECURITY_ERR_INTERACTION_NOT_ALLOWED) => {
                RawContentClassification::Unreadable(UnreadableKind::Inaccessible)
            }
            _ => RawContentClassification::Unreadable(UnreadableKind::Transient),
        };
    }
    if !bo.stdout_complete {
        return RawContentClassification::Unreadable(UnreadableKind::Transient);
    }
    let Ok(raw) = String::from_utf8(bo.output.stdout) else {
        return RawContentClassification::Unreadable(UnreadableKind::Transient);
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return RawContentClassification::Unreadable(UnreadableKind::Transient);
    }
    let json = if raw.starts_with('{') {
        raw.to_string()
    } else {
        let Ok(bytes) = hex::decode(raw) else {
            return RawContentClassification::Unreadable(UnreadableKind::Transient);
        };
        match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return RawContentClassification::Unreadable(UnreadableKind::Transient),
        }
    };
    match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(serde_json::Value::Object(_)) => RawContentClassification::Content(json),
        // Parses as something other than a JSON object, or fails to parse
        // at all — neither is a known "safe to merge with" shape.
        _ => RawContentClassification::Unreadable(UnreadableKind::Transient),
    }
}

/// Every top-level key EXCEPT `claudeAiOauth` from a decoded JSON-object
/// payload — the sibling set BUG-R3-2/F4 exist to preserve. `json` MUST
/// already be known to parse as a JSON object (e.g. via
/// [`RawContentClassification::Content`]); a payload that does not is
/// treated as having no siblings, never as an error here — the CALLER is
/// responsible for having already classified it.
// Platform-independent pure sibling extractor — unconditional so it compiles and
// its tests run on every platform; its only PRODUCTION caller is still
// macOS-gated, so it is genuinely unused in a non-test, non-macOS build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn extract_sibling_object(json: &str) -> serde_json::Map<String, serde_json::Value> {
    match serde_json::from_str::<serde_json::Value>(json) {
        Ok(serde_json::Value::Object(mut obj)) => {
            obj.remove("claudeAiOauth");
            obj
        }
        _ => serde_json::Map::new(),
    }
}

/// The account-scoped classification of `config_dir`'s keychain item — the
/// single `security find-generic-password -s <svc> -a <account> -w` read,
/// classified via [`classify_raw_content`]. v3 ("touch only Claude Code's
/// own item"): every read/write/delete site in this module targets exactly
/// ONE `(service, account)` pair — there is no `-a`-less generic read and
/// no enumeration of sibling/duplicate items anywhere in this file
/// (doc-property-claims.md MUST-4: a prior revision of this doc described
/// a pre-v3 "read every account" design this fn was never part of —
/// stale prose surviving a design replacement, not a description of what
/// this fn does).
#[cfg(target_os = "macos")]
fn raw_content_for(config_dir: &Path) -> RawContentClassification {
    let svc = service_name(config_dir);
    // R7-10 parity: the harvest must read the SAME item the mirror writes and
    // CC reads — the account `csq run`/`csq exec` recorded for this dir, not
    // this process's own derivation (the daemon's USER can differ from the
    // terminal's).
    let account = keychain_account_for(config_dir);
    // `keychain-fix-r8d.md` item 3 (C-F4): a test-installed scripted executor
    // takes priority over the real `security` subprocess, exactly like
    // `force_sync_account_changed`/`reconcile_keychain_to_marker`'s own
    // override check — see `test_keychain_executor_override`'s doc. Without
    // this, `harvest_account_candidates` (this fn's only caller, via
    // `read_raw_keychain` → `read_complete_keychain_content`) called
    // `run_security_bounded` directly, which is UNCONDITIONALLY `None` under
    // `cfg!(test)`/`test-utils` regardless of any installed override — so no
    // test could ever drive a harvest candidate with real content at all,
    // structurally, no matter what `security` state a test tried to script.
    #[cfg(any(test, feature = "test-utils"))]
    if let Some(exec) = test_keychain_executor_override() {
        return exec.find(&svc, &account);
    }
    let output = run_security_bounded(
        &["find-generic-password", "-s", &svc, "-a", &account, "-w"],
        None,
    );
    classify_raw_content(output)
}

/// Non-macOS: no OS keychain item exists at all (CC reads the file directly
/// there), so there is genuinely nothing to read — mirrors
/// [`keychain_expiry_ms`]'s own non-macOS stub, which returns the same
/// "nothing here" fact via `KeychainExpiryRead::NotFound`. Its own only
/// production caller ([`read_complete_keychain_content`]) is macOS-gated,
/// so this non-macOS stub is currently unreachable in a non-test build too.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn raw_content_for(_config_dir: &Path) -> RawContentClassification {
    RawContentClassification::Absent
}

/// Bounded, COMPLETENESS-checked read of the raw credential JSON in
/// `config_dir`'s keychain item — `Some` only for
/// [`RawContentClassification::Content`]; `None` for `Absent` or
/// `Unreadable` alike (this collapsed `Option` is what [`read_raw_keychain`]
/// — a read-only harvest caller with no write/delete decision to make safe
/// — actually needs; `write_raw` and [`force_sync_account_changed`] read
/// the SAME single `(service, account)` pair, via their own equivalent
/// exact-account [`KeychainExecutor::find`] call, since they MUST
/// distinguish `Absent` from `Unreadable` to decide whether writing or
/// deleting is safe — never a second, different account).
#[cfg(target_os = "macos")]
fn read_complete_keychain_content(config_dir: &Path) -> Option<String> {
    match raw_content_for(config_dir) {
        RawContentClassification::Content(s) => Some(s),
        RawContentClassification::Absent | RawContentClassification::Unreadable(_) => None,
    }
}

/// Bounded read of the raw credential JSON in `config_dir`'s keychain item.
/// Distinct from [`read`] (which parses into a `CredentialFile`) — the
/// harvest needs the raw bytes to re-write verbatim. Delegates to
/// [`read_complete_keychain_content`], which is the shared completeness-safe
/// primitive (BUG-R3-1).
#[cfg(target_os = "macos")]
fn read_raw_keychain(config_dir: &Path) -> Option<String> {
    read_complete_keychain_content(config_dir)
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

/// Per-call bound when the operator is present to answer a macOS password
/// dialog: used only inside [`with_interactive_keychain`].
/// [`KEYCHAIN_OP_TIMEOUT`] would kill the `security` call before a person can
/// type a password, leaving an orphaned dialog and a "could not be read"
/// result.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
const KEYCHAIN_INTERACTIVE_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The per-call `security` bound. The long bound applies ONLY inside the
/// explicit [`with_interactive_keychain`] scope (`in_interactive_scope`); a
/// process that merely has a terminal on stdin keeps [`KEYCHAIN_OP_TIMEOUT`],
/// so an unrelated stalled call never holds a lock for a minute.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
fn security_op_timeout(in_interactive_scope: bool) -> std::time::Duration {
    if in_interactive_scope {
        KEYCHAIN_INTERACTIVE_OP_TIMEOUT
    } else {
        KEYCHAIN_OP_TIMEOUT
    }
}

/// Poll interval for [`run_security_bounded`]'s `try_wait` loop. Small enough
/// that the loop's own granularity is negligible against
/// [`KEYCHAIN_OP_TIMEOUT`] (5s / 20ms = 250 polls in the worst case), large
/// enough that idle-polling a `security` call in flight costs no measurable
/// CPU.
// L1: only referenced from `run_bounded`, which the `any(test, feature =
// "test-utils")` build of `run_security_bounded` never calls (it hits the
// tripwire instead) — a plain `--lib --features test-utils` check (no
// `--test`, so `mod tests` is absent too) would otherwise flag this dead.
#[cfg(target_os = "macos")]
#[cfg_attr(any(test, feature = "test-utils"), allow(dead_code))]
const SECURITY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(20);

/// Minimum grace window `run_bounded` gives the reader threads to deliver
/// their buffers AFTER the awaited process has exited, independent of how
/// much of the overall `timeout` remains at that instant (BUG-R3-1: the
/// `try_wait` poll loop only checks the deadline BEFORE sleeping, so a child
/// that exits during the final `SECURITY_POLL_INTERVAL` sleep can leave
/// `deadline.saturating_duration_since(now)` at effectively zero — the
/// reader is then given no time at all to report a payload it may have
/// already fully read). `security` forks no descendants, so EOF follows its
/// own exit almost immediately; this floor absorbs that race without
/// re-arming an unbounded wait. Overall worst-case wall clock for
/// `run_bounded` is therefore `timeout + MIN_POST_EXIT_GRACE`, not `timeout`.
#[cfg(target_os = "macos")]
#[cfg_attr(any(test, feature = "test-utils"), allow(dead_code))]
const MIN_POST_EXIT_GRACE: std::time::Duration = std::time::Duration::from_millis(250);

/// The result of [`run_bounded`]: the captured [`std::process::Output`] plus
/// whether each pipe's reader thread delivered a COMPLETE (EOF-terminated)
/// capture before its grace window expired. A caller that only inspects
/// `output.status` (a delete/write-confirmation call) may ignore the
/// completeness flags; a caller that PARSES `output.stdout` as content (a
/// credential payload) MUST treat `stdout_complete == false` as "unknown
/// content", never as a (possibly empty or truncated) real payload —
/// BUG-R3-1: this distinction did not exist before, so an incomplete capture
/// on the normal-exit path could read as `NoExpiry` (write-allowed) instead
/// of `CouldNotAsk`.
// Platform-independent pure data carrier (process::Output wrapper) — unconditional so it compiles and
// its tests run on every platform; its only PRODUCTION caller is still
// macOS-gated, so it is genuinely unused in a non-test, non-macOS build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct BoundedOutput {
    pub(crate) output: std::process::Output,
    pub(crate) stdout_complete: bool,
    /// Tracked for symmetry with `stdout_complete` and potential future
    /// stderr-diagnostic use (e.g. surfacing a partial `errSec…` reason);
    /// no current caller reads it, since none parses `stderr` as content.
    #[allow(dead_code)]
    pub(crate) stderr_complete: bool,
}

/// Deliberately does NOT derive `Debug` (`credential-type-hygiene.md` Rule 1
/// — same reasoning as [`KeychainRead`]'s manual impl): `output.stdout` may
/// hold a credential payload. Redact it; the status and completeness flags
/// carry no secret material.
#[cfg(target_os = "macos")]
impl fmt::Debug for BoundedOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedOutput")
            .field("status", &self.output.status)
            .field("stdout", &"[REDACTED]")
            .field("stderr", &"[REDACTED]")
            .field("stdout_complete", &self.stdout_complete)
            .field("stderr_complete", &self.stderr_complete)
            .finish()
    }
}

/// Run a `security` subprocess bounded by [`KEYCHAIN_OP_TIMEOUT`]. Returns the
/// captured output, or `None` on spawn failure OR timeout. On timeout the child
/// is SIGKILLed so a hung `security` (locked keychain) cannot leak. `stdin` is
/// `None` for every caller except `add()`'s `security -i` invocation (an internal ticket):
/// `/dev/null` when absent, so `security` never blocks reading a prompt; the
/// caller-supplied bytes (written then closed, signalling EOF) when present.
///
/// **The property that actually holds across this fn's 10 call sites, 6
/// distinct callers (`doc-property-claims.md` MUST-1 — stated precisely
/// rather than as the single word "skip", which is false for most of them,
/// or as "always safe", which was false for [`keychain_expiry_ms`] before
/// BUG-2's fix; re-enumerated after the kc-simplify-brief v3 redesign
/// removed the two duplicate-account call sites this list used to name):
/// no caller EVER reads `None` — "could not complete the ask" — as though
/// it were `Some(output)` from a completed invocation. But "not conflated
/// with a completed ask" does NOT mean every caller's downstream
/// disposition of `None` is safe on its own terms — see the fourth bullet,
/// where it used to mean WRITE (an overwrite risk) and now correctly means
/// SKIP:
/// - **Discarded / best-effort skip**: [`read_raw_keychain`] (harvest loop
///   logs a fixed tag and `continue`s) — the one call site where "skip" is
///   literally accurate.
/// - **Classified via [`classify_raw_content`], folded into
///   [`ForcedSyncResult::Unreadable`]**: [`force_sync_account_changed_with_executor`]'s
///   single read of X returns `Unreadable` directly on a `None` here — the
///   caller (A1: abort the switch; A2: proceed without a mirror) decides
///   what it means; this function performs zero mutations either way.
/// - **Converted to an `Err`**: [`read_impl`] and `write_raw`'s two calls
///   (the single-item read feeds [`plan_mirror_write`], which reads
///   `Unreadable` as `PlanError::Unreadable`; the update call
///   `.ok_or_else(..)` a `PlatformError::Keychain` directly).
/// - **Classified into `KeychainExpiryRead::CouldNotAsk`, which
///   [`decide_sync_action`] treats as UNKNOWN state, not absence**:
///   [`keychain_expiry_ms`] maps a `None` here to `CouldNotAsk`, and
///   `keychain_is_fresher_or_equal_or_unknown` reads `CouldNotAsk` as
///   "SKIP the write" (don't clobber possibly-fresher unknown state) — the
///   OPPOSITE of the pre-BUG-2 behaviour, which propagated `None` as
///   `Option<u64>::None` and read it as "nothing for the file token to lose
///   to", i.e. WRITE. That was the bug: a keychain the ask could not even
///   reach was treated identically to a keychain confirmed empty.
/// - **Retried, then folded into `Err(KeychainClearUnconfirmed)`**:
///   [`delete_service_retrying`]'s two calls feed [`drain_service_inner`],
///   whose `_ => Err(..)` arm treats an unresolved `None` as "needs retry"
///   (the logout-adjacent drain path, out of the kc-simplify-brief's
///   scope).
///
/// Outside this module, `providers::codex::keychain`'s `run_security_find`
/// and `run_security_delete` also call this fn; both map `None` to
/// `SecurityExit::Error` (a failed probe or purge, reported as such), never
/// to a completed ask.
#[cfg(all(target_os = "macos", any(test, feature = "test-utils")))]
pub(crate) fn run_security_bounded(args: &[&str], stdin: Option<Vec<u8>>) -> Option<BoundedOutput> {
    // Test/hermetic guard — never shell `security` against the operator's real
    // login keychain from a test. Reads/deletes degrade to "unavailable" (None);
    // `write_raw` short-circuits to Ok separately so it reports a clean no-op.
    if keychain_mirror_disabled() {
        return None;
    }
    // `stdin` is deliberately unused on this branch: the tripwire panics
    // before any bytes would be written, and the panic message must never be
    // built from a payload this fn was handed (S-LOW-3) — dropping it here,
    // unread, is itself part of that guarantee.
    drop(stdin);
    real_security_spawn_tripwire(args)
}

#[cfg(all(target_os = "macos", not(any(test, feature = "test-utils"))))]
pub(crate) fn run_security_bounded(args: &[&str], stdin: Option<Vec<u8>>) -> Option<BoundedOutput> {
    // Test/hermetic guard — never shell `security` against the operator's real
    // login keychain from a test. Reads/deletes degrade to "unavailable" (None);
    // `write_raw` short-circuits to Ok separately so it reports a clean no-op.
    if keychain_mirror_disabled() {
        return None;
    }
    // A LOCKED default keychain makes `security` raise macOS's interactive
    // "security wants to use the login keychain" unlock dialog — one per
    // call. When nobody is there to answer it the calls queue while the
    // screen is locked and all appear at unlock. So a NON-interactive caller
    // asks the Security framework for the lock state first (that query shows
    // no UI) and, if locked, answers "could not ask" (`None`), which no caller
    // conflates with a completed ask (see this fn's contract above): reads
    // become unknown/skip, writes a retryable error, drains stay queued.
    //
    // Non-interactive = the process DECLARED itself background
    // (`declare_background_keychain_process`: the daemon in every start mode,
    // and the desktop app, which hosts the daemon in-process), or it is a
    // plain CLI invocation whose stdin is not a terminal (automation). A CLI
    // command run at a terminal keeps the prompt — the operator asked for it
    // — and so does any call made inside `with_interactive_keychain` (the
    // desktop's user-initiated logout and Codex login).
    //
    // Skipped work is caught up by the daemon: its refresher re-runs the
    // keychain sweep on the first tick after the keychain stops reading as
    // locked (`keychain_catch_up_due`). When the lock state cannot be read,
    // behaviour is unchanged (we proceed).
    use std::io::IsTerminal;
    let in_interactive_scope = interactive_scope_active();
    // Lock-deferral concept (unchanged): may a password/unlock dialog be
    // raised at all? Distinct from the timeout choice below.
    let interactive =
        in_interactive_scope || (!process_declared_background() && std::io::stdin().is_terminal());
    if should_defer_for_locked_keychain(interactive, || {
        keychain_lock_state(bounded_default_keychain_lock_probe)
    }) {
        note_keychain_deferral();
        return None;
    }
    let mut cmd = std::process::Command::new("security");
    cmd.args(args);
    run_bounded(cmd, security_op_timeout(in_interactive_scope), stdin)
}

/// Whether the default (login) keychain is locked, as far as csq can tell
/// without prompting.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeychainLockState {
    Locked,
    Unlocked,
    /// The status could not be read; callers proceed as before.
    Unknown,
}

/// Raw probe result: `Some(status_bits)` from `SecKeychainGetStatus`, or
/// `None` when the default keychain or its status could not be obtained.
/// Injected so the classification is testable without the real keychain.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
pub(crate) type KeychainStatusProbe = fn() -> Option<u32>;

/// `kSecUnlockStateStatus` from `SecKeychain.h`: set when the keychain is
/// unlocked.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
const K_SEC_UNLOCK_STATE_STATUS: u32 = 1;

#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
pub(crate) fn keychain_lock_state(probe: KeychainStatusProbe) -> KeychainLockState {
    match probe() {
        Some(bits) if bits & K_SEC_UNLOCK_STATE_STATUS != 0 => KeychainLockState::Unlocked,
        Some(_) => KeychainLockState::Locked,
        None => KeychainLockState::Unknown,
    }
}

/// True when a keychain call should be skipped rather than allowed to prompt:
/// only for a NON-interactive process, and only when the keychain is
/// confirmed locked. The lock state is read lazily, so an interactive process
/// never pays for the probe.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
pub(crate) fn should_defer_for_locked_keychain(
    interactive: bool,
    lock_state: impl FnOnce() -> KeychainLockState,
) -> bool {
    !interactive && lock_state() == KeychainLockState::Locked
}

/// Set when a keychain call in THIS process was skipped because the keychain
/// was locked; read and cleared by [`keychain_catch_up_due`] so the daemon
/// redoes the skipped mirroring once the keychain is unlocked rather than
/// waiting for the account's next token refresh.
#[cfg(target_os = "macos")]
static KEYCHAIN_DEFERRED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
fn note_keychain_deferral() {
    // Log once per locked episode at info, not once per call.
    if !KEYCHAIN_DEFERRED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        tracing::info!(
            error_kind = "keychain_locked_deferred",
            "keychain is locked; deferring keychain updates without prompting until it is unlocked"
        );
    }
}

/// Set once at startup by a process that must never raise the keychain
/// unlock dialog: the daemon (foreground, supervised, background) and the
/// desktop app (which runs the daemon in-process). See
/// [`run_security_bounded`].
static PROCESS_KEYCHAIN_BACKGROUND: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Declare this process a background keychain user (never prompt while the
/// keychain is locked; defer instead). Call once at process start.
pub fn declare_background_keychain_process() {
    PROCESS_KEYCHAIN_BACKGROUND.store(true, std::sync::atomic::Ordering::SeqCst);
}

#[cfg_attr(
    any(not(target_os = "macos"), feature = "test-utils"),
    allow(dead_code)
)]
fn process_declared_background() -> bool {
    PROCESS_KEYCHAIN_BACKGROUND.load(std::sync::atomic::Ordering::SeqCst)
}

/// Upper bound on the lock-state probe (`security.md` §6: every keychain
/// call has a timeout path). The Security framework answers a status query
/// in well under a millisecond normally; if it does not answer within this
/// bound the state is Unknown, which proceeds under the old (itself bounded)
/// behaviour. A probe thread stranded by a hang is left to finish on its own.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
const KEYCHAIN_LOCK_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
fn bounded_default_keychain_lock_probe() -> Option<u32> {
    bounded_probe(default_keychain_lock_probe, KEYCHAIN_LOCK_PROBE_TIMEOUT)
}

/// At most one lock probe is in flight per process, so a keychain service
/// that stops answering strands ONE helper thread, not one per call.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
static PROBE_IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
fn bounded_probe(probe: fn() -> Option<u32>, timeout: std::time::Duration) -> Option<u32> {
    bounded_probe_with(&PROBE_IN_FLIGHT, probe, timeout)
}

/// Runs `probe` on a helper thread and waits at most `timeout`; `None` (an
/// Unknown lock state) if it does not answer in time, or — without spawning —
/// if a previous probe is still in flight (`in_flight` set). The helper
/// clears `in_flight` once its probe returns.
#[cfg(target_os = "macos")]
fn bounded_probe_with(
    in_flight: &'static std::sync::atomic::AtomicBool,
    probe: fn() -> Option<u32>,
    timeout: std::time::Duration,
) -> Option<u32> {
    use std::sync::atomic::Ordering;
    if in_flight
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return None;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("csq-keychain-lock-probe".into())
        .spawn(move || {
            let result = probe();
            in_flight.store(false, Ordering::SeqCst);
            let _ = tx.send(result);
        });
    if spawned.is_err() {
        in_flight.store(false, Ordering::SeqCst);
        return None;
    }
    rx.recv_timeout(timeout).ok().flatten()
}

thread_local! {
    static INTERACTIVE_SCOPE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Run `f` as an operation the user explicitly asked for (e.g. a desktop
/// logout or Codex login): keychain calls made on THIS thread inside `f` may
/// raise the unlock dialog even in a process declared background. Wrap the
/// synchronous body on the thread that performs the keychain call — inside
/// any `spawn_blocking`, never around an `.await`.
pub fn with_interactive_keychain<T>(f: impl FnOnce() -> T) -> T {
    struct Exit;
    impl Drop for Exit {
        fn drop(&mut self) {
            INTERACTIVE_SCOPE.with(|c| c.set(c.get().saturating_sub(1)));
        }
    }
    INTERACTIVE_SCOPE.with(|c| c.set(c.get() + 1));
    let _exit = Exit;
    f()
}

#[cfg_attr(
    any(not(target_os = "macos"), feature = "test-utils"),
    allow(dead_code)
)]
fn interactive_scope_active() -> bool {
    INTERACTIVE_SCOPE.with(|c| c.get() > 0)
}

/// Last lock state the daemon's refresher observed (true = locked), used to
/// detect the locked -> unlocked transition regardless of WHICH process
/// skipped work while it was locked.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
static LAST_SEEN_LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True when the daemon should re-run its keychain sweep now: either this
/// process deferred a call while the keychain was locked and it is now
/// unlocked, or the keychain went from locked to not-locked since the last
/// check (another process — a `csq run` from automation — may have skipped
/// its launch-time mirror during that time). Probes the lock state once.
/// Test builds never probe the real keychain: this returns false there.
#[cfg(all(target_os = "macos", not(any(test, feature = "test-utils"))))]
pub(crate) fn keychain_catch_up_due() -> bool {
    let state = keychain_lock_state(bounded_default_keychain_lock_probe);
    catch_up_due_with(&KEYCHAIN_DEFERRED, &LAST_SEEN_LOCKED, state)
}

#[cfg(all(target_os = "macos", any(test, feature = "test-utils")))]
pub(crate) fn keychain_catch_up_due() -> bool {
    false
}

/// Pure decision for [`keychain_catch_up_due`], testable without a keychain.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
fn catch_up_due_with(
    deferred: &std::sync::atomic::AtomicBool,
    last_locked: &std::sync::atomic::AtomicBool,
    state: KeychainLockState,
) -> bool {
    use std::sync::atomic::Ordering;
    let locked = state == KeychainLockState::Locked;
    let was_locked = last_locked.swap(locked, Ordering::SeqCst);
    if locked {
        return false;
    }
    let had_deferral = deferred.swap(false, Ordering::SeqCst);
    had_deferral || was_locked
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn keychain_catch_up_due() -> bool {
    false
}

/// Reads the default keychain's status bits via `SecKeychainCopyDefault` +
/// `SecKeychainGetStatus`. These report state rather than request access
/// (unlike `security find-generic-password`, which asks the user to unlock a
/// locked keychain); measured on the maintainer host 2026-10-02 against an
/// unlocked login keychain: status `0b111`, no dialog. The keychain reference
/// is released on every path that obtained one.
///
/// The DEFAULT keychain is the proxy because csq never passes a keychain
/// path: `security add-generic-password` writes to the default keychain, and
/// on a standard macOS account the default keychain is the login keychain
/// that holds Claude Code's items. On an account whose default keychain is
/// some other, locked keychain, csq's background keychain calls are skipped
/// until it is unlocked.
// Test builds never reach the real chokepoint (the tripwire variant runs
// instead), so the real probe is unused there by design.
#[cfg(target_os = "macos")]
#[cfg_attr(any(test, feature = "test-utils"), allow(dead_code))]
pub(crate) fn default_keychain_lock_probe() -> Option<u32> {
    use std::ffi::c_void;
    #[link(name = "Security", kind = "framework")]
    extern "C" {
        fn SecKeychainCopyDefault(keychain: *mut *mut c_void) -> i32;
        fn SecKeychainGetStatus(keychain: *mut c_void, status: *mut u32) -> i32;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(cf: *const c_void);
    }
    let mut keychain: *mut c_void = std::ptr::null_mut();
    // SAFETY: out-pointer to a local; on success the callee stores a +1
    // retained SecKeychainRef that we release below.
    let rc = unsafe { SecKeychainCopyDefault(&mut keychain) };
    if rc != 0 || keychain.is_null() {
        return None;
    }
    let mut status: u32 = 0;
    // SAFETY: `keychain` is the non-null reference obtained above; `status`
    // is a local out-pointer.
    let rc = unsafe { SecKeychainGetStatus(keychain, &mut status) };
    // SAFETY: balances the +1 from SecKeychainCopyDefault exactly once.
    unsafe { CFRelease(keychain as *const c_void) };
    if rc != 0 {
        return None;
    }
    Some(status)
}

/// L1 tripwire (`instrument-discipline.md` MUST-2 / `guard-reader-writer-parity.md`
/// MUST-4): proves — by CRASHING, not by depending on a specific keychain
/// state's outcome to happen to reveal it — that no test reaches a real
/// `security` spawn. Gated on the SAME conditions
/// [`keychain_mirror_disabled`] treats as "we are in a context that must
/// never touch the real login keychain" (`cfg!(test) || cfg!(feature =
/// "test-utils")`) — so it also holds for `csq-core/tests/*` integration
/// binaries, which never carry `cfg(test)` on the LIBRARY crate they link
/// against (only the test binary itself does) but DO carry
/// `feature = "test-utils"` under every documented/CI invocation
/// (`.github/workflows/test.yml`'s `cargo test --workspace --test '*'
/// --features csq/test-utils,csq-core/test-utils`). An integration run that
/// omits `--features csq-core/test-utils` is NOT covered by this — that
/// build is compile-time indistinguishable from production, and this
/// tripwire must never fire in production (where a real `security` spawn is
/// the whole point).
/// S-LOW-3: prints ONLY `args[0]` (the `security` subcommand, e.g.
/// `"find-generic-password"`) — never the full `args` slice, in case some
/// future caller's argv does carry sensitive material. `add()`'s own call
/// shape is now (an internal ticket) always `["-i"]` — the credential travels hex-encoded
/// on stdin, never on argv — but this fn's own message-construction
/// discipline is pinned unconditionally rather than assumed safe by that
/// fact alone: a panic message built from `{args:?}` would print anything
/// argv DID carry in plaintext into the test failure output (a terminal, a
/// CI log) the moment this tripwire ever fires — exactly the class this fn
/// exists to catch, wearing a leak of its own.
#[cfg(all(target_os = "macos", any(test, feature = "test-utils")))]
fn real_security_spawn_tripwire(args: &[&str]) -> ! {
    let subcommand = args.first().copied().unwrap_or("<empty>");
    panic!(
        "run_security_bounded reached a REAL `security {subcommand}` spawn \
         under test — the keychain_mirror_disabled() guard should have \
         short-circuited before this point; this IS the hermeticity gap \
         this tripwire exists to catch, not a false positive to work around"
    );
}

/// Bounded runner factored out of [`run_security_bounded`] (BUG-A) so the
/// wall-clock bound is testable with `sh`/`sleep` instead of the real
/// `security` binary. `security` writes its diagnostics to stderr, not
/// stdout (callers redact before logging — security.md §2); both pipes are
/// captured so a write failure's actual `errSec…` reason can be surfaced.
///
/// **The bug this fixes.** A command that itself exits within `timeout` can
/// still leave a DESCENDANT holding its stdout/stderr pipes open — e.g.
/// `sh -c 'work & sleep 30'` backgrounds a grandchild that inherits the
/// pipes. The immediate post-BUG-3 version joined the reader threads
/// UNCONDITIONALLY on every return path, and a join waits for pipe EOF —
/// which does not happen until EVERY holder of the write end closes it, not
/// merely the awaited process. Killing `security` does not close a pipe a
/// descendant still holds. Measured against a verbatim copy of that loop
/// with a 500ms timeout: `sh -c 'sleep 4 & sleep 30'` returned after 30.02s
/// (the timeout path, silently unbounded) and `sh -c 'sleep 4 & exit 0'`
/// after 4.03s (the normal-exit path, also silently unbounded).
///
/// **The fix.** The reader threads send their collected buffer over a
/// channel ONLY once `read_to_end` returns (i.e. once the pipe they hold
/// finally closes — which may be arbitrarily late). This fn never blocks on
/// that: it awaits the CHILD via `try_wait` up to `timeout`, then drains
/// each channel with `recv_timeout` bounded by a shared exit-deadline — the
/// remaining time on the ORIGINAL deadline, floored at
/// [`MIN_POST_EXIT_GRACE`] (BUG-R3-1: without the floor, a child that exits
/// during the poll loop's final sleep leaves near-zero remaining time, so
/// the `Ok(Some(status)) => break` arm's caller would get no real chance to
/// receive a payload the reader may already have fully read). If a reader
/// has not finished by then, [`BoundedOutput::stdout_complete`] /
/// `stderr_complete` is `false` and its buffer is abandoned (empty/partial);
/// the `JoinHandle` is dropped without joining — the thread keeps running
/// detached and the OS reclaims it once the pipe eventually closes; there is
/// no safe way to cancel a blocked `read_to_end` short of closing the
/// underlying fd from another thread, which would risk the same kind of
/// recycled-resource race BUG-3 fixed for pids. Returns `None` on the
/// timeout path (nothing usable to report) and `Some(BoundedOutput)` — with
/// possibly empty/partial `stdout`/`stderr`, EXPLICITLY FLAGGED as such — on
/// the normal-exit path, so a caller still gets the exit status it needs
/// even when a descendant is holding a pipe open, without being able to
/// mistake an incomplete capture for a genuine (possibly empty) payload.
/// Overall worst-case wall clock: `timeout + MIN_POST_EXIT_GRACE`.
///
/// `Builder::spawn` (rather than the panicking `thread::spawn`) is used for
/// both readers: an OS thread-table-exhaustion panic there would otherwise
/// unwind past this fn and drop `child` un-killed/un-reaped — a leaked,
/// possibly still-running process.
///
/// Pure decision for one pipe's `recv_timeout` outcome (F6) — extracted
/// (round-5 testing pass, behaviour-preserving refactor; no change to
/// `run_bounded`'s externally observable behaviour) so the "an I/O error
/// is NOT a completed read" rule, otherwise reachable only by provoking a
/// genuine pipe failure from a real subprocess, is unit-testable directly.
/// `Err(RecvTimeoutError)` (timeout or the sender disconnected without
/// sending) and `Ok(Err(io_error))` (the reader thread's `read_to_end`
/// itself failed) both map to `(false, vec![])` — an I/O error is treated
/// exactly like an incomplete capture, never as "here is the (possibly
/// empty) real content". Only `Ok(Ok(buf))` is `(true, buf)`.
#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
fn classify_reader_recv(
    recv: Result<std::io::Result<Vec<u8>>, std::sync::mpsc::RecvTimeoutError>,
) -> (bool, Vec<u8>) {
    let complete = matches!(recv, Ok(Ok(_)));
    let buf = recv.ok().and_then(|r| r.ok()).unwrap_or_default();
    (complete, buf)
}

#[cfg(target_os = "macos")]
#[cfg_attr(feature = "test-utils", allow(dead_code))]
fn run_bounded(
    mut cmd: std::process::Command,
    timeout: std::time::Duration,
    stdin_data: Option<Vec<u8>>,
) -> Option<BoundedOutput> {
    use std::io::Read;
    use std::process::Stdio;
    use std::sync::mpsc;

    let deadline = std::time::Instant::now() + timeout;

    let mut child = cmd
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    // an internal ticket: write the stdin command line, THEN close the pipe (drop) so
    // `security -i` sees EOF and terminates its command-read loop instead of
    // blocking on stdin forever. Written from a detached thread — mirroring
    // the reader threads below — rather than inline, so a `security -i`
    // command that starts emitting output before it has consumed the whole
    // stdin buffer (unobserved in practice, but the readers already assume
    // nothing about ordering) cannot deadlock this thread against a full OS
    // pipe buffer on either side.
    //
    // an internal ticket round 2 (BUG-2, OBSERVED): the prior version discarded BOTH the
    // thread-spawn Result and `write_all`'s Result (`let _ = spawn(...)`,
    // `let _ = stdin_pipe.write_all(...)`) — a spawn failure silently
    // dropped the pipe with NOTHING written, and `security -i` reads EOF
    // with no commands as an empty (successful, exit 0) script; `add()`
    // would then read `status.success()` and report `Ok(())` with nothing
    // actually stored. Both outcomes are now tracked exactly like the
    // reader threads': a spawn failure kills+reaps the child and returns
    // `None` immediately; `write_all`'s Result is sent over a channel and
    // checked below (once the child has finished or timed out) — an error
    // OR the sender never firing (thread panicked, or genuinely still
    // blocked past a bounded grace) is treated as failure.
    let stdin_result_rx = match stdin_data {
        Some(data) => {
            let Some(mut stdin_pipe) = child.stdin.take() else {
                // `stdin_data.is_some()` means `stdin()` was set to
                // `Stdio::piped()` above, so `child.stdin` must be present;
                // its absence here is unreachable in practice but treated
                // as a failure rather than silently continuing without it.
                let _ = child.kill();
                let _ = child.wait();
                return None;
            };
            let (tx, rx) = mpsc::channel::<std::io::Result<()>>();
            match std::thread::Builder::new().spawn(move || {
                use std::io::Write;
                let result = stdin_pipe.write_all(&data);
                // `stdin_pipe` drops here regardless of outcome, closing
                // the fd (the EOF signal `security -i` needs to stop
                // reading commands) — sending the Result first would race
                // a reader that treats EOF-without-a-result the same as
                // failure, so the drop happening after `send` is load-
                // bearing: the receiver can rely on "sender fired" meaning
                // "the pipe is (or is about to be) closed".
                let _ = tx.send(result);
            }) {
                Ok(_handle) => Some(rx),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        }
        None => None,
    };

    // BUG-3 (kept): the `Child` stays owned by THIS thread for its whole
    // lifetime, so `child.kill()` below can never target a recycled pid —
    // `Child::kill`/`Child::wait` operate on the handle the OS gave us for
    // this exact process, never a bare pid number.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    // F6: the channel carries the `read_to_end` RESULT, not a bare `Vec<u8>`
    // — a prior version discarded the `Result` (`let _ = p.read_to_end(..)`)
    // and always sent the (possibly partial) buffer, so a genuine I/O error
    // on the pipe (not merely "still open") looked identical to a completed
    // read: `recv` succeeding was read as "complete" regardless of whether
    // `read_to_end` itself had actually succeeded.
    let (stdout_tx, stdout_rx) = mpsc::channel::<std::io::Result<Vec<u8>>>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<std::io::Result<Vec<u8>>>();

    let stdout_reader = std::thread::Builder::new().spawn(move || {
        let mut buf = Vec::new();
        let result = match stdout_pipe {
            Some(mut p) => p.read_to_end(&mut buf).map(|_| buf),
            None => Ok(buf),
        };
        let _ = stdout_tx.send(result);
    });
    let stderr_reader = std::thread::Builder::new().spawn(move || {
        let mut buf = Vec::new();
        let result = match stderr_pipe {
            Some(mut p) => p.read_to_end(&mut buf).map(|_| buf),
            None => Ok(buf),
        };
        let _ = stderr_tx.send(result);
    });
    let (stdout_handle, stderr_handle) = match (stdout_reader, stderr_reader) {
        (Ok(o), Ok(e)) => (o, e),
        // Reader-thread spawn failed — kill + reap the child explicitly so
        // it is never dropped un-killed/un-reaped, then give up.
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(SECURITY_POLL_INTERVAL);
            }
            Err(_) => break None,
        }
    };

    let status = match status {
        Some(status) => status,
        None => {
            // Timed out or try_wait errored — kill + reap the owned child.
            // The deadline has already elapsed, so the grace window below is
            // ~0: detach the readers (no join) and return `None` immediately
            // rather than waiting on a pipe a descendant may hold open.
            let _ = child.kill();
            let _ = child.wait();
            let grace = deadline.saturating_duration_since(std::time::Instant::now());
            let _ = stdout_rx.recv_timeout(grace);
            let _ = stderr_rx.recv_timeout(grace);
            drop(stdout_handle);
            drop(stderr_handle);
            return None;
        }
    };

    // The awaited process exited within the deadline, but a descendant it
    // forked may still hold the pipes open. Wait for the readers only up to
    // a shared exit-deadline — the REMAINING deadline floored at
    // `MIN_POST_EXIT_GRACE` (BUG-R3-1: without the floor, a child that exits
    // during the poll loop's LAST sleep leaves `grace` at ~0, giving the
    // reader no time at all even though it may have already read the full
    // payload) — so a held-open pipe degrades to a flagged-incomplete
    // buffer instead of blocking indefinitely. Computed ONCE and shared by
    // both reads (rather than re-flooring per pipe) so the two pipes cannot
    // add up to 2x the floor in the worst case.
    let exit_deadline = std::time::Instant::now()
        + deadline
            .saturating_duration_since(std::time::Instant::now())
            .max(MIN_POST_EXIT_GRACE);
    // `stdout_complete`/`stderr_complete` is true ONLY when `recv_timeout`
    // returned in time AND the inner `read_to_end` itself succeeded (F6) —
    // a genuine pipe I/O error is treated exactly like an incomplete
    // capture, never as "here is the (possibly empty) real content". The
    // decision itself lives in `classify_reader_recv`, unit-tested
    // directly against a synthetic `recv_timeout` result.
    let stdout_wait =
        stdout_rx.recv_timeout(exit_deadline.saturating_duration_since(std::time::Instant::now()));
    let (stdout_complete, stdout) = classify_reader_recv(stdout_wait);
    let stderr_wait =
        stderr_rx.recv_timeout(exit_deadline.saturating_duration_since(std::time::Instant::now()));
    let (stderr_complete, stderr) = classify_reader_recv(stderr_wait);
    // Do not join: a still-blocked reader cannot be safely cancelled (see
    // the fn doc); dropping the handle lets it finish in the background.
    drop(stdout_handle);
    drop(stderr_handle);

    // an internal ticket round 2 (BUG-2): the child already exited within the deadline
    // above, so if a stdin write was in flight it has necessarily either
    // completed or failed by now — `write_all` returns as soon as the
    // pipe's write end is fully drained or errors, and a child that has
    // exited is no longer draining it. The bounded wait here is therefore
    // not "hoping it finishes in time" the way the stdout/stderr reads are;
    // it exists only to bound the pathological case (thread scheduling
    // delay) rather than to race a still-legitimately-running writer.
    // Either the channel never fires (thread panicked, or the write is
    // somehow still not done) or it reports an I/O error: BOTH are treated
    // as failure, per the same "no result is not a completed success" rule
    // `classify_reader_recv` applies to the readers.
    if let Some(rx) = stdin_result_rx {
        match rx.recv_timeout(MIN_POST_EXIT_GRACE) {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return None,
        }
    }

    Some(BoundedOutput {
        output: std::process::Output {
            status,
            stdout,
            stderr,
        },
        stdout_complete,
        stderr_complete,
    })
}

/// Write `raw_json` into the keychain item CC reads for `config_dir`. Updates an
/// existing item's value in place (preserving the ACL CC set on it); creates an
/// absent item with all-apps read access (`-A`) so CC reads it without an
/// interactive ACL-grant prompt (which fails outright in non-GUI / daemon
/// sessions).
///
/// Uses the `security` CLI for parity with `read_impl` and because the `-A`
/// create path is not exposed by the `security-framework` high-level API.
///
/// **an internal ticket — the credential no longer travels via argv for a payload that
/// fits `security -i`'s stdin line.** It used to be passed as the literal
/// argument after `-w`, readable in any same-host process's `ps` output for
/// the life of the call — "same-user" does not make that acceptable
/// (`zero-tolerance.md` Rule 5's BLOCKED corpus names exactly that
/// rationalization). The write spawns `security -i` with argv `["-i"]` only
/// and feeds ONE command line — `add-generic-password -A -s <svc> -a
/// <account> -X <hex(payload)>` — on its stdin, hex-encoded; see
/// [`build_add_stdin_command`].
///
/// **an internal ticket (round 4, owner-accepted residual) — a payload too large for
/// that stdin line DOES fall back to argv,** byte-for-byte the pre-an internal ticket
/// v2.19 call shape minus `-U` (`add-generic-password -A -s <svc> -a <account> -w
/// <payload>`), so a user whose credential (with `mcpOAuth` siblings) makes
/// the payload exceed `security -i`'s measured line limit does not regress
/// to a refused write vs v2.19. See [`select_add_invocation`] for the
/// selection and a fixed-vocabulary `tracing::warn!` (`error_kind =
/// "keychain_add_argv_fallback_oversized"`) fires whenever this branch is
/// taken.
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
/// BUG-R3-2: Claude Code's own keychain write path is READ-MODIFY-WRITE, not
/// replace — `specs/01-cc-credential-architecture.md` (~line 249, quoting CC's
/// `utils/auth.ts:1194-1253`, examined at `0e5d0b24`): CC reads the existing
/// item into an object, sets ONLY `storageData.claudeAiOauth = {...}`, and
/// writes the whole object back. The item is therefore a multi-key object BY
/// DESIGN — other keys (e.g. an MCP OAuth token) may share it — and CC
/// preserves every sibling key on every write. csq's mirror previously wiped
/// the entire item on every sync, diverging from the reference client.
///
/// Builds the JSON string to WRITE into the keychain item (F4): the FILE's
/// `claudeAiOauth` value plus every sibling key already accumulated from the
/// EXISTING keychain item(s) — and NEVER any OTHER top-level key from
/// `file_raw_json` itself. Sibling keys belong to the config dir's keychain
/// item, not to the credential FILE, which may carry fields (e.g. its own
/// bookkeeping) with no business being mirrored into the keychain.
///
/// **F8 — `subscriptionType`/`rateLimitTier` backfill.** Anthropic's OAuth
/// token endpoint never returns these two fields; CC backfills them into
/// the credential on its own first API call, and — since CC reads/writes
/// the keychain directly — that backfill can land in the KEYCHAIN item's
/// `claudeAiOauth` WITHOUT ever round-tripping through csq's file store
/// (`refresh/sync.rs`'s backsync guard protects the FILE from losing an
/// already-known `subscription_type`, but has no visibility into a value
/// CC wrote straight to the keychain). Re-derived (F8): `write_raw` has
/// exactly one caller in this crate (`sync_handle_dir_inner`), so this is
/// not a "some callers" gap — every mirror write was exposed.
///
/// **v4 ("switch now or say so") — `backfill_allowed` is the caller's
/// `!account_changed`, a plain boolean, no marker involved.** The
/// account-changed path no longer goes through this function at all: a
/// binding change is handled exclusively by
/// [`force_sync_account_changed_with_executor`], which calls
/// [`plan_mirror_write`] directly with `backfill_allowed = false` — there is
/// no "existing" account whose subscription metadata could apply to a NEW
/// binding, full stop. This function's ONLY caller
/// (`write_raw_with_executor`) is therefore the ORDINARY (same-account)
/// path (K5), where backfill is always correct: X, if present, belongs to
/// the SAME account the file does, so its `subscriptionType`/`rateLimitTier`
/// are safe to carry forward. The prior marker-absence gate (S5, and before
/// it the refresh-token-equality proof, I8) existed only to distinguish
/// "same account" from "pending account change" — a distinction v4 removes
/// by never routing an account change through this function in the first
/// place.
// Platform-independent pure payload builder — unconditional so it compiles and
// its tests run on every platform; its only PRODUCTION caller is still
// macOS-gated, so it is genuinely unused in a non-test, non-macOS build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn build_write_payload(
    siblings: &serde_json::Map<String, serde_json::Value>,
    file_raw_json: &str,
    existing_claude_oauth: Option<&serde_json::Value>,
    backfill_allowed: bool,
) -> Result<String, PlatformError> {
    let file_value: serde_json::Value = serde_json::from_str(file_raw_json).map_err(|_| {
        PlatformError::Keychain("credential file payload is not valid JSON".to_string())
    })?;
    let mut claude_oauth = file_value.get("claudeAiOauth").cloned().ok_or_else(|| {
        PlatformError::Keychain("credential file payload has no claudeAiOauth".to_string())
    })?;
    if backfill_allowed {
        if let (Some(existing), Some(obj)) = (existing_claude_oauth, claude_oauth.as_object_mut()) {
            for field in ["subscriptionType", "rateLimitTier"] {
                let file_is_null_or_absent = obj.get(field).is_none_or(|v| v.is_null());
                if file_is_null_or_absent {
                    if let Some(existing_value) = existing.get(field) {
                        if !existing_value.is_null() {
                            obj.insert(field.to_string(), existing_value.clone());
                        }
                    }
                }
            }
        }
    }
    let mut obj = siblings.clone();
    obj.insert("claudeAiOauth".to_string(), claude_oauth);
    serde_json::to_string(&serde_json::Value::Object(obj)).map_err(|_| {
        PlatformError::Keychain("failed to serialize merged keychain payload".to_string())
    })
}

// ── keychain mirror WRITE — single-item read-modify-write (v3) ─────────
//
// v3 redesign (supersedes the read-all-then-drain-duplicates design).
// Six review rounds on that design each found a real sibling-loss /
// wrong-account bug, several introduced by the PREVIOUS round's fix.
// Root cause, re-derived (kc-simplify-brief): CC's own keychain read is an
// EXACT `(service, account)` lookup — `security find-generic-password -a
// "${username}" -w -s "${storageServiceName}"` (spec 01 ~line 162,
// confirmed against the INSTALLED 2.1.282 bundle's minified source in
// kc-simplify-brief Step 0, not just the 2.1.88 decompile). An item under
// any OTHER account name is therefore INVISIBLE to CC and can never shadow
// its read — draining duplicate-named items treated a symptom (a stale
// SIBLING item existing at all) rather than the actual cause (csq once
// writing under an account name CC would never look up). The fix is
// ACCOUNT-NAME PARITY (`keychain_account()` now derives the identical
// string CC's `getUsername()` does) plus touching EXACTLY the one item CC
// reads — no enumeration, no duplicate reads, no duplicate deletes.
//
// The planner (`plan_mirror_write`) is a PURE function over ONE already
// -classified read — it performs no I/O and no mutation. The executor
// (the macOS `write_raw` below) is the only place that shells `security`,
// and it always executes the plan's write. The write itself is
// delete-then-create inside the executor's `add` (never `-U`); the planner
// issues no delete of its own.

/// The planner's output for the single-item RMW write path: the JSON
/// payload to persist into X via `security -i`'s `add-generic-password -A
/// -s svc -a account -X <hex(write_x)>` (an internal ticket: hex-encoded on stdin,
/// never as an argv literal), issued by `KeychainExecutor::add` AFTER it
/// deletes the existing item — never `-U`, never an in-place update.
// Platform-independent pure plan type — unconditional so it compiles and
// its tests run on every platform; its only PRODUCTION caller is still
// macOS-gated, so it is genuinely unused in a non-test, non-macOS build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MirrorPlan {
    write_x: String,
}

/// Why [`plan_mirror_write`] refused to produce a plan. Either way the
/// caller performs ZERO mutations — the whole call fails closed.
// Platform-independent pure plan-error type — unconditional so it compiles and
// its tests run on every platform; its only PRODUCTION caller is still
// macOS-gated, so it is genuinely unused in a non-test, non-macOS build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum PlanError {
    /// X's read classified [`RawContentClassification::Unreadable`] — its
    /// sibling keys cannot be safely merged NOR safely assumed absent, so
    /// nothing may be written this call.
    Unreadable,
    /// `file_raw_json` was not usable (not valid JSON, or missing
    /// `claudeAiOauth`) — there is nothing safe to write.
    InvalidFilePayload(String),
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::Unreadable => {
                write!(
                    f,
                    "keychain item unreadable; write skipped (nothing was mutated)"
                )
            }
            PlanError::InvalidFilePayload(reason) => {
                write!(f, "credential file payload unusable: {reason}")
            }
        }
    }
}

/// Pure planner for the keychain mirror WRITE (S2) — read-modify-write over
/// ONE already-classified read of X, `config_dir`'s single keychain item.
/// Performs zero I/O and zero mutation; it only decides what the caller
/// should persist.
///
/// - [`RawContentClassification::Unreadable`] → `Err`: X's real state is
///   unknown, so nothing may be safely merged or overwritten (fail closed).
/// - [`RawContentClassification::Content`] → merge: X's sibling keys
///   survive; `claudeAiOauth` comes from `file_raw_json`.
/// - [`RawContentClassification::Absent`] → write the file's
///   `claudeAiOauth` only (no siblings to preserve).
///
/// `file_raw_json` is parsed and validated (valid JSON object carrying
/// `claudeAiOauth`) before any plan is produced. `backfill_allowed` is
/// `false` on the v4 account-changed path
/// ([`force_sync_account_changed_with_executor`]) and `true` on the
/// ordinary same-account path (`write_raw_with_executor`'s
/// `!account_changed`) — see [`build_write_payload`]'s doc for why.
// Platform-independent pure mirror-write planner — unconditional so it compiles and
// its tests run on every platform; its only PRODUCTION caller is still
// macOS-gated, so it is genuinely unused in a non-test, non-macOS build.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn plan_mirror_write(
    x: &RawContentClassification,
    file_raw_json: &str,
    backfill_allowed: bool,
) -> Result<MirrorPlan, PlanError> {
    let (siblings, existing_claude_oauth) = match x {
        RawContentClassification::Unreadable(_) => return Err(PlanError::Unreadable),
        RawContentClassification::Absent => (serde_json::Map::new(), None),
        RawContentClassification::Content(json) => {
            let siblings = extract_sibling_object(json);
            // An emptied login carries no identity, so it cannot prove it
            // belongs to the account being written: never backfill plan
            // metadata from it.
            let existing = serde_json::from_str::<serde_json::Value>(json)
                .ok()
                .and_then(|v| v.get("claudeAiOauth").cloned())
                .filter(|o| !oauth_tokens_both_empty(o));
            (siblings, existing)
        }
    };

    // `build_write_payload` parses + validates `file_raw_json` itself
    // (InvalidFilePayload on malformed JSON or a missing claudeAiOauth) —
    // no separate up-front parse is needed here now that this planner no
    // longer needs a standalone `file_claude_oauth` value (S5 dropped the
    // refresh-token-equality proof that used to consume it).
    let write_x = build_write_payload(
        &siblings,
        file_raw_json,
        existing_claude_oauth.as_ref(),
        backfill_allowed,
    )
    .map_err(|e| PlanError::InvalidFilePayload(e.to_string()))?;

    Ok(MirrorPlan { write_x })
}

/// S10 — the seam every `security` MUTATION on X in the write/clear paths
/// goes through, so a test can RECORD the exact `(verb, service, account)`
/// sequence a planner decision produces — not merely inspect its output.
/// Three verbs only; every keychain call `write_raw`/[`force_sync_account_changed`]
/// perform reduces to one of them.
///
/// `pub` (not `pub(crate)`): the round 7c D-F7 harness registers a scripted
/// implementation of this trait from the `csq` binary crate — a different
/// crate than this one — via [`set_test_keychain_executor`]. Visibility
/// alone does not weaken anything: implementing this trait grants no
/// capability a caller could not already exercise by shelling `security`
/// directly, and every setter that can INSTALL an implementation is itself
/// `#[cfg(any(test, feature = "test-utils"))]`, so none of this compiles
/// into a production binary.
#[cfg(target_os = "macos")]
pub trait KeychainExecutor {
    /// `security find-generic-password -s svc -a account -w`, classified
    /// via `classify_raw_content` (a private helper of this module's
    /// production `SecurityCliExecutor` implementation — a scripted
    /// implementation such as `ScriptedKeychainExecutor` returns its own
    /// caller-supplied classification directly).
    fn find(&self, svc: &str, account: &str) -> RawContentClassification;
    /// `security delete-generic-password -s svc -a account`, THEN `security
    /// -i`'s stdin `add-generic-password -A -s svc -a account -X
    /// <hex(payload)>` (an internal ticket — the credential travels hex-encoded on
    /// stdin, never as an argv literal). Never `-U`: Apple's `-U` on an
    /// existing item rewrites its access control and raises a password
    /// dialog, so a write is delete-then-create (see
    /// [`add_via_delete_create`]).
    fn add(&self, svc: &str, account: &str, payload: &str) -> Result<(), PlatformError>;
    /// [`KeychainExecutor::add`], plus: if the create fails after the item was
    /// deleted, ONE best-effort re-add of `siblings_only` (the caller's
    /// already-read previous content with `claudeAiOauth` removed; never the
    /// full previous content). The default ignores it; only the production
    /// executor, whose `add` deletes first, acts on it. No extra keychain read
    /// is made to compute it.
    fn add_restoring(
        &self,
        svc: &str,
        account: &str,
        payload: &str,
        siblings_only: Option<String>,
    ) -> Result<(), PlatformError> {
        let _ = siblings_only;
        self.add(svc, account, payload)
    }
    /// `security delete-generic-password -s svc -a account`, confirmed via
    /// `security_delete_call_resolved` (a private helper of this module's
    /// production `SecurityCliExecutor` implementation) — never assumed
    /// from a bare attempt (I10).
    fn delete(&self, svc: &str, account: &str) -> bool;
}

// ── round 7c D-F7: cross-crate executor-injection seam ─────────────────
//
// PRIMARY METHODOLOGICAL DIRECTIVE (round 7c brief): `keychain_mirror_disabled()`
// makes `force_sync_account_changed`/`reconcile_keychain_to_marker` a no-op
// under `cfg(test)`/`test-utils`, which is exactly why `csq swap`'s
// `handle()` has never had a test that exercises the REAL keychain decision
// end-to-end — every existing swap-level test drives a PURE helper
// (`decide_swap_disposition`, `decide_ok_repoint_disposition`, ...), never
// `handle()` itself. This thread-local override lets a test in ANY crate
// install a scripted [`KeychainExecutor`] that the two public entry points
// below consult BEFORE the disabled-mirror short-circuit, so `handle()`
// drives the real `decide_cc_keychain_write`/`apply_cc_keychain_write`
// policy against fixture-controlled keychain state — never the real
// `security` binary: the override, when set, replaces `SecurityCliExecutor`
// outright, so `run_security_bounded`'s own hermetic guard
// (`keychain_mirror_disabled()`, returning `None` under any test config —
// see that function's doc) is never even reached via this path, let alone
// its `real_security_spawn_tripwire` panic.
#[cfg(any(test, feature = "test-utils"))]
#[cfg(target_os = "macos")]
thread_local! {
    static TEST_KEYCHAIN_EXECUTOR: std::cell::RefCell<Option<std::rc::Rc<dyn KeychainExecutor>>> =
        const { std::cell::RefCell::new(None) };
}

/// Registers `exec` as the executor every [`force_sync_account_changed`] /
/// [`reconcile_keychain_to_marker`] call on THIS THREAD uses instead of the
/// `keychain_mirror_disabled()` no-op guard. Scoped to the calling thread
/// (thread-local) so parallel `cargo test` workers never interfere with
/// each other's scripted keychain state. Remains installed until
/// [`clear_test_keychain_executor`] runs — callers MUST clear it (a `Drop`
/// guard is the recommended pattern) so a later test on the SAME thread
/// does not inherit a stale script.
///
/// Never compiled into a production binary: gated on
/// `#[cfg(any(test, feature = "test-utils"))]`, mirroring every other seam
/// this module exposes for cross-crate test harnesses (`crate::testing::*`).
#[cfg(any(test, feature = "test-utils"))]
#[cfg(target_os = "macos")]
pub fn set_test_keychain_executor(exec: std::rc::Rc<dyn KeychainExecutor>) {
    TEST_KEYCHAIN_EXECUTOR.with(|c| *c.borrow_mut() = Some(exec));
}

/// Clears a previously-installed [`set_test_keychain_executor`] override on
/// this thread, restoring the ordinary `keychain_mirror_disabled()`
/// no-op behaviour.
#[cfg(any(test, feature = "test-utils"))]
#[cfg(target_os = "macos")]
pub fn clear_test_keychain_executor() {
    TEST_KEYCHAIN_EXECUTOR.with(|c| *c.borrow_mut() = None);
}

/// `Some(exec)` when a test on this thread has installed an override via
/// [`set_test_keychain_executor`]; `None` otherwise (the ordinary
/// production/disabled-mirror path). Internal to this module — the two
/// public entry points below are the only callers.
#[cfg(any(test, feature = "test-utils"))]
#[cfg(target_os = "macos")]
fn test_keychain_executor_override() -> Option<std::rc::Rc<dyn KeychainExecutor>> {
    TEST_KEYCHAIN_EXECUTOR.with(|c| c.borrow().clone())
}

/// Cross-crate scripted [`KeychainExecutor`] for the round 7c D-F7 harness —
/// a public twin of this module's private `RecordingExecutor` (used by its
/// own in-crate unit tests), reachable from a DIFFERENT crate (`csq`'s
/// `swap::tests`) via [`set_test_keychain_executor`]. Scripts a single
/// `find()` result (every call returns the SAME classification — every
/// scenario this harness drives needs at most one distinct read per
/// `handle()` invocation, since `force_sync_account_changed_with_executor`
/// and `reconcile_keychain_to_marker_with_executor` each call `find` once)
/// and independently toggleable `add`/`delete` outcomes. Records every
/// call for call-order/target assertions, mirroring `RecordingExecutor`.
#[cfg(any(test, feature = "test-utils"))]
#[cfg(target_os = "macos")]
pub struct ScriptedKeychainExecutor {
    calls: std::cell::RefCell<Vec<(&'static str, String, String)>>,
    add_payloads: std::cell::RefCell<Vec<String>>,
    /// The single item's current state — STATEFUL (unlike the in-crate
    /// `RecordingExecutor`, which is a fixed one-shot script): a
    /// successful `add()`/`delete()` updates this, so a caller that reads
    /// `find()` again AFTER a mutation (e.g. `reconcile_keychain_to_marker`
    /// re-reading X after `force_sync_account_changed` wrote it) observes
    /// the mutation. Models exactly the single-item RMW invariant this
    /// module's own v3 redesign doc describes ("touching EXACTLY the one
    /// item CC reads") — required for any round 7c D-F7 scenario where a
    /// successful forced write must be visible to the reconcile call that
    /// follows it in the SAME `handle()` invocation.
    current: std::cell::RefCell<RawContentClassification>,
    add_ok: std::cell::Cell<bool>,
    delete_ok: std::cell::Cell<bool>,
}

#[cfg(any(test, feature = "test-utils"))]
#[cfg(target_os = "macos")]
impl ScriptedKeychainExecutor {
    /// `find()` returns `find_result` UNTIL a successful `add()`/`delete()`
    /// mutates it (see the `current` field's doc). `add`/`delete` succeed
    /// by default (`with_add_failing`/`with_delete_failing` flip either).
    pub fn scripted(find_result: RawContentClassification) -> Self {
        Self {
            calls: std::cell::RefCell::new(Vec::new()),
            add_payloads: std::cell::RefCell::new(Vec::new()),
            current: std::cell::RefCell::new(find_result),
            add_ok: std::cell::Cell::new(true),
            delete_ok: std::cell::Cell::new(true),
        }
    }

    /// Builder: subsequent `add()` calls report `Err`.
    pub fn with_add_failing(self) -> Self {
        self.add_ok.set(false);
        self
    }

    /// Builder: subsequent `delete()` calls report `false`.
    pub fn with_delete_failing(self) -> Self {
        self.delete_ok.set(false);
        self
    }

    /// The `(verb, service, account)` sequence this executor observed, in
    /// call order.
    pub fn calls(&self) -> Vec<(&'static str, String, String)> {
        self.calls.borrow().clone()
    }

    /// The payload of the most recent `add()` call, if any.
    pub fn last_add_payload(&self) -> Option<String> {
        self.add_payloads.borrow().last().cloned()
    }
}

#[cfg(any(test, feature = "test-utils"))]
#[cfg(target_os = "macos")]
impl KeychainExecutor for ScriptedKeychainExecutor {
    fn find(&self, svc: &str, account: &str) -> RawContentClassification {
        self.calls
            .borrow_mut()
            .push(("find", svc.to_string(), account.to_string()));
        self.current.borrow().clone()
    }

    fn add(&self, svc: &str, account: &str, payload: &str) -> Result<(), PlatformError> {
        self.calls
            .borrow_mut()
            .push(("add", svc.to_string(), account.to_string()));
        self.add_payloads.borrow_mut().push(payload.to_string());
        if self.add_ok.get() {
            *self.current.borrow_mut() = RawContentClassification::Content(payload.to_string());
            Ok(())
        } else {
            // A failed `add` leaves `current` UNCHANGED — mirrors the real
            // `security add-generic-password` failure mode this module's
            // `ForcedSyncResult::WriteFailedUnknown` doc describes: the
            // disk state after a failed write is genuinely unknown in
            // production, but for THIS scripted executor a failure means
            // "the mutation did not land", so a subsequent `find()` still
            // observes the PRE-write content — exactly what a real stale
            // keychain item would show a caller that re-reads it.
            Err(PlatformError::Keychain("scripted add failure".to_string()))
        }
    }

    fn delete(&self, svc: &str, account: &str) -> bool {
        self.calls
            .borrow_mut()
            .push(("delete", svc.to_string(), account.to_string()));
        if self.delete_ok.get() {
            *self.current.borrow_mut() = RawContentClassification::Absent;
            true
        } else {
            false
        }
    }
}

/// an internal ticket round 2 (INVEST-NOW, security review) — ALLOWLIST, not a denylist:
/// `true` iff `s` is non-empty and every character is in `[A-Za-z0-9 ._-]`.
/// `security -i`'s stdin grammar is undocumented in any stable, versioned
/// spec csq can pin against, so "reject the characters I know are dangerous"
/// (the prior denylist form — quote/backslash/control only) is the wrong
/// shape for an unspecified grammar: it silently admits any OTHER character
/// the parser might treat specially (e.g. `'`, `#`, a shell-metacharacter
/// look-alike, or a future non-ASCII byte) on the unverified assumption that
/// "not currently known to matter" means "safe". The allowlist instead names
/// exactly what is verified safe and refuses everything else, including
/// characters that happen to be harmless today — `guard-reader-writer-parity.md`
/// MUST-2's fail-closed discipline applied to an ungoverned grammar.
///
/// The allowed set is chosen to be a STRICT SUPERSET of what both real
/// producers ever emit — verified below, not assumed:
/// - [`is_well_formed_service_name`] constrains `svc` to
///   `"Claude Code-credentials-"` (letters, a space, hyphens) plus exactly 8
///   lowercase hex characters — every one of those characters is in the
///   allowlist.
/// - [`is_valid_cc_username`]/[`keychain_account`] constrain `account` to
///   `[a-zA-Z0-9._-]+` (falling back to a fixed literal otherwise) — also a
///   strict subset of the allowlist.
///
/// Whitespace (space only, not tab/newline/other Unicode whitespace) stays
/// allowed because it is empirically REQUIRED: the real production `svc`
/// value contains a literal space in `"Claude Code"` (measured on a
/// throwaway keychain, mac-mini, 2026-09-27 — `security -i`'s tokenizer
/// honours double-quoting for a token containing a space; a validator that
/// rejected all whitespace would refuse every real `add()` call). `add()` is
/// a trait method a future caller could invoke with a differently-derived
/// value, so this is re-checked at the point of use rather than assumed
/// from the caller's identity.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn is_stdin_token_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
}

/// an internal ticket — builds the ONE command line written to `security -i`'s stdin for
/// an `add-generic-password` call. `svc`/`account` are wrapped in double
/// quotes (`security -i`'s tokenizer honours quoting — see
/// [`is_stdin_token_safe`]'s doc for the empirical basis — and the real
/// production `svc` value contains a literal space) so callers never need to
/// avoid whitespace; the credential travels hex-encoded (never raw) so it
/// can never be mistaken for `security -i` syntax and never appears as
/// human-readable plaintext in the command line itself. `security` decodes
/// `-X <hex>` back to the original bytes before storing them (the same flag
/// [`read`]'s counterpart, `find-generic-password -w`, has always returned
/// decoded — this call shape is new only in that csq now WRITES via `-X`
/// where it used to write via `-w`).
///
/// Callers MUST validate `svc`/`account` with [`is_stdin_token_safe`] first —
/// this fn performs no validation of its own and trusts its inputs, matching
/// [`build_write_payload`]'s sibling convention of validating at the caller
/// boundary rather than duplicating the check in every pure builder.
///
/// A prior version of this doc claimed a non-printable-ASCII payload byte
/// makes `security` silently corrupt storage — RETRACTED, see
/// [`add_stdin_invocation`]'s "RETRACTED FINDING" doc: storage is correct,
/// re-derived with `find-generic-password -g`.
///
/// **Line-length limit (round 2 finding, 2026-09-27) — the caller,
/// [`add_stdin_invocation`], is responsible for refusing before this fn is
/// invoked if the built command line would approach `security -i`'s
/// undocumented per-line buffer.** Measured on a throwaway keychain
/// (mac-mini): a command line of exactly 4096 bytes (including the trailing
/// `\n`) succeeds; 4098 bytes fails outright (`SecKeychainSearchCopyNext`:
/// item not found) — but critically, in an interactive/GUI session the
/// truncated first chunk can itself be a syntactically complete
/// `add-generic-password … -X <truncated-hex>` with the trailing keychain
/// path silently dropped, which `security` then attempts against the
/// **default** keychain (observed stderr: `SecKeychainItemCreateFromContent
/// (<default>): User interaction is not allowed`) — on a host that CAN
/// answer that prompt, this could write truncated credential bytes into the
/// **login** keychain under the real `(svc, account)` identifiers. This fn
/// does not enforce the limit itself (it is a pure builder); see
/// [`SECURITY_I_MAX_SAFE_LINE_BYTES`].
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn build_add_stdin_command(svc: &str, account: &str, payload: &str) -> Vec<u8> {
    let hex_payload = hex::encode(payload.as_bytes());
    format!("add-generic-password -A -s \"{svc}\" -a \"{account}\" -X {hex_payload}\n").into_bytes()
}

/// RETRACTED FINDING, re-derived (2026-09-27) — an earlier version of this
/// doc claimed `security`'s generic-password storage silently corrupts a
/// non-printable-ASCII payload (stores its own hex text instead of the real
/// bytes), based on reading `find-generic-password -w`'s stdout back and
/// seeing hex characters. That instrument could not discriminate the claim:
/// `-w` is DOCUMENTED to print a non-printable password's bytes as hex
/// text — so hex-looking `-w` output is consistent with BOTH "stored
/// correctly, displayed as hex because it's non-printable" and "stored
/// wrong, as literal hex text". Re-measured with `find-generic-password -g`
/// (which labels the format explicitly: `password: "…"` for printable,
/// `password: 0x<HEX>  "<escaped>"` for non-printable) on a throwaway
/// keychain, mac-mini, 2026-09-27, for a payload `b'a', 0x0A, b'b'` and for
/// `b'a'` + UTF-8 "日" + `b'b'`, via BOTH this fn's `-X` stdin path and the
/// OLD pre-an internal ticket `-w`-on-argv path:
///
/// ```text
/// password: 0x610A62  "a\012b"                    (intended: 61 0A 62)
/// password: 0x61E697A562  "a\346\227\245b"         (intended: 61 E6 97 A5 62)
/// ```
///
/// Both match the INTENDED raw bytes exactly (`\012` octal = 0x0A;
/// `\346\227\245` octal = 0xE6 0x97 0xA5) — storage is correct in every
/// case tested. csq's own read path ([`classify_raw_content`]) already
/// handles this correctly: it distinguishes printable JSON (`starts_with
/// ('{')`) from `-w`'s hex-DISPLAY convention and `hex::decode`s the
/// latter — this is not a new finding, `read`'s hex-decode branch already
/// existed and is exercised by
/// `classify_raw_content_hex_encoded_object_is_content`. No refusal is
/// needed on the write side for NON-printable content; see
/// `is_stdin_token_safe`'s own doc for the (unrelated, still current)
/// reason `svc`/`account` are validated. See
/// [`SECURITY_I_MAX_SAFE_LINE_BYTES`] for the SEPARATE, still-live
/// length-based refusal this fn also performs.
///
/// **BUG (round 2, MEASURED, 2026-09-27) — `security -i` truncates a stdin
/// line at an undocumented buffer size.** On a throwaway keychain
/// (mac-mini): a command line of exactly 4096 bytes (trailing `\n`
/// included) succeeds; 4098 bytes fails — but the truncated first chunk can
/// itself be a syntactically COMPLETE `add-generic-password … -X
/// <truncated-hex>` with the trailing keychain-path argument silently
/// dropped, which `security` then attempts against the caller's DEFAULT
/// keychain (observed: `SecKeychainItemCreateFromContent (<default>): User
/// interaction is not allowed` — refused here only because this test
/// environment cannot answer the resulting GUI prompt). On a host that CAN
/// answer it, this writes TRUNCATED credential bytes into the LOGIN
/// keychain under the real `(svc, account)` identifiers, before ANY error
/// surfaces to the caller. `payload` doubles in size under hex encoding and
/// carries every sibling key (`mcpOAuth`, etc.) — a handful of MCP OAuth
/// servers is enough to exceed this. Refused below, fail-closed, with
/// margin against the measured boundary — THIS fn's job is exactly that
/// refusal; it does not know or care what its caller does next.
///
/// **an internal ticket (round 4, owner-accepted residual) — this fn's `Err` is NOT the
/// end of the road for `add()` anymore.** Round 3's native-update fallback
/// (`security_framework`'s `SecKeychainItemModifyAttributesAndData`) was
/// implemented and then shelved: its discriminating ACL-preservation test
/// could not conclude (confounded by the ad-hoc code signing of the test
/// binary that ran it — see `native_update_generic_password`'s doc for the
/// full measurement), so per that round's stop condition it never shipped.
/// The owner accepted the residual (an internal ticket): rather than leave real users
/// with `mcpOAuth` siblings regressed to a hard refusal vs v2.19, `add()`
/// (via [`select_add_invocation`]) falls back to the OLD pre-an internal ticket argv
/// write shape for exactly this oversized case — the same argv exposure
/// an internal ticket exists to close, deliberately re-accepted ONLY above this line
/// limit, with a fixed-vocabulary warn naming an internal ticket so the fallback is
/// diagnosable without any credential or size detail in the log.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn add_stdin_invocation(svc: &str, account: &str, payload: &str) -> Result<Vec<u8>, PlatformError> {
    if !is_stdin_token_safe(svc) || !is_stdin_token_safe(account) {
        return Err(PlatformError::Keychain(
            "keychain write refused: service or account name contains a character unsafe \
             for `security -i`'s stdin command line (must be [A-Za-z0-9 ._-])"
                .to_string(),
        ));
    }
    let cmd = build_add_stdin_command(svc, account, payload);
    if cmd.len() > SECURITY_I_MAX_SAFE_LINE_BYTES {
        return Err(PlatformError::Keychain(format!(
            "keychain write refused: the security -i command line would be {} bytes, over \
             the safe limit of {} bytes (security -i truncates long stdin lines, which can \
             write truncated credential data before any error surfaces) — no write attempted",
            cmd.len(),
            SECURITY_I_MAX_SAFE_LINE_BYTES
        )));
    }
    Ok(cmd)
}

/// an internal ticket (round 4) — which mechanism `add()` uses to write the credential.
/// Never carries the payload itself in `Stdin`'s companion, since the
/// stdin command line already IS the payload (hex-encoded); `ArgvFallback`
/// DOES carry the raw payload — that is the whole point of the fallback,
/// and callers must treat it exactly as security-sensitive as any other
/// argv-bearing `Command`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
enum AddInvocation {
    /// Fits `security -i`'s stdin line — argv is always [`ADD_STDIN_ARGV`].
    Stdin(Vec<u8>),
    /// an internal ticket — does not fit; the byte-for-byte pre-an internal ticket v2.19 argv shape:
    /// `["add-generic-password", "-A", "-s", svc, "-a", account, "-w", payload]`
    /// (pre-an internal ticket minus `-U`: every write is delete-then-create, see
    /// [`add_via_delete_create`]).
    ArgvFallback(Vec<String>),
}

/// an internal ticket (round 4, owner-accepted residual) — PURE selection between the
/// stdin path (fits) and the argv fallback (does not fit); performs no I/O
/// and emits no log — `add()` (the only production caller) logs the
/// fixed-vocabulary warning when it receives an `ArgvFallback`, keeping this
/// fn testable as a pure function per the round-4 brief's own test ask.
///
/// Reuses [`add_stdin_invocation`]'s validation and size check rather than
/// duplicating them: its `Err` means EITHER an unsafe `svc`/`account` token
/// (not retryable — re-checked directly here with [`is_stdin_token_safe`],
/// rather than string-matching the error text, exactly as round 3's now-
/// reverted native-update dispatch did) OR an oversized command line
/// (retryable via the argv fallback). See [`add_stdin_invocation`]'s doc
/// for the full an internal ticket rationale and [`ADD_STDIN_ARGV`]'s doc for what this
/// fallback re-accepts.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn select_add_invocation(
    svc: &str,
    account: &str,
    payload: &str,
) -> Result<AddInvocation, PlatformError> {
    match add_stdin_invocation(svc, account, payload) {
        Ok(cmd) => Ok(AddInvocation::Stdin(cmd)),
        Err(refusal) => {
            if !is_stdin_token_safe(svc) || !is_stdin_token_safe(account) {
                return Err(refusal);
            }
            Ok(AddInvocation::ArgvFallback(vec![
                "add-generic-password".to_string(),
                "-A".to_string(),
                "-s".to_string(),
                svc.to_string(),
                "-a".to_string(),
                account.to_string(),
                "-w".to_string(),
                payload.to_string(),
            ]))
        }
    }
}

/// an internal ticket round 2 — `security -i`'s measured per-line buffer is exactly 4096
/// bytes (including the trailing `\n`): 4096 succeeds, 4098 fails (see
/// [`add_stdin_invocation`]'s doc for the measurement and the truncation
/// danger). [`SECURITY_I_LINE_MARGIN_BYTES`] leaves headroom below that
/// exact boundary — a different `security` build or a slightly different
/// fixed overhead could shift it by a few bytes either way, and the
/// consequence of guessing wrong in the unsafe direction is silent
/// truncation, not merely a spurious refusal.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SECURITY_I_MEASURED_MAX_LINE_BYTES: usize = 4096;

/// See [`SECURITY_I_MEASURED_MAX_LINE_BYTES`]'s doc for why this margin
/// exists rather than refusing at the measured boundary exactly.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SECURITY_I_LINE_MARGIN_BYTES: usize = 200;

/// The actual refusal threshold [`add_stdin_invocation`] enforces:
/// `SECURITY_I_MEASURED_MAX_LINE_BYTES - SECURITY_I_LINE_MARGIN_BYTES`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const SECURITY_I_MAX_SAFE_LINE_BYTES: usize =
    SECURITY_I_MEASURED_MAX_LINE_BYTES - SECURITY_I_LINE_MARGIN_BYTES;

/// an internal ticket — the argv `add()` passes to [`run_security_bounded`] ON THE
/// STDIN PATH. Always exactly this: the credential (and `svc`/`account`
/// too) never appear here — they travel only in the stdin command line
/// [`build_add_stdin_command`] returns. Pinned as a named constant, rather
/// than inlined at the call site, so a test can assert against the exact
/// production value instead of a hand-copied literal.
///
/// **Does NOT generalize to every `add()` call** — an internal ticket (round 4) added a
/// SEPARATE argv shape, [`AddInvocation::ArgvFallback`], used instead of
/// this one for an oversized payload; that fallback's whole point is that
/// the payload DOES appear on argv. See [`select_add_invocation`]'s doc.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const ADD_STDIN_ARGV: [&str; 1] = ["-i"];

/// Large-payload path, tracked by an internal ticket —
/// **NOT WIRED into `add()`; the discriminating test below could not
/// conclude, and per the
/// round-3 brief's own stop condition ("If the ACL is NOT preserved, STOP
/// and report; do not ship the native path") this ships UNUSED rather than
/// on an unverified claim.**
///
/// **What the test found.** The prescribed protocol — create an item with
/// `/usr/bin/security add-generic-password -A`, update it from THIS test
/// binary via this fn, read back with a SEPARATE `/usr/bin/security`
/// process — passed (`security_framework_native_update_preserves_acl`,
/// stderr `password: "xxxx…"`, no interaction error). The REQUIRED negative
/// control — create an item via this fn's ADD branch (no `-A`) from the
/// SAME test binary, then read with `/usr/bin/security` — was supposed to
/// be REFUSED headless, and was NOT (`security_framework_create_without_acl_prompts_headless`,
/// empty stderr, read succeeded). **The control's failure to go RED means
/// the instrument cannot discriminate here, so the positive result is not
/// trustworthy either** (`instrument-discipline.md` MUST-1/2): both may
/// share one root cause.
///
/// **Root cause, measured, not guessed:** `codesign -dv` on the actual test
/// binary (mac-mini, 2026-09-27) reports `Signature=adhoc`,
/// `TeamIdentifier=not set`, `Identifier=csq_core-<per-build-hash>` — an
/// ad-hoc-signed binary with no stable Team ID (matches
/// `discovery_keychain_reprompt_adhoc_signing`: ad-hoc identity changes per
/// rebuild). `security dump-keychain -a` on a control item created the SAME
/// way (via `/usr/bin/security`, no `-A`) shows its "encrypt" ACL entry
/// with `applications: <null>` — a NULL trusted-application list, which is
/// NOT "trust nobody"; it is consistent with "no enforceable identity to
/// restrict to". The hypothesis this supports: macOS cannot build a
/// meaningful per-app ACL restriction for an ad-hoc/no-Team-ID binary, so
/// BOTH the item this test binary creates AND (possibly) the item it
/// updates end up without the restriction the protocol needed — a
/// confound of the TEST HARNESS's own identity, not necessarily evidence
/// against the mechanism (`SecKeychainItemModifyAttributesAndData` with a
/// NULL attribute list, per the source read below, still only touches
/// content at the API level). **This is UNDETERMINED, not "ACL not
/// preserved"** (`durable-instruments.md` MUST-2's third outcome) — the
/// next round needs a properly Developer-ID-signed (stable Team ID) test
/// harness, or a standalone signed helper binary, to re-derive this
/// cleanly.
///
/// Kept `#[cfg(any(test, feature = "test-utils"))]` — test-only — rather
/// than deleted, so the mechanism and its measurement survive for that
/// re-derivation instead of being re-discovered from scratch.
///
/// `SecKeychain::set_generic_password` (legacy `os::macos` API — the
/// candidate `security-framework` exposes matching Apple's
/// `SecKeychainItemModifyAttributesAndData`, per the round-3 brief) first
/// calls `find_generic_password`; if found, `item.set_password(password)`,
/// which calls `SecKeychainItemModifyAttributesAndData(item, NULL, len,
/// data)` (verified by reading the source of the `security-framework`
/// crate, v3.7.0, module `os::macos::passwords`) — the attribute
/// list argument is a NULL pointer, so ONLY the content changes AT THE API
/// LEVEL; if not found, it calls `add_generic_password`
/// (`SecKeychainAddGenericPassword`, no explicit ACL — see
/// [`set_generic_password_native_update`]'s doc for why that branch must
/// never be reached from `add()` even once this is re-verified and wired).
#[cfg(all(target_os = "macos", any(test, feature = "test-utils")))]
fn native_update_generic_password(
    keychain: &security_framework::os::macos::keychain::SecKeychain,
    svc: &str,
    account: &str,
    payload: &[u8],
) -> Result<(), security_framework::base::Error> {
    keychain.set_generic_password(svc, account, payload)
}

/// an internal ticket round 3 (BUG-1, the large-payload path) — **UNWIRED, see
/// [`native_update_generic_password`]'s doc for the full finding: the
/// discriminating ACL test could not conclude (confounded by the test
/// harness's own ad-hoc code signing), so this stays test-only and `add()`
/// does not call it.** Kept as a `#[cfg(test)]`-scoped reference
/// implementation of what a re-verified version would look like — bounded
/// by [`KEYCHAIN_OP_TIMEOUT`] via a worker thread, matching every other
/// `security`-touching call in this module, with `SecKeychain::default()`
/// resolved INSIDE the worker thread so no CoreFoundation handle needs to
/// cross threads.
///
/// **This would be safe to wire back in ONLY once ACL preservation is
/// re-verified, AND only when the caller has confirmed the item already
/// exists** (`add()`'s prior wiring: `RawContentClassification::Content(_)`
/// from `find()`, immediately before this call) — if the item does NOT
/// exist, [`native_update_generic_password`] takes its ADD branch, which
/// sets no explicit ACL, reintroducing CC's interactive keychain prompt.
#[cfg(all(target_os = "macos", any(test, feature = "test-utils")))]
#[allow(dead_code)] // kept as a reference impl — see this fn's doc for why it's unwired
fn set_generic_password_native_update(
    svc: &str,
    account: &str,
    payload: &[u8],
) -> Result<(), PlatformError> {
    use std::sync::mpsc;

    let (tx, rx) = mpsc::sync_channel::<Result<(), security_framework::base::Error>>(1);
    let svc = svc.to_string();
    let account = account.to_string();
    let payload = payload.to_vec();
    let spawn_result = std::thread::Builder::new().spawn(move || {
        let result = security_framework::os::macos::keychain::SecKeychain::default()
            .and_then(|kc| native_update_generic_password(&kc, &svc, &account, &payload));
        let _ = tx.send(result);
    });
    if spawn_result.is_err() {
        return Err(PlatformError::Keychain(
            "keychain native update: worker thread spawn failed".to_string(),
        ));
    }
    match rx.recv_timeout(KEYCHAIN_OP_TIMEOUT) {
        Ok(Ok(())) => Ok(()),
        // `security_framework::base::Error`'s `Display` renders Apple's own
        // `SecCopyErrorMessageString` text (or "error code {N}") — an
        // OSStatus description, never secret material.
        Ok(Err(e)) => Err(PlatformError::Keychain(format!(
            "keychain native update failed: {e}"
        ))),
        Err(_) => Err(PlatformError::Keychain(
            "keychain native update timed out".to_string(),
        )),
    }
}

/// The production executor — the ONLY thing in this module that shells
/// `security` for the write/clear paths (S10). `write_raw` and
/// [`force_sync_account_changed`] are thin wrappers: guard-check, then
/// delegate to their respective `_with_executor` core against THIS type.
#[cfg(target_os = "macos")]
struct SecurityCliExecutor;

#[cfg(target_os = "macos")]
impl KeychainExecutor for SecurityCliExecutor {
    fn find(&self, svc: &str, account: &str) -> RawContentClassification {
        classify_raw_content(run_security_bounded(
            &["find-generic-password", "-s", svc, "-a", account, "-w"],
            None,
        ))
    }

    fn add(&self, svc: &str, account: &str, payload: &str) -> Result<(), PlatformError> {
        self.add_restoring(svc, account, payload, None)
    }

    fn add_restoring(
        &self,
        svc: &str,
        account: &str,
        payload: &str,
        siblings_only: Option<String>,
    ) -> Result<(), PlatformError> {
        // an internal ticket: the credential (previously the literal argument after
        // `-w`, readable in `ps` output for the life of the call) now
        // travels hex-encoded on `security -i`'s stdin only when it fits;
        // argv is always `ADD_STDIN_ARGV` (`["-i"]`) on that path.
        //
        // an internal ticket (round 4, owner-accepted residual) — when it does NOT fit,
        // `select_add_invocation` returns the pre-an internal ticket v2.19 argv shape
        // instead of an error (round 3's native-update alternative was
        // implemented and shelved — see `add_stdin_invocation`'s doc for
        // why). This re-accepts, ONLY above the measured line limit, the
        // exact argv exposure an internal ticket exists to close everywhere else — a
        // deliberate owner trade-off against silently refusing every write
        // for a user with enough `mcpOAuth` siblings to cross it.
        // Validate BEFORE deleting: a refused name or token must leave the
        // existing item untouched.
        let invocation = select_add_invocation(svc, account, payload)?;
        add_via_delete_create(
            svc,
            account,
            invocation,
            siblings_only,
            &run_security_bounded,
        )
    }

    fn delete(&self, svc: &str, account: &str) -> bool {
        match run_security_bounded(&["delete-generic-password", "-s", svc, "-a", account], None) {
            Some(bo) => security_delete_call_resolved(&bo.output),
            None => false,
        }
    }
}

/// Signature of [`run_security_bounded`], injectable so the delete-then-create
/// sequencing in [`add_via_delete_create`] is testable without a real `security`.
#[cfg(target_os = "macos")]
type SecurityRunner<'a> = &'a dyn Fn(&[&str], Option<Vec<u8>>) -> Option<BoundedOutput>;

/// Write one keychain item by DELETE, then CREATE — never `-U`.
///
/// Apple's `add-generic-password -U` on an existing item calls
/// `SecKeychainItemSetAccess`, which raises a "security wants to access key"
/// password dialog (observed after `csq swap`). A fresh `add-generic-password
/// -A` creates the item with the allow-all-apps ACL and never prompts.
///
/// Sequence: (1) `delete-generic-password`, repeated while it exits 0 (a
/// duplicate item may remain) until it exits [`SECURITY_ITEM_NOT_FOUND`]
/// (44), at most [`MAX_DUPLICATE_DELETE_ITERATIONS`] times; any other
/// outcome, a timeout, or an exhausted budget returns `Err`, no add is
/// attempted, and the item's state is then UNKNOWN (an earlier iteration
/// may already have removed a duplicate); (2) the create.
///
/// If the create fails after the deletes, the item is absent and this
/// returns `Err`. `siblings_only` (the previous content with
/// `claudeAiOauth` removed, never the full previous content, which would
/// restore a superseded account's token) is then re-added ONCE, best
/// effort, so non-token siblings such as `mcpOAuth` are not lost; its own
/// failure is ignored. Claude Code then reads the symlinked
/// `.credentials.json` for the token, which is csq's documented fallback.
#[cfg(target_os = "macos")]
fn add_via_delete_create(
    svc: &str,
    account: &str,
    invocation: AddInvocation,
    siblings_only: Option<String>,
    run: SecurityRunner<'_>,
) -> Result<(), PlatformError> {
    let mut confirmed_absent = false;
    for _ in 0..MAX_DUPLICATE_DELETE_ITERATIONS {
        match run(&["delete-generic-password", "-s", svc, "-a", account], None)
            .map(|bo| bo.output.status.code())
        {
            Some(Some(0)) => continue,
            Some(Some(SECURITY_ITEM_NOT_FOUND)) => {
                confirmed_absent = true;
                break;
            }
            // Timeout, signal, or any other exit: unconfirmed.
            _ => break,
        }
    }
    if !confirmed_absent {
        // F7: fixed vocabulary — no `security` output, svc, or account.
        return Err(PlatformError::Keychain(
            "keychain write refused: removal of the existing item was not confirmed, \
             so its state is unknown; no new item was written"
                .into(),
        ));
    }
    let result = run_add_invocation(invocation, run);
    if result.is_err() {
        if let Some(payload) = siblings_only {
            if let Ok(inv) = select_add_invocation(svc, account, &payload) {
                // Best effort: the original error is what the caller sees.
                let _ = run_add_invocation(inv, run);
            }
        }
    }
    result
}

/// Execute one already-selected add invocation through `run`.
#[cfg(target_os = "macos")]
fn run_add_invocation(
    invocation: AddInvocation,
    run: SecurityRunner<'_>,
) -> Result<(), PlatformError> {
    match invocation {
        AddInvocation::Stdin(stdin_cmd) => {
            let bo = run(&ADD_STDIN_ARGV, Some(stdin_cmd)).ok_or_else(|| {
                PlatformError::Keychain(
                    "keychain write timed out (likely a locked or non-interactive \
                     keychain — e.g. an SSH/tmux session that cannot answer an \
                     authorization prompt)"
                        .into(),
                )
            })?;
            let stderr_complete = bo.stderr_complete;
            let output = bo.output;
            // an internal ticket — empirically measured on a throwaway keychain
            // (mac-mini, 2026-09-27): `security -i`'s OWN exit code DOES
            // reflect the inner command's outcome — a successful add
            // exits 0 with empty stdout/stderr; forcing a duplicate-item
            // failure (an `add` without `-U` against an already-present
            // item) exits 45 (`errSecDuplicateItem`) with the
            // `SecKeychainItemCreateFromContent … already exists` text
            // on stderr; an unrecognized `-i` subcommand exits 1. So the
            // exit code alone is sufficient (matching the old `-w`
            // path's `output.status.success()` check) — the
            // stderr-empty check below is additional defense-in-depth,
            // not a correction for an exit code known to lie.
            // `!stderr_complete` (BUG-R3-1: a descendant still holding
            // the pipe) is ALSO treated as failure — an incomplete
            // capture must never be read as "confirmed empty".
            if !output.status.success() || !stderr_complete || !output.stderr.is_empty() {
                // F7: fixed-vocabulary only — no `security` stderr at
                // all, not even `redact_tokens`-filtered.
                // `redact_tokens` strips KNOWN token shapes (`sk-ant-*`,
                // long hex); `security`'s own error text is not drawn
                // from a closed vocabulary this crate controls, so
                // "filtered" is not the same claim as "safe" — the exit
                // CODE alone is sufficient for diagnosis (locked
                // keychain, denied ACL, etc. each have distinct,
                // documented exit codes) without embedding any of the
                // command's own output.
                let code = output
                    .status
                    .code()
                    .map_or_else(|| "signal".to_string(), |c| c.to_string());
                return Err(PlatformError::Keychain(format!(
                    "keychain write failed (security exit {code})"
                )));
            }
            Ok(())
        }
        AddInvocation::ArgvFallback(argv) => {
            // an internal ticket — fixed-vocabulary only: no credential bytes, no
            // svc/account, no size (not even a coarse bucket) — the
            // fact of the fallback plus the issue number is the whole
            // diagnostic surface.
            warn!(
                error_kind = "keychain_add_argv_fallback_oversized",
                "keychain add payload exceeds security -i's safe stdin line limit; \
                 falling back to the pre-an internal ticket argv write shape (an internal ticket, \
                 owner-accepted residual) rather than refusing the write"
            );
            let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            let bo = run(&argv_refs, None).ok_or_else(|| {
                PlatformError::Keychain(
                    "keychain write timed out (likely a locked or non-interactive \
                     keychain — e.g. an SSH/tmux session that cannot answer an \
                     authorization prompt)"
                        .into(),
                )
            })?;
            let output = bo.output;
            // v2.19 parity: `output.status.success()` alone, no
            // stderr-empty check — that check is specific to `-i`'s own
            // quirks (see the Stdin arm above) and was never part of the
            // argv path this fallback reproduces byte-for-byte.
            if !output.status.success() {
                let code = output
                    .status
                    .code()
                    .map_or_else(|| "signal".to_string(), |c| c.to_string());
                return Err(PlatformError::Keychain(format!(
                    "keychain write failed (security exit {code})"
                )));
            }
            Ok(())
        }
    }
}

// ── v4 — forced, all-or-nothing keychain sync for a KNOWN account change ──
//
// "Switch now or say so" (owner decision 2026-09-26): an account change
// (`csq swap`, `auto_rotate::tick`, or a FRESH handle dir with no prior CC
// session — `csq run`/`csq exec`/phase2b) writes the new account's token
// into X, the ONE keychain item CC reads, synchronously and at its own call
// site — or it says so and changes nothing. There is no deferred background
// completion, no marker recording an owed resolution, and no proof that X
// still holds a superseded account's token: the call site ALREADY KNOWS the
// binding is new, so X's own expiry and its previous content are irrelevant
// to whether this write is safe — only whether X can be READ at all.

/// Outcome of [`force_sync_account_changed`].
///
/// v5 (2026-09-26 "keychain follows the links"): this enum no longer carries
/// what X held BEFORE the call — the compensating action for any failure
/// downstream of this write is [`reconcile_keychain_to_marker`], which reads
/// the handle dir's `.csq-account` marker AS IT IS NOW rather than restoring
/// a pre-write snapshot. A snapshot describes X at read time, not the
/// account the handle dir actually names once a failure settles, which is
/// exactly the class of desync rounds 1-5 kept finding. `Debug`/`Clone` are
/// both safe to derive now that no variant carries raw keychain payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedSyncResult {
    /// X could not be read at all — its real state is UNKNOWN, so NO
    /// mutation was performed (`guard-reader-writer-parity.md` MUST-2). The
    /// caller decides what "could not read the keychain" means at its own
    /// call site: `csq swap`/`auto_rotate` (A1) abort the switch entirely on
    /// EITHER kind. S5: `csq run`/`csq exec`/phase2b (A2) also refuse on
    /// EITHER kind now — a FRESH handle dir with an `Inaccessible` (present,
    /// locked) read names a stale item from an earlier occupant (PID
    /// reuse), which must not be launched against silently. F5/KC4-7:
    /// carries the [`UnreadableKind`] the read failed with, so the operator
    /// message can still name the more specific case (a stale locked item)
    /// separately from a generic transient read failure.
    Unreadable(UnreadableKind),
    /// F4: X WAS read, and was CONFIRMED `Absent` — so there is no stale
    /// item this write could corrupt or leave inconsistent — but the write
    /// attempt that would have installed the new state itself failed (e.g.
    /// a headless/SSH session where `security add-generic-password` cannot
    /// prompt for keychain unlock). Unlike [`ForcedSyncResult::Unreadable`],
    /// the disk state is KNOWN (still absent); every caller therefore
    /// proceeds WITHOUT the mirror rather than refusing — there is nothing
    /// to leave inconsistent, and CC in the same environment cannot write
    /// the keychain either.
    AbsentWriteFailed,
    /// X was read and this call's forced write was APPLIED — either the new
    /// account's token was written (`wrote_token = true`) or, when the new
    /// binding has no valid token, X's siblings were preserved and its
    /// `claudeAiOauth` stripped or the item deleted outright
    /// (`wrote_token = false`).
    Applied { wrote_token: bool },
    /// S4: X was read and held REAL content, and this call's forced write
    /// attempt itself FAILED. Unlike [`ForcedSyncResult::AbsentWriteFailed`],
    /// a failing `security` exit here does NOT prove no mutation landed — a
    /// watchdog-timed-out `add`/`delete` can report a non-zero exit while
    /// the write already partially committed (the same race F8 names for
    /// the absent case, except here the pre-write state was NOT "nothing to
    /// lose"). v5: the caller no longer restores a snapshot here — it
    /// proceeds exactly as for `Applied`, and [`reconcile_keychain_to_marker`]
    /// is the compensating action if the repoint that follows later fails.
    WriteFailedUnknown,
    /// round 7c D1: `decide_cc_keychain_write`'s rule 3 — X holds a valid
    /// Anthropic identity that matches no account this call could name (not
    /// the handle dir's own marker account). No mutation was performed; the
    /// CALLER must harvest it (the custodian's existing validate-and-adopt
    /// path) for its true owner and re-decide, or refuse and "say so" if
    /// harvesting cannot establish ownership.
    ForeignLoginUnharvested,
    /// round 7c D1: rule 4b — X holds a `claudeAiOauth` key whose
    /// `accessToken`/`refreshToken` identity could not be parsed. No
    /// mutation was performed.
    MalformedOauth,
    /// `keychain-fix-r8.md` C-F2 (structural half): the caller's
    /// `new_credentials_json` carries a `claudeAiOauth` key (this slot IS
    /// Anthropic) but the token is expired or its expiry could not be
    /// parsed — the target is untrustworthy right now, not positively
    /// non-Anthropic. X was never even classified against this outcome;
    /// no mutation was performed. Distinct from [`ForeignLoginUnharvested`]
    /// (that names a problem with X's OWN content); this names a problem
    /// with the TARGET this call was asked to switch to.
    ///
    /// [`ForeignLoginUnharvested`]: ForcedSyncResult::ForeignLoginUnharvested
    TargetTokenInvalidated,
    /// Fresh-launch path only: an unidentified keychain login could not be
    /// saved to the quarantine folder, so it was left untouched. No mutation
    /// was performed.
    QuarantineSaveFailed,
}

/// v4 core (S10-style executor injection, mirroring `write_raw_with_executor`):
/// read X exactly ONCE, then apply an all-or-nothing forced write for a
/// KNOWN account change. NO freshness guard (X's own expiry is meaningless
/// across accounts) and NO backfill (there is no "existing" account whose
/// subscription metadata could apply) — the binding is new, full stop.
///
/// `new_credentials_json`: the raw `.credentials.json` content of the
/// account being switched TO, read by the caller — directly from the
/// target account's own credential file for `csq swap`/`auto_rotate`
/// (the handle dir has not been repointed yet), or from the handle dir's
/// own (already-correct) symlink for a FRESH dir (`csq run`/`csq
/// exec`/phase2b). `None` when there is nothing to mirror (3P/Codex slot,
/// or an unreadable/absent file).
#[cfg(target_os = "macos")]
fn force_sync_account_changed_with_executor(
    exec: &(impl KeychainExecutor + ?Sized),
    base: &Path,
    handle_dir: &Path,
    new_credentials_json: Option<&str>,
) -> Result<ForcedSyncResult, PlatformError> {
    force_sync_inner(exec, base, handle_dir, new_credentials_json, false)
}

/// Directory (under the accounts base) holding quarantined foreign logins.
#[cfg(target_os = "macos")]
const QUARANTINE_DIR_NAME: &str = "keychain-quarantine";

/// Minimum gap between repeats of the same recurring warning.
#[cfg(target_os = "macos")]
const WARN_REPEAT_INTERVAL_MS: u64 = 3_600_000;

/// True at most once per [`WARN_REPEAT_INTERVAL_MS`] for `key` in this
/// process, so a sweep that cannot resolve an entry does not log every tick.
#[cfg(target_os = "macos")]
fn warn_due(key: &str) -> bool {
    static LAST: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, u64>>> =
        std::sync::OnceLock::new();
    let now = now_ms();
    let Ok(mut map) = LAST.get_or_init(Default::default).lock() else {
        return true;
    };
    match map.get(key) {
        Some(&last) if now.saturating_sub(last) < WARN_REPEAT_INTERVAL_MS => false,
        _ => {
            map.retain(|_, t| now.saturating_sub(*t) < WARN_REPEAT_INTERVAL_MS);
            map.insert(key.to_string(), now);
            true
        }
    }
}

/// True when some directory directly under `base_dir` hashes to `svc` (the
/// handle dir this queue entry was recorded for exists again, e.g. a recycled
/// PID's new session, which may have a live owner).
#[cfg(target_os = "macos")]
fn handle_dir_exists_for_service(base_dir: &Path, svc: &str) -> bool {
    let Ok(rd) = std::fs::read_dir(base_dir) else {
        // Cannot enumerate: do not claim the dir is gone.
        return true;
    };
    rd.filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .any(|p| {
            let (abs, canonical) = canonicalize_for_keychain_sync(&p);
            dir_may_own_service(&abs, canonical, svc)
        })
}

/// A dir whose real path could not be resolved is assumed to own the service
/// (keep the item); otherwise it owns it iff its service name matches.
#[cfg(target_os = "macos")]
fn dir_may_own_service(abs: &Path, canonical: bool, svc: &str) -> bool {
    !canonical || service_name(abs) == svc
}

/// Save an unidentified keychain item's raw payload before it is replaced:
/// `<base>/keychain-quarantine/<utc>-<svc-hash>.json`, dir 0700, file 0600,
/// written via tmp + `secure_file` + `atomic_replace` with the tmp removed on
/// every failure branch (security.md §5a). Returns `Err` if it could not be
/// saved, in which case the caller MUST NOT discard the item.
#[cfg(target_os = "macos")]
fn quarantine_foreign_item(base: &Path, svc: &str, raw: &str) -> Result<(), PlatformError> {
    use crate::platform::fs::{atomic_replace, secure_file, unique_tmp_path};
    let dir = base.join(QUARANTINE_DIR_NAME);
    // A symlinked quarantine dir could redirect the saved login elsewhere.
    if let Ok(meta) = std::fs::symlink_metadata(&dir) {
        if meta.file_type().is_symlink() {
            return Err(PlatformError::Keychain(
                "keychain quarantine directory is a symlink".to_string(),
            ));
        }
    }
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let hash = quarantine_svc_hash(svc);
    // Already saved (a retry after an unconfirmed delete): do not write a
    // second copy, which would push other services' files out of the
    // newest-N retention.
    let suffix = format!("-{hash}.json");
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for entry in rd.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(&suffix)
                && std::fs::read_to_string(entry.path()).is_ok_and(|c| c == raw)
            {
                return Ok(());
            }
        }
    }
    let stamp = chrono::DateTime::from_timestamp_millis(now_ms() as i64)
        .map(|t| t.format("%Y%m%dT%H%M%S%3fZ").to_string())
        .unwrap_or_else(|| now_ms().to_string());
    let target = dir.join(format!("{stamp}-{hash}.json"));
    let tmp = unique_tmp_path(&target);
    if let Err(e) = std::fs::write(&tmp, raw.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = secure_file(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = atomic_replace(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    prune_quarantine(&dir, QUARANTINE_KEEP, QUARANTINE_MAX_AGE);
    Ok(())
}

/// The 8-hex suffix of a `Claude Code-credentials-{hash}` service name. It
/// names the quarantine file and is logged with every quarantine event so a
/// saved file can be matched to the event that wrote it. Not a secret: it is
/// a hash of a handle-dir path (see the pending-clear queue note above).
#[cfg(target_os = "macos")]
fn quarantine_svc_hash(svc: &str) -> &str {
    svc.rsplit('-').next().unwrap_or("unknown")
}

/// Newest files kept in the quarantine dir.
#[cfg(target_os = "macos")]
const QUARANTINE_KEEP: usize = 10;
/// Files older than this are removed regardless of count.
#[cfg(target_os = "macos")]
const QUARANTINE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(30 * 24 * 3600);

/// Best-effort retention: keep the newest `keep` `*.json` files (the UTC
/// stamp makes name order chronological) and drop any older than `max_age`
/// by mtime. Never fails the caller.
#[cfg(target_os = "macos")]
fn prune_quarantine(dir: &Path, keep: usize, max_age: std::time::Duration) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<std::path::PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files.reverse(); // newest first
    let now = std::time::SystemTime::now();
    for (i, path) in files.iter().enumerate() {
        let too_old = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age > max_age);
        if (i >= keep || too_old) && std::fs::remove_file(path).is_err() {
            warn!(
                error_kind = "keychain_quarantine_prune_failed",
                "could not remove an old quarantined keychain file"
            );
        }
    }
}

/// Shared body of [`force_sync_account_changed_with_executor`].
/// `quarantine_foreign` is true ONLY for a fresh-handle-dir launch, where any
/// existing item belongs to a dead terminal (PID reuse): an item that stays
/// unidentified after the normal recognition is saved to the quarantine dir
/// and then replaced, instead of refusing the launch. Swaps and the daemon
/// pass false and still refuse.
#[cfg(target_os = "macos")]
fn force_sync_inner(
    exec: &(impl KeychainExecutor + ?Sized),
    base: &Path,
    handle_dir: &Path,
    new_credentials_json: Option<&str>,
    quarantine_foreign: bool,
) -> Result<ForcedSyncResult, PlatformError> {
    let svc = service_name(handle_dir);
    let ours = keychain_account_for(handle_dir);
    let x = exec.find(&svc, &ours);
    // F4/S4/guard-reader-writer-parity.md MUST-2: X's real state is UNKNOWN
    // when unreadable, so no mutation is attempted at all — return early,
    // never reaching `decide_cc_keychain_write`/`apply_cc_keychain_write`.
    if let RawContentClassification::Unreadable(kind) = &x {
        return Ok(ForcedSyncResult::Unreadable(*kind));
    }

    // round 7c D1: route through the single policy
    // (`decide_cc_keychain_write` + `apply_cc_keychain_write`) instead of
    // this function's own bespoke T2/T3 walk. `known` is built from the
    // handle dir's CURRENT marker — pre-repoint that is the SOURCE account
    // (`csq swap`/`auto_rotate`'s caller has not repointed yet); for a
    // fresh launch dir (`csq run`/`csq exec`) it is the account being
    // launched. Either way it is the one token this call can cheaply name
    // as "already safely recorded on disk elsewhere" — X matching it (or
    // matching the intended token itself, rule 2's F5 case) means nothing
    // is lost by overwriting; X matching neither is a foreign login the
    // CALLER must harvest (rule 3) before retrying.
    let marker_account = crate::accounts::markers::resolve_marker_to_slot(base, handle_dir);
    let source_raw: Option<String> = marker_account.and_then(|acct| {
        crate::accounts::identity_store::target_token_for_forced_write(base, acct)
            .as_valid_str()
            .map(str::to_string)
    });
    // C-F1: widen recognition to the marker account's own token history —
    // shared by `csq swap`/`auto_rotate`'s forced write (this function) and,
    // via `force_sync_for_launch_locked`, a fresh launch.
    let history = marker_account
        .map(|acct| crate::credentials::token_history::read_history_for_slot(base, acct))
        .unwrap_or_default();
    let known = KnownTokens {
        marker_account_canonical: source_raw.as_deref(),
        marker_account_history: &history,
        ..KnownTokens::default()
    };

    // `keychain-fix-r8.md` C-F2 structural half: `Intended::Strip`'s own
    // contract (see its doc) is "the target slot is POSITIVELY
    // non-Anthropic" — there is no Anthropic token to mirror at all. That
    // is true of `new_credentials_json == None` and of a payload that
    // lacks a `claudeAiOauth` key entirely (a 3P/Codex slot's own
    // credential shape). It is NOT true of a payload that DOES carry a
    // `claudeAiOauth` key but whose token has expired or could not be
    // parsed — that slot IS Anthropic, its token is merely untrustworthy
    // right now, and folding that case into `Strip` force-writes toward it
    // with delete/strip semantics `Intended::Strip` was never meant to
    // carry (exactly the class C-F2's auto_rotate fix (d5b71371) closed at
    // ONE caller; this closes it structurally, for every caller, present
    // and future). Distinguish the three cases explicitly rather than
    // folding "no valid token" into a single `Option`.
    let intended = match new_credentials_json {
        None => Intended::Strip,
        Some(raw) if !raw.contains("\"claudeAiOauth\"") => Intended::Strip,
        Some(raw) => match anthropic_expiry_ms(raw).filter(|&ms| ms > now_ms()) {
            Some(_) => Intended::Token(raw),
            // The payload IS an Anthropic credential shape, but is expired
            // or its expiry could not be parsed — refuse rather than
            // strip. No mutation has happened yet (X has not been touched
            // above this line).
            None => return Ok(ForcedSyncResult::TargetTokenInvalidated),
        },
    };

    match decide_cc_keychain_write(&x, &known, intended) {
        WriteDecision::RefuseUnharvested if quarantine_foreign => {
            // Fresh-launch path: save the unidentified login, then replace
            // it. If it cannot be saved it is NOT discarded: refuse as before.
            // `RefuseUnharvested` is only decided over `Content`; if that ever
            // stops holding, the item's state is unknown, not a disk problem.
            let RawContentClassification::Content(raw_x) = &x else {
                return Ok(ForcedSyncResult::WriteFailedUnknown);
            };
            if quarantine_foreign_item(base, &svc, raw_x).is_err() {
                warn!(
                    error_kind = "keychain_fresh_launch_quarantine_failed",
                    svc_hash = quarantine_svc_hash(&svc),
                    "could not save the unidentified keychain login; refusing the launch"
                );
                return Ok(ForcedSyncResult::QuarantineSaveFailed);
            }
            warn!(
                error_kind = "keychain_fresh_launch_quarantined_foreign_item",
                svc_hash = quarantine_svc_hash(&svc),
                "an unidentified keychain login on a fresh launch was saved and replaced"
            );
            // Write against an ABSENT view so nothing from the foreign item
            // (its siblings) is merged into the new account's item.
            let absent = RawContentClassification::Absent;
            let decision = match intended {
                Intended::Token(raw) => WriteDecision::Write(raw),
                Intended::Strip => WriteDecision::StripAllowed,
            };
            match apply_cc_keychain_write(exec, &svc, &ours, &absent, decision, false) {
                ApplyOutcome::Applied { wrote_token } => {
                    Ok(ForcedSyncResult::Applied { wrote_token })
                }
                // The foreign item is saved; a failed replace leaves its
                // state unknown, so do not launch against it.
                ApplyOutcome::AbsentWriteFailed
                | ApplyOutcome::WriteFailed
                | ApplyOutcome::NoOp => Ok(ForcedSyncResult::WriteFailedUnknown),
            }
        }
        WriteDecision::RefuseUnharvested => Ok(ForcedSyncResult::ForeignLoginUnharvested),
        // `keychain-fix-r11.md` S-M-3 residual: `intended` was already
        // filtered to `ms > now_ms()` above before `Intended::Token` was even
        // constructed — this backstop firing here means the token expired in
        // the (sub-tick) window between that filter and this decision. Same
        // caller-facing shape as an invalid target: the target is not
        // presently trustworthy.
        WriteDecision::RefuseIntendedExpired => Ok(ForcedSyncResult::TargetTokenInvalidated),
        WriteDecision::Unknown(WriteUnknownReason::MalformedOauth) => {
            Ok(ForcedSyncResult::MalformedOauth)
        }
        WriteDecision::Unknown(WriteUnknownReason::KeychainUnreadable) => {
            unreachable!("x was already confirmed non-Unreadable above")
        }
        // F5: X already holds the intended token — nothing to write, but
        // report the same `Applied { wrote_token: true }` shape the old T2
        // code reported for a no-op-equivalent write, so this is not an
        // externally observable behaviour change for existing callers.
        WriteDecision::NoWrite => Ok(ForcedSyncResult::Applied { wrote_token: true }),
        decision @ (WriteDecision::Write(_) | WriteDecision::StripAllowed) => {
            match apply_cc_keychain_write(
                exec, &svc, &ours, &x, decision, /* backfill_allowed */ false,
            ) {
                ApplyOutcome::Applied { wrote_token } => {
                    Ok(ForcedSyncResult::Applied { wrote_token })
                }
                ApplyOutcome::AbsentWriteFailed => Ok(ForcedSyncResult::AbsentWriteFailed),
                ApplyOutcome::WriteFailed => Ok(ForcedSyncResult::WriteFailedUnknown),
                ApplyOutcome::NoOp => {
                    unreachable!(
                        "apply_cc_keychain_write never no-ops a Write/StripAllowed decision"
                    )
                }
            }
        }
    }
}

/// Non-macOS: no keychain item exists at all, so there is nothing to force.
/// Reports the same "resolved, nothing written" shape a would-be caller's
/// disposition logic expects.
#[cfg(not(target_os = "macos"))]
fn force_sync_account_changed_with_executor(
    _base: &Path,
    _handle_dir: &Path,
    _new_credentials_json: Option<&str>,
) -> Result<ForcedSyncResult, PlatformError> {
    Ok(ForcedSyncResult::Applied { wrote_token: false })
}

/// v4 public entry point for a KNOWN account change — read X once, then
/// write an all-or-nothing forced update. See [`ForcedSyncResult`] for what
/// each outcome means and how `csq swap`/`auto_rotate` (A1) vs `csq
/// run`/`csq exec`/phase2b (A2) MUST respond to it.
///
/// `base` (round 7c D1): the accounts base dir, needed to resolve
/// `handle_dir`'s current marker and that account's own canonical token so
/// the write can be routed through the single policy
/// (`decide_cc_keychain_write`) rather than writing unconditionally.
#[cfg(target_os = "macos")]
pub fn force_sync_account_changed(
    base: &Path,
    handle_dir: &Path,
    new_credentials_json: Option<&str>,
) -> Result<ForcedSyncResult, PlatformError> {
    // round 7c D-F7: a test-installed scripted executor takes priority over
    // the disabled-mirror no-op, so `handle()`-level tests drive the real
    // decide+apply policy. Checked BEFORE `keychain_mirror_disabled()` —
    // see `test_keychain_executor_override`'s doc.
    #[cfg(any(test, feature = "test-utils"))]
    if let Some(exec) = test_keychain_executor_override() {
        return force_sync_account_changed_with_executor(
            &*exec,
            base,
            handle_dir,
            new_credentials_json,
        );
    }
    if keychain_mirror_disabled() {
        return Ok(ForcedSyncResult::Applied { wrote_token: false });
    }
    force_sync_account_changed_with_executor(
        &SecurityCliExecutor,
        base,
        handle_dir,
        new_credentials_json,
    )
}

/// [`force_sync_account_changed`] for a FRESH-handle-dir launch: an item that
/// stays unidentified is quarantined and replaced rather than refused.
#[cfg(target_os = "macos")]
fn force_sync_account_changed_for_launch(
    base: &Path,
    handle_dir: &Path,
    new_credentials_json: Option<&str>,
) -> Result<ForcedSyncResult, PlatformError> {
    #[cfg(any(test, feature = "test-utils"))]
    if let Some(exec) = test_keychain_executor_override() {
        return force_sync_inner(&*exec, base, handle_dir, new_credentials_json, true);
    }
    if keychain_mirror_disabled() {
        return Ok(ForcedSyncResult::Applied { wrote_token: false });
    }
    force_sync_inner(
        &SecurityCliExecutor,
        base,
        handle_dir,
        new_credentials_json,
        true,
    )
}

#[cfg(not(target_os = "macos"))]
fn force_sync_account_changed_for_launch(
    base: &Path,
    handle_dir: &Path,
    new_credentials_json: Option<&str>,
) -> Result<ForcedSyncResult, PlatformError> {
    force_sync_account_changed_with_executor(base, handle_dir, new_credentials_json)
}

#[cfg(not(target_os = "macos"))]
pub fn force_sync_account_changed(
    base: &Path,
    handle_dir: &Path,
    new_credentials_json: Option<&str>,
) -> Result<ForcedSyncResult, PlatformError> {
    force_sync_account_changed_with_executor(base, handle_dir, new_credentials_json)
}

// ── v5 — reconcile-to-links (2026-09-26 owner directive) ──────────────
//
// Rounds 1-5 kept finding desync paths in a restore-to-snapshot model that
// used to live here: a snapshot of what X held at READ time, restored back
// on a later failure. That snapshot describes X at read time, not the
// account the handle dir's OWN symlinks/marker actually name by the time a
// caller gets around to restoring it. Any ordering of a repoint's partial
// rollback, a retry, or a second concurrent writer could leave that
// snapshot stale before it was ever written back. It has been removed.
//
// The replacement: after ANY switch failure, do not ask "what did X hold
// before" — ask "what does this handle dir's marker say NOW", and make X
// match THAT. This is idempotent and convergent: however many failures
// preceded it, and in whatever order, reconciling to the current marker
// always ends in the same state — X agrees with the marker. There is no
// snapshot to go stale, because the compensating action is instead
// re-derived every time it runs.

/// Why [`ReconcileOutcome::KeychainUnknown`] fired — message-only; every
/// variant's disposition is identical (no write, no delete, no strip).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainUnknownReason {
    /// X itself could not be classified (rule 2) — `security find` did not
    /// resolve to a clean present/absent read.
    KeychainUnreadable,
    /// X. matched the token this call force-wrote for a DIFFERENT account
    /// than the current marker, but the marker account's OWN canonical file
    /// is unreadable, expired, or not a valid Anthropic token — there is
    /// nothing trustworthy to overwrite X WITH (rule 4's fallback / H1).
    MarkerTokenUntrusted,
    /// X holds real content that matches NEITHER the marker account's own
    /// token NOR (if any) the token this call force-wrote — a login csq did
    /// not write (e.g. CC self-refreshed under an account this call cannot
    /// classify) (rule 6/7).
    ForeignLogin,
}

/// Outcome of [`reconcile_keychain_to_marker`].
#[derive(Debug, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// `handle_dir`'s `.csq-account` marker could not be read or resolved
    /// to a slot (`resolve_marker_to_slot` returned `None`) —
    /// `guard-reader-writer-parity.md` MUST-2: this is a destructive-path
    /// guard, so an unclassifiable marker fails CLOSED. Nothing was
    /// written; X is left however the failed switch left it.
    MarkerUnreadable,
    /// The marker resolved to `marker_account`, and X already held that
    /// account's token BY IDENTITY (`guard-reader-writer-parity.md`
    /// MUST-1: expiry alone cannot tell accounts apart — see the module's
    /// PRIMARY DIRECTIVE note above) — or `marker_account` has no valid
    /// token to mirror, and X was already empty — nothing needed writing.
    AlreadyCurrent { marker_account: AccountNum },
    /// The marker resolved to `marker_account`, and X was written (or
    /// cleared) to match it.
    Reconciled { marker_account: AccountNum },
    /// The marker resolved to `marker_account`, X was CONFIRMED to need a
    /// write toward it (or an existing entry toward it), but the write
    /// itself failed / left X's state unknown.
    WriteFailed { marker_account: AccountNum },
    /// The marker resolved to `marker_account`, but X's state relative to it
    /// could not be safely determined at all — see
    /// [`KeychainUnknownReason`]. No mutation was performed in ANY case.
    KeychainUnknown {
        marker_account: AccountNum,
        reason: KeychainUnknownReason,
    },
}

/// What THIS call's own force-write attempted, passed by the caller so
/// [`reconcile_keychain_to_marker`] can classify X by IDENTITY instead of by
/// expiry alone. PRIMARY DIRECTIVE (2026-09-26): the deleted v4 comment had
/// already recorded that an expiry-only guard cannot tell accounts apart,
/// and the v5 reconcile below reused that same guard (`C1`/`B1`) — this
/// struct is what lets the rewrite stop doing that.
/// Deliberately does NOT `#[derive(Debug)]` (`credential-type-hygiene.md`
/// Rule 1): `raw_json` is a live OAuth credential payload. The manual impl
/// below redacts it; see `forced_write_attempt_debug_redacts_raw_json`.
#[derive(Clone, Copy)]
pub struct ForcedWriteAttempt<'a> {
    /// The account this call attempted to force-write X for.
    pub account: AccountNum,
    /// The raw `.credentials.json` content it attempted to write — `None`
    /// when the write was a strip/delete (no valid token for `account`,
    /// e.g. a 3P/Codex slot) rather than a token write.
    pub raw_json: Option<&'a str>,
}

impl std::fmt::Debug for ForcedWriteAttempt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForcedWriteAttempt")
            .field("account", &self.account)
            .field(
                "raw_json",
                &self.raw_json.map(|_| "[REDACTED]").unwrap_or("None"),
            )
            .finish()
    }
}

/// Extract `(accessToken, refreshToken)` from an Anthropic credential JSON's
/// `claudeAiOauth` object — the IDENTITY of the token, as opposed to its
/// expiry. `None` when the field is missing or either sub-field is not a
/// string (`doc-property-claims.md` MUST-1: this is the mechanism that makes
/// "same account" checkable, rather than an expiry comparison that cannot
/// tell accounts apart at all).
// Platform-independent pure helper — unconditional so it compiles and its
// tests run on every platform; its only PRODUCTION caller
// (`reconcile_keychain_to_marker_with_executor`) is still macOS-gated, so it
// is genuinely unused in a non-test, non-macOS build.
/// S-LOW-2: takes an already-parsed `&serde_json::Value` and returns
/// BORROWED `&str` slices into it — no `String` allocation, so a token's
/// bytes are never copied merely to compare identity. Only the CALLER
/// (`keychain_content_matches_token`) owns the parsed `Value`s, and only
/// for the lifetime of the comparison.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn oauth_identity(v: &serde_json::Value) -> Option<(&str, &str)> {
    let oauth = v.get("claudeAiOauth")?;
    let access = oauth.get("accessToken")?.as_str()?;
    let refresh = oauth.get("refreshToken")?.as_str()?;
    Some((access, refresh))
}

/// Directive rule 1: `x` holds NO login at all — either the item is
/// confirmed absent, or its content parses as a JSON object that lacks
/// the `claudeAiOauth` key ENTIRELY or carries it with both tokens empty
/// ([`oauth_tokens_both_empty`]) (as opposed to one present but
/// malformed/incomplete, which stays rule 6/7's "unclassifiable, never
/// overwrite" case — this fn does NOT collapse the two). A keychain item
/// with no login recorded is free to write; nothing is lost by doing so.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn holds_no_login(x: &RawContentClassification) -> bool {
    match x {
        RawContentClassification::Absent => true,
        RawContentClassification::Content(json) => serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .and_then(|v| {
                v.as_object().map(|o| match o.get("claudeAiOauth") {
                    None => true,
                    Some(oauth) => oauth_tokens_both_empty(oauth),
                })
            })
            .unwrap_or(false),
        RawContentClassification::Unreadable(_) => false,
    }
}

/// `true` when a `claudeAiOauth` object carries BOTH `accessToken` and
/// `refreshToken` as empty strings: the shape Claude Code leaves after a
/// failed refresh clears its login (observed 2026-10-02: empty tokens,
/// `expiresAt: 0`, plan metadata kept). With no refresh token there is no
/// login to lose, so this is "no login" (rule 1), never an unidentified
/// account. Exactly-empty on BOTH sides only: a single empty token, a
/// missing field, or a non-string value is not this shape and stays with the
/// unparseable/unidentified rules.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn oauth_tokens_both_empty(oauth: &serde_json::Value) -> bool {
    let empty = |k: &str| oauth.get(k).and_then(|t| t.as_str()) == Some("");
    empty("accessToken") && empty("refreshToken")
}

/// `true` when `x` is content whose `claudeAiOauth` has both tokens empty
/// ([`oauth_tokens_both_empty`]). Such an item holds no credential, but Claude
/// Code reads it keychain-first and is logged out, so a path that would leave
/// it in place must not report the terminal as current.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn holds_emptied_login(x: &RawContentClassification) -> bool {
    match x {
        RawContentClassification::Content(json) => serde_json::from_str::<serde_json::Value>(json)
            .ok()
            .and_then(|v| v.get("claudeAiOauth").map(oauth_tokens_both_empty))
            .unwrap_or(false),
        RawContentClassification::Absent | RawContentClassification::Unreadable(_) => false,
    }
}

/// `true` only when `x` is [`RawContentClassification::Content`] AND its
/// `claudeAiOauth` identity matches `candidate_raw`'s. A `candidate_raw`
/// (or `x`) whose `claudeAiOauth` is missing/unparseable NEVER matches —
/// rule 7: unparseable is unclassifiable, not a match.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn keychain_content_matches_token(x: &RawContentClassification, candidate_raw: &str) -> bool {
    match x {
        RawContentClassification::Content(json) => {
            // S-LOW-2: parse once each, compare BORROWED &str slices — no
            // token String copies made merely to check identity.
            let Ok(x_val) = serde_json::from_str::<serde_json::Value>(json) else {
                return false;
            };
            let Ok(candidate_val) = serde_json::from_str::<serde_json::Value>(candidate_raw) else {
                return false;
            };
            match (oauth_identity(&x_val), oauth_identity(&candidate_val)) {
                // An empty refresh token is no credential, so it identifies
                // nothing: two emptied logins must never "match".
                (Some(a), Some(b)) => !a.1.is_empty() && a == b,
                _ => false,
            }
        }
        RawContentClassification::Absent | RawContentClassification::Unreadable(_) => false,
    }
}

/// Make `handle_dir`'s keychain item (X, the ONE item CC reads) agree with
/// whatever account its `.csq-account` marker names RIGHT NOW — the
/// compensating action for ANY switch failure (`csq swap`, `auto_rotate`,
/// a repoint whose own rollback did or did not fully land), replacing a
/// restore to a pre-write snapshot. See the module-level "v5" note above
/// for why: the snapshot describes X at read time, not the account the
/// handle dir actually names after the failure settles.
///
/// `base`: the accounts base dir — needed to resolve the marker account's
/// OWN canonical credential file via
/// [`crate::accounts::identity_store::target_token_for_forced_write`],
/// independent of `handle_dir`'s (possibly still-mid-repoint) symlinks.
///
/// PRIMARY DIRECTIVE (2026-09-26, superseding the paragraph this replaces —
/// `doc-property-claims.md` MUST-1/3, "grep and fix every doc that argued
/// for the replaced behaviour"): X is classified by IDENTITY
/// (`oauth_identity` — `claudeAiOauth.accessToken`/`refreshToken`), never by
/// expiry alone. The deleted v4 comment had already recorded that an
/// expiry-only guard cannot tell accounts apart; this function's own v5
/// body used to reuse that same guard anyway (`keychain_is_fresher_or_equal_or_unknown`)
/// via `expiry_read_from_content` — which could report X "already
/// current" against a DIFFERENT account's token merely because that
/// account's own expiry happened to be later. `forced_write` (an
/// [`Option<ForcedWriteAttempt>`]) lets the caller additionally identify X
/// as "the token we just force-wrote for a different account" (rule 4)
/// rather than an unrelated foreign login (rule 6/7) it must never
/// overwrite. A caller MUST hold [`lock_handle_dir_for_swap_bounded`]'s
/// guard across this call, same as [`force_swap_write_before_repoint`].
///
/// Fixed in this pass: every sibling v4/v5 entry point
/// ([`force_sync_account_changed`], [`force_sync_for_launch`]) checks
/// `keychain_mirror_disabled` before touching a real keychain item; this
/// one did not, despite the `_with_executor` core's own doc comment already
/// claiming "that guard belongs to the public entry point" —
/// `doc-property-claims.md`: a property the code did not actually have. Any
/// caller-level test that exercised the FAILURE path (the only path that
/// calls this fn) would have shelled a REAL `security` command. Under the
/// guard, behaves exactly like the non-macOS stub below: resolve the
/// marker and report `AlreadyCurrent`/`MarkerUnreadable` with no write.
#[cfg(target_os = "macos")]
pub fn reconcile_keychain_to_marker(
    base: &Path,
    handle_dir: &Path,
    forced_write: Option<ForcedWriteAttempt<'_>>,
) -> ReconcileOutcome {
    // round 7c D-F7: same override as `force_sync_account_changed` — see
    // that function's comment.
    #[cfg(any(test, feature = "test-utils"))]
    if let Some(exec) = test_keychain_executor_override() {
        return reconcile_keychain_to_marker_with_executor(&*exec, base, handle_dir, forced_write);
    }
    if keychain_mirror_disabled() {
        return match crate::accounts::markers::resolve_marker_to_slot(base, handle_dir) {
            Some(marker_account) => ReconcileOutcome::AlreadyCurrent { marker_account },
            None => ReconcileOutcome::MarkerUnreadable,
        };
    }
    reconcile_keychain_to_marker_with_executor(&SecurityCliExecutor, base, handle_dir, forced_write)
}

/// Executor-injected core of [`reconcile_keychain_to_marker`] — no
/// `keychain_mirror_disabled()` short-circuit here (that guard belongs to
/// the public entry point), so a test can drive this directly against a
/// [`RecordingExecutor`].
///
/// PRIMARY DIRECTIVE (2026-09-26, "reconcile decides by IDENTITY, never by
/// expiry alone, and never destroys what it cannot classify"): X's
/// `claudeAiOauth` is classified against TWO candidate identities — the
/// marker account's own canonical token, and (if given) the token this call
/// itself force-wrote for a possibly-different account — never against
/// expiry alone. Rule numbers below are the brief's.
///
/// (round 7b, 2026-09-26): rewritten to route through the single policy
/// ([`decide_cc_keychain_write`]) + its executor entry
/// ([`apply_cc_keychain_write`]) instead of its own bespoke rule-1..7 walk.
/// The old rule numbers are preserved as comments below so the mapping is
/// auditable; behaviour is unchanged EXCEPT that this version reads X
/// exactly once (the old version's rule-4/5 tail delegated to
/// [`force_sync_account_changed_with_executor`], which performed its OWN
/// second `exec.find()` before writing — a redundant read this module's own
/// v4/v5 history has repeatedly flagged as the source of desync races; it
/// is removed here by calling [`apply_cc_keychain_write`] directly against
/// the SAME `x` this function already read).
#[cfg(target_os = "macos")]
fn reconcile_keychain_to_marker_with_executor(
    exec: &(impl KeychainExecutor + ?Sized),
    base: &Path,
    handle_dir: &Path,
    forced_write: Option<ForcedWriteAttempt<'_>>,
) -> ReconcileOutcome {
    // Old rule 1: marker unreadable -> no write, fail closed.
    let Some(marker_account) = crate::accounts::markers::resolve_marker_to_slot(base, handle_dir)
    else {
        return ReconcileOutcome::MarkerUnreadable;
    };

    let svc = service_name(handle_dir);
    let ours = keychain_account_for(handle_dir);
    let x = exec.find(&svc, &ours);

    // H1: the marker account's own canonical token, three-way classified
    // (Valid / ExpiredOrInvalid / Unreadable) rather than folded into a
    // bare Option — the untrusted-marker fallback below needs to say "this
    // file cannot be trusted", not merely "there is nothing to write".
    let marker_token =
        crate::accounts::identity_store::target_token_for_forced_write(base, marker_account);

    // decide_cc_keychain_write's `Intended` contract (see its own doc): a
    // caller with no VALID token to mirror resolves that BEFORE calling the
    // policy, never inside it — there is no `Intended` variant for "the
    // target is Anthropic but its own file is untrustworthy". When the
    // marker account's own canonical file cannot itself be trusted, fall
    // back directly: old rule 5's `None` arm (nothing to write, nothing
    // lost, when X already holds no login) or old rule 6/7's
    // `MarkerTokenUntrusted` reason (X holds something and there is nothing
    // trustworthy to compare it against) — UNLESS X holds exactly the token
    // THIS call itself force-wrote (`keychain-fix-r8.md` C-F7): that token
    // is already recorded, safely, in ITS OWN account's canonical store
    // (whichever account `forced_write.account` was), so stripping X here
    // loses nothing. Leaving it in place instead would strand the terminal
    // silently reading that OTHER account's token while csq reports this
    // handle dir's own marker account as untrustworthy — the exact
    // "leaving the terminal on the wrong account" case C-F7 names.
    let Some(marker_raw) = marker_token.as_valid_str() else {
        // An emptied login is "no login" for write safety, but it leaves the
        // terminal logged out; with no trusted token to replace it, report it
        // rather than calling the terminal current.
        if holds_no_login(&x) && !holds_emptied_login(&x) {
            return ReconcileOutcome::AlreadyCurrent { marker_account };
        }
        if let Some(csq_written) = forced_write.and_then(|fw| fw.raw_json) {
            if keychain_content_matches_token(&x, csq_written) {
                let strip_known = KnownTokens {
                    csq_written: Some(csq_written),
                    ..KnownTokens::default()
                };
                return match decide_cc_keychain_write(&x, &strip_known, Intended::Strip) {
                    WriteDecision::StripAllowed => match apply_cc_keychain_write(
                        exec,
                        &svc,
                        &ours,
                        &x,
                        WriteDecision::StripAllowed,
                        false,
                    ) {
                        ApplyOutcome::Applied { .. } | ApplyOutcome::AbsentWriteFailed => {
                            ReconcileOutcome::Reconciled { marker_account }
                        }
                        ApplyOutcome::WriteFailed => {
                            ReconcileOutcome::WriteFailed { marker_account }
                        }
                        ApplyOutcome::NoOp => unreachable!(
                            "apply_cc_keychain_write never no-ops a StripAllowed decision"
                        ),
                    },
                    // `keychain_content_matches_token(&x, csq_written)` just
                    // confirmed X matches a token in `strip_known.iter_raw()`,
                    // so rule 2's `matches_known` is true and `Intended::Strip`
                    // can only resolve to `StripAllowed` (rule 1's `holds_no_login`
                    // was already ruled out above; rule 4 requires `current`
                    // itself to be unclassifiable, which a successful content
                    // match rules out).
                    other => unreachable!(
                        "a confirmed csq_written match must decide StripAllowed, got {other:?}"
                    ),
                };
            }
        }
        return ReconcileOutcome::KeychainUnknown {
            marker_account,
            reason: KeychainUnknownReason::MarkerTokenUntrusted,
        };
    };

    // Old rules 3/4 collapse into policy rule 2 (matches ANY known token,
    // not just the marker's): passing the force-write's token as
    // `csq_written` alongside the marker's own canonical token as
    // `marker_account_canonical` reproduces both old cases — when
    // `fw.account == marker_account` the two raw strings are identical
    // (harmless duplication), and F5 (already the intended token) is
    // exactly old rule 3's `AlreadyCurrent`.
    // C-F1: widen recognition to the marker account's own token history.
    let history = crate::credentials::token_history::read_history_for_slot(base, marker_account);
    let known = KnownTokens {
        marker_account_canonical: Some(marker_raw),
        csq_written: forced_write.and_then(|fw| fw.raw_json),
        marker_account_history: &history,
        ..KnownTokens::default()
    };

    match decide_cc_keychain_write(&x, &known, Intended::Token(marker_raw)) {
        WriteDecision::NoWrite => ReconcileOutcome::AlreadyCurrent { marker_account },
        write @ WriteDecision::Write(_) => {
            match apply_cc_keychain_write(exec, &svc, &ours, &x, write, false) {
                ApplyOutcome::Applied { .. } | ApplyOutcome::AbsentWriteFailed => {
                    ReconcileOutcome::Reconciled { marker_account }
                }
                ApplyOutcome::WriteFailed => ReconcileOutcome::WriteFailed { marker_account },
                ApplyOutcome::NoOp => {
                    unreachable!("apply_cc_keychain_write never no-ops a Write decision")
                }
            }
        }
        // Old rule 6/7's "matches neither candidate, a login csq did not
        // write" case — reported identically (`ForeignLogin`); the marker
        // is trusted at this point (checked above), so old's
        // `MarkerTokenUntrusted` alternative in that branch cannot arise
        // here.
        WriteDecision::RefuseUnharvested => ReconcileOutcome::KeychainUnknown {
            marker_account,
            reason: KeychainUnknownReason::ForeignLogin,
        },
        // `keychain-fix-r11.md` S-M-3 residual: `marker_raw` was already
        // confirmed Valid above (`marker_token.as_valid_str()`) — this
        // backstop firing here means the marker account's own token expired
        // in the window between that check and this decision. Reported the
        // same way MarkerTokenUntrusted is reported elsewhere in this
        // function: the marker's own token is not presently trustworthy.
        WriteDecision::RefuseIntendedExpired => ReconcileOutcome::KeychainUnknown {
            marker_account,
            reason: KeychainUnknownReason::MarkerTokenUntrusted,
        },
        // Old rule 2: X itself is unclassifiable.
        WriteDecision::Unknown(WriteUnknownReason::KeychainUnreadable) => {
            ReconcileOutcome::KeychainUnknown {
                marker_account,
                reason: KeychainUnknownReason::KeychainUnreadable,
            }
        }
        // Old rule 6/7's "unparseable `claudeAiOauth`" sub-case — old code
        // reported this identically to a genuine foreign login
        // (`ForeignLogin`); the new policy merely names the malformed case
        // separately (rule 4b) without changing this caller's reported
        // reason.
        WriteDecision::Unknown(WriteUnknownReason::MalformedOauth) => {
            ReconcileOutcome::KeychainUnknown {
                marker_account,
                reason: KeychainUnknownReason::ForeignLogin,
            }
        }
        // `Intended::Token` is always what this function passes — never
        // `Intended::Strip` — so `StripAllowed` cannot be returned. Kept as
        // an explicit arm (not a wildcard) so a future policy change is a
        // compile error here, never a silent fallthrough.
        WriteDecision::StripAllowed => {
            unreachable!("reconcile_keychain_to_marker never passes Intended::Strip")
        }
    }
}

/// Non-macOS: no keychain exists, so there is nothing to reconcile. Still
/// resolves and returns the marker so a caller's fail-closed check
/// (`MarkerUnreadable`) behaves identically cross-platform.
#[cfg(not(target_os = "macos"))]
pub fn reconcile_keychain_to_marker(
    base: &Path,
    handle_dir: &Path,
    _forced_write: Option<ForcedWriteAttempt<'_>>,
) -> ReconcileOutcome {
    match crate::accounts::markers::resolve_marker_to_slot(base, handle_dir) {
        Some(marker_account) => ReconcileOutcome::AlreadyCurrent { marker_account },
        None => ReconcileOutcome::MarkerUnreadable,
    }
}

/// v4 A1 helper for `csq swap`'s same-surface ClaudeCode route and
/// `auto_rotate::tick` — performs the forced write for a KNOWN account
/// change and translates its outcome into the fixed operator-facing
/// disposition A1 requires. Does NOT lock: the caller MUST already hold
/// [`lock_handle_dir_for_swap_bounded`]'s guard across this call AND the
/// repoint that follows it (`record_keychain_account_hint` too, for a
/// CLI-context caller) — the exclusion this whole transition needs is
/// against the daemon custodian's harvest, which spans write+repoint, not
/// just the write.
///
/// Chosen order (owner brief): **write X, then repoint**.
///
/// K5 (doc fix — the prior wording claimed BOTH refusal cases below leave
/// nothing mutated and the switch not proceeding; that is true only of the
/// FIRST): an unreadable X means NOTHING was mutated and the switch cleanly
/// does NOT happen — this function returns `Err` and the caller's `?`
/// returns before any repoint runs. A write failure over a CONFIRMED-absent
/// X (F4) is DIFFERENT: X is unchanged (still absent, same as before the
/// call) but the switch DOES proceed — this function returns
/// `Ok(ForcedSyncResult::AbsentWriteFailed)`, and the caller repoints next
/// exactly as it would for a successful write, just without a keychain
/// mirror. S4: a write failure over KNOWN (`Content`) prior state is a THIRD
/// case — the resulting disk state is UNKNOWN, so this function passes
/// [`ForcedSyncResult::WriteFailedUnknown`] straight through as `Ok` too;
/// the caller proceeds to the repoint exactly as for `Applied`/
/// `AbsentWriteFailed`. v5: there is no longer an immediate restore attempt
/// here — [`reconcile_keychain_to_marker`] is the caller's SINGLE
/// compensating action, run after the repoint (whichever way it goes), so
/// this function no longer needs to distinguish "restore now" from "restore
/// later".
///
/// Returns `Err` with a fixed operator-facing message (no raw paths) when
/// X could not be read — A1: the switch must NOT be performed. On `Ok`, the
/// caller always proceeds to the repoint next, and reconciles afterward.
pub fn force_swap_write_before_repoint(
    base: &Path,
    handle_dir_abs: &Path,
    new_credentials_json: Option<&str>,
) -> Result<ForcedSyncResult, String> {
    decide_swap_disposition(force_sync_account_changed(
        base,
        handle_dir_abs,
        new_credentials_json,
    ))
}

/// F8/KC4-10 decision seam: the disposition `force_swap_write_before_repoint`
/// applies to a [`force_sync_account_changed`] outcome, factored out as a
/// PURE function of that outcome so it is directly unit-testable with a
/// synthetic `Result` — no `security` subprocess, no lock, no hint file.
fn decide_swap_disposition(
    result: Result<ForcedSyncResult, PlatformError>,
) -> Result<ForcedSyncResult, String> {
    match result {
        // F5/KC4-7: swap refuses on EITHER `UnreadableKind` — unlike a
        // launch, an EXISTING dir's symlinks would repoint to a NEW account
        // while its keychain item is left in an UNKNOWN state; "CC can't
        // read the keychain either" is not a safe default here the way it
        // is for a fresh dir with no prior session.
        Ok(ForcedSyncResult::Unreadable(_)) => {
            Err("the keychain could not be read; nothing changed — retry the swap".to_string())
        }
        // F4: X was CONFIRMED absent; the write that would have installed the
        // new token failed, but nothing was left inconsistent (still
        // absent) — proceed with the repoint rather than refuse the swap.
        Ok(ForcedSyncResult::AbsentWriteFailed) => {
            warn!(
                error_kind = "keychain_swap_absent_write_failed_proceeding",
                "csq swap: the keychain item was absent and could not be created; proceeding with the switch without a keychain mirror"
            );
            Ok(ForcedSyncResult::AbsentWriteFailed)
        }
        // round 7c D1/D5: rule 3 — X holds a valid Anthropic identity this
        // call could not name. The D5 CLI caller harvests (the D3 IPC
        // route) BEFORE calling this function at all; reaching this arm
        // means harvesting either was not attempted or failed to establish
        // ownership. No mutation was performed — refuse, "say so".
        //
        // `keychain-fix-r8.md` C-F1 (message rewrite): C-F1's history match
        // now recognizes the marker account's OWN superseded tokens as rule
        // 2, so reaching THIS arm means the item is genuinely unidentified —
        // never "Claude Code just refreshed" stated as fact (that was a
        // guess, and a wrong one whenever the item held a stale-but-known
        // token, which C-F1 now catches earlier). The remedy also no longer
        // loops on the same failing command: it names the account-scoped fix
        // (`csq login`) instead of "run the command again", which repeats
        // the exact refusal against the exact same unidentified item.
        Ok(ForcedSyncResult::ForeignLoginUnharvested) => Err(
            "the keychain holds a login csq could not identify as this account's own; nothing \
             was changed — if it belongs to a different account, run `csq login <n>` for that \
             account to establish ownership, then retry the swap"
                .to_string(),
        ),
        // rule 4b: X's `claudeAiOauth` could not be parsed — as unreadable
        // for this caller's purposes, no mutation was performed.
        Ok(ForcedSyncResult::MalformedOauth) => {
            Err("the keychain could not be read; nothing changed — retry the swap".to_string())
        }
        // `keychain-fix-r8.md` C-F2 (structural half): the TARGET account's
        // own token stopped being valid between selection and this call
        // (a concurrent refresh failure or logout). No mutation was
        // performed — refuse the swap outright rather than force-write
        // toward an untrustworthy target.
        Ok(ForcedSyncResult::TargetTokenInvalidated) => Err(
            "the target account's own login is no longer valid; nothing changed — \
             run `csq login <n>` for that account, then retry the swap"
                .to_string(),
        ),
        // Produced only by the fresh-launch path; a swap never quarantines.
        Ok(ForcedSyncResult::QuarantineSaveFailed) => {
            Err("the keychain is busy or unavailable; nothing changed — retry the swap".to_string())
        }
        Ok(applied) => Ok(applied),
        Err(_e) => {
            Err("the keychain is busy or unavailable; nothing changed — retry the swap".to_string())
        }
    }
}

/// v5: the operator-facing line for ANY switch outcome (`csq swap`,
/// `auto_rotate`'s tick, and the S7 pre-flight refusal alike), derived
/// SOLELY from a [`reconcile_keychain_to_marker`] outcome plus the account
/// the switch STARTED from — never from a repoint's own `Ok`/`Err`, and
/// never from [`crate::error::CredentialError::repoint_rolled_back`]. The
/// marker `reconcile_keychain_to_marker` just read is the one fact that
/// cannot be stale by the time this runs (`guard-reader-writer-parity.md`:
/// "the marker read is the source of truth", 2026-09-26 owner directive) —
/// whether the repoint that preceded it actually committed is inferred
/// from whether the marker MOVED, not asserted by the caller.
///
/// Shared by `csq swap`'s same-surface ClaudeCode route and
/// `daemon::auto_rotate`'s tick so the two operator-facing vocabularies can
/// never drift apart. Each caller prefixes its own context (`"csq swap: "`
/// / `"auto-rotation: "`).
/// B4: `original_account` is `Option<AccountNum>` — the caller passes
/// `None` when the account this switch STARTED from could not be
/// determined (e.g. `csq swap`'s source marker was already unreadable at
/// swap start). Claiming "switched"/"not switched" in that case would be a
/// guess dressed as a fact (`(from_slot.unwrap_or(target) == marker_account)`
/// would silently compare against the TARGET instead, which is always
/// trivially "switched" or "not switched" depending on where the marker
/// happened to land — never actually informative). `None` omits the claim
/// entirely and reports only what IS known: the marker's own account.
pub fn reconcile_outcome_operator_line(
    outcome: &ReconcileOutcome,
    original_account: Option<AccountNum>,
) -> String {
    match outcome {
        ReconcileOutcome::MarkerUnreadable => {
            "terminal state unknown — this terminal's account marker could not \
             be read; run `csq swap` to a known account in that terminal"
                .to_string()
        }
        ReconcileOutcome::AlreadyCurrent { marker_account }
        | ReconcileOutcome::Reconciled { marker_account } => match original_account {
            Some(original) if original == *marker_account => format!(
                "not switched — terminal and keychain both on {}",
                marker_account.get()
            ),
            Some(_) => format!("switched to {}", marker_account.get()),
            None => format!("terminal and keychain now on {}", marker_account.get()),
        },
        ReconcileOutcome::WriteFailed { marker_account } => format!(
            "terminal on {n}, keychain could not be updated — run `csq swap {n}` in that terminal",
            n = marker_account.get()
        ),
        ReconcileOutcome::KeychainUnknown {
            marker_account,
            reason,
        } => {
            let n = marker_account.get();
            match reason {
                KeychainUnknownReason::KeychainUnreadable => format!(
                    "terminal on {n}, keychain could not be read — run `csq swap {n}` in that terminal"
                ),
                KeychainUnknownReason::MarkerTokenUntrusted => format!(
                    "terminal on {n}, but that account's own credentials could not be verified — \
                     run `csq swap {n}` in that terminal"
                ),
                KeychainUnknownReason::ForeignLogin => format!(
                    "terminal on {n}, keychain holds a login csq did not write — \
                     run `csq swap {n}` in that terminal"
                ),
            }
        }
    }
}

impl ReconcileOutcome {
    /// The marker account a [`ReconcileOutcome`] resolved to, or `None` for
    /// [`ReconcileOutcome::MarkerUnreadable`] (the only variant with none).
    pub fn marker_account(&self) -> Option<AccountNum> {
        match self {
            ReconcileOutcome::MarkerUnreadable => None,
            ReconcileOutcome::AlreadyCurrent { marker_account }
            | ReconcileOutcome::Reconciled { marker_account }
            | ReconcileOutcome::WriteFailed { marker_account }
            | ReconcileOutcome::KeychainUnknown { marker_account, .. } => Some(*marker_account),
        }
    }
}

/// B3: whether a `repoint_handle_dir` failure left `handle_dir`'s OWN
/// `ACCOUNT_BOUND_ITEMS` symlinks resolving under TWO different accounts —
/// a signal independent of (and checked ALONGSIDE) the keychain reconcile
/// above. Combines two checks, neither sufficient alone
/// (`crate::error::CredentialError::repoint_rolled_back`'s own doc: "a
/// rollback attempt having RUN is not evidence it SUCCEEDED, and the disk
/// check alone cannot see every failure mode a rollback can hit"): the
/// error's own rollback report, OR a direct disk-state check via
/// [`crate::session::handle_dir::handle_dir_symlinks_are_consistent`].
/// Revives both as production callers (B3) — previously exercised only by
/// their own unit tests, never actually consulted by `csq swap` or
/// `auto_rotate` at the point a repoint fails.
pub fn repoint_left_mixed_links(
    error: &crate::error::CredentialError,
    base: &Path,
    handle_dir: &Path,
) -> bool {
    error.repoint_rolled_back() == Some(false)
        || !crate::session::handle_dir::handle_dir_symlinks_are_consistent(base, handle_dir)
}

/// B3: the operator-facing message when [`repoint_left_mixed_links`] is
/// `true` — distinct from [`reconcile_outcome_operator_line`]'s wording
/// because the keychain and the handle dir's OWN symlinks are two
/// independently-checked things; this names the symlink side specifically
/// so the operator does not read a clean keychain reconcile as "everything
/// is fine" while the terminal's links still point at two accounts.
pub fn mixed_links_operator_line(marker_account: AccountNum) -> String {
    format!(
        "this terminal's links are mixed across accounts — run `csq swap {}` in that terminal",
        marker_account.get()
    )
}

/// K3: the operator-facing message for `repoint_handle_dir`'s S7 pre-flight
/// refusal (`CredentialError::RepointRefusedRealFile`) — this fires BEFORE
/// any symlink is touched, but the v4 forced write into the keychain has
/// ALREADY happened by the time this refusal surfaces, so the keychain can
/// still disagree with the (unmoved) marker. D-F2: the message MUST reflect
/// the [`reconcile_keychain_to_marker`] outcome the caller ran to close that
/// gap — `reconcile_line` is [`reconcile_outcome_operator_line`]'s output.
/// Shared by `csq swap`'s same-surface ClaudeCode route and
/// `daemon::auto_rotate`'s tick so the two operator-facing vocabularies can
/// never drift apart. No raw filesystem path is included — `item` is one of
/// the fixed `ACCOUNT_BOUND_ITEMS` names, never attacker- or
/// user-controlled content.
pub fn repoint_refused_real_file_operator_line(item: &str, reconcile_line: &str) -> String {
    format!(
        "`{item}` in this terminal's folder is a regular file, not a link — \
         remove it and retry; {reconcile_line}"
    )
}

/// v4 A2 helper for `csq run`/`csq exec`/phase2b's FRESH handle dir launch
/// path — acquires the bounded per-handle-dir lock and forces the mirror
/// write for `handle_dir_abs`'s OWN (already-correct) credential file.
///
/// - Lock not acquired → `Err` (A2: do NOT launch).
/// - X unreadable, [`UnreadableKind::Inaccessible`] (S5, "switch now or say
///   so", 2026-09-26: `security` completed and reported the keychain
///   locked — measured live, this exit is returned ONLY when the item is
///   PRESENT) → `Err` with a fixed message naming a stale item from an
///   earlier occupant (PID reuse) and the keychain lock (A2: do NOT
///   launch — the handle dir is FRESH, so a present item there belongs to
///   no session of this dir, and launching silently without verifying it
///   would risk starting against the wrong account).
/// - X unreadable, [`UnreadableKind::Transient`] (spawn failure/timeout, an
///   incomplete capture, or a malformed payload) → `Err` (A2: do NOT
///   launch — nothing tells us CC would fail the same read; a stale item
///   from PID reuse plus a transient read failure must not launch against
///   an unverified account).
/// - X genuinely absent (exit 44 — not `Unreadable` at all; the normal
///   SSH/headless case) and the write fails → `Ok(false)` (A2: launch
///   WITHOUT the mirror; CC falls back to the symlinked credential file,
///   which is the correct account — spec 01 §1.4).
/// - Write fails after a readable read of REAL content → `Err` (A2: do NOT
///   launch — a fresh dir with a colliding stale item from PID reuse must
///   not launch against the wrong account).
/// - X holds a login that stays unidentified → the raw payload is saved to
///   `<base>/keychain-quarantine/` (0600) and the item is then replaced with
///   this account's token (`force_sync_account_changed_for_launch`); if the
///   save fails the launch is refused and the item is left alone. Swaps and
///   the daemon sweep do NOT do this.
/// - Otherwise → `Ok(true)` (mirror applied).
pub fn force_sync_for_launch(base: &Path, handle_dir_abs: &Path) -> Result<bool, String> {
    // keychain-fix-r8d.md item 2: same override-first ordering as
    // `force_sync_account_changed`/`reconcile_keychain_to_marker` (see their
    // shared comment on `test_keychain_executor_override`) — checked BEFORE
    // `keychain_mirror_disabled_now()`'s short-circuit. Without this, a
    // `handle()`-level test that installs a scripted executor via
    // `set_test_keychain_executor` could never reach this function's `Err`
    // arms at all: the short-circuit above returned `Ok(true)` unconditionally
    // under `cfg!(test)`/`test-utils`, before ever reaching the lock +
    // `force_sync_account_changed` call where the override is actually
    // consulted — every `decide_launch_disposition` arm besides the trivial
    // `Ok(true)` was structurally unreachable from any test driving this
    // entry point.
    #[cfg(all(target_os = "macos", any(test, feature = "test-utils")))]
    let override_active = test_keychain_executor_override().is_some();
    #[cfg(not(all(target_os = "macos", any(test, feature = "test-utils"))))]
    let override_active = false;
    if !override_active && keychain_mirror_disabled_now() {
        return Ok(true);
    }
    match lock_handle_dir_for_swap_bounded(handle_dir_abs) {
        BoundedLockOutcome::Acquired(_guard) => force_sync_for_launch_locked(base, handle_dir_abs),
        BoundedLockOutcome::NotNeeded => force_sync_for_launch_locked(base, handle_dir_abs),
        BoundedLockOutcome::TimedOut | BoundedLockOutcome::Failed => {
            Err("keychain busy or unavailable; retry the launch".to_string())
        }
    }
}

fn force_sync_for_launch_locked(base: &Path, handle_dir_abs: &Path) -> Result<bool, String> {
    record_keychain_account_hint(handle_dir_abs);
    let raw = std::fs::read_to_string(handle_dir_abs.join(".credentials.json")).ok();
    decide_launch_disposition(force_sync_account_changed_for_launch(
        base,
        handle_dir_abs,
        raw.as_deref(),
    ))
}

/// F8/KC4-10 decision seam: the disposition `force_sync_for_launch_locked`
/// applies to a [`force_sync_account_changed`] outcome, factored out as a
/// PURE function of that outcome so it is directly unit-testable with a
/// synthetic `Result` — no `security` subprocess, no lock, no hint file.
fn decide_launch_disposition(
    result: Result<ForcedSyncResult, PlatformError>,
) -> Result<bool, String> {
    match result {
        // F5/KC4-7: the read genuinely could not be COMPLETED — spawn
        // failure/timeout, an incomplete capture, or a payload that arrived
        // but failed to decode. None of that tells us CC would ALSO fail to
        // read the same item (an incomplete/malformed capture may be a
        // transient race a fresh CC read resolves cleanly) — do NOT launch.
        Ok(ForcedSyncResult::Unreadable(UnreadableKind::Transient)) => {
            Err("keychain busy or unavailable; retry the launch".to_string())
        }
        // S5 (owner decision, "switch now or say so", 2026-09-26): the
        // handle dir at a launch call site is FRESH — no CC session has
        // ever run against it — so a PRESENT keychain item found there
        // belongs to no session of THIS dir. Measured live
        // (`SECURITY_ERR_INTERACTION_NOT_ALLOWED`'s doc): exit 36
        // (`Inaccessible`) is returned ONLY when the item IS present but
        // the keychain is locked; a locked read of a genuinely ABSENT item
        // exits 44 (`RawContentClassification::Absent`, not `Unreadable` at
        // all — see the `None` arm below for that case). So `Inaccessible`
        // on a launch means: a stale item from an earlier occupant (PID
        // reuse) exists and cannot be overwritten right now — refuse the
        // launch rather than start against an unverified account. The
        // PRIOR reasoning here (CC falls back the same way, so proceed) was
        // never measured for a FRESH dir with no prior session and is
        // retracted; it remains correct only insofar as CC's OWN read would
        // ALSO fail — but that says nothing about whether the stale item
        // names the account this launch is about to start.
        Ok(ForcedSyncResult::Unreadable(UnreadableKind::Inaccessible)) => Err(
            "a keychain entry from an earlier session exists and the keychain is locked \
             — unlock the keychain or retry"
                .to_string(),
        ),
        // F4: X was CONFIRMED absent; the write that would have installed
        // the new token failed, but nothing was left inconsistent (still
        // absent) — proceed with the launch rather than refuse it. This is
        // the normal SSH/headless case (spec 01 §1.4): a genuinely absent
        // item (exit 44) is not a stale leftover.
        Ok(ForcedSyncResult::AbsentWriteFailed) => {
            warn!(
                error_kind = "keychain_force_sync_absent_write_failed_proceeding",
                "the keychain item was absent and could not be created for this launch; proceeding without a keychain mirror"
            );
            Ok(false)
        }
        // S4: the forced write failed while X held REAL content — the
        // resulting disk state is UNKNOWN. Unlike `csq swap`/`auto_rotate`,
        // a launch has no repoint to roll back and no prior session's
        // symlinks pointing anywhere — there is nothing to restore that
        // changes whether this launch may proceed. Refuse, same as a
        // generic write failure: do not launch against an unverified
        // account.
        Ok(ForcedSyncResult::WriteFailedUnknown) => {
            Err("keychain busy or unavailable; retry the launch".to_string())
        }
        // round 7c D1/D5: rule 3 — X holds a valid Anthropic identity from
        // no account this call could name. The launch path now quarantines
        // such an item and replaces it (`force_sync_account_changed_for_launch`),
        // so this arm is kept only for exhaustiveness and is not produced
        // by a production launch; if it were, refusing is the safe answer.
        //
        // `keychain-fix-r8.md` C-F1 (message rewrite): see the identical
        // rewrite in `decide_swap_disposition` — C-F1's history match already
        // recognizes a stale-but-known token as rule 2, so this arm is
        // genuinely unidentified, never a fact ("just refreshed") csq cannot
        // establish. "Retry the launch" would repeat the exact same refusal
        // against the exact same unidentified item, so the remedy names the
        // account-scoped fix instead.
        Ok(ForcedSyncResult::ForeignLoginUnharvested) => Err(
            "the keychain holds a login csq could not identify as this account's own; nothing \
             was changed — if it belongs to a different account, run `csq login <n>` for that \
             account to establish ownership, then retry the launch"
                .to_string(),
        ),
        // rule 4b: X's `claudeAiOauth` could not be parsed — treated the
        // same as a generic unreadable/write-failed case: do not launch.
        Ok(ForcedSyncResult::MalformedOauth) => {
            Err("keychain busy or unavailable; retry the launch".to_string())
        }
        // `keychain-fix-r8.md` C-F2 (structural half): the handle dir's own
        // `.credentials.json` symlink resolved to an Anthropic payload
        // whose token is expired or unparseable — this launch's OWN target
        // account is untrustworthy right now. No mutation was performed;
        // refuse rather than launch against an unverified account.
        Ok(ForcedSyncResult::TargetTokenInvalidated) => Err(
            "this account's own login is no longer valid; nothing changed — \
             run `csq login <n>` for this account, then retry the launch"
                .to_string(),
        ),
        Ok(ForcedSyncResult::QuarantineSaveFailed) => Err(
            "csq could not save the unidentified keychain login to the keychain-quarantine \
             folder in your csq accounts directory (check disk space and permissions); \
             nothing was changed — fix that and retry the launch"
                .to_string(),
        ),
        Ok(ForcedSyncResult::Applied { .. }) => Ok(true),
        Err(_e) => Err("keychain busy or unavailable; retry the launch".to_string()),
    }
}

// ── single-writer policy (round 7b, 2026-09-26 owner directive) ───────
//
// ONE pure decision function every writer of CC's keychain item routes
// through, plus the single executor-level entry that applies its verdict.
// `keychain-fix-r7b.md`'s design names the current-read parameter's type
// `KeychainRead` — this module already has a DIFFERENT, unrelated public
// `KeychainRead` (the three-way Found/NotFound/CouldNotAsk collapse used
// solely by `credentials::post_login`'s retry loop). That type cannot
// express rules 1/4 here: it has no "present but holds no login" case
// distinct from absent, and its `Found` arm is a parsed `CredentialFile`
// with no raw JSON to preserve siblings from or compare by identity.
// `RawContentClassification` (widened to `pub(crate)` above) is the type
// already purpose-built for exactly this classification — it already powers
// `reconcile_keychain_to_marker`'s rules 1-7 — so it is what `current` binds
// to below, per the dispatch brief's "if you find a concrete reason it
// cannot work ... rather than substituting a different design": the reason
// is the name collision with an existing, differently-shaped public type,
// not a disagreement with the five rules themselves, which this function
// implements exactly as specified.

/// Every token csq can cheaply name to classify X's current content
/// against. All fields are OPTIONAL borrowed raw `.credentials.json` bodies
/// (or absent) — never owned copies (S-LOW-2: identity comparison stays on
/// borrowed `&str`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy, Default)]
pub(crate) struct KnownTokens<'a> {
    /// The terminal's `.csq-account` marker account's own canonical token.
    pub marker_account_canonical: Option<&'a str>,
    /// The account this write is switching FROM (`csq swap`/auto-rotate's
    /// source), when different from the marker.
    pub source_account_canonical: Option<&'a str>,
    /// The token THIS call itself already wrote to X, if any (rule 4's
    /// "moved since we force-wrote it" case).
    pub csq_written: Option<&'a str>,
    /// Every other account's canonical token the caller has cheaply
    /// available — optional; omitting entries only makes rule 2's match
    /// narrower, never wrong.
    pub other_accounts_canonical: &'a [&'a str],
    /// The sweep's pre-refresh identity for the account being refreshed
    /// (rule 2/D-F4) — `None` outside the post-refresh sweep.
    ///
    /// `keychain-fix-r8.md` S-LOW-1: a FINGERPRINT, not the raw credential
    /// JSON — the refresher's in-tick `refreshed` map (this field's only
    /// production source) previously held the full pre-refresh
    /// `.credentials.json` STRING per account for the tick's duration,
    /// solely to support this identity comparison. A fingerprint carries
    /// exactly as much matching power (see `decide_cc_keychain_write`'s
    /// fingerprint-based check) with zero token bytes retained in memory
    /// beyond the moment `record_write` fingerprints and discards them.
    pub sweep_pre_refresh: Option<crate::credentials::token_history::Fingerprint>,
    /// `keychain-fix-r8.md` C-F1 (PRIMARY DIRECTIVE): the marker account's
    /// bounded history of SHA-256 refresh-token fingerprints
    /// (`token_history::read_history`/`read_history_for_slot`) — every token
    /// that account's canonical store has held in the last
    /// `token_history::MAX_HISTORY_LEN` writes, oldest first. A keychain item
    /// whose CURRENT fingerprint appears here is the marker account's own
    /// token, superseded by a later refresh the item missed — "same account,
    /// superseded" (rule 2), never an unmatched foreign login (rule 3). Empty
    /// by default (`KnownTokens::default()`): a caller that omits this only
    /// narrows recognition back to current-token-only, never widens it
    /// unsafely.
    pub marker_account_history: &'a [crate::credentials::token_history::Fingerprint],
}

impl<'a> KnownTokens<'a> {
    fn iter_raw(&self) -> impl Iterator<Item = &'a str> + '_ {
        self.marker_account_canonical
            .into_iter()
            .chain(self.source_account_canonical)
            .chain(self.csq_written)
            .chain(self.other_accounts_canonical.iter().copied())
    }
}

/// What this write intends for X. Deliberately only two variants: a caller
/// with an INVALID target token that is not positively non-Anthropic MUST
/// refuse the switch BEFORE calling [`decide_cc_keychain_write`] at all
/// (rule 5's "swap and rotate REFUSE the switch when the target token is
/// not Valid" — `find_target` picks Valid targets only) — this function is
/// never asked to decide over that case, so it has no variant for it.
///
/// `keychain-fix-r8.md` C-F2 (structural half — `doc-property-claims.md`
/// MUST-1): this invariant is now enforced STRUCTURALLY by this module's
/// own [`Intended`]-producing call site
/// (`force_sync_account_changed_with_executor`), not merely by caller
/// discipline external to it. Before round-8, that call site folded "no
/// `new_credentials_json` at all" AND "a payload that IS Anthropic-shaped
/// but expired/unparseable" into the SAME `None` → [`Intended::Strip`] —
/// the second case is exactly the "INVALID target token that is not
/// positively non-Anthropic" this doc says must never reach here. It now
/// refuses (`ForcedSyncResult::TargetTokenInvalidated`) before ever
/// constructing `Intended::Strip` for that case, so the claim below is
/// true of THIS module's own code, not only of its external callers.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy)]
pub(crate) enum Intended<'a> {
    /// The target account has a Valid canonical token to mirror into X.
    Token(&'a str),
    /// The target slot is POSITIVELY non-Anthropic (3P or Codex) per the
    /// identity store — there is no Anthropic token to mirror, only a
    /// possible strip/delete of X.
    ///
    /// `force_sync_account_changed_with_executor` is this variant's only
    /// production constructor. It constructs `Strip` only when
    /// `new_credentials_json` is `None` or lacks a `claudeAiOauth` key
    /// entirely — a payload that carries a `claudeAiOauth` key but fails
    /// its expiry check returns [`ForcedSyncResult::TargetTokenInvalidated`]
    /// instead, never `Strip` (C-F2 structural half).
    Strip,
}

impl fmt::Debug for Intended<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Intended::Token(_) => f.debug_tuple("Token").field(&"[REDACTED]").finish(),
            Intended::Strip => write!(f, "Strip"),
        }
    }
}

/// Why [`WriteDecision::Unknown`] fired — message-only, mirroring
/// [`KeychainUnknownReason`]'s shape for this more general entry point.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteUnknownReason {
    /// X itself could not be classified (rule 4) — `security find` did not
    /// resolve to a clean present/absent read.
    KeychainUnreadable,
    /// X holds a `claudeAiOauth` key, but its `accessToken`/`refreshToken`
    /// identity could not be parsed — present but malformed (rule 4).
    MalformedOauth,
}

/// The single verdict every CC-keychain-item writer MUST obey. Produced by
/// [`decide_cc_keychain_write`]; applied by [`apply_cc_keychain_write`] —
/// the ONLY caller of this module's `add`/`delete` executor calls.
///
/// `keychain-fix-r9.md` D-F8: the "shard S2" carve-out this doc previously
/// named (`csq swap`'s CLI-side callers and `auto_rotate`'s target
/// selection, as not-yet-migrated) is STALE — both now route through
/// [`force_swap_write_before_repoint`] and [`reconcile_keychain_to_marker`]
/// (swap: `csq/src/cli/commands/swap.rs`; auto-rotate:
/// `daemon/auto_rotate.rs`), and both of those are themselves
/// decide-then-apply, so there is no remaining non-decide write path left
/// to migrate.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteDecision<'a> {
    /// Rules 1/2: free to write, or X already held content matching SOME
    /// known account — nothing is lost by installing this token.
    Write(&'a str),
    /// F5: X already holds exactly the intended token — no mutation needed.
    NoWrite,
    /// Rule 3: X holds a valid Anthropic token matching NO known account —
    /// the only live copy. The CALLER must harvest it (adopt via the
    /// custodian's existing validate-and-adopt path) and re-decide; this
    /// function performs no I/O and cannot harvest itself.
    RefuseUnharvested,
    /// `keychain-fix-r11.md` S-M-3 residual: the intended token itself is
    /// ALREADY EXPIRED at decision time — distinct from
    /// [`WriteDecision::RefuseUnharvested`], which tells the caller "harvest
    /// X and re-decide". Harvesting `current` can never fix an expired
    /// INTENDED token, so callers must not treat this the same way; it is
    /// the absolute belt-and-braces backstop firing (a true no-op on every
    /// legitimate path, since `Intended::Token` is expected to already be
    /// Valid) rather than the ordinary rule-3 refusal.
    RefuseIntendedExpired,
    /// Rule 4: X's state could not be safely classified. No mutation.
    Unknown(WriteUnknownReason),
    /// Rule 5: the intended write is a strip/delete of a POSITIVELY
    /// non-Anthropic target, and X's content matches a known account (or
    /// holds no login) — safe to strip/delete.
    StripAllowed,
}

impl fmt::Debug for WriteDecision<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteDecision::Write(_) => f.debug_tuple("Write").field(&"[REDACTED]").finish(),
            WriteDecision::NoWrite => write!(f, "NoWrite"),
            WriteDecision::RefuseUnharvested => write!(f, "RefuseUnharvested"),
            WriteDecision::RefuseIntendedExpired => write!(f, "RefuseIntendedExpired"),
            WriteDecision::Unknown(r) => f.debug_tuple("Unknown").field(r).finish(),
            WriteDecision::StripAllowed => write!(f, "StripAllowed"),
        }
    }
}

/// `true` when `current` is [`RawContentClassification::Content`] and its
/// `claudeAiOauth` key is present but its `accessToken`/`refreshToken`
/// identity could NOT be parsed — the rule-4 "present but malformed" case,
/// distinct from [`holds_no_login`] (no `claudeAiOauth` key at all, or one
/// with both tokens empty, which is rule 1, free-to-write) and distinct from a parseable identity that
/// simply matches nothing known (rule 3, harvest candidate). Re-parses
/// `current`'s JSON rather than threading a borrowed `Value` through,
/// mirroring [`keychain_content_matches_token`]'s own re-parse-per-call
/// shape — no token bytes are copied either way (S-LOW-2).
///
/// Platform-independent pure fn — unconditional so it compiles and its
/// tests run on every platform; its only PRODUCTION caller
/// ([`decide_cc_keychain_write`]) is exercised in production only via
/// [`reconcile_keychain_to_marker_with_executor`], which is macOS-gated.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn current_oauth_unparseable(current: &RawContentClassification) -> bool {
    match current {
        RawContentClassification::Content(json) => {
            let Ok(val) = serde_json::from_str::<serde_json::Value>(json) else {
                // Caller already established `Content` only for JSON-object
                // payloads (`classify_raw_content`); an unparseable `json`
                // here should not occur, but treat it as malformed rather
                // than panicking.
                return true;
            };
            let has_key = val
                .as_object()
                .is_some_and(|o| o.contains_key("claudeAiOauth"));
            has_key && oauth_identity(&val).is_none()
        }
        RawContentClassification::Absent | RawContentClassification::Unreadable(_) => false,
    }
}

/// THE single decision function every code path that writes or deletes CC's
/// keychain item MUST go through (`keychain-fix-r7b.md` PRIMARY
/// METHODOLOGICAL DIRECTIVE). Pure — no I/O, no `security` shell, no
/// logging — so every rule is directly unit-testable against a synthetic
/// `current` and `known`.
///
/// Implements the five rules verbatim:
/// 1. `current` absent, present with no `claudeAiOauth` key at all, or
///    present with both tokens empty ([`oauth_tokens_both_empty`]) →
///    free to write/strip.
/// 2. `current` holds content matching SOME known account's token → nothing
///    lost by overwriting; write (or strip, for [`Intended::Strip`]).
/// 3. `current` holds a real, parseable Anthropic identity matching NO
///    known account → the only live copy; refuse so the CALLER can harvest
///    it, then re-decide.
/// 4. `current` could not be classified at all, OR holds a `claudeAiOauth`
///    key whose identity could not be parsed → `Unknown`; no mutation.
/// 5. [`Intended::Strip`] is the caller's assertion that the target slot is
///    POSITIVELY non-Anthropic (never asked here to re-derive that) — a
///    strip is [`WriteDecision::StripAllowed`] only under rules 1/2 (nothing
///    is destroyed that isn't already known elsewhere); otherwise it is
///    rule 3's harvest-first refusal, same as a token write.
///
/// Platform-independent pure fn — unconditional so it compiles and its
/// tests run on every platform. `keychain-fix-r9.md` D-F8: it now has
/// SEVERAL production callers, every one of them `#[cfg(target_os =
/// "macos")]` — [`reconcile_keychain_to_marker_with_executor`],
/// [`force_sync_account_changed_with_executor`],
/// [`decide_and_clear_dead_handle_with_executor`], and
/// [`decide_and_clear_queued_service_with_executor`] — so on other
/// platforms this remains genuinely unreachable from production code, but
/// the prior "only PRODUCTION caller (singular)" framing is stale.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn decide_cc_keychain_write<'a>(
    current: &RawContentClassification,
    known: &KnownTokens<'a>,
    intended: Intended<'a>,
) -> WriteDecision<'a> {
    // Rule 4a: the ask itself did not resolve to a clean read.
    if matches!(current, RawContentClassification::Unreadable(_)) {
        return WriteDecision::Unknown(WriteUnknownReason::KeychainUnreadable);
    }

    // Rule 1: absent, or present with no login recorded at all.
    if holds_no_login(current) {
        return match intended {
            Intended::Token(t) => WriteDecision::Write(t),
            Intended::Strip => WriteDecision::StripAllowed,
        };
    }

    // Rule 4b: a `claudeAiOauth` key is present but unparseable — never a
    // match, never a harvest candidate (harvesting garbage makes no sense).
    if current_oauth_unparseable(current) {
        return WriteDecision::Unknown(WriteUnknownReason::MalformedOauth);
    }

    // From here `current` is `Content` with a parseable, real identity.
    //
    // `keychain-fix-r8.md` C-F1 (PRIMARY DIRECTIVE): a raw-token match against
    // `known.iter_raw()` is not the only way `current` can be "known, not a
    // foreign login" — it may also be a token from an EARLIER refresh this
    // marker account's own canonical store has since superseded. `current`'s
    // OWN fingerprint is computed at most once (`current`'s bytes never
    // leave this function), and checked against the marker account's bounded
    // history; a hit is "same account, superseded" (rule 2), never rule 3's
    // unmatched foreign login.
    // S-LOW-1: `current`'s fingerprint is computed at most once and checked
    // against BOTH the marker account's bounded on-disk history AND the
    // sweep's in-tick pre-refresh fingerprint (`sweep_pre_refresh` — the
    // in-memory equivalent of a not-yet-appended history entry, for the tick
    // during which the refresh happened but the sweep hasn't caught up on
    // every dir yet).
    let current_fingerprint = match current {
        RawContentClassification::Content(json) => {
            crate::credentials::token_history::fingerprint_from_raw_json(json)
        }
        RawContentClassification::Absent | RawContentClassification::Unreadable(_) => None,
    };
    // `keychain-fix-r9.md` S-M-3: a history hit counts as "same account,
    // superseded" ONLY when `current`'s fingerprint sits STRICTLY BEFORE the
    // marker account's OWN canonical fingerprint in that same bounded,
    // oldest-first history — i.e. `current` is a token the canonical store
    // has demonstrably moved PAST. Without the ordering check, a canonical
    // store rolled back to an OLDER token (a bug, or a restored backup) would
    // make its own bounded history contain a NEWER fingerprint too — and a
    // keychain item still holding that newer, still-live session would read
    // as "known, safe to overwrite" and get silently replaced by the older
    // canonical value, discarding a perfectly good session. Requiring
    // strictly-before means a match is possible only when `current` is
    // provably behind the canonical position, never merely "somewhere in the
    // history" — a fingerprint that TIES the canonical position (handled by
    // `iter_raw`'s raw-string comparison above) or comes AFTER it never
    // qualifies here.
    //
    // Both positions must be independently resolvable in the SAME bounded
    // array or this is a no-match (fail closed, `guard-reader-writer-
    // parity.md` MUST-2): if the canonical fingerprint cannot be computed, or
    // was evicted from (or never entered) the bounded history, there is no
    // safe position to compare against, so a history hit is NOT trusted.
    // `keychain-fix-r11.md` S-M-3 residual: BOTH positions below now use
    // `rposition` (last occurrence), not `position` (first). A bounded
    // history array can hold the SAME fingerprint at more than one index —
    // e.g. `[X, C, X]`, when an account's token X was written, superseded by
    // C, then written again (a rollback/restore) — and a FIRST-occurrence
    // read can find X's index BEFORE C's even though the fingerprint
    // `current` actually carries corresponds to the LAST (most recent)
    // occurrence, which sits AFTER C. Anchoring both sides to their LAST
    // occurrence keeps "strictly before" meaningful under a rolled-back or
    // duplicated history instead of matching on a stale earlier index.
    let history_matches = current_fingerprint.is_some_and(|fp| {
        let canonical_pos = known
            .marker_account_canonical
            .and_then(crate::credentials::token_history::fingerprint_from_raw_json)
            .and_then(|canonical_fp| {
                known
                    .marker_account_history
                    .iter()
                    .rposition(|h| *h == canonical_fp)
            });
        let Some(canonical_pos) = canonical_pos else {
            return false;
        };
        known
            .marker_account_history
            .iter()
            .rposition(|h| *h == fp)
            .is_some_and(|fp_pos| fp_pos < canonical_pos)
    });
    // `keychain-fix-r11.md` S-M-3 residual (D-1): the three recognition
    // channels are no longer folded straight into `matches_known` — a
    // history-ONLY match (recognised via the position channel and NEITHER a
    // raw/csq_written match NOR the sweep's in-tick pre-refresh fingerprint)
    // is weaker evidence than the other two, which directly confirm
    // `current` IS a specific already-known token. The relative guard below
    // applies only to that weaker, history-only case.
    let raw_match = known
        .iter_raw()
        .any(|raw| keychain_content_matches_token(current, raw));
    let pre_refresh_match =
        current_fingerprint.is_some_and(|fp| known.sweep_pre_refresh == Some(fp));
    let matches_known = raw_match || history_matches || pre_refresh_match;

    match intended {
        Intended::Token(t) => {
            if keychain_content_matches_token(current, t) {
                // F5: already the intended token.
                WriteDecision::NoWrite
            } else if matches_known {
                // `keychain-fix-r10.md` S-L-1: belt-and-braces over the
                // recognition channels above — deliberately an ABSOLUTE
                // check (`t`'s own expiry vs now), never a RELATIVE one
                // against `current`'s expiry. A relative "refuse when
                // current's expiresAt is later than the intended token's"
                // was tried and reverted here during this same round: a
                // history-matched, legitimately-superseded keychain item can
                // easily carry a LATER expiresAt than the canonical it is
                // being overwritten by (an adopted or harvested token's TTL
                // is not tied to write order) — proven by
                // `adopt_then_refresh_in_one_tick_leaves_source_dir_recognised`.
                // The SAME lesson was already learned once for the strong
                // (exact raw) match channel — see
                // `reconcile_overwrites_foreign_token_with_later_expiry_when_it_matches_forced_write`'s
                // doc, "the foreign token's LATER expiry reads as already
                // current under the old expiry-only guard, exactly the
                // corruption class this directive removes." expiresAt is a
                // grant TTL, not a write-recency clock, on EITHER side of
                // the comparison, so this ABSOLUTE check applies on EVERY
                // channel: never install a token that is ALREADY EXPIRED at
                // decision time, regardless of what heuristic recognised
                // `current`. A caller's `Intended::Token` is expected to
                // already be Valid (`find_target` picks Valid targets only —
                // see `Intended`'s own doc), so this is a true no-op backstop
                // on every legitimate path and only refuses a genuine bug —
                // which is why it returns its OWN variant
                // ([`WriteDecision::RefuseIntendedExpired`]), never
                // `RefuseUnharvested`: harvesting `current` can never repair
                // an already-expired INTENDED token, so telling the caller to
                // do so (what `RefuseUnharvested` means) would be misleading.
                if anthropic_expiry_ms(t).is_some_and(|exp| exp <= now_ms()) {
                    return WriteDecision::RefuseIntendedExpired;
                }
                // `keychain-fix-r11.md` S-M-3 residual (D-1): a SECOND,
                // RELATIVE guard — narrower than the absolute one above —
                // applies ONLY when `current` was recognised SOLELY via the
                // history-position channel. `raw_match`/`pre_refresh_match`
                // are direct evidence `current` IS a specific token this call
                // already knows to be safely superseded; the history-position
                // channel is weaker (it proves only that SOME earlier
                // fingerprint in the marker account's bounded history sits
                // before the canonical position, never that `current`'s own
                // grant is actually the stale one), so a history-ONLY match
                // additionally requires `current`'s own expiry to be no LATER
                // than the intended token's. Anything else (later, or either
                // expiry unknown) is refused as `RefuseUnharvested` — this IS
                // the ordinary "let the caller harvest and re-decide" case,
                // since a live `current` may genuinely be the account's
                // true-current session rather than something superseded.
                let history_only = history_matches && !raw_match && !pre_refresh_match;
                if history_only {
                    let current_expiry = match current {
                        RawContentClassification::Content(json) => anthropic_expiry_ms(json),
                        RawContentClassification::Absent
                        | RawContentClassification::Unreadable(_) => None,
                    };
                    let intended_expiry = anthropic_expiry_ms(t);
                    let safe_to_write = matches!(
                        (current_expiry, intended_expiry),
                        (Some(c), Some(i)) if c <= i
                    );
                    if !safe_to_write {
                        return WriteDecision::RefuseUnharvested;
                    }
                }
                // Rule 2.
                WriteDecision::Write(t)
            } else {
                // Rule 3.
                WriteDecision::RefuseUnharvested
            }
        }
        Intended::Strip => {
            if matches_known {
                WriteDecision::StripAllowed
            } else {
                WriteDecision::RefuseUnharvested
            }
        }
    }
}

/// Outcome of [`apply_cc_keychain_write`] — mirrors [`ForcedSyncResult`]'s
/// shape for the decisions that actually touch the executor.
///
/// `#[cfg_attr(not(target_os = "macos"), allow(dead_code))]`: production use
/// of this type is entirely macOS-gated — every production caller of
/// [`apply_cc_keychain_write`] (`keychain-fix-r9.md` D-F8: now several, not
/// a single one — see [`decide_cc_keychain_write`]'s own doc for the list)
/// is `#[cfg(target_os = "macos")]` — the non-macOS `apply_cc_keychain_write`
/// stub never returns `AbsentWriteFailed`/`WriteFailed`, so those two
/// variants are genuinely unconstructed there, mirroring the same pattern
/// already used for [`RawContentClassification`] and [`UnreadableKind`].
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApplyOutcome {
    /// [`WriteDecision::Write`] or [`WriteDecision::StripAllowed`] was
    /// applied. `wrote_token` distinguishes an installed token from a
    /// strip-to-siblings-or-delete.
    Applied { wrote_token: bool },
    /// [`WriteDecision::NoWrite`], [`WriteDecision::RefuseUnharvested`], or
    /// [`WriteDecision::Unknown`] — no executor call was made.
    NoOp,
    /// Mirrors [`ForcedSyncResult::AbsentWriteFailed`]: `current` was
    /// CONFIRMED [`RawContentClassification::Absent`] before this call, and
    /// the executor call that would have installed/stripped X itself
    /// failed — but nothing was left inconsistent (X is unchanged, still
    /// absent). Distinct from [`ApplyOutcome::WriteFailed`] so a caller can
    /// choose to proceed rather than refuse, same as every other
    /// forced-write entry in this module.
    AbsentWriteFailed,
    /// A [`WriteDecision::Write`]/[`WriteDecision::StripAllowed`] apply was
    /// attempted over KNOWN (non-absent) prior content and the executor
    /// call itself failed — the resulting disk state is UNKNOWN (a
    /// watchdog-timed-out `add`/`delete` can report a non-zero exit while
    /// the write already partially committed).
    WriteFailed,
}

/// The previous content with `claudeAiOauth` removed, serialized, or `None`
/// when there is nothing to keep. Taken from the caller's ALREADY-READ
/// classification, so no extra keychain read (a possible password dialog) is
/// made. Never the full content: restoring the old token mid-swap would put
/// a superseded account's login back.
#[cfg(target_os = "macos")]
fn siblings_only_payload(current: &RawContentClassification) -> Option<String> {
    match current {
        RawContentClassification::Content(json) => {
            let siblings = extract_sibling_object(json);
            if siblings.is_empty() {
                None
            } else {
                serde_json::to_string(&serde_json::Value::Object(siblings)).ok()
            }
        }
        RawContentClassification::Absent | RawContentClassification::Unreadable(_) => None,
    }
}

/// The single executor-level entry every production caller of CC-item
/// add/delete MUST route through (`keychain-fix-r7b.md`). Takes the SAME
/// `current` [`decide_cc_keychain_write`] decided against, so
/// [`WriteDecision::Write`]'s sibling-preserving merge and
/// [`WriteDecision::StripAllowed`]'s strip-to-siblings-or-delete reuse the
/// existing planner ([`plan_mirror_write`]) / sibling extractor
/// ([`extract_sibling_object`]) rather than re-implementing them.
/// `backfill_allowed` is threaded straight to [`plan_mirror_write`] — `false`
/// for an account-changed forced write, `true` for the ordinary same-account
/// sync path — see that function's own doc for why the two differ.
#[cfg(target_os = "macos")]
fn apply_cc_keychain_write(
    exec: &(impl KeychainExecutor + ?Sized),
    svc: &str,
    account: &str,
    current: &RawContentClassification,
    decision: WriteDecision<'_>,
    backfill_allowed: bool,
) -> ApplyOutcome {
    let was_absent = matches!(current, RawContentClassification::Absent);
    let on_write_failure = || {
        if was_absent {
            ApplyOutcome::AbsentWriteFailed
        } else {
            ApplyOutcome::WriteFailed
        }
    };
    match decision {
        WriteDecision::Write(raw) => match plan_mirror_write(current, raw, backfill_allowed) {
            Ok(plan) => match exec.add_restoring(
                svc,
                account,
                &plan.write_x,
                siblings_only_payload(current),
            ) {
                Ok(()) => ApplyOutcome::Applied { wrote_token: true },
                Err(_) => on_write_failure(),
            },
            // `current` was `Unreadable` by the time the planner re-checked
            // it — only possible if it changed since `decide` ran without
            // the caller's lock held across both calls (a caller bug, not a
            // reachable state under the documented locking contract). Never
            // `was_absent` on this branch (planner only errors on
            // `Unreadable`), so this is always a genuine `WriteFailed`.
            Err(_) => ApplyOutcome::WriteFailed,
        },
        WriteDecision::StripAllowed => {
            let siblings = match current {
                RawContentClassification::Content(json) => extract_sibling_object(json),
                RawContentClassification::Absent | RawContentClassification::Unreadable(_) => {
                    serde_json::Map::new()
                }
            };
            if siblings.is_empty() {
                if exec.delete(svc, account) {
                    ApplyOutcome::Applied { wrote_token: false }
                } else {
                    on_write_failure()
                }
            } else {
                match serde_json::to_string(&serde_json::Value::Object(siblings)) {
                    Ok(remainder) => match exec.add(svc, account, &remainder) {
                        Ok(()) => ApplyOutcome::Applied { wrote_token: false },
                        Err(_) => on_write_failure(),
                    },
                    Err(_) => on_write_failure(),
                }
            }
        }
        WriteDecision::NoWrite
        | WriteDecision::RefuseUnharvested
        | WriteDecision::RefuseIntendedExpired
        | WriteDecision::Unknown(_) => ApplyOutcome::NoOp,
    }
}

/// Non-macOS: no keychain item exists to mutate; every decision resolves to
/// a no-op success, mirroring [`force_sync_account_changed_with_executor`]'s
/// own non-macOS stub.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
fn apply_cc_keychain_write(
    _svc: &str,
    _account: &str,
    _current: &RawContentClassification,
    decision: WriteDecision<'_>,
    _backfill_allowed: bool,
) -> ApplyOutcome {
    match decision {
        WriteDecision::Write(_) => ApplyOutcome::Applied { wrote_token: true },
        WriteDecision::StripAllowed => ApplyOutcome::Applied { wrote_token: false },
        WriteDecision::NoWrite
        | WriteDecision::RefuseUnharvested
        | WriteDecision::RefuseIntendedExpired
        | WriteDecision::Unknown(_) => ApplyOutcome::NoOp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── S10: recording executor — asserts CALL ORDER and TARGETS, not just
    // planner output. `KeychainExecutor`/`SecurityCliExecutor` are
    // macOS-only (so is `keychain_account()`, which `_with_executor` calls),
    // so this whole seam is macOS-gated like `write_raw`/`force_sync_account_changed`
    // themselves.

    #[cfg(target_os = "macos")]
    struct RecordingExecutor {
        calls: std::cell::RefCell<Vec<(&'static str, String, String)>>,
        add_payloads: std::cell::RefCell<Vec<String>>,
        find_result: std::cell::RefCell<RawContentClassification>,
        add_ok: std::cell::Cell<bool>,
        delete_ok: std::cell::Cell<bool>,
        // `keychain-fix-r9.md` D-F5: models N or more never-consolidated
        // items resident under one service — `find` reports `find_result`
        // until this reaches 0, each successful `delete` decrements it by
        // one (mirroring `security delete-generic-password` removing
        // exactly ONE matching item per call). Default 1 (a single item)
        // preserves every pre-existing test's behaviour unchanged.
        items_remaining: std::cell::Cell<u32>,
    }

    #[cfg(target_os = "macos")]
    impl RecordingExecutor {
        fn scripted(find_result: RawContentClassification) -> Self {
            Self {
                calls: std::cell::RefCell::new(Vec::new()),
                add_payloads: std::cell::RefCell::new(Vec::new()),
                find_result: std::cell::RefCell::new(find_result),
                add_ok: std::cell::Cell::new(true),
                delete_ok: std::cell::Cell::new(true),
                items_remaining: std::cell::Cell::new(1),
            }
        }

        /// D-F5: script `n` never-consolidated items under the one service
        /// this executor is scripted against.
        fn with_duplicate_items(self, n: u32) -> Self {
            self.items_remaining.set(n);
            self
        }

        fn calls(&self) -> Vec<(&'static str, String, String)> {
            self.calls.borrow().clone()
        }

        fn last_add_payload(&self) -> Option<String> {
            self.add_payloads.borrow().last().cloned()
        }
    }

    #[cfg(target_os = "macos")]
    impl KeychainExecutor for RecordingExecutor {
        fn find(&self, svc: &str, account: &str) -> RawContentClassification {
            self.calls
                .borrow_mut()
                .push(("find", svc.to_string(), account.to_string()));
            if self.items_remaining.get() == 0 {
                RawContentClassification::Absent
            } else {
                self.find_result.borrow().clone()
            }
        }

        fn add(&self, svc: &str, account: &str, payload: &str) -> Result<(), PlatformError> {
            self.calls
                .borrow_mut()
                .push(("add", svc.to_string(), account.to_string()));
            self.add_payloads.borrow_mut().push(payload.to_string());
            if self.add_ok.get() {
                Ok(())
            } else {
                Err(PlatformError::Keychain("scripted add failure".to_string()))
            }
        }

        fn delete(&self, svc: &str, account: &str) -> bool {
            self.calls
                .borrow_mut()
                .push(("delete", svc.to_string(), account.to_string()));
            if self.delete_ok.get() {
                let n = self.items_remaining.get();
                self.items_remaining.set(n.saturating_sub(1));
                true
            } else {
                false
            }
        }
    }

    // ── R9-3(c) — ClearStale `NoOp` (X read Absent) is UNCONFIRMED, not
    // confirmed, in a daemon-context call with no recorded account hint ──

    // ── kc-simplify-brief Step 0: account-name PARITY with CC's ZA() ────
    //
    // RED against a broken `is_valid_cc_username` that accepts, say, a
    // space or an em-dash would print: assertion failed at
    // `is_valid_cc_username("bad user")`, expected false got true.
    #[test]
    fn is_valid_cc_username_accepts_cc_charset() {
        for good in ["esperie", "jack.hong", "user_1", "a-b-c", "USER123"] {
            assert!(is_valid_cc_username(good), "{good:?} must be accepted");
        }
    }

    #[test]
    fn is_valid_cc_username_rejects_outside_charset_or_empty() {
        for bad in ["", "bad user", "üser", "name\u{2014}dash", "a/b"] {
            assert!(!is_valid_cc_username(bad), "{bad:?} must be rejected");
        }
    }

    // R7-10 — `keychain_account_for` prefers RECORDED_ACCOUNT_FILE's
    // content over a live `keychain_account()` derivation, but only when
    // that content passes the SAME validation `keychain_account` itself
    // applies.
    //
    // RED against a `keychain_account_for` that ignored the recorded file
    // entirely (fell straight through to `keychain_account()`) would
    // print: assertion failed, expected "recorded-user", got the live
    // `$USER`/`getpwuid` value instead.
    #[cfg(target_os = "macos")]
    #[test]
    fn r7_10_keychain_account_for_prefers_recorded_name() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RECORDED_ACCOUNT_FILE), b"recorded-user").unwrap();
        assert_eq!(keychain_account_for(dir.path()), "recorded-user");
    }

    // R7-10 — invalid recorded content (fails CC's own username regex)
    // MUST NOT be trusted; the caller falls back to a live derivation
    // instead of propagating the invalid string.
    //
    // RED against a `keychain_account_for` that trusted the file
    // unconditionally would print: assertion failed, expected the live
    // `keychain_account()` value, got "bad user!" (the invalid recorded
    // content) instead.
    #[cfg(target_os = "macos")]
    #[test]
    fn r7_10_keychain_account_for_falls_back_on_invalid_recorded_content() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RECORDED_ACCOUNT_FILE), b"bad user!").unwrap();
        assert_eq!(keychain_account_for(dir.path()), keychain_account());
    }

    // R7-10 — an absent recorded file falls back to a live derivation too
    // (the common case: a dir `record_keychain_account_hint` never wrote
    // to, or a legacy dir from before this feature existed).
    #[cfg(target_os = "macos")]
    #[test]
    fn r7_10_keychain_account_for_falls_back_when_file_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(keychain_account_for(dir.path()), keychain_account());
    }

    // R7-10 — `record_keychain_account_hint` actually persists a readable,
    // valid value that `keychain_account_for` then prefers on the NEXT
    // call — the round trip the whole feature exists for.
    //
    // RED against a `record_keychain_account_hint` that no-oped (e.g. a
    // broken `atomic_replace` call, or the validation guard rejecting a
    // valid derived name) would print: assertion failed, expected
    // `keychain_account()`'s value via the RECORDED path, got it via the
    // live-fallback path instead — indistinguishable by VALUE alone, which
    // is why this test additionally asserts the file exists on disk.
    #[cfg(target_os = "macos")]
    #[test]
    fn r7_10_record_keychain_account_hint_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        record_keychain_account_hint(dir.path());
        let recorded_path = dir.path().join(RECORDED_ACCOUNT_FILE);
        assert!(
            recorded_path.exists(),
            "record_keychain_account_hint must persist the recorded-account file"
        );
        assert_eq!(keychain_account_for(dir.path()), keychain_account());
    }

    // KC4-2 — `record_keychain_account_hint_if_absent` MUST NOT overwrite an
    // existing hint: the running session's keychain username was fixed at
    // ITS OWN launch, so a later swap of the SAME handle dir must preserve
    // whatever an earlier launch already recorded.
    //
    // RED against an unconditional call (the pre-fix `record_keychain_account_hint`
    // used directly) would print: assertion failed, expected "earlier-launch-user",
    // got the LIVE `keychain_account()` value instead (the file was overwritten).
    #[cfg(target_os = "macos")]
    #[test]
    fn kc4_2_record_keychain_account_hint_if_absent_preserves_existing_hint() {
        let dir = tempfile::tempdir().unwrap();
        let recorded_path = dir.path().join(RECORDED_ACCOUNT_FILE);
        std::fs::write(&recorded_path, b"earlier-launch-user").unwrap();

        record_keychain_account_hint_if_absent(dir.path());

        assert_eq!(
            std::fs::read_to_string(&recorded_path).unwrap(),
            "earlier-launch-user",
            "an existing hint MUST survive a later record_keychain_account_hint_if_absent call"
        );
    }

    // KC4-2 — when no hint exists yet, `record_keychain_account_hint_if_absent`
    // MUST still record one (a fresh handle dir with no prior launch).
    #[cfg(target_os = "macos")]
    #[test]
    fn kc4_2_record_keychain_account_hint_if_absent_writes_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let recorded_path = dir.path().join(RECORDED_ACCOUNT_FILE);
        assert!(!recorded_path.exists());

        record_keychain_account_hint_if_absent(dir.path());

        assert!(
            recorded_path.exists(),
            "record_keychain_account_hint_if_absent must still record a hint when none exists"
        );
    }

    // ── kc-simplify-brief: S1/S2 single-item mirror-write tests ────────
    // All target the pure planner (`plan_mirror_write`) via an injected
    // classification of X — no real `security` subprocess, no real
    // keychain, safe on every runner.

    const FILE_JSON: &str = r#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"file-rt","expiresAt":1,"scopes":[]}}"#;

    // S2 — X Unreadable -> Err, zero mutations (no MirrorPlan is produced
    // to act on; the type system enforces it, not merely the value).
    //
    // RED against a broken planner that ignores the Unreadable case (e.g.
    // `RawContentClassification::Unreadable => (serde_json::Map::new(), None)`,
    // silently treating "we don't know" the same as "we asked and it's
    // gone") would print: assertion failed, expected Err(Unreadable) got
    // Ok(MirrorPlan { write_x: ... }).
    #[test]
    fn s2_unreadable_x_fails_closed_zero_mutations() {
        let err = plan_mirror_write(
            &RawContentClassification::Unreadable(UnreadableKind::Transient),
            FILE_JSON,
            true,
        )
        .unwrap_err();
        assert_eq!(err, PlanError::Unreadable);
    }

    // S2 — X Content -> merge: X's sibling keys survive; claudeAiOauth
    // comes from the FILE, never from X or any other top-level file key.
    #[test]
    fn s2_content_x_merges_siblings_claude_oauth_from_file() {
        let x = RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"old"},"mcp":"keep-me"}"#.to_string(),
        );
        let file = r#"{"claudeAiOauth":{"accessToken":"file-token","refreshToken":"file-rt","expiresAt":1,"scopes":[]},"bookkeeping":"must-not-leak"}"#;
        let plan = plan_mirror_write(&x, file, true).expect("plan");
        let v: serde_json::Value = serde_json::from_str(&plan.write_x).unwrap();
        assert_eq!(
            v["mcp"], "keep-me",
            "X's sibling key must survive the merge"
        );
        assert_eq!(
            v["claudeAiOauth"]["accessToken"], "file-token",
            "claudeAiOauth comes from the FILE, not from X"
        );
        assert!(
            v.get("bookkeeping").is_none(),
            "no OTHER top-level file key may leak into the keychain payload"
        );
    }

    // S2 — X Absent -> write the file's claudeAiOauth ONLY (no siblings to
    // preserve; nothing else in the payload).
    #[test]
    fn s2_absent_x_writes_file_claude_oauth_only() {
        let plan =
            plan_mirror_write(&RawContentClassification::Absent, FILE_JSON, true).expect("plan");
        let v: serde_json::Value = serde_json::from_str(&plan.write_x).unwrap();
        assert_eq!(
            v.as_object().unwrap().len(),
            1,
            "no siblings when X was Absent"
        );
        assert_eq!(v["claudeAiOauth"]["refreshToken"], "file-rt");
    }

    // S2 — payload built + validated before the write: invalid file JSON,
    // or a file object missing claudeAiOauth, fails BEFORE any plan is
    // produced (zero mutations) — regardless of X's own classification.
    #[test]
    fn s2_invalid_file_json_is_err_zero_mutations() {
        let err =
            plan_mirror_write(&RawContentClassification::Absent, "not json", true).unwrap_err();
        assert!(matches!(err, PlanError::InvalidFilePayload(_)));
    }

    #[test]
    fn s2_file_json_missing_claude_oauth_is_err() {
        let err = plan_mirror_write(
            &RawContentClassification::Absent,
            r#"{"somethingElse":true}"#,
            true,
        )
        .unwrap_err();
        assert!(matches!(err, PlanError::InvalidFilePayload(_)));
    }

    // S5 — the mirror image: `backfill_allowed = false` (v4: the caller
    // KNOWS this is a forced account-change write, not the ordinary
    // same-account path — see `force_sync_account_changed_with_executor`)
    // suppresses the backfill even when X's refreshToken happens to equal
    // the file's (which a refresh-token-equality proof would have read as
    // "same account, backfill"). Renamed from
    // `s5_backfill_suppressed_when_marker_pending_even_with_matching_refresh_token`
    // — v4 removed the account-change-pending marker entirely; this test's
    // actual subject was always the `backfill_allowed` parameter, never a
    // marker.
    #[test]
    fn s5_backfill_suppressed_when_backfill_disallowed_even_with_matching_refresh_token() {
        let x = RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"SAME-RT","subscriptionType":"max","rateLimitTier":"tier5"}}"#.to_string(),
        );
        let file = r#"{"claudeAiOauth":{"accessToken":"new","refreshToken":"SAME-RT","expiresAt":1,"scopes":[],"subscriptionType":null,"rateLimitTier":null}}"#;
        let plan = plan_mirror_write(&x, file, false).expect("plan");
        let v: serde_json::Value = serde_json::from_str(&plan.write_x).unwrap();
        assert!(
            v["claudeAiOauth"]["subscriptionType"].is_null(),
            "backfill_allowed=false must suppress the backfill regardless of refreshToken equality, got {v}"
        );
    }

    // ── R9-4 — `read_bounded_sentinel`: non-following, bounded, non-blocking ──

    // A symlink at `path` — even one pointing at a real, readable file —
    // must read as ABSENT, never as the pointed-to file's content.
    //
    // RED against a plain `std::fs::read_to_string` (which follows
    // symlinks) would print: assertion failed, `left: Some("attacker
    // content"), right: None`.
    #[cfg(unix)]
    #[test]
    fn read_bounded_sentinel_symlink_yields_absent() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-file");
        std::fs::write(&real, "attacker content").unwrap();
        let link = dir.path().join("sentinel");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert_eq!(
            read_bounded_sentinel(&link, 256),
            None,
            "a symlink at the sentinel path must read as absent, never follow through"
        );
    }

    // A regular file larger than `max_bytes` must not be read in full —
    // either the read is rejected outright, or it is truncated to a prefix
    // that never reaches the full oversized content. Either is safe; what
    // is NOT safe is materializing the whole thing in memory.
    //
    // RED against an unbounded `std::fs::read_to_string` would print:
    // assertion failed: result content length was NOT bounded — got the
    // full oversized string back.
    #[test]
    fn read_bounded_sentinel_oversized_file_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sentinel");
        let oversized = "a".repeat(10_000);
        std::fs::write(&path, &oversized).unwrap();

        match read_bounded_sentinel(&path, 256) {
            None => {} // rejected outright — safe
            Some(s) => assert!(
                s.len() <= 256,
                "an oversized file must be truncated to the byte cap, got {} bytes",
                s.len()
            ),
        }
    }

    // A FIFO with no writer must be rejected WITHOUT blocking — the whole
    // point of `O_NONBLOCK` in `read_bounded_sentinel`. This test's own
    // completion (rather than a hang) IS the assertion; a bounded budget
    // beyond the test harness's own overall timeout would only mask a
    // regression, so no explicit sleep/timeout wrapper is used here —
    // ordinary `cargo test` and CI already enforce an overall suite budget
    // that would surface a real hang.
    #[cfg(unix)]
    #[test]
    fn read_bounded_sentinel_fifo_is_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sentinel");
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // Private fixture only, no writer ever opens it — opening this
        // FIFO without O_NONBLOCK would wait indefinitely.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

        assert_eq!(
            read_bounded_sentinel(&path, 256),
            None,
            "a FIFO must be rejected (not adopted as content), and this call must return \
             promptly rather than block on the absent writer"
        );
    }

    #[test]
    fn service_name_format() {
        let svc = service_name(Path::new("/Users/test/.claude/accounts/config-1"));
        assert!(svc.starts_with("Claude Code-credentials-"));
        assert_eq!(svc.len(), "Claude Code-credentials-".len() + 8);
    }

    // ── Finding A: KeychainRead three-valued read boundary ────────────────

    /// `credential-type-hygiene.md` Rule 1: `KeychainRead::Found` carries a
    /// live `CredentialFile`; its manual `Debug` MUST print a placeholder
    /// and MUST NOT print the token bytes.
    #[test]
    fn keychain_read_debug_redacts_found_credential() {
        let json = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-NOTREALTOKu9x","refreshToken":"sk-ant-ort01-NOTREALTOKu9x","expiresAt":4102444800000,"scopes":["user:inference"]}}"#;
        let cred: CredentialFile = serde_json::from_str(json).expect("parse fixture");
        let read = KeychainRead::Found(Box::new(cred));
        let debug = format!("{read:?}");
        assert!(
            debug.contains("REDACTED"),
            "Debug output must contain a redaction placeholder: {debug}"
        );
        assert!(
            !debug.contains("NOTREALTOKu9x"),
            "Debug output must NOT contain the token bytes: {debug}"
        );
    }

    /// S-LOW-1 / `credential-type-hygiene.md` Rule 1: `ForcedWriteAttempt`
    /// carries a live `.credentials.json` payload in `raw_json`. Its manual
    /// `Debug` MUST print a placeholder and MUST NOT print the token bytes;
    /// the `None` (strip/delete) case MUST print distinctly from a redacted
    /// `Some`.
    #[test]
    fn forced_write_attempt_debug_redacts_raw_json() {
        let acct = crate::types::AccountNum::try_from(3u16).unwrap();
        let with_token = ForcedWriteAttempt {
            account: acct,
            raw_json: Some(
                r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-NOTREALTOKu9x","refreshToken":"sk-ant-ort01-NOTREALTOKu9x","expiresAt":4102444800000}}"#,
            ),
        };
        let debug = format!("{with_token:?}");
        assert!(
            debug.contains("REDACTED"),
            "Debug output must contain a redaction placeholder: {debug}"
        );
        assert!(
            !debug.contains("NOTREALTOKu9x"),
            "Debug output must NOT contain the token bytes: {debug}"
        );

        let strip = ForcedWriteAttempt {
            account: acct,
            raw_json: None,
        };
        let strip_debug = format!("{strip:?}");
        assert!(
            !strip_debug.contains("REDACTED"),
            "a strip/delete attempt (raw_json: None) must not claim redacted content: {strip_debug}"
        );
    }

    // v5: `ForcedSyncResult` no longer carries any raw keychain payload (the
    // `PreviousKeychainContent` snapshot it used to embed in `Applied`/
    // `WriteFailedUnknown` is gone), so its derived `Debug`/`Clone` no
    // longer needs a redacting hand-written impl — pinned by a plain
    // equality check rather than a redaction probe.
    #[test]
    fn forced_sync_result_applied_debug_has_no_secret_field_to_redact() {
        let applied = ForcedSyncResult::Applied { wrote_token: true };
        assert_eq!(format!("{applied:?}"), "Applied { wrote_token: true }");
    }

    /// Non-secret variants are unaffected by the manual impl — they still
    /// render their real (non-sensitive) content.
    #[test]
    fn keychain_read_debug_not_found_and_could_not_ask_are_plain() {
        assert_eq!(format!("{:?}", KeychainRead::NotFound), "NotFound");
        let debug = format!(
            "{:?}",
            KeychainRead::CouldNotAsk {
                kind: "keychain_invoke_failed"
            }
        );
        assert!(debug.contains("CouldNotAsk"));
        assert!(debug.contains("keychain_invoke_failed"));
    }

    /// `found()` collapses `NotFound` and `CouldNotAsk` identically — this is
    /// the lossy behaviour `read()` relies on; pin it so a future edit that
    /// changes the collapse is visible.
    #[test]
    fn keychain_read_found_collapses_non_found_variants_to_none() {
        assert!(KeychainRead::NotFound.found().is_none());
        assert!(KeychainRead::CouldNotAsk {
            kind: "keychain_utf8"
        }
        .found()
        .is_none());
    }

    #[test]
    fn keychain_read_found_extracts_some_from_found_variant() {
        let json =
            r#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"b","expiresAt":1,"scopes":[]}}"#;
        let cred: CredentialFile = serde_json::from_str(json).expect("parse fixture");
        let out = KeychainRead::Found(Box::new(cred)).found();
        assert!(out.is_some());
    }

    /// Finding A's actual defect: `classify_keychain_error_kind` MUST
    /// distinguish `keychain_not_found` ("asked, item absent") from every
    /// other tag ("could not complete the ask") — the distinction `read()`'s
    /// former public boundary erased.
    #[test]
    fn classify_keychain_error_kind_not_found_is_notfound_variant() {
        assert!(matches!(
            classify_keychain_error_kind("keychain_not_found"),
            KeychainRead::NotFound
        ));
    }

    #[test]
    fn classify_keychain_error_kind_other_tags_are_could_not_ask() {
        for kind in [
            "keychain_invoke_failed",
            "keychain_utf8",
            "keychain_hex_decode",
            "keychain_json_parse",
            "keychain_other",
        ] {
            let got = classify_keychain_error_kind(kind);
            assert!(
                matches!(got, KeychainRead::CouldNotAsk { kind: k } if k == kind),
                "{kind} must classify as CouldNotAsk{{kind: {kind:?}}}, got {got:?}"
            );
        }
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
        record_pending_clear(
            dir.path(),
            "Claude Code-credentials-aaaaaaaa",
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        record_pending_clear(
            dir.path(),
            "Claude Code-credentials-aaaaaaaa",
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        ); // duplicate

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

    /// `keychain-fix-r10.md` T-e (origin end-to-end, half 1): a
    /// `Logout`-origin entry round-trips through `record_pending_clear` /
    /// `load_pending_clears` carrying its origin — the SAME shape
    /// `accounts::logout::logout_account`'s own `record_pending_clear` call
    /// produces for a not-yet-confirmed-cleared handle dir at logout time.
    #[cfg(target_os = "macos")]
    #[test]
    fn record_pending_clear_round_trips_logout_origin() {
        let dir = tempfile::tempdir().unwrap();
        record_pending_clear(
            dir.path(),
            "Claude Code-credentials-aaaaaaaa",
            Some(AccountNum::try_from(1u16).unwrap()),
            PendingClearOrigin::Logout,
            None,
            None,
        );
        let clears = load_pending_clears(dir.path());
        assert_eq!(
            clears.services[0].origin,
            PendingClearOrigin::Logout,
            "the recorded origin must survive a persist+load round trip"
        );
    }

    /// `keychain-fix-r10.md` T-e (origin end-to-end, half 2): a legacy queue
    /// entry with NO `origin` field at all (every entry queued before
    /// `keychain-fix-r9.md` S-M-1/D-F2 introduced the field) MUST deserialize
    /// to `DeadHandle` — the MORE CONSERVATIVE disposition (decide+adopt,
    /// never an unconditional delete) per `guard-reader-writer-parity.md`
    /// MUST-2: an unreadable/absent input on a destructive path fails closed
    /// toward the safer branch, never toward `Logout`'s blind delete.
    #[cfg(target_os = "macos")]
    #[test]
    fn load_pending_clears_legacy_entry_without_origin_defaults_to_dead_handle() {
        let dir = tempfile::tempdir().unwrap();
        let raw = serde_json::json!({
            "services": [
                {"service": "Claude Code-credentials-deadbeef", "attempts": 0, "next_attempt_unix_secs": 0}
            ]
        });
        std::fs::write(
            pending_clears_path(dir.path()),
            serde_json::to_string(&raw).unwrap(),
        )
        .unwrap();

        let clears = load_pending_clears(dir.path());
        assert_eq!(
            clears.services[0].origin,
            PendingClearOrigin::DeadHandle,
            "a legacy entry with no recorded origin must fail closed to \
             DeadHandle, never Logout's unconditional delete"
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
            record_pending_clear(
                dir.path(),
                &fake_service(i),
                None,
                PendingClearOrigin::DeadHandle,
                None,
                None,
            );
        }
        // Queue is now exactly full at PENDING_CLEARS_MAX with fake_service(0..MAX).
        let overflow = fake_service(0xeeee_eeee);
        record_pending_clear(
            dir.path(),
            &overflow,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

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

    /// `keychain-fix-r10.md` C-I2: the OLDEST entry overall is `Logout`-origin
    /// (index 0), but a `DeadHandle` entry (index 1) is present — the
    /// `DeadHandle` one must be evicted instead, never the `Logout` one, even
    /// though it is objectively newer. A `Logout` entry is the only remaining
    /// record that account's keychain item still needs clearing; `DeadHandle`
    /// has other self-healing paths.
    ///
    /// RED: reverting to bare FIFO (`clears.services.remove(0)`) evicts the
    /// `Logout` entry at index 0 instead — this assertion fails, the
    /// `Logout` service name is gone and the `DeadHandle` one survives.
    #[cfg(target_os = "macos")]
    #[test]
    fn record_pending_clear_evicts_dead_handle_before_logout() {
        let dir = tempfile::tempdir().unwrap();
        let logout_svc = fake_service(1);
        record_pending_clear(
            dir.path(),
            &logout_svc,
            None,
            PendingClearOrigin::Logout,
            None,
            None,
        );
        // Fill the rest of the queue with DeadHandle entries so the queue is
        // exactly full at PENDING_CLEARS_MAX (1 Logout + (MAX-1) DeadHandle).
        for i in 2..PENDING_CLEARS_MAX as u32 + 1 {
            record_pending_clear(
                dir.path(),
                &fake_service(i),
                None,
                PendingClearOrigin::DeadHandle,
                None,
                None,
            );
        }
        let overflow = fake_service(0xeeee_eeee);
        record_pending_clear(
            dir.path(),
            &overflow,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

        let clears = load_pending_clears(dir.path());
        let names = service_names(&clears);
        assert!(
            names.contains(&logout_svc),
            "the Logout-origin entry must survive even though it is the \
             objectively OLDEST entry in the queue"
        );
        assert!(
            !names.contains(&fake_service(2)),
            "the oldest DeadHandle entry must be evicted instead"
        );
        assert!(
            names.contains(&overflow),
            "the new entry must be present after eviction"
        );
    }

    /// `keychain-fix-r10.md` S-L-3, security.md §5a: the pending-clears queue
    /// file carries service names, account numbers and email hints — clamp
    /// to 0o600 before the atomic rename, same as every other secret-bearing
    /// tmp write in this module.
    ///
    /// RED: removing the `secure_file(&tmp)` call from `save_pending_clears`
    /// (leaving `std::fs::write` -> `atomic_replace` directly) makes this
    /// assertion fail on the umask-default mode (typically 0o644) the file
    /// is created at.
    #[cfg(target_os = "macos")]
    #[test]
    fn save_pending_clears_secures_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        record_pending_clear(
            dir.path(),
            &fake_service(1),
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        let path = pending_clears_path(dir.path());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "pending-clears queue file must be 0o600, got {mode:o}"
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

    /// `keychain-fix-r10.md` S-N-1: an entry with a genuinely UNPARSEABLE
    /// SHAPE — `attempts` is a string, not a number — must be dropped alone;
    /// the OTHER two well-formed entries in the SAME file must survive.
    /// Distinct from `load_pending_clears_drops_malformed_entries_keeps_well_formed`,
    /// which exercises a malformed SERVICE NAME (a value that still
    /// deserializes as `PendingClearEntry`, just fails the shape filter
    /// afterward) — this exercises a value that fails to deserialize AT ALL,
    /// which previously took the WHOLE FILE down via the single
    /// `serde_json::from_str::<PendingClears>` call.
    ///
    /// RED: reverting `load_pending_clears` to `serde_json::from_str(&raw)
    /// .unwrap_or_else(|_| PendingClears::default())` on the whole file makes
    /// this assertion fail — BOTH well-formed entries are lost, not just the
    /// one with the bad shape.
    #[cfg(target_os = "macos")]
    #[test]
    fn load_pending_clears_drops_one_unparseable_entry_keeps_its_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let raw = serde_json::json!({
            "services": [
                {"service": "Claude Code-credentials-aaaaaaaa", "attempts": 0, "next_attempt_unix_secs": 0},
                {"service": "Claude Code-credentials-bbbbbbbb", "attempts": "not-a-number", "next_attempt_unix_secs": 0},
                {"service": "Claude Code-credentials-cccccccc", "attempts": 0, "next_attempt_unix_secs": 0},
            ]
        });
        std::fs::write(
            pending_clears_path(dir.path()),
            serde_json::to_string(&raw).unwrap(),
        )
        .unwrap();

        let clears = load_pending_clears(dir.path());
        let mut names = service_names(&clears);
        names.sort();
        assert_eq!(
            names,
            vec![
                "Claude Code-credentials-aaaaaaaa".to_string(),
                "Claude Code-credentials-cccccccc".to_string(),
            ],
            "the entry with the unparseable shape must be dropped alone; its \
             well-formed siblings in the SAME file must survive"
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
        record_pending_clear(
            dir.path(),
            "Claude Code-credentials-bbbbbbbb",
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

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
        record_pending_clear(
            dir.path(),
            &svc_a,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

        // Simulate the sweep's pre-attempt snapshot + a confirmed clear of A.
        let snapshot = load_pending_clears(dir.path());
        assert_eq!(service_names(&snapshot), vec![svc_a.clone()]);
        let cleared_entries = snapshot.services.clone();

        // "Concurrently" (between the sweep's read and its locked removal),
        // another logout records B.
        record_pending_clear(
            dir.path(),
            &svc_b,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

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
        record_pending_clear(
            dir.path(),
            &svc_a,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        let snapshot = load_pending_clears(dir.path());
        record_pending_clear(
            dir.path(),
            &svc_b,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        ); // concurrent insert

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
        record_pending_clear(
            dir.path(),
            &svc,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        ); // generation 0, never attempted: (0,0)

        // Sweep's pre-attempt snapshot — captures X at generation 0.
        let snapshot = load_pending_clears(dir.path());
        assert_eq!(snapshot.services[0].generation, 0);
        let cleared_entries = snapshot.services.clone(); // "confirmed cleared" this tick

        // "Concurrently" (between the sweep's read and its locked removal),
        // a NEW logout re-records the SAME service — generation bumps to 1,
        // but attempts/next_attempt reset to the SAME (0,0) the original had.
        record_pending_clear(
            dir.path(),
            &svc,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
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
        record_pending_clear(
            dir.path(),
            &svc,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        let snapshot = load_pending_clears(dir.path());
        let cleared_names: Vec<String> = snapshot
            .services
            .iter()
            .map(|e| e.service.clone())
            .collect();

        record_pending_clear(
            dir.path(),
            &svc,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        ); // concurrent re-record, generation bumps

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
        record_pending_clear(
            dir.path(),
            &svc,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

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
        record_pending_clear(
            dir.path(),
            "Claude Code-credentials-cccccccc",
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

        let mut spy = |_svc: &str,
                       _account: Option<AccountNum>,
                       _origin: PendingClearOrigin,
                       _candidate_email: Option<&str>,
                       _keychain_account_hint: Option<&str>,
                       _queued_identity: Option<(u64, i64)>|
         -> Result<bool, KeychainClearUnconfirmed> {
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
        record_pending_clear(
            dir.path(),
            "Claude Code-credentials-dddddddd",
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        // A freshly-recorded entry has next_attempt_unix_secs == 0, always due.
        let mut attempted = false;
        let mut spy = |_svc: &str,
                       _account: Option<AccountNum>,
                       _origin: PendingClearOrigin,
                       _candidate_email: Option<&str>,
                       _keychain_account_hint: Option<&str>,
                       _queued_identity: Option<(u64, i64)>|
         -> Result<bool, KeychainClearUnconfirmed> {
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
            record_pending_clear(
                dir.path(),
                &fake_service(0xcafe_0000 + i),
                None,
                PendingClearOrigin::DeadHandle,
                None,
                None,
            );
        }

        let mut attempts = 0usize;
        let mut spy = |_svc: &str,
                       _account: Option<AccountNum>,
                       _origin: PendingClearOrigin,
                       _candidate_email: Option<&str>,
                       _keychain_account_hint: Option<&str>,
                       _queued_identity: Option<(u64, i64)>|
         -> Result<bool, KeychainClearUnconfirmed> {
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
        record_pending_clear(
            dir.path(),
            &fake_service(0xf00d_0001),
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        record_pending_clear(
            dir.path(),
            &fake_service(0xf00d_0002),
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

        let mut spy = |_svc: &str,
                       _account: Option<AccountNum>,
                       _origin: PendingClearOrigin,
                       _candidate_email: Option<&str>,
                       _keychain_account_hint: Option<&str>,
                       _queued_identity: Option<(u64, i64)>|
         -> Result<bool, KeychainClearUnconfirmed> { Ok(true) };
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
        record_pending_clear(
            dir.path(),
            &svc,
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        // Hand-set a future backoff window directly (simulating a prior
        // failed attempt) rather than depending on wall-clock time.
        let mut clears = load_pending_clears(dir.path());
        clears.services[0].attempts = 1;
        clears.services[0].next_attempt_unix_secs = 4_102_444_800; // year 2100
        save_pending_clears(dir.path(), &clears, "test");

        // `now` well before the entry's backoff window — must be skipped.
        let mut attempted_early = false;
        let mut spy_early = |_svc: &str,
                             _account: Option<AccountNum>,
                             _origin: PendingClearOrigin,
                             _candidate_email: Option<&str>,
                             _keychain_account_hint: Option<&str>,
                             _queued_identity: Option<(u64, i64)>|
         -> Result<bool, KeychainClearUnconfirmed> {
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
        let mut spy_due = |_svc: &str,
                           _account: Option<AccountNum>,
                           _origin: PendingClearOrigin,
                           _candidate_email: Option<&str>,
                           _keychain_account_hint: Option<&str>,
                           _queued_identity: Option<(u64, i64)>|
         -> Result<bool, KeychainClearUnconfirmed> {
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
    fn sweep_sync_handle_dir_skips_when_marker_unreadable() {
        // No `.csq-account` marker (fresh/torn-down handle dir) → Ok(false),
        // no keychain call. Safe in `cargo test` (never touches the keychain).
        let dir = tempfile::tempdir().unwrap();
        assert!(!sweep_sync_handle_dir(dir.path(), dir.path(), &HashMap::new()).unwrap());
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

    // R7-4 — `BoundedLockOutcome` discrimination, via `lock_bounded_with_params`
    // (small attempts/delay so this costs milliseconds, not the production
    // 20.25s bound).
    //
    // RED against a mapping that collapsed `Ok(None)` and `Ok(Some)` (the
    // pre-R7-4 bare `Option`) would print: assertion failed, expected
    // `Acquired`, matched `TimedOut` (or the reverse) for one of the two
    // free/held cases below.
    #[cfg(target_os = "macos")]
    #[test]
    fn r7_4_lock_bounded_acquired_when_free() {
        let dir = tempfile::tempdir().unwrap();
        let outcome = lock_bounded_with_params(dir.path(), 1, std::time::Duration::from_millis(1));
        assert!(
            matches!(outcome, BoundedLockOutcome::Acquired(_)),
            "expected Acquired on a free lock file, got a different variant"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn r7_4_lock_bounded_times_out_when_held() {
        let dir = tempfile::tempdir().unwrap();
        // Hold the lock ourselves first, exactly like a concurrent `csq
        // swap`/`auto_rotate` would.
        let _holder = lock_handle_dir_for_swap(dir.path()).expect("holder acquires first");
        let outcome = lock_bounded_with_params(dir.path(), 1, std::time::Duration::from_millis(1));
        assert!(
            matches!(outcome, BoundedLockOutcome::TimedOut),
            "expected TimedOut while another holder has the lock, got {outcome:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn r7_4_lock_bounded_fails_on_unopenable_path() {
        // A config_dir whose parent does not exist -> `open_lock_file`'s
        // `OpenOptions::open` errors (ENOENT), never reaching the flock
        // retry loop at all -> `Err`, mapped to `Failed`, distinct from
        // `TimedOut` (an I/O error is NOT ordinary contention).
        let unopenable = std::path::Path::new("/nonexistent-dir-r7-4/deeper");
        let outcome = lock_bounded_with_params(unopenable, 1, std::time::Duration::from_millis(1));
        assert!(
            matches!(outcome, BoundedLockOutcome::Failed),
            "expected Failed on an unopenable lock path, got {outcome:?}"
        );
    }

    // R7-4 — the caller-visible half: `sync_all_handle_dirs` must classify
    // `TimedOut` vs `Failed` into DIFFERENT warn tags, not collapse both
    // into `keychain_sync_lock_timed_out` (the pre-R7-4 behavior — a bare
    // `Option` could not tell them apart). This test does not reach
    // `sync_all_handle_dirs` directly (that needs a live handle-dir tree);
    // it pins the discrimination `BoundedLockOutcome` exists to provide,
    // which every call site (`sync_all_handle_dirs`, `csq run`, `csq
    // exec`, `csq swap`, `phase2b`) matches on identically.
    #[cfg(target_os = "macos")]
    #[test]
    fn r7_4_timed_out_and_failed_are_distinct_variants() {
        let dir = tempfile::tempdir().unwrap();
        let _holder = lock_handle_dir_for_swap(dir.path()).expect("holder acquires first");
        let timed_out =
            lock_bounded_with_params(dir.path(), 1, std::time::Duration::from_millis(1));
        let failed = lock_bounded_with_params(
            std::path::Path::new("/nonexistent-dir-r7-4/deeper"),
            1,
            std::time::Duration::from_millis(1),
        );
        assert!(matches!(timed_out, BoundedLockOutcome::TimedOut));
        assert!(matches!(failed, BoundedLockOutcome::Failed));
    }

    #[test]
    fn sweep_sync_handle_dir_skips_non_anthropic_credential() {
        // Marker resolves to an account whose own canonical file is a
        // Codex/3P shape (no `claudeAiOauth`) → `TargetToken::as_valid_str()`
        // is `None` → Ok(false), no keychain call.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".csq-account"), "1").unwrap();
        let cfg = dir.path().join("config-1");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join(".credentials.json"),
            r#"{"openaiAuth":{"token":"x"}}"#,
        )
        .unwrap();
        assert!(!sweep_sync_handle_dir(dir.path(), dir.path(), &HashMap::new()).unwrap());
    }

    #[test]
    fn sweep_sync_handle_dir_skips_expired_token_no_keychain_call() {
        // Validity guard: an Anthropic credential whose token already expired
        // MUST NOT be mirrored (would propagate a 401 / clobber a fresh login).
        // expiresAt in the past → Ok(false), no keychain syscall (safe in CI).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".csq-account"), "1").unwrap();
        let cfg = dir.path().join("config-1");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join(".credentials.json"),
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","expiresAt":1000}}"#,
        )
        .unwrap();
        assert!(!sweep_sync_handle_dir(dir.path(), dir.path(), &HashMap::new()).unwrap());
    }

    #[test]
    fn sweep_sync_handle_dir_disabled_mirror_reports_not_synced() {
        // F7 (preserved under round 7c D2): in hermetic test mode (or the
        // production `CSQ_DISABLE_KEYCHAIN_MIRROR` kill-switch) the sweep
        // never reaches a keychain call at all — `Ok(false)` (not synced),
        // never `Ok(true)` for a write that never actually happened
        // (previously inflated `sync_all_handle_dirs`'s counted total).
        // No marker/canonical setup needed: the disabled-mirror check now
        // short-circuits before the marker is even resolved.
        let dir = tempfile::tempdir().unwrap();
        assert!(!sweep_sync_handle_dir(dir.path(), dir.path(), &HashMap::new()).unwrap());
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

    // ── BUG-C — synthetic-`Output` test fixtures ───────────────────────────
    //
    // `classify_expiry_output`/`KeychainExpiryRead` (this comment's original
    // subject) were removed at round 7c D2 and again with `write_raw` in
    // `keychain-fix-r8.md` (KA) — the fixtures below now serve
    // `classify_raw_content`'s own tests instead, driving it directly with a
    // synthetic `Output` (never a real `security` invocation).

    #[cfg(target_os = "macos")]
    fn fake_output_with_stdout(code: i32, stdout: &[u8]) -> BoundedOutput {
        fake_bounded_output(code, stdout, true)
    }

    /// Like [`fake_output_with_stdout`] but with an explicit completeness
    /// flag, for BUG-R3-1's incomplete-capture tests.
    #[cfg(target_os = "macos")]
    fn fake_bounded_output(code: i32, stdout: &[u8], stdout_complete: bool) -> BoundedOutput {
        use std::os::unix::process::ExitStatusExt;
        BoundedOutput {
            output: std::process::Output {
                status: std::process::ExitStatus::from_raw((code & 0xff) << 8),
                stdout: stdout.to_vec(),
                stderr: Vec::new(),
            },
            stdout_complete,
            stderr_complete: true,
        }
    }

    /// Drives `add_via_delete_create` with a scripted runner. Deletes pop
    /// `delete_codes` in order (`None` = timeout); once exhausted they report
    /// 44. Adds pop `add_codes` in order, then report 0. Returns every call
    /// (argv, with the stdin line appended) and the result.
    #[cfg(target_os = "macos")]
    fn run_add_scripted(
        invocation: AddInvocation,
        siblings_only: Option<String>,
        delete_codes: Vec<Option<i32>>,
        add_codes: Vec<i32>,
    ) -> (Vec<Vec<String>>, Result<(), PlatformError>) {
        let calls = std::cell::RefCell::new(Vec::<Vec<String>>::new());
        let deletes = std::cell::RefCell::new(std::collections::VecDeque::from(delete_codes));
        let adds = std::cell::RefCell::new(std::collections::VecDeque::from(add_codes));
        let runner = |args: &[&str], stdin: Option<Vec<u8>>| -> Option<BoundedOutput> {
            let mut rec: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            if let Some(line) = stdin {
                rec.push(String::from_utf8_lossy(&line).into_owned());
            }
            let is_delete = args.first() == Some(&"delete-generic-password");
            calls.borrow_mut().push(rec);
            if is_delete {
                match deletes.borrow_mut().pop_front() {
                    Some(c) => c.map(|c| fake_bounded_output(c, b"", true)),
                    None => Some(fake_bounded_output(SECURITY_ITEM_NOT_FOUND, b"", true)),
                }
            } else {
                let c = adds.borrow_mut().pop_front().unwrap_or(0);
                Some(fake_bounded_output(c, b"", true))
            }
        };
        let result = add_via_delete_create("svc", "acct", invocation, siblings_only, &runner);
        (calls.into_inner(), result)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn write_never_uses_dash_u_and_deletes_before_adding() {
        let small = select_add_invocation("svc", "acct", "payload").unwrap();
        let big_payload = "a".repeat(SECURITY_I_MAX_SAFE_LINE_BYTES);
        let big = select_add_invocation("svc", "acct", &big_payload).unwrap();
        assert!(matches!(big, AddInvocation::ArgvFallback(_)));
        for inv in [small, big] {
            let (calls, result) = run_add_scripted(inv, None, vec![], vec![]);
            result.expect("delete(44) then add(0) must succeed");
            assert_eq!(calls.len(), 2, "exactly one delete and one add: {calls:?}");
            assert_eq!(calls[0][0], "delete-generic-password", "delete first");
            assert_ne!(calls[1][0], "delete-generic-password");
            for call in &calls {
                assert!(
                    !call
                        .iter()
                        .any(|a| a == "-U" || a.contains("add-generic-password -U")),
                    "no write invocation may carry -U: {:?}",
                    call.first()
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn delete_failure_other_than_not_found_skips_the_add() {
        for delete_code in [Some(1), Some(51), None] {
            let inv = select_add_invocation("svc", "acct", "payload").unwrap();
            let (calls, result) = run_add_scripted(inv, None, vec![delete_code], vec![]);
            let err = result.expect_err("an unconfirmed delete must fail the write");
            assert!(
                err.to_string().contains("state is unknown"),
                "wording must not claim nothing changed: {err}"
            );
            assert_eq!(calls.len(), 1, "no add after a failed delete: {calls:?}");
            assert_eq!(calls[0][0], "delete-generic-password");
        }
    }

    /// Duplicates: two successful deletes then 44, and only then the add.
    #[cfg(target_os = "macos")]
    #[test]
    fn duplicate_items_are_deleted_until_not_found_before_the_add() {
        let inv = select_add_invocation("svc", "acct", "payload").unwrap();
        let (calls, result) = run_add_scripted(inv, None, vec![Some(0), Some(0)], vec![]);
        assert!(result.is_ok());
        let verbs: Vec<&str> = calls.iter().map(|c| c[0].as_str()).collect();
        assert_eq!(
            verbs,
            ["delete-generic-password"; 3]
                .iter()
                .copied()
                .chain(["-i"])
                .collect::<Vec<_>>()
        );
    }

    /// A delete that never reaches 44 within the budget refuses the write.
    #[cfg(target_os = "macos")]
    #[test]
    fn endless_duplicates_exhaust_the_delete_budget_and_skip_the_add() {
        let inv = select_add_invocation("svc", "acct", "payload").unwrap();
        let codes = vec![Some(0); MAX_DUPLICATE_DELETE_ITERATIONS as usize + 3];
        let (calls, result) = run_add_scripted(inv, None, codes, vec![]);
        assert!(result.is_err());
        assert_eq!(calls.len(), MAX_DUPLICATE_DELETE_ITERATIONS as usize);
        assert!(calls.iter().all(|c| c[0] == "delete-generic-password"));
    }

    /// Add fails after the delete: ONE siblings-only re-add. The previous
    /// content holds BOTH `claudeAiOauth` and `mcpOAuth`; the siblings come
    /// from the real extraction (`siblings_only_payload`), so the re-added
    /// payload must keep `mcpOAuth` and must NOT carry `claudeAiOauth`.
    #[cfg(target_os = "macos")]
    #[test]
    fn add_failure_after_delete_re_adds_siblings_only() {
        let previous = RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"OLDTOKEN"},"mcpOAuth":{"t":"x"}}"#.to_string(),
        );
        let inv = select_add_invocation("svc", "acct", "payload").unwrap();
        let (calls, result) =
            run_add_scripted(inv, siblings_only_payload(&previous), vec![], vec![1, 0]);
        assert!(result.is_err(), "the original add failure must surface");
        assert_eq!(calls.len(), 3, "delete, failed add, re-add: {calls:?}");
        let readd = calls[2].join(" ");
        let hex_payload = readd.rsplit("-X ").next().unwrap().trim();
        let decoded = String::from_utf8(hex::decode(hex_payload).unwrap()).unwrap();
        assert!(decoded.contains("mcpOAuth"), "{decoded}");
        assert!(!decoded.contains("claudeAiOauth"), "{decoded}");
        assert!(!decoded.contains("OLDTOKEN"), "{decoded}");
    }

    /// `apply_cc_keychain_write` hands the executor siblings derived from
    /// the caller's already-read `current`, with no extra `find`.
    #[cfg(target_os = "macos")]
    #[test]
    fn apply_write_passes_siblings_from_current_without_extra_find() {
        struct Spy {
            seen: std::cell::RefCell<Option<Option<String>>>,
            finds: std::cell::Cell<u32>,
        }
        impl KeychainExecutor for Spy {
            fn find(&self, _: &str, _: &str) -> RawContentClassification {
                self.finds.set(self.finds.get() + 1);
                RawContentClassification::Absent
            }
            fn add(&self, _: &str, _: &str, _: &str) -> Result<(), PlatformError> {
                panic!("the write must go through add_restoring")
            }
            fn add_restoring(
                &self,
                _: &str,
                _: &str,
                _: &str,
                siblings_only: Option<String>,
            ) -> Result<(), PlatformError> {
                *self.seen.borrow_mut() = Some(siblings_only);
                Ok(())
            }
            fn delete(&self, _: &str, _: &str) -> bool {
                false
            }
        }
        let spy = Spy {
            seen: std::cell::RefCell::new(None),
            finds: std::cell::Cell::new(0),
        };
        let current = RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"OLD"},"mcpOAuth":{"t":"x"}}"#.to_string(),
        );
        let raw = r#"{"claudeAiOauth":{"accessToken":"NEW","refreshToken":"r","expiresAt":4102444800000}}"#;
        let out = apply_cc_keychain_write(
            &spy,
            "svc",
            "acct",
            &current,
            WriteDecision::Write(raw),
            false,
        );
        assert!(matches!(out, ApplyOutcome::Applied { .. }), "{out:?}");
        assert_eq!(spy.finds.get(), 0, "no extra keychain read");
        let seen = spy.seen.borrow().clone().expect("add_restoring called");
        let siblings = seen.expect("siblings derived from current");
        assert!(siblings.contains("mcpOAuth") && !siblings.contains("claudeAiOauth"));
    }

    /// No previous siblings: no re-add is attempted.
    #[cfg(target_os = "macos")]
    #[test]
    fn add_failure_after_delete_without_siblings_does_not_re_add() {
        let inv = select_add_invocation("svc", "acct", "payload").unwrap();
        let (calls, result) = run_add_scripted(inv, None, vec![], vec![1]);
        assert!(result.is_err());
        assert_eq!(calls.len(), 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn security_op_timeout_long_bound_only_in_explicit_scope() {
        assert_eq!(security_op_timeout(false), KEYCHAIN_OP_TIMEOUT);
        assert_eq!(security_op_timeout(true), KEYCHAIN_INTERACTIVE_OP_TIMEOUT);
        assert!(KEYCHAIN_INTERACTIVE_OP_TIMEOUT > KEYCHAIN_OP_TIMEOUT);
        // A tty-only caller is outside the scope, so it is passed `false`.
        assert!(!interactive_scope_active());
        assert_eq!(
            security_op_timeout(interactive_scope_active()),
            KEYCHAIN_OP_TIMEOUT
        );
        with_interactive_keychain(|| {
            assert_eq!(
                security_op_timeout(interactive_scope_active()),
                KEYCHAIN_INTERACTIVE_OP_TIMEOUT
            );
        });
    }

    /// F3: a raw wait status whose LOW bits encode a terminating SIGNAL
    /// (never an exit code) — the shape `ExitStatus::code()` returns `None`
    /// for on Unix. Exercises the "signal death" path `classify_raw_content`
    /// must NOT fold into `Inaccessible` (F3's bug: the old `_ =>
    /// Inaccessible` wildcard caught `None` as well as every other `Some`).
    #[cfg(target_os = "macos")]
    fn fake_signal_killed_output(signal: i32, stdout: &[u8]) -> BoundedOutput {
        use std::os::unix::process::ExitStatusExt;
        BoundedOutput {
            output: std::process::Output {
                // Low 7 bits = the terminating signal, no exit-code shift —
                // `ExitStatus::code()` is `None` for this raw status.
                status: std::process::ExitStatus::from_raw(signal & 0x7f),
                stdout: stdout.to_vec(),
                stderr: Vec::new(),
            },
            stdout_complete: true,
            stderr_complete: true,
        }
    }

    // round 7c D2: the `classify_expiry_output_*` tests that lived here were
    // removed with the function itself (see the production-side comment at
    // its former definition site) — `sweep_sync_handle_dir` no longer shells
    // a second `security find-generic-password -w` to learn X's expiry; it
    // classifies the SAME `RawContentClassification` read
    // (`classify_raw_content`, tested below) that `decide_cc_keychain_write`
    // already needs. `keychain-fix-r8.md` (KA): the write-allowed-vs-unknown
    // distinction this comment used to attribute to `keychain_is_fresher_or_
    // equal_or_unknown`'s R7-6 guard is now `decide_cc_keychain_write`'s own
    // rule 2/4/5 (that guard, `write_raw`, and the type are all removed —
    // every CC-keychain-item writer routes through the single policy).

    // ── C1 — `classify_raw_content`'s three outcomes ───────────────────────

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_exit_44_is_absent() {
        assert_eq!(
            classify_raw_content(Some(fake_output_with_stdout(SECURITY_ITEM_NOT_FOUND, b""))),
            RawContentClassification::Absent
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_exit_36_is_inaccessible() {
        // F3/F4 (owner decision, "switch now or say so", 2026-09-26):
        // exit 36 (`errSecInteractionNotAllowed`) is the ONLY completed
        // exit classified `Inaccessible` — measured live on
        // esperie-mac-mini, in a Background (SSH-like) launchd session,
        // against a throwaway keychain: a LOCKED read of a PRESENT item
        // exits 36. S5: a launch-time caller REFUSES on this variant — the
        // handle dir is fresh, so a present item names a stale leftover
        // from an earlier occupant (PID reuse), not the current account.
        assert_eq!(
            classify_raw_content(Some(fake_output_with_stdout(
                SECURITY_ERR_INTERACTION_NOT_ALLOWED,
                b""
            ))),
            RawContentClassification::Unreadable(UnreadableKind::Inaccessible)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_other_completed_exits_are_transient() {
        // F3/F4: every OTHER completed, non-44, non-36 exit refuses the
        // launch (Transient), not Inaccessible — the prior `_ =>
        // Inaccessible` wildcard treated ANY non-44 failure as "asked and
        // refused, same as CC", which was never measured for anything but
        // exit 36. 51 (errSecAuthFailed) and 128 (a `security` internal
        // error shape) and 1 (a generic failure) are exercised as
        // representative "some other completed exit" cases.
        for code in [51, 128, 1] {
            assert_eq!(
                classify_raw_content(Some(fake_output_with_stdout(code, b""))),
                RawContentClassification::Unreadable(UnreadableKind::Transient),
                "exit {code} must be Transient, not Inaccessible"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_signal_killed_is_transient() {
        // F3: a signal-terminated child has `ExitStatus::code() == None` on
        // Unix — the bug this test guards is `classify_raw_content` folding
        // that into the SAME wildcard arm as "asked and refused" exits and
        // reporting Inaccessible for a process that never even completed
        // its ask. A signal death tells us nothing about whether CC could
        // read the same item, so it MUST refuse the launch (Transient).
        assert_eq!(
            classify_raw_content(Some(fake_signal_killed_output(9, b""))), // SIGKILL
            RawContentClassification::Unreadable(UnreadableKind::Transient)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_incomplete_capture_is_unreadable() {
        let bo = fake_bounded_output(0, br#"{"claudeAiOauth":{}}"#, false);
        assert_eq!(
            classify_raw_content(Some(bo)),
            RawContentClassification::Unreadable(UnreadableKind::Transient)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_none_is_unreadable() {
        assert_eq!(
            classify_raw_content(None),
            RawContentClassification::Unreadable(UnreadableKind::Transient)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_raw_json_object_is_content() {
        let json = r#"{"claudeAiOauth":{"accessToken":"old"},"mcpOAuth":{"token":"x"}}"#;
        assert_eq!(
            classify_raw_content(Some(fake_output_with_stdout(0, json.as_bytes()))),
            RawContentClassification::Content(json.to_string())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_hex_encoded_object_is_content() {
        // Replaces the old (vacuous) hex "sibling" test — this drives the
        // classifier directly with a HEX-ENCODED BoundedOutput, the exact
        // shape a legacy csq-written item takes.
        let json = r#"{"claudeAiOauth":{"accessToken":"old"},"mcpOAuth":{"token":"x"}}"#;
        let hex = hex::encode(json.as_bytes());
        assert_eq!(
            classify_raw_content(Some(fake_output_with_stdout(0, hex.as_bytes()))),
            RawContentClassification::Content(json.to_string())
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_non_object_json_is_unreadable() {
        // A JSON value that parses but is NOT an object (e.g. a bare
        // string) is neither "confirmed absent" nor "safe to merge with".
        let non_object_json = r#""just a string, not an object""#;
        let hex = hex::encode(non_object_json.as_bytes());
        assert_eq!(
            classify_raw_content(Some(fake_output_with_stdout(0, hex.as_bytes()))),
            RawContentClassification::Unreadable(UnreadableKind::Transient)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_empty_successful_exit_is_unreadable() {
        assert_eq!(
            classify_raw_content(Some(fake_output_with_stdout(0, b""))),
            RawContentClassification::Unreadable(UnreadableKind::Transient)
        );
    }

    // ── F4 — `build_write_payload` merges siblings, never other file keys ──

    #[cfg(target_os = "macos")]
    #[test]
    fn build_write_payload_merges_siblings_with_file_claude_oauth() {
        let mut siblings = serde_json::Map::new();
        siblings.insert("mcpOAuth".to_string(), serde_json::json!({"token": "x"}));
        let file =
            r#"{"claudeAiOauth":{"accessToken":"new"},"someBookkeepingFieldOnTheFile":true}"#;
        let payload = build_write_payload(&siblings, file, None, false).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["claudeAiOauth"]["accessToken"], "new");
        assert_eq!(
            value["mcpOAuth"]["token"], "x",
            "sibling key mcpOAuth must survive the mirror write untouched"
        );
        assert!(
            value.get("someBookkeepingFieldOnTheFile").is_none(),
            "F4: a top-level key from the FILE, other than claudeAiOauth, must never be copied"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_write_payload_no_siblings_writes_claude_oauth_only() {
        // The `Absent` case: nothing to merge with, so the payload is just
        // the file's `claudeAiOauth`.
        let siblings = serde_json::Map::new();
        let file = r#"{"claudeAiOauth":{"accessToken":"new"}}"#;
        let payload = build_write_payload(&siblings, file, None, false).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 1);
        assert_eq!(value["claudeAiOauth"]["accessToken"], "new");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_write_payload_errors_on_file_without_claude_oauth() {
        let siblings = serde_json::Map::new();
        assert!(build_write_payload(&siblings, r#"{"somethingElse":true}"#, None, false).is_err());
    }

    // ── F8 — subscriptionType/rateLimitTier backfill on the SAME account ──

    #[cfg(target_os = "macos")]
    #[test]
    fn build_write_payload_backfills_subscription_fields_when_file_is_null_same_account() {
        let siblings = serde_json::Map::new();
        let file = r#"{"claudeAiOauth":{"accessToken":"new","subscriptionType":null,"rateLimitTier":null}}"#;
        let existing = serde_json::json!({
            "accessToken": "old",
            "subscriptionType": "max",
            "rateLimitTier": "tier4",
        });
        let payload = build_write_payload(&siblings, file, Some(&existing), true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["claudeAiOauth"]["accessToken"], "new");
        assert_eq!(value["claudeAiOauth"]["subscriptionType"], "max");
        assert_eq!(value["claudeAiOauth"]["rateLimitTier"], "tier4");
    }

    /// An emptied login carries no identity, so it never backfills plan
    /// metadata into the account being written; its siblings still survive.
    #[cfg(target_os = "macos")]
    #[test]
    fn plan_mirror_write_emptied_login_keeps_siblings_but_never_backfills() {
        let x = RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"","refreshToken":"","expiresAt":0,"subscriptionType":"max","rateLimitTier":"tier4"},"mcpOAuth":{"k":"v"}}"#
                .to_string(),
        );
        let file = r#"{"claudeAiOauth":{"accessToken":"new","refreshToken":"new-rt","subscriptionType":null,"rateLimitTier":null}}"#;
        let plan = plan_mirror_write(&x, file, true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&plan.write_x).unwrap();
        assert_eq!(value["claudeAiOauth"]["accessToken"], "new");
        assert!(
            value["claudeAiOauth"]["subscriptionType"].is_null(),
            "{value}"
        );
        assert!(value["claudeAiOauth"]["rateLimitTier"].is_null(), "{value}");
        assert_eq!(
            value["mcpOAuth"]["k"], "v",
            "siblings must survive: {value}"
        );
    }

    /// Two emptied logins never "match": an empty refresh token identifies
    /// nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn emptied_logins_never_match_each_other() {
        let emptied = r#"{"claudeAiOauth":{"accessToken":"","refreshToken":"","expiresAt":0}}"#;
        assert!(!keychain_content_matches_token(
            &RawContentClassification::Content(emptied.to_string()),
            emptied
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_write_payload_does_not_backfill_when_file_already_has_a_value() {
        let siblings = serde_json::Map::new();
        let file = r#"{"claudeAiOauth":{"accessToken":"new","subscriptionType":"pro"}}"#;
        let existing = serde_json::json!({"accessToken": "old", "subscriptionType": "max"});
        let payload = build_write_payload(&siblings, file, Some(&existing), true).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            value["claudeAiOauth"]["subscriptionType"], "pro",
            "a genuinely fresh value from the file must not be clobbered by the existing one"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn build_write_payload_does_not_backfill_across_accounts() {
        // A swap: the existing item belongs to the PREVIOUS account — its
        // subscription tier says nothing about the NEW one.
        let siblings = serde_json::Map::new();
        let file = r#"{"claudeAiOauth":{"accessToken":"new","subscriptionType":null}}"#;
        let existing = serde_json::json!({"accessToken": "old", "subscriptionType": "max"});
        let payload = build_write_payload(&siblings, file, Some(&existing), false).unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(
            value["claudeAiOauth"]["subscriptionType"].is_null(),
            "same_account=false must not backfill from a different account's item"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn extract_sibling_object_drops_claude_oauth_keeps_others() {
        let json = r#"{"claudeAiOauth":{"accessToken":"old"},"mcpOAuth":{"token":"x"},"other":1}"#;
        let obj = extract_sibling_object(json);
        assert!(!obj.contains_key("claudeAiOauth"));
        assert_eq!(obj["mcpOAuth"]["token"], "x");
        assert_eq!(obj["other"], 1);
    }

    // ── F3/S4/S6/R7-1 — `plan_clear_stale_action`'s branching ───────────────
    // The planner is PLATFORM-INDEPENDENT (pure, no `security` shelling) —
    // R7-9: no `#[cfg(target_os = "macos")]` gate on these tests; they run
    // on every CI runner.

    // ── F6 — `classify_reader_recv` treats a reader I/O error as incomplete ─

    // ── F6 — `classify_reader_recv` treats a reader I/O error as incomplete ─

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_reader_recv_ok_ok_is_complete_with_buffer() {
        let recv: Result<std::io::Result<Vec<u8>>, std::sync::mpsc::RecvTimeoutError> =
            Ok(Ok(b"hello".to_vec()));
        let (complete, buf) = classify_reader_recv(recv);
        assert!(complete);
        assert_eq!(buf, b"hello");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_reader_recv_reader_io_error_is_not_complete() {
        // F6: the reader thread's own `read_to_end` FAILED — `recv` itself
        // succeeded (the thread sent something), but the payload is not a
        // real, possibly-empty capture. MUST NOT be treated as complete.
        let recv: Result<std::io::Result<Vec<u8>>, std::sync::mpsc::RecvTimeoutError> = Ok(Err(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe error"),
        ));
        let (complete, buf) = classify_reader_recv(recv);
        assert!(
            !complete,
            "a reader I/O error must not be reported as a completed capture"
        );
        assert!(buf.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn classify_reader_recv_timeout_is_not_complete() {
        let recv: Result<std::io::Result<Vec<u8>>, std::sync::mpsc::RecvTimeoutError> =
            Err(std::sync::mpsc::RecvTimeoutError::Timeout);
        let (complete, buf) = classify_reader_recv(recv);
        assert!(!complete);
        assert!(buf.is_empty());
    }

    // ── BUG-A — `run_bounded`'s wall-clock bound survives a descendant
    // holding the pipes open ────────────────────────────────────────────
    //
    // `sh`/`sleep` only, never `security`. `sh -c 'X & Y'` backgrounds `X`
    // (a grandchild that inherits `sh`'s stdout/stderr pipes) then runs `Y`
    // in the foreground. Both cases below leave a descendant holding the
    // pipes open long after the awaited process itself is gone; before the
    // fix, joining the reader threads unconditionally blocked on that
    // descendant regardless of which path (timeout or normal-exit) was hit.

    /// The keychain-lock classifier that keeps csq's background keychain
    /// traffic from raising macOS's "security wants to use the login
    /// keychain" unlock dialog. Locked must be recognised from the status
    /// bits (kSecUnlockStateStatus CLEAR), unlocked from the bit SET, and an
    /// unreadable status must NOT be read as locked (that would silently
    /// stop every keychain mirror on a host where the probe fails).
    #[test]
    #[cfg(target_os = "macos")]
    fn keychain_lock_state_classifies_status_bits() {
        fn locked() -> Option<u32> {
            Some(0) // readable, writable bits may be set elsewhere; unlock bit clear
        }
        fn locked_other_bits() -> Option<u32> {
            Some(0b110) // kSecReadPermStatus | kSecWritePermStatus, unlock bit clear
        }
        fn unlocked() -> Option<u32> {
            Some(0b111)
        }
        fn unreadable() -> Option<u32> {
            None
        }
        assert_eq!(keychain_lock_state(locked), KeychainLockState::Locked);
        assert_eq!(
            keychain_lock_state(locked_other_bits),
            KeychainLockState::Locked
        );
        assert_eq!(keychain_lock_state(unlocked), KeychainLockState::Unlocked);
        assert_eq!(keychain_lock_state(unreadable), KeychainLockState::Unknown);
    }

    /// Only a NON-interactive process with a CONFIRMED-locked keychain skips
    /// the call. An interactive process keeps the prompt (the operator asked
    /// for the operation and is there to answer it) and never pays for the
    /// probe; an unknown lock state proceeds.
    #[test]
    #[cfg(target_os = "macos")]
    fn defer_only_when_non_interactive_and_locked() {
        assert!(should_defer_for_locked_keychain(false, || {
            KeychainLockState::Locked
        }));
        assert!(!should_defer_for_locked_keychain(false, || {
            KeychainLockState::Unlocked
        }));
        assert!(!should_defer_for_locked_keychain(false, || {
            KeychainLockState::Unknown
        }));
        assert!(!should_defer_for_locked_keychain(true, || {
            panic!("an interactive process must not probe the keychain")
        }));
    }

    /// The lock probe is bounded: an answering probe passes its value
    /// through, a hung one yields Unknown (None) within the bound.
    #[test]
    #[cfg(target_os = "macos")]
    fn bounded_probe_returns_value_or_none_on_timeout() {
        fn quick() -> Option<u32> {
            Some(0b111)
        }
        fn hung() -> Option<u32> {
            std::thread::sleep(std::time::Duration::from_secs(5));
            Some(0)
        }
        use std::sync::atomic::{AtomicBool, Ordering};
        static FLIGHT: AtomicBool = AtomicBool::new(false);
        assert_eq!(
            bounded_probe_with(&FLIGHT, quick, std::time::Duration::from_secs(2)),
            Some(0b111)
        );
        assert!(
            !FLIGHT.load(Ordering::SeqCst),
            "a finished probe clears in-flight"
        );
        let t0 = std::time::Instant::now();
        assert_eq!(
            bounded_probe_with(&FLIGHT, hung, std::time::Duration::from_millis(200)),
            None
        );
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
        // The hung probe is still in flight: a second call must not spawn
        // another thread — it returns Unknown immediately.
        assert!(FLIGHT.load(Ordering::SeqCst));
        let t1 = std::time::Instant::now();
        assert_eq!(
            bounded_probe_with(&FLIGHT, quick, std::time::Duration::from_secs(2)),
            None
        );
        assert!(t1.elapsed() < std::time::Duration::from_millis(100));
    }

    /// The interactive scope is active only inside the closure, nests, and
    /// is cleared even if the closure panics.
    #[test]
    fn interactive_scope_is_scoped_and_unwind_safe() {
        assert!(!interactive_scope_active());
        with_interactive_keychain(|| {
            assert!(interactive_scope_active());
            with_interactive_keychain(|| assert!(interactive_scope_active()));
            assert!(interactive_scope_active());
        });
        assert!(!interactive_scope_active());
        let _ = std::panic::catch_unwind(|| with_interactive_keychain(|| panic!("boom")));
        assert!(!interactive_scope_active());
    }

    /// The daemon's catch-up sweep is due exactly once after the keychain
    /// stops reading as locked — whether THIS process deferred a call or
    /// another process (which leaves no flag here) skipped work while it was
    /// locked — and never while it is still locked.
    #[test]
    #[cfg(target_os = "macos")]
    fn catch_up_due_once_after_unlock_from_either_signal() {
        use std::sync::atomic::AtomicBool;
        use KeychainLockState::{Locked, Unknown, Unlocked};
        // Steady unlocked, nothing deferred: no sweep.
        let (d, l) = (AtomicBool::new(false), AtomicBool::new(false));
        assert!(!catch_up_due_with(&d, &l, Unlocked));
        // Locked (another process skipped work): no sweep while locked...
        assert!(!catch_up_due_with(&d, &l, Locked));
        assert!(!catch_up_due_with(&d, &l, Locked));
        // ...one sweep on the transition, then none.
        assert!(catch_up_due_with(&d, &l, Unlocked));
        assert!(!catch_up_due_with(&d, &l, Unlocked));
        // A deferral in this process (no observed lock) also triggers once.
        d.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(catch_up_due_with(&d, &l, Unknown));
        assert!(!catch_up_due_with(&d, &l, Unknown));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn run_bounded_timeout_path_bounded_despite_descendant_holding_pipe() {
        // `sh` itself runs `sleep 30` in the foreground, so `try_wait` never
        // sees it exit before the deadline; `sleep 5` (backgrounded) holds
        // the pipes open independently of whether `sh` gets killed.
        let mut cmd = std::process::Command::new("sh");
        // Constants (tooling-self-verification Rule 3): the fixed code returns
        // at the 300ms deadline plus kill/reap time (well under a second, a few
        // seconds under heavy host load); the bug blocks until the backgrounded
        // `sleep 30` releases the pipe (~30s). A 15s ceiling leaves >=10s of
        // margin on each side, so host load cannot flip the verdict.
        cmd.args(["-c", "sleep 30 & sleep 60"]);
        let start = std::time::Instant::now();
        let out = run_bounded(cmd, std::time::Duration::from_millis(300), None);
        let elapsed = start.elapsed();
        assert!(out.is_none(), "expected timeout -> None, got {out:?}");
        assert!(
            elapsed < std::time::Duration::from_secs(15),
            "run_bounded did not bound the timeout path: {elapsed:?} \
             (BUG-A: reader-thread joins blocked on a descendant's pipe)"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn run_bounded_normal_exit_path_bounded_despite_descendant_holding_pipe() {
        // `sh` itself exits almost immediately (`exit 0`), well within the
        // deadline, but the backgrounded `sleep 5` inherits its pipes and
        // holds them open for ~5s afterward.
        let mut cmd = std::process::Command::new("sh");
        // Constants (tooling-self-verification Rule 3): the deadline must be
        // long enough for `sh` to START and exit even on a heavily loaded host
        // (a 300ms deadline flaked under load: the spawn alone exceeded it, so
        // the run hit the timeout path instead of the path under test). The
        // fixed code returns within deadline + grace (<= ~5.25s); the bug
        // blocks until the backgrounded `sleep 30` releases the pipe (~30s).
        // A 15s ceiling separates them with ~10s of margin on each side.
        cmd.args(["-c", "sleep 30 & exit 0"]);
        let start = std::time::Instant::now();
        let out = run_bounded(cmd, std::time::Duration::from_secs(5), None);
        let elapsed = start.elapsed();
        let out = out.expect("sh exited normally within the deadline -> Some(Output)");
        assert!(out.output.status.success());
        assert!(
            elapsed < std::time::Duration::from_secs(15),
            "run_bounded did not bound the normal-exit path: {elapsed:?} \
             (BUG-A: reader-thread joins blocked on a descendant's pipe)"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn run_bounded_normal_exit_flags_incomplete_stdout_when_reader_starved() {
        // BUG-R3-1: `sh` prints then exits almost immediately, but the
        // backgrounded `sleep 5` inherits the SAME stdout pipe and holds it
        // open well past the process's own exit — the reader thread cannot
        // deliver (`read_to_end` only returns on EOF, which needs every
        // holder of the write end to close it), so `stdout_complete` MUST be
        // `false` even though the exit status itself is a success.
        let mut cmd = std::process::Command::new("sh");
        // Deadline sized so `sh` reliably exits inside it on a loaded host
        // (300ms flaked: the spawn alone exceeded it); the backgrounded
        // `sleep 30` outlives it, so the reader is still starved at return.
        cmd.args(["-c", "echo hello; sleep 30 & exit 0"]);
        let bo = run_bounded(cmd, std::time::Duration::from_secs(5), None)
            .expect("sh exited successfully within the deadline");
        assert!(bo.output.status.success());
        assert!(
            !bo.stdout_complete,
            "expected stdout to be flagged incomplete while a descendant holds the pipe"
        );
    }

    /// an internal ticket round 2 (BUG-2): the stdin bytes `run_bounded` is given DO
    /// reach the child, round-tripped through a shell that echoes its own
    /// stdin — proves the writer thread's happy path actually delivers the
    /// data (not merely that it does not crash).
    #[cfg(target_os = "macos")]
    #[test]
    fn run_bounded_stdin_data_reaches_the_child() {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "read l; printf '%s' \"$l\""]);
        let bo = run_bounded(
            cmd,
            std::time::Duration::from_secs(5),
            Some(b"hello\n".to_vec()),
        )
        .expect("sh exited successfully within the deadline");
        assert!(bo.output.status.success());
        assert_eq!(bo.output.stdout, b"hello");
    }

    /// an internal ticket round 2 (BUG-2, the fix): a stdin write that fails (here:
    /// EPIPE, because the child closes its own stdin before we write) MUST
    /// be treated as failure (`None`) — never as "the process still ran to
    /// completion and its (stdin-independent) exit status is trustworthy".
    /// The prior code (`let _ = stdin_pipe.write_all(&data)`) discarded
    /// this Result entirely and would have returned `Some(..)` here.
    #[cfg(target_os = "macos")]
    #[test]
    fn run_bounded_failed_stdin_write_is_treated_as_failure() {
        // A payload SMALLER than the OS pipe buffer (~64KB on macOS) is a
        // race: `write_all` can complete into the buffer before the child
        // gets around to closing its end, so a fast-exiting child does not
        // reliably reproduce EPIPE. A payload well OVER that size forces
        // `write_all` to make multiple write() calls, so by the time the
        // buffer is full and the child (which never reads stdin, and exits
        // immediately) has exited and closed its end, a subsequent write()
        // deterministically returns EPIPE.
        let big_payload = vec![b'a'; 4 * 1024 * 1024];
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "exit 0"]);
        let out = run_bounded(cmd, std::time::Duration::from_secs(5), Some(big_payload));
        assert!(
            out.is_none(),
            "a failed stdin write must be treated as failure, got {out:?}"
        );
    }

    #[test]
    fn sync_all_handle_dirs_empty_base_is_noop() {
        // No term-* dirs → (0,0,0), no keychain syscall (CI-safe; also the
        // refresher's post-refresh sweep relies on this for test isolation).
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(sync_all_handle_dirs(dir.path(), &HashMap::new()), (0, 0, 0));
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
                // C5: the string `read_impl` now actually emits when
                // `run_security_bounded` returns `None` (spawn failure OR
                // SIGKILLed timeout) — distinct from "keychain entry not
                // found" (a completed invocation reporting absence).
                PlatformError::Keychain("security unavailable (spawn failure or timeout)".into()),
                "keychain_invoke_failed",
            ),
            (
                // BUG-1: `read_impl_error_for_exit`'s string for a completed
                // invocation that exited non-zero with a code OTHER than
                // `SECURITY_ITEM_NOT_FOUND` — a denial, not an absence.
                PlatformError::Keychain("security exit Some(1)".into()),
                "keychain_denied",
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

    // R9-6 — `read_impl`'s ACTUAL post-fix fixed strings (not merely an
    // arbitrary same-prefix fixture, per the cases above) classify
    // correctly. `read_impl` itself is unreachable in-process under
    // `cfg!(test)` (`keychain_mirror_disabled()` short-circuits before any
    // real `security` shelling or JSON parsing occurs), so this is the
    // closest available regression guard: it locks the EXACT literal
    // `read_impl` now emits on a utf8/json-parse failure, so a future edit
    // that reintroduces `{e}` interpolation (which would change the exact
    // string, though likely still keep the prefix) has a test asserting
    // the specific fixed value rather than only the prefix shape.
    #[test]
    fn r9_6_read_impl_fixed_strings_classify_correctly() {
        assert_eq!(
            keychain_error_kind(&PlatformError::Keychain("utf8 decode failed".to_string())),
            "keychain_utf8"
        );
        assert_eq!(
            keychain_error_kind(&PlatformError::Keychain("json parse failed".to_string())),
            "keychain_json_parse"
        );
    }

    #[test]
    fn classifier_falls_back_to_other_for_unknown_messages() {
        let e = PlatformError::Keychain("some future error we didn't anticipate".into());
        assert_eq!(keychain_error_kind(&e), "keychain_other");
    }

    // ── BUG-1 — `read_impl_error_for_exit` MUST NOT collapse denial into NotFound ──
    //
    // Security review finding: the old `read_impl` mapped EVERY non-zero
    // `security` exit to "keychain entry not found", so an access denial
    // (errSecInteractionNotAllowed / errSecAuthFailed — locked keychain, no
    // Aqua session) classified as `KeychainRead::NotFound` exactly like a
    // genuinely absent item. `read_impl_error_for_exit` is the pure mapping
    // under test here because `keychain_mirror_disabled()` forces the
    // early-return "not found" branch in every test process, so `read_impl`
    // itself can never exercise a real `security` exit code.

    #[cfg(target_os = "macos")]
    #[test]
    fn read_impl_error_for_exit_44_is_genuinely_not_found() {
        let e = read_impl_error_for_exit(Some(SECURITY_ITEM_NOT_FOUND));
        let PlatformError::Keychain(msg) = &e else {
            panic!("expected Keychain variant");
        };
        assert_eq!(msg, "keychain entry not found");
        assert_eq!(keychain_error_kind(&e), "keychain_not_found");
        assert!(matches!(
            classify_keychain_error_kind(keychain_error_kind(&e)),
            KeychainRead::NotFound
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_impl_error_for_exit_nonzero_non_44_is_could_not_ask_not_notfound() {
        // exit 1 stands in for errSecInteractionNotAllowed / errSecAuthFailed —
        // a completed invocation that was REFUSED, not one that resolved to
        // "absent". This is the exact case that must NEVER collapse into
        // NotFound: this test REDs against the old
        // `if !output.status.success() { .. "keychain entry not found" .. }`
        // unconditional mapping.
        let e = read_impl_error_for_exit(Some(1));
        let PlatformError::Keychain(msg) = &e else {
            panic!("expected Keychain variant");
        };
        assert_ne!(
            msg, "keychain entry not found",
            "a non-44 exit must not be tagged as genuine absence"
        );
        let kind = keychain_error_kind(&e);
        assert_ne!(kind, "keychain_not_found");
        assert_eq!(kind, "keychain_denied");
        assert!(matches!(
            classify_keychain_error_kind(kind),
            KeychainRead::CouldNotAsk { .. }
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_impl_error_for_exit_no_code_is_could_not_ask_not_notfound() {
        // Signal-terminated child (no exit code at all) must ALSO not
        // collapse into NotFound.
        let e = read_impl_error_for_exit(None);
        let kind = keychain_error_kind(&e);
        assert_ne!(kind, "keychain_not_found");
        assert!(matches!(
            classify_keychain_error_kind(kind),
            KeychainRead::CouldNotAsk { .. }
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn read_impl_error_for_exit_message_never_carries_stderr_or_payload() {
        // The message MUST carry only the numeric exit code (security.md
        // MUST-2: no secrets, no upstream diagnostics, in a log-adjacent
        // string).
        let e = read_impl_error_for_exit(Some(1));
        let PlatformError::Keychain(msg) = &e else {
            panic!("expected Keychain variant");
        };
        assert_eq!(msg, "security exit Some(1)");
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

    // ── C5 — every `security` subprocess in this file MUST be bounded ────
    //
    // Source-scanning tripwire in the `ledger_no_quota_writer_touched` /
    // security.md §5a idiom: a bare `.output()` call bypasses
    // `run_security_bounded`'s `KEYCHAIN_OP_TIMEOUT` and can hang forever on
    // a locked keychain (security.md §6 — every keychain call MUST have a
    // timeout path). `wait_with_output()` is excluded — that string no
    // longer appears in production code at all (BUG-3 replaced it with an
    // owned-`Child` `try_wait` poll loop), but the exclusion is harmless to
    // keep since it simply never matches.
    #[test]
    fn no_bare_unbounded_output_call_in_this_file() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let this_file = std::path::PathBuf::from(manifest_dir).join("src/credentials/keychain.rs");
        let content = std::fs::read_to_string(&this_file).expect("read self for tripwire");

        // Scope to PRODUCTION code only: stop at the `#[cfg(test)] mod tests`
        // boundary. Without this, the scan finds its OWN source lines (the
        // `.output()` / `wait_with_output()` string literals a few lines
        // below this comment) and reports a false positive against itself.
        let boundary = "\nmod tests {";
        let production_code = match content.find(boundary) {
            Some(idx) => &content[..idx],
            None => panic!("could not locate `mod tests {{` boundary in self-scan"),
        };

        let mut offending_lines = Vec::new();
        for (i, line) in production_code.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains(".output()") && !trimmed.contains("wait_with_output()") {
                offending_lines.push(i + 1);
            }
        }

        assert!(
            offending_lines.is_empty(),
            "found bare unbounded `.output()` call(s) at line(s) {offending_lines:?} — \
             every `security` subprocess MUST go through `run_security_bounded` \
             (security.md §6); a locked keychain hangs a bare `.output()` forever."
        );
    }

    // Widened + hardened sibling of the tripwire above: `.output()` catches
    // ONE way to bypass the timeout bound, but a NEW security-CLI spawn
    // anywhere outside `run_security_bounded` — via `.status()`, `.spawn()` +
    // a hand-rolled wait, a differently-quoted program path
    // (`"/usr/bin/security"`), or any other API — bypasses it just as
    // completely. This scans for the SPAWN POINT itself across BOTH files
    // that spawn the `security` CLI (`credentials::keychain` and
    // `providers::codex::keychain`, which now share ONE bounded runner —
    // see the same-class fix cited in the commit that widened this test), so
    // it cannot be evaded by choosing a different reading method, a
    // different quoting of the program name, or a different module.
    #[test]
    fn no_bare_security_spawn_outside_shared_bounded_runner() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let files = [
            "src/credentials/keychain.rs",
            "src/providers/codex/keychain.rs",
        ];

        let mut offending: Vec<(&str, usize, String)> = Vec::new();
        for file in files {
            let path = std::path::PathBuf::from(manifest_dir).join(file);
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {file} for tripwire: {e}"));

            let boundary = "
mod tests {";
            let production_code = match content.find(boundary) {
                Some(idx) => &content[..idx],
                None => panic!("could not locate `mod tests {{` boundary in {file}"),
            };

            let mut current_fn = String::new();
            for (i, line) in production_code.lines().enumerate() {
                match classify_top_level_line(line) {
                    TopLevelLine::FnStart(name) => current_fn = name,
                    // A new non-fn top-level item (impl/mod/macro_rules!/
                    // static/const/struct/enum) means we are no longer
                    // inside the fn body last seen — a stale name here would
                    // mis-attribute (or silently exempt) a violation.
                    TopLevelLine::OtherItem => current_fn.clear(),
                    TopLevelLine::Body => {}
                }

                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    continue;
                }
                if is_security_new_call(trimmed) && current_fn != "run_security_bounded" {
                    offending.push((file, i + 1, current_fn.clone()));
                }
            }
        }

        assert!(
            offending.is_empty(),
            "found a `::new(\"...security\")` spawn outside `run_security_bounded`              at {offending:?} — every `security` CLI subprocess MUST be spawned through the shared `run_security_bounded` so it inherits              KEYCHAIN_OP_TIMEOUT (security.md §6); a locked keychain hangs an ad-hoc spawn forever."
        );
    }

    /// What a production-code line means for the tripwire's "which fn am I
    /// in" tracking.
    #[derive(Debug, PartialEq, Eq)]
    enum TopLevelLine {
        /// Starts a `fn` item (any combination of `pub`/`pub(crate)`/
        /// `pub(super)`/`async`/`unsafe`/`const` modifiers); carries the
        /// extracted fn name.
        FnStart(String),
        /// Starts a DIFFERENT top-level item (`impl`, `mod`, `macro_rules!`,
        /// `static`, `const` [non-fn], `struct`, `enum`) — the tracked fn
        /// name must be cleared, since we are no longer inside it.
        OtherItem,
        /// An ordinary body line — no change to the tracked fn name.
        Body,
    }

    fn classify_top_level_line(line: &str) -> TopLevelLine {
        let mut rest = line.trim_start();
        // Strip at most one visibility modifier.
        for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
            if let Some(r) = rest.strip_prefix(prefix) {
                rest = r;
                break;
            }
        }
        let after_vis = rest;

        // Strip zero or more of async/unsafe/const before `fn` (legal
        // combinations include `async fn`, `unsafe fn`, `const fn`, and
        // `async unsafe fn`).
        let mut probe = after_vis;
        loop {
            let mut stripped = None;
            for kw in ["async ", "unsafe ", "const "] {
                if let Some(r) = probe.strip_prefix(kw) {
                    stripped = Some(r);
                    break;
                }
            }
            match stripped {
                Some(r) => probe = r,
                None => break,
            }
        }

        if let Some(after_fn) = probe.strip_prefix("fn ") {
            let name = after_fn
                .split(|c: char| c == '(' || c == '<' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .to_string();
            return TopLevelLine::FnStart(name);
        }

        for kw in [
            "impl ",
            "impl<",
            "mod ",
            "macro_rules!",
            "static ",
            "const ",
            "struct ",
            "enum ",
        ] {
            if after_vis.starts_with(kw) {
                return TopLevelLine::OtherItem;
            }
        }

        TopLevelLine::Body
    }

    /// `true` when `line` contains a `::new(...)` call whose sole/first
    /// argument is a quoted string literal ending in `security` — catches
    /// `Command::new("security")`, `Command::new("/usr/bin/security")`, and
    /// any other `SomeType::new("...security")` spawn construct.
    fn is_security_new_call(line: &str) -> bool {
        let mut idx = 0;
        while let Some(pos) = line[idx..].find("::new(") {
            let start = idx + pos + "::new(".len();
            let Some(end_rel) = line[start..].find(')') else {
                break;
            };
            let arg = line[start..start + end_rel].trim();
            if let Some(inner) = arg.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                if inner.ends_with("security") {
                    return true;
                }
            }
            idx = start;
        }
        false
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

    // ── A1: decide_harvest defense-in-depth — a zero-expiry candidate never
    //        wins, even if one somehow reached this function directly ──────
    //
    // RENAMED from `harvest_absent_keychain_read_is_none_not_expiry_zero`
    // (`instrument-discipline.md` MUST-2 / this repo's Finding B): that name
    // claimed to test "a torn/absent keychain READ is excluded before it can
    // become expiry=0", but the body never called anything on the read path
    // — it hand-built a `(0_u64, 0)` candidate and fed it straight to
    // `decide_harvest`, which is a DIFFERENT function operating several
    // layers downstream of any read. It was a real, passing assertion about
    // `decide_harvest`'s own defense-in-depth (already covered in spirit by
    // `decide_harvest_all_candidates_le_store_returns_none`), not a test of
    // the read path its name promised. See
    // `harvest_candidate_expiry_none_raw_is_read_absent_not_expiry_zero`
    // below for the real read-path test this test's name should have been.
    #[test]
    fn decide_harvest_zero_expiry_candidate_never_wins_against_positive_store() {
        // Validate: decide_harvest with an expiry-0 candidate does NOT win
        // against a store with any expiry > 0 — defense-in-depth in case a
        // caller ever passes an unfiltered/expired candidate through.
        let store = Some(1_u64);
        let zero_expiry_candidate = [(0_u64, 0)];
        assert_eq!(
            decide_harvest(&zero_expiry_candidate, store),
            None,
            "expiry=0 candidate must not win against store_expiry=1"
        );
    }

    // ── A1 (Finding B fix): harvest_candidate_expiry — the actual read-path
    //        decision, directly testable without a real `security` shell ──

    /// The behaviour the retired test's name promised: a `None` keychain
    /// read (absent item, timeout, spawn failure, or undecodable payload —
    /// exactly what `read_raw_keychain` returns in all four cases) is
    /// classified as [`HarvestSkipReason::ReadAbsentOrFailed`] and NEVER
    /// silently becomes an `expiry_ms` of `0`.
    #[cfg(target_os = "macos")]
    #[test]
    fn harvest_candidate_expiry_none_raw_is_read_absent_not_expiry_zero() {
        let got = harvest_candidate_expiry(None, 1_000);
        assert_eq!(
            got,
            Err(HarvestSkipReason::ReadAbsentOrFailed),
            "a None (absent/timeout/malformed) keychain read must classify as \
             ReadAbsentOrFailed, not silently become Ok(0)"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn harvest_candidate_expiry_non_anthropic_raw_is_rejected() {
        let codex_shaped = r#"{"tokens":{"access_token":"x"}}"#;
        assert_eq!(
            harvest_candidate_expiry(Some(codex_shaped), 1_000),
            Err(HarvestSkipReason::NonAnthropic)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn harvest_candidate_expiry_unparseable_expiry_is_rejected() {
        let malformed = r#"{"claudeAiOauth":{"accessToken":"x"}}"#; // no expiresAt
        assert_eq!(
            harvest_candidate_expiry(Some(malformed), 1_000),
            Err(HarvestSkipReason::ExpiryUnparseable)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn harvest_candidate_expiry_expired_token_is_rejected() {
        let expired = r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":500}}"#;
        assert_eq!(
            harvest_candidate_expiry(Some(expired), /* now */ 1_000),
            Err(HarvestSkipReason::Expired)
        );
        // Boundary: expiry == now is ALSO rejected (`<=`, not `<`).
        let at_now = r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":1000}}"#;
        assert_eq!(
            harvest_candidate_expiry(Some(at_now), 1_000),
            Err(HarvestSkipReason::Expired)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn harvest_candidate_expiry_valid_non_expired_returns_ok_expiry() {
        let live = r#"{"claudeAiOauth":{"accessToken":"x","expiresAt":5000}}"#;
        assert_eq!(
            harvest_candidate_expiry(Some(live), /* now */ 1_000),
            Ok(5000)
        );
    }

    // ── v4 "switch now or say so" — force_sync_account_changed ─────────
    //
    // A far-future non-expired Anthropic token, and X's siblings preserved
    // across a forced write — mirrors FILE_JSON's shape but with a valid
    // (non-expired) expiresAt so the T2 "valid new token" branch is reached.
    #[cfg(target_os = "macos")]
    const VALID_NEW_JSON: &str = r#"{"claudeAiOauth":{"accessToken":"new-at","refreshToken":"new-rt","expiresAt":4102444800000,"scopes":[]}}"#;

    // round 7c D1 test helper: give `dir` (used as both `base` and
    // `handle_dir` by every T1-T4/S4/F4 fixture below) a legacy numeric
    // marker plus a `config-1/.credentials.json` whose OAuth identity
    // matches `old_raw` exactly. `decide_cc_keychain_write` now requires X
    // to match a KNOWN account before a write/strip proceeds (rule 2) — the
    // mechanics these tests exercise (sibling preservation, no-backfill,
    // write-failure classification) are downstream of that check, so the
    // fixture must clear it first, exactly as a real `csq swap`/`auto_rotate`
    // pre-repoint call site would (the marker still names the pre-repoint
    // account, whose own canonical file is what "known" resolves to).
    #[cfg(target_os = "macos")]
    fn seed_marker_matching(dir: &Path, old_raw: &str) {
        std::fs::write(dir.join(".csq-account"), "1").expect("write legacy numeric marker");
        let cfg = dir.join("config-1");
        std::fs::create_dir_all(&cfg).expect("create config-1");
        std::fs::write(cfg.join(".credentials.json"), old_raw).expect("write config-1 creds");
    }

    // T1 — Unreadable X: `force_sync_account_changed` reports `Unreadable`,
    // zero mutations (no add, no delete) — the caller (A1: abort the
    // switch; A2: proceed without a mirror) decides what it means.
    //
    // RED against a version that folded `Unreadable` into the `Absent` arm
    // (treating "we could not ask" as "nothing there") would print:
    // assertion failed, `left: Applied { .. }`, `right: Unreadable` — a
    // mutation would ALSO show up in `calls`, which the next assert catches.
    // No marker/known-token seeding needed: `RawContentClassification::Unreadable`
    // short-circuits `force_sync_account_changed_with_executor` before
    // `decide_cc_keychain_write` is ever called.
    #[cfg(target_os = "macos")]
    #[test]
    fn t1_force_sync_unreadable_x_zero_mutations_reports_unreadable() {
        let rec = RecordingExecutor::scripted(RawContentClassification::Unreadable(
            UnreadableKind::Transient,
        ));
        let dir = tempfile::tempdir().unwrap();
        let result = force_sync_account_changed_with_executor(
            &rec,
            dir.path(),
            dir.path(),
            Some(VALID_NEW_JSON),
        );
        assert!(
            matches!(result, Ok(ForcedSyncResult::Unreadable(_))),
            "expected Ok(Unreadable), got {result:?}"
        );
        let calls = rec.calls();
        assert_eq!(
            calls.len(),
            1,
            "expected exactly one call (find), got {calls:?}"
        );
        assert_eq!(calls[0].0, "find");
    }

    // T2 — Readable X (siblings present), valid new token: exactly ONE
    // `add` carrying the NEW account's `claudeAiOauth` plus X's siblings,
    // no backfill, REGARDLESS of X's own expiry (X's expiresAt here is far
    // LARGER than the new token's would-be comparison point under the
    // ordinary freshness guard — proving the guard is not consulted at
    // all on this path).
    //
    // RED against a version that re-applied `keychain_is_fresher_or_equal_or_unknown`
    // here would print: assertion failed, `calls.len()` == 1 (a spurious
    // skip), instead of the expected find+add pair.
    #[cfg(target_os = "macos")]
    #[test]
    fn t2_force_sync_readable_valid_token_writes_new_oauth_plus_siblings_no_backfill() {
        let old_raw = r#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old-rt","expiresAt":9999999999999,"subscriptionType":"max"},"mcp":"keep"}"#;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(old_raw.to_string()));
        let dir = tempfile::tempdir().unwrap();
        seed_marker_matching(dir.path(), old_raw);
        let result = force_sync_account_changed_with_executor(
            &rec,
            dir.path(),
            dir.path(),
            Some(VALID_NEW_JSON),
        );
        assert!(
            matches!(
                result,
                Ok(ForcedSyncResult::Applied {
                    wrote_token: true,
                    ..
                })
            ),
            "expected Applied{{wrote_token: true}}, got {result:?}"
        );
        let calls = rec.calls();
        assert_eq!(calls.len(), 2, "expected exactly find + add, got {calls:?}");
        assert_eq!(calls[1].0, "add");
        let payload = rec.last_add_payload().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["mcp"], "keep", "X's sibling must survive");
        assert_eq!(
            parsed["claudeAiOauth"]["accessToken"], "new-at",
            "the NEW account's token must be written"
        );
        assert!(
            parsed["claudeAiOauth"].get("subscriptionType").is_none(),
            "v4: no backfill on the account-changed path — got {parsed}"
        );
    }

    // T3 — target is POSITIVELY non-Anthropic (`new_credentials_json` is
    // `None` — a 3P/Codex slot has no `claudeAiOauth` shape to pass at
    // all): X's siblings are kept, its `claudeAiOauth` removed; the item
    // is deleted OUTRIGHT only when nothing else remains (two sub-cases
    // below).
    //
    // `keychain-fix-r8.md` C-F2 (structural half): this test previously
    // used `FILE_JSON` (an EXPIRED but Anthropic-shaped payload) here —
    // that was the exact bug: an expired/unparseable Anthropic payload is
    // not "positively non-Anthropic" and must not reach `Intended::Strip`
    // at all (see `c_f2_target_token_invalidated_refuses_not_strip`
    // below for the corrected behaviour on that input). `None` is the
    // genuine Strip-eligible case this test now exercises.
    #[cfg(target_os = "macos")]
    #[test]
    fn t3_force_sync_invalid_new_token_strips_oauth_keeps_siblings() {
        let old_raw = r#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old-rt","expiresAt":9999999999999},"mcp":"keep"}"#;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(old_raw.to_string()));
        let dir = tempfile::tempdir().unwrap();
        seed_marker_matching(dir.path(), old_raw);
        let result = force_sync_account_changed_with_executor(&rec, dir.path(), dir.path(), None);
        assert!(
            matches!(
                result,
                Ok(ForcedSyncResult::Applied {
                    wrote_token: false,
                    ..
                })
            ),
            "expected Applied{{wrote_token: false}}, got {result:?}"
        );
        let calls = rec.calls();
        assert_eq!(
            calls.len(),
            2,
            "expected find + add (remainder), got {calls:?}"
        );
        assert_eq!(calls[1].0, "add");
        let payload = rec.last_add_payload().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["mcp"], "keep");
        assert!(
            parsed.get("claudeAiOauth").is_none(),
            "claudeAiOauth must be stripped when the new token is invalid"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn t3_force_sync_invalid_new_token_deletes_item_when_no_siblings_remain() {
        let old_raw = r#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old-rt","expiresAt":9999999999999}}"#;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(old_raw.to_string()));
        let dir = tempfile::tempdir().unwrap();
        seed_marker_matching(dir.path(), old_raw);
        // C-F2: `None`, not an expired-but-Anthropic FILE_JSON — see the
        // sibling test above.
        let result = force_sync_account_changed_with_executor(&rec, dir.path(), dir.path(), None);
        assert!(
            matches!(
                result,
                Ok(ForcedSyncResult::Applied {
                    wrote_token: false,
                    ..
                })
            ),
            "expected Applied{{wrote_token: false}}, got {result:?}"
        );
        let calls = rec.calls();
        assert_eq!(calls.len(), 2, "expected find + delete, got {calls:?}");
        assert_eq!(
            calls[1].0, "delete",
            "no siblings remain -> the item must be DELETED, not written empty"
        );
    }

    // T4 — force_sync_for_launch: a write failure after a readable read
    // whose PREVIOUS content is UNKNOWN-if-mutated (X held real `Content`)
    // is an `Err` (A2: do not launch) — the disk state after the failed
    // write cannot be assumed still consistent, so a caller must refuse
    // rather than proceed. Exercised via `force_sync_account_changed`
    // directly (the executor-injection point) rather than the
    // locking/hint-recording wrapper, which is untestable against a real
    // `security` binary in-process — the lock/hint plumbing itself is
    // exercised by `force_sync_for_launch`'s own non-macOS/disabled-mirror
    // stub paths below.
    #[cfg(target_os = "macos")]
    #[test]
    fn s4_force_sync_write_failure_after_content_read_is_write_failed_unknown() {
        // S4: a failing write over KNOWN prior content no longer propagates
        // as a bare `Err` (which callers read as "nothing changed") — the
        // disk state is UNKNOWN (a watchdog-timed-out `add` may have
        // partially committed). v5: the caller no longer restores a
        // snapshot from this outcome — it proceeds to the repoint exactly
        // as for `Applied`, and `reconcile_keychain_to_marker` is the
        // compensating action if that repoint later fails.
        let old_raw = r#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old-rt","expiresAt":9999999999999}}"#;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(old_raw.to_string()));
        rec.add_ok.set(false);
        let dir = tempfile::tempdir().unwrap();
        seed_marker_matching(dir.path(), old_raw);
        let result = force_sync_account_changed_with_executor(
            &rec,
            dir.path(),
            dir.path(),
            Some(VALID_NEW_JSON),
        );
        assert!(
            matches!(result, Ok(ForcedSyncResult::WriteFailedUnknown)),
            "expected Ok(WriteFailedUnknown), got {result:?}"
        );
    }

    #[cfg(target_os = "macos")]
    const FOREIGN_RAW: &str = r#"{"claudeAiOauth":{"accessToken":"foreign-at","refreshToken":"foreign-rt","expiresAt":9999999999999},"mcpOAuth":{"k":"v"}}"#;

    /// Swap/daemon path (`quarantine_foreign = false`): an unidentified item
    /// is still refused, nothing deleted or written.
    #[cfg(target_os = "macos")]
    #[test]
    fn foreign_item_without_quarantine_still_refuses() {
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(FOREIGN_RAW.to_string()));
        let dir = tempfile::tempdir().unwrap();
        let result = force_sync_inner(&rec, dir.path(), dir.path(), Some(VALID_NEW_JSON), false);
        assert!(
            matches!(result, Ok(ForcedSyncResult::ForeignLoginUnharvested)),
            "{result:?}"
        );
        assert!(
            rec.calls().iter().all(|c| c.0 == "find"),
            "{:?}",
            rec.calls()
        );
        assert!(!dir.path().join(QUARANTINE_DIR_NAME).exists());
    }

    /// Swap/daemon path: an item Claude Code emptied after a failed refresh
    /// is replaced with the account's token, not refused, and nothing is
    /// quarantined because there is no login to save.
    #[cfg(target_os = "macos")]
    #[test]
    fn swap_path_replaces_an_emptied_login() {
        let rec = RecordingExecutor::scripted(RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"","refreshToken":"","expiresAt":0,"subscriptionType":"max"}}"#
                .to_string(),
        ));
        let dir = tempfile::tempdir().unwrap();
        let result = force_sync_inner(&rec, dir.path(), dir.path(), Some(VALID_NEW_JSON), false);
        assert!(
            matches!(result, Ok(ForcedSyncResult::Applied { wrote_token: true })),
            "{result:?}"
        );
        assert!(!dir.path().join(QUARANTINE_DIR_NAME).exists());
    }

    /// Fresh-launch path: the foreign payload is saved byte-for-byte at 0600
    /// in a 0700 dir, then the write proceeds and carries none of the
    /// foreign item's content.
    #[cfg(target_os = "macos")]
    #[test]
    fn fresh_launch_quarantines_foreign_item_then_writes() {
        let _trace = quarantine_trace_guard();
        use std::os::unix::fs::PermissionsExt;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(FOREIGN_RAW.to_string()));
        let dir = tempfile::tempdir().unwrap();
        let result = force_sync_inner(&rec, dir.path(), dir.path(), Some(VALID_NEW_JSON), true);
        assert!(
            matches!(result, Ok(ForcedSyncResult::Applied { wrote_token: true })),
            "{result:?}"
        );
        let qdir = dir.path().join(QUARANTINE_DIR_NAME);
        assert_eq!(
            std::fs::metadata(&qdir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let files: Vec<_> = std::fs::read_dir(&qdir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!(std::fs::read_to_string(&files[0]).unwrap(), FOREIGN_RAW);
        assert_eq!(
            std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let payload = rec
            .add_payloads
            .borrow()
            .last()
            .cloned()
            .expect("an add happened");
        assert!(
            !payload.contains("foreign-at") && !payload.contains("mcpOAuth"),
            "{payload}"
        );
    }

    /// If the quarantine cannot be written the item is NOT discarded: refuse,
    /// no add and no delete.
    #[cfg(target_os = "macos")]
    #[test]
    fn fresh_launch_quarantine_failure_refuses_without_mutation() {
        let _trace = quarantine_trace_guard();
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(FOREIGN_RAW.to_string()));
        let dir = tempfile::tempdir().unwrap();
        // A FILE where the quarantine directory must go.
        std::fs::write(dir.path().join(QUARANTINE_DIR_NAME), b"x").unwrap();
        let result = force_sync_inner(&rec, dir.path(), dir.path(), Some(VALID_NEW_JSON), true);
        assert!(
            matches!(result, Ok(ForcedSyncResult::QuarantineSaveFailed)),
            "{result:?}"
        );
        assert!(
            rec.calls().iter().all(|c| c.0 == "find"),
            "{:?}",
            rec.calls()
        );
    }

    /// A symlinked quarantine dir is refused (no write through the link).
    #[cfg(target_os = "macos")]
    #[test]
    fn fresh_launch_quarantine_refuses_symlinked_dir() {
        let _trace = quarantine_trace_guard();
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(FOREIGN_RAW.to_string()));
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), dir.path().join(QUARANTINE_DIR_NAME)).unwrap();
        let result = force_sync_inner(&rec, dir.path(), dir.path(), Some(VALID_NEW_JSON), true);
        assert!(
            matches!(result, Ok(ForcedSyncResult::QuarantineSaveFailed)),
            "{result:?}"
        );
        assert_eq!(std::fs::read_dir(elsewhere.path()).unwrap().count(), 0);
        assert!(rec.calls().iter().all(|c| c.0 == "find"));
    }

    /// Quarantine saves, then the replace add FAILS: the saved copy stays,
    /// the result is `WriteFailedUnknown`, and the launch refuses.
    #[cfg(target_os = "macos")]
    #[test]
    fn fresh_launch_quarantine_ok_but_replace_fails_refuses_launch() {
        let _trace = quarantine_trace_guard();
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(FOREIGN_RAW.to_string()));
        rec.add_ok.set(false);
        let dir = tempfile::tempdir().unwrap();
        let result = force_sync_inner(&rec, dir.path(), dir.path(), Some(VALID_NEW_JSON), true);
        assert!(
            matches!(result, Ok(ForcedSyncResult::WriteFailedUnknown)),
            "{result:?}"
        );
        let q = dir.path().join(QUARANTINE_DIR_NAME);
        assert_eq!(std::fs::read_dir(&q).unwrap().count(), 1, "copy kept");
        assert!(decide_launch_disposition(result).is_err());
    }

    /// Age prune: an old `.json` goes, a fresh one stays, a non-json file
    /// (`notes.txt`) is never touched even when old.
    #[cfg(target_os = "macos")]
    #[test]
    fn quarantine_prune_removes_only_old_json() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(31 * 24 * 3600);
        for name in ["20240101T000000000Z-a.json", "notes.txt"] {
            std::fs::write(q.join(name), "x").unwrap();
            std::fs::File::options()
                .write(true)
                .open(q.join(name))
                .unwrap()
                .set_modified(old)
                .unwrap();
        }
        std::fs::write(q.join("20990101T000000000Z-b.json"), "x").unwrap();
        prune_quarantine(q, QUARANTINE_KEEP, QUARANTINE_MAX_AGE);
        assert!(
            !q.join("20240101T000000000Z-a.json").exists(),
            "old json removed"
        );
        assert!(
            q.join("20990101T000000000Z-b.json").exists(),
            "fresh json kept"
        );
        assert!(q.join("notes.txt").exists(), "non-json untouched");
    }

    /// 12 files, then `prune_quarantine`: only the newest 10 remain (by
    /// name), the oldest two are removed.
    #[cfg(target_os = "macos")]
    #[test]
    fn quarantine_prunes_to_newest_ten() {
        let dir = tempfile::tempdir().unwrap();
        let q = dir.path().join(QUARANTINE_DIR_NAME);
        std::fs::create_dir_all(&q).unwrap();
        for i in 0..12 {
            std::fs::write(
                q.join(format!("20990101T0000{i:02}000Z-aaaaaaaa.json")),
                "{}",
            )
            .unwrap();
        }
        prune_quarantine(&q, QUARANTINE_KEEP, QUARANTINE_MAX_AGE);
        let mut names: Vec<String> = std::fs::read_dir(&q)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names.len(), 10, "{names:?}");
        assert!(
            names[0].contains("000002000Z") || names[0].contains("00002000Z"),
            "{names:?}"
        );
        assert!(
            names.last().unwrap().contains("000011000Z")
                || names.last().unwrap().contains("00011000Z"),
            "{names:?}"
        );
    }

    // F4/KC4: a write failure after a readable read whose PREVIOUS content
    // was CONFIRMED `Absent` MUST NOT refuse — there is nothing to leave
    // inconsistent (still absent either way), so the caller proceeds
    // without a mirror rather than blocking the launch/switch.
    //
    // RED against the pre-F4 code (any write failure => Err unconditionally)
    // would print: assertion failed: result.is_ok() — Err("keychain mirror
    // write skipped: ...") instead of Ok(AbsentWriteFailed).
    #[cfg(target_os = "macos")]
    #[test]
    fn f4_force_sync_write_failure_after_absent_read_is_absent_write_failed() {
        let rec = RecordingExecutor::scripted(RawContentClassification::Absent);
        rec.add_ok.set(false);
        let dir = tempfile::tempdir().unwrap();
        // No marker seeding needed: `Absent` hits rule 1 (`holds_no_login`)
        // unconditionally — free to write regardless of `known`.
        let result = force_sync_account_changed_with_executor(
            &rec,
            dir.path(),
            dir.path(),
            Some(VALID_NEW_JSON),
        );
        assert!(
            matches!(result, Ok(ForcedSyncResult::AbsentWriteFailed)),
            "a write failure over a CONFIRMED-absent X must proceed without a mirror, not refuse — got {result:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn s4_force_sync_delete_unconfirmed_is_write_failed_unknown() {
        // S4: same reasoning as the `add` case above, for the delete path
        // (T3's "no siblings remain -> delete outright" branch).
        let old_raw = r#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old-rt","expiresAt":9999999999999}}"#;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(old_raw.to_string()));
        rec.delete_ok.set(false);
        let dir = tempfile::tempdir().unwrap();
        seed_marker_matching(dir.path(), old_raw);
        // C-F2: `None` (positively non-Anthropic target), not an
        // expired-but-Anthropic FILE_JSON.
        let result = force_sync_account_changed_with_executor(&rec, dir.path(), dir.path(), None);
        assert!(
            matches!(result, Ok(ForcedSyncResult::WriteFailedUnknown)),
            "an unconfirmed delete over known content must be WriteFailedUnknown, not a silent success or a bare Err — got {result:?}"
        );
    }

    // `keychain-fix-r8.md` C-F2 (structural half — the primary test for this
    // fix): `new_credentials_json` carries a `claudeAiOauth` key (this slot
    // IS Anthropic) but its token is expired — `force_sync_account_changed_
    // with_executor` must refuse (`TargetTokenInvalidated`), never treat
    // this as `Intended::Strip` and force-write/delete toward X. X is
    // still classified via `find` (that happens unconditionally, before
    // intent is derived), but no `add`/`delete` follows — X itself is
    // never mutated.
    #[cfg(target_os = "macos")]
    #[test]
    fn c_f2_target_token_invalidated_refuses_not_strip() {
        let old_raw = r#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old-rt","expiresAt":9999999999999},"mcp":"keep"}"#;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(old_raw.to_string()));
        let dir = tempfile::tempdir().unwrap();
        seed_marker_matching(dir.path(), old_raw);
        // FILE_JSON IS Anthropic-shaped (`claudeAiOauth` present) but its
        // expiresAt (1) is long past — this must NOT be folded into Strip.
        let result =
            force_sync_account_changed_with_executor(&rec, dir.path(), dir.path(), Some(FILE_JSON));
        assert!(
            matches!(result, Ok(ForcedSyncResult::TargetTokenInvalidated)),
            "an expired-but-Anthropic new_credentials_json must refuse, not strip — got {result:?}"
        );
        let calls = rec.calls();
        assert_eq!(
            calls.len(),
            1,
            "exactly one `find` (to classify X, which happens before intent \
             is derived) and NO add/delete — X must not be touched: {calls:?}"
        );
        assert_eq!(calls[0].0, "find");
    }

    // The unparseable-expiry sibling of the above: `claudeAiOauth` present
    // but `expiresAt` missing/malformed. `anthropic_expiry_ms` returns
    // `None` for this exactly as it does for a past timestamp, so the same
    // refusal must fire.
    #[cfg(target_os = "macos")]
    #[test]
    fn c_f2_target_token_unparseable_expiry_refuses_not_strip() {
        let old_raw = r#"{"claudeAiOauth":{"accessToken":"old","refreshToken":"old-rt","expiresAt":9999999999999},"mcp":"keep"}"#;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(old_raw.to_string()));
        let dir = tempfile::tempdir().unwrap();
        seed_marker_matching(dir.path(), old_raw);
        let unparseable_expiry = r#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"rt"}}"#;
        let result = force_sync_account_changed_with_executor(
            &rec,
            dir.path(),
            dir.path(),
            Some(unparseable_expiry),
        );
        assert!(
            matches!(result, Ok(ForcedSyncResult::TargetTokenInvalidated)),
            "a claudeAiOauth payload with no parseable expiry must refuse, not strip — got {result:?}"
        );
        let calls = rec.calls();
        assert_eq!(calls.len(), 1, "only `find`, no add/delete: {calls:?}");
        assert_eq!(calls[0].0, "find");
    }

    // ── round 7c D2 — sweep_sync_handle_dir_with_executor ─────────────────
    //
    // The pre-refresh identity a sweep-tick recognizes, and the marker vs
    // `.credentials.json`-link disagreement case D2 requires coverage for.
    // Exercised via the executor-injection seam (`_with_executor`) — the
    // public `sweep_sync_handle_dir` is hermetically no-op'd under
    // `cfg!(test)`, same reasoning as `reconcile_keychain_to_marker`'s split.
    //
    // Real base/handle-dir topology (SIBLING dirs, real symlinks) —
    // `handle_dir_symlinks_are_consistent` requires `.csq-account` AND
    // `.credentials.json` in the handle dir to be SYMLINKS to
    // `config-<slot>/.csq-account` / `config-<slot>/.credentials.json`
    // (`seed_marker_matching` above writes plain files at the SAME path used
    // as both base and handle dir, which this stricter check reports
    // inconsistent — hence a dedicated fixture builder for the sweep).
    #[cfg(target_os = "macos")]
    fn seed_sweep_fixture(base: &Path, slot: u16, canonical_raw: &str) -> PathBuf {
        let handle_dir = base.join(format!("term-{slot}00"));
        std::fs::create_dir_all(&handle_dir).expect("create handle dir");
        let cfg = base.join(format!("config-{slot}"));
        std::fs::create_dir_all(&cfg).expect("create config dir");
        std::fs::write(cfg.join(".credentials.json"), canonical_raw).expect("write canonical");
        std::fs::write(cfg.join(".csq-account"), slot.to_string()).expect("write config marker");
        std::os::unix::fs::symlink(
            cfg.join(".credentials.json"),
            handle_dir.join(".credentials.json"),
        )
        .expect("symlink credentials");
        std::os::unix::fs::symlink(cfg.join(".csq-account"), handle_dir.join(".csq-account"))
            .expect("symlink marker");
        handle_dir
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn sweep_overwrites_the_pre_refresh_token() {
        // X holds the account's OLD (pre-refresh) identity — NOT its current
        // canonical (`VALID_NEW_JSON`) and not anything else "known" — so
        // absent `sweep_pre_refresh`, rule 3 would refuse it (see the next
        // test). Passing it as `refreshed`'s pre-refresh identity is what
        // makes decide() recognize X as "known" (rule 2) and overwrite it
        // with the fresh token.
        let pre_refresh_raw = r#"{"claudeAiOauth":{"accessToken":"pre-refresh-at","refreshToken":"pre-refresh-rt","expiresAt":1}}"#;
        let rec = RecordingExecutor::scripted(RawContentClassification::Content(
            pre_refresh_raw.to_string(),
        ));
        let base = tempfile::tempdir().unwrap();
        let handle_dir = seed_sweep_fixture(base.path(), 1, VALID_NEW_JSON);
        let account = AccountNum::try_from(1u16).unwrap();
        let mut refreshed = HashMap::new();
        refreshed.insert(
            account,
            crate::credentials::token_history::fingerprint_from_raw_json(pre_refresh_raw).unwrap(),
        );
        let result =
            sweep_sync_handle_dir_with_executor(&rec, base.path(), &handle_dir, &refreshed);
        assert!(
            matches!(result, Ok(true)),
            "expected Ok(true), got {result:?}"
        );
        let payload = rec.last_add_payload().unwrap();
        assert!(
            payload.contains("new-at"),
            "the sweep must write the account's CURRENT canonical token, got {payload}"
        );
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn sweep_does_not_overwrite_an_unmatched_token() {
        // X holds a token that matches NEITHER the marker account's current
        // canonical NOR any `refreshed` pre-refresh identity — a foreign
        // login (e.g. CC self-refreshed it independently). The sweep must
        // NOT harvest (that is the custodian's job) and must NOT write.
        let foreign_raw = r#"{"claudeAiOauth":{"accessToken":"foreign-at","refreshToken":"foreign-rt","expiresAt":9999999999999}}"#;
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(foreign_raw.to_string()));
        let base = tempfile::tempdir().unwrap();
        let handle_dir = seed_sweep_fixture(base.path(), 1, VALID_NEW_JSON);
        let result =
            sweep_sync_handle_dir_with_executor(&rec, base.path(), &handle_dir, &HashMap::new());
        assert!(
            matches!(result, Ok(false)),
            "expected Ok(false), got {result:?}"
        );
        assert!(
            rec.calls()
                .iter()
                .all(|(op, _, _)| *op != "add" && *op != "delete"),
            "the sweep must not mutate X when it cannot match a known account, got {:?}",
            rec.calls()
        );
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn sweep_skips_inconsistent_dirs() {
        // A leftover `.swap-tmp` makes `handle_dir_symlinks_are_consistent`
        // report `false` — the sweep must skip before even resolving the
        // marker, let alone touching the keychain.
        let rec = RecordingExecutor::scripted(RawContentClassification::Content(
            VALID_NEW_JSON.to_string(),
        ));
        let base = tempfile::tempdir().unwrap();
        let handle_dir = seed_sweep_fixture(base.path(), 1, VALID_NEW_JSON);
        std::fs::write(handle_dir.join(".credentials.json.swap-tmp"), b"leftover").unwrap();
        let result =
            sweep_sync_handle_dir_with_executor(&rec, base.path(), &handle_dir, &HashMap::new());
        assert!(
            matches!(result, Ok(false)),
            "expected Ok(false), got {result:?}"
        );
        assert!(
            rec.calls().is_empty(),
            "an inconsistent dir must not reach the keychain at all, got {:?}",
            rec.calls()
        );
    }

    #[cfg(all(target_os = "macos", unix))]
    #[test]
    fn sweep_skips_when_marker_and_credentials_link_disagree() {
        // D2: "the sweep uses the marker, not the `.credentials.json` link" —
        // when the two disagree, `handle_dir_symlinks_are_consistent` is the
        // structural gate that catches it BEFORE the sweep ever picks one
        // over the other: it refuses to act on a dir whose `.credentials.json`
        // target doesn't match what the MARKER's resolved account expects,
        // rather than trusting either signal alone. Constructed by pointing
        // the handle dir's `.credentials.json` at a DIFFERENT account's file
        // than the one the marker (account 1) names.
        let rec = RecordingExecutor::scripted(RawContentClassification::Absent);
        let base = tempfile::tempdir().unwrap();
        let handle_dir = seed_sweep_fixture(base.path(), 1, VALID_NEW_JSON);
        let cfg2 = base.path().join("config-2");
        std::fs::create_dir_all(&cfg2).unwrap();
        let account2_raw = r#"{"claudeAiOauth":{"accessToken":"account-2-at","refreshToken":"account-2-rt","expiresAt":4102444800000}}"#;
        std::fs::write(cfg2.join(".credentials.json"), account2_raw).unwrap();
        // Repoint the handle dir's `.credentials.json` to account 2's file —
        // disagreeing with the marker (still account 1).
        std::fs::remove_file(handle_dir.join(".credentials.json")).unwrap();
        std::os::unix::fs::symlink(
            cfg2.join(".credentials.json"),
            handle_dir.join(".credentials.json"),
        )
        .unwrap();
        let result =
            sweep_sync_handle_dir_with_executor(&rec, base.path(), &handle_dir, &HashMap::new());
        assert!(
            matches!(result, Ok(false)),
            "expected Ok(false), got {result:?}"
        );
        assert!(
            rec.calls().is_empty(),
            "a marker/link disagreement must not reach the keychain at all, got {:?}",
            rec.calls()
        );
    }

    // force_sync_for_launch / force_swap_write_before_repoint: under the
    // hermetic test guard (`keychain_mirror_disabled()` always true in this
    // crate's own test binary) both report the disabled/no-op outcome
    // rather than shelling `security` — this is the SAME guard every other
    // production entry point in this module carries (`write_raw`,
    // `sync_all_handle_dirs`), asserted here for the two NEW v4 entry points
    // so a future edit that forgets the guard on one of them is caught.
    #[test]
    fn force_sync_for_launch_disabled_mirror_reports_ok_true() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            force_sync_for_launch(dir.path(), dir.path()),
            Ok(true)
        ));
    }

    #[test]
    fn force_swap_write_before_repoint_disabled_mirror_reports_applied() {
        let dir = tempfile::tempdir().unwrap();
        let result = force_swap_write_before_repoint(dir.path(), dir.path(), Some(FILE_JSON));
        assert!(
            matches!(result, Ok(ForcedSyncResult::Applied { .. })),
            "expected Applied under the disabled-mirror guard, got {result:?}"
        );
    }

    // T5 — ordinary (K5) sync still applies the freshness guard and allows
    // same-account backfill; never strips. Covered end-to-end by the
    // `r7_6_write_raw_skips_add_when_keychain_already_fresher_or_equal`, and
    // `build_write_payload_backfills_subscription_fields_when_file_is_null_same_account`
    // — unchanged by round 7c D2 (the ordinary `write_raw` path's decision
    // logic did not move; only the SWEEP that decides which dirs to call it
    // for did, and that is `sweep_sync_handle_dir`'s own coverage above).
    //
    // These tests exercise the actual DECISION POINTS
    // `decide_launch_disposition`/`decide_swap_disposition` resolve, via the
    // pure seam — no `security` subprocess, no lock, no hint file.

    // S5 — launch: Unreadable(Inaccessible) (exit 36 — a PRESENT, locked
    // item on a FRESH handle dir) REFUSES the launch with the fixed
    // stale-item message. This flips the prior behaviour
    // (`decide_launch_disposition_inaccessible_proceeds`, which asserted
    // `Ok(false)`): that reasoning never distinguished a stale leftover
    // from PID reuse from a genuinely-absent SSH/headless case.
    #[test]
    fn decide_launch_disposition_inaccessible_refuses() {
        let result = Ok(ForcedSyncResult::Unreadable(UnreadableKind::Inaccessible));
        let err = decide_launch_disposition(result).expect_err("must refuse the launch");
        assert!(
            err.contains("earlier session") && err.contains("locked"),
            "expected the fixed stale-item message, got: {err}"
        );
    }

    // S5 — launch: a genuinely ABSENT item (exit 44) whose write fails
    // still PROCEEDS without the mirror — the normal SSH/headless case,
    // unaffected by the Inaccessible flip above.
    #[test]
    fn decide_launch_disposition_absent_write_failed_still_proceeds() {
        let result = Ok(ForcedSyncResult::AbsentWriteFailed);
        assert_eq!(decide_launch_disposition(result), Ok(false));
    }

    // S4 — launch: a write failure over KNOWN content (`WriteFailedUnknown`)
    // refuses — there is no repoint to roll back at launch time, so the
    // disposition is the same "do not launch" as a generic write failure.
    #[test]
    fn decide_launch_disposition_write_failed_unknown_refuses() {
        let result = Ok(ForcedSyncResult::WriteFailedUnknown);
        assert!(decide_launch_disposition(result).is_err());
    }

    // F8/KC4-10 — launch: Unreadable(Transient) refuses (does NOT launch).
    #[test]
    fn decide_launch_disposition_transient_refuses() {
        let result = Ok(ForcedSyncResult::Unreadable(UnreadableKind::Transient));
        assert!(
            decide_launch_disposition(result).is_err(),
            "a transient read failure must refuse the launch"
        );
    }

    // F8/KC4-10 — launch: a write failure over a KNOWN (Content) previous
    // state refuses (A2's original "do not launch" contract, unchanged).
    #[test]
    fn decide_launch_disposition_generic_write_failure_refuses() {
        let result = Err(PlatformError::Keychain("scripted add failure".to_string()));
        assert!(
            decide_launch_disposition(result).is_err(),
            "a generic (non-absent) write failure must refuse the launch"
        );
    }

    // F8/KC4-10 — launch: an absent-write-failure proceeds (F4), and a
    // successful Applied proceeds with the mirror written.
    #[test]
    fn decide_launch_disposition_absent_write_failed_and_applied() {
        assert_eq!(
            decide_launch_disposition(Ok(ForcedSyncResult::AbsentWriteFailed)),
            Ok(false)
        );
        assert_eq!(
            decide_launch_disposition(Ok(ForcedSyncResult::Applied { wrote_token: true })),
            Ok(true)
        );
    }

    // `keychain-fix-r8.md` C-F2 (structural half): both dispositions must
    // refuse (never proceed) on `TargetTokenInvalidated` — it means no
    // mutation was performed and this call's TARGET is untrustworthy right
    // now, which is never "proceed without a mirror" (unlike
    // `AbsentWriteFailed`, where X's disk state is confirmed unaffected).
    #[test]
    fn decide_launch_disposition_target_token_invalidated_refuses() {
        assert!(decide_launch_disposition(Ok(ForcedSyncResult::TargetTokenInvalidated)).is_err());
    }

    #[test]
    fn decide_swap_disposition_target_token_invalidated_refuses() {
        assert!(decide_swap_disposition(Ok(ForcedSyncResult::TargetTokenInvalidated)).is_err());
    }

    // F8/KC4-10 — swap: Unreadable (either kind) is Err, and the CALLER
    // (`csq swap`'s `handle`) must therefore never reach the repoint —
    // `force_swap_write_before_repoint`'s `?`/`bail!` at the call site is
    // what enforces "no repoint"; this asserts the DECISION half of that
    // contract (see `swap.rs`'s `Err(msg) => anyhow::bail!(...)` site).
    #[test]
    fn decide_swap_disposition_unreadable_is_err_either_kind() {
        assert!(decide_swap_disposition(Ok(ForcedSyncResult::Unreadable(
            UnreadableKind::Inaccessible
        )))
        .is_err());
        assert!(decide_swap_disposition(Ok(ForcedSyncResult::Unreadable(
            UnreadableKind::Transient
        )))
        .is_err());
    }

    // F8/KC4-10 — swap: an absent-write-failure proceeds (F4) instead of
    // refusing, unlike a generic write failure over known content.
    #[test]
    fn decide_swap_disposition_absent_write_failed_proceeds() {
        assert_eq!(
            decide_swap_disposition(Ok(ForcedSyncResult::AbsentWriteFailed)),
            Ok(ForcedSyncResult::AbsentWriteFailed)
        );
    }

    // F8/KC4-10 — swap: a lock TimedOut/Failed outcome is modelled by the
    // caller's own bounded-lock match (in `swap.rs`/`auto_rotate.rs`), which
    // never calls `force_swap_write_before_repoint` at all in that case —
    // asserted here via the documented contract rather than re-driving the
    // lock primitive (already covered by `BoundedLockOutcome`'s own tests).
    #[test]
    fn decide_swap_disposition_generic_err_refuses() {
        let result = Err(PlatformError::Keychain("scripted add failure".to_string()));
        assert!(decide_swap_disposition(result).is_err());
    }

    // v5 — `reconcile_outcome_operator_line`: the marker is the source of
    // truth, never a repoint's own Ok/Err. `MarkerUnreadable` fails closed
    // with a fixed "unknown state" line; `AlreadyCurrent`/`Reconciled` are
    // reported identically (both mean "X now agrees with the marker") and
    // differ only on whether `marker_account` equals the account the switch
    // STARTED from; `WriteFailed` always names the concrete repair command.
    fn acct(n: u16) -> AccountNum {
        AccountNum::try_from(n).unwrap()
    }

    #[test]
    fn reconcile_outcome_line_marker_unreadable_is_unknown_state() {
        let msg =
            reconcile_outcome_operator_line(&ReconcileOutcome::MarkerUnreadable, Some(acct(1)));
        assert!(
            msg.contains("terminal state unknown"),
            "must name the unknown-state case: {msg}"
        );
        assert!(msg.contains("csq swap"), "must name the fix: {msg}");
    }

    #[test]
    fn reconcile_outcome_line_already_current_at_original_says_not_switched() {
        let outcome = ReconcileOutcome::AlreadyCurrent {
            marker_account: acct(2),
        };
        let msg = reconcile_outcome_operator_line(&outcome, Some(acct(2)));
        assert_eq!(msg, "not switched — terminal and keychain both on 2");
    }

    #[test]
    fn reconcile_outcome_line_reconciled_at_original_says_not_switched() {
        // Reconciled means X DID need a write, but the marker still landed
        // back on the account the switch started from (e.g. a repoint
        // failure whose own rollback restored the marker) — the operator
        // sees the same "not switched" outcome either way; only the
        // internal WriteFailed/Reconciled/AlreadyCurrent distinction cares
        // whether a write happened.
        let outcome = ReconcileOutcome::Reconciled {
            marker_account: acct(2),
        };
        let msg = reconcile_outcome_operator_line(&outcome, Some(acct(2)));
        assert_eq!(msg, "not switched — terminal and keychain both on 2");
    }

    #[test]
    fn reconcile_outcome_line_marker_moved_says_switched() {
        let outcome = ReconcileOutcome::Reconciled {
            marker_account: acct(3),
        };
        let msg = reconcile_outcome_operator_line(&outcome, Some(acct(2)));
        assert_eq!(msg, "switched to 3");
    }

    #[test]
    fn reconcile_outcome_line_write_failed_names_repair_command() {
        let outcome = ReconcileOutcome::WriteFailed {
            marker_account: acct(2),
        };
        let msg = reconcile_outcome_operator_line(&outcome, Some(acct(2)));
        assert_eq!(
            msg,
            "terminal on 2, keychain could not be updated — run `csq swap 2` in that terminal"
        );
        // Also correct when the marker landed on a DIFFERENT account than
        // the switch started from — the template names whatever the marker
        // says NOW, never the pre-switch account.
        let outcome_target = ReconcileOutcome::WriteFailed {
            marker_account: acct(3),
        };
        let msg_target = reconcile_outcome_operator_line(&outcome_target, Some(acct(2)));
        assert_eq!(
            msg_target,
            "terminal on 3, keychain could not be updated — run `csq swap 3` in that terminal"
        );
    }

    // K3: the S7 pre-flight refusal's dedicated message — names the
    // blocked item AND folds in the reconcile outcome (D-F2), since the
    // v4 forced write into the keychain already ran before this refusal
    // fires, even though no symlink was touched.
    #[test]
    fn repoint_refused_real_file_operator_line_names_item_and_reconcile_outcome() {
        let reconcile_line = reconcile_outcome_operator_line(
            &ReconcileOutcome::AlreadyCurrent {
                marker_account: acct(2),
            },
            Some(acct(2)),
        );
        let msg = repoint_refused_real_file_operator_line(".current-account", &reconcile_line);
        assert!(
            msg.contains(".current-account"),
            "must name the blocked item: {msg}"
        );
        assert!(
            msg.contains("not switched — terminal and keychain both on 2"),
            "must fold in the reconcile outcome (D-F2): {msg}"
        );
    }

    // T6 — the whole branch still passes the existing K1-K6 tests that
    // remain meaningful: asserted by this module's full `cargo test`
    // pass (195+ tests, see the session's verification table) rather than
    // duplicated here.

    // ── v5 reconcile-to-links tests ────────────────────────────────────

    /// Builds a `coexisting_fixture(1)` with `identities/<uuid>/credentials.json`
    /// carrying a distinguishable, far-future-expiry token, and a handle dir
    /// whose `.csq-account` marker names that same slot's UUID. Returns
    /// `(fixture, handle_dir, expiry_ms)`.
    ///
    /// macOS-only: drives `reconcile_keychain_to_marker_with_executor`, which
    /// (like `RecordingExecutor`) exists only under `#[cfg(target_os =
    /// "macos")]` — X is a macOS keychain item and has no cross-platform
    /// equivalent to fixture against.
    #[cfg(target_os = "macos")]
    fn reconcile_fixture() -> (tempfile::TempDir, std::path::PathBuf, u64) {
        let fixture = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = fixture.path();
        let slot = crate::types::AccountNum::try_from(1u16).unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);

        let far_future = now_ms() + 365 * 24 * 60 * 60 * 1000;
        let identity_creds_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        // guard-reader-writer-parity.md MUST-4: a real Anthropic credential
        // ALWAYS carries both `accessToken` AND `refreshToken` — `oauth_identity`
        // requires both to classify a token's IDENTITY, so a fixture missing
        // `refreshToken` would make every identity comparison against this
        // file vacuously `None`, silently disabling rules 3/4 for every test
        // built on this fixture.
        std::fs::write(
            &identity_creds_path,
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":{far_future}}}}}"#
            ),
        )
        .expect("write identity credentials");

        let handle_dir = base.join("term-reconcile-fixture");
        std::fs::create_dir_all(&handle_dir).unwrap();
        crate::accounts::markers::write_csq_account(&handle_dir, uuid)
            .expect("write .csq-account marker");

        let _ = slot; // resolved via profiles.json by_slot, not needed directly here
        (fixture, handle_dir, far_future)
    }

    /// PRIMARY DIRECTIVE rule 4 (superseding the pre-directive version of
    /// this test, which passed `None` for `forced_write` and expected an
    /// overwrite based on the OTHER account's token merely having an OLDER
    /// expiry than the marker's own file — exactly the "expiry is not
    /// identity" bug the directive exists to remove): keychain holds a
    /// token THIS call itself force-wrote for a DIFFERENT account (account
    /// 2) at a LATER expiry than the marker account's (1) own canonical
    /// file — modelling a swap that force-wrote account 2's token, then a
    /// concurrent `csq swap` moved the marker back to 1 before the repoint
    /// settled. Reconcile must OVERWRITE with the marker account's OWN
    /// token, DESPITE the foreign token's later expiry — identity, not
    /// expiry, is what authorizes the overwrite.
    ///
    /// RED proof (quoted in the PR/journal): with the identity comparison
    /// replaced by the pre-directive `keychain_is_fresher_or_equal_or_unknown`
    /// expiry check, this test fails with:
    ///   assertion `left == right` failed
    ///     left: AlreadyCurrent { marker_account: AccountNum(1) }
    ///    right: Reconciled { marker_account: AccountNum(1) }
    /// — the foreign token's LATER expiry reads as "already current" under
    /// the old expiry-only guard, exactly the corruption class this
    /// directive removes.
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_overwrites_foreign_token_with_later_expiry_when_it_matches_forced_write() {
        let (fixture, handle_dir, far_future) = reconcile_fixture();
        let base = fixture.path();

        // The token THIS call force-wrote for account 2 — a LATER expiry
        // than the marker (account 1)'s own far_future canonical token.
        let later_than_marker_file = far_future + 60_000;
        let written_for_account_2 = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"ACCT-2-TOKEN","refreshToken":"ACCT-2-REFRESH","expiresAt":{later_than_marker_file}}}}}"#
        );

        // Keychain currently holds EXACTLY that token (by identity) —
        // modelling the force-write having landed, followed by a
        // concurrent swap moving the marker back to account 1 before this
        // repoint's own failure triggered reconcile.
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            written_for_account_2.clone(),
        ));

        let forced_write = Some(ForcedWriteAttempt {
            account: crate::types::AccountNum::try_from(2u16).unwrap(),
            raw_json: Some(written_for_account_2.as_str()),
        });
        let outcome =
            reconcile_keychain_to_marker_with_executor(&exec, base, &handle_dir, forced_write);
        assert_eq!(
            outcome,
            ReconcileOutcome::Reconciled {
                marker_account: crate::types::AccountNum::try_from(1u16).unwrap()
            }
        );
        let payload = exec
            .last_add_payload()
            .expect("reconcile must have written X");
        assert!(
            payload.contains("MARKER-ACCOUNT-TOKEN"),
            "must write the marker account's OWN token, got: {payload}"
        );
    }

    /// D-F3 / directive rule 1: X holds real JSON content, but it has NO
    /// `claudeAiOauth` key at all (e.g. a mirror of another service's
    /// sibling item, or a plain `{}`) — this holds no login, so it is free
    /// to write, exactly like a confirmed-absent X. Must NOT be classified
    /// as `ForeignLogin`/unclassifiable.
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_writes_over_content_with_no_claude_ai_oauth_key() {
        let (fixture, handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();

        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            r#"{"otherService":{"someKey":"someValue"}}"#.to_string(),
        ));
        let outcome = reconcile_keychain_to_marker_with_executor(&exec, base, &handle_dir, None);
        assert_eq!(
            outcome,
            ReconcileOutcome::Reconciled {
                marker_account: crate::types::AccountNum::try_from(1u16).unwrap()
            },
            "content with no claudeAiOauth key holds no login and must be written over, not treated as ForeignLogin"
        );
        let payload = exec
            .last_add_payload()
            .expect("reconcile must have written X");
        assert!(
            payload.contains("MARKER-ACCOUNT-TOKEN"),
            "must write the marker account's OWN token, got: {payload}"
        );
    }

    /// PRIMARY DIRECTIVE rule 3 (proper): keychain holds BYTE-IDENTICAL
    /// content to the marker account's own canonical file (e.g. reconcile
    /// ran twice back to back, or nothing ever desynced) -> AlreadyCurrent,
    /// no mutation. This is the genuine identity match — distinct from the
    /// superseded test below, which used to accept a MERELY-NEWER expiry as
    /// proof of "already current" without ever checking whose token it was.
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_reports_already_current_when_keychain_matches_marker_token_by_identity() {
        let (fixture, handle_dir, far_future) = reconcile_fixture();
        let base = fixture.path();

        let identical_to_marker_file = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":{far_future}}}}}"#
        );
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            identical_to_marker_file,
        ));

        let outcome = reconcile_keychain_to_marker_with_executor(&exec, base, &handle_dir, None);
        assert_eq!(
            outcome,
            ReconcileOutcome::AlreadyCurrent {
                marker_account: crate::types::AccountNum::try_from(1u16).unwrap()
            }
        );
        assert!(
            exec.calls()
                .iter()
                .all(|(verb, ..)| *verb != "add" && *verb != "delete"),
            "must not mutate X when it already matches the marker account's own token by identity"
        );
    }

    /// PRIMARY DIRECTIVE rule 6/7 (superseding the pre-directive version of
    /// this test, which treated a MERELY-NEWER expiry as sufficient proof
    /// of "already current" — exactly the bug this directive removes: a
    /// keychain token that does not match the marker's own canonical file
    /// BY IDENTITY, and that this call did not itself force-write, is a
    /// login csq cannot classify (it may be a CC self-refresh — the token
    /// bytes ROTATE on every refresh, so a self-refreshed token can NEVER
    /// byte-match the stale on-disk copy). Reconcile must report
    /// `KeychainUnknown` (never silently `AlreadyCurrent`, and never
    /// overwrite) rather than guessing from the expiry alone.
    ///
    /// RED proof (quoted in the PR/journal): under the pre-directive
    /// `keychain_is_fresher_or_equal_or_unknown` expiry check, this
    /// scenario (a later, unrelated expiry) read as `AlreadyCurrent` — the
    /// exact "both on" line this test now asserts must NEVER be produced
    /// for an unclassified foreign token.
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_reports_keychain_unknown_never_already_current_for_unclassified_later_expiry() {
        let (fixture, handle_dir, far_future) = reconcile_fixture();
        let base = fixture.path();

        let newer_than_file = far_future + 60_000;
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(format!(
            r#"{{"claudeAiOauth":{{"accessToken":"SELF-REFRESHED-TOKEN","refreshToken":"SELF-REFRESHED-REFRESH","expiresAt":{newer_than_file}}}}}"#
        )));

        let outcome = reconcile_keychain_to_marker_with_executor(&exec, base, &handle_dir, None);
        assert_eq!(
            outcome,
            ReconcileOutcome::KeychainUnknown {
                marker_account: crate::types::AccountNum::try_from(1u16).unwrap(),
                reason: KeychainUnknownReason::ForeignLogin,
            }
        );
        assert!(
            exec.calls()
                .iter()
                .all(|(verb, ..)| *verb != "add" && *verb != "delete"),
            "must not mutate X for an unclassified token, regardless of its expiry"
        );
        let line = reconcile_outcome_operator_line(
            &outcome,
            Some(crate::types::AccountNum::try_from(1u16).unwrap()),
        );
        assert!(
            !line.contains("both on"),
            "an unclassified foreign token must NEVER be reported as 'both on' \
             (a claim reconcile cannot actually back): {line}"
        );
    }

    /// `keychain-fix-r8.md` C-F7 (reconcile half): the marker account's OWN
    /// canonical token is untrusted (expired), AND X holds EXACTLY the token
    /// THIS call itself force-wrote for a DIFFERENT account (2). That token
    /// is already recorded, safely, in account 2's own canonical store, so
    /// stripping X here loses nothing — leaving it in place instead would
    /// strand the terminal silently reading account 2's token while csq
    /// reports only "marker account (1) untrusted".
    ///
    /// RED proof (pre-fix code): this scenario returned
    /// `KeychainUnknown { reason: MarkerTokenUntrusted }` with ZERO mutation
    /// — X was left holding `ACCT-2-TOKEN` indefinitely. Quoted failure
    /// against that code:
    ///   assertion `left == right` failed
    ///     left: KeychainUnknown { marker_account: AccountNum(1), reason: MarkerTokenUntrusted }
    ///    right: Reconciled { marker_account: AccountNum(1) }
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_strips_csq_written_token_when_marker_account_untrusted() {
        let fixture = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = fixture.path();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);

        // Marker account (1)'s OWN canonical file is EXPIRED — untrustworthy.
        let identity_creds_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        let expired = now_ms().saturating_sub(60_000);
        std::fs::write(
            &identity_creds_path,
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":{expired}}}}}"#
            ),
        )
        .expect("write identity credentials");

        let handle_dir = base.join("term-reconcile-untrusted-marker");
        std::fs::create_dir_all(&handle_dir).unwrap();
        crate::accounts::markers::write_csq_account(&handle_dir, uuid)
            .expect("write .csq-account marker");

        // X holds EXACTLY the token this call itself force-wrote for account 2.
        let far_future = now_ms() + 365 * 24 * 60 * 60 * 1000;
        let written_for_account_2 = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"ACCT-2-TOKEN","refreshToken":"ACCT-2-REFRESH","expiresAt":{far_future}}}}}"#
        );
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            written_for_account_2.clone(),
        ));
        let forced_write = Some(ForcedWriteAttempt {
            account: crate::types::AccountNum::try_from(2u16).unwrap(),
            raw_json: Some(written_for_account_2.as_str()),
        });

        let outcome =
            reconcile_keychain_to_marker_with_executor(&exec, base, &handle_dir, forced_write);
        assert_eq!(
            outcome,
            ReconcileOutcome::Reconciled {
                marker_account: crate::types::AccountNum::try_from(1u16).unwrap()
            },
            "a csq_written token must be STRIPPED, not left as MarkerTokenUntrusted"
        );
        let calls = exec.calls();
        assert!(
            calls.iter().any(|(v, ..)| *v == "delete"),
            "the wrong-account token has no siblings, so the strip must delete X, got {calls:?}"
        );
        assert!(
            calls.iter().all(|(v, ..)| *v != "add"),
            "no siblings to preserve — must never re-add a rewritten payload, got {calls:?}"
        );
    }

    /// The marker account's own token is untrusted and X is an emptied
    /// login: nothing safe can replace it, and the terminal is logged out,
    /// so reconcile must report it, not call the terminal current.
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_reports_emptied_login_when_marker_account_untrusted() {
        let fixture = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = fixture.path();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let identity_creds_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        let expired = now_ms().saturating_sub(60_000);
        std::fs::write(
            &identity_creds_path,
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":{expired}}}}}"#
            ),
        )
        .expect("write identity credentials");
        let handle_dir = base.join("term-reconcile-emptied");
        std::fs::create_dir_all(&handle_dir).unwrap();
        crate::accounts::markers::write_csq_account(&handle_dir, uuid)
            .expect("write .csq-account marker");
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"","refreshToken":"","expiresAt":0}}"#.to_string(),
        ));
        let outcome = reconcile_keychain_to_marker_with_executor(&exec, base, &handle_dir, None);
        assert!(
            !matches!(outcome, ReconcileOutcome::AlreadyCurrent { .. }),
            "an emptied login must not read as current: {outcome:?}"
        );
        assert!(
            exec.calls().iter().all(|(v, ..)| *v == "find"),
            "no mutation without a trusted token: {:?}",
            exec.calls()
        );
    }

    // ── decide_and_clear_dead_handle (keychain-fix-r8.md C-F3) ────────────────

    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_dead_handle_deletes_known_token() {
        // X holds EXACTLY the marker account's own canonical token —
        // known, safe to delete, no adopt attempt needed.
        let (fixture, handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":4102444800000}}"#.to_string(),
        ));
        let result =
            decide_and_clear_dead_handle_with_executor(&exec, base, &handle_dir, &|_, _| {
                panic!("try_adopt must not be called for a KNOWN token")
            });
        assert_eq!(result, Ok(true), "a known token must be deleted");
        assert!(
            exec.calls().iter().any(|(v, ..)| *v == "delete"),
            "must actually delete X, got {:?}",
            exec.calls()
        );
    }

    /// RED proof (quoted in the commit): before this function existed, the
    /// production wiring was `keychain::clear_handle_dir_reporting`, which
    /// deletes X unconditionally with no decide/harvest step at all — an
    /// unmatched-but-valid foreign login would have been destroyed here.
    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_dead_handle_adopts_then_deletes_unmatched_valid_token() {
        let (fixture, handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        // A token that matches NEITHER the marker's canonical file NOR its
        // history — an unmatched but structurally valid Anthropic login.
        let unmatched = r#"{"claudeAiOauth":{"accessToken":"UNMATCHED-TOKEN","refreshToken":"UNMATCHED-REFRESH","expiresAt":4102444800000}}"#;
        let exec =
            RecordingExecutor::scripted(RawContentClassification::Content(unmatched.to_string()));
        let adopt_calls = std::cell::Cell::new(0);
        let result =
            decide_and_clear_dead_handle_with_executor(&exec, base, &handle_dir, &|acct, cand| {
                adopt_calls.set(adopt_calls.get() + 1);
                assert_eq!(acct, crate::types::AccountNum::try_from(1u16).unwrap());
                assert!(cand.raw_json.contains("UNMATCHED-TOKEN"));
                true // simulate a confirmed adopt
            });
        assert_eq!(
            result,
            Ok(true),
            "an adopted candidate must then be deleted, X now matches itself"
        );
        assert_eq!(
            adopt_calls.get(),
            1,
            "try_adopt must be called exactly once"
        );
        assert!(exec.calls().iter().any(|(v, ..)| *v == "delete"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_dead_handle_queues_unconfirmed_candidate_for_retry() {
        // `keychain-fix-r9.md` S-M-2/D-F4: NOW `Err`, not `Ok(false)` — the
        // retry queue is origin-aware (`PendingClearOrigin`), so queuing an
        // unconfirmed dead-handle candidate no longer risks a blind delete
        // on the next tick.
        let (fixture, handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let unmatched = r#"{"claudeAiOauth":{"accessToken":"UNMATCHED-TOKEN","refreshToken":"UNMATCHED-REFRESH","expiresAt":4102444800000}}"#;
        let exec =
            RecordingExecutor::scripted(RawContentClassification::Content(unmatched.to_string()));
        let result =
            decide_and_clear_dead_handle_with_executor(&exec, base, &handle_dir, &|_, _| false);
        assert_eq!(
            result,
            Err(KeychainClearUnconfirmed),
            "an unconfirmed candidate must be KEPT and QUEUED for a decide+adopt \
             retry, never a blind delete: {result:?}"
        );
        assert!(
            exec.calls()
                .iter()
                .all(|(v, ..)| *v != "delete" && *v != "add"),
            "must not mutate X when adoption is not confirmed, got {:?}",
            exec.calls()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_dead_handle_keeps_unclassifiable_x() {
        let (fixture, handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let exec = RecordingExecutor::scripted(RawContentClassification::Unreadable(
            UnreadableKind::Transient,
        ));
        let result =
            decide_and_clear_dead_handle_with_executor(&exec, base, &handle_dir, &|_, _| {
                panic!("try_adopt must not be called for an unclassifiable X")
            });
        assert_eq!(result, Err(KeychainClearUnconfirmed));
        assert!(exec
            .calls()
            .iter()
            .all(|(v, ..)| *v != "delete" && *v != "add"));
    }

    // ── apply_dead_handle_strip duplicate drain (keychain-fix-r9.md D-F5) ──
    // The dead-handle reaper and the pending-clear retry queue both route
    // their decide-gated strip through `apply_dead_handle_strip`. The N1
    // regression (security review 1386: `security delete-generic-password`
    // removes exactly ONE matching item per call) applies here exactly as
    // it does to the legacy `drain_service_inner` path — these pin that
    // this decide-gated path drains duplicates too, scoped to the SAME
    // svc+account throughout, never a blind by-service-only match.

    #[cfg(target_os = "macos")]
    #[test]
    fn apply_dead_handle_strip_drains_duplicate_item_under_same_service() {
        let unmatched = r#"{"claudeAiOauth":{"accessToken":"UNMATCHED-TOKEN","refreshToken":"UNMATCHED-REFRESH","expiresAt":4102444800000}}"#;
        let x = RawContentClassification::Content(unmatched.to_string());
        // Two never-consolidated items resident under this one service — a
        // single delete call only removes ONE of them.
        let exec = RecordingExecutor::scripted(x.clone()).with_duplicate_items(2);
        let result = apply_dead_handle_strip(&exec, "svc-x", "acct-x", &x);
        assert_eq!(result, Ok(true));
        let calls = exec.calls();
        let delete_count = calls.iter().filter(|(v, ..)| *v == "delete").count();
        assert_eq!(
            delete_count, 2,
            "must delete BOTH duplicate items, not stop after the first \
             confirmed delete, got {calls:?}"
        );
        assert!(
            calls
                .iter()
                .all(|(_, svc, acct)| svc == "svc-x" && acct == "acct-x"),
            "every drain call must stay scoped to the SAME svc+account, \
             never a bare by-service-only match: {calls:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apply_dead_handle_strip_stops_at_first_confirmed_absent() {
        // Default RecordingExecutor models exactly ONE resident item — the
        // steady-state case with no duplicate: the drain's first re-`find`
        // must observe `Absent` and stop, costing exactly one extra call.
        let known = r#"{"claudeAiOauth":{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":4102444800000}}"#;
        let x = RawContentClassification::Content(known.to_string());
        let exec = RecordingExecutor::scripted(x.clone());
        let result = apply_dead_handle_strip(&exec, "svc-x", "acct-x", &x);
        assert_eq!(result, Ok(true));
        let calls = exec.calls();
        assert_eq!(
            calls.iter().filter(|(v, ..)| *v == "delete").count(),
            1,
            "no duplicate resident -> exactly one delete, got {calls:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apply_dead_handle_strip_never_drains_when_siblings_preserved() {
        // A sibling-preserving strip writes a REMAINDER back to this exact
        // svc+account (`Applied{wrote_token:false}` via `add`, not
        // `delete`) — the drain must never re-find/re-delete that.
        let with_sibling =
            r#"{"claudeAiOauth":{"accessToken":"a","refreshToken":"rt"},"mcp":"keep"}"#;
        let x = RawContentClassification::Content(with_sibling.to_string());
        let exec = RecordingExecutor::scripted(x.clone()).with_duplicate_items(2);
        let result = apply_dead_handle_strip(&exec, "svc-x", "acct-x", &x);
        assert_eq!(result, Ok(true));
        let calls = exec.calls();
        assert_eq!(
            calls.len(),
            1,
            "sibling-preserving strip must never re-find/re-delete: {calls:?}"
        );
        assert_eq!(calls[0].0, "add");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn apply_dead_handle_strip_drain_bounded_and_unconfirmed_on_budget_exhaustion() {
        // An adversarial/pathological service that never reaches confirmed-
        // absent must not loop forever — bounded, and reports the ORIGINAL
        // clear as `Ok(true)` (the first item WAS confirmed gone) while the
        // caller cannot claim the drain is fully clean is not observable
        // from this function's own `bool` return — the drain's exhaustion
        // is reported via `Err`, taking priority over the already-applied
        // first strip.
        let unmatched = r#"{"claudeAiOauth":{"accessToken":"UNMATCHED-TOKEN","refreshToken":"UNMATCHED-REFRESH","expiresAt":4102444800000}}"#;
        let x = RawContentClassification::Content(unmatched.to_string());
        // More duplicates than the iteration budget can drain.
        let exec = RecordingExecutor::scripted(x.clone())
            .with_duplicate_items(MAX_DUPLICATE_DELETE_ITERATIONS + 10);
        let result = apply_dead_handle_strip(&exec, "svc-x", "acct-x", &x);
        assert_eq!(
            result,
            Err(KeychainClearUnconfirmed),
            "budget exhaustion must report unconfirmed, never silent success"
        );
        let delete_count = exec.calls().iter().filter(|(v, ..)| *v == "delete").count();
        assert_eq!(
            delete_count,
            1 + MAX_DUPLICATE_DELETE_ITERATIONS as usize,
            "1 from the initial apply + the bounded drain loop's own budget"
        );
    }

    // ── decide_and_clear_queued_service (keychain-fix-r8d.md item 1) ──────

    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_queued_service_deletes_known_token() {
        // X holds EXACTLY the marker account's own canonical token — known,
        // safe to delete, no adopt attempt needed.
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":4102444800000}}"#.to_string(),
        ));
        let result = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            "svc-irrelevant-to-decide",
            Some(acct),
            None,
            None,
            &|_, _| panic!("try_adopt must not be called for a KNOWN token"),
        );
        assert_eq!(result, Ok(true), "a known token must be deleted");
        assert!(
            exec.calls().iter().any(|(v, ..)| *v == "delete"),
            "must actually delete X, got {:?}",
            exec.calls()
        );
    }

    /// RED proof (quoted in the commit): before `account` was threaded
    /// through the queue and this decide-based retry existed, the retry
    /// path was `clear_service_reporting` -> `drain_service` — an
    /// unconditional delete-by-service-name with no known-token gate at
    /// all. Mutating the account-required-adopt path to skip straight to
    /// delete (i.e. `WriteDecision::RefuseUnharvested => apply_dead_handle_
    /// strip(...)` without ever calling `try_adopt`) reproduces exactly
    /// that bug and this test catches it: `try_adopt must be called
    /// exactly once` fails with `left: 0, right: 1`.
    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_queued_service_adopts_then_deletes_unmatched_valid_token() {
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        // A token that matches NEITHER the marker's canonical file NOR its
        // history — an unmatched but structurally valid Anthropic login.
        let unmatched = r#"{"claudeAiOauth":{"accessToken":"UNMATCHED-TOKEN","refreshToken":"UNMATCHED-REFRESH","expiresAt":4102444800000}}"#;
        let exec =
            RecordingExecutor::scripted(RawContentClassification::Content(unmatched.to_string()));
        let adopt_calls = std::cell::Cell::new(0);
        let result = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            "svc-irrelevant-to-decide",
            Some(acct),
            None,
            None,
            &|got_acct, cand| {
                adopt_calls.set(adopt_calls.get() + 1);
                assert_eq!(got_acct, acct);
                assert!(cand.raw_json.contains("UNMATCHED-TOKEN"));
                assert!(
                    cand.candidate_email.is_none(),
                    "candidate_email was None on this call — must stay None, never fabricated"
                );
                true // simulate a confirmed adopt
            },
        );
        assert_eq!(
            result,
            Ok(true),
            "an adopted candidate must then be deleted, X now matches itself"
        );
        assert_eq!(
            adopt_calls.get(),
            1,
            "try_adopt must be called exactly once"
        );
        assert!(exec.calls().iter().any(|(v, ..)| *v == "delete"));
    }

    /// An unidentified Anthropic login with a sibling (`mcpOAuth`).
    #[cfg(target_os = "macos")]
    const UNMATCHED_RAW: &str = r#"{"claudeAiOauth":{"accessToken":"UNMATCHED-TOKEN","refreshToken":"UNMATCHED-REFRESH","expiresAt":4102444800000},"mcpOAuth":{"k":"v"}}"#;

    /// Unidentified item, dead handle dir: saved byte-for-byte to the
    /// quarantine folder, then the WHOLE item is deleted (no sibling remainder
    /// is written back) and the entry resolves.
    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_queued_service_quarantines_then_deletes_unconfirmed_candidate() {
        let _trace = quarantine_trace_guard();
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            UNMATCHED_RAW.to_string(),
        ));
        let result = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            "svc-irrelevant-to-decide",
            Some(acct),
            None,
            None,
            &|_, _| false,
        );
        assert_eq!(result, Ok(true));
        let calls = exec.calls();
        assert!(calls.iter().any(|(v, ..)| *v == "delete"), "{calls:?}");
        assert!(
            calls.iter().all(|(v, ..)| *v != "add"),
            "no remainder add: {calls:?}"
        );
        let saved: Vec<String> = std::fs::read_dir(base.join(QUARANTINE_DIR_NAME))
            .unwrap()
            .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
            .collect();
        assert_eq!(saved, vec![UNMATCHED_RAW.to_string()]);
    }

    /// Taken by every test that reaches a quarantine `warn!` without
    /// capturing it. A test hitting a callsite for the first time with no
    /// subscriber installed can cache it as disabled while a capturing test
    /// is installing its subscriber, and the capture then sees nothing.
    #[cfg(target_os = "macos")]
    fn quarantine_trace_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::testing::TRACING_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// `(error_kind, svc_hash)` of every event emitted while `run` executes.
    #[cfg(target_os = "macos")]
    fn capture_quarantine_events<T>(run: impl FnOnce() -> T) -> (T, Vec<(String, String)>) {
        use std::sync::{Arc, Mutex};
        struct Fields(Option<String>, Option<String>);
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                match f.name() {
                    "error_kind" => self.0 = Some(v.to_string()),
                    "svc_hash" => self.1 = Some(v.to_string()),
                    _ => {}
                }
            }
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.record_str(f, format!("{v:?}").trim_matches('"'));
            }
        }
        struct Capture(Arc<Mutex<Vec<(String, String)>>>);
        impl tracing::Subscriber for Capture {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
            fn event(&self, event: &tracing::Event<'_>) {
                let mut f = Fields(None, None);
                event.record(&mut f);
                if let Some(kind) = f.0 {
                    self.0.lock().unwrap().push((kind, f.1.unwrap_or_default()));
                }
            }
        }
        let _guard = quarantine_trace_guard();
        let events = Arc::new(Mutex::new(Vec::new()));
        // A sibling test hitting the same `warn!` with no subscriber installed
        // can register the callsite as "never interested" concurrently with
        // this capture; rebuild the cache once the capture is in place so the
        // callsite is re-evaluated against it.
        let result = tracing::subscriber::with_default(Capture(Arc::clone(&events)), || {
            tracing::callsite::rebuild_interest_cache();
            run()
        });
        let captured = events.lock().unwrap().clone();
        (result, captured)
    }

    /// The hash suffix of the single quarantined file under `base`.
    #[cfg(target_os = "macos")]
    fn only_quarantine_file_hash(base: &Path) -> String {
        let names: Vec<String> = std::fs::read_dir(base.join(QUARANTINE_DIR_NAME))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        names[0]
            .trim_end_matches(".json")
            .rsplit('-')
            .next()
            .unwrap()
            .to_string()
    }

    /// The fresh-launch quarantine event names the saved file's hash, so the
    /// file can be matched to the launch that wrote it.
    #[cfg(target_os = "macos")]
    #[test]
    fn fresh_launch_quarantine_event_names_the_saved_file() {
        let rec =
            RecordingExecutor::scripted(RawContentClassification::Content(FOREIGN_RAW.to_string()));
        let dir = tempfile::tempdir().unwrap();
        let (result, events) = capture_quarantine_events(|| {
            force_sync_inner(&rec, dir.path(), dir.path(), Some(VALID_NEW_JSON), true)
        });
        assert!(
            matches!(result, Ok(ForcedSyncResult::Applied { wrote_token: true })),
            "{result:?}"
        );
        let hash = only_quarantine_file_hash(dir.path());
        assert!(
            events.contains(&(
                "keychain_fresh_launch_quarantined_foreign_item".to_string(),
                hash.clone()
            )),
            "expected the event to carry svc_hash={hash}: {events:?}"
        );
    }

    /// The pending-clear quarantine event names the saved file's hash.
    #[cfg(target_os = "macos")]
    #[test]
    fn pending_clear_quarantine_event_names_the_saved_file() {
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            UNMATCHED_RAW.to_string(),
        ));
        let (result, events) = capture_quarantine_events(|| {
            decide_and_clear_queued_service_with_executor(
                &exec,
                base,
                "Claude Code-credentials-deadbeef",
                Some(acct),
                None,
                None,
                &|_, _| false,
            )
        });
        assert_eq!(result, Ok(true));
        let hash = only_quarantine_file_hash(base);
        assert_eq!(hash, "deadbeef", "suffix of the service name");
        assert!(
            events.contains(&(
                "keychain_pending_clear_quarantined_foreign_item".to_string(),
                hash.clone()
            )),
            "expected the event to carry svc_hash={hash}: {events:?}"
        );
    }

    /// The handle dir that owns the service appears between the first
    /// ownership check and the delete: the item is kept, the entry stays
    /// queued, and the event says so. Deterministic: the service is the one
    /// the quarantine dir itself would own, so the save creates the dir the
    /// re-check then finds.
    #[cfg(target_os = "macos")]
    #[test]
    fn pending_clear_dir_reappearing_before_delete_keeps_item_and_logs() {
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let svc = service_name(
            &std::fs::canonicalize(base)
                .unwrap()
                .join(QUARANTINE_DIR_NAME),
        );
        assert!(!base.join(QUARANTINE_DIR_NAME).exists());
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            UNMATCHED_RAW.to_string(),
        ));
        let (result, events) = capture_quarantine_events(|| {
            decide_and_clear_queued_service_with_executor(
                &exec,
                base,
                &svc,
                Some(acct),
                None,
                None,
                &|_, _| false,
            )
        });
        assert_eq!(result, Err(KeychainClearUnconfirmed));
        let calls = exec.calls();
        assert!(calls.iter().all(|(v, ..)| *v != "delete"), "{calls:?}");
        let hash = only_quarantine_file_hash(base);
        assert!(
            events.contains(&(
                "keychain_pending_clear_quarantined_dir_reappeared".to_string(),
                hash.clone()
            )),
            "expected the reappeared event with svc_hash={hash}: {events:?}"
        );
    }

    /// Quarantine cannot be written: the item and the entry are KEPT.
    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_queued_service_keeps_item_when_quarantine_fails() {
        let _trace = quarantine_trace_guard();
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        std::fs::write(base.join(QUARANTINE_DIR_NAME), b"x").unwrap();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            UNMATCHED_RAW.to_string(),
        ));
        let result = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            "svc-irrelevant-to-decide",
            Some(acct),
            None,
            None,
            &|_, _| false,
        );
        assert_eq!(result, Err(KeychainClearUnconfirmed));
        assert!(
            exec.calls()
                .iter()
                .all(|(v, ..)| *v != "delete" && *v != "add"),
            "must not mutate X, got {:?}",
            exec.calls()
        );
    }

    /// A directory that hashes to this service exists again (a recycled PID's
    /// new session): untouched, nothing quarantined, entry kept.
    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_queued_service_leaves_item_when_a_dir_owns_the_service() {
        let _trace = quarantine_trace_guard();
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let live = base.join("term-424242");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join(".live-pid"), std::process::id().to_string()).unwrap();
        let svc = service_name(&canonicalize_for_keychain_sync(&live).0);
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            UNMATCHED_RAW.to_string(),
        ));
        let result = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            &svc,
            Some(acct),
            None,
            None,
            &|_, _| false,
        );
        assert_eq!(result, Err(KeychainClearUnconfirmed));
        assert!(exec
            .calls()
            .iter()
            .all(|(v, ..)| *v != "delete" && *v != "add"));
        assert!(!base.join(QUARANTINE_DIR_NAME).exists());
    }

    /// Quarantine saves, the delete is NOT confirmed: Err (entry kept) and the
    /// saved copy remains.
    #[cfg(target_os = "macos")]
    #[test]
    fn pending_clear_quarantined_but_delete_unconfirmed_keeps_entry() {
        let _trace = quarantine_trace_guard();
        let (fixture, _h, _f) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            UNMATCHED_RAW.to_string(),
        ));
        exec.delete_ok.set(false);
        let result = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            "svc-irrelevant-to-decide",
            Some(acct),
            None,
            None,
            &|_, _| false,
        );
        assert_eq!(result, Err(KeychainClearUnconfirmed));
        assert_eq!(
            std::fs::read_dir(base.join(QUARANTINE_DIR_NAME))
                .unwrap()
                .count(),
            1
        );
    }

    /// A dir whose real path cannot be resolved counts as present; an
    /// unreadable base counts as present too.
    #[cfg(target_os = "macos")]
    #[test]
    fn unresolvable_dir_or_base_counts_as_owning_the_service() {
        let svc = "Claude Code-credentials-00000000";
        assert!(dir_may_own_service(Path::new("/nonexistent/x"), false, svc));
        assert!(!dir_may_own_service(Path::new("/nonexistent/x"), true, svc));
        assert!(handle_dir_exists_for_service(
            Path::new("/nonexistent-base-dir"),
            svc
        ));
    }

    /// Repeated retries of the same unconfirmed item write ONE quarantine
    /// file, so they cannot push other services' files out of retention.
    #[cfg(target_os = "macos")]
    #[test]
    fn repeated_pending_clear_retry_creates_no_duplicate_quarantine_file() {
        let _trace = quarantine_trace_guard();
        let (fixture, _h, _f) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        for _ in 0..3 {
            let exec = RecordingExecutor::scripted(RawContentClassification::Content(
                UNMATCHED_RAW.to_string(),
            ));
            exec.delete_ok.set(false);
            let _ = decide_and_clear_queued_service_with_executor(
                &exec,
                base,
                "svc-irrelevant-to-decide",
                Some(acct),
                None,
                None,
                &|_, _| false,
            );
        }
        assert_eq!(
            std::fs::read_dir(base.join(QUARANTINE_DIR_NAME))
                .unwrap()
                .count(),
            1
        );
    }

    /// The recurring warning is emitted once per key per interval.
    #[cfg(target_os = "macos")]
    #[test]
    fn warn_due_rate_limits_per_key() {
        assert!(warn_due("rate-limit-test-key"));
        assert!(!warn_due("rate-limit-test-key"));
        assert!(warn_due("rate-limit-test-other-key"));
    }

    /// RED proof (quoted in the commit): the fail-closed guard for a
    /// missing/invalid account — mutating `let Some(acct) = account else {
    /// ... return Err(...) };` to instead default to some account (e.g.
    /// `account.unwrap_or(AccountNum::try_from(1).unwrap())`) reproduces
    /// exactly the class this item exists to close: a legacy entry with no
    /// recorded provenance would then be decided (and potentially deleted)
    /// against a GUESSED account. This test fails under that mutation with:
    ///   assertion `left == right` failed
    ///     left: Ok(true)
    ///    right: Err(KeychainClearUnconfirmed)
    /// (the guessed account happens to match the fixture's marker token,
    /// so the mutated code deletes X outright rather than refusing).
    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_queued_service_fails_closed_with_no_account() {
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        // Same content as the "known token" case above — if the missing-
        // account guard were bypassed, decide would still find a match
        // and delete. The guard must refuse BEFORE ever reaching decide.
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":4102444800000}}"#.to_string(),
        ));
        let result = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            "svc-irrelevant-to-decide",
            None, // legacy entry queued before keychain-fix-r8d, or invalid on reload
            None,
            None,
            &|_, _| panic!("try_adopt must not be called with no account to adopt for"),
        );
        assert_eq!(
            result,
            Err(KeychainClearUnconfirmed),
            "no account on record must fail closed — kept, never deleted blind"
        );
        assert!(
            exec.calls().is_empty(),
            "must never even call `find` — the guard refuses before any keychain \
             access, got {:?}",
            exec.calls()
        );
    }

    /// `keychain-fix-r9.md` D-F5: with a recorded `keychain_account_hint`,
    /// the retry MUST target that account attribute — an item under a
    /// NON-DEFAULT account attribute (i.e. NOT `keychain_account()`'s live
    /// derivation) is the exact case a bare `keychain_account()` fallback
    /// would miss (`find` under the wrong attribute reports Absent, and the
    /// real item, under the hinted attribute, is never touched).
    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_queued_service_uses_recorded_account_hint_not_live_derivation() {
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let exec = RecordingExecutor::scripted(RawContentClassification::Content(
            r#"{"claudeAiOauth":{"accessToken":"MARKER-ACCOUNT-TOKEN","refreshToken":"MARKER-ACCOUNT-REFRESH","expiresAt":4102444800000}}"#.to_string(),
        ));
        let non_default_hint = "not-the-live-os-username";
        let result = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            "svc-irrelevant-to-decide",
            Some(acct),
            None,
            Some(non_default_hint),
            &|_, _| panic!("try_adopt must not be called for a KNOWN token"),
        );
        assert_eq!(result, Ok(true), "a known token must be deleted");
        assert!(
            exec.calls().iter().any(
                |(verb, _svc, account)| *verb == "find" && account.as_str() == non_default_hint
            ),
            "the recorded hint must be the account attribute `find` is called with, \
             not a live `keychain_account()` derivation: {:?}",
            exec.calls()
        );
        assert!(
            exec.calls()
                .iter()
                .any(|(verb, _svc, account)| *verb == "delete"
                    && account.as_str() == non_default_hint),
            "the recorded hint must ALSO be the account attribute `delete` targets: {:?}",
            exec.calls()
        );
    }

    /// `keychain-fix-r9.md` item 1: the entry's captured `candidate_email`
    /// (recorded at queue time, while the config dir still existed) must
    /// reach the `HarvestCandidate` passed to `try_adopt` — not always
    /// `None`, as it was before dead-handle entries began recording one.
    #[cfg(target_os = "macos")]
    #[test]
    fn decide_and_clear_queued_service_threads_recorded_candidate_email() {
        let (fixture, _handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let acct = crate::types::AccountNum::try_from(1u16).unwrap();
        let unmatched = r#"{"claudeAiOauth":{"accessToken":"UNMATCHED-TOKEN","refreshToken":"UNMATCHED-REFRESH","expiresAt":4102444800000}}"#;
        let exec =
            RecordingExecutor::scripted(RawContentClassification::Content(unmatched.to_string()));
        let seen_email = std::cell::RefCell::new(None);
        let _ = decide_and_clear_queued_service_with_executor(
            &exec,
            base,
            "svc-irrelevant-to-decide",
            Some(acct),
            Some("captured-at-queue-time@example.com"),
            None,
            &|_, cand| {
                *seen_email.borrow_mut() = cand.candidate_email.clone();
                false
            },
        );
        assert_eq!(
            seen_email.into_inner(),
            Some("captured-at-queue-time@example.com".to_string()),
            "the recorded candidate_email must reach the HarvestCandidate"
        );
    }

    // ── clear_queued_entry (keychain-fix-r9.md S-M-1/D-F2): origin dispatch ──

    /// A `Logout`-origin entry MUST route to the unconditional-delete
    /// closure, never the decide+adopt one — `csq logout` already destroyed
    /// this login intentionally; the retry repeats that same disposition.
    #[cfg(target_os = "macos")]
    #[test]
    fn clear_queued_entry_inner_routes_logout_origin_to_unconditional_delete() {
        let mut logout_calls = 0usize;
        let mut dead_handle_calls = 0usize;
        let mut logout_fn = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> {
            logout_calls += 1;
            Ok(true)
        };
        let mut dead_handle_fn =
            |_svc: &str, _account: Option<AccountNum>| -> Result<bool, KeychainClearUnconfirmed> {
                dead_handle_calls += 1;
                Ok(true)
            };
        let result = clear_queued_entry_inner(
            "svc",
            PendingClearOrigin::Logout,
            None,
            false,
            &mut logout_fn,
            &mut dead_handle_fn,
        );
        assert_eq!(result, Ok(true));
        assert_eq!(logout_calls, 1, "Logout origin must reach logout_clear_fn");
        assert_eq!(
            dead_handle_calls, 0,
            "Logout origin must NEVER reach the decide+adopt closure"
        );
    }

    /// `keychain-fix-r11.md` S-LOW-1/D-4b (was the `keychain-fix-r10.md`
    /// S-M-2 "downgrade" test): a `Logout`-origin entry whose service maps
    /// to a GENUINE live collision is KEPT — neither closure runs, and the
    /// result is `Ok(false)` (the same "nothing attempted, stays queued"
    /// signal `sweep_pending_clears_inner` already treats as free). The
    /// retired downgrade-to-decide+adopt ran with this entry's own STALE
    /// recorded account, which was never safe against a genuinely different
    /// live session (`clear_queued_entry`'s doc). RED under a mutation that
    /// drops the `if svc_has_live_handle_dir => Ok(false)` arm (falling
    /// through to the old downgrade shape): `dead_handle_calls` would then
    /// be `1` instead of `0`.
    #[cfg(target_os = "macos")]
    #[test]
    fn clear_queued_entry_inner_keeps_logout_origin_untouched_on_genuine_live_collision() {
        let mut logout_calls = 0usize;
        let mut dead_handle_calls = 0usize;
        let mut logout_fn = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> {
            logout_calls += 1;
            Ok(true)
        };
        let mut dead_handle_fn =
            |_svc: &str, _account: Option<AccountNum>| -> Result<bool, KeychainClearUnconfirmed> {
                dead_handle_calls += 1;
                Ok(true)
            };
        let result = clear_queued_entry_inner(
            "svc",
            PendingClearOrigin::Logout,
            None,
            true, // svc_has_live_handle_dir
            &mut logout_fn,
            &mut dead_handle_fn,
        );
        assert_eq!(
            result,
            Ok(false),
            "a genuine live collision must be reported as a structural no-op, \
             never as an attempted clear"
        );
        assert_eq!(
            logout_calls, 0,
            "a live-collision Logout entry must NEVER reach the unconditional delete"
        );
        assert_eq!(
            dead_handle_calls, 0,
            "a live-collision Logout entry must NEVER reach decide+adopt either — \
             it would act against this entry's own STALE recorded account"
        );
    }

    /// The opposite dispatch: `DeadHandle` origin (including the fail-closed
    /// default for any legacy/unrecognized entry) routes to the decide+adopt
    /// closure, never the unconditional delete.
    #[cfg(target_os = "macos")]
    #[test]
    fn clear_queued_entry_inner_routes_dead_handle_origin_to_decide_and_adopt() {
        let mut logout_calls = 0usize;
        let mut dead_handle_calls = 0usize;
        let mut logout_fn = |_svc: &str| -> Result<bool, KeychainClearUnconfirmed> {
            logout_calls += 1;
            Ok(true)
        };
        let mut dead_handle_fn =
            |_svc: &str, _account: Option<AccountNum>| -> Result<bool, KeychainClearUnconfirmed> {
                dead_handle_calls += 1;
                Ok(true)
            };
        let result = clear_queued_entry_inner(
            "svc",
            PendingClearOrigin::DeadHandle,
            None,
            false,
            &mut logout_fn,
            &mut dead_handle_fn,
        );
        assert_eq!(result, Ok(true));
        assert_eq!(
            logout_calls, 0,
            "DeadHandle origin must NEVER reach the unconditional-delete closure"
        );
        assert_eq!(
            dead_handle_calls, 1,
            "DeadHandle origin must reach dead_handle_clear_fn"
        );
    }

    // ── resolve_pending_clear_at_creation (keychain-fix-r11.md S-MEDIUM-1/D-4) ──

    /// The brief's own worked case: a `Logout`-origin entry whose item holds
    /// account N's own credential — the FRESH session at this reused
    /// service has written nothing yet, so a blind delete is safe (as it is
    /// on logout's own first attempt). Confirmed (`Ok(true)`) -> the queue
    /// entry is REMOVED and the new session's own launch proceeds (this fn
    /// returns `()`, never propagates an error to the caller).
    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_pending_clear_at_creation_deletes_logged_out_token_and_removes_entry() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let account = AccountNum::try_from(1u16).unwrap();
        record_pending_clear(
            base,
            "Claude Code-credentials-deadbeef",
            Some(account),
            PendingClearOrigin::Logout,
            None,
            None,
        );
        let mut dead_handle_calls = 0usize;
        resolve_pending_clear_at_creation_with(
            base,
            "Claude Code-credentials-deadbeef",
            // Simulates the real `clear_service_reporting` confirming the
            // logged-out account's item was deleted.
            &mut |_svc| Ok(true),
            &mut |_svc, _acct, _email, _hint| {
                dead_handle_calls += 1;
                Ok(true)
            },
        );
        assert_eq!(
            dead_handle_calls, 0,
            "a Logout-origin entry must never reach the decide+adopt closure"
        );
        let queue_raw =
            std::fs::read_to_string(base.join("keychain-pending-clears.json")).unwrap_or_default();
        assert!(
            !queue_raw.contains("Claude Code-credentials-deadbeef"),
            "a confirmed clear must remove the entry so it is never retried again: {queue_raw}"
        );
    }

    /// `Ok(false)` (structural no-op, `keychain_mirror_disabled()`) must
    /// leave the entry queued — nothing was actually cleared. RED under a
    /// mutation that folds `Ok(false)` into the removal arm (`Ok(_) =>
    /// remove`, the pre-fix shape): the entry would be dropped even though
    /// the item was never touched.
    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_pending_clear_at_creation_leaves_entry_queued_on_structural_noop() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        record_pending_clear(
            base,
            "Claude Code-credentials-cafebabe",
            None,
            PendingClearOrigin::Logout,
            None,
            None,
        );
        resolve_pending_clear_at_creation_with(
            base,
            "Claude Code-credentials-cafebabe",
            &mut |_svc| Ok(false),
            &mut |_svc, _acct, _email, _hint| Ok(true),
        );
        let queue_raw =
            std::fs::read_to_string(base.join("keychain-pending-clears.json")).unwrap_or_default();
        assert!(
            queue_raw.contains("Claude Code-credentials-cafebabe"),
            "Ok(false) cleared nothing — the entry must survive: {queue_raw}"
        );
    }

    /// An unconfirmed clear (`Err`) must ALSO leave the entry queued, for the
    /// daemon's own [`sweep_pending_clears`] to retry.
    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_pending_clear_at_creation_leaves_entry_queued_on_unconfirmed() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        record_pending_clear(
            base,
            "Claude Code-credentials-facefeed",
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        resolve_pending_clear_at_creation_with(
            base,
            "Claude Code-credentials-facefeed",
            &mut |_svc| Ok(true),
            &mut |_svc, _acct, _email, _hint| Err(KeychainClearUnconfirmed),
        );
        let queue_raw =
            std::fs::read_to_string(base.join("keychain-pending-clears.json")).unwrap_or_default();
        assert!(
            queue_raw.contains("Claude Code-credentials-facefeed"),
            "an unconfirmed clear must leave the entry queued for retry: {queue_raw}"
        );
    }

    /// No entry for `svc` at all -> both closures untouched, no queue write.
    #[cfg(target_os = "macos")]
    #[test]
    fn resolve_pending_clear_at_creation_is_noop_when_no_entry_matches() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let mut logout_calls = 0usize;
        let mut dead_handle_calls = 0usize;
        resolve_pending_clear_at_creation_with(
            base,
            "Claude Code-credentials-00000000",
            &mut |_svc| {
                logout_calls += 1;
                Ok(true)
            },
            &mut |_svc, _acct, _email, _hint| {
                dead_handle_calls += 1;
                Ok(true)
            },
        );
        assert_eq!(logout_calls, 0);
        assert_eq!(dead_handle_calls, 0);
    }

    // ── live_handle_dir_maps_to_service (keychain-fix-r10.md S-M-2) ──

    /// A live `term-<pid>` handle dir whose canonicalized path hashes to
    /// `svc` MUST be found. Uses the TEST PROCESS'S OWN pid — guaranteed
    /// alive for the duration of the test, no process spawning needed. RED
    /// under a mutation that returns `false` unconditionally (removing the
    /// `service_name(&abs) == svc` comparison's `true` arm).
    #[cfg(target_os = "macos")]
    #[test]
    fn live_handle_dir_maps_to_service_finds_live_matching_dir() {
        // `live_handle_dir_maps_to_service` shells out to `ps` (via
        // `read_start_time`), resolved through the process-global PATH; other
        // tests set PATH to a tempdir/empty. Hold the shared env lock so PATH
        // is stable for the whole call.
        let _env_guard = crate::platform::test_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let pid = std::process::id();
        let handle = dir.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        crate::accounts::markers::write_live_pid(&handle, pid).unwrap();
        let abs = std::fs::canonicalize(&handle).unwrap();
        let svc = service_name(&abs);
        assert!(live_handle_dir_maps_to_service(dir.path(), &svc, None));
    }

    /// A `term-<pid>` dir whose recorded pid is DEAD must NOT be treated as
    /// a live collision — a dead dir cannot be the "later session" this
    /// check exists to protect, and reaping it is the DeadHandle path's own
    /// job. `2_000_000_004` is not a live pid on any sane system (same
    /// dead-pid convention `accounts::logout`'s own tests use).
    #[cfg(target_os = "macos")]
    #[test]
    fn live_handle_dir_maps_to_service_ignores_dead_pid() {
        let dir = tempfile::tempdir().unwrap();
        let dead_pid: u32 = 2_000_000_004;
        let handle = dir.path().join(format!("term-{dead_pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        crate::accounts::markers::write_live_pid(&handle, dead_pid).unwrap();
        let abs = std::fs::canonicalize(&handle).unwrap();
        let svc = service_name(&abs);
        assert!(
            !live_handle_dir_maps_to_service(dir.path(), &svc, None),
            "a dead-pid handle dir must not count as a live collision"
        );
    }

    /// No `term-*` dir at all — genuinely nothing to find.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_handle_dir_maps_to_service_false_when_no_handle_dirs_exist() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!live_handle_dir_maps_to_service(
            dir.path(),
            "Claude Code-credentials-deadbeef",
            None
        ));
    }

    /// `keychain-fix-r11.md` S-LOW-1/D-4b: a live dir whose OWN identity
    /// matches `queued_identity` is the SAME dir the entry was queued
    /// against, never a collision — must NOT be reported as one, even
    /// though its service and PID both match. RED under a mutation that
    /// drops the identity comparison (falling straight to the PID-alive
    /// check as `keychain-fix-r10.md` S-M-2 did): this would then return
    /// `true`.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_handle_dir_maps_to_service_skips_the_same_queued_dir() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let pid = std::process::id();
        let handle = dir.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        crate::accounts::markers::write_live_pid(&handle, pid).unwrap();
        let abs = std::fs::canonicalize(&handle).unwrap();
        let svc = service_name(&abs);
        let meta = std::fs::metadata(&handle).unwrap();
        let queued_identity = Some((meta.ino(), meta.ctime()));
        assert!(
            !live_handle_dir_maps_to_service(dir.path(), &svc, queued_identity),
            "the entry's own queued dir must never read as a live collision \
             against itself"
        );
    }

    /// The sibling positive case: a live dir with the SAME service but a
    /// DIFFERENT identity than `queued_identity` (a genuinely different,
    /// newer dir occupying the same reused PID) IS a live collision.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_handle_dir_maps_to_service_finds_collision_with_different_queued_identity() {
        // `live_handle_dir_maps_to_service` shells out to `ps` (via
        // `read_start_time`), resolved through the process-global PATH; other
        // tests set PATH to a tempdir/empty. Hold the shared env lock so PATH
        // is stable for the whole call.
        let _env_guard = crate::platform::test_env::lock();
        let dir = tempfile::tempdir().unwrap();
        let pid = std::process::id();
        let handle = dir.path().join(format!("term-{pid}"));
        std::fs::create_dir_all(&handle).unwrap();
        crate::accounts::markers::write_live_pid(&handle, pid).unwrap();
        let abs = std::fs::canonicalize(&handle).unwrap();
        let svc = service_name(&abs);
        // A queued identity that cannot possibly match this dir's real one.
        let queued_identity = Some((u64::MAX, i64::MAX));
        assert!(
            live_handle_dir_maps_to_service(dir.path(), &svc, queued_identity),
            "a live dir with a DIFFERENT identity than the one queued against \
             must be reported as a genuine collision"
        );
    }

    /// End-to-end: `sweep_pending_clears_inner`'s own account round-trip —
    /// an entry recorded with `Some(account)` is re-validated to
    /// `Option<AccountNum>` and handed to `clear_fn`, and a `None`-recorded
    /// (legacy-shaped) entry is handed through as `None`, never silently
    /// promoted to `Some`.
    #[cfg(target_os = "macos")]
    #[test]
    fn sweep_pending_clears_inner_threads_recorded_account_to_clear_fn() {
        let dir = tempfile::tempdir().unwrap();
        let acct = crate::types::AccountNum::try_from(7u16).unwrap();
        record_pending_clear(
            dir.path(),
            &fake_service(0xacc0_0001),
            Some(acct),
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );
        record_pending_clear(
            dir.path(),
            &fake_service(0xacc0_0002),
            None,
            PendingClearOrigin::DeadHandle,
            None,
            None,
        );

        let mut seen: Vec<(String, Option<u16>)> = Vec::new();
        let mut spy = |svc: &str,
                       account: Option<crate::types::AccountNum>,
                       _origin: PendingClearOrigin,
                       _candidate_email: Option<&str>,
                       _keychain_account_hint: Option<&str>,
                       _queued_identity: Option<(u64, i64)>| {
            seen.push((svc.to_string(), account.map(|a| a.get())));
            Err(KeychainClearUnconfirmed)
        };
        let _ = sweep_pending_clears_inner(
            dir.path(),
            pending_clears_now_secs(),
            PENDING_CLEARS_SWEEP_BUDGET,
            &mut spy,
        );

        assert_eq!(seen.len(), 2, "both due entries must be attempted");
        assert!(
            seen.contains(&(fake_service(0xacc0_0001), Some(7))),
            "the account-carrying entry must hand its account to clear_fn: {seen:?}"
        );
        assert!(
            seen.contains(&(fake_service(0xacc0_0002), None)),
            "the account-less entry must hand None, never a guessed account: {seen:?}"
        );
    }

    // ── C-F4: harvest_account_candidates test seam (keychain-fix-r8d.md item 3) ──

    /// The test seam itself: `harvest_account_candidates` (via `raw_content_for`)
    /// now reads through the test-installed executor override, exactly like
    /// `force_sync_account_changed`/`reconcile_keychain_to_marker`. Before this,
    /// `raw_content_for` called `run_security_bounded` directly, which is
    /// UNCONDITIONALLY `None` under `cfg!(test)`/`test-utils` regardless of any
    /// installed override — so no test could ever drive a harvest candidate with
    /// real scripted content, structurally, no matter what was installed.
    #[cfg(target_os = "macos")]
    #[test]
    fn harvest_account_candidates_reads_through_test_executor_override() {
        let fixture = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = fixture.path();
        let account = crate::types::AccountNum::try_from(1u16).unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let far_future = now_ms() + 365 * 24 * 60 * 60 * 1000;

        // `create_handle_dir` only symlinks `.credentials.json` when the
        // identity-keyed target FILE already exists — `coexisting_fixture`
        // seeds `identity.json` but not `credentials.json` at that path, so
        // this must be written first or the symlink (and hence any harvest
        // candidate) never gets created at all.
        let identity_creds_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        std::fs::write(
            &identity_creds_path,
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"at-canonical","refreshToken":"rt-canonical","expiresAt":{far_future}}}}}"#
            ),
        )
        .unwrap();

        let claude_home = tempfile::TempDir::new().unwrap();
        let pid = std::process::id();
        let handle_dir =
            crate::session::create_handle_dir(base, claude_home.path(), account, pid).unwrap();

        let unmatched = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"at-SCRIPTED","refreshToken":"rt-SCRIPTED","expiresAt":{far_future}}}}}"#
        );
        let exec = std::rc::Rc::new(ScriptedKeychainExecutor::scripted(
            RawContentClassification::Content(unmatched.clone()),
        ));
        set_test_keychain_executor(exec);
        let candidates = harvest_account_candidates(base, &uuid.to_string());
        clear_test_keychain_executor();

        let _ = handle_dir;
        assert_eq!(
            candidates.len(),
            1,
            "the scripted executor's content must surface as a harvest candidate"
        );
        assert!(candidates[0].raw_json.contains("at-SCRIPTED"));
    }

    /// RED proof (quoted in the commit): before this seam existed, mutating
    /// `raw_content_for` to skip the override check and call
    /// `run_security_bounded` directly reproduces exactly the pre-fix
    /// structural gap — this test fails with `left: 0, right: 1` (zero
    /// candidates surfaced, since `run_security_bounded` is always `None`
    /// under test).
    ///
    /// End-to-end scenario (`keychain-fix-r8d.md` item 3's own wording):
    /// "test adopt-then-refresh in one refresher tick leaves the source dir
    /// recognised (token history)." A source dir's keychain item holds an
    /// unmatched-but-valid token (T-adopt); the custodian adopts it into the
    /// canonical store; a SUBSEQUENT refresher-tick write installs a NEW
    /// token (T-refresh); the source dir's now-stale item (still T-adopt)
    /// must still classify as KNOWN (rule 2) via the marker account's bounded
    /// history, never as an unmatched foreign login (rule 3).
    #[cfg(target_os = "macos")]
    #[test]
    fn adopt_then_refresh_in_one_tick_leaves_source_dir_recognised() {
        let fixture = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = fixture.path();
        let account = crate::types::AccountNum::try_from(1u16).unwrap();
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(1);
        let far_future = now_ms() + 365 * 24 * 60 * 60 * 1000;

        // Canonical store starts at T0 — a raw fixture write (bypassing the
        // write chokepoint, same as `reconcile_fixture`'s own setup); history
        // is deliberately empty at this point.
        let identity_creds_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(identity_creds_path.parent().unwrap()).unwrap();
        std::fs::write(
            &identity_creds_path,
            format!(
                r#"{{"claudeAiOauth":{{"accessToken":"at-0","refreshToken":"rt-0","expiresAt":{far_future}}}}}"#
            ),
        )
        .unwrap();

        // The "source dir": a fresh handle dir bound to account 1, whose
        // KEYCHAIN item (scripted) holds an unmatched-but-valid token —
        // T-adopt — never written to the canonical store yet.
        let claude_home = tempfile::TempDir::new().unwrap();
        let pid = std::process::id();
        let handle_dir =
            crate::session::create_handle_dir(base, claude_home.path(), account, pid).unwrap();
        // Same email as the fixture's identity.json (`coexisting_fixture`'s
        // stub email format), so the adopt gate's email pre-filter passes.
        std::fs::write(
            handle_dir.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"fixture-slot-1@test.invalid"}}"#,
        )
        .unwrap();

        // Strictly greater than T0's expiry — `save_canonical_for_if_fresher`
        // re-reads the store's CURRENT expiry under the lock and refuses to
        // write anything not STRICTLY fresher (an equal expiry reads as
        // "store already fresher, keep theirs").
        let adopt_expiry = far_future + 1_000;
        let adopt_raw = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"at-ADOPT","refreshToken":"rt-ADOPT","expiresAt":{adopt_expiry}}}}}"#
        );
        let exec = std::rc::Rc::new(ScriptedKeychainExecutor::scripted(
            RawContentClassification::Content(adopt_raw.clone()),
        ));
        set_test_keychain_executor(exec);

        // 1. Harvest — item 3's own seam: reads THROUGH the scripted
        //    executor rather than a real `security` subprocess.
        let candidates = harvest_account_candidates(base, &uuid.to_string());
        assert_eq!(
            candidates.len(),
            1,
            "the scripted keychain content must surface as a candidate"
        );
        assert!(candidates[0].raw_json.contains("at-ADOPT"));

        // 2. Adopt — the real custodian single-candidate adopt path.
        let http_get: crate::daemon::usage_poller::HttpGetFn =
            std::sync::Arc::new(|_url: &str, _tok: &str, _hdrs: &[(&str, &str)]| {
                Ok((
                    200,
                    br#"{"account":{"uuid":"u","email":"fixture-slot-1@test.invalid"}}"#.to_vec(),
                ))
            });
        let adopted = crate::daemon::custodian::adopt_single_candidate_before_delete(
            base,
            account,
            &candidates[0],
            &http_get,
        );
        clear_test_keychain_executor();
        assert!(
            adopted,
            "the candidate must be adopted into the canonical store"
        );

        // 3. Simulate a refresher tick — a NEW token, T-refresh, written
        //    through the SAME canonical chokepoint every real refresh uses.
        //    `keychain-fix-r11.md` S-M-3 residual: expiresAt is STRICTLY
        //    greater than `adopt_expiry`, not merely `far_future` — a real
        //    refresh AFTER an adopt is later than what it superseded, and
        //    the new history-only relative guard (`current_expiry <=
        //    intended_expiry`) requires this fixture to reflect that, or the
        //    stale source dir's item (still `adopt_expiry`) would read as
        //    LATER than the refreshed token and be refused.
        let refresh_raw = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"at-REFRESH","refreshToken":"rt-REFRESH","expiresAt":{}}}}}"#,
            adopt_expiry + 1_000
        );
        let refreshed_cf: CredentialFile = serde_json::from_str(&refresh_raw).unwrap();
        crate::credentials::file::save_canonical_for(base, account, &refreshed_cf).unwrap();

        // 4. The SOURCE dir's stale keychain item (still holding T-adopt,
        //    since nobody rewrote it) must still be RECOGNISED against the
        //    marker account's bounded history — "same account, superseded"
        //    (rule 2), never an unmatched foreign login (rule 3) — even
        //    though the canonical store has since moved on to T-refresh.
        let history = crate::credentials::token_history::read_history(base, uuid);
        let adopt_fp = crate::credentials::token_history::fingerprint_from_raw_json(&adopt_raw)
            .expect("adopt_raw must fingerprint");
        assert!(
            history.contains(&adopt_fp),
            "the adopted token's fingerprint must survive in history after a \
             later refresh — the source dir would otherwise be an unrecognised \
             foreign login: {history:?}"
        );

        // `keychain-fix-r9.md` S-M-3: the position-aware history check needs
        // the marker account's OWN canonical raw content too, so it can
        // resolve `refresh_raw`'s fingerprint as the position `adopt_fp`
        // must sit STRICTLY BEFORE — every real production caller supplies
        // both together (see `KnownTokens::marker_account_canonical`'s doc);
        // omitting it here would fail closed regardless of history content.
        let known = KnownTokens {
            marker_account_canonical: Some(&refresh_raw),
            marker_account_history: &history,
            ..KnownTokens::default()
        };
        let stale_source_x = RawContentClassification::Content(adopt_raw);
        let decision =
            decide_cc_keychain_write(&stale_source_x, &known, Intended::Token(&refresh_raw));
        assert!(
            matches!(decision, WriteDecision::Write(_) | WriteDecision::NoWrite),
            "the source dir's stale item must classify as known (rule 2), not \
             RefuseUnharvested: {decision:?}"
        );
    }

    /// Required test 4 (brief): unreadable/unclassifiable marker -> fail
    /// closed, no write attempted at all (never even reaches X).
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_fails_closed_when_marker_unreadable() {
        let fixture = crate::testing::identity_fixtures::coexisting_fixture(1);
        let base = fixture.path();
        let handle_dir = base.join("term-no-marker");
        std::fs::create_dir_all(&handle_dir).unwrap();
        // Deliberately no `.csq-account` marker written.

        let exec = RecordingExecutor::scripted(RawContentClassification::Absent);
        let outcome = reconcile_keychain_to_marker_with_executor(&exec, base, &handle_dir, None);
        assert_eq!(outcome, ReconcileOutcome::MarkerUnreadable);
        assert!(
            exec.calls().is_empty(),
            "an unclassifiable marker must fail closed BEFORE touching X: {:?}",
            exec.calls()
        );
    }

    /// Rule 2 (carry-over from last round, brief: "prove RED — these were
    /// never shown red"): X itself could not be classified (a genuinely
    /// unreadable/inaccessible keychain read) -> `KeychainUnknown`, NEVER
    /// `AlreadyCurrent` — and the operator line must never claim "both on"
    /// for a keychain state reconcile never actually observed.
    ///
    /// RED proof (quoted in the PR/journal): with the `Unreadable` guard at
    /// the top of `reconcile_keychain_to_marker_with_executor` removed (so
    /// an unreadable X falls through to the identity comparisons below,
    /// where every `keychain_content_matches_token` call against
    /// `RawContentClassification::Unreadable(_)` returns `false`), this
    /// test fails with:
    ///   assertion `left == right` failed
    ///     left: KeychainUnknown { marker_account: AccountNum(1), reason: KeychainUnreadable }
    ///    right: KeychainUnknown { marker_account: AccountNum(1), reason: ForeignLogin }
    /// — the wrong REASON, not a crash, which is exactly the silent
    /// misclassification a reader must not be allowed to miss (and the
    /// `!line.contains("both on")` assertion below independently guards
    /// against the OLD (pre-directive) bug where an unreadable X was mapped
    /// to `KeychainExpiryRead::CouldNotAsk`, which
    /// `keychain_is_fresher_or_equal_or_unknown` treated as "skip" —
    /// i.e. `AlreadyCurrent`, an outright false "both on" claim).
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_reports_keychain_unknown_never_already_current_when_keychain_unreadable() {
        let (fixture, handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();

        let exec = RecordingExecutor::scripted(RawContentClassification::Unreadable(
            UnreadableKind::Transient,
        ));
        let outcome = reconcile_keychain_to_marker_with_executor(&exec, base, &handle_dir, None);
        assert_eq!(
            outcome,
            ReconcileOutcome::KeychainUnknown {
                marker_account: crate::types::AccountNum::try_from(1u16).unwrap(),
                reason: KeychainUnknownReason::KeychainUnreadable,
            }
        );
        assert!(
            exec.calls()
                .iter()
                .all(|(verb, ..)| *verb != "add" && *verb != "delete"),
            "an unreadable X must never be written to or deleted"
        );
        let line = reconcile_outcome_operator_line(
            &outcome,
            Some(crate::types::AccountNum::try_from(1u16).unwrap()),
        );
        assert!(
            !line.contains("both on"),
            "an unreadable keychain must NEVER be reported as 'both on': {line}"
        );
    }

    /// L1: `real_security_spawn_tripwire` — the fn `run_security_bounded`
    /// falls through to whenever `keychain_mirror_disabled()` does NOT
    /// short-circuit it — panics UNCONDITIONALLY, regardless of the local
    /// keychain's actual state. This directly replaces the prior version of
    /// this test suite's discrimination gap (recorded in this file's own
    /// history): removing the guard used to be verified only by OBSERVING
    /// that a real `security find-generic-password` call happened to be
    /// denied on one particular (headless, non-Aqua) host, which does NOT
    /// discriminate "no security process was spawned" from "one was spawned
    /// and its outcome happened not to matter here" — an interactive Aqua
    /// session with no matching item would instead attempt a real WRITE and
    /// the old assertion would not have noticed. The tripwire removes the
    /// dependency on local keychain state entirely: it panics before
    /// `Command::new("security")` is ever constructed, on every host, in
    /// every keychain state.
    #[cfg(all(target_os = "macos", any(test, feature = "test-utils")))]
    #[test]
    #[should_panic(expected = "run_security_bounded reached a REAL")]
    fn real_security_spawn_tripwire_panics_when_reached() {
        // Calls the tripwire fn DIRECTLY (bypassing `keychain_mirror_disabled`'s
        // early return in `run_security_bounded`, which is exactly the path
        // the RED proof exercises via a temporary source mutation) — this
        // is a durable, always-in-CI proof that the tripwire itself panics
        // with the expected message, independent of any session's manual
        // RED demonstration.
        real_security_spawn_tripwire(&["find-generic-password"]);
    }

    /// an internal ticket — the STDIN-PATH argv is always exactly [`ADD_STDIN_ARGV`]
    /// (`["-i"]`): on that path the credential moves to `security -i`'s
    /// stdin and never touches argv at all, in any content or shape. Pins
    /// the production constant directly rather than a hand-copied literal,
    /// so a future edit that widens `ADD_STDIN_ARGV` back out (e.g.
    /// reintroducing `-w payload` for some new code path) reds this test
    /// immediately. Does NOT claim this for `add()` as a whole — an internal ticket
    /// (round 4) added a SEPARATE argv shape,
    /// `AddInvocation::ArgvFallback`, used instead of this one for an
    /// oversized payload; see `select_add_invocation_picks_stdin_or_argv_fallback_by_size`
    /// for that path's own pin.
    #[cfg(target_os = "macos")]
    #[test]
    fn add_stdin_path_argv_never_carries_the_credential() {
        assert_eq!(
            ADD_STDIN_ARGV,
            ["-i"],
            "add()'s STDIN-PATH argv to run_security_bounded must be exactly [\"-i\"] — \
             on that path the credential travels on stdin only (an internal ticket); the argv \
             fallback (an internal ticket) is a separate, deliberate exception for oversized \
             payloads only"
        );
    }

    /// S-LOW-3 — NOT purely hypothetical: `["add-generic-password", ...,
    /// "-w", payload]` is once again a REAL call shape, an internal ticket's argv
    /// fallback for an oversized payload (`add_stdin_path_argv_never_carries_the_credential`
    /// above pins only the STDIN path; it does not claim this shape never
    /// occurs). If `real_security_spawn_tripwire` is ever reached with an
    /// args slice that DOES carry a credential this way, its panic message
    /// MUST name only the subcommand (`args[0]`) — never the full args
    /// slice, which would print the token in plaintext into the panic
    /// output — a second line of defense on top of `run_security_bounded`'s
    /// own `keychain_mirror_disabled()` guard.
    #[cfg(all(target_os = "macos", any(test, feature = "test-utils")))]
    #[test]
    fn real_security_spawn_tripwire_never_prints_the_w_payload() {
        let secret_payload = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-NOTREALTOKu9x","refreshToken":"sk-ant-ort01-NOTREALTOKu9x"}}"#;
        let result = std::panic::catch_unwind(|| {
            real_security_spawn_tripwire(&[
                "add-generic-password",
                "-A",
                "-s",
                "svc",
                "-a",
                "account",
                "-w",
                secret_payload,
            ]);
        });
        let err = result.expect_err("real_security_spawn_tripwire must panic");
        let message = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .expect("panic payload must be a string message");
        assert!(
            message.contains("add-generic-password"),
            "panic message must still name the subcommand: {message}"
        );
        assert!(
            !message.contains("NOTREALTOKu9x"),
            "panic message must NOT contain the -w payload's token bytes: {message}"
        );
    }

    /// an internal ticket — the stdin command builder hex round-trips the payload
    /// byte-for-byte: decoding the `-X <hex>` token recovers the exact
    /// original bytes, including a payload containing quotes, spaces, and
    /// non-ASCII (which is exactly the shape `is_stdin_token_safe` must NOT
    /// need to validate, because the payload never becomes a bare token —
    /// only `svc`/`account` do).
    #[cfg(target_os = "macos")]
    #[test]
    fn build_add_stdin_command_hex_round_trips_payload() {
        let payload = "{\"claudeAiOauth\":{\"accessToken\":\"weird \\\" ' \n \u{1F600}\"}}";
        let cmd = build_add_stdin_command("svc", "acct", payload);
        let cmd_str = String::from_utf8(cmd).expect("command line must be valid UTF-8");
        assert!(
            cmd_str.ends_with('\n'),
            "command line must be newline-terminated: {cmd_str:?}"
        );
        let hex_token = cmd_str
            .trim_end()
            .rsplit(' ')
            .next()
            .expect("command line must have a trailing -X token");
        let decoded = hex::decode(hex_token).expect("the -X token must be valid hex");
        assert_eq!(
            decoded,
            payload.as_bytes(),
            "hex round-trip must recover the exact original payload bytes"
        );
    }

    /// an internal ticket — the payload NEVER appears as raw bytes anywhere in the stdin
    /// command line, only its hex encoding.
    #[cfg(target_os = "macos")]
    #[test]
    fn build_add_stdin_command_never_places_payload_bytes_raw_in_the_line() {
        let payload = "MARKER-PAYLOAD-TOKEN-\"quoted\"";
        let cmd = build_add_stdin_command("svc", "acct", payload);
        let cmd_str = String::from_utf8(cmd).expect("command line must be valid UTF-8");
        assert!(
            !cmd_str.contains(payload),
            "payload must be hex-encoded, never raw, in the stdin command: {cmd_str}"
        );
        assert!(
            cmd_str.contains(&hex::encode(payload.as_bytes())),
            "the hex encoding of the payload must be present: {cmd_str}"
        );
    }

    /// an internal ticket round 2 — `add_stdin_invocation` refuses (fails closed, no
    /// command line produced) when `svc` or `account` carries ANY character
    /// outside the `[A-Za-z0-9 ._-]` allowlist (see [`is_stdin_token_safe`]'s
    /// doc for why this is an allowlist, not a denylist — `'` and `#` are
    /// refused even though neither was empirically shown unsafe), and
    /// accepts the real shapes both actual producers
    /// ([`is_well_formed_service_name`], [`is_valid_cc_username`]) emit —
    /// including [`service_name`]'s literal space in `"Claude Code"`.
    #[cfg(target_os = "macos")]
    #[test]
    fn add_stdin_invocation_refuses_unsafe_service_or_account() {
        // Whitespace is SAFE (quoted) and MUST be accepted — the real `svc`
        // shape depends on it.
        assert!(add_stdin_invocation("svc with space", "acct", "p").is_ok());
        assert!(add_stdin_invocation("svc", "acct\"quote", "p").is_err());
        assert!(add_stdin_invocation("svc", "acct'quote", "p").is_err());
        assert!(add_stdin_invocation("svc", "acct#hash", "p").is_err());
        assert!(add_stdin_invocation("svc", "acct\\backslash", "p").is_err());
        assert!(add_stdin_invocation("svc", "acct\ncontrol", "p").is_err());
        assert!(add_stdin_invocation("svc", "acct日本語", "p").is_err());
        assert!(add_stdin_invocation("svc", "", "p").is_err());
        assert!(
            add_stdin_invocation("Claude Code-credentials-deadbeef", "user.name-1_2", "p").is_ok()
        );
    }

    /// Re-derived (2026-09-27, see `add_stdin_invocation`'s "RETRACTED
    /// FINDING" doc): `-g` readback proves storage of a non-printable-ASCII
    /// payload is CORRECT, so `add_stdin_invocation` accepts one — there is
    /// no printable-ASCII refusal to test. This pins that acceptance
    /// directly (mutation: reintroduce a printable-ASCII-only refusal here
    /// ⇒ REDs).
    #[cfg(target_os = "macos")]
    #[test]
    fn add_stdin_invocation_accepts_non_printable_ascii_payload() {
        assert!(add_stdin_invocation("svc", "acct", "has\nnewline").is_ok());
        assert!(add_stdin_invocation("svc", "acct", "has 日本語").is_ok());
        assert!(add_stdin_invocation("svc", "acct", r#"{"ok":true}"#).is_ok());
    }

    /// an internal ticket round 2 (BUG-1 fix) — `add_stdin_invocation` refuses BEFORE
    /// ever writing anything when the built command line would exceed
    /// `SECURITY_I_MAX_SAFE_LINE_BYTES` (see that const's doc for the
    /// measured 4096/4098 boundary and the truncation danger), and accepts
    /// a payload sized to stay under it. Mutation: comment out the length
    /// check in `add_stdin_invocation` — REDs (the oversized payload no
    /// longer refuses).
    #[cfg(target_os = "macos")]
    #[test]
    fn add_stdin_invocation_refuses_oversized_command_line() {
        // build_add_stdin_command's fixed overhead for these svc/account
        // values plus 2x hex expansion — pad payload so the TOTAL crosses
        // the threshold, then stays comfortably under it.
        let base_len = build_add_stdin_command("svc", "acct", "").len();
        let over_budget = SECURITY_I_MAX_SAFE_LINE_BYTES.saturating_sub(base_len) / 2 + 100;
        let oversized_payload = "a".repeat(over_budget);
        assert!(
            add_stdin_invocation("svc", "acct", &oversized_payload).is_err(),
            "a payload whose command line exceeds the safe limit must be refused"
        );

        let under_budget = SECURITY_I_MAX_SAFE_LINE_BYTES.saturating_sub(base_len) / 2 - 100;
        let safe_payload = "a".repeat(under_budget.max(1));
        assert!(
            add_stdin_invocation("svc", "acct", &safe_payload).is_ok(),
            "a payload comfortably under the safe limit must be accepted"
        );
    }

    /// an internal ticket (round 4) — `select_add_invocation`'s PURE dispatch: a small
    /// payload picks the stdin path (argv exactly `ADD_STDIN_ARGV`, i.e.
    /// `["-i"]`); an oversized payload picks the argv fallback, whose argv
    /// is byte-for-byte the pre-an internal ticket v2.19 shape. Mutation: make the
    /// oversized branch return `AddInvocation::Stdin(build_add_stdin_command(..))`
    /// instead of `ArgvFallback` — REDs (the oversized case no longer
    /// matches the fallback arm).
    #[cfg(target_os = "macos")]
    #[test]
    fn select_add_invocation_picks_stdin_or_argv_fallback_by_size() {
        let small = select_add_invocation("svc", "acct", "small payload")
            .expect("a small payload must be accepted");
        match small {
            AddInvocation::Stdin(cmd) => {
                assert_eq!(cmd, build_add_stdin_command("svc", "acct", "small payload"));
            }
            AddInvocation::ArgvFallback(_) => panic!("a small payload must pick the stdin path"),
        }

        let base_len = build_add_stdin_command("svc", "acct", "").len();
        let over_budget = SECURITY_I_MAX_SAFE_LINE_BYTES.saturating_sub(base_len) / 2 + 100;
        let oversized_payload = "a".repeat(over_budget);
        let oversized = select_add_invocation("svc", "acct", &oversized_payload)
            .expect("an oversized payload must still be accepted, via the argv fallback");
        match oversized {
            AddInvocation::ArgvFallback(argv) => {
                assert_eq!(
                    argv,
                    vec![
                        "add-generic-password".to_string(),
                        "-A".to_string(),
                        "-s".to_string(),
                        "svc".to_string(),
                        "-a".to_string(),
                        "acct".to_string(),
                        "-w".to_string(),
                        oversized_payload.clone(),
                    ],
                    "the argv fallback must be byte-for-byte the pre-an internal ticket v2.19 shape"
                );
            }
            AddInvocation::Stdin(_) => {
                panic!("an oversized payload must pick the argv fallback, not the stdin path")
            }
        }

        // An unsafe svc/account token is refused outright — NOT retried via
        // the argv fallback, regardless of size (the allowlist applies to
        // BOTH paths).
        assert!(select_add_invocation("svc\"quote", "acct", "p").is_err());
    }

    /// an internal ticket (round 4) — an oversized payload, dispatched through
    /// `select_add_invocation` exactly as `add()` does, round-trips
    /// byte-for-byte on a real (throwaway) keychain via the argv fallback.
    /// `SecurityCliExecutor::add` itself cannot be driven for real here —
    /// `run_security_bounded` is hermetically gated under EVERY test build
    /// (`keychain_mirror_disabled()` is `cfg!(test) || cfg!(feature =
    /// "test-utils") || ..`, unconditionally true in `cargo test`), so —
    /// exactly like this file's other an internal ticket real-keychain tests — this
    /// spawns `security` directly with the SAME argv
    /// `select_add_invocation` produced, scoped by `mod tests`'s
    /// `#[cfg(test)]` boundary (exempt from
    /// `no_bare_security_spawn_outside_shared_bounded_runner`, which only
    /// inspects production code).
    ///
    /// Opt-in: see `require_real_keychain_tests_opt_in`.
    #[cfg(target_os = "macos")]
    #[test]
    fn add_argv_fallback_oversized_round_trips_byte_for_byte() {
        if !require_real_keychain_tests_opt_in() {
            return;
        }
        let kc = ThrowawayKeychain::create("argv-fallback");
        let path = kc.path_str().to_string();
        let svc = "csq-test-service-1598-argv-fallback";
        let account = "csq-test-account-1598-argv-fallback";

        // A realistic oversized payload — JSON-shaped, printable ASCII
        // (matching what a real credential with several mcpOAuth siblings
        // looks like), padded past the safe stdin limit.
        let base_len = build_add_stdin_command(svc, account, "").len();
        let over_budget = SECURITY_I_MAX_SAFE_LINE_BYTES.saturating_sub(base_len) + 500;
        let padding = "a".repeat(over_budget);
        let payload = format!(r#"{{"claudeAiOauth":{{"accessToken":"{padding}"}}}}"#);

        // Pin the REAL production dispatch decision for this payload,
        // rather than assuming its size crosses the threshold.
        match select_add_invocation(svc, account, &payload)
            .expect("an oversized payload must still be accepted, via the argv fallback")
        {
            AddInvocation::ArgvFallback(_) => {}
            AddInvocation::Stdin(_) => {
                panic!("test payload did not cross the stdin size threshold — widen it")
            }
        }

        let add_result = std::process::Command::new("security")
            .args([
                "add-generic-password",
                "-A",
                "-s",
                svc,
                "-a",
                account,
                "-w",
                &payload,
                &path,
            ])
            .output()
            .expect("spawn security add-generic-password (argv fallback shape)");
        assert!(
            add_result.status.success(),
            "argv-fallback add failed: {}",
            String::from_utf8_lossy(&add_result.stderr)
        );

        let readback = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                svc,
                "-a",
                account,
                "-w",
                &path,
            ])
            .output()
            .expect("spawn security find-generic-password");
        assert!(
            readback.status.success(),
            "readback failed: {}",
            String::from_utf8_lossy(&readback.stderr)
        );
        let mut got = readback.stdout;
        assert_eq!(
            got.last().copied(),
            Some(b'\n'),
            "expected security's own trailing newline on -w output; got {got:?}"
        );
        got.pop();
        // Printable-ASCII payload here reads back raw via -w; mirror
        // `classify_raw_content`'s hex-decode-if-parseable convention
        // anyway for robustness, matching this file's other round-trip test.
        let decoded = match hex::decode(&got) {
            Ok(bytes) => bytes,
            Err(_) => got,
        };
        assert_eq!(
            decoded,
            payload.as_bytes(),
            "the oversized payload read back from the keychain must match what was written"
        );
    }

    /// an internal ticket round 3 (BUG-1, large-payload path) — the POSITIVE half of the
    /// team-lead's prescribed discriminating protocol: (1) create a
    /// throwaway keychain; (2) create the item with `/usr/bin/security
    /// add-generic-password -A …` (the same all-apps ACL shape CC items
    /// have); (3) update its data from THIS test binary via the native path
    /// with a >4KB payload; (4) read it back with a SEPARATE
    /// `/usr/bin/security find-generic-password -g …` process. This half
    /// PASSES (no interaction error; the new data is printed) — see
    /// `native_update_generic_password`'s doc for why this is NOT read as
    /// proof of ACL preservation: the paired negative control below (the
    /// required RED-capability check) did not reproduce, so this
    /// instrument cannot currently discriminate "ACL survived" from "ACL
    /// was never restrictive for this identity in the first place" — both
    /// tests are kept because the ROOT CAUSE (the test binary's ad-hoc
    /// signing) is itself the load-bearing finding for a future
    /// re-derivation.
    ///
    /// Opt-in: see `require_real_keychain_tests_opt_in`.
    #[cfg(target_os = "macos")]
    #[test]
    fn security_framework_native_update_preserves_acl() {
        if !require_real_keychain_tests_opt_in() {
            return;
        }
        let kc = ThrowawayKeychain::create("acl-pos");
        let path = kc.path_str().to_string();
        let svc = "csq-test-service-1598-acl-pos";
        let account = "csq-test-account-1598-acl-pos";

        // Step 2: create with -A via the separate `/usr/bin/security` binary
        // — the SAME all-apps ACL shape `security -i`'s create path in
        // production establishes.
        let create = std::process::Command::new("security")
            .args([
                "add-generic-password",
                "-A",
                "-s",
                svc,
                "-a",
                account,
                "-w",
                "seed",
                &path,
            ])
            .output()
            .expect("spawn security add-generic-password -A");
        assert!(
            create.status.success(),
            "seed add -A failed: {}",
            String::from_utf8_lossy(&create.stderr)
        );

        // Step 3: update from THIS test binary via the native path, >4KB.
        let big_payload = vec![b'x'; 8 * 1024];
        let keychain_handle = security_framework::os::macos::keychain::SecKeychain::open(&path)
            .expect("SecKeychain::open the throwaway keychain");
        native_update_generic_password(&keychain_handle, svc, account, &big_payload)
            .expect("native update must succeed against the -A-seeded item");

        // Step 4: read back with a SEPARATE `/usr/bin/security` process.
        let g = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-g",
                "-s",
                svc,
                "-a",
                account,
                &path,
            ])
            .output()
            .expect("spawn security find-generic-password -g");
        let g_stderr = String::from_utf8_lossy(&g.stderr).to_string();
        println!("security -g stderr (ACL-preserved case, quoted for the record): {g_stderr:?}");
        assert!(
            !g_stderr.contains("User interaction is not allowed"),
            "the update must have preserved the -A ACL — a SEPARATE process \
             (/usr/bin/security) was refused, meaning the ACL was replaced \
             with an app-scoped one: {g_stderr:?}"
        );
        assert!(
            g_stderr.contains("password:"),
            "expected a password: line on success: {g_stderr:?}"
        );
    }

    /// an internal ticket round 3 — the REQUIRED negative control (team-lead's brief:
    /// "create the item WITHOUT -A from the test binary [...] then read
    /// with /usr/bin/security — that must fail with the interaction error"
    /// — i.e. this test names what a WORKING discriminator would show).
    ///
    /// **MEASURED RESULT: it did not fail.** Create the item WITHOUT `-A`
    /// from THIS TEST BINARY (`native_update_generic_password`'s ADD branch
    /// — the item does not exist yet, so `SecKeychain::set_generic_password`
    /// falls through to `add_generic_password`, no explicit ACL), then read
    /// with `/usr/bin/security` (a DIFFERENT, Apple-signed process/binary):
    /// stderr came back EMPTY, `find-generic-password -g` succeeded. The
    /// prescribed protocol expected the interaction-not-allowed error here;
    /// it never fires, so the instrument cannot discriminate "ACL was
    /// restricted to this app" from "ACL was never restrictive" in THIS
    /// environment. **Root cause, measured — see
    /// `native_update_generic_password`'s doc**: `codesign -dv` on the test
    /// binary shows `Signature=adhoc`, `TeamIdentifier=not set`; a control
    /// item created the same way (via `/usr/bin/security`, no `-A`) shows a
    /// `security dump-keychain -a` ACL entry with `applications: <null>` —
    /// a NULL trust list, not "trust nobody". The assertion below pins the
    /// MEASURED behavior (empty stderr) so a future macOS/security change
    /// that starts enforcing this correctly REDS this test rather than
    /// silently making the sibling positive test meaningful again unnoticed.
    ///
    /// Opt-in: see `require_real_keychain_tests_opt_in`.
    #[cfg(target_os = "macos")]
    #[test]
    fn security_framework_create_without_acl_does_not_prompt_headless_here() {
        if !require_real_keychain_tests_opt_in() {
            return;
        }
        let kc = ThrowawayKeychain::create("acl-neg");
        let path = kc.path_str().to_string();
        let svc = "csq-test-service-1598-acl-neg";
        let account = "csq-test-account-1598-acl-neg";

        // Item does NOT exist yet — this exercises the ADD branch (no -A).
        let keychain_handle = security_framework::os::macos::keychain::SecKeychain::open(&path)
            .expect("SecKeychain::open the throwaway keychain");
        native_update_generic_password(&keychain_handle, svc, account, b"seed-no-acl")
            .expect("native add (no existing item) must succeed");

        let g = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-g",
                "-s",
                svc,
                "-a",
                account,
                &path,
            ])
            .output()
            .expect("spawn security find-generic-password -g");
        let g_stderr = String::from_utf8_lossy(&g.stderr).to_string();
        println!("security -g stderr (no-ACL control, quoted for the record): {g_stderr:?}");
        assert!(
            !g_stderr.contains("User interaction is not allowed"),
            "MEASURED (2026-09-27): reading an app-scoped item created by an \
             ad-hoc-signed test binary from a DIFFERENT process did not \
             require interaction — if this assertion REDS, the environment's \
             ACL enforcement has changed and `security_framework_native_update_preserves_acl` \
             should be re-read as a genuine discriminating result: {g_stderr:?}"
        );
    }

    /// an internal ticket round 3 (BUG-1, size boundary) — a >4KB update through the
    /// native path round-trips byte-for-byte, reading back with `-g` and
    /// hex-decoding (mirrors `security_dash_g_confirms_non_printable_storage_is_correct_not_hex_text`'s
    /// parsing).
    ///
    /// Opt-in: see `require_real_keychain_tests_opt_in`.
    #[cfg(target_os = "macos")]
    #[test]
    fn native_update_large_payload_round_trips_byte_for_byte() {
        if !require_real_keychain_tests_opt_in() {
            return;
        }
        let kc = ThrowawayKeychain::create("size-boundary");
        let path = kc.path_str().to_string();
        let svc = "csq-test-service-1598-size";
        let account = "csq-test-account-1598-size";

        // > SECURITY_I_MEASURED_MAX_LINE_BYTES worth of RAW bytes (not hex
        // chars) — well beyond anything `security -i`'s stdin line could
        // ever carry, seeded first with -A so the update path is exercised.
        let payload: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        assert!(payload.len() > SECURITY_I_MEASURED_MAX_LINE_BYTES);

        let seed = std::process::Command::new("security")
            .args([
                "add-generic-password",
                "-A",
                "-s",
                svc,
                "-a",
                account,
                "-w",
                "seed",
                &path,
            ])
            .output()
            .expect("spawn security add-generic-password -A");
        assert!(seed.status.success());

        let keychain_handle = security_framework::os::macos::keychain::SecKeychain::open(&path)
            .expect("SecKeychain::open the throwaway keychain");
        native_update_generic_password(&keychain_handle, svc, account, &payload)
            .expect("native update of a >4KB payload must succeed");

        let g = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-g",
                "-s",
                svc,
                "-a",
                account,
                &path,
            ])
            .output()
            .expect("spawn security find-generic-password -g");
        let g_stderr = String::from_utf8_lossy(&g.stderr).to_string();
        let line = g_stderr
            .lines()
            .find(|l| l.trim_start().starts_with("password:"))
            .unwrap_or_else(|| panic!("no password: line in -g stderr: {g_stderr:?}"));
        let hex_token = line
            .split_whitespace()
            .find(|tok| tok.starts_with("0x"))
            .unwrap_or_else(|| {
                panic!("password: line has no 0x<HEX> token (expected non-printable): {line:?}")
            });
        let got = hex::decode(hex_token.trim_start_matches("0x"))
            .expect("the 0x token must be valid hex");
        assert_eq!(
            got, payload,
            "the >4KB payload must round-trip byte-for-byte through the native update path"
        );
    }

    /// Re-derived finding, pinned directly: `classify_raw_content` already
    /// hex-decodes `security`'s own non-printable-password hex-display
    /// convention back to the ORIGINAL bytes — this is the read-side
    /// behavior that makes accepting a non-printable payload on write safe.
    /// Not a new test of new code — `classify_raw_content_hex_encoded_object_is_content`
    /// (above) already pins the same property; this one uses genuinely
    /// non-ASCII content (日本語) rather than an all-ASCII JSON string, so it
    /// cannot be satisfied by an implementation that merely checks
    /// "hex-shaped ASCII", only one that generically hex-decodes.
    #[cfg(target_os = "macos")]
    #[test]
    fn classify_raw_content_hex_decodes_non_ascii_content() {
        let json = r#"{"claudeAiOauth":{"accessToken":"日本語-token"}}"#;
        let hex = hex::encode(json.as_bytes());
        assert_eq!(
            classify_raw_content(Some(fake_output_with_stdout(0, hex.as_bytes()))),
            RawContentClassification::Content(json.to_string())
        );
    }

    /// an internal ticket round 2 (BUG-3 fix) — both real-`security`-spawning an internal ticket
    /// integration tests below are opt-in: return `false` (the test returns
    /// immediately, printing why) unless `CSQ_REAL_KEYCHAIN_TESTS=1` is set.
    /// Measured (mac-mini, 2026-09-27): `security create-keychain`/
    /// `delete-keychain` leave `security list-keychains -d user` UNCHANGED
    /// before/after (the throwaway keychain is never added to the user's
    /// default search list) — so the risk this gate guards against is
    /// "spawns real `security` subprocesses on shared/CI macOS
    /// infrastructure unasked", not search-list pollution.
    #[cfg(target_os = "macos")]
    fn require_real_keychain_tests_opt_in() -> bool {
        if std::env::var_os("CSQ_REAL_KEYCHAIN_TESTS").as_deref() != Some(std::ffi::OsStr::new("1"))
        {
            eprintln!(
                "skipping: set CSQ_REAL_KEYCHAIN_TESTS=1 to run this real-keychain an internal ticket test"
            );
            return false;
        }
        true
    }

    /// an internal ticket round 2 (BUG-3 fix) — RAII guard for the throwaway keychains
    /// the real-keychain an internal ticket tests create. `Drop` deletes the keychain
    /// file unconditionally, so a panicking assertion mid-test (which
    /// skipped the prior closure-based `cleanup(&tmp_str)` call entirely —
    /// only reached on the paths that called it explicitly) still cleans
    /// up. See [`require_real_keychain_tests_opt_in`]'s doc for the
    /// measured absence of a search-list side effect (nothing to restore).
    #[cfg(target_os = "macos")]
    struct ThrowawayKeychain {
        path: std::path::PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl ThrowawayKeychain {
        /// Creates the keychain at a fresh temp path and asserts it exists
        /// before returning — never let an absent/unconfirmed keychain
        /// silently fall back to the login keychain.
        fn create(name_hint: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "csq-1598-{name_hint}-{}-{}.keychain-db",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let create = std::process::Command::new("security")
                .args([
                    "create-keychain",
                    "-p",
                    "csq-1598-test-pass",
                    path.to_str().expect("tmp path must be UTF-8"),
                ])
                .output()
                .expect("spawn security create-keychain");
            assert!(
                create.status.success(),
                "create-keychain failed: {}",
                String::from_utf8_lossy(&create.stderr)
            );
            assert!(
                path.is_file(),
                "throwaway keychain was not actually created at {path:?} — refusing to \
                 proceed (an absent keychain path falls back to the LOGIN keychain)"
            );
            Self { path }
        }

        fn path_str(&self) -> &str {
            self.path.to_str().expect("tmp path must be UTF-8")
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for ThrowawayKeychain {
        fn drop(&mut self) {
            let _ = std::process::Command::new("security")
                .args(["delete-keychain", self.path_str()])
                .output();
        }
    }

    /// an internal ticket acceptance test: a real `security -i` add/find round-trip on a
    /// THROWAWAY keychain — never the login keychain, never a real CC item.
    /// Bypasses `SecurityCliExecutor`/`run_security_bounded` entirely (both
    /// are hermetically short-circuited under `cfg(test)`) and shells
    /// `security` directly, scoped by `mod tests`'s `#[cfg(test)]` boundary
    /// so it is exempt from `no_bare_security_spawn_outside_shared_bounded_runner`
    /// (that scanner only inspects PRODUCTION code, before the `mod tests {`
    /// marker) — this is the ONE place in the suite permitted to do so.
    ///
    /// Verifies the exact property an internal ticket exists for: the credential travels
    /// on stdin (never argv) and round-trips byte-for-byte through a real
    /// keychain — quotes, spaces, apostrophes, a RAW embedded newline byte,
    /// and non-ASCII (UTF-8 "日本語"). The readback decode mirrors
    /// `classify_raw_content`'s own logic (`add_stdin_invocation`'s
    /// "RETRACTED FINDING" doc): `security find-generic-password -w` prints
    /// non-printable content as its own hex text, so the byte-for-byte
    /// comparison hex-decodes the readback when it parses as hex, else
    /// compares it as literal bytes.
    ///
    /// Opt-in (round 2, BUG-3): see [`require_real_keychain_tests_opt_in`].
    #[cfg(target_os = "macos")]
    #[test]
    fn security_dash_i_add_find_round_trips_on_throwaway_keychain() {
        if !require_real_keychain_tests_opt_in() {
            return;
        }
        use std::io::Write;
        use std::process::{Command, Stdio};

        let kc = ThrowawayKeychain::create("test");
        let tmp_str = kc.path_str().to_string();

        let svc = "csq-test-service-1598";
        let account = "csq-test-account-1598";
        // Quotes, apostrophes, a RAW embedded newline byte, and non-ASCII —
        // all confirmed safe by the re-derived finding (see this test's doc).
        let payload = "payload with \"quotes\" and 'apostrophes' and\nnewlines and 日本語";

        let hex_payload = hex::encode(payload.as_bytes());
        // Quoted, matching build_add_stdin_command's real shape exactly
        // (production always quotes svc/account — see that fn's doc).
        let stdin_cmd = format!(
            "add-generic-password -A -s \"{svc}\" -a \"{account}\" -X {hex_payload} {tmp_str}\n"
        );

        let mut child = Command::new("security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn security -i");
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(stdin_cmd.as_bytes())
            .expect("write stdin command");
        let add_result = child.wait_with_output().expect("wait for security -i");
        if !add_result.status.success() {
            panic!(
                "security -i add failed: status={:?} stderr={}",
                add_result.status,
                String::from_utf8_lossy(&add_result.stderr)
            );
        }
        assert!(
            add_result.stderr.is_empty(),
            "a successful add must produce no stderr: {}",
            String::from_utf8_lossy(&add_result.stderr)
        );

        // Confirm the argv the ADD spawn actually used never carried the
        // payload: the only args given to `security` above were `["-i"]`.
        // (Structural — no separate assertion needed; this comment records
        // the property the round-trip below indirectly depends on.)

        let readback = Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                svc,
                "-a",
                account,
                "-w",
                &tmp_str,
            ])
            .output()
            .expect("spawn security find-generic-password");
        assert!(
            readback.status.success(),
            "readback failed: {}",
            String::from_utf8_lossy(&readback.stderr)
        );
        // `find-generic-password -w` appends exactly one trailing `\n` that
        // is not part of the stored value (measured empirically on the
        // mini, 2026-09-27: a payload ending `...x27` (no newline) read back
        // as `...x27\n`). Strip exactly that one trailing byte — never a
        // blanket `.trim()`, which would also eat real trailing whitespace
        // the payload itself may have had.
        let mut got = readback.stdout;
        assert_eq!(
            got.last().copied(),
            Some(b'\n'),
            "expected security's own trailing newline on -w output; got {got:?}"
        );
        got.pop();
        // `-w` prints a non-printable-ASCII value as ITS OWN hex text
        // rather than the raw bytes (re-derived finding, this test's doc) —
        // mirror `classify_raw_content`'s decode: if the readback parses as
        // hex, decode it; otherwise it is the literal (printable) bytes.
        let decoded = match hex::decode(&got) {
            Ok(bytes) => bytes,
            Err(_) => got,
        };
        assert_eq!(
            decoded,
            payload.as_bytes(),
            "the byte-for-byte payload read back from the keychain must match what was written"
        );
    }

    /// Independent-reader proof of the re-derived finding (see
    /// `add_stdin_invocation`'s "RETRACTED FINDING" doc): `find-generic-password
    /// -g` labels its output format explicitly (`password: "…"` for
    /// printable, `password: 0x<HEX>  "<escaped>"` for non-printable), so —
    /// unlike `-w` — it CAN discriminate "stored correctly, displayed as
    /// hex" from "stored as literal hex text". Parses that line and asserts
    /// the hex matches the INTENDED raw bytes for a payload containing a
    /// raw control byte (0x0A) and non-ASCII (0xE6 0x97 0xA5, UTF-8 "日").
    ///
    /// Opt-in (round 2, BUG-3): see [`require_real_keychain_tests_opt_in`].
    #[cfg(target_os = "macos")]
    #[test]
    fn security_dash_g_confirms_non_printable_storage_is_correct_not_hex_text() {
        if !require_real_keychain_tests_opt_in() {
            return;
        }
        use std::io::Write;
        use std::process::{Command, Stdio};

        let kc = ThrowawayKeychain::create("g-test");
        let tmp_str = kc.path_str().to_string();

        let svc = "csq-test-service-1598g";
        let account = "csq-test-account-1598g";
        // b'a', 0x0A, 0xE6, 0x97, 0xA5 ("日"), b'b' — intended raw bytes.
        let intended: &[u8] = b"a\x0a\xe6\x97\xa5b";
        let hex_payload = hex::encode(intended);
        let stdin_cmd = format!(
            "add-generic-password -A -s \"{svc}\" -a \"{account}\" -X {hex_payload} {tmp_str}\n"
        );
        let mut child = Command::new("security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn security -i");
        child
            .stdin
            .take()
            .expect("child stdin")
            .write_all(stdin_cmd.as_bytes())
            .expect("write stdin command");
        let add_result = child.wait_with_output().expect("wait for security -i");
        if !add_result.status.success() {
            panic!(
                "add failed: status={:?} stderr={}",
                add_result.status,
                String::from_utf8_lossy(&add_result.stderr)
            );
        }

        let g = Command::new("security")
            .args([
                "find-generic-password",
                "-g",
                "-s",
                svc,
                "-a",
                account,
                &tmp_str,
            ])
            .output()
            .expect("spawn security find-generic-password -g");
        let g_stderr = String::from_utf8_lossy(&g.stderr).to_string();
        println!("security -g stderr (quoted for the record): {g_stderr:?}");

        // Extract the `0x<HEX>` token from the `password: 0x<HEX>  "..."` line.
        let line = g_stderr
            .lines()
            .find(|l| l.trim_start().starts_with("password:"))
            .unwrap_or_else(|| panic!("no password: line in -g stderr: {g_stderr:?}"));
        let hex_token = line
            .split_whitespace()
            .find(|tok| tok.starts_with("0x"))
            .unwrap_or_else(|| {
                panic!("password: line has no 0x<HEX> token — is the content printable? {line:?}")
            });
        let got = hex::decode(hex_token.trim_start_matches("0x"))
            .expect("the 0x token must be valid hex");
        assert_eq!(
            got, intended,
            "the RAW bytes -g reports must equal the intended bytes, not their hex TEXT \
             (line was: {line:?})"
        );
    }

    /// L1: the ONLY test in this file that isolates `run_security_bounded`'s
    /// OWN `keychain_mirror_disabled()` check as the guard under test,
    /// rather than depending on a higher caller's guard
    /// (`reconcile_keychain_to_marker`, `force_sync_account_changed`,
    /// `write_raw` all check the guard themselves BEFORE ever reaching
    /// `SecurityCliExecutor`, so a test that only calls those never
    /// exercises this fn's own check at all). Constructs
    /// `SecurityCliExecutor` directly and calls `.find(..)` — the thinnest
    /// possible wrapper over `run_security_bounded` — to prove THIS
    /// chokepoint's guard holds on its own.
    ///
    /// RED proof (temporary mutation, reverted before landing — removed the
    /// `keychain_mirror_disabled()` check from the `any(test, feature =
    /// "test-utils")` branch of `run_security_bounded`): this test panicked
    /// via `real_security_spawn_tripwire` with the same message asserted
    /// above, proving the mutation was reached — not merely that some OTHER
    /// guard happened to intercept first.
    #[cfg(target_os = "macos")]
    #[test]
    fn security_cli_executor_find_is_hermetic_via_run_security_bounded_guard() {
        let result = SecurityCliExecutor.find("csq-test-service-l1", "csq-test-account-l1");
        assert!(
            matches!(result, RawContentClassification::Unreadable(_)),
            "run_security_bounded's OWN guard must short-circuit to \
             unavailable under test, never reach a real `security` spawn: \
             got {result:?}"
        );
    }

    /// Regression: the PUBLIC `reconcile_keychain_to_marker` (not the
    /// `_with_executor` core the tests above drive directly) MUST check
    /// `keychain_mirror_disabled()` before touching a real keychain item —
    /// every sibling v4/v5 entry point does, and one used to silently not.
    /// Calling the public fn under test with a resolvable marker MUST
    /// short-circuit to `AlreadyCurrent` without ever constructing a
    /// `SecurityCliExecutor` call — if the guard were absent, this exact
    /// call would now UNCONDITIONALLY hit `real_security_spawn_tripwire`
    /// and panic (see that test above), regardless of what the local
    /// keychain happens to hold. This closes the discrimination gap the
    /// prior version of this test's own doc comment recorded: a spy/mock
    /// executor is no longer needed to prove "no security process was
    /// spawned" — the tripwire proves it structurally.
    #[cfg(target_os = "macos")]
    #[test]
    fn reconcile_keychain_to_marker_public_entry_is_hermetic_under_test() {
        let (fixture, handle_dir, _far_future) = reconcile_fixture();
        let base = fixture.path();
        let outcome = reconcile_keychain_to_marker(base, &handle_dir, None);
        assert_eq!(
            outcome,
            ReconcileOutcome::AlreadyCurrent {
                marker_account: crate::types::AccountNum::try_from(1u16).unwrap()
            },
            "the public entry must short-circuit under test, never reach a real `security` call"
        );
    }

    // ── decide_cc_keychain_write (round 7b step 1) ─────────────────────

    fn tok(access: &str, refresh: &str) -> String {
        format!(
            r#"{{"claudeAiOauth":{{"accessToken":"{access}","refreshToken":"{refresh}","expiresAt":4102444800000,"scopes":[]}}}}"#
        )
    }

    fn no_login_content() -> String {
        r#"{"someOtherKey":"value"}"#.to_string()
    }

    fn malformed_oauth_content() -> String {
        // `claudeAiOauth` key present, but missing `refreshToken` — the
        // identity cannot be parsed (`oauth_identity` returns `None`).
        r#"{"claudeAiOauth":{"accessToken":"only-access"}}"#.to_string()
    }

    // Rule 1: absent -> free to write/strip.
    #[test]
    fn decide_rule1_absent_write_writes() {
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Absent,
            &KnownTokens::default(),
            Intended::Token(&intended),
        );
        assert!(matches!(decision, WriteDecision::Write(t) if t == intended));
    }

    #[test]
    fn decide_rule1_absent_strip_is_allowed() {
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Absent,
            &KnownTokens::default(),
            Intended::Strip,
        );
        assert_eq!(decision, WriteDecision::StripAllowed);
    }

    // Rule 1: present but holds NO login at all (no claudeAiOauth key) ->
    // same as absent, per directive rule 1 / D-F3.
    #[test]
    fn decide_rule1_no_login_content_write_writes() {
        let current_json = no_login_content();
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Content(current_json),
            &KnownTokens::default(),
            Intended::Token(&intended),
        );
        assert!(matches!(decision, WriteDecision::Write(t) if t == intended));
    }

    #[test]
    fn decide_rule1_no_login_content_strip_is_allowed() {
        let current_json = no_login_content();
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Content(current_json),
            &KnownTokens::default(),
            Intended::Strip,
        );
        assert_eq!(decision, WriteDecision::StripAllowed);
    }

    /// The login Claude Code leaves after a failed refresh: both tokens
    /// empty, `expiresAt` 0, plan metadata kept.
    fn emptied_login_content() -> String {
        r#"{"claudeAiOauth":{"accessToken":"","refreshToken":"","expiresAt":0,"scopes":["user:inference"],"subscriptionType":"max"}}"#.to_string()
    }

    // Rule 1: a login whose tokens are both empty holds nothing to lose.
    #[test]
    fn decide_rule1_emptied_login_write_writes() {
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Content(emptied_login_content()),
            &KnownTokens::default(),
            Intended::Token(&intended),
        );
        assert!(matches!(decision, WriteDecision::Write(t) if t == intended));
    }

    #[test]
    fn decide_rule1_emptied_login_strip_is_allowed() {
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Content(emptied_login_content()),
            &KnownTokens::default(),
            Intended::Strip,
        );
        assert_eq!(decision, WriteDecision::StripAllowed);
    }

    // Only BOTH empty is "no login": an empty access token next to a real
    // refresh token may still be a live login, so it stays unidentified.
    #[test]
    fn decide_one_empty_token_is_not_no_login() {
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Content(tok("", "someone-elses-rt")),
            &KnownTokens::default(),
            Intended::Token(&intended),
        );
        assert_eq!(decision, WriteDecision::RefuseUnharvested);
    }

    // Rule 4a: the ask itself did not resolve to a clean read -> Unknown,
    // for BOTH `UnreadableKind` variants.
    #[test]
    fn decide_rule4a_unreadable_transient_is_unknown() {
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Unreadable(UnreadableKind::Transient),
            &KnownTokens::default(),
            Intended::Token(&intended),
        );
        assert_eq!(
            decision,
            WriteDecision::Unknown(WriteUnknownReason::KeychainUnreadable)
        );
    }

    #[test]
    fn decide_rule4a_unreadable_inaccessible_is_unknown() {
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Unreadable(UnreadableKind::Inaccessible),
            &KnownTokens::default(),
            Intended::Strip,
        );
        assert_eq!(
            decision,
            WriteDecision::Unknown(WriteUnknownReason::KeychainUnreadable)
        );
    }

    // Rule 4b: `claudeAiOauth` present but its identity is unparseable — a
    // PARTIAL-identity match (has the key, missing `refreshToken`) — MUST
    // be `Unknown`, never treated as a match (rule 2) or a harvest
    // candidate (rule 3).
    #[test]
    fn decide_rule4b_partial_identity_match_is_unknown() {
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Content(malformed_oauth_content()),
            &KnownTokens::default(),
            Intended::Token(&intended),
        );
        assert_eq!(
            decision,
            WriteDecision::Unknown(WriteUnknownReason::MalformedOauth)
        );
    }

    #[test]
    fn decide_rule4b_partial_identity_match_is_unknown_for_strip_too() {
        let decision = decide_cc_keychain_write(
            &RawContentClassification::Content(malformed_oauth_content()),
            &KnownTokens::default(),
            Intended::Strip,
        );
        assert_eq!(
            decision,
            WriteDecision::Unknown(WriteUnknownReason::MalformedOauth)
        );
    }

    // F5: X already holds exactly the intended token -> NoWrite, even
    // though it also happens to be a "known" token (AlreadyCurrent takes
    // priority over rewriting an identical value).
    #[test]
    fn decide_f5_already_intended_token_is_no_write() {
        let same = tok("same-at", "same-rt");
        let current = RawContentClassification::Content(same.clone());
        let decision =
            decide_cc_keychain_write(&current, &KnownTokens::default(), Intended::Token(&same));
        assert_eq!(decision, WriteDecision::NoWrite);
    }

    // Rule 2: X matches the MARKER account's canonical token (not the
    // intended one) -> nothing lost by overwriting; write the intended.
    #[test]
    fn decide_rule2_matches_marker_canonical_writes_intended() {
        let marker_tok = tok("marker-at", "marker-rt");
        let current = RawContentClassification::Content(marker_tok.clone());
        let intended = tok("new-at", "new-rt");
        let known = KnownTokens {
            marker_account_canonical: Some(&marker_tok),
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert!(matches!(decision, WriteDecision::Write(t) if t == intended));
    }

    // Rule 2: X matches the SOURCE account's canonical token.
    #[test]
    fn decide_rule2_matches_source_canonical_writes_intended() {
        let source_tok = tok("source-at", "source-rt");
        let current = RawContentClassification::Content(source_tok.clone());
        let intended = tok("new-at", "new-rt");
        let known = KnownTokens {
            source_account_canonical: Some(&source_tok),
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert!(matches!(decision, WriteDecision::Write(t) if t == intended));
    }

    // Rule 2: X matches the token THIS call itself already force-wrote
    // (`csq_written`).
    #[test]
    fn decide_rule2_matches_csq_written_writes_intended() {
        let written = tok("written-at", "written-rt");
        let current = RawContentClassification::Content(written.clone());
        let intended = tok("new-at", "new-rt");
        let known = KnownTokens {
            csq_written: Some(&written),
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert!(matches!(decision, WriteDecision::Write(t) if t == intended));
    }

    /// `keychain-fix-r10.md` S-L-1: belt-and-braces over the history-position
    /// rule — an ABSOLUTE check (the intended token's own expiry vs now),
    /// never a RELATIVE one against `current`'s expiry. A relative
    /// comparison was tried during this same round and reverted: see this
    /// guard's own doc in `decide_cc_keychain_write` for the two existing
    /// tests (`reconcile_overwrites_foreign_token_with_later_expiry_when_it_matches_forced_write`,
    /// `adopt_then_refresh_in_one_tick_leaves_source_dir_recognised`) that
    /// independently falsify it.
    ///
    /// `matches_known` here is TRUE via `csq_written` — the specific channel
    /// doesn't matter for THIS guard, since it is absolute rather than
    /// evidence-channel-dependent; the intended token is on-its-face EXPIRED
    /// (in the past relative to `now_ms()`), which must never be installed
    /// regardless of what recognised `current` as known.
    ///
    /// RED: deleting the `if anthropic_expiry_ms(t).is_some_and(...)` guard
    /// (reverting to the pre-fix unconditional `WriteDecision::Write(t)`)
    /// makes this assertion fail — the decision comes back `Write(expired)`
    /// instead of `RefuseIntendedExpired`. `keychain-fix-r11.md` S-M-3
    /// residual: this is now its own variant, never `RefuseUnharvested` —
    /// harvesting `current` (which is perfectly live here, via `csq_written`)
    /// can never fix an already-expired INTENDED token.
    #[test]
    fn decide_rule2_refuses_an_already_expired_intended_token() {
        let live =
            r#"{"claudeAiOauth":{"accessToken":"live-at","refreshToken":"live-rt","expiresAt":9999999999999,"scopes":[]}}"#.to_string();
        let expired =
            r#"{"claudeAiOauth":{"accessToken":"expired-at","refreshToken":"expired-rt","expiresAt":1,"scopes":[]}}"#.to_string();
        let current = RawContentClassification::Content(live.clone());
        let known = KnownTokens {
            csq_written: Some(&live),
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&expired));
        assert_eq!(
            decision,
            WriteDecision::RefuseIntendedExpired,
            "an already-expired intended token must never be installed, \
             regardless of what channel recognised current as known"
        );
    }

    /// Sibling of the guard above: an intended token that is genuinely
    /// LIVE (far-future expiry) must still proceed to Write — the
    /// belt-and-braces guard must not become a blanket refusal on every
    /// rule-2 match.
    #[test]
    fn decide_rule2_writes_intended_when_intended_is_still_live() {
        let earlier =
            r#"{"claudeAiOauth":{"accessToken":"earlier-at","refreshToken":"earlier-rt","expiresAt":1000000000000,"scopes":[]}}"#.to_string();
        let newer =
            r#"{"claudeAiOauth":{"accessToken":"newer-at","refreshToken":"newer-rt","expiresAt":9999999999999,"scopes":[]}}"#.to_string();
        let current = RawContentClassification::Content(earlier.clone());
        let known = KnownTokens {
            csq_written: Some(&earlier),
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&newer));
        assert!(matches!(decision, WriteDecision::Write(t) if t == newer));
    }

    // Rule 2 (D-F4): X matches the sweep's pre-refresh identity for the
    // account being refreshed.
    #[test]
    fn decide_rule2_matches_sweep_pre_refresh_writes_intended() {
        let pre_refresh = tok("pre-at", "pre-rt");
        let current = RawContentClassification::Content(pre_refresh.clone());
        let intended = tok("new-at", "new-rt");
        let known = KnownTokens {
            sweep_pre_refresh: crate::credentials::token_history::fingerprint_from_raw_json(
                &pre_refresh,
            ),
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert!(matches!(decision, WriteDecision::Write(t) if t == intended));
    }

    // Rule 2: X matches one of the OPTIONAL "other accounts" the caller had
    // cheaply available.
    #[test]
    fn decide_rule2_matches_other_account_writes_intended() {
        let other = tok("other-at", "other-rt");
        let current = RawContentClassification::Content(other.clone());
        let intended = tok("new-at", "new-rt");
        let known = KnownTokens {
            other_accounts_canonical: &[other.as_str()],
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert!(matches!(decision, WriteDecision::Write(t) if t == intended));
    }

    // Rule 2, strip variant: X matches a known account -> safe to strip.
    #[test]
    fn decide_rule2_strip_matches_known_is_strip_allowed() {
        let known_tok = tok("known-at", "known-rt");
        let current = RawContentClassification::Content(known_tok.clone());
        let known = KnownTokens {
            marker_account_canonical: Some(&known_tok),
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Strip);
        assert_eq!(decision, WriteDecision::StripAllowed);
    }

    // Rule 3: X holds a real, parseable Anthropic identity matching NO known
    // account — the only live copy — refuse so the caller can harvest it.
    #[test]
    fn decide_rule3_unmatched_real_login_refuses_unharvested() {
        let foreign = tok("foreign-at", "foreign-rt");
        let current = RawContentClassification::Content(foreign);
        let intended = tok("new-at", "new-rt");
        // A syntactically-valid known token with a DIFFERENT identity than
        // `foreign` — so this test asserts the real "matches nothing known"
        // path, not "the known candidate itself failed to parse".
        let different = tok("different-at", "different-rt");
        let known = KnownTokens {
            marker_account_canonical: Some(&different),
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert_eq!(decision, WriteDecision::RefuseUnharvested);
    }

    #[test]
    fn decide_rule3_unmatched_real_login_with_no_known_tokens_at_all() {
        let foreign = tok("foreign-at", "foreign-rt");
        let current = RawContentClassification::Content(foreign);
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(
            &current,
            &KnownTokens::default(),
            Intended::Token(&intended),
        );
        assert_eq!(decision, WriteDecision::RefuseUnharvested);
    }

    // Rule 3, strip variant: X holds a real login matching nothing known —
    // stripping it would destroy the only live copy — refuse, not strip.
    #[test]
    fn decide_rule3_strip_unmatched_real_login_refuses_unharvested() {
        let foreign = tok("foreign-at", "foreign-rt");
        let current = RawContentClassification::Content(foreign);
        let decision = decide_cc_keychain_write(&current, &KnownTokens::default(), Intended::Strip);
        assert_eq!(decision, WriteDecision::RefuseUnharvested);
    }

    // ── keychain-fix-r8.md C-F1 (PRIMARY DIRECTIVE): marker_account_history ──
    //
    // A terminal that missed one (or several) refresh cycles holds T(n-2), an
    // OLDER-but-legitimate token for the SAME account. Rule 2 must now
    // recognize that via the marker account's own bounded history, not just
    // its CURRENT canonical token — this is the exact "sweep refuses forever"
    // class the directive names.

    #[test]
    fn decide_rule2_matches_marker_history_writes_intended() {
        // The terminal's item holds T(n-2) — TWO refreshes stale, not the
        // immediately-previous token (which rule 2's plain "current" match
        // would already have caught even pre-C-F1). Only the bounded HISTORY
        // recognizes it.
        let t_n_minus_2 = tok("at-n-2", "rt-n-2");
        let current_raw = tok("current-at", "current-rt");
        let current = RawContentClassification::Content(t_n_minus_2.clone());
        let intended = tok("new-at", "new-rt");
        let history = vec![
            crate::credentials::token_history::fingerprint_from_raw_json(&t_n_minus_2).unwrap(),
            crate::credentials::token_history::fingerprint_from_raw_json(&current_raw).unwrap(),
        ];
        let known = KnownTokens {
            marker_account_canonical: Some(&current_raw),
            marker_account_history: &history,
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert!(
            matches!(decision, WriteDecision::Write(t) if t == intended),
            "a keychain item holding an OLDER token from the marker account's own history \
             must be recognized as rule 2 (same account, superseded), not refused: {decision:?}"
        );
    }

    #[test]
    fn decide_rule2_strip_matches_marker_history_is_strip_allowed() {
        let t_n_minus_2 = tok("at-n-2", "rt-n-2");
        // `keychain-fix-r9.md` S-M-3: a history match now requires the
        // marker account's OWN canonical fingerprint to also be resolvable
        // in the same bounded history, strictly AFTER the fingerprint being
        // tested — so this fixture must supply both, canonical last.
        let current_raw = tok("current-at", "current-rt");
        let current = RawContentClassification::Content(t_n_minus_2.clone());
        let history = vec![
            crate::credentials::token_history::fingerprint_from_raw_json(&t_n_minus_2).unwrap(),
            crate::credentials::token_history::fingerprint_from_raw_json(&current_raw).unwrap(),
        ];
        let known = KnownTokens {
            marker_account_canonical: Some(&current_raw),
            marker_account_history: &history,
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Strip);
        assert_eq!(decision, WriteDecision::StripAllowed);
    }

    // `keychain-fix-r9.md` S-M-3: a history hit is trusted only when it sits
    // STRICTLY BEFORE the marker account's own canonical position in that
    // same history — never merely "present somewhere in it".
    #[test]
    fn decide_history_hit_at_or_after_canonical_position_does_not_match() {
        // Canonical was rolled back to the OLDER token (index 0); the
        // keychain item holds a NEWER token this same history also knows
        // about (index 1) — the item is genuinely ahead of, not behind,
        // what canonical currently claims. Silently overwriting it with the
        // rolled-back canonical value would discard a still-live session.
        let old_tok = tok("old-at", "old-rt");
        let new_tok = tok("new-at", "new-rt");
        let current = RawContentClassification::Content(new_tok.clone());
        let history = vec![
            crate::credentials::token_history::fingerprint_from_raw_json(&old_tok).unwrap(),
            crate::credentials::token_history::fingerprint_from_raw_json(&new_tok).unwrap(),
        ];
        let known = KnownTokens {
            marker_account_canonical: Some(&old_tok), // rolled back
            marker_account_history: &history,
            ..KnownTokens::default()
        };
        let intended = tok("intended-at", "intended-rt");
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert_eq!(
            decision,
            WriteDecision::RefuseUnharvested,
            "a keychain item ahead of (not behind) the rolled-back canonical position \
             must never be treated as safe to overwrite: {decision:?}"
        );
    }

    // Fail-closed companion: when the canonical fingerprint cannot be
    // resolved into the SAME history at all (absent canonical, or a
    // canonical whose own token has aged out of the bounded window), there
    // is no position to compare against — a history hit must not match.
    #[test]
    fn decide_history_hit_with_unresolvable_canonical_position_does_not_match() {
        let t_n_minus_2 = tok("at-n-2", "rt-n-2");
        let current = RawContentClassification::Content(t_n_minus_2.clone());
        let history = vec![
            crate::credentials::token_history::fingerprint_from_raw_json(&t_n_minus_2).unwrap(),
        ];
        let known = KnownTokens {
            marker_account_canonical: None, // no canonical to anchor a position against
            marker_account_history: &history,
            ..KnownTokens::default()
        };
        let intended = tok("intended-at", "intended-rt");
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert_eq!(
            decision,
            WriteDecision::RefuseUnharvested,
            "an unresolvable canonical position must fail closed, not treat every \
             history entry as safe: {decision:?}"
        );
    }

    // A token from ANOTHER account's history MUST NOT satisfy this check —
    // the fingerprint happens to be present in "some" history, but it is the
    // WRONG account's history; this is the cross-account overwrite the
    // directive explicitly forbids.
    #[test]
    fn decide_history_from_another_account_does_not_match() {
        let other_accounts_old_token = tok("other-old-at", "other-old-rt");
        let current = RawContentClassification::Content(other_accounts_old_token.clone());
        let intended = tok("new-at", "new-rt");
        // The CALLER is only permitted to pass the MARKER account's own
        // history (`token_history::read_history_for_slot` is keyed by
        // identity, so there is no cross-account read path at all) — this
        // test simulates the caller ever doing so by mistake, to prove
        // `decide_cc_keychain_write` itself does not widen recognition
        // beyond whatever history it was given: the marker account's history
        // here contains ONLY its own unrelated tokens, never
        // `other_accounts_old_token`.
        let marker_only_history = vec![
            crate::credentials::token_history::fingerprint_from_raw_json(&tok(
                "marker-own-at",
                "marker-own-rt",
            ))
            .unwrap(),
        ];
        let known = KnownTokens {
            marker_account_canonical: Some("irrelevant — different identity entirely"),
            marker_account_history: &marker_only_history,
            ..KnownTokens::default()
        };
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert_eq!(
            decision,
            WriteDecision::RefuseUnharvested,
            "a fingerprint from a DIFFERENT account's history must never satisfy rule 2: {decision:?}"
        );
    }

    // `keychain-fix-r11.md` S-M-3 residual (D-1): the NEW relative guard for
    // history-ONLY matches. `current` is recognised solely via the
    // history-position channel (no raw/csq_written match, no pre-refresh
    // match) but its OWN content outlives the intended token — e.g. a
    // rollback after `start_new_segment` left an old, still-unexpired grant
    // recognised only via the bounded history. Overwriting it would
    // silently discard a still-live session, so this must refuse
    // (`RefuseUnharvested` — the ordinary "let the caller harvest and
    // re-decide" case, not the absolute `RefuseIntendedExpired` backstop,
    // since the INTENDED token here is perfectly live).
    #[test]
    fn decide_history_only_match_with_later_current_expiry_refuses_unharvested() {
        let old_still_live = r#"{"claudeAiOauth":{"accessToken":"old-at","refreshToken":"old-rt","expiresAt":9999999999999,"scopes":[]}}"#.to_string();
        let canonical_now = tok("canon-at", "canon-rt"); // tok()'s fixed expiresAt: 4102444800000
        let current = RawContentClassification::Content(old_still_live.clone());
        let history = vec![
            crate::credentials::token_history::fingerprint_from_raw_json(&old_still_live).unwrap(),
            crate::credentials::token_history::fingerprint_from_raw_json(&canonical_now).unwrap(),
        ];
        let known = KnownTokens {
            marker_account_canonical: Some(&canonical_now),
            marker_account_history: &history,
            ..KnownTokens::default()
        };
        // Genuinely live (far future), but EARLIER than `old_still_live`'s
        // own expiry — a real refresh would never produce this shape; this
        // fixture reproduces the rollback case the relative guard exists for.
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert_eq!(
            decision,
            WriteDecision::RefuseUnharvested,
            "a history-only match whose CURRENT content outlives the intended token \
             must refuse — writing over it would discard a still-live session: {decision:?}"
        );
    }

    // `keychain-fix-r11.md` S-M-3 residual: BOTH history positions now use
    // `rposition` (last occurrence). A bounded history can hold the SAME
    // fingerprint at more than one index — `[X, C, X]`, when X was written,
    // superseded by C, then written again (rollback/restore). `current`
    // actually holds the LAST X, which sits AFTER C's position, not before
    // it — a FIRST-occurrence read would wrongly treat X's leading index as
    // "superseded".
    #[test]
    fn decide_history_duplicate_fingerprint_with_canonical_restored_refuses() {
        let x_tok = tok("x-at", "x-rt");
        let c_tok = tok("c-at", "c-rt");
        let x_fp = crate::credentials::token_history::fingerprint_from_raw_json(&x_tok).unwrap();
        let c_fp = crate::credentials::token_history::fingerprint_from_raw_json(&c_tok).unwrap();
        let history = vec![x_fp, c_fp, x_fp]; // [X, C, X] — X's LAST occurrence is after C
        let current = RawContentClassification::Content(x_tok.clone());
        let known = KnownTokens {
            marker_account_canonical: Some(&c_tok),
            marker_account_history: &history,
            ..KnownTokens::default()
        };
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(&current, &known, Intended::Token(&intended));
        assert_eq!(
            decision,
            WriteDecision::RefuseUnharvested,
            "current's LAST occurrence sits AFTER canonical's position, so a \
             first-occurrence position read must not treat it as superseded: {decision:?}"
        );
    }

    #[test]
    fn decide_empty_history_does_not_change_rule3_refusal() {
        // `KnownTokens::default()`'s `marker_account_history` is `&[]` —
        // confirms the C-F1 addition is a pure widening: an empty history
        // reproduces the pre-C-F1 rule 3 refusal exactly.
        let foreign = tok("foreign-at", "foreign-rt");
        let current = RawContentClassification::Content(foreign);
        let intended = tok("new-at", "new-rt");
        let decision = decide_cc_keychain_write(
            &current,
            &KnownTokens::default(),
            Intended::Token(&intended),
        );
        assert_eq!(decision, WriteDecision::RefuseUnharvested);
    }

    // Debug redaction: a raw token must never appear in `{:?}` output.
    #[test]
    fn write_decision_debug_redacts_token() {
        let leaked = "NOTREALTOKmarker9x";
        let decision = WriteDecision::Write(leaked);
        let rendered = format!("{decision:?}");
        assert!(
            !rendered.contains(leaked),
            "Debug output leaked the raw token: {rendered}"
        );
    }

    #[test]
    fn intended_debug_redacts_token() {
        let leaked = "NOTREALTOKmarker9x";
        let intended = Intended::Token(leaked);
        let rendered = format!("{intended:?}");
        assert!(
            !rendered.contains(leaked),
            "Debug output leaked the raw token: {rendered}"
        );
    }

    #[test]
    fn raw_content_classification_debug_redacts_content() {
        let leaked = "NOTREALTOKmarker9x";
        let current = RawContentClassification::Content(tok(leaked, "rt"));
        let rendered = format!("{current:?}");
        assert!(
            !rendered.contains(leaked),
            "Debug output leaked the raw token: {rendered}"
        );
    }
}
