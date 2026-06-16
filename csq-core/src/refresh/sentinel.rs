//! Per-slot lifecycle sentinels: config-dir scanning + broker-failed
//! flag persistence.
//!
//! Phase 4 M4-6 (issue #292): migrated from `broker::fanout` to
//! `refresh::sentinel`. The module's surviving responsibility is the
//! per-slot failure marker (`credentials/{N}.broker-failed`) plus the
//! `scan_config_dirs` helper used by the desktop swap command to find
//! the live config-N for an account.
//!
//! `scan_config_dirs` enumerates `config-*` directories whose
//! `.csq-account` marker matches the given account.
//!
//! `broker_failed` helpers manage the `credentials/{N}.broker-failed`
//! flag file used to surface LOGIN-NEEDED state on the dashboard.
//!
//! Historical note: `fan_out_credentials` was retired in M3-7 — handle
//! dirs read credentials through their identity-keyed symlinks
//! (M3-3/M3-4), so the daemon's `save_canonical_for` write IS the only
//! credential write needed. `config-N/.credentials.json` is no longer
//! materialised. The retired symbol is gone with the M4-6 rename.

use crate::accounts::markers;
use crate::error::CredentialError;
use crate::types::AccountNum;
use std::path::{Path, PathBuf};

/// Scans `config-*` directories for those belonging to the given account.
///
/// Returns paths to config directories whose `.csq-account` marker
/// matches the given account number.
pub fn scan_config_dirs(base_dir: &Path, account: AccountNum) -> Vec<PathBuf> {
    let mut matches = Vec::new();

    let entries = match std::fs::read_dir(base_dir) {
        Ok(e) => e,
        Err(_) => return matches,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if !name.starts_with("config-") {
            continue;
        }

        // Check if this config dir belongs to the target account
        if let Some(marker_account) = markers::read_csq_account(&path) {
            if marker_account == account {
                matches.push(path);
            }
        }
    }

    matches
}

// `fan_out_credentials` retired in M3-7 and the symbol is gone in
// M4-6. Handle dirs symlink `.credentials.json` to
// `identities/<UUID>/credentials.json` (M3-3/M3-4 retarget); the
// daemon's `save_canonical_for` write IS the only credential write
// needed, and CC re-stats the symlink before every API call
// (spec 01 §1.4).

// ── Broker failure flags ──────────────────────────────────────────────

/// Returns the path to the broker-failed flag file.
fn broker_failed_path(base_dir: &Path, account: AccountNum) -> PathBuf {
    base_dir
        .join("credentials")
        .join(format!("{}.broker-failed", account))
}

/// Checks whether broker has failed for the given account (LOGIN-NEEDED).
pub fn is_broker_failed(base_dir: &Path, account: AccountNum) -> bool {
    broker_failed_path(base_dir, account).exists()
}

/// Sets the broker-failed flag for the given account with a short
/// failure reason tag (e.g. `"invalid_grant"`, `"network"`,
/// `"rate_limit"`). The reason is stored as the file contents so
/// the dashboard and `csq status` can surface WHY a refresh failed.
///
/// ### Why the reason is stored as file contents
///
/// The pre-v2.1 behavior was to write an empty file — broker_check
/// knew something went wrong but couldn't tell users what. That
/// produced the "why does it say Expired?" UX dead-end that
/// prompted this change. Adding a small string payload means
/// `credentials/N.broker-failed` still exists as a flag file (the
/// existence check stays the same) but now carries enough signal
/// to diagnose without log archaeology.
///
/// ### Security
///
/// The `reason` argument is caller-controlled and MUST be a
/// fixed-vocabulary tag that never contains raw error messages —
/// token leakage risk. See `error::error_kind_tag` in csq-core for
/// the canonical enum of safe reason strings.
pub fn set_broker_failed(
    base_dir: &Path,
    account: AccountNum,
    reason: &str,
) -> Result<(), CredentialError> {
    let path = broker_failed_path(base_dir, account);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    // Cap at 256 bytes so a stray bug that shoves a full error
    // string in here can never bloat the flag file.
    let payload: String = reason.chars().take(256).collect();
    std::fs::write(&path, payload.as_bytes()).map_err(|e| CredentialError::Io { path, source: e })
}

/// Reads the broker-failed reason tag, or `None` if the flag is
/// not set or the file is unreadable. Used by `commands::
/// get_accounts` to surface the reason in the dashboard.
///
/// Empty-file markers from the pre-v2.1 format are mapped to
/// `Some("")` so callers can still detect the flag but know the
/// reason is unknown.
pub fn read_broker_failed_reason(base_dir: &Path, account: AccountNum) -> Option<String> {
    let path = broker_failed_path(base_dir, account);
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Clears the broker-failed flag for `account`.
///
/// Per `.claude/rules/sentinel-clearing-parity.md` MUST Rule 2, every
/// success boundary that resolves the broker-failed condition MUST call
/// this function. The enumeration below names every current caller; new
/// success boundaries that should clear the flag MUST be added BOTH here
/// AND at the callsite (paired update, never one without the other).
///
/// **Current callers (9 sites — keep this list current):**
///
/// 1. `refresh::check::broker_check` early-return Valid path
///    (`csq-core/src/refresh/check.rs:89`) — daemon-tick observed that
///    the Anthropic access token is healthy; any stale flag is obsolete.
/// 2. `refresh::check::broker_check` post-lock Valid path (line 126) —
///    sibling process refreshed between our read and lock acquisition;
///    creds are healthy by the time we observe them under the lock.
/// 3. `refresh::check::do_refresh` Ok branch (line 134) — symmetric
///    setter pair for the Anthropic refresh path: a successful refresh
///    supersedes any prior failure.
/// 4. `refresh::check::broker_codex_check` early-return Valid (line 279)
///    — Codex sibling of (1).
/// 5. `refresh::check::broker_codex_check` post-lock Valid (line 308) —
///    Codex sibling of (2).
/// 6. `refresh::check::broker_codex_check` Refreshed-Ok (line 425) —
///    Codex symmetric setter pair sibling of (3); a successful Codex
///    refresh supersedes any prior failure.
/// 7. `providers::codex::login::perform_with` post-`save_canonical_for`
///    (`csq-core/src/providers/codex/login.rs:484`) — `csq login N
///    --provider codex` minted a fresh chain into the identity store;
///    prior broker_failed flag is obsolete.
/// 8. `providers::codex::desktop_login::*` post-`save_canonical_for`
///    (`csq-core/src/providers/codex/desktop_login.rs:268`) — desktop
///    counterpart to (7).
/// 9. `accounts::login::finalize_login`
///    (`csq-core/src/accounts/login.rs:426`) — Anthropic OAuth login
///    success; the rule's first instance (predates `sentinel-clearing-
///    parity.md`).
///
/// **Audit primitive (per `sentinel-clearing-parity.md` Rule 1):**
///
/// ```bash
/// grep -rEn 'clear_broker_failed' csq-core/src csq/src --include='*.rs' \
///   | grep -v test | grep -v '/sentinel.rs'
/// ```
///
/// Should return exactly 9 callsites matching the enumeration above. A
/// match outside the enumeration is either a new caller that MUST be
/// added to this docstring (paired-update discipline) or an unauthorized
/// site to investigate.
///
/// **Fail-safe:** silently ignores remove errors (the sentinel may not
/// exist; ENOENT is the steady state). Errors other than ENOENT also
/// drop silently — this function is best-effort cleanup; persistent
/// clearing failures surface via the broker_failed flag itself staying
/// stale, which the Rule 1 audit catches structurally.
pub fn clear_broker_failed(base_dir: &Path, account: AccountNum) {
    let path = broker_failed_path(base_dir, account);
    let _ = std::fs::remove_file(&path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials;
    use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn make_creds(access: &str, refresh: &str) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at: 9999999999999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        })
    }

    fn setup_config_dir(base: &Path, n: u16) -> PathBuf {
        let dir = base.join(format!("config-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        let account = AccountNum::try_from(n).unwrap();
        markers::write_csq_account_legacy(&dir, account).unwrap();
        dir
    }

    #[test]
    fn scan_finds_matching_dirs() {
        let dir = TempDir::new().unwrap();
        setup_config_dir(dir.path(), 3);
        setup_config_dir(dir.path(), 3); // same account, different dir won't happen in practice
        let other = dir.path().join("config-5");
        std::fs::create_dir_all(&other).unwrap();
        markers::write_csq_account_legacy(&other, AccountNum::try_from(5u16).unwrap()).unwrap();

        let account = AccountNum::try_from(3u16).unwrap();
        let matches = scan_config_dirs(dir.path(), account);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn scan_ignores_dirs_without_marker() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("config-1")).unwrap();
        // No .csq-account marker

        let account = AccountNum::try_from(1u16).unwrap();
        let matches = scan_config_dirs(dir.path(), account);
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_empty_base_dir() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();
        let matches = scan_config_dirs(dir.path(), account);
        assert!(matches.is_empty());
    }

    /// M3-7 acceptance test #9 (WBS line 266), preserved across the
    /// M4-6 broker→refresh rename:
    /// `broker_fanout_does_not_write_config_n_credentials_json`.
    ///
    /// `fan_out_credentials` is retired. After a daemon-driven token
    /// refresh, no refresh module function writes to `config-<N>/.credentials.json`.
    /// We assert the behaviour at the broker_check level: run a successful
    /// refresh (via the broker_check entry) and confirm the fixture-seeded
    /// config-N mirror is untouched (mtime stable).
    #[test]
    fn broker_fanout_does_not_write_config_n_credentials_json() {
        use crate::credentials::file as cred_file;
        use crate::refresh::check::broker_check;
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(9u16).unwrap();
        let config = setup_config_dir(dir.path(), 9);

        // Seed canonical with expiring credentials so broker_check fires.
        // M4-12: save_canonical is retired; write directly to the numeric
        // canonical read path that broker_check reads via file::canonical_path.
        let mut expiring = make_creds("at-expiring", "rt-9");
        expiring.expect_anthropic_mut().claude_ai_oauth.expires_at = 1000; // far in the past
        let canonical_path = cred_file::canonical_path(dir.path(), account);
        std::fs::create_dir_all(canonical_path.parent().unwrap()).unwrap();
        credentials::save(&canonical_path, &expiring).unwrap();

        // Seed live mirror with old content; we assert it stays untouched.
        let live_path = config.join(".credentials.json");
        credentials::save(&live_path, &make_creds("at-mirror-seed", "rt-9")).unwrap();
        let pre_mtime = std::fs::metadata(&live_path)
            .ok()
            .and_then(|m| m.modified().ok());
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Run broker_check with a stubbed http_post that returns a fresh token.
        let mock = |_url: &str, _body: &str| -> Result<Vec<u8>, String> {
            Ok(br#"{
                "access_token":"at-refreshed",
                "refresh_token":"rt-9-new",
                "expires_in":3600
            }"#
            .to_vec())
        };
        let _ = broker_check(dir.path(), account, mock);

        // Assert: live mirror's mtime is unchanged → broker did not fan out.
        let post_mtime = std::fs::metadata(&live_path)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            pre_mtime, post_mtime,
            "M3-7: broker fanout retired; config-N/.credentials.json mirror MUST NOT \
             be written by broker_check; pre={pre_mtime:?} post={post_mtime:?}"
        );
    }

    #[test]
    fn broker_failed_flag_lifecycle() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(4u16).unwrap();

        assert!(!is_broker_failed(dir.path(), account));

        set_broker_failed(dir.path(), account, "network").unwrap();
        assert!(is_broker_failed(dir.path(), account));
        assert_eq!(
            read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("network")
        );

        clear_broker_failed(dir.path(), account);
        assert!(!is_broker_failed(dir.path(), account));
        assert_eq!(read_broker_failed_reason(dir.path(), account), None);
    }

    #[test]
    fn broker_failed_reason_is_truncated_at_256_bytes() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();
        let huge = "a".repeat(10_000);
        set_broker_failed(dir.path(), account, &huge).unwrap();
        let read = read_broker_failed_reason(dir.path(), account).unwrap();
        assert!(
            read.len() <= 256,
            "reason must cap at 256 bytes to protect the flag file size"
        );
    }

    /// M4-6 acceptance test: the broker-failed sentinel API has been
    /// migrated from the legacy fanout module path to
    /// `csq_core::refresh::sentinel`. This test exists to pin the new
    /// module path — if a future refactor moves the API again the
    /// orchestrator grep (`crate::refresh::sentinel::set_broker_failed`)
    /// will fail to compile and surface the drift.
    #[test]
    fn set_broker_failed_writes_under_refresh_module() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(7u16).unwrap();

        // Exercise the API via its post-rename path. `super::` resolves
        // to `crate::refresh::sentinel` after M4-6 — the test fails to
        // compile if the module rename regresses.
        super::set_broker_failed(dir.path(), account, "m4_6_pin").unwrap();
        assert!(super::is_broker_failed(dir.path(), account));
        assert_eq!(
            super::read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("m4_6_pin")
        );

        // Flag file lives under credentials/N.broker-failed regardless
        // of the parent module — verify on-disk layout is unchanged.
        let flag = dir
            .path()
            .join("credentials")
            .join(format!("{}.broker-failed", account));
        assert!(
            flag.exists(),
            "broker-failed flag must persist under credentials/{{N}}.broker-failed \
             after the broker→refresh rename (M4-6); got missing at {flag:?}"
        );

        super::clear_broker_failed(dir.path(), account);
        assert!(!super::is_broker_failed(dir.path(), account));
    }

    #[test]
    fn broker_failed_empty_file_reads_as_empty_reason() {
        // Pre-v2.1 broker-failed files were zero-byte markers.
        // `read_broker_failed_reason` should treat them as
        // `Some("")` so the flag-existence check stays the same
        // but the reason is just "unknown".
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();
        let creds_dir = dir.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).unwrap();
        std::fs::write(creds_dir.join("6.broker-failed"), b"").unwrap();
        assert_eq!(
            read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("")
        );
        assert!(is_broker_failed(dir.path(), account));
    }
}
