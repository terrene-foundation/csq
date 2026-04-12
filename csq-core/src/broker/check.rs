//! Broker check — per-account token refresh with lock coordination.
//!
//! Called periodically (every 5 minutes) by the daemon or statusline.
//! Uses try-lock to ensure only one process refreshes at a time.

use super::fanout;
use crate::credentials::{self, file, refresh, CredentialFile};
use crate::error::{BrokerError, CsqError};
use crate::platform::lock;
use crate::types::AccountNum;
use std::path::Path;
use tracing::{debug, info, warn};

/// Refresh window: refresh if token expires within this many seconds.
/// 2 hours = 7200 seconds, per ADR-006.
const REFRESH_WINDOW_SECS: u64 = 7200;

/// Result of a broker check.
#[derive(Debug)]
pub enum BrokerResult {
    /// Token is still valid, no action taken.
    Valid,
    /// Token was refreshed successfully.
    Refreshed,
    /// Another process is already refreshing (lock contention).
    Skipped,
    /// Refresh failed but recovery succeeded.
    Recovered,
    /// Total failure — LOGIN-NEEDED.
    Failed(BrokerError),
}

/// Performs a broker check for a single account.
///
/// 1. Reads canonical credentials
/// 2. Checks if token is near expiry (2-hour window)
/// 3. Acquires per-account try-lock (skips if contention)
/// 4. Refreshes token via HTTP
/// 5. Fans out to all matching config directories
///
/// The `http_post` parameter allows injection of the HTTP transport.
pub fn broker_check<F>(
    base_dir: &Path,
    account: AccountNum,
    http_post: F,
) -> Result<BrokerResult, CsqError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String> + Clone,
{
    let canonical_path = file::canonical_path(base_dir, account);
    let creds = match credentials::load(&canonical_path) {
        Ok(c) => c,
        Err(e) => return Err(CsqError::Credential(e)),
    };

    // Check if token needs refresh
    if !creds.claude_ai_oauth.is_expired_within(REFRESH_WINDOW_SECS) {
        return Ok(BrokerResult::Valid);
    }

    debug!(account = %account, "token near expiry, attempting refresh");

    // Try-lock per account (non-blocking)
    let lock_path = canonical_path.with_extension("refresh-lock");
    let guard = match lock::try_lock_file(&lock_path)? {
        Some(g) => g,
        None => {
            debug!(account = %account, "refresh lock held by another process, skipping");
            return Ok(BrokerResult::Skipped);
        }
    };

    // CRITICAL: Re-read canonical INSIDE the lock to prevent token ping-pong.
    // Another process may have refreshed between our first read and lock acquisition.
    // If we don't re-read, we'd call refresh with a stale RT that Anthropic has
    // already invalidated, forcing recovery and potentially corrupting state.
    let creds = match credentials::load(&canonical_path) {
        Ok(c) => c,
        Err(e) => {
            drop(guard);
            return Err(CsqError::Credential(e));
        }
    };
    if !creds.claude_ai_oauth.is_expired_within(REFRESH_WINDOW_SECS) {
        debug!(account = %account, "another process refreshed already, returning Valid");
        drop(guard);
        return Ok(BrokerResult::Valid);
    }

    // Attempt refresh
    match do_refresh(base_dir, account, &creds, http_post.clone()) {
        Ok(()) => {
            fanout::clear_broker_failed(base_dir, account);
            drop(guard);
            Ok(BrokerResult::Refreshed)
        }
        Err(primary_err) => {
            // Primary refresh failed — attempt recovery from live siblings
            info!(account = %account, "primary refresh failed, attempting recovery");
            match recover_from_siblings(base_dir, account, http_post) {
                Ok(()) => {
                    fanout::clear_broker_failed(base_dir, account);
                    drop(guard);
                    Ok(BrokerResult::Recovered)
                }
                Err(recovery_err) => {
                    // Log the recovery-error kind so ops can see
                    // why both paths failed. The raw `e.to_string()`
                    // of the recovery error still flows into
                    // BrokerResult::Failed for the HTTP API
                    // (redacted at the command boundary), but the
                    // flag file gets a fixed-vocabulary tag so the
                    // dashboard can render "Expired — <tag>"
                    // without any risk of token leakage.
                    let reason_tag = crate::error::error_kind_tag(&recovery_err);
                    warn!(
                        account = %account,
                        error_kind = reason_tag,
                        "broker recovery failed"
                    );
                    let _ = fanout::set_broker_failed(base_dir, account, reason_tag);
                    drop(guard);
                    // Keep the `reason` field of RefreshFailed as
                    // the string form of the recovery error — the
                    // refresher logs this via error_kind_tag too,
                    // not via Display, so the tight-vocabulary
                    // contract holds end-to-end.
                    let _ = primary_err; // not currently surfaced
                    Ok(BrokerResult::Failed(BrokerError::RefreshFailed {
                        account: account.get(),
                        reason: recovery_err.to_string(),
                    }))
                }
            }
        }
    }
}

/// Performs the actual token refresh and saves the result.
fn do_refresh<F>(
    base_dir: &Path,
    account: AccountNum,
    creds: &CredentialFile,
    http_post: F,
) -> Result<(), CsqError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String>,
{
    let refreshed = refresh::refresh_token(creds, http_post)?;

    // Save to canonical
    file::save_canonical(base_dir, account, &refreshed)?;

    // Fan out to all matching config dirs
    let count = fanout::fan_out_credentials(base_dir, account, &refreshed);
    debug!(account = %account, dirs = count, "fanout complete");

    Ok(())
}

/// Attempts recovery when the canonical refresh token is dead.
///
/// Scans all `config-*/.credentials.json` for a live RT that differs
/// from canonical. If found, promotes it to canonical and retries refresh.
/// On total failure, restores the original canonical.
fn recover_from_siblings<F>(
    base_dir: &Path,
    account: AccountNum,
    http_post: F,
) -> Result<(), CsqError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String>,
{
    let canonical_path = file::canonical_path(base_dir, account);
    let original = credentials::load(&canonical_path)?;
    let original_rt = original
        .claude_ai_oauth
        .refresh_token
        .expose_secret()
        .to_string();

    let dirs = fanout::scan_config_dirs(base_dir, account);
    let mut tried = 0;

    for dir in &dirs {
        let live_path = dir.join(".credentials.json");
        let live = match credentials::load(&live_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let live_rt = live.claude_ai_oauth.refresh_token.expose_secret();
        if live_rt == original_rt {
            continue; // Same dead RT, skip
        }

        tried += 1;
        debug!(
            account = %account,
            dir = %dir.display(),
            "trying sibling RT for recovery"
        );

        // Promote sibling credentials to canonical
        credentials::save(&canonical_path, &live)?;

        // Try refresh with the promoted RT using the provided HTTP function
        // Recovery gets exactly one attempt — the http_post is consumed
        match do_refresh(base_dir, account, &live, http_post) {
            Ok(()) => return Ok(()),
            Err(_) => {
                // Restore original ONLY if the current canonical is not newer
                // than our snapshot — prevents downgrade attacks / races
                // where another process successfully refreshed while we were
                // trying a sibling.
                restore_if_not_downgraded(&canonical_path, &original);
                return Err(CsqError::Broker(BrokerError::RecoveryFailed {
                    account: account.get(),
                    tried,
                }));
            }
        }
    }

    // Total failure — restore original (with monotonicity guard)
    restore_if_not_downgraded(&canonical_path, &original);

    Err(CsqError::Broker(BrokerError::RecoveryFailed {
        account: account.get(),
        tried,
    }))
}

/// Restores `original` to the canonical path ONLY if the current canonical
/// is not already newer. Prevents downgrade attacks and concurrent-refresh
/// races where another process successfully refreshed while we were in
/// the recovery path.
fn restore_if_not_downgraded(canonical_path: &Path, original: &CredentialFile) {
    if let Ok(current) = credentials::load(canonical_path) {
        if current.claude_ai_oauth.expires_at > original.claude_ai_oauth.expires_at {
            debug!("skipping recovery restore: canonical is newer than original snapshot");
            return;
        }
    }
    let _ = credentials::save(canonical_path, original);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::markers;
    use crate::credentials::{CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn make_creds(access: &str, refresh: &str, expires_at: u64) -> CredentialFile {
        CredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new(access.into()),
                refresh_token: RefreshToken::new(refresh.into()),
                expires_at,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: HashMap::new(),
            },
            extra: HashMap::new(),
        }
    }

    fn mock_refresh_success(_url: &str, _body: &str) -> Result<Vec<u8>, String> {
        Ok(
            br#"{"access_token":"at-refreshed","refresh_token":"rt-refreshed","expires_in":18000}"#
                .to_vec(),
        )
    }

    fn mock_refresh_failure(_url: &str, _body: &str) -> Result<Vec<u8>, String> {
        Err("401 Unauthorized".into())
    }

    #[test]
    fn broker_check_valid_token_no_refresh() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(1u16).unwrap();

        // Far-future expiry
        let creds = make_creds("at-1", "rt-1", 9999999999999);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Valid));
    }

    #[test]
    fn broker_check_expired_token_refreshes() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(2u16).unwrap();

        // Already expired
        let creds = make_creds("at-2", "rt-2", 0);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));

        // Verify canonical was updated
        let updated = credentials::load(&file::canonical_path(dir.path(), account)).unwrap();
        assert_eq!(
            updated.claude_ai_oauth.access_token.expose_secret(),
            "at-refreshed"
        );
    }

    #[test]
    fn broker_check_failed_sets_flag() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(3u16).unwrap();

        let creds = make_creds("at-3", "rt-3", 0);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_failure).unwrap();
        assert!(matches!(result, BrokerResult::Failed(_)));
        assert!(fanout::is_broker_failed(dir.path(), account));
    }

    #[test]
    fn broker_check_success_clears_flag() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(4u16).unwrap();

        let creds = make_creds("at-4", "rt-4", 0);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        // Set flag first
        fanout::set_broker_failed(dir.path(), account, "test_reason").unwrap();
        assert!(fanout::is_broker_failed(dir.path(), account));
        assert_eq!(
            fanout::read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("test_reason")
        );

        // Successful refresh clears it
        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));
        assert!(!fanout::is_broker_failed(dir.path(), account));
    }

    #[test]
    fn broker_check_fans_out_to_config_dirs() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();

        // Set up expired canonical
        let creds = make_creds("at-5", "rt-5", 0);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        // Set up two config dirs for the same account
        let config_a = dir.path().join("config-51");
        let config_b = dir.path().join("config-52");
        std::fs::create_dir_all(&config_a).unwrap();
        std::fs::create_dir_all(&config_b).unwrap();
        markers::write_csq_account(&config_a, account).unwrap();
        markers::write_csq_account(&config_b, account).unwrap();
        credentials::save(&config_a.join(".credentials.json"), &creds).unwrap();
        credentials::save(&config_b.join(".credentials.json"), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));

        // Both config dirs should have the new token
        let a = credentials::load(&config_a.join(".credentials.json")).unwrap();
        let b = credentials::load(&config_b.join(".credentials.json")).unwrap();
        assert_eq!(
            a.claude_ai_oauth.access_token.expose_secret(),
            "at-refreshed"
        );
        assert_eq!(
            b.claude_ai_oauth.access_token.expose_secret(),
            "at-refreshed"
        );
    }

    #[test]
    fn broker_concurrent_exactly_one_refresh() {
        use std::thread;

        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();

        // Expired token
        let creds = make_creds("at-6", "rt-6", 0);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let refresh_count = Arc::new(AtomicU32::new(0));
        let base = dir.path().to_path_buf();

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let base = base.clone();
                let count = Arc::clone(&refresh_count);
                thread::spawn(move || {
                    let result = broker_check(&base, account, |url, body| {
                        count.fetch_add(1, Ordering::SeqCst);
                        // Small delay to increase contention window
                        thread::sleep(std::time::Duration::from_millis(10));
                        mock_refresh_success(url, body)
                    });
                    result.unwrap()
                })
            })
            .collect();

        for h in handles {
            match h.join().unwrap() {
                BrokerResult::Refreshed | BrokerResult::Skipped | BrokerResult::Valid => {}
                other => panic!("unexpected: {other:?}"),
            }
        }

        // With the re-read-inside-lock logic (C6 fix), the first thread
        // that acquires the lock performs the single refresh. Every
        // subsequent thread either:
        //   (a) sees the lock held and returns Skipped without touching
        //       http_post, or
        //   (b) waits for the lock, re-reads canonical, finds it no
        //       longer near-expiry, and returns Valid without touching
        //       http_post.
        //
        // Either way, exactly one thread ever calls the http_post
        // closure. Any number >1 means the lock is not coordinating
        // correctly and must be investigated — not hidden with a
        // looser bound.
        let total_calls = refresh_count.load(Ordering::SeqCst);
        assert_eq!(
            total_calls, 1,
            "expected exactly 1 refresh call with lock coordination, got {total_calls}"
        );
    }
}
