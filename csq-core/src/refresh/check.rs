//! Broker check — per-account token refresh with lock coordination.
//!
//! Called periodically (every 5 minutes) by the daemon or statusline.
//! Uses try-lock to ensure only one process refreshes at a time.

use super::sentinel;
use crate::accounts::{identity_store, profiles};
use crate::credentials::{self, file, refresh, CredentialFile};
use crate::error::{BrokerError, CsqError};
use crate::http::codex as http_codex;
use crate::platform::lock;
use crate::types::AccountNum;
use std::path::Path;
use tracing::{debug, warn};

/// Refresh window: refresh if token expires within this many seconds.
/// 2 hours = 7200 seconds, per ADR-006.
pub const REFRESH_WINDOW_SECS: u64 = 7200;

/// Result of a broker check.
#[derive(Debug)]
pub enum BrokerResult {
    /// Token is still valid, no action taken.
    Valid,
    /// Token was refreshed successfully.
    Refreshed,
    /// Another process is already refreshing (lock contention).
    /// The caller should NOT set a cooldown — the lock holder is
    /// doing the work and we'll pick up the result on the next tick.
    Skipped,
    /// Anthropic returned a rate-limit error (429 / `rate_limit_error`)
    /// for the primary refresh. Sibling recovery was suppressed to
    /// avoid further hammering the throttled endpoint. The caller
    /// MUST set a cooldown so the next tick does not retry immediately.
    RateLimited,
    /// Total failure — LOGIN-NEEDED.
    Failed(BrokerError),
}

/// Performs a broker check for a single account.
///
/// 1. Reads canonical credentials
/// 2. Checks if token is near expiry (2-hour window)
/// 3. Acquires per-account try-lock (skips if contention)
/// 4. Refreshes token via HTTP and writes to canonical (M3-7: live-mirror
///    fanout retired; handle-dir symlinks resolve to identity path)
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
    // RN1-C (M4-12): resolve UUID-keyed identity path when by_slot is populated.
    // The numeric credentials/N.json path is retired as a WRITE destination;
    // post-login accounts have credentials ONLY at identities/<UUID>/credentials.json.
    // Mirrors the pattern already used in broker_codex_check (lines 236-242).
    // Fail-closed when no UUID mapping exists: return NoCredentials so the
    // daemon surfaces LOGIN-NEEDED rather than silently reading a stale numeric file.
    let canonical_path = match profiles::resolve_slot_to_uuid(base_dir, account.get()) {
        Some(uuid) => identity_store::credentials_path_for(base_dir, uuid),
        None => {
            // Legacy install with no by_slot entry — fall back to numeric path.
            // Pre-RN1-C accounts never went through mint_for_login, so the numeric
            // file is the authoritative read source until they re-login or Pass 0 runs.
            file::canonical_path(base_dir, account)
        }
    };
    let creds = match credentials::load(&canonical_path) {
        Ok(c) => c,
        Err(e) => return Err(CsqError::Credential(e)),
    };

    // Check if token needs refresh
    if !creds
        .expect_anthropic()
        .claude_ai_oauth
        .is_expired_within(REFRESH_WINDOW_SECS)
    {
        // Auto-clear stale broker_failed sentinel — if the daemon checked
        // this slot and the creds are healthy, any prior failure flag is
        // obsolete. Without this, a sentinel from a transient outage
        // (e.g. a prior refresh attempt that hit `token_invalidated`)
        // persists until the next genuine pre-expiry refresh window
        // (which may be days away).
        sentinel::clear_broker_failed(base_dir, account);
        return Ok(BrokerResult::Valid);
    }

    debug!(account = %account, "token near expiry, attempting refresh");

    // Try-lock per account (non-blocking). Lock file co-located with the
    // resolved canonical credential file so lock and credential are always
    // in the same directory — avoids split-directory lock coordination bugs.
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
    // Use the SAME resolved canonical_path as the initial read (UUID or legacy).
    let creds = match credentials::load(&canonical_path) {
        Ok(c) => c,
        Err(e) => {
            drop(guard);
            return Err(CsqError::Credential(e));
        }
    };
    if !creds
        .expect_anthropic()
        .claude_ai_oauth
        .is_expired_within(REFRESH_WINDOW_SECS)
    {
        debug!(account = %account, "another process refreshed already, returning Valid");
        // Auto-clear stale broker_failed sentinel — see early-return Valid above.
        sentinel::clear_broker_failed(base_dir, account);
        drop(guard);
        return Ok(BrokerResult::Valid);
    }

    // Attempt refresh
    match do_refresh(base_dir, account, &creds, http_post) {
        Ok(()) => {
            sentinel::clear_broker_failed(base_dir, account);
            drop(guard);
            Ok(BrokerResult::Refreshed)
        }
        Err(primary_err) => {
            // On rate-limit errors, do NOT escalate — the throttled
            // endpoint will simply reject another request. Return
            // `RateLimited` so the refresher distinguishes this from
            // the "another process holds the lock" Skipped variant and
            // applies a cooldown. Preserving the existing broker_failed
            // flag state is correct: being throttled is not a re-login
            // condition.
            if is_rate_limited(&primary_err) {
                warn!(
                    account = %account,
                    "primary refresh hit rate limit"
                );
                drop(guard);
                return Ok(BrokerResult::RateLimited);
            }

            // M3-7: sibling-credential recovery retired. Pre-M3-7,
            // `recover_from_siblings` scanned `config-N/.credentials.json`
            // mirrors for a fresher RT that CC may have refreshed directly.
            // Post-M3-7 the mirror is gone — handle dirs read through
            // identity-keyed symlinks (M3-3/M3-4) and the daemon writes
            // canonical IS the only credential write path. A failed
            // primary refresh is therefore terminal for this tick:
            // surface broker_failed and let the user re-login.
            let reason_tag = crate::error::error_kind_tag(&primary_err);
            warn!(
                account = %account,
                error_kind = reason_tag,
                "primary refresh failed; sibling-recovery retired in Phase 3"
            );
            let _ = sentinel::set_broker_failed(base_dir, account, reason_tag);
            drop(guard);
            // R1 M3-Sec fix-wave: `primary_err.to_string()` Display chain can
            // include `serde_json::Error` or upstream HTTP body bytes that
            // echo the submitted refresh token back. Redact before storing
            // in the `reason` field (which is surfaced via `RefreshStatus`
            // → IPC → frontend). Per security.md MUST Rule 8 / an internal journal entry
            Ok(BrokerResult::Failed(BrokerError::RefreshFailed {
                account: account.get(),
                reason: crate::error::redact_tokens(&primary_err.to_string()),
            }))
        }
    }
}

/// Performs the actual token refresh and writes canonical.
///
/// M3-7: live-mirror fanout retired. `save_canonical_for` writes
/// `identities/<UUID>/credentials.json` (primary) + `credentials/N.json`
/// (legacy canonical). Handle dirs read credentials through their symlink
/// which resolves (post-M3-3/M3-4) to the identity path — no fanout needed.
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

    // Save to canonical (writes identity-keyed path only; M4-12:
    // numeric credential files retired — fail-closed if UUID absent).
    file::save_canonical_for(base_dir, account, &refreshed)?;

    Ok(())
}

/// Codex sibling of [`broker_check`].
///
/// Performs a single Codex slot's pre-expiry refresh per spec 07
/// §7.5 INV-P01:
///
/// 1. Loads `identities/<UUID>/credentials-codex.json` when
///    `profiles.json::by_slot[N]` is populated (M4-4); falls back to
///    `credentials/codex-<N>.json` when no UUID mapping exists.
/// 2. Decodes the JWT `exp` claim from `tokens.access_token`.
/// 3. If exp is more than 2h away ([`REFRESH_WINDOW_SECS`]),
///    returns [`BrokerResult::Valid`] without HTTP.
/// 4. Acquires the per-slot try-lock (`refresh-lock` next to the
///    canonical credential file). Lock contention →
///    [`BrokerResult::Skipped`].
/// 5. Re-reads canonical inside the lock to absorb a refresh another
///    process may have just landed (mirrors `broker_check`'s
///    re-read-inside-lock guard against ping-pong).
/// 6. Calls [`http_codex::refresh_with_http_meta`] with the injected
///    transport. The transport returns body + Date header so we can
///    emit `clock_skew_detected` per INV-P01.
/// 7. On `code: "token_expired"` / `"refresh_token_reused"` →
///    [`BrokerResult::Failed`] with the typed
///    [`BrokerError::CodexTokenExpired`] / [`BrokerError::CodexRefreshReused`]
///    variant. Sets the broker_failed flag so subsequent reads (and
///    the statusline LOGIN-NEEDED indicator) see it. Maps to
///    `LOGIN_REQUIRED:` at the IPC boundary via the existing
///    `From<CsqError> for String` impl in `error.rs`.
/// 8. On HTTP 429 → [`BrokerResult::RateLimited`].
/// 9. On success: builds a merged [`CredentialFile::Codex`]
///    (preserving `auth_mode`, `openai_api_key`, `extra`) and writes
///    via [`file::save_canonical_for`] which already coordinates the
///    per-account write mutex (INV-P09) and flips the canonical from
///    0o400 → write at 0o600 → 0o400 (INV-P08). The pre-M3-7
///    `config-<N>/codex-auth.json` mirror write is retired; handle
///    dirs read through their identity-keyed symlink (spec 07 §7.2.2).
///
/// Unlike Anthropic [`broker_check`], there is NO sibling-recovery
/// pass: Codex's RT is single-use (openai/codex#10332), so reading
/// a sibling's RT and trying it would burn a second token. A failed
/// refresh is terminal — the user re-authenticates via
/// `csq login N --provider codex`.
pub fn broker_codex_check<F>(
    base_dir: &Path,
    account: AccountNum,
    http_post: F,
) -> Result<BrokerResult, CsqError>
where
    F: FnOnce(&str, &str) -> Result<(Vec<u8>, Option<String>), String>,
{
    use crate::providers::catalog::Surface;

    // M4-4: resolve through UUID-keyed identity path when by_slot is
    // populated, matching tick's read path so broker_codex_check sees
    // the same credential file that tick's expiry check reads.
    // Legacy fallback: if no UUID mapping exists, use numeric path.
    let canonical_path =
        match crate::accounts::profiles::resolve_slot_to_uuid(base_dir, account.get()) {
            Some(uuid) => {
                crate::accounts::identity_store::credentials_codex_path_for(base_dir, uuid)
            }
            None => file::canonical_path_for(base_dir, account, Surface::Codex),
        };
    let creds = credentials::load(&canonical_path)?;
    let codex = creds
        .codex()
        .ok_or_else(|| codex_shape_mismatch_err(account, &canonical_path))?;

    let now_s = now_secs();
    if !codex_is_expired_within(codex, REFRESH_WINDOW_SECS, now_s) {
        // Auto-clear stale broker_failed sentinel — symmetric to broker_check's
        // Anthropic Valid path. See that branch for rationale.
        sentinel::clear_broker_failed(base_dir, account);
        return Ok(BrokerResult::Valid);
    }

    debug!(account = %account, surface = "codex", "codex token near expiry, attempting refresh");

    // Per-slot try-lock (sibling of Anthropic's `refresh-lock`).
    let lock_path = canonical_path.with_extension("refresh-lock");
    let guard = match lock::try_lock_file(&lock_path)? {
        Some(g) => g,
        None => {
            debug!(
                account = %account,
                surface = "codex",
                "codex refresh lock held by another process, skipping"
            );
            return Ok(BrokerResult::Skipped);
        }
    };

    // Re-read INSIDE the lock — a sibling process may have refreshed.
    let creds = credentials::load(&canonical_path)?;
    let codex = creds
        .codex()
        .ok_or_else(|| codex_shape_mismatch_err(account, &canonical_path))?;
    let now_s = now_secs();
    if !codex_is_expired_within(codex, REFRESH_WINDOW_SECS, now_s) {
        debug!(account = %account, surface = "codex", "another process refreshed already");
        // Auto-clear stale broker_failed sentinel — see early-return Valid above.
        sentinel::clear_broker_failed(base_dir, account);
        drop(guard);
        return Ok(BrokerResult::Valid);
    }

    let refresh_token = match codex.tokens.refresh_token.as_deref() {
        Some(rt) if !rt.is_empty() => rt,
        _ => {
            // Codex slot has no refresh token → user must re-login.
            // Set the failed flag so the statusline / dashboard reflect it.
            drop(guard);
            let _ = sentinel::set_broker_failed(base_dir, account, "codex_token_expired");
            return Ok(BrokerResult::Failed(BrokerError::CodexTokenExpired {
                account: account.get(),
            }));
        }
    };

    let (new_tokens, server_date) =
        match http_codex::refresh_with_http_meta(refresh_token, http_post) {
            Ok(pair) => pair,
            Err(http_codex::CodexHttpError::TokenExpired) => {
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "codex_token_expired",
                    "codex refresh: token_expired (LOGIN-NEEDED)"
                );
                let _ = sentinel::set_broker_failed(base_dir, account, "codex_token_expired");
                drop(guard);
                return Ok(BrokerResult::Failed(BrokerError::CodexTokenExpired {
                    account: account.get(),
                }));
            }
            Err(http_codex::CodexHttpError::RefreshReused) => {
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "codex_refresh_reused",
                    "codex refresh: refresh_token_reused (LOGIN-NEEDED)"
                );
                let _ = sentinel::set_broker_failed(base_dir, account, "codex_refresh_reused");
                drop(guard);
                return Ok(BrokerResult::Failed(BrokerError::CodexRefreshReused {
                    account: account.get(),
                }));
            }
            Err(http_codex::CodexHttpError::Upstream { status: 429, .. }) => {
                warn!(
                    account = %account,
                    surface = "codex",
                    "codex refresh: rate limited"
                );
                drop(guard);
                return Ok(BrokerResult::RateLimited);
            }
            Err(other) => {
                // Convert into a BrokerError. Display only the fixed-vocabulary
                // tag, never the raw upstream body — `CodexHttpError::Display`
                // is already body-fragment-safe (see http::codex tests), but
                // the warn-log site emits an `error_kind` rather than `error`
                // formatter to defend against any future Display refactor.
                let broker_err = other.into_broker(account.get());
                // Compute the kind tag inline rather than wrapping into
                // CsqError just to call `error_kind_tag` — avoids needing a
                // Clone bound on BrokerError.
                let kind: &'static str = match &broker_err {
                    BrokerError::CodexTokenExpired { .. } => "codex_token_expired",
                    BrokerError::CodexRefreshReused { .. } => "codex_refresh_reused",
                    BrokerError::CodexTokenInvalidated { .. } => "codex_token_invalidated",
                    BrokerError::RefreshTokenInvalid { .. } => "broker_token_invalid",
                    BrokerError::RefreshFailed { .. } => "broker_refresh_failed",
                };
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = kind,
                    "codex refresh failed"
                );
                let _ = sentinel::set_broker_failed(base_dir, account, kind);
                drop(guard);
                return Ok(BrokerResult::Failed(broker_err));
            }
        };

    // Clock-skew check (INV-P01). After a successful refresh we have the
    // server's `Date` header — compare to local clock. Warn (but do not
    // fail) when drift exceeds 5 min, because that's the threshold beyond
    // which the daemon's 2h pre-expiry window starts to risk overlap with
    // codex-cli's on-expiry threshold.
    if let Some(date) = server_date.as_deref() {
        if let Some(server_secs) = http_codex::parse_http_date_secs(date) {
            let local = now_secs();
            let drift = local.abs_diff(server_secs);
            if drift > http_codex::CLOCK_SKEW_WARN_SECS {
                warn!(
                    account = %account,
                    surface = "codex",
                    error_kind = "clock_skew_detected",
                    drift_secs = drift,
                    "local clock differs from server `Date` header by > 5 min — \
                     INV-P01 pre-expiry refresh may miss codex on-expiry threshold"
                );
            }
        }
    }

    // Build the merged credential file. Preserves `auth_mode`,
    // `openai_api_key`, `extra` from the existing file; updates the
    // token triple from the refresh response. `last_refresh` is set to
    // ISO-8601 of now so a sibling read can sanity-check freshness.
    let merged = merge_codex_refresh(&creds, &new_tokens);

    // save_canonical_for handles INV-P08 (0o400↔0o600 dance) + INV-P09
    // (per-account mutex) + atomic_replace + live mirror.
    file::save_canonical_for(base_dir, account, &merged)?;

    sentinel::clear_broker_failed(base_dir, account);
    drop(guard);
    Ok(BrokerResult::Refreshed)
}

fn codex_shape_mismatch_err(account: AccountNum, path: &Path) -> CsqError {
    CsqError::Credential(crate::error::CredentialError::Corrupt {
        path: path.to_path_buf(),
        reason: format!(
            "expected Codex credential variant for slot {account}; got Anthropic shape — \
             discovery filenames disagree with payload (operator should re-run \
             `csq login {account} --provider codex` or remove the bad file)"
        ),
    })
}

/// Returns true if the Codex slot's access-token JWT exp claim is
/// within `buffer_secs` of `now_s` (or is undecodeable, which is
/// treated as "needs refresh now").
fn codex_is_expired_within(
    codex: &crate::credentials::CodexCredentialFile,
    buffer_secs: u64,
    now_s: u64,
) -> bool {
    match http_codex::jwt_exp_secs(&codex.tokens.access_token) {
        Some(exp) => exp <= now_s + buffer_secs,
        // Undecodeable JWT — be safe, refresh.
        None => true,
    }
}

/// Builds a fresh `CredentialFile::Codex` from the existing one plus
/// new tokens from `/oauth/token`. Preserves every field except the
/// token triple + `last_refresh`.
///
/// Honors OpenAI's single-use refresh-token semantics: if the response
/// omits a new refresh_token (which the parser allows via `Option`),
/// we keep the existing one — but in production this never happens
/// because `/oauth/token` always returns a rotated RT.
fn merge_codex_refresh(
    existing: &CredentialFile,
    new_tokens: &http_codex::CodexTokens,
) -> CredentialFile {
    let mut next = existing.clone();
    if let Some(c) = next.codex_mut() {
        c.tokens.access_token = new_tokens.access_token.clone();
        if let Some(rt) = &new_tokens.refresh_token {
            c.tokens.refresh_token = Some(rt.clone());
        }
        if let Some(id) = &new_tokens.id_token {
            c.tokens.id_token = Some(id.clone());
        }
        // account_id is set on first login and does not change on refresh —
        // preserve the existing value rather than overwriting from the
        // (possibly absent) field on the refresh response.
        c.last_refresh = Some(rfc3339_now());
    }
    next
}

fn rfc3339_now() -> String {
    let secs = now_secs();
    // YYYY-MM-DDTHH:MM:SSZ assembled from secs since epoch — avoids a
    // chrono dependency. Uses the same days-since-epoch math as
    // http::codex::parse_http_date_secs.
    let days = secs / 86_400;
    let s = secs % 86_400;
    let hour = s / 3_600;
    let minute = (s % 3_600) / 60;
    let second = s % 60;
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let mut remaining = days;
    let mut year: u32 = 1970;
    loop {
        let yr_len: u64 =
            if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) {
                366
            } else {
                365
            };
        if remaining < yr_len {
            break;
        }
        remaining -= yr_len;
        year += 1;
    }
    let mut month_days: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) {
        month_days[1] = 29;
    }
    let mut month: u32 = 1;
    for &d in &month_days {
        if remaining < d {
            break;
        }
        remaining -= d;
        month += 1;
    }
    let day = (remaining as u32) + 1;
    (year, month, day)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Returns `true` if `e` looks like an Anthropic rate-limit error.
///
/// We match on the Display string because the refresh error path
/// wraps structured response bodies through `OAuthError::Exchange`
/// without preserving the HTTP status. Anthropic returns
/// `{"error":{"type":"rate_limit_error", ...}}` for 429s, which
/// `extract_oauth_error` stringifies as `rate_limit_error: ...`.
fn is_rate_limited(e: &CsqError) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("rate_limit") || msg.contains("rate limit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::markers;
    use crate::credentials::{AnthropicCredentialFile, CredentialFile, OAuthPayload};
    use crate::types::{AccessToken, RefreshToken};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;

    /// Provisions a deterministic UUID mapping in `profiles.json::by_slot` for
    /// the given account number. Required because `save_canonical_for` is
    /// fail-closed (M4-12): it returns `Err(NoCredentials)` when no UUID
    /// mapping exists, which would cause broker_check / broker_codex_check
    /// to fail at the canonical write step after a successful refresh.
    fn provision_uuid_for_account(base: &std::path::Path, account: u16) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let profiles_path = crate::accounts::profiles::profiles_path(base);
        let mut profiles = if profiles_path.exists() {
            crate::accounts::profiles::load(&profiles_path)
                .unwrap_or_else(|_| crate::accounts::profiles::ProfilesFile::empty())
        } else {
            crate::accounts::profiles::ProfilesFile::empty()
        };
        profiles.by_slot.insert(account.to_string(), uuid);
        crate::accounts::profiles::save(&profiles_path, &profiles).unwrap();
    }

    /// Writes credentials to the UUID-keyed identity path when by_slot is populated.
    /// RN1-C: broker_check reads the UUID path, so test setup must seed it.
    fn save_creds_uuid(base: &std::path::Path, account: u16, creds: &CredentialFile) {
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(base, uuid);
        std::fs::create_dir_all(uuid_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_path, creds).unwrap();
    }

    fn make_creds(access: &str, refresh: &str, expires_at: u64) -> CredentialFile {
        CredentialFile::Anthropic(AnthropicCredentialFile {
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
        })
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

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path after a successful refresh.
        provision_uuid_for_account(dir.path(), 2);

        // RN1-C: broker_check now reads the UUID path; seed initial expired creds there.
        // Also seed numeric path so existing read fallback is covered.
        let creds = make_creds("at-2", "rt-2", 0);
        save_creds_uuid(dir.path(), 2, &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));

        // Verify canonical was updated — read from UUID-keyed identity path.
        // M4-12: save_canonical_for writes to identities/<UUID>/credentials.json;
        // numeric path (credentials/2.json) is no longer the write destination.
        let uuid2 = crate::testing::identity_fixtures::fixture_uuid_for_slot(2);
        let uuid_path2 = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid2);
        let updated = credentials::load(&uuid_path2).unwrap();
        assert_eq!(
            updated
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
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
        assert!(sentinel::is_broker_failed(dir.path(), account));
    }

    #[test]
    fn broker_check_success_clears_flag() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(4u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path after a successful refresh.
        provision_uuid_for_account(dir.path(), 4);

        // RN1-C: broker_check now reads the UUID path; seed initial expired creds there.
        let creds = make_creds("at-4", "rt-4", 0);
        save_creds_uuid(dir.path(), 4, &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        // Set flag first
        sentinel::set_broker_failed(dir.path(), account, "test_reason").unwrap();
        assert!(sentinel::is_broker_failed(dir.path(), account));
        assert_eq!(
            sentinel::read_broker_failed_reason(dir.path(), account).as_deref(),
            Some("test_reason")
        );

        // Successful refresh clears it
        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));
        assert!(!sentinel::is_broker_failed(dir.path(), account));
    }

    /// M3-7 regression-pin: broker_check no longer fans out to
    /// `config-<N>/.credentials.json` mirrors. Pre-M3-7, this test
    /// asserted the new token landed in every config-N mirror. Post-M3-7,
    /// the mirror writers are retired; the test now asserts the mirrors
    /// remain at their seed content (not overwritten with the refreshed
    /// token). Handle dirs see refreshed credentials via their identity-
    /// keyed symlinks instead.
    #[test]
    fn broker_check_does_not_fan_out_to_config_dirs() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(5u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path after a successful refresh.
        provision_uuid_for_account(dir.path(), 5);

        // RN1-C: broker_check now reads the UUID path; seed initial expired creds there.
        let creds = make_creds("at-5", "rt-5", 0);
        save_creds_uuid(dir.path(), 5, &creds);
        credentials::save(&file::canonical_path(dir.path(), account), &creds).unwrap();

        // Set up two config dirs for the same account with seed credentials
        let config_a = dir.path().join("config-51");
        let config_b = dir.path().join("config-52");
        std::fs::create_dir_all(&config_a).unwrap();
        std::fs::create_dir_all(&config_b).unwrap();
        markers::write_csq_account_legacy(&config_a, account).unwrap();
        markers::write_csq_account_legacy(&config_b, account).unwrap();
        credentials::save(&config_a.join(".credentials.json"), &creds).unwrap();
        credentials::save(&config_b.join(".credentials.json"), &creds).unwrap();

        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));

        // M3-7: live mirrors stay at seed content — fanout retired.
        let a = credentials::load(&config_a.join(".credentials.json")).unwrap();
        let b = credentials::load(&config_b.join(".credentials.json")).unwrap();
        assert_eq!(
            a.expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-5",
            "M3-7: config-N/.credentials.json mirror MUST NOT be overwritten by fanout"
        );
        assert_eq!(
            b.expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-5",
            "M3-7: config-N/.credentials.json mirror MUST NOT be overwritten by fanout"
        );

        // M4-12: UUID-keyed identity path carries the refreshed token
        // (numeric path is no longer the write destination).
        let uuid5 = crate::testing::identity_fixtures::fixture_uuid_for_slot(5);
        let uuid_path5 = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid5);
        let canonical = credentials::load(&uuid_path5).unwrap();
        assert_eq!(
            canonical
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed",
            "M4-12: UUID-keyed identity path MUST receive the refreshed token"
        );
    }

    /// RN1-C regression: broker_check MUST read from identities/<UUID>/credentials.json
    /// when by_slot is populated, NOT from the retired numeric credentials/N.json path.
    ///
    /// Setup: only identities/<UUID>/credentials.json exists (expired token).
    /// credentials/N.json does NOT exist — simulates a post-RN1-C account.
    /// Assert: broker_check returns Ok(Refreshed), not NotFound/Err.
    ///
    /// Pre-fix: broker_check read file::canonical_path (numeric) → file not found
    /// → every Anthropic slot hit LOGIN_REQUIRED on the first daemon tick.
    #[test]
    fn broker_check_reads_uuid_path_when_by_slot_populated() {
        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(20u16).unwrap();

        // Provision UUID mapping in by_slot (what mint_for_login/Pass0 write).
        provision_uuid_for_account(dir.path(), 20);
        let uuid20 = crate::testing::identity_fixtures::fixture_uuid_for_slot(20);

        // Write expired credentials ONLY to the UUID-keyed path.
        // The numeric credentials/20.json does NOT exist.
        let creds = make_creds("at-uuid-only", "rt-uuid-only", 0);
        let uuid_path = crate::accounts::identity_store::credentials_path_for(dir.path(), uuid20);
        std::fs::create_dir_all(uuid_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_path, &creds).unwrap();

        // Verify the numeric path does NOT exist.
        let numeric_path = file::canonical_path(dir.path(), account);
        assert!(
            !numeric_path.exists(),
            "test precondition: numeric credentials/N.json must NOT exist"
        );

        // Act: broker_check should read UUID path, find expired token, refresh.
        let result = broker_check(dir.path(), account, mock_refresh_success).unwrap();
        assert!(
            matches!(result, BrokerResult::Refreshed),
            "broker_check must resolve UUID path when by_slot populated, got {result:?}"
        );

        // Assert: UUID-keyed path carries the refreshed token.
        let updated = credentials::load(&uuid_path).unwrap();
        assert_eq!(
            updated
                .expect_anthropic()
                .claude_ai_oauth
                .access_token
                .expose_secret(),
            "at-refreshed",
            "UUID-keyed credentials.json must carry the refreshed access_token"
        );
    }

    #[test]
    fn broker_concurrent_exactly_one_refresh() {
        use std::thread;

        let dir = TempDir::new().unwrap();
        let account = AccountNum::try_from(6u16).unwrap();

        // M4-12: provision UUID mapping so save_canonical_for can write
        // via the identity-keyed path after a successful refresh.
        provision_uuid_for_account(dir.path(), 6);

        // RN1-C: broker_check now reads the UUID path; seed initial expired creds there.
        let creds = make_creds("at-6", "rt-6", 0);
        save_creds_uuid(dir.path(), 6, &creds);
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

    // ── broker_codex_check (PR-C4) ───────────────────────────────

    use crate::credentials::{CodexCredentialFile, CodexTokensFile};
    use crate::providers::catalog::Surface;

    /// Builds a JWT-shape `<header>.<payload>.<sig>` whose payload's
    /// `exp` claim is `exp_secs`. Header + sig are deterministic stubs.
    fn make_codex_jwt(exp_secs: u64) -> String {
        let payload = format!(r#"{{"exp":{exp_secs},"sub":"test"}}"#);
        let payload_b64 = base64url_encode(payload.as_bytes());
        // header={"alg":"HS256"} → base64url no-padding.
        let header_b64 = "eyJhbGciOiJIUzI1NiJ9";
        format!("{header_b64}.{payload_b64}.testsig")
    }

    fn base64url_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
        let mut buf: u32 = 0;
        let mut bits: u32 = 0;
        for &b in data {
            buf = (buf << 8) | (b as u32);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                let idx = ((buf >> bits) & 0x3f) as usize;
                out.push(ALPHABET[idx] as char);
            }
        }
        if bits > 0 {
            let idx = ((buf << (6 - bits)) & 0x3f) as usize;
            out.push(ALPHABET[idx] as char);
        }
        out
    }

    fn install_codex_account(
        base: &std::path::Path,
        account: u16,
        access_token_exp_secs: u64,
        refresh_token: Option<&str>,
    ) -> AccountNum {
        let num = AccountNum::try_from(account).unwrap();
        let creds = CredentialFile::Codex(CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: Some("acct-test".into()),
                access_token: make_codex_jwt(access_token_exp_secs),
                refresh_token: refresh_token.map(|s| s.into()),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        });
        // M4-12: provision UUID mapping so save_canonical_for (called by
        // broker_codex_check after a successful refresh) can locate the
        // identity write path.
        provision_uuid_for_account(base, account);
        credentials::save(&file::canonical_path_for(base, num, Surface::Codex), &creds).unwrap();
        // M4-4: broker_codex_check now resolves UUID when by_slot is populated.
        // Write the same credentials to the UUID-keyed path so broker_codex_check
        // loads the correct (test-controlled) JWT for expiry checks.
        let uuid = crate::testing::identity_fixtures::fixture_uuid_for_slot(account);
        let uuid_codex_path =
            crate::accounts::identity_store::credentials_codex_path_for(base, uuid);
        std::fs::create_dir_all(uuid_codex_path.parent().unwrap()).unwrap();
        credentials::save(&uuid_codex_path, &creds).unwrap();
        num
    }

    fn now_secs_test() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// JWT exp far in the future (> 2h) → no refresh, returns Valid.
    #[test]
    fn broker_codex_check_valid_token_no_refresh() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 6 * 3600; // 6h ahead
        let acc = install_codex_account(dir.path(), 11, exp, Some("rt_alive"));

        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let mock = move |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Ok((b"{}".to_vec(), None))
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(matches!(result, BrokerResult::Valid));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "Codex broker_check must not POST when token is fresh"
        );
    }

    /// Regression: a Valid result MUST clear any stale broker_failed
    /// sentinel. Without this, a transient `token_invalidated` or
    /// `refresh_reused` flag from earlier in the slot's history persists
    /// until the next pre-expiry refresh window (≥ 9.9 days for fresh
    /// codex tokens), contradicting `csq doctor`'s reported state.
    /// Origin: 2026-05-22 — slot 12 showed LOGIN-NEEDED in `csq doctor`
    /// for hours after a successful `csq login` because the daemon
    /// refresher Valid-branch never cleared the stale flag.
    #[test]
    fn broker_codex_check_valid_clears_stale_broker_failed_sentinel() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 6 * 3600; // 6h ahead
        let acc = install_codex_account(dir.path(), 17, exp, Some("rt_alive"));

        // Seed a stale sentinel as if a prior failed refresh had set it.
        sentinel::set_broker_failed(dir.path(), acc, "codex_token_invalidated").unwrap();
        assert!(sentinel::is_broker_failed(dir.path(), acc));

        let mock = |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Ok((b"{}".to_vec(), None))
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(matches!(result, BrokerResult::Valid));
        assert!(
            !sentinel::is_broker_failed(dir.path(), acc),
            "stale broker_failed sentinel MUST be cleared when Codex creds are healthy"
        );
    }

    /// JWT exp within 2h pre-expiry window → refreshes via injected
    /// transport; canonical credentials/codex-N.json gets the new
    /// access + refresh + id tokens.
    #[test]
    fn broker_codex_check_expiring_token_refreshes_and_writes_new_tokens() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 3600; // 1h ahead → inside 2h window
        let acc = install_codex_account(dir.path(), 12, exp, Some("rt_old"));

        // Build the response with a NEW JWT whose exp is way in the
        // future, so a follow-up read would say "Valid".
        let new_exp = now_secs_test() + 6 * 3600;
        let new_at = make_codex_jwt(new_exp);
        let body = format!(
            r#"{{"access_token":"{new_at}","refresh_token":"rt_new","id_token":"{new_at}","expires_in":3600}}"#
        );
        let mock = move |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Ok((
                body.clone().into_bytes(),
                Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            ))
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(matches!(result, BrokerResult::Refreshed));

        // M4-12: UUID-keyed identity path carries the new tokens.
        let uuid12 = crate::testing::identity_fixtures::fixture_uuid_for_slot(12);
        let path = crate::accounts::identity_store::credentials_codex_path_for(dir.path(), uuid12);
        let saved = credentials::load(&path).unwrap();
        let codex = saved.codex().expect("must be Codex variant");
        assert_eq!(codex.tokens.access_token, new_at);
        assert_eq!(codex.tokens.refresh_token.as_deref(), Some("rt_new"));
        // last_refresh stamped in RFC-3339-ish UTC.
        assert!(
            codex
                .last_refresh
                .as_deref()
                .map(|s| s.contains('T') && s.ends_with('Z'))
                .unwrap_or(false),
            "last_refresh must be set: {:?}",
            codex.last_refresh
        );
    }

    /// `code: "token_expired"` from upstream → Failed(CodexTokenExpired) +
    /// broker_failed flag with `codex_token_expired` reason. This is the
    /// LOGIN-NEEDED path (FR-CORE-03 step 5).
    #[test]
    fn broker_codex_check_token_expired_routes_to_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60); // already expired
        let acc = install_codex_account(dir.path(), 13, exp, Some("rt_dead"));

        let mock = |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Ok((br#"{"error":{"code":"token_expired"}}"#.to_vec(), None))
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        match result {
            BrokerResult::Failed(BrokerError::CodexTokenExpired { account: a }) => {
                assert_eq!(a, 13);
            }
            other => panic!("expected Failed(CodexTokenExpired), got {other:?}"),
        }

        // broker_failed flag MUST be set with the codex-specific reason.
        assert!(sentinel::is_broker_failed(dir.path(), acc));
        let reason = sentinel::read_broker_failed_reason(dir.path(), acc);
        assert_eq!(reason.as_deref(), Some("codex_token_expired"));
    }

    /// `code: "token_invalidated"` → Failed(CodexTokenInvalidated).
    ///
    /// Observed 2026-05-22: ChatGPT returns this when a newer login on
    /// the same account minted a replacement chain. Even though the
    /// refresh-token-handed `/oauth/token` endpoint may also return this,
    /// the routing parity with token_expired / refresh_token_reused is
    /// required so the broker_failed sentinel reason and the dashboard
    /// surface the actionable kind tag.
    #[test]
    fn broker_codex_check_token_invalidated_routes_to_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60);
        let acc = install_codex_account(dir.path(), 12, exp, Some("rt_invalidated"));

        let mock = |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Ok((
                br#"{"error":{"message":"Your authentication token has been invalidated. Please try signing in again.","type":"invalid_request_error","code":"token_invalidated","param":null},"status":401}"#.to_vec(),
                None,
            ))
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        match result {
            BrokerResult::Failed(BrokerError::CodexTokenInvalidated { account: a }) => {
                assert_eq!(a, 12);
            }
            other => panic!("expected Failed(CodexTokenInvalidated), got {other:?}"),
        }
        let reason = sentinel::read_broker_failed_reason(dir.path(), acc);
        assert_eq!(reason.as_deref(), Some("codex_token_invalidated"));
    }

    /// `code: "refresh_token_reused"` → Failed(CodexRefreshReused).
    #[test]
    fn broker_codex_check_refresh_reused_routes_to_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60);
        let acc = install_codex_account(dir.path(), 14, exp, Some("rt_reused"));

        let mock = |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Ok((
                br#"{"error":{"code":"refresh_token_reused"}}"#.to_vec(),
                None,
            ))
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        match result {
            BrokerResult::Failed(BrokerError::CodexRefreshReused { account: a }) => {
                assert_eq!(a, 14);
            }
            other => panic!("expected Failed(CodexRefreshReused), got {other:?}"),
        }
        let reason = sentinel::read_broker_failed_reason(dir.path(), acc);
        assert_eq!(reason.as_deref(), Some("codex_refresh_reused"));
    }

    /// Codex slot with no refresh_token → cannot refresh → Failed
    /// (CodexTokenExpired) without contacting the network.
    #[test]
    fn broker_codex_check_missing_refresh_token_routes_to_login_needed() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60);
        let acc = install_codex_account(dir.path(), 15, exp, None);

        let calls = Arc::new(AtomicU32::new(0));
        let calls_c = Arc::clone(&calls);
        let mock = move |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            calls_c.fetch_add(1, Ordering::SeqCst);
            Ok((b"{}".to_vec(), None))
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(matches!(
            result,
            BrokerResult::Failed(BrokerError::CodexTokenExpired { .. })
        ));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "no HTTP call when there is no refresh_token to send"
        );
    }

    /// Two concurrent refresh attempts on the same Codex slot — exactly
    /// one fires the upstream. Mirrors `broker_concurrent_exactly_one_refresh`
    /// for Anthropic. The lock-coordinated re-read inside the lock means
    /// the second arrival sees a fresh token and returns Valid (or Skipped
    /// if the lock-holder is still working).
    #[test]
    fn broker_codex_check_concurrent_exactly_one_refresh() {
        use std::thread;

        let dir = TempDir::new().unwrap();
        let exp = now_secs_test().saturating_sub(60);
        let acc = install_codex_account(dir.path(), 16, exp, Some("rt_seed"));

        let counter = Arc::new(AtomicU32::new(0));
        let base = dir.path().to_path_buf();

        let new_exp = now_secs_test() + 6 * 3600;
        let new_at = make_codex_jwt(new_exp);
        let body = format!(
            r#"{{"access_token":"{new_at}","refresh_token":"rt_new","id_token":"{new_at}","expires_in":3600}}"#
        );
        let body_arc = Arc::new(body);

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let base = base.clone();
                let count = Arc::clone(&counter);
                let body = Arc::clone(&body_arc);
                thread::spawn(move || {
                    let body_local = (*body).clone();
                    broker_codex_check(&base, acc, move |_u, _b| {
                        count.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(std::time::Duration::from_millis(10));
                        Ok((body_local.into_bytes(), None))
                    })
                })
            })
            .collect();

        for h in handles {
            match h.join().unwrap().unwrap() {
                BrokerResult::Refreshed | BrokerResult::Skipped | BrokerResult::Valid => {}
                other => panic!("unexpected: {other:?}"),
            }
        }

        let total = counter.load(Ordering::SeqCst);
        assert_eq!(
            total, 1,
            "exactly one Codex refresh fires under lock coordination, got {total}"
        );
    }

    /// Successful refresh with a server `Date` header far from local time
    /// — the broker must succeed (clock-skew is a warn, not a failure)
    /// AND emit the `clock_skew_detected` log tag at WARN.
    #[test]
    fn broker_codex_check_clock_skew_emits_warn_but_succeeds() {
        let dir = TempDir::new().unwrap();
        let exp = now_secs_test() + 3600;
        let acc = install_codex_account(dir.path(), 17, exp, Some("rt_skew"));

        // Server reports it's 1970 — local clock is decades ahead, so
        // |drift| > 5min by a wide margin.
        let new_exp = now_secs_test() + 6 * 3600;
        let new_at = make_codex_jwt(new_exp);
        let body =
            format!(r#"{{"access_token":"{new_at}","refresh_token":"rt_new","expires_in":3600}}"#);
        let mock = move |_u: &str, _b: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Ok((
                body.clone().into_bytes(),
                Some("Thu, 01 Jan 1970 00:00:00 GMT".to_string()),
            ))
        };

        let result = broker_codex_check(dir.path(), acc, mock).unwrap();
        assert!(
            matches!(result, BrokerResult::Refreshed),
            "clock skew is a warning, not a failure: got {result:?}"
        );
    }

    // ── R2-MED-1: codex_is_expired_within boundary conditions ────────────────

    /// Builds a minimal `CodexCredentialFile` whose `access_token` JWT exp
    /// claim is `exp_secs`. Used by the boundary tests below.
    fn minimal_codex_cred_with_exp(exp_secs: u64) -> crate::credentials::CodexCredentialFile {
        crate::credentials::CodexCredentialFile {
            auth_mode: Some("chatgpt".into()),
            openai_api_key: None,
            tokens: CodexTokensFile {
                account_id: None,
                access_token: make_codex_jwt(exp_secs),
                refresh_token: Some("rt_boundary_test".into()),
                id_token: None,
                extra: HashMap::new(),
            },
            last_refresh: None,
            extra: HashMap::new(),
        }
    }

    /// Mutation guard: `exp == now + REFRESH_WINDOW_SECS` satisfies the
    /// predicate `exp <= now + buffer_secs` and MUST trigger a refresh.
    ///
    /// A mutation that flips `<=` to `<` would make this return false,
    /// missing the boundary case and failing this test.
    #[test]
    fn codex_is_expired_within_at_exact_boundary_triggers_refresh() {
        let now_s = now_secs_test();
        let exp = now_s + REFRESH_WINDOW_SECS;
        let cred = minimal_codex_cred_with_exp(exp);
        assert!(
            codex_is_expired_within(&cred, REFRESH_WINDOW_SECS, now_s),
            "exp == now + REFRESH_WINDOW_SECS must trigger refresh (boundary condition); \
             exp={exp}, now={now_s}, buffer={REFRESH_WINDOW_SECS}"
        );
    }

    /// Mutation guard: `exp == now + REFRESH_WINDOW_SECS + 1` is strictly
    /// outside the window and MUST NOT trigger a refresh.
    ///
    /// A mutation that flips `<=` to `>=` (or similar) would make this
    /// return true, spuriously triggering a refresh and failing this test.
    #[test]
    fn codex_is_expired_within_one_second_beyond_boundary_does_not_trigger_refresh() {
        let now_s = now_secs_test();
        let exp = now_s + REFRESH_WINDOW_SECS + 1;
        let cred = minimal_codex_cred_with_exp(exp);
        assert!(
            !codex_is_expired_within(&cred, REFRESH_WINDOW_SECS, now_s),
            "exp == now + REFRESH_WINDOW_SECS + 1 must NOT trigger refresh (one second outside \
             boundary); exp={exp}, now={now_s}, buffer={REFRESH_WINDOW_SECS}"
        );
    }
}
