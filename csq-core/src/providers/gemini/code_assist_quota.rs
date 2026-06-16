//! Code Assist (Gemini OAuth) quota retrieval — Phase B' of journal
//! 0046+0047, landed alongside Stage 2 of journal 0048.
//!
//! Polls Google's `cloudcode-pa.googleapis.com` to get per-model token
//! / request quota for users on a Gemini Code Assist subscription.
//! csq is read-only on the OAuth credentials at
//! `~/.gemini/oauth_creds.json` — gemini-cli owns refresh; csq just
//! reads the current access_token and presents it as a Bearer.
//!
//! # Endpoints (verified from gemini-cli source 2026-05-06)
//!
//! - `POST https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist`
//!   — returns the user's project ID + subscription tier. Called
//!   once per account, then cached.
//! - `POST https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota`
//!   — returns per-model `BucketInfo` (remainingFraction, resetTime,
//!   tokenType, modelId). Called every poll tick.
//!
//! Source references in `~/repos/contrib/gemini-cli`:
//! `packages/core/src/code_assist/server.ts:73,363-370,420-423`,
//! `packages/core/src/code_assist/types.ts:250-265`,
//! `packages/core/src/config/storage.ts:206-207` (oauth_creds path).
//!
//! # Auth posture
//!
//! gemini-cli uses google-auth-library which auto-refreshes the
//! access_token when it expires. csq reads `access_token` directly
//! from the file on each poll — if gemini-cli has refreshed since
//! the last poll, csq picks up the new token transparently. csq
//! NEVER writes to `oauth_creds.json` and NEVER attempts refresh
//! itself. If the access_token is expired and gemini-cli has not
//! refreshed it (e.g., gemini-cli not running and the user has not
//! invoked it recently), the poll returns 401 and the caller enters
//! cooldown — gemini-cli will refresh on the user's next session.
//!
//! # Aggregation strategy
//!
//! BucketInfo is per-model + per-tokenType (REQUESTS, TOKENS).
//! For the v1 UsageWindow shape (single percentage), we take the
//! "limiting bucket" — the bucket with the LOWEST `remainingFraction`
//! across all per-model rows for the same tokenType. The user wants
//! to know "when am I going to run out", so the most-pressured bucket
//! is the right answer.

use crate::error::redact_tokens;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer};
use std::path::{Path, PathBuf};

/// Default path to gemini-cli's OAuth credentials file (legacy
/// file-based; new gemini-cli builds may prefer the OS keychain).
/// Per gemini-cli source `packages/core/src/config/storage.ts:206-207`.
pub const OAUTH_CREDS_FILENAME: &str = "oauth_creds.json";

/// Base URL for Google's Code Assist private RPC endpoints. Verified
/// from gemini-cli `packages/core/src/code_assist/server.ts:73`.
pub const CLOUDCODE_PA_BASE_URL: &str = "https://cloudcode-pa.googleapis.com/v1internal";

/// User-Agent header value csq sends on Code Assist requests.
/// Mirrors gemini-cli's pattern (`GeminiCLI/{version}/{model} ({platform}; {arch})`)
/// but identifies as csq so Google can attribute traffic correctly
/// if they instrument by UA. Construct via [`code_assist_user_agent`].
pub fn code_assist_user_agent() -> String {
    format!(
        "csq/{} ({}; {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Errors raised reading or parsing OAuth credentials.
#[derive(Debug, thiserror::Error)]
pub enum OauthCredsError {
    /// `oauth_creds.json` not found at expected path. The user has
    /// not run `gemini auth login` yet (or has logged out).
    #[error("Code Assist OAuth credentials not found at {path}: run `csq login {{slot}} --provider gemini` to authenticate")]
    NotFound { path: PathBuf },
    /// File present but unreadable (permissions, partial write).
    #[error("Code Assist OAuth credentials read error at {path}: {reason}")]
    ReadFailed { path: PathBuf, reason: String },
    /// File present but JSON is malformed or missing required fields.
    #[error("Code Assist OAuth credentials malformed at {path}: {reason}")]
    Malformed { path: PathBuf, reason: String },
}

/// On-disk schema of `~/.gemini/oauth_creds.json` (legacy file-based
/// path). Mirrors the Google Credentials shape from
/// `gemini-cli/packages/core/src/code_assist/oauth-credential-storage.ts:35-44`.
///
/// csq is read-only on this file — `refresh_token` and `expiry_date`
/// are present in the schema for completeness but csq never uses them
/// for refresh (gemini-cli + google-auth-library own that).
///
/// `access_token` is wrapped in [`SecretString`] (zeroize-on-drop, no
/// accidental Display) per redteam round 1 HIGH: bare `String` bearer
/// tokens persisted across `.await` and could land in core dumps. Use
/// `creds.access_token.expose_secret()` only at the HTTP-build
/// boundary.
#[derive(Debug, Clone, Deserialize)]
pub struct OauthCreds {
    /// Bearer token to attach to Code Assist HTTP requests.
    #[serde(deserialize_with = "deserialize_secret_string")]
    pub access_token: SecretString,
    /// Refresh token (csq does NOT use; gemini-cli handles refresh).
    /// Also wrapped for symmetry / defense-in-depth even though csq
    /// reads it back nowhere.
    #[serde(default, deserialize_with = "deserialize_secret_string_opt")]
    pub refresh_token: Option<SecretString>,
    /// Token type — typically `"Bearer"`. csq does not validate.
    pub token_type: Option<String>,
    /// OAuth scope (space-delimited).
    pub scope: Option<String>,
    /// Expiry as Unix milliseconds. csq does not check; gemini-cli
    /// refreshes proactively.
    pub expiry_date: Option<i64>,
}

fn deserialize_secret_string<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
    let s = String::deserialize(d)?;
    Ok(SecretString::new(s.into()))
}

fn deserialize_secret_string_opt<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<SecretString>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    Ok(opt.map(|s| SecretString::new(s.into())))
}

/// Reads `oauth_creds.json` from the user's `~/.gemini/` directory.
/// `home_dir` is typically `dirs::home_dir()`; passed explicitly so
/// tests can use a TempDir.
///
/// Defenses:
///
/// - **Symlink guard**: refuses non-regular files (symlink, fifo,
///   socket) so an attacker who can replace the file with a symlink
///   cannot redirect the read at an arbitrary same-UID file. Mirrors
///   `validate_vertex_sa_path` defense.
/// - **TOCTOU retry**: gemini-cli's writer may not be atomic
///   (`fs.writeFile` in Node.js is truncate-then-write); a partial
///   read during the writer's window produces a JSON parse failure.
///   Retries once after 50ms before reporting `Malformed`.
/// - **Empty access_token reject**: an `access_token: ""` deserializes
///   successfully but burns HTTP roundtrips; reject at read time.
/// - **Token redaction**: every error reason passes through
///   `error::redact_tokens` so partial JSON (which can echo the
///   surrounding token bytes) does not leak through tracing.
pub fn read_oauth_creds(home_dir: &Path) -> Result<OauthCreds, OauthCredsError> {
    let path = home_dir.join(".gemini").join(OAUTH_CREDS_FILENAME);
    match read_oauth_creds_once(&path) {
        Ok(c) => Ok(c),
        Err(first_err) if is_transient_read_error(&first_err) => {
            // Possible race with gemini-cli's writer (non-atomic in
            // some versions of `fs.writeFile`). `Malformed` (partial
            // JSON parse) and `ReadFailed` with a TRANSIENT errno
            // (EBUSY / ETXTBSY / EAGAIN / EINTR) share the same
            // root cause; retry once after a short delay.
            //
            // Round-4 redteam LOW: permission-class ReadFailed
            // (EACCES, EPERM) is NOT transient — retrying wastes
            // 50ms per tick on a permissions-broken slot with no
            // chance of recovery. `is_transient_read_error` filters
            // those out so they fall straight through to the
            // returned error.
            std::thread::sleep(std::time::Duration::from_millis(50));
            match read_oauth_creds_once(&path) {
                Ok(c) => Ok(c),
                // Return the LAST error so the diagnostic reflects
                // the most recent state, not the transient failure.
                Err(retry_err) => Err(retry_err),
            }
        }
        Err(e) => Err(e),
    }
}

/// Classifies an `OauthCredsError` as worth retrying. `Malformed` is
/// always transient (it's the partial-JSON-mid-write race signal).
/// `ReadFailed` is transient ONLY for the small set of errno values
/// that genuinely indicate concurrent activity (EBUSY, ETXTBSY,
/// EAGAIN, EINTR). EACCES / EPERM / ELOOP / etc. are non-transient —
/// retrying them wastes 50ms per tick without recovery.
fn is_transient_read_error(e: &OauthCredsError) -> bool {
    match e {
        OauthCredsError::Malformed { .. } => true,
        OauthCredsError::ReadFailed { reason, .. } => {
            // Substring match on the strerror text in `reason`.
            // (We don't have direct access to `io::Error::raw_os_error`
            // through the redacted reason; the kernel's canonical
            // strerror text for these errnos is stable enough on
            // Linux / macOS / Windows that substring matching is
            // acceptable for a defense-in-depth retry filter.)
            let r = reason.to_lowercase();
            r.contains("resource busy")          // EBUSY
                || r.contains("text file busy")  // ETXTBSY
                || r.contains("would block")     // EAGAIN / EWOULDBLOCK
                || r.contains("interrupted")     // EINTR
                || r.contains("temporarily unavailable") // EAGAIN alt strerror
        }
        OauthCredsError::NotFound { .. } => false,
    }
}

fn read_oauth_creds_once(path: &Path) -> Result<OauthCreds, OauthCredsError> {
    // Symlink guard: refuse non-regular files. An attacker who can
    // replace ~/.gemini/oauth_creds.json with a symlink to an
    // arbitrary file would otherwise have csq's daemon read that
    // file's contents and (with broken redaction elsewhere) leak
    // them via tracing.
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(OauthCredsError::NotFound {
                path: path.to_path_buf(),
            });
        }
        Err(e) => {
            return Err(OauthCredsError::ReadFailed {
                path: path.to_path_buf(),
                reason: redact_tokens(&format!("stat: {e}")),
            });
        }
    };
    if !meta.file_type().is_file() {
        return Err(OauthCredsError::Malformed {
            path: path.to_path_buf(),
            reason: "not a regular file (symlink/fifo/socket rejected)".into(),
        });
    }

    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(OauthCredsError::NotFound {
                path: path.to_path_buf(),
            });
        }
        Err(e) => {
            return Err(OauthCredsError::ReadFailed {
                path: path.to_path_buf(),
                reason: redact_tokens(&format!("{e}")),
            });
        }
    };
    let creds: OauthCreds = serde_json::from_str(&raw).map_err(|e| OauthCredsError::Malformed {
        path: path.to_path_buf(),
        reason: redact_tokens(&format!("json: {e}")),
    })?;
    if creds.access_token.expose_secret().trim().is_empty() {
        return Err(OauthCredsError::Malformed {
            path: path.to_path_buf(),
            reason: "access_token is empty (mid-rotation or corrupt write)".into(),
        });
    }
    Ok(creds)
}

/// Subset of the `:loadCodeAssist` response csq consumes — the rest
/// of the response (tier metadata, available credits) is discarded.
/// gemini-cli source: `packages/core/src/code_assist/server.ts:263-290`.
#[derive(Debug, Clone, Deserialize)]
pub struct LoadCodeAssistResponse {
    /// Resource name of the user's GCP project (e.g.,
    /// `"projects/my-cloudcode-project"`). Used as the `project`
    /// field on subsequent `:retrieveUserQuota` calls.
    #[serde(rename = "cloudaicompanionProject")]
    pub project: Option<String>,
}

/// Per-model / per-tokenType quota bucket. Verified shape from
/// `gemini-cli/packages/core/src/code_assist/types.ts:255-263`.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct BucketInfo {
    /// Remaining quota as a fraction in `[0.0, 1.0]`. The agent
    /// receiving 0.75 has 75% left; 0.0 means exhausted.
    #[serde(rename = "remainingFraction")]
    pub remaining_fraction: Option<f64>,
    /// Remaining quota as an absolute count. JSON int64 over the
    /// wire, hence `String`. csq does not parse — diagnostic only.
    #[serde(rename = "remainingAmount")]
    pub remaining_amount: Option<String>,
    /// ISO-8601 timestamp when this bucket resets.
    #[serde(rename = "resetTime")]
    pub reset_time: Option<String>,
    /// Bucket category — e.g., `"REQUESTS"` or `"TOKENS"`.
    #[serde(rename = "tokenType")]
    pub token_type: Option<String>,
    /// Model the bucket applies to — e.g., `"gemini-2.5-pro"`.
    #[serde(rename = "modelId")]
    pub model_id: Option<String>,
}

/// `:retrieveUserQuota` response. Verified shape from
/// `gemini-cli/packages/core/src/code_assist/types.ts:262-265`.
#[derive(Debug, Clone, Deserialize)]
pub struct RetrieveUserQuotaResponse {
    pub buckets: Option<Vec<BucketInfo>>,
}

/// Aggregates BucketInfo across all models into a single (used%,
/// resets_at) pair suitable for the v1 UsageWindow shape.
///
/// Strategy: pick the "limiting bucket" — the row with the LOWEST
/// `remaining_fraction` across all buckets, regardless of tokenType.
/// `used_percentage = (1 - remaining_fraction) * 100`. `resets_at`
/// is the limiting bucket's `reset_time`.
///
/// **Schema-drift skipping**: buckets with a `remaining_fraction`
/// outside `[0.0, 1.0]` are SKIPPED rather than clamped — a negative
/// or >1.0 value is a schema drift signal from upstream and silently
/// rounding it to 0% or 100% would hide the upstream bug. If every
/// bucket is skipped, returns `None`.
///
/// **Cross-tokenType caveat**: the limiting-bucket pick is across
/// REQUESTS and TOKENS combined. The `limiting_token_type` field on
/// the projection lets the UI surface which dimension is closer to
/// exhaustion ("80% used (REQUESTS)"). Callers that ignore
/// `limiting_token_type` and render only `used_percentage` will
/// conflate two distinct quotas — render both.
///
/// Returns `None` if no usable bucket was provided.
pub fn aggregate_to_usage_window(buckets: &[BucketInfo]) -> Option<UsageWindowProjection> {
    let limiting = buckets
        .iter()
        .filter(|b| match b.remaining_fraction {
            Some(f) => (0.0..=1.0).contains(&f),
            None => false,
        })
        .min_by(|a, b| {
            let af = a.remaining_fraction.unwrap_or(1.0);
            let bf = b.remaining_fraction.unwrap_or(1.0);
            af.partial_cmp(&bf).unwrap_or(std::cmp::Ordering::Equal)
        })?;
    let remaining = limiting.remaining_fraction?;
    let used_pct = (1.0 - remaining) * 100.0;
    Some(UsageWindowProjection {
        used_percentage: used_pct,
        resets_at_iso: limiting.reset_time.clone(),
        limiting_model: limiting.model_id.clone(),
        limiting_token_type: limiting.token_type.clone(),
    })
}

/// Aggregated UsageWindow projection — what the daemon writes into
/// the quota.json `seven_day` (or `five_hour`) row for a Code Assist
/// OAuth slot. Carries diagnostic context (`limiting_model`,
/// `limiting_token_type`) the UI can render alongside the percentage
/// without re-deriving from raw buckets.
#[derive(Debug, Clone, PartialEq)]
pub struct UsageWindowProjection {
    pub used_percentage: f64,
    pub resets_at_iso: Option<String>,
    pub limiting_model: Option<String>,
    pub limiting_token_type: Option<String>,
}

/// Builds the JSON request body for `POST :loadCodeAssist`.
///
/// All three of `ideType`, `platform`, and `pluginType` are proto-enum
/// fields on `ClientMetadata` validated server-side. Free-form values
/// produce HTTP 400 (`Invalid value at 'metadata.ide_type' …`).
/// gemini-cli sends `IDE_UNSPECIFIED` + `PLATFORM_UNSPECIFIED` +
/// `pluginType: "GEMINI"` (verified in `@google/gemini-cli`'s bundled
/// chunks). csq is a Code Assist client of the same plugin type, so
/// it sends the same triple.
pub fn build_load_code_assist_body() -> String {
    serde_json::json!({
        "metadata": {
            "ideType": "IDE_UNSPECIFIED",
            "platform": "PLATFORM_UNSPECIFIED",
            "pluginType": "GEMINI",
        }
    })
    .to_string()
}

/// Builds the JSON request body for `POST :retrieveUserQuota`.
///
/// The proto `RetrieveUserQuotaRequest` only accepts `project`;
/// extra fields (like `userAgent`) are rejected server-side with
/// `Invalid JSON payload received. Unknown name "userAgent"`. The
/// User-Agent identifier travels in the HTTP header, not the body.
pub fn build_retrieve_user_quota_body(project: &str) -> String {
    serde_json::json!({
        "project": project,
    })
    .to_string()
}

/// Builds the headers list for Code Assist HTTP calls. Production
/// callers pass `oauth.access_token` as `bearer`.
pub fn build_headers(bearer: &str) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Accept".to_string(), "application/json".to_string()),
        ("User-Agent".to_string(), code_assist_user_agent()),
        ("Authorization".to_string(), format!("Bearer {bearer}")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn read_oauth_creds_returns_not_found_when_missing() {
        let dir = TempDir::new().unwrap();
        let err = read_oauth_creds(dir.path()).unwrap_err();
        match err {
            OauthCredsError::NotFound { .. } => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn read_oauth_creds_parses_full_google_credentials_shape() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("oauth_creds.json"),
            r#"{
                "access_token": "ya29.a0Ae_test_access_token_xxxxxxxxxxxxxxxx",
                "refresh_token": "1//0test_refresh_xxxxxxxxxxxxxxxx",
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "token_type": "Bearer",
                "expiry_date": 4102444800000
            }"#,
        )
        .unwrap();

        let creds = read_oauth_creds(dir.path()).unwrap();
        assert_eq!(
            creds.access_token.expose_secret(),
            "ya29.a0Ae_test_access_token_xxxxxxxxxxxxxxxx"
        );
        assert_eq!(creds.token_type.as_deref(), Some("Bearer"));
        assert_eq!(creds.expiry_date, Some(4_102_444_800_000));
    }

    #[test]
    fn read_oauth_creds_accepts_minimal_access_token_only() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("oauth_creds.json"),
            r#"{"access_token":"ya29.minimal"}"#,
        )
        .unwrap();

        let creds = read_oauth_creds(dir.path()).unwrap();
        assert_eq!(creds.access_token.expose_secret(), "ya29.minimal");
        assert!(creds.refresh_token.is_none());
        assert!(creds.expiry_date.is_none());
    }

    /// Redteam round 1 HIGH: empty `access_token` deserializes
    /// successfully but burns HTTP roundtrips per slot per tick.
    /// Reject at read time so the daemon poller can skip without
    /// touching cloudcode-pa.
    #[test]
    fn read_oauth_creds_rejects_empty_access_token() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("oauth_creds.json"),
            r#"{"access_token":""}"#,
        )
        .unwrap();

        let err = read_oauth_creds(dir.path()).unwrap_err();
        match err {
            OauthCredsError::Malformed { reason, .. } => {
                assert!(reason.contains("empty"), "got: {reason}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    /// Whitespace-only `access_token` is also empty for our purposes.
    #[test]
    fn read_oauth_creds_rejects_whitespace_only_access_token() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("oauth_creds.json"),
            r#"{"access_token":"   "}"#,
        )
        .unwrap();

        let err = read_oauth_creds(dir.path()).unwrap_err();
        assert!(matches!(err, OauthCredsError::Malformed { .. }));
    }

    /// Redteam round 1 HIGH: symlink at `oauth_creds.json` MUST be
    /// rejected — an attacker who can replace the file with a symlink
    /// to an arbitrary same-UID file would otherwise have csq read
    /// the target and (with broken redaction) leak it via tracing.
    #[cfg(unix)]
    #[test]
    fn read_oauth_creds_rejects_symlink() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        // Plant a real file elsewhere
        let target = dir.path().join("evil.txt");
        std::fs::write(&target, "secret target content").unwrap();
        // Symlink oauth_creds.json -> evil.txt
        std::os::unix::fs::symlink(&target, gemini_dir.join("oauth_creds.json")).unwrap();

        let err = read_oauth_creds(dir.path()).unwrap_err();
        match err {
            OauthCredsError::Malformed { reason, .. } => {
                assert!(reason.contains("not a regular file"), "got: {reason}");
            }
            other => panic!("expected Malformed{{symlink}}, got {other:?}"),
        }
    }

    /// Redteam round 1 HIGH: error reasons MUST pass through
    /// `redact_tokens` so partial-write JSON bodies that echo token
    /// fragments do not leak into tracing.
    #[test]
    fn read_oauth_creds_redacts_token_fragments_in_malformed_reason() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        // Truncated mid-string — serde_json's error Display can echo
        // surrounding bytes including token fragments.
        std::fs::write(
            gemini_dir.join("oauth_creds.json"),
            r#"{"access_token":"ya29.a0Ae_LEAKED_token_xxxxxxxxxxxxxxxxxxxxxxxxxx,"#,
        )
        .unwrap();

        let err = read_oauth_creds(dir.path()).unwrap_err();
        let display = err.to_string();
        assert!(
            !display.contains("ya29.a0Ae_LEAKED_token"),
            "ya29.* token must be redacted from error display: {display}"
        );
    }

    #[test]
    fn read_oauth_creds_rejects_malformed_json() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(gemini_dir.join("oauth_creds.json"), "{ this is not json").unwrap();

        let err = read_oauth_creds(dir.path()).unwrap_err();
        match err {
            OauthCredsError::Malformed { .. } => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn read_oauth_creds_rejects_missing_access_token_field() {
        let dir = TempDir::new().unwrap();
        let gemini_dir = dir.path().join(".gemini");
        std::fs::create_dir_all(&gemini_dir).unwrap();
        std::fs::write(
            gemini_dir.join("oauth_creds.json"),
            r#"{"refresh_token":"only_refresh"}"#,
        )
        .unwrap();

        // serde rejects because access_token is required (no Option<>).
        let err = read_oauth_creds(dir.path()).unwrap_err();
        match err {
            OauthCredsError::Malformed { .. } => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn parses_retrieve_user_quota_response_with_per_model_buckets() {
        // Schema verified from gemini-cli test fixtures
        // (server.test.ts retrieveUserQuota cases).
        let body = r#"{
            "buckets": [
                {
                    "modelId": "gemini-2.5-pro",
                    "tokenType": "REQUESTS",
                    "remainingFraction": 0.75,
                    "resetTime": "2099-10-22T16:01:15Z"
                },
                {
                    "modelId": "gemini-2.5-flash",
                    "tokenType": "REQUESTS",
                    "remainingFraction": 0.32,
                    "resetTime": "2099-10-22T16:01:15Z"
                },
                {
                    "modelId": "gemini-2.5-pro",
                    "tokenType": "TOKENS",
                    "remainingFraction": 0.91,
                    "remainingAmount": "9100000",
                    "resetTime": "2099-10-22T16:01:15Z"
                }
            ]
        }"#;
        let resp: RetrieveUserQuotaResponse = serde_json::from_str(body).unwrap();
        let buckets = resp.buckets.unwrap();
        assert_eq!(buckets.len(), 3);
        assert_eq!(buckets[0].model_id.as_deref(), Some("gemini-2.5-pro"));
        assert_eq!(buckets[0].remaining_fraction, Some(0.75));
        assert_eq!(buckets[2].remaining_amount.as_deref(), Some("9100000"));
    }

    #[test]
    fn aggregation_picks_lowest_remaining_fraction() {
        // The 0.32 row is the limiting bucket — gemini-2.5-flash
        // is closest to exhaustion across all per-model rows.
        let buckets = vec![
            BucketInfo {
                remaining_fraction: Some(0.75),
                remaining_amount: None,
                reset_time: Some("2099-10-22T00:00:00Z".to_string()),
                token_type: Some("REQUESTS".to_string()),
                model_id: Some("gemini-2.5-pro".to_string()),
            },
            BucketInfo {
                remaining_fraction: Some(0.32),
                remaining_amount: None,
                reset_time: Some("2099-10-22T16:01:15Z".to_string()),
                token_type: Some("REQUESTS".to_string()),
                model_id: Some("gemini-2.5-flash".to_string()),
            },
            BucketInfo {
                remaining_fraction: Some(0.91),
                remaining_amount: None,
                reset_time: Some("2099-10-22T00:00:00Z".to_string()),
                token_type: Some("TOKENS".to_string()),
                model_id: Some("gemini-2.5-pro".to_string()),
            },
        ];
        let projection = aggregate_to_usage_window(&buckets).unwrap();
        // 1 - 0.32 = 0.68; * 100 = 68.0
        assert!((projection.used_percentage - 68.0).abs() < 0.001);
        assert_eq!(
            projection.resets_at_iso.as_deref(),
            Some("2099-10-22T16:01:15Z")
        );
        assert_eq!(
            projection.limiting_model.as_deref(),
            Some("gemini-2.5-flash")
        );
        assert_eq!(projection.limiting_token_type.as_deref(), Some("REQUESTS"));
    }

    #[test]
    fn aggregation_returns_none_when_no_usable_buckets() {
        // Buckets present but with no remaining_fraction → nothing
        // to aggregate.
        let buckets = vec![BucketInfo {
            remaining_fraction: None,
            remaining_amount: Some("9100000".to_string()),
            reset_time: Some("2099-10-22T00:00:00Z".to_string()),
            token_type: Some("TOKENS".to_string()),
            model_id: Some("gemini-2.5-pro".to_string()),
        }];
        assert!(aggregate_to_usage_window(&buckets).is_none());
    }

    /// Redteam round 1 MED: a negative `remaining_fraction` is a
    /// SCHEMA-DRIFT signal from upstream (Google's contract is
    /// `[0, 1]`). Earlier revisions clamped it to `0.0 → 100% used`,
    /// which silently rounded broken data into a UI-renderable
    /// percentage and hid the upstream bug. Stage 2 of journal 0048
    /// rejects out-of-range fractions instead — they're skipped from
    /// aggregation so the limiting bucket comes from valid rows.
    #[test]
    fn aggregation_skips_out_of_range_remaining_fraction() {
        // Negative fraction: skipped. The 0.7 bucket becomes the
        // limiting bucket → 30% used.
        let buckets = vec![
            BucketInfo {
                remaining_fraction: Some(-0.01),
                remaining_amount: None,
                reset_time: Some("2099-01-01T00:00:00Z".to_string()),
                token_type: Some("REQUESTS".to_string()),
                model_id: Some("gemini-2.5-pro".to_string()),
            },
            BucketInfo {
                remaining_fraction: Some(0.7),
                remaining_amount: None,
                reset_time: Some("2099-01-01T00:00:00Z".to_string()),
                token_type: Some("REQUESTS".to_string()),
                model_id: Some("gemini-2.5-flash".to_string()),
            },
        ];
        let projection = aggregate_to_usage_window(&buckets).unwrap();
        assert!(
            (projection.used_percentage - 30.0).abs() < 0.001,
            "limiting bucket should be the 0.7 row (30% used), not the rejected -0.01 row"
        );
        assert_eq!(
            projection.limiting_model.as_deref(),
            Some("gemini-2.5-flash")
        );
    }

    /// >1.0 fraction is also out of range and skipped.
    #[test]
    fn aggregation_skips_overshooting_fraction() {
        let buckets = vec![BucketInfo {
            remaining_fraction: Some(1.05),
            remaining_amount: None,
            reset_time: None,
            token_type: None,
            model_id: None,
        }];
        // Only bucket is out-of-range → no usable buckets → None.
        assert!(aggregate_to_usage_window(&buckets).is_none());
    }

    /// `metadata.ideType`, `metadata.platform`, and
    /// `metadata.pluginType` are proto enum fields on
    /// `ClientMetadata`. Sending free-form strings (`"OTHER"`,
    /// `"macos"`, `"CSQ"`) makes Google return HTTP 400 with
    /// `Invalid value at 'metadata.ide_type' …` — that is the bug
    /// this test pins. gemini-cli sends the same triple.
    #[test]
    fn load_code_assist_body_uses_proto_enum_values() {
        let body = build_load_code_assist_body();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["metadata"]["ideType"], "IDE_UNSPECIFIED");
        assert_eq!(v["metadata"]["platform"], "PLATFORM_UNSPECIFIED");
        assert_eq!(v["metadata"]["pluginType"], "GEMINI");
    }

    /// `RetrieveUserQuotaRequest` proto only accepts `project`. Adding
    /// `userAgent` to the body produces HTTP 400 — the User-Agent
    /// identifier MUST live in the HTTP header, not the JSON body.
    #[test]
    fn build_retrieve_user_quota_body_only_carries_project() {
        let body = build_retrieve_user_quota_body("projects/my-cloudcode-project");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["project"], "projects/my-cloudcode-project");
        assert!(v.get("userAgent").is_none());
        assert_eq!(v.as_object().unwrap().len(), 1);
    }

    #[test]
    fn build_headers_includes_authorization_bearer() {
        let headers = build_headers("ya29.test_access_token");
        let auth = headers.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "Bearer ya29.test_access_token");
        assert!(headers
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json"));
        assert!(headers.iter().any(|(k, _)| k == "User-Agent"));
    }

    #[test]
    fn user_agent_includes_csq_version_and_platform() {
        let ua = code_assist_user_agent();
        assert!(ua.starts_with("csq/"), "got: {ua}");
        assert!(ua.contains(std::env::consts::OS), "got: {ua}");
    }

    #[test]
    fn cloudcode_pa_base_url_is_v1internal() {
        assert_eq!(
            CLOUDCODE_PA_BASE_URL,
            "https://cloudcode-pa.googleapis.com/v1internal"
        );
    }

    #[test]
    fn parses_load_code_assist_response_extracting_project() {
        // Verified shape: cloudaicompanionProject is the project name.
        let body = r#"{
            "cloudaicompanionProject": "projects/my-cloudcode-project",
            "currentTier": {
                "name": "free-tier",
                "userDefinedCloudaicompanionProject": false
            }
        }"#;
        let resp: LoadCodeAssistResponse = serde_json::from_str(body).unwrap();
        assert_eq!(
            resp.project.as_deref(),
            Some("projects/my-cloudcode-project")
        );
    }
}
