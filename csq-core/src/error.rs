use std::path::PathBuf;
use thiserror::Error;

/// OAuth error-type strings (RFC 6749 §5.2 + RFC 8628 §3.5 device-auth).
///
/// These are a fixed, spec-defined vocabulary of category names. They carry
/// no secrets — they identify the error class, not the credential. Keeping
/// this allowlist lets diagnostic code surface the category through the
/// redaction layer without widening what `redact_tokens` passes.
///
/// **Security contract:** callers MUST return `&'static str` slices from
/// this array — never borrowed slices from the parsed input. This is the
/// load-bearing defense against prompt-injection: even if an attacker
/// crafts a response body whose `error` field reads `"invalid_scope"`, the
/// returned pointer is into the compile-time constant, not into the
/// attacker-controlled string.
///
/// RFC 8628 device-auth error strings (`authorization_pending`, `slow_down`,
/// `access_denied`, `expired_token`) added per PR-C00 (Codex surface gates
/// journals 0005..0010) in preparation for `codex login --device-auth` flow
/// surfaced by PR-C3.
pub(crate) static OAUTH_ERROR_TYPES: &[&str] = &[
    // RFC 6749 §5.2
    "invalid_request",
    "invalid_grant",
    "invalid_scope",
    "unauthorized_client",
    "unsupported_grant_type",
    // RFC 8628 §3.5 (device-auth)
    "authorization_pending",
    "slow_down",
    "access_denied",
    "expired_token",
];

/// Extracts an RFC 6749 §5.2 OAuth error-type string from a JSON response
/// body, returning a `&'static str` from [`OAUTH_ERROR_TYPES`] on match.
///
/// Returns `None` when:
/// - The body is not valid JSON
/// - The `error` field is absent or not a string
/// - The `error` value does not exactly match an allowlisted string
///   (prefix extensions like `"invalid_scope_extended"` are rejected)
///
/// # Security
///
/// The returned `&str` is a pointer into [`OAUTH_ERROR_TYPES`], NOT into
/// the `body` argument. This is the primary defense against prompt
/// injection: an attacker who controls the upstream response body cannot
/// exfiltrate arbitrary content through this function even if they can
/// reproduce an allowlisted string verbatim, because the returned bytes
/// are always from the compile-time constant. Only the `error` field is
/// consulted — `error_description` is free-form and attacker-controlled
/// and is never examined here.
pub fn extract_oauth_error_type(body: &str) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let error_str = value.get("error")?.as_str()?;
    OAUTH_ERROR_TYPES
        .iter()
        .find(|&&allowlisted| error_str == allowlisted)
        .copied()
}

/// Sanitize HTTP response bodies to prevent token leaks in error messages.
/// Truncates to 200 chars and redacts known token patterns.
fn sanitize_body(body: &str) -> String {
    let truncated = if body.len() > 200 {
        format!("{}...[truncated]", &body[..200])
    } else {
        body.to_string()
    };
    redact_tokens(&truncated)
}

// ---------------------------------------------------------------------------
// Token redaction — relocated to the `csq-redact` leaf crate (W1).
// ---------------------------------------------------------------------------
//
// `redact_tokens`, `redact_excerpt`, `redact_pem_blocks`, and the
// `RedactedString` newtype moved to `csq-redact` so the standalone `csq-sdk`
// crate can depend on them without pulling in csq-core. Re-exported here at
// their historical path (`crate::error::redact_tokens`, …) so every existing
// callsite — and `sanitize_body` below — compiles unchanged. See
// internal-design-docs
pub use csq_redact::{redact_excerpt, redact_pem_blocks, redact_tokens};

/// Top-level error type for csq operations.
///
/// Used at CLI and Tauri command boundaries. Each variant wraps
/// a module-specific error for pattern matching.
#[derive(Error, Debug)]
pub enum CsqError {
    #[error("credential error: {0}")]
    Credential(#[from] CredentialError),

    #[error("platform error: {0}")]
    Platform(#[from] PlatformError),

    #[error("broker error: {0}")]
    Broker(#[from] BrokerError),

    #[error("oauth error: {0}")]
    OAuth(#[from] OAuthError),

    #[error("daemon error: {0}")]
    Daemon(#[from] DaemonError),

    #[error("config error: {0}")]
    Config(#[from] ConfigError),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Maps CsqError to a typed code string for Tauri IPC responses.
impl From<CsqError> for String {
    fn from(e: CsqError) -> String {
        match &e {
            CsqError::Credential(CredentialError::NotFound { .. }) => format!("NOT_FOUND: {e}"),
            CsqError::Credential(CredentialError::InvalidAccount(_)) => {
                format!("INVALID_INPUT: {e}")
            }
            CsqError::Broker(BrokerError::RefreshTokenInvalid { .. })
            | CsqError::Broker(BrokerError::CodexTokenExpired { .. })
            | CsqError::Broker(BrokerError::CodexRefreshReused { .. })
            | CsqError::Broker(BrokerError::CodexTokenInvalidated { .. }) => {
                format!("LOGIN_REQUIRED: {e}")
            }
            CsqError::OAuth(OAuthError::StateMismatch) => format!("CSRF_ERROR: {e}"),
            _ => format!("INTERNAL_ERROR: {e}"),
        }
    }
}

/// Returns a short, fixed-cardinality tag describing a `CsqError`.
///
/// Callers use this instead of `Display` for logs, broker-failed
/// flag files, and dashboard error surfaces — the raw `Display`
/// chain can contain response-body fragments that may echo tokens
/// back from upstream (see an internal journal entry). The tag vocabulary is
/// stable: adding a new `CsqError` variant defaults to `"other"`
/// so existing consumers never break.
///
/// Returned values (sorted):
/// - `"broker_refresh_failed"` — canonical refresh + sibling
///   recovery both failed for a slot
/// - `"broker_token_invalid"` — upstream rejected the refresh
///   token (`invalid_grant`), needs re-login
/// - `"broker_other"` — broker error that isn't the above
/// - `"codex_refresh_reused"` — OpenAI `refresh_token_reused`, needs re-login
/// - `"codex_token_expired"` — OpenAI `token_expired`, needs re-login
/// - `"codex_token_invalidated"` — OpenAI `token_invalidated`, needs re-login
/// - `"config"` — local config file error
/// - `"credential"` — reading/writing credential file on disk
/// - `"daemon"` — daemon lifecycle error
/// - `"oauth"` — OAuth flow error (typically re-login)
/// - `"other"` — unclassified / anyhow-wrapped
/// - `"platform"` — platform-specific syscall error
pub fn error_kind_tag(e: &CsqError) -> &'static str {
    match e {
        CsqError::Credential(_) => "credential",
        CsqError::Platform(_) => "platform",
        CsqError::Broker(BrokerError::RefreshTokenInvalid { .. }) => "broker_token_invalid",
        CsqError::Broker(BrokerError::RefreshFailed { .. }) => "broker_refresh_failed",
        CsqError::Broker(BrokerError::CodexTokenExpired { .. }) => "codex_token_expired",
        CsqError::Broker(BrokerError::CodexRefreshReused { .. }) => "codex_refresh_reused",
        CsqError::Broker(BrokerError::CodexTokenInvalidated { .. }) => "codex_token_invalidated",
        CsqError::OAuth(_) => "oauth",
        CsqError::Daemon(_) => "daemon",
        CsqError::Config(_) => "config",
        CsqError::Other(_) => "other",
    }
}

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("credential file not found: {path}")]
    NotFound { path: PathBuf },

    #[error("corrupt credential file {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },

    #[error("invalid account number: {0}")]
    InvalidAccount(String),

    #[error("no credentials configured for account {0}")]
    NoCredentials(u16),

    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl CredentialError {
    /// Fixed-vocabulary error-kind tag for `SkipReason::CorruptBinding`'s
    /// `kind` payload (security.md §2 — path-free). Mirror of
    /// `ProvisionError::error_kind_tag` at `providers/gemini/provisioning.rs:198`.
    /// Surface context (Gemini vs Codex) is carried separately on the
    /// `SkipReason::CorruptBinding { surface }` discriminant, so these
    /// tags are surface-agnostic.
    pub fn error_kind_tag(&self) -> &'static str {
        match self {
            CredentialError::NotFound { .. } => "credentials_not_found",
            CredentialError::Corrupt { .. } => "credentials_malformed",
            CredentialError::Io { .. } => "credentials_io",
            CredentialError::InvalidAccount(_) => "credentials_invalid_account",
            CredentialError::NoCredentials(_) => "credentials_none",
        }
    }
}

#[cfg(test)]
mod credential_error_kind_tag_tests {
    use super::*;
    use std::collections::HashSet;
    use std::io;
    use std::path::PathBuf;

    #[test]
    fn credential_error_kind_tag_distinct_per_variant() {
        let tags: HashSet<&'static str> = [
            CredentialError::NotFound {
                path: PathBuf::from("/x"),
            }
            .error_kind_tag(),
            CredentialError::Corrupt {
                path: PathBuf::from("/x"),
                reason: "y".into(),
            }
            .error_kind_tag(),
            CredentialError::Io {
                path: PathBuf::from("/x"),
                source: io::Error::other("z"),
            }
            .error_kind_tag(),
            CredentialError::InvalidAccount("a".into()).error_kind_tag(),
            CredentialError::NoCredentials(1).error_kind_tag(),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            tags.len(),
            5,
            "each CredentialError variant must yield a distinct tag"
        );
    }
}

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("lock contention on {path} (held by another process)")]
    LockContention { path: PathBuf },

    #[error("lock timeout after {timeout_ms}ms on {path}")]
    LockTimeout { path: PathBuf, timeout_ms: u64 },

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("process not found: PID {pid}")]
    ProcessNotFound { pid: u32 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("windows error: code {code}, {message}")]
    Win32 { code: u32, message: String },

    /// Returned by `symlink_exclusive` when the link path already exists.
    ///
    /// Distinct from `Io(ErrorKind::AlreadyExists)` so callers can match
    /// this specific case without comparing `io::ErrorKind` strings. Phase 3
    /// uses this variant to detect the losing side of a concurrent symlink
    /// race and retry with the winning link.
    #[error("symlink target already exists")]
    AlreadyExists,
}

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("refresh failed for account {account}: {reason}")]
    RefreshFailed { account: u16, reason: String },

    #[error("refresh token invalid for account {account} (re-login required)")]
    RefreshTokenInvalid { account: u16 },

    // M3-7 fix-wave R1 H4: `AllSiblingsDead` and `RecoveryFailed` were sibling-
    // recovery error variants. Sibling recovery is retired (`broker/check.rs`
    // post-M3-7 has no fanout path), so these variants have no production
    // construction sites. Deleted per zero-tolerance Rule 5.
    /// Codex OAuth returned `code: "token_expired"`.
    ///
    /// Distinguished from generic `RefreshTokenInvalid` because OpenAI's
    /// `/oauth/token` endpoint emits this specific code when the submitted
    /// refresh token's signature or expiry has lapsed, which differs
    /// semantically from a reused-refresh-token scenario. Surfaces specific
    /// UI text ("your Codex session has expired — run `codex login`")
    /// instead of the generic re-login prompt. an internal journal entry / 0010.
    #[error("codex token expired for account {account} (re-login required)")]
    CodexTokenExpired { account: u16 },

    /// Codex OAuth returned `code: "refresh_token_reused"`.
    ///
    /// OpenAI rotates refresh tokens on each successful refresh; using a
    /// previously-consumed refresh token triggers this specific error code.
    /// Surfaces specific UI text identifying the "single-use token already
    /// consumed" scenario rather than the generic re-login prompt.
    /// an internal journal entry / 0010.
    #[error("codex refresh token reused for account {account} (re-login required)")]
    CodexRefreshReused { account: u16 },

    /// Codex API returned `code: "token_invalidated"`.
    ///
    /// ChatGPT's backend revoked the access token server-side, typically
    /// because a newer login on the same account minted a replacement
    /// token chain. The JWT `exp` claim may still be in the future, but
    /// the server no longer accepts it. Distinct from `token_expired`
    /// (clock-based expiry) and `refresh_token_reused` (single-use
    /// violation). User must `codex login` again to mint a fresh chain.
    #[error("codex token invalidated for account {account} (re-login required)")]
    CodexTokenInvalidated { account: u16 },
}

#[derive(Error, Debug)]
pub enum OAuthError {
    #[error("http error: {status} {}", sanitize_body(body))]
    Http { status: u16, body: String },

    #[error("state token expired (TTL {ttl_secs}s exceeded)")]
    StateExpired { ttl_secs: u64 },

    #[error("state token mismatch (CSRF)")]
    StateMismatch,

    #[error("PKCE verification failed")]
    PkceVerification,

    #[error("token exchange failed: {0}")]
    Exchange(String),

    /// The race orchestrator's paste channel was closed without a
    /// value being sent — typically because the user closed the
    /// modal while the race was running. Distinct from
    /// [`OAuthError::Exchange`] so the Tauri bridge can translate
    /// it to a no-op (the cancel event has already fired).
    /// UX-R1-L3 / SEC-R1-09.
    #[error("OAuth race cancelled by user")]
    Cancelled,

    /// The state store is at capacity and refused to accept a new
    /// pending entry. Returned instead of silently evicting the
    /// oldest entry so the orchestrator surfaces a clear error
    /// rather than dropping a legitimate concurrent login on the
    /// floor. UX-R1-L2.
    #[error("OAuth state store at capacity ({max_pending} pending logins)")]
    StoreAtCapacity { max_pending: usize },

    /// A token-exchange operation exceeded its wall-clock budget.
    /// Distinct from a generic Exchange error so the UI can show
    /// "exchange timed out — re-run csq login" instead of a
    /// possibly-misleading network error. UX-R1-M4.
    #[error("token exchange timed out after {timeout_secs}s")]
    ExchangeTimeout { timeout_secs: u64 },

    /// Another csq process (CLI or desktop) holds the per-account
    /// `AccountLoginLock` for this account. SEC-R2-01: the desktop
    /// race path acquires the same lock as `csq login` to prevent
    /// concurrent CLI + desktop logins from stomping
    /// `credentials/N.json` (last-writer-wins).
    ///
    /// `pid` is the holder's PID when readable from the lock file;
    /// `None` when the file is empty or unreadable. The frontend
    /// renders a "cancel previous login (PID …) and retry" UX when
    /// the PID is known, falling back to a generic "wait or use the
    /// CLI" message when not.
    #[error("login already in progress for account {account}")]
    LoginInProgressElsewhere { account: u16, pid: Option<u32> },
}

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("daemon not running (PID file: {pid_path})")]
    NotRunning { pid_path: PathBuf },

    #[error("daemon already running (PID {pid})")]
    AlreadyRunning { pid: u32 },

    #[error("socket connect failed: {path}")]
    SocketConnect { path: PathBuf },

    #[error("ipc timeout after {timeout_ms}ms")]
    IpcTimeout { timeout_ms: u64 },

    #[error("stale PID file (PID {pid} not alive)")]
    StalePidFile { pid: u32 },
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("profile not found: {name}")]
    ProfileNotFound { name: String },

    #[error("invalid JSON in {path}: {reason}")]
    InvalidJson { path: PathBuf, reason: String },

    #[error("settings merge conflict in {key}")]
    MergeConflict { key: String },

    /// M5: a provider bind was refused by the operating envelope's
    /// `data_access.model_residency` policy. Constructed only on enterprise builds
    /// (`phase2b::residency::enforce_provider_write`); the variant exists in both
    /// editions but the community build never constructs it. The message names the
    /// provider, the policy, and the allowed set so the operator can self-correct
    /// (`rules/tauri-commands.md` MUST Rule 6 — named variant → specific UI text).
    #[error(
        "provider '{provider}' is not permitted under residency policy '{policy}' (allowed: {allowed})"
    )]
    ResidencyDenied {
        provider: String,
        policy: String,
        allowed: String,
    },

    /// A per-slot provider-key bind (`csq setkey <3p> --slot N`, desktop
    /// `bind_keyed_provider` / `bind_keyless_provider`) was refused because slot
    /// `slot` is already bound to a non-3P OAuth/device-auth surface
    /// (`bound_surface`: `Claude (Anthropic OAuth)` / `Codex` / `Gemini`).
    /// Overwriting it would silently override the live login and orphan the
    /// account's `by_slot` mapping (an internal ticket). The operator must
    /// `csq logout <N>` first. Constructed by
    /// [`crate::accounts::third_party::bind_provider_to_slot`] via
    /// [`crate::accounts::third_party::conflicting_bound_surface`]. Named
    /// variant → specific UI text (`rules/tauri-commands.md` MUST Rule 6).
    #[error(
        "slot {slot} is bound to {bound_surface} — run `csq logout {slot}` before binding a provider key"
    )]
    SlotSurfaceConflict { slot: u16, bound_surface: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csq_error_display() {
        let err = CsqError::Credential(CredentialError::InvalidAccount("abc".to_string()));
        assert_eq!(
            format!("{err}"),
            "credential error: invalid account number: abc"
        );
    }

    #[test]
    fn csq_error_to_ipc_string() {
        let err = CsqError::Credential(CredentialError::InvalidAccount("0".to_string()));
        let s: String = err.into();
        assert!(s.starts_with("INVALID_INPUT:"));
    }

    #[test]
    fn broker_error_display() {
        let err = BrokerError::RefreshTokenInvalid { account: 3 };
        assert!(format!("{err}").contains("account 3"));
        assert!(format!("{err}").contains("re-login"));
    }

    #[test]
    fn codex_token_expired_tag_and_ipc_mapping() {
        let e = CsqError::Broker(BrokerError::CodexTokenExpired { account: 7 });
        assert_eq!(error_kind_tag(&e), "codex_token_expired");
        let ipc: String = e.into();
        assert!(ipc.starts_with("LOGIN_REQUIRED:"));
    }

    #[test]
    fn codex_refresh_reused_tag_and_ipc_mapping() {
        let e = CsqError::Broker(BrokerError::CodexRefreshReused { account: 7 });
        assert_eq!(error_kind_tag(&e), "codex_refresh_reused");
        let ipc: String = e.into();
        assert!(ipc.starts_with("LOGIN_REQUIRED:"));
    }

    #[test]
    fn credential_not_found_display() {
        let err = CredentialError::NotFound {
            path: PathBuf::from("/tmp/creds.json"),
        };
        assert!(format!("{err}").contains("/tmp/creds.json"));
    }

    // --- extract_oauth_error_type ---

    /// Each allowlisted entry round-trips: parsing a JSON body whose `error`
    /// field equals that entry returns the exact entry.
    #[test]
    fn extract_oauth_error_type_returns_static_for_each_allowlist_entry() {
        for &entry in OAUTH_ERROR_TYPES {
            // Arrange
            let body = format!(r#"{{"error":"{entry}"}}"#);
            // Act
            let result = extract_oauth_error_type(&body);
            // Assert
            assert_eq!(result, Some(entry), "entry '{entry}' should round-trip");
        }
    }

    /// `"invalid_scope_extended"` is NOT in the allowlist; the function must
    /// reject prefix extensions via exact-match semantics.
    #[test]
    fn extract_oauth_error_type_rejects_substring_extension() {
        // Arrange
        let body = r#"{"error":"invalid_scope_extended"}"#;
        // Act
        let result = extract_oauth_error_type(body);
        // Assert
        assert_eq!(result, None, "prefix extension must be rejected");
    }

    /// Completely unknown error types must return None.
    #[test]
    fn extract_oauth_error_type_rejects_unknown() {
        // Arrange
        let body = r#"{"error":"totally_made_up"}"#;
        // Act
        let result = extract_oauth_error_type(body);
        // Assert
        assert_eq!(result, None);
    }

    /// Non-JSON input must return None without panicking.
    #[test]
    fn extract_oauth_error_type_rejects_non_json() {
        // Arrange
        let body = "not json at all";
        // Act
        let result = extract_oauth_error_type(body);
        // Assert
        assert_eq!(result, None);
    }

    /// JSON with no `error` field must return None.
    #[test]
    fn extract_oauth_error_type_rejects_missing_error_field() {
        // Arrange
        let body = r#"{"foo":"bar"}"#;
        // Act
        let result = extract_oauth_error_type(body);
        // Assert
        assert_eq!(result, None);
    }

    /// The `error_description` field must be ignored — only the `error` field
    /// is consulted. This prevents an attacker-controlled description from
    /// leaking through the allowlist.
    #[test]
    fn extract_oauth_error_type_ignores_error_description() {
        // Arrange — `error_description` contains an allowlisted string but
        // `error` is absent, so the function must return None.
        let body = r#"{"error_description":"invalid_scope"}"#;
        // Act
        let result = extract_oauth_error_type(body);
        // Assert
        assert_eq!(result, None);
    }

    /// RFC 8628 device-auth error strings (added in PR-C0 for Codex) MUST be
    /// in the allowlist and round-trip correctly.
    #[test]
    fn extract_oauth_error_type_accepts_rfc8628_device_strings() {
        for device_err in [
            "authorization_pending",
            "slow_down",
            "access_denied",
            "expired_token",
        ] {
            let body = format!(r#"{{"error":"{device_err}"}}"#);
            let result = extract_oauth_error_type(&body);
            assert_eq!(result, Some(device_err));
        }
    }

    /// The returned `&str` must be pointer-equal to the entry in
    /// `OAUTH_ERROR_TYPES` — NOT a slice into the input body.
    ///
    /// This is the load-bearing defense against prompt injection: even if
    /// the attacker controls the body, the bytes returned to the caller are
    /// always from the compile-time constant array.
    #[test]
    fn extract_oauth_error_type_returns_static_pointer() {
        for (i, &entry) in OAUTH_ERROR_TYPES.iter().enumerate() {
            // Arrange — pad the body so the string value occupies different
            // memory than the constant.  The value is the same bytes but at a
            // different address.
            let body = format!(r#"{{  "error"  :  "{entry}"  }}"#);
            // Act
            let result = extract_oauth_error_type(&body).expect("should match");
            // Assert — pointer identity: result must point into the constant,
            // not into `body` (which is on the heap).
            assert!(
                std::ptr::eq(result.as_ptr(), OAUTH_ERROR_TYPES[i].as_ptr()),
                "returned ptr must equal OAUTH_ERROR_TYPES[{i}].as_ptr() — \
                 got a slice into the input instead of the static constant"
            );
        }
    }
}
