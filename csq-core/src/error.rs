use std::path::PathBuf;
use thiserror::Error;

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

/// Returns true if `c` is a valid API-key body character.
#[inline]
fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Returns true if `c` is a valid hex digit.
#[inline]
fn is_hex_char(c: char) -> bool {
    c.is_ascii_hexdigit()
}

/// Known OAuth token prefixes that are ALWAYS redacted regardless of body length.
///
/// These are credential prefixes: any occurrence is a real token. The variable
/// body portion may be short in test inputs (e.g. `LEAKED`), so we must not
/// apply a minimum-length guard to them.
const KNOWN_TOKEN_PREFIXES: &[&str] = &["sk-ant-oat01-", "sk-ant-ort01-"];

/// Replaces token-like strings with [REDACTED].
///
/// Three patterns are covered:
///
/// 1. **Known OAuth prefixes** (`sk-ant-oat01-`, `sk-ant-ort01-`): always
///    redacted, regardless of body length.  These are Anthropic OAuth
///    access/refresh token prefixes; any occurrence in a string is a real
///    credential.
///
/// 2. **Generic `sk-*` keys** — `sk-` followed by ≥20 API-key body characters
///    (`[A-Za-z0-9\-_]`).  Covers `sk-ant-api03-*` (Anthropic API keys) and
///    3P keys from Z.AI, MiniMax, OpenAI-style providers.  Strings shorter than
///    20 chars after the `sk-` prefix are NOT redacted to avoid false positives
///    on error codes and short labels.
///
/// 3. **Long bare hex strings** — ≥32 consecutive hex digits (`[0-9a-fA-F]`).
///    Covers 3P API keys that are raw 128-bit (32-char) or longer hex tokens.
///    Shorter runs (e.g. git SHAs in log messages, short error codes) are left
///    intact.
///
/// Exposed `pub` so modules outside this file can redact user-facing
/// error strings before they reach tracing, the IPC cache, or error
/// messages. Used by `credentials::refresh` to scrub serde_json parse
/// errors that may echo a fragment of the OAuth form body on
/// malformed response bodies.
pub fn redact_tokens(s: &str) -> String {
    // Minimum body length (after "sk-") for the generic sk-* pattern.
    const SK_MIN_BODY: usize = 20;
    // Minimum length of a bare hex run treated as a secret.
    const HEX_MIN_LEN: usize = 32;

    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;

    // Build a lightweight view back into a str position for prefix matching.
    // We keep a parallel byte offset so we can use `str::find` on slices.
    // Since all key chars are ASCII, char index == byte index for the spans we
    // examine — but we use `char` iteration to be safe with the rest of the
    // string.
    let bytes = s.as_bytes();
    // Byte offset corresponding to chars[i].
    // We maintain this separately because chars may be multi-byte.
    let char_byte_offsets: Vec<usize> = s
        .char_indices()
        .map(|(byte_pos, _)| byte_pos)
        .chain(std::iter::once(s.len()))
        .collect();

    while i < len {
        let byte_i = char_byte_offsets[i];

        // --- Pattern 1: known OAuth token prefixes (always redact) ---
        let mut matched_known = false;
        for prefix in KNOWN_TOKEN_PREFIXES {
            let plen = prefix.len();
            if byte_i + plen <= s.len() && &s[byte_i..byte_i + plen] == *prefix {
                // Consume until a delimiter or end of string.
                let mut j = i + prefix.chars().count();
                while j < len && is_key_char(chars[j]) {
                    j += 1;
                }
                out.push_str("[REDACTED]");
                i = j;
                matched_known = true;
                break;
            }
        }
        if matched_known {
            continue;
        }

        // --- Pattern 2: generic sk-* key (minimum body length required) ---
        if i + 2 < len && chars[i] == 's' && chars[i + 1] == 'k' && chars[i + 2] == '-' {
            let span_start = i;
            let mut j = i + 3; // advance past "sk-"
            while j < len && is_key_char(chars[j]) {
                j += 1;
            }
            // Body = everything after the initial "sk-".
            let body_len = j - (span_start + 3);
            if body_len >= SK_MIN_BODY {
                out.push_str("[REDACTED]");
                i = j;
                continue;
            }
        }

        // --- Pattern 3: long bare hex string ---
        // Only enter if bytes[byte_i] is a hex digit to avoid slow scanning.
        if byte_i < bytes.len() && (bytes[byte_i] as char).is_ascii_hexdigit() {
            let mut j = i;
            while j < len && is_hex_char(chars[j]) {
                j += 1;
            }
            let hex_len = j - i;
            if hex_len >= HEX_MIN_LEN {
                out.push_str("[REDACTED]");
                i = j;
                continue;
            }
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

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
            CsqError::Broker(BrokerError::RefreshTokenInvalid { .. }) => {
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
/// back from upstream (see journal 0010). The tag vocabulary is
/// stable: adding a new `CsqError` variant defaults to `"other"`
/// so existing consumers never break.
///
/// Returned values (sorted):
/// - `"broker_refresh_failed"` — canonical refresh + sibling
///   recovery both failed for a slot
/// - `"broker_token_invalid"` — upstream rejected the refresh
///   token (`invalid_grant`), needs re-login
/// - `"broker_other"` — broker error that isn't the above
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
        CsqError::Broker(_) => "broker_other",
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
}

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("refresh failed for account {account}: {reason}")]
    RefreshFailed { account: u16, reason: String },

    #[error("refresh token invalid for account {account} (re-login required)")]
    RefreshTokenInvalid { account: u16 },

    #[error("all siblings dead for account {account}")]
    AllSiblingsDead { account: u16 },

    #[error("recovery failed for account {account}: tried {tried} siblings")]
    RecoveryFailed { account: u16, tried: usize },
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
    fn credential_not_found_display() {
        let err = CredentialError::NotFound {
            path: PathBuf::from("/tmp/creds.json"),
        };
        assert!(format!("{err}").contains("/tmp/creds.json"));
    }

    // --- redact_tokens ---

    #[test]
    fn redact_tokens_oat01_prefix() {
        // Arrange
        let input = "token=sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "token=[REDACTED]");
    }

    #[test]
    fn redact_tokens_ort01_prefix() {
        // Arrange
        let input = "refresh=sk-ant-ort01-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "refresh=[REDACTED]");
    }

    #[test]
    fn redact_tokens_anthropic_api_key() {
        // Arrange – sk-ant-api03-* style (Anthropic API keys, not OAuth tokens)
        let input = "key=sk-ant-api03-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "key=[REDACTED]");
    }

    #[test]
    fn redact_tokens_generic_sk_key() {
        // Arrange – generic long sk-* key (e.g. Z.AI, MiniMax, OpenAI-style)
        let input = "Authorization: Bearer sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "Authorization: Bearer [REDACTED]");
    }

    #[test]
    fn redact_tokens_short_sk_not_redacted() {
        // Arrange – "sk-" followed by fewer than 20 chars must NOT be redacted
        let input = "error code sk-short (retry)";

        // Act
        let output = redact_tokens(input);

        // Assert – unchanged
        assert_eq!(output, input);
    }

    #[test]
    fn redact_tokens_long_hex_string() {
        // Arrange – 32-char hex token (e.g. MiniMax / Z.AI API key)
        let input = "x-api-key: abcdef1234567890abcdef1234567890";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "x-api-key: [REDACTED]");
    }

    #[test]
    fn redact_tokens_64_char_hex_string() {
        // Arrange – 64-char hex (SHA-256-sized API key)
        let hex64 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let input = format!("token={hex64}");

        // Act
        let output = redact_tokens(&input);

        // Assert
        assert_eq!(output, "token=[REDACTED]");
    }

    #[test]
    fn redact_tokens_short_hex_not_redacted() {
        // Arrange – 31-char hex run (just under the threshold) must NOT be redacted
        let input = "hash=abcdef1234567890abcdef123456789";

        // Act
        let output = redact_tokens(input);

        // Assert – unchanged (31 hex chars < 32)
        assert_eq!(output, input);
    }

    #[test]
    fn redact_tokens_plain_text_unchanged() {
        // Arrange
        let input = "no secrets here, just a normal log message";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, input);
    }

    #[test]
    fn redact_tokens_mixed_content_preserves_surrounding_text() {
        // Arrange – key appears mid-sentence; text before and after must survive
        let input =
            "failed to POST: x-api-key=sk-minimax-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ok";

        // Act
        let output = redact_tokens(input);

        // Assert
        assert_eq!(output, "failed to POST: x-api-key=[REDACTED] ok");
    }

    #[test]
    fn redact_tokens_multiple_secrets_in_one_string() {
        // Arrange – two independent keys in the same string
        let key1 = "sk-ant-oat01-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key2 = "sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let input = format!("access={key1} refresh={key2}");

        // Act
        let output = redact_tokens(&input);

        // Assert
        assert_eq!(output, "access=[REDACTED] refresh=[REDACTED]");
    }

    #[test]
    fn redact_tokens_empty_string() {
        assert_eq!(redact_tokens(""), "");
    }
}
