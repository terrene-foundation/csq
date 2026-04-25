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

/// Prefix-with-minimum-body token classes.
///
/// Each entry is `(prefix, min_body_chars)`. A token matches when the prefix
/// appears in the input AND is followed by at least `min_body_chars` valid
/// key-body characters (`[A-Za-z0-9\-_]`). The threshold avoids false
/// positives on short strings that happen to start with a matching prefix
/// (e.g. `rt_queue_size`, `sk-dev`).
///
/// - `sk-*` (≥20 body) — Anthropic API keys `sk-ant-api03-*`, Z.AI, MiniMax,
///   and other OpenAI-style providers.
/// - `sess-*` (≥20 body) — OpenAI session-cookie format (reserved; not
///   observed in auth.json but present in other OpenAI surfaces per
///   redteam H6 / PR-C00 plan §3.3).
/// - `rt_*` (≥20 body) — Codex refresh tokens. Observed in live
///   `~/.codex/auth.json` post PR-C00 re-login (journal 0010): 90-char
///   total length, `rt_` prefix + 87-char base64url body.
///
/// - `AIza*` (≥30 body) — Google AI Studio API keys. Observed shape is
///   `AIza` + 35 base64url body chars (39 total). The 30-char floor
///   distinguishes a real key from short test fixtures while still
///   matching legitimate keys; Google's documented format does not vary
///   the length so a tighter floor is safe. Added by PR-G2a per the
///   security-reviewer hook-error-leakage inventory (§5).
const TOKEN_PREFIXES_WITH_BODY: &[(&str, usize)] =
    &[("sk-", 20), ("sess-", 20), ("rt_", 20), ("AIza", 30)];

/// Minimum length of each JWT segment's body after its header prefix.
///
/// Real-world JWTs (OpenAI id_token / access_token observed in
/// `~/.codex/auth.json` per journal 0010) have segments hundreds of chars
/// long. 17 is a safe floor — any JWT shorter than 20 chars per segment is
/// not a real token and is unlikely to survive upstream verification.
const JWT_SEGMENT_MIN_BODY: usize = 17;

/// Replaces token-like strings with [REDACTED].
///
/// Four patterns are covered:
///
/// 1. **Known OAuth prefixes** (`sk-ant-oat01-`, `sk-ant-ort01-`): always
///    redacted, regardless of body length.  These are Anthropic OAuth
///    access/refresh token prefixes; any occurrence in a string is a real
///    credential.
///
/// 2. **Prefix-with-body tokens** — prefixes in [`TOKEN_PREFIXES_WITH_BODY`]
///    followed by at least the class's minimum body length. Covers `sk-*`
///    (Anthropic + 3P API keys), `sess-*` (OpenAI session tokens), and `rt_*`
///    (Codex refresh tokens). Short strings like `sk-short` or `rt_queue_size`
///    are left intact.
///
/// 3. **Long bare hex strings** — ≥32 consecutive hex digits (`[0-9a-fA-F]`).
///    Covers 3P API keys that are raw 128-bit (32-char) or longer hex tokens.
///    Shorter runs (e.g. git SHAs in log messages, short error codes) are left
///    intact.
///
/// 4. **JWT triple-segment** — `eyJ<b64url>+.eyJ<b64url>+.<b64url>+` where
///    each segment body is ≥[`JWT_SEGMENT_MIN_BODY`] chars. Covers OpenAI
///    Codex access_token and id_token (both JWTs per journal 0010 live
///    capture). The `eyJ` prefix is the base64url encoding of `{"` — any
///    JWT header or payload opens with a JSON object and therefore this
///    prefix. The three-segment `.`-delimited structure pins the match to
///    actual JWTs.
///
/// Exposed `pub` so modules outside this file can redact user-facing
/// error strings before they reach tracing, the IPC cache, or error
/// messages. Used by `credentials::refresh` to scrub serde_json parse
/// errors that may echo a fragment of the OAuth form body on
/// malformed response bodies.
pub fn redact_tokens(s: &str) -> String {
    // Minimum length of a bare hex run treated as a secret.
    const HEX_MIN_LEN: usize = 32;

    // Pre-process: collapse any PEM block to `[REDACTED]` BEFORE the
    // per-char scan. PEM blocks span multiple lines; the per-char loop
    // below cannot detect them in one pass without significant rework.
    // Vertex SA JSON contains a `private_key` field whose value is a
    // PEM block; logging that field with `format!("{e}")` would leak
    // the private key end-to-end. Added by PR-G2a per security-reviewer
    // §5 ("Vertex SA path" row).
    let pem_stripped = redact_pem_blocks(s);
    let s = pem_stripped.as_str();

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
        // Word-boundary guard: prefix patterns (1, 2, 4) only match when the
        // preceding char is NOT a key-body char. Prevents false positives
        // where a prefix string appears mid-word (e.g. `rt_` inside
        // `signature_part_long_enough_to_match`).
        let word_boundary = i == 0 || !is_key_char(chars[i - 1]);

        // --- Pattern 1: known OAuth token prefixes (always redact) ---
        let mut matched_known = false;
        if word_boundary {
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
        }
        if matched_known {
            continue;
        }

        // --- Pattern 2: prefix-with-body tokens (sk-*, sess-*, rt_*) ---
        let mut matched_prefixed = false;
        if word_boundary {
            for (prefix, min_body) in TOKEN_PREFIXES_WITH_BODY {
                let plen_bytes = prefix.len();
                let plen_chars = prefix.chars().count();
                if byte_i + plen_bytes > s.len() {
                    continue;
                }
                if &s[byte_i..byte_i + plen_bytes] != *prefix {
                    continue;
                }
                let mut j = i + plen_chars;
                while j < len && is_key_char(chars[j]) {
                    j += 1;
                }
                let body_len = j - (i + plen_chars);
                if body_len >= *min_body {
                    out.push_str("[REDACTED]");
                    i = j;
                    matched_prefixed = true;
                    break;
                }
            }
        }
        if matched_prefixed {
            continue;
        }

        // --- Pattern 4: JWT triple-segment (`eyJ<b64url>+.eyJ<b64url>+.<b64url>+`) ---
        // Three base64url segments separated by dots; each segment body
        // must be ≥ JWT_SEGMENT_MIN_BODY chars. Placed BEFORE hex because
        // an `eyJ...` prefix would otherwise be partially consumed by the
        // hex-match (first char `e` is a valid hex digit).
        if word_boundary
            && i + 3 <= len
            && chars[i] == 'e'
            && chars[i + 1] == 'y'
            && chars[i + 2] == 'J'
        {
            let seg1_body_start = i + 3;
            let mut j = seg1_body_start;
            while j < len && is_key_char(chars[j]) {
                j += 1;
            }
            let seg1_body_len = j - seg1_body_start;
            // Must have first dot AND second `eyJ` AND body length.
            if seg1_body_len >= JWT_SEGMENT_MIN_BODY
                && j < len
                && chars[j] == '.'
                && j + 4 <= len
                && chars[j + 1] == 'e'
                && chars[j + 2] == 'y'
                && chars[j + 3] == 'J'
            {
                let seg2_body_start = j + 4;
                let mut k = seg2_body_start;
                while k < len && is_key_char(chars[k]) {
                    k += 1;
                }
                let seg2_body_len = k - seg2_body_start;
                if seg2_body_len >= JWT_SEGMENT_MIN_BODY && k < len && chars[k] == '.' {
                    let seg3_start = k + 1;
                    let mut m = seg3_start;
                    while m < len && is_key_char(chars[m]) {
                        m += 1;
                    }
                    let seg3_len = m - seg3_start;
                    if seg3_len >= JWT_SEGMENT_MIN_BODY + 3 {
                        out.push_str("[REDACTED]");
                        i = m;
                        continue;
                    }
                }
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

/// Replaces every `-----BEGIN <tag>-----...-----END <tag>-----` block
/// in `s` with `[REDACTED]`. Multi-line aware. The opening and closing
/// dash-strings are NOT redacted on their own — they are common in
/// non-secret contexts (markdown headings, ASCII art) — only the full
/// block with both markers triggers redaction.
///
/// Intentionally permissive on the tag (we accept any `-----BEGIN X-----`
/// for any reasonable X) because PEM types proliferate (`PRIVATE KEY`,
/// `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `OPENSSH PRIVATE KEY`,
/// `CERTIFICATE`, etc.) and the failure mode is leaking a key, not
/// leaking a certificate.
///
/// Called from [`redact_tokens`] as a pre-processing step. Public so
/// the test module can exercise it directly.
pub fn redact_pem_blocks(s: &str) -> String {
    const BEGIN_MARKER: &str = "-----BEGIN ";
    const END_MARKER: &str = "-----END ";
    if !s.contains(BEGIN_MARKER) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut cursor = 0;
    while cursor < s.len() {
        let rest = &s[cursor..];
        let begin_idx = match rest.find(BEGIN_MARKER) {
            Some(i) => i,
            None => {
                out.push_str(rest);
                break;
            }
        };
        // Emit text before the BEGIN marker as-is.
        out.push_str(&rest[..begin_idx]);
        let after_begin = &rest[begin_idx..];
        // Find the matching END marker after the BEGIN. We accept any
        // line ending after the END tag's `-----`.
        let end_idx = match after_begin.find(END_MARKER) {
            Some(i) => i,
            None => {
                // Unterminated PEM block. Redact the rest defensively
                // — half a private key is still half too much in a log.
                out.push_str("[REDACTED]");
                break;
            }
        };
        // Advance past the END marker AND the closing `-----` and the
        // line break (if any) so the trailing dashes don't leak.
        let after_end = &after_begin[end_idx + END_MARKER.len()..];
        let close_dash_idx = after_end.find("-----");
        let consumed_after_end = match close_dash_idx {
            Some(i) => i + 5, // length of "-----"
            None => after_end.len(),
        };
        out.push_str("[REDACTED]");
        cursor += begin_idx + end_idx + END_MARKER.len() + consumed_after_end;
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
            CsqError::Broker(BrokerError::RefreshTokenInvalid { .. })
            | CsqError::Broker(BrokerError::CodexTokenExpired { .. })
            | CsqError::Broker(BrokerError::CodexRefreshReused { .. }) => {
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
/// - `"codex_refresh_reused"` — OpenAI `refresh_token_reused`, needs re-login
/// - `"codex_token_expired"` — OpenAI `token_expired`, needs re-login
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

    /// Codex OAuth returned `code: "token_expired"`.
    ///
    /// Distinguished from generic [`RefreshTokenInvalid`] because OpenAI's
    /// `/oauth/token` endpoint emits this specific code when the submitted
    /// refresh token's signature or expiry has lapsed, which differs
    /// semantically from a reused-refresh-token scenario. Surfaces specific
    /// UI text ("your Codex session has expired — run `codex login`")
    /// instead of the generic re-login prompt. Journal 0009 / 0010.
    #[error("codex token expired for account {account} (re-login required)")]
    CodexTokenExpired { account: u16 },

    /// Codex OAuth returned `code: "refresh_token_reused"`.
    ///
    /// OpenAI rotates refresh tokens on each successful refresh; using a
    /// previously-consumed refresh token triggers this specific error code.
    /// Surfaces specific UI text identifying the "single-use token already
    /// consumed" scenario rather than the generic re-login prompt.
    /// Journal 0009 / 0010.
    #[error("codex refresh token reused for account {account} (re-login required)")]
    CodexRefreshReused { account: u16 },
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

    // --- Codex-specific redactor patterns (PR-C0, journal 0010) ---

    /// Codex refresh tokens use the `rt_` prefix (observed in
    /// `~/.codex/auth.json` post re-login).
    #[test]
    fn redact_tokens_codex_rt_prefix() {
        let input = "refresh=rt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let output = redact_tokens(input);
        assert_eq!(output, "refresh=[REDACTED]");
    }

    /// Short `rt_` strings (e.g. variable names in logs) must NOT be redacted.
    #[test]
    fn redact_tokens_short_rt_not_redacted() {
        let input = "rt_queue_size value exceeded";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// PR-G2a: Google AI Studio API keys (`AIza` + 35 chars).
    #[test]
    fn redact_tokens_google_aiza_key() {
        // Google's documented key shape: AIza + 35 base64url chars.
        let input = "x-goog-api-key: AIzaSyTESTKEY1234567890_abcdefgh-IJKLM";
        let output = redact_tokens(input);
        assert_eq!(output, "x-goog-api-key: [REDACTED]");
    }

    /// PR-G2a: short `AIza` strings (under the 30-char body floor)
    /// must NOT be redacted — they are not real keys and matching
    /// them would create false positives in error fixtures and test
    /// data that uses the prefix illustratively.
    #[test]
    fn redact_tokens_short_aiza_not_redacted() {
        let input = "see also AIzaShortNotReal";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// PR-G2a: `AIza` mid-word must NOT trigger redaction (word
    /// boundary guard from the existing redactor design).
    #[test]
    fn redact_tokens_aiza_mid_word_not_redacted() {
        let input = "module_AIza_internal_helper_name_long_enough";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// PR-G2a: PEM block (Vertex SA JSON private_key field). One of
    /// the worst leak modes — a stack-trace `format!("{e}")` near a
    /// JSON parse error containing a PEM block would otherwise dump
    /// the entire signing key. Multi-line aware.
    #[test]
    fn redact_tokens_pem_private_key_block() {
        let input = "parse error: \"private_key\": \"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEF\nAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----\\n\"";
        let output = redact_tokens(input);
        assert!(
            output.contains("[REDACTED]"),
            "PEM block must be redacted: {output}"
        );
        assert!(
            !output.contains("MIIEvQIBADANBgkqhkiG"),
            "key body must not appear in output: {output}"
        );
        assert!(
            !output.contains("-----BEGIN"),
            "BEGIN marker must not survive: {output}"
        );
    }

    /// PR-G2a: PEM with the `RSA PRIVATE KEY` tag (legacy format)
    /// must also redact. Permissive tag matching catches every PEM
    /// type without enumerating them.
    #[test]
    fn redact_tokens_pem_rsa_private_key_block() {
        let input = "key: -----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----";
        let output = redact_tokens(input);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("ABCDEF"));
    }

    /// PR-G2a: an unterminated PEM block — defensive redaction. We
    /// would rather over-redact a malformed log line than leak half
    /// a key.
    #[test]
    fn redact_tokens_pem_unterminated_block_redacted() {
        let input = "leaked: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n[truncated]";
        let output = redact_tokens(input);
        assert!(!output.contains("MIIEvQ"));
        assert!(output.contains("[REDACTED]"));
    }

    /// PR-G2a: text containing "-----BEGIN" without a PAIRED PEM
    /// shape (no END marker AND no tag) should not be aggressively
    /// redacted. This documents the chosen behaviour: presence of
    /// `-----BEGIN ` + space implies an attempted PEM, so we redact;
    /// presence of `------BEGIN` (six dashes) or `-----BEGIN-` (no
    /// space) does not.
    #[test]
    fn redact_tokens_text_without_pem_shape_passes_through() {
        let input = "section -----BEGINNING----- of file";
        let output = redact_tokens(input);
        // The "-----BEGINNING-----" string has no following space
        // after BEGIN, so the BEGIN_MARKER `"-----BEGIN "` does NOT
        // match. Expect pass-through.
        assert_eq!(output, input);
    }

    /// OpenAI `sess-*` session tokens (plan §3.3 prefix).
    #[test]
    fn redact_tokens_codex_sess_prefix() {
        let input = "cookie=sess-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let output = redact_tokens(input);
        assert_eq!(output, "cookie=[REDACTED]");
    }

    /// JWT triple-segment (Codex id_token / access_token format per
    /// journal 0010).
    #[test]
    fn redact_tokens_jwt_triple_segment() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.abcdefghijklmnopqrstuvwxyz";
        let output = redact_tokens(input);
        assert_eq!(output, "Authorization: Bearer [REDACTED]");
    }

    /// Realistic long JWT (simulates ~2000-char OpenAI id_token).
    #[test]
    fn redact_tokens_long_jwt() {
        let seg1 = "a".repeat(400);
        let seg2 = "b".repeat(400);
        let seg3 = "c".repeat(64);
        let jwt = format!("eyJ{seg1}.eyJ{seg2}.{seg3}");
        let input = format!("token={jwt}");
        let output = redact_tokens(&input);
        assert_eq!(output, "token=[REDACTED]");
    }

    /// Two-segment `eyJ.eyJ` (malformed JWT — no signature) is NOT redacted
    /// via the JWT pattern. It may still trip other patterns (e.g. hex) but
    /// the JWT pattern specifically requires all three segments.
    #[test]
    fn redact_tokens_two_segment_eyj_not_matched_as_jwt() {
        // Use long-but-non-hex body to avoid pattern-3 false match.
        let seg1 = "z".repeat(40);
        let seg2 = "z".repeat(40);
        let input = format!("header=eyJ{seg1}.eyJ{seg2}");
        let output = redact_tokens(&input);
        // Unchanged — no third segment
        assert_eq!(output, input);
    }

    /// Single-segment `eyJ` is NOT redacted — could be any base64url string
    /// that happens to start with `eyJ` (e.g. encoded data in logs).
    #[test]
    fn redact_tokens_single_segment_eyj_not_matched() {
        let input = "prefix=eyJhbGciOiJIUzI1NiJ9 no dots here";
        let output = redact_tokens(input);
        assert_eq!(output, input);
    }

    /// JWT mid-sentence: surrounding text must survive.
    ///
    /// Uses segment bodies ≥ `JWT_SEGMENT_MIN_BODY` so the pattern fires;
    /// realistic OpenAI id_tokens have seg bodies in the hundreds of chars,
    /// not the test-minimum 17.
    #[test]
    fn redact_tokens_jwt_mid_sentence() {
        let input = "upstream said: eyJhbGciOiJIUzI1NiJ9XXX.eyJpc3MiOiJjc3EifQYYYY.ZZZZsignaturebytesgohere and then more text";
        let output = redact_tokens(input);
        assert_eq!(output, "upstream said: [REDACTED] and then more text");
    }

    /// Multiple distinct token classes in one string redact independently.
    #[test]
    fn redact_tokens_mixed_codex_and_anthropic() {
        let jwt = format!(
            "eyJ{}.eyJ{}.{}",
            "a".repeat(30),
            "b".repeat(30),
            "c".repeat(30)
        );
        let input =
            format!("codex-access={jwt} anthropic-oat=sk-ant-oat01-XXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        let output = redact_tokens(&input);
        assert_eq!(output, "codex-access=[REDACTED] anthropic-oat=[REDACTED]");
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
