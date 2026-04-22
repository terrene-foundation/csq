//! Codex-specific HTTP bridge over the Node subprocess transport.
//!
//! Codex (OpenAI ChatGPT subscription) endpoints sit behind Cloudflare's
//! JA3/JA4 TLS fingerprint filter, which body-strips reqwest/rustls
//! responses (status 401 + `cf-ray` header present, body reduced from the
//! full OpenAI JSON envelope to `{"error": {}, "status": 401}`). This
//! prevents the refresher and wham/usage poller from routing on the
//! `error.code` field they need to distinguish `token_expired` from
//! `refresh_token_reused`. See `workspaces/codex/journal/0007` for the
//! empirical verification and the PR-C0.5 decision to reuse the Node
//! subprocess pattern originally built for Anthropic (journal csq-v2/0056).
//!
//! This module is a THIN wrapper: it does not re-implement HTTP. All
//! transport work is delegated to [`super::post_json_node`] and
//! [`super::get_bearer_node`]. This module's value-add is:
//!
//! 1. Codex-specific URLs + client_id constant (avoids typo-drift at
//!    call sites).
//! 2. Structured request bodies (no hand-rolled JSON at the refresher).
//! 3. Structured response parsing with PII dropped at the deserialize
//!    layer — `#[derive(Deserialize)]` structs omit `user_id`,
//!    `account_id`, `email` fields so those values never enter the Rust
//!    address space, let alone logs or telemetry.
//! 4. Typed error mapping: `code: "token_expired"` →
//!    [`CodexHttpError::TokenExpired`]; `code: "refresh_token_reused"` →
//!    [`CodexHttpError::RefreshReused`]. These convert into the
//!    [`BrokerError`] variants added in PR-C0.
//!
//! # Testability
//!
//! The public entry points ([`refresh_access_token`],
//! [`fetch_wham_usage`]) delegate to transport-injected helpers
//! ([`refresh_with_http`], [`fetch_wham_with_http`]) so tests can feed
//! pre-canned response bodies without spawning Node subprocesses.
//! Matches the `testing.md` Rule 5 contract — the mock closure signature
//! is byte-for-byte identical to the production transport.

use crate::error::BrokerError;
use serde::Deserialize;

/// OpenAI OAuth token endpoint. Same URL Codex-CLI targets.
pub(crate) const OAUTH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

/// ChatGPT subscription usage endpoint. Observed response shape pinned
/// by spec 05 §5.7 / journal 0010.
pub(crate) const WHAM_USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";

/// Codex-CLI's bundled OAuth client_id. Hardcoded in the upstream Node
/// bundle; visible in `grep -r app_EMoam` on the installed codex binary.
/// Mirrors codex-cli's behavior per spec 07 §7.3.3 — any deviation from
/// this constant will cause OAuth to fail.
pub(crate) const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

// ─── Public types ────────────────────────────────────────────────────

/// Tokens returned by a successful `/oauth/token` refresh.
///
/// String ownership is explicit — callers are responsible for hashing
/// into `SecretString` (or equivalent) if they retain these for any
/// appreciable time. This layer does NOT wrap in `SecretString` because
/// the immediate consumer (the refresher) needs to serialize them back
/// to `~/.codex/auth.json` via the atomic-replace helper.
#[derive(Debug, Clone, Deserialize)]
pub struct CodexTokens {
    pub access_token: String,
    /// Optional because OpenAI rotates refresh tokens on every refresh,
    /// but the response shape for some intermediate states may omit it.
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    /// OpenAI account identifier surfaced in post-login auth.json per
    /// journal 0010. Kept as-is — not PII in the same class as email.
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

/// A single rate-limit window (primary 5h OR secondary 7d per spec 05
/// §5.7). Fields mirror the observed response; `used_percent` is already
/// a percentage (0-100), not a fraction (0-1) — consistent with
/// Anthropic's `/api/oauth/usage` convention.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct WhamWindow {
    pub used_percent: f64,
    pub limit_window_seconds: u64,
    pub reset_after_seconds: u64,
    /// Unix epoch (seconds) at which the window resets. Absolute is
    /// preferred over `reset_after_seconds` because it is idempotent
    /// across retries.
    pub reset_at: u64,
}

/// Structured wham/usage response with PII stripped at the deserialize
/// layer. `user_id`, `account_id`, `email` are NOT in this struct — they
/// are silently dropped by serde when parsing.
#[derive(Debug, Clone, Deserialize)]
pub struct WhamSnapshot {
    /// E.g. `"plus"`, `"team"`, `"free"`. Safe to store as UI-label;
    /// not a credential.
    pub plan_type: String,
    pub rate_limit: WhamRateLimit,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhamRateLimit {
    pub allowed: bool,
    pub limit_reached: bool,
    pub primary_window: WhamWindow,
    pub secondary_window: WhamWindow,
}

/// Typed Codex HTTP error variants. Distinguished from generic
/// `BrokerError` so this module can fail-loud on Codex-specific codes
/// (`token_expired`, `refresh_token_reused`) without forcing every
/// caller to pattern-match response bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexHttpError {
    /// `code: "token_expired"` — refresh token expired server-side.
    /// User must `codex login` again.
    TokenExpired,
    /// `code: "refresh_token_reused"` — submitted refresh token was
    /// already consumed. OpenAI rotates refresh tokens on every refresh;
    /// reusing a prior token triggers this. User must `codex login`.
    RefreshReused,
    /// Upstream returned an error envelope that doesn't match the two
    /// known re-login codes. `tag` is the parsed `code` field (if any),
    /// `status` is the HTTP status. Body content is NOT included to
    /// avoid echoing PII / tokens.
    Upstream { status: u16, tag: Option<String> },
    /// Response body couldn't be parsed as either success or error
    /// shape. `status` is the HTTP status. Typically indicates upstream
    /// schema drift — surface as `QuotaKind::Unknown` at the caller.
    MalformedResponse { status: u16 },
    /// Transport layer failed (Node subprocess spawn, TLS handshake,
    /// timeout). Error detail is NOT retained to avoid echoing any
    /// upstream body fragments in logs.
    Transport,
}

impl std::fmt::Display for CodexHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TokenExpired => write!(f, "codex token expired"),
            Self::RefreshReused => write!(f, "codex refresh token reused"),
            Self::Upstream { status, tag } => {
                if let Some(t) = tag {
                    write!(f, "codex upstream {status} ({t})")
                } else {
                    write!(f, "codex upstream {status}")
                }
            }
            Self::MalformedResponse { status } => {
                write!(f, "codex malformed response (status {status})")
            }
            Self::Transport => write!(f, "codex transport failure"),
        }
    }
}

impl std::error::Error for CodexHttpError {}

impl CodexHttpError {
    /// Converts to a `BrokerError` variant given the account number.
    ///
    /// The refresher calls this to route typed HTTP outcomes into the
    /// daemon's broker-error channel. The PR-C0 additions
    /// ([`BrokerError::CodexTokenExpired`],
    /// [`BrokerError::CodexRefreshReused`]) are the target variants.
    pub fn into_broker(self, account: u16) -> BrokerError {
        match self {
            Self::TokenExpired => BrokerError::CodexTokenExpired { account },
            Self::RefreshReused => BrokerError::CodexRefreshReused { account },
            Self::Upstream { status, tag } => BrokerError::RefreshFailed {
                account,
                reason: match tag {
                    Some(t) => format!("upstream {status} ({t})"),
                    None => format!("upstream {status}"),
                },
            },
            Self::MalformedResponse { status } => BrokerError::RefreshFailed {
                account,
                reason: format!("malformed response (status {status})"),
            },
            Self::Transport => BrokerError::RefreshFailed {
                account,
                reason: "transport failure".into(),
            },
        }
    }
}

// ─── Internal wire types (do NOT implement Display; callers pull
//     only typed fields) ────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Debug, Deserialize)]
struct ErrorDetail {
    /// We do NOT read `message` — it may contain upstream body fragments.
    #[serde(default, rename = "code")]
    code: Option<String>,
    /// Kept for observability / tag fallback.
    #[serde(default, rename = "type")]
    #[allow(dead_code)]
    error_type: Option<String>,
}

// ─── Public entry points (transport: Node subprocess) ───────────────

/// Refreshes a Codex access token via OpenAI's `/oauth/token`.
///
/// Hits the production Node transport; the body is piped via stdin so
/// the refresh token never appears in `ps` / argv. Parses the response
/// into either [`CodexTokens`] or a typed [`CodexHttpError`].
pub fn refresh_access_token(refresh_token: &str) -> Result<CodexTokens, CodexHttpError> {
    refresh_with_http(refresh_token, super::post_json_node)
}

/// Like [`refresh_access_token`] but also returns the response `Date`
/// header for clock-skew detection (PR-C4 INV-P01).
///
/// The returned `Option<String>` is whatever the Node transport
/// surfaced as the server's `Date` header (RFC 7231 §7.1.1.2 IMF-fixdate
/// format, e.g. `"Tue, 22 Apr 2026 14:32:01 GMT"`). Callers parse it
/// via [`parse_http_date_secs`] and emit a `clock_skew_detected` warn
/// when local time differs from server by > [`CLOCK_SKEW_WARN_SECS`].
pub fn refresh_access_token_with_date(
    refresh_token: &str,
) -> Result<(CodexTokens, Option<String>), CodexHttpError> {
    refresh_with_http_meta(refresh_token, super::post_json_node_with_date)
}

/// Fetches a wham/usage snapshot via the bearer access token.
///
/// Parses into [`WhamSnapshot`] with PII dropped (user_id, account_id,
/// email are not deserialized — they stay in the raw response bytes and
/// are discarded when the Vec drops).
pub fn fetch_wham_usage(access_token: &str) -> Result<WhamSnapshot, CodexHttpError> {
    fetch_wham_with_http(access_token, super::get_bearer_node)
}

// ─── Transport-injected helpers (for tests) ─────────────────────────

pub(crate) fn refresh_with_http<F>(
    refresh_token: &str,
    http_post: F,
) -> Result<CodexTokens, CodexHttpError>
where
    F: FnOnce(&str, &str) -> Result<Vec<u8>, String>,
{
    // Construct the request body via serde_json so values are properly
    // escaped — the refresh token may contain chars that would break a
    // hand-rolled format! string.
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    })
    .to_string();

    let bytes = http_post(OAUTH_TOKEN_URL, &body).map_err(|_| CodexHttpError::Transport)?;

    // Success/error discrimination by shape, not status (post_json_node
    // doesn't surface status). Try success first; fall back to error.
    parse_refresh_response(200, &bytes)
}

/// Like [`refresh_with_http`] but the injected transport also returns
/// the server `Date` header. PR-C4 broker_codex_check uses this to
/// emit `clock_skew_detected` when local time differs from server by
/// > [`CLOCK_SKEW_WARN_SECS`].
pub(crate) fn refresh_with_http_meta<F>(
    refresh_token: &str,
    http_post: F,
) -> Result<(CodexTokens, Option<String>), CodexHttpError>
where
    F: FnOnce(&str, &str) -> Result<(Vec<u8>, Option<String>), String>,
{
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    })
    .to_string();

    let (bytes, date) = http_post(OAUTH_TOKEN_URL, &body).map_err(|_| CodexHttpError::Transport)?;

    parse_refresh_response(200, &bytes).map(|tokens| (tokens, date))
}

/// Threshold beyond which the daemon emits a `clock_skew_detected`
/// warning (spec 07 §7.5 INV-P01). Local time differing from the
/// server `Date` header by more than this value indicates the host
/// clock has drifted enough to risk the daemon's pre-expiry refresh
/// missing the codex on-expiry threshold.
pub const CLOCK_SKEW_WARN_SECS: u64 = 5 * 60;

/// Parses an RFC 7231 §7.1.1.2 IMF-fixdate `Date` header into seconds
/// since the Unix epoch.
///
/// Returns `None` if the input does not match the IMF-fixdate format.
/// The two RFC-allowed obsolete formats (RFC 850 / asctime) are not
/// accepted — modern HTTP servers (including OpenAI's Cloudflare-
/// fronted endpoints) emit IMF-fixdate; conservative parsing avoids
/// false positives that would mis-fire the clock-skew warning.
///
/// Implementation is hand-rolled to avoid pulling in a date crate
/// (csq currently depends on no time-parsing dependency). Only month
/// and day-of-month parsing is done from scratch; leap-year and
/// month-length tables are inline.
pub fn parse_http_date_secs(date: &str) -> Option<u64> {
    // IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`
    let s = date.trim();
    if !s.ends_with(" GMT") {
        return None;
    }
    let parts: Vec<&str> = s.split_ascii_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    // parts: ["Sun,", "06", "Nov", "1994", "08:49:37", "GMT"]
    let day: u32 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: u32 = parts[3].parse().ok()?;
    let time: Vec<&str> = parts[4].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let hour: u32 = time[0].parse().ok()?;
    let minute: u32 = time[1].parse().ok()?;
    let second: u32 = time[2].parse().ok()?;

    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }

    // Days from epoch (1970-01-01) to the given date.
    let days_to_year: u64 = (1970..year)
        .map(|y| if is_leap(y) { 366 } else { 365 })
        .sum();
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days_to_month: u64 = month_days[..(month as usize - 1)].iter().sum();
    if month > 2 && is_leap(year) {
        days_to_month += 1;
    }
    let total_days = days_to_year + days_to_month + (day as u64 - 1);
    Some(total_days * 86_400 + (hour as u64) * 3_600 + (minute as u64) * 60 + (second as u64))
}

fn is_leap(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Decodes the `exp` claim from a JWT access token, returning epoch
/// seconds. Returns `None` for any malformed input — callers treat
/// "undecodeable" as "needs refresh now" (safer to refresh than to
/// trust an opaque token).
///
/// JWT format: `<base64url-header>.<base64url-payload>.<signature>`.
/// Only the payload is decoded; signature validation is the upstream's
/// job (csq is the client, not the verifier).
///
/// Hand-rolled base64url-no-padding decoder so csq does not pull in a
/// new dependency. The header and signature segments are not touched.
pub fn jwt_exp_secs(jwt: &str) -> Option<u64> {
    let mut parts = jwt.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let _sig = parts.next()?;
    if parts.next().is_some() {
        return None; // more than 3 segments
    }
    let payload_bytes = b64url_decode(payload_b64)?;
    let value: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    let exp = value.get("exp")?;
    exp.as_u64()
        .or_else(|| exp.as_i64().and_then(|n| u64::try_from(n).ok()))
}

/// Minimal base64url (RFC 4648 §5) decoder, no-padding tolerant.
/// Returns `None` on any non-charset byte.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => 26 + (c - b'a') as u32,
            b'0'..=b'9' => 52 + (c - b'0') as u32,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        })
    }

    // Strip optional padding.
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|&b| b != b'=' && b != b'\n' && b != b'\r')
        .collect();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4 + 3);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in bytes {
        let v = val(c)?;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub(crate) fn fetch_wham_with_http<F>(
    access_token: &str,
    http_get: F,
) -> Result<WhamSnapshot, CodexHttpError>
where
    F: FnOnce(&str, &str, &[(&str, &str)]) -> Result<(u16, Vec<u8>), String>,
{
    let (status, bytes) =
        http_get(WHAM_USAGE_URL, access_token, &[]).map_err(|_| CodexHttpError::Transport)?;
    parse_wham_response(status, &bytes)
}

// ─── Pure parsers (no I/O, fully test-exercisable) ─────────────────

fn parse_refresh_response(_status: u16, bytes: &[u8]) -> Result<CodexTokens, CodexHttpError> {
    // Prefer the success shape — it has an `access_token` field that
    // error envelopes never contain.
    if let Ok(tokens) = serde_json::from_slice::<CodexTokens>(bytes) {
        // Sanity: success body must include a non-empty access_token.
        if !tokens.access_token.is_empty() {
            return Ok(tokens);
        }
    }
    // Error envelope.
    if let Ok(err) = serde_json::from_slice::<ErrorEnvelope>(bytes) {
        return Err(classify_error(0, err.error.code));
    }
    Err(CodexHttpError::MalformedResponse { status: 0 })
}

pub(crate) fn parse_wham_response(
    status: u16,
    bytes: &[u8],
) -> Result<WhamSnapshot, CodexHttpError> {
    if status == 200 {
        if let Ok(snap) = serde_json::from_slice::<WhamSnapshot>(bytes) {
            return Ok(snap);
        }
        return Err(CodexHttpError::MalformedResponse { status });
    }
    // Non-200: prefer the error envelope to route on code.
    if let Ok(err) = serde_json::from_slice::<ErrorEnvelope>(bytes) {
        return Err(classify_error(status, err.error.code));
    }
    Err(CodexHttpError::MalformedResponse { status })
}

/// Maps a `code` string into the typed variant. Falls back to
/// [`CodexHttpError::Upstream`] for unknown codes.
fn classify_error(status: u16, code: Option<String>) -> CodexHttpError {
    match code.as_deref() {
        Some("token_expired") => CodexHttpError::TokenExpired,
        Some("refresh_token_reused") => CodexHttpError::RefreshReused,
        _ => CodexHttpError::Upstream { status, tag: code },
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_refresh_response ───────────────────────────────────

    #[test]
    fn parse_refresh_success_returns_tokens() {
        let body = br#"{"access_token":"new_at","refresh_token":"rt_new","id_token":"new_id","token_type":"bearer","expires_in":3600}"#;
        let r = parse_refresh_response(200, body).expect("should parse");
        assert_eq!(r.access_token, "new_at");
        assert_eq!(r.refresh_token.as_deref(), Some("rt_new"));
        assert_eq!(r.id_token.as_deref(), Some("new_id"));
        assert_eq!(r.expires_in, Some(3600));
    }

    #[test]
    fn parse_refresh_token_expired_is_typed() {
        let body = br#"{"error":{"message":"...","type":"invalid_request_error","param":null,"code":"token_expired"}}"#;
        let e = parse_refresh_response(401, body).unwrap_err();
        assert_eq!(e, CodexHttpError::TokenExpired);
    }

    #[test]
    fn parse_refresh_refresh_reused_is_typed() {
        let body = br#"{"error":{"message":"Your refresh token has already been used to generate a new access token. Please try signing in again.","type":"invalid_request_error","param":null,"code":"refresh_token_reused"}}"#;
        let e = parse_refresh_response(401, body).unwrap_err();
        assert_eq!(e, CodexHttpError::RefreshReused);
    }

    #[test]
    fn parse_refresh_unknown_code_is_upstream() {
        let body = br#"{"error":{"message":"x","type":"y","code":"some_new_code"}}"#;
        let e = parse_refresh_response(401, body).unwrap_err();
        assert!(matches!(
            e,
            CodexHttpError::Upstream { tag: Some(ref t), .. } if t == "some_new_code"
        ));
    }

    #[test]
    fn parse_refresh_malformed_body() {
        let body = b"<html>gateway timeout</html>";
        let e = parse_refresh_response(502, body).unwrap_err();
        assert!(matches!(e, CodexHttpError::MalformedResponse { .. }));
    }

    #[test]
    fn parse_refresh_empty_access_token_is_not_success() {
        // An error envelope that happens to have an `access_token` field
        // set to empty string must NOT be misclassified as success.
        let body = br#"{"access_token":"","error":{"code":"token_expired"}}"#;
        let e = parse_refresh_response(401, body).unwrap_err();
        assert_eq!(e, CodexHttpError::TokenExpired);
    }

    // ── parse_wham_response ──────────────────────────────────────

    const WHAM_SUCCESS_BODY: &[u8] = br#"{
        "user_id": "PII-MUST-BE-DROPPED",
        "account_id": "PII-MUST-BE-DROPPED",
        "email": "PII-MUST-BE-DROPPED",
        "plan_type": "plus",
        "rate_limit": {
            "allowed": true,
            "limit_reached": false,
            "primary_window": {
                "used_percent": 42.5,
                "limit_window_seconds": 18000,
                "reset_after_seconds": 9000,
                "reset_at": 4102444800
            },
            "secondary_window": {
                "used_percent": 12.5,
                "limit_window_seconds": 604800,
                "reset_after_seconds": 600000,
                "reset_at": 4102444900
            }
        },
        "code_review_rate_limit": null,
        "additional_rate_limits": null,
        "credits": { "has_credits": false, "unlimited": false, "overage_limit_reached": false, "balance": "0", "approx_local_messages": [0,0], "approx_cloud_messages": [0,0] },
        "spend_control": { "reached": false },
        "rate_limit_reached_type": null,
        "promo": null,
        "referral_beacon": null
    }"#;

    #[test]
    fn parse_wham_success_returns_snapshot() {
        let s = parse_wham_response(200, WHAM_SUCCESS_BODY).expect("should parse");
        assert_eq!(s.plan_type, "plus");
        assert!(s.rate_limit.allowed);
        assert!(!s.rate_limit.limit_reached);
        assert_eq!(s.rate_limit.primary_window.used_percent, 42.5);
        assert_eq!(s.rate_limit.primary_window.limit_window_seconds, 18000);
        assert_eq!(s.rate_limit.primary_window.reset_at, 4_102_444_800);
        assert_eq!(s.rate_limit.secondary_window.limit_window_seconds, 604_800);
    }

    /// PII fields MUST be discarded at deserialize time (the struct
    /// has no fields for them; serde_json silently drops unknown keys).
    /// This test asserts the TYPE has no such fields by attempting a
    /// Debug format and searching for PII values.
    #[test]
    fn parse_wham_drops_pii_fields() {
        let s = parse_wham_response(200, WHAM_SUCCESS_BODY).expect("should parse");
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains("PII-MUST-BE-DROPPED"),
            "PII leaked into parsed snapshot: {dbg}"
        );
    }

    #[test]
    fn parse_wham_401_token_expired() {
        let body = br#"{"error":{"message":"Provided authentication token is expired. Please try signing in again.","type":null,"code":"token_expired","param":null},"status":401}"#;
        let e = parse_wham_response(401, body).unwrap_err();
        assert_eq!(e, CodexHttpError::TokenExpired);
    }

    #[test]
    fn parse_wham_403_unknown_code_is_upstream() {
        let body = br#"{"error":{"message":"x","type":"y","code":"account_suspended"}}"#;
        let e = parse_wham_response(403, body).unwrap_err();
        assert!(matches!(
            e,
            CodexHttpError::Upstream { status: 403, tag: Some(ref t) } if t == "account_suspended"
        ));
    }

    #[test]
    fn parse_wham_500_no_code_is_upstream() {
        let body = br#"{"error":{"message":"server error","type":"server_error","code":null}}"#;
        let e = parse_wham_response(500, body).unwrap_err();
        assert!(matches!(
            e,
            CodexHttpError::Upstream {
                status: 500,
                tag: None
            }
        ));
    }

    #[test]
    fn parse_wham_200_malformed_body() {
        let body = br#"{"not":"the expected shape"}"#;
        let e = parse_wham_response(200, body).unwrap_err();
        assert!(matches!(
            e,
            CodexHttpError::MalformedResponse { status: 200 }
        ));
    }

    // ── refresh_with_http + fetch_wham_with_http (mock transports) ──

    #[test]
    fn refresh_with_http_sends_expected_post_body() {
        // Capture the URL + body passed to the transport and return a
        // canned success response.
        use std::cell::RefCell;
        let captured: RefCell<Option<(String, String)>> = RefCell::new(None);
        let mock_post = |url: &str, body: &str| -> Result<Vec<u8>, String> {
            *captured.borrow_mut() = Some((url.to_string(), body.to_string()));
            Ok(br#"{"access_token":"fresh_at"}"#.to_vec())
        };
        let tokens = refresh_with_http("rt_user_refresh_token", mock_post).expect("ok");
        assert_eq!(tokens.access_token, "fresh_at");

        let (url, body) = captured.into_inner().expect("transport was called");
        assert_eq!(url, OAUTH_TOKEN_URL);
        // Body is JSON-encoded — key order may vary, so parse + check
        // fields.
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["grant_type"], "refresh_token");
        assert_eq!(parsed["refresh_token"], "rt_user_refresh_token");
        assert_eq!(parsed["client_id"], CLIENT_ID);
    }

    #[test]
    fn refresh_with_http_transport_error_maps_to_transport_variant() {
        let mock_post =
            |_url: &str, _body: &str| -> Result<Vec<u8>, String> { Err("connect refused".into()) };
        let e = refresh_with_http("rt_x", mock_post).unwrap_err();
        assert_eq!(e, CodexHttpError::Transport);
    }

    #[test]
    fn fetch_wham_with_http_passes_bearer_and_returns_snapshot() {
        use std::cell::RefCell;
        let captured: RefCell<Option<(String, String)>> = RefCell::new(None);
        let mock_get =
            |url: &str, token: &str, _extra: &[(&str, &str)]| -> Result<(u16, Vec<u8>), String> {
                *captured.borrow_mut() = Some((url.to_string(), token.to_string()));
                Ok((200, WHAM_SUCCESS_BODY.to_vec()))
            };
        let snap = fetch_wham_with_http("test_access_token", mock_get).expect("ok");
        assert_eq!(snap.plan_type, "plus");

        let (url, token) = captured.into_inner().expect("transport was called");
        assert_eq!(url, WHAM_USAGE_URL);
        assert_eq!(token, "test_access_token");
    }

    #[test]
    fn fetch_wham_transport_error_maps_to_transport_variant() {
        let mock_get = |_u: &str,
                        _t: &str,
                        _h: &[(&str, &str)]|
         -> Result<(u16, Vec<u8>), String> { Err("timeout".into()) };
        let e = fetch_wham_with_http("access", mock_get).unwrap_err();
        assert_eq!(e, CodexHttpError::Transport);
    }

    // ── CodexHttpError::into_broker ──────────────────────────────

    #[test]
    fn into_broker_token_expired_maps_to_codex_variant() {
        let b = CodexHttpError::TokenExpired.into_broker(7);
        assert!(matches!(b, BrokerError::CodexTokenExpired { account: 7 }));
    }

    #[test]
    fn into_broker_refresh_reused_maps_to_codex_variant() {
        let b = CodexHttpError::RefreshReused.into_broker(7);
        assert!(matches!(b, BrokerError::CodexRefreshReused { account: 7 }));
    }

    #[test]
    fn into_broker_upstream_falls_back_to_refresh_failed() {
        let b = CodexHttpError::Upstream {
            status: 403,
            tag: Some("account_suspended".into()),
        }
        .into_broker(7);
        match b {
            BrokerError::RefreshFailed { account, reason } => {
                assert_eq!(account, 7);
                assert!(reason.contains("403"));
                assert!(reason.contains("account_suspended"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn into_broker_transport_falls_back_to_refresh_failed() {
        let b = CodexHttpError::Transport.into_broker(9);
        match b {
            BrokerError::RefreshFailed { account, reason } => {
                assert_eq!(account, 9);
                assert_eq!(reason, "transport failure");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    // ── refresh_with_http_meta ───────────────────────────────────

    #[test]
    fn refresh_with_http_meta_returns_date_alongside_tokens() {
        let mock_post = |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Ok((
                br#"{"access_token":"fresh"}"#.to_vec(),
                Some("Tue, 22 Apr 2026 14:32:01 GMT".to_string()),
            ))
        };
        let (tokens, date) = refresh_with_http_meta("rt_x", mock_post).expect("ok");
        assert_eq!(tokens.access_token, "fresh");
        assert_eq!(date.as_deref(), Some("Tue, 22 Apr 2026 14:32:01 GMT"));
    }

    #[test]
    fn refresh_with_http_meta_propagates_transport_error() {
        let mock_post = |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Err("connect refused".into())
        };
        let e = refresh_with_http_meta("rt_x", mock_post).unwrap_err();
        assert_eq!(e, CodexHttpError::Transport);
    }

    #[test]
    fn refresh_with_http_meta_returns_typed_token_expired_with_date() {
        let mock_post = |_url: &str, _body: &str| -> Result<(Vec<u8>, Option<String>), String> {
            Ok((
                br#"{"error":{"code":"token_expired"}}"#.to_vec(),
                Some("Tue, 22 Apr 2026 14:32:01 GMT".to_string()),
            ))
        };
        let e = refresh_with_http_meta("rt_x", mock_post).unwrap_err();
        assert_eq!(e, CodexHttpError::TokenExpired);
    }

    // ── parse_http_date_secs ─────────────────────────────────────

    #[test]
    fn parse_http_date_imf_fixdate_round_trips_known_epoch() {
        // Cross-checked against `date -u -d "2024-01-01 00:00:00" +%s` → 1704067200.
        let secs = parse_http_date_secs("Mon, 01 Jan 2024 00:00:00 GMT").unwrap();
        assert_eq!(secs, 1_704_067_200);
    }

    #[test]
    fn parse_http_date_unix_epoch_is_zero() {
        let secs = parse_http_date_secs("Thu, 01 Jan 1970 00:00:00 GMT").unwrap();
        assert_eq!(secs, 0);
    }

    #[test]
    fn parse_http_date_handles_leap_year() {
        // 2024-02-29 12:00:00 UTC — must not reject the leap day.
        let secs = parse_http_date_secs("Thu, 29 Feb 2024 12:00:00 GMT").unwrap();
        assert!(secs > 1_700_000_000);
    }

    #[test]
    fn parse_http_date_rejects_non_imf_format() {
        // RFC 850 obsolete format — not accepted.
        assert!(parse_http_date_secs("Sunday, 06-Nov-94 08:49:37 GMT").is_none());
        // asctime — not accepted.
        assert!(parse_http_date_secs("Sun Nov  6 08:49:37 1994").is_none());
    }

    #[test]
    fn parse_http_date_rejects_garbage() {
        assert!(parse_http_date_secs("not a date").is_none());
        assert!(parse_http_date_secs("").is_none());
        assert!(parse_http_date_secs("Mon, 32 Apr 2026 14:32:01 GMT").is_none());
        assert!(parse_http_date_secs("Mon, 22 Foo 2026 14:32:01 GMT").is_none());
        assert!(parse_http_date_secs("Mon, 22 Apr 2026 25:32:01 GMT").is_none());
    }

    // ── jwt_exp_secs ────────────────────────────────────────────

    #[test]
    fn jwt_exp_secs_decodes_payload_exp_claim() {
        // header={"alg":"none"}, payload={"exp":1700000000}, sig=anything.
        // base64url no-padding: "eyJhbGciOiJub25lIn0", "eyJleHAiOjE3MDAwMDAwMDB9", "sig".
        let jwt = "eyJhbGciOiJub25lIn0.eyJleHAiOjE3MDAwMDAwMDB9.sig";
        assert_eq!(jwt_exp_secs(jwt), Some(1_700_000_000));
    }

    #[test]
    fn jwt_exp_secs_returns_none_for_malformed_jwt() {
        assert_eq!(jwt_exp_secs("not.a.jwt-payload"), None);
        assert_eq!(jwt_exp_secs("only-one-segment"), None);
        assert_eq!(jwt_exp_secs("two.segments"), None);
        // Four segments
        assert_eq!(jwt_exp_secs("a.b.c.d"), None);
    }

    #[test]
    fn jwt_exp_secs_returns_none_when_payload_missing_exp() {
        // payload={"sub":"foo"} — no exp claim.
        let jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmb28ifQ.sig";
        assert_eq!(jwt_exp_secs(jwt), None);
    }

    #[test]
    fn jwt_exp_secs_returns_none_for_non_b64url_payload() {
        let jwt = "header.+++not_b64url+++.sig";
        assert_eq!(jwt_exp_secs(jwt), None);
    }

    // ── CodexHttpError::Display (no body fragments leak) ─────────

    #[test]
    fn display_does_not_leak_bodies() {
        // Even when tag is attacker-controlled, Display must NOT leak
        // more than the tag + status.
        let e = CodexHttpError::Upstream {
            status: 401,
            tag: Some("attacker_controlled_string".into()),
        };
        let s = format!("{e}");
        assert!(s.contains("401"));
        assert!(s.contains("attacker_controlled_string"));
        // Sanity: no common body phrases that would indicate full-body
        // leakage into Display.
        assert!(!s.contains("message"));
        assert!(!s.contains("refresh_token"));
        assert!(!s.contains("access_token"));
    }
}
