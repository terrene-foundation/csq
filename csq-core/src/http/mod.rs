//! HTTP transports for csq.
//!
//! Two transport layers:
//!
//! 1. **reqwest** (`rustls-tls-webpki-roots`) — used for 3P provider
//!    endpoints (MiniMax, Z.AI, GitHub Releases) that don't fingerprint
//!    TLS connections.
//!
//! 2. **Node.js subprocess** — used for Anthropic endpoints
//!    (`platform.claude.com`, `api.anthropic.com`). Cloudflare's
//!    JA3/JA4 TLS fingerprinting blocks reqwest/rustls connections to
//!    these hosts, returning `429 rate_limit_error` regardless of actual
//!    request volume. Node.js's OpenSSL-based TLS stack produces a
//!    fingerprint Cloudflare accepts. CC itself uses Bun (OpenSSL)
//!    for the same reason.
//!
//! # Security
//!
//! - HTTPS only — the Node.js transport rejects non-`https://` URLs
//!   at the Rust call site before spawning any subprocess.
//! - Request bodies are piped via stdin, never via argv, so refresh
//!   tokens don't appear in `ps` output.
//! - The caller-supplied URL is interpolated into the spawned script as
//!   a JSON-encoded string literal (`js_url_literal`), guarded by a
//!   codepoint allowlist (`url_has_unsafe_js_chars`) that rejects
//!   quotes, backslash, CR/LF, ASCII control codepoints, and
//!   U+2028/U+2029 before the value ever reaches the script text.
//! - `node`'s stderr on a failed request is routed through
//!   [`crate::error::redact_tokens`] before being returned as the
//!   `Err(String)` — `redact_tokens` targets `sk-ant-*`-prefixed and
//!   bare-hex-run secret shapes specifically (see its own doc for the
//!   exact pattern list), so a malformed request or an echoed
//!   Anthropic OAuth token detail is stripped before the string
//!   reaches the caller. This is NOT a claim that every possible
//!   secret shape is caught: 3P API keys (MiniMax, Z.AI, DeepSeek,
//!   Grok, Kimi — none of which are `sk-ant-*`-shaped or necessarily
//!   hex) and a URL's userinfo password do not match `redact_tokens`'
//!   patterns and could still surface in this string if a future
//!   change ever echoed them (round-2 redteam L2 — the userinfo case
//!   is separately closed by `build_get_bearer_script`'s
//!   `uncaughtException` guard, at the script layer, not by
//!   `redact_tokens`).

pub mod codex;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

/// Full HTTP response: `(status_code, lowercased_response_headers, body)`.
///
/// Used by transports that need to inspect the status code or headers in
/// addition to the body — in particular the GitHub Releases update-check
/// path which classifies 403/429 rate-limit responses.
pub type FullResponse = (u16, std::collections::HashMap<String, String>, Vec<u8>);

/// Default timeout for outbound HTTP requests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Max redirects to follow. OAuth endpoints should never redirect.
const MAX_REDIRECTS: usize = 2;

/// Returns the shared blocking HTTP client.
///
/// The client is lazily constructed on first use and reused for the
/// process lifetime. reqwest's blocking client internally spawns a
/// dedicated tokio runtime; keeping one instance avoids repeated
/// runtime startup cost.
fn client() -> &'static reqwest::blocking::Client {
    static CLIENT: OnceLock<reqwest::blocking::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        // Anthropic's OAuth token endpoint rejects requests with
        // unrecognized User-Agent strings (returns 400 "Invalid request
        // format"). Only curl-style UAs are accepted. This appears to
        // be a server-side allowlist on the /v1/oauth/token endpoint.
        let ua = format!("curl/{}", env!("CARGO_PKG_VERSION"));
        reqwest::blocking::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .https_only(true)
            .http1_only()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .user_agent(ua)
            .build()
            .expect("reqwest client build must succeed (rustls, no native TLS)")
    })
}

/// Sanitizes a reqwest error into a short message suitable for logs and
/// user-facing reports.
///
/// # Scope
///
/// This sanitizer only covers **transport-layer** errors (connect
/// refused, timeout, TLS handshake failure, redirect overflow, HTTPS
/// rejection). It does NOT touch the response body.
///
/// If an HTTP call succeeds at the transport layer but the server
/// returns a 4xx/5xx with a body echoing sensitive data (e.g., an
/// OAuth `invalid_grant` response that includes the refresh token
/// prefix), that body is returned to the caller via `Ok(bytes)` and
/// this function is never invoked. The caller is responsible for
/// redacting response bodies before logging them — see the warning
/// on [`post_form`].
///
/// reqwest errors occasionally print the URL in their `Display` impl.
/// We use `without_url()` to strip that, because refresh tokens are
/// query-string encoded and could theoretically end up in an error
/// string if a future refactor changed the request to a GET. Defense
/// in depth.
fn sanitize_err(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "request timed out".into()
    } else if e.is_connect() {
        "connection failed".into()
    } else if e.is_redirect() {
        "too many redirects".into()
    } else if e.is_request() {
        // Could be HTTPS-only rejection, URL parse, etc.
        format!("request error: {}", e.without_url())
    } else {
        format!("http error: {}", e.without_url())
    }
}

/// POSTs a form-encoded body. Returns the response body as bytes
/// regardless of status — the caller decides how to handle non-2xx.
///
/// This signature matches `credentials::refresh::refresh_token`'s
/// `http_post` parameter.
///
/// # Errors
///
/// Returns `Err(String)` on connection failure, timeout, HTTPS
/// rejection, or redirect overflow. A 4xx/5xx response body is
/// returned as `Ok(bytes)` so the caller can parse structured
/// error responses.
///
/// # ⚠ CREDENTIAL-SAFETY WARNING
///
/// The returned `Vec<u8>` is the raw response body. If you are using
/// this function for an OAuth refresh, the Anthropic endpoint may
/// echo parts of your form body back in error responses (observed:
/// `400 {"error":"invalid_grant", ...}`). Callers MUST:
///
/// 1. Parse the body into a structured type and extract only the
///    fields they need (never `Display`/`format!` the whole body).
/// 2. Never log the raw bytes on error paths.
/// 3. Never include the raw bytes in error messages returned to the
///    user — treat them as sensitive by default.
///
/// `credentials::refresh::refresh_token` already follows this
/// contract by calling `serde_json::from_slice::<RefreshResponse>`
/// and never echoing the input body. Any new caller MUST be audited
/// for this property before wiring.
pub fn post_form(url: &str, body: &str) -> Result<Vec<u8>, String> {
    let response = client()
        .post(url)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body.to_string())
        .send()
        .map_err(sanitize_err)?;

    read_body_capped(response, RESPONSE_BODY_CAP)
}

/// POSTs a JSON body. Returns the response body as bytes
/// regardless of status — the caller decides how to handle non-2xx.
///
/// This signature matches [`post_form`] so callers that accept an
/// `FnOnce(&str, &str) -> Result<Vec<u8>, String>` can inject
/// either transport. The only differences are:
///
/// - `Content-Type: application/json` header
/// - Expects the body to be pre-serialized JSON (the caller is
///   responsible for `serde_json::to_string` or `to_vec`)
///
/// # Errors
///
/// Returns `Err(String)` on connection failure, timeout, HTTPS
/// rejection, or redirect overflow. A 4xx/5xx response body is
/// returned as `Ok(bytes)` so the caller can parse structured
/// error responses.
///
/// # ⚠ CREDENTIAL-SAFETY WARNING
///
/// Same as [`post_form`]. If this function is used for an OAuth
/// `authorization_code` exchange (M8.7), the Anthropic endpoint
/// may echo parts of the submitted body back in error responses
/// (observed: `400 {"error":"invalid_grant", ...}`). Callers MUST:
///
/// 1. Parse the body into a structured type and extract only the
///    fields they need (never `Display`/`format!` the whole body).
/// 2. Never log the raw bytes on error paths.
/// 3. Never include the raw bytes in error messages returned to
///    the user — treat them as sensitive by default.
///
/// [`crate::oauth::exchange::exchange_code`] follows this contract
/// by parsing via `serde_json::from_slice::<TokenResponse>` and
/// routing any error string through [`crate::error::redact_tokens`]
/// before wrapping in [`crate::error::OAuthError::Exchange`].
pub fn post_json(url: &str, body: &str) -> Result<Vec<u8>, String> {
    let response = client()
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .map_err(sanitize_err)?;

    read_body_capped(response, RESPONSE_BODY_CAP)
}

/// POSTs a JSON body with custom headers. Returns `(status, body)`.
///
/// This signature matches `providers::validate::validate_key`'s
/// `http_post` parameter.
///
/// # Header trust contract
///
/// Header name/value pairs MUST come from trusted sources (static
/// provider catalog entries, hardcoded constants). This function
/// does NOT sanitize header content — reqwest rejects CRLF in header
/// values, but callers should never pass user-controlled strings
/// here anyway. The only current caller is
/// `providers::validate::build_probe_headers`, which emits static
/// header names and the API key as the only dynamic value.
///
/// # Errors
///
/// Returns `Err(String)` on connection failure or timeout. A 4xx/5xx
/// response is returned as `Ok((status, body))` so the validator can
/// classify the response. See also the credential-safety warning on
/// [`post_form`] — response bodies may echo sensitive request data
/// on error paths, so callers should parse into a typed struct and
/// not log the raw body.
pub fn post_json_probe(
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<(u16, String), String> {
    let mut req = client().post(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let response = req.body(body.to_string()).send().map_err(sanitize_err)?;

    let status = response.status().as_u16();
    let text = read_probe_body(response)?;
    Ok((status, text))
}

/// Maximum response-body bytes [`post_json_probe`] will read. The probe only
/// ever surfaces a 200-char redacted excerpt, so 64 KiB is far past anything
/// shown while bounding the memory the redactor works over.
pub(crate) const PROBE_BODY_CAP: usize = 64 * 1024;

/// Cap for the remaining whole-body reads (OAuth/usage/CRL/update-check JSON,
/// daemon usage polling). Real responses are KiB-scale; 1 MiB bounds memory
/// against a hostile or intercepted endpoint. No caller of a helper using this
/// cap downloads a large or binary artifact (update binaries go through a
/// separate path).
pub(crate) const RESPONSE_BODY_CAP: usize = 1024 * 1024;

/// Fixed body substituted when a probe response exceeds [`PROBE_BODY_CAP`].
/// Carries no response content, so nothing can echo through it.
const PROBE_BODY_OVER_CAP: &str = "[response body exceeded size cap; not shown]";

/// Fixed, body-free error returned when a capped read exceeds its cap.
pub(crate) const RESPONSE_OVER_CAP: &str = "response body exceeded size cap";

/// Converts a body-read `io::Error` into a message that cannot carry a URL or
/// body: a wrapped `reqwest::Error` is reduced to the same fixed phrases
/// [`sanitize_err`] uses for timeout/connect/redirect; anything else reports
/// only the `ErrorKind`.
fn sanitize_read_err(e: &std::io::Error) -> String {
    let wrapped = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<reqwest::Error>());
    match wrapped {
        Some(re) if re.is_timeout() => "request timed out".into(),
        Some(re) if re.is_connect() => "connection failed".into(),
        Some(re) if re.is_redirect() => "too many redirects".into(),
        // Anything else: the kind only. A wrapped reqwest error's Display can
        // carry the URL and `without_url` needs ownership, so it is not used.
        _ => format!("response read error: {:?}", e.kind()),
    }
}

/// Reads at most `cap + 1` bytes (the `take(cap + 1)` pattern of
/// [`post_json_with_headers_capped`]). `Ok(None)` means over cap: no body
/// content is returned.
fn read_capped<R: std::io::Read>(reader: R, cap: usize) -> Result<Option<Vec<u8>>, String> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    reader
        .take((cap as u64) + 1)
        .read_to_end(&mut buf)
        .map_err(|e| sanitize_read_err(&e))?;
    Ok(if buf.len() > cap { None } else { Some(buf) })
}

/// [`read_capped`] with the over-cap case as the fixed [`RESPONSE_OVER_CAP`] error.
pub(crate) fn read_body_capped<R: std::io::Read>(reader: R, cap: usize) -> Result<Vec<u8>, String> {
    read_capped(reader, cap)?.ok_or_else(|| RESPONSE_OVER_CAP.to_string())
}

/// Probe flavour: over-cap yields the fixed [`PROBE_BODY_OVER_CAP`] string so
/// the status still classifies.
fn read_capped_probe_body<R: std::io::Read>(reader: R, cap: usize) -> Result<String, String> {
    Ok(match read_capped(reader, cap)? {
        Some(buf) => String::from_utf8_lossy(&buf).into_owned(),
        None => PROBE_BODY_OVER_CAP.to_string(),
    })
}

fn read_probe_body<R: std::io::Read>(reader: R) -> Result<String, String> {
    read_capped_probe_body(reader, PROBE_BODY_CAP)
}

fn pool_probe_key_header(
    key: &secrecy::SecretString,
) -> Result<reqwest::header::HeaderValue, String> {
    use secrecy::ExposeSecret;
    let mut header = reqwest::header::HeaderValue::from_str(key.expose_secret())
        .map_err(|_| "probe_invalid_request".to_string())?;
    header.set_sensitive(true);
    Ok(header)
}

/// One operator-authorized Messages request. No redirects, retries or body output.
/// The API key is request-scoped and never included in diagnostic text.
pub fn post_messages_status_once(model: &str, key: &secrecy::SecretString) -> Result<u16, String> {
    use secrecy::ExposeSecret;
    if model.is_empty()
        || model.len() > 128
        || !model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
        || crate::pool::validate_key(key.expose_secret()).is_err()
    {
        return Err("probe_invalid_request".into());
    }
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| "probe_transport_unavailable".to_string())?;
    let body = serde_json::json!({"model":model,"max_tokens":1,
        "messages":[{"role":"user","content":"Hi"}]})
    .to_string();
    let key_header = pool_probe_key_header(key)?;
    let response = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key_header)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .map_err(|_| crate::error::redact_tokens("probe_transport_failed"))?;
    Ok(response.status().as_u16())
}

#[cfg(test)]
mod pool_probe_tests {
    #[test]
    fn messages_probe_rejects_header_injection_before_network_and_never_echoes_key() {
        let key = secrecy::SecretString::from("synthetic-private-header".to_owned());
        let header = super::pool_probe_key_header(&key).unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("synthetic-private-header"));
        for (model, value) in [
            ("model\r\ninjected", "synthetic-key"),
            ("model", "synthetic-key\r\ninjected"),
            ("", "synthetic-key"),
        ] {
            let key = secrecy::SecretString::from(value.to_owned());
            assert_eq!(
                super::post_messages_status_once(model, &key).unwrap_err(),
                "probe_invalid_request"
            );
        }
    }
}

/// POSTs a JSON body with custom headers. Returns `(status, response_headers, body)`.
///
/// Like [`post_json_probe`] but also captures response headers. This
/// is the transport behind the 3P usage poller: `POST /v1/messages`
/// with `max_tokens=1` to extract `anthropic-ratelimit-*` headers.
///
/// Response headers are returned as a `HashMap<String, String>` with
/// **lowercased** keys so callers can do case-insensitive lookup.
///
/// # Security
///
/// Same trust contract as [`post_json_probe`]: header name/value
/// pairs MUST come from trusted sources. The API key is sent via
/// `x-api-key` header, not in the URL — it does not appear in
/// error strings. Response bodies may echo sensitive request data
/// on error paths; callers should parse into typed structs and not
/// log raw content.
///
/// `url` is rejected outright if it carries userinfo
/// (`user:pass@host`) or fails to parse (round-2 redteam H2): this is
/// the production transport behind the 3P usage probe (an API key in
/// headers) and the Gemini Code Assist OAuth probe (a bearer token in
/// headers), both of which read a caller/operator-supplied base URL.
/// reqwest folds URL userinfo into a `Basic` `Authorization` header
/// and connects to the host AFTER the `@` — the shared client's
/// `https_only(true)` only checks the scheme, not the authority, so a
/// URL like `https://api.minimax.chat@evil.example/v1` would read as
/// the vendor while sending the live credential to `evil.example`.
/// See `reject_userinfo`.
///
/// # Errors
///
/// Returns `Err(String)` on connection failure, timeout, HTTPS
/// rejection, redirect overflow, or a rejected `url` (see above). A
/// 4xx/5xx response is returned as `Ok(...)` so the caller can
/// inspect both headers and status.
pub fn post_json_with_headers(
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<(u16, std::collections::HashMap<String, String>, String), String> {
    reject_userinfo(url)?;
    let mut req = client().post(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let response = req.body(body.to_string()).send().map_err(sanitize_err)?;

    let status = response.status().as_u16();
    let resp_headers: std::collections::HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let text =
        String::from_utf8_lossy(&read_body_capped(response, RESPONSE_BODY_CAP)?).into_owned();
    Ok((status, resp_headers, text))
}

/// POSTs a JSON body with custom headers, capping ingest at `cap` bytes.
///
/// Mirrors [`post_json_with_headers`] but implements spec-19 §19.6 bounded
/// response ingest at the transport level: the response body is read via
/// [`std::io::Read::take`] so at most `cap + 1` bytes are ever allocated.
/// If the body exceeds `cap` bytes the caller receives a `Vec<u8>` of
/// length `cap + 1`; it MUST reject the response (e.g. return
/// `ProviderError::ResponseTooLarge`) rather than parse it.
///
/// # Why cap+1?
///
/// Reading exactly `cap + 1` bytes lets the caller distinguish
/// "exactly cap bytes" (accepted) from "more than cap bytes" (rejected)
/// with a single `len > cap` test, without having to read a second byte.
///
/// # Returns
///
/// `Ok((status, lowercased_response_headers, body_bytes))` where
/// `body_bytes.len() <= cap + 1`.
///
/// # Security
///
/// `url` is rejected outright if it carries userinfo or fails to parse
/// (round-7 redteam A-M1 — see `reject_userinfo`). This is the
/// production transport behind the enterprise direct-API client,
/// whose `ReqwestTransport::post` implementation carries the
/// caller's unwrapped 3P provider API key in `headers` — the exact
/// credential-in-header shape [`post_json_with_headers`] was guarded
/// against; this capped sibling shared its body but not its guard.
///
/// # Errors
///
/// Returns `Err(String)` on connection failure, timeout, HTTPS rejection,
/// redirect overflow, or a rejected `url` (see above). A 4xx/5xx response
/// is returned as `Ok(...)`.
#[allow(clippy::type_complexity)] // mirrors post_json_with_headers' tuple shape
pub fn post_json_with_headers_capped(
    url: &str,
    headers: &[(String, String)],
    body: &str,
    cap: usize,
) -> Result<(u16, std::collections::HashMap<String, String>, Vec<u8>), String> {
    use std::io::Read as _;

    reject_userinfo(url)?;

    let mut req = client().post(url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let response = req.body(body.to_string()).send().map_err(sanitize_err)?;

    // Capture status and headers BEFORE consuming the body (consuming the body
    // moves the Response).
    let status = response.status().as_u16();
    let resp_headers: std::collections::HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    // Capped read: at most cap+1 bytes are ever allocated.  reqwest's blocking
    // Response implements std::io::Read over the underlying connection.
    let mut limited = response.take((cap as u64) + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        // std::io::Error: convert without leaking URL or body.
        .map_err(|e| sanitize_read_err(&e))?;

    Ok((status, resp_headers, buf))
}

/// GETs a URL with a Bearer token and optional extra headers.
/// Returns `(status_code, body_bytes)` on any HTTP response.
///
/// This is the transport behind the M8.6 usage poller: `GET
/// /api/oauth/usage` with the access token as Bearer auth.
///
/// # Security
///
/// - HTTPS only (inherited from the shared client).
/// - The bearer token is sent in the `Authorization` header, not
///   the URL — it does not appear in error strings (reqwest logs
///   URLs, not headers).
/// - The returned body may contain sensitive data (usage quotas
///   tied to a user's account). Callers should parse into a typed
///   struct and not log the raw bytes.
/// - Extra headers MUST come from trusted constants (e.g.,
///   `Anthropic-Beta`). This function does NOT sanitize header
///   values — reqwest rejects CRLF injection, but callers should
///   never pass user-controlled strings.
/// - `url` is rejected outright if it carries userinfo or fails to parse
///   (round-7 redteam A-M1 — see `reject_userinfo`). reqwest folds URL
///   userinfo into a `Basic`-auth `Authorization` header (which this
///   function then OVERWRITES with the real bearer token via a second
///   `.header("Authorization", ...)` call — but by then the connection
///   has already been made to whatever host followed `@`, so the
///   overwrite does not undo the redirection) and connects to the host
///   AFTER `@`; `https_only(true)` on the shared client only checks the
///   scheme, not the authority.
///
/// # Errors
///
/// Returns `Err(String)` on connection failure, timeout, HTTPS
/// rejection, redirect overflow, or a rejected `url` (see above). A
/// 4xx/5xx response is returned as `Ok((status, bytes))` so the caller
/// can classify.
pub fn get_bearer(
    url: &str,
    token: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), String> {
    reject_userinfo(url)?;
    let mut req = client()
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json");
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let response = req.send().map_err(sanitize_err)?;
    let status = response.status().as_u16();
    Ok((status, read_body_capped(response, RESPONSE_BODY_CAP)?))
}

/// GETs a URL with custom headers and returns the response body.
///
/// Unlike [`get_bearer`], this does not set an `Authorization`
/// header — callers that need an API key bearer use `get_bearer`.
/// Use this for unauthenticated GETs (GitHub Releases API,
/// provider status pages) that still need a `User-Agent` or
/// `Accept` header.
///
/// The shared `client()` already sets `User-Agent: csq/<version>`
/// on every request, but callers may override via `headers`.
///
/// Returns `Ok(body)` on any HTTP response (including 4xx/5xx).
/// Returns `Err(String)` only on transport failure.
pub fn get_with_headers(url: &str, headers: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    let mut req = client().get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let response = req.send().map_err(sanitize_err)?;
    read_body_capped(response, RESPONSE_BODY_CAP)
}

/// GETs a URL with custom headers, returning `(status, response_headers, body)`.
///
/// Like [`get_with_headers`] but also captures the HTTP status code and
/// response headers. This is the transport behind the GitHub Releases
/// update-check path: callers that need to classify 403 rate-limit
/// responses or surface GitHub error envelopes should use this variant.
///
/// Response headers are returned as a `HashMap<String, String>` with
/// **lowercased** keys so callers can do case-insensitive lookup
/// (e.g. `"x-ratelimit-remaining"`, `"x-ratelimit-reset"`).
///
/// # Security
///
/// Same trust contract as [`get_with_headers`]: header name/value
/// pairs MUST come from trusted sources. Response bodies from
/// GitHub error responses may contain message text — callers that
/// surface body-derived content to the user MUST route it through
/// `crate::error::redact_tokens` first.
///
/// # Errors
///
/// Returns `Err(String)` on connection failure, timeout, HTTPS
/// rejection, or redirect overflow. A 4xx/5xx response is returned
/// as `Ok(...)` so the caller can inspect status, headers, and body.
pub fn get_with_headers_full(url: &str, headers: &[(&str, &str)]) -> Result<FullResponse, String> {
    get_with_headers_full_capped(url, headers, RESPONSE_BODY_CAP)
}

/// [`get_with_headers_full`] with an explicit body cap (over-cap is the fixed
/// [`RESPONSE_OVER_CAP`] error, never any body content). For a caller whose
/// legitimate body can exceed the default 1 MiB (the license CRL).
pub fn get_with_headers_full_capped(
    url: &str,
    headers: &[(&str, &str)],
    cap: usize,
) -> Result<FullResponse, String> {
    let mut req = client().get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let response = req.send().map_err(sanitize_err)?;

    let status = response.status().as_u16();
    let resp_headers: std::collections::HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    Ok((status, resp_headers, read_body_capped(response, cap)?))
}

// ─── Node.js subprocess transport (Anthropic endpoints) ──────

/// In-script request bound for Node.js subprocess HTTP requests
/// (milliseconds), emitted into every script builder through the ONE
/// shared [`node_request_timeout_prelude`] snippet so the shapes cannot
/// drift apart.
///
/// TWO shapes, and the script arms both:
///
/// 1. a TOTAL wall-clock timer, armed when the request is issued, which
///    destroys the request and writes the fixed `timeout` diagnostic at
///    [`NODE_TIMEOUT_MS`] after the request STARTS — whatever the socket
///    is doing; and
/// 2. the `timeout` option on `https.request`, kept as the
///    socket-INACTIVITY guard it always was. A server that trickles bytes
///    with gaps shorter than this value keeps resetting it, so on its own
///    it is NOT a total bound — that is exactly the round-2 M2 defect the
///    total timer closes.
///
/// Neither shape bounds process spawn, runtime startup, module loading,
/// stdin consumption, a connect/DNS phase before the request is issued,
/// the child's post-timer exit path, or output drain. Those phases are
/// bounded ONLY on the PARENT side, by [`NODE_CHILD_WAIT_DEADLINE`].
const NODE_TIMEOUT_MS: u64 = 15_000;

/// Parent-side allowance added to [`NODE_TIMEOUT_MS`] to form
/// [`NODE_CHILD_WAIT_DEADLINE`], the wall-clock bound on the parent's wait
/// for one Node child.
///
/// # What is enforced, and by which side
///
/// The REQUEST is bounded structurally inside the child: the shared
/// [`node_request_timeout_prelude`] arms a TOTAL timer that destroys the
/// request at [`NODE_TIMEOUT_MS`] after it starts. A request that is
/// issued therefore always terminates, and the script always reports.
///
/// Everything OUTSIDE the request — spawn/exec, runtime startup, module
/// loading, stdin consumption, and pipe drain — has no in-child timer.
/// [`NODE_CHILD_WAIT_DEADLINE`] is the ONLY enforced wall bound over those
/// phases. This constant is the fixed policy allowance (10 s) added for
/// them so the total parent wait stays at 25 s. It is a policy bound, NOT
/// a derivation from an enforced sequence: nothing enforces that spawn +
/// startup + stdin finish inside it (round-2 L3).
///
/// Ordering is therefore structural only within the request phase:
///
/// - If the pre-request phases finish inside this margin, a slow request
///   surfaces the script's own `timeout` diagnostic (via
///   [`node_failure_error`]) rather than a parent kill.
/// - If they do not, the parent deadline wins. When the child had already
///   started emitting stdout by then, the parent returns
///   [`ERR_NODE_HTTP_OUTCOME_UNKNOWN`] rather than silently discarding a
///   possibly-committed response (round-2 M2).
/// - A child wedged before the request is issued (spawn, startup, DNS, a
///   stuck runtime) is killed at the parent deadline, so the daemon
///   refresher can never block on it indefinitely.
const NODE_WAIT_MARGIN_MS: u64 = 10_000;

/// Wall-clock bound on the parent's wait for ONE Node child, exposed so
/// an enclosing caller can compose its own drain or transaction
/// deadline from it instead of inventing a literal.
///
/// ```text
/// NODE_CHILD_WAIT_DEADLINE = NODE_TIMEOUT_MS + NODE_WAIT_MARGIN_MS
///                          = 15 s (TOTAL in-script request timer)
///                          + 10 s (policy allowance: spawn, runtime
///                                  startup, module loading, stdin
///                                  consumption, and the script's
///                                  post-timer teardown)
///                          = 25 s
/// ```
///
/// This is the ONLY enforced wall bound over the phases outside the
/// request itself; the request is separately bounded inside the child by
/// the total timer. `run_node_script` shares this ONE budget across
/// spawn, stdin consumption, and the wait, so those stages cannot each
/// spend the full constant. The pipe drain that follows the child's exit
/// is bounded separately by `NODE_DRAIN_DEADLINE`, making the composed
/// worst case of one transport call this deadline plus one drain budget.
///
/// A caller issuing several sequential requests can derive its own bound
/// as a multiple of that composed value. See `NODE_WAIT_MARGIN_MS` for
/// what is and is not enforced by this deadline.
pub const NODE_CHILD_WAIT_DEADLINE: Duration =
    Duration::from_millis(NODE_TIMEOUT_MS + NODE_WAIT_MARGIN_MS);

/// Bound on draining a Node child's stdout/stderr after its leader has
/// exited or been killed, and on joining the stdin writer after a kill.
///
/// A pipe reader reaches EOF only when every holder of the write end is
/// gone. The child's process GROUP is signalled on the timeout path, which
/// covers the ordinary case, but a descendant that escaped the group
/// (`setsid`/detached) — or ANY descendant on Windows, where
/// [`kill_child_process_group`] cannot signal a group at all — can keep a
/// pipe open indefinitely. This policy bound (5 s, not derived from a
/// measurement) is what turns that into a fixed-vocabulary error instead of
/// a parent-side hang; a reader thread that has still not reached EOF is
/// detached and documented in [`wait_for_node_child`].
const NODE_DRAIN_DEADLINE: Duration = Duration::from_secs(5);

/// Poll interval for the parent's deadline loop in
/// [`wait_for_node_child`]. Small enough that the deadline is enforced
/// within a few tens of milliseconds, large enough that a 25 s worst
/// case costs only ~2,500 scheduler wakeups.
const NODE_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Fixed-vocabulary failure for a Node child that outlives
/// [`NODE_CHILD_WAIT_DEADLINE`] without having emitted any stdout.
///
/// Deliberately carries NO body, stderr, or token text: the stdin
/// payload of the OAuth exchange transports is a live credential, and
/// a timed-out child may have echoed any of it (rules/security.md §2
/// and §8). A timeout is a timeout; the child's output is discarded.
const ERR_NODE_WAIT_TIMEOUT: &str = "node http transport: child exceeded the parent wait deadline";

/// Fixed-vocabulary classification for every RUNTIME failure of the Node
/// transport that is not one of the two more specific classes below —
/// spawn/exec failure, a missing or unwritable stdin, the stdin writer
/// dying, the wait itself failing, a pipe reader that cannot be created or
/// that errors, a non-zero child exit, and a malformed response framing or
/// status line.
///
/// # Why a constant, not the `io::Error` Display text
///
/// `daemon::usage_poller::poll_error::classify_transport_error` classifies
/// a transport error by EQUALITY against shared constants; any other string
/// becomes `PollError::Transport`. A formatted `io::Error` string carried
/// no classification value (it always landed in `Transport` anyway) and
/// tripped the structural oracle that keeps every poller-facing rejection
/// comparable — the oracle cannot verify an arbitrary formatted string.
/// The failure DETAIL is therefore logged here with a fixed `error_kind`
/// tag and never returned: the returned string is this constant, which the
/// classifier maps to `Transport`.
///
/// It is NOT a `BadUrl`-class constant: these failures are post-pre-flight
/// runtime problems, so the poller must treat them as a retryable
/// transport failure, not as an operator misconfiguration.
pub(crate) const ERR_NODE_TRANSPORT: &str = "node http transport: runtime failed";

/// Fixed-vocabulary classification for a parent-deadline kill AFTER the
/// child had already written to stdout — i.e. the child had begun emitting
/// the response, so the server may already have committed a mutation
/// (in particular an OAuth refresh-token rotation, whose old token is then
/// dead server-side).
///
/// The value is EXACTLY the tag, with no prefix, so a caller can match it
/// verbatim (`err == http::ERR_NODE_HTTP_OUTCOME_UNKNOWN`) without parsing.
/// It never carries the body, stderr, or any token text — the body itself
/// is discarded, because a partially-emitted response is not safe to
/// surface and the point of this class is that the OUTCOME is unknown.
///
/// # What a caller MUST do with it
///
/// - Treat it as POSSIBLY COMMITTED, not as a clean transport failure.
/// - Do NOT retry the same request with a single-use credential (a Codex
///   refresh token is single-use; an Anthropic refresh token may have been
///   rotated). A blind retry of a committed rotation can burn the account.
/// - Do NOT overwrite or delete the stored credential pair on this error:
///   the old pair may be the only durable copy of a pre-rotation state, and
///   the new pair was never observed.
/// - Report the account as needing verification / re-login rather than
///   reporting a plain network failure.
pub(crate) const ERR_NODE_HTTP_OUTCOME_UNKNOWN: &str = "node_http_outcome_unknown";

/// Fixed-vocabulary failure when the child's pipe reader cannot reach EOF
/// inside [`NODE_DRAIN_DEADLINE`] after the child itself is gone.
///
/// Internal only: [`wait_for_node_child_with_drain_budget`] maps EVERY
/// stdout-drain failure to [`ERR_NODE_HTTP_OUTCOME_UNKNOWN`], never to a
/// plain transport class. A reader delivers its buffer only at EOF, so a
/// complete body may be sitting in the reader's partial buffer while it is
/// blocked on a pipe some escaped descendant still holds — discarding that
/// as an ordinary failure is the same round-2 M2 class as the parent
/// deadline case.
const ERR_NODE_DRAIN_TIMEOUT: &str =
    "node http transport: child output did not drain within the drain deadline";

/// Fixed rejection message for a URL failing [`url_has_unsafe_js_chars`].
///
/// `pub(crate)` (round-2 redteam NIT) so
/// `daemon::usage_poller::classify_transport_error` matches on this
/// exact constant instead of a hand-duplicated literal string — the two
/// sides cannot silently diverge on a future rewording, and a compiler
/// error (not a silent `BadUrl`→`Transport` downgrade with only a wrong
/// `error_kind` in logs) is the failure mode if this constant is ever
/// renamed without updating the classifier.
pub(crate) const ERR_URL_UNSAFE_CHARS: &str = "url contains disallowed characters";

/// Fixed rejection message for a non-`https://` URL. See
/// [`ERR_URL_UNSAFE_CHARS`] for why this is a shared constant rather
/// than a literal duplicated at the classifier.
pub(crate) const ERR_HTTPS_REQUIRED: &str = "https required";

/// Fixed rejection message for a URL carrying userinfo (`user:pass@host`).
/// See [`ERR_URL_UNSAFE_CHARS`] for why this is a shared constant.
///
/// This is the THIRD pre-flight URL rejection, and it was the one the
/// shared-constant refactor missed: the literal stayed inline at the
/// rejection site, so `classify_transport_error` — which compares against
/// the constants — could not recognise it and downgraded the verdict to
/// `Transport`. The observable cost was diagnostic, not credential: a
/// userinfo URL logged at `debug!` on the network axis instead of the
/// `warn!` with `error_kind = "<surface>_poll_bad_url"` that exists for
/// exactly this failure. Redirection itself is still blocked — the token
/// is never sent.
pub(crate) const ERR_URL_USERINFO: &str =
    "url must not contain userinfo (user:pass@) — rejected to prevent a hostile \
     url from impersonating a trusted host while receiving a live bearer token";

/// Fixed rejection message for a url that `url::Url::parse` cannot parse at
/// all. See [`ERR_URL_UNSAFE_CHARS`] for why this is a shared constant.
///
/// Added by [`reject_userinfo`] (round-2 redteam H1): a url malformed enough
/// that Rust's `url` crate refuses to parse it is now rejected OUTRIGHT,
/// rather than falling through to the downstream Node.js `new URL(...)`
/// construction unchecked. See `reject_userinfo`'s doc for the fail-open gap
/// this closes.
pub(crate) const ERR_URL_UNPARSEABLE: &str =
    "url could not be parsed — rejected because a url this parser cannot \
     recognise may still be accepted by a downstream runtime's own url \
     parser, with an unverifiable authority";

/// Fixed rejection message for a bearer token carrying control characters or
/// JS line separators. See [`ERR_URL_UNSAFE_CHARS`] for why this is shared.
///
/// Reachable from EVERY caller of the Node-transport `HttpGetFn` closure
/// (round-2 redteam R6-rust), not only operator-configurable-URL callers
/// (`grok`, `minimax`): the guard inspects the TOKEN every caller passes,
/// independent of whether that caller's URL is a fixed constant. Leaving it
/// as an inline literal reproduced the userinfo defect exactly: the
/// classifier could not match it, and a malformed stored credential was
/// reported on the network axis at `debug!` and retried on the backoff
/// schedule forever, instead of the `warn!` telling the operator to
/// re-authenticate the account.
pub(crate) const ERR_TOKEN_UNSAFE_CHARS: &str = "token contains disallowed characters";

/// Fixed rejection message for [`find_js_runtime`] finding neither `node`
/// nor `bun`. See [`ERR_URL_UNSAFE_CHARS`] for why this is a shared
/// constant.
///
/// Added by the M3 round-2 redteam followup: this is a PRE-FLIGHT,
/// PERMANENT-until-the-operator-acts failure (the result is memoized in a
/// process-wide `OnceLock`) exactly like the URL/token guards above, but it
/// was previously an ad hoc literal that `classify_transport_error` could
/// not recognise — so a host with no JS runtime installed silently retried
/// every poll forever at `debug!` instead of surfacing a `warn!` telling the
/// operator to install node or bun.
pub(crate) const ERR_NO_JS_RUNTIME: &str =
    "no JS runtime (node/bun) found in PATH or standard install locations";

/// Fixed rejection message for a `serde_json` encode failure in
/// [`js_url_literal`] or [`bearer_stdin_payload`]. See
/// [`ERR_URL_UNSAFE_CHARS`] for why this is a shared constant.
///
/// Added by the M3 round-2 redteam followup, for the same reason as
/// [`ERR_NO_JS_RUNTIME`]: previously two DIFFERENT ad hoc literals
/// ("failed to encode url" / "failed to encode stdin payload"), neither
/// recognised by `classify_transport_error`.
pub(crate) const ERR_ENCODE_FAILED: &str = "failed to encode outbound payload";

/// Rejects `url` if it cannot be parsed at all, OR if it parses but
/// carries userinfo (`user:pass@host`).
///
/// Shared by every credential-bearing HTTP function in this module
/// (round-2 redteam H2): [`get_bearer_node`] (bearer token in the
/// `Authorization` header), [`post_json_node`] /
/// [`post_json_node_with_date`] (OAuth authorization-code / refresh-token
/// exchange bodies via stdin), and [`post_json_with_headers`] (3P API keys /
/// OAuth bearer tokens via header). The guard originally lived inline in
/// `get_bearer_node` alone, leaving the other three credential-bearing
/// transports open to the exact userinfo-redirection attack this guard
/// exists to close — a URL like `https://<trusted-host>@evil.example/...`
/// reads as the trusted host while the live credential goes to
/// `evil.example`.
///
/// Extended (round-7 redteam A-M1) to also cover [`get_bearer`] (the
/// reqwest transport behind the M8.6 Anthropic usage poller — bearer
/// token via header, byte-for-byte the same trust shape
/// `post_json_with_headers` was guarded against) and
/// [`post_json_with_headers_capped`] (the enterprise direct-API
/// transport, whose `ReqwestTransport::post` implementation carries the
/// caller's unwrapped 3P provider API key via header). Both take a
/// fixed constant URL today, so the guard is defence-in-depth exactly as
/// `post_json_node`/`post_json_node_with_date` were before the H2 fix —
/// but reqwest's userinfo-folding-into-`Authorization` behaviour (see
/// `post_json_with_headers`'s doc) applies identically to any caller
/// that ever accepts an operator-supplied URL through either function.
///
/// # Fail CLOSED on unparseable URLs (round-2 redteam H1)
///
/// A URL that `url::Url::parse` cannot parse at all is REJECTED outright,
/// not passed through unchecked. The previous version of this guard (inline
/// in `get_bearer_node`) only rejected userinfo when Rust's `url` crate
/// successfully parsed the URL — `if let Ok(parsed) = url::Url::parse(url) {
/// check }`, with no `else` branch — so any URL malformed enough for
/// `url::Url::parse` to refuse it skipped the userinfo check ENTIRELY and
/// proceeded to spawn the Node transport with the live credential still
/// attached.
///
/// That was safe for `get_bearer_node` only by accident, and only in the
/// narrow quadrant where Node's OWN `new URL(...)` construction ALSO throws
/// on the same malformed input — `build_get_bearer_script`'s top-level
/// `process.on('uncaughtException', ...)` handler (LOW-2 follow-up) catches
/// that case. The uncovered quadrant is Rust's `url` crate rejecting the
/// URL while Node's independent parser (V8, WHATWG-adjacent but not
/// identical) ACCEPTS it: no Rust-side rejection, no Node exception, the
/// `uncaughtException` handler never fires, and the request proceeds with
/// the live credential to whatever host Node resolves. Failing closed here
/// removes the dependency on the two parsers agreeing, and closes the same
/// gap for the three transports that never had ANY userinfo check before
/// this fix.
fn reject_userinfo(url: &str) -> Result<(), String> {
    let Ok(parsed) = url::Url::parse(url) else {
        return Err(ERR_URL_UNPARSEABLE.into());
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ERR_URL_USERINFO.into());
    }
    Ok(())
}

/// System-wide absolute paths checked when bare-name PATH lookup
/// fails. Order mirrors `accounts::login::SYSTEM_WIDE_DIRS` — Apple
/// Silicon Homebrew first, Intel Homebrew / manual installs second,
/// system bindir last.
const SYSTEM_WIDE_JS_RUNTIMES: &[&str] = &[
    "/opt/homebrew/bin/node",
    "/opt/homebrew/bin/bun",
    "/usr/local/bin/node",
    "/usr/local/bin/bun",
    "/usr/bin/node",
];

/// Per-user install subdirectories (relative to `$HOME`) that host
/// a JS runtime but sit outside the default GUI-launched-app PATH.
/// Order matches `accounts::login::PER_USER_SUBDIRS` for consistency.
const PER_USER_JS_RUNTIMES: &[&str] = &[".bun/bin/bun", ".volta/bin/node"];

/// Finds the first available JS runtime (`node` or `bun`) and
/// returns the command or absolute path suitable for
/// `Command::new`.
///
/// Two-stage resolution:
///
/// 1. **PATH walk** (`node`, then `bun`). Covers the CLI case and
///    any GUI launch that happens to have Homebrew / Bun / Volta on
///    PATH — i.e. launches from a terminal that inherited the
///    shell's PATH.
///
/// 2. **Absolute-path probe**. GUI-launched apps on macOS inherit
///    only `/usr/bin:/bin:/usr/sbin:/sbin`, which excludes every
///    modern runtime installer. This stage walks the same
///    well-known locations `accounts::login::find_claude_binary`
///    uses, so a desktop app launched from Finder or by a
///    `LaunchAgent` can still find `node` / `bun`.
///
/// The result is memoized in a `OnceLock` for the lifetime of the
/// process — runtime location doesn't change mid-run, and the probe
/// spawns a subprocess per candidate. Cloned on every call because
/// `OnceLock::get` returns `&T` and callers need an owned `String`
/// to pass to `Command::new`.
fn find_js_runtime() -> Result<String, String> {
    static RUNTIME: OnceLock<Result<String, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| resolve_js_runtime().ok_or_else(|| ERR_NO_JS_RUNTIME.into()))
        .clone()
}

/// Pure resolver behind `find_js_runtime`. Separated from the
/// cached wrapper so unit tests can exercise the search order
/// without a process-wide `OnceLock` that would latch the first
/// observed result.
fn resolve_js_runtime() -> Option<String> {
    for cmd in ["node", "bun"] {
        if probe_runtime(Path::new(cmd)) {
            return Some(cmd.to_string());
        }
    }

    for abs in SYSTEM_WIDE_JS_RUNTIMES {
        let p = Path::new(abs);
        if probe_runtime(p) {
            return Some(abs.to_string());
        }
    }

    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        for sub in PER_USER_JS_RUNTIMES {
            let p = home.join(sub);
            if probe_runtime(&p) {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }

    None
}

/// Returns the first working `node` or `bun` path, or `None` if none
/// is available. Thin public wrapper over `resolve_js_runtime` for
/// diagnostic callers (e.g. `csq doctor`) that want to surface a
/// "no JS runtime found" warning. Intentionally uncached — doctor is
/// a one-shot command, and the HTTP client has its own memoized
/// `find_js_runtime` for hot paths.
pub fn js_runtime_path() -> Option<String> {
    resolve_js_runtime()
}

/// Spawns `path --version` and reports whether the invocation
/// succeeded. For bare names this still relies on PATH resolution
/// (stage 1); for absolute paths it's an explicit exec (stage 2).
fn probe_runtime(path: &Path) -> bool {
    std::process::Command::new(path)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Formats a failed Node subprocess exit into the caller-facing error
/// string.
///
/// Routes `stderr` through [`crate::error::redact_tokens`] before
/// formatting (MED-2, an internal ticket redteam) — a malformed stdin payload
/// (verified: `node -e 'JSON.parse(badInput)'` embeds a prefix of the
/// unparseable input verbatim in the thrown `SyntaxError.message`), an
/// echoed request detail, or any other node-side error text cannot leak
/// a bearer or refresh token into the string returned to the caller.
///
/// Single shared function — used by all four Node-transport
/// functions in this module — so a future new call site inherits the
/// redaction by construction rather than needing to remember to add it
/// (the `security.md` §5a "named-list drift" failure mode, applied to
/// this module's error formatting).
///
/// The value is now a LOG DETAIL only: the call sites log it through
/// [`log_node_failure`] and return the shared [`ERR_NODE_TRANSPORT`]
/// constant, because the poller classifies by equality against shared
/// constants and a redacted-but-formatted string is not one.
fn node_failure_error(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    format!("node http failed: {}", crate::error::redact_tokens(&stderr))
}

/// Logs a non-zero Node child exit with its REDACTED stderr, so the
/// operator keeps the runtime's own diagnostic while the caller returns the
/// shared [`ERR_NODE_TRANSPORT`] constant the poller can classify.
fn log_node_failure(stderr: &[u8]) {
    let detail = node_failure_error(stderr);
    tracing::warn!(
        error_kind = "node_child_failed",
        detail = %detail,
        "node http transport: the JS runtime reported a request failure"
    );
}

/// Fixed-vocabulary tag for an `io::Error` KIND — the only failure detail a
/// transport warning may carry (security round-2 L1). Never the error's
/// `Display` text: an `io::Error` can render a path, a runtime path, or a
/// syscall detail, and these warnings fire beside credential-bearing
/// transport payloads; a fixed tag keeps the diagnostic surface
/// comparable (the poller classifier's own structural oracle) and guarantees
/// no formatted foreign string reaches a log line.
fn io_error_kind(err: &std::io::Error) -> &'static str {
    use std::io::ErrorKind as K;
    match err.kind() {
        K::NotFound => "not_found",
        K::PermissionDenied => "permission_denied",
        K::ConnectionRefused => "connection_refused",
        K::ConnectionReset => "connection_reset",
        K::ConnectionAborted => "connection_aborted",
        K::NotConnected => "not_connected",
        K::AddrInUse => "addr_in_use",
        K::AddrNotAvailable => "addr_not_available",
        K::BrokenPipe => "broken_pipe",
        K::AlreadyExists => "already_exists",
        K::WouldBlock => "would_block",
        K::InvalidInput => "invalid_input",
        K::InvalidData => "invalid_data",
        K::TimedOut => "timed_out",
        K::WriteZero => "write_zero",
        K::Interrupted => "interrupted",
        K::UnexpectedEof => "unexpected_eof",
        K::OutOfMemory => "out_of_memory",
        K::Unsupported => "unsupported",
        _ => "other",
    }
}

/// Fixed-vocabulary tag for one of THIS module's transport constants,
/// replacing a `%other` render of the same `&'static str` (security
/// round-2 L1). The mapping is exhaustive over the values
/// [`run_node_script`] can return and falls back to a fixed tag, so no
/// future constant can leak an unvetted string into a warning.
fn transport_class_tag(err: &'static str) -> &'static str {
    match err {
        ERR_NODE_TRANSPORT => "node_transport",
        ERR_NODE_WAIT_TIMEOUT => "node_wait_timeout",
        ERR_NODE_HTTP_OUTCOME_UNKNOWN => "node_outcome_unknown",
        ERR_NODE_DRAIN_TIMEOUT => "node_drain_timeout",
        _ => "other_fixed",
    }
}

/// Writes `payload` to `child`'s stdin. On ANY failure — the write
/// itself failing (most commonly `EPIPE`: the child exited or crashed
/// before or during the write) or the stdin handle already being
/// absent — reaps `child` with `kill()` + `wait()` before propagating
/// the error.
///
/// # Why this matters (round-2 redteam LOW finding)
///
/// A bare `?` on the write leaves `child` dropped without ever being
/// `.wait()`-ed. `Child`'s `Drop` impl does NOT reap the process — on
/// Unix that leaves a zombie entry in the process table until
/// something else in the long-running daemon happens to reap a PID
/// (or the daemon exits). This became MORE likely, not less, once the
/// `process.on('uncaughtException', ...)` guard (LOW-2 follow-up) was
/// added to every script this module spawns — that guard makes the
/// child exit deliberately (rather than crash) on more classes of
/// input, and a deliberate early exit is exactly the shape that races
/// this function's stdin write into `EPIPE`.
///
/// `kill()`/`wait()` failures are swallowed (best-effort): by the time
/// this function is called, the write has already failed, so the
/// process is presumed already gone or exiting — there is no
/// meaningful action left to take on either call failing.
/// # Returned errors
///
/// Only the two shared fixed-vocabulary classes are returned —
/// [`ERR_NODE_WAIT_TIMEOUT`] for a wedged write and [`ERR_NODE_TRANSPORT`]
/// for every other failure, whose detail is logged here with a fixed
/// `error_kind` tag. This is what lets a poller classify the enclosing
/// transport call by equality (see [`ERR_NODE_TRANSPORT`]).
fn write_stdin_bounded(
    child: &mut std::process::Child,
    payload: &[u8],
    budget: Duration,
) -> Result<(), &'static str> {
    use std::io::Write;
    // The write itself is bounded: a child that stops reading (or never
    // starts) leaves a full pipe, and a blocking `write_all` on it would
    // hang this call forever — the very class this function's caller
    // exists to bound. The writer runs on its own thread so the budget is
    // enforced here, and a timeout kills the child's process group, which
    // closes the pipe's read end and unblocks the writer.
    let Some(mut stdin) = child.stdin.take() else {
        tracing::warn!(
            error_kind = "node_stdin_unavailable",
            "node http transport: the child's stdin pipe is unavailable"
        );
        let _ = child.kill();
        let _ = child.wait();
        return Err(ERR_NODE_TRANSPORT);
    };
    // This is an extra heap copy of a credential-bearing payload; scrub it
    // when the writer thread drops it instead of leaving it in freed heap
    // memory (round-2 security L1).
    //
    // The type is PINNED on purpose (round-2 correctness L-b): deleting the
    // `Zeroizing` wrapper is a hard compile error at this annotation, not a
    // silent regression a passing test could hide. A writer that is still
    // parked on a pipe (the documented detached-thread residual on the
    // timeout path) holds this buffer until the pipe closes; zeroing on drop
    // is the only bound available when the blocked `write_all` cannot be
    // cancelled portably.
    let owned: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(payload.to_vec());
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let writer = match std::thread::Builder::new()
        .name("csq-node-stdin-writer".into())
        .spawn(move || {
            let outcome = stdin.write_all(&owned);
            // Closing stdin is part of the contract: the script reads its
            // payload to EOF.
            drop(stdin);
            let _ = sender.send(outcome);
        }) {
        Ok(handle) => handle,
        Err(e) => {
            tracing::warn!(
                error_kind = "node_stdin_writer_spawn_failed",
                io_kind = io_error_kind(&e),
                "node http transport: could not start the stdin writer thread"
            );
            let _ = child.kill();
            let _ = child.wait();
            return Err(ERR_NODE_TRANSPORT);
        }
    };
    match receiver.recv_timeout(budget) {
        Ok(outcome) => {
            let _ = writer.join();
            match outcome {
                Ok(()) => Ok(()),
                // `BrokenPipe` (EPIPE) is NOT a transport failure to report — it
                // means the child is already gone or has closed stdin. With the
                // `process.on('uncaughtException', …)` guard now on every script
                // this module spawns, that is precisely the shape of a child that
                // failed DELIBERATELY and already wrote its own diagnostic
                // (`script_error`) to stderr.
                //
                // Returning `Err` here would discard that stderr and surface a
                // generic "stdin write failed: Broken pipe" instead — and WHICH of
                // the two the operator saw would depend on whether the parent's
                // `write_all` reached the pipe buffer before the child exited, i.e.
                // on scheduling. One failure, two different operator-facing strings,
                // chosen by a race.
                //
                // So fall through to the caller's [`wait_for_node_child`], which
                // reaps the child (nothing leaks — that is the same call the
                // success path relies on) and returns the child's own message. All
                // four production call sites invoke it immediately after this
                // function.
                // EPIPE is a fall-through (see the contract above): the child is
                // gone or closed stdin, and the caller's wait surfaces its own
                // diagnostic.
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                Err(e) => {
                    tracing::warn!(
                        error_kind = "node_stdin_write_failed",
                        io_kind = io_error_kind(&e),
                        "node http transport: writing the request payload to the child failed"
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    Err(ERR_NODE_TRANSPORT)
                }
            }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // A wedged write: kill the group so the read end closes, then
            // reap. The writer unblocks on EPIPE and joins.
            //
            // `child.kill()` is unconditional, not only on a group-signal
            // error: the group signal is a no-op (ESRCH, treated as success)
            // when the child is NOT a process-group leader — a caller that
            // spawned it directly rather than through `spawn_node_script` —
            // and `wait()` below would then block forever on a live child.
            // This is exactly the shape a unit row reproduces, and the one
            // that hung the http scope during the bounded-waits freeze.
            if let Err(e) = kill_child_process_group(child) {
                tracing::warn!(
                    error_kind = "node_child_group_kill_failed",
                    io_kind = io_error_kind(&e),
                    "node http transport: timed-out stdin writer could not signal the child group"
                );
            }
            let _ = child.kill();
            let _ = child.wait();
            // The kill above closes the pipe's read end, so the writer
            // normally returns EPIPE at once. Bound the wait for that send
            // anyway: on Windows there is no process-group kill, and a
            // descendant that inherited stdin can hold the read end open,
            // which would otherwise park this call forever (round-2
            // correctness L2). On expiry the writer thread is detached and
            // will end when the pipe finally closes; that parked thread is
            // the documented residual, not a caller hang.
            let _ = receiver.recv_timeout(NODE_DRAIN_DEADLINE);
            drop(writer);
            Err(ERR_NODE_WAIT_TIMEOUT)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            tracing::warn!(
                error_kind = "node_stdin_writer_lost",
                "node http transport: the stdin writer thread exited without reporting"
            );
            let _ = child.kill();
            let _ = child.wait();
            let _ = writer.join();
            Err(ERR_NODE_TRANSPORT)
        }
    }
}

/// Spawns one Node transport child and bounds the WHOLE call — spawn-to-
/// reap — with [`NODE_CHILD_WAIT_DEADLINE`].
///
/// The clock starts before the spawn call, and BOTH later stages receive
/// only the REMAINING part of that one budget — never the full constant —
/// so spawn time, the stdin write, and the child wait cannot each spend
/// [`NODE_CHILD_WAIT_DEADLINE`] in turn (round-2 correctness L1). Every
/// call site uses this entry point so that bound cannot drift per call
/// site.
fn run_node_script(
    runtime: &str,
    script: &str,
    payload: &[u8],
) -> Result<std::process::Output, &'static str> {
    let started = std::time::Instant::now();
    let mut child = match spawn_node_script(runtime, script) {
        Ok(child) => child,
        Err(e) => {
            tracing::warn!(
                error_kind = "node_child_spawn_failed",
                io_kind = io_error_kind(&e),
                "node http transport: could not spawn the JS runtime"
            );
            return Err(ERR_NODE_TRANSPORT);
        }
    };
    // A child that never reads stdin leaves a full pipe and would block a
    // plain `write_all` forever; the bounded writer enforces the remaining
    // budget and kills the child's process group on expiry.
    write_stdin_bounded(
        &mut child,
        payload,
        NODE_CHILD_WAIT_DEADLINE.saturating_sub(started.elapsed()),
    )?;
    wait_for_node_child(
        child,
        NODE_CHILD_WAIT_DEADLINE.saturating_sub(started.elapsed()),
    )
}

/// Spawns `runtime -e <script>` with all three stdio pipes connected
/// and, on Unix, the child in its OWN process group.
///
/// Shared by every Node-transport caller so the process-group
/// invariant cannot drift per call site: [`wait_for_node_child`] kills
/// the child's process group on timeout, and that only reaches the
/// whole runtime subtree because the child is a group leader
/// (`process_group(0)` makes the child's pid its pgid).
///
/// A spawn failure is returned as the raw [`std::io::Error`]; the caller
/// logs it with a fixed tag and classifies it as [`ERR_NODE_TRANSPORT`],
/// because a formatted OS error string is not a shared constant a poller
/// can compare against.
fn spawn_node_script(runtime: &str, script: &str) -> Result<std::process::Child, std::io::Error> {
    let mut cmd = std::process::Command::new(runtime);
    cmd.arg("-e")
        .arg(script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn()
}

/// Kills `child`'s process group on Unix, or the child alone on other
/// platforms.
///
/// MUST be called BEFORE the child is reaped: an unreaped child (even
/// a zombie) still owns its pid, so the group id `-pid` cannot have
/// been recycled onto an unrelated process group in between.
///
/// `ESRCH` is success for this purpose — it means the group already
/// has no members left (the child exited between the last `try_wait`
/// and this signal).
///
/// # Windows: no job object — the subtree is NOT covered
///
/// The non-Unix arm kills the DIRECT child only. csq creates no Job
/// Object for the runtime, so any descendant the child spawned survives
/// this call — including one holding a stdio pipe, which is why
/// [`wait_for_node_child`] bounds its reader joins with
/// [`NODE_DRAIN_DEADLINE`] instead of joining unbounded. The Node
/// scripts this module spawns (`node -e` request drivers) create no
/// children, so the gap is latent today; a future script that spawns one
/// would need a Job Object (or an equivalent) to restore the Unix
/// group-kill guarantee.
fn kill_child_process_group(child: &mut std::process::Child) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: `kill(2)` with a negative pid signals the process
        // group whose id is `pid`; no pointer is involved. `spawn_node_script`
        // made this child a process-group leader, so `-pid` names the
        // group the runtime created.
        let rc = unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(err)
        }
    }
    #[cfg(not(unix))]
    {
        child.kill()
    }
}

/// One pipe-drain stream: the reader thread sends its buffer once, at EOF,
/// and the receiving side decides how long to wait for it.
struct PipeReader {
    receiver: std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
}

/// Reads `pipe` to EOF on a dedicated thread.
///
/// One thread per pipe is what makes stdout and stderr drain
/// CONCURRENTLY: a child that fills the pipe it is not currently
/// being read from would otherwise block forever, never close the
/// other pipe, and deadlock a sequential reader. An absent pipe
/// contributes an empty buffer, exactly as
/// `std::process::Child::wait_with_output` does.
///
/// The thread is created through [`std::thread::Builder`] so a creation
/// failure is a RETURNED error instead of a panic (round-2 security L2):
/// the caller has already spawned the child, and an unwinding panic here
/// would drop the `Child` without killing or reaping it.
fn spawn_pipe_reader<R>(pipe: Option<R>) -> Result<PipeReader, &'static str>
where
    R: std::io::Read + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::channel();
    let handle = std::thread::Builder::new()
        .name("csq-node-pipe-reader".into())
        .spawn(move || {
            let mut buf = Vec::new();
            let outcome = match pipe {
                Some(mut pipe) => pipe.read_to_end(&mut buf).map(|_| buf),
                None => Ok(buf),
            };
            // A failed send means the receiver was dropped after a drain
            // deadline; the thread is terminating anyway.
            let _ = sender.send(outcome);
        })
        .map_err(|e| {
            tracing::warn!(
                error_kind = "node_pipe_reader_spawn_failed",
                io_kind = io_error_kind(&e),
                "node http transport: could not start a pipe reader thread"
            );
            ERR_NODE_TRANSPORT
        })?;
    // The reader is consumed through the channel; the JoinHandle has no
    // further role (dropping it detaches the thread, which the bounded
    // drain may leave parked on a pipe held by an escaped descendant).
    drop(handle);
    Ok(PipeReader { receiver })
}

/// Receives one pipe reader's buffer, waiting no later than `until`.
///
/// Returns [`ERR_NODE_DRAIN_TIMEOUT`] when the reader has not reached EOF
/// by then. The reader thread is NOT joined on that path: it may be parked
/// on a pipe that an escaped descendant still holds open, and joining it
/// would reintroduce the unbounded hang this budget exists to remove.
/// Dropping the receiver makes the thread's eventual send fail harmlessly;
/// the thread ends when the pipe finally closes, and that parked thread is
/// the documented residual of this bound.
fn drain_pipe_within(
    reader: &PipeReader,
    until: std::time::Instant,
) -> Result<Vec<u8>, &'static str> {
    let remaining = until.saturating_duration_since(std::time::Instant::now());
    match reader.receiver.recv_timeout(remaining) {
        Ok(Ok(buf)) => Ok(buf),
        Ok(Err(e)) => {
            tracing::warn!(
                error_kind = "node_pipe_read_failed",
                io_kind = io_error_kind(&e),
                "node http transport: reading the child's output pipe failed"
            );
            Err(ERR_NODE_TRANSPORT)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(ERR_NODE_DRAIN_TIMEOUT),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(ERR_NODE_TRANSPORT),
    }
}

/// Waits for `child` under a parent-side wall-clock `deadline`, then
/// collects its output with the production [`NODE_DRAIN_DEADLINE`].
///
/// See [`wait_for_node_child_with_drain_budget`] for the contract.
fn wait_for_node_child(
    child: std::process::Child,
    deadline: Duration,
) -> Result<std::process::Output, &'static str> {
    wait_for_node_child_with_drain_budget(child, deadline, NODE_DRAIN_DEADLINE)
}

/// Waits for `child` under a parent-side wall-clock `deadline`, then
/// collects its output under a `drain_budget`.
///
/// # Contract
///
/// - Stdin is dropped first, exactly as
///   `std::process::Child::wait_with_output` does. Every Node script in
///   this module reads its request payload from stdin and only issues
///   the request on stdin `end`; holding the handle open would turn
///   every call into a timeout.
/// - stdout and stderr are drained concurrently (see
///   [`spawn_pipe_reader`]) so a child flooding either pipe cannot
///   deadlock the parent.
/// - The child's process group is killed and the child reaped when
///   `deadline` elapses, so no zombie and no live runtime subtree
///   survives a wedged call. The unconditional direct `child.kill()`
///   before every `wait()` is load-bearing: `ESRCH` from the group
///   signal is indistinguishable from a child that was never a group
///   leader, and `wait()` must never block on a live child.
/// - BOTH the post-exit drain and the post-kill drain are bounded by
///   `drain_budget` (round-2 correctness L2). A pipe held open by an
///   escaped descendant — or by ANY descendant on Windows, which has no
///   group kill — ends the wait instead of blocking the caller forever.
///   The reader thread is detached on that path and ends when the pipe
///   closes. A stdout drain that FAILS cannot establish that the child
///   wrote nothing, so it is reported as
///   [`ERR_NODE_HTTP_OUTCOME_UNKNOWN`], not as a plain transport failure:
///   a possibly-complete body may be sitting unread in the reader's
///   buffer.
/// - On the success path the drained bytes are returned verbatim, as
///   `Child::wait_with_output` would. If stdout drains completely but
///   stderr does not, the COMPLETE stdout body is still returned (with a
///   fixed-tag warning and empty stderr): discarding a complete,
///   possibly credential-bearing response because its sibling pipe is
///   held open would be a worse loss than a missing diagnostic.
/// - On timeout the error is fixed vocabulary and NEVER the child's
///   output, which may contain the credential-bearing stdin payload or a
///   token echoed into stderr. It is one of:
///   - [`ERR_NODE_HTTP_OUTCOME_UNKNOWN`] when the child had already
///     written to stdout, OR when the stdout drain itself failed (an
///     unread buffer is zero evidence of "no output"). The response may
///     have been committed by the server (e.g. a refresh-token rotation)
///     before the kill, so the caller MUST treat the outcome as possibly
///     committed — see that constant's doc for the required caller
///     behaviour;
///   - [`ERR_NODE_WAIT_TIMEOUT`] only when stdout demonstrably drained to
///     EOF empty.
fn wait_for_node_child_with_drain_budget(
    mut child: std::process::Child,
    deadline: Duration,
    drain_budget: Duration,
) -> Result<std::process::Output, &'static str> {
    // Mirror `wait_with_output`: close stdin so a script reading its
    // payload to EOF proceeds. See the contract above.
    drop(child.stdin.take());

    let stdout_reader = match spawn_pipe_reader(child.stdout.take()) {
        Ok(reader) => reader,
        Err(e) => {
            // The child is already spawned and nothing downstream will
            // reap it, so this function must (round-2 security L2).
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };
    let stderr_reader = match spawn_pipe_reader(child.stderr.take()) {
        Ok(reader) => reader,
        Err(e) => {
            // The stdout reader thread is detached; killing the child
            // closes the stdout write end, so it reaches EOF and ends.
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    };

    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                // `try_wait` failing leaves the child state unknown;
                // drop would not reap it, so clean up best-effort and
                // report the wait failure.
                let _ = child.kill();
                let _ = child.wait();
                let drain_until = std::time::Instant::now() + drain_budget;
                let _ = drain_pipe_within(&stdout_reader, drain_until);
                let _ = drain_pipe_within(&stderr_reader, drain_until);
                tracing::warn!(
                    error_kind = "node_child_wait_failed",
                    io_kind = io_error_kind(&e),
                    "node http transport: waiting for the child failed"
                );
                return Err(ERR_NODE_TRANSPORT);
            }
        }

        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            // Kill BEFORE reaping (see `kill_child_process_group`).
            // A failed group signal is reported as a fixed-vocabulary
            // warning, and the direct child is still killed
            // best-effort so no runtime outlives the deadline.
            if let Err(e) = kill_child_process_group(&mut child) {
                tracing::warn!(
                    error_kind = "node_child_group_kill_failed",
                    io_kind = io_error_kind(&e),
                    "node http transport: timed-out child process group could not be signalled"
                );
            }
            // Unconditional direct kill, not only on a group-signal error:
            // ESRCH from the group signal is indistinguishable from a child
            // that was never a group leader, and `wait()` must never block on
            // a live child. Harmless when the group signal already killed it.
            let _ = child.kill();
            // Reap so no zombie survives. If the reap itself fails the
            // timeout error below is still the caller-facing outcome;
            // there is no further action available here.
            let _ = child.wait();
            // Bounded drain. The group signal above releases the ordinary
            // pipes; a descendant that escaped the group can still hold
            // one, and the drain budget turns that into a bounded return
            // instead of a blocked join.
            let drain_until = std::time::Instant::now() + drain_budget;
            // stdout is the classification signal: the scripts in this
            // module emit their wire format only from `res.on('end')`, so
            // any bytes here mean the response phase had begun and the
            // server may already have committed a mutation (round-2 M2).
            //
            // Only a SUCCESSFUL drain to EOF that is empty establishes
            // "the child wrote nothing". A failed drain (timeout or read
            // error) leaves a possibly-complete body unread in the
            // reader's buffer, which is zero evidence of no output — so it
            // takes the possibly-committed class, never the plain timeout.
            let stdout_known_empty = matches!(
                drain_pipe_within(&stdout_reader, drain_until),
                Ok(bytes) if bytes.is_empty()
            );
            // stderr is never surfaced on this path; draining it only
            // releases the reader within the same budget.
            let _ = drain_pipe_within(&stderr_reader, drain_until);
            if !stdout_known_empty {
                return Err(ERR_NODE_HTTP_OUTCOME_UNKNOWN);
            }
            return Err(ERR_NODE_WAIT_TIMEOUT);
        }
        std::thread::sleep(remaining.min(NODE_WAIT_POLL_INTERVAL));
    };

    let drain_until = std::time::Instant::now() + drain_budget;
    let stdout = match drain_pipe_within(&stdout_reader, drain_until) {
        Ok(stdout) => stdout,
        Err(e) => {
            // The child exited but its stdout never reached EOF, so a
            // possibly-complete body may be sitting unread in the reader's
            // partial buffer. Fail into the possibly-committed class
            // instead of discarding it as a plain transport failure.
            tracing::warn!(
                error_kind = "node_child_stdout_drain_failed",
                outcome_class = transport_class_tag(e),
                "node http transport: stdout drain did not complete after the child exited; \
                 classifying the outcome as possibly committed"
            );
            return Err(ERR_NODE_HTTP_OUTCOME_UNKNOWN);
        }
    };
    let stderr = match drain_pipe_within(&stderr_reader, drain_until) {
        Ok(stderr) => stderr,
        Err(e) => {
            // stdout is COMPLETE (the child exited and its stdout reached
            // EOF). See the contract: keep the body, report the degraded
            // stderr, never discard a possibly credential-bearing response
            // because a sibling pipe is still held open.
            tracing::warn!(
                error_kind = "node_child_stderr_drain_failed",
                outcome_class = transport_class_tag(e),
                "node http transport: stderr drain did not complete after the child exited; \
                 returning the complete stdout body with empty stderr"
            );
            Vec::new()
        }
    };

    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Returns `true` if `url` contains a codepoint that must never reach
/// a Node.js script literal: a quote character (`'`, `"`, `` ` ``), a
/// backslash, a CR/LF, any ASCII control codepoint (`< 0x20` or
/// `0x7F`), or U+2028/U+2029 (LINE SEPARATOR / PARAGRAPH SEPARATOR).
///
/// # Why codepoint-level, not byte-level
///
/// U+2028/U+2029 encode as `E2 80 A8` / `E2 80 A9` — three bytes, each
/// individually `>= 0x80` — so a byte-oriented scan (the previous
/// implementation) never observed them. Scanning `url.chars()` instead
/// of `url.bytes()` is what makes rejecting them possible; every other
/// disallowed value here is single-byte-equivalent under either scan.
///
/// # U+2028/U+2029 — defensive hardening and a doc correction, NOT a vulnerability fix
///
/// Round-2 redteam (code-review lens) verified live on this host
/// (node v25.9.0, bun): a URL containing U+2028 round-trips through
/// [`js_url_literal`]'s JSON encoding, is embedded inside the
/// double-quoted `new URL(...)` literal exactly as JSON emits it
/// (`hexdump` confirms the raw `E2 80 A8` bytes sit inside the quotes),
/// and the script runs with no parse error and no exit-code anomaly.
/// TC39's ES2019 "JSON superset" change made both codepoints legal,
/// unescaped, and inert inside a JS string literal on every runtime csq
/// currently resolves (node/bun releases are all well past that
/// baseline) — there is no unescaped way to terminate the literal early
/// without a quote character, and quotes are already rejected below. A
/// pre-ES2019 engine would instead have treated them as
/// `LineTerminator`s even inside a string literal, truncating the token
/// and throwing `SyntaxError` — fail-closed, not exploitable, and moot
/// given the runtimes in play. `serde_json` does not escape these two
/// codepoints by default (verified:
/// `serde_json::to_string("a\u{2028}b")` returns the raw codepoint
/// unescaped, matching JS's own historical `JSON.stringify`
/// behavior — see `serde_json_does_not_escape_line_separator`), so
/// adding them to this guard is defense in depth against that
/// already-inert byte class and against a hypothetical future
/// engine regression — not the closure of an exploitable path on any
/// runtime csq resolves today.
///
/// # Defense in depth
///
/// This guard is not the primary escaping mechanism —
/// [`js_url_literal`] JSON-encodes the URL before interpolation, which
/// is sufficient on its own for every runtime csq resolves. Rejecting
/// these codepoints outright means a future edit that reintroduces raw
/// `format!` interpolation still fails closed instead of reopening the
/// quote/backslash/control-byte injection this module's original fix
/// (an internal ticket) closed. A legitimate URL never needs any of these
/// codepoints raw — percent-encoding covers every real case.
fn url_has_unsafe_js_chars(url: &str) -> bool {
    url.chars().any(|c| {
        // `\r` and `\n` are listed explicitly for readability even
        // though both are already caught by `(c as u32) < 0x20` below
        // (C0 control range) — do not read them as load-bearing on
        // their own; removing them changes nothing (round-2 redteam
        // NIT).
        matches!(
            c,
            '\'' | '"' | '`' | '\\' | '\r' | '\n' | '\u{2028}' | '\u{2029}'
        ) || (c as u32) < 0x20
            || c == '\u{7F}'
    })
}

/// Renders `url` as a JSON string literal suitable for direct
/// interpolation into a Node.js script as `new URL({literal})`.
///
/// JS string-literal syntax is a superset of JSON's for this purpose
/// (JSON escapes `"`, `\`, and the C0 control codepoints U+0000–U+001F
/// — corrected per round-2 redteam: read from `serde_json`'s escape
/// table directly, `0x00`–`0x1F` are escaped but `0x7F`/DEL is NOT; the
/// prior comment's "all control bytes" overstated this). That gap is
/// harmless to the property this function relies on: U+007F was never
/// a breakout character in either JSON or JS string-literal grammar —
/// only quotes, backslash, and raw C0 controls terminate a literal
/// early — so a JSON-encoded string is still always a valid, single,
/// self-contained JS string token regardless of its content; the URL
/// cannot break out of it. Callers additionally reject unsafe
/// codepoints via [`url_has_unsafe_js_chars`] (which DOES reject
/// U+007F, as belt-and-braces) before calling this, but the escaping
/// here holds even if that guard is ever bypassed.
///
/// Separated into its own pure function so tests can verify the
/// escaping without spawning a subprocess.
fn js_url_literal(url: &str) -> Result<String, String> {
    serde_json::to_string(url).map_err(|_| ERR_ENCODE_FAILED.to_string())
}

/// The ONE shared in-script request-timeout prelude emitted into EVERY
/// Node script builder (`build_post_script`, `build_post_with_date_script`,
/// `build_get_bearer_script`, `build_get_bearer_with_retry_after_script`).
///
/// # Why a total timer, not just the `timeout` request option
///
/// `https.request`'s `timeout` option is a socket-INACTIVITY timer: a
/// server that trickles bytes with gaps shorter than the value keeps
/// resetting it, so on its own it is not a bound on the request at all
/// (round-2 M2). This prelude arms a TOTAL wall-clock timer that destroys
/// the request `timeout_ms` after it is issued — whatever the socket is
/// doing — and writes the same fixed `timeout` diagnostic the inactivity
/// handler writes.
///
/// One shared function is what keeps the four builders from drifting: a
/// builder that lost the timer would otherwise pass every test the other
/// three pass. The response-end handler calls `__csqSettle()` before
/// writing stdout, which marks the response as won and clears the timer so
/// no timer outlives a completed response; `__csqFail` is the single
/// failure path for both the inactivity timer and request errors.
fn node_request_timeout_prelude(timeout_ms: u64) -> String {
    format!(
        r#"  let __csqSettled = false;
  const __csqFail = (why) => {{ if (__csqSettled) return; __csqSettled = true; process.stderr.write(why); process.exit(1); }};
  // TOTAL request timer: fires whatever the socket is doing. The request
  // option `timeout` above is only an inactivity guard that a trickling
  // response keeps resetting.
  const __csqTimer = setTimeout(() => {{ req.destroy(); __csqFail('timeout'); }}, {timeout_ms});
  // Do not keep the event loop alive after a successful response; the
  // response-end handler's __csqSettle() is the primary release.
  if (typeof __csqTimer.unref === 'function') __csqTimer.unref();
  const __csqSettle = () => {{ if (__csqSettled) return false; __csqSettled = true; clearTimeout(__csqTimer); return true; }};
"#
    )
}

/// Builds the Node.js script body for [`post_json_node`].
///
/// Pure and side-effect-free (round-2 redteam NIT-2) so tests can
/// assert the SINK actually consumes `url_literal` — a
/// `js_url_literal`-produced JSON string token — rather than a
/// hand-quoted `url`. This is the untested composition direction the
/// module's layering doc comments assert but a mutation test never
/// checked: reverting `new URL({url_literal})` back to
/// `new URL('{url}')` while leaving both encoding helpers and every
/// existing guard test in place would otherwise pass the full suite
/// unnoticed.
///
/// The `process.on('uncaughtException', ...)` guard registered first is
/// the LOW-2 follow-up (round-2 redteam): any exception NOT already
/// handled by the `req.on('error' | 'timeout')` handlers below —
/// concretely, `new URL(...)` throwing synchronously on a
/// malformed-but-guard-passing URL (e.g. unbalanced IPv6 brackets,
/// which Rust's `url` crate rejects to parse, so the userinfo check in
/// [`get_bearer_node`] never even sees it) — would otherwise print
/// Node's default uncaught-exception report to stderr, and that report
/// can embed the raw input (live-verified: `TypeError: Invalid URL ...
/// { input: 'https://user:hunter2@[' }` — the password survives into
/// that `input:` field, and `redact_tokens` does not target userinfo
/// passwords). Handling it here bounds every escape hatch to the same
/// fixed-vocabulary `script_error` literal the module's other error
/// paths already use.
fn build_post_script(url_literal: &str, timeout_ms: u64) -> String {
    let prelude = node_request_timeout_prelude(timeout_ms);
    format!(
        r#"
process.on('uncaughtException', () => {{ process.stderr.write('script_error'); process.exit(1); }});
const https = require('https');
const url = new URL({url_literal});
let body = '';
process.stdin.on('data', c => body += c);
process.stdin.on('end', () => {{
  const req = https.request(url, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)}},
    timeout: {timeout_ms}
  }}, res => {{
    let data = [];
    res.on('data', c => data.push(c));
    res.on('end', () => {{
      if (!__csqSettle()) return;
      process.stdout.write(Buffer.concat(data));
    }});
  }});
{prelude}  req.on('timeout', () => {{ req.destroy(); __csqFail('timeout'); }});
  req.on('error', e => __csqFail(e.message));
  req.write(body);
  req.end();
}});
"#
    )
}

/// POSTs a JSON body to `url` using a Node.js subprocess.
///
/// The body is piped via stdin (not argv) so tokens don't appear
/// in `ps` output. Returns the response body bytes on any HTTP
/// status — the caller classifies the response.
///
/// Returns `Err` if no JS runtime (`node` or `bun`) is found.
///
/// `url` is rejected outright if it carries userinfo or fails to parse
/// (round-2 redteam H2 — `post_json_node`'s stdin body is an OAuth
/// authorization-code / refresh-token exchange payload, a live credential
/// just as much as a bearer header). See `reject_userinfo`.
pub fn post_json_node(url: &str, body: &str) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://") {
        return Err(ERR_HTTPS_REQUIRED.into());
    }
    if url_has_unsafe_js_chars(url) {
        tracing::warn!(
            error_kind = "url_rejected_unsafe_js_chars",
            "node http transport: rejected outbound url containing disallowed characters"
        );
        return Err(ERR_URL_UNSAFE_CHARS.into());
    }
    reject_userinfo(url)?;

    let runtime = find_js_runtime()?;
    let url_literal = js_url_literal(url)?;
    let script = build_post_script(&url_literal, NODE_TIMEOUT_MS);

    let output = match run_node_script(&runtime, &script, body.as_bytes()) {
        Ok(output) => output,
        Err(e) if e == ERR_NODE_WAIT_TIMEOUT => {
            return Err(ERR_NODE_WAIT_TIMEOUT.to_string());
        }
        Err(e) if e == ERR_NODE_HTTP_OUTCOME_UNKNOWN => {
            return Err(ERR_NODE_HTTP_OUTCOME_UNKNOWN.to_string());
        }
        Err(other) => {
            tracing::warn!(
                error_kind = "node_transport_failed",
                outcome_class = transport_class_tag(other),
                "node http transport: runtime failure classified as the shared \
                 transport constant"
            );
            return Err(ERR_NODE_TRANSPORT.to_string());
        }
    };

    if !output.status.success() {
        log_node_failure(&output.stderr);
        return Err(ERR_NODE_TRANSPORT.to_string());
    }

    Ok(output.stdout)
}

/// Builds the Node.js script body for [`post_json_node_with_date`].
///
/// See [`build_post_script`] for the composition-test rationale (NIT-2)
/// and the `process.on('uncaughtException', ...)` guard this script
/// shares (LOW-2 follow-up).
fn build_post_with_date_script(url_literal: &str, timeout_ms: u64) -> String {
    let prelude = node_request_timeout_prelude(timeout_ms);
    format!(
        r#"
process.on('uncaughtException', () => {{ process.stderr.write('script_error'); process.exit(1); }});
const https = require('https');
const url = new URL({url_literal});
let body = '';
process.stdin.on('data', c => body += c);
process.stdin.on('end', () => {{
  const req = https.request(url, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body)}},
    timeout: {timeout_ms}
  }}, res => {{
    const dateHeader = res.headers['date'] || '';
    let data = [];
    res.on('data', c => data.push(c));
    res.on('end', () => {{
      if (!__csqSettle()) return;
      // First line: `<status> <date>` (status = res.statusCode; date is
      // empty when the header is absent, but the separating space is
      // always emitted so the parser can split on the first space
      // unconditionally). Then body.
      process.stdout.write(res.statusCode + ' ' + dateHeader + '\n');
      process.stdout.write(Buffer.concat(data));
    }});
  }});
{prelude}  req.on('timeout', () => {{ req.destroy(); __csqFail('timeout'); }});
  req.on('error', e => __csqFail(e.message));
  req.write(body);
  req.end();
}});
"#
    )
}

/// Full response from [`post_json_node_with_date`]: the HTTP status
/// code, the response body, and the `Date` header (if any).
///
/// `Debug` is hand-written, NOT derived: `body` is the raw upstream
/// response, which for the OAuth token endpoints this transport serves
/// may contain an echoed refresh token or other credential fragments
/// in an error envelope (see the module-level `# Security` note and
/// [`post_form`]'s credential-safety warning). The derive would print
/// `body` verbatim on any `{:?}` — a `tracing::debug!(?resp)` or a
/// panic message — so it is rendered as a byte count instead.
pub struct NodeHttpResponse {
    /// The HTTP status code (`res.statusCode`). Never a default:
    /// [`post_json_node_with_date`] parses the status line strictly and
    /// returns `Err` when it is missing or non-numeric, so a value here was
    /// always read from the response. ([`post_json_node`] has no
    /// status-reporting path and never constructs this type.)
    pub status: u16,
    /// The raw response body, byte-for-byte identical to what
    /// [`post_json_node`] returns.
    pub body: Vec<u8>,
    /// The response `Date` header, if present.
    pub date: Option<String>,
}

impl fmt::Debug for NodeHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeHttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("date", &self.date)
            .finish()
    }
}

/// Parses the `<status> <date>` first line written by
/// [`build_post_with_date_script`] onto stdout ahead of the response
/// body.
///
/// `status` MUST be present and parse as `u16` — a missing or
/// unparseable status is an `Err`, never a default (a silently-defaulted
/// status previously made the Codex 429 rate-limit gate unreachable in
/// production: every call site passed a literal `200`, so
/// `classify_error` never saw a real status and the `429` match arm in
/// `refresh/check.rs::broker_codex_check` could never fire). `date` is
/// everything after the first space, treated as absent when empty (the
/// script always emits the separating space even when the header is
/// missing, so splitting unconditionally on the first space is safe).
fn parse_status_date_line(line: &str) -> Result<(u16, Option<String>), String> {
    let mut parts = line.splitn(2, ' ');
    let status_str = parts.next().unwrap_or("");
    // Shared constant, not the offending text: the classifier works by
    // equality, and the raw status line is server-controlled. The caller
    // logs a fixed `node_response_malformed` frame tag instead.
    let Ok(status) = status_str.parse::<u16>() else {
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let date = match parts.next() {
        Some(rest) if !rest.is_empty() => Some(rest.to_string()),
        _ => None,
    };
    Ok((status, date))
}

/// POSTs a JSON body to `url` using a Node.js subprocess and also
/// captures the response status code and `Date` header.
///
/// Behaves identically to [`post_json_node`] (HTTPS-only, body-via-
/// stdin, returns the response body on any HTTP status) but
/// additionally returns the HTTP status code and the `Date` response
/// header via [`NodeHttpResponse`], for callers that need to classify
/// the response by status (e.g. Codex's `429` rate-limit path) or need
/// server clock-skew detection (PR-C4 INV-P01: daemon Codex refresher
/// emits `clock_skew_detected` when local time differs from server
/// `Date` by > 5 min).
///
/// Wire format on stdout (produced by `build_post_with_date_script`):
///
/// - First line: `<status> <date>` — see `parse_status_date_line`.
/// - Remaining bytes: response body, byte-for-byte identical to what
///   [`post_json_node`] returns.
///
/// Splitting on the first `\n` keeps body bytes lossless even if the
/// body itself contains newlines (JSON-pretty-printed responses). A
/// missing or unparseable status/date line is a transport `Err`, not a
/// defaulted status — see `parse_status_date_line`.
///
/// `url` is rejected outright if it carries userinfo or fails to parse
/// (round-2 redteam H2 — same rationale as [`post_json_node`], this
/// function's stdin body is also a live-credential-bearing OAuth exchange
/// payload). See `reject_userinfo`.
pub fn post_json_node_with_date(url: &str, body: &str) -> Result<NodeHttpResponse, String> {
    if !url.starts_with("https://") {
        return Err(ERR_HTTPS_REQUIRED.into());
    }
    if url_has_unsafe_js_chars(url) {
        tracing::warn!(
            error_kind = "url_rejected_unsafe_js_chars",
            "node http transport: rejected outbound url containing disallowed characters"
        );
        return Err(ERR_URL_UNSAFE_CHARS.into());
    }
    reject_userinfo(url)?;

    let runtime = find_js_runtime()?;
    let url_literal = js_url_literal(url)?;
    let script = build_post_with_date_script(&url_literal, NODE_TIMEOUT_MS);

    let output = match run_node_script(&runtime, &script, body.as_bytes()) {
        Ok(output) => output,
        Err(e) if e == ERR_NODE_WAIT_TIMEOUT => {
            return Err(ERR_NODE_WAIT_TIMEOUT.to_string());
        }
        Err(e) if e == ERR_NODE_HTTP_OUTCOME_UNKNOWN => {
            return Err(ERR_NODE_HTTP_OUTCOME_UNKNOWN.to_string());
        }
        Err(other) => {
            tracing::warn!(
                error_kind = "node_transport_failed",
                outcome_class = transport_class_tag(other),
                "node http transport: runtime failure classified as the shared \
                 transport constant"
            );
            return Err(ERR_NODE_TRANSPORT.to_string());
        }
    };

    if !output.status.success() {
        log_node_failure(&output.stderr);
        return Err(ERR_NODE_TRANSPORT.to_string());
    }

    let stdout = output.stdout;
    let Some(newline_pos) = stdout.iter().position(|&b| b == b'\n') else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_date_line",
            "node http transport: the response did not start with a status/date line"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let Ok(first_line) = std::str::from_utf8(&stdout[..newline_pos]) else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_date_line_utf8",
            "node http transport: the status/date line was not valid UTF-8"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let Ok((status, date)) = parse_status_date_line(first_line) else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_date_line_parse",
            "node http transport: the status/date line was missing or non-numeric"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let body = stdout[newline_pos + 1..].to_vec();
    Ok(NodeHttpResponse { status, body, date })
}

/// Debug-only upper bound on the encoded stdin payload
/// ([`bearer_stdin_payload`]'s return value), in bytes.
///
/// Today's two production callers pass one bearer token plus 1-3 small
/// static headers — orders of magnitude under this bound and under
/// typical OS pipe buffer capacity (16-64 KiB). `write_all` happens
/// AFTER `spawn()`, so the OS buffers the write regardless of whether
/// the child has registered its stdin handler yet — no deadlock at
/// current sizes. This bound exists so a future caller that passes an
/// oversized `extra_headers` map fails loudly in a debug build (round-2
/// redteam NIT) rather than silently risking a stdin-pipe deadlock (the
/// writer blocks because the pipe is full; the child blocks because it
/// hasn't drained enough to unblock the writer) in a release build
/// years later once someone extends this function's caller set.
#[cfg(debug_assertions)]
const BEARER_STDIN_PAYLOAD_MAX_BYTES: usize = 8192;

/// Builds the single-JSON stdin payload for [`get_bearer_node`]:
/// `{"token": "...", "extra": {...}}`.
///
/// Built via `serde_json::json!` + `serde_json::Map` so header names
/// and values are proper JSON strings (never manually joined) — this
/// also means encoding cannot silently produce malformed JSON per-pair
/// the way the prior `serde_json::to_string(..).unwrap_or_default()`
/// per-field construction could (an encode failure there degraded to
/// an empty string, e.g. `{:}`, rather than propagating an error).
///
/// Separated into its own pure function, mirroring [`js_url_literal`],
/// so tests can verify the framing survives a `token` value containing
/// bytes that desynchronised the OLD newline-delimited stdin protocol
/// (MED-1) — without spawning a subprocess and without going through
/// `get_bearer_node`'s own defense-in-depth control-byte guard on
/// `token`.
fn bearer_stdin_payload(token: &str, extra_headers: &[(&str, &str)]) -> Result<String, String> {
    let mut extra_map = serde_json::Map::new();
    for (k, v) in extra_headers {
        extra_map.insert(
            (*k).to_string(),
            serde_json::Value::String((*v).to_string()),
        );
    }
    let payload =
        serde_json::json!({ "token": token, "extra": serde_json::Value::Object(extra_map) });
    // Shared-constant rejection in a `return Err(ERR_...)` shape so the
    // poller's structural oracle can see it (a `.map_err(..)?` form hides
    // the constant behind the `?`).
    let Ok(encoded) = serde_json::to_string(&payload) else {
        return Err(ERR_ENCODE_FAILED.to_string());
    };
    #[cfg(debug_assertions)]
    debug_assert!(
        encoded.len() <= BEARER_STDIN_PAYLOAD_MAX_BYTES,
        "bearer stdin payload is {} bytes, exceeding the {}-byte debug bound — a caller \
         passing this much token/header data risks a stdin-pipe deadlock; see the bound's \
         doc comment",
        encoded.len(),
        BEARER_STDIN_PAYLOAD_MAX_BYTES
    );
    Ok(encoded)
}

/// Builds the Node.js script body for [`get_bearer_node`].
///
/// See [`build_post_script`] for the composition-test rationale
/// (NIT-2). The `process.on('uncaughtException', ...)` guard
/// registered first is the LOW-2 follow-up: this is the one script
/// whose synchronous `new URL(...)` construction sits behind a
/// Rust-side userinfo check that can itself be bypassed by a URL
/// malformed enough that Rust's `url` crate refuses to parse it at all
/// (live-verified: `https://user:hunter2@[`, an unbalanced IPv6
/// bracket, fails `url::Url::parse` in Rust but throws
/// `TypeError: Invalid URL` in Node with the password surviving into
/// the error object's `input:` field — a leak `redact_tokens` does not
/// target). The handler bounds that escape hatch, and any future one,
/// to the same fixed-vocabulary `script_error` literal every other
/// error path in this module already uses.
fn build_get_bearer_script(url_literal: &str, timeout_ms: u64) -> String {
    let prelude = node_request_timeout_prelude(timeout_ms);
    format!(
        r#"
process.on('uncaughtException', () => {{ process.stderr.write('script_error'); process.exit(1); }});
const https = require('https');
const url = new URL({url_literal});
let input = '';
process.stdin.on('data', c => input += c);
process.stdin.on('end', () => {{
  const {{ token, extra }} = JSON.parse(input);
  const headers = {{...extra, 'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}};
  const req = https.request(url, {{
    method: 'GET',
    headers,
    timeout: {timeout_ms}
  }}, res => {{
    let data = [];
    res.on('data', c => data.push(c));
    res.on('end', () => {{
      if (!__csqSettle()) return;
      const body = Buffer.concat(data);
      // First line of stdout: status code. Rest: body.
      process.stdout.write(res.statusCode + '\n');
      process.stdout.write(body);
    }});
  }});
{prelude}  req.on('timeout', () => {{ req.destroy(); __csqFail('timeout'); }});
  req.on('error', e => __csqFail(e.message));
  req.end();
}});
"#
    )
}

/// GETs a URL with a Bearer token using a Node.js subprocess.
///
/// Returns `(status_code, body_bytes)`. The bearer token and any extra
/// headers are passed via stdin as a **single JSON object** —
/// `{"token": "...", "extra": {...}}` — not argv.
///
/// # Why a single JSON object, not a newline-delimited protocol
///
/// An earlier version wrote `token\n` then the extra-headers JSON as a
/// second stdin write, and the script split on the first `\n`. `\n` is
/// a legal byte in an OAuth bearer token, so it was simultaneously the
/// wire delimiter *and* representable token content: a token containing
/// an embedded `\n{"Authorization":"Bearer attacker"}` desynchronised
/// the split — the attacker-controlled second line was parsed as the
/// extra-headers object and, spread last into the `headers` literal,
/// silently overrode `Authorization` (MED-1, an internal ticket redteam). A
/// single JSON payload makes this unrepresentable: `token` is a JSON
/// string value, so any embedded control byte is escaped by
/// `serde_json` rather than interpreted as a frame boundary — there is
/// no second field for a crafted value to desynchronise into.
pub fn get_bearer_node(
    url: &str,
    token: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), String> {
    if !url.starts_with("https://") {
        return Err(ERR_HTTPS_REQUIRED.into());
    }
    if url_has_unsafe_js_chars(url) {
        tracing::warn!(
            error_kind = "url_rejected_unsafe_js_chars",
            "node http transport: rejected outbound url containing disallowed characters"
        );
        return Err(ERR_URL_UNSAFE_CHARS.into());
    }
    // Belt-and-braces: the JSON-payload framing below already makes a
    // `\n`-bearing token safe (it's just an escaped byte inside a JSON
    // string), but reject it outright anyway so a future edit that
    // reintroduces raw stdin interpolation still fails closed. No
    // legitimate bearer token needs a raw control byte.
    // Codepoint-oriented, matching `url_has_unsafe_js_chars`: U+2028/U+2029
    // encode as three bytes each individually >= 0x80, so the byte scan this
    // replaces never observed them. Harmless today (the token travels as a
    // serde_json string value and never reaches script text) — but this guard's
    // stated purpose is to stay closed against a FUTURE edit that reintroduces
    // raw stdin interpolation, and under that hypothetical a U+2028-bearing
    // token passed for exactly the reason the URL guard was converted.
    //
    // C1 control range (U+0080-U+009F, incl. U+0085 NEL) is included
    // alongside C0 (round-2 redteam L1): the prior scan admitted it, so a
    // C1-bearing token was NOT rejected pre-flight and would instead
    // corrupt the `Authorization` header the script builds — a silent
    // failure mode, not the fail-closed rejection this guard exists to
    // provide.
    if token.chars().any(|c| {
        matches!(c, '\r' | '\n' | '\u{2028}' | '\u{2029}')
            || (c as u32) < 0x20
            || (0x7F..=0x9F).contains(&(c as u32))
    }) {
        return Err(ERR_TOKEN_UNSAFE_CHARS.into());
    }
    // LOW-2 / H1 / H2: reject userinfo (`user:pass@host`), failing CLOSED
    // on a url this parser cannot parse at all. `get_bearer_node` is a
    // credential-bearing sink — a hostile URL with userinfo reads as the
    // trusted host on operator-facing surfaces (e.g.
    // `https://cli-chat-proxy.grok.com@evil.example/v1` parses to HOST
    // `evil.example`) while the live bearer token is sent to whatever host
    // actually follows `@`. No legitimate csq endpoint uses userinfo. See
    // [`reject_userinfo`]'s doc for why an unparseable url is now also
    // rejected outright, rather than left to the downstream Node.js
    // `new URL(...)` construction.
    reject_userinfo(url)?;

    let runtime = find_js_runtime()?;
    let url_literal = js_url_literal(url)?;
    let payload_json = bearer_stdin_payload(token, extra_headers)?;
    let script = build_get_bearer_script(&url_literal, NODE_TIMEOUT_MS);

    let output = match run_node_script(&runtime, &script, payload_json.as_bytes()) {
        Ok(output) => output,
        Err(e) if e == ERR_NODE_WAIT_TIMEOUT => {
            return Err(ERR_NODE_WAIT_TIMEOUT.to_string());
        }
        Err(e) if e == ERR_NODE_HTTP_OUTCOME_UNKNOWN => {
            return Err(ERR_NODE_HTTP_OUTCOME_UNKNOWN.to_string());
        }
        Err(other) => {
            tracing::warn!(
                error_kind = "node_transport_failed",
                outcome_class = transport_class_tag(other),
                "node http transport: runtime failure classified as the shared \
                 transport constant"
            );
            return Err(ERR_NODE_TRANSPORT.to_string());
        }
    };

    if !output.status.success() {
        log_node_failure(&output.stderr);
        return Err(ERR_NODE_TRANSPORT.to_string());
    }

    let stdout = output.stdout;
    let Some(newline_pos) = stdout.iter().position(|&b| b == b'\n') else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_line",
            "node http transport: the response did not start with a status line"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let Ok(status_str) = std::str::from_utf8(&stdout[..newline_pos]) else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_line_utf8",
            "node http transport: the status line was not valid UTF-8"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let Ok(status) = status_str.parse::<u16>() else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_code",
            "node http transport: the status line was not a numeric status code"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let body = stdout[newline_pos + 1..].to_vec();

    Ok((status, body))
}

/// Builds the Node.js script body for
/// [`get_bearer_node_with_retry_after`].
///
/// Identical to [`build_get_bearer_script`] except for what the
/// response handler writes to stdout: this variant adds a `retry-after`
/// line between the status line and the body. See
/// [`get_bearer_node_with_retry_after`]'s doc for why that line's
/// content is restricted to `/^\d+$/` (or empty) INSIDE this script,
/// before it ever reaches Rust.
fn build_get_bearer_with_retry_after_script(url_literal: &str, timeout_ms: u64) -> String {
    let prelude = node_request_timeout_prelude(timeout_ms);
    format!(
        r#"
process.on('uncaughtException', () => {{ process.stderr.write('script_error'); process.exit(1); }});
const https = require('https');
const url = new URL({url_literal});
let input = '';
process.stdin.on('data', c => input += c);
process.stdin.on('end', () => {{
  const {{ token, extra }} = JSON.parse(input);
  const headers = {{...extra, 'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}};
  const req = https.request(url, {{
    method: 'GET',
    headers,
    timeout: {timeout_ms}
  }}, res => {{
    let data = [];
    res.on('data', c => data.push(c));
    res.on('end', () => {{
      if (!__csqSettle()) return;
      const body = Buffer.concat(data);
      // retry-after is SERVER-controlled. Emit it ONLY when it is a
      // delay-seconds value (RFC 9110 10.2.3, digits only) -- an
      // HTTP-date form or anything else is dropped, never forwarded.
      // This is the emission-time guarantee the Rust-side wire-format
      // doc depends on: only ASCII digits (or nothing) can ever occupy
      // this line, so no value the header could carry can desync the
      // two-newline framing below.
      const ra = res.headers['retry-after'];
      const raLine = (typeof ra === 'string' && /^\d+$/.test(ra)) ? ra : '';
      // First line of stdout: status code. Second: retry-after (or
      // empty). Rest: body.
      process.stdout.write(res.statusCode + '\n');
      process.stdout.write(raLine + '\n');
      process.stdout.write(body);
    }});
  }});
{prelude}  req.on('timeout', () => {{ req.destroy(); __csqFail('timeout'); }});
  req.on('error', e => __csqFail(e.message));
  req.end();
}});
"#
    )
}

/// GETs a URL with a Bearer token using a Node.js subprocess, like
/// [`get_bearer_node`], but additionally captures the response's
/// `retry-after` header as a delay-seconds value.
///
/// # Why a sibling function, not an extended [`get_bearer_node`]
///
/// `HttpGetFn` (the closure type that wraps `get_bearer_node`'s
/// `(u16, Vec<u8>)` signature) is threaded through every usage-poller
/// surface -- codex, kimi, grok, zai, minimax, deepseek, third_party,
/// the refresher, `custodian.rs`, and every mock in their test suites.
/// Only the Anthropic usage poller needs `retry-after`: csq had no code
/// path that read the header on ANY 429 response, and honoring a
/// server-stated wait is correct on its own merits whenever the server
/// sends one — independent of how often that happens in practice for
/// any particular host or account. Widening the shared return type would
/// force every one of those unrelated call sites and mocks to grow a
/// field they never read. See
/// `csq-core/src/daemon/usage_poller/mod.rs`'s
/// `HttpGetWithRetryAfterFn`, which wraps this function and is wired
/// ONLY into the Anthropic poller.
///
/// # Wire format: why `retry-after` is validated in JavaScript, not Rust
///
/// This is the RESPONSE-side analogue of the hazard documented on
/// [`get_bearer_node`] for the REQUEST side (MED-1, an internal ticket redteam):
/// there, an attacker-controlled `token` containing an embedded
/// newline could desynchronise a newline-delimited stdin protocol and
/// override a header. Here, `retry-after` is SERVER-controlled rather
/// than ours, and the stdout wire format below is newline-delimited
/// (status line, retry-after line, body) -- so the same hazard shape
/// applies in the opposite direction: a malicious or misconfigured
/// origin could inject arbitrary bytes, including embedded newlines,
/// into the `retry-after` header value and desynchronise the Rust-side
/// parser's two-newline body offset.
///
/// The fix is the same principle applied at the opposite end: the
/// script in `build_get_bearer_with_retry_after_script` matches the
/// header value against `/^\d+$/` and writes EITHER that validated
/// digit run OR an empty string -- never the raw header value. No byte
/// the origin sends can reach the wire format un-validated, so no
/// value of that header can ever contain a newline (or anything else)
/// by the time it crosses the process boundary. Re-validating in Rust
/// AFTER the bytes have already been spliced into the byte stream
/// would be checking a format that was already unsafe to construct;
/// checking in JS, at the point of emission, is what makes the
/// guarantee structural.
///
/// # Returns
///
/// `(status_code, retry_after_seconds, body_bytes)`. `retry_after_seconds`
/// is `Some(n)` only when the header was present and matched
/// `^\d+$`; an absent header, an HTTP-date value, or any other
/// non-digit content are ALL normalised to `None` here (as is a digit
/// run too large for `u64`, e.g. from a malformed origin) -- this
/// function reports "did the server give us a wait time we could use",
/// not "was the header present". Callers that need to distinguish
/// those cases do not exist today; if one arises, thread the raw
/// string through instead of collapsing it here.
pub fn get_bearer_node_with_retry_after(
    url: &str,
    token: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, Option<u64>, Vec<u8>), String> {
    if !url.starts_with("https://") {
        return Err(ERR_HTTPS_REQUIRED.into());
    }
    if url_has_unsafe_js_chars(url) {
        tracing::warn!(
            error_kind = "url_rejected_unsafe_js_chars",
            "node http transport: rejected outbound url containing disallowed characters"
        );
        return Err(ERR_URL_UNSAFE_CHARS.into());
    }
    // Mirrors get_bearer_node's token guard: belt-and-braces against a
    // future edit reintroducing raw stdin interpolation. See that
    // function's doc for the full rationale, including the C1 control
    // range and U+2028/U+2029 line separators.
    if token.chars().any(|c| {
        matches!(c, '\r' | '\n' | '\u{2028}' | '\u{2029}')
            || (c as u32) < 0x20
            || (0x7F..=0x9F).contains(&(c as u32))
    }) {
        return Err(ERR_TOKEN_UNSAFE_CHARS.into());
    }
    // See get_bearer_node's doc for why an unparseable url is rejected
    // outright rather than left to Node's `new URL(...)`.
    reject_userinfo(url)?;

    let runtime = find_js_runtime()?;
    let url_literal = js_url_literal(url)?;
    let payload_json = bearer_stdin_payload(token, extra_headers)?;
    let script = build_get_bearer_with_retry_after_script(&url_literal, NODE_TIMEOUT_MS);

    let output = match run_node_script(&runtime, &script, payload_json.as_bytes()) {
        Ok(output) => output,
        Err(e) if e == ERR_NODE_WAIT_TIMEOUT => {
            return Err(ERR_NODE_WAIT_TIMEOUT.to_string());
        }
        Err(e) if e == ERR_NODE_HTTP_OUTCOME_UNKNOWN => {
            return Err(ERR_NODE_HTTP_OUTCOME_UNKNOWN.to_string());
        }
        Err(other) => {
            tracing::warn!(
                error_kind = "node_transport_failed",
                outcome_class = transport_class_tag(other),
                "node http transport: runtime failure classified as the shared \
                 transport constant"
            );
            return Err(ERR_NODE_TRANSPORT.to_string());
        }
    };

    if !output.status.success() {
        log_node_failure(&output.stderr);
        return Err(ERR_NODE_TRANSPORT.to_string());
    }

    let stdout = output.stdout;
    let Some(first_nl) = stdout.iter().position(|&b| b == b'\n') else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_line",
            "node http transport: the response did not start with a status line"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let Ok(status_str) = std::str::from_utf8(&stdout[..first_nl]) else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_line_utf8",
            "node http transport: the status line was not valid UTF-8"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let Ok(status) = status_str.parse::<u16>() else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "status_code",
            "node http transport: the status line was not a numeric status code"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };

    let rest = &stdout[first_nl + 1..];
    let Some(second_nl) = rest.iter().position(|&b| b == b'\n') else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "retry_after_line",
            "node http transport: the response did not carry a retry-after line"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    let Ok(retry_after_str) = std::str::from_utf8(&rest[..second_nl]) else {
        tracing::warn!(
            error_kind = "node_response_malformed",
            frame = "retry_after_line_utf8",
            "node http transport: the retry-after line was not valid UTF-8"
        );
        return Err(ERR_NODE_TRANSPORT.to_string());
    };
    // Empty is the script's explicit "absent or unparseable" sentinel.
    // An empty string also fails `str::parse::<u64>`, so folding this
    // into the parse-failure branch below would behave identically --
    // both yield `None` -- but this keeps "the header wasn't there"
    // and "the header was present but corrupt" distinguishable in the
    // reasoning even though callers only observe `None` either way.
    let retry_after = if retry_after_str.is_empty() {
        None
    } else {
        retry_after_str.parse::<u64>().ok()
    };

    let body = rest[second_nl + 1..].to_vec();

    Ok((status, retry_after, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_status_date_line ────────────────────────────────────

    #[test]
    fn parse_status_date_line_status_and_date() {
        let (status, date) = parse_status_date_line("429 Tue, 22 Apr 2026 14:32:01 GMT").unwrap();
        assert_eq!(status, 429);
        assert_eq!(date.as_deref(), Some("Tue, 22 Apr 2026 14:32:01 GMT"));
    }

    #[test]
    fn parse_status_date_line_no_date_is_none() {
        // The script always emits the separating space even when the
        // Date header is absent.
        let (status, date) = parse_status_date_line("200 ").unwrap();
        assert_eq!(status, 200);
        assert_eq!(date, None);
    }

    #[test]
    fn parse_status_date_line_rejects_empty_line() {
        assert!(parse_status_date_line("").is_err());
    }

    #[test]
    fn parse_status_date_line_rejects_non_numeric_status() {
        assert!(parse_status_date_line("abc x").is_err());
    }

    #[test]
    fn client_constructs_without_panic() {
        // Just exercising the OnceLock path — if this panics, the
        // config is invalid.
        let _ = client();
    }

    #[test]
    fn post_form_rejects_http_scheme() {
        // https_only(true) should cause any http:// URL to fail at
        // request time. We don't need a live server for this; the
        // error surfaces synchronously.
        let result = post_form(
            "http://example.invalid/oauth/token",
            "grant_type=refresh_token",
        );
        assert!(result.is_err(), "http:// must be rejected by https_only");
    }

    struct FailingReader;
    impl std::io::Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other(
                "https://api.example.com/v1?key=SECRETURLTOKEN failed",
            ))
        }
    }

    /// G5d: a read error never echoes the wrapped message (URL/body).
    #[test]
    fn capped_read_error_does_not_echo_wrapped_message() {
        let e = read_body_capped(FailingReader, 1024).unwrap_err();
        assert!(!e.contains("SECRETURLTOKEN"), "{e}");
        let e = read_capped_probe_body(FailingReader, 1024).unwrap_err();
        assert!(!e.contains("SECRETURLTOKEN"), "{e}");
    }

    /// G3: every capped helper family shares `read_body_capped`: over cap is
    /// the fixed body-free error; at cap is returned whole.
    #[test]
    fn read_body_capped_over_cap_is_fixed_error_without_body() {
        let secret = "sk-ant-api03-FAKETESTcapbody0123456789abcdefghij";
        let mut body = secret.to_string();
        body.push_str(&"a".repeat(RESPONSE_BODY_CAP));
        let e = read_body_capped(body.as_bytes(), RESPONSE_BODY_CAP).unwrap_err();
        assert_eq!(e, RESPONSE_OVER_CAP);
        assert!(!e.contains("FAKETEST"));
        let ok = read_body_capped("b".repeat(1024).as_bytes(), 1024).unwrap();
        assert_eq!(ok.len(), 1024);
        let e = read_body_capped(std::io::repeat(b'c'), 4096).unwrap_err();
        assert_eq!(e, RESPONSE_OVER_CAP);
    }

    /// The cap applies to a real `reqwest::blocking::Response` reader (a
    /// plain-http loopback server; the shared client is https-only, so this
    /// uses its own client to exercise only the body reader).
    #[test]
    fn read_body_capped_bounds_a_real_response_body() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let total = 300 * 1024;
        let t = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut req = [0u8; 1024];
                let _ = sock.read(&mut req);
                let head = format!(
                    "HTTP/1.1 500 X\r\nContent-Length: {total}\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(head.as_bytes());
                let _ = sock.write_all(&vec![b'z'; total]);
            }
        });
        let resp = reqwest::blocking::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .unwrap();
        let e = read_body_capped(resp, 64 * 1024).unwrap_err();
        assert_eq!(e, RESPONSE_OVER_CAP);
        let _ = t.join();
    }

    #[test]
    fn probe_body_over_cap_yields_fixed_string_without_body_content() {
        let secret = "sk-ant-api03-FAKETESTprobecap0123456789abcdefghij";
        let mut body = secret.to_string();
        body.push_str(&"a".repeat(PROBE_BODY_CAP + 10));
        let out = read_capped_probe_body(body.as_bytes(), PROBE_BODY_CAP).unwrap();
        assert_eq!(out, PROBE_BODY_OVER_CAP);
        assert!(!out.contains("FAKETEST"));
    }

    #[test]
    fn probe_body_at_cap_is_returned_whole_and_never_over_reads() {
        let body = "b".repeat(PROBE_BODY_CAP);
        let out = read_capped_probe_body(body.as_bytes(), PROBE_BODY_CAP).unwrap();
        assert_eq!(out.len(), PROBE_BODY_CAP);
        // A reader that would yield unbounded data is read at most cap+1 bytes.
        let out = read_capped_probe_body(std::io::repeat(b'c'), 1024).unwrap();
        assert_eq!(out, PROBE_BODY_OVER_CAP);
    }

    #[test]
    fn post_json_probe_rejects_http_scheme() {
        let result = post_json_probe(
            "http://example.invalid/v1/messages",
            &[],
            r#"{"model":"x","max_tokens":1}"#,
        );
        assert!(result.is_err(), "http:// must be rejected by https_only");
    }

    #[test]
    fn post_form_invalid_url_errors_cleanly() {
        let result = post_form("not-a-url", "");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        // Should not contain the body or any unexpected content
        assert!(!msg.contains("refresh_token"));
    }

    #[test]
    fn post_form_unreachable_host_times_out_or_connect_fails() {
        // TEST-NET-1 (192.0.2.0/24) is reserved for documentation; any
        // connect attempt will fail (connection refused or timeout).
        // We use a short-lived call to verify error classification
        // without a network round-trip hanging.
        //
        // Note: This test makes a real network attempt. It's fast
        // because the kernel returns "connection refused" for
        // documentation space almost immediately, but if that ever
        // changes it could become slow. Guard with a smaller timeout
        // in the future if needed.
        let result = post_form("https://192.0.2.1/oauth/token", "grant_type=refresh_token");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        // Either "connection failed" or "request timed out" depending
        // on network stack behavior.
        assert!(
            msg.contains("connection") || msg.contains("timed out") || msg.contains("error"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn post_json_rejects_http_scheme() {
        // https_only(true) applies to post_json too — proving the
        // JSON path inherits the shared client configuration.
        let result = post_json(
            "http://example.invalid/v1/oauth/token",
            r#"{"grant_type":"authorization_code"}"#,
        );
        assert!(result.is_err(), "http:// must be rejected by https_only");
    }

    #[test]
    fn post_json_unreachable_host_errors_cleanly() {
        // TEST-NET-1 (192.0.2.0/24) is reserved for documentation.
        let result = post_json(
            "https://192.0.2.1/v1/oauth/token",
            r#"{"grant_type":"authorization_code","code":"abc"}"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("connection") || msg.contains("timed out") || msg.contains("error"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn get_bearer_rejects_http_scheme() {
        let result = get_bearer("http://example.invalid/api/oauth/usage", "tok", &[]);
        assert!(result.is_err(), "http:// must be rejected by https_only");
    }

    #[test]
    fn get_bearer_error_does_not_leak_token() {
        // The token is ALSO in the URL path: reqwest's error Display echoes the
        // URL, so if a transport error ever starts carrying detail, the token
        // reaches the message and this needle reds. The exact-vocabulary
        // assertion pins today's fixed strings ("connection failed" / "request
        // timed out") — sanitize_err renders those, never request detail.
        let result = get_bearer(
            "https://192.0.2.1/sk-ant-oat01-FAKETESTOKEN/api/oauth/usage",
            "sk-ant-oat01-FAKETESTOKEN",
            &[("Anthropic-Beta", "oauth-2025-04-20")],
        );
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg == "connection failed" || msg == "request timed out",
            "transport error must keep a fixed vocabulary, got: {msg}"
        );
        assert!(
            !msg.contains("FAKETESTOKEN"),
            "error message leaked the bearer token: {msg}"
        );
    }

    #[test]
    fn post_json_error_does_not_leak_body() {
        // Critical safety assertion: if post_json ever starts leaking
        // the request body into error strings, OAuth `code` and
        // `code_verifier` values would end up in logs. This test
        // fails if that regression is introduced.
        let result = post_json(
            "https://192.0.2.1/v1/oauth/token",
            r#"{"code":"SECRET_OAUTH_CODE_ABC123","client_id":"test"}"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            !msg.contains("SECRET_OAUTH_CODE_ABC123"),
            "error message leaked the JSON body: {msg}"
        );
    }

    #[test]
    fn sanitize_err_does_not_leak_bodies() {
        // Unit-check: confirm the sanitizer strips URLs and doesn't
        // format the full error debug. We can't easily construct a
        // reqwest::Error directly, so we verify indirectly via
        // post_form above (the returned Err string must not contain
        // the refresh_token we passed).
        let result = post_form(
            "https://192.0.2.1/oauth/token",
            "grant_type=refresh_token&refresh_token=sk-ant-ort01-SECRET",
        );
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            !msg.contains("SECRET"),
            "error message leaked request body: {msg}"
        );
    }

    // ── JS runtime resolution ───────────────────────────────

    #[test]
    fn js_runtime_path_lists_are_non_empty_and_populated_with_expected_entries() {
        // Guards against an accidental edit that wipes out the
        // candidate list — a regression that would silently break
        // token refresh on every GUI-launched desktop install until
        // someone notices the 401s.
        assert!(
            SYSTEM_WIDE_JS_RUNTIMES.contains(&"/opt/homebrew/bin/node"),
            "Apple Silicon Homebrew path must be probed"
        );
        assert!(
            SYSTEM_WIDE_JS_RUNTIMES.contains(&"/usr/local/bin/node"),
            "Intel Homebrew / manual-install path must be probed"
        );
        assert!(
            PER_USER_JS_RUNTIMES.contains(&".bun/bin/bun"),
            "Bun installer default must be probed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_js_runtime_finds_node_via_path_when_available() {
        // On every reasonable dev / CI box `node` or `bun` is on
        // PATH, so the function must succeed. If this ever fails,
        // install node on CI *before* deleting this test.
        let resolved = resolve_js_runtime();
        assert!(
            resolved.is_some(),
            "no JS runtime found — install node or bun on this host"
        );
        let path = resolved.unwrap();
        assert!(!path.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn probe_runtime_accepts_real_runtime_and_rejects_missing_path() {
        // If PATH has node, the bare-name probe succeeds. If not, we
        // still want a clean rejection of a bogus absolute path.
        assert!(!probe_runtime(Path::new("/nonexistent/does-not-exist")));
    }

    // ── Host-speed-independent readiness and deadline helpers ───
    //
    // Every row below drives a REAL child process, so a verdict anchored to an
    // elapsed time is a verdict on the host's scheduling load, not on the
    // production contract. These helpers keep two things separate:
    //
    // - READINESS waits on the observable the child actually produces (a
    //   marker file, a recorded pid, a process state) until it exists. The wait
    //   ends the moment the condition does; hitting the bound is a HARNESS
    //   failure naming its derivation, never a silent pass.
    // - BOUNDS are the production bound the row is about, and an elapsed
    //   ceiling is the helper's STRUCTURAL worst case (deadline plus the
    //   post-deadline budget) plus a NAMED policy margin. No measured typical
    //   time is ever used.

    /// The harness's scheduling allowance: the transport's own fixed policy
    /// allowance ([`NODE_WAIT_MARGIN_MS`], added in production for spawn,
    /// runtime startup, module loading and stdin consumption).
    ///
    /// It is a NAMED policy bound, not an observed typical — the phases a test
    /// harness waits across are exactly the phases that constant covers.
    fn test_host_margin() -> Duration {
        Duration::from_millis(NODE_WAIT_MARGIN_MS)
    }

    /// Readiness bound for a spawned stub to reach a marker it writes: the
    /// production parent wait ([`NODE_CHILD_WAIT_DEADLINE`], which already
    /// covers spawn, startup and stdin) plus [`test_host_margin`].
    fn spawn_readiness_budget() -> Duration {
        NODE_CHILD_WAIT_DEADLINE + test_host_margin()
    }

    /// Readiness bound for an ASYNCHRONOUS process-state transition (a group
    /// SIGKILL taking effect, an orphan being reaped): the module's enforced
    /// [`NODE_DRAIN_DEADLINE`] — its policy bound for waiting on an
    /// asynchronous process/pipe event — plus [`test_host_margin`].
    #[cfg(unix)]
    fn state_readiness_budget() -> Duration {
        NODE_DRAIN_DEADLINE + test_host_margin()
    }

    /// Polls `predicate` until it is true or `budget` elapses. This is a
    /// READINESS wait, not elapsed-time ordering: it ends as soon as the
    /// observable condition exists. Returns `false` on expiry — the caller
    /// asserts the harness condition AFTER whatever cleanup the row performs,
    /// so a broken run cannot leak a 600 s stub.
    fn wait_until(budget: Duration, mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = std::time::Instant::now() + budget;
        loop {
            if predicate() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Ceiling for a deadline-bounded transport call: the injected deadline,
    /// the poll interval its wait loop may overshoot by
    /// ([`NODE_WAIT_POLL_INTERVAL`]), the drain budget it may then spend, and
    /// [`test_host_margin`].
    ///
    /// This is the helper's structural worst case plus a named policy margin —
    /// it tells "returned at the deadline" apart from "returned when the
    /// stub's own 600 s sleep ended". It is never a measured latency.
    #[cfg(unix)]
    fn bounded_call_ceiling(deadline: Duration, drain_budget: Duration) -> Duration {
        deadline + NODE_WAIT_POLL_INTERVAL + drain_budget + test_host_margin()
    }

    /// Parses the single pid a stub recorded in `path`. `None` until the stub's
    /// write has produced a parseable pid, so a reader racing the write never
    /// invents one.
    #[cfg(unix)]
    fn recorded_pid(path: &std::path::Path) -> Option<libc::pid_t> {
        std::fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    /// `true` when `pid` currently exists (running OR a zombie).
    #[cfg(unix)]
    fn process_exists(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 performs the existence/permission check only and
        // touches no memory.
        let rc = unsafe { libc::kill(pid, 0) };
        rc == 0
    }

    /// `true` once `pid` is no longer RUNNING: gone (`ESRCH`) or a zombie.
    ///
    /// `kill(pid, 0)` answers 0 for a zombie, so it cannot separate "dead" from
    /// "running"; `ps -o stat=` reports the state, and `Z` is a zombie. What
    /// the rows below pin is that a SIGNAL REACHED the process, not that its
    /// new parent (init/launchd) has already reaped it — that latency is host
    /// scheduling, not the contract. An unreadable state reports STILL RUNNING
    /// so a missing instrument fails the row instead of passing it.
    #[cfg(unix)]
    fn process_exited(pid: libc::pid_t) -> bool {
        if !process_exists(pid) {
            return true;
        }
        match std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
        {
            Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
                .trim_start()
                .starts_with('Z'),
            _ => false,
        }
    }

    // ── LOW: zombie process on stdin-write failure ──────────────

    #[test]
    fn write_stdin_bounded_reaps_the_child_on_write_failure() {
        // Regression test (round-2 redteam LOW finding): a bare `?` on
        // the stdin write left `child` dropped without ever being
        // `.wait()`-ed, leaking a zombie process entry on Unix.
        //
        // Reproduces the exact failure shape live: spawn a real node
        // process that exits immediately (closing its own stdin), sleep
        // briefly so the exit has actually happened, then attempt to
        // write — this reliably produces a `BrokenPipe`/EPIPE error
        // (verified inline via a standalone harness:
        // `write_result = Err(Os { code: 32, kind: BrokenPipe, .. })`).
        //
        // ROUND-3 AMENDMENT — EPIPE is now a fall-through, not an error.
        //
        // The round-2 version of this test asserted `result.is_err()` and
        // `contains("stdin write failed")` on exactly this input. That
        // assertion encoded the bug a later round found: EPIPE means the child
        // is already gone, and with the `uncaughtException` guard that usually
        // means it exited deliberately having ALREADY written `script_error` to
        // stderr. Reporting the write error discarded that message, and which
        // of the two strings an operator saw depended on scheduling.
        //
        // `write_stdin_bounded` now returns `Ok(())` on EPIPE so the caller's
        // `wait_for_node_child` reaps the child and surfaces its own diagnostic.
        // What this test pins is therefore the CONTRACT, in both directions:
        //   - EPIPE          → `Ok(())`, and the child is still reapable by the
        //                      caller (`try_wait` must not error).
        //   - missing stdin  → `Err`, and reaped HERE (nothing downstream will).
        //
        // READINESS (host-speed fix): EPIPE requires that the child has CLOSED
        // ITS STDIN, which happens exactly when it exits. The row used to sleep
        // 300 ms and hope that had happened, so on a loaded host the child can
        // still be starting, the write then succeeds, and the row passes
        // without ever exercising the fall-through. `try_wait` makes the exit
        // the signal AND keeps `child.stdin` present (`wait` would drop it, and
        // the write below would take the missing-handle branch instead).
        let runtime = find_js_runtime().expect("test host must have node or bun on PATH");
        let mut child = std::process::Command::new(&runtime)
            .arg("-e")
            .arg("process.exit(0);")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn must succeed");

        let readiness = spawn_readiness_budget();
        let exited = wait_until(readiness, || matches!(child.try_wait(), Ok(Some(_))));
        assert!(
            exited,
            "the stub must exit within {readiness:?} \
             (NODE_CHILD_WAIT_DEADLINE + NODE_WAIT_MARGIN_MS); without the exit \
             the write cannot produce EPIPE and this row would be vacuous"
        );

        let result = write_stdin_bounded(
            &mut child,
            b"payload after child already exited",
            NODE_CHILD_WAIT_DEADLINE,
        );
        assert!(
            result.is_ok(),
            "EPIPE must fall through so the caller's wait_for_node_child can \
             surface the child's OWN stderr; got {result:?}"
        );

        // The caller's next step must still succeed; the reap DISCRIMINATION
        // lives in the missing-stdin branch below (a 60 s child reported as
        // already reaped). Here the child is deliberately already reaped so
        // the EPIPE precondition is deterministic.
        let post = child.wait();
        assert!(
            post.is_ok(),
            "child must remain reapable after an EPIPE fall-through: {post:?}"
        );

        // The other direction: a MISSING stdin handle is a real error, and
        // nothing downstream will reap it, so this function must. Reproduced by
        // taking the handle away before the call.
        let mut child2 = std::process::Command::new(&runtime)
            .arg("-e")
            .arg("setTimeout(()=>{},60000);")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn must succeed");
        drop(child2.stdin.take());

        let result2 = write_stdin_bounded(&mut child2, b"payload", NODE_CHILD_WAIT_DEADLINE);
        assert!(
            result2.as_ref().is_err_and(|e| *e == ERR_NODE_TRANSPORT),
            "a missing stdin handle must be the shared transport constant: {result2:?}"
        );
        // `try_wait` returning `Ok(Some(_))` immediately — on a child scripted
        // to live 60s — is only possible because this function already killed
        // and reaped it.
        let post2 = child2.try_wait();
        assert!(
            matches!(post2, Ok(Some(_))),
            "a 60s child must already be reaped after the missing-handle branch: {post2:?}"
        );
    }

    /// A child that never reads its stdin must not hang the write: the
    /// payload is larger than any kernel pipe buffer, so `write_all` blocks
    /// after the pipe fills. Before the bounded writer this call never
    /// returned; with it, the budget expires, the child's group is killed,
    /// and the fixed timeout class comes back. Deterministic: the write is
    /// guaranteed to block because the child never reads, and the expiry is
    /// enforced by the budget, not measured latency.
    #[test]
    fn write_stdin_bounded_times_out_when_the_child_never_reads_a_full_pipe() {
        let runtime = find_js_runtime().expect("test host must have node or bun on PATH");
        let mut child = std::process::Command::new(&runtime)
            .arg("-e")
            .arg("setInterval(()=>{},1000);")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn must succeed");
        let payload = vec![b'x'; 4 * 1024 * 1024];
        // The injected budget IS the property: the write must be bounded by
        // the budget the caller passed, not by the child's cooperation. The
        // ceiling is the helper's structural worst case — the budget, then the
        // writer-report wait the timeout path bounds with NODE_DRAIN_DEADLINE —
        // plus the named policy margin. It is not a measure of host speed.
        let write_budget = Duration::from_millis(300);
        let started = std::time::Instant::now();
        let result = write_stdin_bounded(&mut child, &payload, write_budget);
        let elapsed = started.elapsed();
        assert!(
            result.as_ref().is_err_and(|e| *e == ERR_NODE_WAIT_TIMEOUT),
            "a wedged stdin write must return the fixed timeout class: {result:?}"
        );
        let ceiling = write_budget + NODE_DRAIN_DEADLINE + test_host_margin();
        assert!(
            elapsed < ceiling,
            "the write must be bounded by the budget: took {elapsed:?}, \
             ceiling {ceiling:?} (budget + NODE_DRAIN_DEADLINE + NODE_WAIT_MARGIN_MS)"
        );
        // Killed and reaped here, so nothing outlives the call.
        let post = child.try_wait();
        assert!(
            matches!(post, Ok(Some(_))),
            "the wedged child must already be reaped: {post:?}"
        );
    }

    // ── Parent-side child deadline ──────────────────────────────
    //
    // The in-script `NODE_TIMEOUT_MS` only bounds the request itself.
    // A child wedged outside it (startup, DNS, stuck runtime) used to
    // block the parent forever in `wait_with_output()`, and the daemon
    // refresher awaits these calls. These rows pin the parent-side
    // bound: a wedged child is killed by PROCESS GROUP and reaped at
    // the deadline, flooded pipes drain concurrently, and the success
    // path still returns the child's bytes verbatim.

    /// Spawns a `sh` stub with piped stdio in its OWN process group,
    /// matching the invariant [`spawn_node_script`] establishes for
    /// production children.
    #[cfg(unix)]
    fn spawn_unix_stub(args: &[&str]) -> std::process::Child {
        use std::os::unix::process::CommandExt;
        std::process::Command::new("sh")
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("stub spawn must succeed")
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_node_child_closes_stdin_and_returns_body_bytes() {
        // `cat` exits only on stdin EOF, so this row fails (by hitting
        // the deadline) if the helper ever stops dropping the stdin
        // handle the way `wait_with_output` does. The byte equality
        // pins the success-path contract: no re-encoding, no trim.
        //
        // The deadline is the PRODUCTION parent bound
        // (`NODE_CHILD_WAIT_DEADLINE`, the enforced spawn-to-reap ceiling),
        // not a hand-picked 10 s: a well-behaved stub must finish inside the
        // bound every real transport call is held to.
        let mut child = spawn_unix_stub(&["-c", r#"cat >/dev/null; printf '200\nhello-body'"#]);
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(b"{\"payload\":\"x\"}")
            .expect("write to stub stdin must succeed");

        let output = wait_for_node_child(child, NODE_CHILD_WAIT_DEADLINE)
            .expect("a well-behaved stub must finish inside NODE_CHILD_WAIT_DEADLINE");

        assert!(output.status.success(), "stub must exit 0: {output:?}");
        assert_eq!(output.stdout, b"200\nhello-body");
        assert!(output.stderr.is_empty(), "stub wrote no stderr");
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_node_child_kills_and_reaps_a_wedged_child_at_the_deadline() {
        // RED without the fix: the old `child.wait_with_output()` blocks
        // on this stub forever (it sleeps 600 s and reads no stdin), so
        // this test only ever terminates once the parent deadline kills
        // and reaps the child. The recorded pid proves both: `kill(pid,
        // 0)` answers 0 for a zombie, so ESRCH means the child was
        // actually reaped, not merely killed.
        //
        // READINESS (host-speed fix): the ready signal is the pidfile the stub
        // writes as its LAST act before `exec sleep 600`. The row used to start
        // its 200 ms deadline immediately, so on a loaded host `sh` could still
        // be starting when the deadline expired and the pidfile read below
        // panicked — a harness failure dressed as a product failure.
        let pidfile =
            std::env::temp_dir().join(format!("csq-node-wait-{}-wedged.pid", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        let pidfile_arg = pidfile.to_string_lossy().into_owned();
        let child = spawn_unix_stub(&[
            "-c",
            r#"printf '%s' "$$" > "$1"; exec sleep 600"#,
            "sh",
            pidfile_arg.as_str(),
        ]);

        let readiness = spawn_readiness_budget();
        let ready = wait_until(readiness, || {
            recorded_pid(&pidfile).is_some_and(process_exists)
        });

        let deadline = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let result = wait_for_node_child(child, deadline);
        let elapsed = started.elapsed();
        let ceiling = bounded_call_ceiling(deadline, NODE_DRAIN_DEADLINE);

        assert_eq!(
            result.err(),
            Some(ERR_NODE_WAIT_TIMEOUT),
            "a wedged child must surface the fixed-vocabulary timeout error"
        );
        // The helper's structural worst case, not a latency measurement: it
        // distinguishes "returned at the deadline" from "returned after the
        // stub's 600 s sleep".
        assert!(
            elapsed < ceiling,
            "deadline not enforced: call took {elapsed:?}, ceiling {ceiling:?} \
             (deadline + NODE_WAIT_POLL_INTERVAL + NODE_DRAIN_DEADLINE + NODE_WAIT_MARGIN_MS)"
        );
        // Checked AFTER the call, which killed and reaped the stub, so a
        // harness failure here cannot leak a 600 s sleeper.
        assert!(
            ready,
            "the stub must record its pid within {readiness:?} \
             (NODE_CHILD_WAIT_DEADLINE + NODE_WAIT_MARGIN_MS) before the deadline starts"
        );

        let pid = recorded_pid(&pidfile).expect("stub must record its pid before sleeping");

        // SAFETY: signal 0 performs the existence/permission check only
        // and touches no memory.
        let alive = unsafe { libc::kill(pid, 0) };
        assert_eq!(
            alive, -1,
            "process {pid} survived the deadline kill (kill(pid, 0) == 0)"
        );
        let err = std::io::Error::last_os_error();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ESRCH),
            "process {pid} must be GONE and REAPED after the timeout path: {err}"
        );
        let _ = std::fs::remove_file(&pidfile);
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_node_child_drains_flooded_stdout_and_stderr_concurrently() {
        // RED with a SEQUENTIAL reader: the stub fills stderr past the
        // pipe buffer BEFORE closing stdout. A parent that reads stdout
        // to EOF first blocks on the child, the child blocks on the full
        // stderr pipe, and neither ever moves. Concurrent drain lets the
        // stub finish and exit, so this row returns Ok well inside the
        // production parent bound (`NODE_CHILD_WAIT_DEADLINE`) with both
        // streams intact.
        let child = spawn_unix_stub(&[
            "-c",
            "head -c 1048576 /dev/zero >&2; head -c 1048576 /dev/zero; printf tail",
        ]);

        let output = wait_for_node_child(child, NODE_CHILD_WAIT_DEADLINE)
            .expect("flooded pipes must drain concurrently inside NODE_CHILD_WAIT_DEADLINE");

        assert!(output.status.success(), "stub must exit 0: {output:?}");
        assert_eq!(output.stderr.len(), 1_048_576, "all stderr bytes drained");
        assert_eq!(
            output.stdout.len(),
            1_048_576 + 4,
            "all stdout bytes drained"
        );
        assert!(
            output.stdout.ends_with(b"tail"),
            "stdout tail must arrive after the flood"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_node_child_bounds_a_flooding_child_at_the_deadline() {
        // The deadline row's second shape: a child that floods BOTH
        // pipes and then stays alive forever must still return at the
        // injected deadline. RED without the parent deadline: the old
        // `wait_with_output()` drains concurrently but has no time
        // bound, so this row hangs for the stub's 600 s sleep. The
        // flood also fails a sequential drain, which would block on the
        // stderr pipe before the wait loop ever runs.
        //
        // Classification: this stub HAS written stdout before the
        // deadline, so the kill is reported as the round-2 M2
        // possibly-committed class, NOT the plain timeout. The empty-stdout
        // shape is the wedged row above, which keeps asserting
        // ERR_NODE_WAIT_TIMEOUT.
        //
        // READINESS (host-speed fix): that classification needs stdout BYTES
        // written before the deadline. The stub used to flood stderr first and
        // stdout second, so on a loaded host the deadline could expire before
        // the stdout flood began; the killed child then drained EMPTY and the
        // row reddened as the plain timeout. The stub now writes ONE stdout
        // byte and a readiness marker FIRST — both fit the pipe buffer, so
        // neither needs the parent to drain — which establishes "stdout bytes
        // exist" before the injected deadline starts. The floods and the 600 s
        // sleep follow.
        let readyfile =
            std::env::temp_dir().join(format!("csq-node-flood-{}.ready", std::process::id()));
        let _ = std::fs::remove_file(&readyfile);
        let readyfile_arg = readyfile.to_string_lossy().into_owned();
        let child = spawn_unix_stub(&[
            "-c",
            r#"printf x; printf ready > "$1"; head -c 1048576 /dev/zero >&2; head -c 1048576 /dev/zero; exec sleep 600"#,
            "sh",
            readyfile_arg.as_str(),
        ]);

        let readiness = spawn_readiness_budget();
        let ready = wait_until(readiness, || readyfile.exists());

        let deadline = Duration::from_millis(300);
        let started = std::time::Instant::now();
        let result = wait_for_node_child(child, deadline);
        let elapsed = started.elapsed();
        let ceiling = bounded_call_ceiling(deadline, NODE_DRAIN_DEADLINE);

        assert_eq!(
            result.err(),
            Some(ERR_NODE_HTTP_OUTCOME_UNKNOWN),
            "a flooding-but-alive child that already emitted stdout must be \
             classified as a possibly-committed outcome at the parent deadline"
        );
        assert!(
            elapsed < ceiling,
            "deadline not enforced under flood: call took {elapsed:?}, ceiling \
             {ceiling:?} (deadline + NODE_WAIT_POLL_INTERVAL + NODE_DRAIN_DEADLINE + NODE_WAIT_MARGIN_MS)"
        );
        // Checked AFTER the call, which killed the stub at the deadline, so a
        // harness failure here cannot leak it.
        assert!(
            ready,
            "the stub must write its stdout byte and readiness marker within \
             {readiness:?} (NODE_CHILD_WAIT_DEADLINE + NODE_WAIT_MARGIN_MS)"
        );
        let _ = std::fs::remove_file(&readyfile);
    }

    #[test]
    fn transport_warning_tags_are_fixed_vocabulary() {
        // Round-2 security L1: the transport warnings log these tags, never
        // the `io::Error` Display text. The mapping itself is pinned here so
        // a future edit cannot widen a tag into free-form text without
        // changing this row.
        assert_eq!(
            io_error_kind(&std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            "broken_pipe"
        );
        assert_eq!(
            io_error_kind(&std::io::Error::from(std::io::ErrorKind::NotFound)),
            "not_found"
        );
        assert_eq!(
            io_error_kind(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            "permission_denied"
        );
        assert_eq!(transport_class_tag(ERR_NODE_TRANSPORT), "node_transport");
        assert_eq!(
            transport_class_tag(ERR_NODE_WAIT_TIMEOUT),
            "node_wait_timeout"
        );
        assert_eq!(
            transport_class_tag(ERR_NODE_HTTP_OUTCOME_UNKNOWN),
            "node_outcome_unknown"
        );
        assert_eq!(
            transport_class_tag(ERR_NODE_DRAIN_TIMEOUT),
            "node_drain_timeout"
        );
        // Any other string — a future constant this mapping was not updated
        // for — falls back to a fixed tag, never to the input itself.
        assert_eq!(
            transport_class_tag("an unvetted future string"),
            "other_fixed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_node_child_kills_the_whole_process_group_not_only_the_leader() {
        // Round-2 correctness M4: the existing wedged/flood rows use
        // `exec sleep`, so the DIRECT child is the sleeper and a bare
        // `child.kill()` satisfies every assertion — deleting the group
        // kill reds nothing. This row puts the stdout holder in a
        // GRANDCHILD: `sh -c 'sleep 600 & ...; wait'`. A direct kill of
        // the shell leaves `sleep` alive and holding the pipe.
        //
        // RED without `kill_child_process_group`: the grandchild stays a
        // live `sleep 600` holding stdout, so the stdout drain cannot reach
        // EOF inside the injected drain budget and the call returns the
        // possibly-committed class instead of the plain timeout (the liveness
        // check below would also never see it exit). Either way the row fails,
        // bounded — no hang.
        //
        // Event-synchronised (round-2 correctness L-a): the stub writes the
        // pidfile AND then a readiness marker BEFORE the deadline starts, and
        // this row waits for both first. Previously both the pidfile write and
        // the grandchild fork raced a 200 ms deadline, so under load the shell
        // could be killed before `printf` ran and the pidfile read panicked —
        // a flake in a row that is otherwise a genuine discriminator. The
        // deadline still governs the call itself: after readiness the shell is
        // parked in `wait` with the grandchild holding the pipe, so the call
        // must time out and the group kill is what releases it.
        let pidfile =
            std::env::temp_dir().join(format!("csq-node-wait-{}-group.pid", std::process::id()));
        let readyfile =
            std::env::temp_dir().join(format!("csq-node-wait-{}-group.ready", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_file(&readyfile);
        let pidfile_arg = pidfile.to_string_lossy().into_owned();
        let readyfile_arg = readyfile.to_string_lossy().into_owned();
        let child = spawn_unix_stub(&[
            "-c",
            r#"sleep 600 & printf '%s' "$!" > "$1"; printf ready > "$2"; wait"#,
            "sh",
            pidfile_arg.as_str(),
            readyfile_arg.as_str(),
        ]);
        // The harness's OWN handle on the stub tree: `spawn_unix_stub` makes the
        // child a process-group leader, so this pid is also the pgid of every
        // descendant it forks — including one whose pid the pidfile never
        // recorded.
        let leader_pid = child.id() as libc::pid_t;

        // Bounded READINESS wait: both the marker AND a parseable, existing
        // grandchild pid. It bounds THIS row's own wait, not the production
        // call's: the call below still receives the short deadline, so the kill
        // path under test is unchanged.
        let readiness = spawn_readiness_budget();
        let ready = wait_until(readiness, || {
            readyfile.exists() && recorded_pid(&pidfile).is_some_and(process_exists)
        });

        let deadline = Duration::from_millis(200);
        let drain_budget = Duration::from_millis(500);
        let started = std::time::Instant::now();
        let result = wait_for_node_child_with_drain_budget(child, deadline, drain_budget);
        let elapsed = started.elapsed();
        let ceiling = bounded_call_ceiling(deadline, drain_budget);

        // Poll the ASYNCHRONOUS state change BEFORE asserting, and clean up
        // unconditionally so a RED cannot leak a 600 s sleeper. A zombie is
        // already DEAD: what this row pins is that the group signal REACHED the
        // grandchild, not that its new parent (init/launchd) has reaped it —
        // requiring ESRCH made the row a measurement of the orphan reaper's
        // latency. Without the group kill the sleeper stays RUNNING for 600 s,
        // so the poll expires and the row fails.
        let grandchild = recorded_pid(&pidfile);
        let exited = grandchild.is_some_and(|pid| {
            let exited = wait_until(state_readiness_budget(), || process_exited(pid));
            if !exited {
                // SAFETY: signalling our own recorded grandchild.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            exited
        });

        // Belt-and-braces cleanup that does NOT depend on the pidfile: probe
        // the stub's process group (the leader pid IS the pgid) and kill it when
        // any member survives. Signal 0 first — ESRCH means the group is already
        // empty (nothing to clean, and the id may be recycled), while success
        // means a descendant is still alive, and these stubs sleep for minutes,
        // so the id cannot be released between the probe and the kill. This is
        // what closes the leak when the pidfile was never written (readiness
        // failed) AND the helper's group kill was broken: the pidfile-only
        // cleanup above would have no pid to signal. It runs AFTER the `exited`
        // observation, so the row's discrimination is unchanged.
        let group_probe = unsafe { libc::kill(-leader_pid, 0) };
        if group_probe == 0 {
            // SAFETY: signalling the stub's own process group.
            unsafe {
                libc::kill(-leader_pid, libc::SIGKILL);
            }
        }

        // Checked AFTER the call reaped/killed the group: an unready stub
        // would otherwise leak a 600 s sleeper.
        assert!(
            ready,
            "the stub must signal readiness (pidfile AND marker written, \
             grandchild holding the pipe) within {readiness:?} \
             (NODE_CHILD_WAIT_DEADLINE + NODE_WAIT_MARGIN_MS) before the deadline starts"
        );

        assert_eq!(
            result.err(),
            Some(ERR_NODE_WAIT_TIMEOUT),
            "the shell writes no stdout, so the deadline class is the plain timeout"
        );
        assert!(
            elapsed < ceiling,
            "deadline not enforced with a grandchild holding the pipe: call took \
             {elapsed:?}, ceiling {ceiling:?} (deadline + NODE_WAIT_POLL_INTERVAL + \
             injected drain budget + NODE_WAIT_MARGIN_MS)"
        );

        let grandchild = grandchild.expect("stub must record the background sleeper's pid");
        assert!(
            exited,
            "grandchild {grandchild} survived the deadline: the kill did not reach the \
             process group, only the leader"
        );
        let _ = std::fs::remove_file(&pidfile);
        let _ = std::fs::remove_file(&readyfile);
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_node_child_bounds_the_post_exit_drain() {
        // Round-2 correctness L2: the leader exits immediately, but a
        // grandchild left in its group holds stdout and stderr open. The
        // success path's reader joins used to be unbounded, so this row
        // would only return when the sleeper exits (600 s): RED is a HANG.
        // The RED run quoted in the review shortened the sleeper to 15 s
        // and ignored the injected budget (fixed 600 s recv): the call
        // returned after 15.01 s and this row failed its class + elapsed
        // assertions. With the bound, the call returns inside the injected
        // budget with the possibly-committed class, because the complete
        // body may be sitting unread in the reader's buffer.
        //
        // READINESS (host-speed fix): the stub records BOTH the leader's pid
        // and the grandchild's, and this row waits until the leader has EXITED
        // (a zombie answers `ps stat=` with `Z`) while the grandchild is still
        // running — the exact precondition the row names. The call previously
        // started its wait immediately, so under load the injected drain budget
        // could run while the leader was still starting, and the pidfile read
        // after the call panicked.
        let pidfile =
            std::env::temp_dir().join(format!("csq-node-drain-{}-group.pid", std::process::id()));
        let _ = std::fs::remove_file(&pidfile);
        let pidfile_arg = pidfile.to_string_lossy().into_owned();
        let child = spawn_unix_stub(&[
            "-c",
            r#"sleep 600 & printf '%s %s' "$$" "$!" > "$1""#,
            "sh",
            pidfile_arg.as_str(),
        ]);
        // The harness's own handle on the stub tree (see the group-kill row):
        // the child is a process-group leader, so this pid is the pgid of every
        // descendant it forks, recorded in the pidfile or not.
        let leader_pid = child.id() as libc::pid_t;

        let read_pids = || -> Option<(libc::pid_t, libc::pid_t)> {
            let text = std::fs::read_to_string(&pidfile).ok()?;
            let mut pids = text.split_whitespace();
            let leader: libc::pid_t = pids.next()?.parse().ok()?;
            let grandchild: libc::pid_t = pids.next()?.parse().ok()?;
            Some((leader, grandchild))
        };
        let readiness = spawn_readiness_budget();
        let ready = wait_until(readiness, || {
            read_pids().is_some_and(|(leader, grandchild)| {
                process_exited(leader) && process_exists(grandchild)
            })
        });

        let deadline = NODE_CHILD_WAIT_DEADLINE;
        let drain_budget = Duration::from_millis(200);
        let started = std::time::Instant::now();
        let result = wait_for_node_child_with_drain_budget(child, deadline, drain_budget);
        let elapsed = started.elapsed();

        // Cleanup BEFORE the assertions: the success path does not group-kill,
        // so on a GREEN run the sleeper is still alive and must not leak.
        let grandchild = read_pids().map(|(_, grandchild)| grandchild);
        if let Some(pid) = grandchild {
            // SAFETY: signalling our own recorded grandchild.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        // Same pidfile-independent cleanup as the group-kill row: the success
        // path does not group-kill, so probe the stub's process group (leader
        // pid = pgid) and kill it if a descendant survived. ESRCH means the
        // group is already empty and the id may be recycled; success means a
        // sleeper is still alive and cannot release the id before the kill.
        let group_probe = unsafe { libc::kill(-leader_pid, 0) };
        if group_probe == 0 {
            // SAFETY: signalling the stub's own process group.
            unsafe {
                libc::kill(-leader_pid, libc::SIGKILL);
            }
        }

        assert!(
            ready,
            "the stub must exit its leader with the grandchild still holding the pipes \
             within {readiness:?} (NODE_CHILD_WAIT_DEADLINE + NODE_WAIT_MARGIN_MS)"
        );
        assert_eq!(
            result.err(),
            Some(ERR_NODE_HTTP_OUTCOME_UNKNOWN),
            "a pipe held open by a descendant must bound the post-exit drain, and \
             an undrained stdout is a possibly-committed outcome, not a plain failure"
        );
        // Readiness established the leader's exit BEFORE the call, so the wait
        // deadline has nothing left to spend: the ceiling is the poll it does
        // not need plus the injected drain budget plus the named margin.
        let ceiling = bounded_call_ceiling(Duration::ZERO, drain_budget);
        assert!(
            elapsed < ceiling,
            "the post-exit drain must be bounded by the injected budget: took {elapsed:?}, \
             ceiling {ceiling:?} (NODE_WAIT_POLL_INTERVAL + injected drain budget + NODE_WAIT_MARGIN_MS)"
        );
        let _ = std::fs::remove_file(&pidfile);
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_node_child_preserves_nonzero_exit_for_the_caller_to_classify() {
        // The helper must not turn a non-zero exit into an Err: the
        // callers classify it through `node_failure_error`, exactly as
        // they did with `wait_with_output`. Stderr bytes stay verbatim
        // here; redaction happens in `node_failure_error`.
        let child = spawn_unix_stub(&["-c", "printf boom >&2; exit 3"]);
        let output = wait_for_node_child(child, NODE_CHILD_WAIT_DEADLINE)
            .expect("a non-zero exit is still a completed wait inside NODE_CHILD_WAIT_DEADLINE");
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stderr, b"boom");
    }

    // ── Total in-script request timer (round-2 M2) ──────────────

    #[test]
    fn every_node_script_builder_embeds_the_shared_total_request_timer() {
        // Round-2 M2: `https.request`'s `timeout` option is only a
        // socket-INACTIVITY guard, so a trickling response could outlive
        // the parent deadline. Every builder must carry the ONE shared
        // total-timer prelude, and every response-end handler must settle
        // it before writing stdout.
        //
        // Mutation proof: deleting the `{prelude}` interpolation from any
        // one builder fails the `contains` assertion for that builder.
        let literal = js_url_literal("https://example.com/").expect("encoding must succeed");
        let timer_line =
            "const __csqTimer = setTimeout(() => { req.destroy(); __csqFail('timeout'); }, 15000);";
        for (name, script) in [
            (
                "build_post_script",
                build_post_script(&literal, NODE_TIMEOUT_MS),
            ),
            (
                "build_post_with_date_script",
                build_post_with_date_script(&literal, NODE_TIMEOUT_MS),
            ),
            (
                "build_get_bearer_script",
                build_get_bearer_script(&literal, NODE_TIMEOUT_MS),
            ),
            (
                "build_get_bearer_with_retry_after_script",
                build_get_bearer_with_retry_after_script(&literal, NODE_TIMEOUT_MS),
            ),
        ] {
            assert!(
                script.contains(timer_line),
                "{name} must carry the TOTAL request timer (not only the \
                 inactivity guard): {script}"
            );
            assert!(
                script.contains("if (!__csqSettle()) return;"),
                "{name}'s response-end handler must settle the timer before \
                 writing stdout: {script}"
            );
            assert!(
                !script.contains("process.stderr.write('timeout'); process.exit(1); });"),
                "{name} must route the inactivity timeout through the shared \
                 __csqFail path, not a second ad hoc handler: {script}"
            );
        }
    }

    /// Semantic proof of the total timer: a response that TRICKLES bytes
    /// forever (never `end`s) keeps resetting the socket-INACTIVITY timer,
    /// so only a TOTAL timer can make the script report. The built script
    /// text is executed with only its transport module and URL swapped for
    /// a local plain-HTTP trickle server; the timer logic itself is the
    /// real prelude.
    ///
    /// RED without the total timer: the script never exits, the production
    /// parent deadline ([`NODE_CHILD_WAIT_DEADLINE`]) kills it,
    /// `wait_for_node_child` returns Err, and the `.expect` panics — a bounded
    /// red, no hang.
    #[cfg(unix)]
    #[test]
    fn total_request_timer_fires_on_a_trickling_response() {
        use std::io::Write as _;
        use std::os::unix::process::CommandExt as _;

        let runtime = find_js_runtime().expect("test host must have node or bun on PATH");
        let literal = js_url_literal("https://trickle.invalid/x").expect("encoding must succeed");
        let built = build_get_bearer_script(&literal, 300);
        let script = built
            .replace("require('https')", "require('http')")
            .replace(&literal, "globalThis.__CSQ_TEST_URL");
        let harness = format!(
            r#"
const __http = require('http');
const __srv = __http.createServer((req, res) => {{
  res.writeHead(200);
  res.write('x');
  const __t = setInterval(() => res.write('x'), 20);
  req.on('close', () => clearInterval(__t));
}});
__srv.listen(0, '127.0.0.1', () => {{
  globalThis.__CSQ_TEST_URL = 'http://127.0.0.1:' + __srv.address().port;
  {script}
}});
"#
        );
        let mut child = std::process::Command::new(&runtime)
            .arg("-e")
            .arg(&harness)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .expect("spawn must succeed");
        child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(br#"{"token":"t","extra":{}}"#)
            .expect("write to the script's stdin must succeed");

        let output = wait_for_node_child_with_drain_budget(
            child,
            NODE_CHILD_WAIT_DEADLINE,
            NODE_DRAIN_DEADLINE,
        )
        .expect(
            "the in-script TOTAL timer must make a trickling request exit before \
                     NODE_CHILD_WAIT_DEADLINE",
        );
        assert!(
            !output.status.success(),
            "the total-timer path must exit non-zero: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("timeout"),
            "the script's OWN timer diagnostic must be the outcome, got {stderr:?}"
        );
    }

    // ── Node.js script injection defenses ───────────────────
    //
    // `post_json_node`, `post_json_node_with_date`, and
    // `get_bearer_node` interpolate the caller-supplied URL into a
    // Node.js script string. These tests prove (1) the character
    // guard rejects every byte that could break out of a JS string
    // literal, (2) the guard does not over-reject legitimate URLs,
    // (3) the JSON-encoding escaping holds even for a URL that
    // reached it unfiltered, and (4) each public function actually
    // wires the guard in — before ever spawning a runtime, so no
    // live node/network is needed.

    #[test]
    fn url_has_unsafe_js_chars_rejects_injection_characters() {
        for bad in [
            "https://x.example/'",
            "https://x.example/\"",
            "https://x.example/`",
            "https://x.example/\\",
            "https://x.example/\r",
            "https://x.example/\n",
            "https://x.example/\u{0}",
            "https://x.example/\u{7f}",
        ] {
            assert!(
                url_has_unsafe_js_chars(bad),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn url_has_unsafe_js_chars_allows_legitimate_urls() {
        for good in [
            "https://api.example.com/v1/messages?foo=bar&baz=1",
            "https://example.com:8443/path%20with%20encoding",
            "https://xn--fsq.example.com/",
            "https://m\u{fc}nchen.example/path",
            "https://example.com/path?q=%E2%9C%93",
            // Bracketed IPv6 literal — `[` / `]` are >= 0x20 and not
            // rejected. Matters given csq's `[::1]` loopback history
            // (Anthropic OAuth retired IPv4 loopback callbacks).
            //
            // NOTE: userinfo (`user:pass@host`) is deliberately NOT in
            // this list — it is rejected specifically at the
            // `get_bearer_node` credential-bearing sink (LOW-2), not by
            // this shared character guard (`@`/`:` are still safe JS
            // string bytes and remain legitimate for the other two
            // transport functions). See `get_bearer_node_rejects_url_with_userinfo`.
            "https://[::1]:8443/x",
        ] {
            assert!(
                !url_has_unsafe_js_chars(good),
                "legitimate url wrongly rejected: {good:?}"
            );
        }
    }

    #[test]
    fn url_has_unsafe_js_chars_rejects_line_and_paragraph_separator() {
        // LOW-1: U+2028/U+2029 encode as three bytes each >= 0x80
        // (`E2 80 A8` / `E2 80 A9`), so the byte-oriented predecessor of
        // this function never observed them. Verify the char-level scan
        // now catches both.
        for bad in ["https://x.example/\u{2028}", "https://x.example/\u{2029}"] {
            assert!(
                url_has_unsafe_js_chars(bad),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn serde_json_does_not_escape_line_separator() {
        // NOTE (round-2 redteam NIT): unlike its neighbors in this test
        // group, this test pins a property of the `serde_json`
        // DEPENDENCY, not a property of csq's own code — it provides
        // zero mutation coverage of anything in this module. It exists
        // only to settle the open inference LOW-1's fix depends on: does
        // serde_json escape U+2028 by default? If it did, the
        // `js_url_literal` JSON-encoding step alone would already
        // neutralize it and the codepoint-level guard above would be
        // redundant (still correct, but its rationale would need
        // updating). It does not — the raw codepoint round-trips
        // unescaped, matching JS's own historical `JSON.stringify`
        // behavior (the reason U+2028/U+2029 were a pre-ES2019 "valid
        // JSON is not valid JavaScript" footgun). Read this test as
        // "pinned dependency behavior, re-check on a serde_json major
        // bump," not as a guard-regression test the way its neighbors
        // are.
        let encoded = serde_json::to_string("a\u{2028}b").unwrap();
        assert_eq!(encoded, "\"a\u{2028}b\"");
    }

    #[test]
    fn js_url_literal_round_trips_legitimate_urls() {
        // Proves the escaping path doesn't corrupt real-world URLs —
        // query strings, percent-encoding, non-default ports, and
        // unicode hostnames must survive JSON-encode then decode
        // byte-for-byte identical to the input.
        for good in [
            "https://api.example.com/v1/messages?foo=bar&baz=1",
            "https://example.com:8443/path%20with%20encoding",
            "https://xn--fsq.example.com/",
            "https://m\u{fc}nchen.example/path",
            "https://example.com/path?q=%E2%9C%93",
        ] {
            let literal = js_url_literal(good).expect("encoding must succeed");
            assert!(
                literal.starts_with('"') && literal.ends_with('"'),
                "literal must be a JSON string token: {literal}"
            );
            let round_tripped: String =
                serde_json::from_str(&literal).expect("literal must be valid JSON string");
            assert_eq!(round_tripped, good);
        }
    }

    #[test]
    fn js_url_literal_round_trips_a_quote_bearing_url() {
        // Renamed from `..._neutralizes_single_quote_breakout_attempt`
        // (redteam NIT, an internal ticket): this test asserts a property of
        // `serde_json`'s round-trip guarantee (any string round-trips
        // through its own JSON encoding), not a property specific to JS
        // safety — the name previously implied more than the assertion
        // proves. It IS still evidence for the escaping mechanism (a
        // single JSON string token has no unescaped way to terminate
        // early other than its own closing quote, so round-tripping to
        // the original value proves the embedded `'` never closed one),
        // just under an accurately-scoped name.
        let malicious = "https://evil.example/');require('child_process').execSync('id');//";
        let literal = js_url_literal(malicious).expect("encoding must succeed");

        // Round-2 redteam preference over a bare rename: assert the
        // EXACT bytes handed to node — a real assertion about output,
        // not merely a property of `serde_json` round-tripping its own
        // encoding.
        assert_eq!(
            literal,
            r#""https://evil.example/');require('child_process').execSync('id');//""#
        );

        let round_tripped: String =
            serde_json::from_str(&literal).expect("literal must be valid JSON string");
        assert_eq!(round_tripped, malicious);
    }

    #[test]
    fn post_json_node_rejects_url_with_single_quote() {
        // Must reject before ever spawning a runtime — no live node
        // or network needed to prove this.
        let result = post_json_node("https://evil.example/');process.exit(1);//", "{}");
        assert!(result.is_err(), "single-quote url must be rejected");
        assert_eq!(result.unwrap_err(), ERR_URL_UNSAFE_CHARS);
    }

    #[test]
    fn post_json_node_with_date_rejects_url_with_single_quote() {
        let result = post_json_node_with_date("https://evil.example/');process.exit(1);//", "{}");
        assert!(result.is_err(), "single-quote url must be rejected");
        assert_eq!(result.unwrap_err(), ERR_URL_UNSAFE_CHARS);
    }

    #[test]
    fn get_bearer_node_rejects_url_with_single_quote() {
        let result = get_bearer_node("https://evil.example/');process.exit(1);//", "tok", &[]);
        assert!(result.is_err(), "single-quote url must be rejected");
        assert_eq!(result.unwrap_err(), ERR_URL_UNSAFE_CHARS);
    }

    // ── LOW-2 / H1 / H2: userinfo credential-redirection defense ────

    #[test]
    fn reject_userinfo_fails_closed_on_a_url_it_cannot_parse() {
        // Regression test (H1, round-2 redteam followup). The previous
        // inline check in `get_bearer_node` was
        // `if let Ok(parsed) = url::Url::parse(url) { check }` with NO
        // `else` — a URL malformed enough that `url::Url::parse` itself
        // refuses it skipped the userinfo check ENTIRELY and (in the
        // original code) fell through to spawning node with the live
        // credential still attached. `reject_userinfo` now fails CLOSED:
        // any input `url::Url::parse` cannot parse is rejected outright.
        //
        // Mutation-proof note: reverting `reject_userinfo` to the old
        // `if let Ok(parsed) = url::Url::parse(url) { ... }` shape (no
        // `else`) makes this call implicitly return `Ok(())` for an
        // unparseable input — the assertion below would then fail.
        assert!(
            url::Url::parse("not-a-url-at-all").is_err(),
            "test premise: this string must be unparseable by the url crate \
             (no scheme separator, so RelativeUrlWithoutBase)"
        );
        assert_eq!(
            reject_userinfo("not-a-url-at-all"),
            Err(ERR_URL_UNPARSEABLE.to_string()),
            "an unparseable url must be rejected outright, not silently allowed through"
        );
    }

    #[test]
    fn reject_userinfo_allows_a_url_without_userinfo() {
        // Non-regression: a well-formed, userinfo-free URL must pass.
        assert_eq!(reject_userinfo("https://example.com/api"), Ok(()));
    }

    #[test]
    fn get_bearer_node_rejects_url_with_userinfo() {
        // A URL with userinfo reads as the trusted host on
        // operator-facing surfaces while the live bearer token is
        // actually sent wherever the host AFTER `@` resolves to.
        // Rejected before ever spawning a runtime — no live node or
        // network needed to prove this.
        let result = get_bearer_node(
            "https://cli-chat-proxy.grok.com@evil.example/v1",
            "tok",
            &[],
        );
        assert!(result.is_err(), "userinfo url must be rejected");
        assert!(
            result.unwrap_err().contains("userinfo"),
            "error must name userinfo as the rejection reason"
        );
    }

    #[test]
    fn get_bearer_node_allows_url_without_userinfo() {
        // Non-regression: the userinfo guard must not over-reject a
        // URL with no `@` at all (the common case). Assert
        // UNCONDITIONALLY on the error (round-2 redteam NIT): the prior
        // version of this test nested both assertions inside
        // `if let Err(e) = result`, so it silently asserted NOTHING
        // whenever the call happened to return `Ok` — e.g. on any host
        // whose DNS/CI network policy makes "evil.example" resolve.
        // `.err()` turns the check into an unconditional assertion on
        // every outcome: `None` (Ok) trivially passes both checks below,
        // `Some(msg)` must not be either guard's rejection string.
        let result = get_bearer_node("https://evil.example/oauth/usage", "tok", &[]);
        let err = result.err();
        assert_ne!(err.as_deref(), Some(ERR_URL_UNSAFE_CHARS));
        assert!(!err.as_deref().unwrap_or("").contains("userinfo"));
    }

    #[test]
    fn get_bearer_node_fails_closed_on_a_url_rust_cannot_parse() {
        // Live-node regression test, UPDATED for H1 (round-2 redteam
        // followup). Originally this test proved that when `Rust's url
        // crate rejects the URL AND Node's own `new URL(...)` ALSO
        // throws`, the `process.on('uncaughtException', ...)` guard in
        // `build_get_bearer_script` stops the password leaking via
        // Node's exception `input:` field (live-verified:
        // `TypeError: Invalid URL ... { input: 'https://user:hunter2@[' }`).
        //
        // H1 closes the gap this quadrant represented at the Rust layer
        // FIRST: `reject_userinfo` now fails closed on any URL it cannot
        // parse, so this exact input is rejected in Rust BEFORE node is
        // ever spawned — the `uncaughtException` handler this test used
        // to exercise is no longer reached for this input at all, which
        // is the stronger property H1 exists to provide. Still requires
        // a real node/bun on PATH via `get_bearer_node`'s downstream
        // guards in the general case; this specific assertion no longer
        // needs one (verified nothing was spawned by the absence of any
        // "node http failed" / "script_error" text in the error).
        let result = get_bearer_node("https://user:hunter2@[", "tok", &[]);
        assert!(result.is_err(), "malformed url must fail");
        let err = result.unwrap_err();
        assert!(
            !err.contains("hunter2"),
            "password must not leak into the returned error: {err}"
        );
        assert_eq!(
            err, ERR_URL_UNPARSEABLE,
            "must fail CLOSED in Rust (H1) before ever spawning node — a \
             \"node http failed: script_error\" value here would mean the \
             fail-closed guard was bypassed and node was spawned anyway: {err}"
        );
    }

    #[test]
    fn post_json_node_rejects_url_with_userinfo() {
        // H2: the userinfo guard originally covered `get_bearer_node`
        // alone. `post_json_node`'s stdin body is an OAuth
        // authorization-code / refresh-token exchange payload — a live
        // credential just as much as a bearer header.
        let result = post_json_node("https://trusted.example@evil.example/v1", "{}");
        assert!(result.is_err(), "userinfo url must be rejected");
        assert!(result.unwrap_err().contains("userinfo"));
    }

    #[test]
    fn post_json_node_with_date_rejects_url_with_userinfo() {
        let result = post_json_node_with_date("https://trusted.example@evil.example/v1", "{}");
        assert!(result.is_err(), "userinfo url must be rejected");
        assert!(result.unwrap_err().contains("userinfo"));
    }

    #[test]
    fn post_json_with_headers_rejects_url_with_userinfo() {
        // H2: `post_json_with_headers` is the production `HttpPostProbeFn`
        // behind the 3P usage probe (API key in headers) and the Gemini
        // Code Assist OAuth probe (bearer token in headers). reqwest
        // folds URL userinfo into a `Basic`-auth `Authorization` header
        // and connects to the host AFTER `@` — `https_only(true)` on the
        // shared client only checks the scheme, not the authority.
        let result = post_json_with_headers(
            "https://trusted.example@evil.example/v1",
            &[("x-api-key".to_string(), "secret".to_string())],
            "{}",
        );
        assert!(result.is_err(), "userinfo url must be rejected");
        assert!(result.unwrap_err().contains("userinfo"));
    }

    #[test]
    fn get_bearer_rejects_url_with_userinfo() {
        // A-M1 (round-7 redteam): `get_bearer` is the production reqwest
        // transport behind the M8.6 Anthropic usage poller — bearer token
        // via the `Authorization` header, byte-for-byte the same trust
        // shape `post_json_with_headers` was already guarded against. It
        // had no pre-flight userinfo check until this fix.
        let result = get_bearer(
            "https://trusted.example@evil.example/v1",
            "secret-token",
            &[],
        );
        assert!(result.is_err(), "userinfo url must be rejected");
        assert!(result.unwrap_err().contains("userinfo"));
    }

    #[test]
    fn post_json_with_headers_capped_rejects_url_with_userinfo() {
        // A-M1 (round-7 redteam): `post_json_with_headers_capped` is the
        // enterprise direct-API transport
        // (`ReqwestTransport::post`) — it carries the
        // caller's unwrapped 3P provider API key via `headers`, the exact
        // shape `post_json_with_headers` was guarded against; this capped
        // sibling shared the body but not the guard.
        let result = post_json_with_headers_capped(
            "https://trusted.example@evil.example/v1",
            &[("x-api-key".to_string(), "secret".to_string())],
            "{}",
            4096,
        );
        assert!(result.is_err(), "userinfo url must be rejected");
        assert!(result.unwrap_err().contains("userinfo"));
    }

    // ── NIT-2: script composition is untested — extracted + pinned ──

    #[test]
    fn build_post_script_consumes_json_literal_not_a_hand_quoted_url() {
        // Regression test for NIT-2 (round-2 redteam, code-review
        // lens): reverting `new URL({url_literal})` back to
        // `new URL('{url}')` in the script template — while leaving
        // both encoding helpers (`js_url_literal`, `url_has_unsafe_js_chars`)
        // and every existing guard test in place — previously passed
        // the full suite unnoticed, because nothing asserted on the
        // actual composition of the generated script text.
        let malicious = "https://evil.example/');require('child_process').execSync('id');//";
        let literal = js_url_literal(malicious).expect("encoding must succeed");
        let script = build_post_script(&literal, NODE_TIMEOUT_MS);
        assert!(
            script.contains(&format!("new URL({literal})")),
            "script must interpolate the JSON literal verbatim: {script}"
        );
        assert!(
            script.contains("new URL(\""),
            "sink must consume a JSON string literal (double-quoted), \
             not a hand-quoted url: {script}"
        );
        assert!(
            !script.contains(&format!("new URL('{malicious}')")),
            "script must not contain the hand-quoted single-quote form: {script}"
        );
    }

    #[test]
    fn build_post_with_date_script_consumes_json_literal_not_a_hand_quoted_url() {
        let malicious = "https://evil.example/');require('child_process').execSync('id');//";
        let literal = js_url_literal(malicious).expect("encoding must succeed");
        let script = build_post_with_date_script(&literal, NODE_TIMEOUT_MS);
        assert!(script.contains(&format!("new URL({literal})")));
        assert!(script.contains("new URL(\""));
    }

    #[test]
    fn build_get_bearer_script_consumes_json_literal_not_a_hand_quoted_url() {
        let malicious = "https://evil.example/');require('child_process').execSync('id');//";
        let literal = js_url_literal(malicious).expect("encoding must succeed");
        let script = build_get_bearer_script(&literal, NODE_TIMEOUT_MS);
        assert!(script.contains(&format!("new URL({literal})")));
        assert!(script.contains("new URL(\""));
    }

    #[test]
    fn build_post_script_composition_holds_for_a_line_separator_bearing_literal() {
        // Composition proof using a payload the char-guard specifically
        // exists to reject (U+2028) — even bypassing the guard entirely
        // (this test calls the pure script-builder directly, never
        // through `post_json_node`), the JSON-literal composition
        // still holds: the codepoint is embedded as content inside a
        // double-quoted string token, never breaking out into script
        // structure.
        let literal = js_url_literal("https://x.example/\u{2028}").expect("encoding must succeed");
        let script = build_post_script(&literal, NODE_TIMEOUT_MS);
        assert!(script.contains(&format!("new URL({literal})")));
    }

    #[test]
    fn all_three_script_builders_register_the_uncaught_exception_guard_first() {
        // Regression test for the LOW-2 follow-up: the guard must be
        // registered before ANY other statement (in particular, before
        // `new URL(...)`, which can throw synchronously) — a guard
        // registered later would miss exactly the exception it exists
        // to catch.
        let literal = js_url_literal("https://example.com/").expect("encoding must succeed");
        for script in [
            build_post_script(&literal, NODE_TIMEOUT_MS),
            build_post_with_date_script(&literal, NODE_TIMEOUT_MS),
            build_get_bearer_script(&literal, NODE_TIMEOUT_MS),
        ] {
            let guard_pos = script
                .find("process.on('uncaughtException'")
                .expect("script must register the uncaughtException guard");
            let url_ctor_pos = script
                .find("new URL(")
                .expect("script must construct the URL");
            assert!(
                guard_pos < url_ctor_pos,
                "uncaughtException guard must be registered before new URL(...): {script}"
            );
        }
    }

    // ── MED-1: single-JSON stdin payload, no in-band delimiter ──

    #[test]
    fn bearer_stdin_payload_desync_is_unrepresentable() {
        // Regression test for MED-1 (an internal ticket redteam). The OLD wire
        // format was `token\nextra_headers_json`, split on the first
        // `\n` inside the spawned script. `\n` is a legal byte in an
        // OAuth bearer token, so a token containing an embedded
        // `\n{"Authorization":"Bearer attacker"}` desynchronised that
        // split: the attacker-controlled second line became
        // `lines[1]`, parsed as the extra-headers object, and — spread
        // LAST into the script's headers literal — silently overrode
        // `Authorization`.
        //
        // This test proves the NEW single-JSON-object framing makes
        // that unrepresentable: `token` is a JSON *string value*, so
        // the embedded `\n` and JSON text are opaque escaped content
        // under the "token" key — there is no second top-level field
        // for a crafted value to desynchronise into.
        //
        // Mutation-proof note: this test exercises
        // `bearer_stdin_payload` directly (not `get_bearer_node`),
        // deliberately bypassing `get_bearer_node`'s own
        // defense-in-depth control-byte guard on `token` — it proves
        // the FRAMING itself is safe even if that guard were absent,
        // matching the reasoning `js_url_literal_round_trips_a_quote_bearing_url`
        // applies to the URL side.
        let attack_token = "real-token\n{\"Authorization\":\"Bearer attacker\"}";
        let payload_json =
            bearer_stdin_payload(attack_token, &[("Anthropic-Beta", "oauth-2025-04-20")])
                .expect("encoding must succeed");

        let parsed: serde_json::Value =
            serde_json::from_str(&payload_json).expect("payload must be valid JSON");
        assert_eq!(
            parsed.get("token").and_then(|v| v.as_str()),
            Some(attack_token),
            "token must round-trip verbatim as a single opaque string value"
        );

        let obj = parsed.as_object().expect("payload must be a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["extra", "token"],
            "payload must have exactly the two expected top-level keys — no \
             attacker-injected key leaked in from the token's content"
        );
        assert!(
            !obj.contains_key("Authorization"),
            "attacker-controlled token content must not surface as a sibling \
             top-level key"
        );
    }

    #[test]
    fn get_bearer_node_rejects_token_with_embedded_newline() {
        // Belt-and-braces guard (MED-1 fix): even though the JSON
        // framing above makes a `\n`-bearing token safe, get_bearer_node
        // rejects it outright before ever building the payload.
        let attack_token = "real-token\n{\"Authorization\":\"Bearer attacker\"}";
        let result = get_bearer_node("https://example.com/api/oauth/usage", attack_token, &[]);
        assert!(result.is_err(), "newline-bearing token must be rejected");
        assert_eq!(result.unwrap_err(), "token contains disallowed characters");
    }

    #[test]
    fn get_bearer_node_rejects_token_with_line_separator() {
        // Regression test (M4, round-2 redteam followup): the token
        // guard changed from a byte scan to a codepoint scan
        // (`token.chars()`) specifically to catch U+2028/U+2029 (each
        // encodes as three bytes individually >= 0x80, so a byte-oriented
        // scan never observes them), but the only guard test in place
        // (`get_bearer_node_rejects_token_with_embedded_newline`, above)
        // used pure ASCII — a revert back to a byte scan would still
        // pass the full suite. This asserts the actual codepoint the fix
        // exists to catch.
        let result = get_bearer_node("https://example.com/x", "tok\u{2028}en", &[]);
        assert!(
            result.is_err(),
            "line-separator-bearing token must be rejected"
        );
        assert_eq!(result.unwrap_err(), ERR_TOKEN_UNSAFE_CHARS);
    }

    #[test]
    fn get_bearer_node_rejects_token_with_c1_control_character() {
        // Regression test (L1, round-2 redteam followup). The token
        // guard's control-character class admitted U+0080-U+009F (the
        // C1 control range, including U+0085 NEL — the finding's named
        // example) before this fix: a token containing one of these
        // would corrupt the `Authorization` header the script builds
        // instead of being rejected pre-flight.
        let result = get_bearer_node("https://example.com/x", "tok\u{85}en", &[]);
        assert!(result.is_err(), "C1-control-bearing token must be rejected");
        assert_eq!(result.unwrap_err(), ERR_TOKEN_UNSAFE_CHARS);
    }

    // ── get_bearer_node_with_retry_after: pre-flight guards mirror
    // get_bearer_node's (see that function's tests above for the full
    // rationale on each) ────────────────────────────────────────────

    #[test]
    fn get_bearer_node_with_retry_after_rejects_url_with_userinfo() {
        let result = get_bearer_node_with_retry_after(
            "https://cli-chat-proxy.grok.com@evil.example/v1",
            "tok",
            &[],
        );
        assert!(result.is_err(), "userinfo url must be rejected");
        assert!(
            result.unwrap_err().contains("userinfo"),
            "error must name userinfo as the rejection reason"
        );
    }

    #[test]
    fn get_bearer_node_with_retry_after_rejects_token_with_embedded_newline() {
        let attack_token = "real-token\n{\"Authorization\":\"Bearer attacker\"}";
        let result = get_bearer_node_with_retry_after(
            "https://example.com/api/oauth/usage",
            attack_token,
            &[],
        );
        assert!(result.is_err(), "newline-bearing token must be rejected");
        assert_eq!(result.unwrap_err(), ERR_TOKEN_UNSAFE_CHARS);
    }

    #[test]
    fn get_bearer_node_with_retry_after_rejects_url_with_disallowed_chars() {
        let result = get_bearer_node_with_retry_after(
            "https://evil.example/');process.exit(1);//",
            "tok",
            &[],
        );
        assert!(result.is_err(), "single-quote url must be rejected");
        assert_eq!(result.unwrap_err(), ERR_URL_UNSAFE_CHARS);
    }

    /// The security-critical claim on
    /// [`get_bearer_node_with_retry_after`]'s doc is that the SCRIPT
    /// itself -- not a Rust-side check -- restricts the `retry-after`
    /// line to a validated digit run. Asserted directly on the generated
    /// script text (mirrors `build_get_bearer_script_spreads_extra_before_authorization`
    /// above, which pins a different composition property the same way):
    /// no live node or network needed to prove the regex is present and
    /// that a non-matching value is normalised to an EMPTY line rather
    /// than forwarded verbatim.
    #[test]
    fn build_get_bearer_with_retry_after_script_validates_header_as_digits_only() {
        let script =
            build_get_bearer_with_retry_after_script("\"https://example.com/\"", NODE_TIMEOUT_MS);
        assert!(
            script.contains(r"/^\d+$/.test(ra)"),
            "script must gate emission on a digits-only regex match: {script}"
        );
        assert!(
            script.contains(
                "const raLine = (typeof ra === 'string' && /^\\d+$/.test(ra)) ? ra : '';"
            ),
            "a non-matching (or absent) header must normalise to an EMPTY \
             string, never the raw header value, so the wire format's \
             two-newline framing cannot be desynchronised: {script}"
        );
        assert!(
            script.contains("process.stdout.write(res.statusCode + '\\n');")
                && script.contains("process.stdout.write(raLine + '\\n');")
                && script.contains("process.stdout.write(body);"),
            "wire format must be status-line, then retry-after-line, then \
             body, in that order: {script}"
        );
    }

    #[test]
    fn build_get_bearer_script_spreads_extra_before_authorization() {
        // Regression test (M5, round-2 redteam followup). JS object
        // literals: later keys win over earlier ones at the same key
        // name. `extra` MUST be spread FIRST so the fixed,
        // later-declared `'Authorization'` / `'Accept'` keys always win
        // — a caller-supplied `extra_headers` entry named "Authorization"
        // must not be able to override the live bearer token. This was
        // correct in the script template but unpinned: reverting to
        // `{'Authorization': ..., ...extra}` (spread LAST, letting extra
        // win) previously passed the full suite unnoticed.
        let script = build_get_bearer_script("\"https://example.com/\"", NODE_TIMEOUT_MS);
        assert!(
            script.contains("{...extra, 'Authorization':"),
            "extra headers must be spread BEFORE 'Authorization' so the fixed \
             key always wins: {script}"
        );
    }

    // ── MED-2: node stderr routed through redact_tokens ─────────

    #[test]
    fn node_failure_error_redacts_token_echoed_by_node_stderr() {
        // Regression test for MED-2 (an internal ticket redteam). Exercises the
        // ACTUAL shared function all three Node-transport call sites
        // use (`node_failure_error`), not `redact_tokens` in isolation
        // — a mutation that reverts `node_failure_error` to skip
        // redaction fails this test, whereas a test against
        // `redact_tokens` alone would not catch that regression.
        //
        // Live-verified inline: `node -e 'try{JSON.parse("sk-ant-oat01-SECRET")}
        // catch(e){console.log(e.message)}'` prints
        // `Unexpected token 's', "sk-ant-oat01-SECRET" is not valid JSON` —
        // V8 embeds a prefix of the unparseable input verbatim in the
        // thrown SyntaxError, confirming a malformed stdin payload
        // really can echo token bytes into stderr. This test proves
        // that path is closed at the point where the caller-facing
        // error string is built.
        let stderr_with_secret =
            b"SyntaxError: Unexpected token, \"sk-ant-oat01-LEAKED\" is not valid JSON";
        let msg = node_failure_error(stderr_with_secret);
        assert!(
            msg.starts_with("node http failed: "),
            "message shape must be preserved: {msg}"
        );
        assert!(
            !msg.contains("sk-ant-oat01-LEAKED"),
            "node_failure_error must strip the token-shaped secret: {msg}"
        );
    }

    // ── MED-3: url-guard rejection reachability (Grok, MiniMax) ─

    #[test]
    fn grok_billing_url_survives_the_unsafe_js_chars_guard() {
        // Pins the MED-3 reachability claim: GROK_CLI_CHAT_PROXY_BASE_URL
        // is operator-supplied and feeds directly into get_bearer_node
        // via grok::billing_url(). A legitimate override must never trip
        // the char guard — if it did, the daemon would log the new
        // MED-3 `url_rejected_unsafe_js_chars` WARN forever and Grok
        // quota polling would silently stop.
        let _env_guard = crate::platform::test_env::lock();
        let prev = std::env::var_os("GROK_CLI_CHAT_PROXY_BASE_URL");
        std::env::set_var(
            "GROK_CLI_CHAT_PROXY_BASE_URL",
            "https://cli-chat-proxy.grok.com/v1",
        );

        let url = crate::daemon::usage_poller::grok::billing_url();
        assert!(
            !url_has_unsafe_js_chars(&url),
            "grok billing_url() must survive the js-injection char guard: {url:?}"
        );

        match prev {
            Some(v) => std::env::set_var("GROK_CLI_CHAT_PROXY_BASE_URL", v),
            None => std::env::remove_var("GROK_CLI_CHAT_PROXY_BASE_URL"),
        }
    }

    #[test]
    fn post_json_node_rejects_url_with_backtick() {
        // Backtick opens a JS template literal — a distinct breakout
        // vector from the single-quote string literal used here, so
        // cover it explicitly rather than relying on the single-quote
        // test alone.
        let result = post_json_node("https://evil.example/`+process.exit(1)+`", "{}");
        assert!(result.is_err(), "backtick url must be rejected");
        assert_eq!(result.unwrap_err(), ERR_URL_UNSAFE_CHARS);
    }
}
