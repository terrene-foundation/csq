//! Blocking HTTP client for CLI-path operations (token refresh, key validation).
//!
//! Uses `reqwest::blocking` with `rustls-tls-webpki-roots` so we avoid
//! native OpenSSL linkage and system cert-store dependencies. The daemon
//! (M8.2+) will use the async `reqwest::Client` through the same transport
//! contracts.
//!
//! # Transport contracts
//!
//! Two closure signatures are exposed:
//!
//! - [`post_form`] — `(url, body) -> Result<Vec<u8>, String>` matches
//!   `credentials::refresh::refresh_token`'s `http_post` parameter. Used
//!   for `grant_type=refresh_token` form posts to the Anthropic OAuth
//!   endpoint.
//! - [`post_json_probe`] — `(url, headers, body) -> Result<(u16, String),
//!   String>` matches `providers::validate::validate_key`'s `http_post`
//!   parameter. Used for `max_tokens=1` validation probes against
//!   provider endpoints.
//!
//! # Security
//!
//! - HTTPS only (`https_only(true)`). A `http://` URL will be rejected
//!   by reqwest at request time.
//! - 10-second default timeout. OAuth token exchange is well under 1s
//!   in practice; 10s covers slow CI and retries.
//! - Max 2 redirects. Anthropic/3P APIs never redirect; 2 is generous.
//! - `User-Agent: csq/{version}` so requests are attributable.
//! - Errors are stringified and returned as `Err(String)` — we never
//!   leak the request body (which contains the refresh token) into
//!   error messages. The caller sees only a sanitized reason.

use std::sync::OnceLock;
use std::time::Duration;

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
        let ua = format!("csq/{}", env!("CARGO_PKG_VERSION"));
        reqwest::blocking::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .https_only(true)
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

    let bytes = response.bytes().map_err(sanitize_err)?;
    Ok(bytes.to_vec())
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

    let bytes = response.bytes().map_err(sanitize_err)?;
    Ok(bytes.to_vec())
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
    let text = response.text().map_err(sanitize_err)?;
    Ok((status, text))
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
/// # Errors
///
/// Returns `Err(String)` on connection failure, timeout, HTTPS
/// rejection, or redirect overflow. A 4xx/5xx response is returned
/// as `Ok(...)` so the caller can inspect both headers and status.
pub fn post_json_with_headers(
    url: &str,
    headers: &[(String, String)],
    body: &str,
) -> Result<(u16, std::collections::HashMap<String, String>, String), String> {
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
    let text = response.text().map_err(sanitize_err)?;
    Ok((status, resp_headers, text))
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
///
/// # Errors
///
/// Returns `Err(String)` on connection failure, timeout, HTTPS
/// rejection, or redirect overflow. A 4xx/5xx response is
/// returned as `Ok((status, bytes))` so the caller can classify.
pub fn get_bearer(
    url: &str,
    token: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), String> {
    let mut req = client()
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json");
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let response = req.send().map_err(sanitize_err)?;
    let status = response.status().as_u16();
    let bytes = response.bytes().map_err(sanitize_err)?;
    Ok((status, bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let result = get_bearer(
            "https://192.0.2.1/api/oauth/usage",
            "sk-ant-oat01-SECRET-TOKEN",
            &[("Anthropic-Beta", "oauth-2025-04-20")],
        );
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            !msg.contains("SECRET-TOKEN"),
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
}
