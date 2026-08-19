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
//!   a JSON-encoded string literal ([`js_url_literal`]), guarded by a
//!   codepoint allowlist ([`url_has_unsafe_js_chars`]) that rejects
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
//!   is separately closed by [`build_get_bearer_script`]'s
//!   `uncaughtException` guard, at the script layer, not by
//!   `redact_tokens`).

pub mod codex;

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
/// See [`reject_userinfo`].
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
    let text = response.text().map_err(sanitize_err)?;
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
/// (round-7 redteam A-M1 — see [`reject_userinfo`]). This is the
/// production transport behind the phase2b direct-API moat
/// (`phase2b/clients.rs::ReqwestTransport::post`), which carries the
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
    limited.read_to_end(&mut buf).map_err(|e| {
        // std::io::Error — convert without leaking URL or body.
        format!("response read error: {e}")
    })?;

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
///   (round-7 redteam A-M1 — see [`reject_userinfo`]). reqwest folds URL
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
    let bytes = response.bytes().map_err(sanitize_err)?;
    Ok((status, bytes.to_vec()))
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
    let bytes = response.bytes().map_err(sanitize_err)?;
    Ok(bytes.to_vec())
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
    let bytes = response.bytes().map_err(sanitize_err)?;
    Ok((status, resp_headers, bytes.to_vec()))
}

// ─── Node.js subprocess transport (Anthropic endpoints) ──────

/// Timeout for Node.js subprocess HTTP requests (milliseconds).
const NODE_TIMEOUT_MS: u64 = 15_000;

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
/// [`post_json_with_headers_capped`] (the phase2b direct-API moat
/// transport, `phase2b/clients.rs::ReqwestTransport::post` — carries the
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
/// [`find_js_runtime`] for hot paths.
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
/// Single shared function — used by all three Node-transport
/// functions in this module — so a future new call site inherits the
/// redaction by construction rather than needing to remember to add it
/// (the `security.md` §5a "named-list drift" failure mode, applied to
/// this module's error formatting).
fn node_failure_error(stderr: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    format!("node http failed: {}", crate::error::redact_tokens(&stderr))
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
fn write_stdin_or_reap(child: &mut std::process::Child, payload: &[u8]) -> Result<(), String> {
    use std::io::Write;
    match child.stdin.as_mut() {
        Some(stdin) => match stdin.write_all(payload) {
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
            // So fall through to the caller's `wait_with_output()`, which reaps
            // the child (nothing leaks — that is the same call the success path
            // relies on) and returns the child's own message. All three
            // production call sites invoke it immediately after this function.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(format!("stdin write failed: {e}"))
            }
        },
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Err("failed to open stdin".to_string())
        }
    }
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
fn build_post_script(url_literal: &str) -> String {
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
    timeout: {NODE_TIMEOUT_MS}
  }}, res => {{
    let data = [];
    res.on('data', c => data.push(c));
    res.on('end', () => process.stdout.write(Buffer.concat(data)));
  }});
  req.on('timeout', () => {{ req.destroy(); process.stderr.write('timeout'); process.exit(1); }});
  req.on('error', e => {{ process.stderr.write(e.message); process.exit(1); }});
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
/// just as much as a bearer header). See [`reject_userinfo`].
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
    let script = build_post_script(&url_literal);

    let mut child = std::process::Command::new(&runtime)
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{runtime} spawn failed: {e}"))?;

    // Write body to stdin, then close it.
    write_stdin_or_reap(&mut child, body.as_bytes())?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{runtime} wait failed: {e}"))?;

    if !output.status.success() {
        return Err(node_failure_error(&output.stderr));
    }

    Ok(output.stdout)
}

/// Builds the Node.js script body for [`post_json_node_with_date`].
///
/// See [`build_post_script`] for the composition-test rationale (NIT-2)
/// and the `process.on('uncaughtException', ...)` guard this script
/// shares (LOW-2 follow-up).
fn build_post_with_date_script(url_literal: &str) -> String {
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
    timeout: {NODE_TIMEOUT_MS}
  }}, res => {{
    const dateHeader = res.headers['date'] || '';
    let data = [];
    res.on('data', c => data.push(c));
    res.on('end', () => {{
      // First line: Date header value (empty if absent). Then body.
      process.stdout.write(dateHeader + '\n');
      process.stdout.write(Buffer.concat(data));
    }});
  }});
  req.on('timeout', () => {{ req.destroy(); process.stderr.write('timeout'); process.exit(1); }});
  req.on('error', e => {{ process.stderr.write(e.message); process.exit(1); }});
  req.write(body);
  req.end();
}});
"#
    )
}

/// POSTs a JSON body to `url` using a Node.js subprocess and also
/// captures the response `Date` header.
///
/// Behaves identically to [`post_json_node`] (HTTPS-only, body-via-
/// stdin, returns body bytes on any HTTP status) but additionally
/// returns the `Date` response header as `Option<String>` for
/// callers that need server clock-skew detection (PR-C4 INV-P01:
/// daemon Codex refresher emits `clock_skew_detected` when local
/// time differs from server `Date` by > 5 min).
///
/// Wire format on stdout:
///
/// - First line: server `Date` header value (empty line if absent).
/// - Remaining bytes: response body, byte-for-byte identical to what
///   [`post_json_node`] returns.
///
/// Splitting on the first `\n` keeps body bytes lossless even if the
/// body itself contains newlines (JSON-pretty-printed responses).
///
/// `url` is rejected outright if it carries userinfo or fails to parse
/// (round-2 redteam H2 — same rationale as [`post_json_node`], this
/// function's stdin body is also a live-credential-bearing OAuth exchange
/// payload). See [`reject_userinfo`].
pub fn post_json_node_with_date(
    url: &str,
    body: &str,
) -> Result<(Vec<u8>, Option<String>), String> {
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
    let script = build_post_with_date_script(&url_literal);

    let mut child = std::process::Command::new(&runtime)
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{runtime} spawn failed: {e}"))?;

    write_stdin_or_reap(&mut child, body.as_bytes())?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{runtime} wait failed: {e}"))?;

    if !output.status.success() {
        return Err(node_failure_error(&output.stderr));
    }

    let stdout = output.stdout;
    let newline_pos = stdout
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("missing date line in node output")?;
    let date_str = std::str::from_utf8(&stdout[..newline_pos])
        .map_err(|_| "invalid date line")?
        .to_string();
    let date = if date_str.is_empty() {
        None
    } else {
        Some(date_str)
    };
    let body = stdout[newline_pos + 1..].to_vec();
    Ok((body, date))
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
    let encoded = serde_json::to_string(&payload).map_err(|_| ERR_ENCODE_FAILED.to_string())?;
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
fn build_get_bearer_script(url_literal: &str) -> String {
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
    timeout: {NODE_TIMEOUT_MS}
  }}, res => {{
    let data = [];
    res.on('data', c => data.push(c));
    res.on('end', () => {{
      const body = Buffer.concat(data);
      // First line of stdout: status code. Rest: body.
      process.stdout.write(res.statusCode + '\n');
      process.stdout.write(body);
    }});
  }});
  req.on('timeout', () => {{ req.destroy(); process.stderr.write('timeout'); process.exit(1); }});
  req.on('error', e => {{ process.stderr.write(e.message); process.exit(1); }});
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
    let script = build_get_bearer_script(&url_literal);

    let mut child = std::process::Command::new(&runtime)
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{runtime} spawn failed: {e}"))?;

    write_stdin_or_reap(&mut child, payload_json.as_bytes())?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{runtime} wait failed: {e}"))?;

    if !output.status.success() {
        return Err(node_failure_error(&output.stderr));
    }

    let stdout = output.stdout;
    let newline_pos = stdout
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("missing status line in node output")?;
    let status_str =
        std::str::from_utf8(&stdout[..newline_pos]).map_err(|_| "invalid status line")?;
    let status: u16 = status_str
        .parse()
        .map_err(|_| format!("invalid status code: {status_str}"))?;
    let body = stdout[newline_pos + 1..].to_vec();

    Ok((status, body))
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

    // ── LOW: zombie process on stdin-write failure ──────────────

    #[test]
    fn write_stdin_or_reap_reaps_the_child_on_write_failure() {
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
        // `write_stdin_or_reap` now returns `Ok(())` on EPIPE so the caller's
        // `wait_with_output()` reaps the child and surfaces its own diagnostic.
        // What this test pins is therefore the CONTRACT, in both directions:
        //   - EPIPE          → `Ok(())`, and the child is still reapable by the
        //                      caller (`try_wait` must not error).
        //   - missing stdin  → `Err`, and reaped HERE (nothing downstream will).
        let runtime = find_js_runtime().expect("test host must have node or bun on PATH");
        let mut child = std::process::Command::new(&runtime)
            .arg("-e")
            .arg("process.exit(0);")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn must succeed");

        // Give the child time to actually exit and close its stdin fd.
        std::thread::sleep(std::time::Duration::from_millis(300));

        let result = write_stdin_or_reap(&mut child, b"payload after child already exited");
        assert!(
            result.is_ok(),
            "EPIPE must fall through so the caller's wait_with_output() can \
             surface the child's OWN stderr; got {result:?}"
        );

        // The child must still be reapable by the caller — `wait_with_output`
        // is what every production call site does next, and it is what closes
        // the zombie window on this path.
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

        let result2 = write_stdin_or_reap(&mut child2, b"payload");
        assert!(
            result2
                .as_ref()
                .is_err_and(|e| e.contains("failed to open stdin")),
            "a missing stdin handle must be the missing-handle error variant: {result2:?}"
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
        // phase2b direct-API moat transport
        // (`phase2b/clients.rs::ReqwestTransport::post`) — it carries the
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
        let script = build_post_script(&literal);
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
        let script = build_post_with_date_script(&literal);
        assert!(script.contains(&format!("new URL({literal})")));
        assert!(script.contains("new URL(\""));
    }

    #[test]
    fn build_get_bearer_script_consumes_json_literal_not_a_hand_quoted_url() {
        let malicious = "https://evil.example/');require('child_process').execSync('id');//";
        let literal = js_url_literal(malicious).expect("encoding must succeed");
        let script = build_get_bearer_script(&literal);
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
        let script = build_post_script(&literal);
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
            build_post_script(&literal),
            build_post_with_date_script(&literal),
            build_get_bearer_script(&literal),
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
        let script = build_get_bearer_script("\"https://example.com/\"");
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
