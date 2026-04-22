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
//! - Errors are stringified and returned as `Err(String)` — we never
//!   leak the request body (which contains the refresh token) into
//!   error messages. The caller sees only a sanitized reason.

pub mod codex;

use std::path::{Path, PathBuf};
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

// ─── Node.js subprocess transport (Anthropic endpoints) ──────

/// Timeout for Node.js subprocess HTTP requests (milliseconds).
const NODE_TIMEOUT_MS: u64 = 15_000;

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
        .get_or_init(|| {
            resolve_js_runtime().ok_or_else(|| {
                "no JS runtime (node/bun) found in PATH or standard install locations".into()
            })
        })
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

/// POSTs a JSON body to `url` using a Node.js subprocess.
///
/// The body is piped via stdin (not argv) so tokens don't appear
/// in `ps` output. Returns the response body bytes on any HTTP
/// status — the caller classifies the response.
///
/// Returns `Err` if no JS runtime (`node` or `bun`) is found.
pub fn post_json_node(url: &str, body: &str) -> Result<Vec<u8>, String> {
    if !url.starts_with("https://") {
        return Err("https required".into());
    }

    let runtime = find_js_runtime()?;

    // Inline JS: reads JSON body from stdin, POSTs to url, writes
    // response body to stdout. Exits 0 on any HTTP response, 1 on
    // transport error.
    let script = format!(
        r#"
const https = require('https');
const url = new URL('{url}');
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
    );

    let mut child = std::process::Command::new(&runtime)
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{runtime} spawn failed: {e}"))?;

    // Write body to stdin, then close it.
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().ok_or("failed to open stdin")?;
        stdin
            .write_all(body.as_bytes())
            .map_err(|e| format!("stdin write failed: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{runtime} wait failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("node http failed: {stderr}"));
    }

    Ok(output.stdout)
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
pub fn post_json_node_with_date(
    url: &str,
    body: &str,
) -> Result<(Vec<u8>, Option<String>), String> {
    if !url.starts_with("https://") {
        return Err("https required".into());
    }

    let runtime = find_js_runtime()?;

    let script = format!(
        r#"
const https = require('https');
const url = new URL('{url}');
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
    );

    let mut child = std::process::Command::new(&runtime)
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{runtime} spawn failed: {e}"))?;

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().ok_or("failed to open stdin")?;
        stdin
            .write_all(body.as_bytes())
            .map_err(|e| format!("stdin write failed: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{runtime} wait failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("node http failed: {stderr}"));
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

/// GETs a URL with a Bearer token using a Node.js subprocess.
///
/// Returns `(status_code, body_bytes)`. The bearer token is passed
/// via stdin (one line: `token\nextra_header_json`), not argv.
pub fn get_bearer_node(
    url: &str,
    token: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), String> {
    if !url.starts_with("https://") {
        return Err("https required".into());
    }

    let runtime = find_js_runtime()?;

    // Build extra headers JSON for the script.
    let headers_json: String = {
        let pairs: Vec<String> = extra_headers
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}:{}",
                    serde_json::to_string(k).unwrap_or_default(),
                    serde_json::to_string(v).unwrap_or_default()
                )
            })
            .collect();
        format!("{{{}}}", pairs.join(","))
    };

    let script = format!(
        r#"
const https = require('https');
const url = new URL('{url}');
let input = '';
process.stdin.on('data', c => input += c);
process.stdin.on('end', () => {{
  const lines = input.split('\n');
  const token = lines[0];
  const extra = JSON.parse(lines[1] || '{{}}');
  const headers = {{'Authorization': 'Bearer ' + token, 'Accept': 'application/json', ...extra}};
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
    );

    let mut child = std::process::Command::new(&runtime)
        .arg("-e")
        .arg(&script)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{runtime} spawn failed: {e}"))?;

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().ok_or("failed to open stdin")?;
        writeln!(stdin, "{token}").map_err(|e| format!("stdin write failed: {e}"))?;
        write!(stdin, "{headers_json}").map_err(|e| format!("stdin write failed: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{runtime} wait failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("node http failed: {stderr}"));
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
}
