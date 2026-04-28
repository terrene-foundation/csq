//! Single-shot ephemeral loopback HTTP listener for OAuth callbacks.
//!
//! # Why hand-rolled
//!
//! csq's daemon already uses axum for its UDS API; layering axum
//! here would buy nothing (one path, one method, single accept) and
//! cost a Router + Service + State scaffold. This module is ~150 lines
//! of `tokio::net::TcpListener` + a minimal HTTP/1.1 request-line
//! parser. The parser only understands the `<METHOD> <TARGET>
//! HTTP/1.1\r\n` shape, which is exactly what every browser sends to
//! a localhost callback.
//!
//! # Flow
//!
//! 1. [`LoopbackListener::bind`] opens `127.0.0.1:0` (OS-assigned
//!    port). The port is read off the bound socket and stored on the
//!    listener so the caller can include it in the OAuth `redirect_uri`
//!    query parameter.
//! 2. [`LoopbackListener::accept_one`] enters the accept loop.
//!    - Path other than `/callback`            → `404 Not Found`,
//!      keep listening.
//!    - Method other than `GET`                → `405 Method Not Allowed`,
//!      keep listening.
//!    - Missing `code` or `state` parameter    → `400 Bad Request`,
//!      keep listening.
//!    - Oversized request                      → drop the connection,
//!      keep listening.
//!    - Valid `?code=…&state=…`                → `302` redirect to the
//!      hosted Anthropic success page, then close the listener and
//!      return [`CallbackParams`].
//! 3. The future is cancellation-safe: dropping it (e.g., via
//!    `tokio::select!`) closes the bound socket and aborts any
//!    in-flight request.
//!
//! # Security
//!
//! - **IPv4 loopback only**. Binding `0.0.0.0` would expose the
//!   listener to the LAN; binding `[::1]` is fragile on hosts with
//!   IPv6 disabled or with a divergent IPv4/IPv6 routing table for
//!   `localhost`. Browsers always resolve `127.0.0.1` literally.
//! - **Body cap**: any request whose total bytes (request line +
//!   headers + body, up to the first `\r\n\r\n`) exceed 8 KiB is
//!   dropped before parsing. Defense against accidental gigabyte POSTs
//!   from a malicious tab.
//! - **Single-shot**: after the first valid `?code&state` capture,
//!   the listener is dropped and its port is released. A second
//!   connection attempt on the same port immediately gets
//!   "connection refused".
//! - **Plaintext is intentional**. Loopback HTTPS would require a
//!   self-signed cert + browser trust prompt; loopback HTTP is what
//!   `claude auth login` itself uses. The traffic never leaves the
//!   host.

use crate::error::OAuthError;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Hosted success page Anthropic serves once the user authorizes.
/// Mirrors what `claude auth login` redirects to so the browser tab
/// shows the same success UI users already recognise.
pub const SUCCESS_REDIRECT_URL: &str =
    "https://platform.claude.com/oauth/code/success?app=claude-code";

/// Maximum total bytes we will read from a single connection before
/// the headers terminator (`\r\n\r\n`). Anything larger is treated as
/// adversarial and the connection is dropped without parsing.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Per-connection idle read deadline. A browser request fits in one
/// MSS-sized burst; any peer that hasn't finished sending headers in
/// 5 s is parked or hostile and we close on it.
const PER_CONN_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Captured callback parameters after a successful single-shot accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackParams {
    /// The OAuth `code` query parameter, percent-decoded.
    pub code: String,
    /// The OAuth `state` query parameter, percent-decoded.
    pub state: String,
}

/// A bound, idle TCP listener on `127.0.0.1:<port>` waiting for the
/// browser's OAuth redirect.
pub struct LoopbackListener {
    listener: TcpListener,
    /// The kernel-assigned local port. Stored separately so the
    /// caller can read it without touching the listener.
    pub port: u16,
}

impl LoopbackListener {
    /// Binds `127.0.0.1` with an OS-assigned port and returns the
    /// idle listener. The port is available via [`Self::port`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::Exchange`] (with a sanitised message,
    /// no token material is available at bind time) if the kernel
    /// refuses to bind a loopback socket — typically because a
    /// hardened sandbox forbids it.
    pub async fn bind() -> Result<Self, OAuthError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
            // Bind errors carry no token material — formatting them
            // verbatim is safe and gives the user an actionable
            // reason ("permission denied", "address already in use").
            OAuthError::Exchange(format!("loopback bind failed: {e}"))
        })?;
        let port = listener
            .local_addr()
            .map_err(|e| OAuthError::Exchange(format!("loopback addr failed: {e}")))?
            .port();
        Ok(Self { listener, port })
    }

    /// Waits for one valid `GET /callback?code=…&state=…` request,
    /// redirects the browser to the hosted success page, closes the
    /// listener, and returns the captured parameters.
    ///
    /// Invalid requests (wrong path, wrong method, missing fields,
    /// oversize) are answered with the appropriate HTTP status and
    /// the accept loop continues. The future only resolves on a
    /// VALID capture or on a fatal accept error.
    ///
    /// Cancellation is safe: dropping the returned future closes the
    /// listener.
    pub async fn accept_one(self) -> Result<CallbackParams, OAuthError> {
        let LoopbackListener { listener, .. } = self;
        loop {
            let (stream, _peer) = listener.accept().await.map_err(|e| {
                OAuthError::Exchange(format!("loopback accept failed: {e}"))
            })?;
            match handle_connection(stream).await {
                ConnectionOutcome::Captured(params) => return Ok(params),
                ConnectionOutcome::Continue => continue,
            }
        }
    }
}

/// Result of a single connection. Either we captured the OAuth
/// callback (and the listener should close) or we answered the
/// browser and want to keep listening.
enum ConnectionOutcome {
    Captured(CallbackParams),
    Continue,
}

/// Consumes one connection. Reads the request, validates path /
/// method / query, sends the appropriate response, returns whether
/// the listener should close.
///
/// Errors here are deliberately swallowed (logged at trace level
/// only): a misbehaving browser shouldn't kill the listener while
/// the user might still complete the OAuth flow on a sibling tab.
async fn handle_connection(mut stream: TcpStream) -> ConnectionOutcome {
    let request_bytes = match read_request_head(&mut stream).await {
        Some(b) => b,
        None => return ConnectionOutcome::Continue,
    };

    let head_str = match std::str::from_utf8(&request_bytes) {
        Ok(s) => s,
        Err(_) => {
            let _ = write_response(&mut stream, 400, "Bad Request", "").await;
            return ConnectionOutcome::Continue;
        }
    };

    let request_line = head_str.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method != "GET" {
        let _ = write_response(&mut stream, 405, "Method Not Allowed", "").await;
        return ConnectionOutcome::Continue;
    }

    let (path, query) = split_path_and_query(target);
    if path != "/callback" {
        let _ = write_response(&mut stream, 404, "Not Found", "").await;
        return ConnectionOutcome::Continue;
    }

    let params = parse_query(query);
    let code = match params.iter().find(|(k, _)| k == "code") {
        Some((_, v)) if !v.is_empty() => v.clone(),
        _ => {
            let _ = write_response(&mut stream, 400, "Bad Request", "missing code").await;
            return ConnectionOutcome::Continue;
        }
    };
    let state = match params.iter().find(|(k, _)| k == "state") {
        Some((_, v)) if !v.is_empty() => v.clone(),
        _ => {
            let _ = write_response(&mut stream, 400, "Bad Request", "missing state").await;
            return ConnectionOutcome::Continue;
        }
    };

    // Browser redirect to the hosted success page so the user sees
    // the same "you can close this tab" UI as the CC reference flow.
    let _ = write_redirect(&mut stream, SUCCESS_REDIRECT_URL).await;

    ConnectionOutcome::Captured(CallbackParams { code, state })
}

/// Reads bytes from the stream until `\r\n\r\n` appears, capping at
/// [`MAX_REQUEST_BYTES`]. Returns `None` if the connection closes
/// early, exceeds the cap, or stalls past [`PER_CONN_READ_TIMEOUT`].
async fn read_request_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read_fut = stream.read(&mut chunk);
        let n = match tokio::time::timeout(PER_CONN_READ_TIMEOUT, read_fut).await {
            Ok(Ok(0)) => return None, // peer closed
            Ok(Ok(n)) => n,
            Ok(Err(_)) => return None,
            Err(_) => return None, // timeout
        };
        if buf.len() + n > MAX_REQUEST_BYTES {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(buf);
        }
    }
}

/// Splits `<path>?<query>` into `(path, query)`. If there's no `?`,
/// `query` is empty.
fn split_path_and_query(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    }
}

/// Parses an `application/x-www-form-urlencoded` query string into
/// `(key, value)` pairs with each value percent-decoded.
fn parse_query(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let v = urlencoding::decode(v)
                .map(|cow| cow.into_owned())
                .unwrap_or_else(|_| v.to_string());
            let k = urlencoding::decode(k)
                .map(|cow| cow.into_owned())
                .unwrap_or_else(|_| k.to_string());
            (k, v)
        })
        .collect()
}

/// Writes a minimal HTTP/1.1 response with `Connection: close`.
async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let body_bytes = body.as_bytes();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body_bytes.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body_bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Writes an HTTP 302 redirect. The `location` is trusted (we own
/// it as a constant) so no header-injection sanitisation is needed —
/// but the request line / header parser at the top of this module
/// does still reject any `\r` or `\n` in the captured query
/// parameters via the URL-decoding step (those characters cannot
/// survive percent-decoding into a header value because we never
/// echo the captured params into a response header).
async fn write_redirect(stream: &mut TcpStream, location: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 302 Found\r\n\
         Location: {location}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Sends a raw HTTP request to the listener and returns the
    /// response bytes. Used by the validation tests that need to
    /// inspect the response status line without going through a
    /// real HTTP client.
    async fn send_raw(port: u16, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to loopback listener");
        stream.write_all(request).await.expect("write request");
        let mut buf = Vec::new();
        // Use a deadline so a hung listener doesn't hang the test.
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
        buf
    }

    fn status_code(response: &[u8]) -> Option<u16> {
        let head = std::str::from_utf8(response.get(..256.min(response.len()))?).ok()?;
        let line = head.lines().next()?;
        let mut parts = line.split_whitespace();
        let _http = parts.next()?;
        parts.next()?.parse().ok()
    }

    fn header_value<'a>(response: &'a [u8], name: &str) -> Option<&'a str> {
        let head = std::str::from_utf8(response).ok()?;
        let needle = format!("{name}:");
        let needle_lc = needle.to_ascii_lowercase();
        for line in head.lines() {
            if line.to_ascii_lowercase().starts_with(&needle_lc) {
                return Some(line[needle.len()..].trim());
            }
        }
        None
    }

    #[tokio::test]
    async fn bind_returns_random_port() {
        let a = LoopbackListener::bind().await.unwrap();
        let b = LoopbackListener::bind().await.unwrap();
        assert_ne!(a.port, b.port, "two binds should get distinct ports");
        assert!(a.port > 0);
        assert!(b.port > 0);
    }

    #[tokio::test]
    async fn accept_one_with_valid_query_resolves() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let _ = send_raw(
            port,
            b"GET /callback?code=ABC&state=XYZ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await;

        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server resolved")
            .expect("join")
            .expect("captured");
        assert_eq!(
            result,
            CallbackParams {
                code: "ABC".to_string(),
                state: "XYZ".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn accept_one_with_missing_code_returns_400() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let resp = send_raw(
            port,
            b"GET /callback?state=XYZ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await;
        assert_eq!(status_code(&resp), Some(400));

        // The listener stays alive after the 400 — the future does
        // not resolve. Prove non-resolution with a short timeout.
        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(
            still_running.is_err(),
            "missing-code request must not resolve the listener"
        );
    }

    #[tokio::test]
    async fn accept_one_with_missing_state_returns_400() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let resp = send_raw(
            port,
            b"GET /callback?code=ABC HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await;
        assert_eq!(status_code(&resp), Some(400));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(still_running.is_err());
    }

    #[tokio::test]
    async fn accept_one_wrong_path_returns_404() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let resp = send_raw(
            port,
            b"GET /other?code=ABC&state=XYZ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await;
        assert_eq!(status_code(&resp), Some(404));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(still_running.is_err());
    }

    #[tokio::test]
    async fn accept_one_wrong_method_returns_405() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let resp = send_raw(
            port,
            b"POST /callback?code=ABC&state=XYZ HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert_eq!(status_code(&resp), Some(405));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(still_running.is_err());
    }

    #[tokio::test]
    async fn accept_one_redirects_browser_to_success_page() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let resp = send_raw(
            port,
            b"GET /callback?code=A&state=B HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await;
        assert_eq!(status_code(&resp), Some(302));
        let location = header_value(&resp, "Location").unwrap_or_default();
        assert_eq!(location, SUCCESS_REDIRECT_URL);

        // Listener should resolve.
        let _ = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("resolved")
            .expect("join")
            .expect("captured");
    }

    #[tokio::test]
    async fn accept_one_oversized_request_rejected() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        // Build a request whose total size exceeds MAX_REQUEST_BYTES
        // before the \r\n\r\n terminator. Pad the URL with a long
        // query value (16 KiB).
        let padding = "x".repeat(16 * 1024);
        let request = format!(
            "GET /callback?code=A&state=B&pad={padding} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        );
        let _ = send_raw(port, request.as_bytes()).await;

        // Listener must NOT resolve (we dropped the oversized
        // request before parsing).
        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(
            still_running.is_err(),
            "oversized request must not resolve the listener"
        );
    }

    #[tokio::test]
    async fn accept_one_url_decodes_query() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        // %20 → space, %26 → ampersand, %23 → hash. The hash is the
        // critical one: CC's paste format is `code#state`, but in the
        // loopback path the params come as separate query keys.
        let _ = send_raw(
            port,
            b"GET /callback?code=A%20B&state=X%26Y HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await;

        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server resolved")
            .expect("join")
            .expect("captured");
        assert_eq!(result.code, "A B");
        assert_eq!(result.state, "X&Y");
    }

    #[tokio::test]
    async fn accept_one_after_resolve_listener_closed() {
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let _ = send_raw(
            port,
            b"GET /callback?code=A&state=B HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        )
        .await;
        let _ = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("resolved")
            .expect("join")
            .expect("captured");

        // Give the kernel a beat to actually release the port.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = TcpStream::connect(("127.0.0.1", port)).await;
        assert!(
            second.is_err(),
            "second connection on the released port must fail"
        );
    }

    #[tokio::test]
    async fn dropping_listener_releases_port() {
        // Prove cancellation safety: dropping the future closes the
        // socket. Used by the race orchestrator on the loser path.
        let listener = LoopbackListener::bind().await.unwrap();
        let port = listener.port;
        // Start the accept loop, immediately abort it.
        let server = tokio::spawn(listener.accept_one());
        server.abort();
        // Wait for the abort to actually drop the future.
        let _ = server.await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = TcpStream::connect(("127.0.0.1", port)).await;
        assert!(
            second.is_err(),
            "port must be released after future drop"
        );
    }

    #[test]
    fn split_path_and_query_handles_no_query() {
        assert_eq!(split_path_and_query("/callback"), ("/callback", ""));
    }

    #[test]
    fn split_path_and_query_handles_query() {
        assert_eq!(
            split_path_and_query("/callback?code=A"),
            ("/callback", "code=A")
        );
    }

    #[test]
    fn parse_query_handles_empty() {
        assert!(parse_query("").is_empty());
    }

    #[test]
    fn parse_query_decodes_percent_escapes() {
        let p = parse_query("code=A%20B&state=C");
        assert_eq!(p[0], ("code".to_string(), "A B".to_string()));
        assert_eq!(p[1], ("state".to_string(), "C".to_string()));
    }
}
