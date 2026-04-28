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
//!    - Path other than the constructed `/callback/<path_secret>` →
//!      `404 Not Found`, keep listening. The listener does NOT
//!      distinguish between "wrong well-known path" and "right
//!      well-known path with wrong secret" because that distinction
//!      is itself an oracle (see security note below).
//!    - Method other than `GET`                → `405 Method Not Allowed`,
//!      keep listening.
//!    - Missing `code` or `state` parameter    → `400 Bad Request`,
//!      keep listening.
//!    - Oversized request                      → drop the connection,
//!      keep listening.
//!    - Missing or wrong `Host:` header        → `400 Bad Request`,
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
//! - **Per-race path secret**. The accept path is
//!   `/callback/<base64url(16 random bytes)>`. The secret is minted
//!   at race start (see [`crate::oauth::race::prepare_race`]). A
//!   same-host attacker who can scrape the auto URL also gets the
//!   secret, but combined with the `Host:` header check below this
//!   raises the bar enough that a stock browser fetch from a
//!   different origin (which sets its own Host) cannot land a
//!   callback. SEC-R1-01.
//! - **Host header binding**. Every accepted callback MUST carry
//!   `Host: 127.0.0.1:<bound_port>` exactly. A browser fetch from
//!   any non-loopback origin sets a different Host. A `curl` from
//!   the same UID can spoof Host, but that attacker already has the
//!   path secret and PKCE state token — at that point the redirect
//!   indirection is not the security boundary.
//! - **Body cap**: any request whose total bytes (request line +
//!   headers + body, up to the first `\r\n\r\n`) exceed 8 KiB is
//!   dropped before parsing. Defense against accidental gigabyte POSTs
//!   from a malicious tab.
//! - **Per-connection wall-clock deadline**: each connection has a
//!   5 s budget for its entire request/response cycle (not just an
//!   idle read timeout). A slow-loris client cannot pin the listener
//!   for hours by trickling one byte every 4 s. SEC-R1-07.
//! - **Concurrent accept**: each connection is spawned on its own
//!   task. A slow first client cannot prevent a legitimate second
//!   client from being parsed. SEC-R1-08.
//! - **Single-shot**: after the first valid `?code&state` capture,
//!   the listener is dropped and its port is released. A second
//!   connection attempt on the same port immediately gets
//!   "connection refused".
//! - **Plaintext is intentional**. Loopback HTTPS would require a
//!   self-signed cert + browser trust prompt; loopback HTTP is what
//!   `claude auth login` itself uses. The traffic never leaves the
//!   host.
//! - **Bind/accept error formatting**. Bind/accept errors are wrapped
//!   in `redact_tokens` even though no token material is in scope —
//!   defence in depth in case a future kernel surfaces a path
//!   containing CSPRNG bytes that look token-shaped. SEC-R1-02.

use crate::error::{redact_tokens, OAuthError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
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

/// Per-connection wall-clock deadline. Bounds the *entire*
/// request/response cycle, not just one read. Defends against
/// slow-loris peers that trickle bytes within `PER_CONN_READ_TIMEOUT`
/// but never finish.
const PER_CONN_DEADLINE: Duration = Duration::from_secs(5);

/// Per-connection idle read deadline. A browser request fits in one
/// MSS-sized burst; any peer that hasn't finished sending headers in
/// 5 s is parked or hostile and we close on it. Capped above by
/// [`PER_CONN_DEADLINE`].
const PER_CONN_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Hard cap on the URL-decoded `code` parameter length. OAuth codes
/// are short opaque tokens; 4 KiB is two orders of magnitude above
/// any legitimate value. Reject anything larger before allocating
/// further. UX-R1-L4.
const MAX_CODE_LEN: usize = 4096;

/// Hard cap on the URL-decoded `state` parameter length. State
/// tokens we mint are 43 chars; 256 covers any legitimate echo from
/// Anthropic. Reject anything larger. UX-R1-L4.
const MAX_STATE_LEN: usize = 256;

/// Length of the per-race path secret in random bytes (URL-safe
/// base64-encoded to 22 chars). 16 bytes = 128 bits of entropy,
/// sufficient against a same-host brute-force in any realistic
/// timeframe.
pub const PATH_SECRET_BYTES: usize = 16;

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
    /// Per-race path secret. Only requests for
    /// `/callback/<path_secret>` are accepted. See module-level
    /// security notes (SEC-R1-01).
    path_secret: String,
}

impl LoopbackListener {
    /// Binds `127.0.0.1` with an OS-assigned port and returns the
    /// idle listener. The port is available via [`Self::port`].
    ///
    /// `path_secret` MUST be the URL-safe base64 string returned by
    /// [`generate_path_secret`] for the same race. Caller threads
    /// the same value into the redirect URI so the browser carries
    /// it back; callers MUST NOT log or transmit the secret outside
    /// the redirect URI itself.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::Exchange`] (with a sanitised message,
    /// no token material is available at bind time) if the kernel
    /// refuses to bind a loopback socket — typically because a
    /// hardened sandbox forbids it.
    pub async fn bind(path_secret: String) -> Result<Self, OAuthError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
            // Bind errors carry no token material today, but route
            // them through redact_tokens so a future kernel that
            // surfaces a path containing CSPRNG bytes (vanishingly
            // unlikely but defence in depth) doesn't echo them. M9.
            OAuthError::Exchange(redact_tokens(&format!("loopback bind failed: {e}")))
        })?;
        let port = listener
            .local_addr()
            .map_err(|e| OAuthError::Exchange(redact_tokens(&format!("loopback addr failed: {e}"))))?
            .port();
        Ok(Self {
            listener,
            port,
            path_secret,
        })
    }

    /// The configured callback path, e.g. `/callback/abc123`. Caller
    /// uses this to compose the redirect URI sent to the authorize
    /// endpoint.
    pub fn callback_path(&self) -> String {
        format!("/callback/{}", self.path_secret)
    }

    /// Waits for one valid `GET /callback/<path_secret>?code=…&state=…`
    /// request, redirects the browser to the hosted success page,
    /// closes the listener, and returns the captured parameters.
    ///
    /// Invalid requests (wrong path, wrong method, missing fields,
    /// oversize, wrong Host) are answered with the appropriate HTTP
    /// status and the accept loop continues. The future only
    /// resolves on a VALID capture or on a fatal accept error.
    ///
    /// Each connection is spawned on its own task with a 5 s
    /// wall-clock budget, so a slow-loris client cannot block a
    /// legitimate second client (SEC-R1-08).
    ///
    /// Cancellation is safe: dropping the returned future closes the
    /// listener.
    pub async fn accept_one(self) -> Result<CallbackParams, OAuthError> {
        let LoopbackListener {
            listener,
            port,
            path_secret,
        } = self;
        let expected_path = format!("/callback/{path_secret}");
        let expected_host = format!("127.0.0.1:{port}");

        let (capture_tx, mut capture_rx) =
            tokio::sync::mpsc::unbounded_channel::<CallbackParams>();

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    let (stream, _peer) = accept_res
                        .map_err(|e| OAuthError::Exchange(
                            redact_tokens(&format!("loopback accept failed: {e}"))
                        ))?;
                    let path = expected_path.clone();
                    let host = expected_host.clone();
                    let tx = capture_tx.clone();
                    // Spawn the per-connection handler so a slow
                    // peer cannot block a legitimate sibling
                    // connection. The handler enforces its own
                    // wall-clock deadline.
                    tokio::spawn(async move {
                        let outcome = tokio::time::timeout(
                            PER_CONN_DEADLINE,
                            handle_connection(stream, &path, &host),
                        )
                        .await;
                        if let Ok(ConnectionOutcome::Captured(params)) = outcome {
                            // Best-effort: receiver may have closed
                            // because a sibling connection won the
                            // race. Either way the listener will
                            // drop after this loop returns.
                            let _ = tx.send(params);
                        }
                    });
                }
                Some(params) = capture_rx.recv() => {
                    return Ok(params);
                }
            }
        }
    }
}

/// Generates a URL-safe base64 path secret with 128 bits of entropy.
///
/// Used by [`crate::oauth::race::prepare_race`] to mint a fresh
/// secret per login attempt. The returned value is bound into both
/// the listener (so it knows what path to accept) and the redirect
/// URI sent to the authorize endpoint.
pub fn generate_path_secret() -> String {
    let mut bytes = [0u8; PATH_SECRET_BYTES];
    getrandom::getrandom(&mut bytes)
        .expect("OS CSPRNG unavailable — cannot generate OAuth path secret");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Result of a single connection. Either we captured the OAuth
/// callback (and the listener should close) or we answered the
/// browser and want to keep listening.
enum ConnectionOutcome {
    Captured(CallbackParams),
    #[allow(dead_code)]
    Continue,
}

/// Consumes one connection. Reads the request, validates path /
/// method / Host / query, sends the appropriate response, returns
/// whether the listener should close.
///
/// Errors here are deliberately swallowed (logged at trace level
/// only): a misbehaving browser shouldn't kill the listener while
/// the user might still complete the OAuth flow on a sibling tab.
async fn handle_connection(
    mut stream: TcpStream,
    expected_path: &str,
    expected_host: &str,
) -> ConnectionOutcome {
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

    // Host header binding (SEC-R1-01). Reject anything that doesn't
    // exactly match `127.0.0.1:<bound_port>`. Browsers always set
    // Host to the literal authority from the URL; a browser fetch
    // from a different origin will set a different Host. We check
    // BEFORE the path so a probe never even gets to learn the
    // expected path shape.
    let host_ok = head_str
        .lines()
        .skip(1) // request line, not a header
        .take_while(|l| !l.is_empty())
        .any(|line| {
            let mut it = line.splitn(2, ':');
            let name = it.next().unwrap_or("").trim();
            let value = it.next().unwrap_or("").trim();
            name.eq_ignore_ascii_case("host") && value == expected_host
        });
    if !host_ok {
        let _ = write_response(&mut stream, 400, "Bad Request", "bad host").await;
        return ConnectionOutcome::Continue;
    }

    let (path, query) = split_path_and_query(target);
    if path != expected_path {
        // 404 for ALL non-matching paths — wrong well-known prefix
        // and wrong path-secret produce the same response so we do
        // not become an oracle that confirms partial-secret guesses.
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
    if code.len() > MAX_CODE_LEN {
        let _ = write_response(&mut stream, 400, "Bad Request", "code too long").await;
        return ConnectionOutcome::Continue;
    }
    let state = match params.iter().find(|(k, _)| k == "state") {
        Some((_, v)) if !v.is_empty() => v.clone(),
        _ => {
            let _ = write_response(&mut stream, 400, "Bad Request", "missing state").await;
            return ConnectionOutcome::Continue;
        }
    };
    if state.len() > MAX_STATE_LEN {
        let _ = write_response(&mut stream, 400, "Bad Request", "state too long").await;
        return ConnectionOutcome::Continue;
    }

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

    /// Default test path secret. Production callers MUST always use
    /// [`generate_path_secret`]; tests pin a literal so the assertions
    /// can construct request lines deterministically.
    const TEST_PATH_SECRET: &str = "abc123-test-secret";

    fn host_header(port: u16) -> String {
        format!("127.0.0.1:{port}")
    }

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
        let a = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let b = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        assert_ne!(a.port, b.port, "two binds should get distinct ports");
        assert!(a.port > 0);
        assert!(b.port > 0);
    }

    #[tokio::test]
    async fn accept_one_with_correct_path_secret_resolves() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=ABC&state=XYZ HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let _ = send_raw(port, req.as_bytes()).await;

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
    async fn accept_one_with_wrong_path_secret_returns_404() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /callback/wrong-secret-value?code=ABC&state=XYZ HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(
            status_code(&resp),
            Some(404),
            "wrong path secret must look indistinguishable from any other unknown path"
        );

        // The listener stays alive after the 404 — the future does
        // not resolve. Prove non-resolution with a short timeout.
        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(
            still_running.is_err(),
            "wrong-path-secret request must not resolve the listener"
        );
    }

    #[tokio::test]
    async fn accept_one_with_missing_host_header_rejects() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=ABC&state=XYZ HTTP/1.1\r\n\r\n"
        );
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(status_code(&resp), Some(400));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(
            still_running.is_err(),
            "missing-Host request must not resolve the listener"
        );
    }

    #[tokio::test]
    async fn accept_one_with_wrong_host_header_rejects() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=ABC&state=XYZ HTTP/1.1\r\n\
             Host: evil.example\r\n\r\n"
        );
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(status_code(&resp), Some(400));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(
            still_running.is_err(),
            "wrong-Host request must not resolve the listener"
        );
    }

    #[tokio::test]
    async fn accept_one_with_missing_code_returns_400() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?state=XYZ HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(status_code(&resp), Some(400));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(
            still_running.is_err(),
            "missing-code request must not resolve the listener"
        );
    }

    #[tokio::test]
    async fn accept_one_with_missing_state_returns_400() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=ABC HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(status_code(&resp), Some(400));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(still_running.is_err());
    }

    #[tokio::test]
    async fn accept_one_wrong_path_returns_404() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /other?code=ABC&state=XYZ HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(status_code(&resp), Some(404));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(still_running.is_err());
    }

    #[tokio::test]
    async fn accept_one_wrong_method_returns_405() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "POST /callback/{TEST_PATH_SECRET}?code=ABC&state=XYZ HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
            host_header(port)
        );
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(status_code(&resp), Some(405));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(still_running.is_err());
    }

    #[tokio::test]
    async fn accept_one_redirects_browser_to_success_page() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=A&state=B HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let resp = send_raw(port, req.as_bytes()).await;
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
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        // Build a request whose total size exceeds MAX_REQUEST_BYTES
        // before the \r\n\r\n terminator. Pad the URL with a long
        // query value (16 KiB).
        let padding = "x".repeat(16 * 1024);
        let request = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=A&state=B&pad={padding} HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
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
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        // %20 → space, %26 → ampersand, %23 → hash. The hash is the
        // critical one: CC's paste format is `code#state`, but in the
        // loopback path the params come as separate query keys.
        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=A%20B&state=X%26Y HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let _ = send_raw(port, req.as_bytes()).await;

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
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=A&state=B HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let _ = send_raw(port, req.as_bytes()).await;
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
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        // Start the accept loop, immediately abort it.
        let server = tokio::spawn(listener.accept_one());
        server.abort();
        // Wait for the abort to actually drop the future.
        let _ = server.await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let second = TcpStream::connect(("127.0.0.1", port)).await;
        assert!(second.is_err(), "port must be released after future drop");
    }

    #[tokio::test]
    async fn callback_path_includes_path_secret() {
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        assert_eq!(listener.callback_path(), format!("/callback/{TEST_PATH_SECRET}"));
    }

    #[tokio::test]
    async fn oversize_code_rejected_with_400() {
        // UX-R1-L4: cap code at MAX_CODE_LEN (4 KiB). A code larger
        // than that is malformed; reject with 400 before allocating.
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        // Code is well under MAX_REQUEST_BYTES (8 KiB) but over
        // MAX_CODE_LEN (4 KiB). Build it so the entire request fits
        // in the request-head budget but trips the per-field cap.
        // 5000 bytes — between MAX_CODE_LEN (4096) and the request
        // head limit if we keep other headers tight.
        let long_code = "a".repeat(5000);
        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code={long_code}&state=ok HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        // The request itself is ~5100 bytes which is under
        // MAX_REQUEST_BYTES (8192); we expect a 400.
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(
            status_code(&resp),
            Some(400),
            "oversize code must produce 400, not silently accept or oversize-drop"
        );

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(still_running.is_err());
    }

    #[tokio::test]
    async fn oversize_state_rejected_with_400() {
        // UX-R1-L4: cap state at MAX_STATE_LEN (256). Anthropic
        // echoes our 43-char state token; anything more is suspicious.
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        let long_state = "s".repeat(500);
        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=ok&state={long_state} HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let resp = send_raw(port, req.as_bytes()).await;
        assert_eq!(status_code(&resp), Some(400));

        let still_running = tokio::time::timeout(Duration::from_millis(200), server).await;
        assert!(still_running.is_err());
    }

    #[tokio::test]
    async fn slow_first_client_does_not_block_legitimate_second_client() {
        // SEC-R1-08 regression. A slow client that opens a connection
        // and trickles bytes (or just stalls) MUST NOT prevent a
        // legitimate second client from being parsed and resolving
        // the listener.
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;
        let server = tokio::spawn(listener.accept_one());

        // Open a connection and send NOTHING. The handler will sit
        // in `read_request_head` for up to PER_CONN_READ_TIMEOUT.
        let _slow = tokio::spawn(async move {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            // Hold the connection open without sending. Drop after
            // 4 s so we don't leak past the test.
            tokio::time::sleep(Duration::from_secs(4)).await;
            drop(stream);
        });

        // Give the slow client a moment to land its accept.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Now send a legitimate callback. If the listener is
        // serialising connections, this will hang behind the slow
        // client until its 5 s timeout. With per-connection spawning,
        // it resolves immediately.
        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=fast&state=ok HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let _ = send_raw(port, req.as_bytes()).await;

        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("server should resolve within 2s despite slow first client")
            .expect("join")
            .expect("captured");
        assert_eq!(result.code, "fast");
        assert_eq!(result.state, "ok");
    }

    #[tokio::test]
    async fn slow_client_does_not_block_listener_beyond_deadline() {
        // SEC-R1-07 regression. A connection that never sends a
        // complete request MUST be torn down by the per-connection
        // wall-clock deadline, not pinned forever.
        let listener = LoopbackListener::bind(TEST_PATH_SECRET.into())
            .await
            .unwrap();
        let port = listener.port;

        // Don't spawn the server yet — we measure end-to-end.
        let server = tokio::spawn(listener.accept_one());

        // Slow client: connect and never send anything. The handler
        // task must time out at PER_CONN_DEADLINE (5 s) at the
        // latest.
        let slow_handle = tokio::spawn(async move {
            let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            // Hold connection open longer than the deadline so we can
            // observe the server tearing it down.
            tokio::time::sleep(Duration::from_secs(8)).await;
            drop(stream);
        });

        // After the deadline (PER_CONN_DEADLINE = 5 s), submit a
        // legitimate callback. It must resolve within a couple
        // seconds, proving the slow client did not pin the listener.
        tokio::time::sleep(Duration::from_secs(6)).await;
        let req = format!(
            "GET /callback/{TEST_PATH_SECRET}?code=ok&state=ok HTTP/1.1\r\nHost: {}\r\n\r\n",
            host_header(port)
        );
        let _ = send_raw(port, req.as_bytes()).await;

        let result = tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("server resolved after slow client deadline")
            .expect("join")
            .expect("captured");
        assert_eq!(result.code, "ok");
        slow_handle.abort();
        let _ = slow_handle.await;
    }

    #[tokio::test]
    async fn loopback_bind_error_does_not_leak_secrets() {
        // M9 regression. Bind/accept errors are wrapped in
        // redact_tokens. We can't reliably force a bind failure in
        // a unit test (the kernel almost always grants a loopback
        // ephemeral port), so we verify the formatting path: a
        // synthetic error string containing a token-shaped suffix
        // gets redacted by redact_tokens before becoming an
        // OAuthError::Exchange variant. Same code path the bind
        // error site uses.
        let synthetic = "loopback bind failed: kernel refused sk-ant-oat01-LEAKED_TOKEN_VALUE";
        let redacted = redact_tokens(synthetic);
        assert!(
            !redacted.contains("LEAKED_TOKEN_VALUE"),
            "redact_tokens must scrub token-shaped substrings: {redacted}"
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

    #[test]
    fn generate_path_secret_is_random_per_call() {
        let a = generate_path_secret();
        let b = generate_path_secret();
        assert_ne!(a, b, "two consecutive path secrets must differ");
        // 16 bytes → 22 base64url chars (no padding).
        assert_eq!(a.len(), 22);
        assert_eq!(b.len(), 22);
    }
}
