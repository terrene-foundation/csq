//! Minimal HTTP/1.1 client over a Unix domain socket.
//!
//! Used by CLI commands that want to delegate to a running daemon
//! (e.g. `csq login`, `csq status --daemon`). The daemon's IPC
//! surface is an axum router bound to a Unix socket; we speak a
//! small subset of HTTP/1.1 to it without pulling `reqwest` + tokio
//! into the blocking CLI path.
//!
//! # Scope
//!
//! This module only implements `GET` against an existing socket.
//! It does **not** perform daemon detection — callers should use
//! [`super::detect_daemon`] first and fall back to direct mode if
//! the result is not `Healthy`.
//!
//! The HTTP/1.1 parser is intentionally minimal: it splits on the
//! `\r\n\r\n` header terminator, parses the status line, and returns
//! the body as-is. Chunked transfer encoding is not supported because
//! axum serves `Content-Length`-terminated responses for our routes.
//!
//! # Timeouts
//!
//! Every call applies read and write timeouts so a hung daemon
//! cannot block the CLI. The default timeout is 2 seconds, which is
//! much longer than the 200ms health-check budget because some
//! legitimate routes (`/api/login/{N}`) perform PKCE generation and
//! state-store work that is bounded but not sub-millisecond.
//!
//! # Security
//!
//! The body buffer is capped at [`MAX_RESPONSE_BYTES`] (64 KiB) to
//! prevent a runaway daemon from exhausting CLI memory. All daemon
//! routes return small JSON, so this is generous.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Default read/write timeout for daemon HTTP calls.
///
/// The health-check path in [`super::detect`] uses a tighter 200ms
/// budget; this 2s default is for feature calls where the daemon
/// may do real work (e.g., PKCE generation on `/api/login/{N}`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum response body we will buffer from the daemon. 64 KiB is
/// orders of magnitude larger than any current route's JSON payload
/// (even `/api/accounts` with all 999 slots populated is under 200
/// KiB worst case, and typically < 4 KiB). We cap to bound CLI
/// memory if the daemon ever misbehaves.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A parsed HTTP/1.1 response from the daemon.
#[derive(Debug, Clone)]
pub struct DaemonResponse {
    /// Numeric status code (e.g., 200, 400, 503).
    pub status: u16,
    /// Response body bytes after the `\r\n\r\n` header terminator.
    /// Truncated at [`MAX_RESPONSE_BYTES`] if the daemon returned more.
    pub body: String,
}

/// Error kinds returned by [`http_get_unix`]. These are deliberately
/// narrow so callers can match on them for graceful fallback.
#[derive(Debug)]
pub enum DaemonClientError {
    /// Socket connect failed. Usually means the daemon is not
    /// running at this path.
    Connect(std::io::Error),
    /// Write or read IO error after the connect succeeded. Includes
    /// timeout (`WouldBlock` / `TimedOut`).
    Io(std::io::Error),
    /// Response did not start with a valid `HTTP/1.x NNN` status line.
    MalformedResponse(String),
    /// Response body exceeded [`MAX_RESPONSE_BYTES`].
    ResponseTooLarge,
}

impl std::fmt::Display for DaemonClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect to daemon socket failed: {e}"),
            Self::Io(e) => write!(f, "daemon IO error: {e}"),
            Self::MalformedResponse(s) => write!(f, "malformed daemon response: {s}"),
            Self::ResponseTooLarge => write!(f, "daemon response exceeded 64 KiB cap"),
        }
    }
}

impl std::error::Error for DaemonClientError {}

/// Issues a `GET path_and_query` against the daemon's Unix socket.
///
/// `path_and_query` must start with `/` and may include a query
/// string (e.g., `/api/login/3` or `/api/accounts?all=1`). The
/// caller is responsible for percent-encoding any dynamic segments.
///
/// # Timeouts
///
/// Applies [`DEFAULT_TIMEOUT`] as both read and write timeout. Use
/// [`http_get_unix_with_timeout`] for a custom budget.
///
/// # Errors
///
/// - [`DaemonClientError::Connect`] — socket missing or refused.
///   Caller should treat as "daemon not available" and fall back.
/// - [`DaemonClientError::Io`] — timeout or read/write failure.
/// - [`DaemonClientError::MalformedResponse`] — status line not
///   parseable. Should be unreachable against axum.
/// - [`DaemonClientError::ResponseTooLarge`] — body exceeded the
///   64 KiB cap. Should be unreachable for current routes.
pub fn http_get_unix(
    sock_path: &Path,
    path_and_query: &str,
) -> Result<DaemonResponse, DaemonClientError> {
    http_get_unix_with_timeout(sock_path, path_and_query, DEFAULT_TIMEOUT)
}

/// Same as [`http_get_unix`] but with a caller-specified timeout.
///
/// The timeout applies independently to the connect, write, and
/// read phases.
pub fn http_get_unix_with_timeout(
    sock_path: &Path,
    path_and_query: &str,
    timeout: Duration,
) -> Result<DaemonResponse, DaemonClientError> {
    validate_path_and_query(path_and_query)?;

    let mut stream = UnixStream::connect(sock_path).map_err(DaemonClientError::Connect)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(DaemonClientError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(DaemonClientError::Io)?;

    // Minimal HTTP/1.1 GET. `Host: localhost` is a placeholder — the
    // Unix socket has no real host. `Connection: close` tells axum to
    // end the response after one exchange so we don't need to parse
    // keep-alive framing.
    let request = format!(
        "GET {path_and_query} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(DaemonClientError::Io)?;

    // Read until EOF or the cap. axum sends `Connection: close` back,
    // so the server will close after writing the full response.
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return Err(DaemonClientError::ResponseTooLarge);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err(DaemonClientError::Io(e)),
        }
    }

    parse_response(&buf)
}

/// Issues a `POST path_and_query` with an empty body against the
/// daemon's Unix socket. Used by `csq swap` to notify the daemon
/// to invalidate its caches.
///
/// Same timeout and security properties as [`http_get_unix`].
pub fn http_post_unix(
    sock_path: &Path,
    path_and_query: &str,
) -> Result<DaemonResponse, DaemonClientError> {
    validate_path_and_query(path_and_query)?;

    let mut stream = UnixStream::connect(sock_path).map_err(DaemonClientError::Connect)?;
    stream
        .set_read_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(DaemonClientError::Io)?;
    stream
        .set_write_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(DaemonClientError::Io)?;

    let request = format!(
        "POST {path_and_query} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(DaemonClientError::Io)?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return Err(DaemonClientError::ResponseTooLarge);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => return Err(DaemonClientError::Io(e)),
        }
    }

    parse_response(&buf)
}

/// Validates `path_and_query` for HTTP request-line safety.
///
/// Rejects CRLF characters (`\r`, `\n`) to prevent HTTP header
/// injection. Also rejects paths not starting with `/`. This is a
/// runtime check (not `debug_assert!`) because the function is `pub`
/// and future callers may pass dynamic paths.
fn validate_path_and_query(path_and_query: &str) -> Result<(), DaemonClientError> {
    if !path_and_query.starts_with('/') {
        return Err(DaemonClientError::MalformedResponse(
            "path_and_query must start with '/'".to_string(),
        ));
    }
    if path_and_query.contains('\r') || path_and_query.contains('\n') {
        return Err(DaemonClientError::MalformedResponse(
            "path_and_query must not contain CR or LF".to_string(),
        ));
    }
    Ok(())
}

/// Parses a minimal HTTP/1.1 response buffer into a
/// [`DaemonResponse`]. Split into its own function for unit tests.
///
/// Accepts any `HTTP/1.x` status line (axum currently writes
/// `HTTP/1.1`, but we don't pin on the minor version).
pub(crate) fn parse_response(buf: &[u8]) -> Result<DaemonResponse, DaemonClientError> {
    // Find the end-of-headers marker. The response must contain at
    // least a status line and one blank line.
    let text = std::str::from_utf8(buf).map_err(|_| {
        DaemonClientError::MalformedResponse("response is not valid UTF-8".to_string())
    })?;

    let header_end = text.find("\r\n\r\n").ok_or_else(|| {
        DaemonClientError::MalformedResponse(
            "response is missing CRLFCRLF header terminator".to_string(),
        )
    })?;

    let status_line = text.lines().next().ok_or_else(|| {
        DaemonClientError::MalformedResponse("response has no status line".to_string())
    })?;

    // `HTTP/1.1 200 OK` → split on whitespace, take the second token.
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(DaemonClientError::MalformedResponse(format!(
            "unexpected HTTP version: {version}"
        )));
    }
    let status_str = parts.next().ok_or_else(|| {
        DaemonClientError::MalformedResponse(format!("status line missing code: {status_line}"))
    })?;
    let status: u16 = status_str.parse().map_err(|_| {
        DaemonClientError::MalformedResponse(format!("status code not a number: {status_str}"))
    })?;

    let body = text[header_end + 4..].to_string();
    Ok(DaemonResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_200_ok() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                    content-type: application/json\r\n\
                    content-length: 15\r\n\
                    \r\n\
                    {\"ok\":true}";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "{\"ok\":true}");
    }

    #[test]
    fn parse_400_with_text_body() {
        let raw = b"HTTP/1.1 400 Bad Request\r\n\
                    content-length: 17\r\n\
                    \r\n\
                    invalid account id";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 400);
        assert_eq!(resp.body, "invalid account id");
    }

    #[test]
    fn parse_503_service_unavailable() {
        let raw = b"HTTP/1.1 503 Service Unavailable\r\n\
                    content-length: 20\r\n\
                    \r\n\
                    oauth listener down";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 503);
        assert!(resp.body.starts_with("oauth listener"));
    }

    #[test]
    fn parse_accepts_http10() {
        // We accept any HTTP/1.x minor version.
        let raw = b"HTTP/1.0 200 OK\r\n\r\nhi";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "hi");
    }

    #[test]
    fn parse_rejects_missing_header_terminator() {
        let raw = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n";
        let err = parse_response(raw).unwrap_err();
        match err {
            DaemonClientError::MalformedResponse(s) => {
                assert!(s.contains("CRLFCRLF"), "msg: {s}");
            }
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_non_http_version() {
        let raw = b"HTTP/2.0 200 OK\r\n\r\n";
        let err = parse_response(raw).unwrap_err();
        match err {
            DaemonClientError::MalformedResponse(s) => {
                assert!(s.contains("HTTP version"), "msg: {s}");
            }
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_non_numeric_status() {
        let raw = b"HTTP/1.1 OK OK\r\n\r\n";
        let err = parse_response(raw).unwrap_err();
        match err {
            DaemonClientError::MalformedResponse(s) => {
                assert!(s.contains("status code"), "msg: {s}");
            }
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_invalid_utf8() {
        // Header bytes 0x80-0xFF are not valid ASCII/UTF-8 start bytes.
        let raw = &[0x80u8, 0x81, 0x82, 0x83];
        let err = parse_response(raw).unwrap_err();
        match err {
            DaemonClientError::MalformedResponse(s) => {
                assert!(s.contains("UTF-8"), "msg: {s}");
            }
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    /// End-to-end: bind a throwaway Unix socket, serve a fixed
    /// response on the first connect, verify the client parses it.
    #[test]
    fn http_get_unix_round_trip() {
        use std::os::unix::net::UnixListener;
        use std::thread;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&path).unwrap();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            // Read the request (discard).
            let mut req = [0u8; 512];
            let _ = conn.read(&mut req).unwrap();
            // Write a fixed 200 response.
            let body = r#"{"status":"ok","account":3}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );
            conn.write_all(resp.as_bytes()).unwrap();
        });

        let resp = http_get_unix(&path, "/api/login/3").unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"status\":\"ok\""));
        server.join().unwrap();
    }

    /// End-to-end: bind a throwaway Unix socket, serve a fixed
    /// response on the first POST, verify the client parses it.
    #[test]
    fn http_post_unix_round_trip() {
        use std::os::unix::net::UnixListener;
        use std::thread;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&path).unwrap();

        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = [0u8; 512];
            let _ = conn.read(&mut req).unwrap();
            let body = r#"{"cleared":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 content-type: application/json\r\n\
                 content-length: {}\r\n\
                 connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );
            conn.write_all(resp.as_bytes()).unwrap();
        });

        let resp = http_post_unix(&path, "/api/invalidate-cache").unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("\"cleared\":true"));
        server.join().unwrap();
    }

    #[test]
    fn http_get_unix_connect_failure_when_socket_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let missing = dir.path().join("nope.sock");
        let err = http_get_unix(&missing, "/api/health").unwrap_err();
        match err {
            DaemonClientError::Connect(_) => {}
            other => panic!("expected Connect error, got {other:?}"),
        }
    }

    // ─── CRLF injection regression tests ────────────────────

    #[test]
    fn validate_rejects_crlf_in_path() {
        let err = validate_path_and_query("/api/health\r\nEvil-Header: value").unwrap_err();
        match err {
            DaemonClientError::MalformedResponse(s) => assert!(s.contains("CR or LF")),
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_bare_newline() {
        let err = validate_path_and_query("/api/health\nEvil: header").unwrap_err();
        match err {
            DaemonClientError::MalformedResponse(s) => assert!(s.contains("CR or LF")),
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_missing_leading_slash() {
        let err = validate_path_and_query("api/health").unwrap_err();
        match err {
            DaemonClientError::MalformedResponse(s) => assert!(s.contains("start with '/'")),
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_valid_path() {
        assert!(validate_path_and_query("/api/health").is_ok());
        assert!(validate_path_and_query("/api/login/3?foo=bar").is_ok());
    }
}
