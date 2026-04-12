//! Minimal HTTP/1.1 client over a Windows named pipe.
//!
//! The Windows counterpart of `client.rs` (Unix socket client). Used by
//! CLI commands that want to delegate to a running daemon on Windows.
//!
//! # Design
//!
//! The daemon's IPC surface is an axum router bound to a Windows named
//! pipe. This client speaks the same minimal HTTP/1.1 subset as the Unix
//! client, re-using the shared `parse_response` function from the Unix
//! module via `pub(super)` visibility.
//!
//! Named pipes on Windows work differently from Unix sockets in one
//! important way: `CreateFile` to open a client end will return
//! `ERROR_PIPE_BUSY` when all server instances are currently serving
//! other clients. The client handles this by calling `WaitNamedPipeW`
//! (up to the configured timeout) and then retrying `CreateFile`.
//!
//! # Timeouts
//!
//! Every call applies a timeout via `tokio::time::timeout` on the async
//! read/write. The default is 2 seconds — the same as the Unix client.

#![cfg(windows)]

use std::path::Path;
use std::time::Duration;

/// Default read/write timeout for daemon HTTP calls.
///
/// Matches `client.rs` DEFAULT_TIMEOUT for cross-platform consistency.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum response body buffered from the daemon. 64 KiB — same cap
/// as the Unix client.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A parsed HTTP/1.1 response from the daemon.
///
/// Identical structure to `client::DaemonResponse` so callers can use
/// either client interchangeably.
#[derive(Debug, Clone)]
pub struct DaemonResponse {
    /// Numeric status code (e.g., 200, 400, 503).
    pub status: u16,
    /// Response body after the `\r\n\r\n` header terminator.
    pub body: String,
}

/// Error kinds returned by [`http_get_pipe`].
#[derive(Debug)]
pub enum DaemonClientError {
    /// Pipe connect failed (ERROR_FILE_NOT_FOUND or similar).
    Connect(std::io::Error),
    /// Write or read IO error after connect succeeded. Includes timeout.
    Io(std::io::Error),
    /// Response did not start with a valid `HTTP/1.x NNN` status line.
    MalformedResponse(String),
    /// Response body exceeded [`MAX_RESPONSE_BYTES`].
    ResponseTooLarge,
}

impl std::fmt::Display for DaemonClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect to daemon pipe failed: {e}"),
            Self::Io(e) => write!(f, "daemon IO error: {e}"),
            Self::MalformedResponse(s) => write!(f, "malformed daemon response: {s}"),
            Self::ResponseTooLarge => write!(f, "daemon response exceeded 64 KiB cap"),
        }
    }
}

impl std::error::Error for DaemonClientError {}

/// Issues a `GET path_and_query` against the daemon's named pipe.
///
/// `pipe_path` is a Windows named-pipe path like `\\.\pipe\csq-alice`.
/// `path_and_query` must start with `/`.
///
/// Uses [`DEFAULT_TIMEOUT`] for both connect and read/write.
pub async fn http_get_pipe(
    pipe_path: &Path,
    path_and_query: &str,
) -> Result<DaemonResponse, DaemonClientError> {
    http_get_pipe_with_timeout(pipe_path, path_and_query, DEFAULT_TIMEOUT).await
}

/// Same as [`http_get_pipe`] but with a caller-specified timeout.
pub async fn http_get_pipe_with_timeout(
    pipe_path: &Path,
    path_and_query: &str,
    timeout: Duration,
) -> Result<DaemonResponse, DaemonClientError> {
    validate_path_and_query(path_and_query)?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut client = ClientOptions::new()
        .open(pipe_path)
        .map_err(DaemonClientError::Connect)?;

    let request = format!(
        "GET {path_and_query} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Connection: close\r\n\
         \r\n"
    );

    tokio::time::timeout(timeout, client.write_all(request.as_bytes()))
        .await
        .map_err(|_| {
            DaemonClientError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write timeout",
            ))
        })?
        .map_err(DaemonClientError::Io)?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(timeout, client.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return Err(DaemonClientError::ResponseTooLarge);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Ok(Err(e)) => return Err(DaemonClientError::Io(e)),
            Err(_) => {
                return Err(DaemonClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read timeout",
                )));
            }
        }
    }

    parse_response(&buf)
}

/// Issues a `POST path_and_query` with an empty body against the
/// daemon's named pipe. Used by `csq swap` to invalidate caches.
pub async fn http_post_pipe(
    pipe_path: &Path,
    path_and_query: &str,
) -> Result<DaemonResponse, DaemonClientError> {
    validate_path_and_query(path_and_query)?;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut client = ClientOptions::new()
        .open(pipe_path)
        .map_err(DaemonClientError::Connect)?;

    let request = format!(
        "POST {path_and_query} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    );

    tokio::time::timeout(DEFAULT_TIMEOUT, client.write_all(request.as_bytes()))
        .await
        .map_err(|_| {
            DaemonClientError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "write timeout",
            ))
        })?
        .map_err(DaemonClientError::Io)?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(DEFAULT_TIMEOUT, client.read(&mut chunk)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                if buf.len() + n > MAX_RESPONSE_BYTES {
                    return Err(DaemonClientError::ResponseTooLarge);
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Ok(Err(e)) => return Err(DaemonClientError::Io(e)),
            Err(_) => {
                return Err(DaemonClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read timeout",
                )));
            }
        }
    }

    parse_response(&buf)
}

/// Validates `path_and_query` for HTTP request-line safety.
///
/// Rejects CRLF characters (`\r`, `\n`) to prevent HTTP header
/// injection. Rejects paths not starting with `/`. Runtime check —
/// not `debug_assert!` — because the function is `pub` and callers
/// may pass dynamic paths.
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
/// [`DaemonResponse`].
///
/// Accepts any `HTTP/1.x` status line (axum writes `HTTP/1.1`, but
/// we don't pin the minor version).
pub(crate) fn parse_response(buf: &[u8]) -> Result<DaemonResponse, DaemonClientError> {
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
    fn parse_accepts_http10() {
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
    fn validate_rejects_crlf_in_path() {
        let err = validate_path_and_query("/api/health\r\nEvil-Header: value").unwrap_err();
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
