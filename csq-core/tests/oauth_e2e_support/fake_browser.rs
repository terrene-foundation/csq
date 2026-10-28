//! Fake browser that issues real HTTP GETs to csq's loopback listener.
//!
//! The point of this helper is to exercise the listener's REAL parser
//! (request-line split, Host validation, path-secret comparison,
//! query parsing). The "browser" is the system under test's only
//! external dependency in the loopback path, and we want it to be a
//! real socket round-trip — not a `LoopbackListener` internal API
//! call that would bypass the parser.
//!
//! # Why not reqwest
//!
//! `reqwest` would auto-set the `Host:` header from the URL. We need
//! line-level control to test the wrong-Host and wrong-path-secret
//! cases. A hand-rolled `tokio::net::TcpStream` write of the request
//! line gives us that control without taking on a dep.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Sends a `GET <path>?code=<code>&state=<state>` to `127.0.0.1:port`
/// with `Host: 127.0.0.1:<port>`. Returns the response bytes.
///
/// Uses a 2-second read timeout so a misbehaving listener cannot hang
/// the test.
pub async fn callback_get(port: u16, path: &str, code: &str, state: &str) -> Vec<u8> {
    let request = format!(
        "GET {path}?code={code}&state={state} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         \r\n"
    );
    raw_request(port, request.as_bytes()).await
}

/// Sends a `GET <path>?code=<code>&state=<state>` with a CALLER-CHOSEN
/// `Host:` header. Used by the wrong-Host-header rejection test.
pub async fn callback_get_with_host(
    port: u16,
    path: &str,
    code: &str,
    state: &str,
    host: &str,
) -> Vec<u8> {
    let request = format!(
        "GET {path}?code={code}&state={state} HTTP/1.1\r\n\
         Host: {host}\r\n\
         \r\n"
    );
    raw_request(port, request.as_bytes()).await
}

/// Lower-level helper: writes the raw bytes and reads the response.
/// Read is bounded to 2 s so a hung peer never hangs the test.
async fn raw_request(port: u16, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to loopback listener");
    stream
        .write_all(request)
        .await
        .expect("write request to loopback");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf)).await;
    buf
}

/// Returns the HTTP status code from a response, or `None` if the
/// response is malformed / empty. Used by tests that need to assert
/// the listener's response shape (e.g. 400 for wrong Host, 404 for
/// wrong path secret) without also resolving the listener.
pub fn status_code(response: &[u8]) -> Option<u16> {
    let head = std::str::from_utf8(response.get(..256.min(response.len()))?).ok()?;
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    let _http = parts.next()?;
    parts.next()?.parse().ok()
}
