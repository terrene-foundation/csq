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

/// C-F5 (`keychain-fix-r8.md`), D-F7 (`keychain-fix-r9.md`): dedicated
/// timeout for `POST /api/harvest-account`, wider than [`DEFAULT_TIMEOUT`]
/// because the work this route runs via `spawn_blocking`
/// (`custodian::reconcile_account`) chains real, individually-bounded I/O
/// rather than the sub-millisecond work every other route does:
///
/// - up to an ASSUMED worst case of 4 keychain reads, each bounded by
///   `credentials::keychain`'s private `KEYCHAIN_OP_TIMEOUT` +
///   `MIN_POST_EXIT_GRACE` = 5.25s at this revision (see that module's own
///   `run_bounded` doc — the grace is a real floor on the child-exit wait,
///   not merely `KEYCHAIN_OP_TIMEOUT` alone) — one per live handle dir this
///   account is bound to, freshest-first;
/// - up to `custodian::MAX_VALIDATIONS_PER_RECONCILE`
///   (2) of those candidates going on to a live validation call
///   (`GET /api/oauth/profile` — NOT `/api/oauth/usage`; see
///   `custodian::verify_token_owner`'s own doc for why this endpoint, not
///   that one — over the node-subprocess transport bounded by
///   `http::mod`'s `NODE_TIMEOUT_MS` = 15s at this revision) before
///   `reconcile_account` either adopts one or gives up — the freshest
///   candidate, then (on a 401) the next-freshest. Since D-F7, this cap
///   is ENFORCED BY CODE (`reconcile_candidates_inner` stops and returns
///   `SkippedUnknown` once reached), not merely assumed here.
///
/// `4*5.25 + 2*15 = 21 + 30 = 51s`, plus a margin of 10s for scheduling
/// jitter and the server-side per-account gate's own bookkeeping
/// (`server::harvest_gate`) = 61s. The keychain-read COUNT (4) is still a
/// DOCUMENTED WORST-CASE ASSUMPTION, not a proven bound
/// (`rules/doc-property-claims.md` MUST-1/2) — an account with more than 4
/// simultaneously live terminals can still exceed it; the assumption is
/// written here, by name, so a future change to that count updates this
/// constant deliberately rather than by accident. The validation-call COUNT
/// (2), unlike the read count, is no longer an assumption — see above. Do
/// not mistake the 61s figure for a measured typical: the typical case is a
/// fraction of a second (see `server::harvest_gate`'s own per-account
/// minimum-interval note).
pub const HARVEST_TIMEOUT: Duration = Duration::from_secs(61);

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
    http_post_unix_impl(sock_path, path_and_query, None, &[])
}

/// Issues a `POST path_and_query` with a JSON body against the
/// daemon's Unix socket. Used by `csq login` to submit the paste-
/// code exchange request to `/api/oauth/exchange`.
///
/// The caller is responsible for building the JSON string; this
/// function only wraps it in the HTTP request and sets the
/// `Content-Type: application/json` header.
pub fn http_post_unix_json(
    sock_path: &Path,
    path_and_query: &str,
    json_body: &str,
) -> Result<DaemonResponse, DaemonClientError> {
    http_post_unix_impl(sock_path, path_and_query, Some(json_body), &[])
}

/// Issues a `POST path_and_query` with a JSON body AND caller-supplied
/// extra request headers against the daemon's Unix socket.
///
/// Used by the interactive per-turn enforcement client (an internal ticket) to carry the
/// daemon-minted `X-CSQ-Session-Key` capability header on
/// `/api/interactive/{submit,override,abandon,close}` calls.
///
/// Each `(name, value)` pair in `extra_headers` is validated against CRLF
/// injection: a `\r` or `\n` in either the name or the value returns
/// [`DaemonClientError::MalformedResponse`] BEFORE any bytes are written
/// (`rules/security.md` §9 — runtime CRLF validation on hand-rolled HTTP, not
/// `debug_assert!`, because this is a `pub` surface future callers pass dynamic
/// values to). `Host`, `Content-Type`, `Content-Length`, and `Connection` are
/// emitted by this function and MUST NOT be passed in `extra_headers`.
pub fn http_post_unix_json_with_headers(
    sock_path: &Path,
    path_and_query: &str,
    json_body: &str,
    extra_headers: &[(&str, &str)],
) -> Result<DaemonResponse, DaemonClientError> {
    http_post_unix_impl(sock_path, path_and_query, Some(json_body), extra_headers)
}

/// Fire-and-forget per-slot cache invalidation after `csq move FROM TO`.
///
/// Sends `POST /api/slot-swap {"from": N, "to": M}` to the daemon so it
/// drops `RefreshStatus` cache entries for both slot numbers (SEC-2.11).
/// The discovery cache is also cleared by the route handler.
///
/// Returns `Ok(())` if the request succeeded (HTTP 200) or if the socket
/// is absent/unreachable (fire-and-forget: connect failure is not an
/// error from the caller's perspective). Returns `Err` only when the path
/// contains CRLF characters (security guard, an internal journal entry H3).
///
/// **This is the single production chokepoint for slot-swap IPC.**
/// Both the CLI (`csq move`) and the desktop Tauri command
/// (`move_account`) route through this function. Duplicate inline
/// implementations are BLOCKED — add callers here; do not inline.
pub fn notify_slot_swap(sock_path: &Path, from: u16, to: u16) -> Result<(), DaemonClientError> {
    if !sock_path.exists() {
        return Ok(());
    }
    let body = format!(r#"{{"from":{},"to":{}}}"#, from, to);
    match http_post_unix_json(sock_path, "/api/slot-swap", &body) {
        Ok(_) | Err(DaemonClientError::Connect(_)) => Ok(()),
        Err(e) => Err(e),
    }
}

/// `POST /api/harvest-account` (round 7c D3) — asks the daemon to run the
/// custodian's existing harvest→validate→adopt path for `account` NOW,
/// synchronously, rather than waiting for its next refresh tick. Used by
/// `csq swap`/`auto_rotate`'s D5/D4 "harvest before the per-dir lock" step:
/// a keychain item matching no known account (`WriteDecision::RefuseUnharvested`)
/// may be a login CC itself just self-refreshed, and this is the one channel
/// that can adopt it before the caller re-decides under the lock.
///
/// Absent/unreachable socket, a malformed response, or any transport error
/// all map to [`super::HarvestAccountOutcome::Unavailable`] — the caller's
/// job is to decide what "the daemon could not confirm this" means for ITS
/// operation (D5: refuse if the item holds an unmatched valid token; proceed
/// otherwise), not this function's.
pub fn harvest_account(sock_path: &Path, account: u16) -> super::HarvestAccountOutcome {
    use super::HarvestAccountOutcome;
    if !sock_path.exists() {
        return HarvestAccountOutcome::Unavailable;
    }
    let body = format!(r#"{{"account":{account}}}"#);
    match http_post_unix_impl_with_timeout(
        sock_path,
        "/api/harvest-account",
        Some(&body),
        &[],
        HARVEST_TIMEOUT,
    ) {
        Ok(resp) if resp.status == 200 => {
            if resp.body.contains("\"outcome\":\"adopted\"") {
                HarvestAccountOutcome::Adopted
            } else if resp.body.contains("\"outcome\":\"ownership_unknown\"") {
                HarvestAccountOutcome::OwnershipUnknown
            } else if resp.body.contains("\"outcome\":\"busy\"") {
                HarvestAccountOutcome::Busy
            } else {
                // "nothing_to_harvest", or an unrecognized future outcome
                // string — neither is a reason to refuse the caller's
                // switch, so this is the safe default.
                HarvestAccountOutcome::NothingToHarvest
            }
        }
        Ok(_) | Err(_) => HarvestAccountOutcome::Unavailable,
    }
}

fn http_post_unix_impl(
    sock_path: &Path,
    path_and_query: &str,
    json_body: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> Result<DaemonResponse, DaemonClientError> {
    http_post_unix_impl_with_timeout(
        sock_path,
        path_and_query,
        json_body,
        extra_headers,
        DEFAULT_TIMEOUT,
    )
}

/// Same as [`http_post_unix_impl`] but with a caller-specified timeout —
/// C-F5 (`keychain-fix-r8.md`): `/api/harvest-account` needs a wider budget
/// than [`DEFAULT_TIMEOUT`] (see [`HARVEST_TIMEOUT`]'s doc for the
/// derivation), and every OTHER route keeps using the 2s default unchanged.
fn http_post_unix_impl_with_timeout(
    sock_path: &Path,
    path_and_query: &str,
    json_body: Option<&str>,
    extra_headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<DaemonResponse, DaemonClientError> {
    validate_path_and_query(path_and_query)?;

    // Build the caller-supplied header block, CRLF-validating every name and
    // value BEFORE connecting so a rejected header never opens a socket
    // (`rules/security.md` §9).
    let mut extra = String::new();
    for (name, value) in extra_headers {
        validate_header_field(name)?;
        validate_header_field(value)?;
        extra.push_str(name);
        extra.push_str(": ");
        extra.push_str(value);
        extra.push_str("\r\n");
    }

    let mut stream = UnixStream::connect(sock_path).map_err(DaemonClientError::Connect)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(DaemonClientError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(DaemonClientError::Io)?;

    let request = match json_body {
        Some(body) => format!(
            "POST {path_and_query} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             {extra}\
             Connection: close\r\n\
             \r\n\
             {body}",
            len = body.len(),
        ),
        None => format!(
            "POST {path_and_query} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Length: 0\r\n\
             {extra}\
             Connection: close\r\n\
             \r\n"
        ),
    };
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

/// Validates a request-header name or value for HTTP request-line safety.
///
/// Rejects CR (`\r`) and LF (`\n`) to prevent header injection on the
/// hand-rolled request (`rules/security.md` §9). A runtime check (not
/// `debug_assert!`) because the only caller —
/// [`http_post_unix_json_with_headers`] — is a `pub` surface fed dynamic
/// values (e.g. a client-echoed session key).
fn validate_header_field(field: &str) -> Result<(), DaemonClientError> {
    if field.contains('\r') || field.contains('\n') {
        return Err(DaemonClientError::MalformedResponse(
            "header name/value must not contain CR or LF".to_string(),
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
    use crate::daemon::test_socket_fixture::UnixSocketFixture;

    /// C-F5 (`keychain-fix-r8.md`), D-F7 (`keychain-fix-r9.md`): the timeout
    /// arithmetic named in `HARVEST_TIMEOUT`'s doc — `4*5.25 + 2*15 = 51s`
    /// plus a 10s margin — pinned so a change to any input updates the
    /// constant deliberately.
    ///
    /// The validation-call factor (`2`) is derived from the REAL enforcing
    /// constant, [`crate::daemon::custodian::MAX_VALIDATIONS_PER_RECONCILE`]
    /// — not restated as a bare literal — because D-F7 made that cap
    /// code-enforced rather than merely assumed. The keychain-read factors
    /// (`4` candidates, `5.25s` per read) remain restated literals: their
    /// source constants (`KEYCHAIN_OP_TIMEOUT`, `MIN_POST_EXIT_GRACE` in
    /// `credentials::keychain`) are private to a sibling module this PR does
    /// not own, so this test cannot import them
    /// (`doc-property-claims.md` MUST-1: a measured value is never a bound —
    /// this asserts the STATED arithmetic for those two factors, not a
    /// re-derivation; see the D-F7 cap test in `custodian.rs` for the piece
    /// that IS behaviorally exercised rather than merely asserted as
    /// arithmetic).
    #[test]
    fn harvest_timeout_matches_its_documented_derivation() {
        let keychain_read_worst_case_secs = 5.25; // KEYCHAIN_OP_TIMEOUT + MIN_POST_EXIT_GRACE
        let assumed_max_candidates = 4.0;
        let validation_call_secs = 15.0; // NODE_TIMEOUT_MS
        let max_validations = crate::daemon::custodian::MAX_VALIDATIONS_PER_RECONCILE as f64;
        let margin_secs = 10.0;
        let expected_secs = assumed_max_candidates * keychain_read_worst_case_secs
            + max_validations * validation_call_secs
            + margin_secs;
        assert_eq!(
            expected_secs, 61.0,
            "sanity-check the arithmetic itself before comparing against the constant"
        );
        assert_eq!(
            HARVEST_TIMEOUT,
            Duration::from_secs(expected_secs as u64),
            "HARVEST_TIMEOUT must equal its documented derivation \
             (4*5.25 + 2*15 = 51s, + 10s margin = 61s)"
        );
        assert!(
            HARVEST_TIMEOUT > DEFAULT_TIMEOUT,
            "the harvest route's budget must exceed every other route's 2s default"
        );
    }

    // round 7c D3
    #[test]
    fn harvest_account_unreachable_socket_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("does-not-exist.sock");
        assert_eq!(
            harvest_account(&sock, 1),
            super::super::HarvestAccountOutcome::Unavailable
        );
    }

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
        let dir = UnixSocketFixture::new().unwrap();
        let path = dir.socket_path();
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
        let dir = UnixSocketFixture::new().unwrap();
        let path = dir.socket_path();
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

    #[test]
    fn validate_header_field_rejects_crlf() {
        // CR, LF, and a full CRLF-injection payload must all be rejected so a
        // client-echoed session key cannot smuggle extra headers (an internal ticket).
        assert!(validate_header_field("ok\rval").is_err());
        assert!(validate_header_field("ok\nval").is_err());
        let err = validate_header_field("key\r\nEvil-Header: value").unwrap_err();
        assert!(matches!(err, DaemonClientError::MalformedResponse(_)));
    }

    #[test]
    fn validate_header_field_accepts_session_key_shape() {
        // A daemon-minted ULID-shaped key (the real X-CSQ-Session-Key payload)
        // and ordinary header names must pass.
        assert!(validate_header_field("01J9ZK7C8QABCDEF0123456789").is_ok());
        assert!(validate_header_field("X-CSQ-Session-Key").is_ok());
        assert!(validate_header_field("abc-DEF_123").is_ok());
    }
}
