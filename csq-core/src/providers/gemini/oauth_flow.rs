//! Google OAuth 2.0 flow for Code Assist — csq drives the OAuth dance
//! itself instead of asking the user to "run `gemini` interactively
//! first." Per `feedback_delegate_to_reference_client` we WANTED to
//! delegate, but gemini-cli v0.41.2+ removed the `auth` subcommand
//! AND silently parses `auth login` as a prompt. With no
//! non-interactive surface in gemini-cli, csq has to own the flow.
//!
//! This module:
//!
//! 1. Binds a loopback HTTP server on `127.0.0.1:<random-port>`.
//! 2. Generates a PKCE code verifier + challenge (S256) and a CSPRNG
//!    state token.
//! 3. Builds the Google authorization URL with gemini-cli's extracted
//!    `client_id` + cloud-platform/userinfo scopes + the PKCE
//!    challenge.
//! 4. Opens the URL in the user's default browser via the platform
//!    helper (`open` on macOS, `xdg-open` on Linux, `cmd /c start` on
//!    Windows).
//! 5. Waits for the OAuth callback at `/callback` (with `?code=…&state=…`).
//! 6. Verifies the state token matches what we sent.
//! 7. Exchanges the auth code at `https://oauth2.googleapis.com/token`
//!    using the PKCE verifier + the embedded `client_id`/`client_secret`.
//! 8. Writes the resulting tokens to `~/.gemini/oauth_creds.json` in
//!    gemini-cli's exact JSON shape so subsequent `csq run N` (which
//!    spawns gemini-cli with `selectedType=oauth-personal` pinned)
//!    sees a fresh OAuth state and skips the first-run picker.
//!
//! ## Where the OAuth client credentials come from
//!
//! gemini-cli embeds them in its bundle (public per Google's
//! installed-app OAuth pattern: client_secret on a desktop app is not
//! a real secret because the binary ships with it). Extracted by
//! `grep`-ing `/opt/homebrew/lib/node_modules/@google/gemini-cli/bundle/*.js`.
//! If gemini-cli ever rotates these, csq's flow stops working — the
//! mitigation is operator-visible (`AuthExchangeFailed` error message)
//! and the recovery is to update the constants here.
//!
//! ## Network safety
//!
//! - Loopback IPv4 only (`127.0.0.1`).
//! - State token is 32 bytes CSPRNG, base64url-encoded, validated on
//!   callback before any code exchange.
//! - PKCE S256 — auth code is unusable without the verifier even if
//!   the loopback URL leaks via browser history / extensions.
//! - Token exchange goes over TLS to `oauth2.googleapis.com`.
//! - `oauth_creds.json` is written via `atomic_replace` + chmod 0600.

use crate::platform::fs::{atomic_replace, unique_tmp_path, write_new_private};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// gemini-cli's OAuth client_id + client_secret are NOT embedded as
// constants here — they are extracted from the local gemini-cli
// installation at runtime via `discover_gemini_oauth_credentials()`.
//
// Why: Google's installed-app OAuth pattern technically allows
// embedding the "secret" in the binary (it's not a real secret
// because every distributed binary contains it), but GitHub's
// secret-scanning correctly blocks any `GOCSPX-...` literal in
// committed source. Extracting at runtime keeps csq's git history
// clean AND means csq automatically picks up any rotation gemini-cli
// pushes in a future release.
//
// The discovery function locates `gemini` on PATH, walks up to its
// bundle directory, greps for `[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com`
// (client_id) and `GOCSPX-[A-Za-z0-9_-]+` (client_secret).

/// Scopes Code Assist needs. Mirrors what gemini-cli's first-run flow
/// requests when the user picks "Sign in with Google".
const SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
];

const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// Per-flow timeout — bound the operator's browser window. The OAuth
/// dance fits in ~1-2 minutes; 10 minutes is generous for slow networks
/// or operator distractions.
const FLOW_TIMEOUT: Duration = Duration::from_secs(600);

/// Errors raised by the OAuth flow.
#[derive(Debug, thiserror::Error)]
pub enum OauthFlowError {
    #[error(
        "could not locate gemini-cli's OAuth credentials in its bundle. \
         Reason: {reason}. csq extracts gemini-cli's client_id + client_secret \
         from the local installation; if gemini-cli is not installed or its \
         layout has changed, the OAuth flow cannot run. Install gemini-cli \
         from https://github.com/google-gemini/gemini-cli and retry."
    )]
    GeminiCredentialsNotDiscoverable { reason: String },
    #[error("could not bind loopback listener on 127.0.0.1: {0}")]
    LoopbackBind(std::io::Error),
    #[error("could not open the user's browser to the auth URL: {0}")]
    BrowserOpen(String),
    #[error("OAuth flow timed out after {timeout_secs}s waiting for browser callback")]
    Timeout { timeout_secs: u64 },
    #[error("operator aborted the OAuth flow before the browser callback")]
    Aborted,
    #[error("OAuth callback state mismatch — possible CSRF; refusing the exchange")]
    StateMismatch,
    #[error("OAuth callback carried no `code` parameter; auth was rejected by Google")]
    NoCode,
    #[error("token exchange with Google failed: {0}")]
    TokenExchange(String),
    #[error("oauth_creds.json write failed at {path}: {reason}")]
    WriteFailed { path: PathBuf, reason: String },
    #[error("home directory unavailable; cannot resolve `~/.gemini/oauth_creds.json`")]
    HomeNotSet,
}

/// gemini-cli's `oauth_creds.json` shape. Field names match what
/// gemini-cli writes after a successful `Sign in with Google` flow,
/// so the file is interchangeable.
///
/// `Debug` is hand-written, NOT derived — see the `impl fmt::Debug` just
/// below and `credential-type-hygiene.md` Rule 1. `Serialize` is retained
/// because this struct IS the on-disk `oauth_creds.json` shape; only the
/// `Debug` rendering is redacted, never the write path.
#[derive(Serialize, Deserialize)]
struct OauthCreds {
    access_token: String,
    refresh_token: String,
    scope: String,
    token_type: String,
    id_token: String,
    expiry_date: i64,
}

impl fmt::Debug for OauthCreds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `access_token`/`refresh_token` are bearer material and
        // `id_token` is a Google OpenID JWT carrying email + subject
        // claims, so all three render as `<redacted>`. `scope`,
        // `token_type` and `expiry_date` are non-secret and stay legible
        // — they are the fields that make a Debug line worth printing.
        f.debug_struct("OauthCreds")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .field("id_token", &"<redacted>")
            .field("expiry_date", &self.expiry_date)
            .finish()
    }
}

/// Token-endpoint response shape per Google's docs.
/// `Debug` is hand-written, NOT derived (`credential-type-hygiene.md`
/// Rule 1) — this is the raw Google token-endpoint response.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
    scope: String,
    token_type: String,
    id_token: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same redaction set as `OauthCreds`; `refresh_token` and
        // `id_token` are Option here, so presence is preserved (a
        // missing refresh token is a real diagnostic signal) while the
        // value never renders.
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("token_type", &self.token_type)
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Drives the full OAuth flow, blocking until completion or timeout.
/// On success, `~/.gemini/oauth_creds.json` exists with fresh tokens
/// and `Ok(())` is returned. On any failure, no file write occurs.
pub fn run() -> Result<(), OauthFlowError> {
    run_controlled(|| false, || Ok(()))
}

/// Desktop cancellation is honored only before the exchange. The returned
/// admission guard survives the exchange and atomic write; the caller retains
/// it until its slot binding is published as well.
pub fn run_controlled<P>(
    cancelled: impl Fn() -> bool,
    before_exchange: impl FnOnce() -> Result<P, OauthFlowError>,
) -> Result<P, OauthFlowError> {
    if cancelled() {
        return Err(OauthFlowError::Aborted);
    }
    // Step 0: discover gemini-cli's OAuth credentials from its local
    // bundle. NOT embedded in csq source per GitHub secret-scanning;
    // see comment above the constants block.
    let (client_id, client_secret) = discover_gemini_oauth_credentials()
        .map_err(|reason| OauthFlowError::GeminiCredentialsNotDiscoverable { reason })?;

    // Step 1: bind loopback on a random port.
    let listener = TcpListener::bind("127.0.0.1:0").map_err(OauthFlowError::LoopbackBind)?;
    let port = listener
        .local_addr()
        .map_err(OauthFlowError::LoopbackBind)?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    // Step 2: PKCE + state.
    let (verifier, challenge) = generate_pkce();
    let state = generate_state();

    // Step 3: build authorization URL.
    let scope_param: String = SCOPES.join(" ");
    let auth_url = format!(
        "{AUTH_ENDPOINT}?\
         client_id={client}&\
         redirect_uri={redirect}&\
         response_type=code&\
         scope={scope}&\
         code_challenge={challenge}&\
         code_challenge_method=S256&\
         state={state}&\
         access_type=offline&\
         prompt=consent",
        client = url_encode(&client_id),
        redirect = url_encode(&redirect_uri),
        scope = url_encode(&scope_param),
        challenge = url_encode(&challenge),
        state = url_encode(&state),
    );

    // Step 4: open browser.
    eprintln!("==> Opening browser to sign in with Google for Code Assist OAuth.");
    eprintln!("    If the browser does not open automatically, visit:");
    eprintln!("    {auth_url}");
    eprintln!();
    let _ = std::io::stderr().flush();
    // Headless guard: if `open_browser` cannot reach a GUI session
    // (no $DISPLAY / $WAYLAND_DISPLAY on Linux), DO NOT abort the
    // whole flow — the loopback listener still works as long as the
    // user can reach `port` from a remote GUI machine. Surface
    // concrete SSH-tunnel instructions and continue to
    // `wait_for_callback`. The user sets up port-forwarding on the
    // GUI machine, opens the auth URL there, and Google's redirect
    // to `http://127.0.0.1:<port>/callback` resolves through the
    // tunnel back to this listener.
    if let Err(e) = open_browser(&auth_url) {
        eprintln!("(could not auto-open browser: {e})");
        eprintln!();
        eprintln!("Headless OAuth — complete from a GUI machine:");
        eprintln!("  1. On your GUI machine, set up SSH port forwarding:");
        eprintln!("       ssh -L {port}:localhost:{port} <user@this-host>");
        eprintln!("  2. Open the auth URL above in that machine's browser.");
        eprintln!("  3. Complete the Google sign-in flow.");
        eprintln!("     Google will redirect to http://127.0.0.1:{port}/callback,");
        eprintln!("     which reaches this listener through the tunnel.");
        eprintln!();
        let _ = std::io::stderr().flush();
    }

    // Step 5: accept callback (loop until we get a valid code+state pair,
    // or deadline elapses). State verification happens INSIDE
    // `wait_for_callback` so the success-page HTML is only rendered to
    // the browser after CSRF state matches — see redteam round 1 H2.
    let deadline = SystemTime::now() + FLOW_TIMEOUT;
    finish_after_browser(
        || wait_for_callback_controlled(&listener, deadline, &state, &cancelled),
        before_exchange,
        |code| {
            // Step 7: exchange code for tokens.
            let token_response =
                exchange_code(&code, &verifier, &redirect_uri, &client_id, &client_secret)
                    .map_err(|e| OauthFlowError::TokenExchange(e.to_string()))?;

            // Step 8: write `~/.gemini/oauth_creds.json`.
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let creds = OauthCreds {
                access_token: token_response.access_token,
                refresh_token: token_response.refresh_token.unwrap_or_default(),
                scope: token_response.scope,
                token_type: token_response.token_type,
                id_token: token_response.id_token.unwrap_or_default(),
                expiry_date: now_ms + token_response.expires_in * 1000,
            };
            write_oauth_creds(&creds)
        },
    )
    .inspect(|_admission| {
        eprintln!("==> Sign-in complete; tokens written to ~/.gemini/oauth_creds.json");
        let _ = std::io::stderr().flush();
    })
}

fn finish_after_browser<P, C>(
    wait: impl FnOnce() -> Result<C, OauthFlowError>,
    before_exchange: impl FnOnce() -> Result<P, OauthFlowError>,
    commit: impl FnOnce(C) -> Result<(), OauthFlowError>,
) -> Result<P, OauthFlowError> {
    let code = wait()?;
    mint_and_persist(before_exchange, || commit(code))
}

/// Never acquire admission during the browser wait, or release it between
/// exchange and persistence. This seam contains no provider or host discovery.
fn mint_and_persist<P>(
    before_exchange: impl FnOnce() -> Result<P, OauthFlowError>,
    commit: impl FnOnce() -> Result<(), OauthFlowError>,
) -> Result<P, OauthFlowError> {
    let admission = before_exchange()?;
    commit()?;
    Ok(admission)
}

/// Generate a 64-char URL-safe-base64 PKCE verifier + its S256 challenge.
/// Uses `getrandom` (the same OS-CSPRNG path the Anthropic PKCE module
/// uses) to avoid pulling in the heavier `rand` crate.
fn generate_pkce() -> (String, String) {
    let mut bytes = [0u8; 48];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    (verifier, challenge)
}

/// 32-byte CSPRNG state token, URL-safe-base64 encoded.
fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS CSPRNG unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Minimal URL-encode for query parameters. Encodes anything that's
/// not unreserved per RFC 3986 §2.3 (alphanumeric + `-_.~`). Sufficient
/// for OAuth client_ids, redirect URIs, base64url-encoded values.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Open `url` in the user's default browser. Cross-platform helper
/// mirroring `csq/src/cli/commands/login.rs::open_in_browser`.
///
/// Returns `Err("headless: ...")` when running on Linux without
/// `$DISPLAY` or `$WAYLAND_DISPLAY` set — the caller is expected to
/// fall through to the "print the URL, ask the user to open it
/// manually" branch. This avoids spawning a Chromium subprocess that
/// would emit `ozone_platform_x11` errors and pollute csq's stdio.
fn open_browser(url: &str) -> Result<(), String> {
    use std::process::Command;

    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none_or(|v| v.is_empty())
        && std::env::var_os("WAYLAND_DISPLAY").is_none_or(|v| v.is_empty())
    {
        let _ = url;
        return Err("headless: no DISPLAY/WAYLAND_DISPLAY available".into());
    }

    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "linux")]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        // Suppress noise from whatever browser xdg-open spawns when
        // the GUI session is degraded (e.g. broken Wayland setup).
        c.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/c", "start", "", url]);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err("no browser-open helper for this platform".into());

    cmd.status()
        .map_err(|e| format!("spawn browser opener: {e}"))?
        .success()
        .then_some(())
        .ok_or_else(|| "browser opener exited non-zero".into())
}

/// Wall-clock budget for ONE accepted callback connection, from accept to
/// the end of its request head. Enforced by [`DeadlineReader`], which
/// re-arms `SO_RCVTIMEO` with the REMAINING budget before every read, so a
/// client dripping one byte per interval cannot hold the loop past it.
const CALLBACK_CONN_BUDGET: Duration = Duration::from_secs(5);

/// Byte cap on one connection's request head. A loopback client can send
/// far more than any real callback inside [`CALLBACK_CONN_BUDGET`]; the cap
/// bounds the memory one connection can make `read_line` buffer.
const CALLBACK_MAX_HEAD_BYTES: u64 = 16 * 1024;

/// Block on the loopback listener until either:
/// - a valid `GET /callback?code=…&state=…` arrives whose `state` matches
///   `expected_state` → render success-page HTML and return `Ok(code)`
/// - the same callback arrives but with a state mismatch → render
///   failure-page HTML with HTTP 400 and return `Err(StateMismatch)`
/// - the deadline elapses → `Timeout`
/// - any other malformed/non-callback request → respond 4xx and KEEP
///   LISTENING (back-button reloads, generic probes, browser pre-fetches
///   must not abort the whole flow). Origin: redteam round 1 H2 + M1.
/// - a connection whose socket setup or read fails (a peer that reset,
///   closed early, or stayed silent past [`CALLBACK_CONN_BUDGET`]) → that
///   connection is dropped with a fixed-vocabulary warning and the loop
///   KEEPS LISTENING. Origin: darwin returns EINVAL from
///   `setsockopt(SO_RCVTIMEO)` on an accepted stream whose peer already
///   reset; that one stray connection used to abort the whole login as
///   `LoopbackBind`.
///
/// `listener.accept()` errors that describe ONE pending connection (aborted,
/// reset or interrupted, plus Linux's pending-network-error set — see
/// [`crate::oauth::loopback::accept_error_kind`]) are dropped the same way;
/// a repeat with no successful accept in between backs off 100 ms like
/// `WouldBlock`. Every other accept error (EMFILE, ENFILE, EBADF, EINVAL,
/// ENOTSOCK, …) describes the listener and still aborts as `LoopbackBind`.
fn wait_for_callback_controlled(
    listener: &TcpListener,
    deadline: SystemTime,
    expected_state: &str,
    cancelled: &impl Fn() -> bool,
) -> Result<String, OauthFlowError> {
    wait_for_callback_with_budget(
        listener,
        deadline,
        expected_state,
        cancelled,
        CALLBACK_CONN_BUDGET,
    )
}

fn wait_for_callback_with_budget(
    listener: &TcpListener,
    deadline: SystemTime,
    expected_state: &str,
    cancelled: &impl Fn() -> bool,
    conn_budget: Duration,
) -> Result<String, OauthFlowError> {
    eprintln!(
        "==> Waiting for browser callback on http://127.0.0.1:{}/callback ...",
        listener.local_addr().map(|a| a.port()).unwrap_or(0)
    );
    let _ = std::io::stderr().flush();

    listener
        .set_nonblocking(true)
        .map_err(OauthFlowError::LoopbackBind)?;

    let mut consecutive_accept_drops: u32 = 0;
    loop {
        if cancelled() {
            return Err(OauthFlowError::Aborted);
        }
        let now = SystemTime::now();
        if now >= deadline {
            return Err(OauthFlowError::Timeout {
                timeout_secs: FLOW_TIMEOUT.as_secs(),
            });
        }
        match listener.accept() {
            Ok((stream, _)) => {
                consecutive_accept_drops = 0;
                match serve_callback_conn(stream, expected_state, cancelled, conn_budget, deadline)
                {
                    ConnOutcome::Code(code) => return Ok(code),
                    ConnOutcome::Fail(e) => return Err(e),
                    ConnOutcome::KeepListening => continue,
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => match crate::oauth::loopback::accept_error_kind(&e) {
                Some(kind) => {
                    tracing::warn!(
                        error_kind = "oauth_callback_accept_dropped",
                        kind,
                        "dropped one pending loopback callback connection; still listening"
                    );
                    consecutive_accept_drops += 1;
                    if consecutive_accept_drops > 1 {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                None => return Err(OauthFlowError::LoopbackBind(e)),
            },
        }
    }
}

/// What one accepted connection means for the accept loop.
enum ConnOutcome {
    /// State-verified callback: the flow returns this code.
    Code(String),
    /// Flow-terminating outcome (state mismatch, cancellation).
    Fail(OauthFlowError),
    /// This connection is finished or dropped; keep accepting.
    KeepListening,
}

/// Logs that one connection was dropped. Fixed vocabulary only: never the
/// io error, the request line, the query string, or any code/state value
/// (security.md Rules 2 and 8).
fn drop_conn(stage: &'static str) -> ConnOutcome {
    tracing::warn!(
        error_kind = "oauth_callback_conn_dropped",
        stage,
        "dropped one loopback callback connection; still listening"
    );
    ConnOutcome::KeepListening
}

/// Best-effort response write. A failure only means the browser will not
/// see the page; it never changes the flow's outcome, so it is logged with
/// a fixed tag and otherwise ignored.
fn write_response(stream: &mut std::net::TcpStream, bytes: &[u8], stage: &'static str) {
    if stream
        .write_all(bytes)
        .and_then(|()| stream.flush())
        .is_err()
    {
        tracing::warn!(
            error_kind = "oauth_callback_response_write_failed",
            stage,
            "could not write the loopback callback response"
        );
    }
}

/// A `Read` over the accepted stream that enforces one wall-clock deadline
/// across ALL reads, not a fresh timeout per syscall.
struct DeadlineReader {
    stream: std::net::TcpStream,
    deadline: std::time::Instant,
}

impl std::io::Read for DeadlineReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buf)
    }
}

fn serve_callback_conn(
    mut stream: std::net::TcpStream,
    expected_state: &str,
    cancelled: &impl Fn() -> bool,
    conn_budget: Duration,
    flow_deadline: SystemTime,
) -> ConnOutcome {
    use std::io::Read as _;

    // The connection never outlives the flow: its budget is the smaller of
    // `conn_budget` and the time left before the flow deadline. A deadline
    // already passed — including a FORWARD wall-clock step past it — leaves
    // zero; a BACKWARD step only inflates `flow_left`, which `conn_budget`
    // still caps.
    let flow_left = flow_deadline
        .duration_since(SystemTime::now())
        .unwrap_or(Duration::ZERO);
    let budget = conn_budget.min(flow_left);
    if budget.is_zero() {
        // `set_read_timeout(Some(ZERO))` is an error, and there is no time
        // left to read anyway; the loop reports `Timeout` next.
        return drop_conn("flow_deadline");
    }
    let conn_deadline = std::time::Instant::now() + budget;
    // The listener is non-blocking, and on BSD-derived kernels (macOS) an
    // accepted socket inherits O_NONBLOCK, so a read would return
    // WouldBlock at once instead of honouring the read timeout. Force
    // blocking mode so the timeout below is what bounds the read.
    if stream.set_nonblocking(false).is_err() {
        return drop_conn("set_blocking");
    }
    // A connection whose timeout cannot be set is DROPPED, never read
    // unbounded: an untimed read would let one silent client stall login.
    if stream.set_read_timeout(Some(budget)).is_err() {
        return drop_conn("set_read_timeout");
    }
    let read_half = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return drop_conn("try_clone"),
    };
    let mut reader = BufReader::new(
        DeadlineReader {
            stream: read_half,
            deadline: conn_deadline,
        }
        .take(CALLBACK_MAX_HEAD_BYTES),
    );
    let mut request_line = String::new();
    if let Err(e) = reader.read_line(&mut request_line) {
        return drop_conn(match e.kind() {
            std::io::ErrorKind::TimedOut => "read_request_line_timed_out",
            std::io::ErrorKind::WouldBlock => "read_request_line_would_block",
            _ => "read_request_line_other",
        });
    }
    // No terminating newline means the line was cut at
    // [`CALLBACK_MAX_HEAD_BYTES`] or the peer closed mid-line. A truncated
    // line is never parsed: its query could carry a partial code.
    if request_line.is_empty() {
        return drop_conn("closed_before_request");
    }
    if !request_line.ends_with('\n') {
        return drop_conn("request_line_unterminated");
    }
    // Example: "GET /callback?code=abc&state=xyz HTTP/1.1"
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "GET" {
        write_response(
            &mut stream,
            b"HTTP/1.1 405 Method Not Allowed\r\n\
              Content-Type: text/plain\r\n\
              Content-Length: 18\r\n\
              Connection: close\r\n\
              \r\n\
              method not allowed",
            "write_405",
        );
        return ConnOutcome::KeepListening;
    }
    let target = parts[1];
    if !target.starts_with("/callback") {
        write_response(
            &mut stream,
            b"HTTP/1.1 404 Not Found\r\n\
              Content-Type: text/plain\r\n\
              Content-Length: 9\r\n\
              Connection: close\r\n\
              \r\n\
              not found",
            "write_404",
        );
        return ConnOutcome::KeepListening;
    }
    // Drain headers (we don't strictly need them).
    let mut hdr = String::new();
    loop {
        match reader.read_line(&mut hdr) {
            Ok(n) if n > 2 => {
                if cancelled() {
                    return ConnOutcome::Fail(OauthFlowError::Aborted);
                }
                hdr.clear();
            }
            Ok(_) => break,
            Err(_) => return drop_conn("read_headers"),
        }
    }
    let (code, state) = match parse_callback_query(target) {
        Some(pair) => pair,
        None => {
            // Malformed callback (e.g., browser back-button
            // re-navigation, OAuth provider error path with
            // ?error=... and no ?code=...). Respond 400 and
            // keep listening — the legit callback may still
            // arrive on a subsequent connection. Origin: M1.
            write_response(
                &mut stream,
                b"HTTP/1.1 400 Bad Request\r\n\
                  Content-Type: text/plain\r\n\
                  Content-Length: 26\r\n\
                  Connection: close\r\n\
                  \r\n\
                  missing code/state params",
                "write_400",
            );
            return ConnOutcome::KeepListening;
        }
    };
    // CRITICAL: state verification MUST precede success-HTML
    // rendering. An attacker landing a forged callback on the
    // loopback (port discoverable by guessing 49152..65535
    // once a flow is in progress) could otherwise see a
    // confirmed-looking "Signed in successfully" page in their
    // browser even though csq aborts the exchange. Origin: H2.
    if state != expected_state {
        let html = failure_html(
            "Sign-in failed (state mismatch)",
            "csq received a callback whose CSRF state token does not match the one it generated. This can happen if you opened the OAuth link in a different browser session, or if a forged callback was injected.",
        );
        let body_len = html.len();
        let resp = format!(
            "HTTP/1.1 400 Bad Request\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {body_len}\r\n\
             Connection: close\r\n\
             \r\n\
             {html}"
        );
        write_response(&mut stream, resp.as_bytes(), "write_state_mismatch");
        return ConnOutcome::Fail(OauthFlowError::StateMismatch);
    }
    let html = success_html();
    let body_len = html.len();
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {body_len}\r\n\
         Connection: close\r\n\
         \r\n\
         {html}"
    );
    // The state already matched: a failed page write (tab closed) must not
    // discard a verified code.
    write_response(&mut stream, resp.as_bytes(), "write_success");
    ConnOutcome::Code(code)
}

/// Parses `code` and `state` from a request target like
/// `/callback?code=ABC&state=XYZ`. Returns `None` if either is missing.
fn parse_callback_query(target: &str) -> Option<(String, String)> {
    let q = target.split_once('?')?.1;
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        let decoded = url_decode(v);
        match k {
            "code" => code = Some(decoded),
            "state" => state = Some(decoded),
            _ => {}
        }
    }
    match (code, state) {
        (Some(c), Some(s)) => Some((c, s)),
        _ => None,
    }
}

/// Minimal URL-decoder for query-string values. Handles `%XX` escapes
/// and `+` → space.
fn url_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h * 16) + l) as u8 as char);
                i += 3;
                continue;
            }
        }
        if b == b'+' {
            out.push(' ');
        } else {
            out.push(b as char);
        }
        i += 1;
    }
    out
}

/// Renders an error page shown to the user's browser when the OAuth
/// flow fails inside the loopback handler (state mismatch, etc).
/// Mirrors `success_html`'s style but with a red accent. Used by
/// `wait_for_callback` so the browser's view matches csq's verdict —
/// see redteam round 1 H2.
fn failure_html(title: &str, detail: &str) -> String {
    let title_esc = html_escape(title);
    let detail_esc = html_escape(detail);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign-in failed</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 3rem; background: #1a1a1a; color: #e0e0e0; }}
  .card {{ max-width: 480px; margin: 0 auto; background: #2a2a2a; padding: 2rem; border-radius: 8px; border-left: 4px solid #d32f2f; }}
  h1 {{ margin-top: 0; color: #f44336; }}
  p {{ line-height: 1.5; }}
</style>
</head>
<body>
  <div class="card">
    <h1>{title_esc}</h1>
    <p>{detail_esc}</p>
    <p>Return to your terminal — csq has aborted the sign-in. You can re-run <code>csq login --provider gemini</code> to try again.</p>
  </div>
</body>
</html>
"#
    )
}

/// Minimal HTML escape for failure-page user-facing strings.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn success_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign-in complete</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 3rem; background: #1a1a1a; color: #e0e0e0; }
  .card { max-width: 480px; margin: 0 auto; background: #2a2a2a; padding: 2rem; border-radius: 8px; border-left: 4px solid #4caf50; }
  h1 { margin-top: 0; color: #4caf50; }
  p { line-height: 1.5; }
  code { background: #1a1a1a; padding: 0.1em 0.4em; border-radius: 3px; font-size: 0.95em; }
</style>
</head>
<body>
  <div class="card">
    <h1>Signed in successfully</h1>
    <p>csq has captured your Code Assist OAuth tokens. You can close this tab.</p>
    <p>Return to your terminal — the <code>csq login --provider gemini</code> command should now finish in a moment.</p>
  </div>
</body>
</html>
"#
    .to_string()
}

/// Exchange the auth code for OAuth tokens at Google's token endpoint.
/// Uses gemini-cli's discovered client_id/client_secret + the PKCE
/// verifier so a leaked auth code is unusable to anyone without the
/// verifier.
fn exchange_code(
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<TokenResponse, anyhow::Error> {
    use anyhow::Context;
    let body = format!(
        "code={code}&\
         client_id={client_id_enc}&\
         client_secret={client_secret_enc}&\
         redirect_uri={redirect}&\
         grant_type=authorization_code&\
         code_verifier={verifier}",
        code = url_encode(code),
        client_id_enc = url_encode(client_id),
        client_secret_enc = url_encode(client_secret),
        redirect = url_encode(redirect_uri),
        verifier = url_encode(verifier),
    );
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build reqwest client")?;
    let response = client
        .post(TOKEN_ENDPOINT)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .context("POST oauth2.googleapis.com/token")?;
    let status = response.status();
    let bytes = response.bytes().context("read token response body")?;
    if !status.is_success() {
        let body_str = String::from_utf8_lossy(&bytes);
        // The request carried the auth code, PKCE verifier and client secret:
        // scrub all three structurally before shape redaction and the cut.
        let redacted = crate::error::redact_excerpt_with_secrets(
            &bytes,
            &[code, verifier, client_secret],
            256,
        );
        return Err(anyhow::anyhow!(
            "token endpoint returned HTTP {status}: {redacted} (raw len: {})",
            body_str.len()
        ));
    }
    // CAUTION: do NOT use `serde_json::from_slice(...).context(...)` here.
    // serde_json::Error::Display echoes the offending field VALUE on type
    // mismatches, and Google refresh tokens (prefix `1//`) live in this
    // response body — a malformed JSON shape with the right field type
    // could surface a refresh-token fragment via the error chain.
    // `redact_tokens` covers the `1//` prefix as defense-in-depth, but
    // structural defense lives here: drop the serde error message entirely.
    // Origin: redteam round 1 H1 (an internal journal entry).
    let parsed: TokenResponse = serde_json::from_slice(&bytes).map_err(|_| {
        anyhow::anyhow!(
            "token endpoint returned malformed JSON (len={})",
            bytes.len()
        )
    })?;
    Ok(parsed)
}

/// Atomically writes the OAuth creds to `~/.gemini/oauth_creds.json`
/// at mode 0600.
fn write_oauth_creds(creds: &OauthCreds) -> Result<(), OauthFlowError> {
    // The shared home resolver (`dirs::home_dir`: HOME on unix, the known-folder API
    // on Windows where HOME is usually unset), the same one the daemon-start
    // integrity-label sweep uses for this file.
    let home = crate::platform::home::home_dir()
        .filter(|h| !h.as_os_str().is_empty())
        .ok_or(OauthFlowError::HomeNotSet)?;
    let gemini_dir = home.join(".gemini");
    std::fs::create_dir_all(&gemini_dir).map_err(|e| OauthFlowError::WriteFailed {
        path: gemini_dir.clone(),
        reason: format!("mkdir: {e}"),
    })?;
    let path = gemini_dir.join("oauth_creds.json");
    let json = serde_json::to_string_pretty(creds).map_err(|e| OauthFlowError::WriteFailed {
        path: path.clone(),
        reason: format!("serialize: {e}"),
    })?;
    // §5a: `write_new_private` creates the tmp file at 0o600 at creation,
    // closing the window a separate `std::fs::write` + `secure_file` pair
    // would leave open for this OAuth-credential-bearing tmp file.
    let tmp = unique_tmp_path(&path);
    if let Err(e) = write_new_private(&tmp, json.as_bytes()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(OauthFlowError::WriteFailed {
            path: tmp,
            reason: format!("write: {e}"),
        });
    }
    if let Err(e) = atomic_replace(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(OauthFlowError::WriteFailed {
            path,
            reason: format!("atomic_replace: {e}"),
        });
    }
    Ok(())
}

/// Locates `gemini` on PATH, walks up to its bundle directory, and
/// extracts the OAuth client_id + client_secret by greping the
/// bundle's `.js` files. Cached for the process lifetime so the
/// filesystem scan happens at most once per `csq login` invocation.
///
/// Returns `Err(reason)` if:
/// - `gemini` is not on PATH
/// - the binary's bundle directory cannot be located
/// - no client_id / client_secret pattern matches in the bundle
fn discover_gemini_oauth_credentials() -> Result<(String, String), String> {
    use std::sync::OnceLock;
    // Cache only Ok results. Caching Err would trap a transient failure
    // (gemini-cli not yet installed at first call) for the entire
    // process lifetime — and the daemon is long-running. Origin:
    // redteam round 1 M2.
    static CACHE: OnceLock<(String, String)> = OnceLock::new();
    if let Some(v) = CACHE.get() {
        return Ok(v.clone());
    }
    let bundle_dir = locate_gemini_bundle_dir()?;
    let creds = scan_bundle_for_oauth_creds(&bundle_dir)?;
    let _ = CACHE.set(creds.clone());
    Ok(creds)
}

/// Finds the directory containing gemini-cli's bundled JS files. The
/// `gemini` shim symlinks into the package's `bundle/` directory; we
/// resolve the real path and walk up to find `bundle/`.
fn locate_gemini_bundle_dir() -> Result<PathBuf, String> {
    // Walk PATH directly rather than spawning `which`. A user-writable
    // directory earlier in PATH containing a `which` shim would otherwise
    // get executed and could redirect to a fake bundle. Origin: redteam
    // round 1 M4.
    let bin_path_str =
        which_gemini_on_path().ok_or_else(|| "`gemini` binary not found on PATH".to_string())?;
    let bin_path = std::fs::canonicalize(&bin_path_str)
        .map_err(|e| format!("could not resolve gemini binary path '{bin_path_str}': {e}"))?;
    // The resolved binary is typically at
    // `<root>/lib/node_modules/@google/gemini-cli/bundle/gemini.js`
    // so the bundle dir is the parent. Walk up looking for a sibling
    // `bundle` dir that contains `*.js` files matching the OAuth
    // client_id / client_secret patterns.
    if let Some(parent) = bin_path.parent() {
        // Direct parent might already be the bundle dir.
        if parent
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s == "bundle")
            .unwrap_or(false)
        {
            return Ok(parent.to_path_buf());
        }
    }
    // Search ancestors for a `bundle` subdirectory.
    for ancestor in bin_path.ancestors() {
        let candidate = ancestor.join("bundle");
        if candidate.is_dir() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "could not locate `bundle/` directory near gemini binary at {}",
        bin_path.display()
    ))
}

/// Greps the bundle's `.js` files for gemini-cli's OAuth client_id +
/// client_secret. Specifically looks for the bundled JS variables
/// `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` — NOT
/// `CLOUD_SDK_CLIENT_ID` (gcloud SDK; different OAuth purpose) or any
/// other `*.apps.googleusercontent.com` literal that may appear in
/// the bundle for unrelated reasons.
///
/// The bundled definitions look like:
/// ```js
/// var OAUTH_CLIENT_ID = "681255809395-...apps.googleusercontent.com";
/// var OAUTH_CLIENT_SECRET = "GOCSPX-...";
/// ```
/// Hard cap on how many bytes we'll read from any single bundle JS file
/// while scanning for OAuth credentials. Real gemini-cli bundles ship a
/// single ~5 MB `gemini.js`; this cap defeats a multi-GB bait file from
/// a hijacked / malicious npm-installed sibling that masquerades as
/// `gemini-cli` and exhausts memory during login. Origin: redteam round
/// 1 M3.
const BUNDLE_JS_READ_CAP_BYTES: u64 = 16 * 1024 * 1024;

fn scan_bundle_for_oauth_creds(bundle_dir: &Path) -> Result<(String, String), String> {
    use std::io::Read;
    let entries = std::fs::read_dir(bundle_dir)
        .map_err(|e| format!("read bundle dir {}: {e}", bundle_dir.display()))?;
    let mut client_id: Option<String> = None;
    let mut client_secret: Option<String> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("js") {
            continue;
        }
        // Bounded read: cap at BUNDLE_JS_READ_CAP_BYTES. A file at the
        // cap is treated as suspicious and skipped (not silently
        // truncated) so a bait file does not drop a real match further
        // in the directory.
        let mut body = String::new();
        let mut handle = match std::fs::File::open(&path) {
            Ok(f) => f.take(BUNDLE_JS_READ_CAP_BYTES + 1),
            Err(_) => continue,
        };
        if handle.read_to_string(&mut body).is_err() {
            continue;
        }
        if body.len() as u64 > BUNDLE_JS_READ_CAP_BYTES {
            tracing::warn!(
                error_kind = "gemini_bundle_js_too_large",
                path = %path.display(),
                cap_bytes = BUNDLE_JS_READ_CAP_BYTES,
                "skipping oversize bundle JS file during OAuth credential scan"
            );
            continue;
        }
        if client_id.is_none() {
            client_id = extract_assigned_string(&body, "OAUTH_CLIENT_ID")
                .filter(|s| s.ends_with(".apps.googleusercontent.com"));
        }
        if client_secret.is_none() {
            client_secret = extract_assigned_string(&body, "OAUTH_CLIENT_SECRET")
                .filter(|s| s.starts_with("GOCSPX-") && s.len() >= 20);
        }
        if client_id.is_some() && client_secret.is_some() {
            break;
        }
    }
    match (client_id, client_secret) {
        (Some(id), Some(secret)) => Ok((id, secret)),
        (None, _) => Err("OAUTH_CLIENT_ID variable not found in gemini-cli bundle — \
             gemini-cli may have rotated their OAuth client (the bundle \
             previously used `var OAUTH_CLIENT_ID = \"...\"`); check \
             bundle/*.js for the new variable name and update \
             scan_bundle_for_oauth_creds in csq's oauth_flow.rs"
            .into()),
        (_, None) => Err(
            "OAUTH_CLIENT_SECRET variable not found in gemini-cli bundle — \
             same diagnostic as the client_id path above"
                .into(),
        ),
    }
}

/// Walks `$PATH` looking for an executable `gemini` binary. Returns
/// the first match, or `None` if no such file is found. Used in place
/// of `Command::new("which")` to defeat the PATH-controlled-which
/// attack: a user-writable directory earlier in `$PATH` containing a
/// `which` shim would otherwise get executed and could feed a forged
/// path into the bundle scan. Origin: redteam round 1 M4.
fn which_gemini_on_path() -> Option<String> {
    let path = std::env::var_os("PATH")?;
    #[cfg(unix)]
    let candidate_names: &[&str] = &["gemini"];
    #[cfg(windows)]
    let candidate_names: &[&str] = &["gemini.cmd", "gemini.exe", "gemini"];
    for dir in std::env::split_paths(&path) {
        for name in candidate_names {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

#[cfg(windows)]
fn is_executable_file(p: &Path) -> bool {
    matches!(std::fs::metadata(p), Ok(m) if m.is_file())
}

/// Extracts the string literal RHS of a JS assignment of the form
/// `<var_name> = "<string>"` (or `:`-separated for property syntax).
/// Returns `None` if the pattern isn't found. Tolerates common JS
/// minification artefacts (no whitespace around `=`, single or double
/// quotes).
fn extract_assigned_string(body: &str, var_name: &str) -> Option<String> {
    // Find every occurrence of the variable name; for each, look
    // forward for the string literal RHS.
    let mut search_from = 0usize;
    while let Some(idx) = body[search_from..].find(var_name) {
        let abs = search_from + idx;
        let after = &body[abs + var_name.len()..];
        // Skip optional whitespace + `=` or `:`.
        let mut chars = after.chars().peekable();
        let mut consumed = 0usize;
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                chars.next();
                consumed += c.len_utf8();
            } else if c == '=' || c == ':' {
                chars.next();
                consumed += c.len_utf8();
                break;
            } else {
                // Not an assignment pattern; this match is a different
                // identifier (e.g. inside a longer name). Skip to the
                // next occurrence.
                consumed = 0;
                break;
            }
        }
        if consumed == 0 {
            search_from = abs + var_name.len();
            continue;
        }
        let after_eq = &after[consumed..];
        // Skip whitespace, then expect a string literal.
        let mut start = 0usize;
        for (i, c) in after_eq.char_indices() {
            if !c.is_whitespace() {
                start = i;
                break;
            }
        }
        let rest = &after_eq[start..];
        let quote = rest.chars().next()?;
        if quote != '"' && quote != '\'' {
            search_from = abs + var_name.len();
            continue;
        }
        let body_after_quote = &rest[quote.len_utf8()..];
        // Find the matching close quote; assume no escapes for these
        // OAuth literals (they don't contain backslashes).
        let close = body_after_quote.find(quote)?;
        let value = &body_after_quote[..close];
        return Some(value.to_string());
    }
    None
}

/// Test seam: writes a minimal credential file through the production writer
/// ([`write_oauth_creds`]) so a parity test can prove the writer, the usage poller and the
/// headless check resolve the same home directory.
#[cfg(test)]
pub(crate) fn write_creds_for_test(
    access_token: &str,
    expiry_date: i64,
) -> Result<(), OauthFlowError> {
    write_oauth_creds(&OauthCreds {
        access_token: access_token.to_string(),
        refresh_token: "1//parity".to_string(),
        scope: "parity".to_string(),
        token_type: "Bearer".to_string(),
        id_token: String::new(),
        expiry_date,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Debug redaction (credential-type-hygiene Rule 1) ─────────

    #[test]
    fn oauth_creds_debug_redacts_every_token_field() {
        let creds: OauthCreds = serde_json::from_str(
            r#"{"access_token":"ya29-SECRET-ACCESS","refresh_token":"1//SECRET-REFRESH",
                 "scope":"https://www.googleapis.com/auth/cloud-platform",
                 "token_type":"Bearer","id_token":"eyJ-SECRET-ID","expiry_date":1775726524877}"#,
        )
        .expect("fixture should deserialize");

        // Non-vacuity: the fixture really does carry the secrets.
        assert_eq!(creds.access_token, "ya29-SECRET-ACCESS");

        let rendered = format!("{creds:?}");
        for secret in ["ya29-SECRET-ACCESS", "1//SECRET-REFRESH", "eyJ-SECRET-ID"] {
            assert!(
                !rendered.contains(secret),
                "Debug leaked {secret}: {rendered}"
            );
        }
        assert!(
            rendered.contains("<redacted>"),
            "no redaction placeholder: {rendered}"
        );
        // Serialize is untouched — this struct IS the on-disk shape.
        let json = serde_json::to_string(&creds).expect("should serialize");
        assert!(
            json.contains("ya29-SECRET-ACCESS"),
            "redaction must not reach the on-disk write path: {json}"
        );
    }

    #[test]
    fn token_response_debug_redacts_every_token_field() {
        let tr: TokenResponse = serde_json::from_str(
            r#"{"access_token":"ya29-SECRET-ACCESS","refresh_token":"1//SECRET-REFRESH",
                 "expires_in":3599,"scope":"openid","token_type":"Bearer",
                 "id_token":"eyJ-SECRET-ID"}"#,
        )
        .expect("fixture should deserialize");

        assert_eq!(tr.access_token, "ya29-SECRET-ACCESS");

        let rendered = format!("{tr:?}");
        for secret in ["ya29-SECRET-ACCESS", "1//SECRET-REFRESH", "eyJ-SECRET-ID"] {
            assert!(
                !rendered.contains(secret),
                "Debug leaked {secret}: {rendered}"
            );
        }
        assert!(
            rendered.contains("<redacted>"),
            "no redaction placeholder: {rendered}"
        );
        assert!(
            rendered.contains("3599"),
            "expires_in was masked: {rendered}"
        );
    }

    #[test]
    fn token_response_debug_distinguishes_absent_from_redacted() {
        let tr: TokenResponse = serde_json::from_str(
            r#"{"access_token":"ya29-only","expires_in":3599,"scope":"openid",
                 "token_type":"Bearer"}"#,
        )
        .expect("fixture should deserialize");
        let rendered = format!("{tr:?}");
        assert!(
            rendered.contains("refresh_token: None") && rendered.contains("id_token: None"),
            "absent optionals should render None, got: {rendered}"
        );
        assert!(!rendered.contains("ya29-only"), "leaked: {rendered}");
    }

    #[test]
    fn extract_assigned_string_handles_minified_js() {
        let body = r#"var OAUTH_CLIENT_ID="abc-123.apps.googleusercontent.com";"#;
        assert_eq!(
            extract_assigned_string(body, "OAUTH_CLIENT_ID").as_deref(),
            Some("abc-123.apps.googleusercontent.com")
        );
    }

    #[test]
    fn extract_assigned_string_handles_whitespace() {
        let body = r#"var OAUTH_CLIENT_SECRET = "GOCSPX-test123abc";"#;
        assert_eq!(
            extract_assigned_string(body, "OAUTH_CLIENT_SECRET").as_deref(),
            Some("GOCSPX-test123abc")
        );
    }

    #[test]
    fn extract_assigned_string_skips_property_references() {
        // The JS body references the variable in a config object before
        // declaring it. extract_assigned_string should still find the
        // declaration, not the reference.
        let body = r#"
            const config = { client_id: OAUTH_CLIENT_ID };
            var OAUTH_CLIENT_ID = "real-value";
        "#;
        assert_eq!(
            extract_assigned_string(body, "OAUTH_CLIENT_ID").as_deref(),
            Some("real-value")
        );
    }

    #[test]
    fn extract_assigned_string_returns_none_when_absent() {
        let body = "var SOMETHING_ELSE = \"abc\";";
        assert!(extract_assigned_string(body, "OAUTH_CLIENT_ID").is_none());
    }

    #[test]
    fn extract_assigned_string_does_not_confuse_cloud_sdk_var() {
        // Real-bundle case: CLOUD_SDK_CLIENT_ID appears alphabetically
        // first; OAUTH_CLIENT_ID is the one we want. The function must
        // pick OAUTH_CLIENT_ID, not match-prefix to the wrong var.
        let body = r#"
            exports2.CLOUD_SDK_CLIENT_ID = "gcloud-sdk.apps.googleusercontent.com";
            var OAUTH_CLIENT_ID = "gemini-cli.apps.googleusercontent.com";
        "#;
        assert_eq!(
            extract_assigned_string(body, "OAUTH_CLIENT_ID").as_deref(),
            Some("gemini-cli.apps.googleusercontent.com")
        );
    }

    #[test]
    fn url_encode_handles_unreserved() {
        assert_eq!(url_encode("abc-123_xyz.~"), "abc-123_xyz.~");
    }

    #[test]
    fn url_encode_escapes_reserved() {
        assert_eq!(url_encode("a+b c=d&e"), "a%2Bb%20c%3Dd%26e");
    }

    #[test]
    fn url_decode_round_trips() {
        let s = "https://example.com/cb?x=y z";
        assert_eq!(url_decode(&url_encode(s)), s);
    }

    #[test]
    fn parse_callback_query_extracts_code_and_state() {
        let (code, state) =
            parse_callback_query("/callback?code=abc&state=xyz").expect("expected pair");
        assert_eq!(code, "abc");
        assert_eq!(state, "xyz");
    }

    #[test]
    fn parse_callback_query_returns_none_on_missing_code() {
        assert!(parse_callback_query("/callback?state=xyz").is_none());
    }

    #[test]
    fn parse_callback_query_returns_none_on_missing_state() {
        assert!(parse_callback_query("/callback?code=abc").is_none());
    }

    #[test]
    fn pkce_verifier_and_challenge_have_expected_lengths() {
        let (v, c) = generate_pkce();
        // 48 bytes → 64 chars base64url-no-pad.
        assert_eq!(v.len(), 64);
        // SHA-256 → 32 bytes → 43 chars base64url-no-pad.
        assert_eq!(c.len(), 43);
    }

    #[test]
    fn state_token_has_expected_length() {
        let s = generate_state();
        // 32 bytes → 43 chars base64url-no-pad.
        assert_eq!(s.len(), 43);
    }
}

#[cfg(test)]
mod quit_boundary_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn gemini_quit_cancels_browser_wait_before_callback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let result = wait_for_callback_controlled(
            &listener,
            SystemTime::now() + Duration::from_secs(1),
            "fixture-state",
            &|| true,
        );
        assert!(matches!(result, Err(OauthFlowError::Aborted)));
    }

    #[test]
    fn gemini_browser_wait_precedes_mint_admission() {
        let callback_received = Cell::new(false);
        finish_after_browser(
            || {
                callback_received.set(true);
                Ok("fixture-code")
            },
            || {
                assert!(callback_received.get(), "browser wait held a write permit");
                Ok(())
            },
            |code| {
                assert_eq!(code, "fixture-code");
                Ok(())
            },
        )
        .unwrap();
    }

    #[test]
    fn gemini_closed_admission_never_enters_mint_or_persist() {
        let called = Cell::new(false);
        let result = mint_and_persist(
            || Err::<(), _>(OauthFlowError::Aborted),
            || {
                called.set(true);
                Ok(())
            },
        );
        assert!(matches!(result, Err(OauthFlowError::Aborted)));
        assert!(
            !called.get(),
            "a refused login must not start the token request"
        );
    }

    #[test]
    fn gemini_admission_survives_mint_and_persistence() {
        struct Guard<'a>(&'a Cell<bool>);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }
        let owned = Cell::new(false);
        let persisted = Cell::new(false);
        let permit = mint_and_persist(
            || {
                owned.set(true);
                Ok(Guard(&owned))
            },
            || {
                assert!(owned.get(), "commit lost its admitted writer");
                persisted.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(persisted.get());
        assert!(
            owned.get(),
            "binding caller must retain custody after token write"
        );
        drop(permit);
        assert!(!owned.get());
    }
}

// --- callback-conn-resilience tests ---
#[cfg(test)]
mod callback_conn_resilience_tests {
    use super::*;
    use std::io::Read;
    use std::net::{SocketAddr, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};

    const STATE: &str = "fixture-state";

    fn valid_callback(addr: SocketAddr) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(
            format!("GET /callback?code=good-code&state={STATE} HTTP/1.1\r\nHost: x\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        resp
    }

    /// Sends request bytes, then closes with SO_LINGER(0) so the peer sees
    /// a RESET. On darwin the server's later `setsockopt(SO_RCVTIMEO)` on
    /// this stream fails with EINVAL.
    #[cfg(unix)]
    fn reset_after_data(addr: SocketAddr) {
        use std::os::fd::AsRawFd;
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"GET /callback?code=stray").unwrap();
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        // SAFETY: the fd is owned by `s` and open for this call; `linger`
        // is a live, correctly sized `libc::linger` passed by pointer.
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&linger as *const libc::linger).cast::<libc::c_void>(),
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "SO_LINGER(0) must apply for the reset fixture");
        drop(s);
    }

    /// RESET (unix), FIN-before-any-bytes, and a silent open peer are all
    /// queued before the loop starts; the legitimate callback comes last.
    /// Every bad connection must be dropped and the flow must return the
    /// code. The silent peer reds the OLD code on every platform (its read
    /// timed out into `LoopbackBind`); the reset reds it first on darwin.
    #[test]
    fn stray_connections_are_dropped_and_valid_callback_still_returns_code() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (queued_tx, queued_rx) = mpsc::channel();
        let client = std::thread::spawn(move || {
            #[cfg(unix)]
            reset_after_data(addr);
            drop(TcpStream::connect(addr).unwrap());
            let silent = TcpStream::connect(addr).unwrap();
            queued_tx.send(()).unwrap();
            let resp = valid_callback(addr);
            drop(silent);
            resp
        });
        queued_rx.recv().unwrap();
        // Let the RST land before the first accept.
        std::thread::sleep(Duration::from_millis(100));
        let result = wait_for_callback_with_budget(
            &listener,
            SystemTime::now() + Duration::from_secs(30),
            STATE,
            &|| false,
            Duration::from_millis(300),
        );
        let resp = client.join().unwrap();
        assert!(
            matches!(result, Ok(ref c) if c == "good-code"),
            "flow must survive stray connections, got {result:?}"
        );
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "browser got: {resp:.40}"
        );
    }

    /// A browser that connects and only then writes its request (a normal
    /// TCP pattern) must be read, not dropped: the accepted stream must be
    /// in blocking mode under the read budget even though the listener is
    /// non-blocking.
    #[test]
    fn callback_whose_bytes_arrive_after_accept_is_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            std::thread::sleep(Duration::from_millis(400));
            s.write_all(
                format!("GET /callback?code=good-code&state={STATE} HTTP/1.1\r\n\r\n").as_bytes(),
            )
            .unwrap();
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
            resp
        });
        let result = wait_for_callback_with_budget(
            &listener,
            SystemTime::now() + Duration::from_secs(30),
            STATE,
            &|| false,
            Duration::from_secs(5),
        );
        let resp = client.join().unwrap();
        assert!(
            matches!(result, Ok(ref c) if c == "good-code"),
            "late-writing callback must be read, got {result:?}"
        );
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "browser got: {resp:.40}"
        );
    }

    /// A peer dripping one byte at a time never trips a per-syscall
    /// timeout; the per-connection wall-clock budget must cut it off so the
    /// legitimate callback queued behind it is served before the flow
    /// deadline.
    #[test]
    fn dripping_connection_is_cut_off_by_the_connection_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let drip_stop = Arc::clone(&stop);
        let (queued_tx, queued_rx) = mpsc::channel();
        let dripper = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            queued_tx.send(()).unwrap();
            // Self-bounded so code without a connection budget finishes
            // (late) instead of hanging the test forever.
            let give_up = std::time::Instant::now() + Duration::from_secs(6);
            while !drip_stop.load(Ordering::SeqCst) && std::time::Instant::now() < give_up {
                if s.write_all(b"G").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        queued_rx.recv().unwrap();
        let client = std::thread::spawn(move || valid_callback(addr));
        let started = std::time::Instant::now();
        let result = wait_for_callback_with_budget(
            &listener,
            SystemTime::now() + Duration::from_secs(8),
            STATE,
            &|| false,
            Duration::from_millis(400),
        );
        let elapsed = started.elapsed();
        stop.store(true, Ordering::SeqCst);
        let resp = client.join().unwrap();
        dripper.join().unwrap();
        assert!(
            matches!(result, Ok(ref c) if c == "good-code"),
            "dripping peer must not stall the login, got {result:?}"
        );
        // Budget 400 ms; the dripper runs 6 s. Without a wall-clock
        // budget the loop is held until the dripper gives up (>= 6 s).
        assert!(
            elapsed < Duration::from_secs(3),
            "dripping peer held the loop for {elapsed:?}"
        );
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "browser got: {resp:.40}"
        );
    }

    /// A request line longer than the head cap is cut mid-line. It must be
    /// dropped, never parsed: here the first 16 KiB carry a callback whose
    /// code is NOT the legitimate one, so parsing the truncated line would
    /// return `stray-code`.
    #[test]
    fn over_cap_request_line_is_dropped_not_parsed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (queued_tx, queued_rx) = mpsc::channel();
        let client = std::thread::spawn(move || {
            let mut big = TcpStream::connect(addr).unwrap();
            // Signal BEFORE the ~32 KiB write: the write can block until the
            // server reads, so the loop must already be running.
            queued_tx.send(()).unwrap();
            let pad = "a".repeat(2 * CALLBACK_MAX_HEAD_BYTES as usize);
            let line =
                format!("GET /callback?code=stray-code&state={STATE}&pad={pad} HTTP/1.1\r\n\r\n");
            // The server stops reading at the cap and drops the stream, so
            // the tail of this write may fail; that is expected.
            let _ = big.write_all(line.as_bytes());
            let resp = valid_callback(addr);
            drop(big);
            resp
        });
        queued_rx.recv().unwrap();
        let result = wait_for_callback_with_budget(
            &listener,
            SystemTime::now() + Duration::from_secs(30),
            STATE,
            &|| false,
            Duration::from_secs(2),
        );
        let resp = client.join().unwrap();
        assert!(
            matches!(result, Ok(ref c) if c == "good-code"),
            "over-cap request line must be dropped, got {result:?}"
        );
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "browser got: {resp:.40}"
        );
    }

    /// A silent connection must not hold the loop past the FLOW deadline
    /// even when the per-connection budget is longer.
    #[test]
    fn connection_budget_is_capped_by_the_flow_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let silent = TcpStream::connect(addr).unwrap();
        let started = std::time::Instant::now();
        let result = wait_for_callback_with_budget(
            &listener,
            SystemTime::now() + Duration::from_secs(1),
            STATE,
            &|| false,
            Duration::from_secs(20),
        );
        let elapsed = started.elapsed();
        drop(silent);
        assert!(
            matches!(result, Err(OauthFlowError::Timeout { .. })),
            "expected flow timeout, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "silent connection held the loop past the flow deadline: {elapsed:?}"
        );
    }
}
