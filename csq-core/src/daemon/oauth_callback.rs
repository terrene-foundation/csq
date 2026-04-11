//! TCP listener for the OAuth PKCE browser callback.
//!
//! # Why a second listener
//!
//! The daemon's primary IPC surface is a **Unix domain socket** so
//! browsers cannot reach it — they only speak TCP. The OAuth flow
//! requires Anthropic to 302 the user's browser back to
//! `http://127.0.0.1:{port}/oauth/callback?code=X&state=Y`, which
//! means csq needs a real TCP listener bound to loopback.
//!
//! This module owns that TCP listener. It serves **one** route and
//! nothing else:
//!
//! ```text
//! GET /oauth/callback?code=X&state=Y
//! GET /oauth/callback?error=access_denied&state=Y   (user denied)
//! ```
//!
//! Every other path returns 404. Every other method returns 405.
//! The callback listener has no knowledge of the daemon's other
//! APIs — the attack surface is exactly one handler.
//!
//! # Security posture
//!
//! 1. **Loopback-only binding.** [`serve`] always binds `127.0.0.1`
//!    and rejects any attempt to bind elsewhere — the builder
//!    signature takes a `u16` port, not a full `SocketAddr`.
//! 2. **State store is the authentication boundary.** The handler
//!    looks up the `state` query parameter in the shared
//!    [`OAuthStateStore`] and rejects anything that is not there
//!    (missing, expired, or already consumed). This prevents CSRF
//!    and replay.
//! 3. **No user-controlled data in response HTML.** The success
//!    and failure pages embed only the account number (a validated
//!    `u16`) and a small set of fixed error strings. The incoming
//!    `code`, `state`, and `error_description` query parameters are
//!    NEVER reflected in the response body. That defeats a reflected
//!    XSS path through the OAuth callback.
//! 4. **Body limit.** Not strictly needed — the callback is a `GET`
//!    so the body is empty — but the 1 MiB `DefaultBodyLimit` layer
//!    is attached for defense in depth against pathological
//!    malformed requests.
//! 5. **Structural defense against leaking the code or verifier.**
//!    The handler calls [`crate::oauth::exchange_code`] in
//!    `spawn_blocking` (the blocking HTTP client needs a worker
//!    thread). The exchange function already guarantees the request
//!    body is never formatted into an error — see
//!    `workspaces/csq-v2/journal/0010-RISK-redact-tokens-scope-boundary.md`.
//!
//! # Port allocation
//!
//! Production callers pass [`crate::oauth::DEFAULT_REDIRECT_PORT`]
//! (8420), which matches v1.x and the Anthropic OAuth app
//! registration. Tests pass `0` so the OS picks a free port; the
//! returned [`CallbackHandle::port`] lets the test wire the real
//! port into [`crate::oauth::start_login`].

#![cfg(unix)]

use crate::credentials::{self, CredentialFile};
use crate::daemon::refresher::HttpPostFn;
use crate::error::{CsqError, OAuthError};
use crate::oauth::{exchange_code, redirect_uri, OAuthStateStore, PendingState};
use crate::types::AccountNum;
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Maximum body size accepted on the callback listener.
/// The callback is a GET with no body, so any value > 0 is fine;
/// 8 KiB is generous without being a DoS vector.
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024;

/// Shared state for the callback router.
#[derive(Clone)]
pub struct CallbackState {
    /// The same state store the `/api/login/{N}` handler writes to.
    /// Consume happens here on callback.
    pub store: Arc<OAuthStateStore>,
    /// csq base directory for credential writes.
    pub base_dir: Arc<PathBuf>,
    /// HTTP closure used to exchange the authorization code for a
    /// token pair. Production passes `http::post_json`; tests pass a
    /// mock that returns canned responses.
    pub http_post: HttpPostFn,
    /// Port this listener is bound to. Carried in state so the
    /// exchange handler can reconstruct the `redirect_uri` that
    /// was sent in the authorize URL — Anthropic requires the
    /// redirect_uri on the exchange to be byte-identical to the
    /// one on the authorize request.
    pub oauth_port: u16,
}

/// Handle to a running callback listener.
///
/// Dropping the handle does NOT stop the listener — callers must
/// cancel the shared `CancellationToken` and await the join handle.
/// The `port` field is useful for tests that bound to port 0.
pub struct CallbackHandle {
    pub port: u16,
    pub shutdown: CancellationToken,
}

impl CallbackHandle {
    /// Signals the listener to shut down on the next accept cycle.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// How often the state-store sweeper wakes up to purge expired
/// pending logins. Matches the TTL design in
/// [`crate::oauth::STATE_TTL`] — a 60s tick is frequent enough to
/// keep the store tidy without being a CPU cost.
const STATE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Spawns a background task that periodically calls
/// `store.sweep_expired()` so abandoned pending logins are removed
/// even if their callback never arrives.
///
/// Without this task, expired entries would remain in the store
/// until `MAX_PENDING` was reached and the oldest was evicted.
/// That is still bounded (so not a DoS), but the promised TTL is
/// not actually enforced for entries that never get `consume()`'d.
/// This sweeper closes that gap.
///
/// The task exits immediately on shutdown.
fn spawn_state_sweeper(
    store: Arc<OAuthStateStore>,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(STATE_SWEEP_INTERVAL);
        // Skip the immediate first tick so we don't waste a sweep
        // on a freshly-initialized empty store.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    tracing::info!("oauth state sweeper: shutdown signaled");
                    return;
                }
                _ = ticker.tick() => {
                    let removed = store.sweep_expired();
                    if removed > 0 {
                        tracing::debug!(removed, "oauth state sweeper: expired entries purged");
                    }
                }
            }
        }
    })
}

/// Binds a TCP listener on `127.0.0.1:port` and serves the OAuth
/// callback router on it until the returned shutdown token is
/// cancelled.
///
/// Pass `port = 0` to let the OS pick an ephemeral port (used in
/// tests); the actual bound port is available via
/// [`CallbackHandle::port`] on the returned handle.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the bind fails. The daemon
/// startup path handles this gracefully: it logs a warning and
/// sets `oauth_store = None` in the HTTP router state, which
/// causes `GET /api/login/{N}` to return 503. Other daemon
/// features continue to work.
pub async fn serve(
    port: u16,
    state: CallbackState,
    shutdown: CancellationToken,
) -> std::io::Result<(CallbackHandle, tokio::task::JoinHandle<()>)> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = TcpListener::bind(addr).await?;
    let bound_port = listener.local_addr()?.port();

    info!(port = bound_port, "oauth callback listener bound");

    // Spawn the background sweeper that periodically removes
    // expired pending entries from the state store. Shares the
    // same shutdown token so it exits with the listener.
    let _sweeper = spawn_state_sweeper(Arc::clone(&state.store), shutdown.clone());

    let app = router(state);
    let shutdown_for_serve = shutdown.clone();
    let join = tokio::spawn(async move {
        let result = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                shutdown_for_serve.cancelled().await;
            })
            .await;
        // axum::serve returns an io::Error on unrecoverable accept
        // failures (EMFILE, listener closed out of band, etc.).
        // The error does not contain any OAuth token data — it is
        // a hyper-level IO error — but RISK-0007 prohibits `%e`
        // formatting in daemon/oauth modules as a blanket rule,
        // so we log only a fixed tag.
        if result.is_err() {
            warn!(
                error_kind = "serve_io",
                "oauth callback listener exited with error"
            );
        } else {
            info!("oauth callback listener exited cleanly");
        }
    });

    Ok((
        CallbackHandle {
            port: bound_port,
            shutdown,
        },
        join,
    ))
}

/// Builds the axum router for the callback listener.
///
/// Exactly one route: `GET /oauth/callback`. Everything else 404s.
pub fn router(state: CallbackState) -> Router {
    Router::new()
        .route("/oauth/callback", get(callback_handler))
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
}

/// Query parameters accepted by the callback handler.
///
/// All fields are optional because Anthropic may redirect with
/// either `code`+`state` (success) or `error`+`state` (user denied
/// or authorization failed). The handler pattern-matches on which
/// shape was provided.
#[derive(Debug, Deserialize)]
struct CallbackParams {
    /// Authorization code on success. Passed to `exchange_code`.
    #[serde(default)]
    code: Option<String>,
    /// State token, required in both success and error paths so
    /// the handler can consume the pending entry.
    #[serde(default)]
    state: Option<String>,
    /// Error code when the user denies consent or authorization
    /// fails upstream. Observed values: `access_denied`,
    /// `invalid_scope`, `server_error`.
    #[serde(default)]
    error: Option<String>,
}

/// Handles the OAuth callback from Anthropic.
///
/// Flow:
///
/// 1. Require the `state` parameter — without it we cannot
///    correlate this callback to any pending login. Return a
///    sanitized error page.
/// 2. Consume the pending entry from the state store. This
///    removes it regardless of outcome so a retry sees CSRF, not
///    a fresh exchange.
/// 3. If Anthropic returned an `error` query parameter, render a
///    "login cancelled" page. The pending state has already been
///    removed, so a subsequent retry will correctly fail with
///    `state_mismatch`.
/// 4. Otherwise require `code`, call [`exchange_code`] in
///    `spawn_blocking`, save the resulting credentials via
///    [`credentials::save_canonical`], and render the success
///    page.
///
/// The response body is always static HTML — no dynamic content
/// except the validated account number and a small set of fixed
/// error strings.
async fn callback_handler(
    State(state): State<CallbackState>,
    Query(params): Query<CallbackParams>,
) -> impl IntoResponse {
    let Some(state_token) = params.state else {
        return (
            StatusCode::BAD_REQUEST,
            failure_html(FailureReason::MissingState),
        )
            .into_response();
    };

    // Require either `code` (success) or `error` (upstream denial)
    // before touching the state store. Without this guard, a
    // malicious request that guesses a valid state token could
    // `GET /oauth/callback?state=X` (no code, no error) and
    // pre-consume the pending entry — invalidating the legitimate
    // login that the user is about to complete. The guard is
    // defense-in-depth on top of the 32-byte CSPRNG state token
    // (which makes guessing computationally infeasible) and the
    // 127.0.0.1-only listener (which limits the attacker to
    // same-host code, already a compromised UID scenario). See
    // security review M1.
    if params.code.is_none() && params.error.is_none() {
        warn!("oauth callback: neither code nor error in query");
        return (
            StatusCode::BAD_REQUEST,
            failure_html(FailureReason::MissingCode),
        )
            .into_response();
    }

    // Consume the pending entry. The remove is unconditional — on
    // any outcome (success, error, exchange failure) the state
    // token is burned, preventing replay.
    let pending: PendingState = match state.store.consume(&state_token) {
        Ok(p) => p,
        Err(OAuthError::StateMismatch) => {
            warn!("oauth callback: state mismatch or replay");
            return (
                StatusCode::BAD_REQUEST,
                failure_html(FailureReason::StateMismatch),
            )
                .into_response();
        }
        Err(OAuthError::StateExpired { .. }) => {
            warn!("oauth callback: state expired");
            return (
                StatusCode::BAD_REQUEST,
                failure_html(FailureReason::StateExpired),
            )
                .into_response();
        }
        Err(e) => {
            warn!(
                error_kind = e.kind(),
                "oauth callback: unexpected state error"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                failure_html(FailureReason::Internal),
            )
                .into_response();
        }
    };

    // Anthropic error redirect (user denied, scope invalid, etc).
    if params.error.is_some() {
        info!(
            account = pending.account.get(),
            "oauth callback: user denied or upstream error"
        );
        return (StatusCode::OK, failure_html(FailureReason::UserDenied)).into_response();
    }

    let Some(code) = params.code else {
        warn!(
            account = pending.account.get(),
            "oauth callback: missing code"
        );
        return (
            StatusCode::BAD_REQUEST,
            failure_html(FailureReason::MissingCode),
        )
            .into_response();
    };

    // Run the synchronous HTTP exchange + file IO inside
    // spawn_blocking. We clone the Arcs into the task and move
    // the PendingState by value. `redirect_uri` must match the
    // one embedded in the authorize URL byte-for-byte, which is
    // why `oauth_port` lives on `CallbackState`.
    let base_dir = Arc::clone(&state.base_dir);
    let http_post = Arc::clone(&state.http_post);
    let oauth_port = state.oauth_port;
    let account = pending.account;
    let exchange_result = tokio::task::spawn_blocking(move || {
        let http_closure = move |url: &str, body: &str| http_post(url, body);
        exchange_code(
            &code,
            &pending.code_verifier,
            &redirect_uri(oauth_port),
            http_closure,
        )
    })
    .await;

    match exchange_result {
        Ok(Ok(creds)) => match write_credentials(&base_dir, account, creds).await {
            Ok(()) => {
                info!(account = account.get(), "oauth login complete");
                (StatusCode::OK, success_html(account)).into_response()
            }
            Err(e) => {
                warn!(
                    account = account.get(),
                    error_kind = e.kind(),
                    "oauth callback: credential write failed"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    failure_html(FailureReason::CredentialWrite),
                )
                    .into_response()
            }
        },
        Ok(Err(OAuthError::Exchange(_))) => {
            warn!(
                account = account.get(),
                "oauth callback: code exchange failed"
            );
            (
                StatusCode::BAD_GATEWAY,
                failure_html(FailureReason::ExchangeFailed),
            )
                .into_response()
        }
        Ok(Err(e)) => {
            warn!(
                account = account.get(),
                error_kind = e.kind(),
                "oauth callback: unexpected exchange error"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                failure_html(FailureReason::Internal),
            )
                .into_response()
        }
        Err(_join_err) => {
            // Deliberately do NOT format `join_err` with `%` — a
            // tokio JoinError includes the panic payload, which
            // could (in principle) contain user data. Log only a
            // fixed string so RISK-0007 holds here too.
            warn!(
                account = account.get(),
                error_kind = "join_err",
                "oauth callback: exchange task panicked"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                failure_html(FailureReason::Internal),
            )
                .into_response()
        }
    }
}

/// Writes a freshly-obtained credential file to disk, running the
/// synchronous file IO on a blocking worker.
async fn write_credentials(
    base_dir: &std::path::Path,
    account: AccountNum,
    creds: CredentialFile,
) -> Result<(), CsqError> {
    let base = base_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        credentials::save_canonical(&base, account, &creds).map_err(CsqError::from)
    })
    .await
    .map_err(|e| CsqError::Other(anyhow::anyhow!("save task panicked: {e}")))?
}

/// Enumerated reasons for a failure page. Each variant maps to a
/// fixed, user-safe string — the response body never reflects any
/// query parameter back to the browser.
#[derive(Debug, Clone, Copy)]
enum FailureReason {
    MissingState,
    StateMismatch,
    StateExpired,
    MissingCode,
    UserDenied,
    ExchangeFailed,
    CredentialWrite,
    Internal,
}

impl FailureReason {
    fn message(self) -> &'static str {
        match self {
            Self::MissingState => {
                "The OAuth callback was missing a state parameter. \
                 This usually means the login was started outside of claude-squad."
            }
            Self::StateMismatch => {
                "This OAuth callback could not be matched to an active login. \
                 Return to claude-squad and start the login again."
            }
            Self::StateExpired => {
                "This login took too long to complete. \
                 Return to claude-squad and start the login again."
            }
            Self::MissingCode => {
                "The OAuth callback was missing an authorization code. \
                 Return to claude-squad and try again."
            }
            Self::UserDenied => {
                "The login was cancelled. \
                 Return to claude-squad if you'd like to try again."
            }
            Self::ExchangeFailed => {
                "The authorization code could not be exchanged for a token. \
                 This usually means a temporary Anthropic issue — try again in a moment."
            }
            Self::CredentialWrite => {
                "The login succeeded but the credential file could not be written to disk. \
                 Check that claude-squad has write permission on its config directory."
            }
            Self::Internal => "An internal error occurred. Return to claude-squad and try again.",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::UserDenied => "Login cancelled",
            _ => "Login failed",
        }
    }
}

fn success_html(account: AccountNum) -> Html<String> {
    // The account number is a validated u16 in 1..=999 — safe to
    // embed directly. No other dynamic content.
    Html(format!(
        "<!doctype html>\n\
         <html lang=\"en\"><head>\
         <meta charset=\"utf-8\">\
         <title>claude-squad: login complete</title>\
         <style>body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:40em;margin:4em auto;padding:0 1em;color:#222;}}h1{{color:#2a6;}}code{{background:#f4f4f4;padding:.1em .4em;border-radius:3px;}}</style>\
         </head><body>\
         <h1>Login complete</h1>\
         <p>Account <code>{account_num}</code> was added successfully. \
         You can close this tab and return to claude-squad.</p>\
         </body></html>",
        account_num = account.get()
    ))
}

fn failure_html(reason: FailureReason) -> Html<String> {
    Html(format!(
        "<!doctype html>\n\
         <html lang=\"en\"><head>\
         <meta charset=\"utf-8\">\
         <title>claude-squad: {title}</title>\
         <style>body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:40em;margin:4em auto;padding:0 1em;color:#222;}}h1{{color:#c33;}}</style>\
         </head><body>\
         <h1>{title}</h1>\
         <p>{message}</p>\
         </body></html>",
        title = reason.title(),
        message = reason.message()
    ))
}

// Helper trait — keeps the warn! calls above concise without
// leaking the full error Display. See RISK-0007.
trait CsqErrorKind {
    fn kind(&self) -> &'static str;
}

impl CsqErrorKind for OAuthError {
    fn kind(&self) -> &'static str {
        match self {
            OAuthError::Http { .. } => "http",
            OAuthError::StateExpired { .. } => "state_expired",
            OAuthError::StateMismatch => "state_mismatch",
            OAuthError::PkceVerification => "pkce_verification",
            OAuthError::Exchange(_) => "exchange",
        }
    }
}

impl CsqErrorKind for CsqError {
    fn kind(&self) -> &'static str {
        match self {
            CsqError::Credential(_) => "credential",
            CsqError::Platform(_) => "platform",
            CsqError::Broker(_) => "broker",
            // Delegate to the inner OAuthError's kind() so we get
            // a more specific tag (state_mismatch, exchange, etc.)
            // rather than a generic "oauth". Currently unreachable
            // because write_credentials never produces OAuth errors,
            // but the delegation future-proofs the log-tagging
            // contract if a later caller does.
            CsqError::OAuth(inner) => inner.kind(),
            CsqError::Daemon(_) => "daemon",
            CsqError::Config(_) => "config",
            CsqError::Other(_) => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::cache::TtlCache;
    use crate::oauth::{start_login, CodeVerifier};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tempfile::TempDir;

    /// Mock HTTP closure factory that returns a canned success
    /// response and counts calls.
    fn success_http(counter: Arc<AtomicU32>) -> HttpPostFn {
        Arc::new(move |_url: &str, _body: &str| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(br#"{
                "access_token": "sk-ant-oat01-new-access",
                "refresh_token": "sk-ant-ort01-new-refresh",
                "expires_in": 18000
            }"#
            .to_vec())
        })
    }

    fn failing_http() -> HttpPostFn {
        Arc::new(|_url: &str, _body: &str| Err("upstream unavailable".to_string()))
    }

    /// Issues a raw HTTP GET against the callback listener and
    /// returns (status_code, body).
    async fn http_get(port: u16, path_and_query: &str) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let req = format!(
            "GET {path_and_query} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf).into_owned();
        let status_line = text.lines().next().unwrap_or("");
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let body = text
            .find("\r\n\r\n")
            .map(|i| text[i + 4..].to_string())
            .unwrap_or_default();
        (status, body)
    }

    fn test_state(base: &std::path::Path, http: HttpPostFn, port: u16) -> CallbackState {
        CallbackState {
            store: Arc::new(OAuthStateStore::new()),
            base_dir: Arc::new(base.to_path_buf()),
            http_post: http,
            oauth_port: port,
        }
    }

    #[tokio::test]
    async fn bind_uses_ephemeral_port_when_zero() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let state = test_state(dir.path(), success_http(counter), 0);
        let shutdown = CancellationToken::new();

        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();
        assert_ne!(handle.port, 0, "OS must assign a real port");
        assert!(handle.port >= 1024, "expected non-privileged port");

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let state = test_state(dir.path(), success_http(counter), 0);
        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        let (status, _body) = http_get(handle.port, "/not-a-route").await;
        assert_eq!(status, 404);

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn callback_missing_state_returns_400() {
        let dir = TempDir::new().unwrap();
        let state = test_state(dir.path(), success_http(Arc::new(AtomicU32::new(0))), 0);
        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        let (status, body) = http_get(handle.port, "/oauth/callback?code=abc").await;
        assert_eq!(status, 400);
        assert!(body.contains("Login failed"), "body: {body}");
        // Must NOT leak the code back to the browser
        assert!(
            !body.contains("abc"),
            "body should not echo the code: {body}"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn callback_state_mismatch_returns_400() {
        let dir = TempDir::new().unwrap();
        let state = test_state(dir.path(), success_http(Arc::new(AtomicU32::new(0))), 0);
        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        let (status, body) = http_get(
            handle.port,
            "/oauth/callback?code=abc&state=never-issued-this-state",
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.contains("could not be matched"));
        assert!(!body.contains("never-issued-this-state"));

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn callback_success_writes_credentials() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = success_http(Arc::clone(&counter));

        // Pre-seed the state store with a known entry so we don't
        // have to simulate the /api/login route in this unit test.
        let state = test_state(dir.path(), http, 8420);
        let account = AccountNum::try_from(1u16).unwrap();
        let state_token = state.store.insert(
            CodeVerifier::new("test-verifier-1234567890".to_string()),
            account,
        );

        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        let (status, body) = http_get(
            handle.port,
            &format!("/oauth/callback?code=dummy-code&state={state_token}"),
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains("Login complete"));
        assert!(body.contains("1"), "account number should appear");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "exactly one HTTP exchange call"
        );

        // Credentials file must exist.
        let cred_path = credentials::file::canonical_path(dir.path(), account);
        assert!(
            cred_path.exists(),
            "canonical credential file must be written"
        );
        let loaded = credentials::load(&cred_path).unwrap();
        assert_eq!(
            loaded.claude_ai_oauth.access_token.expose_secret(),
            "sk-ant-oat01-new-access"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn callback_user_denied_returns_200_login_cancelled() {
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = success_http(Arc::clone(&counter));
        let state = test_state(dir.path(), http, 0);
        let account = AccountNum::try_from(1u16).unwrap();
        let state_token = state
            .store
            .insert(CodeVerifier::new("v".to_string()), account);

        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        let (status, body) = http_get(
            handle.port,
            &format!("/oauth/callback?error=access_denied&state={state_token}"),
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains("Login cancelled"));
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "no HTTP exchange on user-denied path"
        );

        // State must still be consumed (no replay).
        let (status2, _) = http_get(
            handle.port,
            &format!("/oauth/callback?code=abc&state={state_token}"),
        )
        .await;
        assert_eq!(status2, 400);

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn callback_exchange_failure_returns_502() {
        let dir = TempDir::new().unwrap();
        let state = test_state(dir.path(), failing_http(), 0);
        let account = AccountNum::try_from(2u16).unwrap();
        let state_token = state
            .store
            .insert(CodeVerifier::new("v".to_string()), account);

        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        let (status, body) = http_get(
            handle.port,
            &format!("/oauth/callback?code=abc&state={state_token}"),
        )
        .await;
        assert_eq!(status, 502);
        assert!(body.contains("could not be exchanged"));

        // No credentials written.
        let cred_path = credentials::file::canonical_path(dir.path(), account);
        assert!(
            !cred_path.exists(),
            "no credentials should be written on failure"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn callback_full_flow_with_real_state_from_start_login() {
        // Integration-style test: drive both halves of the flow
        // through their real APIs (start_login + callback handler)
        // to make sure the state store roundtrip is consistent.
        let dir = TempDir::new().unwrap();
        let counter = Arc::new(AtomicU32::new(0));
        let http = success_http(Arc::clone(&counter));
        let state = test_state(dir.path(), http, 0);

        let account = AccountNum::try_from(5u16).unwrap();
        let login = start_login(&state.store, account, state.oauth_port).unwrap();
        // The state token from start_login is what the browser
        // would carry back in the callback.
        assert!(!login.state.is_empty());

        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        let (status, body) = http_get(
            handle.port,
            &format!("/oauth/callback?code=real-code&state={}", login.state),
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains("Login complete"));
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        let cred_path = credentials::file::canonical_path(dir.path(), account);
        assert!(cred_path.exists());

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn wrong_method_returns_405() {
        let dir = TempDir::new().unwrap();
        let state = test_state(dir.path(), success_http(Arc::new(AtomicU32::new(0))), 0);
        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        // POST /oauth/callback — only GET is registered.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        let mut stream = TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .unwrap();
        stream
            .write_all(
                b"POST /oauth/callback HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await;
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("405") || text.contains("Method Not Allowed"),
            "expected 405, got: {text}"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    /// Placeholder so unused `TtlCache` import doesn't warn if a
    /// future refactor removes some tests.
    #[allow(dead_code)]
    fn _touch_cache() -> TtlCache<u16, crate::daemon::refresher::RefreshStatus> {
        TtlCache::with_default_age()
    }

    /// Regression test for security review M1: a request that has
    /// a valid `state` but neither `code` nor `error` MUST NOT
    /// consume the pending entry. Otherwise an attacker who
    /// guesses a valid state could pre-consume it and invalidate
    /// the legitimate login.
    #[tokio::test]
    async fn callback_with_only_state_does_not_consume_pending() {
        let dir = TempDir::new().unwrap();
        let state = test_state(dir.path(), success_http(Arc::new(AtomicU32::new(0))), 0);
        let account = AccountNum::try_from(1u16).unwrap();
        let store = Arc::clone(&state.store);
        let state_token = store.insert(CodeVerifier::new("v".to_string()), account);
        assert_eq!(store.len(), 1, "precondition: one pending entry");

        let shutdown = CancellationToken::new();
        let (handle, join) = serve(0, state, shutdown.clone()).await.unwrap();

        // Request with state only — no code, no error.
        let (status, body) =
            http_get(handle.port, &format!("/oauth/callback?state={state_token}")).await;
        assert_eq!(status, 400);
        assert!(
            body.contains("Login failed"),
            "body should show failure page: {body}"
        );

        // Critical: the pending entry must still be in the store.
        assert_eq!(
            store.len(),
            1,
            "state must NOT be consumed when code and error are both missing"
        );

        // And the legitimate callback (same state + real code)
        // must still succeed.
        let (status2, body2) = http_get(
            handle.port,
            &format!("/oauth/callback?code=legit-code&state={state_token}"),
        )
        .await;
        assert_eq!(
            status2, 200,
            "legitimate callback must still succeed: {body2}"
        );
        assert_eq!(store.len(), 0, "legitimate callback consumes the entry");

        shutdown.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    /// Smoke test for the state sweeper. Uses a very short TTL so
    /// the sweeper's 60s tick is not exercised directly (that
    /// would make the test slow); instead we verify that
    /// `sweep_expired()` is the right method name and is callable.
    #[tokio::test]
    async fn state_sweeper_removes_expired_entries() {
        use crate::oauth::OAuthStateStore;
        use std::time::Duration as StdDuration;
        let store = Arc::new(OAuthStateStore::with_config(
            StdDuration::from_millis(5),
            100,
        ));
        let _ = store.insert(
            CodeVerifier::new("v".into()),
            AccountNum::try_from(1u16).unwrap(),
        );
        assert_eq!(store.len(), 1);

        tokio::time::sleep(StdDuration::from_millis(20)).await;

        // The sweeper will only run every 60s inside the real
        // listener, but the semantics are: sweep_expired() is the
        // method the sweeper invokes. Verify it does the right
        // thing directly.
        let removed = store.sweep_expired();
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 0);
    }
}
