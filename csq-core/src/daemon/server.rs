//! Unix socket IPC server for the daemon.
//!
//! Serves a minimal axum HTTP/1.1 router over a Unix domain socket.
//! M8.3 only wires the `GET /api/health` route — additional routes
//! (accounts, usage, refresh, OAuth callback) land in M8.4+.
//!
//! # Platform scope
//!
//! This module is Unix-only (`cfg(unix)`). Windows named-pipe
//! support is deferred to M8.6 — see
//! `internal-design-docs` task M8-03.
//!
//! # Security model
//!
//! Three defensive layers protect the IPC surface. Any single layer
//! breaking should not expose the daemon; together they match the
//! hardening baseline sshd and systemd use for local sockets.
//!
//! ## Layer 1 — socket file permissions (0o600)
//!
//! The socket file is created with `0o600` permissions. To close the
//! microsecond window between `bind(2)` and `chmod(2)` during which
//! the socket would otherwise inherit the process umask (typically
//! 0o644 or 0o755), [`serve`] temporarily sets the thread's umask to
//! `0o077` immediately before bind and restores it immediately after.
//! The explicit `set_permissions(0o600)` call remains as
//! defense-in-depth.
//!
//! ## Layer 2 — `SO_PEERCRED` / `LOCAL_PEERCRED` peer UID check
//!
//! Every accepted connection is checked against `geteuid()` before
//! the HTTP router sees the request. Linux uses `SO_PEERCRED` to
//! read `struct ucred.uid`; macOS uses `LOCAL_PEERCRED` to read
//! `struct xucred.cr_uid`. Connections from other UIDs are closed
//! immediately with no HTTP response. This catches the case where
//! a file-permission bug (incorrect chmod, symlink swap, race) lets
//! a different-UID process connect.
//!
//! ## Layer 3 — per-user socket directory
//!
//! The socket path itself lives under a per-user directory:
//! `$XDG_RUNTIME_DIR` on Linux (tmpfs, 0o700), `~/.claude/accounts`
//! on macOS (0o755 but inside the user's HOME), or
//! `/tmp/csq-{uid}.sock` as the Linux fallback (uid in the name so
//! different-UID collisions are harmless).
//!
//! ## HTTP request authentication
//!
//! There is no application-layer authentication on the HTTP
//! requests because the three layers above establish that any
//! caller is the owning user. Anyone who can open the socket is
//! already the same UID, which is exactly the threat model for a
//! per-user daemon.

// This module is shared by both the Unix-socket listener (cfg(unix))
// and the Windows named-pipe listener (cfg(windows) — see
// `server_windows.rs`). The router definition, RouterState, request
// handlers, and request/response types are cross-platform. Only the
// Unix-specific bind/accept loop and SO_PEERCRED helpers are gated
// behind `#[cfg(unix)]` further down.

use super::cache::TtlCache;
use super::refresher::RefreshStatus;
use super::usage_poller::gemini::GeminiConsumerState;
use crate::accounts::{discovery, AccountInfo};
use crate::credentials;
use crate::error::{DaemonError, OAuthError};
use crate::oauth::{
    exchange_code, start_login, LoginRequest, OAuthStateStore, PASTE_CODE_REDIRECT_URI,
};
use crate::types::AccountNum;
#[cfg(feature = "enterprise")]
use axum::http::HeaderMap;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;

// #783 / #794 — interactive per-turn enforcement surface (enterprise-only). The
// dispatch registry + request/response types live in the enterprise-gated
// `interactive_ipc` module; `server.rs` registers the routes + holds the live
// registry behind the same feature gate. The community build compiles none of it.
#[cfg(feature = "enterprise")]
use crate::daemon::interactive_ipc::{
    AuthorizeOverrideRequest, InteractiveSessionRegistry, OpenSessionResponse, SessionKey,
    SessionOpenParams, SessionOptionsResponse, SessionStateView, SubmitInputRequest,
};

/// Shared router state — cache + base_dir paths + OAuth state
/// store. Cloned cheaply (every field is an `Arc` / `PathBuf`
/// inside) for each request via axum's `State` extractor.
#[derive(Clone)]
pub struct RouterState {
    /// Refresh-status cache owned by the daemon lifecycle. The
    /// refresher writes; HTTP routes only read.
    pub cache: Arc<TtlCache<u16, RefreshStatus>>,
    /// Short-TTL cache of the full discovered account list. Used
    /// by `/api/accounts` and `/api/refresh-status` to avoid a
    /// full filesystem scan on every request. Bounded to
    /// [`DISCOVERY_CACHE_MAX_AGE`]. Single-entry — the key is
    /// `()` because discovery is per-base-dir and the base dir
    /// is constant for the life of the daemon.
    ///
    /// Addresses M8.5 security review MED #1 (full fs scan per
    /// request is a DoS vector once the statusline starts
    /// polling on a tight interval).
    pub discovery_cache: Arc<TtlCache<(), Vec<AccountInfo>>>,
    /// csq base directory, passed through for account discovery.
    pub base_dir: Arc<PathBuf>,
    /// OAuth state store for pending paste-code logins. The daemon
    /// keeps this in memory — `start_login` inserts an entry keyed
    /// by a random state token, and the subsequent
    /// `/api/oauth/exchange` call consumes it when the user submits
    /// their copied authorization code.
    ///
    /// `None` when the daemon was started without OAuth support
    /// (tests, custom builds). In that case both `/api/login/{N}`
    /// and `/api/oauth/exchange` return 503.
    pub oauth_store: Option<Arc<OAuthStateStore>>,
    /// Gemini event-consumer state — shared with the NDJSON drain
    /// task so the live IPC route AND the drainer dedup against
    /// the same applied-set and serialise quota writes through the
    /// same per-process mutex (spec 05 §5.8.1 single-writer
    /// invariant). Cloned cheaply (every field is an `Arc`).
    pub gemini_consumer: GeminiConsumerState,
    /// Audit-chain health as determined at daemon startup by
    /// `verify_chain`. Gates the audit subsystem:
    /// - Anchor task skips anchoring when `!is_operational()`.
    /// - `POST /api/audit/record` rejects emits when `!is_operational()`.
    ///
    /// Other subsystems (token-refresh, usage-poller, IPC server itself)
    /// are NEVER gated on this — see spec 12 §12.13.5.
    pub audit_health: crate::audit::AuditHealth,
    /// #783 — the interactive per-turn enforcement session registry
    /// (enterprise-only). Seeded at daemon startup by
    /// `crate::daemon::interactive_live::seed_registry`: a LIVE registry when the
    /// fail-closed activation gate (`<base_dir>/.phase2b-interactive-gate.json`)
    /// is present + valid, otherwise `InteractiveSessionRegistry::empty()` (every
    /// `/api/interactive/*` route returns `503 Unavailable`). The daemon cannot
    /// re-derive the four §10.5 conditions (offline bench artifacts; `specs/10`
    /// §10.5.1) — the activation signal is operator-owned go-live authorization.
    #[cfg(feature = "enterprise")]
    pub interactive: Arc<InteractiveSessionRegistry>,
}

/// Maximum staleness for the discovery cache: 5 seconds.
///
/// Chosen so that:
///
/// 1. A statusline polling every 1–2 seconds pays the fs-scan
///    cost at most once per 5s window, not on every render.
/// 2. A new account added via OAuth callback becomes visible to
///    the rest of the API within 5s without any explicit
///    invalidation wiring.
/// 3. Stale reads are bounded — no user-visible "ghost account"
///    lingers beyond the TTL even if the underlying credentials
///    file is deleted out of band.
///
/// Dogpile race: two concurrent handlers may both miss the cache
/// and both run discovery. This is acceptable at 5s TTL because
/// the cost is exactly one extra fs scan per race, and the
/// filesystem scan at realistic account counts (<= 100) is a
/// few milliseconds. Adding single-flight coordination would
/// require holding an async lock across spawn_blocking, which
/// is strictly worse than the bounded dogpile.
pub const DISCOVERY_CACHE_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum request body size accepted by the daemon HTTP router.
/// M8.3 has no body-accepting routes, but the limit is set now so
/// every future route (M8.5 `/api/login`, `/api/refresh-token/:id`,
/// etc.) inherits it automatically. 1 MiB is generous for JSON
/// command payloads while still bounding worst-case allocation.
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// Health endpoint response body. Deliberately minimal — the client
/// only cares that the endpoint responds with 200 and valid JSON.
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub pid: u32,
}

/// Builds the axum router for the daemon HTTP API.
///
/// Routes mounted:
/// - `GET /api/health` — liveness probe (M8.3)
/// - `GET /api/accounts` — discovered accounts (M8.5)
/// - `GET /api/refresh-status` — all refresh statuses from the cache (M8.5)
/// - `GET /api/refresh-status/:id` — one account's refresh status (M8.5)
/// - `GET /api/login/:id` — initiate a paste-code OAuth flow
/// - `POST /api/oauth/exchange` — submit the paste-code and exchange it
/// - `POST /api/invalidate-cache` — clear all caches (M8-10c)
///
/// `#[cfg(feature = "enterprise")]` also mounts (spec 21 §21.7, #783/#794):
/// - `POST /api/interactive/open` — open a new governed session → `OpenSessionResponse`
/// - `POST /api/interactive/submit` — submit one governed turn (key via header)
/// - `POST /api/interactive/override` — authorize a blocked turn (key via header)
/// - `POST /api/interactive/abandon` — abandon a blocked turn (key via header)
/// - `POST /api/interactive/close` — close a session and free its slot (key via header)
///
/// (Fail-closed `503` unless the §10.5 activation gate is open.)
///
/// The [`DefaultBodyLimit`] layer is installed here so every future
/// route inherits the 1 MiB cap without having to remember. State
/// is shared via `with_state` so each handler gets a cheap clone
/// of the [`RouterState`].
pub fn router(state: RouterState) -> Router {
    let app = Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/accounts", get(accounts_handler))
        .route("/api/refresh-status", get(refresh_status_all_handler))
        .route("/api/refresh-status/{id}", get(refresh_status_one_handler))
        .route("/api/login/{id}", get(login_handler))
        .route("/api/oauth/exchange", post(oauth_exchange_handler))
        .route("/api/invalidate-cache", post(invalidate_cache_handler))
        .route("/api/slot-swap", post(slot_swap_handler))
        .route("/api/gemini/event", post(gemini_event_handler))
        .route("/api/audit/record", post(audit_record_handler))
        .route("/api/provenance/anchor", post(provenance_anchor_handler));

    // #783/#794 — interactive per-turn enforcement routes (enterprise-only,
    // spec 21 §21.7). Registered in the enterprise build; the seeded registry is
    // fail-closed (empty → 503) unless the §10.5 activation gate is present. The
    // SO_PEERCRED same-UID socket auth + 1 MiB body cap apply to these routes too
    // (no per-route auth — security.md §7; the enforcement decision originates in
    // the daemon — account-terminal-separation.md MUST Rule 1).
    //
    // Session lifecycle: open → key in X-CSQ-Session-Key → submit/override/abandon
    //                         → close.  Key is daemon-minted CSPRNG; clients echo it.
    #[cfg(feature = "enterprise")]
    let app = app
        .route("/api/interactive/open", post(interactive_open_handler))
        .route("/api/interactive/submit", post(interactive_submit_handler))
        .route(
            "/api/interactive/override",
            post(interactive_override_handler),
        )
        .route(
            "/api/interactive/abandon",
            post(interactive_abandon_handler),
        )
        .route("/api/interactive/close", post(interactive_close_handler))
        .route(
            "/api/interactive/options",
            post(interactive_options_handler),
        )
        // T-M4.5: signed posture-reset (the only loosening path) + the read-only
        // sealed-audit-proof retrieval surface.
        .route(
            "/api/interactive/posture-reset",
            post(interactive_posture_reset_handler),
        )
        .route(
            "/api/interactive/audit-proof/{session_id}",
            get(interactive_audit_proof_handler),
        )
        // M6 T6.2 Shard 4 — spawn-boundary MCP gate decision attestation. The
        // `csq mcp-proxy` POSTs each gated tools/call decision here; the daemon
        // builds + signs + appends the McpGateDecision chain record server-side
        // (a subprocess never supplies a SignedRecord — account-terminal-
        // separation.md MUST Rule 1). Same SO_PEERCRED same-UID socket auth +
        // 1 MiB body cap as the sibling routes.
        .route("/api/audit/mcp-gate", post(mcp_gate_handler));

    app.with_state(state)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        pid: std::process::id(),
    })
}

/// Fixed-vocabulary error body for the `/api/interactive/*` routes (#783).
///
/// The `error` field carries ONLY the stable `InteractiveIpcError::tag()` or a
/// deserialize tag — never the request body or an upstream payload
/// (`rules/security.md` §2; `rules/tauri-commands.md` MUST-6). The renderer-bound
/// success view (`SessionStateView`) is already token-redacted at the IPC boundary
/// inside `interactive_ipc`.
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Serialize)]
pub struct InteractiveError {
    pub error: &'static str,
}

/// Map an [`crate::daemon::interactive_ipc::InteractiveIpcError`] to its HTTP
/// status + fixed-vocabulary body. `from_u16` cannot fail for the variants'
/// status set (400/409/502/503), but the fallback keeps the handler panic-free
/// (`rules/tauri-commands.md` MUST Rule 1 / MUST NOT Rule 2).
#[cfg(feature = "enterprise")]
fn interactive_err_response(
    e: crate::daemon::interactive_ipc::InteractiveIpcError,
) -> (StatusCode, Json<InteractiveError>) {
    let code = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (code, Json(InteractiveError { error: e.tag() }))
}

/// Extract the `X-CSQ-Session-Key` header and validate its format.
///
/// Returns 400 `session_key_invalid` (via [`interactive_err_response`]) for
/// both an ABSENT header and a syntactically malformed one — the
/// `InteractiveIpcError` vocabulary is the single source of truth for error tags
/// (`rules/tauri-commands.md` MUST Rule 6).  Distinct `session_key_missing`
/// literals are intentionally NOT used: the client sees an invalid/absent key as
/// the same actionable error ("provide a valid key from a prior `open` call").
#[cfg(feature = "enterprise")]
fn extract_session_key(
    headers: &HeaderMap,
) -> Result<SessionKey, (StatusCode, Json<InteractiveError>)> {
    let raw = headers
        .get("x-csq-session-key")
        .ok_or_else(|| {
            interactive_err_response(
                crate::daemon::interactive_ipc::InteractiveIpcError::InvalidSessionKey,
            )
        })?
        .to_str()
        .map_err(|_| {
            interactive_err_response(
                crate::daemon::interactive_ipc::InteractiveIpcError::InvalidSessionKey,
            )
        })?;
    SessionKey::try_from_client(raw).map_err(interactive_err_response)
}

/// `POST /api/interactive/open` — open a new governed session (#794).
///
/// Body: `SessionOpenParams` (all fields optional; unset → gate template values).
/// Returns `OpenSessionResponse { session_key, state: Idle }`.  The client MUST
/// echo the `session_key` in the `X-CSQ-Session-Key` header on all subsequent
/// calls for this session.
#[cfg(feature = "enterprise")]
async fn interactive_open_handler(
    State(state): State<RouterState>,
    body: Bytes,
) -> Result<Json<OpenSessionResponse>, (StatusCode, Json<InteractiveError>)> {
    // Empty body → default (all-None) params; non-empty → parse.
    let params: SessionOpenParams = if body.is_empty() {
        SessionOpenParams {
            provider: None,
            schema: None,
            max_tokens: None,
            coc_dir: None,
            terminal_label: None,
            terminal_pid: None,
            slot: None,
        }
    } else {
        serde_json::from_slice(&body).map_err(|_| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(InteractiveError {
                    error: "interactive_deserialize_error",
                }),
            )
        })?
    };
    state
        .interactive
        .open(params)
        .await
        .map(Json)
        .map_err(interactive_err_response)
}

/// `POST /api/interactive/submit` — submit one user input turn (#783/#794).
///
/// Header: `X-CSQ-Session-Key` — the daemon-minted session capability key.
/// Body: `SubmitInputRequest { input }`. Drives one governed turn end-to-end
/// (`GovernanceLoop::execute` via `InteractiveSession::run_turn`) and returns the
/// resulting `SessionStateView` (`Complete` / `Blocked`). Fail-closed `503`
/// (`interactive_unavailable`) when the activation gate is not open.
#[cfg(feature = "enterprise")]
async fn interactive_submit_handler(
    State(state): State<RouterState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SessionStateView>, (StatusCode, Json<InteractiveError>)> {
    let key = extract_session_key(&headers)?;
    let req: SubmitInputRequest = serde_json::from_slice(&body).map_err(|_| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(InteractiveError {
                error: "interactive_deserialize_error",
            }),
        )
    })?;
    state
        .interactive
        .submit(&key, req)
        .await
        .map(Json)
        .map_err(interactive_err_response)
}

/// `POST /api/interactive/override` — authorize a blocked turn (#783/#794).
///
/// Header: `X-CSQ-Session-Key` — the daemon-minted session capability key.
/// Body: `AuthorizeOverrideRequest { justification }`. The override event is
/// emitted (emit-before-execute) ahead of the corrective turn. Returns the
/// resulting `SessionStateView`.
#[cfg(feature = "enterprise")]
async fn interactive_override_handler(
    State(state): State<RouterState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SessionStateView>, (StatusCode, Json<InteractiveError>)> {
    let key = extract_session_key(&headers)?;
    let req: AuthorizeOverrideRequest = serde_json::from_slice(&body).map_err(|_| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(InteractiveError {
                error: "interactive_deserialize_error",
            }),
        )
    })?;
    state
        .interactive
        .authorize_override(&key, req)
        .await
        .map(Json)
        .map_err(interactive_err_response)
}

/// `POST /api/interactive/abandon` — abandon a blocked turn; session returns to
/// `Idle` (#783/#794).
///
/// Header: `X-CSQ-Session-Key` — the daemon-minted session capability key.
/// No request body.
#[cfg(feature = "enterprise")]
async fn interactive_abandon_handler(
    State(state): State<RouterState>,
    headers: HeaderMap,
) -> Result<Json<SessionStateView>, (StatusCode, Json<InteractiveError>)> {
    let key = extract_session_key(&headers)?;
    state
        .interactive
        .abandon(&key)
        .await
        .map(Json)
        .map_err(interactive_err_response)
}

/// `POST /api/interactive/close` — close a session and free its slot (#794).
///
/// Header: `X-CSQ-Session-Key` — the daemon-minted session capability key.
/// No request body. On success returns `Idle` state view. Does NOT emit any
/// synthetic chain record (directive 4: no `resolve(Abandon)` on close).
#[cfg(feature = "enterprise")]
async fn interactive_close_handler(
    State(state): State<RouterState>,
    headers: HeaderMap,
) -> Result<Json<SessionStateView>, (StatusCode, Json<InteractiveError>)> {
    let key = extract_session_key(&headers)?;
    state
        .interactive
        .close(&key)
        .await
        .map(Json)
        .map_err(interactive_err_response)
}

/// `POST /api/interactive/posture-reset` — apply a SIGNED operator posture-reset
/// authorization (T-M4.5), the only path that loosens a session's posture ratchet.
///
/// Header: `X-CSQ-Session-Key`. Body: `PostureResetAuthorization { nonce_hex,
/// target_posture, signature_hex }`. The renderer merely TRANSPORTS the
/// operator-signed blob; the daemon verifies it against the daemon-held org-root
/// verifying key over a preimage it reconstructs from its OWN session key (R1-S7 —
/// the renderer cannot forge or replay a reset). Fail-closed: `503` when no reset
/// key is configured; `403` (`action_denied`) on a bad / forged / replayed
/// signature; `409` (`session_wrong_state`) on a session with no posture ratchet.
#[cfg(feature = "enterprise")]
async fn interactive_posture_reset_handler(
    State(state): State<RouterState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SessionStateView>, (StatusCode, Json<InteractiveError>)> {
    let key = extract_session_key(&headers)?;
    let auth: csq_trust_contract::PostureResetAuthorization = serde_json::from_slice(&body)
        .map_err(|_| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(InteractiveError {
                    error: "interactive_deserialize_error",
                }),
            )
        })?;
    state
        .interactive
        .reset_posture(&key, auth)
        .await
        .map(Json)
        .map_err(interactive_err_response)
}

/// `GET /api/interactive/audit-proof/{session_id}` — read a sealed lifecycle audit
/// proof (T-M4.5).
///
/// Returns the persisted `SealedAuditProof` (only PUBLIC bytes — sealed head hash,
/// signature, verifying key — non-secret, so no session key is required; the
/// `SO_PEERCRED` same-UID socket auth already restricts callers). `404` when
/// absent. The `session_id` path param is validated (charset `[A-Za-z0-9_-]`, no
/// `..`, length-bounded) BEFORE any filesystem join so it cannot traverse out of
/// the proofs directory.
#[cfg(feature = "enterprise")]
async fn interactive_audit_proof_handler(
    State(state): State<RouterState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Result<Json<csq_trust_contract::SealedAuditProof>, (StatusCode, Json<InteractiveError>)> {
    // Validate the path param BEFORE any filesystem join (traversal defense — the
    // same charset discipline as `SessionKey::try_from_client`, length-relaxed for
    // the longer `interactive-live-{label}-{pid}-{ulid}` session_id form).
    let valid = !session_id.is_empty()
        && session_id.len() <= 128
        && !session_id.contains("..")
        && session_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(InteractiveError {
                error: "audit_proof_session_id_invalid",
            }),
        ));
    }
    let dir = state
        .base_dir
        .join(crate::daemon::interactive_ipc::AUDIT_PROOF_SUBDIR);
    match crate::daemon::interactive_ipc::read_sealed_proof(&dir, &session_id) {
        Some(proof) => Ok(Json(proof)),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(InteractiveError {
                error: "audit_proof_not_found",
            }),
        )),
    }
}

/// `POST /api/interactive/options` — list the subscription accounts the operator
/// may pick BEFORE opening a session, plus the gate's default provider (#793
/// Enforcement-tab picker, an internal journal entry §FD1).
///
/// Fail-closed: returns `503 interactive_unavailable` when the activation gate is
/// closed (`registry.is_active()` false) OR the gate file is no longer readable.
/// No session key required — this is a pre-open query that reveals only account
/// labels (no credentials, no secrets — `rules/security.md` §2). The provider is
/// the gate template's default; the candidate slots are the provider-matching
/// accounts with credentials, lowest-first (the exact set the minter validates
/// `SessionOpenParams.slot` against).
#[cfg(feature = "enterprise")]
async fn interactive_options_handler(
    State(state): State<RouterState>,
) -> Result<Json<SessionOptionsResponse>, (StatusCode, Json<InteractiveError>)> {
    let unavailable = || {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(InteractiveError {
                error: "interactive_unavailable",
            }),
        )
    };
    // Authoritative open/closed signal — same gate every other interactive route
    // checks (the registry was seeded from it at startup).
    if !state.interactive.is_active() {
        return Err(unavailable());
    }
    // The gate's default provider. is_active() ⟹ this was present at seed; map a
    // since-removed/unreadable gate to the same fail-closed 503.
    let provider = match crate::daemon::interactive_live::load_gate(&state.base_dir) {
        Some(cfg) => cfg.provider,
        None => return Err(unavailable()),
    };
    let candidate_slots =
        crate::daemon::interactive_live::candidate_subscription_slots(&state.base_dir, &provider);
    Ok(Json(SessionOptionsResponse {
        provider,
        candidate_slots,
    }))
}

/// Runs account discovery, hitting [`RouterState::discovery_cache`]
/// first and only falling through to a real filesystem scan on
/// cache miss or expiry.
///
/// Returns an empty `Vec` if the underlying spawn_blocking task
/// panics — the error is logged with a fixed tag (no `%e` per
/// RISK-0007) and the handler continues to serve an empty list
/// rather than surfacing a 500. This matches the behavior of
/// `refresh_status_all_handler` before the cache was added.
async fn cached_discovery(
    base_dir: Arc<PathBuf>,
    cache: Arc<TtlCache<(), Vec<AccountInfo>>>,
) -> Vec<AccountInfo> {
    // Fast path: the cached entry is live.
    if let Some(cached) = cache.get(&()) {
        return cached;
    }

    // Cold path: run discovery on a blocking worker. Concurrent
    // callers may both land here (bounded dogpile); see
    // DISCOVERY_CACHE_MAX_AGE docstring.
    //
    // Uses `discover_all` so Codex + third-party (MiniMax/Z.AI/
    // Ollama) + manual slots are visible to /api/accounts
    // consumers (statusline, `csq status`, Tauri dashboard). Prior
    // to this change the route returned Anthropic-only and the
    // CLI rendered an incomplete view for mixed setups.
    let base_for_task = Arc::clone(&base_dir);
    let accounts =
        match tokio::task::spawn_blocking(move || discovery::discover_all(&base_for_task)).await {
            Ok(a) => a,
            Err(_join_err) => {
                // JoinError may include a panic payload — do NOT
                // format it with `%` per RISK-0007. Log only the
                // fixed tag.
                tracing::warn!(
                    error_kind = "discovery_task_panic",
                    "accounts discovery task panicked"
                );
                Vec::new()
            }
        };

    cache.set((), accounts.clone());
    accounts
}

/// GET /api/accounts — returns the full discovered account list.
///
/// Reads from [`RouterState::discovery_cache`] when warm; runs
/// `discovery::discover_anthropic` inside `spawn_blocking` on
/// cache miss. For realistic account counts (<= 100) the response
/// size is well under the 1 MiB body cap.
async fn accounts_handler(State(state): State<RouterState>) -> Json<AccountsResponse> {
    let accounts = cached_discovery(
        Arc::clone(&state.base_dir),
        Arc::clone(&state.discovery_cache),
    )
    .await;
    Json(AccountsResponse { accounts })
}

/// GET /api/refresh-status — returns every currently-cached
/// `RefreshStatus` entry as a map keyed by account ID.
async fn refresh_status_all_handler(
    State(state): State<RouterState>,
) -> Json<RefreshStatusListResponse> {
    // Walk known account IDs via the short-TTL discovery cache
    // and look up each in the refresh-status cache. We do NOT
    // expose the refresh-status cache's internal HashMap directly
    // because that couples the IPC schema to the cache's internal
    // layout. A linear lookup over discovered accounts is fine
    // for the realistic account count.
    let accounts = cached_discovery(
        Arc::clone(&state.base_dir),
        Arc::clone(&state.discovery_cache),
    )
    .await;

    let mut entries = Vec::new();
    for info in accounts {
        if let Some(status) = state.cache.get(&info.id) {
            entries.push(status);
        }
    }

    Json(RefreshStatusListResponse { statuses: entries })
}

/// GET /api/refresh-status/:id — returns one account's cached
/// refresh status, or 404 if no cached entry exists.
///
/// The path parameter `{id}` is validated via
/// `AccountNum::try_from` — values outside 1..=999 are rejected
/// with 400 so path-injection attempts like `/api/refresh-status/
/// ../../etc` fail at deserialization (u16 parse) or the range
/// guard before touching the cache.
async fn refresh_status_one_handler(
    State(state): State<RouterState>,
    AxumPath(id): AxumPath<u16>,
) -> Result<Json<RefreshStatus>, (StatusCode, String)> {
    // Validate account number. This also defends against negative
    // or out-of-range values that slipped past the u16 decode.
    let account = AccountNum::try_from(id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid account id: {e}")))?;

    match state.cache.get(&account.get()) {
        Some(status) => Ok(Json(status)),
        None => Err((
            StatusCode::NOT_FOUND,
            format!("no cached refresh status for account {id}"),
        )),
    }
}

/// GET /api/login/:id — initiates a paste-code OAuth login for
/// the given account slot.
///
/// Generates a fresh PKCE verifier + state token, records them in
/// the shared [`OAuthStateStore`], and returns a [`LoginRequest`]
/// containing the authorize URL the caller should open in a
/// browser. After the user authorizes, Anthropic displays an
/// authorization code on its callback page; the caller then POSTs
/// that code to `/api/oauth/exchange` to complete the login.
///
/// # Errors
///
/// - **400 Bad Request** — account id is outside 1..=999.
/// - **503 Service Unavailable** — the daemon was started without
///   an OAuth state store (`oauth_store: None`). Tests and custom
///   builds can disable OAuth; real daemons always enable it.
/// - **500 Internal Server Error** — unexpected failure in
///   `start_login` (impossible on supported platforms — it only
///   fails if the OS CSPRNG is unavailable).
async fn login_handler(
    State(state): State<RouterState>,
    AxumPath(id): AxumPath<u16>,
) -> Result<Json<LoginRequest>, (StatusCode, String)> {
    let account = AccountNum::try_from(id)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid account id: {e}")))?;

    let Some(store) = state.oauth_store.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth support is not available on this daemon".to_string(),
        ));
    };

    start_login(store, account).map(Json).map_err(|e| {
        // start_login is effectively infallible for valid
        // AccountNum on supported platforms; if it ever errors we
        // map to 500 without echoing internal details.
        tracing::warn!(error = %e, "start_login failed");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "oauth login initiation failed".to_string(),
        )
    })
}

/// Request body for `POST /api/oauth/exchange`.
#[derive(Debug, Deserialize)]
pub struct OAuthExchangeRequest {
    /// State token returned by the preceding `GET /api/login/{N}`.
    pub state: String,
    /// Authorization code displayed by Anthropic on its callback
    /// page after the user authorizes.
    pub code: String,
}

/// Response body for `POST /api/oauth/exchange`.
#[derive(Debug, Clone, Serialize)]
pub struct OAuthExchangeResponse {
    /// The account slot that was authenticated — echoes
    /// [`crate::oauth::PendingState::account`] so callers can
    /// confirm without re-parsing the state token.
    pub account: u16,
}

/// POST /api/oauth/exchange — submits the paste-code from the
/// browser and exchanges it for a credential file.
///
/// Flow:
///
/// 1. Looks up the pending PKCE state keyed by `state` in the
///    [`OAuthStateStore`] — this is the authentication boundary.
///    Missing, expired, or already-consumed tokens map to 400.
/// 2. Calls [`exchange_code`] against the Anthropic token endpoint
///    with the recovered verifier and the paste-code redirect URI
///    (must be byte-identical to what the authorize URL advertised).
/// 3. Writes the resulting credential file to `credentials/N.json`
///    with `0o600` via [`credentials::save_canonical`].
/// 4. Returns the validated account number.
///
/// # Errors
///
/// - **400 Bad Request** — empty code, or state token not found /
///   expired / already consumed.
/// - **502 Bad Gateway** — Anthropic rejected the code or returned
///   a malformed token response.
/// - **500 Internal Server Error** — disk write failed.
/// - **503 Service Unavailable** — daemon started without OAuth
///   support.
///
/// All error messages are redacted by `OAuthError` / `CsqError`
/// before surfacing — the upstream response body (which may echo
/// the submitted code) is never included.
async fn oauth_exchange_handler(
    State(state): State<RouterState>,
    Json(body): Json<OAuthExchangeRequest>,
) -> Result<Json<OAuthExchangeResponse>, (StatusCode, String)> {
    let Some(store) = state.oauth_store.as_ref() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "oauth support is not available on this daemon".to_string(),
        ));
    };

    // Clean the code: strip surrounding whitespace / CRs a shell
    // caller may have included.
    let code = body.code.trim().trim_end_matches('\r').to_string();
    if code.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "code must not be empty".to_string(),
        ));
    }

    // Consume the pending entry — single-use.
    let pending = store.consume(&body.state).map_err(|e| match e {
        OAuthError::StateMismatch => (
            StatusCode::BAD_REQUEST,
            "state token not recognized".to_string(),
        ),
        OAuthError::StateExpired { .. } => {
            (StatusCode::BAD_REQUEST, "state token expired".to_string())
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "state lookup failed".to_string(),
        ),
    })?;

    // The exchange is a synchronous HTTP round-trip via blocking
    // reqwest. Run it on a spawn_blocking worker so we don't stall
    // the tokio runtime.
    let verifier = pending.code_verifier.clone();
    let account = pending.account;
    let exchange_result = tokio::task::spawn_blocking(move || {
        exchange_code(
            &code,
            &verifier,
            PASTE_CODE_REDIRECT_URI,
            crate::http::post_json_node,
        )
    })
    .await;

    let credential = match exchange_result {
        Ok(Ok(c)) => c,
        Ok(Err(OAuthError::Exchange(_))) => {
            tracing::warn!(
                account = account.get(),
                error_kind = "exchange",
                "oauth exchange failed"
            );
            return Err((StatusCode::BAD_GATEWAY, "code exchange failed".to_string()));
        }
        Ok(Err(e)) => {
            tracing::warn!(
                account = account.get(),
                error_kind = e.kind(),
                "oauth exchange unexpected error"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal oauth error".to_string(),
            ));
        }
        Err(_join_err) => {
            tracing::warn!(
                account = account.get(),
                error_kind = "join_err",
                "oauth exchange task panicked"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal oauth error".to_string(),
            ));
        }
    };

    // Persist credentials via UUID-keyed path (M4-12: numeric
    // credentials/<N>.json retired; fail-closed if UUID absent).
    //
    // an internal ticket (legacy/daemon-exchange sibling): this exchange-based path
    // has NO `config-N/.claude.json` (it never spawns `claude auth login`), so
    // `accounts::login::ensure_login_identity_minted` — which sources the email
    // from that file — is structurally inapplicable here. This handler relies on
    // daemon Pass-0 having already minted `by_slot[N]`. If this route is ever
    // made the live first-login path for fresh installs, mint the UUID from the
    // exchanged `credential`'s `oauthAccount.emailAddress` BEFORE this save, or
    // it reintroduces the #633 "no credentials configured" fail-closed.
    let base_dir = Arc::clone(&state.base_dir);
    let save_result = tokio::task::spawn_blocking(move || {
        credentials::save_canonical_for(&base_dir, account, &credential)
    })
    .await;

    match save_result {
        Ok(Ok(())) => {
            // Invalidate caches so the next /api/accounts call
            // shows the new row without waiting for the TTL.
            state.discovery_cache.clear();
            state.cache.clear();
            tracing::info!(account = account.get(), "oauth login complete");
            Ok(Json(OAuthExchangeResponse {
                account: account.get(),
            }))
        }
        Ok(Err(_)) => {
            tracing::warn!(
                account = account.get(),
                error_kind = "credential_save",
                "credential write failed after oauth exchange"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential write failed".to_string(),
            ))
        }
        Err(_join_err) => {
            tracing::warn!(
                account = account.get(),
                error_kind = "join_err",
                "credential save task panicked"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal save error".to_string(),
            ))
        }
    }
}

/// Helper trait — keeps `error_kind = ...` tags small so the
/// exchange handler can classify errors for structured logging
/// without leaking details into the tag string.
trait OAuthErrorKind {
    fn kind(&self) -> &'static str;
}

impl OAuthErrorKind for OAuthError {
    fn kind(&self) -> &'static str {
        match self {
            OAuthError::Http { .. } => "http",
            OAuthError::StateExpired { .. } => "state_expired",
            OAuthError::StateMismatch => "state_mismatch",
            OAuthError::PkceVerification => "pkce_verification",
            OAuthError::Exchange(_) => "exchange",
            OAuthError::Cancelled => "cancelled",
            OAuthError::StoreAtCapacity { .. } => "store_at_capacity",
            OAuthError::ExchangeTimeout { .. } => "exchange_timeout",
            OAuthError::LoginInProgressElsewhere { .. } => "login_in_progress",
        }
    }
}

/// POST /api/invalidate-cache — clears all daemon caches.
///
/// Called by `csq swap` after a successful account switch so that
/// subsequent `/api/accounts` and `/api/refresh-status` calls
/// reflect the new active account immediately instead of waiting
/// for the 5-second TTL to expire.
///
/// Returns `200 {"cleared": true}` unconditionally.
async fn invalidate_cache_handler(
    State(state): State<RouterState>,
) -> Json<InvalidateCacheResponse> {
    state.discovery_cache.clear();
    state.cache.clear();
    tracing::debug!("cache invalidated by client request");
    Json(InvalidateCacheResponse { cleared: true })
}

/// Response body for `POST /api/invalidate-cache`.
#[derive(Debug, Clone, Serialize)]
pub struct InvalidateCacheResponse {
    pub cleared: bool,
}

/// Request body for `POST /api/slot-swap`.
#[derive(Debug, Clone, Deserialize)]
pub struct SlotSwapRequest {
    pub from: u16,
    pub to: u16,
}

/// Response body for `POST /api/slot-swap`.
#[derive(Debug, Clone, Serialize)]
pub struct SlotSwapResponse {
    pub invalidated: bool,
}

/// POST /api/slot-swap — targeted per-slot cache invalidation after `csq move`.
///
/// Called by `csq move FROM TO` after the on-disk rename completes. The daemon
/// must drop any cached refresh-status entries keyed by the FROM and TO slot
/// numbers so that subsequent `/api/refresh-status` calls reflect the new slot
/// assignment (SEC-2.11).
///
/// The discovery cache is also cleared because account discovery reads
/// `config-N/` directory names, which have changed after a rename.
///
/// Returns `200 {"invalidated": false}` when `from == to` (no-op swap —
/// request anomaly; silently discarded per fire-and-forget semantics).
/// Returns `200 {"invalidated": true}` on a valid swap. Validation failures
/// (out-of-range slot) are logged and the in-range slot is still invalidated.
async fn slot_swap_handler(
    State(state): State<RouterState>,
    Json(req): Json<SlotSwapRequest>,
) -> Json<SlotSwapResponse> {
    use crate::types::AccountNum;
    // MED-3 guard: from == to is a no-op request anomaly (nothing was renamed).
    if req.from == req.to {
        tracing::warn!(
            error_kind = "slot_swap_noop",
            from = req.from,
            "slot_swap: from == to — no-op; returning invalidated=false"
        );
        return Json(SlotSwapResponse { invalidated: false });
    }
    if let Ok(from_num) = AccountNum::try_from(req.from) {
        state.cache.delete(&from_num.get());
    } else {
        tracing::warn!(
            error_kind = "slot_swap_invalid_from",
            from = req.from,
            "slot_swap: from slot out of range — cache entry not deleted"
        );
    }
    if let Ok(to_num) = AccountNum::try_from(req.to) {
        state.cache.delete(&to_num.get());
    } else {
        tracing::warn!(
            error_kind = "slot_swap_invalid_to",
            to = req.to,
            "slot_swap: to slot out of range — cache entry not deleted"
        );
    }
    // Clear discovery cache — config-N/ dirs have been renamed.
    state.discovery_cache.clear();
    tracing::debug!(
        from = req.from,
        to = req.to,
        "slot-swap cache invalidation applied"
    );
    Json(SlotSwapResponse { invalidated: true })
}

/// POST /api/gemini/event — accepts a single [`EventEnvelope`] from
/// csq-cli and applies it to `quota.json`.
///
/// This is the **live IPC path** for Gemini events. The csq-cli
/// emitter writes the event to its NDJSON log first (durability
/// floor) then attempts this POST with a 50ms connect ceiling. The
/// daemon dedups via `id`: if the same envelope arrives twice
/// (live IPC + later NDJSON drain), only the first apply mutates
/// `quota.json`. Per spec 05 §5.8.1.
///
/// Always returns 204 (no body) on accept-or-dedup; structured-log
/// records the outcome via `error_kind` tags. On serialisation
/// failure or invalid slot, returns 400 with a fixed-vocabulary
/// error tag (no upstream body echoes — see security.md §2).
async fn gemini_event_handler(
    State(state): State<RouterState>,
    Json(envelope): Json<crate::providers::gemini::capture::EventEnvelope>,
) -> Result<StatusCode, (StatusCode, Json<GeminiEventError>)> {
    use crate::providers::gemini::capture::{EVENT_SCHEMA_VERSION, EVENT_SURFACE_GEMINI};

    if envelope.v != EVENT_SCHEMA_VERSION {
        tracing::debug!(
            error_kind = "gemini_event_unsupported_version",
            v = envelope.v,
            slot = envelope.slot,
            "gemini IPC event with unsupported schema version"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GeminiEventError {
                error: "unsupported_version",
            }),
        ));
    }

    // PR-G3 redteam H1: reject envelopes claiming a non-Gemini
    // surface. Without this gate, a same-UID caller could POST
    // `surface: "anthropic"` and `apply_event` would clobber the
    // Anthropic slot's row (forcing surface back to "gemini" and
    // mutating counter/rate_limit fields the Anthropic UI doesn't
    // expect). Same-UID threat-model bound is real but per
    // zero-tolerance Rule 5 the cheap surface check closes it
    // structurally.
    if envelope.surface != EVENT_SURFACE_GEMINI {
        tracing::warn!(
            error_kind = "gemini_event_invalid_surface",
            slot = envelope.slot,
            received_surface = %envelope.surface,
            "gemini IPC event with non-gemini surface tag refused"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(GeminiEventError {
                error: "invalid_surface",
            }),
        ));
    }

    let slot = match crate::types::AccountNum::try_from(envelope.slot) {
        Ok(s) => s,
        Err(_) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(GeminiEventError {
                    error: "invalid_slot",
                }),
            ));
        }
    };

    // PR-G4a — H2 resolution. PR-G3 deferred this gate because no
    // binding marker existed yet; PR-G4a writes
    // `credentials/gemini-<N>.json` from `csq setkey gemini`, so
    // the daemon can now authoritatively reject IPC traffic for an
    // unprovisioned slot. Single `symlink_metadata` syscall per
    // event — no JSON parse, no vault touch — keeps the live IPC
    // hot path under its 50 ms budget per spec 07 §7.2.3.1.
    if !crate::providers::gemini::provisioning::is_gemini_bound_slot(&state.base_dir, slot) {
        tracing::warn!(
            error_kind = "gemini_event_unbound_slot",
            slot = slot.get(),
            "gemini IPC event for slot with no binding marker — refusing 404"
        );
        return Err((
            StatusCode::NOT_FOUND,
            Json(GeminiEventError {
                error: "slot_not_provisioned",
            }),
        ));
    }

    let consumer = state.gemini_consumer.clone();
    let base_dir = Arc::clone(&state.base_dir);
    let result = tokio::task::spawn_blocking(move || {
        let _q_guard = consumer
            .quota_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut applied = consumer.applied.lock().unwrap_or_else(|p| p.into_inner());
        if !applied.insert(envelope.id.clone()) {
            return Ok::<bool, String>(false);
        }
        drop(applied);
        let mut quota =
            crate::quota::state::load_state(&base_dir).map_err(|e| format!("quota load: {e}"))?;
        // PR-G3 redteam H2: structured-log when IPC creates a quota
        // row for a previously-unseen slot. Same-UID caller can still
        // do this (and we accept it — the live IPC path needs to work
        // for newly-provisioned accounts before the discovery cache
        // refreshes), but operators see the anomaly via log query.
        let new_slot = !quota.accounts.contains_key(&slot.get().to_string());
        if new_slot {
            tracing::warn!(
                error_kind = "gemini_event_first_time_slot",
                slot = slot.get(),
                "live IPC event for previously-unseen slot — verify provisioning"
            );
        }
        let mut breakers = consumer.breakers.lock().unwrap_or_else(|p| p.into_inner());
        let breaker = breakers.entry(slot.get()).or_default();
        // PR-G3 redteam M3: IPC-source events do NOT count toward
        // the schema-drift breaker — only csq-cli's NDJSON drain
        // (which observed a real malformed response) trips it.
        // Stops a same-UID caller from forcing kind=unknown via
        // drift POSTs.
        crate::daemon::usage_poller::gemini::apply_event_with_source(
            &mut quota,
            &envelope,
            breaker,
            crate::daemon::usage_poller::gemini::EventSource::Ipc,
        );
        crate::quota::state::save_state(&base_dir, &quota)
            .map_err(|e| format!("quota save: {e}"))?;
        Ok::<bool, String>(true)
    })
    .await;

    match result {
        Ok(Ok(_applied)) => Ok(StatusCode::NO_CONTENT),
        Ok(Err(reason)) => {
            tracing::warn!(
                error_kind = "gemini_event_apply_failed",
                slot = slot.get(),
                reason = %reason,
                "gemini IPC event apply failed"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GeminiEventError {
                    error: "apply_failed",
                }),
            ))
        }
        Err(_join) => {
            tracing::warn!(
                error_kind = "gemini_event_apply_panicked",
                slot = slot.get(),
                "gemini IPC event apply panicked"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GeminiEventError {
                    error: "apply_panicked",
                }),
            ))
        }
    }
}

/// Error body for `POST /api/gemini/event`. Fixed-vocabulary tag —
/// caller cannot trigger arbitrary strings here per security.md §2.
#[derive(Debug, Clone, Serialize)]
pub struct GeminiEventError {
    pub error: &'static str,
}

/// Error body for `POST /api/audit/record`. Fixed-vocabulary tag —
/// caller cannot trigger arbitrary strings here per security.md §2.
/// The `error` field maps to one of: `invalid_rule_id`,
/// `audit_deserialize_error`, `audit_io_error`, `audit_serialize_error`,
/// `audit_chain_broken`.
/// Note: `record_too_large` is now emitted as a router-level 413 (via
/// `DefaultBodyLimit`) before this handler runs, not from the handler itself.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecordError {
    pub error: &'static str,
}

/// Handler for `POST /api/audit/record`.
///
/// Accepts a JSON body matching `csq-runs-schema-v1.json`, validates
/// RULE_ID strings, serializes, and persists to
/// `~/.claude/accounts/csq-runs/<run_id>.jsonl` via the single write site
/// `audit::persist::write_record`.
///
/// **Audit-subsystem fail-closed gate:** when `RouterState::audit_health` is
/// `Broken` or `Unknown`, this handler rejects all emit requests with
/// `503 Service Unavailable` and the fixed-vocabulary tag `audit_chain_broken`.
/// No new records are appended to a chain that failed verification.
/// (`Verified` and `Degraded` both pass through normally.)
///
/// Inherits the three-layer Unix socket security per `rules/security.md`
/// §7 — no per-route auth needed.
///
/// Returns 204 on success; 400 with a fixed-vocabulary error tag on any
/// write failure; 503 with `audit_chain_broken` when the audit chain is broken.
/// No upstream body is echoed per `rules/security.md` §2.
async fn audit_record_handler(
    State(state): State<RouterState>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<AuditRecordError>)> {
    // Audit-subsystem fail-closed: reject new appends when the chain is broken.
    // Health check MUST run before body deserialization so Broken/Unknown health
    // returns 503 even when the request body would be malformed (422).
    if !state.audit_health.is_operational() {
        tracing::warn!(
            error_kind = "audit_chain_broken",
            "audit emit rejected — chain is not operational (audit_health={:?})",
            state.audit_health
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(AuditRecordError {
                error: "audit_chain_broken",
            }),
        ));
    }

    // Deserialize after health gate passes.
    let record: crate::audit::AuditRecord = serde_json::from_slice(&body).map_err(|_| {
        // Fixed-vocabulary tag only — no `{e}` interpolation (security.md §2;
        // serde_json::Error Display can echo input fragments). The tag is the signal.
        tracing::warn!(
            error_kind = "audit_deserialize_error",
            "audit record deserialize failed"
        );
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(AuditRecordError {
                error: "audit_deserialize_error",
            }),
        )
    })?;

    // M19b: capture the run_id BEFORE the record is moved into the writer so we
    // can emit the chain-level session-floor record after the v1 write succeeds.
    let run_id = record.run_id.clone();

    // Write via the single audited write site, anchored to the daemon's
    // base_dir so integration tests with a TempDir base see the file
    // under their temp path rather than $HOME/.claude/accounts.
    match crate::audit::persist::write_record_to(record, Some(&state.base_dir)) {
        Ok(_) => {
            // M19b: emit the signed chain-level session-floor record. This is
            // DEFENSE-IN-DEPTH on top of the (already-durable) v1 record, so it
            // runs OFF the response path via `spawn_blocking` — the floor emit
            // acquires the `.chain-lock` (up to 5s under contention) and may load
            // the signing key, neither of which should delay the 204 that
            // unblocks the user's `csq run`. The emit is idempotent
            // (`run:<run_id>` dedup), so the rare overlap with the `.pending`
            // reconciler drain appends exactly one floor record. Failures are
            // logged, never surfaced — the v1 record is already persisted.
            let base = state.base_dir.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = crate::audit::run_floor::emit_csq_run_record(&base, &run_id) {
                    // Fixed-vocabulary tag only — no `{e}` interpolation per
                    // security.md §2 (AuditV2Error Display carries no secrets, but
                    // OAuth-adjacent modules keep the fixed-tag discipline). The
                    // typed error is intentionally dropped; the tag is the signal.
                    let _ = e;
                    tracing::warn!(
                        error_kind = "csq_run_floor_emit_failed",
                        "M19b: csq-run session-floor record emit failed (non-fatal)"
                    );
                }
            });
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            let tag = e.fixed_tag();
            tracing::warn!(error_kind = tag, "audit record write failed");
            Err((
                StatusCode::BAD_REQUEST,
                Json(AuditRecordError { error: tag }),
            ))
        }
    }
}

/// Request body for `POST /api/audit/mcp-gate` (M6 T6.2 Shard 4).
///
/// The `csq mcp-proxy` supplies ONLY these minimal decision fields; the daemon
/// builds, signs, and appends the `McpGateDecision` `SignedRecord` server-side.
/// A spawned subprocess NEVER supplies a `SignedRecord` (it cannot sign, and
/// per `account-terminal-separation.md` MUST Rule 1 the enforcement record must
/// originate daemon-side, not from a process the renderer/CLI could influence).
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct McpGateRequest {
    /// Per-proxy-process nonce — the dedup-key namespace component.
    pub session_nonce: String,
    /// Proxy-session-monotonic decision ordinal (second dedup-key component).
    pub record_seq: u64,
    /// The spawned CLI whose MCP traffic was gated (`"codex"` | `"gemini"`).
    pub cli: String,
    /// The MCP-declared tool identifier that was gated.
    pub tool: String,
    /// Fixed-vocabulary gate verdict (`"pass"` | `"block"` | `"escalate"`).
    pub verdict: String,
}

/// Error body for `POST /api/audit/mcp-gate`. Fixed-vocabulary tag — the handler
/// never echoes upstream request content per `rules/security.md` §2 +
/// `rules/tauri-commands.md` MUST-6. Tags: `audit_chain_broken`,
/// `mcp_gate_deserialize_error`, `mcp_gate_invalid_field`, `mcp_gate_write_error`,
/// `mcp_gate_unconfirmed` (503 — the emit did not record the decision on the
/// chain, e.g. a signing-cutoff skip; the proxy queues it to its durable outbox),
/// `mcp_gate_intent_queued` (503 — the chain is uninitialised AND attestation
/// intent is set, so the proxy queues the decision to preserve it until
/// `csq audit init`; shard C decision 1).
#[cfg(feature = "enterprise")]
#[derive(Debug, Clone, Serialize)]
pub struct McpGateError {
    pub error: &'static str,
}

/// Handler for `POST /api/audit/mcp-gate` (M6 T6.2 Shard 4).
///
/// Accepts a minimal [`McpGateRequest`], validates the fixed-vocabulary fields,
/// and appends a signed `McpGateDecision` chain record via the single daemon-side
/// emitter [`crate::audit::mcp_gate_floor::emit_mcp_gate_record`] (which owns the
/// `.chain-lock` + signing key — the proxy subprocess cannot).
///
/// **Audit-subsystem fail-closed gate:** when `audit_health` is not operational,
/// rejects with `503` + `audit_chain_broken` (mirrors `audit_record_handler`).
/// The health check runs BEFORE body deserialization so a broken chain returns
/// 503 even for a malformed body.
///
/// Returns `204` on success (including a deduped/skipped emit — the decision is
/// already on the chain or the chain is uninitialised, neither an error); `422`
/// on a malformed body or invalid field; `503` on a hard chain-write error
/// (a server-side I/O failure — the proxy queues the decision to its durable
/// outbox). No upstream body is echoed (`rules/security.md` §2).
#[cfg(feature = "enterprise")]
async fn mcp_gate_handler(
    State(state): State<RouterState>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<McpGateError>)> {
    // Fail-closed: reject new appends when the chain is not operational. Runs
    // before deserialization so a broken chain returns 503 even for a bad body.
    if !state.audit_health.is_operational() {
        // Proxy queues on this 503 too — mark the outbox maybe-dirty so that once
        // the chain is repaired + the daemon restarts (which re-evaluates
        // audit_health), the first confirmed-on-chain emit drains it event-driven
        // (shard B). The periodic backstop is the belt-and-braces backstop.
        crate::audit::mcp_gate_outbox::mark_outbox_maybe_dirty();
        tracing::warn!(
            error_kind = "audit_chain_broken",
            "mcp-gate emit rejected — chain is not operational (audit_health={:?})",
            state.audit_health
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(McpGateError {
                error: "audit_chain_broken",
            }),
        ));
    }

    let req: McpGateRequest = serde_json::from_slice(&body).map_err(|_| {
        // Fixed-vocabulary tag only — no `{e}` interpolation (security.md §2;
        // serde_json::Error Display can echo input fragments). The tag is the signal.
        tracing::warn!(
            error_kind = "mcp_gate_deserialize_error",
            "mcp-gate request deserialize failed"
        );
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(McpGateError {
                error: "mcp_gate_deserialize_error",
            }),
        )
    })?;

    // Fixed-vocabulary validation via the SHARED authority (the outbox drain
    // validates against the same function, so the two ingestion paths onto the
    // signed chain can never diverge). Any out-of-vocab value is fail-closed
    // rejected (the daemon is the enforcement boundary — never trust the field
    // shape).
    let field_ok = crate::audit::mcp_gate_floor::mcp_gate_fields_valid(
        &req.session_nonce,
        &req.tool,
        &req.cli,
        &req.verdict,
    );
    if !field_ok {
        tracing::warn!(
            error_kind = "mcp_gate_invalid_field",
            "mcp-gate request rejected — field failed fixed-vocabulary validation"
        );
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(McpGateError {
                error: "mcp_gate_invalid_field",
            }),
        ));
    }

    match crate::audit::mcp_gate_floor::emit_mcp_gate_record(
        &state.base_dir,
        &req.session_nonce,
        req.record_seq,
        &req.cli,
        &req.tool,
        &req.verdict,
    ) {
        // The emit's Ok(true)/Ok(false) does NOT distinguish "recorded" from
        // "skipped without recording" — Ok(false) collapses a confirmed Duplicate
        // (on chain), a signing-cutoff skip (chain exists, keychain unavailable →
        // NOT on chain), and the uninitialised-chain case. Classify via the
        // authoritative dedup-index confirmation so the route honors the SAME
        // "204 ⟺ actually on the chain" contract the outbox drain enforces
        // (redteam #909 R3). Without this a cutoff-skip returns a false 204 and the
        // decision is lost with no fallback — the daemon-UP twin of the gap #909
        // closes on the daemon-down path.
        Ok(_) => {
            use crate::audit::mcp_gate_floor::McpGateConfirm;
            match crate::audit::mcp_gate_floor::mcp_gate_confirm(
                &state.base_dir,
                &req.session_nonce,
                req.record_seq,
            ) {
                // On chain (appended or confirmed Duplicate): 204. M6 #909 shard B —
                // the live path is confirmed healthy, so fire an event-driven drain
                // of any backlog queued during a prior outage/cutoff. The cheap
                // relaxed maybe-dirty load is a fast-path filter: the common
                // steady-state (nothing ever queued) skips the spawn entirely, so a
                // burst of gated calls does not spawn a blocking task per call. The
                // authoritative consume is the swap inside `drain_on_live_recovery`.
                // The drain runs on a blocking thread so the 204 is not delayed by
                // its chain I/O; the join is awaited in a detached task ONLY to log a
                // (documented-unreachable) panic as a JoinError — symmetric with the
                // periodic tick's panic handling, so an event-drain panic is never
                // silently dropped.
                McpGateConfirm::OnChain => {
                    if crate::audit::mcp_gate_outbox::outbox_maybe_dirty() {
                        let base = state.base_dir.as_ref().clone();
                        tokio::spawn(async move {
                            if let Err(e) = tokio::task::spawn_blocking(move || {
                                crate::audit::mcp_gate_outbox::drain_on_live_recovery(&base);
                            })
                            .await
                            {
                                tracing::warn!(
                                    error_kind = "mcp_gate_event_drain_task_panicked",
                                    error = %e,
                                    "event-driven mcp-gate outbox drain task panicked"
                                );
                            }
                        });
                    }
                    Ok(StatusCode::NO_CONTENT)
                }
                // No chain to record to (uninitialised). M6 #909 shard C
                // (decision 1): whether this decision is DROPPED or PRESERVED
                // depends on the durable attestation-intent marker —
                //   - intent SET (`csq audit intent on`): the operator will run
                //     `csq audit init`; the decision MUST NOT be silently lost.
                //     Return 503 so the proxy queues it to the durable outbox, and
                //     mark the outbox maybe-dirty so shard B's continuous drain
                //     flushes it within one interval of `csq audit init` (until
                //     then the drain defers on the un-appendable chain and PRESERVES
                //     the file — the pre-init queue is bounded + VISIBLE via the
                //     recurring deferred-drain WARN + `csq doctor`, never
                //     silently dropped).
                //   - intent UNSET (default — non-audit host): 204, drop as the
                //     pre-#909 uninit contract, so a host that will never init a
                //     chain does not accumulate an unbounded outbox.
                // A drain is NOT triggered here regardless: an uninitialised chain
                // is not appendable, so a drain would only defer.
                McpGateConfirm::NoChain => {
                    if crate::audit::outbox_paths::attestation_intent_is_set(&state.base_dir) {
                        crate::audit::mcp_gate_outbox::mark_outbox_maybe_dirty();
                        tracing::warn!(
                            error_kind = "mcp_gate_intent_queued",
                            "mcp-gate decision on an uninitialised chain with attestation \
                             intent SET; signalling the proxy to queue it to the durable \
                             outbox (run `csq audit init` to drain the pre-init queue)"
                        );
                        return Err((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(McpGateError {
                                error: "mcp_gate_intent_queued",
                            }),
                        ));
                    }
                    Ok(StatusCode::NO_CONTENT)
                }
                // Chain exists but the decision did not land (signing-cutoff skip):
                // signal the proxy to queue it to its durable outbox for a
                // next-start drain. A re-queued genuine Duplicate is harmless (the
                // drain re-confirms on-chain and deletes). Mark the outbox
                // maybe-dirty so the next confirmed-on-chain emit drains it
                // event-driven (shard B) instead of waiting for the periodic tick.
                McpGateConfirm::Unrecorded => {
                    crate::audit::mcp_gate_outbox::mark_outbox_maybe_dirty();
                    tracing::warn!(
                        error_kind = "mcp_gate_unconfirmed",
                        "mcp-gate emit did not record the decision (signing skip); \
                         signalling the proxy to queue it to the durable outbox"
                    );
                    Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(McpGateError {
                            error: "mcp_gate_unconfirmed",
                        }),
                    ))
                }
            }
        }
        Err(e) => {
            let tag = e.fixed_tag();
            // Mark the outbox maybe-dirty: the proxy queues on a server-side failure
            // (this 503, and the sibling `mcp_gate_unconfirmed` 503) — NOT on the two
            // 422 client-rejection arms (`mcp_gate_deserialize_error`,
            // `mcp_gate_invalid_field`), whose records are permanently unprocessable
            // (the drain would `invalid`-delete them, never a retryable backlog). So
            // the next confirmed-on-chain emit fires an event-driven drain (shard B).
            crate::audit::mcp_gate_outbox::mark_outbox_maybe_dirty();
            tracing::warn!(error_kind = tag, "mcp-gate record write failed");
            // 503 (not 400): a hard emit I/O failure is a SERVER-side error, not a
            // malformed client request. Consistent with the two sibling
            // server-side failure arms (`mcp_gate_unconfirmed` and the
            // `audit_chain_broken` fail-closed gate) that already return 503.
            // Functionally the proxy queues on any non-204, so this is an
            // accuracy fix for operator diagnosis, not a behaviour change.
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(McpGateError {
                    error: "mcp_gate_write_error",
                }),
            ))
        }
    }
}

/// Error body for `POST /api/provenance/anchor`.
///
/// Fixed-vocabulary tags — the handler never echoes upstream request content
/// per `rules/security.md` §2 and `rules/tauri-commands.md` MUST-6.
///
/// Tags:
/// - `"audit_chain_broken"` — chain broken sentinel present; write refused (503).
/// - `"seam_io_error"`      — quarantine or pending-dir I/O failed (503).
/// - `"seam_chain_write_error"` — chain write failed post-cutoff (503).
/// - `"seam_registry_load_failed"` — operator surface-registry.json is corrupt;
///   non-retryable (500). Operator: fix or delete the file.
/// - `"seam_internal_error"` — internal error (500).
#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceAnchorError {
    pub error: &'static str,
}

/// Handler for `POST /api/provenance/anchor`.
///
/// Accepts a raw loom F101-1 provenance event body and routes it through the
/// M18 seam ingest pipeline:
///
/// - **204 No Content**: event anchored into the audit chain (KnownVersion path).
/// - **202 Accepted**: event quarantined (frontier rejection) or parked
///   (unknown schema version). Daemon accepted custody — caller does not retry.
/// - **503 Service Unavailable**: chain broken, signing failure post-cutoff, or
///   I/O failure writing to custody dirs. Caller MAY retry after operator repair.
///
/// **Audit-subsystem fail-closed gate**: when `audit_health` is `Broken` or
/// `Unknown`, the handler returns `503` before reading the body. This mirrors
/// `audit_record_handler` — a broken chain blocks all audit appends.
///
/// **IPC security**: this route inherits the three-layer Unix socket security
/// (SO_PEERCRED same-UID, 0o600 socket, per-user dir). No per-route auth
/// is needed per `rules/security.md` §7. The inbound body is treated as
/// UNTRUSTED (self-declared actor is UNTRUSTED metadata; validation at the
/// frontier does not trust loom's claimed fields beyond what csq can verify).
///
/// **MAX_BODY_BYTES**: the router-level `DefaultBodyLimit` layer (1 MiB) caps
/// the raw body before this handler runs. The seam frontier also enforces its
/// own 256 KiB cap as defense-in-depth.
///
/// No upstream request body is echoed in any response or log.
async fn provenance_anchor_handler(
    State(state): State<RouterState>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, Json<ProvenanceAnchorError>)> {
    use crate::audit::seam::{ingest_provenance_event, IngestOutcome, SeamError};

    // Audit-subsystem fail-closed: reject appends when chain is broken.
    // Health gate MUST run before body processing.
    if !state.audit_health.is_operational() {
        tracing::warn!(
            error_kind = "seam_chain_broken",
            "provenance/anchor rejected — audit chain not operational"
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProvenanceAnchorError {
                error: "audit_chain_broken",
            }),
        ));
    }

    // Wall-clock for skew validation. Computed here (trusted daemon clock)
    // rather than trusting any timestamp in the request body.
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let base_dir = Arc::clone(&state.base_dir);
    let raw = body.to_vec();

    // Offload blocking I/O (chain lock, quarantine write, optional signing) to
    // the blocking thread pool — must not block the axum runtime.
    let result =
        tokio::task::spawn_blocking(move || ingest_provenance_event(&base_dir, &raw, now_unix))
            .await
            .map_err(|_| {
                tracing::warn!(
                    error_kind = "seam_internal_error",
                    "provenance/anchor spawn_blocking panicked"
                );
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ProvenanceAnchorError {
                        error: "seam_internal_error",
                    }),
                )
            })?;

    match result {
        Ok(IngestOutcome::Anchored { .. }) => {
            tracing::debug!(error_kind = "seam_anchored", "provenance event anchored");
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(IngestOutcome::Rejected { reason }) => {
            // Frontier rejection or quarantine. Daemon accepted custody (202).
            // Fixed-vocab reason tag — no upstream content echoed.
            tracing::info!(
                error_kind = "seam_rejected",
                reason = reason,
                "provenance event quarantined"
            );
            Ok(StatusCode::ACCEPTED)
        }
        Ok(IngestOutcome::ParkedUnknownVersion { .. }) => {
            // Unknown schema version — parked in .pending/provenance/. 202.
            tracing::info!(
                error_kind = "seam_parked",
                "provenance event parked (unknown schema version)"
            );
            Ok(StatusCode::ACCEPTED)
        }
        Ok(IngestOutcome::DuplicateSuppressed { .. }) => {
            // Duplicate decision_id — first record is authoritative. 202.
            // The caller need not retry; the first anchor is the canonical one.
            tracing::debug!(
                error_kind = "seam_duplicate_suppressed",
                "provenance event duplicate suppressed (decision_id already in chain)"
            );
            Ok(StatusCode::ACCEPTED)
        }
        Ok(IngestOutcome::HeldPendingPredecessor { .. }) => {
            // Intra-source counter gap — held in .pending/provenance-ordered/
            // until the predecessor drains or a bounded timeout fires (M20,
            // F-SEAM-09). Custody accepted; the caller need not retry. 202.
            tracing::info!(
                error_kind = "seam_held_predecessor_gap",
                "provenance event held pending intra-source predecessor"
            );
            Ok(StatusCode::ACCEPTED)
        }
        Err(SeamError::Io(_)) => {
            tracing::warn!(
                error_kind = "seam_io_error",
                "provenance/anchor custody write failed"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ProvenanceAnchorError {
                    error: "seam_io_error",
                }),
            ))
        }
        Err(SeamError::ChainWrite(_)) => {
            tracing::warn!(
                error_kind = "seam_chain_write_error",
                "provenance/anchor chain write failed (cutoff active or chain broken)"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ProvenanceAnchorError {
                    error: "seam_chain_write_error",
                }),
            ))
        }
        Err(SeamError::AnchorRequiresInit) => {
            // Pre-`audit init`: the anchored path fails closed (no unsigned
            // provenance), but with an actionable tag so the operator knows to
            // run `csq audit init` (R2 LOW-3).
            tracing::warn!(
                error_kind = "seam_anchor_requires_init",
                "provenance/anchor refused: no signing key — run `csq audit init`"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ProvenanceAnchorError {
                    error: "seam_anchor_requires_init",
                }),
            ))
        }
        Err(SeamError::RegistryLoad) => {
            tracing::warn!(
                error_kind = "seam_registry_load_failed",
                "provenance/anchor surface registry load failed"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ProvenanceAnchorError {
                    error: "seam_registry_load_failed",
                }),
            ))
        }
        Err(SeamError::CustodyFull) => {
            tracing::warn!(
                error_kind = "seam_custody_full",
                "provenance/anchor refused: custody directory at hard cap"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ProvenanceAnchorError {
                    error: "seam_custody_full",
                }),
            ))
        }
        Err(SeamError::Internal) => {
            tracing::warn!(
                error_kind = "seam_internal_error",
                "provenance/anchor internal error"
            );
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ProvenanceAnchorError {
                    error: "seam_internal_error",
                }),
            ))
        }
    }
}

/// Response body for `GET /api/accounts`.
#[derive(Debug, Clone, Serialize)]
pub struct AccountsResponse {
    pub accounts: Vec<AccountInfo>,
}

/// Response body for `GET /api/refresh-status`.
#[derive(Debug, Clone, Serialize)]
pub struct RefreshStatusListResponse {
    pub statuses: Vec<RefreshStatus>,
}

/// Handle to a running daemon HTTP server. Dropping this handle
/// does NOT stop the server — use [`ServerHandle::shutdown`] to
/// initiate graceful shutdown and await the join handle.
pub struct ServerHandle {
    /// Path to the socket file. Removed on shutdown.
    socket_path: PathBuf,
    /// Triggered to start graceful shutdown.
    shutdown: CancellationToken,
}

impl ServerHandle {
    /// Signals the server to shut down. The accept loop exits on the
    /// next poll, and in-flight connections are allowed to complete.
    /// Removes the socket file.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
        // Best-effort socket file cleanup. If the server loop is
        // already removing it, the error is ignored.
        let _ = std::fs::remove_file(&self.socket_path);
    }

    /// Returns a clone of the shutdown token so sibling subsystems
    /// (refresher, poller, future HTTP handlers) can cancel on the
    /// same signal. Cloning a `CancellationToken` is cheap — it's
    /// just an Arc bump.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Returns the socket path the server is bound to.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

/// Binds a Unix domain socket at `socket_path` and serves the daemon
/// HTTP router on it until `shutdown` fires.
///
/// `state` is the shared router state: cache + base_dir. The accept
/// loop clones `state` per-connection so handlers get independent
/// axum `State` extractor instances.
///
/// # Behavior
///
/// 1. Removes any existing file at `socket_path` (cleanup of stale
///    sockets from previous crashed daemons). If a live daemon is
///    bound there, the `try_lock`/PID file guard in
///    [`super::pid::PidFile::acquire`] should have failed already —
///    we trust that guard and overwrite.
/// 2. Binds a `tokio::net::UnixListener`.
/// 3. `chmod` the socket file to `0o600` so only the owning UID can
///    connect. Done via `std::fs::set_permissions` on the path — the
///    kernel honors this on macOS and modern Linux.
/// 4. Spawns the accept loop, which waits for connections and
///    dispatches each to a tokio task running the axum service.
/// 5. On `shutdown.cancelled()`, the accept loop exits. In-flight
///    connections are allowed to complete on their own tasks.
/// 6. Removes the socket file on exit (best-effort).
///
/// Returns a [`ServerHandle`] the caller can use to trigger
/// shutdown, and an awaitable future that resolves when the accept
/// loop has exited.
#[cfg(unix)]
pub async fn serve(
    socket_path: &Path,
    state: RouterState,
) -> Result<(ServerHandle, tokio::task::JoinHandle<()>), DaemonError> {
    // Cleanup stale socket file (previous crash).
    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(|_| DaemonError::SocketConnect {
            path: socket_path.to_path_buf(),
        })?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|_| DaemonError::SocketConnect {
                path: parent.to_path_buf(),
            })?;
        }
    }

    // Tighten umask to 0o077 so the socket file bind(2) creates has
    // 0o600 mode from the very first syscall — closing the
    // bind→chmod race window where an unprivileged local process
    // could otherwise racy-connect(2) to a world-readable socket.
    // umask(2) is process-global on Unix; we restore the previous
    // value immediately after bind. The window is bounded to a
    // single syscall and no other daemon work races it because
    // `serve()` is called from the single-threaded startup path
    // before any background tokio tasks are spawned.
    //
    // SAFETY: libc::umask is always safe to call; we restore the
    // previous mask on all paths via the explicit guard below.
    let old_umask = unsafe { libc::umask(0o077) };

    let bind_result = UnixListener::bind(socket_path);

    // Restore the original umask before handling errors so a bind
    // failure does not leave the process with a tightened mask.
    unsafe {
        libc::umask(old_umask);
    }

    let listener = bind_result.map_err(|e| {
        tracing::debug!(error = %e, path = ?socket_path, "UnixListener::bind failed");
        DaemonError::SocketConnect {
            path: socket_path.to_path_buf(),
        }
    })?;

    // Defense-in-depth: explicit set_permissions even after the
    // umask-controlled bind. If the filesystem or kernel behaved
    // unexpectedly (NFS, container layer), this catches it.
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        tracing::debug!(error = %e, "chmod socket 0o600 failed");
        DaemonError::SocketConnect {
            path: socket_path.to_path_buf(),
        }
    })?;

    let shutdown = CancellationToken::new();
    let handle = ServerHandle {
        socket_path: socket_path.to_path_buf(),
        shutdown: shutdown.clone(),
    };

    let app = Arc::new(router(state));
    let sock_for_cleanup = socket_path.to_path_buf();
    let join = tokio::spawn(async move {
        accept_loop(listener, app, shutdown, sock_for_cleanup).await;
    });

    Ok((handle, join))
}

/// The accept loop. Exits when the shutdown token is cancelled.
///
/// Each accepted connection is handed to a fresh tokio task running
/// the hyper connection service. In-flight tasks are NOT awaited on
/// shutdown — the daemon's main loop (in lifecycle.rs) is
/// responsible for the wider graceful-shutdown deadline via
/// `JoinHandle::abort` or a tokio `timeout`.
#[cfg(unix)]
async fn accept_loop(
    listener: UnixListener,
    app: Arc<Router>,
    shutdown: CancellationToken,
    socket_path: PathBuf,
) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use tower::ServiceExt;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                tracing::info!("daemon server: shutdown signaled, exiting accept loop");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _addr)) => {
                        // Verify the connecting peer runs as our own
                        // UID. Any mismatch is closed immediately —
                        // the HTTP router is never invoked. This is
                        // the second defensive layer after socket
                        // file permissions.
                        if let Err(e) = verify_peer_uid(&stream) {
                            tracing::warn!(error = %e, "rejecting cross-UID connection");
                            drop(stream);
                            continue;
                        }

                        let app = Arc::clone(&app);
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let app = Arc::clone(&app);
                                async move {
                                    let router = (*app).clone();
                                    router.oneshot(req).await
                                }
                            });
                            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                                .serve_connection(io, service)
                                .await
                            {
                                tracing::debug!(error = %e, "connection service error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed, continuing");
                        // A short pause avoids hot-spinning on
                        // persistent accept errors (e.g., EMFILE).
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }

    // Best-effort socket cleanup on exit.
    let _ = std::fs::remove_file(&socket_path);
    tracing::info!(path = ?socket_path, "daemon server: accept loop exited");
}

/// Verifies the peer at the other end of a Unix domain socket is
/// running under the same effective UID as this daemon.
///
/// On Linux this uses `getsockopt(SO_PEERCRED)` which returns a
/// `struct ucred` with the peer's PID, UID, and GID. On macOS this
/// uses `getsockopt(LOCAL_PEERCRED)` which returns a `struct xucred`
/// with `cr_uid` (among other fields).
///
/// Any getsockopt failure or UID mismatch returns `Err` — the
/// caller drops the stream without invoking the HTTP router.
#[cfg(all(unix, target_os = "linux"))]
fn verify_peer_uid(stream: &tokio::net::UnixStream) -> std::io::Result<()> {
    // `libc::ucred` layout: { pid: pid_t, uid: uid_t, gid: gid_t }
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: fd is a valid Unix-domain socket fd; cred is a valid
    // stack allocation of the right type; len matches its size.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let our_uid = unsafe { libc::geteuid() };
    if cred.uid != our_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("peer UID {} != daemon UID {}", cred.uid, our_uid),
        ));
    }
    Ok(())
}

#[cfg(all(unix, target_os = "macos"))]
fn verify_peer_uid(stream: &tokio::net::UnixStream) -> std::io::Result<()> {
    // macOS `struct xucred` from <sys/ucred.h>:
    //   cr_version: u32
    //   cr_uid:     uid_t
    //   cr_ngroups: i16
    //   cr_groups:  [gid_t; NGROUPS]  (NGROUPS = 16)
    #[repr(C)]
    struct XUcred {
        cr_version: u32,
        cr_uid: libc::uid_t,
        cr_ngroups: libc::c_short,
        cr_groups: [libc::gid_t; 16],
    }

    // From <sys/un.h>: SOL_LOCAL = 0, LOCAL_PEERCRED = 1.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERCRED: libc::c_int = 1;

    let fd = stream.as_raw_fd();
    let mut cred: XUcred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<XUcred>() as libc::socklen_t;

    // SAFETY: fd is a valid Unix-domain socket fd; cred is a valid
    // stack allocation matching struct xucred; len reflects size.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            &mut cred as *mut XUcred as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let our_uid = unsafe { libc::geteuid() };
    if cred.cr_uid != our_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("peer UID {} != daemon UID {}", cred.cr_uid, our_uid),
        ));
    }
    Ok(())
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn verify_peer_uid(_stream: &tokio::net::UnixStream) -> std::io::Result<()> {
    // Other Unixes: no portable peer-credential API. The 0o600
    // socket permission is the sole boundary; log a warning so
    // operators on BSD/Illumos/etc. are aware.
    tracing::warn!(
        "peer UID verification not implemented on this platform — \
         relying solely on socket file permissions"
    );
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Builds a minimal RouterState for tests. Both caches start
    /// empty; base_dir points at the provided temp directory. The
    /// OAuth store is present so the `/api/login/{id}` tests
    /// exercise the success path; individual tests that want to
    /// exercise the 503 path pass `oauth_store: None` via
    /// `test_state_no_oauth`. The discovery cache uses the
    /// production 5-second TTL — tests that need a shorter TTL
    /// use `test_state_with_discovery_ttl`.
    ///
    /// `audit_health` defaults to `AuditHealth::Verified` so tests
    /// that don't care about audit gating get the clean path.
    fn test_state(base: &Path) -> RouterState {
        RouterState {
            cache: Arc::new(TtlCache::with_default_age()),
            discovery_cache: Arc::new(TtlCache::new(DISCOVERY_CACHE_MAX_AGE)),
            base_dir: Arc::new(base.to_path_buf()),
            oauth_store: Some(Arc::new(OAuthStateStore::new())),
            gemini_consumer: GeminiConsumerState::default(),
            audit_health: crate::audit::AuditHealth::Verified,
            #[cfg(feature = "enterprise")]
            interactive: Arc::new(InteractiveSessionRegistry::empty()),
        }
    }

    /// Builds a RouterState with `oauth_store: None` so the
    /// `/api/login/{id}` handler returns 503.
    fn test_state_no_oauth(base: &Path) -> RouterState {
        RouterState {
            cache: Arc::new(TtlCache::with_default_age()),
            discovery_cache: Arc::new(TtlCache::new(DISCOVERY_CACHE_MAX_AGE)),
            base_dir: Arc::new(base.to_path_buf()),
            oauth_store: None,
            gemini_consumer: GeminiConsumerState::default(),
            audit_health: crate::audit::AuditHealth::Verified,
            #[cfg(feature = "enterprise")]
            interactive: Arc::new(InteractiveSessionRegistry::empty()),
        }
    }

    /// Builds a RouterState with an explicit discovery-cache TTL.
    /// Used by tests that verify expiry behavior without waiting
    /// the full 5 seconds.
    fn test_state_with_discovery_ttl(
        base: &Path,
        discovery_ttl: std::time::Duration,
    ) -> RouterState {
        RouterState {
            cache: Arc::new(TtlCache::with_default_age()),
            discovery_cache: Arc::new(TtlCache::new(discovery_ttl)),
            base_dir: Arc::new(base.to_path_buf()),
            oauth_store: Some(Arc::new(OAuthStateStore::new())),
            gemini_consumer: GeminiConsumerState::default(),
            audit_health: crate::audit::AuditHealth::Verified,
            #[cfg(feature = "enterprise")]
            interactive: Arc::new(InteractiveSessionRegistry::empty()),
        }
    }

    #[tokio::test]
    async fn serve_binds_and_sets_permissions() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();
        assert!(sock.exists(), "socket file should be created");

        // Verify 0o600 permissions.
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket must be 0o600 (owner-only)");

        handle.shutdown();
        // Give the accept loop a moment to exit.
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();

        // Socket file should be cleaned up.
        assert!(!sock.exists(), "socket file should be removed on shutdown");
    }

    #[tokio::test]
    async fn serve_cleans_stale_socket_file() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        // Pretend a stale socket file exists (regular file, not a real socket).
        std::fs::write(&sock, "stale").unwrap();
        assert!(sock.exists());

        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();
        assert!(sock.exists());

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn health_endpoint_over_real_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        // Connect and send a minimal HTTP/1.1 GET.
        let mut stream = UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        // Read the full response.
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("health response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("200 OK"),
            "expected 200 OK in response, got: {text}"
        );
        assert!(
            text.contains(r#""status":"ok""#),
            "expected JSON body, got: {text}"
        );
        assert!(
            text.contains(r#""version":""#),
            "expected version field, got: {text}"
        );

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");

        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let mut stream = UnixStream::connect(&sock).await.unwrap();
        stream
            .write_all(b"GET /api/nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        stream.flush().await.unwrap();

        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("404"),
            "expected 404 for unknown route, got: {text}"
        );

        handle.shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(1), join)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn health_response_serializes() {
        let r = HealthResponse {
            status: "ok",
            version: "2.0.0-alpha.1",
            pid: 42,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"pid\":42"));
    }

    /// Sends a minimal HTTP/1.1 GET over a Unix socket and reads
    /// the full response. Returns (status_line, body) where body
    /// is everything after the blank CRLF-CRLF.
    async fn http_get(sock: &std::path::Path, path: &str) -> (String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let mut stream = UnixStream::connect(sock).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf).into_owned();
        let status_line = text.lines().next().unwrap_or("").to_string();
        // Find the blank line separating headers from body.
        let body = text
            .find("\r\n\r\n")
            .map(|i| text[i + 4..].to_string())
            .unwrap_or_default();
        (status_line, body)
    }

    /// Issues a raw HTTP POST with a JSON body against the daemon's
    /// Unix socket and returns (status_line, body).
    async fn http_post_json(sock: &std::path::Path, path: &str, body: &str) -> (String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let mut stream = UnixStream::connect(sock).await.unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\r\n{body}",
            len = body.len(),
            body = body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf).into_owned();
        let status_line = text.lines().next().unwrap_or("").to_string();
        let body = text
            .find("\r\n\r\n")
            .map(|i| text[i + 4..].to_string())
            .unwrap_or_default();
        (status_line, body)
    }

    /// Issues a raw HTTP POST with a JSON body AND an `X-CSQ-Session-Key` header
    /// against the daemon's Unix socket; returns (status_line, body).
    #[cfg(feature = "enterprise")]
    async fn http_post_json_with_key(
        sock: &std::path::Path,
        path: &str,
        body: &str,
        session_key: &str,
    ) -> (String, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let mut stream = UnixStream::connect(sock).await.unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             X-CSQ-Session-Key: {session_key}\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\r\n{body}",
            len = body.len(),
            body = body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_to_end(&mut buf),
        )
        .await
        .expect("response within timeout")
        .unwrap();

        let text = String::from_utf8_lossy(&buf).into_owned();
        let status_line = text.lines().next().unwrap_or("").to_string();
        let body = text
            .find("\r\n\r\n")
            .map(|i| text[i + 4..].to_string())
            .unwrap_or_default();
        (status_line, body)
    }

    // ── #783/#794 interactive route integration (enterprise-only) ─────────────
    //
    // These exercise the FULL production path: the registered `/api/interactive/*`
    // routes → `RouterState::interactive` registry → `InteractiveSession::run_turn`
    // → `GovernanceLoop::execute`, over a real Unix socket. Only the provider
    // network is mocked (the live golden-3 leg is the §10.5 maintainer task).

    #[cfg(feature = "enterprise")]
    fn it_answer_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "required": ["answer"],
            "properties": { "answer": { "type": "string" } },
            "additionalProperties": true
        })
    }

    /// RouterState whose interactive registry is SEEDED over a mock `factory`.
    ///
    /// Uses [`InteractiveSessionRegistry::seeded_compat`] so the registry holds
    /// exactly one pre-built session; returns both the state AND the session key
    /// so tests can route subsequent dispatch calls to the right session.
    #[cfg(feature = "enterprise")]
    fn seeded_interactive_state(
        base: &std::path::Path,
        factory: crate::phase2b::interactive::ProviderFactory,
    ) -> (RouterState, crate::daemon::interactive_ipc::SessionKey) {
        let session = crate::phase2b::interactive::InteractiveSession::new(
            factory,
            it_answer_schema(),
            256,
            Some("route-it".into()),
        );
        let (reg, key) = InteractiveSessionRegistry::seeded_compat(session);
        let state = RouterState {
            interactive: Arc::new(reg),
            ..test_state(base)
        };
        (state, key)
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn interactive_route_submit_blocked_override_complete() {
        use crate::phase2b::provider_client::{MockProviderClient, ProviderClient, ProviderId};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Turn 1 returns schema-failing content (block); the override's corrective
        // turn returns passing content (complete). Fresh client per turn via counter.
        let counter = Arc::new(AtomicUsize::new(0));
        let factory: crate::phase2b::interactive::ProviderFactory = {
            let counter = counter.clone();
            Box::new(move || {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let content = if n == 0 {
                    serde_json::json!("not an object")
                } else {
                    serde_json::json!({ "answer": "ok" })
                };
                vec![Box::new(MockProviderClient::passing(
                    ProviderId("mock".into()),
                    content,
                )) as Box<dyn ProviderClient>]
            })
        };

        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-it.sock");
        let (state, key) = seeded_interactive_state(dir.path(), factory);
        let (handle, join) = serve(&sock, state).await.unwrap();
        let key_str = key.as_str().to_owned();

        let (status, body) = http_post_json_with_key(
            &sock,
            "/api/interactive/submit",
            r#"{"input":"do the risky thing"}"#,
            &key_str,
        )
        .await;
        assert!(
            status.contains("200"),
            "submit status: {status} body: {body}"
        );
        assert!(
            body.contains(r#""state":"blocked""#),
            "expected blocked: {body}"
        );

        let (status, body) = http_post_json_with_key(
            &sock,
            "/api/interactive/override",
            r#"{"justification":"operator accepts the risk"}"#,
            &key_str,
        )
        .await;
        assert!(
            status.contains("200"),
            "override status: {status} body: {body}"
        );
        assert!(
            body.contains(r#""state":"complete""#),
            "expected complete: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn interactive_route_fail_closed_503_on_empty_registry() {
        // Default `test_state` seeds an EMPTY registry (production fail-closed).
        // Probe via `POST /api/interactive/open` (no key required) — the route
        // returns 503 `interactive_unavailable` — NOT 404 (route is present) and
        // NOT a panic.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-it-fc.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let (status, body) = http_post_json(&sock, "/api/interactive/open", "{}").await;
        assert!(
            status.contains("503"),
            "expected 503 on empty registry, got: {status} body: {body}"
        );
        assert!(
            body.contains("interactive_unavailable"),
            "expected fail-closed tag: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn interactive_route_options_fail_closed_503_on_empty_registry() {
        // Default `test_state` seeds an EMPTY registry (gate closed). The options
        // pre-open query is fail-closed identically to the keyed routes (#793).
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-it-opt-fc.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let (status, body) = http_post_json(&sock, "/api/interactive/options", "").await;
        assert!(
            status.contains("503"),
            "expected 503 on closed gate, got: {status} body: {body}"
        );
        assert!(
            body.contains("interactive_unavailable"),
            "expected fail-closed tag: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn interactive_route_options_lists_candidate_slots() {
        // Full path: write a valid gate (provider=claude) + stage two credentialed
        // Anthropic accounts, seed a LIVE registry, then the options route returns
        // the provider + both slots lowest-first (#793 §FD1).
        use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
        use crate::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();
        // Gate: provider=claude with a minimal valid schema.
        let gate = serde_json::json!({
            "provider": "claude",
            "schema": it_answer_schema(),
        });
        std::fs::write(
            dir.path()
                .join(crate::daemon::interactive_live::GATE_FILENAME),
            gate.to_string(),
        )
        .unwrap();
        // Stage two credentialed accounts (out of order → expect lowest-first).
        for id in [4u16, 2u16] {
            let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
                claude_ai_oauth: OAuthPayload {
                    access_token: AccessToken::new(format!("at-{id}")),
                    refresh_token: RefreshToken::new(format!("rt-{id}")),
                    expires_at: 9999999999999,
                    scopes: vec![],
                    subscription_type: None,
                    rate_limit_tier: None,
                    extra: std::collections::HashMap::new(),
                },
                extra: std::collections::HashMap::new(),
            });
            credentials::save(
                &dir.path().join("credentials").join(format!("{id}.json")),
                &creds,
            )
            .unwrap();
        }

        let reg = crate::daemon::interactive_live::seed_registry(dir.path(), None, None, None);
        let state = RouterState {
            interactive: Arc::new(reg),
            ..test_state(dir.path())
        };
        let sock = dir.path().join("csq-it-opt.sock");
        let (handle, join) = serve(&sock, state).await.unwrap();

        let (status, body) = http_post_json(&sock, "/api/interactive/options", "").await;
        assert!(
            status.contains("200"),
            "options status: {status} body: {body}"
        );
        assert!(
            body.contains(r#""provider":"claude""#),
            "expected provider claude: {body}"
        );
        // Both staged slots present, lowest-first (slot 2 before slot 4).
        let two = body.find(r#""slot":2"#).expect("slot 2 present");
        let four = body.find(r#""slot":4"#).expect("slot 4 present");
        assert!(two < four, "candidates must be lowest-first: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn interactive_route_abandon_returns_idle() {
        use crate::phase2b::provider_client::{MockProviderClient, ProviderClient, ProviderId};

        // Always-failing factory → submit blocks; abandon → idle (no body needed).
        let factory: crate::phase2b::interactive::ProviderFactory = Box::new(|| {
            vec![Box::new(MockProviderClient::passing(
                ProviderId("mock".into()),
                serde_json::json!("not an object"),
            )) as Box<dyn ProviderClient>]
        });
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-it-ab.sock");
        let (state, key) = seeded_interactive_state(dir.path(), factory);
        let (handle, join) = serve(&sock, state).await.unwrap();
        let key_str = key.as_str().to_owned();

        let (_s1, b1) = http_post_json_with_key(
            &sock,
            "/api/interactive/submit",
            r#"{"input":"risky"}"#,
            &key_str,
        )
        .await;
        assert!(
            b1.contains(r#""state":"blocked""#),
            "expected blocked: {b1}"
        );

        let (s2, b2) =
            http_post_json_with_key(&sock, "/api/interactive/abandon", "", &key_str).await;
        assert!(s2.contains("200"), "abandon status: {s2} body: {b2}");
        assert!(b2.contains(r#""state":"idle""#), "expected idle: {b2}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn interactive_route_malformed_body_422() {
        use crate::phase2b::provider_client::{MockProviderClient, ProviderClient, ProviderId};

        // A malformed JSON body on `submit` is rejected at the handler boundary with
        // 422 `interactive_deserialize_error` (spec 21 §21.7), BEFORE the registry
        // is touched. We send a valid key so the key-extraction step passes.
        let factory: crate::phase2b::interactive::ProviderFactory = Box::new(|| {
            vec![Box::new(MockProviderClient::passing(
                ProviderId("mock".into()),
                serde_json::json!({ "answer": "ok" }),
            )) as Box<dyn ProviderClient>]
        });
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-it-422.sock");
        let (state, key) = seeded_interactive_state(dir.path(), factory);
        let (handle, join) = serve(&sock, state).await.unwrap();
        let key_str = key.as_str().to_owned();

        let (status, body) =
            http_post_json_with_key(&sock, "/api/interactive/submit", "{ not json", &key_str).await;
        assert!(
            status.contains("422"),
            "expected 422, got: {status} body: {body}"
        );
        assert!(
            body.contains("interactive_deserialize_error"),
            "expected deserialize tag: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn interactive_route_missing_key_header_400() {
        use crate::phase2b::provider_client::{MockProviderClient, ProviderClient, ProviderId};

        // POST /api/interactive/submit with NO X-CSQ-Session-Key header must
        // return 400 `session_key_invalid` (FIX 3: absent header → same
        // InteractiveIpcError::InvalidSessionKey path as a malformed key).
        let factory: crate::phase2b::interactive::ProviderFactory = Box::new(|| {
            vec![Box::new(MockProviderClient::passing(
                ProviderId("mock".into()),
                serde_json::json!({ "answer": "ok" }),
            )) as Box<dyn ProviderClient>]
        });
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-it-missing-key.sock");
        let (state, _key) = seeded_interactive_state(dir.path(), factory);
        let (handle, join) = serve(&sock, state).await.unwrap();

        // Send submit with no header — extract_session_key must reject it.
        let (status, body) =
            http_post_json(&sock, "/api/interactive/submit", r#"{"input":"hi"}"#).await;
        assert!(
            status.contains("400"),
            "expected 400 for missing key header, got: {status} body: {body}"
        );
        assert!(
            body.contains("session_key_invalid"),
            "expected session_key_invalid tag: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn accounts_route_returns_empty_list_on_empty_base() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let (status, body) = http_get(&sock, "/api/accounts").await;
        assert!(status.contains("200"), "status: {status}");
        assert!(
            body.contains(r#""accounts":[]"#),
            "body should have empty accounts array: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn accounts_route_lists_discovered_accounts() {
        use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
        use crate::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();

        // Install a valid credentials/1.json so discover_anthropic picks it up.
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at".into()),
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        let num = AccountNum::try_from(1u16).unwrap();
        credentials::save(
            &crate::credentials::file::canonical_path(dir.path(), num),
            &creds,
        )
        .unwrap();

        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let (status, body) = http_get(&sock, "/api/accounts").await;
        assert!(status.contains("200"), "status: {status}");
        assert!(body.contains(r#""id":1"#), "body: {body}");
        assert!(body.contains(r#""source":"Anthropic""#), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_one_returns_404_when_absent() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let (status, body) = http_get(&sock, "/api/refresh-status/1").await;
        assert!(status.contains("404"), "status: {status}");
        assert!(body.contains("no cached refresh status"), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_one_rejects_out_of_range_id() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        // 0 is out of the 1..=999 range so AccountNum::try_from rejects it.
        let (status, body) = http_get(&sock, "/api/refresh-status/0").await;
        assert!(status.contains("400"), "status: {status}");
        assert!(body.contains("invalid account id"), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_one_returns_cached_entry() {
        use crate::daemon::refresher::RefreshStatus;

        let dir = TempDir::new().unwrap();
        let state = test_state(dir.path());

        // Pre-populate the cache with a known status.
        state.cache.set(
            1,
            RefreshStatus {
                account: 1,
                last_result: "refreshed".to_string(),
                expires_at_ms: 1_234_567_890,
                checked_at_secs: 42,
            },
        );

        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, state).await.unwrap();

        let (status, body) = http_get(&sock, "/api/refresh-status/1").await;
        assert!(status.contains("200"), "status: {status}");
        assert!(body.contains(r#""account":1"#), "body: {body}");
        assert!(
            body.contains(r#""last_result":"refreshed""#),
            "body: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_all_returns_only_accounts_in_cache() {
        use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
        use crate::daemon::refresher::RefreshStatus;
        use crate::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();

        // Install account 1 and account 2, but only populate the
        // cache for account 1.
        for id in [1u16, 2] {
            let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
                claude_ai_oauth: OAuthPayload {
                    access_token: AccessToken::new("at".into()),
                    refresh_token: RefreshToken::new("rt".into()),
                    expires_at: 9_999_999_999_999,
                    scopes: vec![],
                    subscription_type: None,
                    rate_limit_tier: None,
                    extra: Default::default(),
                },
                extra: Default::default(),
            });
            let num = AccountNum::try_from(id).unwrap();
            credentials::save(
                &crate::credentials::file::canonical_path(dir.path(), num),
                &creds,
            )
            .unwrap();
        }

        let state = test_state(dir.path());
        state.cache.set(
            1,
            RefreshStatus {
                account: 1,
                last_result: "valid".to_string(),
                expires_at_ms: 9_999_999_999_999,
                checked_at_secs: 99,
            },
        );

        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, state).await.unwrap();

        let (status, body) = http_get(&sock, "/api/refresh-status").await;
        assert!(status.contains("200"), "status: {status}");
        assert!(body.contains(r#""account":1"#), "body: {body}");
        // Account 2 is not in the cache, so it must not appear.
        assert!(!body.contains(r#""account":2"#), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn login_route_returns_authorize_url() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let state = test_state(dir.path());
        // Remember the store so we can verify the pending entry.
        let store = Arc::clone(state.oauth_store.as_ref().unwrap());
        let (handle, join) = serve(&sock, state).await.unwrap();

        let (status, body) = http_get(&sock, "/api/login/3").await;
        assert!(status.contains("200"), "status: {status}");
        // Paste-code flow: authorize URL is the current Anthropic
        // endpoint and the redirect_uri embedded in it is the
        // paste-code callback page, not a loopback URL.
        assert!(
            body.contains(r#""auth_url":"https://claude.com/cai/oauth/authorize"#),
            "body: {body}"
        );
        assert!(
            body.contains("platform.claude.com%2Foauth%2Fcode%2Fcallback"),
            "redirect_uri must be the paste-code callback, body: {body}"
        );
        assert!(body.contains(r#""account":3"#), "body: {body}");
        assert!(body.contains(r#""state":""#));
        assert_eq!(store.len(), 1, "state store should have one pending entry");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn login_route_returns_503_when_oauth_unavailable() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let state = test_state_no_oauth(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        let (status, body) = http_get(&sock, "/api/login/1").await;
        assert!(status.contains("503"), "status: {status}");
        assert!(body.contains("oauth support is not available"));

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn oauth_exchange_rejects_empty_code() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        let req_body = r#"{"state":"anything","code":"   "}"#;
        let (status, body) = http_post_json(&sock, "/api/oauth/exchange", req_body).await;
        assert!(status.contains("400"), "status: {status}");
        assert!(body.contains("code must not be empty"), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn oauth_exchange_rejects_unknown_state() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let (handle, join) = serve(&sock, test_state(dir.path())).await.unwrap();

        // Send a state token that was never issued — the consume
        // step must reject it as state_mismatch and return 400.
        let req_body = r#"{"state":"never-issued-this-token","code":"some-code"}"#;
        let (status, body) = http_post_json(&sock, "/api/oauth/exchange", req_body).await;
        assert!(status.contains("400"), "status: {status}");
        assert!(body.contains("state token"), "body: {body}");

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn oauth_exchange_returns_503_when_oauth_unavailable() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let state = test_state_no_oauth(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        let req_body = r#"{"state":"any","code":"any"}"#;
        let (status, body) = http_post_json(&sock, "/api/oauth/exchange", req_body).await;
        assert!(status.contains("503"), "status: {status}");
        assert!(body.contains("oauth support is not available"));

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn oauth_exchange_route_consumes_state_on_success_path_shape() {
        // The exchange handler pulls the pending state from the
        // store *before* making the HTTP round-trip. This test
        // verifies that the state_mismatch branch drops the entry
        // so a subsequent retry with the same token fails the
        // same way — i.e. state is single-use even on failure.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let state = test_state(dir.path());
        let store = Arc::clone(state.oauth_store.as_ref().unwrap());
        let (handle, join) = serve(&sock, state).await.unwrap();

        // Seed one pending entry so we have a valid state token.
        let account = AccountNum::try_from(1u16).unwrap();
        let verifier = crate::oauth::CodeVerifier::new("test-verifier".into());
        let state_token = store.insert(verifier, account).unwrap();
        assert_eq!(store.len(), 1);

        // First call with a wrong state token — should 400 and
        // leave the pending entry alone.
        let req_body = r#"{"state":"not-the-real-one","code":"dummy"}"#;
        let (status, _body) = http_post_json(&sock, "/api/oauth/exchange", req_body).await;
        assert!(status.contains("400"));
        assert_eq!(
            store.len(),
            1,
            "wrong state token must not consume the legitimate entry"
        );

        // Second call with the real state token and a dummy code:
        // the state gets consumed even though the HTTP exchange
        // will fail (no real token endpoint reachable). We only
        // verify the store length here — the actual exchange
        // failure mode is covered by the csq_core::oauth::exchange
        // unit tests.
        //
        // IMPORTANT: We send the request but do NOT wait for the
        // full HTTP response. The exchange handler calls Anthropic's
        // real token endpoint (no mock injected), which either
        // times out or returns an error. Waiting for that response
        // causes the test to time out at the 2s deadline in
        // http_post_json. Instead, we send the request over the
        // Unix socket and give the handler enough time to consume
        // the state entry (which happens BEFORE the HTTP call).
        {
            use tokio::io::AsyncWriteExt;
            use tokio::net::UnixStream;

            let real_body = format!(r#"{{"state":"{state_token}","code":"some-code"}}"#);
            let req = format!(
                "POST /api/oauth/exchange HTTP/1.1\r\n\
                 Host: localhost\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {len}\r\n\
                 Connection: close\r\n\r\n{body}",
                len = real_body.len(),
                body = real_body,
            );
            let mut stream = UnixStream::connect(&sock).await.unwrap();
            stream.write_all(req.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            // Give the handler time to parse the request and consume
            // the state entry. The consume call is synchronous and
            // happens before spawn_blocking, so 200ms is generous.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            // Drop the stream — we don't need the response.
        }

        assert_eq!(
            store.len(),
            0,
            "successful state lookup must consume the entry"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), join).await;
    }

    #[tokio::test]
    async fn accounts_handler_uses_discovery_cache() {
        // Verify the second GET /api/accounts hits the cache
        // rather than doing a fresh filesystem scan. We do this
        // by deleting the credentials file between calls — if
        // discovery were re-running, the second call would see
        // an empty list, but the cache should still return the
        // pre-deletion state until the TTL elapses.
        use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
        use crate::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();
        let num = AccountNum::try_from(1u16).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at".into()),
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        let cred_path = credentials::file::canonical_path(dir.path(), num);
        credentials::save(&cred_path, &creds).unwrap();

        let sock = dir.path().join("csq-test.sock");
        let state = test_state(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        // First call: runs discovery, finds account 1, caches.
        let (status1, body1) = http_get(&sock, "/api/accounts").await;
        assert!(status1.contains("200"), "status1: {status1}");
        assert!(body1.contains(r#""id":1"#), "body1: {body1}");

        // Delete the credentials file. Discovery would now return
        // an empty list — but the cache should still serve the
        // pre-deletion entry.
        std::fs::remove_file(&cred_path).unwrap();

        // Second call: must hit the cache.
        let (status2, body2) = http_get(&sock, "/api/accounts").await;
        assert!(status2.contains("200"), "status2: {status2}");
        assert!(
            body2.contains(r#""id":1"#),
            "second call must serve cached list, got: {body2}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn accounts_handler_cache_expires_after_ttl() {
        use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
        use crate::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();
        let num = AccountNum::try_from(1u16).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at".into()),
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        let cred_path = credentials::file::canonical_path(dir.path(), num);
        credentials::save(&cred_path, &creds).unwrap();

        // Very short TTL so the test doesn't wait 5 seconds.
        let sock = dir.path().join("csq-test.sock");
        let state = test_state_with_discovery_ttl(dir.path(), std::time::Duration::from_millis(50));
        let (handle, join) = serve(&sock, state).await.unwrap();

        // Populate the cache.
        let (status1, _) = http_get(&sock, "/api/accounts").await;
        assert!(status1.contains("200"));

        // Delete the file so a fresh discovery would return empty.
        std::fs::remove_file(&cred_path).unwrap();

        // Wait past the TTL.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;

        // Third call: cache expired → fresh discovery → empty list.
        let (status3, body3) = http_get(&sock, "/api/accounts").await;
        assert!(status3.contains("200"), "status3: {status3}");
        assert!(
            body3.contains(r#""accounts":[]"#),
            "expired cache should fall through to fresh discovery, got: {body3}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn refresh_status_all_uses_cached_discovery() {
        // Verify refresh_status_all_handler also uses the discovery
        // cache — not just accounts_handler. Two calls in a row
        // must hit the cache on the second even if the underlying
        // filesystem changed.
        use crate::credentials::{self, AnthropicCredentialFile, CredentialFile, OAuthPayload};
        use crate::daemon::refresher::RefreshStatus;
        use crate::types::{AccessToken, RefreshToken};

        let dir = TempDir::new().unwrap();
        let num = AccountNum::try_from(1u16).unwrap();
        let creds = CredentialFile::Anthropic(AnthropicCredentialFile {
            claude_ai_oauth: OAuthPayload {
                access_token: AccessToken::new("at".into()),
                refresh_token: RefreshToken::new("rt".into()),
                expires_at: 9_999_999_999_999,
                scopes: vec![],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        });
        let cred_path = credentials::file::canonical_path(dir.path(), num);
        credentials::save(&cred_path, &creds).unwrap();

        let sock = dir.path().join("csq-test.sock");
        let state = test_state(dir.path());
        // Pre-populate the refresh-status cache so the aggregated
        // response has something to return.
        state.cache.set(
            1,
            RefreshStatus {
                account: 1,
                last_result: "valid".to_string(),
                expires_at_ms: 9_999_999_999_999,
                checked_at_secs: 0,
            },
        );
        let (handle, join) = serve(&sock, state).await.unwrap();

        let (status1, body1) = http_get(&sock, "/api/refresh-status").await;
        assert!(status1.contains("200"), "status1: {status1}");
        assert!(body1.contains(r#""account":1"#), "body1: {body1}");

        // Delete the credential file — discovery on a miss would
        // return empty, which would produce an empty statuses
        // list. The cache must prevent that.
        std::fs::remove_file(&cred_path).unwrap();

        let (status2, body2) = http_get(&sock, "/api/refresh-status").await;
        assert!(status2.contains("200"), "status2: {status2}");
        assert!(
            body2.contains(r#""account":1"#),
            "refresh-status must serve cached discovery, got: {body2}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    #[tokio::test]
    async fn login_route_rejects_out_of_range_id() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let state = test_state(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        // 0 is out of range (AccountNum requires >=1)
        let (status, body) = http_get(&sock, "/api/login/0").await;
        assert!(status.contains("400"), "status: {status}");
        assert!(body.contains("invalid account id"));

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// MED-3 regression: `POST /api/slot-swap` with `from == to` is a no-op
    /// request anomaly. The handler MUST return `{"invalidated": false}` and
    /// MUST NOT clear the discovery cache (no-op means no rename happened).
    #[tokio::test]
    async fn slot_swap_handler_rejects_from_equals_to() {
        // Arrange: start a live server.
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-test.sock");
        let state = test_state(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        // Act: POST /api/slot-swap with from == to (request anomaly).
        let (status, body) = http_post_json(&sock, "/api/slot-swap", r#"{"from":3,"to":3}"#).await;

        // Assert: HTTP 200, invalidated = false.
        assert!(status.contains("200"), "expected 200, got: {status}");
        assert!(
            body.contains("\"invalidated\":false"),
            "expected invalidated=false for from==to noop, got: {body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    // ── Audit-health gate tests ──────────────────────────────────────────────

    /// `POST /api/audit/record` is accepted when `audit_health` is Verified.
    #[tokio::test]
    async fn audit_record_accepted_when_health_verified() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-audit-ok.sock");
        let state = test_state(dir.path()); // Verified by default
        let (handle, join) = serve(&sock, state).await.unwrap();

        // Minimal valid v1 audit record body.
        let body = r#"{"run_id":"r1","ts":"2026-06-05T00:00:00Z","surface":"anthropic","decision":"allow","reason":"test","result":"success"}"#;
        let (status, _resp) = http_post_json(&sock, "/api/audit/record", body).await;
        // 204 = accepted; 400 = write error (no chain yet in tempdir is fine —
        // we only care the gate did NOT return 503.
        assert!(
            !status.contains("503"),
            "verified health must not return 503, got: {status}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// `POST /api/audit/record` is rejected (503) when `audit_health` is Broken.
    #[tokio::test]
    async fn audit_record_rejected_when_health_broken() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-audit-broken.sock");
        let mut state = test_state(dir.path());
        state.audit_health = crate::audit::AuditHealth::Broken {
            error_kind: "audit_chain_broken_at_seq_0".to_string(),
            reason: "test broken chain".to_string(),
        };
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"run_id":"r2","ts":"2026-06-05T00:00:00Z","surface":"anthropic","decision":"allow","reason":"test","result":"success"}"#;
        let (status, resp_body) = http_post_json(&sock, "/api/audit/record", body).await;
        assert!(
            status.contains("503"),
            "broken health must return 503, got: {status}"
        );
        assert!(
            resp_body.contains("audit_chain_broken"),
            "response body must contain audit_chain_broken tag, got: {resp_body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// `POST /api/audit/record` is rejected (503) when `audit_health` is Unknown.
    #[tokio::test]
    async fn audit_record_rejected_when_health_unknown() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-audit-unknown.sock");
        let mut state = test_state(dir.path());
        state.audit_health = crate::audit::AuditHealth::Unknown {
            reason: "audit_verify_timeout".to_string(),
        };
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"run_id":"r3","ts":"2026-06-05T00:00:00Z","surface":"anthropic","decision":"allow","reason":"test","result":"success"}"#;
        let (status, resp_body) = http_post_json(&sock, "/api/audit/record", body).await;
        assert!(
            status.contains("503"),
            "unknown health must return 503, got: {status}"
        );
        assert!(
            resp_body.contains("audit_chain_broken"),
            "response body must contain audit_chain_broken tag, got: {resp_body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// `POST /api/audit/record` is accepted when `audit_health` is Degraded.
    #[tokio::test]
    async fn audit_record_accepted_when_health_degraded() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-audit-degraded.sock");
        let mut state = test_state(dir.path());
        state.audit_health = crate::audit::AuditHealth::Degraded {
            gaps: vec![crate::audit::KeyGap {
                key_id: format!("ed25519:{}", "a".repeat(64)),
                first_seq: 0,
                last_seq: 5,
                count: 6,
            }],
        };
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"run_id":"r4","ts":"2026-06-05T00:00:00Z","surface":"anthropic","decision":"allow","reason":"test","result":"success"}"#;
        let (status, _resp) = http_post_json(&sock, "/api/audit/record", body).await;
        assert!(
            !status.contains("503"),
            "degraded health must not return 503, got: {status}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    // ── M6 T6.2 Shard 4 — MCP gate decision route tests ──────────────────────

    /// A well-formed MCP gate decision is accepted (not 503) under verified
    /// health. With an uninitialised chain in the tempdir the emit skips
    /// (`Ok(false)` — no genesis minting), which still returns 204: the route
    /// contract is "accepted", the append is best-effort.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn mcp_gate_accepted_when_health_verified() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-mcp-ok.sock");
        let state = test_state(dir.path()); // Verified by default
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"session_nonce":"mcp-proxy-1-ab","record_seq":0,"cli":"codex","tool":"mcp__shell__exec","verdict":"block"}"#;
        let (status, _resp) = http_post_json(&sock, "/api/audit/mcp-gate", body).await;
        assert!(
            status.contains("204"),
            "verified health + valid body must return 204, got: {status}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// Shard C (decision 1): on an uninitialised chain with attestation intent SET,
    /// a well-formed decision returns 503 `mcp_gate_intent_queued` (signalling the
    /// proxy to QUEUE it to the durable outbox) instead of the default 204-drop.
    /// This is the setup-ordering window — the operator declared intent before
    /// `csq audit init`, so the decision must be preserved, not lost. Complements
    /// `mcp_gate_accepted_when_health_verified` (uninit + NO intent → 204 drop).
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn mcp_gate_uninit_with_intent_returns_503_intent_queued() {
        let dir = TempDir::new().unwrap();
        // Declare attestation intent BEFORE any decision (pre-init window).
        crate::audit::outbox_paths::set_attestation_intent(dir.path()).unwrap();
        let sock = dir.path().join("csq-mcp-intent.sock");
        let state = test_state(dir.path()); // Verified health, chain uninitialised.
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"session_nonce":"mcp-proxy-9-cd","record_seq":0,"cli":"codex","tool":"mcp__shell__exec","verdict":"block"}"#;
        let (status, resp) = http_post_json(&sock, "/api/audit/mcp-gate", body).await;
        assert!(
            status.contains("503"),
            "uninit chain + intent SET must return 503 (queue), got: {status}"
        );
        assert!(
            resp.contains("mcp_gate_intent_queued"),
            "the 503 tag must be mcp_gate_intent_queued, got: {resp}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// Shard C: the DEFAULT (no intent marker) uninit path still returns 204 — a
    /// non-audit host does not queue. Explicit regression guard that intent is
    /// OPT-IN (the `mcp_gate_accepted_when_health_verified` sibling shares the
    /// behaviour but this pins the intent-unset precondition by name).
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn mcp_gate_uninit_without_intent_returns_204_drop() {
        let dir = TempDir::new().unwrap();
        assert!(
            !crate::audit::outbox_paths::attestation_intent_is_set(dir.path()),
            "precondition: no intent marker"
        );
        let sock = dir.path().join("csq-mcp-noint.sock");
        let state = test_state(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"session_nonce":"mcp-proxy-9-ef","record_seq":0,"cli":"codex","tool":"mcp__shell__exec","verdict":"block"}"#;
        let (status, _resp) = http_post_json(&sock, "/api/audit/mcp-gate", body).await;
        assert!(
            status.contains("204"),
            "uninit chain + NO intent must drop (204), got: {status}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// R3/R4: with an INITIALISED chain a well-formed decision is appended and
    /// CONFIRMED on chain (`mcp_gate_confirm` → OnChain) → 204, and the record is
    /// actually present. Complements `mcp_gate_accepted_when_health_verified`
    /// (which exercises the uninitialised NoChain → 204 path). The `Unrecorded →
    /// 503 mcp_gate_unconfirmed` arm requires a signing-cutoff + keychain-
    /// unavailable state that is not hermetic; it is covered by the floor unit test
    /// `mcp_gate_floor::tests::decision_on_chain_reflects_actual_landing` (all three
    /// `McpGateConfirm` states) plus the handler's exhaustive (wildcard-free) match.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn mcp_gate_confirmed_on_initialised_chain_returns_204_and_records() {
        use crate::audit::persist::write_record_v2;
        use crate::audit::types::{
            Ed25519Signature, EventKind, EventPayload, KeyId, McpGateDecisionPayload, RecordId,
            Sha256Hex, SignedRecord,
        };

        let dir = TempDir::new().unwrap();
        // Bootstrap a chain genesis so the decision has a real chain to land on.
        let boot = SignedRecord {
            schema_version: crate::audit::persist::AUDIT_SCHEMA_VERSION_TEST.to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::McpGateDecision,
            payload: EventPayload::McpGateDecision(McpGateDecisionPayload {
                session_nonce: "bootstrap".to_string(),
                record_seq: 0,
                cli: "codex".to_string(),
                tool: "bootstrap_tool".to_string(),
                verdict: "pass".to_string(),
                enforcement_fidelity: crate::audit::mcp_gate_floor::MCP_ENFORCEMENT_FIDELITY
                    .to_string(),
            }),
            ts: crate::audit::persist::current_iso8601_utc_persist(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
            verification_level: None,
        };
        write_record_v2(boot, Some(dir.path())).unwrap();

        let sock = dir.path().join("csq-mcp-onchain.sock");
        let state = test_state(dir.path()); // Verified
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"session_nonce":"mcp-proxy-9-cafe","record_seq":1,"cli":"codex","tool":"mcp__fs__read","verdict":"pass"}"#;
        let (status, _resp) = http_post_json(&sock, "/api/audit/mcp-gate", body).await;
        assert!(
            status.contains("204"),
            "a decision confirmed on an initialised chain must return 204, got: {status}"
        );

        // The decision is actually on the chain (OnChain, not a false 204).
        assert!(
            crate::audit::mcp_gate_floor::mcp_gate_decision_on_chain(
                dir.path(),
                "mcp-proxy-9-cafe",
                1
            ),
            "the confirmed decision must be present on the chain"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// Fail-closed: an MCP gate decision is rejected (503) when the chain is
    /// broken — no new attestation appends to a chain that failed verification.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn mcp_gate_rejected_when_health_broken() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-mcp-broken.sock");
        let mut state = test_state(dir.path());
        state.audit_health = crate::audit::AuditHealth::Broken {
            error_kind: "audit_chain_broken_at_seq_0".to_string(),
            reason: "test broken chain".to_string(),
        };
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"session_nonce":"mcp-proxy-1-ab","record_seq":0,"cli":"codex","tool":"t","verdict":"block"}"#;
        let (status, resp_body) = http_post_json(&sock, "/api/audit/mcp-gate", body).await;
        assert!(
            status.contains("503"),
            "broken health must return 503, got: {status}"
        );
        assert!(
            resp_body.contains("audit_chain_broken"),
            "response must carry audit_chain_broken tag, got: {resp_body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// An out-of-vocabulary verdict is rejected fail-closed (422
    /// `mcp_gate_invalid_field`) — the daemon never trusts the field shape.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn mcp_gate_rejects_invalid_verdict() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-mcp-badverdict.sock");
        let state = test_state(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        // verdict "allow" is NOT in the fixed vocabulary {pass,block,escalate}.
        let body = r#"{"session_nonce":"mcp-proxy-1-ab","record_seq":0,"cli":"codex","tool":"t","verdict":"allow"}"#;
        let (status, resp_body) = http_post_json(&sock, "/api/audit/mcp-gate", body).await;
        assert!(
            status.contains("422"),
            "invalid verdict must return 422, got: {status}"
        );
        assert!(
            resp_body.contains("mcp_gate_invalid_field"),
            "response must carry mcp_gate_invalid_field tag, got: {resp_body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// An unknown `cli` value is rejected fail-closed (422) — only codex/gemini
    /// are attributable spawn surfaces.
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn mcp_gate_rejects_unknown_cli() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-mcp-badcli.sock");
        let state = test_state(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        let body = r#"{"session_nonce":"mcp-proxy-1-ab","record_seq":0,"cli":"claude","tool":"t","verdict":"block"}"#;
        let (status, resp_body) = http_post_json(&sock, "/api/audit/mcp-gate", body).await;
        assert!(
            status.contains("422"),
            "unknown cli must return 422, got: {status}"
        );
        assert!(
            resp_body.contains("mcp_gate_invalid_field"),
            "got: {resp_body}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    // M5 — provenance anchor handler tests.

    /// M5(a): POST /api/provenance/anchor with a well-formed body whose
    /// schema version is not in the production registry returns 202 (event
    /// parked in `.pending/provenance/`).
    ///
    /// The production version dispatcher has ZERO registered arms (ADR-B2).
    /// Every well-formed inbound event hits `ParkedUnknownVersion` → 202
    /// until M18-bind registers the first decoder arm. This test verifies
    /// the handler maps `ParkedUnknownVersion` correctly to 202 and does
    /// NOT return 503 or 500.
    #[tokio::test]
    async fn provenance_anchor_wellformed_unknown_version_parked_202() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-prov-anchor-parked.sock");
        let state = test_state(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        // A body that passes frontier validation (well-formed UUID, ts within skew,
        // registered surface "cc") but has an unknown schema version.
        // Production dispatcher → ParkedUnknownVersion → 202.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ts = crate::audit::seam::frontier::canonical_ts_for_test(now_unix);
        let decision_id = "12345678-1234-1234-1234-123456789012";
        let body = format!(
            r#"{{"f101_schema_version":"unknown-v99","decision_id":"{decision_id}","claimed_decision_ts":"{ts}","surface":"cc","source_counter":1,"payload":"{{}}"}}"#,
        );
        let (status, resp) = http_post_json(&sock, "/api/provenance/anchor", &body).await;
        assert!(
            status.contains("202"),
            "provenance/anchor with unknown-version body must return 202 (parked); got: {status}, body: {resp}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }

    /// M5(b): POST /api/provenance/anchor with a completely malformed body
    /// returns 202 (event quarantined, not a hard error to the caller).
    ///
    /// Malformed bodies hit the frontier-rejection path → quarantine →
    /// `seam_event_rejected` chain record attempt (which may produce 503 if
    /// no signing key is present for the rejection record). The seam IPC
    /// contract returns 202 for `Rejected` outcomes so loom doesn't retry.
    ///
    /// Note: the rejection path writes an unsigned record pre-`audit init`,
    /// so it succeeds without a signing key.
    #[tokio::test]
    async fn provenance_anchor_accepts_malformed_with_202() {
        let dir = TempDir::new().unwrap();
        let sock = dir.path().join("csq-prov-anchor-malformed.sock");
        let state = test_state(dir.path());
        let (handle, join) = serve(&sock, state).await.unwrap();

        // Completely malformed body — not valid JSON.
        let (status, _resp) = http_post_json(&sock, "/api/provenance/anchor", "not-json").await;
        assert!(
            status.contains("202"),
            "provenance/anchor with malformed body must return 202 (quarantined); got: {status}"
        );

        handle.shutdown();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), join).await;
    }
}
