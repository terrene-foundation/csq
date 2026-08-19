//! axum HTTP/JSON server for csq-ledger (M10, PRIMARY DIRECTIVE 5: axum, not tonic).
//!
//! # Two listeners, two routers (H3)
//!
//! csq-ledger is an INTERNAL-ONLY service — it is never exposed to the public
//! internet, with or without a fronting proxy (spec 17 §17.3). Within that
//! internal-only posture, one operation is still singled out for an extra,
//! narrower boundary: revocation is PERMANENT (there is no un-revoke), so any
//! principal that can reach it can permanently deny any anchor for any tenant.
//! The server therefore builds and serves TWO independent routers on TWO
//! independent listeners, sharing one [`AppState`]:
//!
//! - [`build_read_router`] — submit + all read routes. Bound per `--bind` /
//!   `--port` (defaults to all interfaces, for reachability within the
//!   operator's internal network).
//! - [`build_authority_router`] — revoke + verifier-bootstrap redemption.
//!   Bound per `--authority-bind` / `--authority-port`, defaulting to
//!   `127.0.0.1` (loopback-only) so an operator who does nothing beyond the
//!   defaults still cannot reach revoke/bootstrap from another host.
//!
//! | Listener  | Method | Path                     | Handler                          |
//! |-----------|--------|--------------------------|-----------------------------------|
//! | read      | POST   | `/v1/log/entries`        | [`submit::submit_entry`]         |
//! | read      | GET    | `/v1/log/entries/{id}`   | [`entries::get_entry`]           |
//! | read      | GET    | `/v1/checkpoint`         | [`checkpoint_route::get_checkpoint`] |
//! | read      | GET    | `/v1/health`             | [`health::get_health`]           |
//! | authority | POST   | `/v1/log/entries/{id}/revoke` | [`entries::revoke_entry_anchor`] |
//! | authority | POST   | `/v1/log/verifier-bootstraps/{id}` | [`entries::redeem_verifier_bootstrap`] |
//!
//! # Authn
//!
//! No per-request authentication (per the milestone scope). Access control is
//! network topology, not an in-process check: the read listener is reachable
//! from wherever the operator's internal network places it, and the authority
//! listener additionally requires the operator to have opted the bind address
//! out of loopback-only. The server is the storage + proof primitive, not an
//! internet-facing access-control plane.
//!
//! # No secrets in responses (rules/tauri-commands.md MUST-3, security.md)
//!
//! No response body carries the signing-key seed. The checkpoint exposes only
//! the PUBLIC key (32 bytes). Error bodies are fixed-vocabulary tags — never
//! raw I/O errors or paths.

pub mod checkpoint_route;
pub mod entries;
pub mod health;
pub mod submit;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Semaphore;

use crate::anchor::AnchorTarget;
use crate::signing::ServerSigningKey;
use crate::storage::LedgerStore;

/// Maximum accepted request-body size, in bytes. A valid `SignedRecord` is a
/// few hundred bytes; 64 KiB is generous headroom. Pinned in code (not left to
/// axum's implicit 2 MiB default) so an unauthenticated client cannot stream a
/// large body to OOM / disk-fill the server (security-M1 + rust-R4).
pub const MAX_BODY_BYTES: usize = 65_536;

/// Maximum number of `POST /v1/log/entries` submits processed concurrently.
/// Each submit is O(n) in the tree size (Merkle recompute), so an
/// unauthenticated append-flood is O(n²) in aggregate; capping in-flight
/// submits bounds the amplification. Excess submits get a fast 503 instead of
/// piling onto the blocking pool (security-M1 + rust-R4). Reads (entries,
/// checkpoint, health) are NOT gated — they are cheap and must stay responsive
/// for monitoring even under submit pressure.
pub const MAX_INFLIGHT_SUBMITS: usize = 32;

/// Shared application state handed to every route handler.
pub struct AppState {
    /// The append-only store.
    pub store: LedgerStore,
    /// The server checkpoint signing key.
    pub signing_key: ServerSigningKey,
    /// Optional anchor target (`--anchor-to-sink`). `None` = no external
    /// anchoring configured.
    pub anchor: Option<AnchorTarget>,
    /// Bounds concurrent `POST /v1/log/entries` submits (append-flood guard).
    /// The submit handler acquires a permit before the O(n) Merkle path; when
    /// the semaphore is exhausted it returns 503 rather than queueing unbounded
    /// work onto the blocking pool.
    pub submit_limit: Arc<Semaphore>,
}

impl AppState {
    /// Constructs the shared state.
    #[must_use]
    pub fn new(
        store: LedgerStore,
        signing_key: ServerSigningKey,
        anchor: Option<AnchorTarget>,
    ) -> Self {
        Self {
            store,
            signing_key,
            anchor,
            submit_limit: Arc::new(Semaphore::new(MAX_INFLIGHT_SUBMITS)),
        }
    }
}

/// Builds the READ/WRITE axum [`Router`] (H3) — submit plus all read routes.
/// Bound to `--bind`/`--port` by [`crate::config::Config::socket_addr`].
///
/// Does NOT include `POST .../revoke` or `POST .../verifier-bootstraps/{id}` —
/// those are authority operations served only by [`build_authority_router`] on
/// a separate, loopback-by-default listener (see the module doc "Two
/// listeners, two routers"). A caller who can only reach this router can
/// submit and read; they cannot permanently deny an anchor.
///
/// The router pins an explicit [`DefaultBodyLimit`] of [`MAX_BODY_BYTES`] so the
/// body cap is code-defined, not dependent on axum's implicit 2 MiB default. The
/// submit-concurrency bound is enforced inside the submit handler via the
/// `AppState::submit_limit` semaphore (read routes stay ungated).
pub fn build_read_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/log/entries", post(submit::submit_entry))
        .route("/v1/log/entries/{id}", get(entries::get_entry))
        .route("/v1/checkpoint", get(checkpoint_route::get_checkpoint))
        .route("/v1/health", get(health::get_health))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Builds the AUTHORITY axum [`Router`] (H3) — revoke + verifier-bootstrap
/// redemption ONLY. Bound to `--authority-bind`/`--authority-port` by
/// [`crate::config::Config::authority_socket_addr`], which defaults to
/// `127.0.0.1` — reachable only from the local host unless the operator
/// explicitly widens the bind. Revocation is irreversible, so this listener
/// is deliberately the narrowest-reachable surface in the server (see the
/// module doc "Two listeners, two routers").
///
/// Carries the same [`DefaultBodyLimit`] as the read router; these routes are
/// not exempted from a request-size cap merely because they are narrower-bound.
pub fn build_authority_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/v1/log/entries/{id}/revoke",
            post(entries::revoke_entry_anchor),
        )
        .route(
            "/v1/log/verifier-bootstraps/{id}",
            post(entries::redeem_verifier_bootstrap),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// A fixed-vocabulary error response body. NEVER carries raw I/O errors,
/// filesystem paths, or key material.
#[derive(Debug, serde::Serialize)]
pub struct ErrorBody {
    /// A stable machine-readable error tag (e.g. `"not_found"`, `"durability_failure"`).
    pub error: &'static str,
    /// A short operator-facing description (fixed vocabulary).
    pub detail: &'static str,
}
