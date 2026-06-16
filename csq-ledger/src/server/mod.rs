//! axum HTTP/JSON server for csq-ledger (M10, PRIMARY DIRECTIVE 5: axum, not tonic).
//!
//! # Routes
//!
//! | Method | Path                     | Handler                          |
//! |--------|--------------------------|----------------------------------|
//! | POST   | `/v1/log/entries`        | [`submit::submit_entry`]         |
//! | GET    | `/v1/log/entries/{id}`   | [`entries::get_entry`]           |
//! | GET    | `/v1/checkpoint`         | [`checkpoint_route::get_checkpoint`] |
//! | GET    | `/v1/health`             | [`health::get_health`]           |
//!
//! # Authn
//!
//! None in M10 (per the milestone scope). The operator deploys csq-ledger
//! behind their own reverse proxy / VPN / mTLS termination. The server is the
//! storage + proof primitive, not the access-control plane.
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

/// Builds the axum [`Router`] with all four v1 routes wired to `state`.
///
/// The router pins an explicit [`DefaultBodyLimit`] of [`MAX_BODY_BYTES`] so the
/// body cap is code-defined, not dependent on axum's implicit 2 MiB default. The
/// submit-concurrency bound is enforced inside the submit handler via the
/// `AppState::submit_limit` semaphore (read routes stay ungated).
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/log/entries", post(submit::submit_entry))
        .route("/v1/log/entries/{id}", get(entries::get_entry))
        .route("/v1/checkpoint", get(checkpoint_route::get_checkpoint))
        .route("/v1/health", get(health::get_health))
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
