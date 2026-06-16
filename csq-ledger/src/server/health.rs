//! `GET /v1/health` — health check + first-boot signing-key WARN surface.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::server::AppState;

/// Response for `GET /v1/health`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Always `"ok"` when the server is serving requests.
    pub status: &'static str,
    /// Current tree size (number of logged records).
    pub tree_size: u64,
    /// The persistent first-boot backup warning, present ONLY while an
    /// auto-generated signing key is in use AND has not been acknowledged via
    /// `CSQ_LEDGER_SIGNING_KEY_PATH` (milestone decision 2). Absent once the
    /// operator sets the env var.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_warning: Option<&'static str>,
}

/// Handler for `GET /v1/health`.
pub async fn get_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let signing_key_warning = if state.signing_key.warn_active() {
        Some(crate::signing::AUTO_KEY_WARNING)
    } else {
        None
    };
    Json(HealthResponse {
        status: "ok",
        tree_size: state.store.tree_size(),
        signing_key_warning,
    })
}
