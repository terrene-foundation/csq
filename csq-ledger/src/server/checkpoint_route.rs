//! `GET /v1/checkpoint` — the current signed tree head.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use crate::checkpoint::Checkpoint;
use crate::server::submit::build_checkpoint;
use crate::server::AppState;

/// Handler for `GET /v1/checkpoint`.
///
/// Returns the freshly-signed checkpoint over the current tree. When
/// `--anchor-to-sink` is configured and at least one anchor has been
/// acknowledged, the `anchored_to` field is populated from the latest stored
/// anchor receipt.
pub async fn get_checkpoint(State(state): State<Arc<AppState>>) -> Json<Checkpoint> {
    Json(build_checkpoint(&state))
}
