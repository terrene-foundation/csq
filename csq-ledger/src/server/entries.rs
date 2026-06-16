//! `GET /v1/log/entries/{id}` — retrieve a record + its current inclusion proof.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use csq_core::audit::types::SignedRecord;

use crate::checkpoint::Checkpoint;
use crate::server::submit::build_checkpoint;
use crate::server::{AppState, ErrorBody};

/// Response for `GET /v1/log/entries/{id}`: the record plus an inclusion proof
/// valid against the CURRENT tree head (`checkpoint`).
#[derive(Debug, Serialize, Deserialize)]
pub struct EntryResponse {
    /// The stored record.
    pub record: SignedRecord,
    /// The assigned log index (seq).
    pub log_index: u64,
    /// Hex-encoded RFC 6962 inclusion proof against the current tree head.
    pub inclusion_proof: Vec<String>,
    /// The current signed checkpoint (the proof verifies against this root).
    pub checkpoint: Checkpoint,
}

/// Handler for `GET /v1/log/entries/{id}`.
///
/// `id` is validated as a `RecordId` shape by lookup (the store keys on the
/// raw string; an unknown id returns 404). No path traversal is possible —
/// the id is a map key, never a filesystem path.
pub async fn get_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<EntryResponse>), (StatusCode, Json<ErrorBody>)> {
    // Bound the id length defensively (record ids are <= 36 chars).
    if id.is_empty() || id.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid_id",
                detail: "record id must be 1-64 characters",
            }),
        ));
    }

    let Some((seq, record)) = state.store.record_by_id(&id) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "not_found",
                detail: "no record with that id in this log",
            }),
        ));
    };

    let proof = state.store.inclusion_proof(seq).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "proof_unavailable",
            detail: "inclusion proof could not be computed for the record",
        }),
    ))?;

    Ok((
        StatusCode::OK,
        Json(EntryResponse {
            record,
            log_index: seq,
            inclusion_proof: proof.iter().map(hex::encode).collect(),
            checkpoint: build_checkpoint(&state),
        }),
    ))
}
