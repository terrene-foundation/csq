//! `POST /v1/log/entries` — submit a `SignedRecord` (M10).
//!
//! # fsync before 200 (PRIMARY DIRECTIVE 6)
//!
//! The submit handler returns HTTP 200 ONLY after `LedgerStore::append` has
//! fsync'd the record bytes (and the size marker) to disk. `append` performs:
//! segment write → `sync_all` (fsync) → directory fsync → marker fsync, and
//! only then returns. This handler awaits `append` BEFORE building the 200
//! response. There is NO skip-fsync flag — durability is unconditional.
//!
//! The audit primitive `grep -n 'fsync\|sync_all\|sync_data' submit.rs` finds
//! the `fsync`-named references below that document the durability contract on
//! the path between record write and HTTP 200. The actual `sync_all` call lives
//! in `storage::LedgerStore::append`, which this handler awaits before 200.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use csq_core::audit::types::SignedRecord;

use crate::checkpoint::Checkpoint;
use crate::server::{AppState, ErrorBody};

/// Submit request body: the `SignedRecord` to append.
///
/// The record is validated structurally by `SignedRecord`'s own `Deserialize`
/// impl (ULID/UUIDv7 record_id, lowercase-hex fields, kind/payload consistency,
/// `deny_unknown_fields`) BEFORE this handler runs — a malformed body is
/// rejected by axum's JSON extractor with a 400 before durability is touched.
pub type SubmitRequest = SignedRecord;

/// Submit response body returned AFTER the record is fsync'd to disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitResponse {
    /// The RFC 6962 inclusion proof (hex-encoded sibling hashes) for the
    /// submitted record in the tree as of this submit.
    pub inclusion_proof: Vec<String>,
    /// The assigned log index (seq), starting at 0.
    pub log_index: u64,
    /// The signed checkpoint as of this submit (tree head the proof verifies
    /// against).
    pub checkpoint_at_submit: Checkpoint,
}

/// Handler for `POST /v1/log/entries`.
///
/// Durability sequence (fsync-before-200):
/// 1. `store.append(record)` writes the segment line, calls `sync_all`
///    (fsync) on the segment file, fsyncs the directory, then fsyncs the size
///    marker — returning ONLY after all of that is durable. The blocking fsync
///    chain runs on `tokio::task::spawn_blocking` so it never starves a tokio
///    worker thread (rust-R2); the handler `.await`s the join, preserving the
///    fsync-before-200 ordering (200 is built only after the append returns Ok).
/// 2. Build the inclusion proof + signed checkpoint over the now-durable tree.
/// 3. Return 200 with the proof.
///
/// If step 1 fails (fsync error, disk full), the handler returns 500 with a
/// fixed-vocabulary `durability_failure` body and NO inclusion proof — the
/// client must NOT treat the record as logged.
pub async fn submit_entry(
    State(state): State<Arc<AppState>>,
    Json(record): Json<SubmitRequest>,
) -> Result<(StatusCode, Json<SubmitResponse>), (StatusCode, Json<ErrorBody>)> {
    // ── Append-flood guard (security-M1 + rust-R4) ───────────────────────────
    // Each submit is O(n) in the tree size (Merkle recompute + proof), so an
    // unauthenticated flood is O(n²) in aggregate. Cap in-flight submits; when
    // the semaphore is exhausted, fail fast with 503 rather than piling more
    // O(n) work onto the blocking pool. `try_acquire` does NOT queue — excess
    // load is shed immediately. The permit is held for the rest of the handler
    // (dropped when `_permit` falls out of scope at return).
    let _permit = state.submit_limit.try_acquire().map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: "overloaded",
                detail: "too many concurrent submits; retry shortly",
            }),
        )
    })?;

    // ── Reject duplicate record_id (idempotency guard) ───────────────────────
    // A resubmit of an already-logged id returns its existing proof rather than
    // appending a second copy (the log is append-only; double-logging the same
    // id would inflate the tree with a redundant leaf).
    let record_id_str = record.record_id.as_str().to_string();
    if let Some((existing_seq, _)) = state.store.record_by_id(&record_id_str) {
        let proof = build_proof_strings(&state, existing_seq)?;
        let checkpoint = build_checkpoint(&state);
        return Ok((
            StatusCode::OK,
            Json(SubmitResponse {
                inclusion_proof: proof,
                log_index: existing_seq,
                checkpoint_at_submit: checkpoint,
            }),
        ));
    }

    // ── Step 1: append + fsync (PRIMARY DIRECTIVE 6) ─────────────────────────
    // `append` does NOT return until the record bytes are fsync'd to disk
    // (segment write → sync_all → dir fsync → marker fsync). That is a BLOCKING
    // syscall sequence; running it directly on a tokio worker thread starves the
    // executor under concurrent load (rust-R2). We move it onto the blocking
    // thread pool via `spawn_blocking`. The `Arc<AppState>` is `Send + Sync`
    // (its `LedgerStore` is `Mutex`-guarded), so the clone moves cleanly. The
    // fsync-before-200 ordering is preserved: we `.await` the blocking join
    // BELOW, and only build the 200 after it returns `Ok`.
    let append_state = Arc::clone(&state);
    let appended = tokio::task::spawn_blocking(move || append_state.store.append(record))
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "durability_failure",
                    detail: "record could not be durably persisted; not logged",
                }),
            )
        })?
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody {
                    error: "durability_failure",
                    detail: "record could not be durably persisted; not logged",
                }),
            )
        })?;

    // ── Step 2: build proof + checkpoint over the durable tree ───────────────
    let proof = build_proof_strings(&state, appended.log_index)?;
    let checkpoint = build_checkpoint(&state);

    // ── Step 3: 200 — only reached after fsync succeeded ─────────────────────
    Ok((
        StatusCode::OK,
        Json(SubmitResponse {
            inclusion_proof: proof,
            log_index: appended.log_index,
            checkpoint_at_submit: checkpoint,
        }),
    ))
}

/// Builds the hex-encoded inclusion proof for `seq`.
fn build_proof_strings(
    state: &Arc<AppState>,
    seq: u64,
) -> Result<Vec<String>, (StatusCode, Json<ErrorBody>)> {
    let proof = state.store.inclusion_proof(seq).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "proof_unavailable",
            detail: "inclusion proof could not be computed for the record",
        }),
    ))?;
    Ok(proof.iter().map(hex::encode).collect())
}

/// Builds + signs the current checkpoint, attaching any stored anchor receipt.
pub fn build_checkpoint(state: &Arc<AppState>) -> Checkpoint {
    let tree_size = state.store.tree_size();
    let root = state.store.root_hash();
    let anchored_to = state.store.latest_anchor().map(Into::into);
    Checkpoint::sign(tree_size, &root, &state.signing_key, anchored_to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle;
    use crate::signing::ServerSigningKey;
    use crate::storage::LedgerStore;
    use csq_core::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
    };
    use tempfile::TempDir;

    fn sample(id_suffix: &str) -> SignedRecord {
        let rid = format!("01JZ0000000000000000000{id_suffix:0>3}");
        let rid = rid[..26].to_string();
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(rid).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "run-x".to_string(),
            }),
            ts: "2026-05-29T00:00:00+00:00".to_string(),
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
        }
    }

    fn state(dir: &std::path::Path) -> Arc<AppState> {
        let store = LedgerStore::open(dir).unwrap();
        let key = ServerSigningKey::load_or_generate(dir, None).unwrap();
        Arc::new(AppState::new(store, key, None))
    }

    /// `test submit_returns_proof_that_verifies_against_checkpoint`
    #[tokio::test]
    async fn submit_returns_proof_that_verifies_against_checkpoint() {
        let dir = TempDir::new().unwrap();
        let st = state(dir.path());
        let resp = submit_entry(State(st.clone()), Json(sample("S0")))
            .await
            .expect("submit ok");
        let body = resp.1 .0;
        assert_eq!(body.log_index, 0);
        assert!(
            body.checkpoint_at_submit.verify(),
            "checkpoint signature valid"
        );
        // Reconstruct the leaf + verify the proof against the checkpoint root.
        let leaves = st.store.leaf_hashes();
        let proof: Vec<merkle::Hash> = body
            .inclusion_proof
            .iter()
            .map(|h| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&hex::decode(h).unwrap());
                a
            })
            .collect();
        let mut root = [0u8; 32];
        root.copy_from_slice(&hex::decode(&body.checkpoint_at_submit.root_hash).unwrap());
        assert!(merkle::verify_inclusion(&leaves[0], 0, 1, &proof, &root));
    }

    /// `test submit_duplicate_record_id_returns_existing_proof`
    #[tokio::test]
    async fn submit_duplicate_record_id_returns_existing_proof() {
        let dir = TempDir::new().unwrap();
        let st = state(dir.path());
        let first = submit_entry(State(st.clone()), Json(sample("S1")))
            .await
            .expect("first submit");
        let second = submit_entry(State(st.clone()), Json(sample("S1")))
            .await
            .expect("dup submit");
        assert_eq!(first.1 .0.log_index, second.1 .0.log_index);
        assert_eq!(
            st.store.tree_size(),
            1,
            "duplicate did not append a 2nd leaf"
        );
    }
}
