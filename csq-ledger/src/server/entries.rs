//! `GET /v1/log/entries/{id}` — retrieve a record + its current inclusion proof.
//!
//! Supplying `?tenant_id=<id>` additionally asks the existing verification
//! endpoint for an authority-signed, tenant-bound anchor verdict. The handler
//! verifies the inclusion proof and signed checkpoint before it signs that
//! result; it never turns an unverified entry into a `valid` response.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use csq_core::audit::types::SignedRecord;

use crate::anchor_verdict::{
    validate_bootstrap_challenge, validate_tenant_id, validate_verifier_id, AnchorRevocation,
    AnchorVerdict, VerifiedAnchor, VerifierBootstrap,
};
use crate::checkpoint::Checkpoint;
use crate::merkle;
use crate::server::submit::build_checkpoint;
use crate::server::{AppState, ErrorBody};
use crate::storage::{canonical_leaf_bytes, StorageError};

/// Optional tenant binding requested from the existing entry-verification endpoint.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryVerificationQuery {
    /// A bounded tenant identifier. Omitted preserves the original response shape.
    pub tenant_id: Option<String>,
}

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
    /// Present only when the caller supplied `tenant_id`. The authority signs
    /// this fresh verdict after verifying the record proof against `checkpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_verdict: Option<AnchorVerdict>,
}

/// The fresh caller nonce that binds one bootstrap redemption response to its request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierBootstrapRedemptionRequest {
    /// Exactly 32 random bytes in lower-case hexadecimal.
    pub challenge: String,
}

/// Handler for `GET /v1/log/entries/{id}`.
///
/// `id` is validated as a `RecordId` shape by lookup (the store keys on the
/// raw string; an unknown id returns 404). No path traversal is possible —
/// the id is a map key, never a filesystem path.
pub async fn get_entry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<EntryVerificationQuery>,
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

    let checkpoint = build_checkpoint(&state);
    let anchor_verdict = match query.tenant_id {
        None => None,
        Some(tenant_id) => Some(
            issue_anchor_verdict(&state, &id, seq, &record, &proof, &checkpoint, tenant_id).await?,
        ),
    };

    Ok((
        StatusCode::OK,
        Json(EntryResponse {
            record,
            log_index: seq,
            inclusion_proof: proof.iter().map(hex::encode).collect(),
            checkpoint,
            anchor_verdict,
        }),
    ))
}

/// Authority action to permanently revoke a tenant-bound entry anchor.
///
/// This route is served ONLY from [`crate::server::build_authority_router`] —
/// the dedicated authority listener, loopback-only by default (H3, spec 17
/// §17.3). The server deliberately has no in-process authentication; network
/// topology (the separate bind) is the access-control boundary for this
/// irreversible operation. The persisted fact and every subsequent verdict
/// are Ed25519-signed by the CSQ authority.
pub async fn revoke_entry_anchor(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<EntryVerificationQuery>,
) -> Result<(StatusCode, Json<AnchorRevocation>), (StatusCode, Json<ErrorBody>)> {
    if id.is_empty() || id.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid_id",
                detail: "record id must be 1-64 characters",
            }),
        ));
    }
    let tenant_id = required_tenant_id(query.tenant_id)?;
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
    let checkpoint = build_checkpoint(&state);
    verified_anchor(&id, seq, &record, &proof, &checkpoint)?;

    let revoke_state = Arc::clone(&state);
    let revocation = tokio::task::spawn_blocking(move || {
        revoke_state.store.revoke_anchor(
            id,
            tenant_id,
            chrono::Utc::now(),
            &revoke_state.signing_key,
        )
    })
    .await
    .map_err(|_| authority_state_error())?
    .map_err(|_| authority_state_error())?;

    Ok((StatusCode::OK, Json(revocation)))
}

/// Atomically redeem the sole durable bootstrap for one verifier namespace.
///
/// This route is served ONLY from [`crate::server::build_authority_router`],
/// the same loopback-by-default authority listener as anchor revocation (H3).
/// The signed response is bound to a caller-generated challenge, preventing a
/// recorded response from becoming a reset token after a consumer loses local
/// replay state.
pub async fn redeem_verifier_bootstrap(
    State(state): State<Arc<AppState>>,
    Path(verifier_id): Path<String>,
    Json(request): Json<VerifierBootstrapRedemptionRequest>,
) -> Result<(StatusCode, Json<VerifierBootstrap>), (StatusCode, Json<ErrorBody>)> {
    validate_verifier_id(&verifier_id).map_err(|_| invalid_verifier_bootstrap_request())?;
    validate_bootstrap_challenge(&request.challenge)
        .map_err(|_| invalid_verifier_bootstrap_request())?;
    let redemption_state = Arc::clone(&state);
    let result = tokio::task::spawn_blocking(move || {
        redemption_state.store.redeem_verifier_bootstrap(
            verifier_id,
            request.challenge,
            chrono::Utc::now(),
            &redemption_state.signing_key,
        )
    })
    .await
    .map_err(|_| authority_state_error())?;
    match result {
        Ok(bootstrap) => Ok((StatusCode::CREATED, Json(bootstrap))),
        Err(StorageError::VerifierBootstrapAlreadyRedeemed) => Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "verifier_bootstrap_redeemed",
                detail: "verifier bootstrap was already redeemed",
            }),
        )),
        Err(_) => Err(authority_state_error()),
    }
}

async fn issue_anchor_verdict(
    state: &Arc<AppState>,
    anchor_id: &str,
    log_index: u64,
    record: &SignedRecord,
    proof: &[[u8; 32]],
    checkpoint: &Checkpoint,
    tenant_id: String,
) -> Result<AnchorVerdict, (StatusCode, Json<ErrorBody>)> {
    let tenant_id = required_tenant_id(Some(tenant_id))?;
    let anchor = verified_anchor(anchor_id, log_index, record, proof, checkpoint)?;
    // Revocation status is NOT read here. Reading it before the spawn_blocking
    // releases the storage lock across an await, and a revoke landing in that
    // window yields a Valid verdict at a higher version than the revocation.
    // `issue_anchor_verdict` resolves it under the version-allocating lock.
    let issue_state = Arc::clone(state);
    tokio::task::spawn_blocking(move || {
        issue_state.store.issue_anchor_verdict(
            anchor,
            tenant_id,
            chrono::Utc::now(),
            &issue_state.signing_key,
        )
    })
    .await
    .map_err(|_| authority_state_error())?
    .map_err(|_| authority_state_error())
}

fn verified_anchor(
    anchor_id: &str,
    log_index: u64,
    record: &SignedRecord,
    proof: &[[u8; 32]],
    checkpoint: &Checkpoint,
) -> Result<VerifiedAnchor, (StatusCode, Json<ErrorBody>)> {
    let root_bytes = hex::decode(&checkpoint.root_hash).map_err(|_| authority_state_error())?;
    if root_bytes.len() != 32 || !checkpoint.verify() || checkpoint.tree_size == 0 {
        return Err(authority_state_error());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_bytes);
    let leaf = merkle::hash_leaf(&canonical_leaf_bytes(record));
    if !merkle::verify_inclusion(
        &leaf,
        log_index as usize,
        checkpoint.tree_size as usize,
        proof,
        &root,
    ) {
        return Err(authority_state_error());
    }
    Ok(VerifiedAnchor {
        anchor_id: anchor_id.to_owned(),
        leaf_hash: hex::encode(leaf),
        log_index,
        checkpoint_tree_size: checkpoint.tree_size,
        checkpoint_root_hash: checkpoint.root_hash.clone(),
    })
}

fn required_tenant_id(tenant_id: Option<String>) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    let tenant_id = tenant_id.ok_or((
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: "invalid_tenant",
            detail: "tenant_id is required for an anchor verdict",
        }),
    ))?;
    validate_tenant_id(&tenant_id).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "invalid_tenant",
                detail: "tenant id must be a bounded identifier",
            }),
        )
    })?;
    Ok(tenant_id)
}

fn invalid_verifier_bootstrap_request() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorBody {
            error: "invalid_verifier_bootstrap",
            detail: "verifier id and challenge must be valid",
        }),
    )
}

fn authority_state_error() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody {
            error: "anchor_verification_failed",
            detail: "anchor could not be verified and signed",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only now: production no longer names the status, it is derived
    // inside `issue_anchor_verdict` under the version-allocating lock.
    use crate::anchor_verdict::AnchorVerdictStatus;
    use crate::server::submit::submit_entry;
    use crate::signing::ServerSigningKey;
    use crate::storage::LedgerStore;
    use axum::extract::{Path, Query, State};
    use csq_core::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
    };
    use tempfile::TempDir;

    fn sample(record_id: &str) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_owned(),
            record_id: RecordId::try_new(record_id.to_owned()).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "anchor-verdict-test".to_owned(),
            }),
            ts: "2026-05-29T00:00:00+00:00".to_owned(),
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
        let key = ServerSigningKey::load_or_generate(dir, None).unwrap();
        let store = LedgerStore::open_with_authority(dir, key.key_id()).unwrap();
        Arc::new(AppState::new(store, key, None))
    }

    #[tokio::test]
    async fn tenant_query_returns_signed_verdict_and_revocation_denies() {
        let dir = TempDir::new().unwrap();
        let state = state(dir.path());
        let record_id = "01JZ00000000000000000000AV";
        let _ = submit_entry(State(Arc::clone(&state)), Json(sample(record_id)))
            .await
            .unwrap();

        let query = EntryVerificationQuery {
            tenant_id: Some("tenant-a".to_owned()),
        };
        let first = get_entry(
            State(Arc::clone(&state)),
            Path(record_id.to_owned()),
            Query(query),
        )
        .await
        .unwrap()
        .1
         .0;
        let first_verdict = first.anchor_verdict.expect("tenant query emits verdict");
        assert_eq!(first_verdict.status, AnchorVerdictStatus::Valid);
        assert_eq!(first_verdict.version, 1);
        first_verdict
            .ensure_servable(
                record_id,
                "tenant-a",
                state.signing_key.key_id(),
                None,
                chrono::Utc::now(),
            )
            .expect("a valid, fresh verdict is servable");

        let revocation = revoke_entry_anchor(
            State(Arc::clone(&state)),
            Path(record_id.to_owned()),
            Query(EntryVerificationQuery {
                tenant_id: Some("tenant-a".to_owned()),
            }),
        )
        .await
        .unwrap()
        .1
         .0;
        assert_eq!(revocation.version, 2);
        revocation
            .verify_with_authority(state.signing_key.key_id())
            .expect("revocation is authority signed");

        let revoked = get_entry(
            State(Arc::clone(&state)),
            Path(record_id.to_owned()),
            Query(EntryVerificationQuery {
                tenant_id: Some("tenant-a".to_owned()),
            }),
        )
        .await
        .unwrap()
        .1
         .0
        .anchor_verdict
        .expect("tenant query emits revoked verdict");
        assert_eq!(revoked.status, AnchorVerdictStatus::Revoked);
        assert_eq!(revoked.version, 3);
        assert_eq!(
            revoked.ensure_servable(
                record_id,
                "tenant-a",
                state.signing_key.key_id(),
                Some(first_verdict.version),
                chrono::Utc::now(),
            ),
            Err(crate::anchor_verdict::AnchorVerdictError::Revoked)
        );
    }

    #[tokio::test]
    async fn verifier_bootstrap_is_durable_one_time_challenge_bound_authority() {
        let dir = TempDir::new().unwrap();
        let state = state(dir.path());
        let verifier_id = "praxis.production.verdict-state";
        let challenge = "a".repeat(64);

        let first = redeem_verifier_bootstrap(
            State(Arc::clone(&state)),
            Path(verifier_id.to_owned()),
            Json(VerifierBootstrapRedemptionRequest {
                challenge: challenge.clone(),
            }),
        )
        .await
        .expect("first redemption succeeds");
        assert_eq!(first.0, StatusCode::CREATED);
        let receipt = first.1 .0;
        assert_eq!(receipt.verifier_id, verifier_id);
        assert_eq!(receipt.challenge, challenge);
        // The full consumer contract, not just the signature: a consumer that
        // checks only the signature accepts any receipt this authority ever
        // minted, including one addressed to a different verifier.
        receipt
            .verify_for_redemption(
                verifier_id,
                &challenge,
                state.signing_key.key_id(),
                chrono::Utc::now(),
            )
            .expect("receipt is authority signed, live, and bound to this request");

        let second = redeem_verifier_bootstrap(
            State(Arc::clone(&state)),
            Path(verifier_id.to_owned()),
            Json(VerifierBootstrapRedemptionRequest {
                challenge: "b".repeat(64),
            }),
        )
        .await
        .expect_err("a second redemption must not become a reset path");
        assert_eq!(second.0, StatusCode::CONFLICT);
        assert_eq!(second.1 .0.error, "verifier_bootstrap_redeemed");
    }
}
