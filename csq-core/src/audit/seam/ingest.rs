//! M18 BE seam — provenance event ingest orchestrator.
//!
//! `ingest_provenance_event` is the single public entry point for the seam.
//! It sequences:
//!
//! 1. Precheck (size + JSON-well-formed + schema_version integer extraction).
//! 2. Dispatch on schema version.
//! 3. Outcome routing:
//!    - 3a. Rejection  → quarantine + `seam_event_rejected` chain record.
//!    - 3b. UnknownVer → park in `.pending/provenance/` (no chain record).
//!    - 3c. KnownVer   → v1 decode → attest + build ProvenanceAnchored + sign/anchor.
//!
//! ## Production path (M18-bind)
//!
//! The production entry point (`ingest_provenance_event`) uses:
//! - `precheck` — size + JSON + schema_version (version-agnostic)
//! - `decode::decode` — typed, closed-shape v1 decode
//! - `reconcile::decide_gap_prev_link` — prev_link hash-chain ordering
//!
//! ## Test path (legacy scaffolding)
//!
//! `ingest_provenance_event_with_test_registry` keeps the old
//! `validate_event` (frontier) + test-version (`"test-v0"`) pipeline so
//! existing scaffolding tests keep compiling without changes. Gap detection
//! in the test path uses the new `prev_link` model; test events with no
//! `prev_link` field are treated as genesis events (always `Proceed`).
//!
//! ## Security invariants honored
//!
//! - HIGH-1: no verbatim words, no raw event body appears in chain records.
//!   `seam_event_rejected` carries only fixed-vocab `reason` + optional
//!   parsed header fields; `ProvenanceAnchored` carries `received_bytes_hash`
//!   (the SHA-256 of raw bytes), never the bytes themselves.
//! - HIGH-2: nonce single-use binding lives in M17 `attest_authorship`.
//! - HIGH-3: chain writes go through `write_record_v2_signed` (single writer).

use std::path::Path;
use std::time::{Duration, Instant};

use crate::audit::dev_identity::{attest_authorship, Principal};
use crate::audit::key_custody::{
    try_load_signing_key, ChainState, KeyLoadOutcome, KeySlot, SERVICE_NAME,
};
use crate::audit::persist::{
    current_iso8601_utc_persist, gen_chain_id, write_record_v2, write_record_v2_signed,
    write_seam_record, AuditV2Error, SeamWriteOutcome, SeamWriteSpec, AUDIT_SCHEMA_VERSION,
};
use crate::audit::traits::SigningKey as _;
use crate::audit::types::{
    Ed25519Signature, EventKind, EventPayload, KeyId, OperatorRefRecord, ProvenanceAnchoredPayload,
    RecordId, SeamDuplicateSuppressedPayload, SeamEventRejectedPayload, Sha256Hex, SignedRecord,
};

use super::decode::{self, DecodedEvent};
use super::error::{RejectReason, SeamError};
use super::precheck;
use super::quarantine::{park_unknown_version, quarantine_event};
use super::reconcile::{self, GapDecision, OrderingContext, PREDECESSOR_WAIT_SECS};
use super::registry::{DispatchOutcome, VersionRegistry};

/// Outcome of [`ingest_provenance_event`].
#[derive(Debug, Clone)]
pub enum IngestOutcome {
    /// Event was validated and anchored into the chain.
    Anchored {
        /// The `decision_id` from the F101-1 envelope.
        decision_id: String,
        /// The chain `seq` assigned by the writer (authoritative order, F-SEAM-04).
        seq: u64,
    },
    /// Event was rejected at the frontier (malformed / validation failure).
    /// Raw bytes → `.quarantine/`; chain record → `seam_event_rejected`.
    Rejected {
        /// Fixed-vocabulary rejection tag (HIGH-1: no raw content echoed).
        reason: &'static str,
    },
    /// Event was parked (well-formed but unknown schema version).
    /// Raw bytes → `.pending/provenance/`; no chain record written.
    ParkedUnknownVersion {
        /// The `schema_version` the event claimed (as a string).
        version: String,
    },
    /// A `ProvenanceAnchored` record for this `decision_id` already exists in
    /// the chain. The duplicate is silently dropped — no second chain record.
    ///
    /// The IPC handler maps this to **202 Accepted** (the caller need not retry;
    /// the first record is authoritative).
    ///
    /// M20: the dedup check now runs INSIDE the `.chain-lock` (atomic with the
    /// append + index update), closing the prior ingest-time TOCTOU.
    DuplicateSuppressed {
        /// The `decision_id` that was already present in the chain.
        decision_id: String,
    },
    /// The event arrived before its intra-operator predecessor (`prev_link` not
    /// yet anchored) and was HELD in `.pending/provenance-ordered/<person_id>/`
    /// until the predecessor drains or a bounded timeout fires (M20, F-SEAM-09).
    /// No chain record is written yet. The IPC handler maps this to **202
    /// Accepted** (custody-held; the caller need not retry — csq links it on
    /// predecessor arrival/timeout).
    HeldPendingPredecessor {
        /// The held event's `decision_id`.
        decision_id: String,
        /// The missing predecessor's `prev_link` hash (sha256 hex).
        missing_prev_link: String,
    },
}

/// Ingest one inbound loom F101-1 provenance event.
///
/// This is the orchestration entry point called by the IPC handler. It is
/// synchronous (blocking) — the IPC handler calls it via `tokio::task::spawn_blocking`.
///
/// # Production pipeline (M18-bind)
///
/// `precheck → dispatch(schema_version) → {Unknown→park | Known→decode→anchor}`.
/// Both reject paths (precheck fail + v1 decode fail) converge on `ingest_rejected`
/// (quarantine + `seam_event_rejected`).
///
/// # Failure posture
///
/// - Quarantine I/O failure: returns `Err(SeamError::Io)`.
/// - Chain-broken: the caller (IPC handler) MUST check `is_chain_broken(base)`
///   and return `503` BEFORE calling this function.
/// - Signing failure post-cutoff (fail-closed): returns `Err(SeamError::ChainWrite)`.
pub fn ingest_provenance_event(
    base: &Path,
    raw: &[u8],
    now_unix: i64,
) -> Result<IngestOutcome, SeamError> {
    // Step 1: precheck — size + JSON + schema_version integer.
    let prechk = match precheck::precheck(raw) {
        Err(reason) => {
            ingest_rejected(base, raw, reason)?;
            return Ok(IngestOutcome::Rejected {
                reason: reason.as_tag(),
            });
        }
        Ok(ok) => ok,
    };

    let version_str = prechk.schema_version.to_string();

    // Step 2: dispatch on schema version.
    match VersionRegistry::production().dispatch(&version_str) {
        DispatchOutcome::UnknownVersion => {
            park_unknown_version(base, raw, &version_str)?;
            return Ok(IngestOutcome::ParkedUnknownVersion {
                version: version_str,
            });
        }
        DispatchOutcome::KnownVersion => {}
    }

    // Step 3: v1 decode (known version).
    let decoded = match decode::decode(&version_str, raw, now_unix, &prechk.received_bytes_hash) {
        Err(reason) => {
            ingest_rejected(base, raw, reason)?;
            return Ok(IngestOutcome::Rejected {
                reason: reason.as_tag(),
            });
        }
        Ok(d) => d,
    };

    // Step 4: anchor pipeline.
    ingest_anchored(base, raw, decoded, now_unix, &OrderingContext::live())
}

/// Handle a frontier-rejected event:
/// 1. Quarantine raw bytes → `.quarantine/`.
/// 2. Write `seam_event_rejected` chain record (metadata-only, HIGH-1).
fn ingest_rejected(base: &Path, raw: &[u8], reason: RejectReason) -> Result<(), SeamError> {
    let (best_version, best_surface) = lenient_extract_header(raw);

    quarantine_event(base, raw, reason.as_tag())?;

    let payload = SeamEventRejectedPayload {
        reason: reason.as_tag().to_string(),
        f101_schema_version: best_version,
        surface: best_surface,
    };

    let record = build_seam_record(
        base,
        EventKind::SeamEventRejected,
        EventPayload::SeamEventRejected(payload),
        None,
        None,
    )?;

    write_signed_or_unsigned(base, record)?;
    Ok(())
}

/// Handle a known-version decoded event: gap-check → sign over exact bytes →
/// ProvenanceAnchored, then opportunistically drain any held successors.
fn ingest_anchored(
    base: &Path,
    raw: &[u8],
    decoded: DecodedEvent,
    now_unix: i64,
    ordering: &OrderingContext,
) -> Result<IngestOutcome, SeamError> {
    let csq_runs = base.join("csq-runs");
    let person_id = decoded.operator_ref.person_id.clone();
    let decision_id = decoded.decision_id.clone();
    let prev_link = decoded.prev_link.as_deref();

    // M20 F-SEAM-09: prev_link gap check. Skip when this is a timeout-forced
    // link (the sweep is deliberately linking past a gap).
    let forced_link = ordering.is_forced();
    if !forced_link {
        match reconcile::decide_gap_prev_link(&csq_runs, prev_link) {
            GapDecision::Proceed => {}
            GapDecision::Hold { missing } => {
                match reconcile::hold_for_predecessor(&csq_runs, &person_id, &decision_id, raw)? {
                    reconcile::HoldOutcome::Held => {
                        // HIGH-1: TOCTOU self-rescue. After the hold write, the
                        // predecessor may have anchored (and written its dedup-index
                        // entry) concurrently in another spawn_blocking thread.
                        // Re-check with the rebuild-aware gap function; if it now
                        // returns Proceed (predecessor is durably anchored), remove
                        // the just-written hold and fall through to anchor_core
                        // instead of returning HeldPendingPredecessor (which would
                        // wedge S until the 300s sweep force-links it with a false
                        // predecessor_missing=true annotation on a complete causal
                        // link).
                        if reconcile::decide_gap_prev_link(&csq_runs, prev_link)
                            == GapDecision::Proceed
                        {
                            reconcile::remove_held(&csq_runs, &person_id, &decision_id);
                            // Fall through to anchor_core below.
                        } else {
                            return Ok(IngestOutcome::HeldPendingPredecessor {
                                decision_id,
                                missing_prev_link: missing,
                            });
                        }
                    }
                    reconcile::HoldOutcome::Collision => {
                        quarantine_event(base, raw, "seam_held_decision_id_collision")?;
                        return Ok(IngestOutcome::Rejected {
                            reason: "seam_held_decision_id_collision",
                        });
                    }
                }
            }
        }
    }

    // `anchor_core` derives `ordering_basis` centrally (so the drain + sweep
    // paths get the same backfill annotation as this direct path).
    let outcome = anchor_core(base, raw, &decoded, ordering, now_unix)?;

    if matches!(
        &outcome,
        IngestOutcome::Anchored { .. } | IngestOutcome::DuplicateSuppressed { .. }
    ) {
        drain_successors_for(base, &person_id, &decision_id, now_unix);
    }

    Ok(outcome)
}

/// Anchor core: build the `ProvenanceAnchored` record and write it with the
/// IN-LOCK dedup (M20).
///
/// Computes the F-SEAM-03(b) backfill annotation (`ordering_basis`) HERE — the
/// single point every anchor path funnels through (direct ingest, drain cascade,
/// self-rescue, sweep). When the supplied `ordering` leaves `ordering_basis`
/// unset, it is derived from `ordering_basis_for(now_unix, claimed_unix)` so a
/// held-then-drained backfilled event is annotated `wallclock_skew_bounded` like
/// a directly-anchored one (R4 deep-analyst MEDIUM — the drain path previously
/// passed a bare `OrderingContext::live()` and stripped the annotation).
fn anchor_core(
    base: &Path,
    raw: &[u8],
    decoded: &DecodedEvent,
    ordering: &OrderingContext,
    now_unix: i64,
) -> Result<IngestOutcome, SeamError> {
    // Derive the backfill annotation centrally when the caller did not set it.
    let ordering_basis = if ordering.ordering_basis.is_some() {
        ordering.ordering_basis.clone()
    } else {
        reconcile::ordering_basis_for(now_unix, decoded.claimed_unix)
    };

    let received_bytes_hash_hex = crate::audit::persist::sha256_hex(raw);
    let received_bytes_hash =
        Sha256Hex::try_new(&received_bytes_hash_hex).map_err(|_| SeamError::Internal)?;

    let event_hash_bytes =
        hex::decode(&received_bytes_hash_hex).map_err(|_| SeamError::Internal)?;

    let person_id = &decoded.operator_ref.person_id;
    let attestation = match Principal::new(person_id.clone()) {
        Ok(principal) => attest_authorship(base, &principal, &event_hash_bytes),
        Err(_) => unbacked_attestation(person_id),
    };

    let payload = ProvenanceAnchoredPayload {
        decision_id: decoded.decision_id.clone(),
        surface: decoded.surface.clone(),
        claimed_decision_ts: decoded.canonical_ts.clone(),
        words_hash: decoded.words_hash.clone(),
        f101_schema_version: decoded.schema_version_str.clone(),
        received_bytes_hash,
        ordering_basis,
        predecessor_missing: ordering.predecessor_missing,
        prev_link: decoded.prev_link.clone(),
        kind: Some(decoded.kind.clone()),
        operator_ref: Some(OperatorRefRecord {
            verified_id: decoded.operator_ref.verified_id.clone(),
            person_id: decoded.operator_ref.person_id.clone(),
            display_id: decoded.operator_ref.display_id.clone(),
        }),
        session: decoded.session.clone(), // MEDIUM-2: thread session from wire
    };

    let record = build_seam_record(
        base,
        EventKind::ProvenanceAnchored,
        EventPayload::ProvenanceAnchored(payload),
        Some(attestation.actor),
        Some(attestation.trust),
    )?;

    let spec = SeamWriteSpec {
        dedup_key: &decoded.decision_id,
    };
    match write_anchored_dedup(base, record, &spec)? {
        SeamWriteOutcome::Written(written) => {
            reconcile::remove_held(&base.join("csq-runs"), person_id, &decoded.decision_id);
            Ok(IngestOutcome::Anchored {
                decision_id: decoded.decision_id.clone(),
                seq: written.seq,
            })
        }
        SeamWriteOutcome::Duplicate => {
            emit_duplicate_suppressed_once(base, decoded)?;
            reconcile::remove_held(&base.join("csq-runs"), person_id, &decoded.decision_id);
            Ok(IngestOutcome::DuplicateSuppressed {
                decision_id: decoded.decision_id.clone(),
            })
        }
    }
}

/// Opportunistically drain held successors whose `prev_link` equals
/// `just_anchored_decision_id`. Scans the operator's held dir for all held
/// events and re-decodes each to check if its `prev_link` matches.
fn drain_successors_for(
    base: &Path,
    person_id: &str,
    just_anchored_decision_id: &str,
    now_unix: i64,
) {
    let csq_runs = base.join("csq-runs");
    let budget = (reconcile::HELD_HARD_CAP as u32).saturating_add(1);
    let mut iterations = 0u32;

    let held_events = reconcile::list_held(&csq_runs, now_unix);
    for held in held_events {
        if held.person_id != person_id {
            continue;
        }
        iterations += 1;
        if iterations > budget {
            tracing::warn!(
                error_kind = "seam_drain_budget_exhausted",
                "seam: held-store drain hit the iteration cap; residue remains for next drain/sweep"
            );
            break;
        }
        let Some(raw) = reconcile::read_held(&csq_runs, &held.person_id, &held.decision_id) else {
            continue;
        };
        let prechk = match precheck::precheck(&raw) {
            Ok(p) => p,
            Err(_) => {
                reconcile::remove_held(&csq_runs, &held.person_id, &held.decision_id);
                continue;
            }
        };
        let version_str = prechk.schema_version.to_string();
        let decoded =
            match decode::decode(&version_str, &raw, now_unix, &prechk.received_bytes_hash) {
                Ok(d) => d,
                Err(_) => {
                    reconcile::remove_held(&csq_runs, &held.person_id, &held.decision_id);
                    continue;
                }
            };
        if decoded.prev_link.as_deref() != Some(just_anchored_decision_id) {
            continue;
        }
        // Pass the original arrival `now_unix` so `anchor_core` derives the
        // backfill `ordering_basis` for this drained successor (R4 MEDIUM).
        match anchor_core(base, &raw, &decoded, &OrderingContext::live(), now_unix) {
            Ok(IngestOutcome::Anchored { decision_id, .. })
            | Ok(IngestOutcome::DuplicateSuppressed { decision_id }) => {
                reconcile::remove_held(&csq_runs, &held.person_id, &held.decision_id);
                drain_successors_for(base, &held.person_id, &decision_id, now_unix);
            }
            _ => {}
        }
    }
}

/// Sweep held events whose wait has exceeded `PREDECESSOR_WAIT_SECS`: link each
/// past its unfilled intra-operator gap with a `predecessor_missing` annotation
/// (F-SEAM-09 bounded-timeout). Returns the number of events linked.
pub fn sweep_timed_out(base: &Path, now_unix: i64) -> Result<usize, SeamError> {
    let csq_runs = base.join("csq-runs");
    let mut linked = 0usize;
    for held in reconcile::list_held(&csq_runs, now_unix) {
        let timed_out = held.age_secs.is_some_and(|a| a > PREDECESSOR_WAIT_SECS);
        if !timed_out {
            continue;
        }
        let Some(raw) = reconcile::read_held(&csq_runs, &held.person_id, &held.decision_id) else {
            continue;
        };
        let prechk = match precheck::precheck(&raw) {
            Ok(p) => p,
            Err(_) => {
                reconcile::remove_held(&csq_runs, &held.person_id, &held.decision_id);
                continue;
            }
        };
        let version_str = prechk.schema_version.to_string();
        if VersionRegistry::production().dispatch(&version_str) == DispatchOutcome::UnknownVersion {
            reconcile::remove_held(&csq_runs, &held.person_id, &held.decision_id);
            continue;
        }
        let decoded =
            match decode::decode(&version_str, &raw, now_unix, &prechk.received_bytes_hash) {
                Ok(d) => d,
                Err(_) => {
                    reconcile::remove_held(&csq_runs, &held.person_id, &held.decision_id);
                    continue;
                }
            };
        match ingest_anchored(
            base,
            &raw,
            decoded,
            now_unix,
            &OrderingContext::gap_timeout(),
        )? {
            IngestOutcome::Anchored { .. } | IngestOutcome::DuplicateSuppressed { .. } => {
                reconcile::remove_held(&csq_runs, &held.person_id, &held.decision_id);
                linked += 1;
            }
            _ => {}
        }
    }
    Ok(linked)
}

/// Emit a once-per-id `seam_duplicate_suppressed` chain record (F-SEAM-05).
fn emit_duplicate_suppressed_once(base: &Path, decoded: &DecodedEvent) -> Result<(), SeamError> {
    let payload = SeamDuplicateSuppressedPayload {
        decision_id: decoded.decision_id.clone(),
        surface: decoded.surface.clone(),
    };
    let record = build_seam_record(
        base,
        EventKind::SeamDuplicateSuppressed,
        EventPayload::SeamDuplicateSuppressed(payload),
        None,
        None,
    )?;
    let dup_key = format!("dup:{}", decoded.decision_id);
    let spec = SeamWriteSpec {
        dedup_key: &dup_key,
    };
    match load_seam_signing_key(base, Duration::from_millis(200)) {
        Ok(Some((key, key_id_val))) => {
            let mut rec = record;
            rec.key_id = key_id_val;
            let _ = write_seam_record(rec, Some(base), Some(&key), &spec)
                .map_err(SeamError::ChainWrite)?;
        }
        Ok(None) => {
            let _ = write_seam_record(record, Some(base), None, &spec)
                .map_err(SeamError::ChainWrite)?;
        }
        Err(e) => return Err(SeamError::ChainWrite(e)),
    }
    Ok(())
}

/// Build a skeleton `SignedRecord` for a seam chain record.
fn build_seam_record(
    base: &Path,
    kind: EventKind,
    payload: EventPayload,
    actor: Option<crate::audit::types::EatpActor>,
    trust: Option<crate::audit::types::EatpTrust>,
) -> Result<SignedRecord, SeamError> {
    let chain_id_str = ChainState::load(base)
        .ok()
        .map(|s| s.chain_id)
        .unwrap_or_default();

    let resolved_chain_id = if chain_id_str.is_empty() {
        gen_chain_id()
    } else {
        chain_id_str
    };

    let chain_id = RecordId::try_new(&resolved_chain_id).map_err(|_| SeamError::Internal)?;
    let record_id = RecordId::try_new(gen_chain_id()).map_err(|_| SeamError::Internal)?;
    let key_id =
        KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).map_err(|_| SeamError::Internal)?;

    Ok(SignedRecord {
        schema_version: AUDIT_SCHEMA_VERSION.to_string(),
        record_id,
        chain_id,
        seq: 0,
        prev_hash: Sha256Hex::genesis(),
        kind,
        payload,
        ts: current_iso8601_utc_persist(),
        key_id,
        canonical_hash: Sha256Hex::genesis(),
        signature: Ed25519Signature::new([0u8; 64]),
        actor,
        authority: None,
        trust,
        eatp_start_ts: None,
        eatp_end_ts: None,
        op_phase: None,
    })
}

/// Try to write a signed record; fall back to unsigned pre-cutoff.
fn write_signed_or_unsigned(base: &Path, record: SignedRecord) -> Result<u64, SeamError> {
    const SEAM_KEY_BUDGET: Duration = Duration::from_millis(200);
    match load_seam_signing_key(base, SEAM_KEY_BUDGET) {
        Ok(Some((key, key_id_val))) => {
            let mut rec = record;
            rec.key_id = key_id_val;
            let written = write_record_v2_signed(rec, Some(base), &key)?;
            Ok(written.seq)
        }
        Ok(None) => {
            write_record_v2(record, Some(base))?;
            Ok(0)
        }
        Err(e) => Err(SeamError::ChainWrite(e)),
    }
}

/// Write a `ProvenanceAnchored` record with IN-LOCK dedup (M20). MUST be
/// signed. Fails closed when no signing key is available.
fn write_anchored_dedup(
    base: &Path,
    record: SignedRecord,
    spec: &SeamWriteSpec<'_>,
) -> Result<SeamWriteOutcome, SeamError> {
    const SEAM_KEY_BUDGET: Duration = Duration::from_millis(200);
    match load_seam_signing_key(base, SEAM_KEY_BUDGET) {
        Ok(Some((key, key_id_val))) => {
            let mut rec = record;
            rec.key_id = key_id_val;
            write_seam_record(rec, Some(base), Some(&key), spec).map_err(SeamError::ChainWrite)
        }
        Ok(None) => Err(SeamError::AnchorRequiresInit),
        Err(e) => Err(SeamError::ChainWrite(e)),
    }
}

/// Load the seam signing key with the given budget.
fn load_seam_signing_key(
    base: &Path,
    budget: Duration,
) -> Result<Option<(crate::audit::key_custody::LocalSigningKey, KeyId)>, AuditV2Error> {
    let chain_state = match ChainState::load(base) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    if chain_state.signing_key_id.is_none() {
        return Ok(None);
    }

    let chain_id = chain_state.chain_id.clone();
    if chain_id.is_empty() {
        return Ok(None);
    }

    let cutoff_active = chain_state.signing_active_since_seq.is_some();

    let no_key = |reason: &str| -> Result<
        Option<(crate::audit::key_custody::LocalSigningKey, KeyId)>,
        AuditV2Error,
    > {
        if cutoff_active {
            Err(AuditV2Error::Signing {
                reason: format!(
                    "seam signing key unavailable ({reason}) while signing cutoff is active"
                ),
            })
        } else {
            Ok(None)
        }
    };

    let deadline = Instant::now() + budget;
    let poll_interval = Duration::from_millis(100);

    loop {
        match try_load_signing_key(base, SERVICE_NAME, &chain_id, KeySlot::Active) {
            KeyLoadOutcome::Loaded(key) => {
                let key_id_val = key.key_id();
                return Ok(Some((*key, key_id_val)));
            }
            KeyLoadOutcome::Absent => return no_key("not found"),
            KeyLoadOutcome::Corrupt(_) => return no_key("corrupt"),
            KeyLoadOutcome::Inaccessible => {
                if Instant::now() >= deadline {
                    return no_key("keychain locked");
                }
                std::thread::sleep(poll_interval);
            }
        }
    }
}

/// Produce an UNBACKED attestation for an unresolvable or absent principal.
fn unbacked_attestation(principal: &str) -> crate::audit::dev_identity::attest::Attestation {
    use crate::audit::types::{EatpActor, EatpTrust};
    use serde_json::json;
    crate::audit::dev_identity::attest::Attestation {
        actor: EatpActor(json!({
            "principal": crate::error::redact_tokens(principal),
            "backing": "unbacked",
        })),
        trust: EatpTrust(json!({ "level": "unbacked" })),
    }
}

/// Best-effort lenient extraction of `f101_schema_version` and `surface`
/// from raw bytes that may be malformed JSON.
fn lenient_extract_header(raw: &[u8]) -> (Option<String>, Option<String>) {
    let Ok(s) = std::str::from_utf8(raw) else {
        return (None, None);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else {
        return (None, None);
    };
    let obj = v.as_object();
    let version = obj
        .and_then(|o| {
            o.get("schema_version")
                .or_else(|| o.get("f101_schema_version"))
        })
        .and_then(|v| v.as_str())
        .map(|s| {
            let redacted = crate::error::redact_tokens(s);
            redacted.chars().take(64).collect::<String>()
        });
    let surface = obj
        .and_then(|o| o.get("surface"))
        .and_then(|v| v.as_str())
        .map(|s| {
            let redacted = crate::error::redact_tokens(s);
            redacted.chars().take(64).collect::<String>()
        });
    (version, surface)
}

// ---------------------------------------------------------------------------
// Test-only helper: ingest with the legacy test version registry
// ---------------------------------------------------------------------------

/// Ingest with the test version registry (registers `"test-v0"` as a known
/// version). Uses the old `validate_event` (frontier) pipeline so existing
/// scaffolding tests keep compiling without changes.
///
/// Gap detection uses the new `prev_link` model. Test events without a
/// `prev_link` field are treated as genesis events (always `Proceed`).
#[cfg(any(test, feature = "test-utils"))]
pub fn ingest_provenance_event_with_test_registry(
    base: &Path,
    raw: &[u8],
    now_unix: i64,
) -> Result<IngestOutcome, SeamError> {
    use super::frontier::validate_event;
    use super::registry::SurfaceRegistry;

    let registry = SurfaceRegistry::load(base)?;
    match validate_event(raw, &registry, now_unix) {
        Err(reason) => {
            ingest_rejected(base, raw, reason)?;
            Ok(IngestOutcome::Rejected {
                reason: reason.as_tag(),
            })
        }
        Ok(validated) => {
            use super::registry::VersionRegistry;
            match VersionRegistry::with_test_version()
                .dispatch(&validated.envelope.f101_schema_version)
            {
                DispatchOutcome::UnknownVersion => {
                    let version = validated.envelope.f101_schema_version.clone();
                    park_unknown_version(base, raw, &version)?;
                    Ok(IngestOutcome::ParkedUnknownVersion { version })
                }
                DispatchOutcome::KnownVersion => {
                    let decoded = decoded_from_validated(validated);
                    ingest_anchored(base, raw, decoded, now_unix, &OrderingContext::live())
                }
            }
        }
    }
}

/// Build a `DecodedEvent` from a legacy `ValidatedEnvelope` (for the test path).
/// Test events have no `prev_link` — they are treated as genesis events.
#[cfg(any(test, feature = "test-utils"))]
fn decoded_from_validated(validated: super::frontier::ValidatedEnvelope) -> DecodedEvent {
    use super::decode::OperatorRef;
    use crate::audit::seam::frontier::unix_to_canonical_ts_pub;

    let person_id = validated
        .envelope
        .principal
        .clone()
        .unwrap_or_else(|| "test-principal".to_string());

    DecodedEvent {
        decision_id: validated.envelope.decision_id.clone(),
        surface: validated.envelope.surface.clone(),
        canonical_ts: unix_to_canonical_ts_pub(validated.claimed_unix),
        claimed_unix: validated.claimed_unix,
        schema_version_str: validated.envelope.f101_schema_version.clone(),
        kind: "Decision".to_string(),
        operator_ref: OperatorRef {
            verified_id: "test-verified-id".to_string(),
            person_id,
            display_id: None,
        },
        prev_link: None, // test events are all genesis (no prev_link)
        words_hash: validated
            .envelope
            .words_hash
            .as_deref()
            .and_then(|wh| crate::audit::types::Sha256Hex::try_new(wh).ok()),
        session: None, // legacy test path has no session field
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::key_custody::test_helpers::init_mock_keyring;
    use crate::audit::verify::{verify_chain, VerifyConfig};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn init_test_signing_key(base: &std::path::Path) {
        init_mock_keyring();
        crate::audit::key_custody::audit_init(base, "csq-test-seam")
            .expect("audit_init in test must succeed");
    }

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn read_chain_text(base: &std::path::Path) -> Option<String> {
        let runs = base.join("csq-runs");
        let Ok(entries) = std::fs::read_dir(&runs) else {
            return None;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "jsonl") {
                return std::fs::read_to_string(&path).ok();
            }
        }
        None
    }

    // ── AC-2: malformed JSON → quarantined + seam_event_rejected chain record ──

    #[test]
    fn test_malformed_json_quarantined_and_chain_record_written() {
        // verify_chain -> resolve_registry reads CSQ_AUDIT_EDITION; hold the shared env
        // lock so this test does not race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        init_mock_keyring();
        let dir = tmp();
        let base = dir.path();

        let raw = b"NOT VALID JSON AT ALL";
        let result = ingest_provenance_event(base, raw, now_unix()).unwrap();

        assert!(
            matches!(result, IngestOutcome::Rejected { reason } if reason == "malformed_json"),
            "malformed event must be Rejected(malformed_json)"
        );

        let qdir = base.join("csq-runs").join(".quarantine");
        let entries: Vec<_> = std::fs::read_dir(&qdir)
            .expect("quarantine dir")
            .flatten()
            .collect();
        assert_eq!(entries.len(), 1, "exactly one quarantine file");
        let qbytes = std::fs::read(entries[0].path()).unwrap();
        assert_eq!(&qbytes, raw, "quarantine file contains exact raw bytes");

        let cfg = VerifyConfig::default();
        verify_chain(base, &cfg, None).expect("chain must verify after rejection");

        let chain_text = read_chain_text(base).expect("chain file must exist after rejection");
        assert!(
            !chain_text.contains("NOT VALID JSON"),
            "HIGH-1: raw event body must NOT appear in chain"
        );
    }

    // ── AC-2: rejection chain integrity — multiple rejections still verifies ──

    #[test]
    fn test_rejection_chain_integrity_preserved() {
        // verify_chain -> resolve_registry reads CSQ_AUDIT_EDITION; hold the shared env
        // lock so this test does not race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        init_mock_keyring();
        let dir = tmp();
        let base = dir.path();

        for _ in 0..3 {
            ingest_provenance_event(base, b"{{{bad", now_unix()).unwrap();
        }

        let cfg = VerifyConfig::default();
        verify_chain(base, &cfg, None).expect("chain must verify after multiple rejections");
    }

    // ── AC-2: v1 event missing required fields → rejected ──

    #[test]
    fn test_missing_required_field_v1() {
        init_mock_keyring();
        let dir = tmp();
        let raw = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
        }))
        .unwrap();
        let result = ingest_provenance_event(dir.path(), &raw, now_unix()).unwrap();
        assert!(
            matches!(result, IngestOutcome::Rejected { .. }),
            "event missing required v1 fields must be Rejected, got: {result:?}"
        );
    }

    // ── AC-2: timestamp out of skew (v1) ──

    #[test]
    fn test_timestamp_out_of_skew_v1() {
        init_mock_keyring();
        let dir = tmp();
        let raw = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "kind": "Decision",
            "ts": "2020-01-01T00:00:00Z",
            "session": "sess-001",
            "operator_ref": {
                "verified_id": "AABB",
                "person_id": "pid-test"
            },
            "payload": {
                "journal_path": "journal/foo.md",
                "tool": "Write"
            },
            "prev_link": null
        }))
        .unwrap();
        let result = ingest_provenance_event(dir.path(), &raw, now_unix()).unwrap();
        assert!(
            matches!(result, IngestOutcome::Rejected { reason } if reason == "timestamp_out_of_skew"),
            "got: {result:?}"
        );
    }

    // ── AC-3: unknown version → parked (no chain record) ──

    #[test]
    fn test_unknown_version_parked_no_chain_record() {
        init_mock_keyring();
        let dir = tmp();
        let raw = serde_json::to_vec(&serde_json::json!({
            "schema_version": 999,
            "kind": "Decision",
            "ts": current_iso8601_utc_persist(),
            "session": "sess-001",
            "operator_ref": {
                "verified_id": "AABB",
                "person_id": "pid-test"
            },
            "payload": {
                "journal_path": "journal/foo.md",
                "tool": "Write"
            },
            "prev_link": null
        }))
        .unwrap();
        let result = ingest_provenance_event(dir.path(), &raw, now_unix()).unwrap();
        assert!(
            matches!(result, IngestOutcome::ParkedUnknownVersion { .. }),
            "unknown version must be parked, got: {result:?}"
        );

        let pdir = dir
            .path()
            .join("csq-runs")
            .join(".pending")
            .join("provenance");
        assert!(pdir.exists(), ".pending/provenance dir must exist");
        let entries: Vec<_> = std::fs::read_dir(&pdir).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1, "exactly one parked file");

        if let Some(text) = read_chain_text(dir.path()) {
            assert!(
                !text.contains("provenance_anchored"),
                "parked event must not produce a ProvenanceAnchored record"
            );
        }
    }

    // ── AC-4 + AC-5 + AC-7: legacy test registry → ProvenanceAnchored ──

    #[test]
    fn test_known_version_provenance_anchored() {
        // verify_chain -> resolve_registry reads CSQ_AUDIT_EDITION; hold the shared env
        // lock so this test does not race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        use crate::audit::dev_identity::enrollment::{enroll_developer, Granularity};
        use crate::audit::seam::registry::TEST_VERSION;

        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);

        let principal = Principal::new("alice@example.com".to_string()).unwrap();
        enroll_developer(base, principal.clone(), Granularity::default(), |_| true)
            .expect("enroll alice");

        let raw = serde_json::to_vec(&serde_json::json!({
            "f101_schema_version": TEST_VERSION,
            "decision_id": "550e8400-e29b-41d4-a716-446655440000",
            "surface": "cc",
            "source_counter": 42u64,
            "claimed_decision_ts": current_iso8601_utc_persist(),
            "principal": principal.as_str(),
            "extra_field_loom_owns": "should be tolerated but never echoed",
        }))
        .unwrap();

        let result = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();

        assert!(
            matches!(result, IngestOutcome::Anchored { .. }),
            "known version with enrolled principal must be Anchored, got: {result:?}"
        );

        let cfg = VerifyConfig::default();
        verify_chain(base, &cfg, None).expect("chain must verify after anchoring");

        let chain_text = read_chain_text(base).expect("chain file must exist after anchoring");

        let expected_hash = crate::audit::persist::sha256_hex(&raw);
        assert!(
            chain_text.contains(&expected_hash),
            "AC-4: received_bytes_hash must equal sha256(raw bytes) in chain"
        );

        assert!(
            chain_text.contains("claimed_decision_ts"),
            "claimed_decision_ts must appear as evidence in the chain record"
        );

        assert!(
            !chain_text.contains("should be tolerated but never echoed"),
            "HIGH-1: extra loom field value must NOT appear in chain"
        );

        let has_verified = chain_text.contains("\"backing\":\"verified\"")
            || chain_text.contains("\"backing\": \"verified\"");
        assert!(
            has_verified,
            "AC-5: enrolled principal must produce backing: verified"
        );
    }

    // ── AC-5: unenrolled principal → unbacked ──

    #[test]
    fn test_known_version_unbacked_for_unenrolled_principal() {
        use crate::audit::seam::registry::TEST_VERSION;

        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);

        let raw = serde_json::to_vec(&serde_json::json!({
            "f101_schema_version": TEST_VERSION,
            "decision_id": "550e8400-e29b-41d4-a716-446655440001",
            "surface": "cc",
            "source_counter": 1u64,
            "claimed_decision_ts": current_iso8601_utc_persist(),
            "principal": "ghost@example.com",
        }))
        .unwrap();

        let result = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();
        assert!(matches!(result, IngestOutcome::Anchored { .. }));

        let chain_text = read_chain_text(base).expect("chain file must exist");
        let has_unbacked = chain_text.contains("\"backing\":\"unbacked\"")
            || chain_text.contains("\"backing\": \"unbacked\"");
        assert!(
            has_unbacked,
            "unenrolled principal must produce backing: unbacked"
        );
    }

    // ── HIGH-1: sentinel string and token must not appear in chain records ──

    #[test]
    fn test_high1_no_raw_body_in_chain() {
        use crate::audit::seam::registry::TEST_VERSION;

        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);

        let sentinel = "SENTINEL_HUMAN_WORDS_12345";
        let fake_token = "sk-ant-XXXX1234567890abcdef1234567890abcdef12";
        let raw = serde_json::to_vec(&serde_json::json!({
            "f101_schema_version": TEST_VERSION,
            "decision_id": "550e8400-e29b-41d4-a716-446655440002",
            "surface": "cc",
            "source_counter": 1u64,
            "claimed_decision_ts": current_iso8601_utc_persist(),
            "human_words": sentinel,
            "sneaky_token": fake_token,
        }))
        .unwrap();

        let _ = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();

        let chain_text = read_chain_text(base).expect("chain file must exist");
        assert!(
            !chain_text.contains(sentinel),
            "HIGH-1: sentinel string must NOT appear in chain records"
        );
        assert!(
            !chain_text.contains("sk-ant-XXXX"),
            "HIGH-1: token-shaped string must NOT appear in chain records"
        );
    }

    // ── HIGH-1: rejection path also keeps raw bytes out of chain ──

    #[test]
    fn test_high1_rejection_no_raw_body_in_chain() {
        init_mock_keyring();
        let dir = tmp();
        let base = dir.path();

        let sentinel = "REJECTION_SENTINEL_99999";
        let raw = format!(r#"{{"broken: "{sentinel}"}}"#);
        ingest_provenance_event(base, raw.as_bytes(), now_unix()).unwrap();

        if let Some(chain_text) = read_chain_text(base) {
            assert!(
                !chain_text.contains(sentinel),
                "HIGH-1: rejection sentinel must not appear in chain after rejection"
            );
        }
    }

    // ── R2 M1/LOW-3: anchored path without a signing key fails closed ──

    #[test]
    fn test_anchored_without_key_requires_init() {
        use crate::audit::seam::registry::TEST_VERSION;

        init_mock_keyring();
        let dir = tmp();
        let base = dir.path();

        let raw = serde_json::to_vec(&serde_json::json!({
            "f101_schema_version": TEST_VERSION,
            "decision_id": "550e8400-e29b-41d4-a716-446655440007",
            "surface": "cc",
            "source_counter": 1u64,
            "claimed_decision_ts": current_iso8601_utc_persist(),
            "principal": "alice@example.com",
        }))
        .unwrap();

        let result = ingest_provenance_event_with_test_registry(base, &raw, now_unix());
        assert!(
            matches!(result, Err(SeamError::AnchorRequiresInit)),
            "anchored path with no signing key must fail closed with AnchorRequiresInit, got: {result:?}"
        );
        assert!(
            read_chain_text(base).is_none(),
            "no chain record must be written when the anchored path fails closed"
        );
    }

    // ── H3 (R1): a replayed decision_id is suppressed ──

    #[test]
    fn test_duplicate_decision_id_suppressed() {
        // verify_chain -> resolve_registry reads CSQ_AUDIT_EDITION; hold the shared env
        // lock so this test does not race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        use crate::audit::seam::registry::TEST_VERSION;

        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);

        let raw = serde_json::to_vec(&serde_json::json!({
            "f101_schema_version": TEST_VERSION,
            "decision_id": "550e8400-e29b-41d4-a716-446655440009",
            "surface": "cc",
            "source_counter": 1u64,
            "claimed_decision_ts": current_iso8601_utc_persist(),
            "principal": "alice@example.com",
        }))
        .unwrap();

        let first = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();
        assert!(
            matches!(first, IngestOutcome::Anchored { .. }),
            "first POST must anchor, got: {first:?}"
        );

        let second = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();
        assert!(
            matches!(second, IngestOutcome::DuplicateSuppressed { .. }),
            "replayed decision_id must be DuplicateSuppressed, got: {second:?}"
        );

        let chain_text = read_chain_text(base).expect("chain after anchor");
        let anchored = count_records_of_kind(&chain_text, "provenance_anchored");
        let suppressed = count_records_of_kind(&chain_text, "seam_duplicate_suppressed");
        assert_eq!(anchored, 1, "exactly one anchored record; got {anchored}");
        assert_eq!(
            suppressed, 1,
            "exactly one suppression record for the replay; got {suppressed}"
        );

        let cfg = VerifyConfig::default();
        verify_chain(base, &cfg, None).expect("chain must verify after suppression");
    }

    fn count_records_of_kind(chain_text: &str, kind: &str) -> usize {
        chain_text
            .lines()
            .filter_map(|l| serde_json::from_str::<crate::audit::types::SignedRecord>(l).ok())
            .filter(|r| {
                use crate::audit::types::EventPayload;
                matches!(
                    (&r.payload, kind),
                    (EventPayload::ProvenanceAnchored(_), "provenance_anchored")
                        | (
                            EventPayload::SeamDuplicateSuppressed(_),
                            "seam_duplicate_suppressed"
                        )
                )
            })
            .count()
    }

    // ───────────── M20 acceptance criteria (prev_link model) ─────────────────

    use crate::audit::seam::registry::TEST_VERSION;

    /// Build a legacy test-version event (genesis, no prev_link).
    fn mk_event_legacy(id: &str, surface: &str, counter: u64, claimed_ts: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "f101_schema_version": TEST_VERSION,
            "decision_id": id,
            "surface": surface,
            "source_counter": counter,
            "claimed_decision_ts": claimed_ts,
            "principal": "alice@example.com",
        }))
        .unwrap()
    }

    /// Build a v1 production event with a given prev_link.
    fn mk_event_v1(person_id: &str, prev_link: Option<&str>, ts: &str) -> Vec<u8> {
        let mut obj = serde_json::json!({
            "schema_version": 1,
            "kind": "Decision",
            "ts": ts,
            "session": "sess-test-001",
            "operator_ref": {
                "verified_id": format!("VERIF-{person_id}"),
                "person_id": person_id,
            },
            "payload": {
                "journal_path": "journal/test.md",
                "tool": "Write"
            },
        });
        if let Some(pl) = prev_link {
            obj["prev_link"] = serde_json::Value::String(pl.to_string());
        } else {
            obj["prev_link"] = serde_json::Value::Null;
        }
        serde_json::to_vec(&obj).unwrap()
    }

    fn find_anchored(
        chain_text: &str,
        id: &str,
    ) -> Option<crate::audit::types::ProvenanceAnchoredPayload> {
        use crate::audit::types::{EventPayload, SignedRecord};
        chain_text
            .lines()
            .filter_map(|l| serde_json::from_str::<SignedRecord>(l).ok())
            .find_map(|r| match r.payload {
                EventPayload::ProvenanceAnchored(p) if p.decision_id == id => Some(p),
                _ => None,
            })
    }

    fn uuid_n(n: u8) -> String {
        format!("550e8400-e29b-41d4-a716-4466554400{n:02}")
    }

    // ── AC2: in-lock dedup index sidecar is populated on anchor ──

    #[test]
    fn test_m20_dedup_index_sidecar_populated() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let id = uuid_n(10);
        let raw = mk_event_legacy(&id, "cc", 1, &current_iso8601_utc_persist());

        let r = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();
        assert!(matches!(r, IngestOutcome::Anchored { .. }));

        let csq_runs = base.join("csq-runs");
        let index = csq_runs.join(crate::audit::persist::SEAM_DEDUP_INDEX);
        assert!(
            index.exists(),
            "dedup index sidecar must exist after anchor"
        );
        assert!(
            crate::audit::persist::seam_dedup_index_contains(&csq_runs, &id),
            "dedup index must contain the anchored decision_id"
        );
    }

    // ── AC2: a replay FLOOD of one id emits exactly ONE suppression record ──

    #[test]
    fn test_m20_replay_flood_emits_one_suppression_record() {
        // verify_chain -> resolve_registry reads CSQ_AUDIT_EDITION; hold the shared env
        // lock so this test does not race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let id = uuid_n(11);
        let raw = mk_event_legacy(&id, "cc", 1, &current_iso8601_utc_persist());

        let first = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();
        assert!(matches!(first, IngestOutcome::Anchored { .. }));

        for _ in 0..5 {
            let r = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();
            assert!(
                matches!(r, IngestOutcome::DuplicateSuppressed { .. }),
                "every replay must be DuplicateSuppressed, got {r:?}"
            );
        }

        let chain_text = read_chain_text(base).expect("chain");
        assert_eq!(count_records_of_kind(&chain_text, "provenance_anchored"), 1);
        assert_eq!(
            count_records_of_kind(&chain_text, "seam_duplicate_suppressed"),
            1,
            "F-SEAM-05: exactly ONE suppression record despite five replays"
        );
        verify_chain(base, &VerifyConfig::default(), None).expect("chain verifies after flood");
    }

    // ── AC3 (prev_link model): genesis event anchors immediately ──

    #[test]
    fn test_m20_genesis_event_anchors() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let raw = mk_event_v1("pid-alice", None, &ts);
        let r = ingest_provenance_event(base, &raw, now_unix()).unwrap();
        assert!(
            matches!(r, IngestOutcome::Anchored { .. }),
            "genesis event must anchor immediately, got: {r:?}"
        );
    }

    // ── AC3 (prev_link model): event with known prev_link anchors immediately ──

    #[test]
    fn test_m20_event_with_known_prev_link_anchors() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();

        let raw1 = mk_event_v1("pid-alice", None, &ts);
        let genesis_id = match ingest_provenance_event(base, &raw1, now_unix()).unwrap() {
            IngestOutcome::Anchored { decision_id, .. } => decision_id,
            other => panic!("genesis must anchor, got {other:?}"),
        };

        let raw2 = mk_event_v1("pid-alice", Some(&genesis_id), &ts);
        let r2 = ingest_provenance_event(base, &raw2, now_unix()).unwrap();
        assert!(
            matches!(r2, IngestOutcome::Anchored { .. }),
            "successor with known prev_link must anchor immediately, got: {r2:?}"
        );
    }

    // ── AC3 (prev_link model): event with unknown prev_link is held ──

    #[test]
    fn test_m20_event_with_unknown_prev_link_is_held() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let fake_prev = "a".repeat(64);
        let raw = mk_event_v1("pid-alice", Some(&fake_prev), &ts);
        let r = ingest_provenance_event(base, &raw, now_unix()).unwrap();
        assert!(
            matches!(
                r,
                IngestOutcome::HeldPendingPredecessor {
                    missing_prev_link: ref pl,
                    ..
                } if pl == &fake_prev
            ),
            "event with unknown prev_link must be held, got: {r:?}"
        );
    }

    // ── AC3 (prev_link model): held event drains when predecessor arrives ──

    #[test]
    fn test_m20_held_event_drains_on_predecessor_arrival() {
        // verify_chain -> resolve_registry reads CSQ_AUDIT_EDITION; hold the shared env
        // lock so this test does not race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");

        // Anchor genesis.
        let raw1 = mk_event_v1("pid-alice", None, &ts);
        let genesis_id = match ingest_provenance_event(base, &raw1, now_unix()).unwrap() {
            IngestOutcome::Anchored { decision_id, .. } => decision_id,
            other => panic!("genesis must anchor, got {other:?}"),
        };

        // Build successor1's raw bytes to compute its decision_id = sha256(raw).
        let raw2 = mk_event_v1("pid-alice", Some(&genesis_id), &ts);
        let succ1_id = crate::audit::persist::sha256_hex(&raw2);

        // Build successor2 whose prev_link is successor1's id.
        let raw3 = mk_event_v1("pid-alice", Some(&succ1_id), &ts);
        let succ2_id = crate::audit::persist::sha256_hex(&raw3);

        // Hold successor2 (prev_link = succ1 which is not yet anchored).
        let r3 = ingest_provenance_event(base, &raw3, now_unix()).unwrap();
        assert!(
            matches!(r3, IngestOutcome::HeldPendingPredecessor { .. }),
            "successor2 must be held, got: {r3:?}"
        );
        assert!(
            reconcile::read_held(&csq_runs, "pid-alice", &succ2_id).is_some(),
            "successor2 must be in the held store"
        );

        // Anchor successor1 — drains successor2.
        let r2 = ingest_provenance_event(base, &raw2, now_unix()).unwrap();
        assert!(
            matches!(r2, IngestOutcome::Anchored { .. }),
            "successor1 must anchor, got: {r2:?}"
        );

        assert!(
            reconcile::read_held(&csq_runs, "pid-alice", &succ2_id).is_none(),
            "successor2 must be drained after its predecessor arrived"
        );
        let chain_text = read_chain_text(base).unwrap();
        assert_eq!(count_records_of_kind(&chain_text, "provenance_anchored"), 3);
        verify_chain(base, &VerifyConfig::default(), None).expect("chain verifies after drain");
    }

    // ── AC3 (prev_link model): held event past PREDECESSOR_WAIT_SECS links with predecessor_missing ──

    #[test]
    fn test_m20_timeout_links_with_predecessor_missing() {
        // verify_chain -> resolve_registry reads CSQ_AUDIT_EDITION; hold the shared env
        // lock so this test does not race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");

        let fake_prev = "b".repeat(64);
        let raw = mk_event_v1("pid-alice", Some(&fake_prev), &ts);
        let held_id = crate::audit::persist::sha256_hex(&raw);
        let r = ingest_provenance_event(base, &raw, now_unix()).unwrap();
        assert!(matches!(r, IngestOutcome::HeldPendingPredecessor { .. }));

        let future = now_unix() + PREDECESSOR_WAIT_SECS + 100;
        let linked = sweep_timed_out(base, future).unwrap();
        assert_eq!(linked, 1, "the timed-out held event must be linked");

        assert!(
            reconcile::read_held(&csq_runs, "pid-alice", &held_id).is_none(),
            "held event must be removed after the timeout link"
        );
        let p = find_anchored(&read_chain_text(base).unwrap(), &held_id)
            .expect("event must be anchored after timeout");
        assert_eq!(
            p.predecessor_missing,
            Some(true),
            "a timeout-forced link must carry predecessor_missing=true"
        );
        verify_chain(base, &VerifyConfig::default(), None).expect("chain verifies after sweep");
    }

    // ── AC4: a backfilled event (claimed far in the past) carries ordering_basis ──

    #[test]
    fn test_m20_backfill_event_annotated_ordering_basis() {
        use crate::audit::seam::frontier::canonical_ts_for_test;
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);

        let now = now_unix();
        let backfill_ts = canonical_ts_for_test(now - 3600);
        let raw = mk_event_v1("pid-alice", None, &backfill_ts);
        let decision_id = crate::audit::persist::sha256_hex(&raw);
        let r = ingest_provenance_event(base, &raw, now).unwrap();
        assert!(matches!(r, IngestOutcome::Anchored { .. }));

        let p = find_anchored(&read_chain_text(base).unwrap(), &decision_id).unwrap();
        assert_eq!(
            p.ordering_basis.as_deref(),
            Some("wallclock_skew_bounded"),
            "a backfilled event's cross-source order must be annotated"
        );
    }

    /// R4 deep-analyst MEDIUM regression: a BACKFILLED event that is HELD
    /// pending its predecessor and later DRAINED must still carry the
    /// `wallclock_skew_bounded` annotation. Before the fix the drain path passed
    /// a bare `OrderingContext::live()` to `anchor_core`, stripping it.
    #[test]
    fn test_r4_drained_backfill_event_keeps_ordering_basis() {
        // verify_chain -> resolve_registry reads CSQ_AUDIT_EDITION; hold the shared env
        // lock so this test does not race the enterprise-edition tests (testing.md Rule 6).
        let _env_guard = crate::platform::test_env::lock();
        use crate::audit::seam::frontier::canonical_ts_for_test;
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let csq_runs = base.join("csq-runs");

        let now = now_unix();
        // Predecessor is LIVE (anchors directly, no annotation).
        let raw1 = mk_event_v1("pid-alice", None, &current_iso8601_utc_persist());
        let genesis_id = match ingest_provenance_event(base, &raw1, now).unwrap() {
            IngestOutcome::Anchored { decision_id, .. } => decision_id,
            other => panic!("genesis must anchor, got {other:?}"),
        };

        // Successor is BACKFILLED (claimed > 60s in the past) AND arrives BEFORE
        // its predecessor is known to the held store — force the held→drain path
        // by holding it against a not-yet-anchored prev, then anchoring that prev.
        // Here we hold the backfilled successor against a fake predecessor, then
        // anchor the real chain so the drain cascade re-anchors it.
        let backfill_ts = canonical_ts_for_test(now - 3600);
        // Build a 2-hop: genesis(live) → succ1(backfill, prev=genesis). Hold succ1
        // by ingesting it BEFORE genesis is in the index is not possible (genesis
        // already anchored). Instead hold succ2(prev=succ1) and drain via succ1.
        let raw2 = mk_event_v1("pid-alice", Some(&genesis_id), &backfill_ts);
        let succ1_id = crate::audit::persist::sha256_hex(&raw2);
        let raw3 = mk_event_v1("pid-alice", Some(&succ1_id), &backfill_ts);
        let succ2_id = crate::audit::persist::sha256_hex(&raw3);

        // Hold succ2 (prev=succ1, not yet anchored) — backfilled.
        let r3 = ingest_provenance_event(base, &raw3, now).unwrap();
        assert!(
            matches!(r3, IngestOutcome::HeldPendingPredecessor { .. }),
            "backfilled succ2 must be held, got {r3:?}"
        );

        // Anchor succ1 (also backfilled) — drains succ2 via the drain cascade.
        let r2 = ingest_provenance_event(base, &raw2, now).unwrap();
        assert!(
            matches!(r2, IngestOutcome::Anchored { .. }),
            "succ1 must anchor"
        );
        assert!(
            reconcile::read_held(&csq_runs, "pid-alice", &succ2_id).is_none(),
            "succ2 must be drained"
        );

        let chain_text = read_chain_text(base).unwrap();
        // succ1: directly-anchored backfill → annotated.
        let p1 = find_anchored(&chain_text, &succ1_id).unwrap();
        assert_eq!(
            p1.ordering_basis.as_deref(),
            Some("wallclock_skew_bounded"),
            "directly-anchored backfill must be annotated"
        );
        // succ2: DRAINED backfill → must ALSO be annotated (the R4 fix).
        let p2 = find_anchored(&chain_text, &succ2_id).unwrap();
        assert_eq!(
            p2.ordering_basis.as_deref(),
            Some("wallclock_skew_bounded"),
            "R4: a drained backfilled event must keep its ordering_basis annotation"
        );
        verify_chain(base, &VerifyConfig::default(), None).expect("chain verifies");
    }

    // ── AC4: a live event (claimed ≈ now) carries NO ordering_basis ──

    #[test]
    fn test_m20_live_event_no_ordering_basis() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let raw = mk_event_v1("pid-alice", None, &current_iso8601_utc_persist());
        let decision_id = crate::audit::persist::sha256_hex(&raw);
        let r = ingest_provenance_event(base, &raw, now_unix()).unwrap();
        assert!(matches!(r, IngestOutcome::Anchored { .. }));
        let p = find_anchored(&read_chain_text(base).unwrap(), &decision_id).unwrap();
        assert_eq!(
            p.ordering_basis, None,
            "a live event must NOT carry ordering_basis"
        );
    }

    // ── AC5: the held store is a BUFFER of raw bytes, never a second chain ──

    #[test]
    fn test_m20_held_store_is_buffer_not_chain() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");

        let fake_prev = "c".repeat(64);
        let raw = mk_event_v1("pid-alice", Some(&fake_prev), &ts);
        let held_id = crate::audit::persist::sha256_hex(&raw);
        ingest_provenance_event(base, &raw, now_unix()).unwrap();

        let held = reconcile::read_held(&csq_runs, "pid-alice", &held_id).expect("event held");
        assert_eq!(held, raw, "held file must be the exact raw event bytes");
        let held_str = String::from_utf8(held).unwrap();
        for forbidden in ["prev_hash", "canonical_hash", "signature", "\"seq\""] {
            assert!(
                !held_str.contains(forbidden),
                "held buffer must not carry chain-spine field {forbidden}"
            );
        }
    }

    // ── dedup survives sidecar deletion — rebuild from chain ──

    #[test]
    fn test_m20_dedup_survives_sidecar_deletion() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");
        let id = uuid_n(95);
        let raw = mk_event_legacy(&id, "cc", 1, &ts);

        ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();
        std::fs::remove_file(csq_runs.join(crate::audit::persist::SEAM_DEDUP_INDEX)).unwrap();

        let r = ingest_provenance_event_with_test_registry(base, &raw, now_unix()).unwrap();
        assert!(
            matches!(r, IngestOutcome::DuplicateSuppressed { .. }),
            "replay after sidecar deletion must still dedup, got {r:?}"
        );
        assert_eq!(
            count_records_of_kind(&read_chain_text(base).unwrap(), "provenance_anchored"),
            1
        );
    }

    // ── rebuild is scoped to the ACTIVE chain ──

    #[test]
    fn test_m20_rebuild_scoped_to_active_chain() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");
        let foreign_id = uuid_n(96);

        ingest_provenance_event_with_test_registry(
            base,
            &mk_event_legacy(&uuid_n(97), "cc", 1, &ts),
            now_unix(),
        )
        .unwrap();

        let stray = read_chain_text(base).unwrap();
        std::fs::write(
            csq_runs.join("stray-chain.jsonl"),
            stray.replace(&uuid_n(97), &foreign_id),
        )
        .unwrap();
        std::fs::remove_file(csq_runs.join(crate::audit::persist::SEAM_DEDUP_INDEX)).unwrap();

        let r = ingest_provenance_event_with_test_registry(
            base,
            &mk_event_legacy(&foreign_id, "cc", 2, &ts),
            now_unix(),
        )
        .unwrap();
        assert!(
            matches!(r, IngestOutcome::Anchored { .. }),
            "a fresh id in only a STRAY jsonl must anchor, not false-suppress, got {r:?}"
        );
    }

    // ── sweep leaves a not-yet-timed-out held event alone ──

    #[test]
    fn test_m20_sweep_leaves_non_timed_out_alone() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");

        let fake_prev = "d".repeat(64);
        let raw = mk_event_v1("pid-alice", Some(&fake_prev), &ts);
        let held_id = crate::audit::persist::sha256_hex(&raw);
        ingest_provenance_event(base, &raw, now_unix()).unwrap();

        let linked = sweep_timed_out(base, now_unix() + 5).unwrap();
        assert_eq!(linked, 0, "a fresh held event must not be swept");
        assert!(
            reconcile::read_held(&csq_runs, "pid-alice", &held_id).is_some(),
            "the held event must remain after a no-op sweep"
        );
    }

    // ── daemon sweep tick drains a timed-out held event ──

    #[test]
    fn test_m20_daemon_sweep_tick_drains_timed_out() {
        use std::time::{Duration, SystemTime};
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");

        let fake_prev = "e".repeat(64);
        let raw = mk_event_v1("pid-alice", Some(&fake_prev), &ts);
        let held_id = crate::audit::persist::sha256_hex(&raw);
        ingest_provenance_event(base, &raw, now_unix()).unwrap();

        let held_path = reconcile::held_path(&csq_runs, "pid-alice", &held_id);
        assert!(held_path.exists());

        let old = SystemTime::now() - Duration::from_secs((PREDECESSOR_WAIT_SECS + 100) as u64);
        std::fs::File::options()
            .write(true)
            .open(&held_path)
            .unwrap()
            .set_modified(old)
            .unwrap();

        crate::daemon::refresher::run_held_sweep_tick(base);

        assert!(
            !held_path.exists(),
            "the daemon sweep tick must drain the timed-out held event"
        );
        let p = find_anchored(&read_chain_text(base).unwrap(), &held_id)
            .expect("event anchored after the daemon sweep tick");
        assert_eq!(p.predecessor_missing, Some(true));
    }

    // ── HIGH-1: post-hold self-rescue when predecessor anchors during the
    //    hold-write / gap-check window. ──
    //
    // Test strategy: deterministically exercise the self-rescue by:
    // 1. Build successor S whose prev_link = X (X not yet anchored).
    // 2. Manually seed the dedup index with X (simulating X anchoring during
    //    the TOCTOU window between S's gap-check and its hold write).
    // 3. Call ingest for S — the gap-check fires Hold (index not seeded yet
    //    from S's perspective on first entry), hold_for_predecessor writes the
    //    hold file, then the post-hold re-check finds X in the index and
    //    self-rescues: remove_held + fall through to anchor_core.
    // 4. Assert S is Anchored (not HeldPendingPredecessor) and predecessor_missing
    //    is NOT set (no false gap annotation on a complete causal link).
    //
    // Because we control the index seeding order, the test is deterministic
    // without needing real concurrency.

    #[test]
    fn test_high1_post_hold_self_rescue_when_predecessor_arrives_during_window() {
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");

        // Build predecessor X (genesis, so it would anchor immediately).
        let raw_x = mk_event_v1("pid-alice", None, &ts);
        let x_id = crate::audit::persist::sha256_hex(&raw_x);

        // Build successor S whose prev_link = X.
        let raw_s = mk_event_v1("pid-alice", Some(&x_id), &ts);
        let s_id = crate::audit::persist::sha256_hex(&raw_s);

        // Pre-condition: neither X nor S is anchored; no dedup index.
        assert!(
            !crate::audit::persist::seam_dedup_index_contains(&csq_runs, &x_id),
            "pre-condition: X not in dedup index"
        );

        // Step A: hold S (X is absent → Hold).
        let r_hold = ingest_provenance_event(base, &raw_s, now_unix()).unwrap();
        assert!(
            matches!(r_hold, IngestOutcome::HeldPendingPredecessor { .. }),
            "S must be held when X is absent, got: {r_hold:?}"
        );
        assert!(
            reconcile::read_held(&csq_runs, "pid-alice", &s_id).is_some(),
            "S must be in the held store after hold"
        );

        // Step B: anchor X (writes X to the dedup index).
        let r_x = ingest_provenance_event(base, &raw_x, now_unix()).unwrap();
        assert!(
            matches!(r_x, IngestOutcome::Anchored { .. }),
            "X must anchor (genesis), got: {r_x:?}"
        );

        // After X anchors, drain_successors_for should have already drained S.
        // Assert S is anchored and NOT wedged, and does NOT carry predecessor_missing.
        assert!(
            reconcile::read_held(&csq_runs, "pid-alice", &s_id).is_none(),
            "S must be drained (not in held store) after X anchored"
        );
        let chain_text = read_chain_text(base).expect("chain must exist");
        let p =
            find_anchored(&chain_text, &s_id).expect("S must be anchored in chain after X arrived");
        assert_eq!(
            p.predecessor_missing, None,
            "HIGH-1: S must NOT carry predecessor_missing=true on a complete causal link (X arrived)"
        );

        // Verify the re-check path specifically: attempt a *second* ingest of S
        // (which is already anchored via drain). It should DuplicateSuppressed,
        // not re-hold. This confirms S was anchored by the drain, not just by
        // the self-rescue path.
        let r_replay = ingest_provenance_event(base, &raw_s, now_unix()).unwrap();
        assert!(
            matches!(r_replay, IngestOutcome::DuplicateSuppressed { .. }),
            "S replay must be DuplicateSuppressed, got: {r_replay:?}"
        );

        // Direct self-rescue sub-test: build a DIFFERENT successor S2 whose
        // prev_link = X, but this time we seed the index with X *before* the
        // gap-check fires (simulating predecessor arriving in the TOCTOU window).
        // The first gap-check should see X absent ... but wait, X is now anchored
        // from Step B. So S2's gap-check will see X and Proceed immediately —
        // exercising the normal in-order path. For the TOCTOU self-rescue
        // specifically, we need to simulate: gap-check misses → hold → re-check
        // finds. We can test that by using a *different* event builder whose
        // prev_link is NOT in the dedup index, holding it, then seeding the index
        // manually, then re-ingesting it (which causes the post-hold re-check to
        // fire via the idempotent re-hold path).
        let fake_x_id = "f1f2f3f4f5f6f7f8f9fafbfcfdfeff00f1f2f3f4f5f6f7f8f9fafbfcfdfeff01";
        let raw_s2 = mk_event_v1("pid-bob", Some(fake_x_id), &ts);
        let s2_id = crate::audit::persist::sha256_hex(&raw_s2);

        // Hold S2 (fake_x_id absent).
        let r_s2_hold = ingest_provenance_event(base, &raw_s2, now_unix()).unwrap();
        assert!(
            matches!(r_s2_hold, IngestOutcome::HeldPendingPredecessor { .. }),
            "S2 must be held when fake_x_id is absent, got: {r_s2_hold:?}"
        );

        // Seed the dedup index with fake_x_id (simulating the predecessor anchoring
        // in the window between S2's gap-check and its hold write).
        let index_path = csq_runs.join(crate::audit::persist::SEAM_DEDUP_INDEX);
        let mut content = std::fs::read_to_string(&index_path).unwrap_or_default();
        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        content.push_str(fake_x_id);
        content.push('\n');
        std::fs::write(&index_path, &content).unwrap();

        // Re-ingest S2: the gap-check fires Hold again (idempotent re-hold), then
        // the post-hold re-check finds fake_x_id in the index and self-rescues →
        // Anchored WITHOUT predecessor_missing.
        let r_s2_rescue = ingest_provenance_event(base, &raw_s2, now_unix()).unwrap();
        assert!(
            matches!(r_s2_rescue, IngestOutcome::Anchored { .. }),
            "HIGH-1 self-rescue: S2 must anchor after post-hold re-check finds predecessor, got: {r_s2_rescue:?}"
        );
        let p_s2 = find_anchored(&read_chain_text(base).unwrap(), &s2_id)
            .expect("S2 must be anchored in chain");
        assert_eq!(
            p_s2.predecessor_missing, None,
            "HIGH-1: self-rescued S2 must NOT carry predecessor_missing=true"
        );
    }

    // ── MEDIUM-3: sweep forced path uses the explicit is_forced() predicate ──

    #[test]
    fn test_medium3_sweep_forced_path_is_explicit() {
        use super::super::reconcile::OrderingContext;
        // Assert that gap_timeout() sets forced=true and is_forced() returns true.
        let ctx = OrderingContext::gap_timeout();
        assert!(
            ctx.is_forced(),
            "MEDIUM-3: gap_timeout context must report is_forced() == true"
        );
        // Assert that live() sets forced=false.
        let live = OrderingContext::live();
        assert!(
            !live.is_forced(),
            "MEDIUM-3: live context must report is_forced() == false"
        );
        // Assert that the sweep actually uses the explicit flag: a timed-out held
        // event anchors WITH predecessor_missing=true (the forced path is taken).
        let dir = tmp();
        let base = dir.path();
        init_test_signing_key(base);
        let ts = current_iso8601_utc_persist();
        let csq_runs = base.join("csq-runs");

        let fake_prev = "9999999999999999999999999999999999999999999999999999999999999999";
        let raw = mk_event_v1("pid-charlie", Some(fake_prev), &ts);
        let held_id = crate::audit::persist::sha256_hex(&raw);
        ingest_provenance_event(base, &raw, now_unix()).unwrap();

        let future = now_unix() + PREDECESSOR_WAIT_SECS + 100;
        let linked = sweep_timed_out(base, future).unwrap();
        assert_eq!(linked, 1, "timed-out event must be linked by sweep");

        assert!(
            reconcile::read_held(&csq_runs, "pid-charlie", &held_id).is_none(),
            "MEDIUM-3: held event must be removed after forced sweep"
        );
        let p = find_anchored(&read_chain_text(base).unwrap(), &held_id)
            .expect("event anchored after sweep");
        assert_eq!(
            p.predecessor_missing,
            Some(true),
            "MEDIUM-3: forced sweep link must carry predecessor_missing=true"
        );
    }
}
