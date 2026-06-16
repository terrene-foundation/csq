//! M13 — F-LEDGER-02 orphan-intent detection.
//!
//! A side-effecting op emits a pre-op INTENT record (drained before the side
//! effect) and a post-op OUTCOME record (appended after it terminates), sharing
//! one `correlation_id` (see [`crate::audit::types::OpPhase`]). A crash or kill
//! between the two leaves an INTENT with no matching OUTCOME — the F-LEDGER-02
//! "the side effect may have happened but its outcome was never recorded" state.
//!
//! [`scan_orphan_intents`] walks the committed chain and returns every such
//! orphan. `csq doctor` surfaces them so the operator can investigate (the op
//! may have half-completed). This is detection only — it never mutates the
//! chain.
//!
//! # Scope
//!
//! Only top-level `<base_dir>/csq-runs/*.jsonl` files (the committed chain, one
//! per `chain_id`) are scanned. The `.pending/`, `.quarantine/`, and
//! `.pending-<sink>/` subdirectories are deliberately excluded — they hold
//! not-yet-drained or corrupt records, not committed chain state.

use std::path::Path;

use crate::audit::types::{OpPhase, SignedRecord};

/// A pre-op INTENT record on the committed chain with no matching OUTCOME.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct OrphanIntent {
    /// The correlation id shared by the intent and its (missing) outcome.
    pub correlation_id: String,
    /// The intent record's own id.
    pub record_id: String,
    /// The op kind the intent precedes, snake_case (e.g. `"key_rotate"`).
    pub kind: String,
    /// The intent record's sequence number within its chain.
    pub seq: u64,
}

/// Errors from [`scan_orphan_intents`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrphanScanError {
    /// Failed to read the `csq-runs/` directory or a chain file.
    #[error("orphan-intent scan I/O error")]
    Io(#[from] std::io::Error),
    /// A chain line did not parse as a `SignedRecord`. The chain verifier
    /// (`verify_chain`) is the authority on corruption; the scan refuses to
    /// guess at orphans from a partially-parseable file (a dropped OUTCOME
    /// line would manufacture a false orphan).
    #[error("orphan-intent scan: chain line did not parse as a SignedRecord")]
    Parse,
}

/// Walks the committed chain under `<base_dir>/csq-runs/` and returns every
/// INTENT record whose `correlation_id` has no matching OUTCOME record.
///
/// Returns an empty `Vec` when there is no `csq-runs/` directory, no chain
/// file, or no intent records.
///
/// **Correlation is global across ALL top-level chain files** — the `resolved`
/// set accumulates every outcome's `correlation_id` from every file before the
/// final retain, so an outcome in any file resolves an intent in any file. This
/// is the deliberately-lenient direction: a re-genesis that split an intent and
/// its outcome across two files would still resolve correctly (fewer false
/// orphans), and `correlation_id` is a 128-bit CSPRNG ULID so cross-file
/// collision (a false non-orphan) is cryptographically negligible.
pub fn scan_orphan_intents(base_dir: &Path) -> Result<Vec<OrphanIntent>, OrphanScanError> {
    use std::collections::HashSet;

    let csq_runs = base_dir.join("csq-runs");
    if !csq_runs.is_dir() {
        return Ok(Vec::new());
    }

    let mut intents: Vec<OrphanIntent> = Vec::new();
    let mut resolved: HashSet<String> = HashSet::new();

    for entry in std::fs::read_dir(&csq_runs)? {
        let entry = entry?;
        let path = entry.path();
        // Top-level chain files only: `*.jsonl`, not the `.pending/` etc. dirs.
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: SignedRecord = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(_) => {
                    // Mirror `verify_chain`'s mixed-schema tolerance (see
                    // `verify.rs` module docs): a line that fails to parse as a
                    // v2 `SignedRecord` AND carries the v1 schema marker is a
                    // legacy record left on a long-lived chain — SKIP it, do not
                    // fail the whole scan. Only a non-v1 unparseable line is a
                    // genuine corruption signal worth surfacing.
                    if line.contains(r#""schema_version":"1""#) {
                        continue;
                    }
                    return Err(OrphanScanError::Parse);
                }
            };
            match &record.op_phase {
                Some(OpPhase::Intent { correlation_id }) => {
                    intents.push(OrphanIntent {
                        correlation_id: correlation_id.as_str().to_string(),
                        record_id: record.record_id.as_str().to_string(),
                        // EventKind serializes snake_case; reuse that vocabulary.
                        kind: serde_json::to_value(record.kind)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_string))
                            .unwrap_or_else(|| format!("{:?}", record.kind)),
                        seq: record.seq,
                    });
                }
                Some(OpPhase::Outcome { correlation_id, .. }) => {
                    resolved.insert(correlation_id.as_str().to_string());
                }
                None => {}
            }
        }
    }

    intents.retain(|i| !resolved.contains(&i.correlation_id));
    // Stable order: by seq ascending so doctor output is deterministic.
    intents.sort_by_key(|i| i.seq);
    Ok(intents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::persist::write_record_v2;
    use crate::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, OpOutcome, RecordId,
        Sha256Hex, SignedRecord,
    };
    use tempfile::TempDir;

    fn base_record(run: &str, op_phase: Option<OpPhase>) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: run.to_string(),
            }),
            ts: "2100-01-01T00:00:00+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase,
        }
    }

    #[test]
    fn empty_base_has_no_orphans() {
        let tmp = TempDir::new().unwrap();
        assert!(scan_orphan_intents(tmp.path()).unwrap().is_empty());
    }

    #[test]
    fn intent_with_matching_outcome_is_not_orphan() {
        let tmp = TempDir::new().unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        write_record_v2(
            base_record(
                "i",
                Some(OpPhase::Intent {
                    correlation_id: corr.clone(),
                }),
            ),
            Some(tmp.path()),
        )
        .unwrap();
        write_record_v2(
            base_record(
                "o",
                Some(OpPhase::Outcome {
                    correlation_id: corr,
                    result: OpOutcome::Ok,
                }),
            ),
            Some(tmp.path()),
        )
        .unwrap();
        assert!(scan_orphan_intents(tmp.path()).unwrap().is_empty());
    }

    #[test]
    fn intent_without_outcome_is_orphan() {
        let tmp = TempDir::new().unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        write_record_v2(
            base_record(
                "i",
                Some(OpPhase::Intent {
                    correlation_id: corr.clone(),
                }),
            ),
            Some(tmp.path()),
        )
        .unwrap();
        let orphans = scan_orphan_intents(tmp.path()).unwrap();
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].correlation_id, corr.as_str());
        assert_eq!(orphans[0].kind, "csq_run");
    }

    #[test]
    fn records_without_op_phase_are_ignored() {
        let tmp = TempDir::new().unwrap();
        write_record_v2(base_record("plain", None), Some(tmp.path())).unwrap();
        assert!(scan_orphan_intents(tmp.path()).unwrap().is_empty());
    }

    /// A legacy v1 record (`schema_version: "1"`) left on a long-lived chain MUST
    /// be SKIPPED, not fail the whole scan — mirrors `verify_chain`'s mixed-schema
    /// tolerance. A v2 intent on the same chain is still detected. Regression for
    /// the `audit_orphan_intent_scan_failed` WARN observed on a real host chain
    /// carrying v1 (csq 2.6.2-era) launch-log records.
    #[test]
    fn v1_legacy_record_is_skipped_not_scan_failure() {
        let tmp = TempDir::new().unwrap();
        let csq_runs = tmp.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        // A real v1 launch-log line (the exact shape that tripped the scan on the
        // maintainer host): parses-fail as a v2 SignedRecord, carries the v1 marker.
        let v1_line = r#"{"schema_version":"1","run_id":"002064d7-1b67-4a0f-a99a-0474b17efb55","csq_version":"2.6.2","surface":"cc","result_state":"pass"}"#;
        let intent = base_record(
            "i",
            Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
        );
        std::fs::write(
            csq_runs.join("mixed.jsonl"),
            format!("{v1_line}\n{}\n", serde_json::to_string(&intent).unwrap()),
        )
        .unwrap();
        let orphans =
            scan_orphan_intents(tmp.path()).expect("v1 line must be skipped, not error the scan");
        assert_eq!(
            orphans.len(),
            1,
            "the v2 intent is still detected past the skipped v1 line"
        );
        assert_eq!(orphans[0].correlation_id, corr.as_str());
    }

    /// A genuinely-corrupt (non-v1, non-parseable) line is still a hard error —
    /// the v1-skip tolerance must NOT swallow real corruption.
    #[test]
    fn corrupt_non_v1_line_still_errors() {
        let tmp = TempDir::new().unwrap();
        let csq_runs = tmp.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        std::fs::write(csq_runs.join("bad.jsonl"), "{not valid json at all}\n").unwrap();
        assert!(
            matches!(scan_orphan_intents(tmp.path()), Err(OrphanScanError::Parse)),
            "a non-v1 unparseable line must surface as a Parse error, not be silently skipped"
        );
    }

    /// `.pending/` (and any other subdirectory) is excluded from the scan — an
    /// intent buffered there is not yet committed and must NOT count as an
    /// orphan on the committed chain.
    #[test]
    fn pending_subdir_is_excluded() {
        let tmp = TempDir::new().unwrap();
        let pending = tmp.path().join("csq-runs").join(".pending");
        std::fs::create_dir_all(&pending).unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        let rec = base_record(
            "buffered",
            Some(OpPhase::Intent {
                correlation_id: corr,
            }),
        );
        std::fs::write(
            pending.join("buffered.jsonl"),
            serde_json::to_string(&rec).unwrap() + "\n",
        )
        .unwrap();
        // The intent lives only under .pending/ → not scanned → no orphan.
        assert!(scan_orphan_intents(tmp.path()).unwrap().is_empty());
    }

    /// Correlation is global: an outcome in one committed chain file resolves an
    /// intent in another (the re-genesis split case).
    #[test]
    fn outcome_in_a_different_file_resolves_the_intent() {
        let tmp = TempDir::new().unwrap();
        let csq_runs = tmp.path().join("csq-runs");
        std::fs::create_dir_all(&csq_runs).unwrap();
        let corr = RecordId::try_new(crate::audit::persist::gen_chain_id()).unwrap();
        let intent = base_record(
            "i",
            Some(OpPhase::Intent {
                correlation_id: corr.clone(),
            }),
        );
        let outcome = base_record(
            "o",
            Some(OpPhase::Outcome {
                correlation_id: corr,
                result: OpOutcome::Ok,
            }),
        );
        std::fs::write(
            csq_runs.join("chain-a.jsonl"),
            serde_json::to_string(&intent).unwrap() + "\n",
        )
        .unwrap();
        std::fs::write(
            csq_runs.join("chain-b.jsonl"),
            serde_json::to_string(&outcome).unwrap() + "\n",
        )
        .unwrap();
        assert!(
            scan_orphan_intents(tmp.path()).unwrap().is_empty(),
            "outcome in chain-b must resolve the intent in chain-a"
        );
    }
}
