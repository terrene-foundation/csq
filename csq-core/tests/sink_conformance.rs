//! M07 `LedgerSink` conformance harness.
//!
//! Every `LedgerSink` reference impl MUST pass the append→verify
//! round-trip assertion for every record in the fixed corpus below.
//! New reference impls in the catalog MUST add a test here under their
//! feature flag.
//!
//! # Running
//!
//! Default (NoopSink only — always compiled):
//! ```sh
//! cargo test --features csq-core/test-utils -p csq-core \
//!   --test sink_conformance
//! ```
//!
//! Rekor sink (feature-on path):
//! ```sh
//! cargo test --features csq-core/test-utils,csq-core/rekor-sink -p csq-core \
//!   --test sink_conformance
//! ```

use csq_core::audit::traits::LedgerSink;
use csq_core::audit::types::{
    CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, RecordId, Sha256Hex,
    SignedRecord,
};

/// Fixed test corpus: 5 records with distinct ids and seq numbers.
fn test_corpus() -> Vec<SignedRecord> {
    let ids = [
        "01JZ00000000000000000000C0",
        "01JZ00000000000000000000C1",
        "01JZ00000000000000000000C2",
        "01JZ00000000000000000000C3",
        "01JZ00000000000000000000C4",
    ];
    ids.iter()
        .enumerate()
        .map(|(seq, id)| SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(*id).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XX").unwrap(),
            seq: seq as u64,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: format!("run-{seq}"),
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
        })
        .collect()
}

/// Core conformance assertion: append every record, then verify each one.
/// Every record returned by `verify_at` MUST equal the originally appended.
async fn assert_sink_conforms(sink: &dyn LedgerSink, sink_label: &str) {
    let corpus = test_corpus();
    // Phase 1 — append all records.
    for record in &corpus {
        let receipt = sink.append(record).await.unwrap_or_else(|e| {
            panic!("[{sink_label}] append failed for seq {}: {e:?}", record.seq)
        });
        assert_eq!(
            receipt.sink.as_str(),
            sink.name(),
            "[{sink_label}] receipt.sink should match sink.name()"
        );
    }
    // Phase 2 — verify each record round-trips.
    for record in &corpus {
        let fetched = sink.verify_at(&record.record_id).await.unwrap_or_else(|e| {
            panic!(
                "[{sink_label}] verify_at failed for seq {}: {e:?}",
                record.seq
            )
        });
        assert_eq!(
            fetched, *record,
            "[{sink_label}] round-trip: fetched record differs from appended for seq {}",
            record.seq
        );
    }
}

/// M15 retry-safety: re-anchoring the SAME record (a retry after a partial
/// failure, or a duplicate poll) MUST be a no-op or safe overwrite — the record
/// is still retrievable and unchanged. Asserts `append(r); append(r); verify_at(r) == r`.
#[cfg(any(
    feature = "s3-sink",
    feature = "azure-sink",
    feature = "gcp-sink",
    feature = "azure-sql-sink"
))]
async fn assert_sink_retry_safe(sink: &dyn LedgerSink, sink_label: &str) {
    let r = &test_corpus()[0];
    sink.append(r)
        .await
        .unwrap_or_else(|e| panic!("[{sink_label}] first append failed: {e:?}"));
    sink.append(r)
        .await
        .unwrap_or_else(|e| panic!("[{sink_label}] retry append failed: {e:?}"));
    let fetched = sink
        .verify_at(&r.record_id)
        .await
        .unwrap_or_else(|e| panic!("[{sink_label}] verify after retry failed: {e:?}"));
    assert_eq!(
        fetched, *r,
        "[{sink_label}] retry-safety: record changed after re-anchor"
    );
}

/// M15 failure-surfaced: a `verify_at` for a record that was never anchored MUST
/// surface a typed `SinkError::NotFound` — never silently succeed, never panic.
#[cfg(any(
    feature = "s3-sink",
    feature = "azure-sink",
    feature = "gcp-sink",
    feature = "azure-sql-sink"
))]
async fn assert_sink_surfaces_missing(sink: &dyn LedgerSink, sink_label: &str) {
    use csq_core::audit::types::SinkError;
    let absent = RecordId::try_new("01JZ00000000000000000000ZZ").unwrap();
    match sink.verify_at(&absent).await {
        Err(SinkError::NotFound { record_id }) => {
            assert_eq!(
                record_id, absent,
                "[{sink_label}] NotFound must carry the queried id"
            );
        }
        Err(other) => panic!("[{sink_label}] expected NotFound, got {other:?}"),
        Ok(_) => panic!("[{sink_label}] verify_at on an absent record must NOT succeed"),
    }
}

// ── NoopSink (always compiled in test builds) ────────────────────────────────

#[cfg(any(test, feature = "test-utils"))]
#[tokio::test]
async fn ledger_sink_conformance_noop() {
    use csq_core::audit::impls::noop::NoopSink;
    let sink = NoopSink::new("conformance-noop").expect("valid name");
    assert_sink_conforms(&sink, "NoopSink").await;
}

// ── RekorSink ────────────────────────────────────────────────────────────────

#[cfg(feature = "rekor-sink")]
#[tokio::test]
async fn ledger_sink_conformance_rekor() {
    use csq_core::audit::impls::sinks::RekorSink;
    let sink = RekorSink::with_defaults().expect("valid config");
    assert_sink_conforms(&sink, "RekorSink").await;
}

// ── S3ObjectLockSink ─────────────────────────────────────────────────────────

#[cfg(feature = "s3-sink")]
#[tokio::test]
async fn ledger_sink_conformance_s3() {
    use csq_core::audit::impls::sinks::S3ObjectLockSink;
    let sink = S3ObjectLockSink::with_defaults().expect("valid config");
    assert_sink_conforms(&sink, "S3ObjectLockSink").await;
    assert_sink_retry_safe(&sink, "S3ObjectLockSink").await;
    assert_sink_surfaces_missing(&sink, "S3ObjectLockSink").await;
}

// ── AzureImmutableBlobSink ───────────────────────────────────────────────────

#[cfg(feature = "azure-sink")]
#[tokio::test]
async fn ledger_sink_conformance_azure() {
    use csq_core::audit::impls::sinks::AzureImmutableBlobSink;
    let sink = AzureImmutableBlobSink::with_defaults().expect("valid config");
    assert_sink_conforms(&sink, "AzureImmutableBlobSink").await;
    assert_sink_retry_safe(&sink, "AzureImmutableBlobSink").await;
    assert_sink_surfaces_missing(&sink, "AzureImmutableBlobSink").await;
}

// ── GcpBucketLockSink ────────────────────────────────────────────────────────

#[cfg(feature = "gcp-sink")]
#[tokio::test]
async fn ledger_sink_conformance_gcp() {
    use csq_core::audit::impls::sinks::GcpBucketLockSink;
    let sink = GcpBucketLockSink::with_defaults().expect("valid config");
    assert_sink_conforms(&sink, "GcpBucketLockSink").await;
    assert_sink_retry_safe(&sink, "GcpBucketLockSink").await;
    assert_sink_surfaces_missing(&sink, "GcpBucketLockSink").await;
}

// ── AzureSqlLedgerSink (M15) ─────────────────────────────────────────────────

#[cfg(feature = "azure-sql-sink")]
#[tokio::test]
async fn ledger_sink_conformance_azure_sql() {
    use csq_core::audit::impls::sinks::AzureSqlLedgerSink;
    let sink = AzureSqlLedgerSink::with_defaults().expect("valid config");
    assert_sink_conforms(&sink, "AzureSqlLedgerSink").await;
    assert_sink_retry_safe(&sink, "AzureSqlLedgerSink").await;
    assert_sink_surfaces_missing(&sink, "AzureSqlLedgerSink").await;
}

// ── CsqLedgerSink (M10) ──────────────────────────────────────────────────────
//
// Uses the in-memory mock transport (the conformance harness has no live
// server). The trait contract (append → verify round-trip) is identical to a
// live server; the mock proves the JSON wire encoding + the LedgerSink impl.
// Requires `--features csq-core/csq-ledger-sink,csq-core/test-utils`.

#[cfg(all(feature = "csq-ledger-sink", any(test, feature = "test-utils")))]
#[tokio::test]
async fn ledger_sink_conformance_csq_ledger() {
    use csq_core::audit::impls::csq_ledger_sink::CsqLedgerSink;
    let sink = CsqLedgerSink::mock_in_memory();
    assert_sink_conforms(&sink, "CsqLedgerSink").await;
}
