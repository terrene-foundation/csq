//! `NoopSink` — in-memory test-only sink.
//!
//! Per the M01 PRIMARY METHODOLOGICAL DIRECTIVE: `NoopSink` is
//! gated `#[cfg(any(test, feature = "test-utils"))]` AND the
//! `audit::impls` module itself is gated the same way. The release
//! pipeline builds with `--no-default-features --features cli`, which
//! structurally excludes `test-utils` — `NoopSink` cannot ship in a
//! release binary.
//!
//! # NOTE for M07 reference-impl authors
//!
//! Production sinks MUST handle mutex poisoning explicitly (`PoisonError::into_inner`
//! pattern below) rather than `.expect()`-panicking, since
//! `LedgerSink::append` is called from daemon-shared async tasks and a
//! panic kills the daemon worker. NoopSink demonstrates the safe shape.
//!
//! Constructor validates the sink name via [`SinkName::try_new`] —
//! production sinks should do the same so the `[a-z0-9-]{1,64}` shape
//! invariant is enforced at construction, not only documented.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::audit::traits::LedgerSink;
use crate::audit::types::{
    IdError, RecordId, SignedRecord, SinkError, SinkId, SinkName, SinkReceipt,
};

/// In-memory test sink. Stores submitted records keyed by their
/// [`RecordId`] and serves them back from [`LedgerSink::verify_at`].
/// NOT a stub — the impl is functionally complete for its domain
/// (test-only verification of the trait shape).
#[derive(Debug)]
pub struct NoopSink {
    name: SinkName,
    store: Mutex<HashMap<RecordId, SignedRecord>>,
}

impl NoopSink {
    /// Constructs a fresh `NoopSink` with the given operator name.
    /// `name` MUST match the [`SinkName`] charset (`[a-z0-9-]{1,64}`).
    ///
    /// # Errors
    ///
    /// Returns [`IdError`] when `name` fails [`SinkName::try_new`].
    pub fn new(name: impl Into<String>) -> Result<Self, IdError> {
        Ok(Self {
            name: SinkName::try_new(name)?,
            store: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the number of records currently stored.
    #[must_use]
    pub fn len(&self) -> usize {
        // PoisonError::into_inner: returns the inner data even if a
        // prior holder panicked. The data is consistent because every
        // write below is a single `insert` that cannot be interrupted
        // mid-mutation by a panic from the same thread.
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Returns whether the sink is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl LedgerSink for NoopSink {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.insert(record.record_id.clone(), record.clone());
        let sink_id =
            SinkId::try_new(format!("noop-{}", record.seq)).map_err(|e| SinkError::Internal {
                // `from_trusted` is safe here: `IdError::Display` emits only
                // static format templates with `&'static str` field names and
                // numeric bounds — no external string content. Production
                // sinks copying this pattern that receive sink-assigned ids
                // from the network MUST use `from_untrusted` here so any
                // attacker-controlled byte in the id is redacted.
                message: crate::audit::types::RedactedString::from_trusted(e.to_string()),
            })?;
        Ok(SinkReceipt {
            sink: self.name.clone(),
            sink_id,
            anchored_at: record.ts.clone(),
            inclusion_proof: None,
        })
    }

    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        store.get(id).cloned().ok_or_else(|| SinkError::NotFound {
            record_id: id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, Sha256Hex,
    };

    fn sample_record(seq: u64, id: &str) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(id).unwrap(),
            // Valid 26-char Crockford Base32 ULID for chain_id.
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: format!("run-{seq}"),
            }),
            ts: "2026-05-28T12:34:56+00:00".to_string(),
            key_id: KeyId::try_new(format!("ed25519:{}", "0".repeat(64))).unwrap(),
            canonical_hash: Sha256Hex::genesis(),
            signature: Ed25519Signature::new([0u8; 64]),
            actor: None,
            authority: None,
            trust: None,
            eatp_start_ts: None,
            eatp_end_ts: None,
            op_phase: None,
        }
    }

    #[tokio::test]
    async fn noop_sink_round_trip() {
        let sink = NoopSink::new("noop-test").expect("valid name");
        assert_eq!(sink.name(), "noop-test");
        assert!(sink.is_empty());
        // Valid 26-char Crockford Base32 ULID for record_id.
        let record = sample_record(0, "01JZ00000000000000000000R0");
        let receipt = sink.append(&record).await.expect("append");
        assert_eq!(receipt.sink.as_str(), "noop-test");
        assert_eq!(receipt.sink_id.as_str(), "noop-0");
        assert_eq!(sink.len(), 1);
        let fetched = sink
            .verify_at(&RecordId::try_new("01JZ00000000000000000000R0").unwrap())
            .await
            .expect("verify");
        assert_eq!(fetched, record);
    }

    #[tokio::test]
    async fn noop_sink_missing_record_returns_not_found() {
        let sink = NoopSink::new("noop-test").expect("valid name");
        // UUIDv7 shape: version nibble 7, variant nibble 8.
        let result = sink
            .verify_at(&RecordId::try_new("01931234-5678-7abc-8def-000000000000").unwrap())
            .await;
        assert!(
            matches!(result, Err(SinkError::NotFound { .. })),
            "missing record must surface NotFound (not Rejected)"
        );
    }

    #[test]
    fn noop_sink_rejects_invalid_name() {
        let result = NoopSink::new("Rekor\r\nX-Inject");
        assert!(result.is_err(), "name with CRLF must be rejected");
    }
}
