//! `GcpBucketLockSink` — GCP Cloud Storage Bucket Lock reference impl.
//!
//! Gated: `--features gcp-sink`.
//!
//! # Production hardening
//!
//! Uses an in-memory mock substrate. Operators replace with
//! `google-cloud-storage` SDK. See `docs/audit-sinks/gcp.md` for:
//! - Bucket Lock (retention policy locked — makes retention permanent)
//! - IAM role: `roles/storage.objectCreator` + `roles/storage.objectViewer`
//! - Object naming: `<chain_id>/<record_id>.json`
//!
//! # Default cadence
//!
//! Regular: `1d`, High-impact: `1d`.
//! Operator override: `csq audit config-cadence gcp cadence <value>`

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::audit::traits::LedgerSink;
use crate::audit::types::{
    IdError, RecordId, RedactedString, SignedRecord, SinkError, SinkId, SinkName, SinkReceipt,
};

/// GCP sink configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GcpConfig {
    /// GCP project ID.
    pub project_id: String,
    /// Bucket name (must have Bucket Lock enabled).
    pub bucket: String,
}

impl Default for GcpConfig {
    fn default() -> Self {
        Self {
            project_id: "csq-audit-project".to_string(),
            bucket: "csq-audit-chain".to_string(),
        }
    }
}

/// GCP Cloud Storage Bucket Lock sink.
#[derive(Debug)]
pub struct GcpBucketLockSink {
    name: SinkName,
    _config: GcpConfig,
    store: Mutex<HashMap<RecordId, SignedRecord>>,
    counter: Mutex<u64>,
}

impl GcpBucketLockSink {
    /// Constructs a `GcpBucketLockSink` with the given config.
    pub fn new(config: GcpConfig) -> Result<Self, IdError> {
        Ok(Self {
            name: SinkName::try_new("gcp")?,
            _config: config,
            store: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        })
    }

    /// Constructs with default config.
    pub fn with_defaults() -> Result<Self, IdError> {
        Self::new(GcpConfig::default())
    }
}

#[async_trait]
impl LedgerSink for GcpBucketLockSink {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
        let index = {
            let mut ctr = self.counter.lock().unwrap_or_else(|p| p.into_inner());
            let v = *ctr;
            *ctr += 1;
            v
        };
        let sink_id =
            SinkId::try_new(format!("gcp-gen-{index}")).map_err(|e| SinkError::Internal {
                message: RedactedString::from_trusted(e.to_string()),
            })?;
        let mut store = self.store.lock().unwrap_or_else(|p| p.into_inner());
        store.insert(record.record_id.clone(), record.clone());
        Ok(SinkReceipt {
            sink: self.name.clone(),
            sink_id,
            anchored_at: record.ts.clone(),
            inclusion_proof: None,
        })
    }

    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
        let store = self.store.lock().unwrap_or_else(|p| p.into_inner());
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

    fn sample_record(id: &str, seq: u64) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(id).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq,
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
        }
    }

    #[tokio::test]
    async fn gcp_bucket_lock_sink_stubbed_round_trip() {
        let sink = GcpBucketLockSink::with_defaults().expect("valid config");
        assert_eq!(sink.name(), "gcp");
        let record = sample_record("01JZ00000000000000000000G1", 0);
        let receipt = sink.append(&record).await.expect("append");
        assert_eq!(receipt.sink.as_str(), "gcp");
        let fetched = sink.verify_at(&record.record_id).await.expect("verify");
        assert_eq!(fetched, record);
    }
}
