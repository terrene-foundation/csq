//! `AzureImmutableBlobSink` — Azure Immutable Blob Storage reference impl.
//!
//! Gated: `--features azure-sink`.
//!
//! # Production hardening
//!
//! Uses an in-memory mock substrate. Operators replace with
//! `azure-storage-blobs` SDK.  See `docs/audit-sinks/azure.md` for:
//! - Container-level immutability policy (time-based / legal hold)
//! - Azure AD application registration + RBAC (`Storage Blob Data Contributor`)
//! - Blob naming scheme: `<chain_id>/<record_id>.json`
//!
//! # Default cadence
//!
//! Regular: `1d`, High-impact: `1d`.
//! Operator override: `csq audit config-cadence azure cadence <value>`

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::audit::traits::LedgerSink;
use crate::audit::types::{
    IdError, RecordId, RedactedString, SignedRecord, SinkError, SinkId, SinkName, SinkReceipt,
};

/// Azure sink configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AzureConfig {
    /// Azure storage account name.
    pub account: String,
    /// Container name (must have immutability policy applied).
    pub container: String,
}

impl Default for AzureConfig {
    fn default() -> Self {
        Self {
            account: "csqauditstore".to_string(),
            container: "audit-chain".to_string(),
        }
    }
}

/// Azure Immutable Blob Storage sink.
#[derive(Debug)]
pub struct AzureImmutableBlobSink {
    name: SinkName,
    _config: AzureConfig,
    store: Mutex<HashMap<RecordId, SignedRecord>>,
    counter: Mutex<u64>,
}

impl AzureImmutableBlobSink {
    /// Constructs an `AzureImmutableBlobSink` with the given config.
    pub fn new(config: AzureConfig) -> Result<Self, IdError> {
        Ok(Self {
            name: SinkName::try_new("azure")?,
            _config: config,
            store: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        })
    }

    /// Constructs with default config.
    pub fn with_defaults() -> Result<Self, IdError> {
        Self::new(AzureConfig::default())
    }
}

#[async_trait]
impl LedgerSink for AzureImmutableBlobSink {
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
            SinkId::try_new(format!("azure-etag-{index}")).map_err(|e| SinkError::Internal {
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
    async fn azure_immutable_blob_sink_stubbed_round_trip() {
        let sink = AzureImmutableBlobSink::with_defaults().expect("valid config");
        assert_eq!(sink.name(), "azure");
        let record = sample_record("01JZ00000000000000000000A1", 0);
        let receipt = sink.append(&record).await.expect("append");
        assert_eq!(receipt.sink.as_str(), "azure");
        let fetched = sink.verify_at(&record.record_id).await.expect("verify");
        assert_eq!(fetched, record);
    }
}
