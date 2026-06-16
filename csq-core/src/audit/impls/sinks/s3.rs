//! `S3ObjectLockSink` — AWS S3 Object Lock reference implementation.
//!
//! Gated: `--features s3-sink`.
//!
//! # Production hardening
//!
//! This impl uses an in-memory mock substrate. Operators replace the mock
//! with `aws-sdk-s3` (declared in Cargo.toml under `s3-sink` when the
//! operator adds the SDK dep).  See `docs/audit-sinks/s3.md` for:
//! - Bucket configuration (Object Lock compliance mode, versioning)
//! - IAM policy minimum — `s3:PutObject`, `s3:GetObject`, `s3:GetObjectVersion`
//! - WORM invariant: compliance mode prevents deletion during retention period
//! - Object key scheme: `<chain_id>/<record_id>.json`
//!
//! # Default cadence
//!
//! - Regular: `1d`
//! - High-impact: `1d`
//! - Operator override: `csq audit config-cadence s3 cadence <value>`

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::audit::traits::LedgerSink;
use crate::audit::types::{
    IdError, RecordId, RedactedString, SignedRecord, SinkError, SinkId, SinkName, SinkReceipt,
};

/// S3 sink configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct S3Config {
    /// S3 bucket name.
    pub bucket: String,
    /// AWS region (e.g. `"us-east-1"`).
    pub region: String,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            bucket: "csq-audit-default".to_string(),
            region: "us-east-1".to_string(),
        }
    }
}

/// AWS S3 Object Lock sink.
#[derive(Debug)]
pub struct S3ObjectLockSink {
    name: SinkName,
    _config: S3Config,
    store: Mutex<HashMap<RecordId, SignedRecord>>,
    counter: Mutex<u64>,
}

impl S3ObjectLockSink {
    /// Constructs an `S3ObjectLockSink` with the given config.
    pub fn new(config: S3Config) -> Result<Self, IdError> {
        Ok(Self {
            name: SinkName::try_new("s3")?,
            _config: config,
            store: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        })
    }

    /// Constructs with default config.
    pub fn with_defaults() -> Result<Self, IdError> {
        Self::new(S3Config::default())
    }
}

#[async_trait]
impl LedgerSink for S3ObjectLockSink {
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
        // Object key format: `<chain_id>/<record_id>.json` (mock uses index).
        let sink_id =
            SinkId::try_new(format!("s3-etag-{index}")).map_err(|e| SinkError::Internal {
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
    async fn s3_object_lock_sink_stubbed_round_trip() {
        let sink = S3ObjectLockSink::with_defaults().expect("valid config");
        assert_eq!(sink.name(), "s3");
        let record = sample_record("01JZ00000000000000000000S1", 0);
        let receipt = sink.append(&record).await.expect("append");
        assert_eq!(receipt.sink.as_str(), "s3");
        let fetched = sink.verify_at(&record.record_id).await.expect("verify");
        assert_eq!(fetched, record);
    }
}
