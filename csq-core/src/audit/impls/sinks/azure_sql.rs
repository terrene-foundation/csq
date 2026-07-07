//! `AzureSqlLedgerSink` — Azure SQL Database **ledger table** reference impl.
//!
//! Gated: `--features azure-sql-sink`.
//!
//! Azure SQL ledger tables are append-only tables whose rows are
//! cryptographically hashed into a Merkle tree and periodically anchored to a
//! digest the operator stores out-of-band — giving tamper-evidence at the
//! database tier (distinct from the object-storage WORM sinks `s3` / `azure` /
//! `gcp`). A record is one row keyed by `record_id`; `verify_at` is a primary-key
//! SELECT.
//!
//! # Production hardening
//!
//! This impl uses an in-memory mock substrate (per spec 15 §15.4.2). Operators
//! replace the mock with the `tiberius` SQL Server driver. See
//! `docs/audit-sinks/azure-sql.md` for:
//! - Ledger-table DDL (`WITH (LEDGER = ON (APPEND_ONLY = ON))`)
//! - Azure AD auth + minimum grant (`INSERT`, `SELECT` on the ledger table)
//! - Digest export cadence + out-of-band digest storage for tamper-evidence
//! - Row scheme: `(record_id PK, chain_id, seq, canonical_hash, record_json)`
//!
//! # Default cadence
//!
//! Regular: `1d`, High-impact: `1d`.
//! Operator override: `csq audit config-cadence azure-sql cadence <value>`

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::audit::traits::LedgerSink;
use crate::audit::types::{
    IdError, RecordId, RedactedString, SignedRecord, SinkError, SinkId, SinkName, SinkReceipt,
};

/// Azure SQL ledger-table sink configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AzureSqlConfig {
    /// SQL server host (e.g. `csq-audit.database.windows.net`).
    pub server: String,
    /// Database name.
    pub database: String,
    /// Ledger table name.
    pub table: String,
}

impl Default for AzureSqlConfig {
    fn default() -> Self {
        Self {
            server: "csq-audit.database.windows.net".to_string(),
            database: "csq_audit".to_string(),
            table: "audit_chain".to_string(),
        }
    }
}

/// Azure SQL Database ledger-table sink.
#[derive(Debug)]
pub struct AzureSqlLedgerSink {
    name: SinkName,
    _config: AzureSqlConfig,
    store: Mutex<HashMap<RecordId, SignedRecord>>,
    counter: Mutex<u64>,
}

impl AzureSqlLedgerSink {
    /// Constructs an `AzureSqlLedgerSink` with the given config.
    pub fn new(config: AzureSqlConfig) -> Result<Self, IdError> {
        Ok(Self {
            name: SinkName::try_new("azure-sql")?,
            _config: config,
            store: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        })
    }

    /// Constructs with default config.
    pub fn with_defaults() -> Result<Self, IdError> {
        Self::new(AzureSqlConfig::default())
    }
}

#[async_trait]
impl LedgerSink for AzureSqlLedgerSink {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
        // Ledger-table INSERT is keyed by record_id. Re-anchoring the same
        // record is a safe overwrite (the production DDL uses an idempotent
        // MERGE on the record_id PK); the mock mirrors this by overwriting the
        // store entry. The returned sink_id is the ledger transaction id.
        let index = {
            let mut ctr = self.counter.lock().unwrap_or_else(|p| p.into_inner());
            let v = *ctr;
            *ctr += 1;
            v
        };
        let sink_id = SinkId::try_new(format!("azure-sql-txid-{index}")).map_err(|e| {
            SinkError::Internal {
                message: RedactedString::from_trusted(e.to_string()),
            }
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
            verification_level: None,
        }
    }

    #[tokio::test]
    async fn azure_sql_ledger_sink_stubbed_round_trip() {
        let sink = AzureSqlLedgerSink::with_defaults().expect("valid config");
        assert_eq!(sink.name(), "azure-sql");
        let record = sample_record("01JZ00000000000000000000Q1", 0);
        let receipt = sink.append(&record).await.expect("append");
        assert_eq!(receipt.sink.as_str(), "azure-sql");
        let fetched = sink.verify_at(&record.record_id).await.expect("verify");
        assert_eq!(fetched, record);
    }
}
