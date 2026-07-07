//! `RekorSink` — Sigstore Rekor reference implementation.
//!
//! Gated: `--features rekor-sink`.
//!
//! # Production hardening
//!
//! This impl uses an in-memory mock substrate for the initial M07 ship so
//! the trait contract (append/verify round-trip) is provable in CI without
//! live network access.  Operators replace `RekorBackend` with a real
//! Sigstore Rekor HTTP client to send anchor records to the public Rekor
//! instance (`rekor.sigstore.dev`) or a self-hosted instance.
//!
//! See `docs/audit-sinks/rekor.md` for the full operator guide including:
//! - Rekor API surface (`POST /api/v1/log/entries`, `GET /api/v1/log/entries/{uuid}`)
//! - Log index vs UUID lookup
//! - `sigstore` / `sigstore-rekor` crate integration (declared in Cargo.toml
//!   under the `rekor-sink` feature when the operator adds the SDK dep)
//! - Cadence defaults: `1d` regular + `immediate` on high-impact operations
//!
//! # Default cadence (per workspace-owner decision §5)
//!
//! - Regular: `1d` (one anchor per day)
//! - High-impact ops (key rotation, release auth): `immediate`
//! - Operator override: `csq audit config-cadence rekor cadence <value>`
//!
//! `#[non_exhaustive]` on `RekorConfig` allows adding fields (e.g. TLS cert,
//! auth token path) without breaking existing callers.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::audit::traits::LedgerSink;
use crate::audit::types::{
    IdError, RecordId, RedactedString, SignedRecord, SinkError, SinkId, SinkName, SinkReceipt,
};

/// Rekor sink configuration.
///
/// Operators populate this from `~/.claude/accounts/audit-sink.json`
/// (keyed under `rekor`). The daemon constructs a `RekorSink` from the
/// config and holds it behind an `Arc<dyn LedgerSink>`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RekorConfig {
    /// Rekor instance URL. Defaults to `https://rekor.sigstore.dev`.
    pub endpoint: String,
}

impl Default for RekorConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://rekor.sigstore.dev".to_string(),
        }
    }
}

/// Sigstore Rekor sink.
///
/// Implements [`LedgerSink`] by submitting `SignedRecord` bytes to a Rekor
/// transparency log.  The current impl uses an in-memory mock substrate;
/// operators replace it with a live Rekor HTTP client per
/// `docs/audit-sinks/rekor.md`.
#[derive(Debug)]
pub struct RekorSink {
    name: SinkName,
    /// Rekor config (endpoint, etc.). Held for future live integration.
    _config: RekorConfig,
    /// In-memory mock: keyed by RecordId → (SinkId, SignedRecord).
    store: Mutex<HashMap<RecordId, (SinkId, SignedRecord)>>,
    /// Monotonic counter used to mint stable SinkIds in the mock.
    counter: Mutex<u64>,
}

impl RekorSink {
    /// Constructs a `RekorSink` with the given config.
    ///
    /// # Errors
    ///
    /// Returns [`IdError`] when `name` fails `SinkName::try_new`.
    pub fn new(config: RekorConfig) -> Result<Self, IdError> {
        Ok(Self {
            name: SinkName::try_new("rekor")?,
            _config: config,
            store: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        })
    }

    /// Constructs a `RekorSink` with default config (public Rekor instance).
    pub fn with_defaults() -> Result<Self, IdError> {
        Self::new(RekorConfig::default())
    }
}

#[async_trait]
impl LedgerSink for RekorSink {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
        // Mint a stable SinkId: `rekor-log-<counter>` (mock shape).
        // In a live integration this would be the Rekor log index returned
        // by `POST /api/v1/log/entries`.
        let index = {
            let mut ctr = self.counter.lock().unwrap_or_else(|p| p.into_inner());
            let v = *ctr;
            *ctr += 1;
            v
        };
        let sink_id =
            SinkId::try_new(format!("rekor-log-{index}")).map_err(|e| SinkError::Internal {
                message: RedactedString::from_trusted(e.to_string()),
            })?;
        let mut store = self.store.lock().unwrap_or_else(|p| p.into_inner());
        store.insert(record.record_id.clone(), (sink_id.clone(), record.clone()));
        Ok(SinkReceipt {
            sink: self.name.clone(),
            sink_id,
            anchored_at: record.ts.clone(),
            // In a live integration the inclusion proof would be the Rekor
            // Merkle proof returned alongside the log entry.
            inclusion_proof: None,
        })
    }

    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
        let store = self.store.lock().unwrap_or_else(|p| p.into_inner());
        store
            .get(id)
            .map(|(_, r)| r.clone())
            .ok_or_else(|| SinkError::NotFound {
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
    async fn rekor_sink_append_verify_roundtrip_stubbed() {
        let sink = RekorSink::with_defaults().expect("valid config");
        assert_eq!(sink.name(), "rekor");
        let record = sample_record("01JZ00000000000000000000R1", 0);
        let receipt = sink.append(&record).await.expect("append");
        assert_eq!(receipt.sink.as_str(), "rekor");
        assert!(
            receipt.sink_id.as_str().starts_with("rekor-log-"),
            "sink_id should be rekor-log-<N>"
        );
        let fetched = sink.verify_at(&record.record_id).await.expect("verify_at");
        assert_eq!(fetched, record);
    }

    #[tokio::test]
    async fn rekor_sink_verify_missing_returns_not_found() {
        let sink = RekorSink::with_defaults().expect("valid config");
        let result = sink
            .verify_at(&RecordId::try_new("01JZ00000000000000000000R2").unwrap())
            .await;
        assert!(matches!(result, Err(SinkError::NotFound { .. })));
    }
}
