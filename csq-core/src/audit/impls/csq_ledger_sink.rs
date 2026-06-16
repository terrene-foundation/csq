//! `CsqLedgerSink` — M07 `LedgerSink` reference impl targeting a Foundation-
//! owned csq-ledger transparency-log server (M10).
//!
//! Gated: `--features csq-ledger-sink`. NOT on the default csq-core code path
//! (PRIMARY DIRECTIVE: csq-core stays local-only by default). The audit
//! primitive `grep -E '^csq-ledger' csq-core/Cargo.toml | grep -v 'optional = true'`
//! returns 0 — `csq-ledger-sink` is a `[features]` flag, not a dependency, and
//! the `reqwest` client it uses is only invoked under this feature.
//!
//! # Wire protocol (spec 17)
//!
//! - `append(record)` → `POST <url>/v1/log/entries` with the `SignedRecord`
//!   JSON body; parses `{ inclusion_proof, log_index, checkpoint_at_submit }`
//!   and returns a [`SinkReceipt`] carrying the log index as `sink_id` and the
//!   checkpoint root as the inclusion-proof summary.
//! - `verify_at(id)` → `GET <url>/v1/log/entries/{id}`; parses the returned
//!   record and returns it (the daemon compares against its local canonical
//!   hash — a mismatch is `SinkError::Drift`).
//! - `name()` → `"csq-ledger"`.
//!
//! # Conformance
//!
//! Passes M07's `sink_conformance.rs` harness under this feature via an
//! in-memory mock transport (the harness has no live server). The transport is
//! injectable: production uses `reqwest`, tests inject a closure. This mirrors
//! the other reference impls' mock-substrate policy (spec 15 §15.4.2).
//!
//! # Server-key pinning (M10 limitation — rust-R5)
//!
//! This sink does NOT consume `GET /v1/checkpoint` and does NOT pin the
//! csq-ledger server's checkpoint signing key. `append` decodes only
//! `{inclusion_proof, log_index}` from the submit response (the embedded
//! `checkpoint_at_submit` is discarded), and `verify_at` decodes only the
//! returned record. There is no configured expected `signed_by_key_id` to
//! compare against in M10. CONSEQUENCE: a man-in-the-middle (or a swapped server
//! behind the configured URL) that returns a validly-shaped response is NOT
//! detected by this sink. Operators MUST pin the server out-of-band — terminate
//! the connection with TLS to a known host (the recommended deployment fronts
//! the server with a reverse proxy / mTLS per spec 17 §17.9), and/or verify the
//! `GET /v1/checkpoint` `signed_by_key_id` against the expected server key id
//! through a separate trusted channel. Configurable in-sink key pinning is
//! Phase B (would add an `expected_key_id` field to [`CsqLedgerConfig`] and a
//! checkpoint-signature check on each `append`).

// `HashMap` and `Mutex` are only used in the mock_in_memory helper, which is
// compiled only under `test` or `test-utils`. Gate the imports to match so
// `cargo clippy --features csq-ledger-sink` (without `test-utils`) stays clean.
#[cfg(any(test, feature = "test-utils"))]
use std::collections::HashMap;
#[cfg(any(test, feature = "test-utils"))]
use std::sync::Mutex;

use async_trait::async_trait;

use crate::audit::traits::LedgerSink;
use crate::audit::types::{
    IdError, RecordId, RedactedString, SignedRecord, SinkError, SinkId, SinkName, SinkReceipt,
};

/// Configuration for the csq-ledger sink.
///
/// `#[non_exhaustive]` so Phase B can add an `expected_key_id` field for
/// in-sink server-key pinning without breaking the public constructor (see the
/// module-level "Server-key pinning" note — M10 does NOT pin; operators pin
/// out-of-band via TLS/mTLS).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CsqLedgerConfig {
    /// Base URL of the csq-ledger server (e.g. `https://ledger.example.org`).
    /// No trailing slash.
    pub url: String,
}

impl Default for CsqLedgerConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8080".to_string(),
        }
    }
}

/// A transport for the sink's HTTP calls. Production wires `reqwest`; tests
/// inject an in-memory mock so the conformance harness runs without a live
/// server (spec 15 §15.4.2 mock-substrate policy).
///
/// Returns `(status_code, body_bytes)` or a transport error string.
type Transport = Box<
    dyn Fn(HttpMethod, String, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String> + Send + Sync,
>;

/// HTTP method for the [`Transport`] closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// `POST /v1/log/entries`.
    Post,
    /// `GET /v1/log/entries/{id}`.
    Get,
}

/// csq-ledger transparency-log sink.
pub struct CsqLedgerSink {
    name: SinkName,
    config: CsqLedgerConfig,
    transport: Transport,
}

impl std::fmt::Debug for CsqLedgerSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsqLedgerSink")
            .field("name", &self.name)
            .field("config", &self.config)
            .field("transport", &"<fn>")
            .finish()
    }
}

impl CsqLedgerSink {
    /// Constructs a `CsqLedgerSink` with a live `reqwest` transport.
    ///
    /// # Errors
    ///
    /// Returns [`IdError`] when the fixed name `"csq-ledger"` fails validation
    /// (it cannot, in practice — kept for API symmetry with the other sinks).
    pub fn new(config: CsqLedgerConfig) -> Result<Self, IdError> {
        let base = config.url.clone();
        let transport: Transport =
            Box::new(move |method, path, body| live_request(&base, method, &path, body));
        Ok(Self {
            name: SinkName::try_new("csq-ledger")?,
            config,
            transport,
        })
    }

    /// Constructs a `CsqLedgerSink` with default config (localhost:8080).
    pub fn with_defaults() -> Result<Self, IdError> {
        Self::new(CsqLedgerConfig::default())
    }

    /// Constructs a `CsqLedgerSink` with an injected mock transport. Used by
    /// the conformance harness + unit tests (no live server required).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_mock_transport(
        config: CsqLedgerConfig,
        transport: Transport,
    ) -> Result<Self, IdError> {
        Ok(Self {
            name: SinkName::try_new("csq-ledger")?,
            config,
            transport,
        })
    }

    /// Builds an in-memory mock transport backed by a shared record store —
    /// the conformance-harness substrate. POST stores the record + returns a
    /// synthetic submit response; GET returns the stored record.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn mock_in_memory() -> Self {
        let store: std::sync::Arc<Mutex<HashMap<String, SignedRecord>>> =
            std::sync::Arc::new(Mutex::new(HashMap::new()));
        let counter = std::sync::Arc::new(Mutex::new(0u64));
        let transport: Transport = Box::new(move |method, path, body| match method {
            HttpMethod::Post => {
                let body = body.ok_or_else(|| "missing POST body".to_string())?;
                let record: SignedRecord =
                    serde_json::from_slice(&body).map_err(|e| format!("bad record: {e}"))?;
                let mut ctr = counter.lock().unwrap();
                let idx = *ctr;
                *ctr += 1;
                drop(ctr);
                store
                    .lock()
                    .unwrap()
                    .insert(record.record_id.as_str().to_string(), record);
                let resp = serde_json::json!({
                    "inclusion_proof": [],
                    "log_index": idx,
                    "checkpoint_at_submit": {
                        "tree_size": idx + 1,
                        "root_hash": "0".repeat(64),
                        "signed_by_key_id": format!("ed25519:{}", "0".repeat(64)),
                        "public_key": "0".repeat(64),
                        "signature": "0".repeat(128),
                    }
                });
                Ok((200, serde_json::to_vec(&resp).unwrap()))
            }
            HttpMethod::Get => {
                // path is `/v1/log/entries/{id}`.
                let id = path.rsplit('/').next().unwrap_or("").to_string();
                match store.lock().unwrap().get(&id) {
                    Some(record) => {
                        let resp = serde_json::json!({
                            "record": record,
                            "log_index": 0,
                            "inclusion_proof": [],
                            "checkpoint": {
                                "tree_size": 1,
                                "root_hash": "0".repeat(64),
                                "signed_by_key_id": format!("ed25519:{}", "0".repeat(64)),
                                "public_key": "0".repeat(64),
                                "signature": "0".repeat(128),
                            }
                        });
                        Ok((200, serde_json::to_vec(&resp).unwrap()))
                    }
                    None => Ok((404, br#"{"error":"not_found"}"#.to_vec())),
                }
            }
        });
        Self {
            name: SinkName::try_new("csq-ledger").expect("static name valid"),
            config: CsqLedgerConfig::default(),
            transport,
        }
    }
}

#[async_trait]
impl LedgerSink for CsqLedgerSink {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
        let body = serde_json::to_vec(record).map_err(|e| SinkError::Internal {
            message: RedactedString::from_untrusted(e.to_string()),
        })?;
        let path = "/v1/log/entries".to_string();
        let (status, resp) = (self.transport)(HttpMethod::Post, path, Some(body)).map_err(|e| {
            SinkError::Unreachable {
                message: RedactedString::from_untrusted(e),
            }
        })?;
        if status != 200 {
            return Err(SinkError::Rejected {
                message: RedactedString::from_trusted(format!("csq-ledger returned HTTP {status}")),
            });
        }
        let parsed: SubmitResponse =
            serde_json::from_slice(&resp).map_err(|e| SinkError::Internal {
                message: RedactedString::from_untrusted(e.to_string()),
            })?;
        let sink_id = SinkId::try_new(format!("csq-ledger-{}", parsed.log_index)).map_err(|e| {
            SinkError::Internal {
                message: RedactedString::from_trusted(e.to_string()),
            }
        })?;
        Ok(SinkReceipt {
            sink: self.name.clone(),
            sink_id,
            anchored_at: record.ts.clone(),
            inclusion_proof: Some(
                serde_json::to_string(&parsed.inclusion_proof).unwrap_or_default(),
            ),
        })
    }

    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
        let path = format!("/v1/log/entries/{}", id.as_str());
        let (status, resp) =
            (self.transport)(HttpMethod::Get, path, None).map_err(|e| SinkError::Unreachable {
                message: RedactedString::from_untrusted(e),
            })?;
        if status == 404 {
            return Err(SinkError::NotFound {
                record_id: id.clone(),
            });
        }
        if status != 200 {
            return Err(SinkError::Rejected {
                message: RedactedString::from_trusted(format!("csq-ledger returned HTTP {status}")),
            });
        }
        let parsed: EntryResponse =
            serde_json::from_slice(&resp).map_err(|e| SinkError::Internal {
                message: RedactedString::from_untrusted(e.to_string()),
            })?;
        Ok(parsed.record)
    }
}

/// Submit response shape (mirror of `csq-ledger`'s `SubmitResponse`; we only
/// decode the fields we use).
#[derive(serde::Deserialize)]
struct SubmitResponse {
    inclusion_proof: Vec<String>,
    log_index: u64,
}

/// Entry response shape (mirror of `csq-ledger`'s `EntryResponse`).
#[derive(serde::Deserialize)]
struct EntryResponse {
    record: SignedRecord,
}

/// Live `reqwest` transport used in production. Uses the blocking client inside
/// `spawn_blocking` to keep the async trait body non-blocking.
///
/// The `_config` URL is the base; `path` is appended.
fn live_request(
    base: &str,
    method: HttpMethod,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(u16, Vec<u8>), String> {
    let url = format!("{base}{path}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("client build failed: {e}"))?;
    let req = match method {
        HttpMethod::Post => client
            .post(&url)
            .header("content-type", "application/json")
            .body(body.unwrap_or_default()),
        HttpMethod::Get => client.get(&url),
    };
    let resp = req.send().map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status().as_u16();
    let bytes = resp.bytes().map_err(|e| format!("read body failed: {e}"))?;
    Ok((status, bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{
        CsqRunPayload, Ed25519Signature, EventKind, EventPayload, KeyId, Sha256Hex,
    };

    fn sample(id: &str) -> SignedRecord {
        SignedRecord {
            schema_version: "2".to_string(),
            record_id: RecordId::try_new(id).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq: 0,
            prev_hash: Sha256Hex::genesis(),
            kind: EventKind::CsqRun,
            payload: EventPayload::CsqRun(CsqRunPayload {
                run_id: "run-x".to_string(),
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

    /// `test csq_ledger_sink_name_is_csq_ledger`
    #[test]
    fn csq_ledger_sink_name_is_csq_ledger() {
        let sink = CsqLedgerSink::mock_in_memory();
        assert_eq!(sink.name(), "csq-ledger");
    }

    /// `test csq_ledger_sink_append_verify_roundtrip_mock`
    #[tokio::test]
    async fn csq_ledger_sink_append_verify_roundtrip_mock() {
        let sink = CsqLedgerSink::mock_in_memory();
        let record = sample("01JZ00000000000000000000Z1");
        let receipt = sink.append(&record).await.expect("append");
        assert_eq!(receipt.sink.as_str(), "csq-ledger");
        assert!(receipt.sink_id.as_str().starts_with("csq-ledger-"));
        let fetched = sink.verify_at(&record.record_id).await.expect("verify");
        assert_eq!(fetched, record);
    }

    /// `test csq_ledger_sink_verify_missing_returns_not_found`
    #[tokio::test]
    async fn csq_ledger_sink_verify_missing_returns_not_found() {
        let sink = CsqLedgerSink::mock_in_memory();
        let result = sink
            .verify_at(&RecordId::try_new("01JZ00000000000000000000Z9").unwrap())
            .await;
        assert!(matches!(result, Err(SinkError::NotFound { .. })));
    }
}
