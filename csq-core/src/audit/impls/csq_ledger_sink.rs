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
//!   and returns a [`SinkReceipt`](crate::audit::types::SinkReceipt) carrying the log index as `sink_id` and a
//!   structured [`crate::audit::types::LedgerInclusionProof`] JSON
//!   (`{leaf_index, tree_size, audit_path}`) as the `inclusion_proof` — or
//!   `None` when the server returned no checkpoint (honest-null, #1060 redteam).
//!   The blocking `reqwest` transport is invoked inside `spawn_blocking`.
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
//! csq-ledger server's checkpoint signing key. `append` decodes
//! `{inclusion_proof, log_index}` plus `checkpoint_at_submit.tree_size` from the
//! submit response (only to SIZE the structured inclusion proof — #1060; the
//! checkpoint root + signature are NOT verified), and `verify_at` decodes only
//! the returned record. There is no configured expected `signed_by_key_id` to
//! compare against in M10. CONSEQUENCE: a man-in-the-middle (or a swapped server
//! behind the configured URL) that returns a validly-shaped response is NOT
//! detected by this sink. Operators MUST pin the server out-of-band — terminate
//! the connection with TLS to a known host (the recommended deployment fronts
//! the server with a reverse proxy / mTLS per spec 17 §17.9), and/or verify the
//! `GET /v1/checkpoint` `signed_by_key_id` against the expected server key id
//! through a separate trusted channel. Configurable in-sink key pinning is
//! Phase B (would add an `expected_key_id` field to [`CsqLedgerConfig`](crate::audit::impls::csq_ledger_sink::CsqLedgerConfig) and a
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
///
/// `Arc` (not `Box`) so `append`/`verify_at` can clone it into
/// `tokio::task::spawn_blocking` — the production transport is the BLOCKING
/// `reqwest` client and must not run on a tokio worker thread (#1060 redteam B1).
type Transport = std::sync::Arc<
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
            std::sync::Arc::new(move |method, path, body| live_request(&base, method, &path, body));
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
        let transport: Transport = std::sync::Arc::new(move |method, path, body| match method {
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
        // #1060 redteam B1 — the production transport is a BLOCKING `reqwest`
        // client; run it on a blocking pool so it never stalls a tokio worker
        // thread (the daemon serves every IPC route on that pool).
        let transport = std::sync::Arc::clone(&self.transport);
        let (status, resp) =
            tokio::task::spawn_blocking(move || transport(HttpMethod::Post, path, Some(body)))
                .await
                .map_err(|_join| SinkError::Internal {
                    message: RedactedString::from_trusted(
                        "csq-ledger transport task failed".to_string(),
                    ),
                })?
                .map_err(|e| SinkError::Unreachable {
                    message: RedactedString::from_untrusted(e),
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
        // #1060 — project the wire response into a STRUCTURED
        // `{leaf_index, tree_size, audit_path}` proof so the daemon anchor
        // handler surfaces a real `AnchorPayload.inclusion_proof` instead of a
        // bare hash array. `leaf_index` = the log index; `tree_size` comes from
        // the checkpoint-at-submit summary; `audit_path` = the sibling hashes.
        //
        // #1060 redteam F1 — HONEST-NULL, never fabricate: when the server
        // returned no checkpoint (`tree_size` 0/absent) there is no verifiable
        // tree to prove inclusion in. Emit `None` so the daemon boundary
        // surfaces `inclusion_proof: null` rather than a structurally-impossible
        // `{leaf_index: N, tree_size: 0}` proof (0 is a concrete, wrong claim —
        // "empty tree containing leaf N" — not "absent"). The daemon's
        // structural-soundness gate (`project_inclusion_proof`) is the backstop.
        let tree_size = parsed
            .checkpoint_at_submit
            .as_ref()
            .map(|c| c.tree_size)
            .unwrap_or(0);
        let inclusion_proof = if tree_size == 0 {
            None
        } else {
            let proof = crate::audit::types::LedgerInclusionProof {
                leaf_index: parsed.log_index,
                tree_size,
                audit_path: parsed.inclusion_proof,
            };
            Some(serde_json::to_string(&proof).unwrap_or_default())
        };
        Ok(SinkReceipt {
            sink: self.name.clone(),
            sink_id,
            anchored_at: record.ts.clone(),
            inclusion_proof,
        })
    }

    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
        let path = format!("/v1/log/entries/{}", id.as_str());
        // #1060 redteam B1 — blocking transport off the tokio worker pool.
        let transport = std::sync::Arc::clone(&self.transport);
        let (status, resp) =
            tokio::task::spawn_blocking(move || transport(HttpMethod::Get, path, None))
                .await
                .map_err(|_join| SinkError::Internal {
                    message: RedactedString::from_trusted(
                        "csq-ledger transport task failed".to_string(),
                    ),
                })?
                .map_err(|e| SinkError::Unreachable {
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
    /// The checkpoint the server had at submit time. Optional: the daemon does
    /// NOT pin the checkpoint signing key (M10 limitation, see module note), and
    /// only `tree_size` is consumed — to size the structured inclusion proof
    /// (#1060). Absent → `tree_size` defaults to 0 (honest, never fabricated).
    #[serde(default)]
    checkpoint_at_submit: Option<CheckpointSummary>,
}

/// Minimal checkpoint summary — only the field the structured inclusion proof
/// needs. The full checkpoint (root hash, signature, key id) is intentionally
/// not decoded here (M10 does not pin the server key; see module note).
#[derive(serde::Deserialize)]
struct CheckpointSummary {
    #[serde(default)]
    tree_size: u64,
}

/// Entry response shape (mirror of `csq-ledger`'s `EntryResponse`).
#[derive(serde::Deserialize)]
struct EntryResponse {
    record: SignedRecord,
}

/// Live `reqwest` transport used in production. This is a BLOCKING call; the
/// `LedgerSink` impls (`append` / `verify_at`) invoke it inside
/// `tokio::task::spawn_blocking` so it never runs on a tokio worker thread
/// (#1060 redteam B1).
///
/// The `base` URL is the base; `path` is appended.
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
            verification_level: None,
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

    /// `test csq_ledger_sink_append_returns_structured_inclusion_proof`
    ///
    /// #1060 — the receipt's `inclusion_proof` string MUST parse as a structured
    /// [`crate::audit::types::LedgerInclusionProof`] with `leaf_index` = the log
    /// index, `tree_size` from the checkpoint summary, and `audit_path` = the
    /// returned sibling hashes. The in-memory mock's first POST returns
    /// `log_index=0`, `checkpoint_at_submit.tree_size=1`, empty proof.
    #[tokio::test]
    async fn csq_ledger_sink_append_returns_structured_inclusion_proof() {
        let sink = CsqLedgerSink::mock_in_memory();
        let record = sample("01JZ00000000000000000000Z2");
        let receipt = sink.append(&record).await.expect("append");
        let proof_str = receipt
            .inclusion_proof
            .expect("csq-ledger receipt carries a structured inclusion_proof");
        let proof: crate::audit::types::LedgerInclusionProof =
            serde_json::from_str(&proof_str).expect("parses as LedgerInclusionProof");
        assert_eq!(proof.leaf_index, 0, "first mock append → leaf_index 0");
        assert_eq!(
            proof.tree_size, 1,
            "checkpoint_at_submit.tree_size = log_index + 1 = 1"
        );
        assert!(
            proof.audit_path.is_empty(),
            "mock returns an empty audit_path"
        );
    }

    /// `test csq_ledger_sink_append_honest_null_when_no_checkpoint`
    ///
    /// #1060 redteam F1 — when the server response omits `checkpoint_at_submit`
    /// (no `tree_size`), the sink MUST emit `inclusion_proof: None` rather than a
    /// structurally-impossible `{leaf_index: N, tree_size: 0}` proof.
    #[tokio::test]
    async fn csq_ledger_sink_append_honest_null_when_no_checkpoint() {
        let transport: Transport = std::sync::Arc::new(|_method, _path, _body| {
            Ok((200, br#"{"inclusion_proof":[],"log_index":5}"#.to_vec()))
        });
        let sink =
            CsqLedgerSink::with_mock_transport(CsqLedgerConfig::default(), transport).unwrap();
        let record = sample("01JZ00000000000000000000Z3");
        let receipt = sink.append(&record).await.expect("append");
        assert!(
            receipt.inclusion_proof.is_none(),
            "no checkpoint → honest null, not a tree_size:0 proof"
        );
        // sink_id still carries the log index.
        assert_eq!(receipt.sink_id.as_str(), "csq-ledger-5");
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
