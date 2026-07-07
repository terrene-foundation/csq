//! `CustomerBodyStoreSink` — M3 (T3.5) `LedgerSink` reference impl that POSTs
//! the full `SignedRecord` to an operator-configured HTTP endpoint.
//!
//! Gated: `--features customer-body-store-sink`. NOT on the default csq-core code
//! path (PRIMARY DIRECTIVE: csq-core stays local-only by default).
//!
//! # Why this sink exists — operator residency / sovereignty control
//!
//! The other catalog sinks anchor to a SPECIFIC substrate (Sigstore Rekor, AWS
//! S3, Azure, GCP) or to the Foundation-owned csq-ledger transparency log. The
//! customer body store is the **sovereignty** control: the operator names their
//! OWN endpoint, and every signed record is POSTed there so the full record
//! bodies stay inside the customer's infrastructure — they never transit a
//! Foundation- or vendor-owned service. This is the enterprise data-residency
//! answer ("our audit records never leave our network").
//!
//! # Wire protocol
//!
//! - `append(record)` → `POST <url>` with the `SignedRecord` JSON body and (when
//!   configured) an `Authorization: Bearer <auth_token>` header. Any `2xx` is
//!   success; the [`SinkReceipt`]'s `sink_id` is derived deterministically from
//!   the record id (`customer-body-store-<record_id>`) — a generic endpoint
//!   returns no log index, and the receipt references the record we stored.
//! - `verify_at(id)` → `GET <url>/<id>` (same Bearer header); the endpoint echoes
//!   the stored `SignedRecord` JSON, which the daemon compares against its local
//!   canonical hash (a mismatch is `SinkError::Drift` at the caller). `404` →
//!   `SinkError::NotFound`.
//! - `name()` → `"customer-body-store"`.
//!
//! # Secret handling (`security.md` §2)
//!
//! The bearer token is held as a `secrecy::SecretString` (masked `Debug`,
//! zeroize-on-drop) and exposed ONLY transiently when building each request's
//! header. Every error path wraps its message in [`RedactedString`] (the
//! `from_untrusted` constructor scrubs `sk-ant-*` / long-hex patterns), so a
//! transport error that echoes a credential cannot reach a log or an IPC payload.
//! The token is never serialized into a record, a receipt, or an error.
//!
//! # Conformance
//!
//! Passes M07's `sink_conformance.rs` harness under this feature via an in-memory
//! mock transport (the harness has no live endpoint). The transport is
//! injectable: production uses `reqwest`, tests inject a closure — mirroring
//! [`crate::audit::impls::csq_ledger_sink::CsqLedgerSink`].

// `HashMap` + `Mutex` are used only by the mock_in_memory helper, compiled only
// under `test` / `test-utils`. Gate the imports to match so
// `cargo clippy --features customer-body-store-sink` (no test-utils) stays clean.
#[cfg(any(test, feature = "test-utils"))]
use std::collections::HashMap;
#[cfg(any(test, feature = "test-utils"))]
use std::sync::Mutex;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

use crate::audit::traits::LedgerSink;
use crate::audit::types::{
    IdError, RecordId, RedactedString, SignedRecord, SinkError, SinkId, SinkName, SinkReceipt,
};

/// Configuration for the customer body-store sink.
///
/// `#[non_exhaustive]` so future hardening (e.g. a custom path template, a
/// client-cert handle) can be added without breaking the public constructor.
/// Deliberately NOT `Clone`/`PartialEq`: the `SecretString` token must not be
/// duplicated or compared in the clear.
#[derive(Debug)]
#[non_exhaustive]
pub struct CustomerBodyStoreConfig {
    /// Operator endpoint base URL (e.g. `https://audit.corp.internal/records`).
    /// No trailing slash — `append` POSTs to it directly; `verify_at` appends
    /// `/<record_id>`.
    pub url: String,
    /// Optional bearer token sent as `Authorization: Bearer <token>`. Held
    /// masked + zeroize-on-drop; exposed only when building a request header.
    pub auth_token: Option<SecretString>,
}

impl Default for CustomerBodyStoreConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8080".to_string(),
            auth_token: None,
        }
    }
}

/// HTTP method for the [`Transport`] closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// `POST <url>`.
    Post,
    /// `GET <url>/<id>`.
    Get,
}

/// A transport for the sink's HTTP calls. Production wires `reqwest`; tests
/// inject an in-memory mock so the conformance harness runs without a live
/// endpoint. Returns `(status_code, body_bytes)` or a transport error string.
type Transport = Box<
    dyn Fn(HttpMethod, String, Option<Vec<u8>>) -> Result<(u16, Vec<u8>), String> + Send + Sync,
>;

/// Operator-endpoint residency sink.
pub struct CustomerBodyStoreSink {
    name: SinkName,
    /// Base URL — retained for `Debug` + receipts. NOT a secret.
    url: String,
    transport: Transport,
}

impl std::fmt::Debug for CustomerBodyStoreSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomerBodyStoreSink")
            .field("name", &self.name)
            .field("url", &self.url)
            .field("transport", &"<fn>")
            .finish()
    }
}

impl CustomerBodyStoreSink {
    /// Constructs a `CustomerBodyStoreSink` with a live `reqwest` transport.
    ///
    /// The bearer token (if any) is MOVED into the transport closure and exposed
    /// only per-request, so it is never copied into a long-lived `String`.
    ///
    /// # Errors
    ///
    /// Returns [`IdError`] if the fixed name `"customer-body-store"` fails
    /// validation (it cannot, in practice — kept for API symmetry).
    pub fn new(config: CustomerBodyStoreConfig) -> Result<Self, IdError> {
        let url = config.url.clone();
        let base = config.url;
        let token = config.auth_token;
        let transport: Transport = Box::new(move |method, path, body| {
            live_request(&base, token.as_ref(), method, &path, body)
        });
        Ok(Self {
            name: SinkName::try_new("customer-body-store")?,
            url,
            transport,
        })
    }

    /// Constructs a sink with an injected mock transport (conformance + unit
    /// tests; no live endpoint required).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_mock_transport(url: String, transport: Transport) -> Result<Self, IdError> {
        Ok(Self {
            name: SinkName::try_new("customer-body-store")?,
            url,
            transport,
        })
    }

    /// Builds an in-memory mock transport backed by a shared record store — the
    /// conformance-harness substrate. POST stores the record (keyed by its id);
    /// GET returns the stored record JSON; an unknown id GETs `404`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn mock_in_memory() -> Self {
        let store: std::sync::Arc<Mutex<HashMap<String, Vec<u8>>>> =
            std::sync::Arc::new(Mutex::new(HashMap::new()));
        let transport: Transport = Box::new(move |method, path, body| match method {
            HttpMethod::Post => {
                let body = body.ok_or_else(|| "missing POST body".to_string())?;
                let record: SignedRecord =
                    serde_json::from_slice(&body).map_err(|e| format!("bad record: {e}"))?;
                store
                    .lock()
                    .unwrap()
                    .insert(record.record_id.as_str().to_string(), body);
                // A residency endpoint returns 2xx with no meaningful body.
                Ok((200, Vec::new()))
            }
            HttpMethod::Get => {
                // path is `/<record_id>`.
                let id = path.rsplit('/').next().unwrap_or("").to_string();
                match store.lock().unwrap().get(&id) {
                    Some(bytes) => Ok((200, bytes.clone())),
                    None => Ok((404, br#"{"error":"not_found"}"#.to_vec())),
                }
            }
        });
        Self {
            name: SinkName::try_new("customer-body-store").expect("static name valid"),
            url: CustomerBodyStoreConfig::default().url,
            transport,
        }
    }
}

#[async_trait]
impl LedgerSink for CustomerBodyStoreSink {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    async fn append(&self, record: &SignedRecord) -> Result<SinkReceipt, SinkError> {
        let body = serde_json::to_vec(record).map_err(|e| SinkError::Internal {
            message: RedactedString::from_untrusted(e.to_string()),
        })?;
        // POST to the bare endpoint (empty path → base URL).
        let (status, _resp) = (self.transport)(HttpMethod::Post, String::new(), Some(body))
            .map_err(|e| SinkError::Unreachable {
                message: RedactedString::from_untrusted(e),
            })?;
        if !(200..300).contains(&status) {
            return Err(SinkError::Rejected {
                message: RedactedString::from_trusted(format!(
                    "customer body store returned HTTP {status}"
                )),
            });
        }
        // A generic residency endpoint returns no log index; the receipt
        // references the record we stored, keyed by its id.
        let sink_id = SinkId::try_new(format!("customer-body-store-{}", record.record_id.as_str()))
            .map_err(|e| SinkError::Internal {
                message: RedactedString::from_trusted(e.to_string()),
            })?;
        Ok(SinkReceipt {
            sink: self.name.clone(),
            sink_id,
            anchored_at: record.ts.clone(),
            // No inclusion proof from a generic residency endpoint.
            inclusion_proof: None,
        })
    }

    async fn verify_at(&self, id: &RecordId) -> Result<SignedRecord, SinkError> {
        let path = format!("/{}", id.as_str());
        let (status, resp) =
            (self.transport)(HttpMethod::Get, path, None).map_err(|e| SinkError::Unreachable {
                message: RedactedString::from_untrusted(e),
            })?;
        if status == 404 {
            return Err(SinkError::NotFound {
                record_id: id.clone(),
            });
        }
        if !(200..300).contains(&status) {
            return Err(SinkError::Rejected {
                message: RedactedString::from_trusted(format!(
                    "customer body store returned HTTP {status}"
                )),
            });
        }
        // The endpoint echoes the bare stored record JSON.
        let record: SignedRecord =
            serde_json::from_slice(&resp).map_err(|e| SinkError::Internal {
                message: RedactedString::from_untrusted(e.to_string()),
            })?;
        Ok(record)
    }
}

/// Live `reqwest` transport used in production. Uses the blocking client inside
/// the async trait body's call (the `LedgerSink::append` future is awaited on the
/// daemon's sink path, which already offloads blocking work). `token` is exposed
/// only here, transiently, to build the `Authorization` header.
fn live_request(
    base: &str,
    token: Option<&SecretString>,
    method: HttpMethod,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(u16, Vec<u8>), String> {
    let url = format!("{base}{path}");
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("client build failed: {e}"))?;
    let mut req = match method {
        HttpMethod::Post => client
            .post(&url)
            .header("content-type", "application/json")
            .body(body.unwrap_or_default()),
        HttpMethod::Get => client.get(&url),
    };
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {}", token.expose_secret()));
    }
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

    /// `test customer_body_store_sink_name`
    #[test]
    fn customer_body_store_sink_name() {
        let sink = CustomerBodyStoreSink::mock_in_memory();
        assert_eq!(sink.name(), "customer-body-store");
    }

    /// `test customer_body_store_append_verify_roundtrip_mock`
    #[tokio::test]
    async fn customer_body_store_append_verify_roundtrip_mock() {
        let sink = CustomerBodyStoreSink::mock_in_memory();
        let record = sample("01JZ00000000000000000000Z1");
        let receipt = sink.append(&record).await.expect("append");
        assert_eq!(receipt.sink.as_str(), "customer-body-store");
        assert_eq!(
            receipt.sink_id.as_str(),
            "customer-body-store-01JZ00000000000000000000Z1"
        );
        // A residency endpoint yields no inclusion proof.
        assert!(receipt.inclusion_proof.is_none());
        let fetched = sink.verify_at(&record.record_id).await.expect("verify");
        assert_eq!(fetched, record);
    }

    /// `test customer_body_store_verify_missing_returns_not_found`
    #[tokio::test]
    async fn customer_body_store_verify_missing_returns_not_found() {
        let sink = CustomerBodyStoreSink::mock_in_memory();
        let result = sink
            .verify_at(&RecordId::try_new("01JZ00000000000000000000Z9").unwrap())
            .await;
        assert!(matches!(result, Err(SinkError::NotFound { .. })));
    }

    /// `test customer_body_store_non_2xx_is_rejected`
    #[tokio::test]
    async fn customer_body_store_non_2xx_is_rejected() {
        // A transport that returns 500 on POST → `SinkError::Rejected`, NOT a
        // panic and NOT a silent success.
        let transport: Transport =
            Box::new(|_method, _path, _body| Ok((500, b"upstream error".to_vec())));
        let sink =
            CustomerBodyStoreSink::with_mock_transport("http://x".to_string(), transport).unwrap();
        let record = sample("01JZ00000000000000000000Z2");
        let result = sink.append(&record).await;
        assert!(matches!(result, Err(SinkError::Rejected { .. })));
    }

    /// `test customer_body_store_transport_error_is_unreachable`
    #[tokio::test]
    async fn customer_body_store_transport_error_is_unreachable() {
        // A transport-layer failure (connection refused, DNS, etc.) →
        // `SinkError::Unreachable`, message redacted.
        let transport: Transport =
            Box::new(|_method, _path, _body| Err("connection refused".to_string()));
        let sink =
            CustomerBodyStoreSink::with_mock_transport("http://x".to_string(), transport).unwrap();
        let record = sample("01JZ00000000000000000000Z3");
        let result = sink.append(&record).await;
        assert!(matches!(result, Err(SinkError::Unreachable { .. })));
    }

    /// `test customer_body_store_debug_redacts_token`
    #[test]
    fn customer_body_store_debug_redacts_token() {
        // The bearer token must never appear in the config's Debug output
        // (secrecy masks it) — a structural guard against accidental logging.
        let cfg = CustomerBodyStoreConfig {
            url: "https://audit.corp.internal/records".to_string(),
            auth_token: Some(SecretString::from("super-secret-token-value".to_string())),
        };
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("super-secret-token-value"),
            "Debug leaked the bearer token: {dbg}"
        );
    }
}
