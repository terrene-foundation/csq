//! Session-directive wire types: `csq.directive.v1` (input) and the receipt,
//! receipts and inbox payloads (`csq.directive_receipt.v1`,
//! `csq.directive_receipts.v1`, `csq.directive_inbox.v1`).
//!
//! This module owns only the public serialized shape. Validation, the store and the
//! lifecycle live in the app (`csq-core::sessions::directives`). Optional fields are
//! ABSENT on the wire, never `null` (spec 30 §5). Directive text is untrusted data
//! addressed to an agent; csq never executes it.

use serde::{Deserialize, Serialize};

/// Which session a directive addresses: identity is `(pid, started_at)` because pids
/// are reused (contract INV-31-01).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirectiveTarget {
    /// OS process id of the target session.
    pub pid: u32,
    /// OS process start time, unix seconds.
    pub started_at: u64,
    /// Host name the issuer believes the session lives on.
    pub host: String,
}

impl DirectiveTarget {
    /// Build a target.
    #[must_use]
    pub fn new(pid: u32, started_at: u64, host: impl Into<String>) -> Self {
        Self {
            pid,
            started_at,
            host: host.into(),
        }
    }
}

/// The measurement that motivated a directive. `source` is displayed verbatim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirectiveWhy {
    /// Metric name, e.g. `session_cpu_cores`.
    pub metric: String,
    /// Measured value.
    pub value: f64,
    /// Threshold the value crossed.
    pub threshold: f64,
    /// Unix seconds the value was measured.
    pub measured_at: u64,
    /// The exact command that produced `value`.
    pub source: String,
}

impl DirectiveWhy {
    /// Build a measurement record.
    #[must_use]
    pub fn new(
        metric: impl Into<String>,
        value: f64,
        threshold: f64,
        measured_at: u64,
        source: impl Into<String>,
    ) -> Self {
        Self {
            metric: metric.into(),
            value,
            threshold,
            measured_at,
            source: source.into(),
        }
    }
}

/// A `csq.directive.v1` document, as read from stdin and as stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Directive {
    /// Always `csq.directive.v1`.
    pub schema: String,
    /// UUID chosen by the issuer; the idempotency key.
    pub id: String,
    /// Issuer name, `[a-z0-9-]{1,64}`.
    pub issuer: String,
    /// Unix seconds the issuer issued it.
    pub issued_at: u64,
    /// Unix seconds after which it reads as expired (at most 24 h after `issued_at`).
    pub expires_at: u64,
    /// The addressed session.
    pub target: DirectiveTarget,
    /// `offload`, `land_and_drain`, `delete_scratch` or `free_disk`.
    pub kind: String,
    /// One plain-language sentence, at most 500 characters.
    pub summary: String,
    /// The measurement behind it.
    pub why: DirectiveWhy,
    /// Suggested steps, at most 10 of at most 500 characters; absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suggested: Vec<String>,
    /// Required for the deleting kinds: exactly `only paths this session created`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl Directive {
    /// Build a directive with the required fields; `suggested` and `scope` start absent.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        issuer: impl Into<String>,
        issued_at: u64,
        expires_at: u64,
        target: DirectiveTarget,
        kind: impl Into<String>,
        summary: impl Into<String>,
        why: DirectiveWhy,
    ) -> Self {
        Self {
            schema: "csq.directive.v1".to_string(),
            id: id.into(),
            issuer: issuer.into(),
            issued_at,
            expires_at,
            target,
            kind: kind.into(),
            summary: summary.into(),
            why,
            suggested: Vec::new(),
            scope: None,
        }
    }

    /// Set the suggested steps; an empty vector stays absent on the wire.
    #[must_use]
    pub fn with_suggested(mut self, suggested: Vec<String>) -> Self {
        self.suggested = suggested;
        self
    }

    /// Set the scope statement.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<Option<String>>) -> Self {
        self.scope = scope.into();
        self
    }
}

/// The session's answer to a directive.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirectiveAck {
    /// `done`, `declined` or `deferred`.
    pub outcome: String,
    /// Optional note, at most 500 characters; absent when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl DirectiveAck {
    /// Build an acknowledgement.
    #[must_use]
    pub fn new(outcome: impl Into<String>, note: impl Into<Option<String>>) -> Self {
        Self {
            outcome: outcome.into(),
            note: note.into(),
        }
    }
}

/// `csq.directive_receipt.v1` payload: where a directive is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirectiveReceipt {
    /// The directive id.
    pub id: String,
    /// `queued`, `surfaced`, `acknowledged` or `expired`.
    pub status: String,
    /// Unix seconds the directive was queued.
    pub queued_at: u64,
    /// Unix seconds after which an unanswered directive reads as expired.
    pub expires_at: u64,
    /// Unix seconds the session first saw it; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surfaced_at: Option<u64>,
    /// Unix seconds it was acknowledged; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<u64>,
    /// The acknowledgement; absent until acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<DirectiveAck>,
}

impl DirectiveReceipt {
    /// Build a receipt with the required fields; the lifecycle fields start absent.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        status: impl Into<String>,
        queued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            id: id.into(),
            status: status.into(),
            queued_at,
            expires_at,
            surfaced_at: None,
            acknowledged_at: None,
            ack: None,
        }
    }

    /// Set the surfaced time.
    #[must_use]
    pub fn with_surfaced_at(mut self, at: impl Into<Option<u64>>) -> Self {
        self.surfaced_at = at.into();
        self
    }

    /// Set the acknowledged time.
    #[must_use]
    pub fn with_acknowledged_at(mut self, at: impl Into<Option<u64>>) -> Self {
        self.acknowledged_at = at.into();
        self
    }

    /// Set the acknowledgement.
    #[must_use]
    pub fn with_ack(mut self, ack: impl Into<Option<DirectiveAck>>) -> Self {
        self.ack = ack.into();
        self
    }
}

/// Payload of a `rate_limited` refusal: when the issuer may try again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirectiveRefusalPayload {
    /// Unix seconds at which the rolling-hour window frees.
    pub next_allowed_at: u64,
}

impl DirectiveRefusalPayload {
    /// Build a refusal payload.
    #[must_use]
    pub fn new(next_allowed_at: u64) -> Self {
        Self { next_allowed_at }
    }
}

/// `csq.directive_receipts.v1` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirectiveReceiptsPayload {
    /// Receipts ordered by last transition; the key is present even when empty.
    pub receipts: Vec<DirectiveReceipt>,
}

impl DirectiveReceiptsPayload {
    /// Build a receipts payload.
    #[must_use]
    pub fn new(receipts: Vec<DirectiveReceipt>) -> Self {
        Self { receipts }
    }
}

/// One inbox row: the directive text plus its current receipt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirectiveInboxEntry {
    /// The directive, as untrusted data from a named issuer.
    pub directive: Directive,
    /// Its current lifecycle state.
    pub receipt: DirectiveReceipt,
}

impl DirectiveInboxEntry {
    /// Build an inbox row.
    #[must_use]
    pub fn new(directive: Directive, receipt: DirectiveReceipt) -> Self {
        Self { directive, receipt }
    }
}

/// `csq.directive_inbox.v1` payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DirectiveInboxPayload {
    /// Directives addressed to the calling session; present even when empty.
    pub directives: Vec<DirectiveInboxEntry>,
}

impl DirectiveInboxPayload {
    /// Build an inbox payload.
    #[must_use]
    pub fn new(directives: Vec<DirectiveInboxEntry>) -> Self {
        Self { directives }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> Directive {
        Directive::new(
            "0b6c3c1e-7d0e-4b0a-9d3e-2f8f1a2b3c4d",
            "trestle-steward",
            100,
            200,
            DirectiveTarget::new(7, 50, "h"),
            "offload",
            "s",
            DirectiveWhy::new("m", 3.5, 2.0, 90, "cmd"),
        )
    }

    #[test]
    fn directive_omits_absent_optionals_and_round_trips() {
        let d = sample();
        let v = serde_json::to_value(&d).unwrap();
        assert!(
            v.get("suggested").is_none() && v.get("scope").is_none(),
            "{v}"
        );
        let back: Directive = serde_json::from_value(v).unwrap();
        assert_eq!(back, d);
        let with = sample()
            .with_suggested(vec!["a".into()])
            .with_scope(Some("x".to_string()));
        let v = serde_json::to_value(&with).unwrap();
        assert_eq!(v["suggested"], json!(["a"]));
        assert_eq!(v["scope"], "x");
    }

    #[test]
    fn receipt_queued_shape_has_no_nulls() {
        let r = DirectiveReceipt::new("i", "queued", 10, 20);
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"id": "i", "status": "queued", "queued_at": 10, "expires_at": 20})
        );
    }

    #[test]
    fn receipt_acknowledged_shape_and_empty_payloads() {
        let r = DirectiveReceipt::new("i", "acknowledged", 10, 20)
            .with_surfaced_at(11u64)
            .with_acknowledged_at(12u64)
            .with_ack(DirectiveAck::new("done", Some("ok".to_string())));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["ack"], json!({"outcome": "done", "note": "ok"}));
        assert_eq!(v["surfaced_at"], 11);
        assert_eq!(
            serde_json::to_value(DirectiveReceiptsPayload::new(vec![])).unwrap(),
            json!({"receipts": []})
        );
        assert_eq!(
            serde_json::to_value(DirectiveInboxPayload::new(vec![])).unwrap(),
            json!({"directives": []})
        );
        assert_eq!(
            serde_json::to_value(DirectiveRefusalPayload::new(5)).unwrap(),
            json!({"next_allowed_at": 5})
        );
    }
}
