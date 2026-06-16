//! Cell 10 — Ollama keyless probe.
//!
//! GET `http://127.0.0.1:11434/api/tags`. No auth. Per spec 11 §11.2
//! Cell 10:
//!
//! 1. HTTP 200 — Ollama is up; OR connection-refused returns a SOFT
//!    FAIL with `ollama_not_running` hint (informational; spec 11
//!    §11.4 — does not block tag).
//! 2. Body has `models` array (may be empty — empty is valid).

use super::{ProbeDiagnostic, ProbeRecord, ProbeStatus, SCHEMA_VERSION};
use crate::types::AccountNum;
use std::time::{Duration, Instant};

const CELL_NAME: &str = "ollama-keyless";
const SPEC_ANCHOR: &str = "11§11.2-Cell10";
// Round-2 redteam B3 — load-bearing invariant. Both endpoints are
// loopback-only HTTP because the client built below intentionally drops
// `https_only(true)` (HTTP is required for talking to a local Ollama
// daemon, which has no TLS surface). DO NOT parameterize the host or
// accept it from operator config — the loopback restriction is the
// threat-model rationale for the HTTPS bypass; lifting it would allow
// plaintext exfiltration to any host. The runtime assertion at probe()
// entry pins this invariant against future drift.
const ENDPOINT_V4: &str = "http://127.0.0.1:11434/api/tags";
const ENDPOINT_V6: &str = "http://[::1]:11434/api/tags";

pub fn probe(slot: AccountNum) -> ProbeRecord {
    // Round-2 redteam B3 — pin the loopback invariant. The HTTPS-bypass
    // for this cell is sound only because both endpoints are
    // loopback-only; parameterizing the host would silently turn the
    // bypass into a plaintext-exfiltration vector.
    debug_assert!(
        ENDPOINT_V4.starts_with("http://127.0.0.1:") && ENDPOINT_V6.starts_with("http://[::1]:"),
        "ollama probe endpoints MUST be loopback-only — see comment above ENDPOINT_V4"
    );
    let started = Instant::now();

    // Ollama runs locally; cannot use the shared `http::client()`
    // because that client enforces `https_only(true)` for safety
    // against accidental plaintext exfiltration on remote endpoints.
    // Localhost-only loopback is the documented exception.
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            return fail(
                slot,
                elapsed_ms,
                ENDPOINT_V4,
                0,
                "transport: reqwest client construction",
                "client builder failed",
                &format!("internal error: {e}"),
            );
        }
    };

    // Round-1 redteam H1-d: try IPv4 then IPv6 fallback. Ollama on
    // macOS Sequoia binds `[::1]:11434` by default when launched via
    // the menubar app; v4-only would soft-skip with `ollama_not_running`
    // while Ollama is actually fine.
    let (response, endpoint_used) = match client.get(ENDPOINT_V4).send() {
        Ok(r) => (r, ENDPOINT_V4),
        Err(_) => match client.get(ENDPOINT_V6).send() {
            Ok(r) => (r, ENDPOINT_V6),
            Err(e) => {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                return ollama_not_running(slot, elapsed_ms, &e.to_string());
            }
        },
    };
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let status = response.status().as_u16();
    if status != 200 {
        let body_preview = response.text().unwrap_or_default();
        return fail_with_body(
            slot,
            elapsed_ms,
            endpoint_used,
            0,
            "A1: HTTP status is 200",
            &format!("HTTP {status}"),
            "Ollama is reachable but returned a non-200 status. Check `ollama serve` logs.",
            body_preview.as_bytes(),
        );
    }

    let body = match response.text() {
        Ok(t) => t,
        Err(e) => {
            return fail(
                slot,
                elapsed_ms,
                endpoint_used,
                1,
                "A2: response body readable",
                &format!("read error: {e}"),
                "Ollama returned 200 but body could not be read.",
            );
        }
    };

    // A2: body has `models` field (may be empty array).
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            return fail_with_body(
                slot,
                elapsed_ms,
                endpoint_used,
                1,
                "A2: body parses as JSON",
                &format!("parse error: {e}"),
                "Ollama returned 200 but body is not JSON. Check ollama version.",
                body.as_bytes(),
            );
        }
    };
    if json.get("models").and_then(|v| v.as_array()).is_none() {
        return fail_with_body(
            slot,
            elapsed_ms,
            endpoint_used,
            1,
            "A2: body has `models` array",
            &format!("top-level keys: {}", top_keys(&json)),
            "Ollama /api/tags must return {\"models\": [...]}; missing `models` key is upstream schema drift.",
            body.as_bytes(),
        );
    }

    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Ok,
        endpoint: endpoint_used.to_string(),
        elapsed_ms,
        assertions_passed: 2,
        assertions_total: 2,
        diagnostic: None,
        redacted_response_excerpt: None,
    }
}

fn ollama_not_running(slot: AccountNum, elapsed_ms: u64, transport_err: &str) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        // Soft skip — Ollama not running is operator state, not a
        // probe FAIL or contract regression. Spec 11 §11.4: this
        // does NOT block a release tag.
        status: ProbeStatus::Skipped,
        endpoint: format!("tried {ENDPOINT_V4} and {ENDPOINT_V6}"),
        elapsed_ms,
        assertions_passed: 0,
        assertions_total: 2,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: "ollama_not_running (soft)".to_string(),
            observed_shape: format!("transport: {transport_err}"),
            hint: "informational — start Ollama via `ollama serve` if you need this slot. Does NOT block release tag.".to_string(),
        }),
        redacted_response_excerpt: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn fail(
    slot: AccountNum,
    elapsed_ms: u64,
    endpoint: &str,
    assertions_passed: u32,
    failed_assertion: &str,
    observed_shape: &str,
    hint: &str,
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Fail,
        endpoint: endpoint.to_string(),
        elapsed_ms,
        assertions_passed,
        assertions_total: 2,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: failed_assertion.to_string(),
            observed_shape: observed_shape.to_string(),
            hint: hint.to_string(),
        }),
        redacted_response_excerpt: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn fail_with_body(
    slot: AccountNum,
    elapsed_ms: u64,
    endpoint: &str,
    assertions_passed: u32,
    failed_assertion: &str,
    observed_shape: &str,
    hint: &str,
    body: &[u8],
) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Fail,
        endpoint: endpoint.to_string(),
        elapsed_ms,
        assertions_passed,
        assertions_total: 2,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: failed_assertion.to_string(),
            observed_shape: observed_shape.to_string(),
            hint: hint.to_string(),
        }),
        // Round-1 redteam H2-sec: redact_excerpt (redact-then-truncate)
        // — earlier code skipped redaction entirely.
        redacted_response_excerpt: Some(crate::error::redact_excerpt(body, 256)),
    }
}

fn top_keys(v: &serde_json::Value) -> String {
    v.as_object()
        .map(|o| o.keys().cloned().collect::<Vec<_>>().join(", "))
        .unwrap_or_else(|| "<not an object>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_includes_diagnostic_with_hint() {
        let r = fail(
            AccountNum::try_from(1).unwrap(),
            100,
            ENDPOINT_V4,
            0,
            "test",
            "obs",
            "hint",
        );
        assert_eq!(r.status, ProbeStatus::Fail);
        let d = r.diagnostic.unwrap();
        assert_eq!(d.failed_assertion, "test");
        assert_eq!(d.hint, "hint");
    }

    #[test]
    fn ollama_not_running_is_soft_skip_not_fail() {
        let r = ollama_not_running(AccountNum::try_from(11).unwrap(), 50, "connection refused");
        assert_eq!(r.status, ProbeStatus::Skipped);
        assert!(r
            .diagnostic
            .unwrap()
            .hint
            .contains("Does NOT block release tag"));
    }

    #[test]
    fn fail_with_body_truncates_at_256_chars() {
        let big = "x".repeat(1000);
        let r = fail_with_body(
            AccountNum::try_from(11).unwrap(),
            10,
            ENDPOINT_V4,
            0,
            "x",
            "y",
            "z",
            big.as_bytes(),
        );
        let excerpt = r.redacted_response_excerpt.unwrap();
        assert_eq!(excerpt.len(), 256);
    }

    #[test]
    fn top_keys_handles_object() {
        let v = serde_json::json!({"a": 1, "b": 2});
        assert!(top_keys(&v).contains("a"));
        assert!(top_keys(&v).contains("b"));
    }

    #[test]
    fn top_keys_handles_non_object() {
        let v = serde_json::json!([1, 2, 3]);
        assert_eq!(top_keys(&v), "<not an object>");
    }
}
