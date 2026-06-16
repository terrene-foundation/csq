//! Cell 02 — Anthropic API key probe.
//!
//! **Status: PENDING LIVE EVIDENCE.** Round-1 redteam C1 (deep-analyst)
//! flagged that `sk-ant-api03-…` API keys are not known to authenticate
//! against `/api/oauth/usage` — the endpoint name and the
//! `Anthropic-Beta: oauth-2025-04-20` header are OAuth-bound. Probing
//! API-key slots there would always 401 and emit a misleading
//! "refresher bug" hint, sending operators down a phantom remediation
//! path.
//!
//! Until either (a) Anthropic publishes an API-key-compatible quota
//! endpoint, or (b) live evidence shows `/api/oauth/usage` accepts
//! `sk-ant-api03-…` tokens, this cell returns `Skipped` with a
//! `provider-drift-investigation` hint. Spec 11 §11.2 Cell 02 amended
//! 2026-05-07 to reflect this posture.

use super::{ProbeDiagnostic, ProbeRecord, ProbeStatus, SCHEMA_VERSION};
use crate::types::AccountNum;

const CELL_NAME: &str = "anthropic-api-key";
const SPEC_ANCHOR: &str = "05§5.1";

pub fn probe(slot: AccountNum) -> ProbeRecord {
    ProbeRecord {
        schema_version: SCHEMA_VERSION,
        slot: slot.get(),
        cell: CELL_NAME,
        spec_anchor: SPEC_ANCHOR,
        status: ProbeStatus::Skipped,
        endpoint: "pending: live-evidence gate".to_string(),
        elapsed_ms: 0,
        assertions_passed: 0,
        assertions_total: 6,
        diagnostic: Some(ProbeDiagnostic {
            failed_assertion: "prerequisite: Cell 02 has live evidence its endpoint accepts API keys".into(),
            observed_shape: "Anthropic OAuth usage endpoint is OAuth-bound (Anthropic-Beta: oauth-2025-04-20 header). API-key compatibility unverified.".into(),
            hint: "spec 11 §11.2 Cell 02 — provider-drift-investigation. Until live evidence is gathered, API-key Anthropic slots cannot be probed without burning a request on a 401-guaranteed endpoint. File a [provider-drift] issue if Anthropic publishes an API-key-compatible quota endpoint.".into(),
        }),
        redacted_response_excerpt: None,
    }
}
