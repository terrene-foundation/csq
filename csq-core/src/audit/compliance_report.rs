//! Plain-language compliance-report generator (FR-GOV #788).
//!
//! The audit export bundle (`csq-core/src/audit/export.rs`) is machine-readable
//! only: `chain.jsonl` (canonical-form signed records) plus a `verify` script.
//! That is evidence a *verifier script* checks — not evidence a compliance
//! officer, auditor, or works council can *read*. This module renders the
//! already-signed operation chain (`csq-runs/`) into an auditor-readable
//! document (Markdown or HTML), grounded in the canonical records: it PRESENTS
//! verified facts, it never re-derives them.
//!
//! # Chain scope
//!
//! The report renders the **operation chain** (`csq-runs/<chain_id>.jsonl`) —
//! the same chain `csq audit verify` and `summarize_residency` read, and where
//! every governed decision ([`EventKind::GovernanceTurn`]) and lifecycle op is
//! written. The separate **born-canonical EATP attestation chain**
//! (`eatp-runs/`, [`EventKind::EatpAttestation`]) is NOT rendered here: it has
//! its own `chain_id`, key custody, and verification, and has no production
//! record writer yet (M3 §10.5 W2b is the first — `csq audit init` only
//! provisions its `chain.json` + key, not a genesis record). The
//! `EatpAttestation` classify arm is retained as a forward-compatible
//! drift-catch; when a W2b producer lands, rendering the EATP chain (with its
//! own injected verification verdict) is a tracked follow-up.
//!
//! # What the report shows
//!
//! Two sections, matching how a regulated buyer reads an attestation:
//!
//! - **Governed decisions** — the per-turn governance verdicts
//!   ([`EventKind::GovernanceTurn`]): which turns passed, which were blocked
//!   (with the redacted reason), which were operator-overridden (with the
//!   redacted justification), and residency verdicts. This is the
//!   revenue-relevant surface — the enterprise Phase-2b governance writer
//!   (`governance_audit::build_governance_turn_record`) emits these; the
//!   community edition never constructs one, so its report carries only the
//!   lifecycle section.
//! - **Lifecycle operations** — everything else the chain records (`csq run`,
//!   account swaps, identity mints, key rotations, logouts, replication, …).
//!
//! # Redaction posture
//!
//! The renderer only reads fields off already-persisted [`SignedRecord`]s. The
//! human-readable free-text fields it surfaces (`GovernanceTurnPayload`'s
//! `justification_redacted` / `governance_reason`, the sink/re-genesis reasons)
//! are typed [`RedactedString`] — redacted at the
//! source AND re-redacted on deserialize (`types.rs`), so a forged on-disk chain
//! with raw tokens still renders redacted. The report never reads a raw payload,
//! a credential file, or the keychain. The HTML renderer additionally
//! HTML-escapes every cell so a redacted string containing `<`/`&` cannot inject
//! markup.
//!
//! # Verification grounding
//!
//! [`build_compliance_report`] takes the chain's [`verify_chain`] result as an
//! injected argument (mirroring [`crate::audit::verify::to_json_output`]) rather
//! than re-running verification itself. This keeps the builder + renderers
//! keychain-free and fully unit-testable, and lets the caller (`csq audit
//! compliance-report`) surface the verification verdict in the report header so
//! the document states plainly whether the facts it presents come from a chain
//! that verified end-to-end.
//!
//! [`verify_chain`]: crate::audit::verify::verify_chain
//! [`EventKind::GovernanceTurn`]: crate::audit::types::EventKind::GovernanceTurn
//! [`EventKind::EatpAttestation`]: crate::audit::types::EventKind::EatpAttestation

use std::path::Path;

use crate::audit::types::{EventPayload, SignedRecord};
use crate::audit::verify::VerifySummary;
use crate::audit::LedgerError;

/// The chain-verification verdict surfaced in the report header.
///
/// Built from the `Result<VerifySummary, LedgerError>` the caller obtained from
/// [`verify_chain`](crate::audit::verify::verify_chain). `Failed` carries a
/// redacted reason — `LedgerError`'s `Display` is already redaction-safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    /// The chain verified end-to-end (no integrity violation). Carries the
    /// grounding facts an auditor pins the report to.
    Verified {
        /// Records chain-linked without error.
        verified_count: u64,
        /// Highest verified sequence number (the chain head).
        head_seq: u64,
        /// Whether every historical signing key was present (no signature
        /// gaps). `false` when a rotated-out key was absent from the keychain —
        /// chain-linking still verified, per-record signatures for the gap were
        /// skipped.
        no_key_gaps: bool,
        /// Keychain integrity-anchor status string (`confirmed` / `unconfirmed`
        /// / `mismatch`) — a DETECTOR, never fatal.
        keychain_anchor: String,
        /// Records NOT verified this run because they fell outside the verifier's
        /// tail window (`VerifyConfig::record_limit`, default 10,000 — the OLDEST
        /// records, including the genesis link, are the ones skipped). `0` for a
        /// whole-chain verify. When `> 0` the report renders a PARTIAL-coverage
        /// banner instead of the "seq 0..=head" full-coverage line, because the
        /// classifier lists ALL on-disk records (it reads the whole chain) while
        /// only the tail was verified — claiming `seq 0..=head` would present
        /// unverified older records under a full-coverage header.
        limit_exceeded_count: u64,
    },
    /// Verification returned an integrity violation; the report is produced but
    /// prominently marked UNVERIFIED so the auditor does not treat it as clean.
    Failed {
        /// Redaction-safe failure reason (`LedgerError` Display).
        reason: String,
    },
}

impl VerificationStatus {
    /// Projects a `verify_chain` result into the report's verdict.
    #[must_use]
    pub fn from_verify(result: &Result<VerifySummary, LedgerError>) -> Self {
        match result {
            Ok(summary) => Self::Verified {
                verified_count: summary.verified_count,
                head_seq: summary.head_seq,
                no_key_gaps: summary.historical_key_gaps.is_empty(),
                keychain_anchor: format!("{:?}", summary.keychain_anchor).to_lowercase(),
                limit_exceeded_count: summary.limit_exceeded_count,
            },
            Err(e) => Self::Failed {
                // `LedgerError: Display` routes user-facing strings through
                // `RedactedString`; formatting it here is redaction-safe.
                reason: e.to_string(),
            },
        }
    }

    /// `true` iff the chain verified end-to-end.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

/// One governed-decision row (a per-turn governance verdict or EATP
/// attestation). Every string field is either a fixed-vocabulary tag, a
/// non-secret catalog id, or an already-redacted free-text string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernedRow {
    /// Chain sequence number.
    pub seq: u64,
    /// ISO-8601 UTC chain-write timestamp (`SignedRecord::ts`).
    pub ts: String,
    /// The live session id the decision belongs to (empty for EATP genesis).
    pub session_id: String,
    /// Session-level turn number (`0` where the record carries none).
    pub turn: u32,
    /// Fixed-vocabulary event class (`turn_completed`, `governance_failure`,
    /// `governance_override`, `residency_enforcement`, `failover`,
    /// `turn_started`, `eatp_attestation`).
    pub class: String,
    /// Plain-language decision label an auditor reads (`passed`, `blocked`,
    /// `overridden`, `residency: pass`, `failover`, `attestation`, …).
    pub decision: String,
    /// PACT verification level for this record, if stamped. The enterprise
    /// Phase-2b governance writer (`governance_audit::build_governance_turn_record`)
    /// populates this on every governed turn today (`AUTO_APPROVED` / `FLAGGED` /
    /// `HELD` / `SIGNED_ATTESTATION`); it renders `—` only for community records,
    /// lifecycle rows, or records that predate the field.
    pub verification_level: Option<String>,
    /// Whether an EATP authority attestation is present on the record. The
    /// enterprise governance writer sets `authority: Some(..)` on every governed
    /// turn today; it is `false` for community records, lifecycle rows, or
    /// records that predate the field. The opaque blob is never rendered raw.
    pub authority_attested: bool,
    /// Redacted, human-readable reason-of-record: the override justification, a
    /// governance-failure reason, or a residency policy/provider detail. `None`
    /// where the class carries none.
    pub detail: Option<String>,
}

/// One lifecycle-operation row (a non-governance chain record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRow {
    /// Chain sequence number.
    pub seq: u64,
    /// ISO-8601 UTC chain-write timestamp.
    pub ts: String,
    /// Plain-language operation label (`csq run`, `account swap`, …).
    pub operation: String,
    /// Non-secret per-operation detail (ids, slots, hashes, redacted reasons).
    pub detail: String,
}

/// A fully classified, render-ready compliance report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceReport {
    /// The chain identifier the records belong to (empty when no chain exists).
    pub chain_id: String,
    /// The verification verdict grounding the report.
    pub verification: VerificationStatus,
    /// Governed decisions, in chain order.
    pub governed: Vec<GovernedRow>,
    /// Lifecycle operations, in chain order.
    pub lifecycle: Vec<LifecycleRow>,
    /// Count of governed turns that passed (`turn_completed` + residency pass).
    pub passed: u64,
    /// Count of governed turns that were blocked (`governance_failure` +
    /// residency block).
    pub blocked: u64,
    /// Count of operator overrides (`governance_override`).
    pub overridden: u64,
    /// Number of non-empty chain lines that failed to parse into a
    /// [`SignedRecord`] and were therefore omitted from the report. Surfaced in
    /// the header when non-zero so a corrupted line is a VISIBLE omission, not a
    /// silent drop — a compliance document must not under-report without a
    /// signal. `0` for the pure [`classify_records`] path (it folds
    /// already-parsed records).
    pub skipped_lines: u64,
}

/// Builds the compliance report from the on-disk op-chain plus an injected
/// verification result.
///
/// Reads `csq-runs/<chain_id>.jsonl` (the same source `summarize_residency`
/// reads), parses each line into a [`SignedRecord`], and classifies. Returns an
/// empty-but-well-formed report (no records) when no chain exists — never an
/// error. The `verify` argument is the caller's
/// [`verify_chain`](crate::audit::verify::verify_chain) result; it is projected
/// into the report header verdict and is the ONLY verification signal (the
/// builder never touches the keychain itself).
#[must_use]
pub fn build_compliance_report(
    base_dir: &Path,
    verify: &Result<VerifySummary, LedgerError>,
) -> ComplianceReport {
    let chain_id = crate::audit::op_emit::load_chain_id(base_dir);
    let mut skipped_lines = 0u64;
    let records: Vec<SignedRecord> = if chain_id.is_empty() {
        Vec::new()
    } else {
        let jsonl = base_dir.join("csq-runs").join(format!("{chain_id}.jsonl"));
        match std::fs::read_to_string(&jsonl) {
            Ok(content) => content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| match serde_json::from_str::<SignedRecord>(l) {
                    Ok(rec) => Some(rec),
                    Err(_) => {
                        // A non-empty line that does not parse is a corrupted /
                        // unrecognized record. Count it so the header can surface
                        // the omission (NIT-2) instead of dropping it silently.
                        skipped_lines += 1;
                        None
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    };
    let mut report = classify_records(&records);
    report.chain_id = chain_id;
    report.verification = VerificationStatus::from_verify(verify);
    report.skipped_lines = skipped_lines;
    report
}

/// Pure classification fold over already-parsed records (the testable core of
/// [`build_compliance_report`]). Leaves `chain_id` empty and `verification`
/// defaulted to `Failed` with an empty reason — [`build_compliance_report`]
/// fills both. Callers that only want the classification (tests) ignore those
/// two fields.
#[must_use]
pub fn classify_records(records: &[SignedRecord]) -> ComplianceReport {
    let mut governed: Vec<GovernedRow> = Vec::new();
    let mut lifecycle: Vec<LifecycleRow> = Vec::new();
    let mut passed = 0u64;
    let mut blocked = 0u64;
    let mut overridden = 0u64;

    for rec in records {
        match &rec.payload {
            EventPayload::GovernanceTurn(p) => {
                let verification_level = rec
                    .verification_level
                    .as_ref()
                    .map(|l| l.as_canonical_str().to_string());
                let (decision, detail) = match p.event_class.as_str() {
                    "turn_completed" => {
                        passed += 1;
                        ("passed".to_string(), None)
                    }
                    "governance_failure" => {
                        blocked += 1;
                        (
                            "blocked".to_string(),
                            p.governance_reason.as_ref().map(|r| r.as_str().to_string()),
                        )
                    }
                    "governance_override" => {
                        overridden += 1;
                        (
                            "overridden".to_string(),
                            p.justification_redacted
                                .as_ref()
                                .map(|r| r.as_str().to_string()),
                        )
                    }
                    "residency_enforcement" => {
                        let verdict = p.residency_verdict.as_deref().unwrap_or("");
                        // Residency emits pass/block; account for the full
                        // EnvelopeVerdict projection fail-closed (any non-pass
                        // reads as a block) so passed+blocked never silently
                        // drops a residency record — mirrors
                        // phase2b::residency::summarize_records.
                        if matches!(verdict, "pass" | "conditional") {
                            passed += 1;
                        } else {
                            blocked += 1;
                        }
                        let provider = p.provider_id.as_deref().unwrap_or("—");
                        let policy = p.residency_policy_name.as_deref().unwrap_or("—");
                        (
                            format!(
                                "residency: {}",
                                if verdict.is_empty() { "—" } else { verdict }
                            ),
                            Some(format!("provider {provider}, policy {policy}")),
                        )
                    }
                    "failover" => {
                        let from = p.failover_from.as_deref().unwrap_or("—");
                        let to = p.provider_id.as_deref().unwrap_or("—");
                        let reason = p.failover_reason.as_deref().unwrap_or("—");
                        (
                            "failover".to_string(),
                            Some(format!("{from} → {to} ({reason})")),
                        )
                    }
                    "turn_started" => ("turn started".to_string(), None),
                    other => (other.to_string(), None),
                };
                governed.push(GovernedRow {
                    seq: rec.seq,
                    ts: rec.ts.clone(),
                    session_id: p.session_id.clone(),
                    turn: p.turn,
                    class: p.event_class.clone(),
                    decision,
                    verification_level,
                    authority_attested: rec.authority.is_some(),
                    detail,
                });
            }
            EventPayload::EatpAttestation(p) => {
                governed.push(GovernedRow {
                    seq: rec.seq,
                    ts: rec.ts.clone(),
                    session_id: String::new(),
                    turn: 0,
                    class: "eatp_attestation".to_string(),
                    decision: "attestation".to_string(),
                    verification_level: rec
                        .verification_level
                        .as_ref()
                        .map(|l| l.as_canonical_str().to_string()),
                    authority_attested: rec.authority.is_some(),
                    detail: Some(format!("anchor {} seq {}", p.anchor_id, p.sequence)),
                });
            }
            EventPayload::McpGateDecision(p) => {
                // Spawn-boundary MCP gate decision (M6 T6.2 Shard 4). Counts as a
                // governed decision: `pass` → passed, `block`/`escalate` (and any
                // non-`pass` verdict, fail-closed) → blocked — so an auditor sees
                // every gated tool-call accounted for, and no MCP decision silently
                // escapes the passed/blocked tally.
                if p.verdict == "pass" {
                    passed += 1;
                } else {
                    blocked += 1;
                }
                governed.push(GovernedRow {
                    seq: rec.seq,
                    ts: rec.ts.clone(),
                    session_id: p.session_nonce.clone(),
                    turn: 0,
                    class: "mcp_gate_decision".to_string(),
                    decision: p.verdict.clone(),
                    verification_level: rec
                        .verification_level
                        .as_ref()
                        .map(|l| l.as_canonical_str().to_string()),
                    authority_attested: rec.authority.is_some(),
                    detail: Some(format!(
                        "{} tool {} ({})",
                        p.cli, p.tool, p.enforcement_fidelity
                    )),
                });
            }
            other => {
                let (operation, detail) = lifecycle_label(other);
                lifecycle.push(LifecycleRow {
                    seq: rec.seq,
                    ts: rec.ts.clone(),
                    operation,
                    detail,
                });
            }
        }
    }

    ComplianceReport {
        chain_id: String::new(),
        verification: VerificationStatus::Failed {
            reason: String::new(),
        },
        governed,
        lifecycle,
        passed,
        blocked,
        overridden,
        skipped_lines: 0,
    }
}

/// Maps a non-governance payload to a `(label, detail)` pair. Every field cited
/// is non-secret (ids, slots, hashes, fixed-vocabulary tags, redacted reasons).
fn lifecycle_label(payload: &EventPayload) -> (String, String) {
    use EventPayload as P;
    match payload {
        P::CsqRun(p) => ("csq run".into(), format!("run {}", p.run_id)),
        P::OAuthRefresh(p) => (
            "oauth refresh".into(),
            format!("slot {}, identity {}", p.slot.get(), p.identity_uuid),
        ),
        P::ArtifactLoad(p) => (
            "artifact load".into(),
            format!("sha256 {}", p.artifact_sha256.as_str()),
        ),
        P::ModelInvoke(p) => (
            "model invoke".into(),
            format!("{} on {}", p.model, p.surface),
        ),
        P::OutputCapture(p) => (
            "output capture".into(),
            format!("sha256 {}", p.output_sha256.as_str()),
        ),
        P::AccountSwap(p) => (
            "account swap".into(),
            format!("slot {} → {}", p.from_slot.get(), p.to_slot.get()),
        ),
        P::IdentityMint(p) => (
            "identity mint".into(),
            format!("identity {}, slot {}", p.identity_uuid, p.slot.get()),
        ),
        P::KeyRotate(p) => (
            "key rotate".into(),
            format!(
                "{} → {} ({:?})",
                p.previous_key_id.as_str(),
                p.new_key_id.as_str(),
                p.rotation_reason
            ),
        ),
        P::ReleaseAuth(p) => (
            "release authorization".into(),
            format!("{} (sha256 {})", p.release_tag, p.artifact_sha256.as_str()),
        ),
        P::ReplicationAck(p) => (
            "replication ack".into(),
            format!("sink {}", p.sink.as_str()),
        ),
        P::ReplicationFailed(p) => (
            "replication failed".into(),
            format!("sink {} — {}", p.sink.as_str(), p.reason.as_str()),
        ),
        P::ChainContinuation(p) => (
            "chain continuation".into(),
            format!("resumed at seq {}", p.resumed_at_seq),
        ),
        P::ChainReGenesis(p) => (
            "chain re-genesis".into(),
            format!("reason {}", p.reason.as_str()),
        ),
        P::SinkDriftDetected(p) => (
            "sink drift detected".into(),
            format!("sink {}, record {}", p.sink.as_str(), p.record_id.as_str()),
        ),
        P::AccountLogout(p) => (
            "account logout".into(),
            match &p.orphaned_uuid {
                Some(u) => format!("slot {}, orphaned identity {u}", p.slot.get()),
                None => format!("slot {}", p.slot.get()),
            },
        ),
        P::AccountMove(p) => (
            "account move".into(),
            format!("slot {} → {}", p.from_slot.get(), p.to_slot.get()),
        ),
        P::SeamEventRejected(p) => ("seam event rejected".into(), format!("reason {}", p.reason)),
        P::ProvenanceAnchored(_) => ("provenance anchored".into(), String::new()),
        P::ProvenanceCaptureMatrix(_) => ("provenance capture matrix".into(), String::new()),
        P::SeamDuplicateSuppressed(_) => ("seam duplicate suppressed".into(), String::new()),
        // #787 b2b — a signed policy-bundle install (own-op lifecycle record).
        // Cites only non-secret fields: the bundle version and an 8-byte hex
        // fingerprint of the PUBLIC verifying key. The fingerprint is built
        // byte-by-byte (not by slicing a formatted string) so it is panic-proof
        // regardless of on-disk record content — though `bundle_pubkey`'s
        // validating deserializer already guarantees 32 valid bytes.
        P::PolicyBundleInstall(p) => {
            let fp: String = p
                .bundle_pubkey
                .0
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            (
                "policy bundle install".into(),
                format!("bundle v{} (pubkey {fp}…)", p.bundle_version),
            )
        }
        // Governance kinds never reach here (classified above); exhaustive
        // match keeps this a compile-time drift catch if a kind is added.
        P::GovernanceTurn(_) | P::EatpAttestation(_) | P::McpGateDecision(_) => {
            ("governance".into(), String::new())
        }
    }
}

// ───────────────────────────── rendering ─────────────────────────────────

impl ComplianceReport {
    /// Governed rows that carry no admit/deny verdict — `turn_started`,
    /// `failover`, `eatp_attestation`, and any unrecognized event class. These
    /// are listed in the governed table but counted in neither `passed`,
    /// `blocked`, nor `overridden`, so `passed + blocked + overridden +
    /// informational == governed.len()` is a total partition (the Summary line
    /// prints all four so an auditor's arithmetic reconciles).
    #[must_use]
    pub fn informational_count(&self) -> u64 {
        // `saturating_sub` guards the (unreachable via `classify_records`, but
        // `pub`-field-constructible) case where a hand-built report carries
        // tallies exceeding `governed.len()` — a debug underflow panic in a
        // renderer would be a worse failure than a floored 0.
        (self.governed.len() as u64)
            .saturating_sub(self.passed)
            .saturating_sub(self.blocked)
            .saturating_sub(self.overridden)
    }

    /// Renders the report as an auditor-readable Markdown document.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# csq Compliance Report\n\n");

        // ── Provenance + verification banner ──────────────────────────────
        if self.chain_id.is_empty() {
            out.push_str("_No audit chain found on this host._\n\n");
        } else {
            out.push_str(&format!("**Chain:** `{}`\n\n", self.chain_id));
        }
        match &self.verification {
            VerificationStatus::Verified {
                verified_count,
                head_seq,
                no_key_gaps,
                keychain_anchor,
                limit_exceeded_count,
            } => {
                out.push_str(&format!(
                    "**Verification:** ✅ VERIFIED — {verified_count} record(s) chain-linked, head seq {head_seq}\n\n"
                ));
                if *limit_exceeded_count > 0 {
                    // Partial verify: only the tail was checked, but the tables
                    // below list ALL on-disk records — say so, and do NOT claim
                    // the full `seq 0..=head` range.
                    out.push_str(&format!(
                        "> ⚠️ PARTIAL verification — only the most recent {verified_count} record(s) (up to head seq {head_seq}) were verified this run; {limit_exceeded_count} older record(s), INCLUDING the genesis, were NOT verified. The tables below list ALL records, including the unverified older ones. Run `csq audit verify --full` for whole-chain coverage.\n\n"
                    ));
                } else if *verified_count > 0 {
                    out.push_str(&format!(
                        "**Records covered:** seq 0..={head_seq} — pin this range when reproducing against an exported bundle's `CUTOFF.json` (the bundle head must match seq {head_seq}).\n\n"
                    ));
                }
                if !no_key_gaps {
                    out.push_str("> ⚠️ Some historical signing keys were absent; chain-linking verified, signatures for rotated-out keys were skipped.\n\n");
                }
                out.push_str(&format!("**Integrity anchor:** {keychain_anchor}\n\n"));
            }
            VerificationStatus::Failed { reason } => {
                out.push_str(&format!(
                    "**Verification:** ❌ UNVERIFIED — {}\n\n",
                    if reason.is_empty() {
                        "no verification result"
                    } else {
                        reason
                    }
                ));
                out.push_str("> ⚠️ This report was produced from a chain that did not verify end-to-end. Treat the records below as UNCONFIRMED.\n\n");
            }
        }
        if self.skipped_lines > 0 {
            out.push_str(&format!(
                "> ⚠️ {} chain line(s) were unparseable and are OMITTED from this report.\n\n",
                self.skipped_lines
            ));
        }

        out.push_str("To reproduce independently, export a bundle (`csq audit export`) and run its self-contained `./verify` script against the bundle's `CUTOFF.json`.\n\n");

        // ── Summary ───────────────────────────────────────────────────────
        out.push_str("## Summary\n\n");
        out.push_str(&format!(
            "- Governed decisions: {} (passed {}, blocked {}, overridden {}, informational {})\n",
            self.governed.len(),
            self.passed,
            self.blocked,
            self.overridden,
            self.informational_count(),
        ));
        out.push_str(&format!(
            "- Lifecycle operations: {}\n\n",
            self.lifecycle.len()
        ));

        // ── Governed decisions ────────────────────────────────────────────
        out.push_str("## Governed Decisions\n\n");
        if self.governed.is_empty() {
            out.push_str("_No governed decisions recorded._ (Per-turn governance decisions are produced by the enterprise Phase-2b interactive enforcement session; a community-edition chain carries none.)\n\n");
        } else {
            out.push_str("| Seq | Time (UTC) | Session | Turn | Decision | Verification level | Authority | Reason / detail |\n");
            out.push_str("| --- | --- | --- | --- | --- | --- | --- | --- |\n");
            for r in &self.governed {
                out.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                    r.seq,
                    md_cell(&r.ts),
                    md_cell(if r.session_id.is_empty() {
                        "—"
                    } else {
                        &r.session_id
                    }),
                    r.turn,
                    md_cell(&r.decision),
                    md_cell(r.verification_level.as_deref().unwrap_or("—")),
                    if r.authority_attested {
                        "attested"
                    } else {
                        "—"
                    },
                    md_cell(r.detail.as_deref().unwrap_or("—")),
                ));
            }
            out.push('\n');
        }

        // ── Lifecycle operations ──────────────────────────────────────────
        out.push_str("## Lifecycle Operations\n\n");
        if self.lifecycle.is_empty() {
            out.push_str("_No lifecycle operations recorded._\n\n");
        } else {
            out.push_str("| Seq | Time (UTC) | Operation | Detail |\n");
            out.push_str("| --- | --- | --- | --- |\n");
            for r in &self.lifecycle {
                out.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    r.seq,
                    md_cell(&r.ts),
                    md_cell(&r.operation),
                    md_cell(if r.detail.is_empty() {
                        "—"
                    } else {
                        &r.detail
                    }),
                ));
            }
            out.push('\n');
        }

        out
    }

    /// Renders the report as a self-contained HTML document. Every dynamic cell
    /// is HTML-escaped (a redacted string containing `<`/`&` cannot inject
    /// markup).
    #[must_use]
    pub fn render_html(&self) -> String {
        let mut out = String::new();
        out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>csq Compliance Report</title>\n");
        out.push_str("<style>body{font-family:system-ui,-apple-system,sans-serif;margin:2rem;color:#1a1a1a}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}th{background:#f2f2f2}.verified{color:#0a7f3f}.unverified{color:#b00020}.warn{color:#a15c00}</style>\n");
        out.push_str("</head>\n<body>\n<h1>csq Compliance Report</h1>\n");

        if self.chain_id.is_empty() {
            out.push_str("<p><em>No audit chain found on this host.</em></p>\n");
        } else {
            out.push_str(&format!(
                "<p><strong>Chain:</strong> <code>{}</code></p>\n",
                html_escape(&self.chain_id)
            ));
        }
        match &self.verification {
            VerificationStatus::Verified {
                verified_count,
                head_seq,
                no_key_gaps,
                keychain_anchor,
                limit_exceeded_count,
            } => {
                out.push_str(&format!(
                    "<p class=\"verified\"><strong>Verification:</strong> \u{2705} VERIFIED — {verified_count} record(s) chain-linked, head seq {head_seq}</p>\n"
                ));
                if *limit_exceeded_count > 0 {
                    out.push_str(&format!(
                        "<p class=\"warn\">\u{26a0} PARTIAL verification — only the most recent {verified_count} record(s) (up to head seq {head_seq}) were verified this run; {limit_exceeded_count} older record(s), INCLUDING the genesis, were NOT verified. The tables below list ALL records, including the unverified older ones. Run <code>csq audit verify --full</code> for whole-chain coverage.</p>\n"
                    ));
                } else if *verified_count > 0 {
                    out.push_str(&format!(
                        "<p><strong>Records covered:</strong> seq 0..={head_seq} — pin this range when reproducing against an exported bundle's <code>CUTOFF.json</code> (the bundle head must match seq {head_seq}).</p>\n"
                    ));
                }
                if !no_key_gaps {
                    out.push_str("<p class=\"warn\">\u{26a0} Some historical signing keys were absent; chain-linking verified, signatures for rotated-out keys were skipped.</p>\n");
                }
                out.push_str(&format!(
                    "<p><strong>Integrity anchor:</strong> {}</p>\n",
                    html_escape(keychain_anchor)
                ));
            }
            VerificationStatus::Failed { reason } => {
                out.push_str(&format!(
                    "<p class=\"unverified\"><strong>Verification:</strong> \u{274c} UNVERIFIED — {}</p>\n",
                    html_escape(if reason.is_empty() { "no verification result" } else { reason })
                ));
                out.push_str("<p class=\"warn\">\u{26a0} This report was produced from a chain that did not verify end-to-end. Treat the records below as UNCONFIRMED.</p>\n");
            }
        }
        if self.skipped_lines > 0 {
            out.push_str(&format!(
                "<p class=\"warn\">\u{26a0} {} chain line(s) were unparseable and are OMITTED from this report.</p>\n",
                self.skipped_lines
            ));
        }
        out.push_str("<p>To reproduce independently, export a bundle (<code>csq audit export</code>) and run its self-contained <code>./verify</code> script against the bundle's <code>CUTOFF.json</code>.</p>\n");

        out.push_str("<h2>Summary</h2>\n<ul>\n");
        out.push_str(&format!(
            "<li>Governed decisions: {} (passed {}, blocked {}, overridden {}, informational {})</li>\n",
            self.governed.len(),
            self.passed,
            self.blocked,
            self.overridden,
            self.informational_count(),
        ));
        out.push_str(&format!(
            "<li>Lifecycle operations: {}</li>\n</ul>\n",
            self.lifecycle.len()
        ));

        out.push_str("<h2>Governed Decisions</h2>\n");
        if self.governed.is_empty() {
            out.push_str("<p><em>No governed decisions recorded.</em> Per-turn governance decisions are produced by the enterprise Phase-2b interactive enforcement session; a community-edition chain carries none.</p>\n");
        } else {
            out.push_str("<table>\n<thead><tr><th>Seq</th><th>Time (UTC)</th><th>Session</th><th>Turn</th><th>Decision</th><th>Verification level</th><th>Authority</th><th>Reason / detail</th></tr></thead>\n<tbody>\n");
            for r in &self.governed {
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    r.seq,
                    html_escape(&r.ts),
                    html_escape(if r.session_id.is_empty() { "—" } else { &r.session_id }),
                    r.turn,
                    html_escape(&r.decision),
                    html_escape(r.verification_level.as_deref().unwrap_or("—")),
                    if r.authority_attested { "attested" } else { "—" },
                    html_escape(r.detail.as_deref().unwrap_or("—")),
                ));
            }
            out.push_str("</tbody>\n</table>\n");
        }

        out.push_str("<h2>Lifecycle Operations</h2>\n");
        if self.lifecycle.is_empty() {
            out.push_str("<p><em>No lifecycle operations recorded.</em></p>\n");
        } else {
            out.push_str("<table>\n<thead><tr><th>Seq</th><th>Time (UTC)</th><th>Operation</th><th>Detail</th></tr></thead>\n<tbody>\n");
            for r in &self.lifecycle {
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    r.seq,
                    html_escape(&r.ts),
                    html_escape(&r.operation),
                    html_escape(if r.detail.is_empty() {
                        "—"
                    } else {
                        &r.detail
                    }),
                ));
            }
            out.push_str("</tbody>\n</table>\n");
        }

        out.push_str("</body>\n</html>\n");
        out
    }
}

/// Escapes a Markdown table cell: `|` would break the column and a newline
/// would break the row, so both are neutralized.
///
/// This neutralizes table STRUCTURE only, not Markdown link/image syntax
/// (`[x](url)`, `![x](url)`). That is safe because every free-text field routed
/// through this fn is either a fixed-vocabulary tag or a [`RedactedString`]
/// (redacted at source AND re-redacted on deserialize) — an attacker cannot
/// place attacker-controlled free-text that both survives redaction and renders
/// as an active link. INVARIANT: if a future change ever routes a
/// non-`RedactedString`, attacker-influenceable free-text field into a Markdown
/// cell, that gating disappears and link/image neutralization must be added here.
fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

/// Escapes the five HTML metacharacters so a redacted free-text field cannot
/// inject markup into the HTML report.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::{
        Ed25519Signature, EventKind, EventPayload, GovernanceTurnPayload, KeyId, RecordId,
        Sha256Hex, SignedRecord,
    };
    use crate::types::AccountNum;

    /// A minimal signed record carrying `payload` at `seq`. The signature /
    /// hash fields are placeholders — the report renderer never verifies them
    /// (verification is the injected `VerificationStatus`), so a syntactically
    /// valid record is enough to exercise classification + rendering.
    fn rec(seq: u64, kind: EventKind, payload: EventPayload) -> SignedRecord {
        SignedRecord {
            schema_version: "2".into(),
            record_id: RecordId::try_new(format!("01JZ0000000000000000000{seq:03}")).unwrap(),
            chain_id: RecordId::try_new("01JZ00000000000000000000XY").unwrap(),
            seq,
            prev_hash: Sha256Hex::genesis(),
            kind,
            payload,
            ts: format!("2026-07-01T12:00:{seq:02}+00:00"),
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

    fn gov(
        seq: u64,
        class: &str,
        mut mutate: impl FnMut(&mut GovernanceTurnPayload),
    ) -> SignedRecord {
        let mut p = GovernanceTurnPayload {
            session_id: "sess-1".into(),
            record_seq: seq,
            event_class: class.into(),
            turn: 1,
            provider_id: None,
            failover_from: None,
            failover_reason: None,
            usage: None,
            justification_hash: None,
            justification_redacted: None,
            governance_reason: None,
            governed_at: None,
            kailash_canonical_hash: None,
            auth_mode: None,
            residency_verdict: None,
            residency_policy_name: None,
            residency_policy_hash: None,
        };
        mutate(&mut p);
        rec(
            seq,
            EventKind::GovernanceTurn,
            EventPayload::GovernanceTurn(p),
        )
    }

    /// M6 T6.2 Shard 4: MCP gate decisions classify as governed rows —
    /// `pass` → passed, `block`/`escalate` → blocked — so an auditor sees every
    /// gated tool-call on the compliance report (not silently in lifecycle).
    fn mcp_gate(seq: u64, tool: &str, verdict: &str) -> SignedRecord {
        rec(
            seq,
            EventKind::McpGateDecision,
            EventPayload::McpGateDecision(crate::audit::types::McpGateDecisionPayload {
                session_nonce: "mcp-proxy-1-ab".into(),
                record_seq: seq,
                cli: "codex".into(),
                tool: tool.into(),
                verdict: verdict.into(),
                enforcement_fidelity: "spawn_boundary_only".into(),
            }),
        )
    }

    #[test]
    fn mcp_gate_decisions_classify_as_governed_pass_and_block() {
        let records = vec![
            mcp_gate(0, "mcp__fs__read", "pass"),
            mcp_gate(1, "mcp__shell__exec", "block"),
            mcp_gate(2, "ksp_create", "escalate"),
        ];
        let report = classify_records(&records);
        assert_eq!(report.governed.len(), 3, "all three are governed rows");
        assert!(report.lifecycle.is_empty(), "none fall to lifecycle");
        assert_eq!(report.passed, 1, "one pass verdict");
        assert_eq!(report.blocked, 2, "block + escalate both count as blocked");
        // The governed row carries the fixed-vocab class + the verdict as decision.
        let block_row = report
            .governed
            .iter()
            .find(|r| r.decision == "block")
            .expect("a block row");
        assert_eq!(block_row.class, "mcp_gate_decision");
        assert!(
            block_row
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("spawn_boundary_only")),
            "detail names the honest fidelity: {:?}",
            block_row.detail
        );
    }

    #[test]
    fn policy_bundle_install_renders_as_lifecycle_row() {
        use crate::audit::types::{Ed25519PublicKey, PolicyBundleInstallPayload};
        let records = vec![rec(
            0,
            EventKind::PolicyBundleInstall,
            EventPayload::PolicyBundleInstall(PolicyBundleInstallPayload {
                bundle_version: 7,
                bundle_pubkey: Ed25519PublicKey::new([0xab; 32]),
                installed_at: "2026-07-04T00:00:00+00:00".to_string(),
            }),
        )];
        let report = classify_records(&records);
        assert!(
            report.governed.is_empty(),
            "PolicyBundleInstall is a lifecycle row, not governed"
        );
        assert_eq!(report.lifecycle.len(), 1, "one lifecycle row");
        assert_eq!(report.lifecycle[0].operation, "policy bundle install");
        // Detail cites the version + the 8-byte hex fingerprint of [0xab; 32].
        assert!(
            report.lifecycle[0].detail.contains("v7"),
            "detail names the bundle version: {:?}",
            report.lifecycle[0].detail
        );
        assert!(
            report.lifecycle[0].detail.contains("abababababababab"),
            "detail carries the 8-byte pubkey fingerprint: {:?}",
            report.lifecycle[0].detail
        );
    }

    #[test]
    fn classify_splits_governed_from_lifecycle() {
        let records = vec![
            rec(
                0,
                EventKind::CsqRun,
                EventPayload::CsqRun(crate::audit::types::CsqRunPayload {
                    run_id: "run-abc".into(),
                }),
            ),
            gov(1, "turn_completed", |_| {}),
            gov(2, "governance_failure", |p| {
                p.governance_reason = Some(crate::audit::types::RedactedString::from_trusted(
                    "rate cap exceeded",
                ));
            }),
        ];
        let report = classify_records(&records);
        assert_eq!(report.governed.len(), 2, "two GovernanceTurn records");
        assert_eq!(report.lifecycle.len(), 1, "one CsqRun record");
        assert_eq!(report.passed, 1);
        assert_eq!(report.blocked, 1);
        assert_eq!(report.overridden, 0);
        assert_eq!(report.lifecycle[0].operation, "csq run");
        assert_eq!(report.lifecycle[0].detail, "run run-abc");
    }

    #[test]
    fn override_justification_renders_from_redacted_field() {
        let records = vec![gov(1, "governance_override", |p| {
            p.justification_redacted = Some(crate::audit::types::RedactedString::from_trusted(
                "approved by compliance lead for incident INC-42",
            ));
        })];
        let report = classify_records(&records);
        assert_eq!(report.overridden, 1);
        assert_eq!(
            report.governed[0].detail.as_deref(),
            Some("approved by compliance lead for incident INC-42")
        );
        // Renders into the Markdown decision table.
        let md = report.render_markdown();
        assert!(md.contains("overridden"), "override decision label present");
        assert!(
            md.contains("approved by compliance lead for incident INC-42"),
            "override justification present in report"
        );
    }

    #[test]
    fn residency_pass_and_block_counted() {
        let records = vec![
            gov(1, "residency_enforcement", |p| {
                p.residency_verdict = Some("pass".into());
                p.provider_id = Some("claude".into());
                p.residency_policy_name = Some("eu-only".into());
            }),
            gov(2, "residency_enforcement", |p| {
                p.residency_verdict = Some("block".into());
                p.provider_id = Some("deepseek".into());
                p.residency_policy_name = Some("eu-only".into());
            }),
        ];
        let report = classify_records(&records);
        assert_eq!(report.passed, 1);
        assert_eq!(report.blocked, 1);
        assert!(report.governed[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("claude"));
    }

    #[test]
    fn unknown_residency_verdict_counts_as_block_fail_closed() {
        let records = vec![gov(1, "residency_enforcement", |p| {
            p.residency_verdict = Some("something_new".into());
        })];
        let report = classify_records(&records);
        assert_eq!(report.passed, 0, "unknown verdict is not a pass");
        assert_eq!(report.blocked, 1, "unknown verdict fails closed to block");
    }

    #[test]
    fn markdown_cell_escapes_pipe_and_newline() {
        let records = vec![gov(1, "governance_override", |p| {
            p.justification_redacted = Some(crate::audit::types::RedactedString::from_trusted(
                "line one | col two\nsecond line",
            ));
        })];
        let md = classify_records(&records).render_markdown();
        // The raw pipe/newline must not appear unescaped inside the row.
        assert!(md.contains("line one \\| col two second line"));
    }

    #[test]
    fn html_escapes_metacharacters() {
        let records = vec![gov(1, "governance_override", |p| {
            p.justification_redacted = Some(crate::audit::types::RedactedString::from_trusted(
                "<script>alert('x')</script> & more",
            ));
        })];
        let html = classify_records(&records).render_html();
        assert!(
            !html.contains("<script>alert"),
            "raw <script> must not appear in HTML output"
        );
        assert!(html.contains("&lt;script&gt;"), "angle brackets escaped");
        assert!(html.contains("&amp; more"), "ampersand escaped");
    }

    #[test]
    fn verification_status_projects_ok_and_err() {
        let ok = Ok(VerifySummary {
            verified_count: 7,
            head_seq: 6,
            ..VerifySummary::default()
        });
        let status = VerificationStatus::from_verify(&ok);
        assert!(status.is_verified());
        match status {
            VerificationStatus::Verified {
                verified_count,
                head_seq,
                ..
            } => {
                assert_eq!(verified_count, 7);
                assert_eq!(head_seq, 6);
            }
            _ => panic!("expected Verified"),
        }

        let err: Result<VerifySummary, LedgerError> = Err(LedgerError::Io {
            context: crate::audit::types::RedactedString::from_trusted("seq gap at 4"),
            source: std::io::Error::other("boom"),
        });
        let status = VerificationStatus::from_verify(&err);
        assert!(!status.is_verified());
        let md = ComplianceReport {
            chain_id: "c".into(),
            verification: status,
            governed: vec![],
            lifecycle: vec![],
            passed: 0,
            blocked: 0,
            overridden: 0,
            skipped_lines: 0,
        }
        .render_markdown();
        assert!(
            md.contains("UNVERIFIED"),
            "failed verification is prominent"
        );
    }

    #[test]
    fn empty_chain_renders_well_formed_report() {
        let report = classify_records(&[]);
        let md = report.render_markdown();
        assert!(md.contains("No governed decisions recorded"));
        assert!(md.contains("No lifecycle operations recorded"));
        let html = report.render_html();
        assert!(html.contains("</html>"));
    }

    #[test]
    fn account_swap_lifecycle_detail() {
        let records = vec![rec(
            0,
            EventKind::AccountSwap,
            EventPayload::AccountSwap(crate::audit::types::AccountSwapPayload {
                from_slot: AccountNum::try_from(2u16).unwrap(),
                to_slot: AccountNum::try_from(5u16).unwrap(),
            }),
        )];
        let report = classify_records(&records);
        assert_eq!(report.lifecycle[0].operation, "account swap");
        assert_eq!(report.lifecycle[0].detail, "slot 2 → 5");
    }

    #[test]
    fn informational_rows_are_listed_but_not_tallied() {
        // failover + turn_started are governed rows that carry no admit/deny
        // verdict: they land in `governed` but increment no counter, so
        // passed+blocked+overridden+informational == governed.len() (a total
        // partition — the Summary's arithmetic reconciles).
        let records = vec![
            gov(1, "turn_started", |_| {}),
            gov(2, "failover", |p| {
                p.failover_from = Some("claude".into());
                p.provider_id = Some("gemini".into());
                p.failover_reason = Some("rate_limited".into());
            }),
            gov(3, "turn_completed", |_| {}),
        ];
        let report = classify_records(&records);
        assert_eq!(report.governed.len(), 3);
        assert_eq!(report.passed, 1);
        assert_eq!(report.blocked, 0);
        assert_eq!(report.overridden, 0);
        assert_eq!(report.informational_count(), 2, "turn_started + failover");
        assert_eq!(
            report.passed + report.blocked + report.overridden + report.informational_count(),
            report.governed.len() as u64,
            "the four verdict buckets partition the governed rows"
        );
        // The failover detail renders its from → to (reason) shape.
        let md = report.render_markdown();
        assert!(md.contains("claude → gemini (rate_limited)"));
        assert!(
            md.contains("informational 2"),
            "summary shows the partition"
        );
    }

    #[test]
    fn skipped_lines_surfaced_in_header() {
        // A report carrying an unparseable-line count must announce the omission
        // (NIT-2: a compliance doc never under-reports silently).
        let report = ComplianceReport {
            chain_id: "c".into(),
            verification: VerificationStatus::Verified {
                verified_count: 1,
                head_seq: 0,
                no_key_gaps: true,
                keychain_anchor: "confirmed".into(),
                limit_exceeded_count: 0,
            },
            governed: vec![],
            lifecycle: vec![],
            passed: 0,
            blocked: 0,
            overridden: 0,
            skipped_lines: 3,
        };
        assert!(report
            .render_markdown()
            .contains("3 chain line(s) were unparseable"));
        assert!(report
            .render_html()
            .contains("3 chain line(s) were unparseable"));
        // The verified banner pins the covered seq range (AC4 binding).
        assert!(report.render_markdown().contains("seq 0..=0"));
    }

    #[test]
    fn empty_verified_chain_omits_records_covered_line() {
        // A VERIFIED-but-empty chain (verified_count == 0) must NOT print the
        // "Records covered: seq 0..=0" line — that would imply a record at seq 0.
        let report = ComplianceReport {
            chain_id: String::new(),
            verification: VerificationStatus::Verified {
                verified_count: 0,
                head_seq: 0,
                no_key_gaps: true,
                keychain_anchor: "confirmed".into(),
                limit_exceeded_count: 0,
            },
            governed: vec![],
            lifecycle: vec![],
            passed: 0,
            blocked: 0,
            overridden: 0,
            skipped_lines: 0,
        };
        assert!(!report.render_markdown().contains("Records covered"));
        assert!(!report.render_html().contains("Records covered"));
        // But the VERIFIED verdict itself is still present.
        assert!(report.render_markdown().contains("VERIFIED — 0 record(s)"));
    }

    #[test]
    fn partial_verify_tail_window_renders_honest_banner() {
        // A chain longer than the verifier's tail limit: only the tail was
        // verified, but the classifier lists ALL on-disk records. The header MUST
        // say "PARTIAL" and MUST NOT claim the full "seq 0..=head" range under a
        // clean VERIFIED banner (the R4 verification-honesty finding).
        let report = ComplianceReport {
            chain_id: "long-chain".into(),
            verification: VerificationStatus::Verified {
                verified_count: 10_000,
                head_seq: 14_999,
                no_key_gaps: true,
                keychain_anchor: "confirmed".into(),
                limit_exceeded_count: 5_000,
            },
            governed: vec![],
            lifecycle: vec![],
            passed: 0,
            blocked: 0,
            overridden: 0,
            skipped_lines: 0,
        };
        let md = report.render_markdown();
        assert!(
            md.contains("PARTIAL verification"),
            "partial banner present"
        );
        assert!(
            md.contains("5000 older record(s)"),
            "names the unverified older count"
        );
        assert!(
            !md.contains("Records covered:** seq 0..="),
            "must NOT claim the full seq 0..=head range on a partial verify"
        );
        let html = report.render_html();
        assert!(html.contains("PARTIAL verification"));
        assert!(!html.contains("Records covered:</strong> seq 0..="));
    }
}
