//! Closed-set error taxonomy for the capability-layer pipeline.
//!
//! Authoritative spec: `specs/10-capability-layer-architecture.md`
//! §10.3.4 (variant catalog) + §10.6 (family taxonomy) + spec 03
//! §3.9 (exit-code reservation).
//!
//! Every variant maps to a unique exit code in `[20, 26]` (with
//! `[27, 29]` reserved for future stages); every variant has a
//! canonical UI surface text per `.claude/rules/tauri-commands.md`
//! MUST NOT Rule 6.

use crate::providers::catalog::Surface;

/// Compliance-classifier confidence threshold (spec 10 §10.7.1).
/// Confidence below this triggers `StageError::ClassifierLowConfidence`
/// AND defaults the class to `Compliance` per spec 10 §10.7.2.
pub const CLASSIFIER_THRESHOLD: f32 = 0.15;

/// Closed-set capability-layer error taxonomy.
///
/// `Display` produces the canonical UI surface text from spec 10
/// §10.3.4. `exit_code()` produces the spec 03 §3.9 reservation.
/// `tag()` produces the structured-log fixed-vocabulary tag (per
/// `.claude/rules/security.md` MUST Rule 2 — never echo internal
/// state into log messages).
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum StageError {
    /// PR-CA4 stub stages return this. The driver propagates it
    /// verbatim with exit code 20 + the stage name in the message
    /// per the journal-0012 round-2 action 4 mitigation.
    #[error("internal: stage `{stage}` not yet implemented (PR-CA4 trace)")]
    StubUnimplemented {
        /// Stable stage identifier — `scaffold`, `mcp_gate`,
        /// `struct_out_decode`, `post_validate`, `classifier`,
        /// `audit_emit`, etc.
        stage: &'static str,
    },

    /// `.coc/` parsed but scaffold construction failed (e.g. unknown
    /// `applies_to` Surface, or rule body exceeds vocabulary cap).
    #[error("scaffold construction failed: {reason}")]
    ScaffoldFailed { reason: String },

    /// MCP filter config invalid (e.g. denylist references a tool
    /// name with shell metacharacters or a duplicate denied entry).
    #[error("MCP gate config invalid: {reason}")]
    McpGateConfigInvalid { reason: String },

    /// Per-Surface translator failed (e.g. codex schema validation
    /// rejected the `.coc/` rule shape; gemini approval-mode
    /// constraint conflict).
    #[error("translation to {surface} failed: {reason}")]
    TranslateFailed { surface: Surface, reason: String },

    /// Post-validate detected non-compliance. Fail-closed on first
    /// attempt — there is no corrective re-prompt path (spec 10
    /// §10.1.4; sequential automatic retries are forbidden).
    #[error("post-validation failed: {reason}")]
    PostValidateFailed { reason: String },

    /// Classifier confidence below threshold; this is a **tagged
    /// success** per spec 10 §10.3.4 — DOES NOT abort the pipeline.
    /// The driver records this and continues with the fail-secure
    /// `Compliance` default.
    #[error("classifier confidence {conf} below {threshold}")]
    ClassifierLowConfidence { conf: f32, threshold: f32 },

    /// Layer total or any per-stage cap breached. Bench-gate on the
    /// release-tag CI uses this; production runs do NOT abort on
    /// latency breach alone (the CI gate is the enforcement point).
    #[error("stage {stage} took {observed_ms}ms (ceiling {ceiling_ms}ms)")]
    LatencyBudgetExceeded {
        stage: &'static str,
        observed_ms: u64,
        ceiling_ms: u64,
    },
}

impl StageError {
    /// Map to the spec 03 §3.9 exit code. Codes `[20, 26]` are
    /// allocated; `[27, 29]` are reserved for future error classes
    /// without re-mapping existing codes.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::StubUnimplemented { .. } => 20,
            Self::ScaffoldFailed { .. } => 21,
            Self::McpGateConfigInvalid { .. } => 22,
            Self::TranslateFailed { .. } => 23,
            Self::PostValidateFailed { .. } => 24,
            Self::ClassifierLowConfidence { .. } => 25,
            Self::LatencyBudgetExceeded { .. } => 26,
        }
    }

    /// Fixed-vocabulary log tag per `.claude/rules/security.md`
    /// MUST Rule 2. Used for structured `tracing` events; never
    /// formatted into log messages (which would echo internal
    /// state).
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::StubUnimplemented { .. } => "stub_unimplemented",
            Self::ScaffoldFailed { .. } => "capability_scaffold_failed",
            Self::McpGateConfigInvalid { .. } => "capability_mcp_invalid",
            Self::TranslateFailed { .. } => "cli_subprocess_translate",
            Self::PostValidateFailed { .. } => "capability_postvalidate_fail",
            Self::ClassifierLowConfidence { .. } => "classifier_low_confidence",
            Self::LatencyBudgetExceeded { .. } => "capability_latency_exceeded",
        }
    }

    /// Stage identifier when applicable (`StubUnimplemented`,
    /// `LatencyBudgetExceeded`). Returns `None` for variants whose
    /// stage attribution lives in the message (e.g. `ScaffoldFailed`).
    pub const fn stage(&self) -> Option<&'static str> {
        match self {
            Self::StubUnimplemented { stage } => Some(*stage),
            Self::LatencyBudgetExceeded { stage, .. } => Some(*stage),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_distinct_and_in_range() {
        // Distinctness — the spec table requires 20..=26 with no
        // collisions (27..=29 reserved per spec 03 §3.9).
        let codes = [
            StageError::StubUnimplemented { stage: "x" }.exit_code(),
            StageError::ScaffoldFailed {
                reason: String::new(),
            }
            .exit_code(),
            StageError::McpGateConfigInvalid {
                reason: String::new(),
            }
            .exit_code(),
            StageError::TranslateFailed {
                surface: Surface::ClaudeCode,
                reason: String::new(),
            }
            .exit_code(),
            StageError::PostValidateFailed {
                reason: String::new(),
            }
            .exit_code(),
            StageError::ClassifierLowConfidence {
                conf: 0.0,
                threshold: 0.15,
            }
            .exit_code(),
            StageError::LatencyBudgetExceeded {
                stage: "x",
                observed_ms: 0,
                ceiling_ms: 0,
            }
            .exit_code(),
        ];
        let mut sorted = codes;
        sorted.sort_unstable();
        assert_eq!(sorted, [20, 21, 22, 23, 24, 25, 26]);
        // Reserved range upper bound — none of the assigned codes
        // bleed into 27..=29 (reserved).
        for c in codes {
            assert!((20..=26).contains(&c), "exit code {c} out of 20..=26");
        }
    }

    #[test]
    fn tags_are_distinct_and_lowercase_snake() {
        let tags = [
            StageError::StubUnimplemented { stage: "x" }.tag(),
            StageError::ScaffoldFailed {
                reason: String::new(),
            }
            .tag(),
            StageError::McpGateConfigInvalid {
                reason: String::new(),
            }
            .tag(),
            StageError::TranslateFailed {
                surface: Surface::ClaudeCode,
                reason: String::new(),
            }
            .tag(),
            StageError::PostValidateFailed {
                reason: String::new(),
            }
            .tag(),
            StageError::ClassifierLowConfidence {
                conf: 0.0,
                threshold: 0.15,
            }
            .tag(),
            StageError::LatencyBudgetExceeded {
                stage: "x",
                observed_ms: 0,
                ceiling_ms: 0,
            }
            .tag(),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for t in tags {
            assert!(seen.insert(t), "duplicate tag: {t}");
            assert!(
                t.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "tag `{t}` is not lower_snake_case (security.md Rule 2)"
            );
        }
    }

    #[test]
    fn stub_unimplemented_message_names_the_stage() {
        // Round-2 action 4 (NEW-D1) acceptance — the stub error
        // message must name the unimplemented stage so the user
        // sees "stage `mcp_gate` not yet implemented" not just
        // "internal error".
        let e = StageError::StubUnimplemented { stage: "mcp_gate" };
        let msg = e.to_string();
        assert!(msg.contains("mcp_gate"), "stage name missing from `{msg}`");
        assert_eq!(e.stage(), Some("mcp_gate"));
        assert_eq!(e.exit_code(), 20);
    }

    #[test]
    fn classifier_low_conf_does_not_abort_intent_marker() {
        // Spec 10 §10.3.4 — exit code 25 is "tagged success", DOES
        // NOT abort. The exit code value itself documents this; the
        // driver semantics test in `driver.rs::tests` verifies the
        // continuation behavior at runtime.
        let e = StageError::ClassifierLowConfidence {
            conf: 0.1,
            threshold: 0.15,
        };
        assert_eq!(e.exit_code(), 25);
        assert_eq!(e.tag(), "classifier_low_confidence");
    }
}
