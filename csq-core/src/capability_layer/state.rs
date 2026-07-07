//! Pipeline state types per spec 10 §10.3.2.
//!
//! State types are **mutually exclusive families**: a stage that holds
//! `&mut PreSpawnState` cannot simultaneously hold `&PostSpawnState`,
//! and vice versa. This is what makes the
//! [`crate::capability_layer::pipeline::PipelineStage`] trait
//! ordering-correct at compile time.
//!
//! # Determinism by type (spec 10 §10.3.5)
//!
//! All map/set fields use `BTreeMap`/`BTreeSet`. This guarantees that
//! the cross-process determinism test in spec 10 §10.3.5 (40 binary
//! spawns × 4 surfaces, byte-identical) holds by construction.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::coc::translate::SurfaceArtifacts;

/// User prompt — the input to the pipeline before any classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPrompt {
    pub text: String,
}

/// Classifier verdict — set by the pre-scaffold classifier stage
/// (PR-CA7; stubbed at PR-CA4 — driver passes a default).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PromptClass {
    pub class: PromptClassKind,
    /// Confidence in `[0.0, 1.0]`. Below
    /// [`crate::capability_layer::errors::CLASSIFIER_THRESHOLD`] yields
    /// `StageError::ClassifierLowConfidence` AND defaults to
    /// `Compliance` per spec 10 §10.7.2 (fail-secure).
    pub conf: f32,
}

/// Two-class prompt classification per spec 10 §10.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptClassKind {
    /// Free-form chat. Compliance enforcement does not apply.
    FreeForm,
    /// Compliance prompt — RULE_ID-cited refusal expected on denied
    /// actions; structured-output enforcement applies.
    Compliance,
}

impl PromptClass {
    /// Default for PR-CA4 driver where the classifier stage is not
    /// yet wired. Per spec 10 §10.7.2 fail-secure rule, the safer
    /// default is `Compliance` with low confidence.
    pub const PR_CA4_DEFAULT: Self = Self {
        class: PromptClassKind::Compliance,
        conf: 0.0,
    };
}

/// Pre-spawn pipeline state — written by scaffold + MCP gate +
/// translator stages BEFORE the downstream CLI is spawned.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PreSpawnState {
    /// System-prompt scaffold built from the `CocSet`. `None` until
    /// [`crate::capability_layer::scaffold::ScaffoldStage`] runs.
    pub scaffold: Option<String>,
    /// MCP tool-name denylist intersection (`.coc/` policy ∩ user
    /// policy per spec 10 §10.8.2).
    pub mcp_filter: McpFilter,
    /// Per-kind flattened artifacts in scope for the target Surface
    /// (rules / agents / skills / commands), produced by the shared
    /// `coc::translate::flatten_artifacts` — the SAME flatten the
    /// scaffold's delivered prose (`scaffold`) is built from. CU1b (issue
    /// #764) establishes this as the substrate CU3's native-materialization
    /// leg extends: today only the prose blob is DELIVERED, but the
    /// per-kind breakdown (with full artifact bodies) is recorded here so
    /// CU3 can add a native-emit variant without re-architecting the
    /// pipeline state. Deterministic by construction — each list sorted
    /// `(precedence DESC, id ASC)` (spec 10 §10.3.5).
    pub artifacts: SurfaceArtifacts,
}

/// MCP gate filter — denylisted tool invocation names. The
/// intersection of `.coc/` MCP policy and the user's MCP policy
/// (spec 10 §10.8.2). Applied before spawn; rejected invocations emit
/// the structured `mcp_denied` audit record (spec 10 §10.8.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct McpFilter {
    pub denied: BTreeSet<String>,
}

/// Spawned-process handles. Pipe shapes are placeholder for PR-CA4 —
/// PR-CA5 wires the fork-vs-exec branch + PTY allocation per spec 10
/// §10.4.2.
#[derive(Debug)]
pub struct SpawnedState {
    pub pid: u32,
}

/// Post-spawn state — written by struct-out decode and post-validate
/// stages AFTER the downstream CLI returns output.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PostSpawnState {
    /// Raw stdout/stderr captured from the spawned CLI (with-layer
    /// fork+pipe path only — without-layer `exec` path bypasses the
    /// pipeline entirely per spec 10 §10.4.2).
    pub raw_output: String,
    /// Decoded structured-output fields, `None` until
    /// [`crate::capability_layer::struct_out::StructOutDecodeStage`]
    /// runs.
    pub decoded: Option<StructuredFields>,
}

/// Decoded structured-output fields per spec 10 §10.3.4
/// (`PostValidateFailed` consumes this).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StructuredFields {
    pub fields: BTreeMap<String, serde_json::Value>,
}

/// Persisted audit record per spec 10 §10.4.3. Written by the audit
/// emit stage at process Drop time (spec 10 §10.4.4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditState {
    pub run_id: String,
    pub fixture_sha: [u8; 32],
    pub coc_sha: [u8; 32],
    pub rule_ids_cited: BTreeSet<String>,
    pub decision: Decision,
}

impl AuditState {
    /// Empty audit record with deterministic zero hashes — used by
    /// the PR-CA4 driver where no real spawn or post-validation has
    /// occurred yet.
    pub fn pending(run_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            fixture_sha: [0u8; 32],
            coc_sha: [0u8; 32],
            rule_ids_cited: BTreeSet::new(),
            decision: Decision::Pending,
        }
    }
}

/// Pipeline outcome per spec 10 §10.3.4 (audit record `decision`
/// field). Driver and post-validation set this before audit emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Pipeline did not reach a terminal verdict (e.g. PR-CA4 stub
    /// abort before spawn).
    Pending,
    /// Compliance prompt accepted; downstream CLI invoked.
    Allowed,
    /// MCP denylist or post-validate rejected the invocation.
    Denied,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pre_spawn_state_default_is_empty() {
        let s = PreSpawnState::default();
        assert!(s.scaffold.is_none());
        assert!(s.mcp_filter.denied.is_empty());
        assert!(s.artifacts.is_empty());
    }

    #[test]
    fn audit_pending_has_zero_hashes() {
        let a = AuditState::pending("run-1");
        assert_eq!(a.run_id, "run-1");
        assert_eq!(a.fixture_sha, [0u8; 32]);
        assert_eq!(a.coc_sha, [0u8; 32]);
        assert_eq!(a.decision, Decision::Pending);
    }

    #[test]
    fn pr_ca4_default_class_is_compliance_with_zero_conf() {
        // Spec 10 §10.7.2 fail-secure: misclassified compliance is
        // worse than misclassified free-form, so the default routes
        // unknown prompts to compliance even at zero confidence.
        assert_eq!(
            PromptClass::PR_CA4_DEFAULT.class,
            PromptClassKind::Compliance
        );
        assert_eq!(PromptClass::PR_CA4_DEFAULT.conf, 0.0);
    }
}
