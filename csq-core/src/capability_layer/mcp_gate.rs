//! MCP gate (FR-CL-03) — csq-side prompt-edit interception.
//!
//! Authoritative spec: `specs/10-capability-layer-architecture.md`
//! §10.8 (coverage envelope, intersection-not-union, partial-coverage
//! warning, rejection records).
//!
//! # PR-CA6b ship state — minimal pass-through
//!
//! At PR-CA6b the stage is **real** but minimal: it leaves the
//! pre-spawn `McpFilter` at its default (empty `denied` set) and
//! returns `Ok(())`. The pipeline progresses past mcp_gate, so the
//! spawn step (just landed alongside in PR-CA6b) becomes reachable.
//!
//! The pass-through is correct under the v2.4.0-alpha shape because
//! no `.coc/tools/policy.json` reader exists yet — every translator
//! emits `McpFilter::default()` (see `csq-core/src/coc/translate/{cc,
//! codex,gemini}.rs`). Reading non-existent files would always yield
//! the empty filter, which is what we produce directly.
//!
//! # PR-CA6c — real intersection-not-union semantics
//!
//! PR-CA6c (blocked on a spec 09 Amendment H registering
//! `.coc/tools/policy.json`) replaces this body with:
//!
//! 1. Parse `.coc/tools/policy.json` into a `(allow, deny)` shape.
//! 2. Read the user's CLI-bound MCP policy (`~/.claude/mcp_settings.
//!    json` for cc; `~/.codex/mcp.toml` for codex; `~/.gemini/settings.
//!    json` for gemini).
//! 3. Compute the deny-union (per spec 10 §10.8.2 — a tool is allowed
//!    iff neither side denies it).
//! 4. Write the resulting denylist into `PreSpawnState::mcp_filter`.
//! 5. Spec 10 §10.8.4 rejection records (`mcp_denied` audit JSONL) at
//!    the spawn step's enforcement point.

use crate::capability_layer::errors::StageError;
use crate::capability_layer::pipeline::PipelineStage;
use crate::capability_layer::state::PreSpawnState;

/// Stable stage tag — used in structured-log events and exit-code
/// attribution. Consumers grep on this verbatim.
pub const STAGE: &str = "mcp_gate";

/// Marker type for the MCP gate stage.
pub struct McpGateStage;

impl PipelineStage for McpGateStage {
    type Reads = ();
    type Writes = PreSpawnState;

    fn run(_input: Self::Reads, output: &mut Self::Writes) -> Result<(), StageError> {
        // PR-CA6b pass-through: the default `McpFilter` is already
        // empty (see `state::PreSpawnState::default`). Touching the
        // field here is a no-op but the assignment makes the intent
        // explicit for a reader who lands on this file expecting to
        // see the filter populated.
        output.mcp_filter = Default::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_layer::state::McpFilter;

    /// PR-CA6b primary acceptance: the stage no longer aborts the
    /// pipeline. Returns `Ok(())` and leaves the filter empty so
    /// every tool invocation passes through untouched.
    #[test]
    fn mcp_gate_pass_through_returns_ok_and_leaves_filter_empty() {
        let mut state = PreSpawnState::default();
        let result = McpGateStage::run((), &mut state);
        assert!(
            result.is_ok(),
            "mcp_gate must not abort the pipeline at PR-CA6b: {result:?}"
        );
        assert_eq!(
            state.mcp_filter,
            McpFilter::default(),
            "filter must be the empty (pass-through) default"
        );
        assert!(
            state.mcp_filter.denied.is_empty(),
            "no tools should be denied under v2.4.0-alpha pass-through"
        );
    }

    /// PR-CA6b determinism: running the stage repeatedly produces
    /// byte-identical state (relevant when the cross-process
    /// determinism test in spec 10 §10.3.5 invokes the pipeline).
    #[test]
    fn mcp_gate_is_idempotent() {
        let mut a = PreSpawnState::default();
        let mut b = PreSpawnState::default();
        McpGateStage::run((), &mut a).unwrap();
        McpGateStage::run((), &mut b).unwrap();
        // Run b a second time; result MUST be identical to first run.
        McpGateStage::run((), &mut b).unwrap();
        assert_eq!(a, b);
    }

    /// PR-CA6c forward pointer: when the real impl lands, this test
    /// becomes the regression guard for "denylist applied without a
    /// policy file ⇒ empty filter (no spurious denies)". Until then
    /// it documents the contract.
    #[test]
    fn mcp_gate_no_policy_file_means_no_denies() {
        let mut state = PreSpawnState::default();
        McpGateStage::run((), &mut state).unwrap();
        assert!(
            state.mcp_filter.denied.is_empty(),
            "absence of `.coc/tools/policy.json` must not synthesize denies"
        );
    }
}
