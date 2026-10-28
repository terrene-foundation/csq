//! Capability-layer pipeline (Phase 2a).
//!
//! Authoritative spec: `specs/10-capability-layer-architecture.md`.
//! Scope of this module: in-process pipeline that sits between user
//! prompt and downstream invocation (cc / codex / gemini in Phase 2a;
//! direct provider API in Phase 2b — out of scope here).
//!
//! # PR-CA4 ship state
//!
//! This is the M3/PR-CA4 scaffold. Concretely:
//!
//! - [`pipeline::PipelineStage`] trait is materialized per spec 10 §10.3.
//! - [`state`] structs match spec 10 §10.3.2 (`UserPrompt`,
//!   `PreSpawnState`, `PostSpawnState`, etc.).
//! - [`errors::StageError`] enumerates the closed-set error taxonomy
//!   per spec 10 §10.3.4 with exit codes 20-29.
//! - [`scaffold::ScaffoldStage`] — rule-citation prompt assembly.
//! - [`mcp_gate::McpGateStage`] (real since PR-CA6b),
//!   [`struct_out::StructOutDecodeStage`] (real decoder since PR-CA7c),
//!   [`post_validate::PostValidateStage`] (real since PR-CA7b1) — all
//!   stages run without `StageError::StubUnimplemented`; the variant is
//!   retained only for future stage additions (see `driver.rs` static
//!   record + the `no_pipeline_stage_emits_stub_unimplemented_at_pr_ca7b1`
//!   guard test).
//! - [`driver::run_pre_spawn`] runs the pipeline and propagates the first
//!   stage error per the FR-CL-* ordering.
//!
//! # Compile-time stage ordering (spec 10 §10.3.3)
//!
//! Each stage declares `type Reads` and `type Writes` on the
//! [`pipeline::PipelineStage`] trait. The borrow checker enforces, at
//! compile time, that no stage holds `&mut PreSpawnState` and
//! `&PostSpawnState` simultaneously. Spec 10 §10.3.3 is the single
//! load-bearing invariant; it is enforced by the type system, not by
//! a runtime "scrambled order" test (per an internal journal entry).
//!
//! # Determinism (spec 10 §10.3.5)
//!
//! All maps in the [`state`] module are `BTreeMap`/`BTreeSet` —
//! determinism by type. PR-CA6+ stages MUST NOT introduce
//! `HashMap`/`HashSet` to `PipelineStage::Writes` shapes; the
//! `tests::no_hash_collections_in_state` static-grep test enforces
//! this without a project-wide clippy lint config (the lint exists in
//! spec 09 §9.2.5 + spec 10 §10.3.5 as text; the test materializes
//! it for the new module without touching the 215 existing
//! call-sites elsewhere in the workspace).

pub mod classifier;
pub mod driver;
pub mod errors;
pub mod instrumentation;
pub mod log_volume;
pub mod logging;
pub mod mcp_coverage;
pub mod mcp_gate;
pub mod pipeline;
pub mod post_validate;
pub mod preclassify;
pub mod scaffold;
pub mod settings;
pub mod state;
pub mod struct_out;

pub use classifier::{build_keyword_index, ClassifierInputs, ClassifierStage};
pub use driver::{
    extract_rule_ids_in_scope, run_post_spawn, run_post_spawn_toggled, run_pre_spawn,
    run_pre_spawn_toggled, run_with_layer, run_with_layer_toggled, LayerOutcome,
};
pub use errors::StageError;
pub use instrumentation::{
    drain_timings, emit_stage_timing, PipelineTimings, StageResult, StageTimer, StageTiming,
    STAGE_COC_LOAD, STAGE_COC_LOAD_COLD, STAGE_COMPLIANCE_REPAIR, STAGE_LAYER_TOTAL,
    STAGE_MCP_GATE, STAGE_POST_VALIDATE, STAGE_SCAFFOLD, STAGE_TRANSLATE_CC, STAGE_TRANSLATE_CODEX,
    STAGE_TRANSLATE_GEMINI,
};
pub use pipeline::PipelineStage;
pub use post_validate::{PostValidateInputs, PostValidateStage};
pub use preclassify::{PreClassifyInputs, PreClassifyStage, SpawnMode};
pub use settings::{
    load_capability_layer_toggles, save_capability_layer_toggles, CapabilityLayerToggles,
    CAPABILITY_LAYER_FILE,
};
pub use state::{
    AuditState, Decision, McpFilter, PostSpawnState, PreSpawnState, PromptClass, PromptClassKind,
    SpawnedState, StructuredFields, UserPrompt,
};
