//! `PipelineStage` trait — load-bearing type contract per spec 10
//! §10.3.1.
//!
//! Each capability-layer stage declares the state it reads and the
//! state it writes via the associated types `Reads` and `Writes`.
//! Rust's borrow checker enforces ordering at compile time: a stage
//! that holds `&mut PreSpawnState` cannot simultaneously hold
//! `&PostSpawnState` because the state types are mutually exclusive
//! families per spec 10 §10.3.2.
//!
//! Spec 10 §10.3.3 — the single ordering invariant — is enforced by
//! the type system, not by a runtime "scrambled order" test.
//!
//! # Lifetime stance
//!
//! Spec 10 §10.3.1 declares the trait without a lifetime parameter
//! (matching here verbatim). For stages whose `Reads` borrow upstream
//! state, the impl block parametrizes its own lifetime via the stage
//! marker type or input struct (see [`super::scaffold::ScaffoldStage`]
//! for the canonical pattern). PR-CA6 may refactor to GATs if borrow
//! ergonomics need it; PR-CA4's stubs and the minimum-viable scaffold
//! impl do not.

use crate::capability_layer::errors::StageError;

/// One stage in the capability-layer pipeline.
///
/// `Reads` is the input — owned or borrowed depending on the impl.
/// `Writes` is the output target the stage mutates in place. The
/// `run` associated function is callable without a stage instance
/// because all stage marker types are zero-sized.
///
/// # Compile-time stage ordering
///
/// The orchestration in [`super::driver`] passes the right `Writes`
/// reference per stage. A stage that declares
/// `type Writes = PreSpawnState` cannot be invoked with a
/// `&mut PostSpawnState` (type mismatch). A stage that declares
/// `type Reads = PostSpawnState` cannot be invoked before the spawn
/// step has produced one. Both checks are compile-time.
pub trait PipelineStage {
    /// Read-only inputs to the stage.
    type Reads;
    /// Mutable output state the stage updates in place.
    type Writes;
    /// Run the stage. All shipped stages are real (no stage emits
    /// `StageError::StubUnimplemented` since PR-CA7b1; the variant is
    /// retained for future stage additions only).
    fn run(input: Self::Reads, output: &mut Self::Writes) -> Result<(), StageError>;
}
