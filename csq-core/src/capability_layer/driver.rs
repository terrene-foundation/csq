//! Pipeline driver — orchestrates [`super::PipelineStage`] invocations
//! in the canonical order from spec 10 §10.2.1:
//!
//! ```text
//! .coc/ load → classify(prompt) → scaffold → MCP gate → spawn →
//!     struct-out decode → post-validate → audit emit
//! ```
//!
//! # PR-CA4 scope
//!
//! Spawn is in PR-CA5. The driver here covers the **pre-spawn** half
//! (scaffold real-impl + mcp_gate stub) and exposes a thin entry
//! point for the **post-spawn** half (struct_out_decode +
//! post_validate stubs) so the `StubUnimplemented` propagation
//! pattern is exercised end-to-end without needing a real subprocess.
//!
//! # Compile-time stage ordering enforcement
//!
//! The driver's signatures pin which `&mut State` reference each
//! stage receives. A future contributor who writes a "post-spawn
//! stage that mutates pre-spawn state" cannot wire it in here —
//! `run_pre_spawn` only hands out `&mut PreSpawnState`, and
//! `run_post_spawn` only hands out `&mut PostSpawnState`. Reordering
//! to "post-validate before mcp_gate" would route `&mut
//! PostSpawnState` into a function that expects `&mut PreSpawnState`
//! and the borrow checker would reject the build.

use std::collections::BTreeSet;

use crate::capability_layer::classifier::{build_keyword_index, ClassifierInputs, ClassifierStage};
use crate::capability_layer::errors::StageError;
use crate::capability_layer::instrumentation::{
    emit_stage_timing, StageResult, StageTimer, STAGE_LAYER_TOTAL, STAGE_MCP_GATE,
    STAGE_POST_VALIDATE, STAGE_SCAFFOLD,
};
use crate::capability_layer::mcp_gate::McpGateStage;
use crate::capability_layer::pipeline::PipelineStage;
use crate::capability_layer::post_validate::{PostValidateInputs, PostValidateStage};
use crate::capability_layer::preclassify::{PreClassifyInputs, PreClassifyStage, SpawnMode};
use crate::capability_layer::scaffold::{ScaffoldInputs, ScaffoldStage};
use crate::capability_layer::settings::CapabilityLayerToggles;
use crate::capability_layer::state::{PostSpawnState, PreSpawnState, PromptClass, UserPrompt};
use crate::capability_layer::struct_out::StructOutDecodeStage;
use crate::coc::types::{CocSet, CocSource};
use crate::providers::catalog::Surface;

// Re-export `drain_timings` at driver level for csq-cli consumers.
pub use crate::capability_layer::instrumentation::drain_timings;

/// Run the pre-spawn pipeline half: scaffold (real) → mcp_gate
/// (real-but-minimal pass-through at PR-CA6b). Returns the populated
/// [`PreSpawnState`] on success or the first stage error encountered.
///
/// PR-CA6b promotes mcp_gate from stub to a pass-through implementation,
/// so the pre-spawn pipeline now succeeds for every input. Real
/// `.coc/`-policy intersection lands in PR-CA6c when the
/// `.coc/tools/policy.json` reader ships (gated on spec 09 Amendment H).
///
/// All techniques run unconditionally; for per-technique opt-out
/// (FR-CL-05) call [`run_pre_spawn_toggled`] instead.
pub fn run_pre_spawn(scaffold_inputs: ScaffoldInputs) -> Result<PreSpawnState, StageError> {
    run_pre_spawn_toggled(scaffold_inputs, &CapabilityLayerToggles::default())
}

/// Run the pre-spawn pipeline half with per-technique opt-out
/// honored. `toggles.disable_scaffold` skips
/// [`ScaffoldStage`] (state.scaffold stays `None` so no rule-citation
/// directive is appended). `toggles.disable_mcp_gate` skips
/// [`McpGateStage`] (state.mcp_filter stays at its allow-all
/// default). Stages that are skipped do NOT emit a timing record
/// (they did not run); the caller can detect skipped techniques by
/// inspecting the returned state shape.
pub fn run_pre_spawn_toggled(
    scaffold_inputs: ScaffoldInputs,
    toggles: &CapabilityLayerToggles,
) -> Result<PreSpawnState, StageError> {
    let mut state = PreSpawnState::default();

    // Scaffold stage. Skipped iff the user disabled scaffold via
    // `--no-scaffold` or via the desktop tray's "Scaffold" toggle.
    if !toggles.disable_scaffold {
        let t = StageTimer::start(STAGE_SCAFFOLD);
        let scaffold_result = ScaffoldStage::run(scaffold_inputs, &mut state);
        let timing = t.finish(match &scaffold_result {
            Ok(()) => StageResult::Applied,
            Err(_) => StageResult::Error,
        });
        emit_stage_timing(&timing);
        scaffold_result?;
    }

    // MCP gate stage. Skipped iff the user disabled mcp_gate via
    // `--no-mcp-gate` or via the desktop tray's "MCP gate" toggle.
    if !toggles.disable_mcp_gate {
        let t = StageTimer::start(STAGE_MCP_GATE);
        let mcp_result = McpGateStage::run((), &mut state);
        let timing = t.finish(match &mcp_result {
            Ok(()) => StageResult::Applied,
            Err(_) => StageResult::Error,
        });
        emit_stage_timing(&timing);
        mcp_result?;
    }

    Ok(state)
}

/// Outcome of [`run_with_layer`].
#[derive(Debug)]
pub enum LayerOutcome {
    /// Capability layer is OFF for this invocation. The caller falls
    /// through to the v2.3.1 bare-CLI launch path. This is the
    /// expected outcome when:
    /// - The user did not set `--capability-layer`.
    /// - The user set `--capability-layer` but `.coc/` resolution
    ///   produced `CocSource::Empty` (FR-RUN-04 graceful no-`.coc/`).
    Disabled,
    /// Capability layer ran the pre-spawn pipeline successfully and
    /// the spawn step should follow. PR-CA6b promoted mcp_gate from
    /// stub to pass-through, so this branch is now reachable for
    /// every populated `.coc/` invocation. The csq-cli caller maps
    /// `mode` to the spawn-step branch (one-shot piped capture vs
    /// interactive inherited-stdio per spec 10 §10.4.2).
    Enabled {
        /// Pre-spawn state populated by scaffold + mcp_gate. Boxed to keep the
        /// `LayerOutcome` enum small (`clippy::large_enum_variant`) — S2 grew
        /// `PreSpawnState` with `rules_only_scaffold`, tipping the size delta
        /// against the `Disabled` variant.
        pre_spawn: Box<PreSpawnState>,
        /// Spawn-mode dispatch decision from the pre-classifier.
        mode: SpawnMode,
        /// Prompt classifier verdict (FR-CL classifier; spec 10 §10.7).
        /// PR-CA7b1's post-validation gates on `class == Compliance`.
        class: PromptClass,
        /// RULE_IDs in scope for the target Surface (same filter as
        /// scaffold). PR-CA7b1's post-validation requires the model
        /// output to cite at least one when `class == Compliance` and
        /// the set is non-empty.
        rule_ids_in_scope: BTreeSet<String>,
    },
}

/// Run the capability-layer pre-flight in front of `csq run`'s spawn
/// step. The caller provides the resolved `CocSet`, the target
/// Surface, and the argv/stdin shape used for one-shot vs interactive
/// classification.
///
/// Returns:
/// - `Ok(LayerOutcome::Disabled)` when the layer is off for this
///   invocation (caller takes the v2.3.1 exec path).
/// - `Ok(LayerOutcome::Enabled { .. })` when the pre-spawn pipeline
///   succeeded (PR-CA6+ behavior; unreachable at PR-CA5).
/// - `Err(StageError)` when any stage in the pre-spawn pipeline
///   errored. The caller maps `err.exit_code()` to the process exit
///   code per spec 03 §3.9.
pub fn run_with_layer(
    enabled: bool,
    coc_set: CocSet,
    surface: Surface,
    argv: Vec<String>,
    stdin_is_tty: bool,
) -> Result<LayerOutcome, StageError> {
    run_with_layer_toggled(
        enabled,
        coc_set,
        surface,
        argv,
        stdin_is_tty,
        &CapabilityLayerToggles::default(),
    )
}

/// Like [`run_with_layer`] but honors per-technique opt-out
/// (FR-CL-05) from `toggles`. The full-disable case
/// (`toggles.is_layer_fully_disabled()`) short-circuits to
/// [`LayerOutcome::Disabled`] before doing any work.
pub fn run_with_layer_toggled(
    enabled: bool,
    coc_set: CocSet,
    surface: Surface,
    argv: Vec<String>,
    stdin_is_tty: bool,
    toggles: &CapabilityLayerToggles,
) -> Result<LayerOutcome, StageError> {
    if !enabled || toggles.is_layer_fully_disabled() {
        return Ok(LayerOutcome::Disabled);
    }
    // FR-RUN-04 — empty .coc/ disables the layer for this invocation
    // (spec 10 §10.1.2). Legacy sources keep the layer active so the
    // legacy translator path can run; only literal `Empty` falls
    // through.
    if matches!(coc_set.source, CocSource::Empty) {
        return Ok(LayerOutcome::Disabled);
    }

    // cap.layer_total timer wraps the entire pre-spawn pipeline
    // (design 08 §1.1 — ceiling enforced at NFR-PERF-01; the
    // compliance-repair stage is OUTSIDE this timer per finding B20).
    let layer_total_timer = StageTimer::start(STAGE_LAYER_TOTAL);

    // Pre-classifier (spawn-mode) — argv inspection only, never errors.
    // CU2 (an internal ticket): `surface` is now threaded in so the classifier
    // can use surface-specific one-shot detection (Gemini `--prompt` vs
    // CC `--print`/`-p`).
    let mut mode = SpawnMode::default();
    PreClassifyStage::run(
        PreClassifyInputs {
            argv: argv.clone(),
            stdin_is_tty,
            surface,
        },
        &mut mode,
    )?;

    // Prompt classifier (FR-CL classifier; spec 10 §10.7) — runs
    // BEFORE scaffold per the canonical order in spec 10 §10.2.1.
    // Extracts the prompt from one-shot argv (`--print` / `-p`); for
    // interactive launches the prompt is empty here and the
    // classifier falls through to its fail-secure Compliance default
    // because csq cannot see the per-turn prompt at preflight.
    // PR-CA7b moves classification per-turn for the interactive path
    // when the post-validation PTY shape lands.
    let prompt = extract_prompt_from_argv(&argv);
    let keywords = build_keyword_index(&coc_set, surface);
    let mut class = PromptClass::PR_CA4_DEFAULT;
    match ClassifierStage::run(
        ClassifierInputs {
            prompt: prompt.clone(),
            keywords,
        },
        &mut class,
    ) {
        Ok(()) => {}
        Err(StageError::ClassifierLowConfidence { .. }) => {
            // Spec 10 §10.7.2 + §10.3.4 — tagged success. The
            // classifier already populated `class` with the
            // fail-secure Compliance default; the driver records
            // the low-confidence signal for audit (PR-CA7d
            // surfaces it via `--debug`) and continues.
        }
        Err(other) => {
            // Layer total records Error on early abort.
            let timing = layer_total_timer.finish(StageResult::Error);
            emit_stage_timing(&timing);
            return Err(other);
        }
    }

    // Extract the in-scope RULE_ID set BEFORE moving `coc_set` into
    // ScaffoldInputs. PR-CA7b1's post-validation needs this to verify
    // the model cited at least one in-scope rule when `class ==
    // Compliance`. Same Surface filter scaffold uses — divergence
    // would mean a rule appears in the scaffold but is not required
    // for citation (or vice versa), a class of silent inconsistency
    // the harness wouldn't catch.
    let rule_ids_in_scope = extract_rule_ids_in_scope(&coc_set, surface);

    // Pre-spawn pipeline (scaffold real → mcp_gate pass-through at
    // PR-CA6b). The classified `class` flows through to scaffold so
    // PR-CA7b1's post-validation can branch on it. Per-technique
    // opt-out (`toggles.disable_scaffold`, `toggles.disable_mcp_gate`)
    // is honored inside `run_pre_spawn_toggled`.
    let scaffold_inputs = ScaffoldInputs {
        coc_set,
        prompt,
        class,
        surface,
    };
    let pre_spawn = match run_pre_spawn_toggled(scaffold_inputs, toggles) {
        Ok(s) => s,
        Err(e) => {
            let timing = layer_total_timer.finish(StageResult::Error);
            emit_stage_timing(&timing);
            return Err(e);
        }
    };

    // Emit layer-total timing (Applied = pipeline completed successfully).
    let timing = layer_total_timer.finish(StageResult::Applied);
    emit_stage_timing(&timing);

    Ok(LayerOutcome::Enabled {
        pre_spawn: Box::new(pre_spawn),
        mode,
        class,
        rule_ids_in_scope,
    })
}

/// Extract RULE_IDs from `coc_set` whose `applies_to` is empty
/// (universal) or contains the target `surface`. Shares the single
/// surface-scope predicate `crate::coc::translate::flatten::in_scope` with
/// the scaffold's full-body flatten (`flatten_artifacts`), so the rules
/// that appear in the delivered scaffold are EXACTLY the rules required for
/// citation — they cannot drift (redteam R1 DA-2). This produces a
/// rules-only ID *set*, a different output than the full-body flatten, which
/// is why the two functions stay distinct (CU1b boundary note); only the
/// predicate is shared.
///
/// Pure function; deterministic by `BTreeMap` iteration order +
/// `BTreeSet` collection (spec 10 §10.3.5).
pub fn extract_rule_ids_in_scope(coc_set: &CocSet, surface: Surface) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (rule_id, rule) in &coc_set.rules {
        if crate::coc::translate::flatten::in_scope(&rule.applies_to, surface) {
            out.insert(rule_id.as_str().to_string());
        }
    }
    out
}

/// Extract a one-shot prompt from argv. Recognizes:
///
/// - CC/Codex: `--print PROMPT`, `--print=PROMPT`, `-p PROMPT`,
///   `-pPROMPT` short combinator.
/// - Gemini (CU2, an internal ticket): `--prompt PROMPT`, `--prompt=PROMPT`.
///
/// Surface-agnostic extraction is correct here: only Gemini argv
/// carries `--prompt`, and only CC argv carries `--print`/`-p`, so
/// there is no cross-surface ambiguity in practice. Returns an empty
/// `UserPrompt` for interactive launches — the classifier's
/// fail-secure path then handles them.
///
/// Pure function; deterministic; no side effects.
fn extract_prompt_from_argv(argv: &[String]) -> UserPrompt {
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        // CC / Codex: space-separated `--print PROMPT` or `-p PROMPT`.
        if arg == "--print" || arg == "-p" {
            // Next arg is the prompt; if missing, return empty.
            if let Some(next) = iter.next() {
                return UserPrompt { text: next.clone() };
            }
            return UserPrompt {
                text: String::new(),
            };
        }
        if let Some(rest) = arg.strip_prefix("--print=") {
            return UserPrompt {
                text: rest.to_string(),
            };
        }
        // CC `-pX` short combinator (no space). Same `-p` test the
        // pre-classifier uses for one-shot mode (spec 10 §10.4.2).
        if arg.starts_with("-p") && !arg.starts_with("--") && arg.len() > 2 {
            return UserPrompt {
                text: arg[2..].to_string(),
            };
        }
        // Gemini (CU2): `--prompt PROMPT` space-separated form.
        if arg == "--prompt" {
            if let Some(next) = iter.next() {
                return UserPrompt { text: next.clone() };
            }
            return UserPrompt {
                text: String::new(),
            };
        }
        // Gemini (CU2): `--prompt=PROMPT` single-arg form.
        if let Some(rest) = arg.strip_prefix("--prompt=") {
            return UserPrompt {
                text: rest.to_string(),
            };
        }
    }
    UserPrompt {
        text: String::new(),
    }
}

/// Run the post-spawn pipeline half: `struct_out_decode` (pass-through
/// at PR-CA7b1) → `post_validate` (real at PR-CA7b1).
///
/// `class` is the prompt classifier's verdict (gates post-validate per
/// spec 10 §10.7); `rule_ids_in_scope` is the surface-filtered RULE_ID
/// set the post-validate citation check requires when `class ==
/// Compliance`.
///
/// Returns the populated [`PostSpawnState`] on success or the first
/// stage error encountered. `StageError::PostValidateFailed` (exit 24)
/// is the failure shape when the model output is missing the citation
/// or contains role-confusion patterns.
pub fn run_post_spawn(
    raw_output: String,
    class: PromptClass,
    rule_ids_in_scope: BTreeSet<String>,
) -> Result<PostSpawnState, StageError> {
    run_post_spawn_toggled(
        raw_output,
        class,
        rule_ids_in_scope,
        &CapabilityLayerToggles::default(),
    )
}

/// Like [`run_post_spawn`] but honors per-technique opt-out
/// (FR-CL-05) from `toggles`. `toggles.disable_struct_out` skips the
/// JSON envelope decoder so post-validate falls back to the substring
/// citation match. `toggles.disable_post_validate` skips the
/// post-validate stage entirely — the captured CC output passes
/// through unchecked, mirroring the v2.3.1 behavior for that
/// technique.
pub fn run_post_spawn_toggled(
    raw_output: String,
    class: PromptClass,
    rule_ids_in_scope: BTreeSet<String>,
    toggles: &CapabilityLayerToggles,
) -> Result<PostSpawnState, StageError> {
    let mut state = PostSpawnState {
        raw_output,
        decoded: None,
    };

    // struct_out decode (pass-through at PR-CA7b1). Skipped iff the
    // user disabled struct-out via `--no-structured-output` or the
    // desktop tray's "Structured output" toggle. Runs silently (no
    // timer) until a future STAGE_STRUCT_OUT constant lands.
    if !toggles.disable_struct_out {
        StructOutDecodeStage::run((), &mut state)?;
    }

    // Post-validate stage. Skipped iff the user disabled
    // post-validate via `--no-post-validate` or the desktop tray's
    // "Post-validate" toggle.
    if !toggles.disable_post_validate {
        let t = StageTimer::start(STAGE_POST_VALIDATE);
        let pv_result = PostValidateStage::run(
            PostValidateInputs {
                class,
                rule_ids_in_scope,
            },
            &mut state,
        );
        let timing = t.finish(match &pv_result {
            Ok(()) => StageResult::Applied,
            Err(_) => StageResult::Error,
        });
        emit_stage_timing(&timing);
        pv_result?;
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_layer::state::{PromptClass, UserPrompt};
    use crate::coc::types::{CocSet, RuleDef, RuleId};
    use crate::providers::catalog::Surface;
    use std::collections::{BTreeMap, BTreeSet};

    fn one_rule_set() -> CocSet {
        let id = RuleId::parse("RULE-NO-PII").unwrap();
        let mut rules = BTreeMap::new();
        rules.insert(
            id.clone(),
            RuleDef {
                id,
                paths: Vec::new(),
                applies_to: BTreeSet::new(),
                precedence: 0,
                disable: BTreeSet::new(),
                body: "Do not echo PII verbatim.".into(),
                unknowns: BTreeMap::new(),
            },
        );
        let mut set = CocSet::empty();
        set.rules = rules;
        set
    }

    /// PR-CA6b primary acceptance: pre-spawn pipeline runs to
    /// completion (scaffold real → mcp_gate pass-through). The
    /// returned state has scaffold populated and an empty mcp_filter.
    ///
    /// Replaces the PR-CA4 test that asserted the mcp_gate stub
    /// aborted with exit 20 — that abort is gone in PR-CA6b. The
    /// "stub propagates with stage name" contract still applies to
    /// the post-spawn stub stages (struct_out_decode, post_validate);
    /// see `post_spawn_propagates_first_stub_in_order` below.
    #[test]
    fn pre_spawn_completes_to_populated_state() {
        let inputs = ScaffoldInputs {
            coc_set: one_rule_set(),
            prompt: UserPrompt {
                text: "ignored".into(),
            },
            class: PromptClass::PR_CA4_DEFAULT,
            surface: Surface::ClaudeCode,
        };
        let state = run_pre_spawn(inputs).expect("pre-spawn must succeed at PR-CA6b");
        assert!(
            state.scaffold.is_some(),
            "scaffold real-impl must populate `state.scaffold`"
        );
        let scaffold_text = state.scaffold.as_deref().unwrap();
        assert!(
            scaffold_text.contains("RULE-NO-PII"),
            "scaffold must cite the test rule: {scaffold_text}"
        );
        assert!(
            state.mcp_filter.denied.is_empty(),
            "mcp_gate pass-through must leave `denied` empty (PR-CA6c populates it)"
        );
    }

    /// PR-CA7b1 acceptance: post-spawn pipeline runs to completion
    /// when class is FreeForm — struct_out passes through, post_validate
    /// skips. Replaces the PR-CA6b `post_spawn_propagates_first_stub_in_order`
    /// test (struct_out is no longer a stub).
    #[test]
    fn post_spawn_freeform_class_completes_with_struct_out_pass_through() {
        let class = PromptClass {
            class: crate::capability_layer::state::PromptClassKind::FreeForm,
            conf: 0.9,
        };
        let state = run_post_spawn("free-form chat output".into(), class, BTreeSet::new())
            .expect("FreeForm post-spawn must complete");
        assert_eq!(state.raw_output, "free-form chat output");
        // struct_out pass-through leaves decoded=None; post_validate
        // skips on FreeForm without populating decoded either.
        assert!(state.decoded.is_none());
    }

    /// PR-CA7b1 acceptance: Compliance class with citation passes
    /// post-spawn end-to-end; decoded carries the cited RULE_IDs.
    #[test]
    fn post_spawn_compliance_with_citation_succeeds() {
        let class = PromptClass {
            class: crate::capability_layer::state::PromptClassKind::Compliance,
            conf: 0.9,
        };
        let mut rule_ids = BTreeSet::new();
        rule_ids.insert("RULE-NO-PII".to_string());
        let state = run_post_spawn(
            "Per RULE-NO-PII I refuse to echo the data.".into(),
            class,
            rule_ids,
        )
        .expect("citation present must succeed");
        let decoded = state.decoded.expect("decoded populated on success");
        assert_eq!(
            decoded.fields.get("rule_ids_cited").unwrap(),
            &serde_json::json!(["RULE-NO-PII"])
        );
    }

    /// PR-CA7b1 acceptance: Compliance class without citation aborts
    /// with PostValidateFailed (exit 24).
    #[test]
    fn post_spawn_compliance_without_citation_fails_with_exit_24() {
        let class = PromptClass {
            class: crate::capability_layer::state::PromptClassKind::Compliance,
            conf: 0.9,
        };
        let mut rule_ids = BTreeSet::new();
        rule_ids.insert("RULE-NO-PII".to_string());
        let err = run_post_spawn("Sure, here is the data.".into(), class, rule_ids).unwrap_err();
        assert_eq!(err.exit_code(), 24);
        match &err {
            StageError::PostValidateFailed { reason } => {
                assert!(
                    reason.contains("RULE_ID"),
                    "reason must explain the missing citation: {reason}"
                );
            }
            other => panic!("expected PostValidateFailed, got {other:?}"),
        }
    }

    /// Static record: at PR-CA7b1 ship there are NO remaining stub
    /// stages in the pipeline. struct_out (CA7b1) and mcp_gate (CA6b)
    /// are pass-throughs; scaffold + classifier + post_validate are
    /// real. The `StubUnimplemented` variant remains in the enum for
    /// future stage additions but no live stage emits it.
    #[test]
    fn no_pipeline_stage_emits_stub_unimplemented_at_pr_ca7b1() {
        // Exercise every stage's `Writes` path with minimal inputs;
        // assert none returns StubUnimplemented.
        let mut pre = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: one_rule_set(),
                prompt: UserPrompt {
                    text: "ignored".into(),
                },
                class: PromptClass::PR_CA4_DEFAULT,
                surface: Surface::ClaudeCode,
            },
            &mut pre,
        )
        .unwrap();
        McpGateStage::run((), &mut pre).unwrap();

        let mut post = PostSpawnState::default();
        StructOutDecodeStage::run((), &mut post).unwrap();
        PostValidateStage::run(
            PostValidateInputs {
                class: PromptClass {
                    class: crate::capability_layer::state::PromptClassKind::FreeForm,
                    conf: 0.9,
                },
                rule_ids_in_scope: BTreeSet::new(),
            },
            &mut post,
        )
        .unwrap();
    }

    /// PR-CA5 acceptance: layer disabled → caller falls through to
    /// the v2.3.1 path (no pipeline cost).
    #[test]
    fn run_with_layer_disabled_short_circuits_to_disabled_outcome() {
        // enabled=false bypasses everything regardless of CocSet.
        let outcome =
            run_with_layer(false, one_rule_set(), Surface::ClaudeCode, vec![], true).unwrap();
        assert!(matches!(outcome, LayerOutcome::Disabled));
    }

    /// FR-RUN-04: even when --capability-layer is set, an empty
    /// `.coc/` source disables the layer for that invocation. No
    /// stage error, no pipeline run.
    #[test]
    fn run_with_layer_empty_coc_source_falls_through() {
        let mut empty = CocSet::empty();
        // CocSet::empty() already sets source = Empty, but be
        // explicit for the test.
        empty.source = CocSource::Empty;
        let outcome = run_with_layer(true, empty, Surface::ClaudeCode, vec![], true).unwrap();
        assert!(matches!(outcome, LayerOutcome::Disabled));
    }

    /// PR-CA6b acceptance: enabled + populated CocSet now reaches
    /// `LayerOutcome::Enabled` (the mcp_gate stub abort is gone). The
    /// pre-classifier's `SpawnMode` is recorded on the outcome so the
    /// csq-cli caller can dispatch one-shot vs interactive.
    #[test]
    fn run_with_layer_populated_coc_reaches_enabled_with_classified_mode() {
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        let outcome = run_with_layer(
            true,
            populated,
            Surface::ClaudeCode,
            vec!["--print".into()],
            true,
        )
        .expect("PR-CA6b: pre-spawn pipeline must succeed end-to-end");
        match outcome {
            LayerOutcome::Enabled {
                pre_spawn,
                mode,
                rule_ids_in_scope,
                ..
            } => {
                // `--print` argv ⇒ one-shot per spec 10 §10.4.2.
                assert_eq!(
                    mode,
                    crate::capability_layer::preclassify::SpawnMode::OneShot,
                    "argv `--print` must classify as one-shot"
                );
                assert!(
                    pre_spawn.scaffold.is_some(),
                    "scaffold must be populated by the time spawn dispatches"
                );
                assert!(
                    pre_spawn.mcp_filter.denied.is_empty(),
                    "PR-CA6b mcp_gate is a pass-through; no denies"
                );
                // PR-CA7b1: in-scope RULE_IDs flow back to the caller
                // so post-validate can require citation. The single-rule
                // fixture must surface here.
                assert!(
                    rule_ids_in_scope.contains("RULE-NO-PII"),
                    "in-scope RULE_IDs must include the surface-filtered fixture"
                );
            }
            LayerOutcome::Disabled => {
                panic!(
                    "PR-CA6b: populated `.coc/` + enabled flag must reach Enabled, not Disabled"
                );
            }
        }
    }

    /// PR-CA6b: interactive classification reaches the same Enabled
    /// outcome but with `SpawnMode::Interactive`, which the csq-cli
    /// caller routes to the inherited-stdio path (PR-CA6b) or the
    /// PTY-allocated path (PR-CA7+).
    #[test]
    fn run_with_layer_populated_coc_classifies_interactive_when_no_print_flag() {
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        let outcome = run_with_layer(
            true,
            populated,
            Surface::ClaudeCode,
            // No `--print` / `-p` and stdin IS a TTY ⇒ interactive.
            Vec::new(),
            true,
        )
        .expect("interactive classification must complete the pipeline");
        match outcome {
            LayerOutcome::Enabled { mode, .. } => {
                assert_eq!(
                    mode,
                    crate::capability_layer::preclassify::SpawnMode::Interactive
                );
            }
            LayerOutcome::Disabled => panic!("expected Enabled outcome"),
        }
    }

    /// PR-CA7a: `--print PROMPT` extracts the prompt and the
    /// classifier's keyword index (built from `RULE-NO-PII`) hits
    /// "pii" in the prompt, producing a high-confidence Compliance
    /// classification. Verifies the classifier-driver wire-up.
    #[test]
    fn run_with_layer_one_shot_compliance_prompt_classifies_compliance() {
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        let outcome = run_with_layer(
            true,
            populated,
            Surface::ClaudeCode,
            vec![
                "--print".into(),
                "Will my PII PII PII end up in the audit log?".into(),
            ],
            // stdin TTY irrelevant when --print present.
            true,
        )
        .expect("classifier wire-up must complete the pipeline");
        // Pipeline must reach Enabled regardless of classifier verdict
        // (low-confidence is a tagged success per spec 10 §10.7.2).
        assert!(matches!(outcome, LayerOutcome::Enabled { .. }));
    }

    /// PR-CA7a: low-confidence classifier verdict (interactive path
    /// where prompt is empty at preflight) does NOT abort the
    /// pipeline. Spec 10 §10.7.2 fail-secure tagged success.
    #[test]
    fn run_with_layer_low_confidence_does_not_abort() {
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        // Empty argv (interactive launch) ⇒ extract_prompt_from_argv
        // returns an empty UserPrompt ⇒ classifier returns
        // ClassifierLowConfidence as tagged success ⇒ driver continues.
        let outcome = run_with_layer(true, populated, Surface::ClaudeCode, Vec::new(), true);
        assert!(
            outcome.is_ok(),
            "low-confidence classifier verdict must not abort: {outcome:?}"
        );
        match outcome.unwrap() {
            LayerOutcome::Enabled { pre_spawn, .. } => {
                // Scaffold ran; pipeline progressed past the classifier.
                assert!(pre_spawn.scaffold.is_some());
            }
            LayerOutcome::Disabled => panic!("expected Enabled outcome"),
        }
    }

    /// PR-CA7a + CU2: `extract_prompt_from_argv` recognizes all
    /// supported one-shot forms — CC/Codex and Gemini.
    #[test]
    fn extract_prompt_from_argv_recognizes_all_one_shot_forms() {
        let cases: &[(&[&str], &str)] = &[
            // CC / Codex forms (unchanged)
            (&["--print", "hello world"], "hello world"),
            (&["--print=hello world"], "hello world"),
            (&["-p", "hello world"], "hello world"),
            (&["-phello"], "hello"),
            (&[], ""),
            (&["--resume"], ""), // unrelated flag
            // Gemini forms (CU2, an internal ticket)
            (&["--prompt", "gemini query"], "gemini query"),
            (&["--prompt=gemini query"], "gemini query"),
            (&["--prompt="], ""), // empty prompt= form
        ];
        for (argv_strs, expected) in cases {
            let argv: Vec<String> = argv_strs.iter().map(|s| s.to_string()).collect();
            let prompt = extract_prompt_from_argv(&argv);
            assert_eq!(
                prompt.text, *expected,
                "argv {argv:?} must extract prompt {expected:?}, got {:?}",
                prompt.text
            );
        }
    }

    /// PR-CA7b1: `extract_rule_ids_in_scope` includes a rule with
    /// empty `applies_to` (universal) for every Surface, AND a rule
    /// whose `applies_to` lists the target Surface explicitly.
    #[test]
    fn extract_rule_ids_in_scope_includes_universal_and_surface_specific() {
        use crate::coc::types::{RuleDef, RuleId};

        let mut set = CocSet::empty();
        // Universal rule — no applies_to.
        let id_universal = RuleId::parse("RULE-UNIVERSAL").unwrap();
        set.rules.insert(
            id_universal.clone(),
            RuleDef {
                id: id_universal,
                paths: Vec::new(),
                applies_to: BTreeSet::new(),
                precedence: 0,
                disable: BTreeSet::new(),
                body: "universal body".into(),
                unknowns: std::collections::BTreeMap::new(),
            },
        );
        // CC-only rule.
        let id_cc = RuleId::parse("RULE-CC-ONLY").unwrap();
        let mut cc_applies = BTreeSet::new();
        cc_applies.insert(Surface::ClaudeCode);
        set.rules.insert(
            id_cc.clone(),
            RuleDef {
                id: id_cc,
                paths: Vec::new(),
                applies_to: cc_applies,
                precedence: 0,
                disable: BTreeSet::new(),
                body: "cc-only body".into(),
                unknowns: std::collections::BTreeMap::new(),
            },
        );

        let cc = extract_rule_ids_in_scope(&set, Surface::ClaudeCode);
        assert!(cc.contains("RULE-UNIVERSAL"), "universal must apply to cc");
        assert!(
            cc.contains("RULE-CC-ONLY"),
            "cc-specific must apply to its surface"
        );

        let codex = extract_rule_ids_in_scope(&set, Surface::Codex);
        assert!(
            codex.contains("RULE-UNIVERSAL"),
            "universal must apply to codex"
        );
        assert!(
            !codex.contains("RULE-CC-ONLY"),
            "cc-specific must NOT apply to codex"
        );
    }

    /// PR-CA7b1: `LayerOutcome::Enabled` carries the classifier
    /// verdict + in-scope RULE_IDs end-to-end so the csq-cli caller
    /// can run post-validate on captured one-shot output without
    /// re-deriving them.
    #[test]
    fn run_with_layer_enabled_outcome_carries_class_and_rule_ids() {
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        let outcome = run_with_layer(
            true,
            populated,
            Surface::ClaudeCode,
            vec!["--print".into(), "Will my PII be logged?".into()],
            true,
        )
        .expect("populated .coc/ must reach Enabled");
        match outcome {
            LayerOutcome::Enabled {
                class,
                rule_ids_in_scope,
                ..
            } => {
                // Classifier had a real prompt + matching keyword
                // (`pii` from RULE-NO-PII tokens), so confidence MAY
                // exceed threshold and we get Compliance with conf > 0.
                // BUT the fail-secure default is also Compliance, so
                // either path produces the same `class` value here.
                assert_eq!(
                    class.class,
                    crate::capability_layer::state::PromptClassKind::Compliance,
                    "compliance fixture or fail-secure default both yield Compliance"
                );
                assert!(rule_ids_in_scope.contains("RULE-NO-PII"));
            }
            LayerOutcome::Disabled => panic!("expected Enabled outcome"),
        }
    }

    // ====================================================================
    // T10 instrumentation tests (PR-CA9b Group 3)
    // ====================================================================

    /// After `run_with_layer` on a populated CocSet, `drain_timings` must
    /// return at least one timing per pipeline stage that ran:
    /// scaffold, mcp_gate, and layer_total. The closed-set constant
    /// values are the contract bench scripts depend on.
    #[test]
    fn run_with_layer_emits_stage_timing_for_every_stage() {
        use crate::capability_layer::instrumentation::{
            drain_timings, ALL_STAGE_IDS, STAGE_LAYER_TOTAL, STAGE_MCP_GATE, STAGE_SCAFFOLD,
        };
        use std::collections::BTreeSet;

        // Drain any residue from prior tests.
        drain_timings();

        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        run_with_layer(true, populated, Surface::ClaudeCode, vec![], true)
            .expect("pipeline must complete");

        let result = drain_timings();
        let emitted_ids: BTreeSet<&str> = result.timings.iter().map(|t| t.stage_id).collect();

        // These three stages MUST emit timings on every successful run_with_layer.
        assert!(
            emitted_ids.contains(STAGE_SCAFFOLD),
            "scaffold stage must emit timing; got: {:?}",
            emitted_ids
        );
        assert!(
            emitted_ids.contains(STAGE_MCP_GATE),
            "mcp_gate stage must emit timing; got: {:?}",
            emitted_ids
        );
        assert!(
            emitted_ids.contains(STAGE_LAYER_TOTAL),
            "layer_total must emit timing; got: {:?}",
            emitted_ids
        );

        // Every emitted stage_id must be a member of the closed set.
        let closed: BTreeSet<&str> = ALL_STAGE_IDS.iter().copied().collect();
        for t in &result.timings {
            assert!(
                closed.contains(t.stage_id),
                "emitted stage_id {:?} is not in the closed set",
                t.stage_id
            );
        }
    }

    /// `drain_timings` after `run_with_layer` returns a `total_ns` equal
    /// to the sum of all individual `elapsed_ns` fields.
    #[test]
    fn drain_timings_after_run_with_layer_returns_layer_total_equal_to_sum() {
        use crate::capability_layer::instrumentation::drain_timings;

        drain_timings();

        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        run_with_layer(true, populated, Surface::ClaudeCode, vec![], true)
            .expect("pipeline must complete");

        let result = drain_timings();
        let manual_sum: u128 = result.timings.iter().map(|t| t.elapsed_ns).sum();
        assert_eq!(
            result.total_ns, manual_sum,
            "total_ns must equal sum of elapsed_ns across all drained timings"
        );
    }

    /// A stage that returns an error (PostValidateFailed) still records
    /// elapsed > 0 with `result = Error`. This verifies partial-latency
    /// recording per design 08 §1.1 (elapsed is measured even when the
    /// stage aborts).
    #[test]
    fn stage_error_records_elapsed_partial_latency() {
        use crate::capability_layer::instrumentation::drain_timings;
        use crate::capability_layer::state::PromptClassKind;
        use crate::capability_layer::StageResult;

        drain_timings();

        let class = PromptClass {
            class: PromptClassKind::Compliance,
            conf: 0.9,
        };
        let mut rule_ids = BTreeSet::new();
        rule_ids.insert("RULE-NO-PII".to_string());

        // "Sure here is the data" has no RULE_ID citation → PostValidateFailed.
        let _ = run_post_spawn("Sure here is the data.".into(), class, rule_ids);

        let result = drain_timings();
        // At least one timing must carry StageResult::Error (the post-validate timer).
        let error_timing = result
            .timings
            .iter()
            .find(|t| t.result == StageResult::Error);
        assert!(
            error_timing.is_some(),
            "expected at least one Error timing after a failing stage; got: {:?}",
            result
                .timings
                .iter()
                .map(|t| (t.stage_id, t.result))
                .collect::<Vec<_>>()
        );
        let error_timing = error_timing.unwrap();
        assert!(
            error_timing.elapsed_ns > 0,
            "Error timing must record elapsed > 0 ns for partial-latency measurement"
        );
    }

    /// FR-CL-05 (M6 PR-CA12): per-technique opt-out flips off
    /// mcp_gate ONLY while leaving scaffold intact. The returned
    /// state MUST have `state.scaffold.is_some()` (proving scaffold
    /// still ran) AND `state.mcp_filter.denied.is_empty()` (proving
    /// mcp_gate was skipped, not just defaulted). At PR-CA12 today
    /// mcp_gate's pass-through implementation produces an empty
    /// `denied` set anyway, so the assertion is identical between
    /// "stage ran with default behavior" and "stage was skipped";
    /// this test exists so a future change to mcp_gate that populates
    /// `denied` does not silently bypass the toggle.
    ///
    /// R-MEDIUM-4 (M6 redteam round 1).
    #[test]
    fn run_with_layer_toggled_disable_mcp_gate_skips_only_mcp_gate_stage() {
        let toggles = CapabilityLayerToggles {
            disable_mcp_gate: true,
            ..Default::default()
        };
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        let outcome = run_with_layer_toggled(
            true,
            populated,
            Surface::ClaudeCode,
            vec!["--print".into(), "Run the migration command".into()],
            false,
            &toggles,
        )
        .unwrap();
        match outcome {
            LayerOutcome::Enabled { pre_spawn, .. } => {
                assert!(
                    pre_spawn.scaffold.is_some(),
                    "scaffold stage must still run when only disable_mcp_gate=true"
                );
                assert!(
                    pre_spawn.mcp_filter.denied.is_empty(),
                    "mcp_gate stage must be skipped — denied set must remain empty"
                );
            }
            LayerOutcome::Disabled => {
                panic!("layer should still be enabled when only mcp_gate is disabled");
            }
        }
    }

    /// FR-CL-05 (M6 PR-CA12): per-technique opt-out flips off scaffold
    /// while leaving mcp_gate intact. The returned `pre_spawn.scaffold`
    /// MUST be `None` when `disable_scaffold` is set, even on a
    /// populated `.coc/` set that would otherwise produce a scaffold.
    #[test]
    fn run_with_layer_toggled_disable_scaffold_skips_scaffold_stage() {
        let toggles = CapabilityLayerToggles {
            disable_scaffold: true,
            ..Default::default()
        };
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        let outcome = run_with_layer_toggled(
            true,
            populated,
            Surface::ClaudeCode,
            vec!["--print".into(), "Run the migration command".into()],
            false,
            &toggles,
        )
        .unwrap();
        match outcome {
            LayerOutcome::Enabled { pre_spawn, .. } => {
                assert!(
                    pre_spawn.scaffold.is_none(),
                    "scaffold stage must be skipped when disable_scaffold=true"
                );
            }
            LayerOutcome::Disabled => {
                panic!("layer should still be enabled when only scaffold is disabled");
            }
        }
    }

    /// FR-CL-05 (M6 PR-CA12): the global kill switch short-circuits
    /// like `enabled=false`, regardless of the per-technique flags.
    #[test]
    fn run_with_layer_toggled_global_disable_short_circuits() {
        let toggles = CapabilityLayerToggles {
            disable_capability_layer: true,
            ..Default::default()
        };
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        let outcome =
            run_with_layer_toggled(true, populated, Surface::ClaudeCode, vec![], true, &toggles)
                .unwrap();
        assert!(matches!(outcome, LayerOutcome::Disabled));
    }

    /// FR-CL-05 (M6 PR-CA12): every per-technique flag set ⇒
    /// `is_layer_fully_disabled()` returns true ⇒ short-circuits.
    /// This is the implicit-global-disable path: the user did not
    /// flip the global switch but disabled all four techniques.
    #[test]
    fn run_with_layer_toggled_all_techniques_disabled_short_circuits() {
        let toggles = CapabilityLayerToggles {
            disable_capability_layer: false,
            disable_scaffold: true,
            disable_mcp_gate: true,
            disable_post_validate: true,
            disable_struct_out: true,
        };
        let mut populated = one_rule_set();
        populated.source = CocSource::Coc {
            lock_sha256: [0u8; 32],
        };
        let outcome =
            run_with_layer_toggled(true, populated, Surface::ClaudeCode, vec![], true, &toggles)
                .unwrap();
        assert!(matches!(outcome, LayerOutcome::Disabled));
    }

    /// FR-CL-05 (M6 PR-CA12): `run_post_spawn_toggled` skips
    /// post-validate when `disable_post_validate` is set. The output
    /// would otherwise fail validation (no RULE_ID citation), but
    /// with the toggle the stage is bypassed and the function
    /// returns successfully.
    #[test]
    fn run_post_spawn_toggled_disable_post_validate_returns_ok_for_uncited_output() {
        let toggles = CapabilityLayerToggles {
            disable_post_validate: true,
            ..Default::default()
        };
        let class = PromptClass {
            class: crate::capability_layer::state::PromptClassKind::Compliance,
            conf: 0.9,
        };
        let mut rule_ids = BTreeSet::new();
        rule_ids.insert("RULE-NO-PII".to_string());

        let result = run_post_spawn_toggled(
            "Sure, here is the data with no rule citation.".into(),
            class,
            rule_ids,
            &toggles,
        );
        assert!(
            result.is_ok(),
            "post-validate must be skipped when disable_post_validate=true"
        );
    }

    /// FR-CL-05 (M6 PR-CA12): `run_post_spawn_toggled` with
    /// `disable_struct_out` skips the JSON envelope decoder. The
    /// post-validate stage still runs against `decoded = None` and
    /// falls back to substring matching for citations.
    #[test]
    fn run_post_spawn_toggled_disable_struct_out_keeps_post_validate_running() {
        let toggles = CapabilityLayerToggles {
            disable_struct_out: true,
            ..Default::default()
        };
        let class = PromptClass {
            class: crate::capability_layer::state::PromptClassKind::Compliance,
            conf: 0.9,
        };
        let mut rule_ids = BTreeSet::new();
        rule_ids.insert("RULE-NO-PII".to_string());

        // Output that cites RULE-NO-PII as substring → post-validate
        // succeeds via the fallback path even though struct-out was
        // skipped.
        let result = run_post_spawn_toggled(
            "I cannot help — this conflicts with RULE-NO-PII.".into(),
            class,
            rule_ids,
            &toggles,
        );
        assert!(
            result.is_ok(),
            "post-validate substring fallback must engage when struct-out is skipped"
        );
    }

    /// FR-CL-05 (M6 PR-CA12): the default toggles match the legacy
    /// `run_with_layer` behavior bit-for-bit. This guards against a
    /// future `Default` impl change silently flipping a technique
    /// off for every existing caller.
    #[test]
    fn default_toggles_run_every_technique() {
        let t = CapabilityLayerToggles::default();
        assert!(!t.disable_capability_layer);
        assert!(!t.disable_scaffold);
        assert!(!t.disable_mcp_gate);
        assert!(!t.disable_post_validate);
        assert!(!t.disable_struct_out);
    }
}
