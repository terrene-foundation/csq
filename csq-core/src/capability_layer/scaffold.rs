//! Prompt scaffolding (FR-CL-02).
//!
//! Authoritative spec: `specs/10-capability-layer-architecture.md`
//! §10.2 (technique catalog) + §10.3 (typing). Authoritative FR:
//! FR-CL-02 in
//! `internal-design-docs`.
//!
//! # Ship state
//!
//! The scaffold stage delivers the live `csq run` system-prompt-append
//! block. Since CU1b (an internal ticket, G1=UNIFY) it does NOT build the block
//! itself — it delegates to the shared `coc::translate` flattener so the
//! live spawn, `csq translate`, and the neutral launcher all derive from
//! ONE code path:
//!
//! 1. `translate::flatten_artifacts` + `render_sections(surface_header(..))`
//!    flatten rules + agents + skills + commands in scope for the Surface, in
//!    deterministic `(precedence DESC, id ASC)` order, into the per-Surface
//!    system-prompt text — the SAME shared flattener `csq translate`'s
//!    `system_text()` renders through (byte-identical; flattened ONCE).
//! 2. The structured-output directive (FR-CL-01) is appended ONLY when the
//!    prompt classifies as `Compliance` (spec 10 §10.4.6.1).
//! 3. The per-kind breakdown is recorded on `PreSpawnState::artifacts` (the
//!    substrate CU3's native-materialization leg extends).
//!
//! Before CU1b this stage iterated `coc_set.rules` only, so agents, skills,
//! and commands reached no model on the live path — the divergence CU1b
//! fixes. The per-`.coc/`-artifact `coc.disable: ["scaffold"]` opt-out from
//! spec 09 §9.2.2 remains future work tracked outside this module.

use crate::capability_layer::errors::StageError;
use crate::capability_layer::pipeline::PipelineStage;
use crate::capability_layer::state::{PreSpawnState, PromptClass, PromptClassKind, UserPrompt};
use crate::coc::translate as translate_root;
use crate::coc::types::CocSet;
use crate::providers::catalog::Surface;

/// Inputs to the scaffold stage. Owned for PR-CA4; PR-CA6 may
/// refactor to borrow via `Arc<CocSet>` when warm-path cost matters.
pub struct ScaffoldInputs {
    pub coc_set: CocSet,
    pub prompt: UserPrompt,
    pub class: PromptClass,
    pub surface: Surface,
}

/// Marker type for the scaffold stage.
pub struct ScaffoldStage;

impl PipelineStage for ScaffoldStage {
    type Reads = ScaffoldInputs;
    type Writes = PreSpawnState;

    fn run(input: Self::Reads, output: &mut Self::Writes) -> Result<(), StageError> {
        // CU1b (an internal ticket, G1=UNIFY — owner-ratified 2026-06-19): the live
        // `csq run` spawn delivers the SAME all-four-kinds (rules + agents +
        // skills + commands) prose the `csq translate` / neutral-launcher
        // path produces — ONE flattener (`coc::translate`), no drift.
        // Pre-CU1b this stage iterated `coc_set.rules` ONLY, so agents,
        // skills, and commands declared in `.coc/` reached NO model on the
        // live path. Collapsing onto the translator fixes that.
        //
        // The delivered TEXT is host-context-INDEPENDENT on all three
        // Surfaces — the flattener builds text from `coc_set` + `surface`
        // only; `HostContext` affects solely Gemini's
        // `host_isolation_warning` payload bit, which the live spawn emits
        // SEPARATELY (`run.rs::emit_host_isolation_warning_if_needed`).
        //
        // Single flatten (redteam R1 IR-1): flatten the `.coc/` ONCE and
        // render the per-Surface text from it via the shared
        // `render_sections` + `surface_header`, rather than dispatching
        // through `translate::translate` (which would re-flatten for the
        // text and then again for the per-kind channel below). The result is
        // byte-identical to `csq translate`'s `system_text()` — both render
        // through `render_sections(surface_header(surface), flatten_artifacts(..))`
        // — pinned by `flatten::surface_header_matches_translator_empty_output`
        // + `scaffold_text_byte_equals_translate_system_text_freeform` (CU5
        // byte-parity counterparty).
        let arts = translate_root::flatten_artifacts(&input.coc_set, input.surface);
        let (mut scaffold, _contributing_ids) =
            translate_root::render_sections(translate_root::surface_header(input.surface), &arts);

        // PR-CA8 commit 1a: Surface gate dropped. The structured-output
        // directive is Surface-agnostic — same JSON envelope shape works
        // for CC, Codex, and Gemini per spec 10 §10.4.6.1. Class gate
        // remains: free-form chat prompts skip the directive to avoid
        // polluting chat UX. Directive is self-conditional ("for
        // compliance prompts") — belt-and-suspenders if a misclassified
        // FreeForm prompt routes through Compliance via fail-secure.
        //
        // `csq translate` keeps the directive as the SEPARATE
        // `output_schema_directive` payload field; the live spawn inlines it
        // here because each Surface's carrier (CC env var / Codex
        // config.toml `instructions` / Gemini settings.json
        // `system_instruction`) is a single string.
        if input.class.class == PromptClassKind::Compliance {
            scaffold.push_str(&translate_root::build_output_schema_directive());
        }

        output.scaffold = Some(scaffold);

        // CU1b WB1/AC4 — per-kind channel: record the per-kind breakdown the
        // delivered prose was built from (full artifact bodies, sorted
        // deterministically). This is the code substrate CU3's native
        // materialization leg extends; it is the SAME `arts` the delivered
        // text above was rendered from (single flatten), so the channel and
        // the delivered text can never disagree.
        output.artifacts = arts;

        // `prompt` is received but consumed by the classifier stage
        // (PR-CA7), not by scaffold.
        let _ = input.prompt;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_layer::state::PromptClass;
    use crate::coc::types::{CocSet, RuleDef, RuleId};
    use std::collections::{BTreeMap, BTreeSet};

    fn rule_with_applies_to(id: &str, body: &str, applies: &[Surface]) -> (RuleId, RuleDef) {
        let id = RuleId::parse(id).unwrap();
        let mut applies_to = BTreeSet::new();
        for s in applies {
            applies_to.insert(*s);
        }
        let def = RuleDef {
            id: id.clone(),
            paths: Vec::new(),
            applies_to,
            precedence: 0,
            disable: BTreeSet::new(),
            body: body.to_string(),
            unknowns: BTreeMap::new(),
        };
        (id, def)
    }

    fn coc_set_with_rules(rules: Vec<(RuleId, RuleDef)>) -> CocSet {
        let mut set = CocSet::empty();
        for (id, def) in rules {
            set.rules.insert(id, def);
        }
        set
    }

    #[test]
    fn scaffold_includes_universal_rule_for_every_surface() {
        let set = coc_set_with_rules(vec![rule_with_applies_to(
            "RULE-NO-PII",
            "Do not echo PII verbatim.",
            &[],
        )]);
        for surface in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let mut out = PreSpawnState::default();
            ScaffoldStage::run(
                ScaffoldInputs {
                    coc_set: set.clone(),
                    prompt: UserPrompt {
                        text: "ignored".into(),
                    },
                    class: PromptClass::PR_CA4_DEFAULT,
                    surface,
                },
                &mut out,
            )
            .expect("scaffold real impl never errors at PR-CA4");
            let scaffold = out.scaffold.expect("scaffold field set");
            assert!(
                scaffold.contains("RULE-NO-PII"),
                "universal rule absent for {surface}"
            );
            assert!(
                scaffold.contains("Do not echo PII verbatim."),
                "rule body absent for {surface}"
            );
        }
    }

    #[test]
    fn scaffold_filters_by_applies_to_surface() {
        let set = coc_set_with_rules(vec![
            rule_with_applies_to("RULE-CC-ONLY", "cc-only body", &[Surface::ClaudeCode]),
            rule_with_applies_to("RULE-CODEX-ONLY", "codex-only body", &[Surface::Codex]),
        ]);
        let mut cc_state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: set.clone(),
                prompt: UserPrompt { text: "x".into() },
                class: PromptClass::PR_CA4_DEFAULT,
                surface: Surface::ClaudeCode,
            },
            &mut cc_state,
        )
        .unwrap();
        let cc_scaffold = cc_state.scaffold.unwrap();
        assert!(cc_scaffold.contains("RULE-CC-ONLY"));
        assert!(!cc_scaffold.contains("RULE-CODEX-ONLY"));

        let mut codex_state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: set,
                prompt: UserPrompt { text: "x".into() },
                class: PromptClass::PR_CA4_DEFAULT,
                surface: Surface::Codex,
            },
            &mut codex_state,
        )
        .unwrap();
        let codex_scaffold = codex_state.scaffold.unwrap();
        assert!(codex_scaffold.contains("RULE-CODEX-ONLY"));
        assert!(!codex_scaffold.contains("RULE-CC-ONLY"));
    }

    #[test]
    fn scaffold_iteration_is_deterministic_btreemap_order() {
        // BTreeMap iterates in sorted-key order. This test asserts
        // scaffold output preserves that — same set, same surface,
        // byte-identical scaffold across runs.
        let set = coc_set_with_rules(vec![
            rule_with_applies_to("RULE-A", "first", &[]),
            rule_with_applies_to("RULE-B", "second", &[]),
            rule_with_applies_to("RULE-C", "third", &[]),
        ]);
        let mut runs = Vec::new();
        for _ in 0..5 {
            let mut state = PreSpawnState::default();
            ScaffoldStage::run(
                ScaffoldInputs {
                    coc_set: set.clone(),
                    prompt: UserPrompt { text: "x".into() },
                    class: PromptClass::PR_CA4_DEFAULT,
                    surface: Surface::ClaudeCode,
                },
                &mut state,
            )
            .unwrap();
            runs.push(state.scaffold.unwrap());
        }
        for r in &runs[1..] {
            assert_eq!(*r, runs[0], "scaffold output must be byte-identical");
        }
        // Ordering check — RULE-A before RULE-B before RULE-C in
        // the scaffold body.
        let s = &runs[0];
        let pos_a = s.find("RULE-A").unwrap();
        let pos_b = s.find("RULE-B").unwrap();
        let pos_c = s.find("RULE-C").unwrap();
        assert!(
            pos_a < pos_b && pos_b < pos_c,
            "scaffold rules out of order"
        );
    }

    /// CU1b: an empty `.coc/` set produces the Surface header only (no
    /// `## Rules`/`## Agents`/… sections) — the unified flattener's
    /// header-only shape, identical to `csq translate` for an empty set.
    /// (The old "(no rules in scope for this surface)" marker is gone; the
    /// driver short-circuits a truly-`Empty` `.coc/` to `Disabled` before
    /// the scaffold stage runs, so this is the no-in-scope-artifact shape.)
    #[test]
    fn scaffold_empty_set_is_header_only_no_sections() {
        let mut state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: CocSet::empty(),
                prompt: UserPrompt { text: "x".into() },
                // FreeForm so the directive is not appended — isolate the
                // header-only shape.
                class: PromptClass {
                    class: PromptClassKind::FreeForm,
                    conf: 0.9,
                },
                surface: Surface::ClaudeCode,
            },
            &mut state,
        )
        .unwrap();
        let scaffold = state.scaffold.unwrap();
        assert_eq!(scaffold, "# csq capability layer (claude-code)\n");
        assert!(!scaffold.contains("## Rules"));
        assert!(state.artifacts.is_empty());
    }

    /// PR-CA7c: when surface == ClaudeCode AND class == Compliance, the
    /// scaffold appends the FR-CL-01 structured-output directive
    /// (single source of truth: `cc::build_output_schema_directive`).
    #[test]
    fn scaffold_appends_output_directive_for_cc_compliance() {
        use crate::capability_layer::state::PromptClassKind;

        let set = coc_set_with_rules(vec![rule_with_applies_to(
            "RULE-NO-PII",
            "Do not echo PII verbatim.",
            &[],
        )]);
        let mut state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: set,
                prompt: UserPrompt {
                    text: "Will my PII be logged?".into(),
                },
                class: PromptClass {
                    class: PromptClassKind::Compliance,
                    conf: 0.9,
                },
                surface: Surface::ClaudeCode,
            },
            &mut state,
        )
        .unwrap();
        let scaffold = state.scaffold.unwrap();
        assert!(
            scaffold.contains("Structured citation format"),
            "directive header must appear in CC+Compliance scaffold"
        );
        assert!(
            scaffold.contains("rule_id"),
            "directive must name the envelope `rule_id` field"
        );
    }

    /// PR-CA7c: free-form classified prompts on ClaudeCode surface do
    /// NOT get the directive — chat UX is preserved.
    #[test]
    fn scaffold_skips_output_directive_for_cc_freeform() {
        use crate::capability_layer::state::PromptClassKind;

        let set = coc_set_with_rules(vec![rule_with_applies_to(
            "RULE-NO-PII",
            "Do not echo PII verbatim.",
            &[],
        )]);
        let mut state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: set,
                prompt: UserPrompt {
                    text: "What's the weather?".into(),
                },
                class: PromptClass {
                    class: PromptClassKind::FreeForm,
                    conf: 0.9,
                },
                surface: Surface::ClaudeCode,
            },
            &mut state,
        )
        .unwrap();
        let scaffold = state.scaffold.unwrap();
        assert!(
            !scaffold.contains("Structured citation format"),
            "free-form prompt MUST NOT see the directive (chat UX): {scaffold}"
        );
    }

    /// PR-CA8 commit 1a: Codex compliance prompts get the structured-output
    /// directive in their scaffold. Replaces PR-CA7c's
    /// `_skips_output_directive_for_non_cc_surfaces` test (Surface gate
    /// dropped per spec 10 §10.4.6.1).
    #[test]
    fn scaffold_appends_output_directive_for_codex_compliance() {
        use crate::capability_layer::state::PromptClassKind;

        let set = coc_set_with_rules(vec![rule_with_applies_to(
            "RULE-NO-PII",
            "Do not echo PII verbatim.",
            &[],
        )]);
        let mut state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: set,
                prompt: UserPrompt {
                    text: "Will my PII be logged on codex?".into(),
                },
                class: PromptClass {
                    class: PromptClassKind::Compliance,
                    conf: 0.9,
                },
                surface: Surface::Codex,
            },
            &mut state,
        )
        .unwrap();
        let scaffold = state.scaffold.unwrap();
        assert!(
            scaffold.contains("Structured citation format"),
            "directive header must appear in Codex+Compliance scaffold"
        );
        assert!(
            scaffold.contains("rule_id"),
            "directive must name the envelope `rule_id` field"
        );
    }

    /// PR-CA8 commit 1a: Gemini compliance prompts get the structured-output
    /// directive in their scaffold.
    #[test]
    fn scaffold_appends_output_directive_for_gemini_compliance() {
        use crate::capability_layer::state::PromptClassKind;

        let set = coc_set_with_rules(vec![rule_with_applies_to(
            "RULE-NO-PII",
            "Do not echo PII verbatim.",
            &[],
        )]);
        let mut state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: set,
                prompt: UserPrompt {
                    text: "Will my PII be logged on gemini?".into(),
                },
                class: PromptClass {
                    class: PromptClassKind::Compliance,
                    conf: 0.9,
                },
                surface: Surface::Gemini,
            },
            &mut state,
        )
        .unwrap();
        let scaffold = state.scaffold.unwrap();
        assert!(
            scaffold.contains("Structured citation format"),
            "directive header must appear in Gemini+Compliance scaffold"
        );
        assert!(
            scaffold.contains("rule_id"),
            "directive must name the envelope `rule_id` field"
        );
    }

    /// PR-CA8 commit 1a: free-form prompts on ANY surface (CC, Codex, Gemini)
    /// skip the directive — the class gate is the only remaining gate.
    /// Replaces PR-CA7c's `_skips_output_directive_for_non_cc_surfaces`
    /// test (Surface gate dropped per spec 10 §10.4.6.1).
    #[test]
    fn scaffold_skips_output_directive_for_freeform_on_all_surfaces() {
        use crate::capability_layer::state::PromptClassKind;

        let set = coc_set_with_rules(vec![rule_with_applies_to(
            "RULE-NO-PII",
            "Do not echo PII verbatim.",
            &[],
        )]);
        for surface in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let mut state = PreSpawnState::default();
            ScaffoldStage::run(
                ScaffoldInputs {
                    coc_set: set.clone(),
                    prompt: UserPrompt {
                        text: "What's the weather?".into(),
                    },
                    class: PromptClass {
                        class: PromptClassKind::FreeForm,
                        conf: 0.9,
                    },
                    surface,
                },
                &mut state,
            )
            .unwrap();
            let scaffold = state.scaffold.unwrap();
            assert!(
                !scaffold.contains("Structured citation format"),
                "{surface:?}: free-form prompt MUST NOT see the directive (chat UX): {scaffold}"
            );
        }
    }

    // ====================================================================
    // CU1b (an internal ticket) — unify the live spawn flattener onto translate
    // ====================================================================

    use crate::coc::types::{AgentDef, AgentId, CommandDef, CommandId, SkillDef, SkillId};

    /// Build a `.coc/` set carrying one rule, one agent, one skill, and one
    /// command — all universal (`applies_to: []`) so they reach every
    /// Surface.
    fn full_kind_set() -> CocSet {
        let mut set = CocSet::empty();
        set.rules.insert(
            RuleId("RULE-X".into()),
            rule_with_applies_to("RULE-X", "rule body text", &[]).1,
        );
        set.agents.insert(
            AgentId("AGENT-Y".into()),
            AgentDef {
                id: AgentId("AGENT-Y".into()),
                applies_to: BTreeSet::new(),
                precedence: 0,
                disable: BTreeSet::new(),
                body: "agent body text".into(),
                unknowns: BTreeMap::new(),
            },
        );
        set.skills.insert(
            SkillId("SKILL-Z".into()),
            SkillDef {
                id: SkillId("SKILL-Z".into()),
                applies_to: BTreeSet::new(),
                precedence: 0,
                disable: BTreeSet::new(),
                body: "skill body text".into(),
                unknowns: BTreeMap::new(),
            },
        );
        set.commands.insert(
            CommandId("COMMAND-W".into()),
            CommandDef {
                id: CommandId("COMMAND-W".into()),
                applies_to: BTreeSet::new(),
                precedence: 0,
                disable: BTreeSet::new(),
                body: "command body text".into(),
                unknowns: BTreeMap::new(),
            },
        );
        set
    }

    fn run_scaffold(set: CocSet, surface: Surface, class: PromptClass) -> PreSpawnState {
        let mut state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: set,
                prompt: UserPrompt { text: "x".into() },
                class,
                surface,
            },
            &mut state,
        )
        .unwrap();
        state
    }

    const FREEFORM: PromptClass = PromptClass {
        class: PromptClassKind::FreeForm,
        conf: 0.9,
    };
    const COMPLIANCE: PromptClass = PromptClass {
        class: PromptClassKind::Compliance,
        conf: 0.9,
    };

    /// CU1b AC1: a live scaffold now delivers rules + agents + skills +
    /// commands as prose on ALL three Surfaces (pre-CU1b: rules only).
    #[test]
    fn scaffold_delivers_all_four_kinds_on_every_surface() {
        for surface in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let state = run_scaffold(full_kind_set(), surface, FREEFORM);
            let s = state.scaffold.expect("scaffold set");
            assert!(s.contains("rule body text"), "{surface:?}: rule missing");
            assert!(s.contains("agent body text"), "{surface:?}: agent missing");
            assert!(s.contains("skill body text"), "{surface:?}: skill missing");
            assert!(
                s.contains("command body text"),
                "{surface:?}: command missing"
            );
            assert!(s.contains("## Rules"));
            assert!(s.contains("## Agents"));
            assert!(s.contains("## Skills"));
            assert!(s.contains("## Commands"));
        }
    }

    /// CU1b AC1 / WB6 — parity (FreeForm, no directive): the live-delivered
    /// scaffold text is byte-identical to `translate::translate(..)
    /// .system_text()` for the same `.coc/` + Surface. This is the "one
    /// flattener" proof — the live spawn and `csq translate` derive from
    /// the same code path. HostContext::None matches the translate path's
    /// host-neutral text (the text is host-independent — see ScaffoldStage
    /// doc).
    #[test]
    fn scaffold_text_byte_equals_translate_system_text_freeform() {
        for surface in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let set = full_kind_set();
            let expected =
                translate_root::translate(&set, surface, &translate_root::HostContext::None)
                    .system_text()
                    .to_string();
            let state = run_scaffold(set, surface, FREEFORM);
            assert_eq!(
                state.scaffold.unwrap(),
                expected,
                "{surface:?}: live scaffold text must byte-equal translate system_text (FreeForm)"
            );
        }
    }

    /// CU1b AC1+AC2 / WB6 — parity (Compliance): the live-delivered text
    /// equals `system_text()` PLUS the class-gated structured-output
    /// directive. The directive is the documented live-path super-set
    /// (`csq translate` carries it as the separate `output_schema_directive`
    /// field, not inlined into `system_text()`).
    #[test]
    fn scaffold_text_equals_translate_system_text_plus_directive_compliance() {
        for surface in [Surface::ClaudeCode, Surface::Codex, Surface::Gemini] {
            let set = full_kind_set();
            let expected = format!(
                "{}{}",
                translate_root::translate(&set, surface, &translate_root::HostContext::None)
                    .system_text(),
                translate_root::build_output_schema_directive(),
            );
            let state = run_scaffold(set, surface, COMPLIANCE);
            assert_eq!(
                state.scaffold.unwrap(),
                expected,
                "{surface:?}: Compliance scaffold = system_text + directive"
            );
        }
    }

    /// CU1b AC4: the per-kind channel (`PreSpawnState::artifacts`) is
    /// populated with all four kinds, with full (untrimmed) bodies — the
    /// substrate CU3 extends.
    #[test]
    fn scaffold_populates_per_kind_channel() {
        let state = run_scaffold(full_kind_set(), Surface::ClaudeCode, FREEFORM);
        let arts = &state.artifacts;
        assert_eq!(arts.rules.len(), 1, "rules channel");
        assert_eq!(arts.agents.len(), 1, "agents channel");
        assert_eq!(arts.skills.len(), 1, "skills channel");
        assert_eq!(arts.commands.len(), 1, "commands channel");
        assert_eq!(arts.rules[0].id, "RULE-X");
        assert_eq!(arts.agents[0].body, "agent body text");
        assert_eq!(arts.commands[0].id, "COMMAND-W");
    }

    /// CU1b AC5: the reconciled all-kinds payload (scaffold text AND the
    /// per-kind channel) is byte-identical across 30+ invocations
    /// (spec 10 §10.3.5 determinism).
    #[test]
    fn scaffold_all_kinds_payload_deterministic_30_runs() {
        let first = run_scaffold(full_kind_set(), Surface::Gemini, COMPLIANCE);
        for _ in 0..30 {
            let next = run_scaffold(full_kind_set(), Surface::Gemini, COMPLIANCE);
            assert_eq!(
                next.scaffold, first.scaffold,
                "scaffold text not deterministic"
            );
            assert_eq!(
                next.artifacts, first.artifacts,
                "per-kind channel not deterministic"
            );
        }
    }

    /// CU1b AC3: the live scaffold text and the post-validate rule-id set
    /// (`extract_rule_ids_in_scope` — the single rule-id source) cover
    /// exactly the same rules. Both use the identical `applies_to`
    /// predicate, so a CC-only rule appears in the CC scaffold + CC rule-id
    /// set but NOT in the Codex ones.
    #[test]
    fn scaffold_rules_align_with_extract_rule_ids_in_scope() {
        use crate::capability_layer::driver::extract_rule_ids_in_scope;
        let mut set = CocSet::empty();
        set.rules.insert(
            RuleId("RULE-UNIVERSAL".into()),
            rule_with_applies_to("RULE-UNIVERSAL", "u", &[]).1,
        );
        set.rules.insert(
            RuleId("RULE-CC-ONLY".into()),
            rule_with_applies_to("RULE-CC-ONLY", "cc", &[Surface::ClaudeCode]).1,
        );
        let cc_ids = extract_rule_ids_in_scope(&set, Surface::ClaudeCode);
        let cc = run_scaffold(set.clone(), Surface::ClaudeCode, FREEFORM)
            .scaffold
            .unwrap();
        for id in &cc_ids {
            assert!(
                cc.contains(id.as_str()),
                "CC scaffold missing in-scope {id}"
            );
        }
        let codex_ids = extract_rule_ids_in_scope(&set, Surface::Codex);
        assert!(!codex_ids.contains("RULE-CC-ONLY"));
        let codex = run_scaffold(set, Surface::Codex, FREEFORM)
            .scaffold
            .unwrap();
        assert!(
            !codex.contains("RULE-CC-ONLY"),
            "CC-only rule leaked to Codex"
        );
    }
}
