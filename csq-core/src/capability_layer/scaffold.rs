//! Prompt scaffolding (FR-CL-02).
//!
//! Authoritative spec: `specs/10-capability-layer-architecture.md`
//! §10.2 (technique catalog) + §10.3 (typing). Authoritative FR:
//! FR-CL-02 in
//! `workspaces/csq-as-cli/01-analysis/01-research/01-functional-requirements.md`.
//!
//! # PR-CA4 ship state
//!
//! This is the **real** PR-CA4 stage (the others under
//! `capability_layer/` are stubs). The minimum-viable scaffold:
//!
//! 1. Iterate the `CocSet`'s rules in deterministic `BTreeMap` order.
//! 2. Filter by `applies_to`: include rules whose `applies_to` is
//!    empty (universal) OR contains the target Surface.
//! 3. Emit a system-prompt-append block that cites each kept rule
//!    by its `RULE_ID`, followed by the rule body.
//!
//! This is enough to wire the FR-CL-02 stage into the pipeline so
//! the next-stage stubs (mcp_gate, struct_out, post_validate) can
//! demonstrate the StubUnimplemented propagation pattern. M4/PR-CA6
//! extends scaffold to include agents/skills/commands and applies
//! the per-`.coc/`-artifact `coc.disable: ["scaffold"]` opt-out from
//! spec 09 §9.2.2.

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
        let mut scaffold = build_scaffold(&input.coc_set, input.surface);

        // PR-CA8 commit 1a: Surface gate dropped. The structured-output
        // directive is Surface-agnostic — same JSON envelope shape works
        // for CC, Codex, and Gemini per spec 10 §10.4.6.1. Class gate
        // remains: free-form chat prompts skip the directive to avoid
        // polluting chat UX. Directive is self-conditional ("for
        // compliance prompts") — belt-and-suspenders if a misclassified
        // FreeForm prompt routes through Compliance via fail-secure.
        //
        // Spec 10 §10.4.6.1 (PR-CA8). Per-Surface delivery (CC env var /
        // Codex config.toml / Gemini settings.json) lives in csq-cli; the
        // scaffold stage outputs the same text regardless.
        if input.class.class == PromptClassKind::Compliance {
            scaffold.push_str(&translate_root::build_output_schema_directive());
        }

        output.scaffold = Some(scaffold);
        // `prompt` is received but not consumed — the classifier (which
        // reads the prompt) lands in PR-CA7a; the scaffold uses the
        // class verdict produced by that stage.
        let _ = input.prompt;
        Ok(())
    }
}

/// Build the rule-citation block. Returns the empty string when no
/// rules apply (still wraps in `Some(_)` at the call site so the
/// state field reflects "scaffold ran, produced nothing").
fn build_scaffold(coc_set: &CocSet, surface: Surface) -> String {
    let mut out = String::new();
    out.push_str("# Compliance rules from .coc/\n\n");
    out.push_str(
        "Cite the relevant RULE_ID(s) when explaining decisions. \
         Refuse explicitly when a rule prohibits the requested action.\n\n",
    );
    let mut included = 0u32;
    for (rule_id, rule) in &coc_set.rules {
        if !applies_to_surface(&rule.applies_to, surface) {
            continue;
        }
        included += 1;
        out.push_str("## ");
        out.push_str(rule_id.as_str());
        out.push('\n');
        out.push_str(rule.body.trim_end());
        out.push_str("\n\n");
    }
    if included == 0 {
        // Still leave the header so harness tests can detect "scaffold
        // ran" even when no rules matched the surface filter.
        out.push_str("(no rules in scope for this surface)\n");
    }
    out
}

/// `applies_to` semantics per spec 09 §9.2.4: an empty set means
/// "universal — applies to every Surface"; a non-empty set means
/// "applies only to the listed surfaces".
fn applies_to_surface(applies_to: &std::collections::BTreeSet<Surface>, surface: Surface) -> bool {
    applies_to.is_empty() || applies_to.contains(&surface)
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

    #[test]
    fn scaffold_emits_no_rules_marker_when_set_is_empty() {
        let mut state = PreSpawnState::default();
        ScaffoldStage::run(
            ScaffoldInputs {
                coc_set: CocSet::empty(),
                prompt: UserPrompt { text: "x".into() },
                class: PromptClass::PR_CA4_DEFAULT,
                surface: Surface::ClaudeCode,
            },
            &mut state,
        )
        .unwrap();
        let scaffold = state.scaffold.unwrap();
        assert!(scaffold.contains("(no rules in scope for this surface)"));
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
}
