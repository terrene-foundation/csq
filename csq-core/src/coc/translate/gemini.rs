//! Gemini translator (FR-DISP-04).
//!
//! Maps a `CocSet` to a `GeminiSpawnPayload` per spec 09 + spec 07
//! §7.2.3/§7.3.4. The capability layer's spawn step writes the
//! `system_instruction` field to the handle-dir copy of
//! `~/.gemini/settings.json` and applies the approval-mode argv flag.
//!
//! Per spec 08 MED-03 host-isolation caveat: csq surfaces a
//! `host_isolation_warning` when the host environment is detected to
//! carry production-shaped secrets. The translator does NOT scan
//! `std::env::vars()` directly (that would break FR-DISP-05 determinism);
//! instead, the orchestrator inspects the host once at startup and
//! passes the result via `HostContext`. The default-shape `translate`
//! returns a payload with the warning bit cleared, suitable for the
//! deterministic golden-file tests; M3+ wiring uses
//! `translate_with_options` to feed the host-context check in.

use std::collections::{BTreeMap, BTreeSet};

use crate::coc::types::CocSet;
use crate::providers::catalog::Surface;

use super::flatten::{flatten_artifacts, is_real_path_restriction, render_sections};
use super::types::{ApprovalMode, GeminiSpawnPayload, McpFilter};

/// FR-CL-01 system-prompt directive — re-exported from
/// `crate::coc::translate::build_output_schema_directive` per PR-CA8 commit
/// 1a. Same byte content as the CC + Codex variants (single source of truth).
/// Payload-side population of `GeminiSpawnPayload::output_schema_directive`
/// lands in commit 1b alongside the gemini wire-up.
pub use super::build_output_schema_directive;

const SURFACE_HEADER: &str = "# csq capability layer (gemini)\n";

/// Optional host context. The translator function consults this purely
/// to set the `host_isolation_warning` bit on the payload — the rest
/// of translation is deterministic over `coc_set`.
///
/// Round-3 R3-M3: this struct is now wrapped by the outer-enum
/// `crate::coc::translate::types::HostContext::Gemini(...)` for
/// dispatcher-level Surface-genericity. `Copy` derive dropped in
/// PR-CA8b commit 1b (round-2 R2-H8) because `BTreeSet<String>` and
/// `Option<String>` aren't `Copy`.
#[derive(Debug, Clone, Default)]
pub struct HostContext {
    /// Set true when the orchestrator detects production-shaped secrets
    /// on the host environment (per spec 08 MED-03).
    pub production_secrets_present: bool,
    /// All detected production-shaped env-var names, sorted (BTreeSet
    /// iteration is deterministic). Names only — never values — per
    /// `.claude/rules/security.md` MUST Rule 2 / round-1 H3 disclosure-
    /// minimization. csq-cli's `csq doctor --verbose` surfaces this
    /// list; the default doctor output + stderr warning use only
    /// `first_exemplar(detected_var_names)`.
    pub detected_var_names: std::collections::BTreeSet<String>,
}

/// Default translate path — no host context. Callers that need
/// host-isolation warning surfacing use `translate_with_options`.
pub fn translate(coc_set: &CocSet) -> GeminiSpawnPayload {
    translate_with_options(coc_set, None)
}

/// Translate with optional host context. When `host_ctx` is provided
/// and indicates production secrets are present, the payload's
/// `host_isolation_warning` is set true.
pub fn translate_with_options(
    coc_set: &CocSet,
    host_ctx: Option<&HostContext>,
) -> GeminiSpawnPayload {
    // CU1b: the system_instruction text is built by the shared
    // `super::flatten` flattener (the single flattener the CC + codex
    // translators and the live capability-layer scaffold stage also use).
    // The text is host-context-INDEPENDENT — `host_ctx` affects only the
    // `host_isolation_warning` + `detected_var_first` payload bits below,
    // never the flattened prose.
    let arts = flatten_artifacts(coc_set, Surface::Gemini);
    let (system_instruction, contributing_ids) = render_sections(SURFACE_HEADER, &arts);

    // MED-2 (round-13 review): Gemini has no per-file rule-scoping
    // mechanism — every in-scope rule reaches `system_instruction` as flat
    // global prose regardless of `paths`. Record the broadening via the
    // shared predicate so the loss is disclosed, not silent (the same
    // pre-existing gap Kimi had — see
    // `CodexSpawnPayload::unscoped_path_rules`'s doc comment).
    let unscoped_path_rules: BTreeSet<String> = arts
        .rules
        .iter()
        .filter(|r| is_real_path_restriction(&r.paths))
        .map(|r| r.id.clone())
        .collect();

    let host_isolation_warning = host_ctx
        .map(|c| c.production_secrets_present)
        .unwrap_or(false);

    // PR-CA8b commit 1b — round-3 R3-H7: surface a single exemplar
    // name from the detected set so the operator-facing stderr line
    // does not enumerate the full inventory. Priority: EXACT-match
    // list (ANTHROPIC_API_KEY > ... > GITHUB_TOKEN) over lex-first.
    let detected_var_first = host_ctx.and_then(|c| {
        if !c.production_secrets_present {
            return None;
        }
        crate::env::first_exemplar(&c.detected_var_names).map(|s| s.to_string())
    });

    GeminiSpawnPayload {
        settings_json_overlay: BTreeMap::new(),
        system_instruction,
        approval_mode: ApprovalMode::Plan,
        mcp_filter: McpFilter::default(),
        contributing_ids,
        host_isolation_warning,
        // PR-CA8b commit 1b: Surface-agnostic structured-output
        // directive. Delivered to gemini via settings.json
        // `system_instruction` field by csq-cli's gemini layer
        // wire-up (commit 4).
        output_schema_directive: Some(super::build_output_schema_directive()),
        detected_var_first,
        unscoped_path_rules,
    }
}

/// Heuristic — does an env-var name look like it carries a production
/// secret? Re-exported from `csq_core::env` per PR-CA8b commit 1b
/// (round-2 R2-M6). The function moved to a dedicated `env` module
/// because host-environment scope is broader than gemini-translator
/// scope. Backwards-compat re-export so existing call sites keep
/// working.
pub use crate::env::looks_like_production_secret;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coc::types::{CocSet, CocSource, RuleDef, RuleId};
    use crate::coc::version::CocVersion;
    use sha2::{Digest, Sha256};

    fn rule(id: &str, precedence: i32, surfaces: &[Surface], body: &str) -> RuleDef {
        let mut applies_to = std::collections::BTreeSet::new();
        for s in surfaces {
            applies_to.insert(*s);
        }
        RuleDef {
            id: RuleId(id.to_string()),
            paths: vec!["**".to_string()],
            applies_to,
            precedence,
            disable: std::collections::BTreeSet::new(),
            body: body.to_string(),
            unknowns: BTreeMap::new(),
        }
    }

    fn scoped_rule(id: &str, paths: &[&str], body: &str) -> RuleDef {
        RuleDef {
            id: RuleId(id.to_string()),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            applies_to: std::collections::BTreeSet::new(),
            precedence: 0,
            disable: std::collections::BTreeSet::new(),
            body: body.to_string(),
            unknowns: BTreeMap::new(),
        }
    }

    fn build_set(rules: Vec<RuleDef>) -> CocSet {
        let mut set = CocSet::empty();
        for r in rules {
            set.rules.insert(r.id.clone(), r);
        }
        set.version = CocVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        set.source = CocSource::LegacyGemini;
        set
    }

    fn sha256_of(p: &GeminiSpawnPayload) -> [u8; 32] {
        let json = serde_json::to_vec(p).unwrap();
        let mut h = Sha256::new();
        h.update(&json);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }

    #[test]
    fn empty_set_minimal_instruction() {
        let set = build_set(vec![]);
        let p = translate(&set);
        assert_eq!(p.system_instruction, SURFACE_HEADER);
        assert_eq!(p.approval_mode, ApprovalMode::Plan);
        assert!(!p.host_isolation_warning);
        assert!(p.unscoped_path_rules.is_empty());
    }

    /// MED-2 (round-13 review) non-vacuity: a rule carrying real path scope
    /// MUST be reported as broadened, not silently dropped or silently
    /// treated as still-scoped — Gemini has the identical pre-existing gap
    /// Kimi had, now closed via the shared predicate.
    #[test]
    fn path_scoped_rule_is_recorded_as_unscoped_and_still_reaches_prose() {
        let set = build_set(vec![scoped_rule(
            "RULE-SCOPED",
            &["src/**/*.rs"],
            "only for rust files",
        )]);
        let p = translate(&set);
        assert!(p.unscoped_path_rules.contains("RULE-SCOPED"));
        assert!(p.system_instruction.contains("only for rust files"));
    }

    /// An unscoped rule (default `paths: ["**"]` from the parser) is NOT
    /// recorded — only rules that actually declared a narrower scope are.
    #[test]
    fn wildcard_path_rule_is_not_recorded_as_unscoped() {
        let set = build_set(vec![rule("RULE-WILD", 0, &[], "applies everywhere")]);
        let p = translate(&set);
        assert!(!p.unscoped_path_rules.contains("RULE-WILD"));
    }

    #[test]
    fn host_isolation_warning_fires_when_secrets_detected() {
        // PR-CA8b R2-H8: HostContext lost Copy; use ..Default::default()
        // to fill in the new BTreeSet field.
        let set = build_set(vec![]);
        let p = translate_with_options(
            &set,
            Some(&HostContext {
                production_secrets_present: true,
                ..Default::default()
            }),
        );
        assert!(p.host_isolation_warning);
    }

    #[test]
    fn host_isolation_warning_clear_by_default() {
        let set = build_set(vec![]);
        let p = translate(&set);
        assert!(!p.host_isolation_warning);
    }

    #[test]
    fn rules_filtered_by_applies_to() {
        let set = build_set(vec![
            rule("RULE-CC", 0, &[Surface::ClaudeCode], "claude only"),
            rule("RULE-GEM", 0, &[Surface::Gemini], "gemini only"),
        ]);
        let p = translate(&set);
        assert!(p.system_instruction.contains("RULE-GEM"));
        assert!(!p.system_instruction.contains("RULE-CC"));
    }

    #[test]
    fn higher_precedence_first() {
        let set = build_set(vec![
            rule("RULE-LO", 0, &[Surface::Gemini], "low"),
            rule("RULE-HI", 5, &[Surface::Gemini], "high"),
        ]);
        let p = translate(&set);
        let h = p.system_instruction.find("RULE-HI").unwrap();
        let l = p.system_instruction.find("RULE-LO").unwrap();
        assert!(h < l);
    }

    /// NIT-1 (round-13 review): this loops a PURE function 30x in ONE
    /// process — it can only fail if `translate` reads mutable global
    /// state, which it does not by construction. It does NOT exercise
    /// FR-DISP-05's actual contract, which is cross-PROCESS byte-identity
    /// (spec 10 §10.3.5) — that is covered by
    /// `coc-eval/lib/delivery.py::run_csq_translate`, which shells out to a
    /// fresh `csq translate` invocation per call. Renamed from
    /// `deterministic_30_invocations` (which claimed the cross-process
    /// contract) to name what this test actually proves.
    #[test]
    fn translate_is_pure_across_repeated_calls_same_process() {
        let set = build_set(vec![
            rule("RULE-A", 5, &[Surface::Gemini], "alpha"),
            rule("RULE-B", 0, &[Surface::Gemini], "beta"),
        ]);
        let first = sha256_of(&translate(&set));
        for _ in 0..30 {
            assert_eq!(first, sha256_of(&translate(&set)));
        }
    }

    #[test]
    fn looks_like_production_secret_recognizes_common_patterns() {
        // PR-CA8b R2-M2 / R3-L2: heuristic re-tuned. Bare `_SECRET`
        // dropped from SUFFIXES (over-broad — `SUPER_SECRET` is
        // generic vocab, not a credential pattern); `_SECRET_KEY`
        // remains. EXACT list expanded to known SaaS shapes.
        assert!(looks_like_production_secret("MY_API_KEY"));
        assert!(looks_like_production_secret("APP_TOKEN"));
        assert!(looks_like_production_secret("ANTHROPIC_API_KEY"));
        assert!(looks_like_production_secret("anthropic_api_key")); // case-insensitive
        assert!(looks_like_production_secret("AWS_SECRET_ACCESS_KEY"));
        assert!(looks_like_production_secret("AWS_ACCESS_KEY_ID")); // exact match
    }

    #[test]
    fn looks_like_production_secret_rejects_safe_names() {
        assert!(!looks_like_production_secret("PATH"));
        assert!(!looks_like_production_secret("HOME"));
        assert!(!looks_like_production_secret("TERM"));
        assert!(!looks_like_production_secret("USER"));
        assert!(!looks_like_production_secret("CARGO_TARGET_DIR"));
    }

    #[test]
    fn applies_to_all_includes_gemini() {
        let set = build_set(vec![rule(
            "RULE-ALL",
            0,
            &[Surface::ClaudeCode, Surface::Codex, Surface::Gemini],
            "all",
        )]);
        let p = translate(&set);
        assert!(p.system_instruction.contains("RULE-ALL"));
    }

    #[test]
    fn approval_mode_default_is_plan() {
        let set = build_set(vec![]);
        let p = translate(&set);
        // Plan = read-only; M2 doesn't escalate to auto.
        assert_eq!(p.approval_mode, ApprovalMode::Plan);
    }

    /// PR-CA8 R1-H11: universal rule (`applies_to: []` empty set) MUST
    /// appear in gemini translator output per spec 09 §9.2.4.
    #[test]
    fn universal_rule_appears_in_gemini_translator() {
        let set = build_set(vec![rule(
            "RULE-UNIVERSAL",
            0,
            &[],
            "applies to all surfaces",
        )]);
        let p = translate(&set);
        assert!(
            p.system_instruction.contains("RULE-UNIVERSAL"),
            "universal rule must appear in gemini translator output"
        );
        assert!(p.contributing_ids.contains("RULE-UNIVERSAL"));
    }

    /// PR-CA8 R1-H11: universal agent (empty `applies_to`) MUST appear in
    /// gemini translator output.
    #[test]
    fn universal_agent_appears_in_gemini_translator() {
        use crate::coc::types::{AgentDef, AgentId};
        let mut set = build_set(vec![]);
        set.agents.insert(
            AgentId("AGENT-UNIVERSAL".to_string()),
            AgentDef {
                id: AgentId("AGENT-UNIVERSAL".to_string()),
                applies_to: std::collections::BTreeSet::new(),
                precedence: 0,
                disable: std::collections::BTreeSet::new(),
                body: "applies to all surfaces".to_string(),
                unknowns: BTreeMap::new(),
            },
        );
        let p = translate(&set);
        assert!(
            p.system_instruction.contains("AGENT-UNIVERSAL"),
            "universal agent must appear in gemini translator output"
        );
    }

    /// PR-CA8 R1-H11: universal skill (empty `applies_to`) MUST appear in
    /// gemini translator output.
    #[test]
    fn universal_skill_appears_in_gemini_translator() {
        use crate::coc::types::{SkillDef, SkillId};
        let mut set = build_set(vec![]);
        set.skills.insert(
            SkillId("SKILL-UNIVERSAL".to_string()),
            SkillDef {
                id: SkillId("SKILL-UNIVERSAL".to_string()),
                applies_to: std::collections::BTreeSet::new(),
                precedence: 0,
                disable: std::collections::BTreeSet::new(),
                body: "applies to all surfaces".to_string(),
                unknowns: BTreeMap::new(),
            },
        );
        let p = translate(&set);
        assert!(
            p.system_instruction.contains("SKILL-UNIVERSAL"),
            "universal skill must appear in gemini translator output"
        );
    }

    /// PR-CA8 R1-H11: universal command (empty `applies_to`) MUST appear in
    /// gemini translator output.
    #[test]
    fn universal_command_appears_in_gemini_translator() {
        use crate::coc::types::{CommandDef, CommandId};
        let mut set = build_set(vec![]);
        set.commands.insert(
            CommandId("COMMAND-UNIVERSAL".to_string()),
            CommandDef {
                id: CommandId("COMMAND-UNIVERSAL".to_string()),
                applies_to: std::collections::BTreeSet::new(),
                precedence: 0,
                disable: std::collections::BTreeSet::new(),
                body: "applies to all surfaces".to_string(),
                unknowns: BTreeMap::new(),
            },
        );
        let p = translate(&set);
        assert!(
            p.system_instruction.contains("COMMAND-UNIVERSAL"),
            "universal command must appear in gemini translator output"
        );
    }

    /// CU1b redteam R1 IR-2 — host-independence guard. The AC1 disposition
    /// (option b) rests on the delivered TEXT (`system_instruction`) being
    /// host-context-independent: `HostContext` must affect ONLY the
    /// `host_isolation_warning` + `detected_var_first` payload bits, never
    /// the text. The scaffold flattens host-neutral (`HostContext::None`)
    /// while the live spawn detects a real host; if a future change ever
    /// wired host context into the text, the scaffold would silently diverge
    /// from the live host. This pins the invariant: same `.coc/`, the text is
    /// byte-equal across host contexts; only the warning bit differs.
    #[test]
    fn system_instruction_is_host_context_independent() {
        let set = build_set(vec![
            rule("RULE-A", 5, &[Surface::Gemini], "alpha body"),
            rule("RULE-B", 0, &[], "beta body universal"),
        ]);
        let neutral = translate_with_options(&set, None);
        let with_secrets = translate_with_options(
            &set,
            Some(&HostContext {
                production_secrets_present: true,
                detected_var_names: ["ANTHROPIC_API_KEY".to_string()].into_iter().collect(),
            }),
        );
        assert_eq!(
            neutral.system_instruction, with_secrets.system_instruction,
            "system_instruction TEXT must be identical across host contexts (AC1 option b)"
        );
        // The payload BIT, by contrast, MUST reflect the host context.
        assert!(!neutral.host_isolation_warning);
        assert!(with_secrets.host_isolation_warning);
    }
}
