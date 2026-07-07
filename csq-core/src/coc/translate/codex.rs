//! Codex translator (FR-DISP-03).
//!
//! Maps a `CocSet` to a `CodexSpawnPayload` per spec 09 + spec 07
//! §7.2.2/§7.3.3/§7.7.2. The capability layer's spawn step writes the
//! `instructions` block to `~/.codex/config.toml` (handle-dir copy)
//! and applies the sandbox-mode argv flag.
//!
//! Note: codex has no native MCP allowlist as of 2026-04 (per FR-DISP-03);
//! MCP gating is performed csq-side at the prompt-edit boundary by the
//! capability layer (spec 10 §10.8.1).

use std::collections::BTreeMap;

use crate::coc::types::CocSet;
use crate::providers::catalog::Surface;

use super::flatten::{flatten_artifacts, render_sections};
use super::types::{CodexSpawnPayload, McpFilter, SandboxMode};

/// FR-CL-01 system-prompt directive — re-exported from
/// `crate::coc::translate::build_output_schema_directive` per PR-CA8 commit
/// 1a. Same byte content as the CC + Gemini variants.
pub use super::build_output_schema_directive;

const SURFACE_HEADER: &str = "# csq capability layer (codex)\n";

/// CU1b: shares `super::flatten` with the CC + Gemini translators and the
/// live capability-layer scaffold stage — one flattener, no per-surface
/// drift. Only the Surface header + the codex-specific payload fields
/// (sandbox mode, config overlay) differ.
pub fn translate(coc_set: &CocSet) -> CodexSpawnPayload {
    let arts = flatten_artifacts(coc_set, Surface::Codex);
    let (instructions, contributing_ids) = render_sections(SURFACE_HEADER, &arts);

    CodexSpawnPayload {
        config_toml_overlay: BTreeMap::new(),
        instructions,
        sandbox_mode: SandboxMode::ReadOnly,
        mcp_filter: McpFilter::default(),
        contributing_ids,
        // PR-CA8 commit 1a: Surface-agnostic structured-output directive.
        // Delivered into config.toml::instructions by csq-cli's
        // materialize_handle_config_toml helper at spawn time (PR-CA8
        // commit 2; renamed from _with_instructions in M6 T6.2 Shard 3a
        // when the MCP-proxy rewrite transform was composed in).
        output_schema_directive: Some(build_output_schema_directive()),
    }
}

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
        set.source = CocSource::LegacyAgentsMd;
        set
    }

    fn sha256_of(p: &CodexSpawnPayload) -> [u8; 32] {
        let json = serde_json::to_vec(p).unwrap();
        let mut h = Sha256::new();
        h.update(&json);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }

    #[test]
    fn empty_set_produces_minimal_instructions() {
        let set = build_set(vec![]);
        let payload = translate(&set);
        assert_eq!(payload.instructions, SURFACE_HEADER);
        assert_eq!(payload.sandbox_mode, SandboxMode::ReadOnly);
        assert!(payload.mcp_filter.is_empty());
    }

    #[test]
    fn rule_filtered_when_not_for_codex() {
        let set = build_set(vec![rule(
            "RULE-CC",
            0,
            &[Surface::ClaudeCode],
            "claude only",
        )]);
        let payload = translate(&set);
        assert!(!payload.instructions.contains("RULE-CC"));
    }

    #[test]
    fn rule_appears_when_codex_listed() {
        let set = build_set(vec![rule(
            "RULE-CDX",
            5,
            &[Surface::Codex],
            "deny shell exec",
        )]);
        let payload = translate(&set);
        assert!(payload.instructions.contains("### RULE-CDX"));
        assert!(payload.instructions.contains("deny shell exec"));
    }

    #[test]
    fn precedence_orders_high_first() {
        let set = build_set(vec![
            rule("RULE-LOW", 0, &[Surface::Codex], "low"),
            rule("RULE-HIGH", 9, &[Surface::Codex], "high"),
        ]);
        let payload = translate(&set);
        let h = payload.instructions.find("RULE-HIGH").unwrap();
        let l = payload.instructions.find("RULE-LOW").unwrap();
        assert!(h < l);
    }

    #[test]
    fn deterministic_30_invocations() {
        let set = build_set(vec![
            rule("RULE-A", 5, &[Surface::Codex], "alpha"),
            rule("RULE-B", 0, &[Surface::Codex], "beta"),
        ]);
        let first = sha256_of(&translate(&set));
        for _ in 0..30 {
            assert_eq!(first, sha256_of(&translate(&set)));
        }
    }

    #[test]
    fn applies_to_all_includes_codex() {
        let set = build_set(vec![rule(
            "RULE-ALL",
            0,
            &[Surface::ClaudeCode, Surface::Codex, Surface::Gemini],
            "all surfaces",
        )]);
        let payload = translate(&set);
        assert!(payload.instructions.contains("RULE-ALL"));
    }

    #[test]
    fn default_sandbox_is_read_only() {
        let set = build_set(vec![]);
        let payload = translate(&set);
        // Default safe sandbox per spec 07 §7.2.2; M2 doesn't escalate.
        assert_eq!(payload.sandbox_mode, SandboxMode::ReadOnly);
    }

    /// PR-CA8 commit 1a: every Codex payload carries the FR-CL-01
    /// structured-output directive (Surface-agnostic body shared with
    /// CC + Gemini per spec 10 §10.4.6.1). Delivered to codex via the
    /// per-spawn handle-dir `config.toml::instructions` block in
    /// PR-CA8 commit 2.
    #[test]
    fn output_schema_directive_present_on_codex_payload() {
        let set = build_set(vec![]);
        let payload = translate(&set);
        let directive = payload
            .output_schema_directive
            .expect("PR-CA8: directive must be Some");
        assert!(directive.contains("rule_id"));
        assert!(directive.contains("decision"));
        assert!(directive.contains("rationale"));
        assert!(directive.contains("compliance"));
    }

    /// PR-CA8 R1-H11: universal rule (`applies_to: []` empty set) MUST
    /// appear in codex translator output per spec 09 §9.2.4.
    #[test]
    fn universal_rule_appears_in_codex_translator() {
        let set = build_set(vec![rule(
            "RULE-UNIVERSAL",
            0,
            &[],
            "applies to all surfaces",
        )]);
        let payload = translate(&set);
        assert!(
            payload.instructions.contains("RULE-UNIVERSAL"),
            "universal rule must appear in codex translator output"
        );
        assert!(payload.contributing_ids.contains("RULE-UNIVERSAL"));
    }

    /// PR-CA8 R1-H11: universal agent (empty `applies_to`) MUST appear
    /// in codex translator output.
    #[test]
    fn universal_agent_appears_in_codex_translator() {
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
        let payload = translate(&set);
        assert!(
            payload.instructions.contains("AGENT-UNIVERSAL"),
            "universal agent must appear in codex translator output"
        );
    }

    /// PR-CA8 R1-H11: universal skill (empty `applies_to`) MUST appear
    /// in codex translator output.
    #[test]
    fn universal_skill_appears_in_codex_translator() {
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
        let payload = translate(&set);
        assert!(
            payload.instructions.contains("SKILL-UNIVERSAL"),
            "universal skill must appear in codex translator output"
        );
    }

    /// PR-CA8 R1-H11: universal command (empty `applies_to`) MUST appear
    /// in codex translator output.
    #[test]
    fn universal_command_appears_in_codex_translator() {
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
        let payload = translate(&set);
        assert!(
            payload.instructions.contains("COMMAND-UNIVERSAL"),
            "universal command must appear in codex translator output"
        );
    }
}
