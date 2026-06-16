//! Claude Code translator (FR-DISP-02).
//!
//! Maps a `CocSet` to a `ClaudeSpawnPayload` per spec 09 + spec 07
//! §7.2.1. The capability-layer scaffold prepends the assembled
//! `system_prompt_append` to claude's system-prompt context via
//! `settings.json::env.CLAUDE_SYSTEM_PROMPT_APPEND`.
//!
//! Determinism (FR-DISP-05): all collections are `BTreeMap`/`BTreeSet`,
//! and the prompt-builder iterates in sorted order. Same input yields
//! byte-identical output across runs and across processes.

use std::collections::{BTreeMap, BTreeSet};

use crate::coc::types::{AgentDef, CocSet, CommandDef, RuleDef, SkillDef};
use crate::providers::catalog::Surface;

use super::types::{ClaudeSpawnPayload, McpFilter};

const SURFACE_HEADER: &str = "# csq capability layer (claude-code)\n";

/// Translate a `CocSet` to a `ClaudeSpawnPayload`. Pure function; no I/O.
pub fn translate(coc_set: &CocSet) -> ClaudeSpawnPayload {
    let target = Surface::ClaudeCode;

    let rules = filter_rules(coc_set, target);
    let agents = filter_agents(coc_set, target);
    let skills = filter_skills(coc_set, target);
    let commands = filter_commands(coc_set, target);

    let mut prompt = String::new();
    prompt.push_str(SURFACE_HEADER);

    let mut contributing_ids: BTreeSet<String> = BTreeSet::new();

    if !rules.is_empty() {
        prompt.push_str("\n## Rules\n");
        for rule in &rules {
            push_artifact_section(&mut prompt, &rule.id.0, rule.precedence, &rule.body);
            contributing_ids.insert(rule.id.0.clone());
        }
    }

    if !agents.is_empty() {
        prompt.push_str("\n## Agents\n");
        for agent in &agents {
            push_artifact_section(&mut prompt, &agent.id.0, agent.precedence, &agent.body);
            contributing_ids.insert(agent.id.0.clone());
        }
    }

    if !skills.is_empty() {
        prompt.push_str("\n## Skills\n");
        for skill in &skills {
            push_artifact_section(&mut prompt, &skill.id.0, skill.precedence, &skill.body);
            contributing_ids.insert(skill.id.0.clone());
        }
    }

    if !commands.is_empty() {
        prompt.push_str("\n## Commands\n");
        for command in &commands {
            push_artifact_section(
                &mut prompt,
                &command.id.0,
                command.precedence,
                &command.body,
            );
            contributing_ids.insert(command.id.0.clone());
        }
    }

    let permissions_allow = BTreeSet::new();
    let mcp_filter = McpFilter::default();
    let settings_overlay = BTreeMap::new();
    let output_schema_directive = Some(build_output_schema_directive());

    ClaudeSpawnPayload {
        system_prompt_append: prompt,
        permissions_allow,
        mcp_filter,
        settings_overlay,
        contributing_ids,
        output_schema_directive,
    }
}

/// FR-CL-01 system-prompt directive — re-exported from
/// `crate::coc::translate::build_output_schema_directive` per PR-CA8 commit
/// 1a. The directive text is Surface-agnostic; CC, Codex, and Gemini all
/// reach the same module-level function for byte-identical output.
///
/// Origin: PR-CA7c authored the function here; PR-CA8 promoted it to
/// `coc/translate/mod.rs` for cross-Surface use. Existing callers
/// (`scaffold.rs`, this translator's `output_schema_directive` field) keep
/// working via this re-export.
pub use super::build_output_schema_directive;

fn push_artifact_section(out: &mut String, id: &str, precedence: i32, body: &str) {
    out.push('\n');
    out.push_str("### ");
    out.push_str(id);
    out.push_str(" (precedence=");
    let s = precedence.to_string();
    out.push_str(&s);
    out.push_str(")\n");
    out.push_str(body.trim_end());
    out.push('\n');
}

fn filter_rules(coc_set: &CocSet, surface: Surface) -> Vec<&RuleDef> {
    let mut v: Vec<&RuleDef> = coc_set
        .rules
        .values()
        .filter(|r| r.applies_to.is_empty() || r.applies_to.contains(&surface))
        .collect();
    sort_artifacts(&mut v, |r| (r.precedence, r.id.0.as_str()));
    v
}

fn filter_agents(coc_set: &CocSet, surface: Surface) -> Vec<&AgentDef> {
    let mut v: Vec<&AgentDef> = coc_set
        .agents
        .values()
        .filter(|a| a.applies_to.is_empty() || a.applies_to.contains(&surface))
        .collect();
    sort_artifacts(&mut v, |a| (a.precedence, a.id.0.as_str()));
    v
}

fn filter_skills(coc_set: &CocSet, surface: Surface) -> Vec<&SkillDef> {
    let mut v: Vec<&SkillDef> = coc_set
        .skills
        .values()
        .filter(|s| s.applies_to.is_empty() || s.applies_to.contains(&surface))
        .collect();
    sort_artifacts(&mut v, |s| (s.precedence, s.id.0.as_str()));
    v
}

fn filter_commands(coc_set: &CocSet, surface: Surface) -> Vec<&CommandDef> {
    let mut v: Vec<&CommandDef> = coc_set
        .commands
        .values()
        .filter(|c| c.applies_to.is_empty() || c.applies_to.contains(&surface))
        .collect();
    sort_artifacts(&mut v, |c| (c.precedence, c.id.0.as_str()));
    v
}

/// Sort artifacts by (precedence DESC, id ASC). Higher precedence first;
/// stable on id for tie-break.
fn sort_artifacts<T, F>(v: &mut [&T], key: F)
where
    F: Fn(&T) -> (i32, &str),
{
    v.sort_by(|a, b| {
        let (pa, ia) = key(a);
        let (pb, ib) = key(b);
        pb.cmp(&pa).then_with(|| ia.cmp(ib))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coc::types::{AgentId, CocSet, CocSource, RuleId, SkillId};
    use crate::coc::version::CocVersion;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

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

    fn agent(id: &str, surfaces: &[Surface], body: &str) -> AgentDef {
        let mut applies_to = std::collections::BTreeSet::new();
        for s in surfaces {
            applies_to.insert(*s);
        }
        AgentDef {
            id: AgentId(id.to_string()),
            applies_to,
            precedence: 0,
            disable: std::collections::BTreeSet::new(),
            body: body.to_string(),
            unknowns: BTreeMap::new(),
        }
    }

    fn build_set(rules: Vec<RuleDef>, agents: Vec<AgentDef>) -> CocSet {
        let mut set = CocSet::empty();
        for r in rules {
            set.rules.insert(r.id.clone(), r);
        }
        for a in agents {
            set.agents.insert(a.id.clone(), a);
        }
        set.version = CocVersion {
            major: 1,
            minor: 0,
            patch: 0,
        };
        set.source = CocSource::LegacyClaude;
        set
    }

    fn sha256_of(payload: &ClaudeSpawnPayload) -> [u8; 32] {
        // Serialize to deterministic JSON (BTreeMap + serde_json default)
        let json = serde_json::to_vec(payload).unwrap();
        let mut h = Sha256::new();
        h.update(&json);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    #[test]
    fn empty_set_produces_minimal_prompt() {
        let set = build_set(vec![], vec![]);
        let payload = translate(&set);
        assert_eq!(payload.system_prompt_append, SURFACE_HEADER);
        assert!(payload.contributing_ids.is_empty());
    }

    #[test]
    fn rule_appears_in_prompt() {
        let set = build_set(
            vec![rule(
                "RULE-X",
                0,
                &[Surface::ClaudeCode],
                "do not exec shells.",
            )],
            vec![],
        );
        let payload = translate(&set);
        assert!(payload.system_prompt_append.contains("### RULE-X"));
        assert!(payload.system_prompt_append.contains("do not exec shells."));
        assert!(payload.contributing_ids.contains("RULE-X"));
    }

    #[test]
    fn rules_filtered_by_applies_to() {
        let set = build_set(
            vec![
                rule("RULE-CC", 0, &[Surface::ClaudeCode], "claude only"),
                rule("RULE-CODEX", 0, &[Surface::Codex], "codex only"),
            ],
            vec![],
        );
        let payload = translate(&set);
        assert!(payload.system_prompt_append.contains("RULE-CC"));
        assert!(!payload.system_prompt_append.contains("RULE-CODEX"));
        assert!(!payload.system_prompt_append.contains("codex only"));
    }

    #[test]
    fn higher_precedence_appears_first() {
        let set = build_set(
            vec![
                rule("RULE-LOW", 0, &[Surface::ClaudeCode], "low"),
                rule("RULE-HIGH", 5, &[Surface::ClaudeCode], "high"),
            ],
            vec![],
        );
        let payload = translate(&set);
        let high_pos = payload.system_prompt_append.find("RULE-HIGH").unwrap();
        let low_pos = payload.system_prompt_append.find("RULE-LOW").unwrap();
        assert!(high_pos < low_pos, "higher precedence should sort first");
    }

    #[test]
    fn equal_precedence_tiebreaks_by_id_alphabetical() {
        let set = build_set(
            vec![
                rule("RULE-Z", 0, &[Surface::ClaudeCode], "z"),
                rule("RULE-A", 0, &[Surface::ClaudeCode], "a"),
                rule("RULE-M", 0, &[Surface::ClaudeCode], "m"),
            ],
            vec![],
        );
        let payload = translate(&set);
        let a = payload.system_prompt_append.find("RULE-A").unwrap();
        let m = payload.system_prompt_append.find("RULE-M").unwrap();
        let z = payload.system_prompt_append.find("RULE-Z").unwrap();
        assert!(a < m);
        assert!(m < z);
    }

    #[test]
    fn deterministic_30_invocations() {
        let set = build_set(
            vec![
                rule("RULE-A", 5, &[Surface::ClaudeCode], "alpha"),
                rule("RULE-B", 0, &[Surface::ClaudeCode], "beta"),
                rule("RULE-C", 5, &[Surface::ClaudeCode], "gamma"),
            ],
            vec![agent("AGENT-X", &[Surface::ClaudeCode], "agent body")],
        );
        let first = sha256_of(&translate(&set));
        for _ in 0..30 {
            let next = sha256_of(&translate(&set));
            assert_eq!(first, next, "FR-DISP-05 determinism violated");
        }
    }

    #[test]
    fn applies_to_all_includes_claude() {
        let set = build_set(
            vec![rule(
                "RULE-ALL",
                0,
                &[Surface::ClaudeCode, Surface::Codex, Surface::Gemini],
                "all surfaces",
            )],
            vec![],
        );
        let payload = translate(&set);
        assert!(payload.system_prompt_append.contains("RULE-ALL"));
    }

    #[test]
    fn surface_header_present_even_when_empty() {
        let set = build_set(vec![], vec![]);
        let payload = translate(&set);
        assert!(payload.system_prompt_append.starts_with(SURFACE_HEADER));
    }

    #[test]
    fn contributing_ids_includes_all_artifact_kinds() {
        let mut set = build_set(
            vec![rule("RULE-X", 0, &[Surface::ClaudeCode], "r")],
            vec![agent("AGENT-Y", &[Surface::ClaudeCode], "a")],
        );
        set.skills.insert(
            SkillId("SKILL-Z".to_string()),
            SkillDef {
                id: SkillId("SKILL-Z".to_string()),
                applies_to: [Surface::ClaudeCode].into_iter().collect(),
                precedence: 0,
                disable: std::collections::BTreeSet::new(),
                body: "s".to_string(),
                unknowns: BTreeMap::new(),
            },
        );
        let payload = translate(&set);
        assert!(payload.contributing_ids.contains("RULE-X"));
        assert!(payload.contributing_ids.contains("AGENT-Y"));
        assert!(payload.contributing_ids.contains("SKILL-Z"));
    }

    #[test]
    fn permissions_allow_default_empty_in_v1() {
        // M2 ships with empty permissions.allow — tool-policy ingestion
        // is M4/PR-CA6 territory.
        let set = build_set(vec![rule("RULE-X", 0, &[Surface::ClaudeCode], "r")], vec![]);
        let payload = translate(&set);
        assert!(payload.permissions_allow.is_empty());
    }

    /// PR-CA7c: every CC payload carries the FR-CL-01 structured-output
    /// directive instructing the model to use the `{rule_id, decision,
    /// rationale}` envelope for compliance-class prompts. The directive
    /// itself is conditional ("for compliance prompts") so free-form
    /// chat UX is unaffected.
    #[test]
    fn output_schema_directive_is_emitted_with_envelope_fields() {
        let set = build_set(vec![rule("RULE-X", 0, &[Surface::ClaudeCode], "r")], vec![]);
        let payload = translate(&set);
        let directive = payload
            .output_schema_directive
            .expect("PR-CA7c: directive must be Some");
        assert!(
            directive.contains("rule_id"),
            "directive must name `rule_id` field: {directive}"
        );
        assert!(
            directive.contains("decision"),
            "directive must name `decision` field: {directive}"
        );
        assert!(
            directive.contains("rationale"),
            "directive must name `rationale` field: {directive}"
        );
        assert!(
            directive.contains("compliance"),
            "directive must reference compliance gating: {directive}"
        );
        assert!(
            directive.contains("free-form"),
            "directive must explicitly opt free-form chat OUT: {directive}"
        );
    }

    /// PR-CA7c: directive is byte-identical across translations of the
    /// same `CocSet` — pure-function determinism (FR-DISP-05).
    #[test]
    fn output_schema_directive_is_deterministic() {
        let set = build_set(vec![rule("RULE-X", 0, &[Surface::ClaudeCode], "r")], vec![]);
        let p1 = translate(&set);
        let p2 = translate(&set);
        assert_eq!(p1.output_schema_directive, p2.output_schema_directive);
    }

    /// PR-CA7c: directive is independent of `CocSet` content — empty
    /// `.coc/` produces the same directive as a populated one. Rationale:
    /// the directive describes the OUTPUT format the model should use,
    /// not the rule content itself; rule content is in
    /// `system_prompt_append`.
    #[test]
    fn output_schema_directive_is_independent_of_coc_set_content() {
        let empty_set = CocSet {
            source: CocSource::Empty,
            ..CocSet::empty()
        };
        let populated = build_set(vec![rule("RULE-X", 0, &[Surface::ClaudeCode], "r")], vec![]);
        let p_empty = translate(&empty_set);
        let p_populated = translate(&populated);
        assert_eq!(
            p_empty.output_schema_directive, p_populated.output_schema_directive,
            "directive describes shape, not content; CocSet diffs must not affect it"
        );
    }

    /// PR-CA8 R1-H11: universal rule (`applies_to: []` empty set) MUST appear
    /// in cc translator output per spec 09 §9.2.4 universal-artifact contract.
    /// Pre-PR-CA8 versions of the cc translator excluded it — divergence from
    /// scaffold + driver semantics. PR-CA8 reconciles.
    #[test]
    fn universal_rule_appears_in_cc_translator() {
        let set = build_set(
            vec![rule("RULE-UNIVERSAL", 0, &[], "applies to all surfaces")],
            vec![],
        );
        let payload = translate(&set);
        assert!(
            payload.system_prompt_append.contains("RULE-UNIVERSAL"),
            "universal rule must appear in cc translator output"
        );
        assert!(
            payload.contributing_ids.contains("RULE-UNIVERSAL"),
            "universal rule's id must contribute"
        );
    }

    /// PR-CA8 R1-H11: universal agent (empty `applies_to`) MUST appear in
    /// cc translator output.
    #[test]
    fn universal_agent_appears_in_cc_translator() {
        let set = build_set(
            vec![],
            vec![agent("AGENT-UNIVERSAL", &[], "applies to all surfaces")],
        );
        let payload = translate(&set);
        assert!(
            payload.system_prompt_append.contains("AGENT-UNIVERSAL"),
            "universal agent must appear in cc translator output"
        );
    }

    /// PR-CA8 R1-H11: universal skill (empty `applies_to`) MUST appear in
    /// cc translator output.
    #[test]
    fn universal_skill_appears_in_cc_translator() {
        let mut set = build_set(vec![], vec![]);
        set.skills.insert(
            SkillId("SKILL-UNIVERSAL".to_string()),
            SkillDef {
                id: SkillId("SKILL-UNIVERSAL".to_string()),
                applies_to: std::collections::BTreeSet::new(), // empty = universal
                precedence: 0,
                disable: std::collections::BTreeSet::new(),
                body: "applies to all surfaces".to_string(),
                unknowns: BTreeMap::new(),
            },
        );
        let payload = translate(&set);
        assert!(
            payload.system_prompt_append.contains("SKILL-UNIVERSAL"),
            "universal skill must appear in cc translator output"
        );
    }

    /// PR-CA8 R1-H11: universal command (empty `applies_to`) MUST appear in
    /// cc translator output.
    #[test]
    fn universal_command_appears_in_cc_translator() {
        use crate::coc::types::{CommandDef, CommandId};
        let mut set = build_set(vec![], vec![]);
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
            payload.system_prompt_append.contains("COMMAND-UNIVERSAL"),
            "universal command must appear in cc translator output"
        );
    }
}
