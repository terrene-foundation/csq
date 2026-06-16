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

use crate::coc::types::{AgentDef, CocSet, CommandDef, RuleDef, SkillDef};
use crate::providers::catalog::Surface;

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
    let target = Surface::Gemini;

    let mut system_instruction = String::new();
    system_instruction.push_str(SURFACE_HEADER);

    let mut contributing_ids: BTreeSet<String> = BTreeSet::new();

    let rules = filter_rules(coc_set, target);
    if !rules.is_empty() {
        system_instruction.push_str("\n## Rules\n");
        for r in &rules {
            push_section(&mut system_instruction, &r.id.0, r.precedence, &r.body);
            contributing_ids.insert(r.id.0.clone());
        }
    }

    let agents = filter_agents(coc_set, target);
    if !agents.is_empty() {
        system_instruction.push_str("\n## Agents\n");
        for a in &agents {
            push_section(&mut system_instruction, &a.id.0, a.precedence, &a.body);
            contributing_ids.insert(a.id.0.clone());
        }
    }

    let skills = filter_skills(coc_set, target);
    if !skills.is_empty() {
        system_instruction.push_str("\n## Skills\n");
        for s in &skills {
            push_section(&mut system_instruction, &s.id.0, s.precedence, &s.body);
            contributing_ids.insert(s.id.0.clone());
        }
    }

    let commands = filter_commands(coc_set, target);
    if !commands.is_empty() {
        system_instruction.push_str("\n## Commands\n");
        for c in &commands {
            push_section(&mut system_instruction, &c.id.0, c.precedence, &c.body);
            contributing_ids.insert(c.id.0.clone());
        }
    }

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
    }
}

/// Heuristic — does an env-var name look like it carries a production
/// secret? Re-exported from `csq_core::env` per PR-CA8b commit 1b
/// (round-2 R2-M6). The function moved to a dedicated `env` module
/// because host-environment scope is broader than gemini-translator
/// scope. Backwards-compat re-export so existing call sites keep
/// working.
pub use crate::env::looks_like_production_secret;

fn push_section(out: &mut String, id: &str, precedence: i32, body: &str) {
    out.push('\n');
    out.push_str("### ");
    out.push_str(id);
    out.push_str(" (precedence=");
    out.push_str(&precedence.to_string());
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
    v.sort_by(|a, b| {
        b.precedence
            .cmp(&a.precedence)
            .then_with(|| a.id.0.as_str().cmp(b.id.0.as_str()))
    });
    v
}

fn filter_agents(coc_set: &CocSet, surface: Surface) -> Vec<&AgentDef> {
    let mut v: Vec<&AgentDef> = coc_set
        .agents
        .values()
        .filter(|x| x.applies_to.is_empty() || x.applies_to.contains(&surface))
        .collect();
    v.sort_by(|a, b| {
        b.precedence
            .cmp(&a.precedence)
            .then_with(|| a.id.0.as_str().cmp(b.id.0.as_str()))
    });
    v
}

fn filter_skills(coc_set: &CocSet, surface: Surface) -> Vec<&SkillDef> {
    let mut v: Vec<&SkillDef> = coc_set
        .skills
        .values()
        .filter(|x| x.applies_to.is_empty() || x.applies_to.contains(&surface))
        .collect();
    v.sort_by(|a, b| {
        b.precedence
            .cmp(&a.precedence)
            .then_with(|| a.id.0.as_str().cmp(b.id.0.as_str()))
    });
    v
}

fn filter_commands(coc_set: &CocSet, surface: Surface) -> Vec<&CommandDef> {
    let mut v: Vec<&CommandDef> = coc_set
        .commands
        .values()
        .filter(|x| x.applies_to.is_empty() || x.applies_to.contains(&surface))
        .collect();
    v.sort_by(|a, b| {
        b.precedence
            .cmp(&a.precedence)
            .then_with(|| a.id.0.as_str().cmp(b.id.0.as_str()))
    });
    v
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

    #[test]
    fn deterministic_30_invocations() {
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
}
