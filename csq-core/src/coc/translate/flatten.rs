//! The single `.coc/` → per-Surface flattener (CU1b, an internal ticket).
//!
//! Before CU1b the surface-filter + precedence-sort logic was triplicated
//! across `cc.rs`, `codex.rs`, and `gemini.rs` (each with its own
//! `filter_rules`/`filter_agents`/`filter_skills`/`filter_commands` +
//! `sort_artifacts`), AND a fourth rules-only copy lived in
//! `capability_layer::scaffold::build_scaffold` (the live-spawn path). CU1b
//! collapses the artifact flatten onto this one module:
//!
//! - The three translators build their per-Surface text from
//!   [`flatten_artifacts`] + [`render_sections`].
//! - The live capability-layer scaffold stage renders the SAME text by
//!   calling `render_sections(surface_header(surface), flatten_artifacts(..))`
//!   directly (flattening the `.coc/` once — byte-identical to the
//!   translators' `system_text()`, not via a `translate::translate` dispatch)
//!   and records the per-kind breakdown ([`SurfaceArtifacts`]) on
//!   `PreSpawnState` — the substrate CU3 (native materialization) extends.
//!
//! Determinism (FR-DISP-05 / spec 10 §10.3.5): every list is sorted by
//! `(precedence DESC, id ASC)` so identical input yields byte-identical
//! output across runs and processes.
//!
//! Note: `extract_rule_ids_in_scope` (`capability_layer::driver`) is a
//! DISTINCT concern — it returns the rules-only RULE_ID *set* the
//! post-validate citation gate + `csq classify` consume, not the
//! full-body flatten this module produces. The two share the same
//! `applies_to` predicate but serve different outputs; they are NOT merged
//! (CU1b boundary note — `extract_rule_ids_in_scope` has two production
//! consumers and stays the single rule-id source).

use std::collections::BTreeSet;

use crate::coc::types::CocSet;
use crate::providers::catalog::Surface;

/// One flattened artifact (rule / agent / skill / command) in scope for a
/// Surface. Owned (not borrowed) so the capability-layer per-kind channel
/// ([`SurfaceArtifacts`] on `PreSpawnState`) can hold it past the
/// `CocSet`'s lifetime. `body` is the full untrimmed artifact body — the
/// text renderer trims trailing whitespace at render time, but the channel
/// keeps the full body for CU3 native materialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatArtifact {
    pub id: String,
    pub precedence: i32,
    pub body: String,
}

/// Per-kind flattened artifacts in scope for a Surface. Each `Vec` is
/// sorted `(precedence DESC, id ASC)` — deterministic by construction
/// (spec 10 §10.3.5; the determinism contract permits sorted `Vec`
/// alongside `BTreeMap`/`BTreeSet`). This is THE single filter+sort feeding
/// both the per-Surface text builders ([`render_sections`]) and the
/// capability-layer per-kind channel (`PreSpawnState::artifacts`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SurfaceArtifacts {
    pub rules: Vec<FlatArtifact>,
    pub agents: Vec<FlatArtifact>,
    pub skills: Vec<FlatArtifact>,
    pub commands: Vec<FlatArtifact>,
}

impl SurfaceArtifacts {
    /// True when no artifact of any kind is in scope for the Surface.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
            && self.agents.is_empty()
            && self.skills.is_empty()
            && self.commands.is_empty()
    }
}

/// `applies_to` semantics per spec 09 §9.2.4: an empty set means
/// "universal — applies to every Surface"; a non-empty set means "applies
/// only to the listed surfaces".
///
/// This is THE single surface-scope predicate. `flatten_artifacts` (the
/// full-body flatten) AND `capability_layer::driver::extract_rule_ids_in_scope`
/// (the rules-only citation ID set) both call it, so the rules that appear in
/// the delivered scaffold are exactly the rules required for citation — they
/// cannot drift (redteam R1 DA-2). `pub(crate)` so the driver can reach it.
pub(crate) fn in_scope(applies_to: &BTreeSet<Surface>, surface: Surface) -> bool {
    applies_to.is_empty() || applies_to.contains(&surface)
}

/// The per-Surface system-prompt header — the single source for the
/// `# csq capability layer (<surface>)` first line. Each translator's
/// `system_text()` and the live capability-layer scaffold stage both render
/// through `render_sections(surface_header(surface), ..)`, so the live spawn
/// flattens the `.coc/` exactly ONCE (redteam R1 IR-1) instead of going
/// through a translator dispatch that re-flattens. The
/// `surface_header_matches_translator_empty_output` test pins this against the
/// translators' own headers so the two cannot drift.
pub fn surface_header(surface: Surface) -> &'static str {
    match surface {
        Surface::ClaudeCode => "# csq capability layer (claude-code)\n",
        Surface::Codex => "# csq capability layer (codex)\n",
        Surface::Gemini => "# csq capability layer (gemini)\n",
    }
}

/// Sort `(precedence DESC, id ASC)`: higher precedence first, id as a
/// stable tie-break. Matches the pre-CU1b per-translator `sort_artifacts`
/// byte-for-byte.
fn sort_flat(v: &mut [FlatArtifact]) {
    v.sort_by(|a, b| {
        b.precedence
            .cmp(&a.precedence)
            .then_with(|| a.id.as_str().cmp(b.id.as_str()))
    });
}

/// Flatten a `CocSet` into the per-kind, surface-filtered, precedence-sorted
/// artifact lists. Pure function; deterministic by construction.
pub fn flatten_artifacts(coc_set: &CocSet, surface: Surface) -> SurfaceArtifacts {
    let mut rules: Vec<FlatArtifact> = coc_set
        .rules
        .values()
        .filter(|r| in_scope(&r.applies_to, surface))
        .map(|r| FlatArtifact {
            id: r.id.0.clone(),
            precedence: r.precedence,
            body: r.body.clone(),
        })
        .collect();
    sort_flat(&mut rules);

    let mut agents: Vec<FlatArtifact> = coc_set
        .agents
        .values()
        .filter(|a| in_scope(&a.applies_to, surface))
        .map(|a| FlatArtifact {
            id: a.id.0.clone(),
            precedence: a.precedence,
            body: a.body.clone(),
        })
        .collect();
    sort_flat(&mut agents);

    let mut skills: Vec<FlatArtifact> = coc_set
        .skills
        .values()
        .filter(|s| in_scope(&s.applies_to, surface))
        .map(|s| FlatArtifact {
            id: s.id.0.clone(),
            precedence: s.precedence,
            body: s.body.clone(),
        })
        .collect();
    sort_flat(&mut skills);

    let mut commands: Vec<FlatArtifact> = coc_set
        .commands
        .values()
        .filter(|c| in_scope(&c.applies_to, surface))
        .map(|c| FlatArtifact {
            id: c.id.0.clone(),
            precedence: c.precedence,
            body: c.body.clone(),
        })
        .collect();
    sort_flat(&mut commands);

    SurfaceArtifacts {
        rules,
        agents,
        skills,
        commands,
    }
}

/// Append one `### {id} (precedence={p})\n{body}\n` section. Identical
/// across all three Surfaces (was triplicated as
/// `push_artifact_section`/`push_section`). `body` is trimmed of trailing
/// whitespace at render time.
fn push_artifact_section(out: &mut String, art: &FlatArtifact) {
    out.push('\n');
    out.push_str("### ");
    out.push_str(&art.id);
    out.push_str(" (precedence=");
    out.push_str(&art.precedence.to_string());
    out.push_str(")\n");
    out.push_str(art.body.trim_end());
    out.push('\n');
}

/// Build the per-Surface system text from a Surface header + the flattened
/// artifacts, returning the text AND the set of contributing artifact IDs.
/// Shared by all three translators so their `## Rules / ## Agents / ##
/// Skills / ## Commands` sections are byte-identical (only the header
/// differs per Surface).
pub fn render_sections(header: &str, arts: &SurfaceArtifacts) -> (String, BTreeSet<String>) {
    let mut out = String::new();
    out.push_str(header);
    let mut contributing_ids: BTreeSet<String> = BTreeSet::new();

    if !arts.rules.is_empty() {
        out.push_str("\n## Rules\n");
        for a in &arts.rules {
            push_artifact_section(&mut out, a);
            contributing_ids.insert(a.id.clone());
        }
    }
    if !arts.agents.is_empty() {
        out.push_str("\n## Agents\n");
        for a in &arts.agents {
            push_artifact_section(&mut out, a);
            contributing_ids.insert(a.id.clone());
        }
    }
    if !arts.skills.is_empty() {
        out.push_str("\n## Skills\n");
        for a in &arts.skills {
            push_artifact_section(&mut out, a);
            contributing_ids.insert(a.id.clone());
        }
    }
    if !arts.commands.is_empty() {
        out.push_str("\n## Commands\n");
        for a in &arts.commands {
            push_artifact_section(&mut out, a);
            contributing_ids.insert(a.id.clone());
        }
    }

    (out, contributing_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coc::types::{
        AgentDef, AgentId, CommandDef, CommandId, RuleDef, RuleId, SkillDef, SkillId,
    };
    use std::collections::BTreeMap;

    fn rule(id: &str, precedence: i32, surfaces: &[Surface], body: &str) -> RuleDef {
        let mut applies_to = BTreeSet::new();
        for s in surfaces {
            applies_to.insert(*s);
        }
        RuleDef {
            id: RuleId(id.to_string()),
            paths: vec!["**".to_string()],
            applies_to,
            precedence,
            disable: BTreeSet::new(),
            body: body.to_string(),
            unknowns: BTreeMap::new(),
        }
    }

    fn full_set() -> CocSet {
        let mut set = CocSet::empty();
        set.rules
            .insert(RuleId("RULE-X".into()), rule("RULE-X", 0, &[], "rule body"));
        set.agents.insert(
            AgentId("AGENT-Y".into()),
            AgentDef {
                id: AgentId("AGENT-Y".into()),
                applies_to: BTreeSet::new(),
                precedence: 0,
                disable: BTreeSet::new(),
                body: "agent body".into(),
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
                body: "skill body".into(),
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
                body: "command body".into(),
                unknowns: BTreeMap::new(),
            },
        );
        set
    }

    #[test]
    fn flatten_includes_all_four_kinds() {
        let set = full_set();
        let arts = flatten_artifacts(&set, Surface::ClaudeCode);
        assert_eq!(arts.rules.len(), 1);
        assert_eq!(arts.agents.len(), 1);
        assert_eq!(arts.skills.len(), 1);
        assert_eq!(arts.commands.len(), 1);
        assert_eq!(arts.rules[0].id, "RULE-X");
        assert_eq!(arts.agents[0].id, "AGENT-Y");
        assert_eq!(arts.skills[0].id, "SKILL-Z");
        assert_eq!(arts.commands[0].id, "COMMAND-W");
        assert!(!arts.is_empty());
    }

    #[test]
    fn flatten_filters_by_applies_to_surface() {
        let mut set = CocSet::empty();
        set.rules.insert(
            RuleId("RULE-CC".into()),
            rule("RULE-CC", 0, &[Surface::ClaudeCode], "cc only"),
        );
        set.rules.insert(
            RuleId("RULE-CODEX".into()),
            rule("RULE-CODEX", 0, &[Surface::Codex], "codex only"),
        );
        let cc = flatten_artifacts(&set, Surface::ClaudeCode);
        assert_eq!(cc.rules.len(), 1);
        assert_eq!(cc.rules[0].id, "RULE-CC");
        let codex = flatten_artifacts(&set, Surface::Codex);
        assert_eq!(codex.rules.len(), 1);
        assert_eq!(codex.rules[0].id, "RULE-CODEX");
    }

    #[test]
    fn flatten_sorts_precedence_desc_then_id_asc() {
        let mut set = CocSet::empty();
        set.rules
            .insert(RuleId("RULE-LOW".into()), rule("RULE-LOW", 0, &[], "low"));
        set.rules.insert(
            RuleId("RULE-HIGH".into()),
            rule("RULE-HIGH", 5, &[], "high"),
        );
        set.rules
            .insert(RuleId("RULE-A".into()), rule("RULE-A", 0, &[], "a tie"));
        let arts = flatten_artifacts(&set, Surface::ClaudeCode);
        // precedence 5 first, then the two precedence-0 rules id-ASC.
        assert_eq!(arts.rules[0].id, "RULE-HIGH");
        assert_eq!(arts.rules[1].id, "RULE-A");
        assert_eq!(arts.rules[2].id, "RULE-LOW");
    }

    #[test]
    fn flatten_keeps_full_untrimmed_body() {
        let mut set = CocSet::empty();
        set.rules.insert(
            RuleId("RULE-X".into()),
            rule("RULE-X", 0, &[], "body with trailing\n\n"),
        );
        let arts = flatten_artifacts(&set, Surface::ClaudeCode);
        // Channel keeps the full body (trim happens only at text render).
        assert_eq!(arts.rules[0].body, "body with trailing\n\n");
    }

    #[test]
    fn render_sections_emits_all_kinds_with_headers() {
        let set = full_set();
        let arts = flatten_artifacts(&set, Surface::ClaudeCode);
        let (text, ids) = render_sections("# header\n", &arts);
        assert!(text.starts_with("# header\n"));
        assert!(text.contains("\n## Rules\n"));
        assert!(text.contains("\n## Agents\n"));
        assert!(text.contains("\n## Skills\n"));
        assert!(text.contains("\n## Commands\n"));
        assert!(text.contains("### RULE-X (precedence=0)"));
        assert!(text.contains("rule body"));
        assert!(text.contains("agent body"));
        assert!(text.contains("skill body"));
        assert!(text.contains("command body"));
        assert!(ids.contains("RULE-X"));
        assert!(ids.contains("AGENT-Y"));
        assert!(ids.contains("SKILL-Z"));
        assert!(ids.contains("COMMAND-W"));
    }

    #[test]
    fn render_sections_empty_is_header_only() {
        let arts = SurfaceArtifacts::default();
        let (text, ids) = render_sections("# header\n", &arts);
        assert_eq!(text, "# header\n");
        assert!(ids.is_empty());
    }

    #[test]
    fn render_sections_trims_trailing_body_whitespace() {
        let mut set = CocSet::empty();
        set.rules.insert(
            RuleId("RULE-X".into()),
            rule("RULE-X", 0, &[], "body\n\n\n"),
        );
        let arts = flatten_artifacts(&set, Surface::ClaudeCode);
        let (text, _) = render_sections("# h\n", &arts);
        // Section ends with the trimmed body + exactly one newline.
        assert!(text.ends_with("body\n"));
        assert!(!text.contains("body\n\n\n"));
    }

    /// redteam R1 DA-1 + R2 DA-NEW-2: BYTE-EXACT golden for the multi-kind
    /// render. The translator output bytes are CU1a's FROZEN `csq translate
    /// --json` contract (CU5 byte-parity compares against it); the pre-CU1b
    /// substring/ordering tests could not catch a whitespace/trim regression
    /// in the unified `render_sections`/`push_artifact_section`. This pins
    /// every byte: the leading `\n` per section, the `## <Kind>\n` header
    /// spacing, the `### {id} (precedence={p})\n{body}\n` shape, and the
    /// trim. A change here is a deliberate format change, not an accident.
    ///
    /// The `expected` literal below is the PRE-CU1b frozen output format,
    /// verified byte-identical during R2 redteam against the deleted
    /// per-translator renderers (`git show main:csq-core/src/coc/translate/cc.rs`
    /// — same `SURFACE_HEADER`, `\n## <Kind>\n` headers, and
    /// `push_artifact_section` body). So this golden is the retroactive
    /// proof-of-equality with pre-CU1b AND the forward regression guard.
    #[test]
    fn render_sections_byte_exact_golden() {
        let set = full_set();
        let arts = flatten_artifacts(&set, Surface::ClaudeCode);
        let (text, _) = render_sections(surface_header(Surface::ClaudeCode), &arts);
        let expected = "# csq capability layer (claude-code)\n\
\n## Rules\n\
\n### RULE-X (precedence=0)\nrule body\n\
\n## Agents\n\
\n### AGENT-Y (precedence=0)\nagent body\n\
\n## Skills\n\
\n### SKILL-Z (precedence=0)\nskill body\n\
\n## Commands\n\
\n### COMMAND-W (precedence=0)\ncommand body\n";
        assert_eq!(text, expected, "render_sections byte-exact format drift");
    }

    /// redteam R1 IR-1/DA-1: `surface_header` is the single header source the
    /// live scaffold renders through (flattening once). This pins it against
    /// each translator's OWN header (empty set → header only) so the scaffold
    /// path and the `csq translate` path stay byte-identical and cannot drift.
    #[test]
    fn surface_header_matches_translator_empty_output() {
        let empty = CocSet::empty();
        assert_eq!(
            surface_header(Surface::ClaudeCode),
            super::super::cc::translate(&empty).system_prompt_append,
            "cc header drift"
        );
        assert_eq!(
            surface_header(Surface::Codex),
            super::super::codex::translate(&empty).instructions,
            "codex header drift"
        );
        assert_eq!(
            surface_header(Surface::Gemini),
            super::super::gemini::translate(&empty).system_instruction,
            "gemini header drift"
        );
    }
}
