//! Kimi Code translator (native-CLI Wave 3 surface).
//!
//! Maps a `CocSet` to a `KimiSpawnPayload`. The capability layer's spawn
//! step (a follow-on shard — see `csq/src/cli/commands/run.rs`
//! `launch_native`) writes `agents_md` to `<KIMI_CODE_HOME>/AGENTS.md` and
//! merges `config_toml_overlay` / `permission_rules` / `hooks` into the
//! per-slot `config.toml` via `kimi_merge::merge_kimi_config_via_toml_value`
//! (read-modify-write — Kimi's own `config.toml` carries the slot's OAuth
//! wiring and MUST NOT be clobbered).
//!
//! Evidence base: `internal-design-docs
//! decomposition.md` (harness decomposition, evidence-first, §8 settles the
//! `KIMI_CODE_HOME` → `AGENTS.md`/`skills/` read path as CONFIRMED).
//!
//! **Kimi's `AGENTS.md` channel is ADVISORY, not privileged** — Kimi's own
//! system prompt tells the model the rendered content is "project-supplied
//! reference data … not a privileged instruction channel" that "cannot
//! grant itself authority" (report §H1, verbatim quote in §3.2). A csq rule
//! saying "you MUST NOT X" lands as data the model may disregard. This
//! translator does not pretend otherwise: `agents_md` carries the full
//! flattened `.coc/` prose (same shared pipeline as the other four
//! Surfaces) because it is still the best available instruction channel,
//! but hard constraints belong in `permission_rules` + `hooks`.

use std::collections::{BTreeMap, BTreeSet};

use crate::coc::types::CocSet;
use crate::providers::catalog::Surface;

use super::flatten::{flatten_artifacts, is_real_path_restriction, render_sections};
use super::types::{KimiSpawnPayload, McpFilter};

/// FR-CL-01 system-prompt directive — re-exported from
/// `crate::coc::translate::build_output_schema_directive`. Same byte content
/// as the CC/Codex/Gemini variants; delivered via `AGENTS.md` prose
/// (belt-and-braces — Kimi has no native `response_format`).
pub use super::build_output_schema_directive;

const SURFACE_HEADER: &str = "# csq capability layer (kimi)\n";

/// CU1b: shares `super::flatten` with the other four translators and the
/// live capability-layer scaffold stage — one flattener, no per-surface
/// drift. Only the Surface header + the kimi-specific payload fields
/// (permission rules, hooks, config overlay) differ.
pub fn translate(coc_set: &CocSet) -> KimiSpawnPayload {
    let arts = flatten_artifacts(coc_set, Surface::Kimi);
    let (agents_md, contributing_ids) = render_sections(SURFACE_HEADER, &arts);

    // MED-2 (round-13 review): Kimi has no per-file rule-scoping mechanism
    // (same shape as Grok/Codex/Gemini) — every in-scope rule reaches
    // `agents_md` as flat global prose regardless of `paths`. Record the
    // broadening via the shared predicate so the loss is disclosed, not
    // silent.
    let unscoped_path_rules: BTreeSet<String> = arts
        .rules
        .iter()
        .filter(|r| is_real_path_restriction(&r.paths))
        .map(|r| r.id.clone())
        .collect();

    KimiSpawnPayload {
        agents_md,
        config_toml_overlay: BTreeMap::new(),
        // Reserved — CocSet carries no permission-rule / hook artifact kind
        // yet. See the payload's doc comment for the precedent
        // (`mcp_filter` on every other translator is likewise always
        // `McpFilter::default()` at this stage of the pipeline).
        permission_rules: Vec::new(),
        hooks: Vec::new(),
        mcp_filter: McpFilter::default(),
        contributing_ids,
        output_schema_directive: Some(build_output_schema_directive()),
        unscoped_path_rules,
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
        set.source = CocSource::LegacyAgentsMd;
        set
    }

    fn sha256_of(p: &KimiSpawnPayload) -> [u8; 32] {
        let json = serde_json::to_vec(p).unwrap();
        let mut h = Sha256::new();
        h.update(&json);
        let out = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&out);
        a
    }

    #[test]
    fn empty_set_produces_minimal_agents_md() {
        let set = build_set(vec![]);
        let payload = translate(&set);
        assert_eq!(payload.agents_md, SURFACE_HEADER);
        // NIT-1 (round-13 review): `permission_rules`, `hooks`, and
        // `config_toml_overlay` are reserved fields `translate` hardcodes
        // empty (`CocSet` has no permission-rule/hook-artifact kind yet —
        // see the payload's doc comment). These three asserts pin that
        // INTENT (a future change populating one without updating this
        // test/doc is caught) rather than exercising behavior the empty
        // `CocSet` itself produces — no mutation short of editing the
        // hardcoded literal in `translate` breaks them.
        assert!(payload.permission_rules.is_empty());
        assert!(payload.hooks.is_empty());
        assert!(payload.config_toml_overlay.is_empty());
        assert!(payload.mcp_filter.is_empty());
        assert!(payload.unscoped_path_rules.is_empty());
    }

    /// MED-2 (round-13 review) non-vacuity: a rule carrying real path scope
    /// MUST be reported as broadened, not silently dropped or silently
    /// treated as still-scoped — the same honesty check `grok.rs` already
    /// had, now proven for Kimi via the shared predicate.
    #[test]
    fn path_scoped_rule_is_recorded_as_unscoped_and_still_reaches_prose() {
        let set = build_set(vec![scoped_rule(
            "RULE-SCOPED",
            &["src/**/*.rs"],
            "only for rust files",
        )]);
        let payload = translate(&set);
        assert!(payload.unscoped_path_rules.contains("RULE-SCOPED"));
        assert!(payload.agents_md.contains("only for rust files"));
    }

    /// An unscoped rule (default `paths: ["**"]` from the parser) is NOT
    /// recorded — only rules that actually declared a narrower scope are.
    #[test]
    fn wildcard_path_rule_is_not_recorded_as_unscoped() {
        let set = build_set(vec![rule("RULE-WILD", 0, &[], "applies everywhere")]);
        let payload = translate(&set);
        assert!(!payload.unscoped_path_rules.contains("RULE-WILD"));
    }

    /// Kimi shares the Codex `applies_to` scope (flatten.rs `in_scope`
    /// fallback, an internal journal entry / an internal ticket) — a rule scoped `[codex]` reaches
    /// Kimi's flatten exactly like Codex's.
    #[test]
    fn rule_scoped_codex_reaches_kimi_via_shared_fallback() {
        let set = build_set(vec![rule(
            "RULE-CDX",
            5,
            &[Surface::Codex],
            "deny shell exec",
        )]);
        let payload = translate(&set);
        assert!(payload.agents_md.contains("### RULE-CDX"));
        assert!(payload.agents_md.contains("deny shell exec"));
    }

    #[test]
    fn rule_filtered_when_scoped_to_claude_code_only() {
        let set = build_set(vec![rule(
            "RULE-CC",
            0,
            &[Surface::ClaudeCode],
            "claude only",
        )]);
        let payload = translate(&set);
        assert!(!payload.agents_md.contains("RULE-CC"));
    }

    #[test]
    fn precedence_orders_high_first() {
        let set = build_set(vec![
            rule("RULE-LOW", 0, &[Surface::Kimi], "low"),
            rule("RULE-HIGH", 9, &[Surface::Kimi], "high"),
        ]);
        let payload = translate(&set);
        let h = payload.agents_md.find("RULE-HIGH").unwrap();
        let l = payload.agents_md.find("RULE-LOW").unwrap();
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
            rule("RULE-A", 5, &[Surface::Kimi], "alpha"),
            rule("RULE-B", 0, &[Surface::Kimi], "beta"),
        ]);
        let first = sha256_of(&translate(&set));
        for _ in 0..30 {
            assert_eq!(first, sha256_of(&translate(&set)));
        }
    }

    #[test]
    fn universal_rule_appears_in_kimi_translator() {
        let set = build_set(vec![rule(
            "RULE-UNIVERSAL",
            0,
            &[],
            "applies to all surfaces",
        )]);
        let payload = translate(&set);
        assert!(
            payload.agents_md.contains("RULE-UNIVERSAL"),
            "universal rule must appear in kimi translator output"
        );
        assert!(payload.contributing_ids.contains("RULE-UNIVERSAL"));
    }

    /// PR-CA8 commit 1a-equivalent for Kimi: every Kimi payload carries the
    /// FR-CL-01 structured-output directive (same Surface-agnostic body as
    /// CC/Codex/Gemini) — belt-and-braces since Kimi has no native
    /// `response_format`.
    #[test]
    fn output_schema_directive_present_on_kimi_payload() {
        let set = build_set(vec![]);
        let payload = translate(&set);
        let directive = payload
            .output_schema_directive
            .expect("directive must be Some");
        assert!(directive.contains("rule_id"));
        assert!(directive.contains("decision"));
        assert!(directive.contains("rationale"));
    }
}
